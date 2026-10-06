//! [`Sql`] over a Cloudflare Durable Object's SQL API, through a small
//! JavaScript adapter the Worker supplies (`workers/src/sql-adapter.js`).
//!
//! A Durable Object refuses `BEGIN`, so a unit of work is the adapter's
//! `transaction`, which runs the body inside `ctx.storage.transactionSync` and
//! rolls everything back when the body reports failure. Rows are read from a
//! cursor one at a time, so a query that stops early reads only what it keeps
//! plus one. This file carries no relay rule; the table modules do not know
//! they are running here.

use crate::error::{Error, Result};
use crate::relay::sql::{Row, Sql, Value};
use js_sys::{Array, ArrayBuffer, Uint8Array};
use std::cell::Cell;
use wasm_bindgen::closure::ScopedClosure;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// What the Worker hands in: `query(sql, params)` returns a cursor and
    /// `transaction(body)` runs `body` (a function returning whether to
    /// commit) atomically and returns whether it committed.
    pub type SqlAdapter;

    #[wasm_bindgen(method, catch)]
    fn query(this: &SqlAdapter, sql: &str, params: &Array) -> std::result::Result<Cursor, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn transaction(
        this: &SqlAdapter,
        body: &ScopedClosure<dyn FnMut() -> bool>,
    ) -> std::result::Result<bool, JsValue>;

    /// A query's rows, one array of cells per call to `next`, `undefined`
    /// when there are no more.
    pub type Cursor;

    #[wasm_bindgen(method, catch)]
    fn next(this: &Cursor) -> std::result::Result<JsValue, JsValue>;
}

/// SQLite integers a JavaScript number carries exactly.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub struct DoSql {
    adapter: SqlAdapter,
    depth: Cell<u32>,
}

// SAFETY: a Worker isolate runs one request at a time inside a Durable Object, and
// wasm32 here has one thread, so the store's mutex is never contended.
// `SqlRelayStore` asks for `Send` because the native host shares a store
// across threads; there is no thread to send a value to on this target.
unsafe impl Send for DoSql {}

impl DoSql {
    pub fn new(adapter: SqlAdapter) -> Self {
        Self {
            adapter,
            depth: Cell::new(0),
        }
    }
}

fn store_error(context: &str, error: &JsValue) -> Error {
    // The adapter's error text is SQLite's (a constraint name, a syntax
    // error), never a bound value, but keep it to a short, single line.
    let text = error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(error, &JsValue::from_str("message"))
                .ok()
                .and_then(|message| message.as_string())
        })
        .unwrap_or_default();
    let text: String = text.chars().filter(|c| !c.is_control()).take(200).collect();
    Error::Store(format!("{context}: {text}"))
}

fn to_js(value: &Value) -> Result<JsValue> {
    Ok(match value {
        Value::Null => JsValue::NULL,
        Value::Integer(n) if n.abs() <= MAX_SAFE_INTEGER => JsValue::from_f64(*n as f64),
        Value::Integer(_) => {
            return Err(Error::Store(
                "sql: an integer is too large for a Durable Object binding".into(),
            ))
        }
        Value::Real(n) => JsValue::from_f64(*n),
        Value::Text(text) => JsValue::from_str(text),
        Value::Blob(bytes) => Uint8Array::from(bytes.as_slice()).buffer().into(),
    })
}

fn from_js(cell: &JsValue) -> Result<Value> {
    if cell.is_null() || cell.is_undefined() {
        return Ok(Value::Null);
    }
    if let Some(n) = cell.as_f64() {
        return Ok(
            if n.is_finite() && n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER as f64 {
                Value::Integer(n as i64)
            } else {
                Value::Real(n)
            },
        );
    }
    if let Some(text) = cell.as_string() {
        return Ok(Value::Text(text));
    }
    if let Some(buffer) = cell.dyn_ref::<ArrayBuffer>() {
        return Ok(Value::Blob(Uint8Array::new(buffer).to_vec()));
    }
    if let Some(view) = cell.dyn_ref::<Uint8Array>() {
        return Ok(Value::Blob(view.to_vec()));
    }
    if let Some(flag) = cell.as_bool() {
        return Ok(Value::Integer(i64::from(flag)));
    }
    Err(Error::Store(
        "sql: a column has a type the relay does not store".into(),
    ))
}

impl Sql for DoSql {
    fn execute(&self, sql: &str, params: &[Value]) -> Result<usize> {
        // Run the statement, then ask SQLite how many rows it changed: a
        // Durable Object's cursor reports rows written (indexes included),
        // not rows changed.
        self.query_each(sql, params, &mut |_| Ok(true))?;
        Ok(usize::try_from(self.changes()?).unwrap_or(usize::MAX))
    }

    fn execute_batch(&self, sql: &str) -> Result<()> {
        // The adapter runs a multi-statement string as one `exec`.
        self.query_each(sql, &[], &mut |_| Ok(true))
    }

    fn query_each(
        &self,
        sql: &str,
        params: &[Value],
        each: &mut dyn FnMut(&Row) -> Result<bool>,
    ) -> Result<()> {
        let bound = Array::new();
        for value in params {
            bound.push(&to_js(value)?);
        }
        let cursor = self
            .adapter
            .query(sql, &bound)
            .map_err(|error| store_error("sql", &error))?;
        loop {
            let next = cursor.next().map_err(|error| store_error("sql", &error))?;
            if next.is_undefined() || next.is_null() {
                return Ok(());
            }
            let cells: Array = next
                .dyn_into()
                .map_err(|_| Error::Store("sql: a row is not an array".into()))?;
            let mut values = Vec::with_capacity(cells.length() as usize);
            for cell in cells.iter() {
                values.push(from_js(&cell)?);
            }
            if !each(&Row::new(values))? {
                return Ok(());
            }
        }
    }

    fn last_insert_rowid(&self) -> Result<i64> {
        let mut rowid = 0;
        self.query_each("SELECT last_insert_rowid()", &[], &mut |row| {
            rowid = row.get(0)?;
            Ok(false)
        })?;
        Ok(rowid)
    }

    fn changes(&self) -> Result<u64> {
        let mut changes = 0i64;
        self.query_each("SELECT changes()", &[], &mut |row| {
            changes = row.get(0)?;
            Ok(false)
        })?;
        Ok(u64::try_from(changes).unwrap_or(0))
    }

    fn transaction(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        if self.depth.get() > 0 {
            return f();
        }
        let mut outcome: Option<Result<()>> = None;
        let committed = {
            let mut body = || {
                self.depth.set(1);
                let result = f();
                self.depth.set(0);
                let ok = result.is_ok();
                outcome = Some(result);
                ok
            };
            let closure = ScopedClosure::borrow_mut(&mut body);
            self.adapter.transaction(&closure)
        };
        self.depth.set(0);
        match (committed, outcome) {
            (Ok(true), Some(Ok(()))) => Ok(()),
            (_, Some(Err(error))) => Err(error),
            (Ok(_), _) => Err(Error::Store(
                "sql: the transaction did not commit and reported no failure".into(),
            )),
            (Err(error), _) => Err(store_error("transaction", &error)),
        }
    }
}
