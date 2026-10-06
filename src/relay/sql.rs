//! The one SQL surface the relay's table modules are written against.
//!
//! Every relay module (`api_key`, `audit`, `mailbox`, `device_mail`,
//! `device_directory`, `org_tree`, `key_delivery`) takes `&dyn Sql`, never a
//! `rusqlite::Connection`, so the same rule code runs over any SQLite
//! executor: the owner-only file the native host opens, an in-memory
//! database in tests and the browser lab, and (planned) the SQL API of a
//! Cloudflare Durable Object, where `BEGIN` is refused and a transaction is
//! `transactionSync`. This trait carries no rule: it binds values, runs a
//! statement, streams rows and nests a transaction. SQL stays SQL (SQLite's
//! own `'now'`, `INSERT OR IGNORE`, `ON CONFLICT`), so a backend must be
//! SQLite, not a lookalike.
//!
//! A [`Value`]'s `Debug` prints its kind and length, never its content: a
//! blob here can be a sealed letter and a text a key hash.

use crate::error::{Error, Result};
use std::fmt;

/// One SQLite value, bound as a parameter or read from a row.
#[derive(Clone, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("Null"),
            Value::Integer(_) => f.write_str("Integer(..)"),
            Value::Real(_) => f.write_str("Real(..)"),
            Value::Text(text) => write!(f, "Text({} bytes)", text.len()),
            Value::Blob(bytes) => write!(f, "Blob({} bytes)", bytes.len()),
        }
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Value::Integer(value)
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Value::Integer(i64::from(value))
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Value::Integer(i64::from(value))
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Value::Integer(i64::from(value))
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Value::Real(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::Text(value.to_owned())
    }
}

impl From<&String> for Value {
    fn from(value: &String) -> Self {
        Value::Text(value.clone())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value::Text(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Value::Blob(value.to_vec())
    }
}

impl From<&Vec<u8>> for Value {
    fn from(value: &Vec<u8>) -> Self {
        Value::Blob(value.clone())
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Value::Blob(value)
    }
}

impl<const N: usize> From<&[u8; N]> for Value {
    fn from(value: &[u8; N]) -> Self {
        Value::Blob(value.to_vec())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        value.map_or(Value::Null, Into::into)
    }
}

/// `params![a, b]` for [`Sql`]: each argument becomes a [`Value`].
macro_rules! params {
    ($($param:expr),* $(,)?) => {
        &[$($crate::relay::sql::Value::from($param)),*][..]
    };
}
pub(crate) use params;

/// A value read from a row, by the type the caller asks for.
pub trait FromValue: Sized {
    fn from_value(value: &Value) -> Option<Self>;
}

impl FromValue for i64 {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Integer(n) => Some(*n),
            _ => None,
        }
    }
}

impl FromValue for u64 {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Integer(n) => u64::try_from(*n).ok(),
            _ => None,
        }
    }
}

impl FromValue for bool {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Integer(n) => Some(*n != 0),
            _ => None,
        }
    }
}

impl FromValue for f64 {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Real(n) => Some(*n),
            Value::Integer(n) => Some(*n as f64),
            _ => None,
        }
    }
}

impl FromValue for String {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        }
    }
}

impl FromValue for Vec<u8> {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Blob(bytes) => Some(bytes.clone()),
            _ => None,
        }
    }
}

impl<T: FromValue> FromValue for Option<T> {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Null => Some(None),
            other => T::from_value(other).map(Some),
        }
    }
}

/// One result row.
#[derive(Debug)]
pub struct Row {
    values: Vec<Value>,
}

impl Row {
    pub fn new(values: Vec<Value>) -> Self {
        Self { values }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Column `index` as `T`. A missing column, or one of another type, is an
    /// error naming the column and the expected type, never the value.
    pub fn get<T: FromValue>(&self, index: usize) -> Result<T> {
        let value = self
            .values
            .get(index)
            .ok_or_else(|| Error::Store(format!("sql: no column {index}")))?;
        T::from_value(value).ok_or_else(|| {
            Error::Store(format!(
                "sql: column {index} is not a {}",
                std::any::type_name::<T>()
            ))
        })
    }
}

/// A SQLite executor. One value is one connection (or one Durable Object's
/// storage), so it is used from one writer at a time by its owner.
pub trait Sql {
    /// Runs one statement and returns the rows it changed.
    fn execute(&self, sql: &str, params: &[Value]) -> Result<usize>;

    /// Runs several `;`-separated statements that take no parameters.
    fn execute_batch(&self, sql: &str) -> Result<()>;

    /// Runs a query and hands each row to `each` as it is read; the query
    /// stops early when `each` returns `Ok(false)`. Rows are not collected
    /// first, so a caller that stops early reads only what it keeps plus one.
    fn query_each(
        &self,
        sql: &str,
        params: &[Value],
        each: &mut dyn FnMut(&Row) -> Result<bool>,
    ) -> Result<()>;

    /// The rowid of the last successful insert on this executor.
    fn last_insert_rowid(&self) -> i64;

    /// The rows the last statement changed.
    fn changes(&self) -> u64;

    /// Runs `f` as one atomic write: committed when it returns `Ok`, rolled
    /// back when it returns `Err`. A call made while a transaction is already
    /// open just runs `f` inside it (the outer one decides).
    fn transaction(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()>;
}

impl dyn Sql + '_ {
    /// The first row of a query, mapped by `map`; no row is
    /// `rusqlite::Error::QueryReturnedNoRows`, as `Connection::query_row` was.
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[Value],
        map: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        self.query_opt(sql, params, map)?
            .ok_or(Error::Db(rusqlite::Error::QueryReturnedNoRows))
    }

    /// The first row of a query, mapped by `map`, or `None` when there is none.
    pub fn query_opt<T>(
        &self,
        sql: &str,
        params: &[Value],
        map: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<Option<T>> {
        let mut map = Some(map);
        let mut found = None;
        self.query_each(sql, params, &mut |row| {
            let map = map.take().expect("query_opt reads one row");
            found = Some(map(row)?);
            Ok(false)
        })?;
        Ok(found)
    }

    /// Every row of a query, mapped by `map`, in order. For a result that is
    /// small by construction; a page of sealed letters streams through
    /// [`Sql::query_each`] instead.
    pub fn query_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        mut map: impl FnMut(&Row) -> Result<T>,
    ) -> Result<Vec<T>> {
        let mut out = Vec::new();
        self.query_each(sql, params, &mut |row| {
            out.push(map(row)?);
            Ok(true)
        })?;
        Ok(out)
    }

    /// [`Sql::transaction`] returning a value.
    pub fn with_transaction<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut f = Some(f);
        let mut out = None;
        self.transaction(&mut || {
            let f = f.take().expect("a transaction body runs once");
            out = Some(f()?);
            Ok(())
        })?;
        Ok(out.expect("a committed transaction produced its value"))
    }
}

impl rusqlite::types::ToSql for Value {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::{ToSqlOutput, ValueRef};
        Ok(ToSqlOutput::Borrowed(match self {
            Value::Null => ValueRef::Null,
            Value::Integer(n) => ValueRef::Integer(*n),
            Value::Real(n) => ValueRef::Real(*n),
            Value::Text(text) => ValueRef::Text(text.as_bytes()),
            Value::Blob(bytes) => ValueRef::Blob(bytes),
        }))
    }
}

fn read_row(row: &rusqlite::Row<'_>) -> Result<Row> {
    use rusqlite::types::ValueRef;
    let columns = row.as_ref().column_count();
    let mut values = Vec::with_capacity(columns);
    for index in 0..columns {
        values.push(match row.get_ref(index)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(n) => Value::Integer(n),
            ValueRef::Real(n) => Value::Real(n),
            ValueRef::Text(bytes) => Value::Text(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| Error::Store(format!("sql: column {index} is not UTF-8")))?,
            ),
            ValueRef::Blob(bytes) => Value::Blob(bytes.to_vec()),
        });
    }
    Ok(Row::new(values))
}

impl Sql for rusqlite::Connection {
    fn execute(&self, sql: &str, params: &[Value]) -> Result<usize> {
        Ok(rusqlite::Connection::execute(
            self,
            sql,
            rusqlite::params_from_iter(params),
        )?)
    }

    fn execute_batch(&self, sql: &str) -> Result<()> {
        Ok(rusqlite::Connection::execute_batch(self, sql)?)
    }

    fn query_each(
        &self,
        sql: &str,
        params: &[Value],
        each: &mut dyn FnMut(&Row) -> Result<bool>,
    ) -> Result<()> {
        let mut statement = self.prepare(sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            if !each(&read_row(row)?)? {
                break;
            }
        }
        Ok(())
    }

    fn last_insert_rowid(&self) -> i64 {
        rusqlite::Connection::last_insert_rowid(self)
    }

    fn changes(&self) -> u64 {
        rusqlite::Connection::changes(self)
    }

    fn transaction(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        crate::db::with_immediate_transaction(self, f)
    }
}

#[cfg(test)]
#[path = "sql/tests.rs"]
mod tests;
