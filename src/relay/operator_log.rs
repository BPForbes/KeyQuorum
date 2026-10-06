//! Who did what in the provider's console, and which changes have been done.
//!
//! The key lifecycle itself is in the hash-chained `api_key_events`, whose
//! actor is `host` for anyone holding the operator lock (a customer can read
//! the events about their own key, so no operator identity is put there). This
//! adds the identity Cloudflare Access verified for the person who acted, and
//! the attempts the lock refused.
//!
//! A change that went through is recorded with the operation id the console
//! sent, **in the same unit of work as the change** ([`Note::record_done`]).
//! That is the console's recovery contract: if a response is lost, sending the
//! same operation id again finds the record ([`find_operation`]) and is told
//! the change is done, with the ids it produced, and never makes it twice. The
//! sealed files themselves are not retained, so a lost download is replaced by
//! replacing the key, not by repeating the issue.
//!
//! It never holds a lock, a bearer, a hash or sealed bytes, and is not
//! hash-chained; Cloudflare's Access log is the authority for identity.
//!
//! This module owns the `operator_actions` table.

use super::sql::{params, Row, Sql};
use crate::error::{Error, Result};

/// The longest operator identity (an email address), in characters.
pub const MAX_OPERATOR_CHARS: usize = 320;

/// One recorded action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorAction {
    pub id: i64,
    pub operator: String,
    pub action: String,
    pub subject: Option<String>,
    pub success: bool,
    pub occurred_at: String,
    pub operation_id: Option<String>,
    /// What the change produced, as ids only (JSON text).
    pub result: Option<String>,
}

/// Who is doing what, for a change that is to be recorded with it.
pub struct Note<'a> {
    pub operation_id: Option<&'a str>,
    pub operator: &'a str,
    pub action: &'a str,
    pub subject: &'a str,
}

/// An operation id the console may send: 8 to 64 of `A-Z a-z 0-9 _ -`.
pub fn valid_operation_id(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn clip(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn row_to_action(row: &Row) -> Result<OperatorAction> {
    Ok(OperatorAction {
        id: row.get(0)?,
        operator: row.get(1)?,
        action: row.get(2)?,
        subject: row.get(3)?,
        success: row.get(4)?,
        occurred_at: row.get(5)?,
        operation_id: row.get(6)?,
        result: row.get(7)?,
    })
}

const SELECT: &str =
    "SELECT id, operator, action, subject, success, occurred_at, operation_id, result
 FROM operator_actions";

/// Records that `operator` tried `action` on `subject` (an id or a short
/// name, never a secret), and whether it went through. For an attempt that did
/// not change anything; a change is recorded by [`Note::record_done`].
pub fn record(
    conn: &dyn Sql,
    operator: &str,
    action: &str,
    subject: Option<&str>,
    success: bool,
) -> Result<()> {
    let operator = clip(operator.trim(), MAX_OPERATOR_CHARS);
    let action = clip(action, 64);
    if operator.is_empty() || action.is_empty() {
        return Err(Error::InvalidApiKeyRequest);
    }
    let subject = subject.map(|text| clip(text, 200));
    conn.execute(
        "INSERT INTO operator_actions (operator, action, subject, success)
         VALUES (?1, ?2, ?3, ?4)",
        params![operator, action, subject, success],
    )?;
    Ok(())
}

impl Note<'_> {
    /// Records that the change succeeded, with the ids it produced. Called
    /// inside the change's own transaction, so the record and the change stand
    /// or fall together.
    pub fn record_done(&self, conn: &dyn Sql, result: &str) -> Result<()> {
        let operator = clip(self.operator.trim(), MAX_OPERATOR_CHARS);
        let action = clip(self.action, 64);
        if operator.is_empty() || action.is_empty() {
            return Err(Error::InvalidApiKeyRequest);
        }
        if self.operation_id.is_some_and(|id| !valid_operation_id(id)) || result.len() > 1000 {
            return Err(Error::InvalidApiKeyRequest);
        }
        conn.execute(
            "INSERT INTO operator_actions
                (operator, action, subject, success, operation_id, result)
             VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            params![
                operator,
                action,
                clip(self.subject, 200),
                self.operation_id,
                result
            ],
        )?;
        Ok(())
    }
}

/// The change recorded under `operation_id`, if it was made.
pub fn find_operation(conn: &dyn Sql, operation_id: &str) -> Result<Option<OperatorAction>> {
    conn.query_opt(
        &format!("{SELECT} WHERE operation_id = ?1"),
        params![operation_id],
        row_to_action,
    )
}

/// The newest `limit` actions (1 to 500), newest first, older than `before`
/// when that cursor is given.
pub fn recent(conn: &dyn Sql, limit: i64, before: Option<i64>) -> Result<Vec<OperatorAction>> {
    conn.query_map(
        &format!("{SELECT} WHERE (?2 IS NULL OR id < ?2) ORDER BY id DESC LIMIT ?1"),
        params![limit.clamp(1, 500), before],
        row_to_action,
    )
}

#[cfg(test)]
#[path = "operator_log/tests.rs"]
mod tests;
