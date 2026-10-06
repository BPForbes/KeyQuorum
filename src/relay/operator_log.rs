//! Who did what in the provider's console.
//!
//! The key lifecycle itself is in the hash-chained `api_key_events`, whose
//! actor is `host` for anyone holding the operator lock (a customer can read
//! the events about their own key, so no operator identity is put there). This
//! adds the identity Cloudflare Access verified for the person who acted, and
//! the attempts the lock refused. It never holds a lock, a bearer, a hash or
//! sealed bytes, and is not hash-chained; Cloudflare's Access log is the
//! authority for identity.
//!
//! This module owns the `operator_actions` table.

use super::sql::{params, Sql};
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
}

fn clip(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Records that `operator` tried `action` on `subject` (an id or a short
/// name, never a secret), and whether it went through.
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

/// The newest `limit` actions (1 to 500), newest first.
pub fn recent(conn: &dyn Sql, limit: i64) -> Result<Vec<OperatorAction>> {
    conn.query_map(
        "SELECT id, operator, action, subject, success, occurred_at
         FROM operator_actions ORDER BY id DESC LIMIT ?1",
        params![limit.clamp(1, 500)],
        |row| {
            Ok(OperatorAction {
                id: row.get(0)?,
                operator: row.get(1)?,
                action: row.get(2)?,
                subject: row.get(3)?,
                success: row.get(4)?,
                occurred_at: row.get(5)?,
            })
        },
    )
}

#[cfg(test)]
#[path = "operator_log/tests.rs"]
mod tests;
