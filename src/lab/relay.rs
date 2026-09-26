//! The lab's mailbox relay. [`MemoryLabRelay`] is the crate's own relay
//! store — `relay::store` and `relay::list_after` over the relay schema —
//! on an in-memory SQLite database, so the browser exercises the same
//! opaque-envelope rules (routing on the recipient key only, device
//! letters refused) a hosted relay applies.
//!
//! A cross-browser relay would implement [`LabRelay`] over explicit
//! push/pull batches fetched outside the WASM call, so the lab domain code
//! does not change and no request is made per render.

use crate::error::Result;
use crate::relay::{self, StoredEnvelope};
use rusqlite::Connection;

pub trait LabRelay {
    /// Store one sealed envelope. Returns the mailbox id.
    fn push(&mut self, envelope: &[u8]) -> Result<i64>;
    /// Every envelope routed to `fingerprint`, oldest first.
    fn pull(&self, fingerprint: &str) -> Result<Vec<StoredEnvelope>>;
}

pub struct MemoryLabRelay {
    conn: Connection,
}

impl MemoryLabRelay {
    pub fn new() -> Result<Self> {
        Ok(Self {
            conn: relay::open_in_memory()?,
        })
    }
}

impl LabRelay for MemoryLabRelay {
    fn push(&mut self, envelope: &[u8]) -> Result<i64> {
        let (id, _, _) = relay::store(&self.conn, envelope)?;
        Ok(id)
    }

    fn pull(&self, fingerprint: &str) -> Result<Vec<StoredEnvelope>> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = relay::list_after(&self.conn, fingerprint, after, None)?;
            out.extend(page.envelopes);
            match page.next_after {
                Some(next) => after = Some(next),
                None => return Ok(out),
            }
        }
    }
}
