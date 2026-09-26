//! KeyQuorum Lab: a mock-hardware demonstration environment that runs the
//! crate's own logic in a browser.
//!
//! Everything a visitor does goes through [`LabState`], which holds a real
//! organization store (`db::open_in_memory`, the same schema), real
//! `device` containers on mock USB drives ([`drives`]), and the crate's
//! relay mailbox ([`relay`]). The lab adds seed data and a view layer;
//! quorum, custody, visibility, approval, and envelope rules are the
//! crate's. Mock drives do not provide the physical property real hardware
//! does: their slot passphrases are published demo values.
//!
//! The `lab` feature must never ship provider code. See the build guard
//! in `lib.rs`.

pub mod drives;
pub mod relay;
pub mod seed;
mod state;
pub mod terminal;
pub mod view;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use state::{LabState, Outcome};
pub use view::{ActionResult, Snapshot};

impl LabState {
    /// Attach the current snapshot to an outcome.
    pub fn result(
        &self,
        outcome: Outcome,
        output: Vec<String>,
    ) -> crate::error::Result<ActionResult> {
        Ok(ActionResult {
            ok: outcome.ok,
            message: outcome.message,
            trace: outcome.trace,
            opened: outcome.opened,
            output,
            snapshot: self.snapshot()?,
        })
    }
}

#[cfg(test)]
mod tests;
