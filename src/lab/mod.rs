//! KeyQuorum Lab: a mock-hardware demonstration environment that runs the
//! crate's own logic in a browser.
//!
//! The lab is a small sandboxed machine ([`vm`]): an in-memory filesystem,
//! mock USB drives mounted under `/media` ([`drives`]), one SQLite store
//! per path, and the crate's relay service answering in process. Every
//! action — a GUI button or a terminal line — runs real `keyquorum` /
//! `keyquorum-device` command lines ([`crate::cli`]) in that machine, so
//! quorum, custody, visibility, approval, bridge, and delivery rules are
//! the CLI's own. [`LabState`] adds what a desktop adds (who is signed in,
//! which drives are plugged in) plus seed data and read-only views. Mock
//! drives do not provide the physical property real hardware does: their
//! slot passphrases are published demo values.
//!
//! The `lab` feature must never ship provider code. See the build guard
//! in `lib.rs`.

pub mod drives;
pub mod seed;
mod state;
pub mod terminal;
pub mod view;
pub mod vm;
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
