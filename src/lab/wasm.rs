//! The browser facade. A deliberate, small surface: each method runs one
//! lab action and returns one JSON [`ActionResult`] (outcome, trace, and a
//! full snapshot), so the UI makes one call per click rather than one per
//! rendered value. Nothing else in the crate is exported to JavaScript.

use super::state::{LabState, Outcome};
use super::terminal;
use super::view::ActionResult;
use crate::error::Result;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct KeyQuorumLab {
    state: LabState,
}

fn to_js(result: Result<ActionResult>) -> std::result::Result<String, JsError> {
    let result = result.map_err(|err| JsError::new(&err.to_string()))?;
    serde_json::to_string(&result).map_err(|err| JsError::new(&err.to_string()))
}

#[wasm_bindgen]
impl KeyQuorumLab {
    /// Seed a fresh lab. Takes about as long as provisioning seven
    /// Argon2id slot tokens.
    #[wasm_bindgen(constructor)]
    pub fn new() -> std::result::Result<KeyQuorumLab, JsError> {
        let state = LabState::seed().map_err(|err| JsError::new(&err.to_string()))?;
        Ok(Self { state })
    }

    pub fn snapshot(&self) -> std::result::Result<String, JsError> {
        to_js(self.state.result(
            Outcome {
                ok: true,
                message: String::new(),
                trace: vec![],
                opened: None,
            },
            vec![],
        ))
    }

    pub fn reset(&mut self) -> std::result::Result<String, JsError> {
        self.state = LabState::seed().map_err(|err| JsError::new(&err.to_string()))?;
        to_js(self.state.result(
            Outcome {
                ok: true,
                message: "Lab reset to its seeded state".into(),
                trace: vec![],
                opened: None,
            },
            vec![],
        ))
    }

    pub fn switch_user(&mut self, id: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.switch_user(id);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn insert_drive(&mut self, id: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.set_drive(id, true);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn eject_drive(&mut self, id: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.set_drive(id, false);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Move a slot's token to a different drive (`device::relocate_slot_in`
    /// plus a `device_placements` re-bind). Both drives must be inserted.
    pub fn move_slot(
        &mut self,
        label: &str,
        to_drive_id: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.move_slot(label, to_drive_id);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn inspect_file(&self, id: &str) -> std::result::Result<String, JsError> {
        let view = self
            .state
            .inspect(id)
            .map_err(|err| JsError::new(&err.to_string()))?;
        serde_json::to_string(&view).map_err(|err| JsError::new(&err.to_string()))
    }

    pub fn unlock_file(&mut self, id: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.unlock(id);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn send_file(
        &mut self,
        file_id: &str,
        recipient_id: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.send(file_id, recipient_id);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn receive(&mut self, relay_id: i32) -> std::result::Result<String, JsError> {
        let outcome = self.state.receive(i64::from(relay_id), true);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn reject(&mut self, relay_id: i32) -> std::result::Result<String, JsError> {
        let outcome = self.state.receive(i64::from(relay_id), false);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn refresh_inbox(&mut self) -> std::result::Result<String, JsError> {
        let outcome = self.state.refresh_inbox();
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    pub fn answer_approval(
        &mut self,
        id: u32,
        approve: bool,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.answer_approval(u64::from(id), approve);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// One terminal line against the same state the GUI uses.
    pub fn run_command(&mut self, line: &str) -> std::result::Result<String, JsError> {
        if line.trim() == "reset" {
            return self.reset();
        }
        let ran = terminal::run(&mut self.state, line);
        to_js(ran.and_then(|(outcome, output)| self.state.result(outcome, output)))
    }
}
