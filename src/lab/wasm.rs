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

    /// Lock a note as a password-protected file using the password (and
    /// optional PIN) the person typed, instead of a seeded demo secret.
    pub fn lock_password_file(
        &mut self,
        name: &str,
        contents: &str,
        password: &str,
        pin: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self
            .state
            .lock_password_file(name, contents, password, pin.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Open a password-locked file with the password (and PIN, if it was
    /// set with one) the person typed.
    pub fn unlock_password_file(
        &mut self,
        id: i32,
        password: &str,
        pin: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self
            .state
            .unlock_password_file(i64::from(id), password, pin.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Provision a new device slot on an inserted drive with a passphrase
    /// the person chose.
    pub fn provision_slot(
        &mut self,
        drive_id: &str,
        label: &str,
        passphrase: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.provision_slot(drive_id, label, passphrase);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum-device list` for an inserted drive, shown like an opened file.
    pub fn device_log(&mut self, drive_id: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.device_log(drive_id);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Ban a node's hardware key from any future tree and drop its
    /// existing bindings and bridge pairings.
    pub fn revoke_key(&mut self, node_label: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.revoke_key(node_label);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Copy an active identity to a second drive, leaving the source
    /// active, using the passphrase that already unlocks its slot.
    pub fn transfer_copy(
        &mut self,
        label: &str,
        to_drive_id: &str,
        passphrase: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.transfer_copy(label, to_drive_id, passphrase);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Export a password-locked file as a portable `KQXB` bundle sealed to
    /// another lab user's public key, using the file's own lock password.
    pub fn export_file(
        &mut self,
        id: i32,
        recipient_label: &str,
        password: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self
            .state
            .export_file(i64::from(id), recipient_label, password);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// View a bundle's sealed bytes as hex; only its own exporter can.
    pub fn view_export(&mut self, id: i32) -> std::result::Result<String, JsError> {
        let outcome = self.state.view_export(i64::from(id));
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Create a time-limited share link for one of the active user's own
    /// password-locked files; the bearer token is returned once.
    pub fn create_file_share(
        &mut self,
        file_id: i32,
        ttl_seconds: i32,
        pin: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.create_file_share(
            i64::from(file_id),
            i64::from(ttl_seconds),
            pin.as_deref(),
        );
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Redeem a file share's bearer token. Not identity-scoped: any lab
    /// user may redeem a token they were given.
    pub fn redeem_file_share(
        &mut self,
        share_id: i32,
        token: &str,
        pin: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self
            .state
            .redeem_file_share(i64::from(share_id), token, pin.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Revoke a share link the active user created.
    pub fn revoke_file_share(&mut self, share_id: i32) -> std::result::Result<String, JsError> {
        let outcome = self.state.revoke_file_share(i64::from(share_id));
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Sign a public or received file's plaintext with the active user's
    /// personal cross-department bridge signing key.
    pub fn sign_file(&mut self, file_id: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.sign_file(file_id);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Verify a signature against its private bridge's roster. Either
    /// bridge member may verify the other's signature.
    pub fn verify_signature(&mut self, signature_id: i32) -> std::result::Result<String, JsError> {
        let outcome = self.state.verify_signature(i64::from(signature_id));
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Register a provisioned slot's keys and insert it as a new leaf
    /// under an existing org-tree node.
    pub fn register_leaf(
        &mut self,
        drive_id: &str,
        slot_label: &str,
        parent_label: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.register_leaf(drive_id, slot_label, parent_label);
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
