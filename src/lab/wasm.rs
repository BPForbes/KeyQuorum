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

    /// Reissue a node's hardware key onto a freshly provisioned replacement
    /// token, authorized by the lab's one org-update authority label.
    pub fn reissue_key(
        &mut self,
        node_label: &str,
        to_drive_id: &str,
        passphrase: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.reissue_key(node_label, to_drive_id, passphrase);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Propose republishing the org tree at its next public generation.
    /// Not the root, so this only records a pending proposal.
    pub fn propose_restructure(&mut self) -> std::result::Result<String, JsError> {
        let outcome = self.state.propose_restructure();
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// Countersign every pending restructure proposal addressed to the
    /// active user, using their own device slot passphrase.
    pub fn countersign_restructure(
        &mut self,
        passphrase: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.countersign_restructure(passphrase);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file track`: start tracking a new file as the active person.
    pub fn history_track(
        &mut self,
        name: &str,
        text: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_track(name, text);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file checkin`, signed with the active person's slot or not.
    pub fn history_checkin(
        &mut self,
        path: &str,
        text: &str,
        signed: bool,
        label: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self
            .state
            .history_checkin(path, text, signed, label.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file sign` for a revision (the sole head when `None`).
    pub fn history_sign(
        &mut self,
        path: &str,
        revision: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_sign(path, revision.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file countersign` for a revision (the sole head when `None`).
    pub fn history_countersign(
        &mut self,
        path: &str,
        revision: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_countersign(path, revision.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file merge`: join a forked history's two heads.
    pub fn history_merge(
        &mut self,
        path: &str,
        label: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_merge(path, label.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file verify`, shown like an opened file.
    pub fn history_verify(&mut self, path: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_verify(path);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file review`, shown like an opened file.
    pub fn history_review(&mut self, path: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_review(path);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file expire`: schedule (`at`, UTC `yyyy-mm-ddThh:mm`) or,
    /// with no time, destroy the content now.
    pub fn history_expire(
        &mut self,
        path: &str,
        at: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_expire(path, at.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file diff` between two revisions (defaults: head and its parent).
    pub fn history_diff(
        &mut self,
        path: &str,
        from: Option<String>,
        to: Option<String>,
    ) -> std::result::Result<String, JsError> {
        let outcome = self
            .state
            .history_diff(path, from.as_deref(), to.as_deref());
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file checkout` of one revision, shown like an opened file.
    pub fn history_view_revision(
        &mut self,
        path: &str,
        revision: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_view_revision(path, revision);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file history --export`: write a verifiable history snapshot.
    pub fn history_export(&mut self, path: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_export(path);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file verify-snapshot --against` the tracked file.
    pub fn history_verify_snapshot(
        &mut self,
        path: &str,
        snapshot: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_verify_snapshot(path, snapshot);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file import`: bring another followed copy into this one.
    pub fn history_import(
        &mut self,
        path: &str,
        from: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_import(path, from);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file link|unlink` a quorum (`gate = "quorum"`) or password
    /// (`gate = "password"`) file.
    pub fn history_link(
        &mut self,
        path: &str,
        gate: &str,
        id: i32,
        link: bool,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_link(path, gate, i64::from(id), link);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file share`: seal the newest trusted revision to another person.
    pub fn history_share(
        &mut self,
        path: &str,
        to_user: &str,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_share(path, to_user);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file receive` of a letter, accepting or refusing it.
    pub fn history_receive(
        &mut self,
        letter_id: i32,
        accept: bool,
    ) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_receive(i64::from(letter_id), accept);
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// `keyquorum file ack`: record a letter's answer in the sender's copy.
    pub fn history_ack(&mut self, letter_id: i32) -> std::result::Result<String, JsError> {
        let outcome = self.state.history_ack(i64::from(letter_id));
        to_js(outcome.and_then(|outcome| self.state.result(outcome, vec![])))
    }

    /// One terminal line against the same state the GUI uses.
    pub fn run_command(&mut self, line: &str) -> std::result::Result<String, JsError> {
        if line.trim() == "reset" {
            return self.reset();
        }
        let ran = terminal::run(&mut self.state, line);
        to_js(ran.and_then(|(outcome, output)| {
            self.state.note_action(
                "terminal",
                "Ran a Terminal command",
                outcome.ok,
                Some(line.to_string()),
            );
            self.state.result(outcome, output)
        }))
    }

    /// Record a meaningful browser interaction which has no CLI operation.
    pub fn note_ui(&mut self, kind: &str, title: &str) -> std::result::Result<String, JsError> {
        let outcome = self.state.note_ui(kind, title);
        to_js(self.state.result(outcome, vec![]))
    }
}
