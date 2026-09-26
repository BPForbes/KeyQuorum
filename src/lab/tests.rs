use super::terminal;
use super::view::{Snapshot, StepStatus};
use super::LabState;

fn lab() -> LabState {
    LabState::seed().expect("lab should seed")
}

fn snap(state: &LabState) -> Snapshot {
    state.snapshot().expect("snapshot")
}

fn connected(state: &LabState) -> Vec<String> {
    let mut ids: Vec<String> = snap(state)
        .drives
        .into_iter()
        .filter(|drive| drive.connected)
        .map(|drive| drive.id)
        .collect();
    ids.sort();
    ids
}

fn failed(outcome: &super::Outcome) -> Vec<String> {
    outcome
        .trace
        .iter()
        .filter(|step| step.status == StepStatus::Fail)
        .map(|step| step.text.clone())
        .collect()
}

fn file<'a>(snapshot: &'a Snapshot, id: &str) -> &'a super::view::FileView {
    snapshot
        .files
        .iter()
        .find(|file| file.id == id)
        .unwrap_or_else(|| panic!("no seeded file {id}"))
}

#[test]
fn lab_seeds_the_same_structure_every_time() {
    let first = snap(&lab());
    let second = snap(&lab());
    for snapshot in [&first, &second] {
        assert_eq!(snapshot.active_user.id, "alice");
        assert_eq!(snapshot.active_user.label, "M.S.1");
        let labels: Vec<&str> = snapshot.users.iter().map(|u| u.label.as_str()).collect();
        assert_eq!(
            labels,
            ["M", "M.S", "M.S.1", "M.S.2", "M.A", "M.A.1", "M.A.2"]
        );
        assert_eq!(snapshot.files.len(), 18, "expected 18 seeded files");
        let tree: Vec<&str> = snapshot
            .tree
            .nodes
            .iter()
            .map(|n| n.label.as_str())
            .collect();
        assert_eq!(
            tree,
            ["M", "M.S", "M.S.1", "M.S.2", "M.A", "M.A.1", "M.A.2"]
        );
        assert_eq!(snapshot.tree.bridges, [("M.S".into(), "M.A".into())]);
        assert!(snapshot.inbox.is_empty() && snapshot.sent.is_empty());
    }
    let mut first_connected: Vec<&str> = first
        .drives
        .iter()
        .filter(|drive| drive.connected)
        .map(|drive| drive.id.as_str())
        .collect();
    first_connected.sort();
    assert_eq!(first_connected, ["alice", "sarah"]);
    // One drive per person plus a spare: eight drives, eight distinct ids.
    let ids: std::collections::HashSet<&str> = first.drives.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(
        ids,
        std::collections::HashSet::from([
            "morgan", "sarah", "alice", "bob", "david", "emma", "chris", "spare"
        ])
    );
}

#[test]
fn each_person_has_their_own_drive_by_default() {
    let snapshot = snap(&lab());
    for (person_label, drive_id) in [
        ("M", "morgan"),
        ("M.S", "sarah"),
        ("M.S.1", "alice"),
        ("M.S.2", "bob"),
        ("M.A", "david"),
        ("M.A.1", "emma"),
        ("M.A.2", "chris"),
    ] {
        let drive = snapshot
            .drives
            .iter()
            .find(|drive| drive.id == drive_id)
            .unwrap();
        assert_eq!(
            drive
                .slots
                .iter()
                .map(|slot| slot.label.as_str())
                .collect::<Vec<_>>(),
            [person_label],
            "{drive_id} should carry only {person_label} at seed time"
        );
    }
    let spare = snapshot.drives.iter().find(|d| d.id == "spare").unwrap();
    assert!(spare.slots.is_empty());
    assert!(!spare.connected);
}

#[test]
fn each_drive_is_a_signed_container_with_one_token_per_slot() {
    let state = lab();
    let alice = snap(&state)
        .drives
        .into_iter()
        .find(|drive| drive.id == "alice")
        .unwrap();
    assert!(alice.connected);
    assert!(alice.files.contains(&"device.kq".to_string()));
    assert!(alice.files.contains(&"device.skey".to_string()));
    assert!(alice
        .files
        .contains(&"vault/slot-M.S.1/token.kqst".to_string()));
}

#[test]
fn switching_user_changes_identity_and_visible_slice() {
    let mut state = lab();
    let alice = snap(&state);
    let visible = |s: &Snapshot| -> Vec<String> {
        s.users
            .iter()
            .filter(|u| u.visible)
            .map(|u| u.label.clone())
            .collect()
    };
    // Lineage + sibling + the M.S <-> M.A bridge, not David's reports.
    assert_eq!(visible(&alice), ["M", "M.S", "M.S.1", "M.S.2", "M.A"]);

    assert!(state.switch_user("david").unwrap().ok);
    let david = snap(&state);
    assert_eq!(david.active_user.label, "M.A");
    assert_eq!(visible(&david), ["M", "M.S", "M.A", "M.A.1", "M.A.2"]);
    assert!(state.switch_user("M").unwrap().ok);
    assert_eq!(snap(&state).active_user.name, "Morgan");
    assert!(!state.switch_user("nobody").unwrap().ok);
}

#[test]
fn inserting_and_ejecting_changes_the_connected_device_set() {
    let mut state = lab();
    assert_eq!(connected(&state), ["alice", "sarah"]);
    assert!(state.set_drive("bob", true).unwrap().ok);
    assert_eq!(connected(&state), ["alice", "bob", "sarah"]);
    assert!(state.set_drive("sarah", false).unwrap().ok);
    assert_eq!(connected(&state), ["alice", "bob"]);
    let ejected = snap(&state)
        .drives
        .into_iter()
        .find(|d| d.id == "sarah")
        .unwrap();
    assert!(ejected.files.is_empty(), "an ejected drive shows no files");
}

#[test]
fn ejecting_your_drive_removes_your_shares() {
    let mut state = lab();
    assert!(state.unlock("architecture.md").unwrap().ok);
    state.set_drive("alice", false).unwrap();
    let denied = state.unlock("architecture.md").unwrap();
    assert!(!denied.ok);
    assert!(failed(&denied)
        .iter()
        .any(|line| line.contains("Alice's USB, which is not inserted")));
}

#[test]
fn cross_department_quorum_changes_when_a_second_device_arrives() {
    let mut state = lab();
    let denied = state.unlock("acquisition-plan.txt").unwrap();
    assert!(!denied.ok, "only Sarah's drive (M.S) is present");
    assert!(failed(&denied)
        .iter()
        .any(|line| line.starts_with("Quorum not satisfied")));
    let last = snap(&state).last_access.unwrap();
    assert_eq!(last.required, ["M", "M.S", "M.A"]);
    assert_eq!(last.satisfied, ["M.S"]);

    state.set_drive("david", true).unwrap();
    let granted = state.unlock("acquisition-plan.txt").unwrap();
    assert!(granted.ok, "{:?}", granted.trace);
    assert!(granted
        .trace
        .iter()
        .any(|step| step.text.starts_with("Physical devices: 2 (minimum 2)")));
    assert!(granted.opened.unwrap().text.contains("Acquisition plan"));
}

#[test]
fn logical_custody_lets_two_slots_on_one_drive_meet_the_threshold() {
    let mut state = lab();
    // With one drive per person, meeting a 2-of-3 engineering threshold
    // normally means two physical devices. Move Bob's slot onto Alice's
    // drive first so one physical device genuinely carries two slots.
    state.set_drive("bob", true).unwrap();
    assert!(state.move_slot("M.S.2", "alice").unwrap().ok);
    // Sarah's own M.S share would otherwise let the search satisfy the
    // threshold with two devices (hers plus Alice's) before ever trying
    // Alice's two slots alone, since minimum_physical_devices is 1 either
    // way. Eject both other drives so Alice's is the only route left.
    state.set_drive("bob", false).unwrap();
    state.set_drive("sarah", false).unwrap();
    let outcome = state.unlock("deployment-plan.txt").unwrap();
    assert!(outcome.ok, "{:?}", outcome.trace);
    assert!(outcome
        .trace
        .iter()
        .any(|step| step.text.starts_with("Physical devices: 1 (minimum 1)")));
}

#[test]
fn moving_a_slot_creates_a_real_multi_user_drive() {
    let mut state = lab();
    state.set_drive("bob", true).unwrap();
    let moved = state.move_slot("M.S.2", "alice").unwrap();
    assert!(moved.ok, "{:?}", moved.trace);
    state.set_drive("bob", false).unwrap();

    let snapshot = snap(&state);
    let alice_drive = snapshot.drives.iter().find(|d| d.id == "alice").unwrap();
    let mut labels: Vec<&str> = alice_drive
        .slots
        .iter()
        .map(|slot| slot.label.as_str())
        .collect();
    labels.sort();
    assert_eq!(labels, ["M.S.1", "M.S.2"]);
    let bob_drive = snapshot.drives.iter().find(|d| d.id == "bob").unwrap();
    assert!(bob_drive.slots.is_empty());

    // Bob's own (now-empty) drive is irrelevant to his access now — his
    // slot lives on Alice's drive, which is already inserted.
    state.switch_user("bob").unwrap();
    let granted = state.unlock("architecture.md").unwrap();
    assert!(granted.ok, "{:?}", granted.trace);

    // Ejecting Alice's drive (not Bob's own, now-empty one) is what
    // removes Bob's access, proving the placement really moved.
    state.set_drive("alice", false).unwrap();
    let denied = state.unlock("architecture.md").unwrap();
    assert!(!denied.ok, "Bob's slot is on Alice's ejected drive now");
}

#[test]
fn moving_requires_both_drives_inserted() {
    let mut state = lab();
    state.set_drive("alice", false).unwrap();
    let denied = state.move_slot("M.S.1", "spare").unwrap();
    assert!(!denied.ok);
    assert!(failed(&denied)
        .iter()
        .any(|line| line.contains("Alice's USB (currently holding M.S.1) is not inserted")));

    state.set_drive("alice", true).unwrap();
    let denied = state.move_slot("M.S.1", "spare").unwrap();
    assert!(!denied.ok);
    assert!(failed(&denied)
        .iter()
        .any(|line| line.contains("Spare USB is not inserted")));

    state.set_drive("spare", true).unwrap();
    assert!(state.move_slot("M.S.1", "spare").unwrap().ok);
}

#[test]
fn authorization_follows_the_active_user() {
    let mut state = lab();
    let payroll = state.unlock("payroll.csv").unwrap();
    assert!(!payroll.ok);
    assert!(failed(&payroll)[0].contains("holds no share"));
    let access = |state: &LabState, name: &str| file(&snap(state), name).access.clone();
    assert_eq!(access(&state, "payroll"), "none");
    assert_eq!(access(&state, "architecture"), "holder");

    state.switch_user("emma").unwrap();
    // payroll.csv needs 2 of 3 accounting slots; with one drive per
    // person, that now genuinely takes two physical devices.
    state.set_drive("emma", true).unwrap();
    state.set_drive("chris", true).unwrap();
    assert_eq!(access(&state, "payroll"), "holder");
    let unlocked = state.unlock("payroll.csv").unwrap();
    assert!(unlocked.ok, "{:?}", unlocked.trace);
    assert!(!state.unlock("architecture.md").unwrap().ok);

    state.switch_user("morgan").unwrap();
    assert_eq!(access(&state, "payroll"), "oversight");
}

#[test]
fn parent_approval_is_requested_signed_and_then_accepted() {
    let mut state = lab();
    let first = state.unlock("prod-credentials.txt").unwrap();
    assert!(!first.ok);
    assert!(failed(&first)
        .iter()
        .any(|line| line.starts_with("Parent approval from Sarah (M.S) missing")));
    let request = snap(&state).approvals[0].clone();
    assert_eq!(request.status, "pending");
    assert!(!request.actionable, "Alice cannot approve her own unlock");
    assert!(!state.answer_approval(request.id, true).unwrap().ok);

    state.switch_user("sarah").unwrap();
    let approvals = snap(&state).approvals;
    assert!(approvals[0].actionable);
    assert!(state.answer_approval(request.id, true).unwrap().ok);

    state.switch_user("alice").unwrap();
    let granted = state.unlock("prod-credentials.txt").unwrap();
    assert!(granted.ok, "{:?}", granted.trace);
    assert!(granted
        .trace
        .iter()
        .any(|step| step.text.starts_with("Parent approval: Sarah (M.S) signed")));
}

#[test]
fn send_receive_and_acknowledge_through_the_relay() {
    let mut state = lab();
    let sent = state.send("architecture.md", "david").unwrap();
    assert!(sent.ok, "{:?}", sent.trace);
    let alice = snap(&state);
    assert_eq!(alice.sent.len(), 1);
    assert_eq!(alice.sent[0].status, "delivered");
    let relay_id = alice.sent[0].relay_id;

    state.switch_user("david").unwrap();
    let inbox = snap(&state).inbox;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].relay_id, relay_id);
    assert_eq!(inbox[0].status, "new");
    assert!(
        inbox[0].from.is_none(),
        "the sender stays sealed until opened"
    );

    let locked_out = state.receive(relay_id, true).unwrap();
    assert!(!locked_out.ok, "David's drive is not inserted by default");

    state.set_drive("david", true).unwrap();
    let received = state.receive(relay_id, true).unwrap();
    assert!(received.ok, "{:?}", received.trace);
    let david = snap(&state);
    assert_eq!(david.inbox[0].status, "received");
    assert_eq!(david.inbox[0].from.as_deref(), Some("Alice (M.S.1)"));
    let copy = david
        .files
        .iter()
        .find(|f| f.protection == "received")
        .expect("received copy");
    assert_eq!(copy.access, "holder");
    assert!(state.unlock(&copy.id).unwrap().ok);

    state.switch_user("alice").unwrap();
    assert_eq!(snap(&state).pending_acks, 1);
    assert!(state.refresh_inbox().unwrap().ok);
    let alice = snap(&state);
    assert_eq!(alice.sent[0].status, "acknowledged");
    assert_eq!(alice.pending_acks, 0);
    assert!(
        !alice.files.iter().any(|f| f.protection == "received"),
        "David's copy is not Alice's"
    );
}

#[test]
fn rejection_is_reported_back_to_the_sender() {
    let mut state = lab();
    state.send("project-roadmap.md", "bob").unwrap();
    let relay_id = snap(&state).sent[0].relay_id;
    state.switch_user("bob").unwrap();
    state.set_drive("bob", true).unwrap();
    assert!(state.receive(relay_id, false).unwrap().ok);
    assert_eq!(snap(&state).inbox[0].status, "rejected");
    state.switch_user("alice").unwrap();
    state.refresh_inbox().unwrap();
    assert_eq!(snap(&state).sent[0].status, "rejected");
}

#[test]
fn sending_outside_the_visible_slice_is_refused() {
    let mut state = lab();
    let refused = state.send("project-roadmap.md", "emma").unwrap();
    assert!(!refused.ok);
    assert!(failed(&refused)[0].contains("outside your visible slice"));
    assert!(snap(&state).sent.is_empty());
}

#[test]
fn you_cannot_send_a_file_you_cannot_open() {
    let mut state = lab();
    let refused = state.send("acquisition-plan.txt", "sarah").unwrap();
    assert!(!refused.ok);
    assert!(snap(&state).sent.is_empty());
}

// ----- date properties: expiry -----------------------------------------

#[test]
fn an_already_expired_file_is_shown_as_expired_before_any_unlock_attempt() {
    let state = lab();
    let snapshot = snap(&state);
    assert!(file(&snapshot, "api-keys-rotation").expired);
    assert!(file(&snapshot, "vendor-contract-acme").expired);
    assert!(file(&snapshot, "succession-plan").expired);
    // Not yet expired: their offsets are in the future relative to seed time.
    assert!(!file(&snapshot, "sprint-notes").expired);
    assert!(!file(&snapshot, "audit-checklist").expired);
    // A file that never expires has no cutoff at all.
    assert!(file(&snapshot, "architecture").expires_at.is_none());
    assert!(!file(&snapshot, "architecture").expired);
}

#[test]
fn unlocking_an_already_expired_file_is_denied_and_destroys_it_for_good() {
    let mut state = lab();
    // Alice holds M.S.1, one of api-keys-rotation.log's leaves, and her
    // drive is inserted — this would otherwise succeed.
    let denied = state.unlock("api-keys-rotation.log").unwrap();
    assert!(!denied.ok);
    assert!(failed(&denied)
        .iter()
        .any(|line| line.contains("expired") && line.contains("removed")));
    // A second attempt reports the same thing rather than a raw DB error,
    // even though the underlying `files` row is now gone.
    let again = state.unlock("api-keys-rotation.log").unwrap();
    assert!(!again.ok);
    assert!(failed(&again).iter().any(|line| line.contains("expired")));
    // Still listed (as expired), not silently dropped from the Explorer.
    assert!(file(&snap(&state), "api-keys-rotation").expired);
}

#[test]
fn an_expired_manager_only_file_is_denied_even_for_its_only_holder() {
    let mut state = lab();
    state.switch_user("morgan").unwrap();
    state.set_drive("morgan", true).unwrap();
    let denied = state.unlock("succession-plan.txt").unwrap();
    assert!(!denied.ok, "{:?}", denied.trace);
    assert!(failed(&denied).iter().any(|line| line.contains("expired")));
}

// ----- ghosts ------------------------------------------------------------

#[test]
fn a_ghosts_share_was_evicted_and_the_survivors_must_both_be_present() {
    let mut state = lab();
    let snapshot = snap(&state);
    let requirement = file(&snapshot, "legacy-migration-notes")
        .requirement
        .clone()
        .expect("quorum requirement");
    let ghost = requirement
        .children
        .iter()
        .find(|child| child.label == "Priya")
        .expect("Priya's evicted leaf stays in the tree");
    assert!(ghost.ghost);
    // Her registry label is the same string as her tree-node label, so
    // `holder` stays empty rather than repeating "Priya" redundantly.
    assert_eq!(ghost.holder, None);
    let alice_leaf = requirement
        .children
        .iter()
        .find(|child| child.label == "M.S.1")
        .unwrap();
    assert!(!alice_leaf.ghost);

    // Only Alice present: originally 2 of 3 would have been enough with
    // Priya, but her share is gone, so this alone is not enough.
    let denied = state.unlock("legacy-migration-notes.txt").unwrap();
    assert!(!denied.ok, "{:?}", denied.trace);
    assert!(failed(&denied)
        .iter()
        .any(|line| line.starts_with("Quorum not satisfied")));

    state.set_drive("bob", true).unwrap();
    let granted = state.unlock("legacy-migration-notes.txt").unwrap();
    assert!(granted.ok, "{:?}", granted.trace);
}

#[test]
fn a_ghost_never_appears_as_a_switchable_user() {
    let state = lab();
    assert!(state.user_names().iter().all(|(name, ..)| name != "Priya"));
}

#[test]
fn terminal_and_gui_share_one_state() {
    let mut state = lab();
    let (outcome, output) = terminal::run(&mut state, "usb insert david").unwrap();
    assert!(outcome.ok);
    assert!(output[0].contains("David's USB inserted"));
    assert_eq!(connected(&state), ["alice", "david", "sarah"]);
    let (_, output) = terminal::run(&mut state, "su david").unwrap();
    assert!(output[0].contains("David"));
    assert_eq!(snap(&state).active_user.id, "david");
    let (outcome, _) = terminal::run(&mut state, "unlock q3-budget.csv").unwrap();
    assert!(outcome.ok);
    assert_eq!(
        snap(&state).activity[0].title,
        "Access granted: q3-budget.csv"
    );
    let (outcome, _) = terminal::run(&mut state, "move M.A.1 spare").unwrap();
    assert!(!outcome.ok, "M.A.1 (Emma) is not David's slot to move, but move has no such ownership check — this just checks the command parses and runs against real state");
    let (outcome, _) = terminal::run(&mut state, "frobnicate").unwrap();
    assert!(!outcome.ok);
}

#[test]
fn reset_restores_the_seeded_state() {
    let mut state = lab();
    state.set_drive("david", true).unwrap();
    state.switch_user("david").unwrap();
    state.send("q3-budget.csv", "sarah").unwrap();
    state.move_slot("M.S.2", "spare").unwrap();
    state = lab();
    let fresh = snap(&state);
    assert_eq!(fresh.active_user.id, "alice");
    assert_eq!(connected(&state), ["alice", "sarah"]);
    assert!(fresh.sent.is_empty() && fresh.inbox.is_empty() && fresh.approvals.is_empty());
    assert_eq!(fresh.activity.len(), 1);
    let bob_drive = fresh.drives.iter().find(|d| d.id == "bob").unwrap();
    assert_eq!(
        bob_drive
            .slots
            .iter()
            .map(|s| s.label.as_str())
            .collect::<Vec<_>>(),
        ["M.S.2"]
    );
}

#[test]
fn unlock_records_a_real_audit_row() {
    let mut state = lab();
    let (_, output) = terminal::run(&mut state, "unlock architecture.md").unwrap();
    assert!(output.iter().any(|line| line.contains("AES-256-GCM")));
    let command = snap(&state).activity[0].command.clone().unwrap();
    assert!(command.starts_with("keyquorum access quorum --state 1 --id "));
    assert!(command.contains("--slot /media/alice-usb=M.S.1"));
}
