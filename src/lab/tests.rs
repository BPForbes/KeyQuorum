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

/// The whole transcript of an outcome, one string, for loose matching of
/// what the CLI printed.
fn said(outcome: &super::Outcome) -> String {
    outcome
        .trace
        .iter()
        .map(|step| step.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
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
    state.set_drive("sarah", false).unwrap();
    let denied = state.unlock("architecture.md").unwrap();
    assert!(!denied.ok, "{}", said(&denied));
    assert!(!failed(&denied).is_empty());
}

#[test]
fn cross_department_quorum_changes_when_a_second_device_arrives() {
    let mut state = lab();
    let denied = state.unlock("acquisition-plan.txt").unwrap();
    assert!(!denied.ok, "only Sarah's drive (M.S) is present");
    let last = snap(&state).last_access.unwrap();
    assert_eq!(last.required, ["M", "M.S", "M.A"]);
    assert_eq!(last.satisfied, ["M.S"]);

    state.set_drive("david", true).unwrap();
    let granted = state.unlock("acquisition-plan.txt").unwrap();
    assert!(granted.ok, "{}", said(&granted));
    assert!(said(&granted).contains("Physical devices: 2 (minimum 2)"));
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
    assert!(outcome.ok, "{}", said(&outcome));
    assert!(said(&outcome).contains("Physical devices: 1 (minimum 1)"));
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
    // removes Bob's access, proving the placement really moved. Sarah's
    // M.S share alone would meet this 1-of-3 file, so hers goes too.
    state.set_drive("alice", false).unwrap();
    state.set_drive("sarah", false).unwrap();
    let denied = state.unlock("architecture.md").unwrap();
    assert!(!denied.ok, "Bob's slot is on Alice's ejected drive now");
}

#[test]
fn moving_requires_both_drives_inserted() {
    let mut state = lab();
    state.set_drive("alice", false).unwrap();
    let denied = state.move_slot("M.S.1", "spare").unwrap();
    assert!(!denied.ok, "{}", said(&denied));

    state.set_drive("alice", true).unwrap();
    let denied = state.move_slot("M.S.1", "spare").unwrap();
    assert!(!denied.ok, "{}", said(&denied));

    state.set_drive("spare", true).unwrap();
    let moved = state.move_slot("M.S.1", "spare").unwrap();
    assert!(moved.ok, "{}", said(&moved));
    assert!(said(&moved).contains(
        "keyquorum-device relocate --from /media/alice-usb --to /media/spare-usb --label M.S.1"
    ));
}

#[test]
fn authorization_follows_the_active_user() {
    let mut state = lab();
    let payroll = state.unlock("payroll.csv").unwrap();
    assert!(!payroll.ok, "{}", said(&payroll));
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
    // Whoever is at the keyboard, a file opens when inserted drives carry
    // enough of its shares — there is no separate lab check. With the
    // engineering drives out, Emma's accounting slots cannot open it.
    state.set_drive("alice", false).unwrap();
    state.set_drive("sarah", false).unwrap();
    assert!(!state.unlock("architecture.md").unwrap().ok);

    state.switch_user("morgan").unwrap();
    assert_eq!(access(&state, "payroll"), "oversight");
}

#[test]
fn parent_approval_needs_the_parents_drive_to_sign() {
    let mut state = lab();
    state.set_drive("sarah", false).unwrap();
    let first = state.unlock("prod-credentials.txt").unwrap();
    assert!(!first.ok, "{}", said(&first));
    assert!(!said(&first).contains("--approve"));

    // Sarah plugs her drive in: the unlock line carries her signature.
    state.set_drive("sarah", true).unwrap();
    let granted = state.unlock("prod-credentials.txt").unwrap();
    assert!(granted.ok, "{}", said(&granted));
    let transcript = said(&granted);
    assert!(transcript.contains("--approve M.S.1=/media/sarah-usb>M.S"));
    assert!(transcript.contains("Parent approval: M.S signed for M.S.1"));
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
    assert_eq!(locked_out.message, "Insert your USB to open the letter");

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

    // Alice's drive is inserted, so signing in checks the acknowledgement.
    let back = state.switch_user("alice").unwrap();
    assert!(said(&back).contains("accepted by M.A"), "{}", said(&back));
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
fn a_letter_needs_the_senders_slot() {
    let mut state = lab();
    state.set_drive("alice", false).unwrap();
    let refused = state.send("project-roadmap.md", "emma").unwrap();
    assert!(!refused.ok, "{}", said(&refused));
    assert!(snap(&state).sent.is_empty());
}

#[test]
fn you_cannot_send_a_file_you_cannot_open() {
    let mut state = lab();
    let refused = state.send("acquisition-plan.txt", "sarah").unwrap();
    assert!(!refused.ok);
    assert!(snap(&state).sent.is_empty());
}

#[test]
fn receiving_pulls_first_and_shows_both_commands() {
    let mut state = lab();
    state.send("architecture.md", "david").unwrap();
    let relay_id = snap(&state).sent[0].relay_id;
    state.switch_user("david").unwrap();
    state.set_drive("david", true).unwrap();
    assert!(state.receive(relay_id, true).unwrap().ok);
    let command = snap(&state).activity[0].command.clone().unwrap();
    assert!(command.contains("inbox list --dir"), "{command}");
    assert!(
        command.contains(&format!("inbox open {relay_id}")),
        "{command}"
    );
}

#[test]
fn an_acknowledgement_is_collected_when_the_senders_drive_comes_back() {
    let mut state = lab();
    state.send("architecture.md", "david").unwrap();
    let relay_id = snap(&state).sent[0].relay_id;
    state.switch_user("david").unwrap();
    state.set_drive("david", true).unwrap();
    assert!(state.receive(relay_id, true).unwrap().ok);

    // Alice returns without her drive: the answer waits, sealed to her key.
    state.set_drive("alice", false).unwrap();
    state.switch_user("alice").unwrap();
    let waiting = snap(&state);
    assert_eq!(waiting.sent[0].status, "delivered");
    assert_eq!(waiting.pending_acks, 1);

    // Plugging her drive in opens it; there is no refresh to click.
    state.set_drive("alice", true).unwrap();
    let done = snap(&state);
    assert_eq!(done.sent[0].status, "acknowledged");
    assert_eq!(done.pending_acks, 0);
}

#[test]
fn the_terminal_opens_a_letter_by_id_or_every_new_one() {
    let mut state = lab();
    state.send("architecture.md", "david").unwrap();
    state.send("project-roadmap.md", "david").unwrap();
    state.switch_user("david").unwrap();
    state.set_drive("david", true).unwrap();
    let (outcome, _) = terminal::run(&mut state, "inbox open 999").unwrap();
    assert!(!outcome.ok);
    let (outcome, _) = terminal::run(&mut state, "inbox open").unwrap();
    assert!(outcome.ok);
    let inbox = snap(&state).inbox;
    assert_eq!(inbox.len(), 2);
    assert!(
        inbox.iter().all(|item| item.status == "received"),
        "{inbox:?}"
    );
    let (_, output) = terminal::run(&mut state, "doctor").unwrap();
    assert!(!output.is_empty(), "doctor answers in the lab terminal");
}

#[test]
fn a_tracked_answer_is_recorded_when_the_sender_returns() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "a\n"));
    ok(state.history_share(NOTES, "alice"));
    state.switch_user("alice").unwrap();
    let letter = snap(&state).tracked_letters[0].id;
    ok(state.history_receive(letter, true));
    assert!(!snap(&state).tracked_letters[0].ack_recorded);

    // Signing back in as Sarah (her drive is in) records Alice's answer with
    // the real `file ack`, and the button's own action then has nothing to do.
    let back = state.switch_user("sarah").unwrap();
    assert!(
        snap(&state).tracked_letters[0].ack_recorded,
        "{}",
        said(&back)
    );
    let again = state.history_ack(letter).unwrap();
    assert!(again.ok);
    assert_eq!(again.message, "That answer is already recorded");
}

#[test]
fn a_tracked_request_answer_is_recorded_when_the_requester_returns() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "a\n"));
    ok(state.history_share(NOTES, "alice"));
    state.switch_user("alice").unwrap();
    let letter = snap(&state).tracked_letters[0].id;
    ok(state.history_receive(letter, true));
    state.switch_user("sarah").unwrap();
    ok(state.history_request(NOTES, "alice", true, "tighten the intro"));
    let request = snap(&state).tracked_requests[0].id;
    state.switch_user("alice").unwrap();
    ok(state.history_answer_request(request, true));
    assert!(!snap(&state).tracked_requests[0].answer_recorded);
    state.switch_user("sarah").unwrap();
    assert!(snap(&state).tracked_requests[0].answer_recorded);
}

#[test]
fn create_and_register_leaf_provisions_with_a_typed_passphrase_and_registers() {
    let mut state = lab();
    state.set_drive("bob", true).unwrap();
    state.set_drive("spare", true).unwrap();
    let outcome = state
        .create_and_register_leaf("spare", "M.S.3", "M.S", "my own passphrase")
        .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let text = said(&outcome);
    assert!(
        text.contains("keyquorum-device provision") || text.contains("slot M.S.3"),
        "{text}"
    );
    let tree = snap(&state).tree;
    assert!(tree.nodes.iter().any(|node| node.label == "M.S.3"));

    // A refused provision (empty passphrase) registers nothing.
    let mut state = lab();
    state.set_drive("spare", true).unwrap();
    let refused = state
        .create_and_register_leaf("spare", "M.S.3", "M.S", "")
        .unwrap();
    assert!(!refused.ok);
    assert!(!snap(&state)
        .tree
        .nodes
        .iter()
        .any(|node| node.label == "M.S.3"));
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
    assert!(
        failed(&denied).iter().any(|line| line.contains("expired")),
        "{}",
        said(&denied)
    );
    // A second attempt still fails: the ciphertext and its row are gone.
    let again = state.unlock("api-keys-rotation.log").unwrap();
    assert!(!again.ok);
    // Still listed (as expired), not silently dropped from the Explorer.
    assert!(file(&snap(&state), "api-keys-rotation").expired);
}

#[test]
fn an_expired_manager_only_file_is_denied_even_for_its_only_holder() {
    let mut state = lab();
    state.switch_user("morgan").unwrap();
    state.set_drive("morgan", true).unwrap();
    let denied = state.unlock("succession-plan.txt").unwrap();
    assert!(!denied.ok, "{}", said(&denied));
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
    state.set_drive("sarah", false).unwrap();
    let denied = state.unlock("legacy-migration-notes.txt").unwrap();
    assert!(!denied.ok, "{}", said(&denied));

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
    assert!(
        !outcome.ok,
        "neither Emma's drive nor the spare is inserted"
    );
    let (outcome, output) = terminal::run(&mut state, "frobnicate").unwrap();
    assert!(!outcome.ok);
    assert_eq!(output, ["frobnicate: command not found. Type `help`."]);
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
    assert!(fresh.sent.is_empty() && fresh.inbox.is_empty());
    // The newest entry is the seed itself; the tracked files' history sits
    // beneath it, and nothing else has happened yet.
    assert_eq!(fresh.activity[0].title, "Lab seeded");
    assert!(fresh.activity[1..]
        .iter()
        .all(|entry| entry.kind == "history"));
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
    let (outcome, _) = terminal::run(&mut state, "unlock architecture.md").unwrap();
    assert!(outcome.ok);
    let command = snap(&state).activity[0].command.clone().unwrap();
    assert!(command
        .starts_with("keyquorum --db /srv/keyquorum/org.sqlite access quorum --state 1 --id "));
    assert!(command.contains("--slot /media/alice-usb=M.S.1"));
}

/// Run one terminal line; bridge commands take the CLI's own syntax.
fn term(state: &mut LabState, line: &str) -> (super::Outcome, Vec<String>) {
    let key_id = snap(state).tree.key_id.to_string();
    terminal::run(state, &line.replace("$KEY", &key_id)).unwrap()
}

#[test]
fn bridge_commands_run_the_cli_code_and_print_its_output() {
    let mut state = lab();
    let (outcome, output) = term(&mut state, "bridge list $KEY");
    assert!(outcome.ok);
    assert_eq!(
        output,
        [
            "Allowed:",
            "  M.A -> M.S",
            "  M.S -> M.A",
            "Established:",
            "  M.S <-> M.A"
        ]
    );
    // The full CLI line works too, as it would be typed in a shell.
    let (outcome, output) = term(
        &mut state,
        "keyquorum --db /srv/keyquorum/org.sqlite bridge allow $KEY --node M.S.2 --peer M.A.2",
    );
    assert!(outcome.ok);
    assert_eq!(output[0], "Allowed M.S.2 to bridge to M.A.2");
    let activity = snap(&state).activity;
    assert_eq!(activity[0].kind, "command");
    assert!(activity[0]
        .command
        .as_deref()
        .unwrap()
        .starts_with("keyquorum --db /srv/keyquorum/org.sqlite bridge allow "));
}

#[test]
fn a_link_needs_a_whitelist_entry_first() {
    let mut state = lab();
    let (refused, _) = term(&mut state, "bridge add $KEY --from M.S.1 --to M.A.1");
    assert!(!refused.ok);
    assert_eq!(
        refused.message,
        "error: cross-branch link is not whitelisted by either node"
    );
    assert_eq!(snap(&state).tree.bridges, [("M.S".into(), "M.A".into())]);

    // Either side's whitelist authorizes the link, whichever end adds it.
    assert!(
        term(&mut state, "bridge allow $KEY --node M.A.1 --peer M.S.1")
            .0
            .ok
    );
    assert!(snap(&state)
        .tree
        .allowed
        .contains(&("M.A.1".into(), "M.S.1".into())));
    let (added, _) = term(&mut state, "bridge add $KEY --from M.S.1 --to M.A.1");
    assert!(added.ok);
    assert_eq!(added.message, "Established bridge M.S.1 <-> M.A.1");
    assert!(snap(&state)
        .tree
        .bridges
        .contains(&("M.S.1".into(), "M.A.1".into())));
}

#[test]
fn a_new_link_widens_the_visible_slice() {
    let mut state = lab();
    term(&mut state, "bridge allow $KEY --node M.S.1 --peer M.A.1");
    let (added, _) = term(&mut state, "bridge add $KEY --from M.S.1 --to M.A.1");
    assert!(added.ok);
    let texts: Vec<&str> = added.trace.iter().map(|step| step.text.as_str()).collect();
    assert!(texts.contains(&"Alice (M.S.1) now sees M.A.1"));
    assert!(texts.contains(&"Emma (M.A.1) now sees M.S.1"));
}

#[test]
fn removing_a_link_keeps_the_whitelist_but_deny_clears_both() {
    let mut state = lab();
    let (removed, _) = term(&mut state, "bridge remove $KEY --from M.A --to M.S");
    assert!(removed.ok);
    assert!(snap(&state).tree.bridges.is_empty());
    assert!(removed
        .trace
        .iter()
        .any(|step| step.text == "Alice (M.S.1) no longer sees M.A"));

    // The seeded whitelist survived, so the link can come straight back.
    assert!(term(&mut state, "bridge add $KEY --from M.S --to M.A").0.ok);

    assert!(
        term(&mut state, "bridge deny $KEY --node M.S --peer M.A")
            .0
            .ok
    );
    let tree = snap(&state).tree;
    assert!(tree.bridges.is_empty() && tree.allowed.is_empty());
    assert!(!term(&mut state, "bridge add $KEY --from M.S --to M.A").0.ok);
}

#[test]
fn bridge_parse_errors_and_help_come_from_clap() {
    let mut state = lab();
    let (outcome, output) = term(&mut state, "keyquorum bridge --help");
    assert!(outcome.ok);
    assert!(output.iter().any(|line| line.contains("allow")));
    // `add` without --to fails in clap's parser, before any state is touched.
    let (outcome, output) = term(&mut state, "bridge add $KEY --from M.S.1");
    assert!(!outcome.ok);
    assert!(output.iter().any(|line| line.contains("--to")));
    let (unknown, _) = term(&mut state, "bridge allow $KEY --node M.S.1 --peer M.Z");
    assert_eq!(
        unknown.message,
        "error: no node with that label or id exists in this key"
    );
}

#[test]
fn the_terminal_is_a_shell_on_the_lab_machine() {
    let mut state = lab();
    let (_, output) = terminal::run(&mut state, "pwd").unwrap();
    assert_eq!(output, ["/home/alice"]);
    let (_, output) = terminal::run(&mut state, "ls /media/alice-usb").unwrap();
    assert!(
        output.iter().any(|entry| entry.ends_with("device.kq")),
        "{output:?}"
    );
    let (outcome, output) =
        terminal::run(&mut state, "keyquorum-device list /media/alice-usb").unwrap();
    assert!(outcome.ok, "{output:?}");
    assert!(
        output.iter().any(|line| line.contains("M.S.1")),
        "{output:?}"
    );
    // Bob's drive is not plugged in, so it is not there to read.
    let (outcome, _) = terminal::run(&mut state, "keyquorum-device list /media/bob-usb").unwrap();
    assert!(!outcome.ok);
    let (_, output) = terminal::run(&mut state, "cd /srv/keyquorum").unwrap();
    assert_eq!(output, ["/srv/keyquorum"]);
    assert_eq!(snap(&state).cwd, "/srv/keyquorum");
    let (_, output) = terminal::run(&mut state, "cd").unwrap();
    assert_eq!(output, ["/home/alice"]);
}

#[test]
fn an_unknown_recipient_is_a_usage_error_from_the_cli() {
    let mut state = lab();
    let (outcome, output) = terminal::run(
        &mut state,
        "keyquorum send /srv/keyquorum/public/company-handbook.txt --to M.Z --as M.S.1 --slot /media/alice-usb=M.S.1",
    )
    .unwrap();
    assert!(!outcome.ok);
    assert!(
        output
            .iter()
            .any(|line| line.contains("no encryption key is registered for M.Z")),
        "{output:?}"
    );
}

// ----- custom secrets (password-locked files, device provisioning) --------

#[test]
fn a_password_locked_file_is_protected_by_the_typed_password_not_a_demo_value() {
    let mut state = lab();
    let outcome = state
        .lock_password_file("my-note.txt", "top secret plan", "hunter2", None)
        .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let files = snap(&state).password_files;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "my-note.txt");
    assert_eq!(files[0].owner, "M.S.1");
    assert!(!files[0].pin_protected);
    let id = files[0].id;

    // The seeded demo password does not open it: the typed password is the
    // only one that unwraps this file, not `DEMO_PASSWORD`.
    let denied = state
        .unlock_password_file(id, "lab-demo-password", None)
        .unwrap();
    assert!(!denied.ok);
    assert!(denied.opened.is_none());

    let granted = state.unlock_password_file(id, "hunter2", None).unwrap();
    assert!(granted.ok, "{}", said(&granted));
    assert_eq!(
        granted.opened.map(|opened| opened.text),
        Some("top secret plan".to_string())
    );
}

#[test]
fn a_password_locked_file_with_a_custom_pin_needs_both_the_pin_and_the_password() {
    let mut state = lab();
    let outcome = state
        .lock_password_file("pinned.txt", "guarded", "correct-password", Some("7392"))
        .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let id = snap(&state).password_files[0].id;

    let wrong_pin = state
        .unlock_password_file(id, "correct-password", Some("0000"))
        .unwrap();
    assert!(!wrong_pin.ok);

    let right = state
        .unlock_password_file(id, "correct-password", Some("7392"))
        .unwrap();
    assert!(right.ok, "{}", said(&right));
}

#[test]
fn only_the_owner_can_unlock_their_own_password_file() {
    let mut state = lab();
    state
        .lock_password_file("mine.txt", "alice's secret", "alice-password", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;
    state.switch_user("bob").unwrap();
    let outcome = state
        .unlock_password_file(id, "alice-password", None)
        .unwrap();
    assert!(!outcome.ok);
}

// ----- issue #36: password-file ids are scoped to the owning store --------

#[test]
fn a_row_id_collision_across_stores_does_not_deny_the_real_owner() {
    // Fixes #36: each lab user has their own SQLite store, so Alice's and
    // Bob's first password-locked file are both row id 1 there. Looking a
    // file up by id alone used to resolve to whichever tracking entry was
    // inserted first (Alice's), so Bob's own unlock/export/share of *his*
    // file 1 was denied as belonging to Alice.
    let mut state = lab();
    state
        .lock_password_file("alice-note.txt", "alice's secret", "alice-password", None)
        .unwrap();
    let alice_id = snap(&state).password_files[0].id;

    state.switch_user("bob").unwrap();
    state
        .lock_password_file("bob-note.txt", "bob's secret", "bob-password", None)
        .unwrap();
    let bob_id = snap(&state)
        .password_files
        .iter()
        .find(|file| file.owner == "M.S.2")
        .expect("bob's file should be tracked")
        .id;
    assert_eq!(
        alice_id, bob_id,
        "both stores should hand out the same first row id, or this test proves nothing"
    );

    // Bob can unlock, export, and share his own file 1...
    let unlocked = state
        .unlock_password_file(bob_id, "bob-password", None)
        .unwrap();
    assert!(unlocked.ok, "{}", said(&unlocked));
    let exported = state.export_file(bob_id, "M.S.1", "bob-password").unwrap();
    assert!(exported.ok, "{}", said(&exported));
    let shared = state.create_file_share(bob_id, 3600, None).unwrap();
    assert!(shared.ok, "{}", said(&shared));

    // Bob's own file 1 was never Alice's data — his unlock/export/share
    // above ran entirely against his own store. To prove genuine cross-
    // owner access is still denied (not just masked by the id collision
    // above, where "alice_id" only ever resolved to Bob's own matching
    // row), give Alice a *second* file whose id cannot collide with
    // anything Bob owns, and confirm Bob can't reach it by id at all.
    state.switch_user("alice").unwrap();
    state
        .lock_password_file(
            "alice-second.txt",
            "alice's other secret",
            "alice-second-password",
            None,
        )
        .unwrap();
    let alice_second_id = snap(&state)
        .password_files
        .iter()
        .find(|file| file.owner == "M.S.1" && file.name == "alice-second.txt")
        .expect("alice's second file should be tracked")
        .id;
    assert_ne!(
        alice_second_id, bob_id,
        "a non-colliding id is the whole point of this half of the test"
    );
    let alice_unlock = state
        .unlock_password_file(alice_second_id, "alice-second-password", None)
        .unwrap();
    assert!(alice_unlock.ok, "{}", said(&alice_unlock));

    state.switch_user("bob").unwrap();
    let cross_owner_unlock = state
        .unlock_password_file(alice_second_id, "alice-second-password", None)
        .unwrap();
    assert!(!cross_owner_unlock.ok);
    let cross_owner_export = state
        .export_file(alice_second_id, "M.S.1", "alice-second-password")
        .unwrap();
    assert!(!cross_owner_export.ok);
    let cross_owner_share = state
        .create_file_share(alice_second_id, 3600, None)
        .unwrap();
    assert!(!cross_owner_share.ok);
}

#[test]
fn provisioning_a_new_slot_uses_the_typed_passphrase_not_the_seeded_demo_one() {
    let mut state = lab();
    let outcome = state
        .provision_slot("alice", "M.S.1.spare", "my-own-passphrase")
        .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    // The new slot's public keys show up in a device log for that drive.
    let log = state.device_log("alice").unwrap();
    assert!(log.ok);
    let text = log.opened.map(|opened| opened.text).unwrap_or_default();
    assert!(text.contains("M.S.1.spare"), "{text}");
}

#[test]
fn provisioning_on_an_ejected_drive_is_refused() {
    let mut state = lab();
    state.set_drive("alice", false).unwrap();
    let outcome = state
        .provision_slot("alice", "M.S.1.spare", "my-own-passphrase")
        .unwrap();
    assert!(!outcome.ok);
}

#[test]
fn device_log_reports_every_seeded_slot_on_that_drive() {
    let state = lab();
    let mut state = state;
    let outcome = state.device_log("alice").unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let text = outcome.opened.map(|opened| opened.text).unwrap_or_default();
    assert!(text.contains("slot M.S.1"), "{text}");
}

#[test]
fn relay_status_counts_reflect_what_the_seeded_lab_has_stored() {
    let state = lab();
    let snapshot = snap(&state);
    // Nothing has pushed a letter, published a tree, or registered a
    // device descriptor yet; the admin and per-user API keys the seed
    // issues out of band (`issue_api_key`) do show up.
    assert_eq!(snapshot.relay_status.package_letters, 0);
    assert_eq!(snapshot.relay_status.device_letters, 0);
    assert_eq!(snapshot.relay_status.published_trees, 0);
    assert_eq!(snapshot.relay_status.registered_devices, 0);
    assert!(snapshot.relay_status.api_keys > 0);
    assert_eq!(snapshot.relay_status.url, super::vm::RELAY_URL);
}

#[test]
fn revoking_a_leafs_hardware_key_bans_it_from_future_trees() {
    let mut state = lab();
    let outcome = state.revoke_key("M.S.2").unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    assert!(said(&outcome).contains("Revoked key"), "{}", said(&outcome));
}

#[test]
fn revoking_a_split_node_is_refused() {
    let mut state = lab();
    let outcome = state.revoke_key("M.S").unwrap();
    assert!(!outcome.ok);
}

#[test]
fn revoking_an_unknown_node_is_refused() {
    let mut state = lab();
    let outcome = state.revoke_key("M.Nope").unwrap();
    assert!(!outcome.ok);
}

#[test]
fn transfer_copy_leaves_the_source_active_and_writes_the_destination_slot() {
    let mut state = lab();
    state.set_drive("spare", true).unwrap();
    let outcome = state
        .transfer_copy("M.S.1", "spare", &super::seed::demo_passphrase("M.S.1"))
        .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    assert!(
        said(&outcome).contains("copied M.S.1"),
        "{}",
        said(&outcome)
    );

    // The source drive still carries M.S.1 (COPY leaves it active)...
    let source_log = state.device_log("alice").unwrap();
    assert!(source_log
        .opened
        .map(|opened| opened.text)
        .unwrap_or_default()
        .contains("slot M.S.1"));
    // ...and the destination now carries a copy of the same slot.
    let dest_log = state.device_log("spare").unwrap();
    assert!(dest_log
        .opened
        .map(|opened| opened.text)
        .unwrap_or_default()
        .contains("slot M.S.1"));
}

#[test]
fn transfer_copy_requires_the_destination_drive_inserted() {
    let mut state = lab();
    let outcome = state
        .transfer_copy("M.S.1", "spare", &super::seed::demo_passphrase("M.S.1"))
        .unwrap();
    assert!(!outcome.ok, "{}", said(&outcome));
}

#[test]
fn transfer_copy_rejects_the_wrong_passphrase() {
    let mut state = lab();
    state.set_drive("spare", true).unwrap();
    let outcome = state
        .transfer_copy("M.S.1", "spare", "not-the-real-passphrase")
        .unwrap();
    assert!(!outcome.ok);
}

#[test]
fn transfer_copy_to_the_same_drive_is_a_no_op_refusal() {
    let mut state = lab();
    let outcome = state
        .transfer_copy("M.S.1", "alice", &super::seed::demo_passphrase("M.S.1"))
        .unwrap();
    assert!(!outcome.ok);
    assert!(outcome.message.contains("already on that drive"));
}

// ----- issue #35: one lab database per path across concurrent opens -------

#[test]
fn concurrent_opens_of_the_same_lab_db_path_share_state() {
    // `LabVm::open_db` used to `remove` the path's connection from
    // `stores` and hand back a brand-new empty in-memory database when it
    // was not there (i.e. already checked out). Two opens of the same
    // path before either is closed — exactly what `keyquorum transfer
    // copy --from-db PATH --to-db PATH` does — used to see the second
    // open land on an unrelated empty database instead of the first
    // open's data.
    use super::drives::DriveBay;
    use super::vm::LabVm;
    use crate::cli::env::Env;

    let mut vm = LabVm::new(DriveBay::default()).expect("vm should start");
    let path = std::path::Path::new("/srv/keyquorum/issue-35.sqlite");

    let source_conn = vm.open_db(path).expect("first open");
    let dest_conn = vm.open_db(path).expect("second, concurrent open");
    dest_conn
        .execute_batch("CREATE TABLE IF NOT EXISTS issue_35_probe (id INTEGER PRIMARY KEY)")
        .unwrap();
    dest_conn
        .execute("INSERT INTO issue_35_probe DEFAULT VALUES", [])
        .unwrap();
    let seen_from_source: i64 = source_conn
        .query_row("SELECT COUNT(*) FROM issue_35_probe", [], |row| row.get(0))
        .expect("the source handle should see the destination handle's write");
    assert_eq!(seen_from_source, 1);

    // Hand both back in the same order `run_transfer`'s locals drop in
    // (reverse declaration order: dest, then source) and confirm the
    // write is still there afterward, not discarded by whichever
    // connection closed last.
    vm.close_db(path, dest_conn);
    vm.close_db(path, source_conn);
    let reopened = vm.open_db(path).expect("reopen after both close");
    let count: i64 = reopened
        .query_row("SELECT COUNT(*) FROM issue_35_probe", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn transfer_copy_with_the_same_from_and_to_db_path_does_not_lose_the_new_device_placement() {
    // End-to-end version of the same bug through the public API:
    // `transfer_copy` runs `keyquorum transfer copy --from-db ORG_DB
    // --to-db ORG_DB`, opening the org store twice in one command
    // (source, then destination). The old `LabVm::open_db` handed the
    // second open a brand-new empty database, which made the destination
    // side of the two-phase transfer protocol (`transfer_transactions`)
    // see no record of the source's own preparation and refuse it as a
    // replay the moment a fix made the two opens see real, shared data
    // (see the `transfer.rs` `stage_destination` same-store handling).
    // Whichever connection's `close_db` ran last then silently overwrote
    // the other's commit, discarding the actual copy either way. With
    // both fixed, the command succeeds and Bob's slot really is copied
    // onto Alice's drive, which unlocking a file naming both of them
    // still confirms afterward.
    let mut state = lab();
    state.set_drive("bob", true).unwrap();
    let copied = state
        .transfer_copy("M.S.2", "alice", &super::seed::demo_passphrase("M.S.2"))
        .unwrap();
    assert!(copied.ok, "{}", said(&copied));
    state.set_drive("bob", false).unwrap();
    state.set_drive("sarah", false).unwrap();

    // Bob's own drive is now empty of consequence to this file; both
    // shares it needs (M.S.1 and the copied M.S.2) are satisfied from
    // Alice's drive alone, proving the copy's new device_placement row
    // for M.S.2 actually landed in the shared org store.
    let outcome = state.unlock("deployment-plan.txt").unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
}

// ----- export and share links ---------------------------------------------

#[test]
fn export_file_seals_a_bundle_that_only_its_exporter_can_view() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;

    let outcome = state.export_file(id, "M.S.2", "lock-pass").unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let exports = snap(&state).exports;
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].owner, "M.S.1");
    assert_eq!(exports[0].recipient, "M.S.2");
    assert!(exports[0].size > 0);
    let export_id = exports[0].id;

    let view = state.view_export(export_id).unwrap();
    assert!(view.ok, "{}", said(&view));
    assert!(view
        .opened
        .map(|opened| !opened.text.is_empty())
        .unwrap_or(false));

    // Bob was the recipient, but the bundle lives in Alice's home
    // directory: only Alice, its exporter, can view it here.
    state.switch_user("bob").unwrap();
    let denied = state.view_export(export_id).unwrap();
    assert!(!denied.ok);
}

#[test]
fn export_file_requires_owning_the_password_locked_file() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;
    state.switch_user("bob").unwrap();
    let outcome = state.export_file(id, "M.S.2", "lock-pass").unwrap();
    assert!(!outcome.ok);
}

#[test]
fn export_file_rejects_the_wrong_password() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;
    let outcome = state.export_file(id, "M.S.2", "not-the-password").unwrap();
    assert!(!outcome.ok);
    assert!(snap(&state).exports.is_empty());
}

#[test]
fn create_file_share_returns_a_token_once_and_only_the_owner_may_create_it() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;

    state.switch_user("bob").unwrap();
    let denied = state.create_file_share(id, 3600, None).unwrap();
    assert!(!denied.ok);

    state.switch_user("alice").unwrap();
    let outcome = state.create_file_share(id, 3600, None).unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let token_text = outcome.opened.map(|opened| opened.text).unwrap_or_default();
    assert!(token_text.contains("Token:"), "{token_text}");
    let shares = snap(&state).file_shares;
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].owner, "M.S.1");
    assert!(!shares[0].pin_protected);
    assert!(!shares[0].revoked);
}

#[test]
fn redeem_file_share_consumes_a_use_and_is_not_identity_scoped() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;
    let created = state.create_file_share(id, 3600, None).unwrap();
    let token = created
        .opened
        .unwrap()
        .text
        .lines()
        .find_map(|line| line.strip_prefix("Token: "))
        .unwrap()
        .to_string();
    let share_id = snap(&state).file_shares[0].id;

    // Bob never held Alice's share, but the bearer token alone authorizes
    // redeeming it — the CLI does not check who is asking.
    state.switch_user("bob").unwrap();
    let outcome = state.redeem_file_share(share_id, &token, None).unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
}

#[test]
fn redeeming_with_the_wrong_token_is_refused() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;
    state.create_file_share(id, 3600, None).unwrap();
    let share_id = snap(&state).file_shares[0].id;
    let outcome = state
        .redeem_file_share(share_id, "not-the-real-token", None)
        .unwrap();
    assert!(!outcome.ok);
}

#[test]
fn revoke_file_share_prevents_further_redemption() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;
    let created = state.create_file_share(id, 3600, None).unwrap();
    let token = created
        .opened
        .unwrap()
        .text
        .lines()
        .find_map(|line| line.strip_prefix("Token: "))
        .unwrap()
        .to_string();
    let share_id = snap(&state).file_shares[0].id;

    let revoke = state.revoke_file_share(share_id).unwrap();
    assert!(revoke.ok, "{}", said(&revoke));
    assert!(snap(&state).file_shares[0].revoked);

    let outcome = state.redeem_file_share(share_id, &token, None).unwrap();
    assert!(!outcome.ok);
}

#[test]
fn only_the_owner_can_revoke_their_share() {
    let mut state = lab();
    state
        .lock_password_file("plan.txt", "confidential plan", "lock-pass", None)
        .unwrap();
    let id = snap(&state).password_files[0].id;
    state.create_file_share(id, 3600, None).unwrap();
    let share_id = snap(&state).file_shares[0].id;

    state.switch_user("bob").unwrap();
    let outcome = state.revoke_file_share(share_id).unwrap();
    assert!(!outcome.ok);
}

// ----- sign / verify --------------------------------------------------------

#[test]
fn sarah_signs_a_public_file_and_david_verifies_it() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    let outcome = state.sign_file("company-handbook").unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let signatures = snap(&state).signatures;
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].signer, "M.S");
    assert!(signatures[0].size > 0);
    let signature_id = signatures[0].id;

    // David is on the same private bridge and can verify Sarah's
    // signature even though he holds no sealed copy of its secret.
    state.switch_user("david").unwrap();
    let verified = state.verify_signature(signature_id).unwrap();
    assert!(verified.ok, "{}", said(&verified));
    assert!(verified.message.contains("is valid"));
}

#[test]
fn davids_own_signing_attempt_fails_without_a_sealed_bridge_key() {
    let mut state = lab();
    state.switch_user("david").unwrap();
    state.set_drive("david", true).unwrap();
    let outcome = state.sign_file("company-handbook").unwrap();
    // David is a full roster member (his signing and encryption public
    // keys were registered at seed time) but this shared org store only
    // ever holds Sarah's sealed copy of the bridge secret — the crate's
    // own "at most one store" rule for a private bridge.
    assert!(!outcome.ok);
}

#[test]
fn only_a_bridge_member_can_sign_or_verify() {
    let mut state = lab();
    let outcome = state.sign_file("company-handbook").unwrap();
    assert!(!outcome.ok, "{}", said(&outcome));
    assert!(outcome.message.contains("holds no personal signing key"));
}

#[test]
fn quorum_locked_files_cannot_be_signed_here() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    let outcome = state.sign_file("architecture").unwrap();
    assert!(!outcome.ok);
    assert!(outcome.message.contains("Only public or received files"));
}

// ----- registering a new leaf -----------------------------------------------

#[test]
fn register_leaf_succeeds_once_enough_siblings_are_present() {
    let mut state = lab();
    // M.S's threshold is 2 of {M.S.1, M.S.2}; both must be present to
    // reshare it for a new sibling. Bob's drive is ejected by default.
    state.set_drive("bob", true).unwrap();
    state.set_drive("spare", true).unwrap();
    state
        .provision_slot("spare", "M.S.3", &super::seed::demo_passphrase("M.S.3"))
        .unwrap();

    let outcome = state.register_leaf("spare", "M.S.3", "M.S").unwrap();
    assert!(outcome.ok, "{}", said(&outcome));

    let tree = snap(&state).tree;
    let leaf = tree
        .nodes
        .iter()
        .find(|node| node.label == "M.S.3")
        .expect("M.S.3 should now be in the org tree");
    assert_eq!(leaf.parent.as_deref(), Some("M.S"));
    assert_eq!(leaf.kind, "leaf");
}

#[test]
fn register_leaf_is_refused_without_enough_siblings() {
    let mut state = lab();
    // Bob's drive stays ejected: only M.S.1 can help reshare M.S, short
    // of its 2-of-2 threshold.
    state.set_drive("spare", true).unwrap();
    state
        .provision_slot("spare", "M.S.3", &super::seed::demo_passphrase("M.S.3"))
        .unwrap();

    let outcome = state.register_leaf("spare", "M.S.3", "M.S").unwrap();
    assert!(!outcome.ok, "{}", said(&outcome));
    let tree = snap(&state).tree;
    assert!(!tree.nodes.iter().any(|node| node.label == "M.S.3"));
}

#[test]
fn register_leaf_rejects_an_unprovisioned_slot() {
    let mut state = lab();
    state.set_drive("bob", true).unwrap();
    state.set_drive("spare", true).unwrap();
    let outcome = state.register_leaf("spare", "M.S.3", "M.S").unwrap();
    assert!(!outcome.ok);
    assert!(outcome.message.contains("no provisioned slot"));
}

#[test]
fn register_leaf_rejects_an_unknown_parent() {
    let mut state = lab();
    state.set_drive("spare", true).unwrap();
    state
        .provision_slot("spare", "M.S.3", &super::seed::demo_passphrase("M.S.3"))
        .unwrap();
    let outcome = state.register_leaf("spare", "M.S.3", "M.NOPE").unwrap();
    assert!(!outcome.ok);
    assert!(outcome.message.contains("No node"));
}

// ----- reissue --------------------------------------------------------------

#[test]
fn reissue_replaces_an_employees_hardware_key_when_authorized_by_their_manager() {
    let mut state = lab();
    state.set_drive("spare", true).unwrap();
    state
        .provision_slot("spare", "M.A.1", &super::seed::demo_passphrase("M.A.1"))
        .unwrap();

    let outcome = state
        .reissue_key("M.A.1", "spare", &super::seed::demo_passphrase("M.A.1"))
        .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    assert!(
        outcome.message.contains("Reissued M.A.1"),
        "{}",
        outcome.message
    );

    // The replacement token is now bound in the org store.
    let dest_log = state.device_log("spare").unwrap();
    assert!(dest_log
        .opened
        .map(|opened| opened.text)
        .unwrap_or_default()
        .contains("slot M.A.1"));

    // M.A.1 is still a live, hardware-backed leaf under M.A.
    let tree = snap(&state).tree;
    let leaf = tree
        .nodes
        .iter()
        .find(|node| node.label == "M.A.1")
        .expect("M.A.1 should still be in the org tree");
    assert_eq!(leaf.kind, "leaf");
    assert_eq!(leaf.parent.as_deref(), Some("M.A"));
}

#[test]
fn reissue_is_refused_for_a_node_outside_the_authoritys_subtree() {
    let mut state = lab();
    state.set_drive("spare", true).unwrap();
    state
        .provision_slot("spare", "M.S.1", &super::seed::demo_passphrase("M.S.1"))
        .unwrap();

    // `M.S.1` answers to `M.S`, not `M.A` — the only label in this lab
    // holding a plaintext authorizer key — so the real CLI's own
    // `is_ancestor_or_self` check refuses this before anything changes.
    let outcome = state
        .reissue_key("M.S.1", "spare", &super::seed::demo_passphrase("M.S.1"))
        .unwrap();
    assert!(!outcome.ok, "{}", said(&outcome));
}

#[test]
fn reissue_requires_the_replacement_token_provisioned_first() {
    let mut state = lab();
    state.set_drive("spare", true).unwrap();
    let outcome = state
        .reissue_key("M.A.1", "spare", &super::seed::demo_passphrase("M.A.1"))
        .unwrap();
    assert!(!outcome.ok);
    assert!(outcome.message.contains("no provisioned slot"));
}

// ----- tree restructure ------------------------------------------------------

#[test]
fn m_a_proposes_and_m_countersigns_a_restructure() {
    let mut state = lab();
    let proposed = state.propose_restructure().unwrap();
    assert!(proposed.ok, "{}", said(&proposed));

    // One proposal per active leaf under `M.A` (`M.A.1`, `M.A.2`) — `M.A`
    // herself is a split node, not a hardware-backed recipient.
    let pending = snap(&state).pending_restructures;
    assert_eq!(pending.len(), 2);
    assert!(pending
        .iter()
        .all(|proposal| proposal.authorizer_label == "M.A" && proposal.countersigner_label == "M"));

    state.switch_user("morgan").unwrap();
    state.set_drive("morgan", true).unwrap();
    let countersigned = state
        .countersign_restructure(&super::seed::demo_passphrase("M"))
        .unwrap();
    assert!(countersigned.ok, "{}", said(&countersigned));

    assert!(snap(&state).pending_restructures.is_empty());
}

#[test]
fn countersign_is_refused_for_someone_with_no_pending_proposal() {
    let mut state = lab();
    state.propose_restructure().unwrap();

    // The default active user (Alice, `M.S.1`) is not the countersigner
    // any pending proposal names.
    let outcome = state
        .countersign_restructure(&super::seed::demo_passphrase("M.S.1"))
        .unwrap();
    assert!(!outcome.ok, "{}", said(&outcome));
    assert!(outcome.message.contains("no pending restructure"));
}

#[test]
fn countersign_rejects_the_wrong_passphrase() {
    let mut state = lab();
    state.propose_restructure().unwrap();
    state.switch_user("morgan").unwrap();
    state.set_drive("morgan", true).unwrap();
    let outcome = state
        .countersign_restructure("not-the-real-passphrase")
        .unwrap();
    assert!(!outcome.ok);
    assert!(!snap(&state).pending_restructures.is_empty());
}

fn history(state: &LabState) -> Vec<crate::lab::view::ActivityView> {
    snap(state)
        .activity
        .into_iter()
        .filter(|entry| entry.kind == "history")
        .collect()
}

fn events_of(entries: &[crate::lab::view::ActivityView], file: &str) -> Vec<String> {
    // Newest first, as the snapshot orders them; read oldest first.
    entries
        .iter()
        .rev()
        .filter_map(|e| e.history.as_ref())
        .filter(|h| h.file_name == file)
        .map(|h| h.history_event_type.clone())
        .collect()
}

#[test]
fn the_seeded_tracked_files_tell_three_different_stories_from_real_commands() {
    let state = lab();
    let entries = history(&state);

    // 1. An unsigned newer edit: sharing falls back to the last trusted revision.
    let budget = events_of(&entries, "budget.txt");
    for kind in [
        "TrackingStarted",
        "RevisionSigned",
        "EditCheckedIn",
        "ShareAttempted",
    ] {
        assert!(budget.iter().any(|k| k == kind), "{kind}: {budget:?}");
    }
    let share = entries
        .iter()
        .find(|e| {
            e.history.as_ref().is_some_and(|h| {
                h.file_name == "budget.txt" && h.history_event_type == "ShareAttempted"
            })
        })
        .unwrap();
    assert!(share
        .trace
        .iter()
        .any(|step| step.text.contains("LastTrustedRevision")));
    assert_eq!(share.outcome, "granted");

    // 2. Non-overlapping edits merge on their own.
    let forecast = events_of(&entries, "forecast.txt");
    assert!(
        forecast.iter().any(|k| k == "HistoryImported"),
        "{forecast:?}"
    );
    assert!(
        forecast.iter().any(|k| k == "AutoMergeClean"),
        "{forecast:?}"
    );
    assert!(!forecast.iter().any(|k| k == "AutoMergeRequiresHuman"));

    // 3. Two edits to one line stop for a person, who is named.
    let memo = events_of(&entries, "memo.txt");
    for kind in [
        "AutoMergeRequiresHuman",
        "ContentConflictDetected",
        "ConflictReviewAssigned",
    ] {
        assert!(memo.iter().any(|k| k == kind), "{kind}: {memo:?}");
    }
    assert!(!memo.iter().any(|k| k == "AutoMergeClean"));
    let assigned = entries
        .iter()
        .find(|e| {
            e.history
                .as_ref()
                .is_some_and(|h| h.history_event_type == "ConflictReviewAssigned")
        })
        .unwrap();
    // Who reviews, and by which rule, is whatever the event itself recorded.
    for key in ["reviewer: M.S", "selection_rule: PRIOR_NEUTRAL_OWNER"] {
        assert!(
            assigned.trace.iter().any(|step| step.text.starts_with(key)),
            "{key}: {:?}",
            assigned.trace
        );
    }
    assert_eq!(
        assigned.history.as_ref().unwrap().history_category,
        "conflict"
    );
}

#[test]
fn history_entries_carry_the_containers_own_facts() {
    let state = lab();
    let entries = history(&state);
    let signed = entries
        .iter()
        .rev()
        .find(|e| {
            e.history
                .as_ref()
                .is_some_and(|h| h.history_event_type == "RevisionSigned")
        })
        .unwrap();
    let h = signed.history.as_ref().unwrap();
    assert_eq!(h.file_id.len(), 32);
    assert_eq!(h.history_root.len(), 64);
    assert_eq!(h.revision_id.as_deref().map(str::len), Some(64));
    assert!(h
        .generated_label
        .as_deref()
        .is_some_and(|l| l.starts_with('R')));
    assert_eq!(h.finalization_state.as_deref(), Some("trusted"));
    assert_eq!(h.history_category, "revision");
    // The unsigned late edit is pending, and a merge revision names both parents.
    let pending = entries.iter().any(|e| {
        e.history.as_ref().is_some_and(|h| {
            h.history_event_type == "EditCheckedIn"
                && h.finalization_state.as_deref() == Some("pending")
        })
    });
    assert!(pending);
    let merged = entries
        .iter()
        .filter_map(|e| e.history.as_ref())
        .any(|h| h.history_event_type == "AutoMergeClean" && h.parent_revision_ids.len() == 2);
    assert!(merged);
    // Every history entry names the command that shows the same history.
    assert!(entries.iter().all(|e| e
        .command
        .as_deref()
        .is_some_and(|c| c.starts_with("keyquorum file history "))));
}

#[test]
fn only_history_entries_carry_history_fields_when_serialized() {
    let state = lab();
    let json = serde_json::to_value(snap(&state)).unwrap();
    let activity = json["activity"].as_array().unwrap();
    let seeded = &activity[0];
    assert_eq!(seeded["kind"], "reset");
    assert!(seeded.get("fileId").is_none() && seeded.get("historyEventType").is_none());
    let event = activity.iter().find(|e| e["kind"] == "history").unwrap();
    for key in [
        "fileId",
        "fileName",
        "historyEventType",
        "historyCategory",
        "historyRoot",
    ] {
        assert!(event.get(key).is_some(), "{key}: {event}");
    }
}

// ---- tracked files from the GUI --------------------------------------------

fn tracked<'a>(snapshot: &'a Snapshot, path: &str) -> &'a crate::lab::view::TrackedFileView {
    snapshot
        .tracked_files
        .iter()
        .find(|file| file.path == path)
        .unwrap_or_else(|| panic!("{path} is not tracked"))
}

fn ok(outcome: crate::error::Result<super::Outcome>) -> super::Outcome {
    let outcome = outcome.expect("action runs");
    assert!(outcome.ok, "{}\n{}", outcome.message, said(&outcome));
    outcome
}

const NOTES: &str = "/home/sarah/tracked/notes.txt.kqtf";

#[test]
fn a_file_tracked_edited_shared_and_signed_from_the_gui_shows_up_live() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "draft 1\n"));
    let s = snap(&state);
    // The action's own entry is newest, the history it wrote right below.
    assert_eq!(s.activity[0].kind, "history-track");
    let started = s.activity[1].history.as_ref().unwrap();
    assert_eq!(started.history_event_type, "PolicyDecision");
    let file = tracked(&s, NOTES);
    assert_eq!(file.owner.as_deref(), Some("sarah"));
    assert_eq!(file.revisions.len(), 1);
    assert_eq!(file.revisions[0].trust, "trusted");
    assert_eq!(file.revisions[0].text.as_deref(), Some("draft 1\n"));

    ok(state.history_checkin(NOTES, "draft 2\n", false, Some("Unsigned edit")));
    let s = snap(&state);
    assert_eq!(s.activity[0].kind, "history-checkin");
    let file = tracked(&s, NOTES);
    let head = file.revisions.last().unwrap();
    assert_eq!(head.trust, "pending");
    assert_eq!(head.user_label.as_deref(), Some("Unsigned edit"));
    assert_eq!(
        file.shareable.as_deref(),
        Some(file.revisions[0].id.as_str())
    );

    // Sharing now sends the last trusted revision, not the unsigned one.
    let shared = ok(state.history_share(NOTES, "morgan"));
    assert!(
        said(&shared).contains("LastTrustedRevision"),
        "{}",
        said(&shared)
    );
    assert_eq!(snap(&state).tracked_letters.len(), 1);

    ok(state.history_sign(NOTES, None));
    let s = snap(&state);
    assert_eq!(s.activity[0].kind, "history-sign");
    let file = tracked(&s, NOTES);
    assert!(file.revisions.iter().all(|r| r.trust == "trusted"));
    assert_eq!(
        file.shareable.as_deref(),
        Some(file.revisions[1].id.as_str())
    );
    let verified = ok(state.history_verify(NOTES));
    assert!(verified
        .opened
        .unwrap()
        .text
        .contains("History and revision graph verify"));
}

#[test]
fn the_cli_decides_and_the_lab_reports_a_refusal() {
    let mut state = lab();
    // Alice may not sign Sarah's revision; the CLI refuses and history says so.
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "draft 1\n"));
    ok(state.history_checkin(NOTES, "draft 2\n", false, None));
    state.switch_user("alice").unwrap();
    let refused = state.history_sign(NOTES, None).unwrap();
    assert!(!refused.ok);
    assert_eq!(snap(&state).activity[0].outcome, "denied");
    // Without the actor's drive, nothing is signed either.
    state.switch_user("sarah").unwrap();
    state.set_drive("sarah", false).unwrap();
    assert!(!state.history_sign(NOTES, None).unwrap().ok);
    assert_eq!(tracked(&snap(&state), NOTES).revisions[1].trust, "pending");
    // An unknown path is not a tracked file.
    assert!(!state.history_verify("/etc/passwd").unwrap().ok);
}

#[test]
fn terminal_commands_on_a_tracked_file_reach_the_timeline() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    let budget = "/srv/keyquorum/tracked/budget.txt.kqtf";
    let revisions = tracked(&snap(&state), budget).revisions.len();
    let (outcome, _) = terminal::run(
        &mut state,
        &format!(
            "keyquorum --db /home/sarah/keyquorum.sqlite file checkin {budget} \
             --from /srv/keyquorum/tracked/forecast.txt.alice --as M.S --unsigned"
        ),
    )
    .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    let s = snap(&state);
    // The command's own entry is newest; the events it wrote sit below it.
    assert_eq!(s.activity[0].kind, "command");
    let checked_in = s.activity[1].history.as_ref().unwrap();
    assert_eq!(checked_in.history_event_type, "PolicyDecision");
    assert_eq!(
        s.activity[2].history.as_ref().unwrap().history_event_type,
        "EditCheckedIn"
    );
    assert_eq!(tracked(&s, budget).revisions.len(), revisions + 1);

    // A container first named on the command line is followed from then on.
    let (outcome, _) = terminal::run(
        &mut state,
        "keyquorum --db /home/sarah/keyquorum.sqlite file track /srv/keyquorum/tracked/memo.txt.bob \
         --scope M.S --as M.S --slot /media/sarah-usb=M.S --out /home/sarah/memo-copy.kqtf",
    )
    .unwrap();
    assert!(outcome.ok, "{}", said(&outcome));
    assert!(snap(&state)
        .tracked_files
        .iter()
        .any(|f| f.path == "/home/sarah/memo-copy.kqtf"));
}

#[test]
fn two_people_fork_a_file_by_letter_and_one_of_them_merges_it() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "a\nb\nc\n"));
    ok(state.history_share(NOTES, "alice"));

    // Alice keeps her own copy.
    state.switch_user("alice").unwrap();
    let letter = snap(&state).tracked_letters[0].id;
    ok(state.history_receive(letter, true));
    let copy = "/home/alice/tracked/notes.txt.kqtf";
    assert!(snap(&state).tracked_files.iter().any(|f| f.path == copy));
    assert_eq!(snap(&state).tracked_letters[0].status, "accepted");
    // Alice's signed edit still needs Sarah, her direct parent.
    ok(state.history_checkin(copy, "a\nb\nC\n", true, None));
    assert_eq!(tracked(&snap(&state), copy).revisions[1].trust, "pending");

    // Sarah records Alice's answer, countersigns Alice's edit, and edits her own copy.
    state.switch_user("sarah").unwrap();
    ok(state.history_ack(letter));
    assert!(snap(&state).tracked_letters[0].ack_recorded);
    ok(state.history_countersign(copy, None));
    assert_eq!(tracked(&snap(&state), copy).revisions[1].trust, "trusted");
    ok(state.history_checkin(NOTES, "A\nb\nc\n", true, None));

    // Alice sends hers back; Sarah's copy now has two heads.
    state.switch_user("alice").unwrap();
    ok(state.history_share(copy, "sarah"));
    state.switch_user("sarah").unwrap();
    let back = snap(&state).tracked_letters[1].id;
    ok(state.history_receive(back, true));
    assert!(tracked(&snap(&state), NOTES).forked);
    let review = ok(state.history_review(NOTES));
    assert!(review.opened.unwrap().text.contains("CHANGED LINES (LEFT)"));

    // Edits on different lines merge on their own; Sarah signs the result.
    ok(state.history_merge(NOTES, Some("Both edits")));
    let file = tracked(&snap(&state), NOTES).clone();
    assert!(!file.forked);
    let merged = file.revisions.last().unwrap();
    assert_eq!(merged.parents.len(), 2);
    assert_eq!(merged.text.as_deref(), Some("A\nb\nC\n"));
    assert_eq!(merged.trust, "pending");
    ok(state.history_sign(NOTES, None));
    assert_eq!(
        tracked(&snap(&state), NOTES)
            .revisions
            .last()
            .unwrap()
            .trust,
        "trusted"
    );
    let kinds: Vec<String> = snap(&state)
        .activity
        .iter()
        .filter_map(|e| e.history.as_ref())
        .filter(|h| h.file_name == "notes.txt")
        .map(|h| h.history_event_type.clone())
        .collect();
    for kind in ["HistoryImported", "AutoMergeClean", "ShareDelivered"] {
        assert!(kinds.iter().any(|k| k == kind), "{kind}: {kinds:?}");
    }
}

#[test]
fn renaming_a_tracked_file_keeps_its_identity_and_shows_the_current_and_trusted_head() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "first\n"));
    let before = tracked(&snap(&state), NOTES).clone();
    assert_eq!(before.current_revision, before.trusted_revision);
    // Alice is a descendant, not the scope owner or an ancestor.
    state.switch_user("alice").unwrap();
    assert!(!state.history_rename(NOTES, "renamed.txt").unwrap().ok);
    state.switch_user("sarah").unwrap();
    ok(state.history_rename(NOTES, "renamed.txt"));
    let s = snap(&state);
    let after = tracked(&s, NOTES);
    assert_eq!(after.name, "renamed.txt");
    assert_eq!(after.file_id, before.file_id);
    assert_eq!(
        after
            .revisions
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>(),
        before
            .revisions
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(s.activity[0].kind, "history-rename");
    assert_eq!(
        s.activity[1].history.as_ref().unwrap().history_event_type,
        "FileRenamed"
    );
}

#[test]
fn expiring_a_tracked_file_from_the_gui_leaves_a_tombstone_the_timeline_shows() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "SECRET draft\n"));
    // Alice, a descendant, may not end Sarah's file.
    state.switch_user("alice").unwrap();
    assert!(!state.history_expire(NOTES, None).unwrap().ok);
    state.switch_user("sarah").unwrap();
    ok(state.history_expire(NOTES, Some("2099-01-01T00:00")));
    assert_eq!(
        tracked(&snap(&state), NOTES).expires_at.as_deref(),
        Some("2099-01-01T00:00:00Z")
    );
    ok(state.history_expire(NOTES, None));
    let s = snap(&state);
    let file = tracked(&s, NOTES);
    assert!(file.destroyed);
    assert!(file.revisions.iter().all(|r| r.text.is_none()));
    assert_eq!(s.activity[0].kind, "history-expire");
    let recorded: Vec<&str> = s.activity[1..3]
        .iter()
        .filter_map(|e| e.history.as_ref())
        .map(|h| h.history_event_type.as_str())
        .collect();
    assert_eq!(recorded, ["ContentDestroyed", "FileExpired"]);
    // Using the content afterwards is refused by the CLI and recorded.
    let refused = state.history_checkin(NOTES, "more\n", true, None).unwrap();
    assert!(!refused.ok);
    assert_eq!(
        snap(&state).activity[1]
            .history
            .as_ref()
            .unwrap()
            .history_event_type,
        "ExpiredAccessAttempt"
    );
    assert!(!state.read_text(NOTES).unwrap().contains("SECRET draft"));
}

#[test]
fn diff_view_export_and_snapshot_checks_run_from_the_gui() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "one\ntwo\n"));
    ok(state.history_checkin(NOTES, "one\nTWO\n", true, None));
    let diff = ok(state.history_diff(NOTES, None, None))
        .opened
        .unwrap()
        .text;
    assert!(
        diff.contains("- ") && diff.contains("two") && diff.contains("TWO"),
        "{diff}"
    );
    let first = tracked(&snap(&state), NOTES).revisions[0].id.clone();
    let view = ok(state.history_view_revision(NOTES, &first))
        .opened
        .unwrap();
    assert_eq!(view.text, "one\ntwo\n");
    // The scratch file used to show it is gone again.
    assert!(state.read_text("/home/sarah/tracked/.checkout").is_err());

    ok(state.history_export(NOTES));
    let snapshot = tracked(&snap(&state), NOTES).snapshots[0].clone();
    assert!(snapshot.ends_with("notes.txt-1.kqhs"));
    // Still a point in the history after more is recorded.
    ok(state.history_checkin(NOTES, "one\nTWO\nthree\n", true, None));
    let checked = ok(state.history_verify_snapshot(NOTES, &snapshot))
        .opened
        .unwrap()
        .text;
    assert!(
        checked.contains("It is a point in the history of notes.txt"),
        "{checked}"
    );
}

#[test]
fn importing_another_followed_copy_joins_its_revisions() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "a\n"));
    ok(state.history_share(NOTES, "alice"));
    state.switch_user("alice").unwrap();
    let letter = snap(&state).tracked_letters[0].id;
    ok(state.history_receive(letter, true));
    let copy = "/home/alice/tracked/notes.txt.kqtf";
    ok(state.history_checkin(copy, "b\n", false, None));
    state.switch_user("sarah").unwrap();
    ok(state.history_import(NOTES, copy));
    assert_eq!(tracked(&snap(&state), NOTES).revisions.len(), 2);
    assert!(snap(&state).activity[1..]
        .iter()
        .filter_map(|e| e.history.as_ref())
        .any(|h| h.history_event_type == "HistoryImported"));
}

#[test]
fn a_linked_quorum_file_records_its_unlocks_in_the_tracked_timeline() {
    let mut state = lab();
    let path = "/home/alice/tracked/notes.txt.kqtf";
    ok(state.history_track("notes.txt", "a\n"));
    let id = snap(&state)
        .files
        .iter()
        .find(|f| f.name == "architecture.md")
        .and_then(|f| f.quorum_file_id)
        .unwrap();
    ok(state.history_link(path, "quorum", id, true));
    let links = tracked(&snap(&state), path).links.clone();
    assert_eq!(links.len(), 1);
    assert_eq!((links[0].gate.as_str(), links[0].id), ("quorum", id));

    assert!(state.unlock("architecture.md").unwrap().ok);
    let unlocked = snap(&state)
        .activity
        .iter()
        .filter_map(|e| e.history.as_ref())
        .any(|h| h.file_name == "notes.txt" && h.history_event_type == "QuorumUnlockAttempted");
    assert!(unlocked);
    ok(state.history_link(path, "quorum", id, false));
    assert!(tracked(&snap(&state), path).links.is_empty());
    assert!(!state.history_link(path, "sideways", id, true).unwrap().ok);
}

const MEMO: &str = "/srv/keyquorum/tracked/memo.txt.kqtf";

#[test]
fn only_the_assigned_reviewer_can_resolve_the_seeded_memo_conflict() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    assert!(tracked(&snap(&state), MEMO).forked, "seeded as a conflict");

    // Alice wrote one side: the CLI refuses her, and the lab adds no rule.
    state.switch_user("alice").unwrap();
    let refused = state
        .history_resolve(MEMO, "left", None, None)
        .expect("action runs");
    assert!(!refused.ok, "{}", refused.message);
    assert!(tracked(&snap(&state), MEMO).forked);

    // Sarah is the assigned reviewer (M.S): an edited result settles it.
    state.switch_user("sarah").unwrap();
    let unknown = state
        .history_resolve(MEMO, "sideways", None, None)
        .expect("action runs");
    assert!(!unknown.ok);
    let done = ok(state.history_resolve(
        MEMO,
        "edited",
        Some("Owner: TBD\nBudget: 100\n"),
        Some("Settled"),
    ));
    assert!(said(&done).contains("resolve"), "{}", said(&done));
    let file = tracked(&snap(&state), MEMO).clone();
    assert!(!file.forked);
    let resolved = file.revisions.last().unwrap();
    assert_eq!(resolved.parents.len(), 2);
    assert_eq!(resolved.text.as_deref(), Some("Owner: TBD\nBudget: 100\n"));
    assert_eq!(resolved.trust, "trusted", "the reviewer's own signature");
}

#[test]
fn a_change_request_is_asked_answered_and_recorded_by_real_commands() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "a\n"));
    ok(state.history_share(NOTES, "alice"));
    state.switch_user("alice").unwrap();
    let letter = snap(&state).tracked_letters[0].id;
    ok(state.history_receive(letter, true));
    state.switch_user("sarah").unwrap();
    ok(state.history_request(NOTES, "alice", true, "tighten the intro"));
    let request = snap(&state).tracked_requests[0].clone();
    assert_eq!(request.kind, "change");
    assert_eq!(request.status, "waiting");
    state.switch_user("alice").unwrap();
    ok(state.history_answer_request(request.id, true));
    assert_eq!(snap(&state).tracked_requests[0].status, "accepted");
    state.switch_user("sarah").unwrap();
    ok(state.history_open_answer(request.id));
    let view = snap(&state);
    assert!(view.tracked_requests[0].answer_recorded);
    let events: Vec<_> = view
        .activity
        .iter()
        .filter_map(|e| e.history.as_ref())
        .map(|h| h.history_event_type.as_str())
        .collect();
    assert!(events.contains(&"ChangeRequested"), "{events:?}");
    assert!(events.contains(&"RequestAnswered"), "{events:?}");
    // The message is shown to the holder in the CLI output, never recorded.
    assert!(!format!("{:?}", view.activity).contains("tighten the intro\"}"));
}

// ----- one command per task: quorum send, tracked letters, doctor --------

#[test]
fn a_quorum_file_is_sent_by_one_command_against_the_org_store_with_no_temp_file() {
    let mut state = lab();
    let sent = state.send("architecture.md", "david").unwrap();
    assert!(sent.ok, "{}", said(&sent));
    let command = snap(&state).activity[0].command.clone().unwrap();
    assert!(
        command.contains("--db /srv/keyquorum/org.sqlite send --quorum-file"),
        "{command}"
    );
    assert!(command.contains("--unlock-slot /media/"), "{command}");
    assert!(!command.contains("access quorum"), "{command}");
    assert!(!command.contains("rm "), "{command}");
    let text = said(&sent);
    assert!(!text.contains("temporary plaintext"), "{text}");
    assert_eq!(snap(&state).sent[0].status, "delivered");
}

#[test]
fn tracked_letters_travel_through_the_relay_and_are_opened_with_inbox_open() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "a\n"));
    ok(state.history_share(NOTES, "alice"));
    let share = snap(&state)
        .activity
        .iter()
        .find(|a| a.kind == "history-share")
        .cloned()
        .unwrap();
    let command = share.command.unwrap();
    assert!(command.contains(" send "), "{command}");
    assert!(
        !command.contains("--output-dir"),
        "no folder hand-off: {command}"
    );

    state.switch_user("alice").unwrap();
    let letter = snap(&state).tracked_letters[0].id;
    ok(state.history_receive(letter, true));
    let received = snap(&state)
        .activity
        .iter()
        .find(|a| a.kind == "history-receive")
        .cloned()
        .unwrap();
    let command = received.command.unwrap();
    assert!(command.contains(" inbox open "), "{command}");
    assert!(
        command.contains("--out /home/alice/tracked/notes.txt.kqtf"),
        "{command}"
    );
    assert!(!command.contains(" file receive"), "{command}");
    assert!(
        !said_all(&received.trace).contains("legacy command"),
        "no legacy notes"
    );

    // Her answer travelled the relay too, and Sarah's copy records it.
    state.switch_user("sarah").unwrap();
    let ack = snap(&state)
        .activity
        .iter()
        .find(|a| a.kind == "history-ack")
        .cloned()
        .unwrap();
    assert!(ack.command.unwrap().contains(" inbox open "));
    assert!(snap(&state).tracked_letters[0].ack_recorded);
}

fn said_all(trace: &[super::view::TraceStep]) -> String {
    trace
        .iter()
        .map(|step| step.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_request_is_answered_with_one_inbox_open_command() {
    let mut state = lab();
    state.switch_user("sarah").unwrap();
    ok(state.history_track("notes.txt", "a\n"));
    ok(state.history_share(NOTES, "alice"));
    state.switch_user("alice").unwrap();
    let letter = snap(&state).tracked_letters[0].id;
    ok(state.history_receive(letter, true));
    state.switch_user("sarah").unwrap();
    ok(state.history_request(NOTES, "alice", true, "tighten the intro"));
    let request = snap(&state).tracked_requests[0].id;
    state.switch_user("alice").unwrap();
    ok(state.history_answer_request(request, true));
    let answered = snap(&state)
        .activity
        .iter()
        .find(|a| a.kind == "history-answer-request")
        .cloned()
        .unwrap();
    let command = answered.command.unwrap();
    assert!(command.contains(" inbox open "), "{command}");
    assert!(command.contains("--accept"), "{command}");
    assert!(!command.contains("open-request"), "{command}");
}

#[test]
fn doctor_is_green_for_a_seeded_person_and_names_a_missing_drive() {
    let mut state = lab();
    let green = state.doctor().unwrap();
    assert_eq!(green.message, "Everything checks out", "{}", said(&green));
    let text = said(&green);
    assert!(text.contains("acting as M.S.1"), "{text}");
    assert!(text.contains("the slot is bound to its device"), "{text}");

    state.set_drive("alice", false).unwrap();
    let red = state.doctor().unwrap();
    assert!(red.ok, "a report, not a failure");
    let text = said(&red);
    assert!(text.contains("cannot be opened"), "{text}");
    assert!(text.contains("plug the device in"), "{text}");
    assert_ne!(red.message, "Everything checks out");
    // A FIX line is shown as a failure and an ok line as a pass, never the
    // other way round.
    assert!(
        red.trace
            .iter()
            .any(|step| step.status == StepStatus::Fail && step.text.contains("FIX")),
        "{text}"
    );
    assert!(
        red.trace
            .iter()
            .filter(|step| step.status == StepStatus::Pass)
            .all(|step| !step.text.contains("FIX")),
        "{text}"
    );
}

#[test]
fn moving_a_slot_keeps_its_owners_defaults_and_binding_whole() {
    let mut state = lab();
    state.set_drive("bob", true).unwrap();
    ok(state.move_slot("M.S.1", "bob"));
    let doctor = state.doctor().unwrap();
    assert_eq!(doctor.message, "Everything checks out", "{}", said(&doctor));
    assert!(
        said(&doctor).contains("/media/bob-usb"),
        "{}",
        said(&doctor)
    );
    let moved = snap(&state)
        .activity
        .iter()
        .find(|a| a.kind == "move")
        .cloned()
        .unwrap();
    let command = moved.command.unwrap();
    assert!(
        command.contains(" use --device /media/bob-usb --slot M.S.1"),
        "{command}"
    );
}

#[test]
fn use_and_bind_run_the_real_commands_in_the_active_persons_store() {
    let mut state = lab();
    let used = state.use_current_drive().unwrap();
    assert!(used.ok, "{}", said(&used));
    let bound = state.bind_slot().unwrap();
    assert!(bound.ok, "{}", said(&bound));
    let log: Vec<_> = snap(&state)
        .activity
        .iter()
        .take(2)
        .map(|a| (a.kind.clone(), a.command.clone().unwrap_or_default()))
        .collect();
    assert_eq!(log[0].0, "bind");
    assert!(
        log[0]
            .1
            .contains("--db /home/alice/keyquorum.sqlite device bind"),
        "{log:?}"
    );
    assert_eq!(log[1].0, "use");
    assert!(
        log[1]
            .1
            .contains("--db /home/alice/keyquorum.sqlite use --device"),
        "{log:?}"
    );
}
