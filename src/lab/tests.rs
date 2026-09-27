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
        "keyquorum deliver send --file /srv/keyquorum/public/company-handbook.txt --to M.Z --as M.S.1 --slot /media/alice-usb=M.S.1 --push",
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
