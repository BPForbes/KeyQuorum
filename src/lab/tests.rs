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
