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
    snap(state)
        .drives
        .into_iter()
        .filter(|drive| drive.connected)
        .map(|drive| drive.id)
        .collect()
}

fn failed(outcome: &super::Outcome) -> Vec<String> {
    outcome
        .trace
        .iter()
        .filter(|step| step.status == StepStatus::Fail)
        .map(|step| step.text.clone())
        .collect()
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
        let files: Vec<&str> = snapshot.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            files,
            [
                "company-handbook.txt",
                "project-roadmap.md",
                "architecture.md",
                "deployment-plan.txt",
                "prod-credentials.txt",
                "payroll.csv",
                "q3-budget.csv",
                "acquisition-plan.txt"
            ]
        );
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
    assert_eq!(
        first.drives.iter().map(|d| d.connected).collect::<Vec<_>>(),
        [true, false, false]
    );
    // Device ids are minted per container, independent of the mount path.
    let ids: std::collections::HashSet<&str> =
        first.drives.iter().map(|d| d.device_id.as_str()).collect();
    assert_eq!(ids.len(), 3);
}

#[test]
fn each_drive_is_a_signed_container_with_one_token_per_slot() {
    let state = lab();
    let engineering = snap(&state)
        .drives
        .into_iter()
        .find(|drive| drive.id == "engineering")
        .unwrap();
    assert!(engineering.files.contains(&"device.kq".to_string()));
    assert!(engineering.files.contains(&"device.skey".to_string()));
    for slot in ["M.S", "M.S.1", "M.S.2"] {
        assert!(engineering
            .files
            .contains(&format!("vault/slot-{slot}/token.kqst")));
    }
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
    assert_eq!(connected(&state), ["engineering"]);
    assert!(state.set_drive("accounting", true).unwrap().ok);
    assert_eq!(connected(&state), ["engineering", "accounting"]);
    assert!(state.set_drive("engineering", false).unwrap().ok);
    assert_eq!(connected(&state), ["accounting"]);
    let ejected = snap(&state)
        .drives
        .into_iter()
        .find(|d| d.id == "engineering")
        .unwrap();
    assert!(ejected.files.is_empty(), "an ejected drive shows no files");
}

#[test]
fn ejecting_your_drive_removes_your_shares() {
    let mut state = lab();
    assert!(state.unlock("architecture.md").unwrap().ok);
    state.set_drive("engineering", false).unwrap();
    let denied = state.unlock("architecture.md").unwrap();
    assert!(!denied.ok);
    assert!(failed(&denied)
        .iter()
        .any(|line| line.contains("Engineering USB, which is not inserted")));
}

#[test]
fn cross_department_quorum_changes_when_a_second_device_arrives() {
    let mut state = lab();
    let denied = state.unlock("acquisition-plan.txt").unwrap();
    assert!(!denied.ok, "only M.S is present");
    assert!(failed(&denied)
        .iter()
        .any(|line| line.starts_with("Quorum not satisfied")));
    let last = snap(&state).last_access.unwrap();
    assert_eq!(last.required, ["M", "M.S", "M.A"]);
    assert_eq!(last.satisfied, ["M.S"]);

    state.set_drive("accounting", true).unwrap();
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
    let outcome = state.unlock("deployment-plan.txt").unwrap();
    assert!(outcome.ok, "{:?}", outcome.trace);
    assert!(outcome
        .trace
        .iter()
        .any(|step| step.text.starts_with("Physical devices: 1 (minimum 1)")));
}

#[test]
fn authorization_follows_the_active_user() {
    let mut state = lab();
    let payroll = state.unlock("payroll.csv").unwrap();
    assert!(!payroll.ok);
    assert!(failed(&payroll)[0].contains("holds no share"));
    let access = |state: &LabState, name: &str| {
        snap(state)
            .files
            .into_iter()
            .find(|f| f.name == name)
            .unwrap()
            .access
    };
    assert_eq!(access(&state, "payroll.csv"), "none");
    assert_eq!(access(&state, "architecture.md"), "holder");

    state.switch_user("emma").unwrap();
    state.set_drive("accounting", true).unwrap();
    assert_eq!(access(&state, "payroll.csv"), "holder");
    assert!(state.unlock("payroll.csv").unwrap().ok);
    assert!(!state.unlock("architecture.md").unwrap().ok);

    state.switch_user("morgan").unwrap();
    assert_eq!(access(&state, "payroll.csv"), "oversight");
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
    assert!(
        !locked_out.ok,
        "David's key is on the ejected Accounting USB"
    );

    state.set_drive("accounting", true).unwrap();
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

#[test]
fn terminal_and_gui_share_one_state() {
    let mut state = lab();
    let (outcome, output) = terminal::run(&mut state, "usb insert accounting").unwrap();
    assert!(outcome.ok);
    assert!(output[0].contains("Accounting USB inserted"));
    assert_eq!(connected(&state), ["engineering", "accounting"]);
    let (_, output) = terminal::run(&mut state, "su david").unwrap();
    assert!(output[0].contains("David"));
    assert_eq!(snap(&state).active_user.id, "david");
    let (outcome, _) = terminal::run(&mut state, "unlock q3-budget.csv").unwrap();
    assert!(outcome.ok);
    assert_eq!(
        snap(&state).activity[0].title,
        "Access granted: q3-budget.csv"
    );
    let (outcome, _) = terminal::run(&mut state, "frobnicate").unwrap();
    assert!(!outcome.ok);
}

#[test]
fn reset_restores_the_seeded_state() {
    let mut state = lab();
    state.set_drive("accounting", true).unwrap();
    state.switch_user("david").unwrap();
    state.send("q3-budget.csv", "sarah").unwrap();
    state = lab();
    let fresh = snap(&state);
    assert_eq!(fresh.active_user.id, "alice");
    assert_eq!(connected(&state), ["engineering"]);
    assert!(fresh.sent.is_empty() && fresh.inbox.is_empty() && fresh.approvals.is_empty());
    assert_eq!(fresh.activity.len(), 1);
}

#[test]
fn unlock_records_a_real_audit_row() {
    let mut state = lab();
    let (_, output) = terminal::run(&mut state, "unlock architecture.md").unwrap();
    assert!(output.iter().any(|line| line.contains("AES-256-GCM")));
    let command = snap(&state).activity[0].command.clone().unwrap();
    assert!(command.starts_with("keyquorum access quorum --state 1 --id "));
    assert!(command.contains("--slot /media/engineering-usb=M.S.1"));
}
