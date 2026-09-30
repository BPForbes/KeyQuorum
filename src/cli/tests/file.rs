use super::memory_env::MemoryEnv;
use crate::storage::Storage;
use std::path::Path;

pub(super) const DB: &str = "--db /home/org/keyquorum.sqlite";

/// (container directory, label). Everyone's signing key is registered in
/// the one org store, as in a real deployment.
const PEOPLE: [(&str, &str); 5] = [
    ("m", "M"),
    ("ma", "M.A"),
    ("ma1", "M.A.1"),
    ("mb", "M.B"),
    ("ms1", "M.S.1"),
];

pub(super) fn org() -> MemoryEnv {
    let mut env = MemoryEnv::default();
    for (dir, label) in PEOPLE {
        env.device(&format!("keyquorum-device init /usb/{dir}"))
            .0
            .unwrap();
        let (ok, _) = env.device(&format!(
            "keyquorum-device provision /usb/{dir} --label {label}"
        ));
        assert!(ok.is_ok(), "{ok:?}");
        let (ok, _) = env.keyquorum(&format!(
            "keyquorum {DB} device register /usb/{dir} --slot {label} --type signing"
        ));
        assert!(ok.is_ok(), "{ok:?}");
    }
    env.fs
        .write_new(Path::new("/work/report.txt"), b"totals: 100\n")
        .unwrap();
    env
}

/// A top-level `keyquorum` command against the org store that must succeed.
fn ok_keyquorum(env: &mut MemoryEnv, args: &str) -> String {
    let (result, out) = env.keyquorum(&format!("keyquorum {DB} {args}"));
    assert!(result.is_ok(), "{args}: {result:?}\n{out}");
    out
}

pub(super) fn slot(label: &str) -> String {
    let dir = PEOPLE.iter().find(|(_, l)| *l == label).unwrap().0;
    format!("/usb/{dir}={label}")
}

pub(super) fn run(env: &mut MemoryEnv, args: &str) -> (crate::error::Result<()>, String) {
    env.keyquorum(&format!("keyquorum {DB} file {args}"))
}

pub(super) fn ok(env: &mut MemoryEnv, args: &str) -> String {
    let (result, out) = run(env, args);
    assert!(result.is_ok(), "{args}: {result:?}\n{out}");
    out
}

pub(super) fn track(env: &mut MemoryEnv, scope: &str, label: &str) -> String {
    track_with(env, scope, label, "")
}

fn track_with(env: &mut MemoryEnv, scope: &str, label: &str, extra: &str) -> String {
    ok(
        env,
        &format!(
            "track /work/report.txt --scope {scope} --as {label} --slot {} {extra}",
            slot(label)
        ),
    )
}

fn edit(env: &mut MemoryEnv, text: &str) {
    env.fs
        .write(Path::new("/work/edited.txt"), text.as_bytes())
        .unwrap();
}

#[test]
fn tracking_writes_a_signed_trusted_container() {
    let mut env = org();
    let out = track(&mut env, "M.A", "M.A");
    assert!(out.contains("Tracking report.txt as "), "{out}");
    assert!(out.contains("trust    TRUSTED"), "{out}");
    assert!(out.contains("Wrote /work/report.txt.kqtf"));
    assert!(env.fs.exists(Path::new("/work/report.txt.kqtf")));

    let status = ok(&mut env, "status /work/report.txt.kqtf");
    assert!(status.contains("scope        M.A"), "{status}");
    assert!(status.contains("trust TRUSTED"), "{status}");
    assert!(status.contains("would share this revision"), "{status}");
    assert!(!status.contains("FORK"));

    let history = ok(&mut env, "history /work/report.txt.kqtf");
    let kinds: Vec<&str> = history
        .lines()
        .map(|l| l.split_whitespace().nth(2).unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["TrackingStarted", "RevisionSigned", "PolicyDecision"]
    );
    assert!(history.contains("by M.A"));

    let verify = ok(&mut env, "verify /work/report.txt.kqtf");
    assert!(
        verify.starts_with("History and revision graph verify"),
        "{verify}"
    );
    assert!(verify.contains("TRUSTED"));
}

#[test]
fn tracking_refuses_an_existing_target_a_foreign_author_and_a_wrong_key() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    // The container already exists.
    let (result, _) = run(
        &mut env,
        &format!(
            "track /work/report.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(result.is_err());
    // An author outside the file's scope.
    let (result, _) = run(
        &mut env,
        &format!(
            "track /work/report.txt --scope M.A --as M.S.1 --slot {} --out /work/other.kqtf",
            slot("M.S.1")
        ),
    );
    // M.S.1 is cross-branch, so it may author (with a bridge or the owner),
    // but "X.1" is unrelated and may not.
    assert!(result.is_ok());
    let (result, _) = run(
        &mut env,
        &format!(
            "track /work/report.txt --scope M.A --as X.1 --slot {} --out /work/x.kqtf",
            slot("M.B")
        ),
    );
    assert!(result.is_err());
    assert!(!env.fs.exists(Path::new("/work/x.kqtf")));
    // Signing as M.A with someone else's key is caught before anything is written.
    let (result, _) = run(
        &mut env,
        &format!(
            "track /work/report.txt --scope M.A --as M.A --slot {} --out /work/wrong.kqtf",
            slot("M.B")
        ),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not the one registered"));
    assert!(!env.fs.exists(Path::new("/work/wrong.kqtf")));
}

#[test]
fn an_unsigned_edit_is_pending_and_sharing_falls_back_until_it_is_signed() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: 125\n");
    let out = ok(
        &mut env,
        "checkin /work/report.txt.kqtf --from /work/edited.txt --as M.A --unsigned",
    );
    assert!(out.contains("PENDING (MissingContentSignature)"), "{out}");

    let status = ok(&mut env, "status /work/report.txt.kqtf");
    assert!(
        status.contains("PENDING (MissingContentSignature)"),
        "{status}"
    );
    assert!(
        status.contains("would share the last trusted revision"),
        "{status}"
    );

    let out = ok(
        &mut env,
        &format!("sign /work/report.txt.kqtf --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
    let status = ok(&mut env, "status /work/report.txt.kqtf");
    assert!(status.contains("would share this revision"), "{status}");

    let history = ok(&mut env, "history /work/report.txt.kqtf");
    assert!(history.contains("EditCheckedIn"));
    assert_eq!(history.matches("PolicyDecision").count(), 3);
}

#[test]
fn a_descendant_needs_its_direct_parent_to_countersign() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: 130\n");
    let out = ok(
        &mut env,
        &format!(
            "checkin /work/report.txt.kqtf --from /work/edited.txt --as M.A.1 --slot {}",
            slot("M.A.1")
        ),
    );
    assert!(out.contains("PENDING (MissingCountersignature)"), "{out}");

    // Neither M (an ancestor) nor M.B (a sibling of the parent) is the direct
    // parent, so their countersignatures are recorded but earn nothing.
    for who in ["M", "M.B"] {
        let out = ok(
            &mut env,
            &format!(
                "countersign /work/report.txt.kqtf --as {who} --slot {}",
                slot(who)
            ),
        );
        assert!(
            out.contains("PENDING (MissingCountersignature)"),
            "{who}: {out}"
        );
    }
    let out = ok(
        &mut env,
        &format!(
            "countersign /work/report.txt.kqtf --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
    let history = ok(&mut env, "history /work/report.txt.kqtf");
    assert!(history.contains("CountersignatureAdded"));
    assert!(history.contains("for_actor=M.A.1"));
}

#[test]
fn only_the_author_can_sign_and_only_once() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let (result, _) = run(
        &mut env,
        &format!("sign /work/report.txt.kqtf --as M --slot {}", slot("M")),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("only a revision's author"));
    let (result, _) = run(
        &mut env,
        &format!("sign /work/report.txt.kqtf --as M.A --slot {}", slot("M.A")),
    );
    assert!(result.is_err(), "already signed");
}

#[test]
fn a_tampered_container_is_refused() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let path = Path::new("/work/report.txt.kqtf");
    let mut bytes = env.fs.read(path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    env.fs.write(path, &bytes).unwrap();
    for command in ["status", "history", "verify"] {
        let (result, _) = run(&mut env, &format!("{command} /work/report.txt.kqtf"));
        assert!(result.is_err(), "{command}");
    }
}

#[test]
fn a_revision_is_named_by_a_unique_prefix() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: 140\n");
    ok(
        &mut env,
        "checkin /work/report.txt.kqtf --from /work/edited.txt --as M.A --unsigned",
    );
    let verify = ok(&mut env, "verify /work/report.txt.kqtf");
    let ids: Vec<String> = verify
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2);
    let (result, _) = run(
        &mut env,
        &format!(
            "sign /work/report.txt.kqtf --revision zz --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(result.is_err());
    let out = ok(
        &mut env,
        &format!(
            "sign /work/report.txt.kqtf --revision {} --as M.A --slot {}",
            ids[1],
            slot("M.A")
        ),
    );
    assert!(out.contains(&ids[1]));
}

#[test]
fn a_ghost_identity_cannot_author_or_sign_anything_new() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let container = Path::new("/work/report.txt.kqtf");
    let before = env.fs.read(container).unwrap();
    // M.A becomes a ghost here: the hierarchy row stays, the key is gone.
    let conn = env.store("/home/org/keyquorum.sqlite");
    conn.execute(
        "INSERT INTO key_identities
             (id, label, parent_label, enc_public, sign_public, enc_fingerprint, sign_fingerprint)
         VALUES (?1, 'M.A', 'M', ?2, ?2, 'e', 's')",
        rusqlite::params![vec![7u8; 16], vec![9u8; 32]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO key_possession (identity_id, state, generation) VALUES (?1, 'ghost', 1)",
        rusqlite::params![vec![7u8; 16]],
    )
    .unwrap();

    edit(&mut env, "totals: 200\n");
    let attempts = [
        format!(
            "track /work/report.txt --scope M.A --as M.A --slot {} --out /work/g.kqtf",
            slot("M.A")
        ),
        "checkin /work/report.txt.kqtf --from /work/edited.txt --as M.A --unsigned".to_string(),
        format!(
            "checkin /work/report.txt.kqtf --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
        format!("sign /work/report.txt.kqtf --as M.A --slot {}", slot("M.A")),
        format!(
            "countersign /work/report.txt.kqtf --as M.A --slot {}",
            slot("M.A")
        ),
    ];
    for attempt in attempts {
        let (result, _) = run(&mut env, &attempt);
        let error = result.expect_err(&attempt).to_string();
        assert!(error.contains("ghost"), "{attempt}: {error}");
    }
    assert!(!env.fs.exists(Path::new("/work/g.kqtf")));
    assert_eq!(
        env.fs.read(container).unwrap(),
        before,
        "nothing was written"
    );
    // Other labels are unaffected.
    edit(&mut env, "totals: 201\n");
    let out = ok(
        &mut env,
        "checkin /work/report.txt.kqtf --from /work/edited.txt --as M.B --unsigned",
    );
    assert!(out.contains("Checked in"), "{out}");
}

// ---- merge, review, graph, diff, checkout ---------------------------------

pub(super) const KQTF: &str = "/work/report.txt.kqtf";

/// Track `base` as M.A (signed, trusted), then add two children of it by
/// M.A.1 and M.S.1, giving a forked container.
fn forked(env: &mut MemoryEnv, base: &str, left: &str, right: &str) {
    forked_with(env, base, left, right, "");
}

fn forked_with(env: &mut MemoryEnv, base: &str, left: &str, right: &str, extra: &str) {
    use crate::file_history::{NewRevision, TrackedFile};
    env.fs
        .write(Path::new("/work/report.txt"), base.as_bytes())
        .unwrap();
    track_with(env, "M.A", "M.A", extra);
    let mut file = TrackedFile::decode(&env.fs.read(Path::new(KQTF)).unwrap()).unwrap();
    let base_id = file.graph().heads()[0];
    let policy_hash = file.policy().unwrap().policy_hash().unwrap();
    for (label, minute, text) in [("M.A.1", 1, left), ("M.S.1", 2, right)] {
        file.check_in(
            NewRevision {
                parent_revision_ids: vec![base_id],
                user_label: None,
                author_identity: Some([minute; 16]),
                author_hcp_label: label.to_string(),
                created_at_utc: format!("2026-09-27T00:0{minute}:00Z"),
                topology_generation: 0,
                policy_hash,
            },
            text.as_bytes().to_vec(),
        )
        .unwrap();
    }
    env.fs
        .write(Path::new(KQTF), &file.encode().unwrap())
        .unwrap();
}

#[test]
fn a_clean_fork_merges_into_a_pending_revision_that_the_author_can_sign() {
    let mut env = org();
    forked(
        &mut env,
        "north\n100\nsouth\n",
        "north\n125\nsouth\n",
        "north\n100\nsouth-east\n",
    );
    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(graph.contains("FORK: 2 heads"), "{graph}");

    let out = ok(&mut env, &format!("merge {KQTF} --as M.A"));
    assert!(
        out.contains("Automatic merge: CleanMerge (THREE_WAY_TEXT)"),
        "{out}"
    );
    assert!(
        out.contains("trust PENDING (MissingContentSignature)"),
        "{out}"
    );

    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(!graph.contains("FORK"), "{graph}");
    assert!(graph.contains(" + "), "a two-parent revision: {graph}");
    let status = ok(&mut env, &format!("status {KQTF}"));
    assert!(
        status.contains("would share the last trusted revision"),
        "{status}"
    );

    // The merge carries both edits.
    let merged = ok(&mut env, &format!("checkout {KQTF} --out /work/merged.txt"));
    assert!(merged.contains("Wrote report.txt revision"), "{merged}");
    assert_eq!(
        env.fs.read(Path::new("/work/merged.txt")).unwrap(),
        b"north\n125\nsouth-east\n"
    );

    let out = ok(
        &mut env,
        &format!("sign {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("AutoMergeAttempted"));
    assert!(history.contains("AutoMergeClean"));
    assert!(history.contains("trust_state=PENDING"));
}

#[test]
fn a_conflicting_fork_is_recorded_and_assigned_to_a_reviewer() {
    let mut env = org();
    forked(&mut env, "totals: 100\n", "totals: 125\n", "totals: 130\n");
    let out = ok(&mut env, &format!("merge {KQTF} --as M.A"));
    assert!(out.contains("RequiresHuman (OVERLAPPING_EDIT)"), "{out}");
    assert!(
        out.contains("review assigned to M.A (PriorNeutralOwner)"),
        "{out}"
    );
    // Both heads remain; nothing was overwritten.
    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(graph.contains("FORK: 2 heads"), "{graph}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    for kind in [
        "AutoMergeRequiresHuman",
        "HistoryForkDetected",
        "ContentConflictDetected",
        "ConflictReviewAssigned",
    ] {
        assert!(history.contains(kind), "{kind}: {history}");
    }
    // A second attempt does not pretend to resolve it.
    let again = ok(&mut env, &format!("merge {KQTF} --as M.A"));
    assert!(again.contains("RequiresHuman"), "{again}");

    let review = ok(&mut env, &format!("review {KQTF}"));
    assert!(review.contains("CHANGED LINES (LEFT)"), "{review}");
    assert!(review.contains("M.A.1 · Rreport"), "{review}");
    assert!(review.contains("-    1 | totals: 100"), "{review}");
    assert!(review.contains("+    1 | totals: 125"), "{review}");
    assert!(review.contains("CHANGED LINES (RIGHT)"), "{review}");
    assert!(review.contains("M.S.1 · Rreport"), "{review}");
    assert!(review.contains("+    1 | totals: 130"), "{review}");
    assert!(
        review.contains("merge  RequiresHuman (OVERLAPPING_EDIT)"),
        "{review}"
    );
    assert!(
        review.contains("review M.A (PriorNeutralOwner)"),
        "{review}"
    );
}

#[test]
fn the_assigned_reviewer_resolves_a_conflict_and_signs_the_result() {
    let mut env = org();
    forked(&mut env, "totals: 100\n", "totals: 125\n", "totals: 130\n");
    ok(&mut env, &format!("merge {KQTF} --as M.A"));

    // The conflicting authors and a stranger may not decide it.
    for who in ["M.A.1", "M.S.1", "M.B"] {
        let (result, _) = run(
            &mut env,
            &format!(
                "resolve {KQTF} --keep right --as {who} --slot {}",
                slot(who)
            ),
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not the reviewer"), "{who}: {err}");
    }
    // The assigned reviewer keeps the right side; the result is theirs,
    // signed, and trusted under the file's rules.
    let out = ok(
        &mut env,
        &format!(
            "resolve {KQTF} --keep right --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(!graph.contains("FORK"), "{graph}");
    ok(
        &mut env,
        &format!("checkout {KQTF} --out /work/resolved.txt"),
    );
    assert_eq!(
        env.fs.read(Path::new("/work/resolved.txt")).unwrap(),
        b"totals: 130\n"
    );
    let history = ok(&mut env, &format!("history {KQTF}"));
    let line = history
        .lines()
        .find(|l| l.contains("ConflictResolved"))
        .expect("a recorded resolution");
    assert!(
        line.contains("by M.A") && line.contains("resolution=KEEP_RIGHT"),
        "{history}"
    );
    // Nothing is left to resolve.
    let (result, _) = run(
        &mut env,
        &format!("resolve {KQTF} --keep left --as M.A --slot {}", slot("M.A")),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("nothing to resolve"));
}

#[test]
fn a_reviewer_can_supply_an_edited_result_and_a_wrong_key_is_refused() {
    let mut env = org();
    forked(&mut env, "totals: 100\n", "totals: 125\n", "totals: 130\n");
    ok(&mut env, &format!("merge {KQTF} --as M.A"));
    env.fs
        .write(Path::new("/work/decided.txt"), b"totals: 128\n")
        .unwrap();
    // Another label's key is not M.A's: nothing is written.
    let before = env.fs.read(Path::new(KQTF)).unwrap();
    let (result, _) = run(
        &mut env,
        &format!(
            "resolve {KQTF} --from /work/decided.txt --as M.A --slot {}",
            slot("M.B")
        ),
    );
    assert!(result.is_err());
    assert_eq!(env.fs.read(Path::new(KQTF)).unwrap(), before);
    let out = ok(
        &mut env,
        &format!(
            "resolve {KQTF} --from /work/decided.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
    ok(
        &mut env,
        &format!("checkout {KQTF} --out /work/resolved.txt"),
    );
    assert_eq!(
        env.fs.read(Path::new("/work/resolved.txt")).unwrap(),
        b"totals: 128\n"
    );
    assert!(ok(&mut env, &format!("history {KQTF}")).contains("resolution=EDITED"));
}

#[test]
fn a_rejected_proposed_merge_is_never_signed_and_the_reviewer_settles_it() {
    let mut env = org();
    forked(
        &mut env,
        "north\n100\nsouth\n",
        "north\n125\nsouth\n",
        "north\n100\nsouth-east\n",
    );
    // M.A.1 proposes the clean merge.
    let out = ok(&mut env, &format!("merge {KQTF} --as M.A.1"));
    assert!(out.contains("CleanMerge"), "{out}");
    // A conflicting author may not reject it; the scope owner may.
    let (result, _) = run(
        &mut env,
        &format!(
            "resolve {KQTF} --reject --as M.S.1 --slot {}",
            slot("M.S.1")
        ),
    );
    assert!(result.is_err());
    let out = ok(
        &mut env,
        &format!("resolve {KQTF} --reject --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("Rejected merge"), "{out}");
    // Rejected once is enough, and its author can no longer sign it.
    let (result, _) = run(
        &mut env,
        &format!("resolve {KQTF} --reject --as M.A --slot {}", slot("M.A")),
    );
    assert!(result.is_err());
    let (result, _) = run(
        &mut env,
        &format!("sign {KQTF} --as M.A.1 --slot {}", slot("M.A.1")),
    );
    assert!(result.unwrap_err().to_string().contains("rejected"));
    // The reviewer settles it on top of the rejected proposal.
    let out = ok(
        &mut env,
        &format!("resolve {KQTF} --keep left --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
    ok(
        &mut env,
        &format!("checkout {KQTF} --out /work/resolved.txt"),
    );
    assert_eq!(
        env.fs.read(Path::new("/work/resolved.txt")).unwrap(),
        b"north\n125\nsouth\n"
    );
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("MergeRejected Denied by M.A"), "{history}");
    assert!(history.contains("resolution=KEEP_LEFT"), "{history}");
}

#[test]
fn only_a_bridges_signed_approval_of_the_revision_authorizes_a_cross_branch_edit() {
    let mut env = org();
    for (dir, label) in [("m", "M"), ("ms1", "M.S.1"), ("ma", "M.A"), ("mb", "M.B")] {
        let (result, out) = env.keyquorum(&format!(
            "keyquorum {DB} device register /usb/{dir} --slot {label} --type encryption"
        ));
        assert!(result.is_ok(), "{out}");
    }
    // A tree whose sibling leaves M.S and M.A are bound (a live tree link).
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {DB} split --label M --leaf M.S=/keys/ms.pub --leaf M.A=/keys/ma.pub \
         --generate-keys --register"
    ));
    assert!(result.is_ok(), "{result:?} {out}");
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: 110\n");
    let out = ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.S.1 --slot {}",
            slot("M.S.1")
        ),
    );
    // A bridge merely existing between the labels approves nothing.
    assert!(
        out.contains("trust PENDING (MissingBridgeOrOwnerApproval)"),
        "{out}"
    );
    let create = |env: &mut MemoryEnv, members: &str, dir: &str| {
        let out = ok_keyquorum(
            env,
            &format!(
                "bridge private create 1 {members} --supervisor M.S=/keys/ms.pub --self M.S.1 \
                 --output-dir {dir}"
            ),
        );
        out.split_whitespace()
            .nth(3)
            .expect("the bridge uid")
            .to_string()
    };
    // A private bridge from M.S.1 to someone off the scope's line (M.B):
    // its approval is signed and kept, but does not reach M.A's file.
    let elsewhere = create(&mut env, "--member M.S.1 --member M.B", "/pb/b");
    let out = ok(
        &mut env,
        &format!(
            "bridge-approve {KQTF} --bridge {elsewhere} --as M.S.1 --slot {}",
            slot("M.S.1")
        ),
    );
    assert!(out.contains("trust PENDING"), "{out}");
    // A private bridge from M.S.1 to M.A does.
    let reaching = create(&mut env, "--member M.S.1 --member M.A", "/pb/a");
    let out = ok(
        &mut env,
        &format!(
            "bridge-approve {KQTF} --bridge {reaching} --as M.S.1 --slot {}",
            slot("M.S.1")
        ),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(
        history.contains("reason=AUTHOR_SIGNATURE + BRIDGE_OR_SCOPE_OWNER_APPROVAL"),
        "{history}"
    );
    assert!(history.contains("satisfied_by=BRIDGE"), "{history}");
    // The private bridge is never named in the file, nor in its history.
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    for uid in [&reaching, &elsewhere] {
        assert!(!history.contains(uid.as_str()), "{history}");
        assert!(!bytes.windows(uid.len()).any(|w| w == uid.as_bytes()));
    }
    // A bridge generation change (a membership rotation) voids the approval
    // until the bridge approves again: it is live evidence, not stored trust.
    env.store("/home/org/keyquorum.sqlite")
        .execute("UPDATE private_bridges SET generation = generation + 1", [])
        .unwrap();
    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(graph.contains("MissingBridgeOrOwnerApproval"), "{graph}");
}

#[test]
fn cross_branch_policy_history_names_scope_owner_without_exposing_bridge_details() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: 115\n");
    let out = ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.S.1 --slot {}",
            slot("M.S.1")
        ),
    );
    assert!(out.contains("MissingBridgeOrOwnerApproval"), "{out}");

    ok(
        &mut env,
        &format!("countersign {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("satisfied_by=SCOPE_OWNER"), "{history}");
    assert!(!history.contains("bridge_id="), "{history}");
}

#[test]
fn a_restructure_keeps_recorded_generations_judged_and_unknown_ones_pending() {
    let mut env = org();
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {DB} split --label M --leaf M.S=/keys/ms.pub --leaf M.A=/keys/ma.pub \
         --generate-keys --register"
    ));
    assert!(result.is_ok(), "{result:?} {out}");
    track(&mut env, "M.A", "M.A");
    // The revision is stamped with the tree's generation, not 0.
    let generation: i64 = env
        .store("/home/org/keyquorum.sqlite")
        .query_row(
            "SELECT public_generation FROM keys WHERE label = 'M'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(generation > 0);
    let sql = |env: &mut MemoryEnv, statement: &str| {
        env.store("/home/org/keyquorum.sqlite")
            .execute(statement, [])
            .unwrap();
    };
    // A restructure moves the tree on; the revision's generation was held
    // here when it was made, so it is still judged.
    sql(
        &mut env,
        "UPDATE keys SET public_generation = public_generation + 1 WHERE label = 'M'",
    );
    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(graph.contains("TRUSTED"), "{graph}");
    // A store that never held that generation does not judge it by today's
    // topology: it stays pending.
    sql(&mut env, "DELETE FROM tree_generations_seen");
    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(graph.contains("MissingTopologyEvidence"), "{graph}");
}

#[test]
fn a_command_that_proves_the_key_signs_its_event_and_history_says_where_it_verifies() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    ok(
        &mut env,
        &format!("rename {KQTF} summary.txt --as M.A --slot {}", slot("M.A")),
    );
    let history = ok(&mut env, &format!("history {KQTF}"));
    let renamed = history
        .lines()
        .find(|l| l.contains("FileRenamed"))
        .expect("a rename");
    assert!(renamed.ends_with("[signed by M.A]"), "{history}");
    // Events no command signed stay plain hash-chained records.
    let started = history
        .lines()
        .find(|l| l.contains("TrackingStarted"))
        .unwrap();
    assert!(!started.contains("[signed"), "{history}");
    // A store that never met M.A cannot vouch for the signature.
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs
        .write(Path::new("/elsewhere/r.kqtf"), &bytes)
        .unwrap();
    let (result, out) =
        env.keyquorum("keyquorum --db /elsewhere/keyquorum.sqlite file history /elsewhere/r.kqtf");
    assert!(result.is_ok(), "{out}");
    assert!(
        out.contains("FileRenamed") && out.contains("[signature not verified in this store]"),
        "{out}"
    );
}

#[test]
fn merge_and_review_need_a_fork() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let (result, _) = run(&mut env, &format!("merge {KQTF} --as M.A"));
    assert!(result.unwrap_err().to_string().contains("nothing to merge"));
    let review = ok(&mut env, &format!("review {KQTF}"));
    assert!(review.contains("Nothing to review"), "{review}");
    // An author outside the scope may not merge either.
    let (result, _) = run(&mut env, &format!("merge {KQTF} --as X.1"));
    assert!(result.is_err());
}

#[test]
fn diff_shows_removed_then_added_lines() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: 125\n");
    ok(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A --unsigned"),
    );
    let out = ok(&mut env, &format!("diff {KQTF}"));
    assert!(out.contains("-    1 | totals: 100"), "{out}");
    assert!(out.contains("+    1 | totals: 125"), "{out}");
    // Against the empty text for the root revision.
    let root = ok(&mut env, &format!("verify {KQTF}"));
    let first = root
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let out = ok(&mut env, &format!("diff {KQTF} --to {first}"));
    assert!(out.contains("(empty) →"), "{out}");
    assert!(out.contains("+    1 | totals: 100"), "{out}");
}

#[test]
fn checkout_writes_the_shareable_revision_and_never_overwrites() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: 125\n");
    ok(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A --unsigned"),
    );
    // The head is unsigned, so the shareable revision is the trusted first one.
    ok(
        &mut env,
        &format!("checkout {KQTF} --shareable --out /work/shared.txt"),
    );
    assert_eq!(
        env.fs.read(Path::new("/work/shared.txt")).unwrap(),
        b"totals: 100\n"
    );
    ok(&mut env, &format!("checkout {KQTF} --out /work/head.txt"));
    assert_eq!(
        env.fs.read(Path::new("/work/head.txt")).unwrap(),
        b"totals: 125\n"
    );
    let (result, _) = run(&mut env, &format!("checkout {KQTF} --out /work/head.txt"));
    assert!(result.is_err(), "refuses to overwrite");
    // A forked history has no single head to check out by default.
    let mut env = org();
    forked(&mut env, "a\n", "b\n", "c\n");
    let (result, _) = run(&mut env, &format!("checkout {KQTF} --out /work/x.txt"));
    assert!(result.unwrap_err().to_string().contains("forked"));
    assert!(!env.fs.exists(Path::new("/work/x.txt")));
}

// ---- the index -------------------------------------------------------------

fn wipe_index(env: &MemoryEnv) {
    let conn = env.store("/home/org/keyquorum.sqlite");
    conn.execute("DELETE FROM tracked_files", []).unwrap();
}

#[test]
fn commands_keep_the_index_current_and_reindex_restores_it() {
    let mut env = org();
    assert!(ok(&mut env, "list").contains("No tracked files are indexed"));
    track(&mut env, "M.A", "M.A");
    let listed = ok(&mut env, "list");
    assert!(listed.contains("report.txt ("), "{listed}");
    assert!(
        listed.contains("scope M.A · heads 1 · events 3"),
        "{listed}"
    );

    edit(&mut env, "totals: 125\n");
    ok(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A --unsigned"),
    );
    let after = ok(&mut env, "list");
    assert!(after.contains("heads 1 · events 5"), "{after}");

    // The index is only a cache: losing it changes nothing about the file.
    wipe_index(&env);
    assert!(ok(&mut env, "list").contains("No tracked files are indexed"));
    let out = ok(&mut env, &format!("reindex {KQTF}"));
    assert!(out.contains("Indexed 1 file(s)"), "{out}");
    assert_eq!(ok(&mut env, "list"), after);
    // Reindexing twice does not duplicate anything.
    ok(&mut env, &format!("reindex {KQTF}"));
    assert_eq!(ok(&mut env, "list"), after);
}

#[test]
fn reindex_verifies_first_and_changes_nothing_on_failure() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let before = ok(&mut env, "list");
    let path = Path::new(KQTF);
    let mut bytes = env.fs.read(path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    env.fs.write(Path::new("/work/bad.kqtf"), &bytes).unwrap();
    let (result, _) = run(&mut env, &format!("reindex {KQTF} /work/bad.kqtf --clear"));
    assert!(result.is_err());
    assert_eq!(ok(&mut env, "list"), before, "nothing was touched");
}

#[test]
fn reindex_clear_drops_rows_for_files_not_named() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    env.store("/home/org/keyquorum.sqlite")
        .execute(
            "INSERT INTO tracked_files
                 (file_id, logical_name, scope_root, history_root, head_count, event_count)
             VALUES (?1, 'stale.txt', NULL, ?2, 1, 1)",
            rusqlite::params![vec![9u8; 16], vec![0u8; 32]],
        )
        .unwrap();
    assert!(ok(&mut env, "list").contains("stale.txt"));
    ok(&mut env, &format!("reindex {KQTF}"));
    assert!(
        ok(&mut env, "list").contains("stale.txt"),
        "without --clear it stays"
    );
    ok(&mut env, &format!("reindex {KQTF} --clear"));
    let listed = ok(&mut env, "list");
    assert!(!listed.contains("stale.txt"), "{listed}");
    assert!(listed.contains("report.txt"));
}

#[test]
fn a_forked_file_is_indexed_with_both_heads() {
    let mut env = org();
    forked(&mut env, "a\nb\n", "A\nb\n", "a\nB\n");
    ok(&mut env, &format!("reindex {KQTF}"));
    assert!(ok(&mut env, "list").contains("heads 2"));
}

#[test]
fn a_file_that_disables_auto_merge_sends_every_fork_to_a_person() {
    let mut env = org();
    // These edits would merge cleanly under the default policy.
    forked_with(
        &mut env,
        "north\n100\nsouth\n",
        "north\n125\nsouth\n",
        "north\n100\nsouth-east\n",
        "--no-auto-merge",
    );
    let out = ok(&mut env, &format!("merge {KQTF} --as M.A"));
    assert!(out.contains("PolicyBlocked (AUTO_MERGE_DISABLED)"), "{out}");
    assert!(out.contains("review assigned to M.A"), "{out}");
    let graph = ok(&mut env, &format!("graph {KQTF}"));
    assert!(
        graph.contains("FORK: 2 heads"),
        "no revision was made: {graph}"
    );
    let review = ok(&mut env, &format!("review {KQTF}"));
    assert!(
        review.contains("merge  PolicyBlocked (AUTO_MERGE_DISABLED)"),
        "{review}"
    );
    assert!(
        review.contains("review M.A (PriorNeutralOwner)"),
        "{review}"
    );
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("AutoMergeBlocked"), "{history}");
    assert!(history.contains("ConflictReviewAssigned"), "{history}");
    // The default policy still merges the same edits.
    let mut env = org();
    forked(
        &mut env,
        "north\n100\nsouth\n",
        "north\n125\nsouth\n",
        "north\n100\nsouth-east\n",
    );
    assert!(ok(&mut env, &format!("merge {KQTF} --as M.A")).contains("CleanMerge"));
}

#[test]
fn review_still_names_the_reviewer_when_a_diff_is_too_large() {
    let mut env = org();
    let lines = |word: &str| -> String { (0..3000).map(|i| format!("{word} {i}\n")).collect() };
    forked(&mut env, &lines("base"), &lines("left"), &lines("right"));
    let review = ok(&mut env, &format!("review {KQTF}"));
    assert_eq!(
        review
            .matches("(too large to compare: no line view)")
            .count(),
        2,
        "{review}"
    );
    assert!(
        review.contains("merge  UnsupportedContent (TOO_LARGE)"),
        "{review}"
    );
    assert!(
        review.contains("review M.A (PriorNeutralOwner)"),
        "{review}"
    );
    let out = ok(&mut env, &format!("merge {KQTF} --as M.A"));
    assert!(out.contains("UnsupportedContent (TOO_LARGE)"), "{out}");
}

// ---- import and snapshots --------------------------------------------------

const COPY: &str = "/work/copy.kqtf";

/// Track a three-line file as M.A and give a second holder a copy of it.
fn two_copies(env: &mut MemoryEnv) {
    env.fs
        .write(Path::new("/work/report.txt"), b"a\nb\nc\n")
        .unwrap();
    track(env, "M.A", "M.A");
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new(COPY), &bytes).unwrap();
}

fn checkin_unsigned(env: &mut MemoryEnv, container: &str, text: &str) {
    edit(env, text);
    ok(
        env,
        &format!("checkin {container} --from /work/edited.txt --as M.A --unsigned"),
    );
}

#[test]
fn diverged_copies_import_merge_and_converge() {
    let mut env = org();
    two_copies(&mut env);
    checkin_unsigned(&mut env, KQTF, "A\nb\nc\n");
    checkin_unsigned(&mut env, COPY, "a\nb\nC\n");

    let out = ok(&mut env, &format!("import {KQTF} --from {COPY} --as M.A"));
    assert!(
        out.contains("Imported: Diverged; 1 revision(s) and 0 proof(s) added"),
        "{out}"
    );
    assert!(out.contains("The history has forked"), "{out}");
    assert!(ok(&mut env, &format!("graph {KQTF}")).contains("FORK: 2 heads"));
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("HistoryImported"), "{history}");
    assert!(history.contains("relation=Diverged"), "{history}");
    assert!(
        ok(&mut env, "list").contains("heads 2"),
        "the index follows an import"
    );

    let out = ok(&mut env, &format!("merge {KQTF} --as M.A"));
    assert!(out.contains("CleanMerge"), "{out}");
    ok(&mut env, &format!("checkout {KQTF} --out /work/merged.txt"));
    assert_eq!(
        env.fs.read(Path::new("/work/merged.txt")).unwrap(),
        b"A\nb\nC\n"
    );
    let out = ok(
        &mut env,
        &format!("sign {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
}

#[test]
fn a_copy_that_is_ahead_fast_forwards() {
    let mut env = org();
    two_copies(&mut env);
    checkin_unsigned(&mut env, COPY, "a\nB\nc\n");
    let out = ok(&mut env, &format!("import {KQTF} --from {COPY} --as M.A"));
    assert!(
        out.contains("Imported: RemoteAhead; 1 revision(s)"),
        "{out}"
    );
    assert!(!out.contains("forked"), "{out}");
    ok(&mut env, &format!("checkout {KQTF} --out /work/head.txt"));
    assert_eq!(
        env.fs.read(Path::new("/work/head.txt")).unwrap(),
        b"a\nB\nc\n"
    );
}

#[test]
fn importing_what_is_already_here_does_nothing() {
    let mut env = org();
    two_copies(&mut env);
    let before = env.fs.read(Path::new(KQTF)).unwrap();
    let out = ok(&mut env, &format!("import {KQTF} --from {COPY} --as M.A"));
    assert!(out.contains("Nothing new to import (Identical)"), "{out}");
    assert_eq!(env.fs.read(Path::new(KQTF)).unwrap(), before);
    // A copy that is behind is a no-op too.
    checkin_unsigned(&mut env, KQTF, "x\nb\nc\n");
    let ahead = env.fs.read(Path::new(KQTF)).unwrap();
    let out = ok(&mut env, &format!("import {KQTF} --from {COPY} --as M.A"));
    assert!(out.contains("(LocalAhead)"), "{out}");
    assert_eq!(env.fs.read(Path::new(KQTF)).unwrap(), ahead);
}

#[test]
fn import_refuses_other_files_bad_copies_and_bad_authors() {
    let mut env = org();
    two_copies(&mut env);
    let before = env.fs.read(Path::new(KQTF)).unwrap();
    // A different tracked file is not a copy of this one.
    env.fs.write(Path::new("/work/other.txt"), b"x\n").unwrap();
    ok(
        &mut env,
        &format!(
            "track /work/other.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let (result, _) = run(
        &mut env,
        &format!("import {KQTF} --from /work/other.txt.kqtf --as M.A"),
    );
    assert!(result.unwrap_err().to_string().contains("not another copy"));
    // A copy that fails verification.
    let mut bytes = env.fs.read(Path::new(COPY)).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    env.fs.write(Path::new("/work/bad.kqtf"), &bytes).unwrap();
    let (result, _) = run(
        &mut env,
        &format!("import {KQTF} --from /work/bad.kqtf --as M.A"),
    );
    assert!(result.is_err());
    // An importer outside the file's scope.
    let (result, _) = run(&mut env, &format!("import {KQTF} --from {COPY} --as X.1"));
    assert!(result.is_err());
    assert_eq!(env.fs.read(Path::new(KQTF)).unwrap(), before);
}

#[test]
fn a_snapshot_exports_verifies_and_matches_its_file() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let out = ok(
        &mut env,
        &format!("history {KQTF} --export /work/snap.kqhs"),
    );
    assert_eq!(out.lines().count(), 3, "the listing is unchanged: {out}");
    assert!(env.fs.exists(Path::new("/work/snap.kqhs")));

    let out = ok(&mut env, "verify-snapshot /work/snap.kqhs");
    assert!(out.starts_with("Snapshot verifies: file "), "{out}");
    assert!(out.contains("3 event(s)"), "{out}");
    let out = ok(
        &mut env,
        &format!("verify-snapshot /work/snap.kqhs --against {KQTF}"),
    );
    assert!(
        out.contains("It is a point in the history of report.txt"),
        "{out}"
    );

    // The file moves on; the earlier snapshot is still a point in its history.
    edit(&mut env, "totals: 125\n");
    ok(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A --unsigned"),
    );
    ok(
        &mut env,
        &format!("verify-snapshot /work/snap.kqhs --against {KQTF}"),
    );

    // It is not a point in some other file's history, and a damaged snapshot
    // does not verify.
    env.fs.write(Path::new("/work/other.txt"), b"x\n").unwrap();
    ok(
        &mut env,
        &format!(
            "track /work/other.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let (result, _) = run(
        &mut env,
        "verify-snapshot /work/snap.kqhs --against /work/other.txt.kqtf",
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not a point in the history"));
    let mut bytes = env.fs.read(Path::new("/work/snap.kqhs")).unwrap();
    bytes[10] ^= 1;
    env.fs.write(Path::new("/work/bad.kqhs"), &bytes).unwrap();
    let (result, _) = run(&mut env, "verify-snapshot /work/bad.kqhs");
    assert!(result.is_err());
    // Exporting never overwrites.
    let (result, _) = run(
        &mut env,
        &format!("history {KQTF} --export /work/snap.kqhs"),
    );
    assert!(result.is_err());
}

#[test]
fn export_tracked_file_seals_the_complete_binary_kqtf() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let original = env.fs.read(Path::new(KQTF)).unwrap();
    assert!(std::str::from_utf8(&original).is_err());

    let recipient = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    env.fs
        .write_new(
            Path::new("/keys/recipient.pub"),
            hex::encode(recipient.public_key().as_bytes()).as_bytes(),
        )
        .unwrap();
    ok_keyquorum(
        &mut env,
        &format!(
            "export tracked-file {KQTF} --recipient-key-file /keys/recipient.pub \
             --output /work/report.kqxb"
        ),
    );

    let bundle = env.fs.read(Path::new("/work/report.kqxb")).unwrap();
    assert_eq!(&bundle[..6], b"KQXB\x01\x03");
    let sealed_len = u32::from_be_bytes(bundle[38..42].try_into().unwrap()) as usize;
    let plaintext = recipient.unseal(&bundle[42..42 + sealed_len]).unwrap();
    let name_len = u16::from_be_bytes(plaintext[..2].try_into().unwrap()) as usize;
    assert_eq!(&plaintext[2..2 + name_len], b"report.txt");
    assert_eq!(&plaintext[2 + name_len..], original);
}

// ---- tracked delivery ------------------------------------------------------

pub(super) fn dir_file(env: &MemoryEnv, dir: &str) -> String {
    let files = env.fs.list(Path::new(dir)).unwrap_or_default();
    assert_eq!(files.len(), 1, "{dir}: {files:?}");
    files[0].display().to_string()
}

/// M.A tracks `report.txt`; M.B can receive letters in the org store.
fn delivering() -> MemoryEnv {
    let mut env = org();
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} device register /usb/mb --slot M.B --type encryption"
    ));
    assert!(result.is_ok());
    track(&mut env, "M.A", "M.A");
    env
}

fn share_to_mb(env: &mut MemoryEnv, extra: &str) -> (crate::error::Result<()>, String) {
    run(
        env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out {extra}",
            slot("M.A")
        ),
    )
}

fn receive_as_mb(env: &mut MemoryEnv, extra: &str) -> (crate::error::Result<()>, String) {
    let letter = dir_file(env, "/out");
    run(
        env,
        &format!(
            "receive --letter {letter} --slot {} --ack-dir /acks {extra}",
            slot("M.B")
        ),
    )
}

#[test]
fn a_trusted_revision_is_delivered_accepted_and_acknowledged() {
    let mut env = delivering();
    let out = ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    assert!(out.contains("CurrentTrustedRevision"), "{out}");

    let letter = dir_file(&env, "/out");
    let (result, out) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    assert!(result.is_ok(), "{result:?}\n{out}");
    assert!(env.fs.exists(Path::new("/work/received.kqtf")));
    let verify = ok(&mut env, "verify /work/received.kqtf");
    assert!(verify.contains("TRUSTED"), "{verify}");
    let history = ok(&mut env, "history /work/received.kqtf");
    assert!(
        history.contains("ShareDelivered Success by M.B"),
        "{history}"
    );

    // The sender records the answer once, and only against its own delivery.
    let ack = dir_file(&env, "/acks");
    let out = ok(
        &mut env,
        &format!("ack {KQTF} --ack {ack} --slot {}", slot("M.A")),
    );
    assert!(out.contains("accepted by M.B"), "{out}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("ShareAttempted"), "{history}");
    assert!(history.contains("ShareDelivered"), "{history}");
    let again = ok(
        &mut env,
        &format!("ack {KQTF} --ack {ack} --slot {}", slot("M.A")),
    );
    assert!(again.contains("already recorded"), "{again}");
    assert_eq!(
        ok(&mut env, &format!("history {KQTF}"))
            .matches("ShareDelivered")
            .count(),
        1
    );
    // The letter is opaque: the payload is not readable in it.
    let bytes = env.fs.read(Path::new(&letter)).unwrap();
    assert!(!bytes.windows(11).any(|w| w == b"totals: 100"));
}

#[test]
fn receiving_the_same_letter_again_does_not_record_the_delivery_twice() {
    let mut env = delivering();
    ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    let (result, out) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    assert!(result.is_ok(), "{out}");
    // The acknowledgement was lost, so the recipient runs it again against
    // the copy it already holds.
    env.fs.delete(Path::new(&dir_file(&env, "/acks"))).unwrap();
    let (result, out) = receive_as_mb(&mut env, "--into /work/received.kqtf");
    assert!(result.is_ok(), "{result:?}\n{out}");
    assert!(out.contains("already recorded"), "{out}");
    let history = ok(&mut env, "history /work/received.kqtf");
    assert_eq!(history.matches("ShareDelivered").count(), 1, "{history}");
    // The acknowledgement is sealed again, so the sender can still get it.
    assert!(env.fs.exists(Path::new(&dir_file(&env, "/acks"))));
}

#[test]
fn receiving_the_same_letter_to_the_same_out_file_resends_only_the_answer() {
    let mut env = delivering();
    ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    let (result, out) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    assert!(result.is_ok(), "{out}");
    let before = env.fs.read(Path::new("/work/received.kqtf")).unwrap();
    env.fs.delete(Path::new(&dir_file(&env, "/acks"))).unwrap();
    let (result, out) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    assert!(result.is_ok(), "{result:?}\n{out}");
    assert!(out.contains("already saved"), "{out}");
    assert_eq!(
        env.fs.read(Path::new("/work/received.kqtf")).unwrap(),
        before
    );
    assert!(env.fs.exists(Path::new(&dir_file(&env, "/acks"))));

    // An unrelated file at --out is still refused.
    env.fs
        .write(Path::new("/work/other.kqtf"), b"not this file")
        .unwrap();
    let (result, _) = receive_as_mb(&mut env, "--out /work/other.kqtf");
    assert!(result.is_err());
}

#[test]
fn a_receiver_records_whether_each_history_is_newer_than_what_it_accepted() {
    use crate::file_history::TrackedFile;
    let mut env = delivering();
    let first = TrackedFile::decode(&env.fs.read(Path::new(KQTF)).unwrap())
        .unwrap()
        .graph()
        .heads()[0];
    let fresh_of = |env: &mut MemoryEnv| {
        let history = ok(env, "history /work/r.kqtf");
        history
            .lines()
            .rfind(|l| l.contains("ShareDelivered"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("freshness=")))
            .map(str::to_string)
            .expect("a recorded delivery")
    };
    let clear = |env: &mut MemoryEnv| {
        for dir in ["/out", "/acks"] {
            for file in env.fs.list(Path::new(dir)).unwrap_or_default() {
                env.fs.delete(&file).unwrap();
            }
        }
    };
    let (result, out) = share_to_mb(&mut env, "");
    assert!(result.is_ok(), "{out}");
    let (result, out) = receive_as_mb(&mut env, "--out /work/r.kqtf");
    assert!(result.is_ok(), "{out}");
    assert_eq!(fresh_of(&mut env), "freshness=FIRST");
    clear(&mut env);

    // A newer signed revision: its history holds what was accepted before.
    edit(&mut env, "totals: 200\n");
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    share_to_mb(&mut env, "").0.unwrap();
    let (result, out) = receive_as_mb(&mut env, "--into /work/r.kqtf");
    assert!(result.is_ok(), "{out}");
    assert_eq!(fresh_of(&mut env), "freshness=NEWER");
    clear(&mut env);

    // The first revision re-sent: accepted (it is trusted), but never
    // called newer.
    share_to_mb(&mut env, &format!("--revision {}", hex::encode(first)))
        .0
        .unwrap();
    let (result, out) = receive_as_mb(&mut env, "--into /work/r.kqtf");
    assert!(result.is_ok(), "{out}");
    assert_eq!(fresh_of(&mut env), "freshness=NOT_NEWER");
}

#[test]
fn a_newer_revision_on_a_rewritten_event_chain_is_not_called_newer() {
    let mut env = delivering();
    let before = env.fs.read(Path::new(KQTF)).unwrap();
    let freshness = |env: &mut MemoryEnv, path: &str| {
        let history = ok(env, &format!("history {path}"));
        history
            .lines()
            .rfind(|l| l.contains("ShareDelivered"))
            .and_then(|l| l.split_whitespace().find(|w| w.starts_with("freshness=")))
            .map(str::to_string)
            .expect("a recorded delivery")
    };
    let clear = |env: &mut MemoryEnv| {
        for dir in ["/out", "/acks"] {
            for file in env.fs.list(Path::new(dir)).unwrap_or_default() {
                env.fs.delete(&file).unwrap();
            }
        }
    };
    // M.B accepts R1 after a rename to a.txt.
    ok(
        &mut env,
        &format!("rename {KQTF} a.txt --as M.A --slot {}", slot("M.A")),
    );
    share_to_mb(&mut env, "").0.unwrap();
    let (result, out) = receive_as_mb(&mut env, "--out /work/r.kqtf");
    assert!(result.is_ok(), "{out}");
    assert_eq!(freshness(&mut env, "/work/r.kqtf"), "freshness=FIRST");
    clear(&mut env);

    // The sender's copy from before that rename takes another event chain
    // (renamed to b.txt instead) and adds R2 on top of the same R1. The
    // revisions extend what M.B accepted; the event history does not.
    env.fs.delete(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new(KQTF), &before).unwrap();
    ok(
        &mut env,
        &format!("rename {KQTF} b.txt --as M.A --slot {}", slot("M.A")),
    );
    edit(&mut env, "totals: 200\n");
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    share_to_mb(&mut env, "").0.unwrap();
    let (result, out) = receive_as_mb(&mut env, "--out /work/r2.kqtf");
    assert!(result.is_ok(), "{out}");
    assert_eq!(freshness(&mut env, "/work/r2.kqtf"), "freshness=NOT_NEWER");
}

#[test]
fn a_received_file_answers_its_provenance_without_the_senders_store() {
    let mut env = delivering();
    share_to_mb(&mut env, "").0.unwrap();
    let (result, out) = receive_as_mb(&mut env, "--out /work/r.kqtf");
    assert!(result.is_ok(), "{out}");
    // A store that has never met the sender: an empty database.
    let bytes = env.fs.read(Path::new("/work/r.kqtf")).unwrap();
    env.fs
        .write(Path::new("/elsewhere/r.kqtf"), &bytes)
        .unwrap();
    let elsewhere = "--db /elsewhere/keyquorum.sqlite";
    let run_elsewhere = |env: &mut MemoryEnv, args: &str| {
        let (result, out) = env.keyquorum(&format!("keyquorum {elsewhere} file {args}"));
        assert!(result.is_ok(), "{args}: {result:?}\n{out}");
        out
    };
    // Who edited and signed it, under which rules, and whether the history
    // is intact, all from the container itself.
    let history = run_elsewhere(&mut env, "history /elsewhere/r.kqtf");
    assert!(
        history.contains("TrackingStarted Success by M.A"),
        "{history}"
    );
    assert!(
        history.contains("RevisionSigned Success by M.A"),
        "{history}"
    );
    assert!(
        history.contains("ShareDelivered Success by M.B"),
        "{history}"
    );
    let policy = run_elsewhere(&mut env, "policy /elsewhere/r.kqtf");
    assert!(policy.contains("M.A"), "{policy}");
    // The structure verifies anywhere; trust is this store's to judge, and
    // without M.A's key it is not trusted here, so `verify` says so and fails.
    let (result, verify) = env.keyquorum(&format!(
        "keyquorum {elsewhere} file verify /elsewhere/r.kqtf"
    ));
    assert!(result.is_err());
    assert!(
        verify.contains("History and revision graph verify"),
        "{verify}"
    );
    assert!(verify.contains("DENIED (UnknownSigner)"), "{verify}");
}

#[test]
fn a_signed_history_snapshot_tells_the_receiver_how_their_copy_compares() {
    let mut env = delivering();
    share_to_mb(&mut env, "").0.unwrap();
    let (result, out) = receive_as_mb(&mut env, "--out /work/r.kqtf");
    assert!(result.is_ok(), "{out}");
    // The sender's history moves on; they send its snapshot, not content.
    edit(&mut env, "totals: 300\n");
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let out = ok(
        &mut env,
        &format!(
            "send-history {KQTF} --to M.B --as M.A --slot {} --output-dir /hist",
            slot("M.A")
        ),
    );
    assert!(out.contains("Sealed the history of report.txt"), "{out}");
    let letter = dir_file(&env, "/hist");
    let bytes = env.fs.read(Path::new(&letter)).unwrap();
    assert!(!bytes.windows(11).any(|w| w == b"totals: 300"));
    // The receiver's copy has a delivery event the sender's lacks, so the
    // two histories have diverged; against the sender's own copy it is the
    // same history.
    let open = |env: &mut MemoryEnv, against: &str| {
        ok(
            env,
            &format!(
                "open-history --letter {letter} --slot {} --against {against}",
                slot("M.B")
            ),
        )
    };
    let out = open(&mut env, "/work/r.kqtf");
    assert!(out.contains("sender signature verified"), "{out}");
    assert!(out.contains("DIVERGED"), "{out}");
    let out = open(&mut env, KQTF);
    assert!(out.contains(": SAME"), "{out}");
    // A snapshot of an older point is behind a copy that moved on.
    edit(&mut env, "totals: 400\n");
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let out = open(&mut env, KQTF);
    assert!(out.contains("LOCAL_AHEAD"), "{out}");
    // Only the addressed label's key opens it.
    let (result, _) = run(
        &mut env,
        &format!("open-history --letter {letter} --slot {}", slot("M.A")),
    );
    assert!(result.is_err());
}

#[test]
fn an_untrusted_newer_revision_is_never_sent() {
    let mut env = delivering();
    edit(&mut env, "totals: SECRETNEWER\n");
    ok(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A --unsigned"),
    );
    let out = ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    assert!(out.contains("LastTrustedRevision"), "{out}");
    assert!(out.contains("is not trusted, so it was left out"), "{out}");
    // The sender's history names the candidate and why it was left out.
    let history = ok(&mut env, &format!("history {KQTF}"));
    let line = history
        .lines()
        .find(|l| l.contains("ShareAttempted"))
        .expect("a recorded share");
    assert!(
        line.contains("candidate=") && line.contains("fallback_reason=MISSINGCONTENTSIGNATURE"),
        "{history}"
    );
    let (result, out) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    assert!(result.is_ok(), "{out}");
    let received = env.fs.read(Path::new("/work/received.kqtf")).unwrap();
    assert!(!received.windows(9).any(|w| w == b"SECRETNEW"));
    let checkout = ok(&mut env, "checkout /work/received.kqtf --out /work/got.txt");
    assert!(checkout.contains("Wrote"), "{checkout}");
    assert_eq!(
        env.fs.read(Path::new("/work/got.txt")).unwrap(),
        b"totals: 100\n"
    );
}

#[test]
fn nothing_trusted_means_nothing_is_sealed_and_the_attempt_is_recorded() {
    let mut env = delivering();
    // A descendant's first revision needs its parent's countersignature, so
    // nothing in this file is trusted yet.
    ok(
        &mut env,
        &format!(
            "track /work/report.txt --scope M.A --as M.A.1 --slot {} --out /work/none.kqtf",
            slot("M.A.1")
        ),
    );
    let (result, _) = run(
        &mut env,
        &format!(
            "share /work/none.kqtf --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    assert!(result.is_err());
    assert!(env
        .fs
        .list(Path::new("/out"))
        .unwrap_or_default()
        .is_empty());
    let history = ok(&mut env, "history /work/none.kqtf");
    assert!(history.contains("ShareAttempted Denied"), "{history}");
}

#[test]
fn a_recipient_can_reject_and_the_sender_records_it() {
    let mut env = delivering();
    let (result, _) = share_to_mb(&mut env, "");
    assert!(result.is_ok());
    let (result, out) = receive_as_mb(&mut env, "--reject");
    assert!(result.is_ok(), "{out}");
    assert!(!env.fs.exists(Path::new("/work/received.kqtf")));
    let ack = dir_file(&env, "/acks");
    let out = ok(
        &mut env,
        &format!("ack {KQTF} --ack {ack} --slot {}", slot("M.A")),
    );
    assert!(out.contains("rejected by M.B"), "{out}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("Denied"), "{history}");
    // Replaying the same rejection records nothing more.
    let again = ok(
        &mut env,
        &format!("ack {KQTF} --ack {ack} --slot {}", slot("M.A")),
    );
    assert!(again.contains("already recorded"), "{again}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert_eq!(history.matches("result=rejected").count(), 1, "{history}");
    assert_eq!(history.matches("ShareDelivered").count(), 0, "{history}");
}

#[test]
fn a_letter_merges_into_an_existing_copy() {
    let mut env = delivering();
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new("/work/mb.kqtf"), &bytes).unwrap();
    edit(&mut env, "totals: 200\n");
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let (result, _) = share_to_mb(&mut env, "");
    assert!(result.is_ok());
    let (result, out) = receive_as_mb(&mut env, "--into /work/mb.kqtf");
    assert!(result.is_ok(), "{out}");
    assert!(out.contains("RemoteAhead"), "{out}");
    let status = ok(&mut env, "status /work/mb.kqtf");
    assert!(status.contains("trust TRUSTED"), "{status}");
    assert!(!status.contains("FORK"), "{status}");
    // A missing target is refused.
    let (result, _) = receive_as_mb(&mut env, "--into /work/other-file.kqtf");
    assert!(result.is_err());
}

#[test]
fn only_the_addressed_recipient_can_open_and_a_stale_ack_matches_nothing() {
    let mut env = delivering();
    let (result, _) = share_to_mb(&mut env, "");
    assert!(result.is_ok());
    let letter = dir_file(&env, "/out");
    let (result, _) = run(
        &mut env,
        &format!(
            "receive --letter {letter} --slot {} --ack-dir /acks --out /work/x.kqtf",
            slot("M.A")
        ),
    );
    assert!(result.is_err());
    assert!(!env.fs.exists(Path::new("/work/x.kqtf")));

    // An acknowledgement from another delivery is not recorded here.
    let (result, _) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    assert!(result.is_ok());
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new("/work/twin.kqtf"), &bytes).unwrap();
    let ack = dir_file(&env, "/acks");
    let (result, _) = run(
        &mut env,
        &format!("ack /work/received.kqtf --ack {ack} --slot {}", slot("M.A")),
    );
    assert!(result.is_err(), "the receiver never sent that delivery");
}

#[test]
fn a_recipient_that_cannot_trust_the_revision_refuses_it_and_says_so() {
    let mut env = delivering();
    // M.B forwards M.A's file. The recipient's store knows a different
    // signing key for M.A, so the sender is authentic but the revision is not.
    let b = "--db /home/b/keyquorum.sqlite";
    env.device("keyquorum-device init /usb/fake").0.unwrap();
    let (result, _) = env.device("keyquorum-device provision /usb/fake --label M.A");
    assert!(result.is_ok());
    for line in [
        "device register /usb/mb --slot M.B --type signing",
        "device register /usb/mb --slot M.B --type encryption",
        "device register /usb/fake --slot M.A --type signing",
    ] {
        let (result, _) = env.keyquorum(&format!("keyquorum {b} {line}"));
        assert!(result.is_ok(), "{line}: {result:?}");
    }
    let (result, out) = run(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.B --slot {} --output-dir /out",
            slot("M.B")
        ),
    );
    assert!(result.is_ok(), "{out}");
    let letter = dir_file(&env, "/out");
    let (result, out) = env.keyquorum(&format!(
        "keyquorum {b} file receive --letter {letter} --slot {} --ack-dir /acks --out /work/r.kqtf",
        slot("M.B")
    ));
    assert!(result.is_ok(), "{out}");
    assert!(!env.fs.exists(Path::new("/work/r.kqtf")));
    // The refusal is still answered, so the sender learns of it.
    let ack = dir_file(&env, "/acks");
    let out = ok(
        &mut env,
        &format!("ack {KQTF} --ack {ack} --slot {}", slot("M.B")),
    );
    assert!(out.contains("rejected by M.B"), "{out}");
}

#[test]
fn an_imported_forged_signature_does_not_stop_the_author_signing() {
    use crate::file_history::TrackedFile;
    let mut env = org();
    two_copies(&mut env);
    checkin_unsigned(&mut env, COPY, "a\nB\nc\n");
    // Someone signs the shared unsigned revision with an arbitrary secret.
    let mut copy = TrackedFile::decode(&env.fs.read(Path::new(COPY)).unwrap()).unwrap();
    let head = copy.graph().heads()[0];
    let author = copy.graph().get(&head).unwrap().revision.author_identity;
    copy.sign_revision(&head, author.unwrap(), "M.A", &[99; 32])
        .unwrap();
    env.fs
        .write(Path::new(COPY), &copy.encode().unwrap())
        .unwrap();

    let out = ok(&mut env, &format!("import {KQTF} --from {COPY} --as M.A"));
    assert!(out.contains("1 proof(s) added"), "{out}");
    let out = ok(
        &mut env,
        &format!("sign {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("trust TRUSTED"), "{out}");
}

// ---- review view -----------------------------------------------------------

#[test]
fn the_review_view_lists_each_sides_changes_with_who_wrote_them() {
    use crate::cli::review_view::ReviewView;
    use crate::file_history::{ChangeKind, TrackedFile};
    let mut env = org();
    forked(&mut env, "totals: 100\n", "totals: 125\n", "totals: 130\n");
    let file = TrackedFile::decode(&env.fs.read(Path::new(KQTF)).unwrap()).unwrap();
    let view = ReviewView::of(&file).expect("two heads");
    assert_eq!(view.panes.len(), 2);
    for (pane, text, who) in [
        (&view.panes[0], "totals: 125", "M.A.1"),
        (&view.panes[1], "totals: 130", "M.S.1"),
    ] {
        assert!(pane.note.is_none());
        assert_eq!(pane.lines.len(), 2, "one removal and one addition");
        assert_eq!(pane.lines[0].kind, ChangeKind::Removed);
        assert_eq!(pane.lines[0].text, "totals: 100");
        assert_eq!(pane.lines[1].kind, ChangeKind::Added);
        assert_eq!(pane.lines[1].text, text);
        assert!(
            pane.lines[1].provenance.starts_with(who),
            "{}",
            pane.lines[1].provenance
        );
    }
    // The printed review is drawn from the same view.
    let out = ok(&mut env, &format!("review {KQTF}"));
    assert!(
        out.contains("CHANGED LINES (LEFT)") && out.contains("+    1 | totals: 125"),
        "{out}"
    );
    // One head is not a review.
    let mut solo = org();
    track(&mut solo, "M.A", "M.A");
    let single = TrackedFile::decode(&solo.fs.read(Path::new(KQTF)).unwrap()).unwrap();
    assert!(ReviewView::of(&single).is_none());
}

#[test]
fn interactive_review_needs_the_tui_build_and_a_fork() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let (result, _) = run(&mut env, &format!("review {KQTF} --interactive"));
    assert!(result.is_err());
}

#[test]
fn each_changed_line_is_attributed_to_the_revision_that_wrote_it() {
    use crate::cli::review_view::ReviewView;
    use crate::file_history::{ChangeKind, NewRevision, TrackedFile};
    let mut env = org();
    env.fs
        .write(Path::new("/work/report.txt"), b"one\ntwo\nthree\n")
        .unwrap();
    track(&mut env, "M.A", "M.A");
    let mut file = TrackedFile::decode(&env.fs.read(Path::new(KQTF)).unwrap()).unwrap();
    let base = file.graph().heads()[0];
    let policy_hash = file.policy().unwrap().policy_hash().unwrap();
    let revision = |file: &mut TrackedFile, parent, label: &str, minute: u8, text: &str| {
        file.check_in(
            NewRevision {
                parent_revision_ids: vec![parent],
                user_label: None,
                author_identity: Some([minute; 16]),
                author_hcp_label: label.to_string(),
                created_at_utc: format!("2026-09-27T00:0{minute}:00Z"),
                topology_generation: 0,
                policy_hash,
            },
            text.as_bytes().to_vec(),
        )
        .unwrap()
    };
    // Left: M.A.1 edits line 1, then M.A.2 edits line 3 and drops line 2.
    let first = revision(&mut file, base, "M.A.1", 1, "ONE\ntwo\nthree\n");
    revision(&mut file, first, "M.A.2", 2, "ONE\nTHREE\n");
    // Right: one author edits line 2.
    revision(&mut file, base, "M.S.1", 3, "one\nTWO\nthree\n");

    let view = ReviewView::of(&file).expect("two heads");
    let left = &view.panes[0];
    let by = |kind, text: &str| {
        left.lines
            .iter()
            .find(|l| l.kind == kind && l.text == text)
            .unwrap_or_else(|| panic!("{kind:?} {text}: {:?}", left.lines))
            .provenance
            .clone()
    };
    assert!(
        by(ChangeKind::Added, "ONE").starts_with("M.A.1"),
        "{}",
        by(ChangeKind::Added, "ONE")
    );
    assert!(by(ChangeKind::Removed, "one").starts_with("M.A.1"));
    assert!(by(ChangeKind::Added, "THREE").starts_with("M.A.2"));
    assert!(by(ChangeKind::Removed, "two").starts_with("M.A.2"));
    assert!(by(ChangeKind::Removed, "three").starts_with("M.A.2"));
    // The other side names its own author, and the pane header still names the head.
    assert!(view.panes[1]
        .lines
        .iter()
        .all(|l| l.provenance.starts_with("M.S.1")));
    assert!(left.revision.starts_with("M.A.2"));
}

#[test]
fn the_review_names_a_user_label_before_the_generated_label_and_hash() {
    use crate::cli::review_view::ReviewView;
    use crate::file_history::{NewRevision, TrackedFile};
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let mut file = TrackedFile::decode(&env.fs.read(Path::new(KQTF)).unwrap()).unwrap();
    let base = file.graph().heads()[0];
    let policy_hash = file.policy().unwrap().policy_hash().unwrap();
    for (label, minute, user) in [("M.A.1", 1, Some("Q4 draft")), ("M.S.1", 2, None)] {
        file.check_in(
            NewRevision {
                parent_revision_ids: vec![base],
                user_label: user.map(str::to_string),
                author_identity: Some([minute; 16]),
                author_hcp_label: label.to_string(),
                created_at_utc: format!("2026-09-27T00:0{minute}:00Z"),
                topology_generation: 0,
                policy_hash,
            },
            format!("totals: {minute}\n").into_bytes(),
        )
        .unwrap();
    }
    let view = ReviewView::of(&file).expect("two heads");
    let described: Vec<&str> = view.panes.iter().map(|p| p.revision.as_str()).collect();
    let labelled = described
        .iter()
        .find(|d| d.contains("Q4 draft"))
        .unwrap_or_else(|| panic!("{described:?}"));
    let user_at = labelled.find("Q4 draft").unwrap();
    let generated_at = labelled.find("Rreport").unwrap();
    assert!(user_at < generated_at, "{labelled}");
    // The other side has no user label and still shows its generated one.
    assert!(
        described
            .iter()
            .any(|d| !d.contains("Q4 draft") && d.contains("Rreport")),
        "{described:?}"
    );
}

#[test]
fn the_printed_review_carries_the_merge_status_the_interactive_one_shows() {
    let mut env = org();
    forked(&mut env, "totals: 100\n", "totals: 125\n", "totals: 130\n");
    let out = ok(&mut env, &format!("review {KQTF}"));
    assert!(out.contains("STATUS"), "{out}");
    assert!(
        out.contains("merge  RequiresHuman (OVERLAPPING_EDIT)"),
        "{out}"
    );
    assert!(out.contains("review M.A (PriorNeutralOwner)"), "{out}");
}

// ---- expiry ----------------------------------------------------------------

#[test]
fn a_scheduled_expiry_destroys_every_revision_on_first_touch_and_leaves_a_tombstone() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: SECOND\n");
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let out = ok(
        &mut env,
        &format!(
            "expire {KQTF} --as M.A --at 2026-09-28T12:00 --slot {}",
            slot("M.A")
        ),
    );
    assert!(out.contains("expires at 2026-09-28T12:00:00Z"), "{out}");
    assert!(ok(&mut env, &format!("status {KQTF}")).contains("expires      2026-09-28T12:00:00Z"));
    // Still before the expiry: content is readable.
    ok(&mut env, &format!("checkout {KQTF} --out /work/before.txt"));

    env.now = Some("2026-09-29 00:00".into());
    let (result, _) = run(&mut env, &format!("checkout {KQTF} --out /work/after.txt"));
    assert!(
        matches!(result, Err(crate::error::Error::FileExpired)),
        "{result:?}"
    );
    assert!(!env.fs.exists(Path::new("/work/after.txt")));
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    for secret in [&b"totals: 100"[..], b"totals: SECOND"] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
    }
    let history = ok(&mut env, &format!("history {KQTF}"));
    for kind in [
        "ExpiryScheduled",
        "FileExpired",
        "ContentDestroyed",
        "ExpiredAccessAttempt",
    ] {
        assert_eq!(history.matches(kind).count(), 1, "{kind}\n{history}");
    }
    assert!(history.contains("revisions_destroyed=2"), "{history}");

    // The tombstone still verifies, and later attempts are recorded.
    let verify = ok(&mut env, &format!("verify {KQTF}"));
    assert!(
        verify.contains("Tombstone: the content of all 2 revision(s)"),
        "{verify}"
    );
    assert!(ok(&mut env, &format!("status {KQTF}")).contains("EXPIRED"));
    let (result, _) = run(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A --unsigned"),
    );
    assert!(result.is_err());
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert_eq!(
        history.matches("ExpiredAccessAttempt").count(),
        2,
        "{history}"
    );
    let attempt = history
        .lines()
        .rfind(|line| line.contains("ExpiredAccessAttempt"))
        .expect("a recorded attempt");
    assert!(
        attempt.contains("by M.A") && attempt.contains("checkin"),
        "{history}"
    );
}

#[test]
fn only_the_scope_owner_or_an_ancestor_expires_a_file_and_never_into_the_past() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    // A descendant may edit the file but may not end it.
    let (result, _) = run(
        &mut env,
        &format!("expire {KQTF} --as M.A.1 --now --slot {}", slot("M.A.1")),
    );
    assert!(result.is_err());
    let (result, _) = run(
        &mut env,
        &format!(
            "expire {KQTF} --as M.A --at 2020-01-01T00:00 --slot {}",
            slot("M.A")
        ),
    );
    assert!(result.is_err());
    assert!(!ok(&mut env, &format!("history {KQTF}")).contains("Expiry"));
    // The root, an ancestor, may destroy it now.
    let out = ok(
        &mut env,
        &format!("expire {KQTF} --as M --now --slot {}", slot("M")),
    );
    assert!(
        out.contains("Destroyed the content of 1 revision(s)"),
        "{out}"
    );
    let (result, _) = run(
        &mut env,
        &format!("expire {KQTF} --as M --now --slot {}", slot("M")),
    );
    assert!(result.is_err(), "already destroyed");
}

#[test]
fn a_tombstone_cannot_be_shared_imported_or_merged_into() {
    let mut env = org();
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} device register /usb/mb --slot M.B --type encryption"
    ));
    assert!(result.is_ok());
    track(&mut env, "M.A", "M.A");
    let live = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new("/work/live.kqtf"), &live).unwrap();
    ok(
        &mut env,
        &format!("expire {KQTF} --as M.A --now --slot {}", slot("M.A")),
    );

    let (result, _) = run(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    assert!(
        matches!(result, Err(crate::error::Error::FileExpired)),
        "{result:?}"
    );
    assert!(env
        .fs
        .list(Path::new("/out"))
        .unwrap_or_default()
        .is_empty());
    // Live content is not imported into the tombstone, nor the tombstone into a live copy.
    let (result, _) = run(
        &mut env,
        &format!("import {KQTF} --from /work/live.kqtf --as M.A"),
    );
    assert!(result.is_err());
    let (result, _) = run(
        &mut env,
        &format!("import /work/live.kqtf --from {KQTF} --as M.A"),
    );
    assert!(result.is_err());
    assert!(ok(&mut env, "checkout /work/live.kqtf --out /work/still.txt").contains("Wrote"));
}

#[test]
fn expiry_needs_the_owners_own_key_not_just_the_label() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    // No proof at all.
    let (result, _) = run(&mut env, &format!("expire {KQTF} --as M --now"));
    assert!(result.is_err());
    // Someone else's key does not stand in for M.
    let (result, _) = run(
        &mut env,
        &format!("expire {KQTF} --as M --now --slot {}", slot("M.A")),
    );
    assert!(result.is_err());
    // A label outside the file's ancestry is refused before any key is opened.
    let (result, _) = run(
        &mut env,
        &format!("expire {KQTF} --as X --now --slot {}", slot("M")),
    );
    assert!(result.is_err());
    assert!(!ok(&mut env, &format!("history {KQTF}")).contains("Expiry"));
    assert!(!ok(&mut env, &format!("status {KQTF}")).contains("destroyed"));
}

#[test]
fn a_held_lock_blocks_writes_and_says_how_to_clear_it() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: LOCKED\n");
    let lock = format!("{KQTF}.lock");
    env.fs.write(Path::new(&lock), b"held").unwrap();
    let (result, _) = run(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let message = result.unwrap_err().to_string();
    assert!(message.contains("another command is updating"), "{message}");
    assert!(message.contains(&lock), "{message}");
    // A refused write leaves the other command's lock alone.
    assert!(env.fs.exists(Path::new(&lock)));
    env.fs.delete(Path::new(&lock)).unwrap();
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(!env.fs.exists(Path::new(&lock)), "the lock is released");
}

#[test]
fn a_container_changed_since_it_was_read_is_not_overwritten() {
    use crate::cli::file_cmd::{load, save};
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let (result, _) = env.run(|| {
        let file = load(Path::new(KQTF))?;
        // Another command replaces the container after this one read it.
        let mut other = load(Path::new(KQTF))?;
        other.logical_name = "changed.txt".into();
        crate::cli::env::write(Path::new(KQTF), &other.encode()?)?;
        let stale = save(Path::new(KQTF), &file);
        assert!(stale.is_err(), "a stale save must be refused");
        Ok(())
    });
    assert!(result.is_ok(), "{result:?}");
    let name = ok(&mut env, &format!("status {KQTF}"));
    assert!(name.contains("changed.txt"), "{name}");
}

#[test]
fn a_new_container_never_replaces_one_that_appeared_meanwhile() {
    use crate::cli::file_cmd::{load, save};
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let live = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new("/work/other.kqtf"), &live).unwrap();
    let (result, _) = env.run(|| {
        // This command never read /work/other.kqtf, so saving there means
        // creating it; someone else already did.
        let file = load(Path::new(KQTF))?;
        assert!(save(Path::new("/work/other.kqtf"), &file).is_err());
        // A container that vanished after being read is not silently recreated.
        crate::cli::env::remove_file(Path::new(KQTF))?;
        assert!(save(Path::new(KQTF), &file).is_err());
        Ok(())
    });
    assert!(result.is_ok(), "{result:?}");
}

// ---- activation, rename, derived heads -------------------------------------

#[test]
fn the_first_content_signature_starts_tracking_and_never_a_second_identity() {
    let mut env = org();
    // An ordinary signature starts tracking: with no --scope, the signer's
    // own label is the scope, so their own signature makes R1 trusted.
    let out = ok(
        &mut env,
        &format!("sign /work/report.txt --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("Tracking report.txt as "), "{out}");
    let policy = ok(&mut env, &format!("policy {KQTF}"));
    assert!(policy.contains("M.A"), "{policy}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("TrackingStarted"), "{history}");
    assert!(history.contains("RevisionSigned"), "{history}");
    let id = ok(&mut env, &format!("status {KQTF}"))
        .lines()
        .next()
        .unwrap()
        .to_string();

    // Signing the native file again does not mint a second identity.
    let (result, _) = run(
        &mut env,
        &format!(
            "sign /work/report.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(result.unwrap_err().to_string().contains("already tracks"));
    assert_eq!(
        ok(&mut env, &format!("status {KQTF}"))
            .lines()
            .next()
            .unwrap(),
        id
    );
    // --scope belongs to activation only.
    let (result, _) = run(
        &mut env,
        &format!("sign {KQTF} --scope M.A --as M.A --slot {}", slot("M.A")),
    );
    assert!(result.is_err());

    // A copy of the same bytes at another path is its own file: signing it
    // starts a separate lineage with a different id.
    let bytes = env.fs.read(Path::new("/work/report.txt")).unwrap();
    env.fs.write(Path::new("/work/copy.txt"), &bytes).unwrap();
    ok(
        &mut env,
        &format!("sign /work/copy.txt --as M.A --slot {}", slot("M.A")),
    );
    let copy_id = ok(&mut env, "status /work/copy.txt.kqtf")
        .lines()
        .next()
        .unwrap()
        .to_string();
    assert_ne!(copy_id, id);
}

#[test]
fn a_binary_payload_round_trips_byte_for_byte() {
    let mut env = org();
    let blob: Vec<u8> = (0u8..=255).chain([0, 255, 0, 10, 13]).collect();
    env.fs.write(Path::new("/work/sheet.xlsx"), &blob).unwrap();
    ok(
        &mut env,
        &format!(
            "sign /work/sheet.xlsx --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
    ok(
        &mut env,
        "checkout /work/sheet.xlsx.kqtf --out /work/sheet.out.xlsx",
    );
    assert_eq!(
        env.fs.read(Path::new("/work/sheet.out.xlsx")).unwrap(),
        blob
    );
}

#[test]
fn status_tells_the_current_head_from_the_latest_trusted_one() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let status = ok(&mut env, &format!("status {KQTF}"));
    let field = |text: &str, key: &str| {
        text.lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_string()
    };
    let first = field(&status, "current_revision_id");
    assert_eq!(field(&status, "trusted_revision_id"), first);

    edit(&mut env, "totals: NEWER\n");
    ok(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A --unsigned"),
    );
    let status = ok(&mut env, &format!("status {KQTF}"));
    assert_ne!(field(&status, "current_revision_id"), first);
    assert_eq!(field(&status, "trusted_revision_id"), first);
}

#[test]
fn renaming_keeps_the_file_and_revision_identity_and_is_recorded() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let before = ok(&mut env, &format!("status {KQTF}"));
    let id_line = before.lines().next().unwrap().to_string();
    let head = before
        .lines()
        .find(|l| l.trim_start().starts_with("current_revision_id"))
        .unwrap()
        .to_string();

    // Outside the scope, or with someone else's key, nothing changes.
    let (result, _) = run(
        &mut env,
        &format!("rename {KQTF} q3.txt --as M.B --slot {}", slot("M.B")),
    );
    assert!(result.is_err());
    let (result, _) = run(
        &mut env,
        &format!("rename {KQTF} q3.txt --as M.A --slot {}", slot("M.B")),
    );
    assert!(result.is_err());
    let (result, _) = run(
        &mut env,
        &format!("rename {KQTF} a/b.txt --as M.A --slot {}", slot("M.A")),
    );
    assert!(result.is_err(), "a path is not a name");

    let out = ok(
        &mut env,
        &format!("rename {KQTF} q3.txt --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("unchanged"), "{out}");
    let after = ok(&mut env, &format!("status {KQTF}"));
    assert!(after.starts_with("q3.txt ("), "{after}");
    // Same 128-bit id and same revision ids; only the display name moved.
    assert_eq!(
        id_line.split_once(' ').unwrap().1,
        after.lines().next().unwrap().split_once(' ').unwrap().1
    );
    assert!(after.contains(&head), "{after}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("FileRenamed"), "{history}");
    assert!(history.contains("from=report.txt"), "{history}");
    assert!(history.contains("to=q3.txt"), "{history}");
    let verify = ok(&mut env, &format!("verify {KQTF}"));
    assert!(verify.contains("TRUSTED"), "{verify}");
    // A copy of the container elsewhere is the same file.
    let bytes = env.fs.read(Path::new(KQTF)).unwrap();
    env.fs.write(Path::new("/work/moved.kqtf"), &bytes).unwrap();
    let moved = ok(&mut env, "status /work/moved.kqtf");
    assert_eq!(
        moved.lines().next().unwrap().split_once(' ').unwrap().1,
        after.lines().next().unwrap().split_once(' ').unwrap().1
    );
}

#[test]
fn a_rename_travels_with_the_delivered_history() {
    let mut env = delivering();
    ok(
        &mut env,
        &format!("rename {KQTF} q3.txt --as M.A --slot {}", slot("M.A")),
    );
    ok(
        &mut env,
        &format!(
            "share {KQTF} --to M.B --as M.A --slot {} --output-dir /out",
            slot("M.A")
        ),
    );
    let (result, out) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    assert!(result.is_ok(), "{result:?}\n{out}");
    let history = ok(&mut env, "history /work/received.kqtf");
    assert!(history.contains("FileRenamed"), "{history}");
    assert!(ok(&mut env, "status /work/received.kqtf").starts_with("q3.txt ("));
}

#[test]
fn rules_no_ancestor_can_meet_are_refused_but_a_root_scope_has_no_ancestors() {
    let mut env = org();
    // Below the root, the root is an ancestor and has no parent to countersign.
    let (result, _) = run(
        &mut env,
        &format!(
            "track /work/report.txt --scope M.A --as M.A --slot {} --ancestors-rule author+parent",
            slot("M.A")
        ),
    );
    assert!(result.is_err());
    assert!(!env.fs.exists(Path::new(KQTF)));
    // A root scope has no ancestors, so the rule is never asked of anyone.
    ok(
        &mut env,
        &format!(
            "track /work/report.txt --scope M --as M --slot {} --ancestors-rule author+parent",
            slot("M")
        ),
    );
}

#[test]
fn deliver_open_also_requires_the_named_recipient_to_own_the_opening_key() {
    use crate::file_delivery::{seal_letter, Outgoing};
    let mut env = delivering();
    let mb_public: [u8; 32] = crate::keys::active_keys_for(
        env.store("/home/org/keyquorum.sqlite"),
        "M.B",
        crate::keys::KeyType::Encryption,
    )
    .unwrap()[0]
        .public_key
        .clone()
        .try_into()
        .unwrap();
    let (result, _) = env.run(|| {
        let secrets = crate::cli::open_slot_secrets(&slot("M.A"))?;
        let sender_public = crate::keys::encryption_public_from_secret(&secrets.encryption_secret);
        let letter = seal_letter(&Outgoing {
            sender_label: "M.A",
            sender_signing_secret: &secrets.signing_secret,
            sender_encryption_public: &sender_public,
            recipient_label: "M",
            recipient_encryption_public: &mb_public,
            file_name: "note.txt",
            contents: b"hello",
        })?;
        crate::cli::env::create_dir_all(Path::new("/out"))?;
        crate::cli::env::write(Path::new("/out/forged.kqpb"), &letter.bytes)
    });
    assert!(result.is_ok(), "{result:?}");
    let (result, _) = env.keyquorum(&format!(
        "keyquorum {DB} deliver open --file /out/forged.kqpb --slot {} --ack-dir /acks",
        slot("M.B")
    ));
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("matching the key that opened it"),
        "{message}"
    );
}

#[test]
fn a_letter_must_name_the_label_whose_key_opened_it() {
    use crate::file_delivery::{seal_history_letter, OutgoingHistory};
    use crate::file_history::TrackedFile;
    let mut env = delivering();
    let mb_public = crate::keys::active_keys_for(
        env.store("/home/org/keyquorum.sqlite"),
        "M.B",
        crate::keys::KeyType::Encryption,
    )
    .unwrap()[0]
        .public_key
        .clone();
    let mb_public: [u8; 32] = mb_public.try_into().unwrap();
    let container = env.fs.read(Path::new(KQTF)).unwrap();
    let file = TrackedFile::decode(&container).unwrap();
    let head = file.graph().heads()[0];
    let (result, _) = env.run(|| {
        let secrets = crate::cli::open_slot_secrets(&slot("M.A"))?;
        let sender_public = crate::keys::encryption_public_from_secret(&secrets.encryption_secret);
        // Sealed to M.B's key, but claiming to be for M.
        let letter = seal_history_letter(&OutgoingHistory {
            sender_label: "M.A",
            sender_signing_secret: &secrets.signing_secret,
            sender_encryption_public: &sender_public,
            recipient_label: "M",
            recipient_encryption_public: &mb_public,
            file_name: &file.logical_name,
            file_id: file.file_id,
            revision_id: head,
            history_root: file.history_root(),
            decision: 1,
            content_proof: crate::file_history::proof_descriptor(&file, &head)?,
            container: &container,
        })?;
        crate::cli::env::create_dir_all(Path::new("/out"))?;
        crate::cli::env::write(Path::new("/out/forged.kqpb"), &letter.bytes)
    });
    assert!(result.is_ok(), "{result:?}");
    let (result, _) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("matching the key that opened it"),
        "{message}"
    );
    assert!(!env.fs.exists(Path::new("/work/received.kqtf")));
}

#[test]
fn a_letter_whose_proof_descriptor_does_not_match_its_container_is_refused() {
    use crate::file_delivery::{seal_history_letter, OutgoingHistory};
    use crate::file_history::{proof_descriptor, TrackedFile};
    let mut env = delivering();
    let mb_public = crate::keys::active_keys_for(
        env.store("/home/org/keyquorum.sqlite"),
        "M.B",
        crate::keys::KeyType::Encryption,
    )
    .unwrap()[0]
        .public_key
        .clone();
    let mb_public: [u8; 32] = mb_public.try_into().unwrap();
    let container = env.fs.read(Path::new(KQTF)).unwrap();
    let file = TrackedFile::decode(&container).unwrap();
    let head = file.graph().heads()[0];
    // The sender signs a descriptor naming no proofs, while the container
    // carries the author's signature: the header and payload disagree.
    let bare = TrackedFile::new(file.file_id, &file.logical_name);
    let wrong = proof_descriptor(&bare, &head).unwrap();
    assert_ne!(wrong, proof_descriptor(&file, &head).unwrap());
    let (result, _) = env.run(|| {
        let secrets = crate::cli::open_slot_secrets(&slot("M.A"))?;
        let sender_public = crate::keys::encryption_public_from_secret(&secrets.encryption_secret);
        let letter = seal_history_letter(&OutgoingHistory {
            sender_label: "M.A",
            sender_signing_secret: &secrets.signing_secret,
            sender_encryption_public: &sender_public,
            recipient_label: "M.B",
            recipient_encryption_public: &mb_public,
            file_name: &file.logical_name,
            file_id: file.file_id,
            revision_id: head,
            history_root: file.history_root(),
            decision: 1,
            content_proof: wrong,
            container: &container,
        })?;
        crate::cli::env::create_dir_all(Path::new("/out"))?;
        crate::cli::env::write(Path::new("/out/mismatch.kqpb"), &letter.bytes)
    });
    assert!(result.is_ok(), "{result:?}");
    let (result, _) = receive_as_mb(&mut env, "--out /work/received.kqtf");
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("does not match the container"),
        "{message}"
    );
    assert!(!env.fs.exists(Path::new("/work/received.kqtf")));
}

// ---- labels, policy ----------------------------------------------------------

#[test]
fn a_precise_clock_puts_milliseconds_in_the_generated_label() {
    let mut env = org();
    env.millis = Some("482".into());
    track(&mut env, "M.A", "M.A");
    let status = ok(&mut env, &format!("graph {KQTF}"));
    assert!(status.contains("T000000.482Z-M.A"), "{status}");
    // Events keep whole seconds, so time comparisons stay simple.
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(!history.contains(".482"), "{history}");
}

#[test]
fn a_tracked_files_rules_are_chosen_when_it_starts_and_shown_with_their_hash() {
    let mut env = org();
    let out = track_with(
        &mut env,
        "M.A",
        "M.A",
        "--descendants-rule forbidden --cross-branch-rule author",
    );
    assert!(out.contains("trust    TRUSTED"), "{out}");
    let policy = ok(&mut env, &format!("policy {KQTF}"));
    assert!(policy.contains("descendants         forbidden"), "{policy}");
    assert!(policy.contains("cross-branch        author"), "{policy}");
    assert!(policy.contains("edits by descendants false"), "{policy}");
    assert!(policy.contains("policy_hash"), "{policy}");
    // A descendant may not edit a file whose rules forbid it.
    edit(&mut env, "totals: NOPE\n");
    let (result, _) = run(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A.1 --slot {}",
            slot("M.A.1")
        ),
    );
    assert!(result.is_err());
    // The standard rules are what you get without flags.
    let mut standard = org();
    track(&mut standard, "M.A", "M.A");
    let policy = ok(&mut standard, &format!("policy {KQTF}"));
    assert!(
        policy.contains("descendants         author+parent"),
        "{policy}"
    );
    assert!(
        policy.contains("cross-branch        author+bridge-or-owner"),
        "{policy}"
    );

    let mut strict = org();
    track_with(
        &mut strict,
        "M.A",
        "M.A",
        "--cross-branch-rule author+bridge+owner",
    );
    let policy = ok(&mut strict, &format!("policy {KQTF}"));
    assert!(
        policy.contains("cross-branch        author+bridge+owner"),
        "{policy}"
    );
}

#[test]
fn rules_that_cannot_be_met_are_refused_before_anything_is_written() {
    for extra in [
        "--owner-rule forbidden",
        "--owner-rule author+bridge-or-owner",
        "--owner-rule author+bridge+owner",
        "--descendants-rule author+bridge-or-owner",
        "--descendants-rule author+bridge+owner",
        "--cross-branch-rule author+parent",
    ] {
        let mut env = org();
        let (result, _) = run(
            &mut env,
            &format!(
                "track /work/report.txt --scope M.A --as M.A --slot {} {extra}",
                slot("M.A")
            ),
        );
        assert!(result.is_err(), "{extra}");
        assert!(!env.fs.exists(Path::new(KQTF)), "{extra}");
    }
    // The root has no parent to countersign for it.
    let mut env = org();
    let (result, _) = run(
        &mut env,
        &format!(
            "track /work/report.txt --scope M --as M --slot {} --owner-rule author+parent",
            slot("M")
        ),
    );
    assert!(result.is_err());
}

#[test]
fn a_countersignature_records_the_relationship_and_the_decision_its_reason() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    edit(&mut env, "totals: BY DESCENDANT\n");
    ok(
        &mut env,
        &format!(
            "checkin {KQTF} --from /work/edited.txt --as M.A.1 --slot {}",
            slot("M.A.1")
        ),
    );
    ok(
        &mut env,
        &format!("countersign {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("for_actor=M.A.1"), "{history}");
    assert!(history.contains("relationship=DIRECT_PARENT"), "{history}");
    assert!(
        history.contains("reason=AUTHOR_SIGNATURE + REQUIRED_PARENT_COUNTERSIGNATURE"),
        "{history}"
    );
}

#[test]
fn signing_a_native_file_starts_tracking_only_when_the_first_revision_is_trusted() {
    let mut env = org();
    // A descendant's first revision would wait for its parent, so signing
    // does not start tracking; nothing is written.
    let (result, _) = run(
        &mut env,
        &format!(
            "sign /work/report.txt --scope M.A --as M.A.1 --slot {}",
            slot("M.A.1")
        ),
    );
    let message = result.unwrap_err().to_string();
    assert!(message.contains("not trusted"), "{message}");
    assert!(!env.fs.exists(Path::new(KQTF)));
    // The scope owner's signature alone is enough.
    ok(
        &mut env,
        &format!(
            "sign /work/report.txt --scope M.A --as M.A --slot {}",
            slot("M.A")
        ),
    );
    assert!(env.fs.exists(Path::new(KQTF)));
}

// ---- finalization -------------------------------------------------------------

#[test]
fn the_owner_finalizes_a_trusted_revision_and_status_says_so() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    let status = ok(&mut env, &format!("status {KQTF}"));
    assert!(status.contains("finalized none"), "{status}");

    let out = ok(
        &mut env,
        &format!("finalize {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    assert!(out.contains("Finalized "), "{out}");
    let status = ok(&mut env, &format!("status {KQTF}"));
    assert!(!status.contains("finalized none"), "{status}");
    let history = ok(&mut env, &format!("history {KQTF}"));
    assert!(history.contains("RevisionFinalized"), "{history}");
    // The container still verifies and trust is unchanged.
    let verify = ok(&mut env, &format!("verify {KQTF}"));
    assert!(verify.contains("TRUSTED"), "{verify}");
    // Doing it twice is refused rather than repeated.
    let (result, _) = run(
        &mut env,
        &format!("finalize {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("already finalized"));
}

#[test]
fn only_a_trusted_revision_can_be_finalized_and_only_by_the_owner_or_an_ancestor() {
    let mut env = org();
    track(&mut env, "M.A", "M.A");
    // A descendant's unsigned edit is the head and is not trusted.
    edit(&mut env, "totals: DRAFT\n");
    ok(
        &mut env,
        &format!("checkin {KQTF} --from /work/edited.txt --as M.A.1 --unsigned"),
    );
    let (result, _) = run(
        &mut env,
        &format!("finalize {KQTF} --as M.A --slot {}", slot("M.A")),
    );
    let message = result.unwrap_err().to_string();
    assert!(message.contains("only a trusted revision"), "{message}");
    // A descendant may not finalize, even the trusted first revision.
    let first = ok(&mut env, &format!("graph {KQTF}"));
    let first = first
        .split_whitespace()
        .find(|w| w.len() == 12 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("a short id")
        .to_string();
    let (result, _) = run(
        &mut env,
        &format!(
            "finalize {KQTF} --revision {first} --as M.A.1 --slot {}",
            slot("M.A.1")
        ),
    );
    assert!(result.is_err());
    // Someone else's key does not stand in for the owner's.
    let (result, _) = run(
        &mut env,
        &format!(
            "finalize {KQTF} --revision {first} --as M.A --slot {}",
            slot("M.B")
        ),
    );
    assert!(result.is_err());
    assert!(ok(&mut env, &format!("status {KQTF}")).contains("finalized none"));
    // The owner can finalize the trusted first revision while a newer
    // unsigned one is the head; the head itself stays unfinalized.
    ok(
        &mut env,
        &format!(
            "finalize {KQTF} --revision {first} --as M.A --slot {}",
            slot("M.A")
        ),
    );
    let status = ok(&mut env, &format!("status {KQTF}"));
    assert!(status.contains("finalized "), "{status}");
    assert!(!status.contains("finalized none"), "{status}");
}
