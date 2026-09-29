use super::memory_env::MemoryEnv;
use crate::storage::Storage;
use std::path::Path;

const DB: &str = "--db /home/org/keyquorum.sqlite";

/// (container directory, label). Everyone's signing key is registered in
/// the one org store, as in a real deployment.
const PEOPLE: [(&str, &str); 5] = [
    ("m", "M"),
    ("ma", "M.A"),
    ("ma1", "M.A.1"),
    ("mb", "M.B"),
    ("ms1", "M.S.1"),
];

fn org() -> MemoryEnv {
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

fn slot(label: &str) -> String {
    let dir = PEOPLE.iter().find(|(_, l)| *l == label).unwrap().0;
    format!("/usb/{dir}={label}")
}

fn run(env: &mut MemoryEnv, args: &str) -> (crate::error::Result<()>, String) {
    env.keyquorum(&format!("keyquorum {DB} file {args}"))
}

fn ok(env: &mut MemoryEnv, args: &str) -> String {
    let (result, out) = run(env, args);
    assert!(result.is_ok(), "{args}: {result:?}\n{out}");
    out
}

fn track(env: &mut MemoryEnv, scope: &str, label: &str) -> String {
    ok(
        env,
        &format!(
            "track /work/report.txt --scope {scope} --as {label} --slot {}",
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

const KQTF: &str = "/work/report.txt.kqtf";

/// Track `base` as M.A (signed, trusted), then add two children of it by
/// M.A.1 and M.S.1, giving a forked container.
fn forked(env: &mut MemoryEnv, base: &str, left: &str, right: &str) {
    use crate::file_history::{NewRevision, TrackedFile};
    env.fs
        .write(Path::new("/work/report.txt"), base.as_bytes())
        .unwrap();
    track(env, "M.A", "M.A");
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
    assert!(review.contains("M.A.1 · revision"), "{review}");
    assert!(review.contains("-    1 | totals: 100"), "{review}");
    assert!(review.contains("+    1 | totals: 125"), "{review}");
    assert!(review.contains("CHANGED LINES (RIGHT)"), "{review}");
    assert!(review.contains("M.S.1 · revision"), "{review}");
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
