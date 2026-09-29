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
