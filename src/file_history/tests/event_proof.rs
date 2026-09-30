use super::*;
use ed25519_dalek::SigningKey;

/// One registered key: identity `[1; 16]` as M.A, seeded from `[1; 32]`.
struct Keys;

impl TrustContext for Keys {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        (*identity == [1; 16] && label == "M.A")
            .then(|| SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes())
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }
}

/// Nobody's key: a store that never met M.A.
struct NoKeys;

impl TrustContext for NoKeys {
    fn signing_public(&self, _: &[u8; 16], _: &str) -> Option<[u8; 32]> {
        None
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }
}

/// Two events by M.A and one with no actor.
fn chain() -> TrackedFile {
    let mut file = sample();
    file.append(new_event(HistoryEventType::FileRenamed, None))
        .unwrap();
    file.append(sparse_event()).unwrap();
    file
}

fn last_by_ma(file: &TrackedFile) -> u64 {
    file.events()
        .iter()
        .rev()
        .find(|e| e.actor_label.as_deref() == Some("M.A"))
        .unwrap()
        .sequence
}

#[test]
fn an_actor_signs_its_own_event_and_a_store_with_its_key_attests_it() {
    let mut file = chain();
    let seq = last_by_ma(&file);
    assert_eq!(
        event_attested(&file, seq, &Keys),
        None,
        "unsigned is not attested"
    );
    file.sign_event(seq, [1; 16], "M.A", &[1; 32]).unwrap();
    assert_eq!(event_attested(&file, seq, &Keys).as_deref(), Some("M.A"));
    // A store without the key keeps it a hash-chained record only.
    assert_eq!(event_attested(&file, seq, &NoKeys), None);
    // Another event is not attested by this proof.
    assert_eq!(event_attested(&file, 0, &Keys), None);
}

#[test]
fn only_the_events_own_actor_signs_it_and_only_once() {
    let mut file = chain();
    let seq = last_by_ma(&file);
    let actorless = file.events().len() as u64 - 1;
    assert!(file
        .sign_event(actorless, [1; 16], "M.A", &[1; 32])
        .is_err());
    assert!(file.sign_event(seq, [2; 16], "M.A", &[1; 32]).is_err());
    assert!(file.sign_event(seq, [1; 16], "M.B", &[1; 32]).is_err());
    assert!(file.sign_event(99, [1; 16], "M.A", &[1; 32]).is_err());
    file.sign_event(seq, [1; 16], "M.A", &[1; 32]).unwrap();
    assert!(file.sign_event(seq, [1; 16], "M.A", &[1; 32]).is_err());
}

#[test]
fn a_wrong_key_or_a_changed_signature_does_not_attest() {
    let mut file = chain();
    let seq = last_by_ma(&file);
    file.sign_event(seq, [1; 16], "M.A", &[9; 32]).unwrap();
    assert_eq!(event_attested(&file, seq, &Keys), None);
    let mut file = chain();
    file.sign_event(seq, [1; 16], "M.A", &[1; 32]).unwrap();
    file.event_proofs[0].signature[0] ^= 1;
    assert_eq!(event_attested(&file, seq, &Keys), None);
}

#[test]
fn event_proofs_round_trip_as_version_7_and_older_containers_still_decode() {
    let mut file = chain();
    let unsigned = file.encode().unwrap();
    assert_eq!(unsigned[4], 5, "no event proof keeps the older version");
    assert_eq!(TrackedFile::decode(&unsigned).unwrap(), file);
    let seq = last_by_ma(&file);
    file.sign_event(seq, [1; 16], "M.A", &[1; 32]).unwrap();
    let bytes = file.encode().unwrap();
    assert_eq!(bytes[4], 7);
    let back = TrackedFile::decode(&bytes).unwrap();
    assert_eq!(back, file);
    assert_eq!(event_attested(&back, seq, &Keys).as_deref(), Some("M.A"));
    // Version 7 with an empty proof list is a second encoding: refused.
    let mut empty = unsigned.clone();
    empty[4] = 7;
    empty.extend_from_slice(&0u32.to_be_bytes());
    assert!(TrackedFile::decode(&empty).is_err());
    // An older version cannot carry proofs: the trailing bytes are refused.
    let mut old = bytes.clone();
    old[4] = 6;
    assert!(TrackedFile::decode(&old).is_err());
}

#[test]
fn a_proof_moved_to_another_actors_event_fails_structure() {
    let mut file = chain();
    let seq = last_by_ma(&file);
    file.sign_event(seq, [1; 16], "M.A", &[1; 32]).unwrap();
    // Re-point it at the event with no actor.
    file.event_proofs[0].sequence = file.events().len() as u64 - 1;
    assert!(file.encode().is_err());
}

#[test]
fn an_attested_event_decides_no_trust() {
    // Event proofs attest what an actor did, never a revision's content.
    let mut file = sample();
    let head = file.graph().heads()[0];
    let policy = file
        .policy()
        .cloned()
        .unwrap_or_else(|| FilePolicy::standard("M.A"));
    let before = evaluate_revision_trust(&file, &head, &policy, &Keys).unwrap();
    file.append(new_event(HistoryEventType::RevisionSigned, Some(head)))
        .unwrap();
    let seq = file.events().len() as u64 - 1;
    file.sign_event(seq, [1; 16], "M.A", &[1; 32]).unwrap();
    assert_eq!(
        evaluate_revision_trust(&file, &head, &policy, &Keys).unwrap(),
        before
    );
}

#[test]
fn an_extract_keeps_the_proofs_of_the_events_it_keeps() {
    let mut file = tracked_file();
    let head = file
        .check_in(new_revision(vec![], T1), b"one\n".to_vec())
        .unwrap();
    file.append(new_event(HistoryEventType::RevisionSigned, Some(head)))
        .unwrap();
    let seq = file.events().len() as u64 - 1;
    file.sign_event(seq, [1; 16], "M.A", &[1; 32]).unwrap();
    let extract = file.extract_revision(&head).unwrap();
    assert_eq!(extract.event_proofs(), file.event_proofs());
    assert_eq!(event_attested(&extract, seq, &Keys).as_deref(), Some("M.A"));
}
