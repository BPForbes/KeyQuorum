use super::*;
use crate::db;
use crate::keys::{self, KeyType};
use crate::relay;
use zeroize::Zeroizing;

struct Party {
    label: &'static str,
    encryption_secret: Zeroizing<[u8; 32]>,
    encryption_public: [u8; 32],
    signing_secret: Zeroizing<[u8; 32]>,
}

fn register(conn: &Connection, label: &'static str) -> Party {
    let (encryption_secret, encryption_public) = keys::generate_encryption_keypair();
    let (signing_secret, signing_public) = keys::generate_signing_keypair();
    keys::register_key(conn, label, KeyType::Encryption, &encryption_public).unwrap();
    keys::register_key(conn, label, KeyType::Signing, &signing_public).unwrap();
    Party {
        label,
        encryption_secret,
        encryption_public,
        signing_secret,
    }
}

fn letter_from(alice: &Party, david: &Party, contents: &[u8]) -> SealedLetter {
    seal_letter(&Outgoing {
        sender_label: alice.label,
        sender_signing_secret: &alice.signing_secret,
        sender_encryption_public: &alice.encryption_public,
        recipient_label: david.label,
        recipient_encryption_public: &david.encryption_public,
        file_name: "architecture.md",
        contents,
    })
    .unwrap()
}

#[test]
fn letter_round_trips_through_the_relay_mailbox_and_back_as_an_ack() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let sealed = letter_from(&alice, &david, b"# Architecture\n");

    let relay_conn = relay::open_in_memory().unwrap();
    let (id, fingerprint, duplicate) = relay::store(&relay_conn, &sealed.bytes).unwrap();
    assert!(!duplicate);
    assert_eq!(fingerprint, keys::fingerprint(&david.encryption_public));
    let page = relay::list_after(&relay_conn, &fingerprint, None, None).unwrap();
    assert_eq!(page.envelopes.len(), 1);
    assert_eq!(page.envelopes[0].id, id);

    let letter = open_letter(&conn, &david.encryption_secret, &page.envelopes[0].bytes).unwrap();
    assert_eq!(letter.delivery_id, sealed.delivery_id);
    assert_eq!(letter.sender_label, "M.S.1");
    assert_eq!(letter.recipient_label, "M.A");
    assert_eq!(letter.file_name, "architecture.md");
    assert_eq!(letter.contents, b"# Architecture\n");

    let ack_bytes = seal_ack(&letter, &david.signing_secret, true).unwrap();
    relay::store(&relay_conn, &ack_bytes).unwrap();
    let ack = open_ack(&conn, &alice.encryption_secret, &ack_bytes).unwrap();
    assert_eq!(
        ack,
        DeliveryAck {
            delivery_id: sealed.delivery_id,
            recipient_label: "M.A".into(),
            content_hash: sealed.content_hash,
            accepted: true,
        }
    );
}

#[test]
fn only_the_recipient_key_opens_a_letter() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let sealed = letter_from(&alice, &david, b"payload");
    assert!(open_letter(&conn, &alice.encryption_secret, &sealed.bytes).is_err());
}

#[test]
fn a_letter_signed_by_an_unregistered_key_is_refused() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let (forged_secret, _) = keys::generate_signing_keypair();
    let sealed = seal_letter(&Outgoing {
        sender_label: alice.label,
        sender_signing_secret: &forged_secret,
        sender_encryption_public: &alice.encryption_public,
        recipient_label: david.label,
        recipient_encryption_public: &david.encryption_public,
        file_name: "architecture.md",
        contents: b"payload",
    })
    .unwrap();
    assert!(matches!(
        open_letter(&conn, &david.encryption_secret, &sealed.bytes),
        Err(Error::SignatureVerificationFailed)
    ));
}

#[test]
fn a_rejection_ack_is_signed_and_cannot_be_flipped() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let sealed = letter_from(&alice, &david, b"payload");
    let letter = open_letter(&conn, &david.encryption_secret, &sealed.bytes).unwrap();
    let ack_bytes = seal_ack(&letter, &david.signing_secret, false).unwrap();
    let ack = open_ack(&conn, &alice.encryption_secret, &ack_bytes).unwrap();
    assert!(!ack.accepted);

    // Re-seal the same body with the accepted byte flipped: the signature
    // covers that byte, so the forgery fails.
    let (_, _, mut plain) = envelope::open(&ack_bytes, &alice.encryption_secret).unwrap();
    let flag = plain.len() - 65;
    plain[flag] = 1;
    let forged = envelope::seal(
        PACKAGE,
        envelope::KIND_FILE_DELIVERY_ACK,
        &alice.encryption_public,
        &plain,
    )
    .unwrap();
    assert!(open_ack(&conn, &alice.encryption_secret, &forged).is_err());
}

// ---- tracked-file letters ---------------------------------------------------

const CONTAINER: &[u8] = b"pretend this is a KQTF container";

fn history_from(alice: &Party, david: &Party) -> SealedHistoryLetter {
    seal_history_letter(&OutgoingHistory {
        sender_label: alice.label,
        sender_signing_secret: &alice.signing_secret,
        sender_encryption_public: &alice.encryption_public,
        recipient_label: david.label,
        recipient_encryption_public: &david.encryption_public,
        file_name: "plan.txt",
        file_id: [3; 16],
        revision_id: [4; 32],
        history_root: [5; 32],
        decision: 2,
        content_proof: [6; 32],
        container: CONTAINER,
    })
    .unwrap()
}

/// Unseal with the recipient's key, change one plaintext byte, and seal it
/// again, as an attacker who could alter the payload in flight would have to.
fn tampered(bytes: &[u8], david: &Party, kind: u8, offset: usize) -> Vec<u8> {
    let (found, _, mut plain) = envelope::open(bytes, &david.encryption_secret).unwrap();
    assert_eq!(found, kind);
    plain[offset] ^= 1;
    envelope::seal(PACKAGE, kind, &david.encryption_public, &plain).unwrap()
}

#[test]
fn a_tracked_letter_round_trips_through_the_inbox_and_back_as_an_ack() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let sealed = history_from(&alice, &david);

    // The relay carries it in the bridge inbox, not the device mailbox.
    assert!(!envelope::is_device_workflow_kind(
        envelope::KIND_FILE_HISTORY
    ));
    assert!(!envelope::is_device_workflow_kind(
        envelope::KIND_FILE_HISTORY_ACK
    ));
    let relay_conn = relay::open_in_memory().unwrap();
    let (_, fingerprint, _) = relay::store(&relay_conn, &sealed.bytes).unwrap();
    assert_eq!(fingerprint, keys::fingerprint(&david.encryption_public));
    let page = relay::list_after(&relay_conn, &fingerprint, None, None).unwrap();
    assert_eq!(page.envelopes.len(), 1);

    let letter =
        open_history_letter(&conn, &david.encryption_secret, &page.envelopes[0].bytes).unwrap();
    assert_eq!(letter.delivery_id, sealed.delivery_id);
    assert_eq!(
        (
            letter.sender_label.as_str(),
            letter.recipient_label.as_str()
        ),
        ("M.S.1", "M.A")
    );
    assert_eq!(letter.file_name, "plan.txt");
    assert_eq!(letter.file_id, [3; 16]);
    assert_eq!(letter.revision_id, [4; 32]);
    assert_eq!(letter.history_root, [5; 32]);
    assert_eq!(letter.decision, 2);
    assert_eq!(letter.content_proof, [6; 32]);
    assert_eq!(letter.container, CONTAINER);
    assert_eq!(letter.container_hash, sealed.container_hash);

    for accepted in [true, false] {
        let ack_bytes = seal_history_ack(&letter, &david.signing_secret, accepted).unwrap();
        relay::store(&relay_conn, &ack_bytes).unwrap();
        let ack = open_history_ack(&conn, &alice.encryption_secret, &ack_bytes).unwrap();
        assert_eq!(
            ack,
            HistoryAck {
                delivery_id: sealed.delivery_id,
                recipient_label: "M.A".into(),
                file_id: [3; 16],
                revision_id: [4; 32],
                container_hash: sealed.container_hash,
                accepted,
            }
        );
    }
}

#[test]
fn only_the_recipient_opens_a_tracked_letter_and_kinds_do_not_mix() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let sealed = history_from(&alice, &david);
    assert!(open_history_letter(&conn, &alice.encryption_secret, &sealed.bytes).is_err());
    // A tracked letter is not an ordinary delivery, and the reverse.
    assert!(open_letter(&conn, &david.encryption_secret, &sealed.bytes).is_err());
    let plain = letter_from(&alice, &david, b"text");
    assert!(open_history_letter(&conn, &david.encryption_secret, &plain.bytes).is_err());
    // Nor are the two kinds of answer interchangeable.
    let letter = open_history_letter(&conn, &david.encryption_secret, &sealed.bytes).unwrap();
    let ack = seal_history_ack(&letter, &david.signing_secret, true).unwrap();
    assert!(open_ack(&conn, &alice.encryption_secret, &ack).is_err());
}

#[test]
fn a_letter_signed_by_someone_else_or_an_unregistered_label_is_refused() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let mallory = register(&conn, "M.B");
    // Mallory claims to be alice but signs with her own key.
    let forged = seal_history_letter(&OutgoingHistory {
        sender_label: alice.label,
        sender_signing_secret: &mallory.signing_secret,
        sender_encryption_public: &mallory.encryption_public,
        recipient_label: david.label,
        recipient_encryption_public: &david.encryption_public,
        file_name: "plan.txt",
        file_id: [3; 16],
        revision_id: [4; 32],
        history_root: [5; 32],
        decision: 2,
        content_proof: [6; 32],
        container: CONTAINER,
    })
    .unwrap();
    assert!(open_history_letter(&conn, &david.encryption_secret, &forged.bytes).is_err());
    // A label this store has never registered.
    let stranger = Party {
        label: "X.9",
        ..register(&db::open_in_memory().unwrap(), "X.9")
    };
    let unknown = history_from(&stranger, &david);
    assert!(open_history_letter(&conn, &david.encryption_secret, &unknown.bytes).is_err());
}

#[test]
fn every_signed_header_field_and_the_container_are_bound() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let sealed = history_from(&alice, &david);
    // Plaintext layout for these labels and name: delivery id 0..16, sender
    // 16..23, recipient 23..28, return key 28..60, name 60..70, then the
    // file id, revision id, history root, the decision, the proof
    // descriptor and the container.
    let header = [
        ("file id", 70),
        ("revision id", 86),
        ("history root", 118),
        ("decision", 150),
        ("proof descriptor", 151),
        ("container", 187),
        ("return key", 30),
        ("delivery id", 0),
    ];
    for (field, offset) in header {
        let altered = tampered(&sealed.bytes, &david, envelope::KIND_FILE_HISTORY, offset);
        assert!(
            open_history_letter(&conn, &david.encryption_secret, &altered).is_err(),
            "{field} is not covered by the signature"
        );
    }
}

#[test]
fn an_ack_binds_the_answer_and_what_it_answers() {
    let conn = db::open_in_memory().unwrap();
    let alice = register(&conn, "M.S.1");
    let david = register(&conn, "M.A");
    let sealed = history_from(&alice, &david);
    let letter = open_history_letter(&conn, &david.encryption_secret, &sealed.bytes).unwrap();
    let ack = seal_history_ack(&letter, &david.signing_secret, true).unwrap();
    // Layout: delivery id 0..16, label 16..21, file id 21..37, revision
    // 37..69, container hash 69..101, then the accepted flag.
    for (field, offset) in [
        ("delivery id", 0),
        ("file id", 21),
        ("revision id", 37),
        ("container hash", 69),
        ("accepted", 101),
    ] {
        let (_, _, mut plain) = envelope::open(&ack, &alice.encryption_secret).unwrap();
        plain[offset] ^= 1;
        let altered = envelope::seal(
            PACKAGE,
            envelope::KIND_FILE_HISTORY_ACK,
            &alice.encryption_public,
            &plain,
        )
        .unwrap();
        assert!(
            open_history_ack(&conn, &alice.encryption_secret, &altered).is_err(),
            "{field} is not covered by the signature"
        );
    }
}
