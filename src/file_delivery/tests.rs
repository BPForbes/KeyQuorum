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
