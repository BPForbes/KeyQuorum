use super::*;
use crate::db;
use crate::keys::{self, KeyType};
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

fn request(from: &Party, to: &Party, kind: RequestKind, message: &str) -> SealedRequest {
    seal_request(&OutgoingRequest {
        sender_label: from.label,
        sender_signing_secret: &from.signing_secret,
        sender_encryption_public: &from.encryption_public,
        recipient_label: to.label,
        recipient_encryption_public: &to.encryption_public,
        file_name: "report.txt",
        file_id: [7; 16],
        kind,
        base_revision: (kind == RequestKind::Change).then_some([9; 32]),
        message,
    })
    .unwrap()
}

#[test]
fn a_change_request_round_trips_and_its_answer_is_bound_to_it() {
    let conn = db::open_in_memory().unwrap();
    let (bob, alice) = (register(&conn, "M.B"), register(&conn, "M.A"));
    let sealed = request(&bob, &alice, RequestKind::Change, "please fix the total");

    let opened = open_request(&conn, &alice.encryption_secret, &sealed.bytes).unwrap();
    assert_eq!(opened.request_id, sealed.request_id);
    assert_eq!(opened.requester_label, "M.B");
    assert_eq!(opened.holder_label, "M.A");
    assert_eq!(opened.kind, RequestKind::Change);
    assert_eq!(opened.base_revision, Some([9; 32]));
    assert_eq!(opened.message, "please fix the total");
    assert_eq!(opened.return_public, bob.encryption_public);

    let answer_bytes = seal_request_answer(&opened, &alice.signing_secret, true).unwrap();
    let answer = open_request_answer(&conn, &bob.encryption_secret, &answer_bytes).unwrap();
    assert_eq!(answer.request_id, sealed.request_id);
    assert_eq!(answer.holder_label, "M.A");
    assert_eq!(answer.request_hash, opened.request_hash);
    assert!(answer.accepted);
    let declined = seal_request_answer(&opened, &alice.signing_secret, false).unwrap();
    assert!(
        !open_request_answer(&conn, &bob.encryption_secret, &declined)
            .unwrap()
            .accepted
    );
}

#[test]
fn a_file_request_carries_no_message_and_no_base_revision() {
    let conn = db::open_in_memory().unwrap();
    let (bob, alice) = (register(&conn, "M.B"), register(&conn, "M.A"));
    let sealed = request(&bob, &alice, RequestKind::File, "");
    let opened = open_request(&conn, &alice.encryption_secret, &sealed.bytes).unwrap();
    assert_eq!(opened.kind, RequestKind::File);
    assert_eq!(opened.base_revision, None);
    assert!(opened.message.is_empty());
    // Asking for a file cannot smuggle a message, and a message has a limit.
    let refused = seal_request(&OutgoingRequest {
        message: "extra",
        ..outgoing(&bob, &alice, RequestKind::File)
    });
    assert!(refused.is_err());
    let too_long = "x".repeat(MAX_REQUEST_MESSAGE + 1);
    assert!(seal_request(&OutgoingRequest {
        message: &too_long,
        ..outgoing(&bob, &alice, RequestKind::Change)
    })
    .is_err());
}

fn outgoing<'a>(from: &'a Party, to: &'a Party, kind: RequestKind) -> OutgoingRequest<'a> {
    OutgoingRequest {
        sender_label: from.label,
        sender_signing_secret: &from.signing_secret,
        sender_encryption_public: &from.encryption_public,
        recipient_label: to.label,
        recipient_encryption_public: &to.encryption_public,
        file_name: "report.txt",
        file_id: [7; 16],
        kind,
        base_revision: None,
        message: "",
    }
}

#[test]
fn a_request_is_only_believed_from_the_signing_key_this_store_registered() {
    let conn = db::open_in_memory().unwrap();
    let (bob, alice) = (register(&conn, "M.B"), register(&conn, "M.A"));
    // A stranger signs as M.B with a key this store never registered.
    let impostor = seal_request(&OutgoingRequest {
        sender_signing_secret: &Zeroizing::new(*keys::generate_signing_keypair().0),
        ..outgoing(&bob, &alice, RequestKind::File)
    })
    .unwrap();
    assert!(open_request(&conn, &alice.encryption_secret, &impostor.bytes).is_err());
    // Only the holder's key opens it.
    let genuine = request(&bob, &alice, RequestKind::File, "");
    assert!(open_request(&conn, &bob.encryption_secret, &genuine.bytes).is_err());
}

#[test]
fn an_answer_forged_by_anyone_but_the_holder_is_refused() {
    let conn = db::open_in_memory().unwrap();
    let (bob, alice) = (register(&conn, "M.B"), register(&conn, "M.A"));
    let sealed = request(&bob, &alice, RequestKind::File, "");
    let opened = open_request(&conn, &alice.encryption_secret, &sealed.bytes).unwrap();
    // Bob signs the "answer" himself: it does not verify as M.A's.
    let forged = seal_request_answer(&opened, &bob.signing_secret, true).unwrap();
    assert!(open_request_answer(&conn, &bob.encryption_secret, &forged).is_err());
    // A tampered byte breaks the seal or the signature.
    let mut bytes = seal_request_answer(&opened, &alice.signing_secret, true).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(open_request_answer(&conn, &bob.encryption_secret, &bytes).is_err());
}

#[test]
fn a_request_and_an_answer_never_open_as_each_other_or_as_a_file_letter() {
    let conn = db::open_in_memory().unwrap();
    let (bob, alice) = (register(&conn, "M.B"), register(&conn, "M.A"));
    let sealed = request(&bob, &alice, RequestKind::File, "");
    assert!(open_request_answer(&conn, &alice.encryption_secret, &sealed.bytes).is_err());
    let opened = open_request(&conn, &alice.encryption_secret, &sealed.bytes).unwrap();
    let answer = seal_request_answer(&opened, &alice.signing_secret, true).unwrap();
    assert!(open_request(&conn, &bob.encryption_secret, &answer).is_err());
    assert!(crate::file_delivery::open_history_snapshot(
        &conn,
        &alice.encryption_secret,
        &sealed.bytes
    )
    .is_err());
}

#[test]
fn requests_and_answers_travel_through_the_relay_mailbox_like_any_letter() {
    use crate::relay;
    let conn = db::open_in_memory().unwrap();
    let (bob, alice) = (register(&conn, "M.B"), register(&conn, "M.A"));
    let sealed = request(&bob, &alice, RequestKind::File, "");
    let relay_conn = relay::open_in_memory().unwrap();
    let (_, holder_fingerprint, duplicate) = relay::store(&relay_conn, &sealed.bytes).unwrap();
    assert!(!duplicate);
    assert_eq!(
        holder_fingerprint,
        keys::fingerprint(&alice.encryption_public)
    );
    let page = relay::list_after(&relay_conn, &holder_fingerprint, None, None).unwrap();
    let opened = open_request(&conn, &alice.encryption_secret, &page.envelopes[0].bytes).unwrap();
    let answer = seal_request_answer(&opened, &alice.signing_secret, true).unwrap();
    let (_, requester_fingerprint, _) = relay::store(&relay_conn, &answer).unwrap();
    assert_eq!(
        requester_fingerprint,
        keys::fingerprint(&bob.encryption_public)
    );
    // The relay only ever holds the sealed bytes.
    assert!(!page.envelopes[0]
        .bytes
        .windows(10)
        .any(|w| w == b"report.txt"));
}
