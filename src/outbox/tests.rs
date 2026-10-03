use super::*;
use crate::envelope::{self, EXPORT_BUNDLE, KIND_FILE_DELIVERY, PACKAGE};
use crate::keys::{self, KeyType};
use std::cell::RefCell;

struct People {
    conn: Connection,
    bob: [u8; 32],
    carol: [u8; 32],
}

/// Alice's store, where she and two recipients have encryption keys.
fn people() -> People {
    let conn = crate::db::open_in_memory().expect("store");
    let (_, alice) = keys::generate_encryption_keypair();
    let (_, bob) = keys::generate_encryption_keypair();
    let (_, carol) = keys::generate_encryption_keypair();
    keys::register_key(&conn, "alice", KeyType::Encryption, &alice).expect("alice");
    keys::register_key(&conn, "bob", KeyType::Encryption, &bob).expect("bob");
    keys::register_key(&conn, "carol", KeyType::Encryption, &carol).expect("carol");
    People { conn, bob, carol }
}

fn letter(to: &[u8; 32], body: &[u8]) -> Vec<u8> {
    envelope::seal(PACKAGE, KIND_FILE_DELIVERY, to, body).expect("seal")
}

/// A `.kqbn` notice naming `removed`, `remaining` and nobody to notify.
fn notice(removed: &str, remaining: &[&str]) -> Vec<u8> {
    let mut out = b"KQBN".to_vec();
    out.push(2);
    out.push(1);
    envelope::push_len_prefixed(&mut out, b"bridge-uid").unwrap();
    envelope::push_len_prefixed(&mut out, removed.as_bytes()).unwrap();
    out.extend_from_slice(&(remaining.len() as u16).to_be_bytes());
    for label in remaining {
        envelope::push_len_prefixed(&mut out, label.as_bytes()).unwrap();
    }
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn sent_by(conn: &Connection, owner: &str) -> Option<(QueuedItem, Vec<u8>)> {
    let out = RefCell::new(None);
    let item = send_next(conn, owner, |item, bytes| {
        *out.borrow_mut() = Some((item.clone(), bytes.to_vec()));
        Ok(())
    })
    .expect("send");
    assert_eq!(item.is_some(), out.borrow().is_some());
    out.into_inner()
}

#[test]
fn the_ring_is_first_in_first_out_and_wraps_around() {
    let p = people();
    set_capacity(&p.conn, "alice", 3).expect("capacity");
    assert_eq!(ring(&p.conn, "alice").unwrap().state(), RingState::Empty);
    assert!(
        sent_by(&p.conn, "alice").is_none(),
        "an empty ring sends nothing"
    );

    for n in 0..3u8 {
        let item = push(&p.conn, "alice", "bob", &letter(&p.bob, &[n])).expect("push");
        assert_eq!(item.index, u32::from(n));
        assert_eq!(item.kind, ItemKind::Package);
    }
    let full = ring(&p.conn, "alice").unwrap();
    assert_eq!(
        (full.state(), full.size, full.free()),
        (RingState::Full, 3, 0)
    );
    // Full: refused, and nothing already held is overwritten.
    assert!(matches!(
        push(&p.conn, "alice", "bob", &letter(&p.bob, b"x")),
        Err(Error::OutboxFull)
    ));
    assert_eq!(list(&p.conn, "alice").unwrap().len(), 3);

    // The read pointer gives the oldest first and frees its slot.
    let (first, bytes) = sent_by(&p.conn, "alice").expect("one sent");
    assert_eq!(first.index, 0);
    assert_eq!(bytes, letter_body_check(&bytes));
    let partial = ring(&p.conn, "alice").unwrap();
    assert_eq!(
        (
            partial.state(),
            partial.read_index,
            partial.write_index,
            partial.size
        ),
        (RingState::Partial, 1, 0, 2)
    );

    // The next item is written into the freed slot 0: the ring wraps.
    let wrapped = push(&p.conn, "alice", "bob", &letter(&p.bob, b"w")).expect("push");
    assert_eq!(wrapped.index, 0);
    let order: Vec<u32> = list(&p.conn, "alice")
        .unwrap()
        .iter()
        .map(|i| i.index)
        .collect();
    assert_eq!(order, vec![1, 2, 0]);

    while sent_by(&p.conn, "alice").is_some() {}
    let empty = ring(&p.conn, "alice").unwrap();
    assert_eq!((empty.state(), empty.sent_total), (RingState::Empty, 4));
    let rows: i64 = p
        .conn
        .query_row("SELECT COUNT(*) FROM outbox_slots", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "sent slots are deleted, not kept");
}

/// The bytes handed to the sender are the bytes that were queued.
fn letter_body_check(bytes: &[u8]) -> Vec<u8> {
    envelope::parse_outer(bytes).expect("still a whole letter");
    bytes.to_vec()
}

#[test]
fn items_go_only_to_a_trusted_recipient_they_pertain_to() {
    let p = people();
    // No key registered for dave: not trusted.
    let (_, dave) = keys::generate_encryption_keypair();
    assert!(matches!(
        push(&p.conn, "alice", "dave", &letter(&dave, b"x")),
        Err(Error::UntrustedRecipient)
    ));
    // Sealed to carol, addressed to bob: refused.
    assert!(matches!(
        push(&p.conn, "alice", "bob", &letter(&p.carol, b"x")),
        Err(Error::UntrustedRecipient)
    ));
    // The same rule for export bundles.
    let bundle = envelope::seal(EXPORT_BUNDLE, 1, &p.carol, b"bundle").unwrap();
    assert!(matches!(
        push(&p.conn, "alice", "bob", &bundle),
        Err(Error::UntrustedRecipient)
    ));
    assert_eq!(
        push(&p.conn, "alice", "carol", &bundle).unwrap().kind,
        ItemKind::ExportBundle
    );
    // A notice goes only to someone it names.
    assert!(matches!(
        push(&p.conn, "alice", "carol", &notice("dave", &["bob"])),
        Err(Error::UntrustedRecipient)
    ));
    assert_eq!(
        push(&p.conn, "alice", "bob", &notice("dave", &["bob"]))
            .unwrap()
            .kind,
        ItemKind::EvictionNotice
    );
    // An owner this store does not know has no ring.
    assert!(matches!(
        push(&p.conn, "mallory", "bob", &letter(&p.bob, b"x")),
        Err(Error::NodeNotFound)
    ));
}

#[test]
fn revoking_the_recipient_stops_a_queued_send_and_moves_nothing() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x")).expect("push");
    let bob_key = keys::active_keys_for(&p.conn, "bob", KeyType::Encryption).unwrap()[0].id;
    keys::revoke_key(&p.conn, bob_key).expect("revoke");

    let mut called = false;
    assert!(matches!(
        send_next(&p.conn, "alice", |_, _| {
            called = true;
            Ok(())
        }),
        Err(Error::UntrustedRecipient)
    ));
    assert!(!called, "nothing is handed out for an untrusted recipient");
    let ring_now = ring(&p.conn, "alice").unwrap();
    assert_eq!((ring_now.read_index, ring_now.size), (0, 1));

    // The owner can drop it; it is wiped and not counted as sent.
    let dropped = drop_next(&p.conn, "alice").unwrap().expect("dropped");
    assert_eq!(dropped.recipient, "bob");
    let after = ring(&p.conn, "alice").unwrap();
    assert_eq!((after.state(), after.sent_total), (RingState::Empty, 0));
}

#[test]
fn a_failed_delivery_keeps_the_item_at_the_read_pointer() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x")).expect("push");
    assert!(send_next(&p.conn, "alice", |_, _| Err(Error::RelayRequest(
        "down".into()
    )))
    .is_err());
    let ring_now = ring(&p.conn, "alice").unwrap();
    assert_eq!(
        (ring_now.read_index, ring_now.size, ring_now.sent_total),
        (0, 1, 0)
    );
    assert!(sent_by(&p.conn, "alice").is_some(), "the retry sends it");
}

#[test]
fn only_outbox_kinds_of_a_bounded_size_are_queued() {
    let p = people();
    for refused in [
        b"KQTF\x07tracked file content in the clear".to_vec(),
        b"KQTX\x01transfer package".to_vec(),
        b"not a kq file".to_vec(),
        b"KQPB".to_vec(),
    ] {
        assert!(
            push(&p.conn, "alice", "bob", &refused).is_err(),
            "{refused:?}"
        );
    }
    let mut huge = letter(&p.bob, b"x");
    huge.resize(MAX_ITEM_BYTES + 1, 0);
    assert!(matches!(
        push(&p.conn, "alice", "bob", &huge),
        Err(Error::BundleFieldTooLarge)
    ));
    assert_eq!(ring(&p.conn, "alice").unwrap().state(), RingState::Empty);
}

#[test]
fn only_an_empty_ring_is_resized() {
    let p = people();
    assert_eq!(ring(&p.conn, "alice").unwrap().capacity, DEFAULT_CAPACITY);
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x")).expect("push");
    assert!(matches!(
        set_capacity(&p.conn, "alice", 4),
        Err(Error::OutboxNotEmpty)
    ));
    sent_by(&p.conn, "alice").expect("sent");
    assert_eq!(set_capacity(&p.conn, "alice", 4).unwrap().capacity, 4);
    assert!(set_capacity(&p.conn, "alice", 0).is_err());
    assert!(set_capacity(&p.conn, "alice", MAX_CAPACITY + 1).is_err());
}

#[test]
fn each_person_has_their_own_ring() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"from alice")).expect("alice");
    push(&p.conn, "bob", "carol", &letter(&p.carol, b"from bob")).expect("bob");
    assert_eq!(ring(&p.conn, "alice").unwrap().size, 1);
    assert_eq!(ring(&p.conn, "bob").unwrap().size, 1);
    let (item, _) = sent_by(&p.conn, "bob").expect("bob sends");
    assert_eq!(item.recipient, "carol");
    assert_eq!(
        ring(&p.conn, "alice").unwrap().size,
        1,
        "alice's ring is untouched"
    );
}

#[test]
fn signatures_and_history_snapshots_are_carried_to_registered_recipients() {
    let p = people();
    let signature = crate::signing::encode_bridge_signature(&crate::signing::BridgeSignature {
        uid: "bridge-uid".into(),
        generation: 1,
        bridge_salt: [1; crate::crypto::SALT_LEN],
        signature_salt: [2; crate::crypto::SALT_LEN],
        signer_label: "alice".into(),
        signer_public_key: [3; 32],
        bridge_signature: [4; 64],
        personal_signature: [5; 64],
    })
    .unwrap();
    assert_eq!(
        push(&p.conn, "alice", "bob", &signature).unwrap().kind,
        ItemKind::BridgeSignature
    );
    let file_id = [9u8; 16];
    let snapshot = crate::file_history::HistorySnapshot {
        file_id,
        history_root: crate::file_history::genesis_hash(&file_id),
        events: Vec::new(),
    }
    .encode()
    .unwrap();
    assert_eq!(
        push(&p.conn, "alice", "carol", &snapshot).unwrap().kind,
        ItemKind::HistorySnapshot
    );
    // Unsealed kinds still need a registered recipient.
    assert!(matches!(
        push(&p.conn, "alice", "dave", &snapshot),
        Err(Error::UntrustedRecipient)
    ));
    // A truncated artifact is not accepted as one.
    assert!(push(&p.conn, "alice", "bob", &signature[..signature.len() - 1]).is_err());
}
