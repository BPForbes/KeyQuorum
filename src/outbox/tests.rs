use super::*;
use crate::envelope::{self, EXPORT_BUNDLE, KIND_FILE_DELIVERY, PACKAGE};
use crate::file_delivery::exchange::Step;
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

    let queued: Vec<Vec<u8>> = (0..3u8).map(|n| letter(&p.bob, &[n])).collect();
    for (n, bytes) in (0u32..).zip(&queued) {
        let item = push(&p.conn, "alice", "bob", bytes, None).expect("push");
        assert_eq!(item.index, n);
        assert_eq!(item.kind, KIND_FILE_DELIVERY);
    }
    let full = ring(&p.conn, "alice").unwrap();
    assert_eq!(
        (full.state(), full.size, full.free()),
        (RingState::Full, 3, 0)
    );
    // Full: refused, and nothing already held is overwritten.
    assert!(matches!(
        push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None),
        Err(Error::OutboxFull)
    ));
    assert_eq!(list(&p.conn, "alice").unwrap().len(), 3);

    // The read pointer gives the oldest first, exactly as it was queued,
    // and frees its slot.
    let (first, bytes) = sent_by(&p.conn, "alice").expect("one sent");
    assert_eq!(first.index, 0);
    assert_eq!(bytes, queued[0]);
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
    let wrapped_bytes = letter(&p.bob, b"w");
    let wrapped = push(&p.conn, "alice", "bob", &wrapped_bytes, None).expect("push");
    assert_eq!(wrapped.index, 0);
    let order: Vec<u32> = list(&p.conn, "alice")
        .unwrap()
        .iter()
        .map(|i| i.index)
        .collect();
    assert_eq!(order, vec![1, 2, 0]);

    let rest: Vec<Vec<u8>> = std::iter::from_fn(|| sent_by(&p.conn, "alice"))
        .map(|(_, bytes)| bytes)
        .collect();
    assert_eq!(
        rest,
        vec![queued[1].clone(), queued[2].clone(), wrapped_bytes]
    );
    let empty = ring(&p.conn, "alice").unwrap();
    assert_eq!((empty.state(), empty.sent_total), (RingState::Empty, 4));
    let rows: i64 = p
        .conn
        .query_row("SELECT COUNT(*) FROM outbox_slots", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "sent slots are deleted, not kept");
}

#[test]
fn letters_go_only_to_the_trusted_recipient_they_are_sealed_to() {
    let p = people();
    // No key registered for dave: not trusted.
    let (_, dave) = keys::generate_encryption_keypair();
    assert!(matches!(
        push(&p.conn, "alice", "dave", &letter(&dave, b"x"), None),
        Err(Error::UntrustedRecipient)
    ));
    // Sealed to carol, addressed to bob: refused.
    assert!(matches!(
        push(&p.conn, "alice", "bob", &letter(&p.carol, b"x"), None),
        Err(Error::UntrustedRecipient)
    ));
    // An owner this store does not know has no ring.
    assert!(matches!(
        push(&p.conn, "mallory", "bob", &letter(&p.bob, b"x"), None),
        Err(Error::NodeNotFound)
    ));
}

#[test]
fn only_a_kqpb_passport_crosses_between_rings() {
    let p = people();
    // An export bundle sealed to bob is still not a letter: it travels
    // inside one (`keyquorum send`), signed.
    let bundle = envelope::seal(EXPORT_BUNDLE, 1, &p.bob, b"bundle").unwrap();
    // A device letter moves someone's own identity between their own
    // devices; it never goes to another person's ring.
    let device = envelope::seal(PACKAGE, envelope::KIND_DEVICE_TRANSFER, &p.bob, b"KQTX").unwrap();
    for refused in [
        bundle,
        device,
        b"KQTF\x07tracked file content in the clear".to_vec(),
        b"KQHS\x01snapshot".to_vec(),
        b"KQBN\x02notice".to_vec(),
        b"not a kq file".to_vec(),
    ] {
        assert!(
            matches!(
                push(&p.conn, "alice", "bob", &refused, None),
                Err(Error::OutboxItemRefused)
            ),
            "{refused:?}"
        );
    }
    assert_eq!(ring(&p.conn, "alice").unwrap().state(), RingState::Empty);
}

#[test]
fn a_tracked_file_letter_needs_the_copy_that_shows_its_order() {
    let p = people();
    // A request opens an exchange and needs nothing before it.
    let request = envelope::seal(PACKAGE, envelope::KIND_FILE_REQUEST, &p.bob, b"r").unwrap();
    assert_eq!(
        push(&p.conn, "alice", "bob", &request, None).unwrap().kind,
        envelope::KIND_FILE_REQUEST
    );
    // Every later step is checked against the sender's copy of the file.
    for kind in [
        envelope::KIND_FILE_REQUEST_ANSWER,
        envelope::KIND_FILE_HISTORY,
        envelope::KIND_FILE_HISTORY_ACK,
        envelope::KIND_FILE_HISTORY_SNAPSHOT,
    ] {
        assert!(Step::for_kind(kind).is_some());
        let later = envelope::seal(PACKAGE, kind, &p.bob, b"x").unwrap();
        assert!(
            matches!(
                push(&p.conn, "alice", "bob", &later, None),
                Err(Error::ExchangeOutOfOrder(_))
            ),
            "kind {kind}"
        );
    }
}

#[test]
fn revoking_the_recipient_stops_a_queued_send_and_moves_nothing() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None).expect("push");
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
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None).expect("push");
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
fn an_oversized_letter_is_refused() {
    let p = people();
    let mut huge = letter(&p.bob, b"x");
    huge.resize(MAX_ITEM_BYTES + 1, 0);
    assert!(matches!(
        push(&p.conn, "alice", "bob", &huge, None),
        Err(Error::BundleFieldTooLarge)
    ));
    assert_eq!(ring(&p.conn, "alice").unwrap().state(), RingState::Empty);
}

#[test]
fn only_an_empty_ring_is_resized() {
    let p = people();
    assert_eq!(ring(&p.conn, "alice").unwrap().capacity, DEFAULT_CAPACITY);
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None).expect("push");
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
    push(
        &p.conn,
        "alice",
        "bob",
        &letter(&p.bob, b"from alice"),
        None,
    )
    .expect("alice");
    push(
        &p.conn,
        "bob",
        "carol",
        &letter(&p.carol, b"from bob"),
        None,
    )
    .expect("bob");
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

fn rules(conn: &Connection, owner: &str) -> Vec<Refusal> {
    refusals(conn, owner, MAX_REFUSALS_KEPT)
        .unwrap()
        .into_iter()
        .map(|r| r.refusal)
        .collect()
}

#[test]
fn every_letter_turned_away_at_departure_is_recorded_with_its_rule() {
    let p = people();
    set_capacity(&p.conn, "alice", 1).expect("capacity");
    let (_, dave) = keys::generate_encryption_keypair();
    let device = envelope::seal(PACKAGE, envelope::KIND_DEVICE_TRANSFER, &p.bob, b"KQTX").unwrap();
    let mut huge = letter(&p.bob, b"x");
    huge.resize(MAX_ITEM_BYTES + 1, 0);
    let answer = envelope::seal(PACKAGE, envelope::KIND_FILE_REQUEST_ANSWER, &p.bob, b"a").unwrap();

    assert!(push(&p.conn, "alice", "bob", &huge, None).is_err());
    assert!(push(&p.conn, "alice", "bob", b"not a kq file", None).is_err());
    assert!(push(&p.conn, "alice", "bob", &device, None).is_err());
    assert!(push(&p.conn, "alice", "dave", &letter(&dave, b"x"), None).is_err());
    assert!(push(&p.conn, "alice", "bob", &answer, None).is_err());
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"one"), None).expect("fits");
    assert!(matches!(
        push(&p.conn, "alice", "bob", &letter(&p.bob, b"two"), None),
        Err(Error::OutboxFull)
    ));

    // Newest first, each with the rule it broke.
    assert_eq!(
        rules(&p.conn, "alice"),
        vec![
            Refusal::RingFull,
            Refusal::OutOfOrder,
            Refusal::UnrecognisedDestination,
            Refusal::DeviceLetter,
            Refusal::NoPassport,
            Refusal::Oversized,
        ]
    );
    let recorded = refusals(&p.conn, "alice", MAX_REFUSALS_KEPT).unwrap();
    let out_of_order = &recorded[1];
    assert_eq!(out_of_order.kind, Some(envelope::KIND_FILE_REQUEST_ANSWER));
    assert!(out_of_order
        .step
        .as_deref()
        .is_some_and(|s| s.contains("needs your copy")));
    assert_eq!(recorded[2].recipient, "dave");
    assert_eq!(recorded[4].kind, None, "no readable header, no kind");

    // The record holds nothing from the letter: no content, no hash.
    let columns: Vec<String> = p
        .conn
        .prepare("SELECT name FROM pragma_table_info('outbox_refusals')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(columns
        .iter()
        .all(|c| !c.contains("content") && !c.contains("hash")));

    // An owner this store does not know has nothing recorded.
    assert!(push(&p.conn, "mallory", "bob", b"junk", None).is_err());
    assert!(rules(&p.conn, "mallory").is_empty());
}

#[test]
fn a_letter_stopped_at_the_gate_is_recorded_though_the_send_rolls_back() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None).expect("push");

    // A failed delivery is not a refusal: nothing is recorded.
    assert!(send_next(&p.conn, "alice", |_, _| Err(Error::RelayRequest(
        "down".into()
    )))
    .is_err());
    assert!(rules(&p.conn, "alice").is_empty());

    // The held letter is altered: refused as tampered, never handed out.
    p.conn
        .execute(
            "UPDATE outbox_slots SET content = zeroblob(length(content))",
            [],
        )
        .unwrap();
    let mut called = false;
    assert!(matches!(
        send_next(&p.conn, "alice", |_, _| {
            called = true;
            Ok(())
        }),
        Err(Error::IntegrityCheckFailed)
    ));
    assert!(!called);
    assert_eq!(rules(&p.conn, "alice"), vec![Refusal::Tampered]);
    drop_next(&p.conn, "alice").unwrap();

    // The recipient's key is revoked after queuing: stopped at the gate.
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"y"), None).expect("push");
    let bob_key = keys::active_keys_for(&p.conn, "bob", KeyType::Encryption).unwrap()[0].id;
    keys::revoke_key(&p.conn, bob_key).expect("revoke");
    assert!(matches!(
        send_next(&p.conn, "alice", |_, _| Ok(())),
        Err(Error::UntrustedRecipient)
    ));
    assert_eq!(
        rules(&p.conn, "alice"),
        vec![Refusal::UnrecognisedDestination, Refusal::Tampered]
    );
    let ring_now = ring(&p.conn, "alice").unwrap();
    assert_eq!(
        (ring_now.size, ring_now.sent_total),
        (1, 0),
        "nothing moved"
    );
}

#[test]
fn only_the_newest_refusals_are_kept() {
    let p = people();
    for _ in 0..MAX_REFUSALS_KEPT + 5 {
        assert!(push(&p.conn, "alice", "bob", b"junk", None).is_err());
    }
    assert!(push(&p.conn, "bob", "carol", b"junk", None).is_err());
    let kept: i64 = p
        .conn
        .query_row(
            "SELECT COUNT(*) FROM outbox_refusals WHERE owner_label = 'alice'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, i64::from(MAX_REFUSALS_KEPT));
    assert_eq!(rules(&p.conn, "bob").len(), 1, "each owner keeps their own");
    assert_eq!(refusals(&p.conn, "alice", 3).unwrap().len(), 3);
}

#[test]
fn a_send_in_flight_holds_no_transaction_and_keeps_the_head_from_others() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None).expect("push");
    push(&p.conn, "alice", "carol", &letter(&p.carol, b"y"), None).expect("push");

    let sent = send_next(&p.conn, "alice", |item, _| {
        // Delivered with no transaction open, so the rest of the store can
        // be written meanwhile.
        assert!(p.conn.is_autocommit(), "no transaction during delivery");
        keys::register_key(&p.conn, "dave", KeyType::Encryption, &[7; 32]).expect("other write");
        // The claimed head is taken by neither another send nor a drop.
        assert!(matches!(
            send_next(&p.conn, "alice", |_, _| Ok(())),
            Err(Error::Usage(_))
        ));
        assert!(matches!(drop_next(&p.conn, "alice"), Err(Error::Usage(_))));
        assert_eq!(item.recipient, "bob");
        Ok(())
    })
    .expect("send")
    .expect("an item");
    assert_eq!(sent.recipient, "bob");
    let after = ring(&p.conn, "alice").unwrap();
    assert_eq!((after.size, after.sent_total), (1, 1));
}

#[test]
fn a_failed_delivery_frees_the_claim_at_once() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None).expect("push");
    assert!(send_next(&p.conn, "alice", |_, _| Err(Error::RelayRequest(
        "down".into()
    )))
    .is_err());
    // The retry does not wait for the claim to lapse.
    assert!(send_next(&p.conn, "alice", |_, _| Ok(()))
        .expect("retry")
        .is_some());
    assert_eq!(ring(&p.conn, "alice").unwrap().state(), RingState::Empty);
}

#[test]
fn a_claim_left_by_a_crashed_send_lapses_and_the_letter_goes_again() {
    let p = people();
    push(&p.conn, "alice", "bob", &letter(&p.bob, b"x"), None).expect("push");
    // A send claimed the head and never came back.
    p.conn
        .execute(
            "UPDATE outbox_slots
             SET claim_token = 'crashed', claimed_at = CAST(strftime('%s', 'now') AS INTEGER)",
            [],
        )
        .unwrap();
    assert!(matches!(
        send_next(&p.conn, "alice", |_, _| Ok(())),
        Err(Error::Usage(_))
    ));
    assert!(matches!(drop_next(&p.conn, "alice"), Err(Error::Usage(_))));

    p.conn
        .execute(
            "UPDATE outbox_slots SET claimed_at = claimed_at - ?1",
            [CLAIM_LEASE_SECS + 1],
        )
        .unwrap();
    assert!(send_next(&p.conn, "alice", |_, _| Ok(()))
        .expect("send after the lease")
        .is_some());
    let after = ring(&p.conn, "alice").unwrap();
    assert_eq!((after.state(), after.sent_total), (RingState::Empty, 1));
}
