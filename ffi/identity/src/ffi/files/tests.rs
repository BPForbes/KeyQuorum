use super::*;
use std::ffi::CString;

const FILE_ID: [u8; 16] = [7; 16];
const T1: &str = "2026-10-20T09:00:00.000Z";
const T2: &str = "2026-10-20T10:00:00.000Z";
const T3: &str = "2026-10-20T11:00:00.000Z";

struct Account {
    label: CString,
    signing_secret: Zeroizing<[u8; 32]>,
    signing_public: [u8; 32],
    box_secret: Zeroizing<[u8; 32]>,
    box_public: [u8; 32],
}

fn account(label: &str) -> Account {
    let (signing_secret, signing_public) = crate::account::generate();
    let (box_secret, box_public) = crate::account::generate_box();
    Account {
        label: CString::new(label).unwrap(),
        signing_secret,
        signing_public,
        box_secret,
        box_public,
    }
}

fn s(text: &str) -> CString {
    CString::new(text).unwrap()
}

/// Owns the key table and the labels it points into.
struct Trust {
    _labels: Vec<CString>,
    keys: Vec<KqFileKey>,
}

impl Trust {
    fn of(accounts: &[&Account]) -> Self {
        let labels: Vec<CString> = accounts.iter().map(|a| a.label.clone()).collect();
        let keys = labels
            .iter()
            .zip(accounts)
            .map(|(label, a)| KqFileKey {
                label: label.as_ptr(),
                signing_public: a.signing_public,
            })
            .collect();
        Trust {
            _labels: labels,
            keys,
        }
    }

    fn table(&self) -> KqFileTrust {
        KqFileTrust {
            keys: self.keys.as_ptr(),
            nkeys: self.keys.len(),
        }
    }
}

/// Calls an output-buffer function twice: once to size, once to fill.
fn collect(mut call: impl FnMut(*mut u8, usize, *mut usize) -> c_int) -> (c_int, Vec<u8>) {
    let mut len = 0usize;
    let first = call(std::ptr::null_mut(), 0, &mut len);
    if first != KQ_FILE_NO_ROOM {
        return (first, Vec::new());
    }
    let mut out = vec![0u8; len];
    let rc = call(out.as_mut_ptr(), out.len(), &mut len);
    out.truncate(len);
    (rc, out)
}

fn new_file(owner: &str) -> Vec<u8> {
    let (name, owner) = (s("plan.txt"), s(owner));
    let (rc, c) = collect(|out, cap, len| unsafe {
        kq_file_new(
            FILE_ID.as_ptr(),
            name.as_ptr(),
            owner.as_ptr(),
            out,
            cap,
            len,
        )
    });
    assert_eq!(rc, KQ_FILE_OK, "kq_file_new");
    c
}

fn check_in(c: &[u8], author: &Account, at: &str, payload: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let at = s(at);
    let mut rev = [0u8; 32];
    let rev_ptr = rev.as_mut_ptr();
    let (rc, out) = collect(|out, cap, len| unsafe {
        kq_file_check_in(
            c.as_ptr(),
            c.len(),
            author.label.as_ptr(),
            at.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            author.signing_secret.as_ptr(),
            out,
            cap,
            len,
            rev_ptr,
        )
    });
    assert_eq!(rc, KQ_FILE_OK, "kq_file_check_in");
    (out, rev)
}

fn offer_of(c: &[u8], rev: &[u8; 32]) -> KqFileOffer {
    let mut offer = std::mem::MaybeUninit::<KqFileOffer>::uninit();
    let rc = unsafe { kq_file_offer(c.as_ptr(), c.len(), rev.as_ptr(), offer.as_mut_ptr()) };
    assert_eq!(rc, KQ_FILE_OK, "kq_file_offer");
    unsafe { offer.assume_init() }
}

fn readiness(c: &[u8], rev: &[u8; 32], recipient: &Account, trust: &Trust) -> (c_int, u32, u32) {
    let (mut have, mut need) = (0u32, 0u32);
    let table = trust.table();
    let rc = unsafe {
        kq_file_readiness(
            c.as_ptr(),
            c.len(),
            rev.as_ptr(),
            recipient.label.as_ptr(),
            &table,
            &mut have,
            &mut need,
        )
    };
    (rc, have, need)
}

#[test]
fn abi_version_and_label_identity_match_the_library() {
    assert_eq!(kq_file_abi_version(), KQ_FILE_ABI_VERSION);
    let mut id = [0u8; 16];
    let label = s("Root.Mya");
    assert_eq!(
        unsafe { kq_file_label_identity(label.as_ptr(), id.as_mut_ptr()) },
        KQ_FILE_OK
    );
    assert_eq!(id, file_history::label_identity("Root.Mya"));
    assert_eq!(
        unsafe { kq_file_label_identity(std::ptr::null(), id.as_mut_ptr()) },
        KQ_FILE_INVALID
    );
}

#[test]
fn a_co_signed_delivery_from_mya_to_steve_end_to_end() {
    let mya = account("Root.Mya");
    let steve = account("Root.Steve");
    let trust = Trust::of(&[&mya, &steve]);

    // Encoder: Mya checks in and signs; the file is hers (scope Root.Mya).
    let c = new_file("Root.Mya");
    let (c, rev) = check_in(&c, &mya, T1, b"quarterly plan v1\n");
    assert_eq!(
        unsafe { kq_file_verify(c.as_ptr(), c.len(), std::ptr::null_mut()) },
        KQ_FILE_OK
    );

    // Latent space: the host gets only the public offer and checks Mya.
    let offer = offer_of(&c, &rev);
    assert_eq!(
        unsafe { kq_file_offer_verify(&offer, mya.label.as_ptr(), mya.signing_public.as_ptr()) },
        KQ_FILE_OK
    );
    assert_eq!(
        unsafe {
            kq_file_offer_verify(&offer, steve.label.as_ptr(), steve.signing_public.as_ptr())
        },
        KQ_FILE_UNTRUSTED,
        "an offer does not verify as someone else's"
    );

    // Below threshold until Steve co-signs.
    assert_eq!(
        readiness(&c, &rev, &steve, &trust),
        (KQ_FILE_BELOW_THRESHOLD, 2, 3)
    );

    // Steve co-signs the public offer, without the content.
    let mut sig = [0u8; 64];
    assert_eq!(
        unsafe {
            kq_file_coauthor_sign(
                &offer,
                steve.label.as_ptr(),
                steve.signing_secret.as_ptr(),
                sig.as_mut_ptr(),
            )
        },
        KQ_FILE_OK
    );
    assert_eq!(
        unsafe {
            kq_file_coauthor_verify(
                &offer,
                steve.label.as_ptr(),
                steve.signing_public.as_ptr(),
                sig.as_ptr(),
            )
        },
        KQ_FILE_OK
    );
    // Mya cannot co-sign her own revision.
    let mut own = [0u8; 64];
    assert_eq!(
        unsafe {
            kq_file_coauthor_sign(
                &offer,
                mya.label.as_ptr(),
                mya.signing_secret.as_ptr(),
                own.as_mut_ptr(),
            )
        },
        KQ_FILE_INVALID
    );

    // Encoded: sealed to Steve's box key.
    let table = trust.table();
    let mut delivery_id = [0u8; 16];
    let delivery_ptr = delivery_id.as_mut_ptr();
    let (rc, letter) = collect(|out, cap, len| unsafe {
        kq_file_seal_letter(
            c.as_ptr(),
            c.len(),
            rev.as_ptr(),
            &table,
            mya.label.as_ptr(),
            mya.signing_secret.as_ptr(),
            mya.box_public.as_ptr(),
            steve.label.as_ptr(),
            steve.box_public.as_ptr(),
            out,
            cap,
            len,
            delivery_ptr,
        )
    });
    assert_eq!(rc, KQ_FILE_OK, "kq_file_seal_letter");
    assert!(
        !letter
            .windows(b"quarterly plan".len())
            .any(|w| w == b"quarterly plan"),
        "the letter does not carry the plaintext"
    );

    // Decoder: Steve opens it with his box key, attaches his co-signature,
    // and the delivery is complete.
    let (mut opened_rev, mut root) = ([0u8; 32], [0u8; 32]);
    let (rev_ptr, root_ptr) = (opened_rev.as_mut_ptr(), root.as_mut_ptr());
    let (rc, opened) = collect(|out, cap, len| unsafe {
        kq_file_open_letter(
            letter.as_ptr(),
            letter.len(),
            steve.box_secret.as_ptr(),
            mya.label.as_ptr(),
            steve.label.as_ptr(),
            mya.signing_public.as_ptr(),
            out,
            cap,
            len,
            rev_ptr,
            root_ptr,
        )
    });
    assert_eq!(rc, KQ_FILE_OK, "kq_file_open_letter");
    assert_eq!(opened_rev, rev);
    let (rc, cosigned) = collect(|out, cap, len| unsafe {
        kq_file_attach_coauthor(
            opened.as_ptr(),
            opened.len(),
            &offer,
            steve.label.as_ptr(),
            sig.as_ptr(),
            out,
            cap,
            len,
        )
    });
    assert_eq!(rc, KQ_FILE_OK, "kq_file_attach_coauthor");
    assert_eq!(
        readiness(&cosigned, &rev, &steve, &trust),
        (KQ_FILE_OK, 3, 3)
    );
    let (rc, payload) = collect(|out, cap, len| unsafe {
        kq_file_payload(
            cosigned.as_ptr(),
            cosigned.len(),
            rev.as_ptr(),
            out,
            cap,
            len,
        )
    });
    assert_eq!(rc, KQ_FILE_OK, "kq_file_payload");
    assert_eq!(payload, b"quarterly plan v1\n");

    // Freshness: first, then the same again is a replay.
    let mut pair = [0u8; 64];
    pair[..32].copy_from_slice(&rev);
    pair[32..].copy_from_slice(&root);
    let fresh = |seen: &[[u8; 64]]| unsafe {
        kq_file_freshness(
            seen.as_ptr(),
            seen.len(),
            cosigned.as_ptr(),
            cosigned.len(),
            rev.as_ptr(),
            root.as_ptr(),
        )
    };
    assert_eq!(fresh(&[]), KQ_FILE_FIRST);
    assert_eq!(fresh(&[pair]), KQ_FILE_REPLAYED);
}

#[test]
fn a_letter_is_refused_from_the_wrong_sender_or_to_the_wrong_recipient() {
    let mya = account("Root.Mya");
    let steve = account("Root.Steve");
    let eve = account("Root.Eve");
    let trust = Trust::of(&[&mya, &steve]);
    let c = new_file("Root.Mya");
    let (c, rev) = check_in(&c, &mya, T1, b"v1");
    let table = trust.table();
    let mut delivery_id = [0u8; 16];
    let delivery_ptr = delivery_id.as_mut_ptr();
    let (_, letter) = collect(|out, cap, len| unsafe {
        kq_file_seal_letter(
            c.as_ptr(),
            c.len(),
            rev.as_ptr(),
            &table,
            mya.label.as_ptr(),
            mya.signing_secret.as_ptr(),
            mya.box_public.as_ptr(),
            steve.label.as_ptr(),
            steve.box_public.as_ptr(),
            out,
            cap,
            len,
            delivery_ptr,
        )
    });
    let open = |box_secret: &[u8; 32], sender: &Account, recipient: &Account, key: &[u8; 32]| {
        let (mut r, mut h) = ([0u8; 32], [0u8; 32]);
        let mut len = 0usize;
        let mut out = vec![0u8; 1 << 16];
        unsafe {
            kq_file_open_letter(
                letter.as_ptr(),
                letter.len(),
                box_secret.as_ptr(),
                sender.label.as_ptr(),
                recipient.label.as_ptr(),
                key.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
                r.as_mut_ptr(),
                h.as_mut_ptr(),
            )
        }
    };
    assert_eq!(
        open(&steve.box_secret, &mya, &steve, &mya.signing_public),
        KQ_FILE_OK
    );
    // Eve's box key cannot open it.
    assert_ne!(
        open(&eve.box_secret, &mya, &steve, &mya.signing_public),
        KQ_FILE_OK
    );
    // A signature from anyone but the sender Steve expects is refused.
    assert_eq!(
        open(&steve.box_secret, &mya, &steve, &eve.signing_public),
        KQ_FILE_UNTRUSTED
    );
    assert_eq!(
        open(&steve.box_secret, &eve, &steve, &mya.signing_public),
        KQ_FILE_UNTRUSTED
    );
    assert_eq!(
        open(&steve.box_secret, &mya, &eve, &mya.signing_public),
        KQ_FILE_UNTRUSTED
    );
}

#[test]
fn an_unsigned_or_unknown_signer_revision_is_neither_sealed_nor_served() {
    let mya = account("Root.Mya");
    let steve = account("Root.Steve");
    let c = new_file("Root.Mya");
    let (c, first) = check_in(&c, &mya, T1, b"v1");
    // Steve edits Mya's file; his signature is not enough under her policy
    // without her approval, so a read keeps serving her revision.
    let (c, second) = check_in(&c, &steve, T2, b"v2 by steve");
    let trust = Trust::of(&[&mya, &steve]);
    let table = trust.table();
    let accepted = [first, second];
    let mut rev = [0u8; 32];
    let rc = unsafe {
        kq_file_select_read(
            c.as_ptr(),
            c.len(),
            &table,
            accepted.as_ptr(),
            2,
            rev.as_mut_ptr(),
        )
    };
    assert_eq!(rc, KQ_FILE_OK);
    assert_eq!(rev, first, "an unapproved newer edit is never served");

    let mut delivery_id = [0u8; 16];
    let delivery_ptr = delivery_id.as_mut_ptr();
    let (rc, _) = collect(|out, cap, len| unsafe {
        kq_file_seal_letter(
            c.as_ptr(),
            c.len(),
            second.as_ptr(),
            &table,
            steve.label.as_ptr(),
            steve.signing_secret.as_ptr(),
            steve.box_public.as_ptr(),
            mya.label.as_ptr(),
            mya.box_public.as_ptr(),
            out,
            cap,
            len,
            delivery_ptr,
        )
    });
    assert_eq!(rc, KQ_FILE_UNTRUSTED);

    // With no keys at all nothing is trusted.
    let empty = Trust::of(&[]);
    let table = empty.table();
    let rc = unsafe {
        kq_file_select_read(
            c.as_ptr(),
            c.len(),
            &table,
            accepted.as_ptr(),
            2,
            rev.as_mut_ptr(),
        )
    };
    assert_eq!(rc, KQ_FILE_NO_REVISION);
}

#[test]
fn a_read_only_sees_revisions_accepted_by_the_request_time() {
    let mya = account("Root.Mya");
    let trust = Trust::of(&[&mya]);
    let table = trust.table();
    let c = new_file("Root.Mya");
    let (c, first) = check_in(&c, &mya, T1, b"v1");
    let (c, second) = check_in(&c, &mya, T2, b"v2");
    let mut rev = [0u8; 32];
    // The host accepted only `first` before the request.
    let rc = unsafe {
        kq_file_select_read(
            c.as_ptr(),
            c.len(),
            &table,
            [first].as_ptr(),
            1,
            rev.as_mut_ptr(),
        )
    };
    assert_eq!((rc, rev), (KQ_FILE_OK, first));
    let rc = unsafe {
        kq_file_select_read(
            c.as_ptr(),
            c.len(),
            &table,
            [first, second].as_ptr(),
            2,
            rev.as_mut_ptr(),
        )
    };
    assert_eq!((rc, rev), (KQ_FILE_OK, second));
}

#[test]
fn a_forked_file_is_refused_until_merged() {
    let mya = account("Root.Mya");
    let trust = Trust::of(&[&mya]);
    let table = trust.table();
    let base = new_file("Root.Mya");
    let (base, _) = check_in(&base, &mya, T1, b"v1");
    let (left, l) = check_in(&base, &mya, T2, b"left");
    let (right, r) = check_in(&base, &mya, T3, b"right");
    let (actor, at) = (s("Root.Mya"), s(T3));
    let (rc, merged) = collect(|out, cap, len| unsafe {
        kq_file_merge(
            left.as_ptr(),
            left.len(),
            right.as_ptr(),
            right.len(),
            actor.as_ptr(),
            at.as_ptr(),
            out,
            cap,
            len,
        )
    });
    assert_eq!(rc, KQ_FILE_OK, "kq_file_merge");
    let mut rev = [0u8; 32];
    assert_eq!(
        unsafe { kq_file_head(merged.as_ptr(), merged.len(), rev.as_mut_ptr()) },
        KQ_FILE_FORKED
    );
    let accepted = [l, r];
    assert_eq!(
        unsafe {
            kq_file_select_read(
                merged.as_ptr(),
                merged.len(),
                &table,
                accepted.as_ptr(),
                2,
                rev.as_mut_ptr(),
            )
        },
        KQ_FILE_FORKED
    );
    // A check-in on a forked file is refused too.
    let at = s(T3);
    let mut out = vec![0u8; 1 << 16];
    let mut len = 0usize;
    assert_eq!(
        unsafe {
            kq_file_check_in(
                merged.as_ptr(),
                merged.len(),
                mya.label.as_ptr(),
                at.as_ptr(),
                b"x".as_ptr(),
                1,
                mya.signing_secret.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
                rev.as_mut_ptr(),
            )
        },
        KQ_FILE_FORKED
    );
}

#[test]
fn signers_lists_every_label_the_trust_table_needs() {
    let mya = account("Root.Mya");
    let steve = account("Root.Steve");
    let c = new_file("Root.Mya");
    let (c, _) = check_in(&c, &mya, T1, b"v1");
    let (c, _) = check_in(&c, &steve, T2, b"v2");
    let (rc, list) =
        collect(|out, cap, len| unsafe { kq_file_signers(c.as_ptr(), c.len(), out, cap, len) });
    assert_eq!(rc, KQ_FILE_OK);
    let labels: Vec<&str> = list
        .split(|b| *b == 0)
        .filter(|l| !l.is_empty())
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    assert_eq!(labels, vec!["Root.Mya", "Root.Steve"]);
}

#[test]
fn a_small_buffer_reports_the_size_needed_and_writes_nothing() {
    let c = new_file("Root.Mya");
    let mut len = 0usize;
    let mut tiny = [0u8; 4];
    let (name, owner) = (s("plan.txt"), s("Root.Mya"));
    let rc = unsafe {
        kq_file_new(
            FILE_ID.as_ptr(),
            name.as_ptr(),
            owner.as_ptr(),
            tiny.as_mut_ptr(),
            tiny.len(),
            &mut len,
        )
    };
    assert_eq!(rc, KQ_FILE_NO_ROOM);
    assert_eq!(len, c.len());
    assert_eq!(tiny, [0u8; 4]);
}

#[test]
fn box_keys_round_trip_through_the_account_seal() {
    let mut secret = [0u8; 32];
    let mut public = [0u8; 32];
    assert_eq!(
        unsafe { crate::ffi::kq_account_box_keygen(secret.as_mut_ptr(), public.as_mut_ptr()) },
        crate::ffi::KQ_ACCOUNT_OK
    );
    let mut again = [0u8; 32];
    assert_eq!(
        unsafe { crate::ffi::kq_account_box_public(secret.as_ptr(), again.as_mut_ptr()) },
        crate::ffi::KQ_ACCOUNT_OK
    );
    assert_eq!(again, public);
}

#[test]
fn a_revision_stamped_with_a_topology_generation_is_never_trusted() {
    let mya = account("Root.Mya");
    let steve = account("Root.Steve");
    let trust = Trust::of(&[&mya, &steve]);
    let mut file = TrackedFile::decode(&new_file("Root.Mya")).unwrap();
    let policy_hash = file.policy().unwrap().policy_hash().unwrap();
    let identity = file_history::label_identity("Root.Mya");
    let rev = file
        .check_in(
            NewRevision {
                parent_revision_ids: Vec::new(),
                user_label: None,
                author_identity: Some(identity),
                author_hcp_label: "Root.Mya".to_string(),
                created_at_utc: T1.to_string(),
                topology_generation: 5,
                policy_hash,
            },
            b"generation five\n".to_vec(),
        )
        .unwrap();
    file.sign_revision(&rev, identity, "Root.Mya", &mya.signing_secret)
        .unwrap();
    let c = file.encode().unwrap();

    // A key table records no topology, so the revision stays pending: it is
    // neither ready, nor sealed, even with a valid author signature.
    let (rc, _, _) = readiness(&c, &rev, &steve, &trust);
    assert_ne!(rc, KQ_FILE_OK, "kq_file_readiness at generation 5");
    let table = trust.table();
    let mut delivery = [0u8; 16];
    let delivery_ptr = delivery.as_mut_ptr();
    let (rc, _) = collect(|out, cap, len| unsafe {
        kq_file_seal_letter(
            c.as_ptr(),
            c.len(),
            rev.as_ptr(),
            &table,
            mya.label.as_ptr(),
            mya.signing_secret.as_ptr(),
            mya.box_public.as_ptr(),
            steve.label.as_ptr(),
            steve.box_public.as_ptr(),
            out,
            cap,
            len,
            delivery_ptr,
        )
    });
    assert_ne!(rc, KQ_FILE_OK, "kq_file_seal_letter at generation 5");
}

#[test]
fn freshness_judges_only_the_containers_own_revision_and_root() {
    let mya = account("Root.Mya");
    let (c, rev) = check_in(&new_file("Root.Mya"), &mya, T1, b"v1\n");
    let mut root = [0u8; 32];
    assert_eq!(
        unsafe { kq_file_verify(c.as_ptr(), c.len(), root.as_mut_ptr()) },
        KQ_FILE_OK,
        "kq_file_verify"
    );
    let fresh = |rev: &[u8; 32], root: &[u8; 32]| unsafe {
        kq_file_freshness(
            std::ptr::null(),
            0,
            c.as_ptr(),
            c.len(),
            rev.as_ptr(),
            root.as_ptr(),
        )
    };
    assert_eq!(fresh(&rev, &root), KQ_FILE_FIRST);
    // A revision the container does not hold, or a root that is not its own.
    assert_eq!(fresh(&[9u8; 32], &root), KQ_FILE_INVALID);
    assert_eq!(fresh(&rev, &[9u8; 32]), KQ_FILE_INVALID);
}
