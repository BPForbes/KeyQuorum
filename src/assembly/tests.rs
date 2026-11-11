use super::*;
use crate::test_secrets::bytes32;

struct Child {
    label: String,
    secret: [u8; 32],
    public: [u8; 32],
    device: [u8; DEVICE_ID_LEN],
}

fn child(label: &str, device: u8) -> Child {
    let secret = bytes32();
    let public = crypto_box::SecretKey::from(secret).public_key().to_bytes();
    Child {
        label: label.into(),
        secret,
        public,
        device: [device; DEVICE_ID_LEN],
    }
}

fn holders(children: &[Child]) -> Vec<ChildHolder<'_>> {
    children
        .iter()
        .map(|c| ChildHolder {
            label: &c.label,
            encryption_public: c.public,
        })
        .collect()
}

fn unlocked<'a>(children: &[&'a Child]) -> Vec<UnlockedChild<'a>> {
    children
        .iter()
        .map(|c| UnlockedChild {
            label: &c.label,
            encryption_secret: &c.secret,
            device_id: c.device,
        })
        .collect()
}

fn kids(n: usize) -> Vec<Child> {
    (0..n)
        .map(|i| child(&format!("M.A.{}", i + 1), i as u8 + 1))
        .collect()
}

#[test]
fn the_threshold_follows_the_rule() {
    let want = [
        None,
        Some(1),
        Some(2),
        Some(2),
        Some(3),
        Some(3),
        Some(4),
        Some(5),
        Some(5),
        Some(6),
        Some(7),
    ];
    for (x, w) in want.iter().enumerate() {
        assert_eq!(assembly_threshold(x), *w, "holders {x}");
    }
    assert_eq!(assembly_threshold(255), Some(170));
    assert_eq!(assembly_threshold(256), None);
}

#[test]
fn two_children_assemble_the_parent_and_one_cannot() {
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let ch = kids(2);
    let a = split_parent_key(&seed, &holders(&ch), 1).unwrap().unwrap();
    assert_eq!((a.threshold, a.generation, a.shares.len()), (2, 1, 2));
    let got = assemble_parent_key(&a, &unlocked(&[&ch[0], &ch[1]]), 2, &public).unwrap();
    assert_eq!(*got, seed);
    assert!(matches!(
        assemble_parent_key(&a, &unlocked(&[&ch[0]]), 0, &public),
        Err(Error::QuorumNotMet)
    ));
}

#[test]
fn a_single_child_holds_a_one_of_one_assembly() {
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let ch = kids(1);
    let a = split_parent_key(&seed, &holders(&ch), 0).unwrap().unwrap();
    assert_eq!(a.threshold, 1);
    assert_eq!(
        *assemble_parent_key(&a, &unlocked(&[&ch[0]]), 1, &public).unwrap(),
        seed
    );
}

#[test]
fn no_children_means_no_assembly() {
    assert!(split_parent_key(&bytes32(), &[], 0).unwrap().is_none());
}

#[test]
fn a_larger_group_needs_exactly_its_threshold() {
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let ch = kids(5); // threshold 3
    let a = split_parent_key(&seed, &holders(&ch), 4).unwrap().unwrap();
    assert_eq!(a.threshold, 3);
    let three = unlocked(&[&ch[4], &ch[0], &ch[2]]);
    assert_eq!(*assemble_parent_key(&a, &three, 3, &public).unwrap(), seed);
    let two = unlocked(&[&ch[1], &ch[3]]);
    assert!(matches!(
        assemble_parent_key(&a, &two, 0, &public),
        Err(Error::QuorumNotMet)
    ));
}

#[test]
fn the_custody_minimum_counts_distinct_devices() {
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let mut ch = kids(2);
    ch[1].device = ch[0].device; // both children on one drive
    let a = split_parent_key(&seed, &holders(&ch), 1).unwrap().unwrap();
    let both = unlocked(&[&ch[0], &ch[1]]);
    assert!(matches!(
        assemble_parent_key(&a, &both, 2, &public),
        Err(Error::QuorumNotMet)
    ));
    assert_eq!(*assemble_parent_key(&a, &both, 1, &public).unwrap(), seed);
}

#[test]
fn a_child_counts_once_and_a_stranger_counts_never() {
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let ch = kids(2);
    let a = split_parent_key(&seed, &holders(&ch), 1).unwrap().unwrap();
    let stranger = child("M.B.1", 9);
    let dup = unlocked(&[&ch[0], &ch[0], &stranger]);
    assert!(matches!(
        assemble_parent_key(&a, &dup, 0, &public),
        Err(Error::QuorumNotMet)
    ));
    // a child that presents the wrong secret contributes nothing
    let mut wrong = child(&ch[1].label, 2);
    wrong.public = ch[1].public;
    let bad = unlocked(&[&ch[0], &wrong]);
    assert!(matches!(
        assemble_parent_key(&a, &bad, 0, &public),
        Err(Error::QuorumNotMet)
    ));
}

#[test]
fn a_planted_share_never_yields_a_wrong_key() {
    // Sealing is anonymous: anyone with a child's public key can seal a share, so the result
    // is accepted only when it derives the parent's key.
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let ch = kids(2);
    let a = split_parent_key(&seed, &holders(&ch), 1).unwrap().unwrap();
    let forged = split_parent_key(&bytes32(), &holders(&ch), 1)
        .unwrap()
        .unwrap();
    let mut mixed = a.clone();
    mixed.shares[1] = forged.shares[1].clone();
    let both = unlocked(&[&ch[0], &ch[1]]);
    assert!(matches!(
        assemble_parent_key(&mixed, &both, 0, &public),
        Err(Error::IntegrityCheckFailed)
    ));
    assert!(matches!(
        assemble_parent_key(&a, &both, 0, &signing::public_key(&bytes32())),
        Err(Error::IntegrityCheckFailed)
    ));
}

#[test]
fn a_reissue_deals_the_next_generation_and_the_old_shares_no_longer_assemble() {
    let old_seed = bytes32();
    let new_seed = bytes32();
    let ch = kids(3);
    let a = split_parent_key(&old_seed, &holders(&ch), 7)
        .unwrap()
        .unwrap();
    let b = reissue_assembly(&a, &new_seed, &holders(&ch[..2]))
        .unwrap()
        .unwrap();
    assert_eq!((b.generation, b.threshold), (8, 2));
    let two = unlocked(&[&ch[0], &ch[1]]);
    assert_eq!(
        *assemble_parent_key(&b, &two, 0, &signing::public_key(&new_seed)).unwrap(),
        new_seed
    );
    // The revoked child's OLD share, beside a surviving child's NEW share, assembles neither
    // key: the old share is worthless after the reseed. (Handing the old assembly's own shares
    // back still gives the old seed, which is why the parent's key itself had to rotate.)
    let mixed = Assembly {
        threshold: b.threshold,
        generation: b.generation,
        shares: vec![b.shares[0].clone(), a.shares[2].clone()],
    };
    let pair = unlocked(&[&ch[0], &ch[2]]);
    assert!(matches!(
        assemble_parent_key(&mixed, &pair, 0, &signing::public_key(&new_seed)),
        Err(Error::IntegrityCheckFailed)
    ));
    assert!(matches!(
        assemble_parent_key(&mixed, &pair, 0, &signing::public_key(&old_seed)),
        Err(Error::IntegrityCheckFailed)
    ));
    assert_eq!(
        *assemble_parent_key(&a, &pair, 0, &signing::public_key(&old_seed)).unwrap(),
        old_seed
    );
    assert!(reissue_assembly(
        &Assembly {
            generation: u32::MAX,
            ..a
        },
        &new_seed,
        &holders(&ch)
    )
    .is_err());
}

#[test]
fn the_holders_are_checked() {
    let ch = kids(2);
    let mut dup = holders(&ch);
    dup[1].label = dup[0].label;
    assert!(split_parent_key(&bytes32(), &dup, 1).is_err());
    let mut weak = holders(&ch);
    weak[0].encryption_public = [0u8; 32];
    assert!(split_parent_key(&bytes32(), &weak, 1).is_err());
    let many: Vec<Child> = (0..256).map(|i| child(&format!("M.A.{i}"), 1)).collect();
    assert!(split_parent_key(&bytes32(), &holders(&many), 1).is_err());
}

#[test]
fn the_encoding_round_trips_and_refuses_damage() {
    let ch = kids(3);
    let a = split_parent_key(&bytes32(), &holders(&ch), 2)
        .unwrap()
        .unwrap();
    let bytes = a.encode().unwrap();
    assert_eq!(&bytes[..4], b"KQAS");
    assert_eq!(Assembly::decode(&bytes).unwrap(), a);
    for cut in [0, 3, 5, 10, bytes.len() - 1] {
        assert!(Assembly::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Assembly::decode(&trailing).is_err());
    let mut bad_version = bytes.clone();
    bad_version[4] = 2;
    assert!(Assembly::decode(&bad_version).is_err());
    let mut bad_threshold = bytes.clone();
    bad_threshold[9] = 3; // 3 holders need 2
    assert!(Assembly::decode(&bad_threshold).is_err());
}

#[test]
fn a_failed_entry_does_not_shadow_a_later_entry_for_the_same_child() {
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let ch = kids(2);
    let a = split_parent_key(&seed, &holders(&ch), 1).unwrap().unwrap();
    let wrong_secret = bytes32();
    let list = [
        UnlockedChild {
            label: &ch[0].label,
            encryption_secret: &wrong_secret,
            device_id: ch[0].device,
        },
        UnlockedChild {
            label: &ch[0].label,
            encryption_secret: &ch[0].secret,
            device_id: ch[0].device,
        },
        UnlockedChild {
            label: &ch[1].label,
            encryption_secret: &ch[1].secret,
            device_id: ch[1].device,
        },
    ];
    assert_eq!(*assemble_parent_key(&a, &list, 2, &public).unwrap(), seed);
}

#[test]
fn an_extra_share_with_a_held_coordinate_does_not_reject_a_good_group() {
    let seed = bytes32();
    let public = signing::public_key(&seed);
    let ch = kids(3); // threshold 2
    let a = split_parent_key(&seed, &holders(&ch), 1).unwrap().unwrap();
    // A share sealed to the third child that carries the first child's x-coordinate.
    let other = split_parent_key(&bytes32(), &holders(&ch), 1)
        .unwrap()
        .unwrap();
    let raw = Zeroizing::new(
        crypto_box::SecretKey::from(ch[0].secret)
            .unseal(&other.shares[0].sealed)
            .unwrap(),
    );
    let mut planted = a.clone();
    planted.shares[2].sealed = crypto_box::PublicKey::from_bytes(ch[2].public)
        .seal(&mut crate::crypto::os_rng(), &raw)
        .unwrap();
    let all = unlocked(&[&ch[0], &ch[1], &ch[2]]);
    assert_eq!(
        *assemble_parent_key(&planted, &all, 2, &public).unwrap(),
        seed
    );
    // With only the planted share and one good one the coordinates are distinct, so the group
    // recovers a wrong seed, and the public-key check refuses it.
    let two = unlocked(&[&ch[1], &ch[2]]);
    assert!(matches!(
        assemble_parent_key(&planted, &two, 0, &public),
        Err(Error::IntegrityCheckFailed)
    ));
}
