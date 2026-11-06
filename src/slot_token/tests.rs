use super::*;
use crate::test_secrets::{empty_passphrase, other_passphrase, passphrase};

const DEVICE: [u8; DEVICE_ID_LEN] = [3; DEVICE_ID_LEN];

struct Slot {
    token: Vec<u8>,
    encryption_public: [u8; 32],
    signing_public: [u8; 32],
}

fn slot(label: &str, pass: &str) -> Slot {
    let (encryption_secret, encryption_public) = keys::generate_encryption_keypair();
    let (signing_secret, signing_public) = keys::generate_signing_keypair();
    let token = seal_token(label, &DEVICE, &encryption_secret, &signing_secret, pass).unwrap();
    Slot {
        token,
        encryption_public,
        signing_public,
    }
}

fn open(slot: &Slot, label: &str, pass: &str) -> Result<SlotSecrets> {
    open_slot_token(
        &slot.token,
        label,
        pass,
        &DEVICE,
        &slot.signing_public,
        &slot.encryption_public,
    )
}

#[test]
fn a_token_opens_with_only_its_passphrase_and_the_expected_facts() {
    let pass = passphrase();
    let slot = slot("Root.Bob", &pass);
    assert_eq!(&slot.token[..4], TOKEN_MAGIC);
    let secrets = open(&slot, "Root.Bob", &pass).unwrap();
    assert_eq!(secrets.label, "Root.Bob");
    assert_eq!(secrets.signing_public, slot.signing_public);
    assert_eq!(secrets.encryption_public, slot.encryption_public);
    assert_eq!(
        signing::public_key(&secrets.signing_secret),
        slot.signing_public
    );
}

#[test]
fn a_wrong_passphrase_is_a_password_error_and_every_mismatch_is_an_invalid_slot() {
    let pass = passphrase();
    let slot = slot("Root.Bob", &pass);
    assert!(matches!(
        open(&slot, "Root.Bob", &other_passphrase(&pass)),
        Err(Error::InvalidPassword)
    ));
    assert!(matches!(
        open(&slot, "Root.Eve", &pass),
        Err(Error::InvalidSlot)
    ));
    let other = |device: [u8; 16], signing: [u8; 32], encryption: [u8; 32]| {
        open_slot_token(
            &slot.token,
            "Root.Bob",
            &pass,
            &device,
            &signing,
            &encryption,
        )
    };
    assert!(matches!(
        other([4; 16], slot.signing_public, slot.encryption_public),
        Err(Error::InvalidSlot)
    ));
    let (_, stranger) = keys::generate_signing_keypair();
    assert!(matches!(
        other(DEVICE, stranger, slot.encryption_public),
        Err(Error::InvalidSlot)
    ));
    assert!(matches!(
        other(DEVICE, slot.signing_public, stranger),
        Err(Error::InvalidSlot)
    ));
}

#[test]
fn a_truncated_tampered_or_foreign_token_is_refused() {
    let pass = passphrase();
    let slot = slot("Root.Bob", &pass);
    for len in [0, 4, 5, 20, slot.token.len() - 1] {
        let short = Slot {
            token: slot.token[..len].to_vec(),
            ..Slot {
                token: Vec::new(),
                encryption_public: slot.encryption_public,
                signing_public: slot.signing_public,
            }
        };
        assert!(open(&short, "Root.Bob", &pass).is_err(), "prefix {len}");
    }
    for at in [0usize, 4, 10, 40, slot.token.len() - 1] {
        let mut altered = slot.token.clone();
        altered[at] ^= 1;
        let altered = Slot {
            token: altered,
            encryption_public: slot.encryption_public,
            signing_public: slot.signing_public,
        };
        assert!(open(&altered, "Root.Bob", &pass).is_err(), "byte {at}");
    }
}

#[test]
fn tokens_are_salted_so_two_seals_differ() {
    let pass = passphrase();
    let (e, _) = keys::generate_encryption_keypair();
    let (s, _) = keys::generate_signing_keypair();
    let a = seal_token("Root.Bob", &DEVICE, &e, &s, &pass).unwrap();
    let b = seal_token("Root.Bob", &DEVICE, &e, &s, &pass).unwrap();
    assert_ne!(a, b);
    // Salt sits after magic(4) + version(1); a nonce-only change must not pass.
    assert_ne!(&a[5..5 + SALT_LEN], &b[5..5 + SALT_LEN]);
}

#[test]
fn an_empty_passphrase_cannot_seal_a_token() {
    let (e, _) = keys::generate_encryption_keypair();
    let (s, _) = keys::generate_signing_keypair();
    let empty = empty_passphrase();
    assert!(matches!(
        seal_token("Root.Bob", &DEVICE, &e, &s, &empty),
        Err(Error::InvalidPassword)
    ));
}

#[test]
fn an_oversized_token_is_refused_before_decryption() {
    let pass = passphrase();
    let slot = slot("Root.Bob", &pass);
    let mut huge = slot.token.clone();
    huge.resize(MAX_TOKEN_LEN + 1, 0);
    let huge = Slot {
        token: huge,
        encryption_public: slot.encryption_public,
        signing_public: slot.signing_public,
    };
    assert!(matches!(
        open(&huge, "Root.Bob", &pass),
        Err(Error::InvalidDevice)
    ));
}

#[test]
fn a_token_of_the_largest_encodable_size_still_opens() {
    // A u16::MAX-byte label fills the layout exactly, so the size guard must
    // accept MAX_TOKEN_LEN; only a token above it is refused.
    let pass = passphrase();
    let label = "a".repeat(u16::MAX as usize);
    let slot = slot(&label, &pass);
    assert_eq!(slot.token.len(), MAX_TOKEN_LEN);
    let secrets = open(&slot, &label, &pass).unwrap();
    assert_eq!(secrets.label, label);
}
