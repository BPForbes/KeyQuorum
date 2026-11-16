use super::*;
use keyquorum::{keys, signing, slot_token};
use std::ffi::CString;

const DEVICE: [u8; 16] = [9; 16];

struct Fixture {
    token: Vec<u8>,
    label: CString,
    passphrase: CString,
    signing_public: [u8; 32],
    encryption_public: [u8; 32],
    signing_secret: [u8; 32],
    encryption_secret: [u8; 32],
}

fn fixture() -> Fixture {
    let (encryption_secret, encryption_public) = keys::generate_encryption_keypair();
    let (signing_secret, signing_public) = keys::generate_signing_keypair();
    // A passphrase drawn at run time, never a literal.
    let (pass, _) = keys::generate_signing_keypair();
    let passphrase =
        CString::new(pass.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap();
    let token = slot_token::seal_token(
        "Root.Bob",
        &DEVICE,
        &encryption_secret,
        &signing_secret,
        passphrase.to_str().unwrap(),
    )
    .unwrap();
    Fixture {
        token,
        label: CString::new("Root.Bob").unwrap(),
        passphrase,
        signing_public,
        encryption_public,
        signing_secret: *signing_secret,
        encryption_secret: *encryption_secret,
    }
}

fn open(f: &Fixture, passphrase: &CString, device: &[u8; 16]) -> (c_int, [u8; 32], [u8; 32]) {
    // Non-zero sentinels: an error path that clears outs would still pass
    // if the buffers started as zeroes.
    let (mut signing_out, mut encryption_out) = ([0x5Au8; 32], [0xA5u8; 32]);
    let rc = unsafe {
        kq_slot_open(
            f.token.as_ptr(),
            f.token.len(),
            f.label.as_ptr(),
            passphrase.as_ptr(),
            device.as_ptr(),
            f.signing_public.as_ptr(),
            f.encryption_public.as_ptr(),
            signing_out.as_mut_ptr(),
            encryption_out.as_mut_ptr(),
        )
    };
    (rc, signing_out, encryption_out)
}

#[test]
fn a_token_opens_from_the_callers_registry_facts_alone() {
    let f = fixture();
    let (rc, signing_out, encryption_out) = open(&f, &f.passphrase, &DEVICE);
    assert_eq!(rc, KQ_ACCOUNT_OK);
    assert_eq!(signing_out, f.signing_secret);
    assert_eq!(encryption_out, f.encryption_secret);
    assert_eq!(signing::public_key(&signing_out), f.signing_public);
}

#[test]
fn a_wrong_passphrase_is_distinct_and_every_mismatch_writes_nothing() {
    let f = fixture();
    let wrong = fixture().passphrase;
    let (rc, signing_out, encryption_out) = open(&f, &wrong, &DEVICE);
    assert_eq!(rc, KQ_ACCOUNT_WRONG_PASSWORD);
    assert_eq!(signing_out, [0x5Au8; 32]);
    assert_eq!(encryption_out, [0xA5u8; 32]);
    let (rc, signing_out, encryption_out) = open(&f, &f.passphrase, &[1; 16]);
    assert_eq!(rc, KQ_ACCOUNT_INVALID);
    assert_eq!(signing_out, [0x5Au8; 32]);
    assert_eq!(encryption_out, [0xA5u8; 32]);
    let mut cut = fixture();
    cut.token.truncate(10);
    let (rc, signing_out, encryption_out) = open(&cut, &cut.passphrase, &DEVICE);
    assert_eq!(rc, KQ_ACCOUNT_INVALID);
    assert_eq!(signing_out, [0x5Au8; 32]);
    assert_eq!(encryption_out, [0xA5u8; 32]);
}

#[test]
fn overlapping_secret_outputs_are_refused() {
    let f = fixture();
    let mut both = [0u8; 64];
    let rc = unsafe {
        kq_slot_open(
            f.token.as_ptr(),
            f.token.len(),
            f.label.as_ptr(),
            f.passphrase.as_ptr(),
            DEVICE.as_ptr(),
            f.signing_public.as_ptr(),
            f.encryption_public.as_ptr(),
            both.as_mut_ptr(),
            both.as_mut_ptr().add(16),
        )
    };
    assert_eq!(rc, KQ_ACCOUNT_INVALID);
}

#[test]
fn null_arguments_are_invalid() {
    let f = fixture();
    let rc = unsafe {
        kq_slot_open(
            f.token.as_ptr(),
            f.token.len(),
            f.label.as_ptr(),
            f.passphrase.as_ptr(),
            DEVICE.as_ptr(),
            f.signing_public.as_ptr(),
            f.encryption_public.as_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc, KQ_ACCOUNT_INVALID);
}

fn seal(
    label: &CString,
    passphrase: &CString,
    signing_secret: &[u8; 32],
    encryption_secret: &[u8; 32],
    cap: usize,
) -> (c_int, Vec<u8>, usize, [u8; 32], [u8; 32]) {
    let mut token = vec![0u8; cap];
    let mut len = 0usize;
    let (mut signing_public, mut encryption_public) = ([0u8; 32], [0u8; 32]);
    let rc = unsafe {
        kq_slot_seal(
            label.as_ptr(),
            passphrase.as_ptr(),
            DEVICE.as_ptr(),
            signing_secret.as_ptr(),
            encryption_secret.as_ptr(),
            token.as_mut_ptr(),
            token.len(),
            &mut len,
            signing_public.as_mut_ptr(),
            encryption_public.as_mut_ptr(),
        )
    };
    token.truncate(len.min(cap));
    (rc, token, len, signing_public, encryption_public)
}

#[test]
fn a_sealed_token_opens_to_the_same_keys() {
    let f = fixture();
    let label = CString::new("Root.Flinstone").unwrap();
    let need = slot_token_len("Root.Flinstone".len());
    let (rc, token, len, signing_public, encryption_public) = seal(
        &label,
        &f.passphrase,
        &f.signing_secret,
        &f.encryption_secret,
        need,
    );
    assert_eq!(rc, KQ_ACCOUNT_OK);
    assert_eq!(len, need);
    // The account keeps its keys: the public keys are the ones it already had.
    assert_eq!(signing_public, f.signing_public);
    assert_eq!(encryption_public, f.encryption_public);
    let sealed = Fixture {
        token,
        label,
        passphrase: f.passphrase.clone(),
        signing_public,
        encryption_public,
        signing_secret: f.signing_secret,
        encryption_secret: f.encryption_secret,
    };
    let (rc, signing_out, encryption_out) = open(&sealed, &f.passphrase, &DEVICE);
    assert_eq!(rc, KQ_ACCOUNT_OK);
    assert_eq!(signing_out, f.signing_secret);
    assert_eq!(encryption_out, f.encryption_secret);
    // Another device id, or another passphrase, does not open it.
    assert_eq!(open(&sealed, &f.passphrase, &[1; 16]).0, KQ_ACCOUNT_INVALID);
    assert_eq!(
        open(&sealed, &fixture().passphrase, &DEVICE).0,
        KQ_ACCOUNT_WRONG_PASSWORD
    );
}

#[test]
fn seal_reports_the_size_it_needs_and_refuses_bad_input() {
    let f = fixture();
    let label = CString::new("Root.Flinstone").unwrap();
    let need = slot_token_len("Root.Flinstone".len());
    let (rc, _, len, signing_public, _) = seal(
        &label,
        &f.passphrase,
        &f.signing_secret,
        &f.encryption_secret,
        need - 1,
    );
    assert_eq!(rc, KQ_ACCOUNT_NO_ROOM);
    assert_eq!(len, need);
    assert_eq!(signing_public, [0; 32]);
    let empty = CString::new("").unwrap();
    assert_eq!(
        seal(
            &label,
            &empty,
            &f.signing_secret,
            &f.encryption_secret,
            need
        )
        .0,
        KQ_ACCOUNT_INVALID
    );
    let bad = CString::new("Flinstone.Bob").unwrap();
    assert_eq!(
        seal(
            &bad,
            &f.passphrase,
            &f.signing_secret,
            &f.encryption_secret,
            need
        )
        .0,
        KQ_ACCOUNT_INVALID
    );
    let mut len = 0usize;
    let rc = unsafe {
        kq_slot_seal(
            label.as_ptr(),
            f.passphrase.as_ptr(),
            DEVICE.as_ptr(),
            core::ptr::null(),
            f.encryption_secret.as_ptr(),
            [0u8; 256].as_mut_ptr(),
            256,
            &mut len,
            [0u8; 32].as_mut_ptr(),
            [0u8; 32].as_mut_ptr(),
        )
    };
    assert_eq!(rc, KQ_ACCOUNT_INVALID);
}
