use super::*;
use crate::ffi::kq_bridge_connects;
use keyquorum::bridge_proof::seal_bridge_secret;
use keyquorum::{crypto, keys};
use std::ffi::CString;

struct Person {
    label: CString,
    encryption_secret: [u8; 32],
    encryption_public: [u8; 32],
    signing_secret: [u8; 32],
    signing_public: [u8; 32],
}

fn person(label: &str) -> Person {
    let (e, encryption_public) = keys::generate_encryption_keypair();
    let (s, signing_public) = keys::generate_signing_keypair();
    Person {
        label: CString::new(label).unwrap(),
        encryption_secret: *e,
        encryption_public,
        signing_secret: *s,
        signing_public,
    }
}

struct Bridge {
    uid: CString,
    salt: [u8; 16],
    public: [u8; 32],
    secret: [u8; 32],
}

fn bridge() -> Bridge {
    let (secret, public) = keys::generate_signing_keypair();
    Bridge {
        uid: CString::new("bridge-1").unwrap(),
        salt: crypto::random_salt(),
        public,
        secret: *secret,
    }
}

const GENERATION: u32 = 7;

fn prove(b: &Bridge, p: &Person, sealed_to: &Person, challenge: &[u8]) -> (c_int, Vec<u8>) {
    let wrap_salt = crypto::random_salt();
    let sealed = seal_bridge_secret(&sealed_to.encryption_public, &wrap_salt, &b.secret).unwrap();
    let mut out = vec![0u8; 1024];
    let mut len = 0usize;
    let rc = unsafe {
        kq_bridge_prove(
            b.uid.as_ptr(),
            GENERATION,
            b.salt.as_ptr(),
            b.public.as_ptr(),
            p.label.as_ptr(),
            sealed.as_ptr(),
            sealed.len(),
            wrap_salt.as_ptr(),
            p.encryption_secret.as_ptr(),
            p.signing_secret.as_ptr(),
            challenge.as_ptr(),
            challenge.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    out.truncate(len);
    (rc, out)
}

fn verify(
    b: &Bridge,
    generation: u32,
    destroyed: c_int,
    roster: &[&Person],
    verifier: &Person,
    challenge: &[u8],
    artifact: &[u8],
) -> c_int {
    let labels: Vec<*const c_char> = roster.iter().map(|p| p.label.as_ptr()).collect();
    let publics: Vec<u8> = roster.iter().flat_map(|p| p.signing_public).collect();
    unsafe {
        kq_bridge_verify(
            b.uid.as_ptr(),
            generation,
            b.salt.as_ptr(),
            b.public.as_ptr(),
            destroyed,
            labels.as_ptr(),
            publics.as_ptr(),
            roster.len(),
            verifier.label.as_ptr(),
            challenge.as_ptr(),
            challenge.len(),
            artifact.as_ptr(),
            artifact.len(),
        )
    }
}

#[test]
fn a_member_proves_and_the_live_bridge_verifies_it_end_to_end() {
    let (a, s, b) = (person("M.A.1"), person("M.S.1"), bridge());
    let challenge = crypto::random_key();
    let (rc, artifact) = prove(&b, &a, &a, &*challenge);
    assert_eq!(rc, KQ_BRIDGE_OK);
    assert_eq!(
        verify(&b, GENERATION, 0, &[&a, &s], &s, &*challenge, &artifact),
        KQ_BRIDGE_OK
    );
}

#[test]
fn a_non_first_roster_member_proves_and_verifies() {
    // Signing as the second roster entry detects a regression that always
    // picks the first public key.
    let (a, s, b) = (person("M.A.1"), person("M.S.1"), bridge());
    let challenge = crypto::random_key();
    let (rc, artifact) = prove(&b, &s, &s, &*challenge);
    assert_eq!(rc, KQ_BRIDGE_OK);
    assert_eq!(
        verify(&b, GENERATION, 0, &[&a, &s], &a, &*challenge, &artifact),
        KQ_BRIDGE_OK
    );
}

#[test]
fn a_stale_destroyed_or_foreign_proof_is_refused() {
    let (a, s, x, b) = (person("M.A.1"), person("M.S.1"), person("M.X.1"), bridge());
    let challenge = crypto::random_key();
    let (_, artifact) = prove(&b, &a, &a, &*challenge);
    // Another generation: the bridge changed (a member was removed) since this proof.
    assert_eq!(
        verify(&b, GENERATION + 1, 0, &[&a, &s], &s, &*challenge, &artifact),
        KQ_BRIDGE_STALE
    );
    assert_eq!(
        verify(&b, GENERATION, 1, &[&a, &s], &s, &*challenge, &artifact),
        KQ_BRIDGE_STALE
    );
    // The signer was removed, or the verifier is not a member.
    assert_eq!(
        verify(&b, GENERATION, 0, &[&s], &s, &*challenge, &artifact),
        KQ_BRIDGE_REFUSED
    );
    assert_eq!(
        verify(&b, GENERATION, 0, &[&a, &s], &x, &*challenge, &artifact),
        KQ_BRIDGE_REFUSED
    );
    // A different challenge, a tampered artifact, a truncated one.
    let other = crypto::random_key();
    assert_eq!(
        verify(&b, GENERATION, 0, &[&a, &s], &s, &*other, &artifact),
        KQ_BRIDGE_REFUSED
    );
    let mut tampered = artifact.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        verify(&b, GENERATION, 0, &[&a, &s], &s, &*challenge, &tampered),
        KQ_BRIDGE_REFUSED
    );
    assert_eq!(
        verify(
            &b,
            GENERATION,
            0,
            &[&a, &s],
            &s,
            &*challenge,
            &artifact[..10]
        ),
        KQ_BRIDGE_INVALID
    );
}

#[test]
fn a_member_who_does_not_hold_the_bridge_key_cannot_prove() {
    let (a, s, b) = (person("M.A.1"), person("M.S.1"), bridge());
    let challenge = crypto::random_key();
    // The sealed key was sealed to another member, or belongs to another bridge.
    assert_eq!(prove(&b, &a, &s, &*challenge).0, KQ_BRIDGE_REFUSED);
    let mut elsewhere = bridge();
    elsewhere.public = b.public;
    assert_eq!(prove(&elsewhere, &a, &a, &*challenge).0, KQ_BRIDGE_REFUSED);
    // A small buffer reports the size needed.
    let wrap_salt = crypto::random_salt();
    let sealed = seal_bridge_secret(&a.encryption_public, &wrap_salt, &b.secret).unwrap();
    let mut len = 0usize;
    let rc = unsafe {
        kq_bridge_prove(
            b.uid.as_ptr(),
            GENERATION,
            b.salt.as_ptr(),
            b.public.as_ptr(),
            a.label.as_ptr(),
            sealed.as_ptr(),
            sealed.len(),
            wrap_salt.as_ptr(),
            a.encryption_secret.as_ptr(),
            a.signing_secret.as_ptr(),
            challenge.as_ptr(),
            challenge.len(),
            core::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    assert_eq!(rc, KQ_BRIDGE_NO_ROOM);
    assert!(len > 0);
}

#[test]
fn bridge_reach_is_the_authority_rule_one_hop_and_null_safe() {
    let c = |s: &str| CString::new(s).unwrap();
    let reach = |a: &str, b: &str, actor: &str, scope: &str| unsafe {
        kq_bridge_connects(
            c(a).as_ptr(),
            c(b).as_ptr(),
            c(actor).as_ptr(),
            c(scope).as_ptr(),
        )
    };
    assert_eq!(reach("M.A", "M.S", "M.A.1", "M.S.1"), 1);
    assert_eq!(reach("M.S", "M.A", "M.A.1", "M.S.1"), 1);
    assert_eq!(reach("M.A", "M.S", "M.A.1", "M.X.1"), 0);
    assert_eq!(reach("M.A", "M.A", "M.A.1", "M.A.2"), 0);
    assert_eq!(
        unsafe {
            kq_bridge_connects(
                core::ptr::null(),
                c("M.S").as_ptr(),
                c("a").as_ptr(),
                c("b").as_ptr(),
            )
        },
        0
    );
}
