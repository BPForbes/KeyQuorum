use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn generate() -> (SigningKey, [u8; 32]) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    (signing_key, public_key)
}

#[test]
fn valid_signature_verifies() {
    let (signing_key, public_key) = generate();
    let message = b"the quorum has been reached";
    let signature = signing_key.sign(message);

    let result = verify_signature(&public_key, message, &signature.to_bytes());
    assert!(result.is_ok());
}

#[test]
fn tampered_message_is_rejected() {
    let (signing_key, public_key) = generate();
    let signature = signing_key.sign(b"the quorum has been reached");

    let result = verify_signature(
        &public_key,
        b"the quorum has NOT been reached",
        &signature.to_bytes(),
    );
    assert!(matches!(result, Err(Error::SignatureVerificationFailed)));
}

#[test]
fn wrong_public_key_is_rejected() {
    let (signing_key, _public_key) = generate();
    let (_other_signing_key, other_public_key) = generate();
    let message = b"the quorum has been reached";
    let signature = signing_key.sign(message);

    let result = verify_signature(&other_public_key, message, &signature.to_bytes());
    assert!(matches!(result, Err(Error::SignatureVerificationFailed)));
}

#[test]
fn malformed_public_key_is_rejected() {
    // Not every 32-byte value decompresses to a valid Edwards point —
    // this one doesn't (verified against ed25519-dalek directly).
    let mut malformed_public_key = [0u8; 32];
    malformed_public_key[0] = 0x01;
    malformed_public_key[31] = 0x20;
    let (signing_key, _public_key) = generate();
    let signature = signing_key.sign(b"the quorum has been reached");

    let result = verify_signature(
        &malformed_public_key,
        b"the quorum has been reached",
        &signature.to_bytes(),
    );
    assert!(matches!(result, Err(Error::InvalidPublicKey)));
}

#[test]
fn sign_round_trips_through_verify() {
    let (signing_key, public_key) = generate();
    let message = b"file bytes";
    let signature = sign(&signing_key.to_bytes(), message);
    assert!(verify_signature(&public_key, message, &signature).is_ok());
}

#[test]
fn bridge_dual_signature_binds_salts_and_rejects_wrong_message() {
    let (bridge, bridge_pub) = generate();
    let (personal, _) = generate();
    let message = b"co-signed pdf";
    let artifact = sign_with_bridge(
        "abc",
        1,
        &[7u8; 16],
        "M.A.2",
        &bridge.to_bytes(),
        &personal.to_bytes(),
        message,
    )
    .expect("sign");
    let personal_pub = personal.verifying_key().to_bytes();
    assert!(verify_bridge_signature(&artifact, &bridge_pub, &personal_pub, message).is_ok());
    assert!(matches!(
        verify_bridge_signature(&artifact, &bridge_pub, &personal_pub, b"tampered"),
        Err(Error::SignatureVerificationFailed)
    ));
    let (_, other_pub) = generate();
    assert!(matches!(
        verify_bridge_signature(&artifact, &bridge_pub, &other_pub, message),
        Err(Error::SignatureVerificationFailed)
    ));
    let encoded = encode_bridge_signature(&artifact).expect("encode");
    let decoded = decode_bridge_signature(&encoded).expect("decode");
    assert_eq!(decoded, artifact);
    let again = sign_with_bridge(
        "abc",
        1,
        &[7u8; 16],
        "M.A.2",
        &bridge.to_bytes(),
        &personal.to_bytes(),
        message,
    )
    .expect("sign");
    assert_ne!(artifact.signature_salt, again.signature_salt);
}

const FILE: [u8; 16] = [1; 16];
const REV: [u8; 32] = [2; 32];
const COMMIT: [u8; 32] = [3; 32];
const WHO: [u8; 16] = [4; 16];
const POLICY: [u8; 32] = [5; 32];

fn revision() -> [u8; 32] {
    file_revision_preimage(&FILE, &REV, &COMMIT, &WHO, 7, &POLICY)
}

fn countersign() -> [u8; 32] {
    file_countersign_preimage(&FILE, &REV, &WHO, &COMMIT, &[6; 16], "M.A", 7, &POLICY).unwrap()
}

fn event(revision_id: Option<&[u8; 32]>) -> [u8; 32] {
    file_history_event_preimage(&FILE, revision_id, 9, &COMMIT, &POLICY)
}

#[test]
fn file_preimages_are_deterministic() {
    assert_eq!(revision(), revision());
    assert_eq!(countersign(), countersign());
    assert_eq!(event(Some(&REV)), event(Some(&REV)));
}

#[test]
fn file_preimage_domains_never_collide() {
    // Same underlying bytes fed to each constructor still differ.
    let digests = [revision(), countersign(), event(Some(&REV))];
    assert_ne!(digests[0], digests[1]);
    assert_ne!(digests[0], digests[2]);
    assert_ne!(digests[1], digests[2]);
}

#[test]
fn revision_preimage_binds_every_field() {
    let base = revision();
    assert_ne!(
        base,
        file_revision_preimage(&[9; 16], &REV, &COMMIT, &WHO, 7, &POLICY)
    );
    assert_ne!(
        base,
        file_revision_preimage(&FILE, &[9; 32], &COMMIT, &WHO, 7, &POLICY)
    );
    assert_ne!(
        base,
        file_revision_preimage(&FILE, &REV, &[9; 32], &WHO, 7, &POLICY)
    );
    assert_ne!(
        base,
        file_revision_preimage(&FILE, &REV, &COMMIT, &[9; 16], 7, &POLICY)
    );
    assert_ne!(
        base,
        file_revision_preimage(&FILE, &REV, &COMMIT, &WHO, 8, &POLICY)
    );
    assert_ne!(
        base,
        file_revision_preimage(&FILE, &REV, &COMMIT, &WHO, 7, &[9; 32])
    );
}

#[test]
fn countersign_preimage_binds_every_field() {
    let base = countersign();
    #[allow(clippy::too_many_arguments)]
    let other =
        |f: [u8; 16],
         r: [u8; 32],
         a: [u8; 16],
         h: [u8; 32],
         s: [u8; 16],
         l: &str,
         g: u64,
         p: [u8; 32]| { file_countersign_preimage(&f, &r, &a, &h, &s, l, g, &p).unwrap() };
    assert_ne!(
        base,
        other([9; 16], REV, WHO, COMMIT, [6; 16], "M.A", 7, POLICY)
    );
    assert_ne!(
        base,
        other(FILE, [9; 32], WHO, COMMIT, [6; 16], "M.A", 7, POLICY)
    );
    assert_ne!(
        base,
        other(FILE, REV, [9; 16], COMMIT, [6; 16], "M.A", 7, POLICY)
    );
    assert_ne!(
        base,
        other(FILE, REV, WHO, [9; 32], [6; 16], "M.A", 7, POLICY)
    );
    assert_ne!(
        base,
        other(FILE, REV, WHO, COMMIT, [9; 16], "M.A", 7, POLICY)
    );
    assert_ne!(
        base,
        other(FILE, REV, WHO, COMMIT, [6; 16], "M.B", 7, POLICY)
    );
    assert_ne!(
        base,
        other(FILE, REV, WHO, COMMIT, [6; 16], "M.A", 8, POLICY)
    );
    assert_ne!(
        base,
        other(FILE, REV, WHO, COMMIT, [6; 16], "M.A", 7, [9; 32])
    );
}

#[test]
fn countersign_label_is_length_prefixed_and_size_checked() {
    // A shifted label boundary cannot alias another field layout.
    let a = file_countersign_preimage(&FILE, &REV, &WHO, &COMMIT, &[6; 16], "M.A", 7, &POLICY);
    let b = file_countersign_preimage(&FILE, &REV, &WHO, &COMMIT, &[6; 16], "M.", 7, &POLICY);
    assert_ne!(a.unwrap(), b.unwrap());
    let huge = "x".repeat(70_000);
    assert!(
        file_countersign_preimage(&FILE, &REV, &WHO, &COMMIT, &[6; 16], &huge, 7, &POLICY).is_err()
    );
}

#[test]
fn countersign_distinguishes_author_from_supervisor() {
    // Swapping the two identities must change the digest.
    let mk = |a: [u8; 16], s: [u8; 16]| {
        file_countersign_preimage(&FILE, &REV, &a, &COMMIT, &s, "M.A", 7, &POLICY).unwrap()
    };
    assert_ne!(mk([1; 16], [2; 16]), mk([2; 16], [1; 16]));
}

#[test]
fn event_preimage_binds_every_field_and_none_is_distinct() {
    let base = event(Some(&REV));
    assert_ne!(
        base,
        file_history_event_preimage(&[9; 16], Some(&REV), 9, &COMMIT, &POLICY)
    );
    assert_ne!(base, event(Some(&[9; 32])));
    assert_ne!(
        base,
        file_history_event_preimage(&FILE, Some(&REV), 10, &COMMIT, &POLICY)
    );
    assert_ne!(
        base,
        file_history_event_preimage(&FILE, Some(&REV), 9, &[9; 32], &POLICY)
    );
    assert_ne!(
        base,
        file_history_event_preimage(&FILE, Some(&REV), 9, &COMMIT, &[9; 32])
    );
    // "No revision" differs from every revision id, including all zeros.
    assert_ne!(event(None), event(Some(&[0; 32])));
    assert_ne!(event(None), base);
}

#[test]
fn file_preimages_sign_and_verify_through_the_shared_engine() {
    let (signing_key, public_key) = generate();
    let seed = signing_key.to_bytes();
    let digest = revision();
    let signature = sign(&seed, &digest);
    verify_signature(&public_key, &digest, &signature).unwrap();
    // The same signature does not verify under another domain's preimage.
    assert!(verify_signature(&public_key, &countersign(), &signature).is_err());
    assert!(verify_signature(&public_key, &event(Some(&REV)), &signature).is_err());
}

#[test]
fn a_finalization_preimage_is_domain_separated_and_binds_every_field() {
    let file = [1u8; 16];
    let revision = [2u8; 32];
    let who = [3u8; 16];
    let policy = [4u8; 32];
    let base = file_finalize_preimage(&file, &revision, &who, "M.A", 7, &policy).unwrap();
    assert_eq!(
        base,
        file_finalize_preimage(&file, &revision, &who, "M.A", 7, &policy).unwrap()
    );
    for other in [
        file_finalize_preimage(&[9; 16], &revision, &who, "M.A", 7, &policy).unwrap(),
        file_finalize_preimage(&file, &[9; 32], &who, "M.A", 7, &policy).unwrap(),
        file_finalize_preimage(&file, &revision, &[9; 16], "M.A", 7, &policy).unwrap(),
        file_finalize_preimage(&file, &revision, &who, "M.B", 7, &policy).unwrap(),
        file_finalize_preimage(&file, &revision, &who, "M.A", 8, &policy).unwrap(),
        file_finalize_preimage(&file, &revision, &who, "M.A", 7, &[9; 32]).unwrap(),
    ] {
        assert_ne!(base, other);
    }
    // Not interchangeable with a countersignature over the same fields.
    let counter =
        file_countersign_preimage(&file, &revision, &who, &[0; 32], &who, "M.A", 7, &policy)
            .unwrap();
    assert_ne!(base, counter);
}
