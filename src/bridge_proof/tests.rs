use super::*;
use crate::crypto;

const UID: &str = "bridge-1";

struct Person {
    label: &'static str,
    encryption_secret: Zeroizing<[u8; 32]>,
    encryption_public: [u8; 32],
    signing_secret: Zeroizing<[u8; 32]>,
    signing_public: [u8; 32],
}

fn person(label: &'static str) -> Person {
    let (encryption_secret, encryption_public) = keys::generate_encryption_keypair();
    let (signing_secret, signing_public) = keys::generate_signing_keypair();
    Person {
        label,
        encryption_secret,
        encryption_public,
        signing_secret,
        signing_public,
    }
}

struct Bridge {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    salt: [u8; SALT_LEN],
}

fn bridge() -> Bridge {
    let (secret, public) = keys::generate_signing_keypair();
    Bridge {
        secret,
        public,
        salt: crypto::random_salt(),
    }
}

fn sealed_for(bridge: &Bridge, member: &Person) -> SealedBridgeKey {
    let wrap_salt = crypto::random_salt();
    let sealed = seal_bridge_secret(&member.encryption_public, &wrap_salt, &bridge.secret).unwrap();
    SealedBridgeKey { sealed, wrap_salt }
}

fn roster<'a>(people: &[&'a Person]) -> Vec<MemberFact<'a>> {
    people
        .iter()
        .map(|p| MemberFact {
            label: p.label,
            signing_public: Some(p.signing_public),
        })
        .collect()
}

fn facts<'a>(bridge: &Bridge, members: &'a [MemberFact<'a>]) -> BridgeFacts<'a> {
    BridgeFacts {
        uid: UID,
        generation: 4,
        salt: bridge.salt,
        bridge_public: bridge.public,
        destroyed: false,
        members,
    }
}

fn local(p: &Person) -> LocalMember {
    LocalMember {
        encryption_public: p.encryption_public,
        holds_sealed_key: true,
    }
}

fn prove_as(
    facts: &BridgeFacts<'_>,
    p: &Person,
    sealed: SealedBridgeKey,
    challenge: &[u8],
) -> Result<BridgeSignature> {
    prove(
        facts,
        p.label,
        &local(p),
        sealed,
        &p.encryption_secret,
        &p.signing_secret,
        challenge,
    )
}

#[test]
fn a_member_proves_a_challenge_and_another_member_verifies_it() {
    let (a, b, bridge) = (person("M.A.1"), person("M.S.1"), bridge());
    let members = roster(&[&a, &b]);
    let facts = facts(&bridge, &members);
    let challenge = crypto::random_key();
    let proof = prove_as(&facts, &a, sealed_for(&bridge, &a), &*challenge).unwrap();
    assert_eq!(proof.signer_label, "M.A.1");
    verify(&facts, "M.S.1", &*challenge, &proof).unwrap();
    // The proof is bound to the challenge.
    let other = crypto::random_key();
    assert!(verify(&facts, "M.S.1", &*other, &proof).is_err());
}

#[test]
fn verification_is_against_the_live_bridge_only() {
    let (a, b, bridge) = (person("M.A.1"), person("M.S.1"), bridge());
    let members = roster(&[&a, &b]);
    let live = facts(&bridge, &members);
    let challenge = crypto::random_key();
    let proof = prove_as(&live, &a, sealed_for(&bridge, &a), &*challenge).unwrap();

    let mut next_generation = live;
    next_generation.generation = 5;
    assert!(matches!(
        verify(&next_generation, "M.S.1", &*challenge, &proof),
        Err(Error::BridgeGenerationMismatch)
    ));
    let mut other_salt = live;
    other_salt.salt = crypto::random_salt();
    assert!(matches!(
        verify(&other_salt, "M.S.1", &*challenge, &proof),
        Err(Error::BridgeGenerationMismatch)
    ));
    let mut other_uid = live;
    other_uid.uid = "bridge-2";
    assert!(matches!(
        verify(&other_uid, "M.S.1", &*challenge, &proof),
        Err(Error::BridgeGenerationMismatch)
    ));
    let mut gone = live;
    gone.destroyed = true;
    assert!(matches!(
        verify(&gone, "M.S.1", &*challenge, &proof),
        Err(Error::BridgeDestroyed)
    ));
    // A removed member can no longer be a signer or a verifier.
    let remaining = roster(&[&b]);
    assert!(matches!(
        verify(&facts(&bridge, &remaining), "M.S.1", &*challenge, &proof),
        Err(Error::NotBridgeMember)
    ));
    assert!(matches!(
        verify(&live, "M.X.1", &*challenge, &proof),
        Err(Error::NotBridgeMember)
    ));
    // A roster that holds a different key for the signer refuses the signature.
    let imposter = person("M.A.1");
    let swapped = roster(&[&imposter, &b]);
    assert!(verify(&facts(&bridge, &swapped), "M.S.1", &*challenge, &proof).is_err());
    // The bridge's own key matters: another bridge's public key does not verify it.
    let mut other_bridge = live;
    other_bridge.bridge_public = self::bridge().public;
    assert!(verify(&other_bridge, "M.S.1", &*challenge, &proof).is_err());
}

#[test]
fn only_a_local_member_holding_the_right_keys_can_prove() {
    let (a, b, bridge) = (person("M.A.1"), person("M.S.1"), bridge());
    let members = roster(&[&a, &b]);
    let facts = facts(&bridge, &members);
    let challenge = crypto::random_key();

    // Not a member.
    let outsider = person("M.X.1");
    assert!(matches!(
        prove_as(
            &facts,
            &outsider,
            sealed_for(&bridge, &outsider),
            &*challenge
        ),
        Err(Error::NotBridgeMember)
    ));
    // No sealed key held here.
    let no_key = LocalMember {
        holds_sealed_key: false,
        ..local(&a)
    };
    assert!(matches!(
        prove(
            &facts,
            "M.A.1",
            &no_key,
            sealed_for(&bridge, &a),
            &a.encryption_secret,
            &a.signing_secret,
            &*challenge
        ),
        Err(Error::SealedKeyNotHeld)
    ));
    // Someone else's encryption or signing secret.
    assert!(matches!(
        prove(
            &facts,
            "M.A.1",
            &local(&a),
            sealed_for(&bridge, &a),
            &b.encryption_secret,
            &a.signing_secret,
            &*challenge
        ),
        Err(Error::IntegrityCheckFailed)
    ));
    assert!(matches!(
        prove(
            &facts,
            "M.A.1",
            &local(&a),
            sealed_for(&bridge, &a),
            &a.encryption_secret,
            &b.signing_secret,
            &*challenge
        ),
        Err(Error::IntegrityCheckFailed)
    ));
    // A sealed key for another bridge, or one sealed to someone else, or with a wrong salt.
    let elsewhere = self::bridge();
    assert!(matches!(
        prove_as(&facts, &a, sealed_for(&elsewhere, &a), &*challenge),
        Err(Error::IntegrityCheckFailed)
    ));
    assert!(matches!(
        prove_as(&facts, &a, sealed_for(&bridge, &b), &*challenge),
        Err(Error::IntegrityCheckFailed)
    ));
    let mut wrong_salt = sealed_for(&bridge, &a);
    wrong_salt.wrap_salt = crypto::random_salt();
    assert!(matches!(
        prove_as(&facts, &a, wrong_salt, &*challenge),
        Err(Error::IntegrityCheckFailed)
    ));
    // A destroyed bridge proves nothing.
    let mut gone = facts;
    gone.destroyed = true;
    assert!(matches!(
        prove_as(&gone, &a, sealed_for(&bridge, &a), &*challenge),
        Err(Error::BridgeDestroyed)
    ));
}

#[test]
fn the_registry_hooks_can_refuse_either_side() {
    let (a, b, bridge) = (person("M.A.1"), person("M.S.1"), bridge());
    let members = roster(&[&a, &b]);
    let facts = facts(&bridge, &members);
    let challenge = crypto::random_key();
    let refused = prove_with(
        &facts,
        "M.A.1",
        &local(&a),
        &a.encryption_secret,
        &a.signing_secret,
        &*challenge,
        |_, _| Err(Error::IntegrityCheckFailed),
        || Ok(sealed_for(&bridge, &a)),
    );
    assert!(matches!(refused, Err(Error::IntegrityCheckFailed)));
    let proof = prove_as(&facts, &a, sealed_for(&bridge, &a), &*challenge).unwrap();
    assert!(matches!(
        verify_with(&facts, "M.S.1", &*challenge, &proof, |_, _| Err(
            Error::IntegrityCheckFailed
        )),
        Err(Error::IntegrityCheckFailed)
    ));
}
