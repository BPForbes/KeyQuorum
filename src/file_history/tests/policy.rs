use super::*;
use ed25519_dalek::SigningKey;

const GEN: u64 = 7;

fn ident(n: u8) -> [u8; 16] {
    [n; 16]
}

fn secret(n: u8) -> [u8; 32] {
    [n; 32]
}

fn public(n: u8) -> [u8; 32] {
    SigningKey::from_bytes(&secret(n))
        .verifying_key()
        .to_bytes()
}

/// Registered keys by (identity byte, label); `n` doubles as the key seed.
struct Ctx {
    keys: Vec<(u8, &'static str)>,
    bridge: BridgeEvidence,
}

impl Ctx {
    fn new() -> Self {
        Self {
            keys: vec![(1, "M"), (2, "M.A"), (3, "M.A.1"), (4, "M.S.1"), (5, "M.B")],
            bridge: BridgeEvidence::None,
        }
    }
}

impl TrustContext for Ctx {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        self.keys
            .iter()
            .find(|(n, l)| ident(*n) == *identity && *l == label)
            .map(|(n, _)| public(*n))
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        self.bridge
    }
}

fn policy() -> FilePolicy {
    FilePolicy::standard("M.A")
}

fn revision_by(
    file: &mut TrackedFile,
    parents: Vec<[u8; 32]>,
    label: &str,
    who: u8,
    policy: &FilePolicy,
    at: &str,
) -> [u8; 32] {
    let mut new = new_revision(parents, at);
    new.author_hcp_label = label.to_string();
    new.author_identity = Some(ident(who));
    new.topology_generation = GEN;
    new.policy_hash = policy.policy_hash().unwrap();
    file.check_in(new, format!("{label}@{at}").into_bytes())
        .unwrap()
}

fn one(label: &str, who: u8) -> (TrackedFile, [u8; 32]) {
    let mut file = TrackedFile::new(FILE, "report.txt");
    let id = revision_by(&mut file, vec![], label, who, &policy(), T1);
    (file, id)
}

fn state(file: &TrackedFile, id: &[u8; 32], ctx: &Ctx) -> TrustState {
    evaluate_revision_trust(file, id, &policy(), ctx).unwrap()
}

use TrustReason as R;
use TrustState::{Denied, Pending, Trusted};

#[test]
fn a_scope_owner_self_signature_is_trusted_and_unsigned_is_pending() {
    let (mut file, id) = one("M.A", 2);
    let ctx = Ctx::new();
    assert_eq!(state(&file, &id, &ctx), Pending(R::MissingContentSignature));
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(state(&file, &id, &ctx), Trusted);
}

#[test]
fn an_ancestor_may_self_sign() {
    let (mut file, id) = one("M", 1);
    file.sign_revision(&id, ident(1), "M", &secret(1)).unwrap();
    assert_eq!(state(&file, &id, &Ctx::new()), Trusted);
}

#[test]
fn a_valid_descendant_signature_alone_is_not_trusted() {
    let (mut file, id) = one("M.A.1", 3);
    file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    assert_eq!(
        state(&file, &id, &Ctx::new()),
        Pending(R::MissingCountersignature)
    );
}

#[test]
fn only_the_direct_parent_countersignature_counts() {
    let ctx = Ctx::new();
    for (who, label) in [(1u8, "M"), (5, "M.B")] {
        let (mut file, id) = one("M.A.1", 3);
        file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
            .unwrap();
        file.countersign_revision(&id, ident(who), label, &secret(who))
            .unwrap();
        assert_eq!(
            state(&file, &id, &ctx),
            Pending(R::MissingCountersignature),
            "{label}"
        );
    }
    let (mut file, id) = one("M.A.1", 3);
    file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    file.countersign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(state(&file, &id, &ctx), Trusted);
}

#[test]
fn cross_branch_needs_a_bridge_or_the_scope_owner() {
    let mut ctx = Ctx::new();
    let (mut file, id) = one("M.S.1", 4);
    file.sign_revision(&id, ident(4), "M.S.1", &secret(4))
        .unwrap();
    assert_eq!(
        state(&file, &id, &ctx),
        Pending(R::MissingBridgeOrOwnerApproval)
    );
    for evidence in [
        BridgeEvidence::NonPrivateAuthorized,
        BridgeEvidence::PrivateAuthorized,
    ] {
        ctx.bridge = evidence;
        assert_eq!(state(&file, &id, &ctx), Trusted);
    }
    ctx.bridge = BridgeEvidence::None;
    // A countersignature from someone other than the scope owner is not enough.
    file.countersign_revision(&id, ident(1), "M", &secret(1))
        .unwrap();
    assert_eq!(
        state(&file, &id, &ctx),
        Pending(R::MissingBridgeOrOwnerApproval)
    );
    file.countersign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(state(&file, &id, &ctx), Trusted);
}

#[test]
fn bridge_evidence_alone_does_not_replace_the_author_signature() {
    let mut ctx = Ctx::new();
    ctx.bridge = BridgeEvidence::PrivateAuthorized;
    let (file, id) = one("M.S.1", 4);
    assert_eq!(state(&file, &id, &ctx), Pending(R::MissingContentSignature));
}

#[test]
fn an_unrelated_author_is_denied() {
    let (file, id) = one("X.1", 9);
    assert_eq!(state(&file, &id, &Ctx::new()), Denied(R::UnrelatedActor));
}

#[test]
fn a_forbidden_role_is_denied() {
    let mut strict = policy();
    strict.descendants = Requirement::Forbidden;
    let mut file = TrackedFile::new(FILE, "report.txt");
    let id = revision_by(&mut file, vec![], "M.A.1", 3, &strict, T1);
    let verdict = evaluate_revision_trust(&file, &id, &strict, &Ctx::new()).unwrap();
    assert_eq!(verdict, Denied(R::RoleForbidden));
}

#[test]
fn the_policy_hash_pins_the_rules_a_revision_was_made_under() {
    let mut file = TrackedFile::new(FILE, "report.txt");
    let mut lax = policy();
    lax.descendants = Requirement::AuthorSign;
    let id = revision_by(&mut file, vec![], "M.A.1", 3, &lax, T1);
    assert_eq!(
        state(&file, &id, &Ctx::new()),
        Denied(R::PolicyHashMismatch)
    );
    let hashes: Vec<_> = [
        policy(),
        lax,
        FilePolicy::standard("M.B"),
        FilePolicy {
            ancestors: Requirement::Forbidden,
            ..policy()
        },
        FilePolicy {
            cross_branch: Requirement::AuthorSign,
            ..policy()
        },
        FilePolicy {
            scope_owner: Requirement::Forbidden,
            ..policy()
        },
        FilePolicy {
            auto_merge: false,
            ..policy()
        },
    ]
    .iter()
    .map(|p| p.policy_hash().unwrap())
    .collect();
    for (i, a) in hashes.iter().enumerate() {
        for b in &hashes[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_eq!(
        policy().policy_hash().unwrap(),
        policy().policy_hash().unwrap()
    );
}

#[test]
fn bad_keys_and_bad_signatures_are_denied() {
    let (mut file, id) = one("M.A", 2);
    // Signed with the wrong secret.
    file.sign_revision(&id, ident(2), "M.A", &secret(9))
        .unwrap();
    assert_eq!(
        state(&file, &id, &Ctx::new()),
        Denied(R::InvalidContentSignature)
    );
    // No key registered for the signer.
    let mut ctx = Ctx::new();
    ctx.keys.retain(|(_, l)| *l != "M.A");
    assert_eq!(state(&file, &id, &ctx), Denied(R::UnknownSigner));
}

#[test]
fn a_proof_from_someone_else_or_another_generation_is_denied() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let ctx = Ctx::new();

    // A proof that does not come from the author is ignored, not trusted.
    let mut other = file.clone();
    other.proofs[0].signer_label = "M.B".into();
    assert_eq!(
        state(&other, &id, &ctx),
        Pending(R::MissingContentSignature)
    );

    let mut moved = file.clone();
    moved.proofs[0].topology_generation += 1;
    assert_eq!(state(&moved, &id, &ctx), Denied(R::GenerationMismatch));

    let mut rebound = file.clone();
    rebound.proofs[0].policy_hash = [0; 32];
    assert_eq!(state(&rebound, &id, &ctx), Denied(R::GenerationMismatch));
}

#[test]
fn a_signature_does_not_survive_changed_content() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    file.revisions[0].revision.content_commitment = [0xee; 32];
    assert_eq!(
        state(&file, &id, &Ctx::new()),
        Denied(R::InvalidContentSignature)
    );
}

#[test]
fn a_countersignature_backs_the_exact_author_signature() {
    let ctx = Ctx::new();
    let (mut file, id) = one("M.A.1", 3);
    file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    file.countersign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(state(&file, &id, &ctx), Trusted);

    let mut rebound = file.clone();
    rebound.proofs[1].author_signature_hash = Some([1; 32]);
    assert_eq!(
        state(&rebound, &id, &ctx),
        Denied(R::InvalidCountersignature)
    );

    let mut forged = file.clone();
    forged.proofs[1].signature[0] ^= 1;
    assert_eq!(
        state(&forged, &id, &ctx),
        Denied(R::InvalidCountersignature)
    );

    let mut moved = file.clone();
    moved.proofs[1].topology_generation += 1;
    assert_eq!(state(&moved, &id, &ctx), Denied(R::GenerationMismatch));

    let mut unknown = file.clone();
    unknown.proofs[1].signer_identity = ident(99);
    assert_eq!(state(&unknown, &id, &ctx), Denied(R::UnknownSigner));
}

#[test]
fn signing_is_limited_to_the_author_and_not_repeatable() {
    let (mut file, id) = one("M.A.1", 3);
    assert!(file
        .sign_revision(&id, ident(2), "M.A", &secret(2))
        .is_err());
    assert!(file
        .sign_revision(&[9; 32], ident(3), "M.A.1", &secret(3))
        .is_err());
    // A countersignature needs the author's signature first.
    assert!(file
        .countersign_revision(&id, ident(2), "M.A", &secret(2))
        .is_err());
    file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    assert!(file
        .sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .is_err());
    file.countersign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert!(file
        .countersign_revision(&id, ident(2), "M.A", &secret(2))
        .is_err());
}

#[test]
fn proofs_round_trip_and_are_structurally_checked() {
    let (mut file, id) = one("M.A.1", 3);
    file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    file.countersign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(TrackedFile::decode(&file.encode().unwrap()).unwrap(), file);

    let decodes = |f: &dyn Fn(&mut TrackedFile)| {
        let mut broken = file.clone();
        f(&mut broken);
        TrackedFile::decode(&broken.encode_unchecked().unwrap()).is_ok()
    };
    assert!(!decodes(&|f| f.proofs[0].revision_id = [9; 32]));
    assert!(!decodes(&|f| {
        let copy = f.proofs[0].clone();
        f.proofs.push(copy);
    }));
    assert!(!decodes(
        &|f| f.proofs[0].author_signature_hash = Some([1; 32])
    ));
    assert!(!decodes(&|f| f.proofs[1].author_signature_hash = None));
    assert!(decodes(&|_| {}));
}

#[test]
fn any_flipped_byte_in_a_signed_file_is_detected() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let ctx = Ctx::new();
    let bytes = file.encode().unwrap();
    // Name text is not authenticated; everything else is either rejected on
    // decode or fails trust evaluation.
    let name_text = 4 + 1 + 16 + 2;
    for index in 0..bytes.len() {
        if (name_text..name_text + file.logical_name.len()).contains(&index) {
            continue;
        }
        let mut tampered = bytes.clone();
        tampered[index] ^= 1;
        if let Ok(decoded) = TrackedFile::decode(&tampered) {
            let id = decoded.revisions[0].revision.revision_id;
            assert_ne!(
                evaluate_revision_trust(&decoded, &id, &policy(), &ctx).ok(),
                Some(Trusted),
                "flip at byte {index} stayed trusted"
            );
        }
    }
}

fn shared(file: &TrackedFile, candidate: &[u8; 32], held: Option<&[u8; 32]>) -> DeliveryDecision {
    select_shareable_revision(file, candidate, held, &policy(), &Ctx::new()).unwrap()
}

#[test]
fn an_unsigned_newer_revision_falls_back_to_the_last_trusted_one() {
    // The sales-report example: R1 signed by the owner, R2 edited unsigned.
    let mut file = TrackedFile::new(FILE, "report.txt");
    let r1 = revision_by(&mut file, vec![], "M.A", 2, &policy(), T1);
    file.sign_revision(&r1, ident(2), "M.A", &secret(2))
        .unwrap();
    let r2 = revision_by(&mut file, vec![r1], "M.A", 2, &policy(), T2);

    let d = shared(&file, &r2, None);
    assert_eq!(d.decision, DeliveryDecisionKind::LastTrustedRevision);
    assert_eq!(d.candidate_revision, r2);
    assert_eq!(d.delivered_revision, Some(r1));

    file.sign_revision(&r2, ident(2), "M.A", &secret(2))
        .unwrap();
    let d = shared(&file, &r2, None);
    assert_eq!(d.decision, DeliveryDecisionKind::CurrentTrustedRevision);
    assert_eq!(d.delivered_revision, Some(r2));
    assert_eq!(
        shared(&file, &r2, Some(&r2)).decision,
        DeliveryDecisionKind::RequesterAlreadyCurrent
    );
}

#[test]
fn a_requester_already_holding_the_fallback_is_told_so() {
    let mut file = TrackedFile::new(FILE, "report.txt");
    let r1 = revision_by(&mut file, vec![], "M.A", 2, &policy(), T1);
    file.sign_revision(&r1, ident(2), "M.A", &secret(2))
        .unwrap();
    let r2 = revision_by(&mut file, vec![r1], "M.A", 2, &policy(), T2);
    let d = shared(&file, &r2, Some(&r1));
    assert_eq!(d.decision, DeliveryDecisionKind::RequesterAlreadyCurrent);
    assert_eq!(d.delivered_revision, Some(r1));
}

#[test]
fn nothing_trusted_means_nothing_is_delivered() {
    let (file, id) = one("M.A", 2);
    let d = shared(&file, &id, None);
    assert_eq!(d.decision, DeliveryDecisionKind::DeniedNoTrustedRevision);
    assert_eq!(d.delivered_revision, None);
    assert!(select_shareable_revision(&file, &[9; 32], None, &policy(), &Ctx::new()).is_err());
}

#[test]
fn fallback_only_considers_ancestors_of_the_candidate() {
    // Trusted work on a sibling branch is not a fallback for this one.
    let mut file = TrackedFile::new(FILE, "report.txt");
    let base = revision_by(&mut file, vec![], "M.A", 2, &policy(), T1);
    let left = revision_by(&mut file, vec![base], "M.A", 2, &policy(), T2);
    let right = revision_by(
        &mut file,
        vec![base],
        "M.A",
        2,
        &policy(),
        "2026-10-02T15:00:00Z",
    );
    file.sign_revision(&right, ident(2), "M.A", &secret(2))
        .unwrap();
    let d = shared(&file, &left, None);
    assert_eq!(d.decision, DeliveryDecisionKind::DeniedNoTrustedRevision);
    file.sign_revision(&base, ident(2), "M.A", &secret(2))
        .unwrap();
    let d = shared(&file, &left, None);
    assert_eq!(d.delivered_revision, Some(base));
    assert_eq!(d.decision, DeliveryDecisionKind::LastTrustedRevision);
}

#[test]
fn a_countersignature_cannot_be_relabelled_onto_another_position() {
    // The same key is registered for identity 1 under two labels. A
    // countersignature made as "M" must not pass as one made by "M.A".
    let mut ctx = Ctx::new();
    ctx.keys.push((1, "M.A"));
    let (mut file, id) = one("M.A.1", 3);
    file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    file.countersign_revision(&id, ident(1), "M", &secret(1))
        .unwrap();
    assert_eq!(state(&file, &id, &ctx), Pending(R::MissingCountersignature));
    file.proofs[1].signer_label = "M.A".into();
    assert_eq!(state(&file, &id, &ctx), Denied(R::InvalidCountersignature));
}

#[test]
fn a_bogus_content_proof_cannot_shadow_the_authors() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let mut bogus = file.proofs[0].clone();
    bogus.signer_label = "M.B".into();
    bogus.signer_identity = ident(5);
    file.proofs.insert(0, bogus);
    assert_eq!(state(&file, &id, &Ctx::new()), Trusted);
    // A container carrying a non-author content proof does not decode.
    assert!(TrackedFile::decode(&file.encode_unchecked().unwrap()).is_err());
}

fn import_context() -> crate::file_history::ImportContext {
    crate::file_history::ImportContext {
        actor_identity: Some(ident(9)),
        actor_label: "M.A".to_string(),
        occurred_at: "2026-10-06T00:00:00Z".to_string(),
        topology_generation: GEN,
    }
}

/// A copy of `file` where the revision's author slot holds a forgery: a
/// well-formed proof signed with the wrong secret.
fn forged_copy(file: &TrackedFile, id: &[u8; 32], label: &str, who: u8) -> TrackedFile {
    let mut copy = file.clone();
    copy.sign_revision(id, ident(who), label, &secret(99))
        .unwrap();
    copy
}

#[test]
fn an_imported_forgery_does_not_keep_the_real_author_out() {
    let (mut local, id) = one("M.A", 2);
    let remote = forged_copy(&local, &id, "M.A", 2);
    let merged = local.merge_history(&remote, &import_context()).unwrap();
    assert_eq!(merged.proofs_added, 1);
    assert_eq!(
        state(&local, &id, &Ctx::new()),
        Denied(R::InvalidContentSignature)
    );
    // The author can still sign, and the revision is trusted.
    local
        .sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(local.proofs().len(), 2);
    assert_eq!(state(&local, &id, &Ctx::new()), Trusted);
    // Signing the same thing again is still refused.
    assert!(local
        .sign_revision(&id, ident(2), "M.A", &secret(2))
        .is_err());
    // The result survives an encode round trip.
    assert_eq!(
        TrackedFile::decode(&local.encode().unwrap()).unwrap(),
        local
    );
}

#[test]
fn an_imported_forgery_does_not_displace_a_real_proof() {
    let (mut local, id) = one("M.A", 2);
    local
        .sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let mut remote = one("M.A", 2).0;
    remote
        .sign_revision(&id, ident(2), "M.A", &secret(99))
        .unwrap();
    local.merge_history(&remote, &import_context()).unwrap();
    assert_eq!(local.proofs().len(), 2);
    assert_eq!(state(&local, &id, &Ctx::new()), Trusted);
}

#[test]
fn a_real_proof_imported_after_a_forgery_is_trusted() {
    let (mut local, id) = one("M.A", 2);
    let forged = forged_copy(&local, &id, "M.A", 2);
    local.merge_history(&forged, &import_context()).unwrap();
    let mut real = one("M.A", 2).0;
    real.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    local.merge_history(&real, &import_context()).unwrap();
    assert_eq!(state(&local, &id, &Ctx::new()), Trusted);
}

#[test]
fn an_unknown_key_forgery_cannot_poison_a_later_registration() {
    let (mut local, id) = one("M.A", 2);
    let forged = forged_copy(&local, &id, "M.A", 2);
    local.merge_history(&forged, &import_context()).unwrap();
    local
        .sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let mut no_keys = Ctx::new();
    no_keys.keys.retain(|(_, l)| *l != "M.A");
    assert_eq!(state(&local, &id, &no_keys), Denied(R::UnknownSigner));
    assert_eq!(state(&local, &id, &Ctx::new()), Trusted);
}

#[test]
fn an_imported_forged_countersignature_does_not_block_the_real_one() {
    let (mut local, id) = one("M.A.1", 3);
    local
        .sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    let mut remote = local.clone();
    remote
        .countersign_revision(&id, ident(2), "M.A", &secret(99))
        .unwrap();
    local.merge_history(&remote, &import_context()).unwrap();
    assert_eq!(
        state(&local, &id, &Ctx::new()),
        Denied(R::InvalidCountersignature)
    );
    local
        .countersign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(state(&local, &id, &Ctx::new()), Trusted);
    // A countersigner with keys backs the verifying author proof even when
    // a forged author proof comes first.
    let (mut file, id) = one("M.A.1", 3);
    file.sign_revision(&id, ident(3), "M.A.1", &secret(99))
        .unwrap();
    file.sign_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    file.countersign_revision_checked(&id, ident(2), "M.A", &secret(2), &Ctx::new())
        .unwrap();
    assert_eq!(state(&file, &id, &Ctx::new()), Trusted);
}

#[test]
fn competing_proofs_per_slot_are_bounded() {
    use crate::file_history::proof::MAX_PROOFS_PER_SLOT;
    let (local, id) = one("M.A", 2);
    let mut crowded = local.clone();
    for n in 0..(MAX_PROOFS_PER_SLOT as u8 + 5) {
        crowded
            .sign_revision(&id, ident(2), "M.A", &secret(50 + n))
            .unwrap();
    }
    // Local signing evicts the oldest instead of growing.
    assert_eq!(crowded.proofs().len(), MAX_PROOFS_PER_SLOT);
    // An import into a full slot adds nothing.
    let mut more = local.clone();
    more.sign_revision(&id, ident(2), "M.A", &secret(200))
        .unwrap();
    let merged = crowded.merge_history(&more, &import_context()).unwrap();
    assert_eq!(merged.proofs_added, 0);
    assert_eq!(crowded.proofs().len(), MAX_PROOFS_PER_SLOT);
    // The real author can still get in.
    crowded
        .sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(crowded.proofs().len(), MAX_PROOFS_PER_SLOT);
    assert_eq!(state(&crowded, &id, &Ctx::new()), Trusted);
    // A container over the cap is not structurally valid.
    let mut over = crowded.clone();
    let extra = over.proofs[0].clone();
    over.proofs.push(RevisionProof {
        signature: [7; 64],
        ..extra
    });
    assert!(over.encode().is_err() || TrackedFile::decode(&over.encode().unwrap()).is_err());
}
