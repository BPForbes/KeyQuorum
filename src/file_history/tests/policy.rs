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

/// A store holding a private bridge's approval, and a tree link that must
/// not count as one.
struct PrivateLink(Ctx);

impl TrustContext for PrivateLink {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        self.0.signing_public(identity, label)
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }

    /// Approved only when the bridge (M.S <-> M.A) reaches from the author
    /// to the scope, as a store holding a signed approval would report it.
    fn revision_bridge_evidence(&self, revision: &FileRevision, scope: &str) -> BridgeEvidence {
        if crate::authority::bridge_connects("M.S", "M.A", &revision.author_hcp_label, scope) {
            BridgeEvidence::PrivateAuthorized
        } else {
            BridgeEvidence::None
        }
    }

    fn bridge_between(&self, _: &str, _: &str) -> BridgeEvidence {
        // A link between labels is not an approval of any revision.
        BridgeEvidence::NonPrivateAuthorized
    }
}

#[test]
fn a_live_bridge_between_the_author_and_the_scope_satisfies_the_cross_branch_rule() {
    let (mut file, id) = one("M.S.1", 4);
    file.sign_revision(&id, ident(4), "M.S.1", &secret(4))
        .unwrap();
    assert_eq!(
        state(&file, &id, &Ctx::new()),
        Pending(R::MissingBridgeOrOwnerApproval)
    );
    let bridged = PrivateLink(Ctx::new());
    assert_eq!(
        evaluate_revision_trust(&file, &id, &policy(), &bridged).unwrap(),
        Trusted
    );
    // A bridge from another sector does not reach this scope.
    let mut elsewhere = TrackedFile::new(FILE, "report.txt");
    let mut far = policy();
    far.scope_root = "M.B".into();
    let id = revision_by(&mut elsewhere, vec![], "M.S.1", 4, &far, T1);
    elsewhere
        .sign_revision(&id, ident(4), "M.S.1", &secret(4))
        .unwrap();
    assert_eq!(
        evaluate_revision_trust(&elsewhere, &id, &far, &bridged).unwrap(),
        Pending(R::MissingBridgeOrOwnerApproval)
    );
}

/// A store that holds only some topology generations.
struct Generations(Ctx, Vec<u64>);

impl TrustContext for Generations {
    fn signing_public(&self, identity: &[u8; 16], label: &str) -> Option<[u8; 32]> {
        self.0.signing_public(identity, label)
    }

    fn bridge_evidence(&self, _: &[u8; 32]) -> BridgeEvidence {
        BridgeEvidence::None
    }

    fn generation_evidence(&self, _: &str, generation: u64) -> GenerationEvidence {
        match self.1.as_slice() {
            [.., current] if *current == generation => GenerationEvidence::Current,
            held if held.contains(&generation) => GenerationEvidence::Recorded,
            _ => GenerationEvidence::Unavailable,
        }
    }
}

#[test]
fn a_revision_from_a_generation_the_store_never_held_is_pending_not_judged_today() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let judge = |held: Vec<u64>| {
        evaluate_revision_trust(&file, &id, &policy(), &Generations(Ctx::new(), held)).unwrap()
    };
    // GEN is current, or an earlier generation this store held: judged.
    assert_eq!(judge(vec![GEN]), Trusted);
    assert_eq!(judge(vec![GEN, GEN + 1]), Trusted);
    // A generation the store never held (older, or newer than it knows).
    assert_eq!(judge(vec![GEN + 1]), Pending(R::MissingTopologyEvidence));
    assert_eq!(judge(vec![GEN - 1]), Pending(R::MissingTopologyEvidence));
    // Missing evidence is never a reason to deliver: nothing trusted here.
    let decision = select_shareable_revision(
        &file,
        &id,
        None,
        &policy(),
        &Generations(Ctx::new(), vec![GEN + 1]),
    )
    .unwrap();
    assert_eq!(decision.delivered_revision, None);
}

#[test]
fn an_unrelated_author_is_denied() {
    let (file, id) = one("X.1", 9);
    assert_eq!(state(&file, &id, &Ctx::new()), Denied(R::UnrelatedActor));
}

#[test]
fn a_branch_with_no_common_ancestor_never_gets_the_cross_branch_rule() {
    // Even when cross-branch authors need only their own signature, an author
    // under another root entirely (`CrossBranch { common_ancestor: None }`)
    // has no hierarchy that could connect them to the scope.
    let mut open = policy();
    open.cross_branch = Requirement::AuthorSign;
    assert_eq!(open.requirement_for("M.S.1"), Some(Requirement::AuthorSign));
    assert_eq!(open.requirement_for("X.1"), None);
    assert!(!open.may_author("X.1"));
    let mut file = TrackedFile::new(FILE, "report.txt");
    let id = revision_by(&mut file, vec![], "X.1", 9, &open, T1);
    let verdict = evaluate_revision_trust(&file, &id, &open, &Ctx::new()).unwrap();
    assert_eq!(verdict, Denied(R::UnrelatedActor));
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
fn a_revision_the_rules_refuse_is_denied_by_policy_not_just_untrusted() {
    // An author outside the file's scope is refused outright, unlike a
    // revision that is merely waiting for its signature.
    let (file, id) = one("X.1", 2);
    let d = shared(&file, &id, None);
    assert_eq!(d.decision, DeliveryDecisionKind::DeniedPolicy);
    assert_eq!(d.delivered_revision, None);
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

// ---- finalization ------------------------------------------------------------

fn finalized(file: &TrackedFile, id: &[u8; 32], ctx: &Ctx) -> bool {
    is_finalized(file, id, &policy(), ctx)
}

#[test]
fn only_a_trusted_revision_the_owner_or_an_ancestor_finalized_is_final() {
    let (mut file, id) = one("M.A", 2);
    let ctx = Ctx::new();
    // Not trusted yet, so a finalization proof does not count.
    file.finalize_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert!(!finalized(&file, &id, &ctx));
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(state(&file, &id, &ctx), Trusted);
    assert!(finalized(&file, &id, &ctx));
    // Finalizing does not touch trust.
    assert_eq!(state(&file, &id, &ctx), Trusted);
}

#[test]
fn a_descendant_or_a_stranger_cannot_finalize() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let ctx = Ctx::new();
    // M.A.1 (a descendant) and M.S.1 (cross-branch) hold valid keys but not
    // the standing to finalize.
    file.finalize_revision(&id, ident(3), "M.A.1", &secret(3))
        .unwrap();
    file.finalize_revision(&id, ident(4), "M.S.1", &secret(4))
        .unwrap();
    assert!(!finalized(&file, &id, &ctx));
    // An ancestor may.
    file.finalize_revision(&id, ident(1), "M", &secret(1))
        .unwrap();
    assert!(finalized(&file, &id, &ctx));
}

#[test]
fn a_finalization_signed_with_the_wrong_key_does_not_verify() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    file.finalize_revision(&id, ident(2), "M.A", &secret(9))
        .unwrap();
    assert!(!finalized(&file, &id, &Ctx::new()));
}

#[test]
fn the_latest_finalized_ancestor_is_per_branch_and_never_a_winner() {
    let mut file = TrackedFile::new(FILE, "report.txt");
    let base = revision_by(&mut file, vec![], "M.A", 2, &policy(), T1);
    file.sign_revision(&base, ident(2), "M.A", &secret(2))
        .unwrap();
    file.finalize_revision(&base, ident(2), "M.A", &secret(2))
        .unwrap();
    let left = revision_by(&mut file, vec![base], "M.A", 2, &policy(), T2);
    let right = revision_by(
        &mut file,
        vec![base],
        "M.A",
        2,
        &policy(),
        "2026-10-02T15:00:00Z",
    );
    for id in [left, right] {
        file.sign_revision(&id, ident(2), "M.A", &secret(2))
            .unwrap();
    }
    file.finalize_revision(&right, ident(2), "M.A", &secret(2))
        .unwrap();
    let ctx = Ctx::new();
    let checkpoints = finalized_checkpoints(&file, &policy(), &ctx);
    assert_eq!(checkpoints.len(), 2);
    // The left branch is only final as far as the shared base; the right one
    // is final at its own head.
    assert!(checkpoints.contains(&(left, Some(base))));
    assert!(checkpoints.contains(&(right, Some(right))));
    assert_eq!(
        latest_finalized_ancestor(&file, &left, &policy(), &ctx),
        Some(base)
    );
}

#[test]
fn a_finalization_survives_the_container_round_trip_and_older_versions_refuse_it() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let without = file.encode().unwrap();
    assert_eq!(without[4], 5, "no finalization keeps the older version");
    file.finalize_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    let bytes = file.encode().unwrap();
    assert_eq!(
        bytes[4], 6,
        "a finalization without event proofs is version 6"
    );
    let back = TrackedFile::decode(&bytes).unwrap();
    assert!(finalized(&back, &id, &Ctx::new()));
    // A container claiming to be version 5 cannot carry one.
    let mut old = bytes.clone();
    old[4] = 5;
    assert!(TrackedFile::decode(&old).is_err());
}

#[test]
fn current_and_trusted_views_are_derived_per_store_and_a_fork_has_no_current_head() {
    let mut file = TrackedFile::new(FILE, "report.txt");
    let base = revision_by(&mut file, vec![], "M.A", 2, &policy(), T1);
    file.sign_revision(&base, ident(2), "M.A", &secret(2))
        .unwrap();
    // M signs its own newer revision; M.A.1's descendant edit stays pending.
    let by_root = revision_by(&mut file, vec![base], "M", 1, &policy(), T2);
    file.sign_revision(&by_root, ident(1), "M", &secret(1))
        .unwrap();
    let full = Ctx::new();
    let mut no_root = Ctx::new();
    no_root.keys.retain(|(_, label)| *label != "M");
    // One head: it is current in every store; which revision is trusted
    // depends on the keys the store holds.
    assert_eq!(current_revision(&file), Some(by_root));
    assert_eq!(
        latest_trusted_revision(&file, &policy(), &full),
        Some(by_root)
    );
    assert_eq!(
        latest_trusted_revision(&file, &policy(), &no_root),
        Some(base)
    );
    // A fork has no current head, and nothing picks a winner for it.
    let side = revision_by(
        &mut file,
        vec![base],
        "M.A",
        2,
        &policy(),
        "2026-10-02T15:00:00Z",
    );
    file.sign_revision(&side, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(current_revision(&file), None);
    // The trusted view is still just the most recently stored trusted
    // revision, a display value: sharing picks from a head's own ancestry.
    assert_eq!(latest_trusted_revision(&file, &policy(), &full), Some(side));
    let decision = select_shareable_revision(&file, &by_root, None, &policy(), &no_root).unwrap();
    assert_eq!(decision.delivered_revision, Some(base));
    // Nothing about either view is stored: the bytes are the same for both.
    assert_eq!(TrackedFile::decode(&file.encode().unwrap()).unwrap(), file);
}

#[test]
fn a_store_without_the_finalizers_key_does_not_see_it_final() {
    let (mut file, id) = one("M.A", 2);
    file.sign_revision(&id, ident(2), "M.A", &secret(2))
        .unwrap();
    file.finalize_revision(&id, ident(1), "M", &secret(1))
        .unwrap();
    // This store trusts the revision (it knows M.A) but has no key for M:
    // the finalization is missing evidence here, not assumed.
    let mut here = Ctx::new();
    here.keys.retain(|(_, label)| *label != "M");
    assert_eq!(state(&file, &id, &here), Trusted);
    assert!(!finalized(&file, &id, &here));
    assert!(finalized(&file, &id, &Ctx::new()));
}

#[test]
fn two_stores_judge_the_same_competing_heads_by_their_own_keys() {
    let mut file = TrackedFile::new(FILE, "report.txt");
    let base = revision_by(&mut file, vec![], "M.A", 2, &policy(), T1);
    file.sign_revision(&base, ident(2), "M.A", &secret(2))
        .unwrap();
    let left = revision_by(&mut file, vec![base], "M.A", 2, &policy(), T2);
    let right = revision_by(
        &mut file,
        vec![base],
        "M.A",
        2,
        &policy(),
        "2026-10-02T15:00:00Z",
    );
    for id in [left, right] {
        file.sign_revision(&id, ident(2), "M.A", &secret(2))
            .unwrap();
    }
    // M finalizes the left head, M.A the right one.
    file.finalize_revision(&left, ident(1), "M", &secret(1))
        .unwrap();
    file.finalize_revision(&right, ident(2), "M.A", &secret(2))
        .unwrap();
    // The bytes travel unchanged; each store derives its own view.
    let copy = TrackedFile::decode(&file.encode().unwrap()).unwrap();
    let full = Ctx::new();
    let mut no_root = Ctx::new();
    no_root.keys.retain(|(_, label)| *label != "M");
    let a = finalized_checkpoints(&file, &policy(), &full);
    assert!(a.contains(&(left, Some(left))) && a.contains(&(right, Some(right))));
    let b = finalized_checkpoints(&copy, &policy(), &no_root);
    assert!(b.contains(&(left, None)), "{b:?}");
    assert!(b.contains(&(right, Some(right))), "{b:?}");
    // Neither store picks a winner: both heads stay.
    assert_eq!(b.len(), 2);
}

#[test]
fn an_unsigned_merge_of_two_finalized_heads_is_not_final() {
    let mut file = TrackedFile::new(FILE, "report.txt");
    let base = revision_by(&mut file, vec![], "M.A", 2, &policy(), T1);
    file.sign_revision(&base, ident(2), "M.A", &secret(2))
        .unwrap();
    let left = revision_by(&mut file, vec![base], "M.A", 2, &policy(), T2);
    let right = revision_by(
        &mut file,
        vec![base],
        "M.A",
        2,
        &policy(),
        "2026-10-02T15:00:00Z",
    );
    for id in [left, right] {
        file.sign_revision(&id, ident(2), "M.A", &secret(2))
            .unwrap();
        file.finalize_revision(&id, ident(2), "M.A", &secret(2))
            .unwrap();
    }
    let merge = revision_by(
        &mut file,
        vec![left, right],
        "M.A",
        2,
        &policy(),
        "2026-10-03T15:00:00Z",
    );
    let ctx = Ctx::new();
    // A merge carries no proofs of its own, so it starts untrusted and a
    // finalization proof on it does not count until it is signed.
    file.finalize_revision(&merge, ident(2), "M.A", &secret(2))
        .unwrap();
    assert_eq!(
        state(&file, &merge, &ctx),
        Pending(R::MissingContentSignature)
    );
    assert!(!finalized(&file, &merge, &ctx));
    // Its latest finalized ancestor is one of its finalized parents, never
    // the unsigned merge itself.
    let behind = latest_finalized_ancestor(&file, &merge, &policy(), &ctx);
    assert!(behind == Some(left) || behind == Some(right), "{behind:?}");
    file.sign_revision(&merge, ident(2), "M.A", &secret(2))
        .unwrap();
    assert!(finalized(&file, &merge, &ctx));
}
