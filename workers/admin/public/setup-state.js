// What the first-time setup guide shows, decided from the overview alone and with
// no DOM, so a test can run it. The relay enforces its own rules (it refuses to
// create the lock, or to issue or seal anything, without an identity, and refuses
// to issue without the lock); this says so before the operator tries, and in
// order. What the relay reports about its identity is a check, not a count of
// secrets: `identity_check.state` is `trusted` only when the certificate is
// signed by the root the relay pins, has not expired, grants the provider
// capabilities and names the key the relay holds, which is what an official
// client checks. Anything else, an absent field included, is not trusted.
//
// A step is `done`, `todo` (the operator's next action), `pending` (started, not
// finished), `waiting` (needs an earlier step first), `failed` (done, but the
// relay says it is wrong) or `offline` (happens off this page and cannot be seen
// from it).

export const STEP_IDS = ["root", "identity", "lock", "issue"];

// Why an identity that is present is not trusted, in words for the operator.
export const UNTRUSTED_REASONS = {
  certificate_not_signed_by_pinned_root:
    "The certificate is not signed by the root this relay pins, or it is not a certificate. Check the pinned root shown in step 1 against your ceremony's public key, and that the certificate was issued under that root.",
  certificate_expired: "The certificate has expired. Have a new one issued offline and install it.",
  capabilities_missing: "The certificate does not grant the provider capabilities a relay needs. Have it re-issued.",
  key_does_not_match_certificate:
    "The relay key does not match the certificate: they are from different key pairs. Set the relay key and the certificate that were made together.",
};

export function identityState(overview) {
  const state = overview.identity_check?.state;
  if (state === "trusted") return "trusted";
  if (state === "untrusted") return "untrusted";
  return overview.identity_configured === true ? "unverified" : "missing";
}

export function untrustedReason(overview) {
  const reason = overview.identity_check?.reason;
  return UNTRUSTED_REASONS[reason] ?? "The relay could not confirm its identity is one clients will trust.";
}

export function setupSteps(overview) {
  const identity = identityState(overview);
  const trusted = identity === "trusted";
  const lock = overview.operator_lock === true;
  const pending = overview.operator_lock_pending === true;
  const reason = overview.identity_check?.reason;
  // A key that does not match proves the certificate itself verified, so the
  // fault is in what was installed (step 2); any other failure is in the
  // certificate or the pinned root (step 1).
  const keyFault = reason === "key_does_not_match_certificate";
  const certificateFault = identity === "untrusted" && !keyFault;
  return [
    // The offline ceremony leaves no trace on the relay except its result, a
    // certificate the relay holds, so it reads as done only once that result is
    // trusted, and as failed when the relay says the result is wrong.
    { id: "root", status: trusted || keyFault ? "done" : certificateFault ? "failed" : "offline" },
    { id: "identity", status: trusted ? "done" : keyFault ? "failed" : identity === "missing" ? "todo" : "waiting" },
    { id: "lock", status: lock ? "done" : !trusted ? "waiting" : pending ? "pending" : "todo" },
    { id: "issue", status: trusted && lock ? "todo" : "waiting" },
  ];
}

// Setup is complete when the relay can issue: it holds a trusted identity and the lock.
export function setupComplete(overview) {
  return identityState(overview) === "trusted" && overview.operator_lock === true;
}

// Why issuing is not possible yet, as a short sentence naming the missing step,
// or null when it is.
export function issuanceBlock(overview) {
  const identity = identityState(overview);
  if (identity === "missing") {
    return "The relay has no identity yet (step 2 on the Overview page), so it cannot seal keys.";
  }
  if (identity !== "trusted") {
    return `The relay's identity is not one clients will trust (see the Overview page). ${identity === "untrusted" ? untrustedReason(overview) : "It has not been checked."}`;
  }
  if (overview.operator_lock !== true) {
    return overview.operator_lock_pending === true
      ? "The operator lock was created but not confirmed (step 3 on the Overview page)."
      : "The operator lock has not been created (step 3 on the Overview page).";
  }
  return null;
}
