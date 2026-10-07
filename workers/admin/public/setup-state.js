// What the first-time setup guide shows, decided from the overview alone and with
// no DOM, so a test can run it. The relay enforces every rule here itself (it
// refuses to create the lock, or to issue or seal anything, without an identity,
// and refuses to issue without the lock); this only says so before the operator
// tries, and in order.
//
// A step is `done`, `todo` (the operator's next action), `pending` (started, not
// finished), `waiting` (needs an earlier step first) or `offline` (happens off
// this page and cannot be seen from it).

export const STEP_IDS = ["root", "identity", "lock", "issue"];

export function setupSteps(overview) {
  const identity = overview.identity_configured === true;
  const lock = overview.operator_lock === true;
  const pending = overview.operator_lock_pending === true;
  return [
    // The offline root ceremony leaves no trace on the relay except its result,
    // a certificate the relay holds; so it reads as done only once step 2 is.
    { id: "root", status: identity ? "done" : "offline" },
    { id: "identity", status: identity ? "done" : "todo" },
    { id: "lock", status: lock ? "done" : !identity ? "waiting" : pending ? "pending" : "todo" },
    { id: "issue", status: identity && lock ? "todo" : "waiting" },
  ];
}

// Setup is complete when the relay can issue: it holds an identity and the lock.
export function setupComplete(overview) {
  return overview.identity_configured === true && overview.operator_lock === true;
}

// Why issuing is not possible yet, as a short sentence naming the missing step,
// or null when it is.
export function issuanceBlock(overview) {
  if (overview.identity_configured !== true) {
    return "The relay has no identity yet (step 2 on the Overview page), so it cannot seal keys.";
  }
  if (overview.operator_lock !== true) {
    return overview.operator_lock_pending === true
      ? "The operator lock was created but not confirmed (step 3 on the Overview page)."
      : "The operator lock has not been created (step 3 on the Overview page).";
  }
  return null;
}
