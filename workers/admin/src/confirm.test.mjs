// The change helpers of the console page (admin/public/confirm.js and api.js
// error types): an operation id is kept while a change's outcome is unknown and
// renewed once the relay has answered, and a change that was already made is
// told in words, never repeated.
import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, NetworkError } from "../public/api.js";
import { describeChange, operation } from "../public/confirm.js";

const OPERATION = /^[0-9a-f-]{36}$/;

test("an operation id is a fresh id, and is kept while the outcome is unknown", () => {
  const op = operation();
  assert.match(op.id, OPERATION);
  const first = op.id;
  // No answer at all, or an error that does not say it was refused: the change
  // may have been made, so the next try repeats the id and is told if it was.
  op.settle(new NetworkError());
  assert.equal(op.id, first);
  op.settle(new ApiError(503, { error: "relay unavailable" }));
  assert.equal(op.id, first);
  op.settle(new ApiError(500, { code: "commit_unknown", error: "x" }));
  assert.equal(op.id, first);
});

test("an operation id is renewed once the relay has answered, either way", () => {
  const op = operation();
  const first = op.id;
  op.settle(new ApiError(409, { code: "conflict", error: "x" }));
  const second = op.id;
  assert.notEqual(second, first);
  assert.match(second, OPERATION);
  op.settle(null);
  assert.notEqual(op.id, second);
  const third = op.id;
  op.settle(new ApiError(401, { code: "lock_refused", error: "x" }));
  assert.notEqual(op.id, third);
  assert.notEqual(operation().id, operation().id);
});

test("a change that was already made is told with what it made, and that it was not repeated", () => {
  const error = new ApiError(409, {
    code: "already_done",
    error: "this operation was already done",
    operation: {
      operation_id: "op-0123456789",
      occurred_at: "2026-10-06T12:00:00.000Z",
      result: { customer_id: 4, licence_id: 7, key_ids: [11, 12], voided_licence_id: null },
    },
  });
  const text = describeChange(error);
  assert.match(text, /Already done at 2026-10-06T12:00:00.000Z/);
  assert.match(text, /customer id: 4/);
  assert.match(text, /key ids: 11, 12/);
  assert.doesNotMatch(text, /voided/, "an empty id is left out");
  assert.match(text, /not repeated/);
  assert.match(text, /Sealed files are not kept/);
  assert.equal(error.unknownOutcome, false, "the relay answered: the id may be renewed");
});

test("every other failure is told in the words the console has for it", () => {
  assert.match(describeChange(new NetworkError()), /may have been made/);
  assert.match(describeChange(new ApiError(401, { code: "lock_refused", error: "x" })), /refused.*recorded/);
  assert.match(describeChange(new ApiError(409, { code: "no_lock", error: "x" })), /Overview/);
  assert.match(describeChange(new ApiError(400, { error: "licence is malformed" })), /licence is malformed/);
  assert.match(describeChange(new TypeError("boom")), /Reload the page/);
  assert.ok(!describeChange(new TypeError("secret detail")).includes("secret detail"));
});
