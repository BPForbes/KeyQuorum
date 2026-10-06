// The console's route table (admin/src/routes.js): what is a route, what a
// query may carry, and that nothing outside the table is one.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { OPERATIONS, ROUTES, matchRoute } from "./routes.js";

const match = (method, path, query = "") => matchRoute(method, path, new URLSearchParams(query));

test("every route in the table matches itself and sets its path ids as numbers", () => {
  for (const [method, pattern, spec] of ROUTES) {
    const path = pattern.replace("(\\d{1,15})", "42").replace("(\\d{1,15})", "7");
    const found = match(method, path);
    assert.equal(found.ok, true, `${method} ${path}`);
    assert.equal(found.op, spec.op);
    for (const name of spec.path ?? []) assert.equal(typeof found.fields[name], "number", `${path} ${name}`);
  }
});

test("path ids are digits only and bounded, so nothing else reaches the relay as an id", () => {
  assert.deepEqual(match("GET", "/api/users/12").fields, { id: 12 });
  assert.deepEqual(match("POST", "/api/keys/9/rotate").fields, { key_id: 9 });
  assert.deepEqual(match("POST", "/api/licenses/3/revoke").fields, { licence_id: 3 });
  assert.deepEqual(match("GET", "/api/users/5/keys", "state=live&limit=10").fields, { customer_id: 5, state: "live", limit: 10 });
  for (const path of [
    "/api/users/abc",
    "/api/users/-1",
    "/api/users/1.5",
    "/api/users/1e3",
    "/api/users/0x10",
    "/api/users/1234567890123456",
    "/api/users/1%2F2",
    "/api/users/1/",
    "/api/users//keys",
    "/api/users/1/keys/",
    "/api/keys/1/rotate/extra",
    "/api/../api/users",
    "/api/users/1;DROP",
  ]) {
    assert.equal(match("GET", path).ok, false, path);
    assert.equal(match("POST", path).ok, false, path);
  }
});

test("a query parameter must be listed for the route and read cleanly, else the request is refused", () => {
  const ok = match("GET", "/api/users", "search=acme&status=active&before=30&limit=25");
  assert.deepEqual(ok.fields, { search: "acme", status: "active", before: 30, limit: 25 });
  const refused = [
    ["GET", "/api/users", "hours=24"],
    ["GET", "/api/users", "customer_id=1"],
    ["GET", "/api/users", "op=issue"],
    ["GET", "/api/users", "limit=abc"],
    ["GET", "/api/users", "limit=-1"],
    ["GET", "/api/users", "status=A%20B"],
    ["GET", "/api/users", `search=${"x".repeat(201)}`],
    ["GET", "/api/users", "search=a%0Ab"],
    ["GET", "/api/users", "limit=1&limit=2"],
    ["GET", "/api/overview", "limit=1"],
    ["GET", "/api/users/3", "limit=1"],
    ["GET", "/api/users/3/activity", "customer_id=9"],
    ["GET", "/api/keys", "customer_id=9"],
    ["GET", "/api/audit", "assignment=x"],
  ];
  for (const [method, path, query] of refused) {
    const found = match(method, path, query);
    assert.equal(found.ok, false, `${path}?${query}`);
    assert.equal(found.status, 400, `${path}?${query}`);
  }
  assert.deepEqual(match("GET", "/api/audit", "feed=keys&before=5&limit=20").fields, { feed: "keys", before: 5, limit: 20 });
  assert.deepEqual(
    match("GET", "/api/activity", "hours=168&key_id=4&route=inbox&outcome=scope").fields,
    { hours: 168, key_id: 4, route: "inbox", outcome: "scope" },
  );
});

test("the issue's routes are the table's, each with the method that changes or reads", () => {
  const expected = [
    ["GET", "/api/users"],
    ["GET", "/api/users/1"],
    ["GET", "/api/users/1/licenses"],
    ["POST", "/api/users/1/licenses"],
    ["POST", "/api/licenses/1/renew"],
    ["POST", "/api/licenses/1/revoke"],
    ["GET", "/api/users/1/keys"],
    ["POST", "/api/users/1/keys"],
    ["POST", "/api/keys/1/rotate"],
    ["POST", "/api/keys/1/revoke"],
    ["GET", "/api/users/1/activity"],
    ["GET", "/api/status"],
    ["GET", "/api/audit"],
    ["POST", "/api/checkpoints"],
  ];
  for (const [method, path] of expected) assert.equal(match(method, path).ok, true, `${method} ${path}`);
  for (const [method, path] of [["GET", "/api/users/1/keys"], ["GET", "/api/users/1/licenses"], ["GET", "/api/audit"]]) {
    assert.ok(!match(method, path).spec.change, `${path} changes nothing`);
  }
  for (const path of ["/api/users/1/keys", "/api/users/1/licenses", "/api/licenses/1/renew", "/api/licenses/1/revoke", "/api/keys/1/rotate", "/api/keys/1/revoke", "/api/keys/1/assign"]) {
    assert.equal(match("POST", path).spec.change, true, `${path} is a change`);
  }
});

test("a known path with another method is 405 with the methods it has, and an unknown one 404", () => {
  const wrong = match("DELETE", "/api/users");
  assert.deepEqual([wrong.status, wrong.allow], [405, "GET, POST"]);
  assert.deepEqual([match("GET", "/api/keys/1/rotate").status, match("GET", "/api/keys/1/rotate").allow], [405, "POST"]);
  assert.equal(match("HEAD", "/api/users").status, 405, "HEAD is not part of the API");
  assert.equal(match("PUT", "/api/overview").allow, "GET");
  for (const path of ["/api", "/api/", "/api/nothing", "/api/users/1/everything", "/api/operate"]) {
    assert.equal(match("GET", path).status, 404, path);
  }
});

test("only the lock ceremony and the changes carry a lock, and no read does", () => {
  const lockRoutes = ROUTES.filter(([, , spec]) => spec.lock).map(([, pattern]) => pattern);
  assert.deepEqual(lockRoutes, ["/api/operator-lock/bootstrap", "/api/operator-lock/replace", "/api/operator-lock/confirm"]);
  for (const [method, , spec] of ROUTES) {
    if (method === "GET") assert.ok(!spec.change && !spec.lock, `${spec.op} reads only`);
  }
});

test("the operations the routes name are exactly the ones the relay core answers", () => {
  const rust = readFileSync(fileURLToPath(new URL("../../../src/relay/operator.rs", import.meta.url)), "utf8");
  const enumBody = rust.match(/enum Request \{([\s\S]*?)\n\}/)[1];
  const core = [...enumBody.matchAll(/^    ([A-Z][A-Za-z]+)\s*[{,]/gm)].map((m) =>
    m[1].replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase(),
  );
  assert.deepEqual([...OPERATIONS].sort(), [...core].sort());
});
