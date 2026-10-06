// The console's API, as a table: which path and method is which operation of
// the relay core (src/relay/operator.rs), which query parameters it takes, and
// whether it changes anything. Pure: no I/O, so every route is tested without a
// Worker. The Worker keeps out what is not in this table; the core decides
// everything else.
//
// Identifiers are in the path and are digits only. A query parameter not
// listed for a route is refused, never passed on. A request that changes
// anything is a POST with an `Idempotency-Key` (the operation id: see
// `relay::operator`), and the operator lock in `x-operator-lock`.

const ID = "(\\d{1,15})";
const NUMBER = /^\d{1,15}$/;

// name -> how to read a query parameter
const NUM = (value) => (NUMBER.test(value) ? Number(value) : undefined);
const WORD = (value) => (/^[a-z_]{1,32}$/.test(value) ? value : undefined);
const TEXT = (value) => (value.length <= 200 && !/[\u0000-\u001f]/.test(value) ? value : undefined);

const QUERY = {
  search: ["search", TEXT],
  status: ["status", WORD],
  before: ["before", NUM],
  limit: ["limit", NUM],
  hours: ["hours", NUM],
  key_id: ["key_id", NUM],
  route: ["route", WORD],
  outcome: ["outcome", WORD],
  state: ["state", WORD],
  assignment: ["assignment", WORD],
  feed: ["feed", WORD],
};

// Each route: method, pattern, then either { op, query: [...] } for a read, or
// { op, change: true } for a change, with `path` naming the path ids it sets in
// the request (in the order the pattern captures them).
export const ROUTES = [
  // Reads.
  ["GET", "/api/overview", { op: "overview" }],
  ["GET", "/api/users", { op: "users", query: ["search", "status", "before", "limit"] }],
  ["GET", `/api/users/${ID}`, { op: "user", path: ["id"] }],
  ["GET", `/api/users/${ID}/licenses`, { op: "user", path: ["id"], pick: "licences" }],
  ["GET", `/api/users/${ID}/keys`, { op: "keys", path: ["customer_id"], query: ["state", "before", "limit"] }],
  ["GET", `/api/users/${ID}/activity`, { op: "activity", path: ["customer_id"], query: ["hours", "key_id", "route", "outcome"] }],
  ["GET", "/api/keys", { op: "keys", query: ["state", "assignment", "before", "limit"] }],
  ["GET", "/api/activity", { op: "activity", query: ["hours", "key_id", "route", "outcome"] }],
  ["GET", "/api/audit", { op: "audit", query: ["feed", "before", "limit"] }],
  ["GET", "/api/letters", { op: "letters" }],
  ["GET", "/api/trees", { op: "trees" }],
  ["GET", "/api/status", { op: "status", runtime: true }],
  // The signed checkpoint is produced on request, so it is a POST, but it
  // changes nothing in the relay and needs no lock.
  ["POST", "/api/checkpoints", { op: "checkpoint" }],
  // Changes.
  ["POST", "/api/users", { op: "create_customer", change: true }],
  ["POST", `/api/users/${ID}/licenses`, { op: "create_licence", change: true, path: ["customer_id"] }],
  ["POST", `/api/users/${ID}/keys`, { op: "issue", change: true, path: ["customer_id"] }],
  ["POST", `/api/licenses/${ID}/renew`, { op: "renew_licence", change: true, path: ["licence_id"] }],
  ["POST", `/api/licenses/${ID}/revoke`, { op: "void_licence", change: true, path: ["licence_id"] }],
  ["POST", `/api/keys/${ID}/rotate`, { op: "rotate", change: true, path: ["key_id"] }],
  ["POST", `/api/keys/${ID}/revoke`, { op: "void_key", change: true, path: ["key_id"] }],
  ["POST", `/api/keys/${ID}/assign`, { op: "assign_key", change: true, path: ["key_id"] }],
  // The operator lock's ceremony: staged, shown once, then confirmed.
  ["POST", "/api/operator-lock/bootstrap", { op: "bootstrap", lock: true }],
  ["POST", "/api/operator-lock/replace", { op: "rotate_lock", lock: true }],
  ["POST", "/api/operator-lock/confirm", { op: "confirm_lock", lock: true }],
];

const COMPILED = ROUTES.map(([method, pattern, spec]) => [method, new RegExp(`^${pattern}$`), spec]);

// -> { ok: true, op, spec, fields } | { ok: false, status, error, allow? }
// `fields` carries the path ids and query values, ready to merge into the
// request. A body, where the route takes one, is the caller's.
export function matchRoute(method, pathname, searchParams) {
  const methods = new Set();
  for (const [routeMethod, pattern, spec] of COMPILED) {
    const match = pattern.exec(pathname);
    if (!match) continue;
    if (routeMethod !== method) {
      methods.add(routeMethod);
      continue;
    }
    const fields = {};
    (spec.path ?? []).forEach((name, index) => {
      fields[name] = Number(match[index + 1]);
    });
    const allowed = new Set(spec.query ?? []);
    for (const [name, value] of searchParams) {
      const reader = QUERY[name];
      if (!allowed.has(name) || reader === undefined) {
        return { ok: false, status: 400, error: `the query parameter ${JSON.stringify(name).slice(0, 40)} is not accepted here` };
      }
      const read = reader[1](value);
      if (read === undefined) return { ok: false, status: 400, error: `the query parameter ${name} is not valid` };
      if (name in fields) return { ok: false, status: 400, error: `the query parameter ${name} is given twice` };
      fields[reader[0]] = read;
    }
    return { ok: true, op: spec.op, spec, fields };
  }
  if (methods.size > 0) {
    return { ok: false, status: 405, error: "method not allowed", allow: [...methods].sort().join(", ") };
  }
  return { ok: false, status: 404, error: "not found" };
}

// The operations the core answers, as the routes name them. The Worker's own
// test reads the core's request enum and checks this set is exactly it.
export const OPERATIONS = new Set(ROUTES.map(([, , spec]) => spec.op));

