import test from "node:test";
import assert from "node:assert/strict";
import { createSqlAdapter } from "../src/sql-adapter.js";
import { createFakeStorage } from "./fake-storage.mjs";

function open() {
  const storage = createFakeStorage();
  storage.sql.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)");
  return { storage, adapter: createSqlAdapter(storage) };
}

const count = (storage) => storage.db.prepare("SELECT COUNT(*) AS n FROM t").get().n;

test("a transaction whose body returns true commits what it wrote", () => {
  const { storage, adapter } = open();
  const committed = adapter.transaction(() => {
    adapter.query("INSERT INTO t (n) VALUES (?)", [1]);
    return true;
  });
  assert.equal(committed, true);
  assert.equal(count(storage), 1);
});

test("a transaction whose body returns false rolls back what it wrote and says so", () => {
  const { storage, adapter } = open();
  const committed = adapter.transaction(() => {
    adapter.query("INSERT INTO t (n) VALUES (?)", [1]);
    adapter.query("INSERT INTO t (n) VALUES (?)", [2]);
    return false;
  });
  assert.equal(committed, false);
  assert.equal(count(storage), 0);
});

test("an error from the body or the statements is rethrown after a rollback", () => {
  const { storage, adapter } = open();
  assert.throws(() =>
    adapter.transaction(() => {
      adapter.query("INSERT INTO t (n) VALUES (?)", [1]);
      adapter.query("INSERT INTO missing (n) VALUES (?)", [2]);
      return true;
    }),
  );
  assert.equal(count(storage), 0);
});

test("a transaction statement of the caller's own is refused, as a Durable Object refuses it", () => {
  const { adapter } = open();
  for (const statement of ["BEGIN IMMEDIATE", "COMMIT", "SAVEPOINT x"]) {
    assert.throws(() => adapter.query(statement, []), /transactionSync/, statement);
  }
});

test("a cursor yields one row at a time and then undefined", () => {
  const { adapter } = open();
  for (const n of [1, 2, 3]) adapter.query("INSERT INTO t (n) VALUES (?)", [n]);
  const cursor = adapter.query("SELECT n FROM t ORDER BY id", []);
  assert.deepEqual([cursor.next(), cursor.next(), cursor.next()], [[1], [2], [3]]);
  assert.equal(cursor.next(), undefined);
});
