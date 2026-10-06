// A stand-in for a Durable Object's `ctx.storage` over Node's built-in SQLite
// (a real SQLite), so the relay core runs here the way it runs in a Durable
// Object: `sql.exec` returns a cursor with `raw()`, a transaction statement of
// the caller's own is refused, `transactionSync` commits or rolls back (and
// nests), blobs bind as ArrayBuffer and come back as ArrayBuffer.
import { DatabaseSync } from "node:sqlite";

const TRANSACTION_STATEMENT = /^\s*(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b/i;

export function createFakeStorage() {
  const db = new DatabaseSync(":memory:");
  let depth = 0;
  const sql = {
    exec(query, ...bindings) {
      // The real object refuses a transaction statement of the caller's own, by
      // what the statement is, not by the text: the END that closes a trigger
      // body is not one (checked on local workerd).
      const withoutTriggers = query.replace(/CREATE\s+TRIGGER[\s\S]*?\bEND\s*;/gi, "");
      for (const statement of withoutTriggers.split(";")) {
        if (TRANSACTION_STATEMENT.test(statement)) {
          throw new Error("To execute a transaction, please use the state.storage.transactionSync() API");
        }
      }
      const bound = bindings.map((value) => (value instanceof ArrayBuffer ? new Uint8Array(value) : value));
      if (bound.length === 0 && query.includes(";") && query.trim().replace(/;$/, "").includes(";")) {
        db.exec(query);
        return { raw: () => [][Symbol.iterator]() };
      }
      const statement = db.prepare(query);
      statement.setReturnArrays(true);
      const columns = statement.columns().length;
      if (columns === 0) {
        statement.run(...bound);
        return { raw: () => [][Symbol.iterator]() };
      }
      const rows = statement
        .all(...bound)
        .map((row) => row.map((cell) => (cell instanceof Uint8Array ? cell.slice().buffer : cell)));
      return { raw: () => rows[Symbol.iterator]() };
    },
  };
  return {
    sql,
    db,
    transactionSync(body) {
      if (depth > 0) return body();
      db.exec("BEGIN IMMEDIATE");
      depth = 1;
      try {
        const result = body();
        db.exec("COMMIT");
        return result;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      } finally {
        depth = 0;
      }
    },
  };
}
