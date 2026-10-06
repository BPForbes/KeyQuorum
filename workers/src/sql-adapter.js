// The adapter the relay core (relay-wasm, `RelayCore`) runs its SQL through:
// a Durable Object's `ctx.storage`. It carries no relay rule. The core asks
// for a cursor per query and for a transaction per unit of work, because a
// Durable Object refuses BEGIN: a unit of work is `transactionSync`, rolled
// back by throwing.
const ROLLBACK = Symbol("rollback");

export function createSqlAdapter(storage) {
  return {
    // Returns a cursor: `next()` gives one row (an array of cells), then
    // `undefined`. A statement that returns no rows is run when it is called.
    query(sql, params) {
      const rows = storage.sql.exec(sql, ...params).raw()[Symbol.iterator]();
      return {
        next() {
          const step = rows.next();
          return step.done ? undefined : step.value;
        },
      };
    },
    // Runs `body` inside one transaction. `body` returns whether to commit;
    // false rolls everything it wrote back. Returns whether it committed.
    transaction(body) {
      try {
        storage.transactionSync(() => {
          if (!body()) throw ROLLBACK;
        });
        return true;
      } catch (error) {
        if (error === ROLLBACK) return false;
        throw error;
      }
    },
  };
}
