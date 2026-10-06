// Throwaway probe, never deployed. Each probe records what a SQLite-backed
// Durable Object did, as JSON, so the hosting decision rests on measurements.
import { DurableObject } from "cloudflare:workers";
import SCHEMA from "../../../src/relay/schema.sql";

const MIB = 1024 * 1024;

function attempt(fn) {
  try {
    const value = fn();
    return { ok: true, value: value === undefined ? null : value };
  } catch (error) {
    return { ok: false, error: String(error?.message ?? error).slice(0, 240) };
  }
}

export class SpikeDO extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
  }

  async alarm() {
    this.ctx.storage.kv.put("alarm_fired_at", Date.now());
  }

  async probe() {
    const sql = this.sql;
    const out = {};

    // The relay's real schema, as one multi-statement exec.
    out.schema_exec = attempt(() => {
      sql.exec(SCHEMA);
      return sql
        .exec("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .toArray()
        .map((row) => row.name);
    });
    out.pragma_foreign_keys_on = attempt(() => {
      sql.exec("PRAGMA foreign_keys = ON");
      return sql.exec("PRAGMA foreign_keys").toArray();
    });

    // Transactions: the relay's SQLite store issues BEGIN IMMEDIATE.
    out.explicit_begin = attempt(() => sql.exec("BEGIN IMMEDIATE"));
    out.transaction_sync_commit = attempt(() =>
      this.ctx.storage.transactionSync(() => {
        sql.exec("INSERT INTO api_keys (key_hash, scope) VALUES ('probe-commit', 'admin')");
        return "returned";
      }),
    );
    out.transaction_sync_rolls_back_on_throw = attempt(() => {
      const before = sql.exec("SELECT COUNT(*) AS n FROM api_keys").one().n;
      try {
        this.ctx.storage.transactionSync(() => {
          sql.exec("INSERT INTO api_keys (key_hash, scope) VALUES ('probe-rollback', 'admin')");
          throw new Error("abort");
        });
      } catch {}
      const after = sql.exec("SELECT COUNT(*) AS n FROM api_keys").one().n;
      return { before, after };
    });
    out.transaction_sync_nested = attempt(() =>
      this.ctx.storage.transactionSync(() =>
        this.ctx.storage.transactionSync(() => "inner"),
      ),
    );

    // Time: the relay's SQL uses strftime('now') and a column default of it.
    out.strftime_now = attempt(() => {
      const row = sql
        .exec("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now') AS t, datetime('now') AS d")
        .one();
      return { ...row, js: new Date().toISOString() };
    });
    out.column_default_uses_now = attempt(
      () => sql.exec("SELECT created_at FROM api_keys WHERE key_hash='probe-commit'").one().created_at,
    );

    // The relay's migrations.
    out.pragma_table_info = attempt(() =>
      sql.exec("PRAGMA table_info(mailbox)").toArray().map((row) => row.name),
    );
    out.alter_add_column = attempt(() => {
      sql.exec("CREATE TABLE IF NOT EXISTS spike_alter (id INTEGER PRIMARY KEY)");
      sql.exec("ALTER TABLE spike_alter ADD COLUMN extra TEXT");
      return sql.exec("PRAGMA table_info(spike_alter)").toArray().map((row) => row.name);
    });
    out.alter_rename_and_drop = attempt(() => {
      sql.exec("CREATE TABLE spike_old (id INTEGER PRIMARY KEY)");
      sql.exec("ALTER TABLE spike_old RENAME TO spike_new");
      sql.exec("DROP TABLE spike_new");
      return "renamed and dropped";
    });

    // Row ids, change counts and constraint errors.
    out.last_insert_rowid_and_changes = attempt(() => {
      const cursor = sql.exec(
        "INSERT INTO api_keys (key_hash, scope) VALUES ('probe-rowid', 'admin') RETURNING id",
      );
      const returned = cursor.one().id;
      const rowid = sql.exec("SELECT last_insert_rowid() AS id").one().id;
      const changes = sql.exec("SELECT changes() AS n").one().n;
      return { returned, rowid, changes };
    });
    out.unique_violation = attempt(() =>
      sql.exec("INSERT INTO api_keys (key_hash, scope) VALUES ('probe-rowid', 'admin')"),
    );
    out.check_violation = attempt(() =>
      sql.exec("INSERT INTO api_keys (key_hash, scope) VALUES ('probe-check', 'not-a-scope')"),
    );

    // Billing signal: rows written by an authenticated request's last_used_at stamp.
    out.rows_written_by_last_used_stamp = attempt(() => {
      const cursor = sql.exec(
        "UPDATE api_keys SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE key_hash='probe-commit'",
      );
      cursor.toArray();
      return { rowsRead: cursor.rowsRead, rowsWritten: cursor.rowsWritten };
    });

    // Row size limits: a letter is at most 1 MiB; a public tree document is unbounded.
    sql.exec("CREATE TABLE IF NOT EXISTS spike_blob (id INTEGER PRIMARY KEY, b BLOB, t TEXT)");
    out.blob_sizes = {};
    for (const size of [1 * MIB, 2 * MIB - 4096, 2 * MIB, 2 * MIB + 1, 4 * MIB]) {
      out.blob_sizes[size] = attempt(() => {
        sql.exec("INSERT INTO spike_blob (b) VALUES (?)", new Uint8Array(size));
        return "inserted";
      });
    }
    out.text_sizes = {};
    for (const size of [1 * MIB, 2 * MIB, 2 * MIB + 1]) {
      out.text_sizes[size] = attempt(() => {
        sql.exec("INSERT INTO spike_blob (t) VALUES (?)", "x".repeat(size));
        return "inserted";
      });
    }

    // A full inbox page: 16 letters of 1 MiB read and encoded as the relay would.
    out.sixteen_mib_page = attempt(() => {
      sql.exec("DELETE FROM spike_blob");
      for (let i = 0; i < 16; i += 1) {
        sql.exec("INSERT INTO spike_blob (b) VALUES (?)", new Uint8Array(MIB).fill(i));
      }
      const started = performance.now();
      const letters = [];
      for (const row of sql.exec("SELECT b FROM spike_blob ORDER BY id")) {
        const bytes = new Uint8Array(row.b);
        let binary = "";
        for (let i = 0; i < bytes.length; i += 0x8000) {
          binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        }
        letters.push(btoa(binary));
      }
      const body = JSON.stringify({ letters });
      return { letters: letters.length, bodyBytes: body.length, ms: Math.round(performance.now() - started) };
    });
    out.database_size_bytes = attempt(() => sql.databaseSize);

    // Randomness and scheduling primitives the relay needs.
    out.get_random_values = attempt(() => crypto.getRandomValues(new Uint8Array(32)).length);
    try {
      await this.ctx.storage.setAlarm(Date.now() + 300);
      out.set_alarm = { ok: true, value: "scheduled" };
    } catch (error) {
      out.set_alarm = { ok: false, error: String(error?.message ?? error).slice(0, 240) };
    }
    return out;
  }

  async alarmState() {
    return { fired_at: this.ctx.storage.kv.get("alarm_fired_at") ?? null };
  }
}

export default {
  async fetch(request, env) {
    const stub = env.SPIKE.get(env.SPIKE.idFromName("spike"));
    const { pathname } = new URL(request.url);
    if (pathname === "/probe") return Response.json(await stub.probe());
    if (pathname === "/alarm") return Response.json(await stub.alarmState());
    return new Response("spike", { status: 404 });
  },
};
