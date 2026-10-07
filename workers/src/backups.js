// Sealed backups of the relay's database, written to an R2 bucket (`BACKUPS`)
// by the Durable Object's alarm (docs/operator/r2-backups.md).
//
// The relay core builds the whole snapshot in one synchronous turn, sealed to
// the operator's backup key and signed by the relay (src/relay/backup.rs), so
// what is uploaded here is opaque to this object, to R2 and to Cloudflare. This
// module decides only when, where and how many: it uploads the chunks, the
// manifest last (a backup without a manifest is incomplete and is never trusted
// or counted), keeps the newest few, and reports what happened. Nothing in it
// reads a backup.
//
// The snapshot lives in memory while it is uploaded, so there is a ceiling
// (BACKUP_MAX_BYTES, default 16 MiB of plaintext): past it the core refuses and
// this records "too large" rather than risk the object's 128 MB. The platform's
// 30-day point-in-time recovery of the object's storage is the other, larger
// safety net and does not depend on this.

export const DEFAULT_EVERY_HOURS = 24;
export const DEFAULT_KEEP = 14;
export const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
export const MAX_MAX_BYTES = 32 * 1024 * 1024;
export const PREFIX = "backups/";
export const MANIFEST = "manifest.kqbk";
// An unfinished backup (no manifest) is removed after this long.
const STALE_MS = 24 * 60 * 60 * 1000;

const within = (text, low, high, fallback) => {
  const raw = typeof text === "string" ? text.trim() : "";
  if (!/^\d{1,9}$/.test(raw)) return fallback;
  return Math.min(Math.max(Number(raw), low), high);
};

// Backups run only with a bound bucket and a valid backup public key (64 hex
// characters). Anything else is off, and says why.
export function backupSettings(env) {
  const recipient = typeof env.BACKUP_RECIPIENT === "string" ? env.BACKUP_RECIPIENT.trim() : "";
  const base = {
    everyHours: within(env.BACKUP_EVERY_HOURS, 1, 720, DEFAULT_EVERY_HOURS),
    keep: within(env.BACKUP_KEEP, 1, 365, DEFAULT_KEEP),
    maxBytes: within(env.BACKUP_MAX_BYTES, 1024 * 1024, MAX_MAX_BYTES, DEFAULT_MAX_BYTES),
  };
  if (recipient === "") return { ...base, enabled: false, reason: "no backup key set (BACKUP_RECIPIENT)" };
  if (!/^[0-9a-fA-F]{64}$/.test(recipient)) return { ...base, enabled: false, reason: "BACKUP_RECIPIENT is not a 64-character hex public key" };
  return { ...base, enabled: true, recipient: recipient.toLowerCase(), reason: null };
}

export function backupBucketOf(env) {
  const bucket = env.BACKUPS;
  const usable = bucket && ["put", "get", "delete", "list"].every((name) => typeof bucket[name] === "function");
  return usable ? bucket : null;
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// The time an id was taken: its leading `YYYYMMDDHHMMSSmmm`, as milliseconds.
function takenAt(id) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{3})-/.exec(id);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], +m[7]) : null;
}

export function createBackups({ core, bucket, storage, settings, relayTime, clock = () => new Date(), log = console }) {
  const state = { lastSkipped: null, lastFailure: null, lastPruneFailure: null, running: false };

  async function listAll(options) {
    const out = { objects: [], prefixes: [] };
    let cursor;
    do {
      const page = await bucket.list({ ...options, cursor });
      out.objects.push(...(page.objects ?? []));
      out.prefixes.push(...(page.delimitedPrefixes ?? []));
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor);
    return out;
  }

  // Whether the last backup that finished is old enough that another is due.
  async function due() {
    const last = await storage.get("backup:last");
    return !last || clock().getTime() - last.at >= settings.everyHours * 3600 * 1000;
  }

  // Keeps the newest `keep` complete backups and removes the rest, and any
  // unfinished one past a day old. A failure here never fails the backup.
  async function prune(currentId) {
    try {
      const { prefixes } = await listAll({ prefix: PREFIX, delimiter: "/" });
      const found = [];
      for (const prefix of prefixes) {
        const { objects } = await listAll({ prefix });
        const id = prefix.slice(PREFIX.length).replace(/\/$/, "");
        found.push({ id, keys: objects.map((o) => o.key), complete: objects.some((o) => o.key === `${prefix}${MANIFEST}`) });
      }
      found.sort((a, b) => (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
      let kept = 0;
      for (const backup of found) {
        let drop = false;
        if (backup.complete) {
          kept += 1;
          drop = kept > settings.keep;
        } else if (backup.id !== currentId) {
          const at = takenAt(backup.id);
          drop = at === null || clock().getTime() - at > STALE_MS;
        }
        if (drop) {
          for (let i = 0; i < backup.keys.length; i += 1000) await bucket.delete(backup.keys.slice(i, i + 1000));
        }
      }
      state.lastPruneFailure = null;
    } catch (error) {
      state.lastPruneFailure = error?.name ?? "Error";
      log.error("relay: old backups could not be pruned", error?.name);
    }
  }

  // Takes one backup. -> { id } when stored, { skipped } when the database is
  // too large for one pass; throws when the bucket or the core failed, with the
  // earlier backups untouched (the manifest, written last, is what makes a
  // backup count).
  async function run() {
    if (state.running) return { skipped: "already running" };
    state.running = true;
    try {
      let plan;
      try {
        plan = JSON.parse(core.backup_begin(settings.recipient, relayTime(clock()), settings.maxBytes));
      } catch (error) {
        if (/too large/i.test(String(error?.message))) {
          state.lastSkipped = "the database is too large to back up in one pass";
          log.error("relay: a backup was skipped, the database is too large");
          return { skipped: "too_large" };
        }
        throw error;
      }
      try {
        const base = `${PREFIX}${plan.id}/`;
        for (let i = 0; i < plan.objects.length; i += 1) {
          const bytes = core.backup_object(i);
          await bucket.put(`${base}${plan.objects[i].name}`, bytes, { sha256: await sha256Hex(bytes) });
        }
        const manifest = core.backup_manifest();
        await bucket.put(`${base}${plan.manifest.name}`, manifest, { sha256: await sha256Hex(manifest) });
      } finally {
        core.backup_end();
      }
      await storage.put("backup:last", { at: clock().getTime(), id: plan.id, tables: plan.tables, rows: plan.rows, objects: plan.objects.length + 1 });
      state.lastSkipped = null;
      state.lastFailure = null;
      await prune(plan.id);
      return { id: plan.id };
    } catch (error) {
      state.lastFailure = error?.name ?? "Error";
      throw error;
    } finally {
      state.running = false;
    }
  }

  async function status() {
    const last = (await storage.get("backup:last")) ?? null;
    return {
      enabled: true,
      every_hours: settings.everyHours,
      keep: settings.keep,
      max_bytes: settings.maxBytes,
      last: last && { at: new Date(last.at).toISOString(), id: last.id, tables: last.tables, rows: last.rows, objects: last.objects },
      last_skipped: state.lastSkipped,
      last_failure: state.lastFailure,
      last_prune_failure: state.lastPruneFailure,
    };
  }

  return { due, run, status };
}
