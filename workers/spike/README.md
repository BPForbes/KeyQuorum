# Feasibility spike (issue #88, stage 3)

A throwaway probe. It is not part of the relay, is never deployed, and holds no
secrets; `scripts/guard.mjs` checks its configuration like the Worker's, so it
cannot gain a route, `workers.dev` or preview URLs, or a destructive migration.

It runs the relay's real `src/relay/schema.sql` and the SQL the relay's code
uses (transactions, `strftime('now')`, `PRAGMA table_info`, `ALTER TABLE`,
constraint errors, row and blob sizes, a 16 MiB inbox page, alarms) inside a
SQLite-backed Durable Object under local workerd, and prints what happened as
JSON.

```sh
cd workers
npx wrangler dev --local --port 8799 --config spike/wrangler.toml
curl http://127.0.0.1:8799/probe     # run the probes
curl http://127.0.0.1:8799/alarm     # a second later: did the alarm fire?
```

The measured results, what they prove and what they cannot, are in
`docs/operator/relay-hosting.md`, "What the spike measured". The main caveat:
local workerd does not enforce production's limits (it accepted a 4 MiB row),
so size and memory limits are not evidenced by this run.
