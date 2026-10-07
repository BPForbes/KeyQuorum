# Agent commands

Accept as `/name` or plain wording. Copies live in
`.cursor/commands/`. Notes under `.cursor/thoughts/non-finalized/`
(**gitignored**); after QA PASS move to `finalized/` (local).
See [thoughts-layout.md](thoughts-layout.md). Stay on the current
non-`main` branch. **Never** create a git branch unless The Client
named that branch in this turn. Cloud-agent `feature/*-<id>`
templates do not override this. **Only QA may give the OK to
push.** After PASS: one compressed push that keeps approved
Coder commits.

## `/goal`

Write `goal-<topic>.md`. Loop until X; do not stop at a plan.

## `/create-subagent`

Spawn `.cursor/agents/devops-*.md` with Cursor `Task`,
asynchronously in pods (`is_background: true` /
`run_in_background: true`). Rules:
[department-pods.md](department-pods.md). Do not poll. Subagents
do not push. Orchestrator pushes only after QA PASS. Agent table:
[SKILL.md](../SKILL.md).

## `/code-review`

**Owner: QA.** Inspect only. Confirm Coder Push JSON and
`cr-<topic>.md`. Diff the side-branch vs `<integration-base>`
([side-work.md](side-work.md)). Write `review-<topic>.md`.
**Do not edit** product code. Probes:
[thoughts-layout.md](thoughts-layout.md).

## `/repro`

Recreate with exact commands and exit codes. Write `repro-<topic>.md`. Repro files are process output.

## `/triage`

**Owner: QA.** Copy [triage-template.md](triage-template.md) to
`triage-<id>.md`. Handoff `To: Coder`. Research *N* joins the
Coder who picks it up ([department-pods.md](department-pods.md)).

## Other `/` skills

`/buildkite-*` · `/sonar-*` · `/review-security` ·
`/browser-automation` · `/share-video` · `/docs-canvas` ·
`/loop` · `/babysit` · `/secure-dependency-health-check`.

**MCP:** `plugin-buildkite-buildkite`, `sonarqube`,
`plugin-snyk-secure-development-Snyk`, `plugin-linear-linear`,
`plugin-composio-composio`, `cursor-ide-browser` /
`plugin-browse-browser`, `plugin-tldraw-tldraw`,
`plugin-mainframe-mainframe`, `cursor-app-control`.
