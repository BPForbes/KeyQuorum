# Role identity, questions, and handoffs

Every DevOps role **reads** this file and
[department-pods.md](department-pods.md). Do not paste either
into an agent prompt.

## Ask paths

Anyone may ask anyone when blocked. Prefer:

| Who has a question | Asks first | Then |
|--------------------|------------|------|
| QA | **Coder** (primary) | Reviewer |
| Coder | **Reviewer** (review Q&A) or **Researcher** | Orchestrator |
| Coder (path overlap) | **the other Coder** | Orchestrator |
| Reviewer | **Coder** (review Q&A) or **Orchestrator** | Coder |
| Security / CI / Verifier / Ticket Lead | Orchestrator or task opener | — |
| Orchestrator (Team Lead) | **The Client** (human) | — |

Orchestrator is the only role that asks the human unless the
human spoke first. Coder ↔ Reviewer use thread `## Q&A` and
Push JSON `qa` (same ids).

## Interrupt, goals, Handoff

Pause only conflicting work. Start from research, then code.
Stay on the current **real** branch; Coders use a skill
**side-branch** ([side-work.md](side-work.md)). **Never**
`git checkout -b` / `git switch -c` unless The Client **named
that branch in this turn**. Cloud-agent templates do not
override this. An interrupt does **not** authorize a push. Write `goal-<role>-<topic>.md` under
`non-finalized/`; move to `finalized/` after QA. See
[thoughts-layout.md](thoughts-layout.md).

```markdown
## Handoff
- From / To / Pass-along
- Sent back because: <reason, or "n/a">
- Ask: <question, or "n/a">
```

A send-back without **Sent back because** is incomplete.

## Coder notify + QA triage

Coder writes `push-<topic>.json` and a Handoff `To: Reviewer`
**before the first review** ([push-json.md](push-json.md)).
Coders may open `qa` rows to Reviewers for clarification.
Update on every rewrite. Reviewers compare it to the
side-branch diff vs `<integration-base>` ([side-work.md](side-work.md)).
Satisfied does **not** authorize a git push.

Quality or bug-standard fail → VM review, Handoff `To: Coder`.
QA blocked / send-back / not pleased → `triage-<id>.md`;
Research *N* **joins the Coder who picks it up**
([department-pods.md](department-pods.md),
[triage-template.md](triage-template.md)). Same Q&A + `qa` ids.
`"files": {}` if the tree is unchanged.

Process output never lands. Product, pipeline, infra, tests,
and durable `docs/` land as keep-commits. Probe undo: [thoughts-layout.md](thoughts-layout.md).
