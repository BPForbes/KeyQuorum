# Department pods

Letters are **departments / subject matters**, not people. Teams work
**dynamically**: research can run with coding; coding can run with
review. Do not run roles as a linear 1→N queue.

Read this file. Do not paste it into agent prompts.

| Dept | Owns | Coder seat |
|------|------|------------|
| **A** | skill `SKILL.md`, `references/*`, `.cursor/agents/*` | Coder A |
| **B** | `AGENTS.md`, `CLAUDE.md`, PR description text | Coder B |

## Research → Coder

- Research **A** done → Coder **A**. Research A **joins Coder A**.
- Research **B** not done → **do not** run Coder B.
- Same for every letter: no Coder until that department’s brief
  exists (or the Orchestrator already knows the surface).

## Reviewer primary

Coder B submits → Reviewer A and Reviewer B may both review it.
If Coder A then submits, Reviewer A **prioritizes** Coder A.
If Coder B is still writing and Coder A has not submitted,
Reviewer A reviews other ready code.

Cross-review until a coder of the **same department** submits.
Each reviewer has a primary. If they cannot review that goal,
they review other ready code.

## Finish the line, then pass notes

Mid-review, if a primary arrives: finish the current **line of a
file**, then pass notes to the reviewer whose primary it is.
The Orchestrator records the handoff. Do not swap silently.

## QA primary

If nothing matches a QA’s primary, they test other ready items.
Mid-test, if their primary becomes ready: finish the current
assessment, pass notes, then switch.

## Send-back (review)

**a.** One reviewer on their primary → coder rewrites. That reviewer
joins other topics and **receives context + existing feedback**
before commenting.

**b.** Several reviewers in one session → **label which reviewer**
left each finding. On send-back, priority may shift with goals.

## Send-back (QA triage)

When QA is **blocked**, **sends back**, or is **not pleased**: open
`triage-<id>.md` from [triage-template.md](triage-template.md).
Handoff `To: Coder` from a **VM** review
([role-identity.md](role-identity.md)). Do not wait for a serial
research-then-coder queue.

The Coder who picks up the item owns the rewrite. Research *N* of
that department **joins that Coder immediately** and stays paired
until Reviewers take the rewrite. Same-department Research/Coder
letter rule still applies to *new* work; triage is the exception
that pairs them at once.

Prioritize the assigned item when available. Pass findings when
helping on another item.

## Orchestrator duties

- Spawn `/create-subagent` (`Task`, `run_in_background: true`) so
  pods overlap. Do not poll background subagents.
- Do not start Coder *N* before Research *N* is done (new work).
- Record primaries, finish-the-line handoffs, and QA swaps.
- Gates: no push while review is open; Security before publish;
  **only QA may give the OK to push.** Coders cut a skill
  side-branch (clone, not worktree, **not** a new git branch);
  no shared commits until QA PASS. Record overlapping **files
  owned** so Coders talk before they collide
  ([side-work.md](side-work.md)). Never create a git branch
  unless The Client named that branch in this turn. Cloud-agent
  templates do not override this.
