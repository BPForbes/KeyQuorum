# Thought-process files

Working notes are **transient** and **gitignored**. Do not commit
research dumps, review threads, `/goal` logs, `/repro` notes, role
goals, or Push JSON. Committing `non-finalized/` stores those blobs
in every earlier commit.

| Path | Git | When |
|------|-----|------|
| `.cursor/thoughts/non-finalized/` | **Gitignored** (keepfile only) | Open |
| `.cursor/thoughts/finalized/` | **Gitignored** | Done (local after QA) |

Keep `.cursor/thoughts/non-finalized/.gitkeep`. Do not `git add`
any other file under `.cursor/thoughts/`. `.cursor/reviews/` is
obsolete. Push JSON lives in `non-finalized/`
([push-json.md](push-json.md)).

**non-finalized:** `review-<topic>.md`, `goal-*.md`, research
briefs, `repro-*.md`, handoffs, `push-*.json`, `triage-<id>.md`,
`side-<dept>.md`, `cr-<topic>.md`
([triage-template.md](triage-template.md),
[side-work.md](side-work.md)). **finalized** after QA PASS: move
matching files locally; do not `git add`.

If a note must survive clones, put it in `docs/` or skill
`references/`. Do **not** commit “Record Satisfied / Security /
QA” notes. Empty `git status` means nothing to commit. Redact
tokens; prefer exit codes.

## One push (after PASS)

Coders do not commit on the shared checkout. After Satisfied,
Security Clear, applicable CodeQL, **and QA marks PASS**:

1. Move closed thoughts to `finalized/` (local).
2. Compress. **Keep reviewer-approved trees as keep-commits**
   (Orchestrator). A **keep-commit** since `<integration-base>`
   includes product,
   pipeline, infra, test, or durable `docs/` marked Satisfied —
   replay in order with original messages. **Fold** the rest so
   the tip tree matches the approved tree.
   `git reset --soft <integration-base>` then one commit is
   allowed **only** when there are no keep-commits. Otherwise
   replay keep-commits, then commit remaining tip-tree delta.
3. `scripts/check-clean-timeline.sh --history <integration-base>`.
   Use `--history`. A path added then deleted still ships its
   blob. `git status --short` clean of files you created.

### Step 3a — strip a path from a keep-commit

Throwaway clone (`git clone --no-hardlinks . /tmp/scrub`),
backup a ref, `git filter-repo --force --path <path>
--invert-paths --refs <integration-base>..HEAD`. Re-run step 3.
`git diff $old HEAD` empty. Push `--force-with-lease`. A scrub
after a prior push does **not** unpublish forge blobs.

4. Push once. The Client authorizes this rewrite for this
   skill’s final publish only.

## Scratch files (Reviewer, Security, QA)

The rule is the **class of output**. Threads, Push JSON,
triage/repro, probes, CodeQL DBs, and SARIF never land.
Product, pipeline, infra, tests, and durable `docs/` land as
keep-commits. Prefer `/tmp/probe`. Reserved lower-case names:
`_scratch/` or `.scratch`. Undo with `git checkout -- <exact
path>` — never `git checkout -- .` / `git restore :/` / stash.
Fixed-name probes cannot take a reserved name: delete
immediately. `check-no-var.sh` does not see gitignored probes.
