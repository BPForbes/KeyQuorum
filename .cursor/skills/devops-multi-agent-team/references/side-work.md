# Side-work and comments

Coders do not put commits on the shared checkout until **QA PASS**.
The Orchestrator then makes the keep-commit(s) and one push
([thoughts-layout.md](thoughts-layout.md)).

## Side-branch (skill-tracked, not a git branch)

A **side-branch** is a name the skill tracks. It is **not**
`git checkout -b` and must not be pushed. **Never** create a
real git branch unless The Client **named that branch in this
turn**. Cloud-agent `feature/*-<id>` templates do **not**
override this. Isolation is a **clone of the current real
branch**, not a new ref.

1. Write `.cursor/thoughts/non-finalized/side-<dept>.md`: `name`
   (`side/<dept>-<topic>`), `clone` (`/tmp/side-<dept>-<topic>`),
   `base` (current shared branch), **files owned** (paths this
   Coder will edit).
2. Isolate with a **clone** (the supported mechanism):

   ```text
   git clone --no-hardlinks . /tmp/side-<dept>-<topic>
   ```

   Stay on the same real branch name as the shared checkout.
3. If a tool needs a commit, commit **only** in that clone. Never
   `git push` it. Never commit on the shared checkout.

### Clone, not `git worktree add`

Do **not** use `git worktree add` for isolation.

[Git’s `worktree add`](https://git-scm.com/docs/git-worktree)
refuses a branch that is already checked out in another worktree
(the shared checkout) unless `--force`. That is the default.

Do not work around it:

| Workaround | Why not |
|------------|---------|
| `git worktree add <path>` on the current branch | Refused: branch is already checked out. |
| `--force` on that same branch | Two indexes on one branch; Git documents this as unsafe. |
| `--detach` | Detached HEAD is not the same real branch name. |
| `-b` / `-B` / a new worktree branch | Invents a real git branch; violates branch policy. |

The clone is a separate repository. It may check out the same
real branch name without `worktree add`’s already-checked-out
refusal. That is why the clone is the supported isolation
mechanism. There is no supported detached-worktree procedure.

## Coder ↔ Coder (prevent merge conflicts)

Skill side-branches are parallel. They must not collide when the
Orchestrator keep-commits.

- Before editing, read every other `side-*.md` **files owned**
  list. If a path is claimed, **talk to that Coder** (Handoff
  `To: Coder <letter>`, or Push JSON `qa` with `to`: `Coder`).
- Record the handshake in both `side-*.md` files: who takes the
  path, who waits, or how hunks are split. Do not silently
  overwrite.
- Prefer department ownership ([department-pods.md](department-pods.md)).
  Cross-department files need an Orchestrator note.
- Before the Orchestrator keep-commit, Coders confirm no
  uncoordinated overlapping hunks. If two clones touched the
  same path, the owners merge in one clone first.

## Run the change

In the side **clone**, use a VM, `computerUse`, `dotnet` / `npm` /
`cargo`, and `/repro` as needed. The shared worktree stays free
for other departments. Probe undo:
[thoughts-layout.md](thoughts-layout.md).

## Coder → Reviewer comments

Coders may open review-thread `## Q&A` rows and Push JSON `qa`
(`from`: `Coder`, `to`: `Reviewer`) to ask for clarification
before or during review. Same ids. Open rows block Satisfied.
