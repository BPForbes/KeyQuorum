# QA triage item

Copy to `.cursor/thoughts/non-finalized/triage-<id>.md`. Same
Handoff + **Q&A** as the review thread. Copy ids into Push JSON
`qa`. `"files"` may be `{}`. Do not `git add`. After QA PASS,
move to `finalized/`.

When QA is **blocked**, **sends back**, or is **not pleased**, QA
opens this file. Research *N* of that department **joins the Coder
who picks the item up** and stays until Reviewers take the rewrite
([department-pods.md](department-pods.md)). Not a serial
research-then-coder queue.

```markdown
# Triage: <id>

**State:** active | closed
**Opened by:** QA
**Discovered during:** <command, `/repro`, VM, CodeQL, CI>
**Branch:** <current checkout>
**Review thread:** `.cursor/thoughts/non-finalized/review-<topic>.md`

## What went wrong / Expected / Actual
- …

## Environment
- VM / host; commands; exit code

## Active loop
- [ ] Research *N* joins Coder who picked this up (paired, not serial)
- [ ] Coder rewrite + Push JSON
- [ ] Reviewers compared JSON to the side-branch vs `<integration-base>`
- [ ] Security (after Satisfied)
- [ ] QA re-check on the VM

## Q&A
| Id | From | To | Ask | Answer | Status |
|----|------|----|-----|--------|--------|
| t1 | QA | Coder | … | | open |

## Handoff
- From: QA / To: Coder / Pass-along /
  Sent back because: <quality / bug standard, or "n/a">
```
