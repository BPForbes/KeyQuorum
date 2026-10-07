# Review thread template

Copy to `.cursor/thoughts/non-finalized/review-<topic>.md`.
Local only; do not commit. After QA PASS, move to `finalized/`.
See [thoughts-layout.md](thoughts-layout.md).

```markdown
# Review: <topic>

**Branch:** <shared checkout; do not invent a real git branch>
**Side-branch:** `side/<dept>-<topic>` (`side-<dept>.md`)
**Status:** In review | Changes requested | Satisfied — ready for security | Closed
**Push policy:** Only QA may give the OK to push.

## Research brief
### Local docs / Online media / Recommendations
- … · | URL | Takeaway |

## Push JSON
- Latest: `.cursor/thoughts/non-finalized/push-<topic>.json`
- Coder writes this **before the first review**. Reviewers compare
  it to the side-branch tree vs `<integration-base>`.

## Change summary (Coder)
- Files / Intent / Notify (Handoff + Push JSON path)

## Review round N (Reviewers)
### Request changes
- [ ] `path` — finding (cite research/doc/URL; label which reviewer)
### Questions / Suggestions (non-blocking)
- …
### Reviewer sign-off
| Reviewer | Verdict | Notes |
|----------|---------|-------|
| reviewer-1 | Changes requested / Satisfied | … |

## Q&A (Coder ↔ Reviewer)
| Id | From | To | Ask | Answer | Status |
|----|------|----|-----|--------|--------|
| q1 | Reviewer | Coder | … | | open |
| q2 | Coder | Reviewer | … | | open |

## Coder response (round N)
- Replies + what changed; q-ids closed

## Handoff
- From / To / Pass-along / Sent back because / Ask

## Security (after Satisfied)
- Verdict: Clear / Blocked

## QA handoff
- Commands; .NET / TS / Rust validation + CodeQL; clean timeline
  (`check-clean-timeline.sh --history <base>`); publish gate
  PASS / BLOCKED; VM send-back; triage ids; thoughts to finalize
```
