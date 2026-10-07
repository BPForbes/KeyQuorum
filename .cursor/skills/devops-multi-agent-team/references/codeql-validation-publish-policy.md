# CodeQL, Validation, and Publish Policy

This repo has .NET/C#, TypeScript/JavaScript, and Rust. GitHub
Actions runs CodeQL for all three. Treat CodeQL as a required
gate before publish.

## Core rule

**Only QA may give the OK to push.** Anyone who changes product,
pipeline, or infra code must run applicable CodeQL. That developer
run does not authorize a push. Review Satisfied, Security Clear,
compilation, tests, and linters do not substitute for CodeQL.

“CodeQL is satisfied”: applicable database created; analysis
completed; SARIF inspected; no unresolved finding introduced or
materially affected by this change remains; no query, path, or
check was weakened to obtain a pass.

If CodeQL cannot run when required: do not claim it passed and do
not publish. Do not weaken `.github/codeql/codeql-config.yml` /
`.github/workflows/codeql.yml`. Fix the code.

## Fast validation (before full CodeQL)

Repo scripts only. Do not invent targets.

- **.NET:** `dotnet restore` · `dotnet format --verify-no-changes`
  · `dotnet build --warnaserror` · `dotnet test` (repo `.sln`).
- **TypeScript:** `npm ci` · `npm run lint` · `npm run typecheck`
  · `npm test`.
- **Rust:** `cargo check --workspace --all-targets` ·
  `cargo test --workspace` (`rust/` here).

## Local CodeQL (match GitHub Actions)

Match the workflow query suite. Report if local parity is
impossible. Language-only changes run that language; cross-stack
runs all three. Unaffected targets may be `NOT APPLICABLE` unless
CI requires all three. Mandatory for auth, secrets, crypto, HTTP,
SQL/ORM, uploads, command execution, serialization, XSS/SSRF, and
security configuration.

**C#** — create `.codeql-db-csharp --language=csharp --command="dotnet build"`; analyze `codeql/csharp-queries` → `codeql-csharp.sarif`

**JS/TS** (`--language=javascript` covers `.ts`) — create
`.codeql-db-javascript`; analyze `codeql/javascript-queries` →
`codeql-javascript.sarif`

**Rust** (`--build-mode=none`; no `--command` / autobuild) —
create `.codeql-db-rust`; analyze
`codeql/rust-queries:codeql-suites/rust-security-and-quality.qls`
→ `codeql-rust.sarif`. Inspect each SARIF.

## Findings

For each finding introduced or materially affected: rule, file,
line; fix; re-run build/tests and CodeQL; inspect SARIF.
**NEW** must resolve; **EXISTING** report only; **MODIFIED /
RE-EXPOSED** resolve when this change contributes. Full CodeQL
after a security-sensitive or substantial set, and always before
the publish gate.

## Publish

**Prohibited** when FAIL, NOT RUN when required, INCOMPLETE,
SARIF not reviewed, a new finding unresolved, or required
build/tests FAIL.

**Allowed** (full-stack): .NET / TS / Rust validation and tests
PASS; C# / TS / Rust CodeQL PASS; SARIF reviewed; new unresolved
= 0. Also: `scripts/check-clean-timeline.sh --history
<integration-base>` passes, **or** every reported path is
recorded for Orchestrator step 3a (keep-commit finding is not a
Coder send-back). `git status --short` clean of files you
created. Diff paths stay under `backend/`, `frontend/`, `rust/`,
`scripts/`, `tools/`, `llm-service/`, `docs/`, `deploy/`,
`.github/`, `.vscode/`, `.cursor/`, and tracked root config.

## Definition of done

Report .NET / TS / Rust validation and tests plus C# / TS / Rust
CodeQL (PASS / FAIL / FINDINGS / NOT RUN / NOT APPLICABLE); new
unresolved N; publish gate PASS / BLOCKED. Never call the change
CodeQL-clean unless analysis ran and SARIF was reviewed. Never
publish while BLOCKED.
