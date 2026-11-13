# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, Copilot, Cursor, Gemini CLI…) and humans.

## Project

`creep` is a model-agnostic CLI that finds vulnerabilities in local source code. Go, single binary, Apache-2.0.
Design summary: [docs/design.md](docs/design.md). Package map: [docs/map.md](docs/map.md) — read it instead of exploring.

## Commands

```sh
make check                        # all PR checks; run before every PR
make test PKG=./internal/<pkg>    # one package
make map                          # regenerate docs/map.md after adding/removing packages
go test ./... -failfast           # tests replay recorded model responses; no keys needed
```

## Invariants — never break these

1. Only `internal/gateway` may import `net/http` or open network connections. A linter enforces it.
2. Every model call goes through the gateway, which redacts secrets first and writes `egress.log`.
3. The planner receives only IDs, enums and booleans — never text from the scanned repo.
4. Model output is never executed on the host. PoCs run only in the sandbox (v0.2).
5. No telemetry. No network calls except to configured model endpoints.
6. No new direct dependency without an ADR in `docs/adr/`.

## Conventions

- Standard library first. Functions do one thing. Guard clauses over nesting. Files under 400 lines.
- Each package has a `doc.go` explaining why it exists.
- Errors wrap with context: `fmt.Errorf("redact %s: %w", path, err)`.
- Tests are table-driven. New behavior needs a test; new model behavior needs a replay fixture.
- Prompts live in `prompts/` as versioned data, one variant per model tier, with a token-budget test.
- Commits: Conventional Commits with `Signed-off-by` (`git commit -s`); SSH or GPG signing recommended (required once #49 lands).
- Test fixtures are generated in `t.TempDir()` unless they must be committed files; throwaway worktrees or folders go outside the repo and are removed when done.

## Workflow (spec-driven)

- **The GitHub issue is the spec**: context, scope, acceptance criteria. If the spec changes, edit the issue — do not add new `.md` files.
- **Agent loop (mandatory for every model-assisted change, enforced by `make budget`):** agents in order **developer → tester → pentester → auditor** ([ADR 0002](docs/adr/0002-agent-loop-scope.md)).
  - The developer implements the issue; the tester checks every acceptance criterion; the pentester does a static security review (no external network); the auditor re-rates each finding by real impact (exploitability, who can trigger it, existing mitigations) and posts its decision as a PR comment.
  - Developer, tester and auditor share context (issue, diff, test output, earlier verdicts). The pentester gets no shared context: only the issue, the diff and the repository, so its review stays independent.
  - The pentester runs only when the issue carries the `security-sensitive` label, which only maintainers apply. If the auditor sees security impact in an unlabeled change, it asks a maintainer to add the label and the pentester runs before merge.
  - Confirmed Critical or High blocks the merge and goes back to the developer with the findings. Maximum 3 cycles, then escalate to the maintainer.
  - Medium, Low and Info do not block; each open finding becomes a follow-up issue.
  - Documentation-only changes run only the auditor (saves tokens): the PR touches only `*.md` files or `docs/`, and not code, workflows, settings, Makefile or the policy files (AGENTS.md, CLAUDE.md, CONTRIBUTING.md, PR template).
  - The auditor triages every open finding (audited severity, priority, size, milestone) and adds each follow-up issue to the project board (Roadmap, project 4) with those fields.
  - Changing or removing this loop needs an ADR in `docs/adr/` and maintainer approval; do not weaken it as a side effect of another change.
- Merge (squash) only when GitHub checks are green, the tester passes and the auditor allows it. One feature at a time.
- Branch `feat/<issue>-<slug>`; PR body `Closes #N`; labels from the issue.
- ADR only when a change adds a dependency or alters a public contract.
- After each merge, update **Current state** below (max 10 lines).

## Current state

- Merged: #1 base CLI (`internal/cli`, `internal/exitcode`, `internal/buildinfo`); #18 CI (10 required jobs) and `internal/tools/budget` (`make budget`); #39 rulesets, `release` environment and settings as code (`make rulesets`). Main accepts only squash PRs with green checks. #55 agent-loop policy enforced by `make budget`. #2 layered config (`internal/config`, `creep config explain`, ADR 0001 yaml/v3); #61 project file cannot loosen built-in CI gates; #4 redaction (`internal/redact`): callers must fragment only `redact.File` output; #74 linear whole-file key scan; #69 bounded linear sweep and per-run value caps: callers must treat `redact.ErrRunFull` as scan incomplete. #96 ADR 0002: developer, tester and auditor share context; the pentester stays independent and runs only on maintainer-labeled `security-sensitive` issues. Unimplemented commands fail closed (exit 2).
- Next (by board priority; L issues split into sub-issues): #3 (#78, #80–#84) → #75 → #72 → #70 → #73 → #102 → #5 → #8 → #16 → #9 (#85–#88) → #11 (#89–#91) → #12 → #13 (#92–#95) → #14; then #6, #62, #63, #43, #49, #10, #20, #17, #19, #7, #15. Other follow-ups: #41, #50–#52, #56, #57, #64, #71, #101, #105, #107 (v0.1); #44–#46, #58, #76, #100, #106 (v0.2).
- Review lessons: never exit 0 on unimplemented paths; open files without blocking (FIFO); escape every printed error; run golangci-lint locally (CI lint is required); redact whole files before fragmenting; back every documented worst case with a benchmark.
- Windows dev: Go 1.27 and make via winget (no cgo, so `-race` runs only on Linux). Linux check: `docker run --rm -v "$PWD:/src" -w /src golang:1.27.4 go test -race ./...`.

## Do not read

`testdata/replay/`, `bin/`, `dist/` — large generated data.
