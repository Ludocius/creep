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
- Commits: Conventional Commits, signed, with `Signed-off-by` (`git commit -s`).

## Workflow (spec-driven)

- **The GitHub issue is the spec**: context, scope, acceptance criteria. If the spec changes, edit the issue — do not add new `.md` files.
- Per feature, three independent agents with no shared context: **developer → tester → pentester**. Maximum 3 cycles; the next developer receives only the findings.
- Merge (squash) only when GitHub checks are green **and** the pentester approves. One feature at a time.
- Branch `feat/<issue>-<slug>`; PR body `Closes #N`; labels from the issue.
- ADR only when a change adds a dependency or alters a public contract.
- After each merge, update **Current state** below (max 10 lines).

## Current state

- Merged: —
- Next: #1 base CLI → #18 CI → then dependency order in the Roadmap project (Priority P0 first)
- Windows dev: Go 1.27 and make via winget; tests must pass on Windows and Linux.

## Do not read

`testdata/replay/`, `bin/`, `dist/` — large generated data.
