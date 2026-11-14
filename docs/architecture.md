# Architecture

This is the source of truth for what each part of `creep` does, which way dependencies may point, and which contracts are stable. Decisions that change it go through an ADR ([index](#adr-index)). The package-by-package list is generated in [map.md](map.md).

## 1. Context

```
            ┌──────────────┐  local repo (untrusted content)
 developer ─┤              │◄──────────────────────────────
 or CI      │  creep (one  │
 (flags,    │  Go binary)  │──HTTPS──► model endpoints (allowlisted, consented)
  config,   │              │──API────► Docker/Podman (v0.2, sandbox only)
  policy)   └──────┬───────┘
                   ▼
   reports (SARIF/JSON/MD) · run state (JSONL) · egress.log · payloads/
```

- The scanned repository is **untrusted input**. Its text can only reach the reader and the redacted gateway payload. It can never reach the planner, a shell or config that loosens a gate.
- The only network peers are configured model endpoints. There is no telemetry or update check by default.
- There is no server and no database. Each run is independent; state is files.

## 2. Pipeline

| Step | Component | Input | Output | Version |
|---|---|---|---|---|
| 1 | calibrate | model contract, seeded templates | per-class scores, tier S/M/L | v0.1 |
| 2 | static | repo files | route/sink/auth graph as **IDs and enums** | v0.1 |
| 3 | planner | IDs, enums, booleans, calibration | prioritized hypotheses | v0.1 |
| 4 | reader | redacted slices + hypothesis | closed-schema verdicts | v0.1 |
| 5 | sandbox + verify | app build, PoC template | verified / discarded | v0.2 |
| 6 | fix | verified finding | suggested diff | v3 |
| 7 | report | run state | SARIF, JSON, Markdown (HTML v1.0) | v0.1 |

Every model call in steps 1, 3 and 4 goes through the gateway, in this order: `redact.File` → fragment → consent → allowlisted dialer → `egress.log` write-ahead → send.

## 3. Components and layers

A package may import only packages in **lower** layers and only those listed in its row. `make budget` enforces this table (#119), so this block is data and must stay parseable.

```layers
# layer  package                 may import (internal only)
0        internal/exitcode       -
0        internal/buildinfo      -
1        internal/config         exitcode
1        internal/redact         -
2        internal/gateway        config redact exitcode
3        internal/models         gateway config
3        internal/state          config
4        internal/static         state config
4        internal/calibrate      models state config
4        internal/planner        models state config
4        internal/reader         models redact state config
4        internal/sandbox        state config
5        internal/report         state config buildinfo
5        internal/verify         sandbox state config
6        internal/cli            *
6        internal/mcp            report state config
7        cmd/creep               cli
-        internal/tools/*        (build tooling; never imported by the product)
```

| Package | Responsibility | Invariants it owns | State |
|---|---|---|---|
| `exitcode` | Process exit codes | 0 ok · 1 gate · 2 config/consent · 3 model/sandbox | ✅ |
| `buildinfo` | Version and provenance strings | none | ✅ |
| `config` | Five config layers, org policy, CI detection | Project file never loosens CI gates or grants consent (#61, #82) | ✅ (#62, #63 open) |
| `redact` | Secret and PII redaction with stable markers | Whole file redacted before fragmenting; linear time; `ErrRunFull` fails closed | ✅ (follow-ups open) |
| `gateway` | **Only** network path | Allowlist before DNS, TLS, pinning, no redirects, consent, run and endpoint token budget, AIMD concurrency, write-ahead `egress.log`, opaque client | ✅ |
| `models` | HTTP and command contracts, tool canary | No provider SDK; model output decoded into closed structs, never executed; key only from `CREEP_API_KEY` | ✅ HTTP (#5); ⬜ command #6 |
| `state` | JSONL run state, `--record`, `--replay`, resume | Append-only; replay is deterministic | ⬜ #8 |
| `static` | tree-sitter (WASM) routes, sinks and auth; optional scanners | Output is IDs and enums only | ⬜ #85–#88, #10 |
| `calibrate` | Seeded tasks, per-class score, tier, 30-day cache | Same seed gives the same tasks; runs through gateway | ⬜ #89–#91 |
| `planner` | Hypotheses from IDs and enums | **Never receives repository text** (no import of `reader`, `redact`, `static` text types) | ⬜ #12 |
| `reader` | Quarantined reading, closed output schema | Output never flows to planner as text | ⬜ #92–#95 |
| `report` | SARIF, JSON (`schema_version`), Markdown, coverage | Every class is covered, partial or not evaluated | ⬜ #14 |
| `sandbox`, `verify` | Container runtime, internal network, PoC runs | No internet; never on the host | ⬜ v0.2 |
| `mcp` | Read-only MCP server | No sandbox, no writes | ⬜ v0.3 |
| `cli` | Commands and flags (`flag`, no framework) | Unimplemented commands fail closed | ✅ |

`planner` and `reader` must never import each other. This prompt-injection boundary is the one with the highest stakes in the layering.

## 4. Stable contracts

These follow semver once v1.0 ships. Before then, any change needs a note in the PR and, if the change breaks a contract, an ADR.

| Contract | Where | Versioning |
|---|---|---|
| CLI flags and exit codes | `cli`, `exitcode` | semver |
| Config and policy schema | `config` | `version:` key |
| JSON report | `report` | `schema_version` |
| SARIF | `report` | SARIF 2.1.0 |
| Run state (JSONL) | `state` | per-line `v` |
| `egress.log` line | `gateway` | additive fields only |
| HTTP model contract | `models` | OpenAI-compatible + Anthropic |
| Command model contract | `models` | stdin prompt, stdout JSON |
| Recipes, presets, language kits | `recipes/`, `presets/`, kits | own `version:`; data, not code |
| Prompts | `prompts/` | versioned per tier, token-budget test |

## 5. Extension points

Contributors add **data**, not core code:

- **Presets** (`presets/*.yaml`): command lines for model CLIs. They are community-owned because they track third-party flags.
- **Recipes** (v0.3): source, sink and hint records with fixtures, pinned by commit in `creep.lock`.
- **Language kits**: grammar WASM + sources/sinks + PoC templates + vulnerable/safe fixtures. A kit enters only if its conformance test passes. v0.1 ships Python and JS/TS only.

## 6. Maintainability matrix

Evidence from 2026-11-13 (lines are source/test, churn is commits on `main`).

| Component | Size | Churn | Open follow-ups | External load | Decision |
|---|---|---|---|---|---|
| `redact` | 1593 / 2565 | 3 | ~10 | none | **Simplify.** Freeze features after v0.1. Pin perf budgets with CI benchmarks. Close follow-ups in batches, not one per PR. |
| `gateway` | 1671 / 2008 | 4 | 6 | Go `net/http` | **Keep.** Freeze the exported API after #84. Use a `go/types` API guard (#115). |
| `tools/budget` | 1188 / 779 | 5 (highest) | 6 | none | **Trim.** The layer rule (#119) replaces ad-hoc import checks. The net source line count may not grow. |
| `config` | 860 / 657 | 3 | 3 | YAML | **Keep.** |
| `cli` | 727 / 655 | 3 | 1 | none | **Keep.** |
| presets (#7) | — | — | — | CLI flags change often | **Defer to the community.** The core keeps only the two contracts. |
| `static` grammars | — | — | — | grammar releases | **Kits with a conformance test.** No third language before v1.0. |
| `calibrate` templates | — | — | — | none | **Keep** (core differentiator). Templates are versioned data. |
| Agent loop | — | — | 14 Lows in one day | — | **Adjust.** The pentester runs per release ([ADR 0004](adr/0004-pentester-per-release.md)), and the auditor groups Lows per component in one living issue. |

## 7. Non-goals

- No `--url` and no scanning of targets that `creep` did not build from local source.
- No server, no telemetry, no "enterprise edition".
- No provider SDKs in the core, and no framework for the CLI.
- No languages beyond Python and JS/TS before v1.0.
- No automatic application of fixes.

## 8. Engineering principles

The developer follows these and the auditor checks every PR against them ([ADR 0005](adr/0005-auditor-architecture-review.md)). They are defaults, not rules to force: a deviation with a stated reason is fine.

- **Patterns** only where they remove real duplication or coupling. Name the problem first; never add a pattern for its own sake.
- **Modularity.** Small packages with one reason to exist (`doc.go` says which). Deep modules: a narrow exported API hiding real work. The layer table in §3 is respected.
- **Testing where it is needed.** New behavior is covered through its edge cases, failure paths and security protections, not trivial happy paths or getters. No test that only restates the implementation. Table-driven; model behavior gets a replay fixture.
- **Scalability and reuse.** Reuse an existing package before adding one. Work per input is bounded: linear time, capped size, and a documented worst case backed by a benchmark. No speculative abstraction.
- **SOLID the Go way, not forced.** Small interfaces declared by the consumer, composition over inheritance, dependencies passed in explicitly (no globals, no init-time wiring).
- **Paradigm mix.** Plain functions and data first; methods on a type when it owns state. Concurrency and parallelism only when they measurably help (I/O fan-out, CPU-bound batches), always bounded and cancellable through `context`.

## 9. Fitness functions

Automated checks that guard an architectural property. A new property needs a check here, not only prose. Atomic checks run on every PR; the per-version review (ADR 0005) is the holistic one.

| Property | Check | Where it runs |
|---|---|---|
| Only `gateway` reaches the network (invariant 1) | Net/exec/syscall import and reach rules, `internal/tools/budget/imports.go`, `reach.go`; depguard as editor feedback | `make budget`, CI `budget` and `lint` |
| No dependency without an ADR (invariant 6) | Dependency allowlist vs `docs/adr/dependencies.txt`, `go mod tidy -diff` | `make check`, CI `budget` |
| Small, auditable build | Module-graph and release-binary caps; no non-Go sources, `go.work`, `vendor/` or local replace | `make budget` |
| Small files | Go file cap of 400 lines, build-tagged files included (`lineProblems`) | `make budget` |
| Agent loop cannot erode | Pinned policy phrases in AGENTS.md, CONTRIBUTING.md, PR template (`policy.go`) | `make budget` |
| Workflows are pinned and safe | Immutable action/image pins, no `pull_request_target`; actionlint, zizmor | `make budget`, CI |
| Secrets never leave unredacted | Redaction leak tests (`redact/*_test.go`), gateway fragment scan test | `make check` |
| Model spend is bounded | Over-budget and concurrent-overspend tests, AIMD table test (`gateway/budget_test.go`, `aimd_test.go`; race on Linux CI) | `make check` |
| Redaction stays linear | `TestRedactLargeInputIsBounded`; `Benchmark*` in `internal/redact` | `make check`; benchmarks at the per-version review |
| No known-vulnerable code or leaked secret | govulncheck, gitleaks over full history, CodeQL | CI |
| Layer table holds | `layers` block in §3: every module package has a row and imports only lower layers its row lists (`layers.go`) | `make budget`, CI `budget` |

Function length has no automated check; the auditor reviews it.

## 10. Evolutionary architecture

Adapted from *Building Evolutionary Architectures* (Ford, Parsons, Kua), taking only what fits a single-binary CLI with one maintainer.

| Book idea | How creep adapts it | Not adopted |
|---|---|---|
| Fitness functions | The checks in §9, in one table; add one only when a property has no automated guard | No fitness-function framework or dashboard |
| Atomic vs holistic, triggered vs continual | Atomic and triggered: `make check` and CI on every PR. Holistic: the per-version review (whole diff, benchmarks over time) | No production monitoring (no telemetry, invariant 5) |
| Incremental change | Small issues, up to three features in flight in different packages ([ADR 0006](adr/0006-three-features-in-flight.md)), squash merges, sub-issues for L | — |
| Appropriate coupling (connascence) | Layer table and narrow interfaces; the auditor flags strong connascence across a package boundary | No coupling metrics tooling |
| Anticorruption layer | Model contracts translate vendor output into closed schemas before planner or reader see it | — |
| Last responsible moment | ADRs only when a dependency or public contract changes | — |
| Evolvability over predictability | Prefer data (prompts, rules, kits, layer table) over code so changes stay local | No speculative plugin systems |

Skipped on purpose: architectural quanta per service, cross-service schema evolution and per-team deployment pipelines. They target distributed systems; creep is one binary with no server.

## ADR index

| ADR | Decision |
|---|---|
| [0001](adr/0001-yaml-parser.md) | `go.yaml.in/yaml/v3` for config |
| [0002](adr/0002-agent-loop-scope.md) | Shared context in the agent loop; pentester independent |
| [0003](adr/0003-architecture-layers.md) | Layers, stable contracts, maintainability decisions, module path |
| [0004](adr/0004-pentester-per-release.md) | Pentester once per version and on external PRs |
| [0005](adr/0005-auditor-architecture-review.md) | Auditor reviews PRs against this document; per-version architecture review |
| [0006](adr/0006-three-features-in-flight.md) | Up to three features in flight, each with its own loop |
