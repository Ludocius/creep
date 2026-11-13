# ADR 0003: Architecture layers, stable contracts and maintainability decisions

- **Status:** Accepted
- **Date:** 2026-11-13
- **Deciders:** @Ludocius

## Context

Until now, `docs/design.md` was a 47-line summary, and `docs/map.md` did not exist even though AGENTS.md told agents to read it. Nothing enforced which package may depend on which, beyond the net-import rule. A review on 2026-11-13 found maintenance risk in three places: `internal/redact`, which does not converge; `internal/tools/budget`, which changes more than any other package; and code that tracks third-party software. Details are in [architecture.md §6](../architecture.md#6-maintainability-matrix).

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Keep the summary, rely on review | No work | Boundaries erode; every agent rediscovers the code |
| B. Architecture document only | Shared map | Drifts from the code because nothing checks it |
| C. Architecture document with a machine-checked layer table, plus a generated `map.md` | The document cannot silently drift | A table to maintain, plus one budget check |

## Decision

Option C. `docs/architecture.md` is the single source of truth. Its `layers` block is data that `make budget` enforces (#119), and `docs/map.md` is generated and checked in CI (#120). The maintainability matrix in §6 is accepted as the plan: simplify `redact`, keep `gateway` with its API frozen after #84, trim `budget`, leave presets to the community, add languages only as kits, and keep calibration templates as data.

**Module path:** move to `github.com/sneakercreepers/creep` now, while the code is small (maintainer decision, 2026-11-13). Options considered:

| Option | Consequence |
|---|---|
| Keep `github.com/Ludocius/creep` | No change. A later move to an org breaks every import, and each merged PR makes that more expensive. |
| Move to `github.com/sneakercreepers/creep` now | One mechanical PR (module line plus imports) and a repo transfer. Today the code is small. |

## Consequences

- The module path changes to `github.com/sneakercreepers/creep`: one PR for the module line and imports, then the repository transfer, tracked as a follow-up issue.
- `docs/design.md` now points to `architecture.md`.
- New packages must add a row to the `layers` block in the same PR, or `make budget` fails once #119 lands.
- `planner` and `reader` can never import each other, enforced by the layer table.
- Follow-up issues come from §6: freeze `redact` and batch its follow-ups, trim `budget`, move presets to the community, and have the auditor group Lows per component.
