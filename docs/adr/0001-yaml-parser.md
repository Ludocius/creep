# ADR 0001: YAML parser for config files

- **Status:** Accepted
- **Date:** 2026-11-12
- **Deciders:** @Ludocius

## Context

Issue #2 adds layered configuration: org policy (`CREEP_POLICY`), `~/.creep/config.yaml` and `./creep.yaml`. YAML is what CI users already write, and the design summary budgets about three direct dependencies for v0.1 (YAML, wazero, JSON Schema). The standard library has no YAML parser.

Requirements: strict decoding into typed structs (an unknown key is an error, so a fixed protection such as `sandbox.internet` can never be silently accepted), line numbers in errors, duplicate-key detection, no network or cgo, and a small transitive footprint (`make budget` caps the module graph at 30 modules).

## Options

| Option | Pros | Cons |
|---|---|---|
| `go.yaml.in/yaml/v3` | Maintained continuation of `gopkg.in/yaml.v3` under the YAML org; `KnownFields(true)` strict mode; node API gives line numbers; rejects duplicate keys; no dependencies outside the standard library | YAML 1.1/1.2 quirks (anchors, aliases) need caps; one more module to track |
| `gopkg.in/yaml.v3` | Same API, widely used | Archived upstream; no further fixes |
| `github.com/goccy/go-yaml` | Good error messages, strict mode | Larger code base, more surface for a config parser |
| JSON or TOML via the standard library / a TOML library | JSON needs no dependency | JSON has no comments and is unfriendly for hand-written policy; TOML still needs a dependency and is less familiar in CI |

## Decision

Use `go.yaml.in/yaml/v3`: it is the maintained line of the parser most Go tools already use, and it gives strict, line-numbered decoding with no transitive dependencies. The JSON Schema library waits for #12/#13; `schema/config.schema.json` is kept in sync by a test, not validated at runtime.

## Consequences

- `docs/adr/dependencies.txt` lists the module; `make budget` enforces it.
- Config files are read by `internal/cli` (non-blocking open, 1 MiB cap, regular files only) before the parser sees them, which bounds alias expansion work together with the parser's own alias limits.
- Upgrades come through Dependabot; a major version change needs a new ADR.
