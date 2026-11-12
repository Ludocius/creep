# Design summary

The short version of the design. Decisions that change it go through an [ADR](adr/0000-template.md).

## Pipeline

```
creep scan .
  1 Calibration     measure the model per vulnerability class (cached per model+version, 30 days)
  2 Static          gitleaks rules as data + tree-sitter (WASM): routes, sinks, auth; optional semgrep/osv-scanner/gitleaks
  3 Planner         sees only IDs and enums → prioritized hypotheses
  4 Reader          reads code (quarantined), answers in a closed schema
  5 Sandbox  v0.2   optional Docker/Podman, internal network, PoC against HEAD (differential in v2)
  6 Fix      v3     diff → oracle → tests, suggested only
  7 Report          verified · probable · discarded · not evaluated → SARIF, JSON, Markdown
```

Every model call goes through the **gateway**: redaction → egress allowlist → `egress.log`.

## Model contracts

- **HTTP**: OpenAI-compatible + Anthropic.
- **Command**: prompt on stdin, JSON on stdout. Guarded by the tool canary.

No provider-specific code in the core. Presets for CLIs are community data in `presets/`.

## Fixed protections (not configurable)

- Model output never runs on the host.
- Sandbox has no internet access.
- Only targets built from local source; no `--url`.
- Secrets always redacted; `egress.log` always on.
- The planner never reads code.

## Configuration layers

1. Built-in safe defaults → 2. Org policy (`CREEP_POLICY`, can lock keys) → 3. User (`~/.creep/config.yaml`) → 4. Project (`./creep.yaml`) → 5. CLI flags.
`creep config explain` shows each final value and its source.

## CI gates

- PR: `probable:critical` (no sandbox).
- Nightly: `verified:high`.

## Dependencies

About three direct dependencies in v0.1 (YAML, wazero, JSON Schema). State in JSONL files. External scanners are optional; when missing, the report says "not evaluated".
