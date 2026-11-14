# ADR 0007: Exit code 4 for incomplete runs

- **Status:** Proposed
- **Date:** 2026-11-14
- **Deciders:** @Ludocius
- **Changes:** the exit-code contract (architecture §4, `internal/exitcode`)

## Context

A scan can stop before its last file: redaction hits its per-run cap (`redact.ErrRunFull`), the token or call budget runs out, or a model call fails (`gateway.ScanReport.Incomplete`; `run_full`, `budget`, `send_failed`). The run state can also end incomplete. The report (#14) still gets written so the user sees what was and was not evaluated, but such a run must never exit 0 or read as a clean result (the #127 audit).

The contract today is `0` nothing blocking · `1` gate exceeded · `2` usage or configuration · `3` model or sandbox. None of them fits: `0` is a clean result; `1` says the findings exceed the gate, while an incomplete run may have no findings at all; `2` and `3` are for runs that fail before producing a report, so a CI step cannot tell "the scan broke" from "the scan ran but covered less".

## Options

| Option | Pros | Cons |
|---|---|---|
| A. Reuse `3` (model or sandbox) | No contract change | Wrong for `run_full` and `budget`, which are not model failures; hides that a report exists |
| B. Reuse `1` (gate exceeded) | No contract change | Says findings blocked the build when coverage did; "fix the findings" is the wrong action |
| C. New code `4`: report written, not everything evaluated | One meaning per code; CI can branch on it; never 0 | Adds a value to a public contract |

## Decision

Option C. `exitcode.Incomplete = 4` means the run wrote its report but did not evaluate everything. `exitcode.ForReport(incomplete, gateExceeded)` maps a finished run to its code:

1. Errors before a report exists keep returning `2` or `3` directly.
2. An incomplete run returns `4`, even when the gate is also exceeded: the report says both, but a gate verdict over partial coverage is not trustworthy.
3. Otherwise a gate breach returns `1`, and only a complete run within the gate returns `0`.

What decided it: an incomplete scan is neither clean nor a finding, and only a distinct code lets CI treat it as its own failure.

## Consequences

- `--help`, README and architecture §3/§4 list `4`; `internal/exitcode` tests pin the value and the precedence.
- The JSON report (`run.incomplete`, `run.reason`), SARIF (`executionSuccessful: false`, an error notification, `properties.incomplete`) and Markdown (a banner) mark the same runs incomplete.
- `creep scan` must use `ForReport` when it is wired (v0.1 milestone); until then it fails closed with `2`.
- Values `0`–`4` keep their meaning; new codes need another ADR.
