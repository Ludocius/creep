// Package state keeps creep's run state on disk as JSONL, so runs can be
// recorded, replayed with no network, and resumed after an interruption.
//
// It exists so that tests and CI runs are deterministic and free (model
// responses replay from disk) without a database dependency. Layout under the
// state directory (normally ./.creep):
//
//	runs/<id>/events.jsonl   append-only event log of one run
//	cache/<sha256>.json      one recorded model response, shared across runs
//
// The run directory is also where the gateway writes egress.log (Run.Dir).
//
// What it guarantees:
//   - Every line carries a version field "v". Readers accept unknown fields,
//     so new fields are additive; a newer "v" fails closed. A committed v1
//     fixture (testdata/v1) must keep decoding with no unknown fields, so a
//     removed or retyped field fails the tests.
//   - Files are 0600 and directories 0700. Cache entries are written to a
//     temporary file, synced and renamed, so a reader never sees half of one.
//     Events are appended with one write and an fsync per line.
//   - Reading is bounded (MaxLineBytes, MaxResponseBytes) and fails closed: a
//     torn, oversized, out-of-order or unknown line is ErrCorrupt, never
//     skipped. Files are opened without following a swapped-in link and
//     without blocking on a FIFO.
//   - A run is complete only when its log ends with an "end" line whose
//     outcome is "complete". A run that stopped early (a crash, or
//     redact.ErrRunFull reported by the caller as OutcomeIncomplete) loads as
//     incomplete, so it can never be read back as a clean scan.
//
// What it does not do: redact. Events hold only IDs and enums (Step and
// Reason are checked against an ID alphabet), and the cache holds model
// responses exactly as the gateway returned them for already redacted
// requests. Callers must not store anything else.
package state
