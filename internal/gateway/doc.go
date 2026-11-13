// Package gateway is the only code in creep that may touch the network.
//
// It exists so that every byte leaving the machine passes one reviewable
// choke point (AGENTS.md invariants 1, 2 and 5):
//   - It is the only package allowed to import net, net/http, crypto/tls and
//     the other networking packages. `make budget` fails the build when any
//     other package, test files and dev tooling included, imports them or
//     reaches them through a dependency; golangci-lint's depguard rule gives
//     the same feedback in editors.
//   - Every model call is redacted first: repository text is passed through
//     redact.File before it is fragmented, every fragment through the run's
//     Redactor before it is sent, and a run that returns redact.ErrRunFull
//     stops sending and is reported as incomplete.
//   - Every request is recorded in egress.log, so a user can audit exactly
//     what was sent and where.
//   - It connects only to configured model endpoints; creep has no telemetry.
//
// The client, redaction hook and egress log arrive with the rest of #3; this
// file reserves the package path that the import rule exempts.
package gateway
