// Package report turns a run's results into the three report formats: SARIF
// 2.1.0 (for GitHub code scanning), JSON (schema_version 1, published in
// docs/schemas/report-v1.json) and Markdown.
//
// It exists because honesty about coverage is the product: one package owns
// how covered, partial and not evaluated work is shown, so the three formats
// cannot disagree about it.
//
// What it guarantees:
//   - Every finding has one of four statuses: verified, probable, discarded
//     or not evaluated. Every class is covered, partial or not evaluated.
//   - Every file the gateway did not scan is listed as not evaluated with its
//     closed-enum reason. An unknown reason is an error, never dropped.
//   - An incomplete run (the scan stopped, or the run state did not end
//     complete) is marked incomplete in all three formats, and no class of
//     it reads as covered: covered becomes partial. Callers map it to
//     exitcode.Incomplete through exitcode.ForReport, never to 0.
//   - Strings that come from the scanned repository or from egress.log
//     (paths, endpoints, models, labels) are escaped before they reach
//     Markdown: each is printed as a code span with control, format and bidi
//     runes shown as escapes, so no file name can inject markup, links or
//     terminal sequences. SARIF URIs are percent-encoded; JSON escaping is
//     encoding/json's.
//   - Output is deterministic (no clock, sorted findings), so a replayed run
//     renders byte-identical reports.
//
// SARIF carries only verified (level error) and probable (level warning)
// findings as results; discarded and not evaluated ones would read as open
// alerts in code scanning, so they appear only in JSON and Markdown, and
// not-evaluated files appear as SARIF tool notifications.
//
// The data-handling section is summarized from egress.log (SummarizeEgress):
// requests, bytes, models, outcomes, tokens and redaction counts per
// endpoint. The reader is bounded and fails closed on any line it cannot
// account for, because an understated summary would misreport what left the
// machine.
package report
