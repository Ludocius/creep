// Package exitcode defines the process exit codes of creep.
//
// CI pipelines branch on these values, so they are a public contract: they
// live in one place, never change meaning, and are rendered into --help from
// the same table so documentation cannot drift from behavior.
package exitcode
