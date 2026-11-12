// Package cli parses the command line and dispatches to subcommands.
//
// It exists so that main stays a one-liner and the whole command surface
// (global flags, subcommands, usage text and exit codes) can be exercised in
// tests through Run without building or spawning a binary. It uses only the
// standard library flag package; no third-party CLI framework.
package cli
