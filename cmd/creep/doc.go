// Command creep is the entrypoint of the creep CLI.
//
// It only wires the process (arguments, standard streams, exit code) to
// internal/cli so that all behavior stays testable without a binary.
package main
