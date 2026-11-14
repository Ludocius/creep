// Package static parses repository files into syntax trees so creep can find
// routes, sinks and auth checks without running the scanned code.
//
// It exists because the planner needs structure, not text: later passes
// (#86, #87) turn these trees into IDs and enums. Parsing uses tree-sitter
// grammars compiled to WebAssembly and run by wazero, so the binary stays
// static (CGO_ENABLED=0) and a parser bug triggered by a hostile file stays
// inside a sandbox with no file system, network, clock or environment
// (ADR 0008).
//
// Each parse gets a fresh module instance with a memory cap, a node cap and a
// deadline, and the host validates every record the guest returns before it
// builds a Tree. A Tree holds grammar node types and byte offsets only; the
// source text stays in the caller's buffer.
package static
