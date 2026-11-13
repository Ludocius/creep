// Command budget enforces creep's supply-chain and size budget in CI.
//
// creep reads untrusted source code and talks to model endpoints, so every
// dependency is attack surface. Reviews miss slow growth, so this tool fails
// the build when a direct dependency lacks an ADR, code outside the
// module-root internal/gateway imports a package that can reach the network
// (net, crypto/tls, syscall, unsafe, cgo, os/exec outside an allowlist…) or
// calls os.StartProcess or os.NewFile, the repository holds non-Go sources
// (assembly, C, .syso…), a go.work, vendor/ or a local replace, a package
// imports outside the layers table of docs/architecture.md, the module graph
// or the release binary outgrows its cap, or a workflow uses
// pull_request_target, an action or image not pinned immutably, or YAML a
// line scan cannot resolve.
//
// It is a static backstop, not a sandbox: it reads source text and cannot see
// everything a determined author can hide. Code review and CODEOWNERS remain
// required, and zizmor and actionlint in CI are the authoritative workflow
// checks.
//
// It is stdlib-only and runs with `make budget`.
package main
