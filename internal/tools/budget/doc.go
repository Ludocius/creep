// Command budget enforces creep's supply-chain and size budget in CI.
//
// creep reads untrusted source code and talks to model endpoints, so every
// dependency is attack surface. Reviews miss slow growth, so this tool fails
// the build when a direct dependency lacks an ADR, the module graph or the
// release binary outgrows its cap, a Go file passes 400 lines, or a workflow
// uses pull_request_target or an action not pinned by commit SHA.
//
// It is stdlib-only and runs with `make budget`.
package main
