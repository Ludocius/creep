// Command budget enforces creep's supply-chain and size budget in CI.
//
// creep reads untrusted source code and talks to model endpoints, so every
// dependency is attack surface. Reviews miss slow growth, so this tool fails
// the build when a direct dependency lacks an ADR, code outside the
// module-root internal/gateway imports a package that can reach the network
// (net, crypto/tls, syscall, unsafe, cgo, os/exec outside an allowlist…), the
// module graph or the release binary outgrows its cap, a Go file passes 400
// lines, or a workflow uses pull_request_target or an action or image not
// pinned immutably.
//
// It is stdlib-only and runs with `make budget`.
package main
