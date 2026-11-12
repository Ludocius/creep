//go:build unix

// Fixture: parsed by the budget tests, never built. The name matches a
// syscall allowlist entry, so only the call is reported.
package cli

import "syscall"

func spawn() { syscall.ForkExec("/bin/sh", nil, nil) }
