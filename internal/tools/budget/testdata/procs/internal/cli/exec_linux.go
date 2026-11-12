//go:build linux

// Fixture: parsed by the budget tests, never built.
package cli

import sc "syscall"

func replace() { sc.Exec("/bin/sh", nil, nil) }
