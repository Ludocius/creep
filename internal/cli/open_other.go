//go:build !unix

package cli

import "os"

// openForCheck is a plain open: Windows has no FIFOs that block on open, and
// devices such as NUL or CON are rejected by the regular-file check.
func openForCheck(path string) (*os.File, error) {
	return os.Open(path)
}

func restoreBlocking(*os.File) error { return nil }
