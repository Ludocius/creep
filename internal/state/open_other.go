//go:build !unix

package state

import (
	"io/fs"
	"os"
)

// nonblockFlag is empty: Windows has no FIFOs that block on open, and the
// regular-file check refuses devices.
const nonblockFlag = 0

// syncDir is a no-op: Windows cannot flush a directory handle, and NTFS
// journals directory entries itself.
func syncDir(*os.Root, string) error { return nil }

// looseMode is not checked off Unix, where permission bits are not ACLs.
func looseMode(fs.FileInfo) bool { return false }
