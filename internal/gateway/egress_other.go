//go:build !unix

package gateway

import (
	"io/fs"
	"os"
)

// extraOpenFlags is empty: Windows has no O_NOFOLLOW; the same-file check
// after open still catches a swapped log.
const extraOpenFlags = 0

// ownedBySelf is not checked off Unix; checkAccess skips Windows.
func ownedBySelf(fs.FileInfo) bool { return true }

// linkCount is not checked off Unix; checkLogFile skips Windows.
func linkCount(fs.FileInfo) uint64 { return 1 }

// syncDir is a no-op: Windows cannot flush a directory handle, and NTFS
// journals directory entries itself.
func syncDir(*os.File) error { return nil }
