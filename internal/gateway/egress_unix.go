//go:build unix

package gateway

import (
	"io/fs"
	"os"
	"syscall"
)

// extraOpenFlags: O_NOFOLLOW refuses a link swapped in after Lstat, and
// O_NONBLOCK makes opening a swapped-in FIFO fail instead of hanging. Both
// are no-ops on the regular files the checks expect.
const extraOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// ownedBySelf reports whether info belongs to the effective user.
func ownedBySelf(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// linkCount returns the number of hard links; a second link would let
// another path, possibly readable by others, alias the log.
func linkCount(info fs.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(st.Nlink) // Nlink is narrower on some platforms
}

// syncDir makes new directory entries durable.
func syncDir(d *os.File) error {
	return d.Sync()
}
