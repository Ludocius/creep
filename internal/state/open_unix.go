//go:build unix

package state

import (
	"io/fs"
	"os"
	"syscall"
)

// nonblockFlag makes opening a FIFO swapped in after Lstat fail or return
// at once instead of hanging; it is a no-op on regular files.
const nonblockFlag = syscall.O_NONBLOCK

// syncDir makes a rename or new entry in d durable.
func syncDir(root *os.Root, dir string) error {
	d, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// looseMode reports whether group or others can write to a directory, which
// would let another user swap files under creep.
func looseMode(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o022 != 0
}
