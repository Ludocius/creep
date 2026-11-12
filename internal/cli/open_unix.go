//go:build unix

package cli

import (
	"os"
	"syscall"
)

// openForCheck opens path without blocking: a plain open of a FIFO waits for a
// writer forever, so creep would hang before it could reject the file.
func openForCheck(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// restoreBlocking puts a file that passed the regular-file check back into
// blocking mode so later reads behave like a plain os.Open.
func restoreBlocking(f *os.File) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = conn.Control(func(fd uintptr) {
		setErr = syscall.SetNonblock(int(fd), false)
	})
	if err != nil {
		return err
	}
	return setErr
}
