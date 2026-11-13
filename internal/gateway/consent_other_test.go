//go:build !unix

package gateway

import "testing"

func mkfifo(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no FIFOs on this platform")
}
