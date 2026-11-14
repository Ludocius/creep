package state

import (
	"bytes"
	"fmt"
	"testing"
)

// BenchmarkDecodeEvents backs the documented worst case: reading a log is
// linear in its size, one bounded line at a time.
func BenchmarkDecodeEvents(b *testing.B) {
	for _, steps := range []int{1_000, 100_000} {
		var log bytes.Buffer
		log.WriteString(startLine)
		for i := range steps {
			fmt.Fprintf(&log, `{"v":1,"seq":%d,"kind":"step","step":"route:%d"}`+"\n", i+2, i)
		}
		b.Run(fmt.Sprintf("steps=%d", steps), func(b *testing.B) {
			b.SetBytes(int64(log.Len()))
			for b.Loop() {
				if _, err := decodeEvents(bytes.NewReader(log.Bytes())); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
