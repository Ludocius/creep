package state

import (
	"bytes"
	"fmt"
	"testing"
)

const benchRunID = "20261113T000000Z-00000000"

// BenchmarkDecodeEvents backs the documented worst case: reading a log is
// linear in its size, one bounded, MAC-checked line at a time.
func BenchmarkDecodeEvents(b *testing.B) {
	for _, steps := range []int{1_000, 100_000} {
		var log bytes.Buffer
		log.Write(signedLog(benchRunID, startLine))
		for i := range steps {
			line := fmt.Sprintf(`{"v":1,"seq":%d,"kind":"step","step":"route:%d"}`, i+2, i)
			log.Write(signedLog(benchRunID, line+"\n"))
		}
		b.Run(fmt.Sprintf("steps=%d", steps), func(b *testing.B) {
			b.SetBytes(int64(log.Len()))
			for b.Loop() {
				if _, err := decodeEvents(bytes.NewReader(log.Bytes()), testSecret, benchRunID); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
