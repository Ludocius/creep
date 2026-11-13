package redact

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// emailFragment holds n distinct email addresses that no other fragment
// holds: each one becomes a new value in the run's map.
func emailFragment(id, n int) string {
	var b strings.Builder
	for j := range n {
		fmt.Fprintf(&b, "contact user%dx%d@example.com today\n", id, j)
	}
	return b.String()
}

// BenchmarkSweepGrowth redacts one fragment after a run has already seen
// many fragments of distinct values. The time per fragment must not grow
// with the number of values seen (issue #69).
func BenchmarkSweepGrowth(b *testing.B) {
	const perFragment = 1500
	probe := emailFragment(-1, perFragment)
	for _, seen := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("seen=%d", seen*perFragment), func(b *testing.B) {
			r := newRedactor(b)
			for i := range seen {
				mustRedact(b, r, emailFragment(i, perFragment))
			}
			b.SetBytes(int64(len(probe)))
			for b.Loop() {
				mustRedact(b, r, probe)
			}
		})
	}
}

// BenchmarkRedactRepoChunk reports the median time of one Redact call on a
// full-size chunk of the repository's own code, the ordinary input.
func BenchmarkRedactRepoChunk(b *testing.B) {
	chunks := repoChunks(b)
	r := newRedactor(b)
	var times []time.Duration
	for b.Loop() {
		for _, c := range chunks {
			start := time.Now()
			mustRedact(b, r, c)
			times = append(times, time.Since(start))
		}
	}
	slices.Sort(times)
	b.ReportMetric(float64(times[len(times)/2].Nanoseconds()), "median-ns/chunk")
}
