package redact

import (
	"errors"
	"fmt"
	"strings"
)

// MaxFileBytes bounds one File call. Ordinary code costs about 1.8 s per MiB
// on a 2019 laptop CPU (BenchmarkFileRepoCode); input crafted to wake every
// rule costs about 7 s per chunk (BenchmarkRedact, "every keyword"), so about
// two minutes at the cap. The whole-file key scan is linear in the file size
// (TestFileBlankTailIsLinear), but lines near MaxLineBytes make chunks overlap
// more, so a crafted file can take several times longer. A larger cap would
// let one hostile file stall a scan for longer; larger files fail closed with
// ErrFileTooLarge.
const MaxFileBytes = 1 << 20

// MaxLineBytes bounds one line of a file given to File, newline included.
// Every line must fit in one chunk with the overlap that precedes it (see
// chunkBounds); longer lines are minified or generated data and fail closed
// with ErrLineTooLong.
const MaxLineBytes = (MaxInputBytes - chunkOverlap) / 2

// chunkOverlap is how far each chunk reaches back into the previous one.
// Every match whose bytes before the start of its last line number at most
// chunkOverlap is seen whole by some chunk (chunkBounds). TestChunkOverlapBound
// derives that reach from each regex's syntax tree: at most 284 bytes for the
// vendored rules and this package's detectors (a key name and a separator
// with a few blanks or newlines), so 4 KiB leaves a wide margin. The rules it
// lists as exempt have no byte bound: the private-key rule (keys are found
// over the whole file first), base64-encoded JWTs wrapped over lines (caught
// by the whole-file key-body detector when wrapped at 40 to 76 columns), the
// two curl rules, which allow five continuation lines of any length and are
// covered while those lines fit in 4 KiB, and three rules that reach further
// only through a run of blanks.
const chunkOverlap = 4 << 10

var (
	// ErrFileTooLarge is returned by File for content over MaxFileBytes.
	ErrFileTooLarge = errors.New("file exceeds redact.MaxFileBytes")
	// ErrLineTooLong is returned by File for a line over MaxLineBytes.
	ErrLineTooLong = errors.New("line exceeds redact.MaxLineBytes")
)

// File redacts a whole file and returns the text that callers may then cut
// into fragments. It fails closed on content over MaxFileBytes or with a line
// over MaxLineBytes.
//
// Private keys are found over the whole file, so a key is masked from its
// BEGIN line to its END line wherever the file is later cut. The other
// detectors run on overlapping chunks of at most MaxInputBytes, cut at line
// ends; their spans are merged over the whole file before any marker is
// written, so a value found by two chunks is masked once, with one marker.
func (r *Redactor) File(content []byte) (string, error) {
	if len(content) > MaxFileBytes {
		return "", fmt.Errorf("redact file of %d bytes: %w", len(content), ErrFileTooLarge)
	}
	text := string(content)
	if n := longestLine(text); n > MaxLineBytes {
		return "", fmt.Errorf("redact file with a %d-byte line: %w", n, ErrLineTooLong)
	}
	return r.finish(text, r.detectFile(text)), nil
}

// detectFile finds private keys over the whole text and runs every other
// detector chunk by chunk, with spans in whole-text offsets. Gates open on
// the whole text, as gitleaks gates on the whole file, so an AWS key id in
// one chunk still wakes the bare secret key detector in another.
func (r *Redactor) detectFile(text string) []span {
	found := findPrivateKeys(text)
	set := r.gated(text)
	for _, c := range chunkBounds(text) {
		for _, sp := range set.find(text[c.start:c.end]) {
			sp.start += c.start
			sp.end += c.start
			found = append(found, sp)
		}
	}
	return found
}

// chunk is a byte range of the text: whole lines, at most MaxInputBytes.
type chunk struct{ start, end int }

// chunkBounds cuts text into chunks of whole lines, at most MaxInputBytes
// each, every chunk starting at the last line start at least chunkOverlap
// bytes before the end of the previous one.
//
// So every line L lies in some chunk together with the chunkOverlap bytes
// before it: take the last chunk k that starts at or before L's start minus
// chunkOverlap; chunk k+1 starts after that point and at least chunkOverlap
// before chunk k's end, so chunk k ends past L's start, and since it ends at
// a line end, past L's end. A match ending on L whose earlier lines span at
// most chunkOverlap bytes is therefore whole in chunk k.
//
// Lines of at most MaxLineBytes guarantee progress: a chunk's end is more than
// MaxInputBytes-MaxLineBytes past its start, so the next start falls after
// the chunk's first line.
func chunkBounds(text string) []chunk {
	var out []chunk
	for start := 0; ; {
		end := lineStartBefore(text, start+MaxInputBytes)
		out = append(out, chunk{start, end})
		if end == len(text) {
			return out
		}
		next := lineStartBefore(text, end-chunkOverlap)
		if next <= start {
			// next <= start means a line over MaxLineBytes, which File
			// rejects; ending here keeps a broken caller from looping.
			return out
		}
		start = next
	}
}

// lineStartBefore returns the last line start at or before pos, or the end
// of text when pos is past it.
func lineStartBefore(text string, pos int) int {
	if pos >= len(text) {
		return len(text)
	}
	return strings.LastIndexByte(text[:pos], '\n') + 1
}

// longestLine returns the length of the longest line, newline included.
func longestLine(text string) int {
	longest := 0
	for len(text) > 0 {
		n := strings.IndexByte(text, '\n') + 1
		if n == 0 {
			n = len(text)
		}
		longest = max(longest, n)
		text = text[n:]
	}
	return longest
}
