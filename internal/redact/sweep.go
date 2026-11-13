package redact

import (
	"crypto/rand"
	"errors"
	"math/bits"
)

// minSweepLen is the shortest known value re-masked wherever it appears.
// Shorter values would match inside ordinary identifiers. It is also the
// width of the window that indexes each value.
const minSweepLen = 8

// The run's value map is bounded so a hostile repository cannot grow memory
// or the sweep without limit. Every masked value counts, by entries and by
// bytes: since File stores an unterminated private key as one value of up
// to MaxFileBytes, a count alone would not bound memory.
const (
	maxRunValues = 1 << 17
	maxRunBytes  = 32 << 20
	// maxWindowValues bounds the values indexed under one 8-byte window, so
	// each text position checks at most this many candidates. A value takes
	// its least crowded window.
	maxWindowValues = 16
	// maxOverflowValues bounds the values whose every window is full (runs of
	// one byte or one short pattern, such as "xxxxxxxx" placeholders). They
	// are checked at every position, so this bounds that cost too; only when
	// it is also full does the run end.
	maxOverflowValues = 256
)

// ErrRunFull is returned once the run's value map reaches its cap (about
// 128k values or 32 MiB of values). The call that reaches it returns no
// output, and so does every later Redact or File call on the same Redactor,
// because a value it could not remember would not be re-masked in later
// fragments. Callers must stop sending fragments of that run, report the scan
// as incomplete and start a new run with a new Redactor if they continue.
var ErrRunFull = errors.New("redact: run value map is full")

// hashMod is the Mersenne prime 2^61-1: products reduce with shifts.
const hashMod = 1<<61 - 1

// sweepIndex finds known values in text in time linear in the text: each
// value is indexed under one 8-byte window it contains, and a polynomial
// hash of the text's prefixes checks a candidate in constant time.
type sweepIndex struct {
	base          uint64
	values        []sweepValue
	windows       map[uint64][]int // window bytes -> value ids
	overflow      [256][]int       // first byte -> ids of values whose every window was full
	overflowCount int
}

// sweepValue is a known value: its length, where its window starts, its hash
// and base^length, which lifts a prefix hash past it.
type sweepValue struct {
	length, offset int
	hash, scale    uint64
}

// newSweepIndex picks a random hash base, so input cannot be crafted to
// collide. A collision would only mask more.
func newSweepIndex() sweepIndex {
	return sweepIndex{
		base:    randomBase(),
		windows: map[uint64][]int{},
	}
}

// randomBase returns a base in [256, hashMod): above every byte value.
func randomBase() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:]) // never fails since Go 1.24
	return window(string(b[:]), 0)%(hashMod-256) + 256
}

// add indexes value under its least crowded window, or in the overflow list
// when every window already holds maxWindowValues values. It reports false
// only when the overflow list is full too.
func (x *sweepIndex) add(value string) bool {
	offset, crowd := 0, maxWindowValues
	for i := 0; i+minSweepLen <= len(value) && crowd > 0; i++ {
		if n := len(x.windows[window(value, i)]); n < crowd {
			offset, crowd = i, n
		}
	}
	id := len(x.values)
	switch {
	case crowd < maxWindowValues:
		w := window(value, offset)
		x.windows[w] = append(x.windows[w], id)
	case x.overflowCount < maxOverflowValues:
		offset = 0
		x.overflow[value[0]] = append(x.overflow[value[0]], id)
		x.overflowCount++
	default:
		return false
	}
	hash, scale := x.hashOf(value)
	x.values = append(x.values, sweepValue{length: len(value), offset: offset, hash: hash, scale: scale})
	return true
}

// sweepScan is the state of one find: the text's prefix hashes and where
// each value's last occurrence ends.
type sweepScan struct {
	x        *sweepIndex
	text     string
	prefix   []uint64
	nextFree map[int]int // value id -> end of its last occurrence
	found    []span
}

// find returns every occurrence of a known value in text. Like a search per
// value, occurrences of one value do not overlap; occurrences of different
// values may. Each position checks at most maxWindowValues values from its
// window plus the overflow values that start with the byte at that position.
func (x *sweepIndex) find(text string) []span {
	if len(x.values) == 0 || len(text) < minSweepLen {
		return nil
	}
	s := sweepScan{x: x, text: text, prefix: x.prefixHashes(text), nextFree: map[int]int{}}
	for p := 0; p+minSweepLen <= len(text); p++ {
		s.check(p, x.windows[window(text, p)])
		s.check(p, x.overflow[text[p]])
	}
	return s.found
}

// check records each value among ids that occurs with its window at p.
func (s *sweepScan) check(p int, ids []int) {
	for _, id := range ids {
		v := s.x.values[id]
		start := p - v.offset
		end := start + v.length
		if start < 0 || end > len(s.text) || substringHash(s.prefix, start, end, v.scale) != v.hash {
			continue
		}
		if start >= s.nextFree[id] {
			s.found = append(s.found, span{start: start, end: end})
			s.nextFree[id] = end
		}
	}
}

// window reads the 8 bytes of s at i as one map key.
func window(s string, i int) uint64 {
	s = s[i : i+minSweepLen]
	return uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
		uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56
}

// hashOf returns the hash of s and base^len(s).
func (x *sweepIndex) hashOf(s string) (hash, scale uint64) {
	scale = 1
	for i := 0; i < len(s); i++ {
		hash = reduce(mulMod(hash, x.base) + uint64(s[i]) + 1)
		scale = mulMod(scale, x.base)
	}
	return hash, scale
}

// prefixHashes returns the hash of every prefix of text, by length.
func (x *sweepIndex) prefixHashes(text string) []uint64 {
	h := make([]uint64, len(text)+1)
	for i := 0; i < len(text); i++ {
		h[i+1] = reduce(mulMod(h[i], x.base) + uint64(text[i]) + 1)
	}
	return h
}

// substringHash returns the hash of text[start:end] given its prefix hashes
// and base^(end-start).
func substringHash(prefix []uint64, start, end int, scale uint64) uint64 {
	return reduce(prefix[end] + hashMod - mulMod(prefix[start], scale))
}

// mulMod returns a*b mod hashMod for a, b < hashMod: 2^64 is 8 mod hashMod.
func mulMod(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return reduce(hi<<3 | lo>>61 + lo&hashMod)
}

// reduce maps x < 2^63 to x mod hashMod.
func reduce(x uint64) uint64 {
	x = x&hashMod + x>>61
	if x >= hashMod {
		x -= hashMod
	}
	return x
}
