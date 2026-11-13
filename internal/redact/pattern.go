package redact

import "regexp"

// patternDetector finds one kind of value with a regex written by this
// package (PII and credential shapes the gitleaks rules miss).
//
// valid, when set, rejects candidates whose checksum or structure is wrong,
// which keeps ordinary numbers and code in the input unmasked. when, when set,
// must match somewhere in the input before re runs: it is a cheap gate for
// detectors that only make sense in some context.
type patternDetector struct {
	label string
	re    *regexp.Regexp
	valid func(string) bool
	when  *regexp.Regexp
}

// applies reports whether the context gate, if any, matches text.
func (d patternDetector) applies(text string) bool {
	return d.when == nil || d.when.MatchString(text)
}

// scan returns the spans of valid values, ignoring the context gate: the
// first group that matched, so a pattern can offer quoted and unquoted
// alternatives. Patterns may start with one boundary character; scan pads
// the text with newlines so boundaries also hold at both ends. Each search
// restarts at the end of the previous value, so its trailing boundary
// character can lead the next match ("a@b.io,c@d.io"); every step advances,
// so the scan stays linear.
func (d patternDetector) scan(text string) []span {
	padded := "\n" + text + "\n"
	var out []span
	for pos := 0; pos < len(padded); {
		m := d.re.FindStringSubmatchIndex(padded[pos:])
		if m == nil {
			break
		}
		start, end := firstGroup(m)
		next := pos + max(end, m[0]+1)
		start, end, pos = pos+start, pos+end, next
		if start == end || (d.valid != nil && !d.valid(padded[start:end])) {
			continue
		}
		out = append(out, span{start: start - 1, end: end - 1, label: d.label})
	}
	return out
}

// firstGroup returns the bounds of the first group that took part in the
// match, else of the whole match.
func firstGroup(m []int) (int, int) {
	for g := 2; g+1 < len(m); g += 2 {
		if m[g] >= 0 {
			return m[g], m[g+1]
		}
	}
	return m[0], m[1]
}
