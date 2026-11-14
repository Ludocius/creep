package calibrate

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// probeStream is the PCG stream of the probes ("creepprb"), distinct from
// the task stream, so adding a probe never changes the tasks.
const probeStream = 0x6372656570707262

// contextSizes are the input sizes, in bytes, the effective-context probe
// tries in order. Bytes bound tokens from above, so a model that answers at
// a size handles at least that many bytes of code.
var contextSizes = []int{8 << 10, 32 << 10, 128 << 10}

// probeWords are neutral words for probe names and values: no keyword, no
// secret-like shape, so redaction leaves the probes unchanged.
var probeWords = []string{
	"amber", "birch", "cedar", "delta", "ember", "fjord", "garnet", "harbor",
	"indigo", "juniper", "kestrel", "lagoon", "meadow", "nectar", "onyx", "pebble",
}

// toolProbe is one tool-calling question and the call that answers it.
type toolProbe struct {
	prompt   string
	tool     string
	argument string
}

// contextProbe is a long file hiding one assignment, and its value.
type contextProbe struct {
	prompt string
	value  string
}

func probeSource(seed uint64) rand.Source {
	// Not for secrets: probes must be reproducible from the seed.
	return rand.NewPCG(seed, probeStream)
}

func word(src rand.Source) string {
	return probeWords[intN(src, len(probeWords))]
}

// toolProbes returns one probe per tool, with seeded arguments.
func toolProbes(src rand.Source) []toolProbe {
	file := fmt.Sprintf("src/%s/%s.js", word(src), word(src))
	dir := fmt.Sprintf("lib/%s", word(src))
	ident := fmt.Sprintf("%s_%s", word(src), word(src))
	return []toolProbe{
		{prompt: "Show me what is inside the file " + file + ".", tool: toolReadFile, argument: file},
		{prompt: "Which files are in the directory " + dir + "?", tool: toolListDir, argument: dir},
		{prompt: "Where is the function " + ident + " used in the code?", tool: toolSearch, argument: ident},
	}
}

// newContextProbe builds a file of at least size bytes of similar
// assignments with the needle at a seeded line between 10% and 90% of it,
// so neither end of the input gives it away.
func newContextProbe(src rand.Source, size int) contextProbe {
	name := fmt.Sprintf("marker_%s_%s", word(src), word(src))
	value := fmt.Sprintf("%s-%s-%04d", word(src), word(src), intN(src, 10000))
	lines := fillerLines(src, size)
	at := len(lines)/10 + intN(src, len(lines)*8/10+1)
	needle := fmt.Sprintf("let %s = %q;", name, value)
	lines = append(lines[:at], append([]string{needle}, lines[at:]...)...)
	prompt := strings.Join(lines, "\n") + "\n\nQuestion: what string is assigned to " + name + "?"
	return contextProbe{prompt: prompt, value: value}
}

// fillerLines returns distractor assignments totalling at least size bytes.
// Their values have one word, the needle's two, so none can equal it.
func fillerLines(src rand.Source, size int) []string {
	var lines []string
	for n, i := 0, 0; n < size; i++ {
		line := fmt.Sprintf("let v%05d = \"%s-%04d\";", i, word(src), intN(src, 10000))
		lines = append(lines, line)
		n += len(line) + 1
	}
	return lines
}
