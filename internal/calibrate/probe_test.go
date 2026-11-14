package calibrate

import (
	"reflect"
	"strings"
	"testing"
)

// Probes are creep's text, built to pass redaction unchanged: a marker in
// place of the needle or an argument would fail a model that is right.
func TestProbesPassRedactionUnchanged(t *testing.T) {
	r := newRedactor(t)
	for _, seed := range []uint64{0, 1, 2, 90, 1 << 63} {
		src := probeSource(seed)
		var prompts []string
		for _, p := range toolProbes(src) {
			prompts = append(prompts, p.prompt)
		}
		for _, size := range contextSizes {
			prompts = append(prompts, newContextProbe(src, size).prompt)
		}
		for _, p := range prompts {
			req, err := newRequest(r, purposeContext, contextSystem, p)
			if err != nil {
				t.Fatal(err)
			}
			if req.Prompt != p || len(req.Redactions) != 0 {
				t.Fatalf("seed %d: redaction changed a probe (%v)", seed, req.Redactions)
			}
		}
	}
}

func TestContextProbe(t *testing.T) {
	for _, size := range contextSizes {
		p := newContextProbe(probeSource(7), size)
		if len(p.prompt) < size {
			t.Errorf("probe for %d bytes is %d bytes", size, len(p.prompt))
		}
		m := needlePattern.FindAllStringSubmatch(p.prompt, -1)
		if len(m) != 1 || m[0][2] != p.value {
			t.Fatalf("size %d: want one needle with value %q, got %v", size, p.value, m)
		}
		if strings.Count(p.prompt, p.value) != 1 {
			t.Errorf("size %d: value appears more than once", size)
		}
		at := strings.Index(p.prompt, m[0][0])
		if at < len(p.prompt)/20 || at > len(p.prompt)*19/20 {
			t.Errorf("size %d: needle at byte %d of %d, too near an end", size, at, len(p.prompt))
		}
	}
}

func TestProbesFollowTheSeed(t *testing.T) {
	a, b := toolProbes(probeSource(5)), toolProbes(probeSource(5))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same seed gave different tool probes")
	}
	if reflect.DeepEqual(newContextProbe(probeSource(5), 8<<10), newContextProbe(probeSource(6), 8<<10)) {
		t.Error("different seeds gave the same context probe")
	}
	for _, p := range a {
		if !strings.Contains(p.prompt, p.argument) {
			t.Errorf("probe %q does not hold its argument %q", p.prompt, p.argument)
		}
	}
}
