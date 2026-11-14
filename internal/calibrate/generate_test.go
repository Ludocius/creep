package calibrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func mustGenerate(t *testing.T, seed uint64) []Task {
	t.Helper()
	tasks, err := Generate(seed)
	if err != nil {
		t.Fatalf("Generate(%d): %v", seed, err)
	}
	return tasks
}

func hashTasks(t *testing.T, tasks []Task) string {
	t.Helper()
	data, err := json.Marshal(tasks)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// invariantSeeds covers the edges (0, max) and a spread in between.
func invariantSeeds() []uint64 {
	seeds := []uint64{0, 1, math.MaxUint64, math.MaxUint64 - 1, 1 << 63, 0xdeadbeef}
	for s := uint64(2); s < 40; s++ {
		seeds = append(seeds, s)
	}
	return seeds
}

// TestGenerateGolden pins the output across Go versions and platforms. A
// template or algorithm change updates these hashes on purpose, and the PR
// carries the affects-results label.
func TestGenerateGolden(t *testing.T) {
	golden := map[uint64]string{
		0:              "b6e3b05545da34ba6d79d211812b5d940883390e936e28995d0954a35a73b494",
		1:              "28cf64d2552276273a01424b6a7194b46336354c595cf2768b27a1224cbd6bf0",
		42:             "27dd34b25d95829d9551c3d61cbc4bef3b9878227fcb31e8aba5c86830b338ed",
		math.MaxUint64: "0e16712bd6c73bfca47e0a3d0964518a23d771d84dedff92ecf685f1915f1757",
	}
	for seed, want := range golden {
		if got := hashTasks(t, mustGenerate(t, seed)); got != want {
			t.Errorf("Generate(%d) hash = %s, want %s", seed, got, want)
		}
	}
}

func TestGenerateSameSeedSameTasks(t *testing.T) {
	for _, seed := range []uint64{0, 1, math.MaxUint64} {
		a, b := mustGenerate(t, seed), mustGenerate(t, seed)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("Generate(%d) differs between calls", seed)
		}
	}
}

func TestGenerateDifferentSeedsDifferentMutations(t *testing.T) {
	seen := map[string]uint64{}
	for _, seed := range invariantSeeds() {
		h := hashTasks(t, mustGenerate(t, seed))
		if prev, dup := seen[h]; dup {
			t.Errorf("seeds %d and %d give the same tasks", prev, seed)
		}
		seen[h] = seed
	}
	// Shuffling alone must not be the only difference: the code itself
	// changes between seeds, not just its order.
	codes := func(seed uint64) map[string]bool {
		m := map[string]bool{}
		for _, task := range mustGenerate(t, seed) {
			m[task.Code] = true
		}
		return m
	}
	a, b := codes(0), codes(1)
	if reflect.DeepEqual(a, b) {
		t.Error("seeds 0 and 1 give the same set of code")
	}
}

func TestGenerateInvariants(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]template{}
	for _, tpl := range cat.templates {
		byID[tpl.id] = tpl
	}
	for _, seed := range invariantSeeds() {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			tasks := mustGenerate(t, seed)
			checkShape(t, tasks)
			checkBalance(t, tasks, len(cat.templates))
			for _, task := range tasks {
				checkGroundTruth(t, task, byID[task.Template])
			}
		})
	}
}

func checkShape(t *testing.T, tasks []Task) {
	t.Helper()
	if len(tasks) != TaskCount {
		t.Fatalf("got %d tasks, want %d", len(tasks), TaskCount)
	}
	codes := map[string]string{}
	for i, task := range tasks {
		if want := fmt.Sprintf("task-%03d", i); task.ID != want {
			t.Errorf("task %d ID = %q, want %q", i, task.ID, want)
		}
		if prev, dup := codes[task.Code]; dup {
			t.Errorf("%s duplicates the code of %s", task.ID, prev)
		}
		codes[task.Code] = task.ID
	}
}

// checkBalance wants half vulnerable, every template in both labels, and
// no template more than one pair ahead of another.
func checkBalance(t *testing.T, tasks []Task, templates int) {
	t.Helper()
	perLabel := map[bool]int{}
	perTemplate := map[string]map[bool]int{}
	for _, task := range tasks {
		perLabel[task.Vulnerable]++
		if perTemplate[task.Template] == nil {
			perTemplate[task.Template] = map[bool]int{}
		}
		perTemplate[task.Template][task.Vulnerable]++
	}
	if perLabel[true] != TaskCount/2 || perLabel[false] != TaskCount/2 {
		t.Errorf("labels = %v, want %d each", perLabel, TaskCount/2)
	}
	if len(perTemplate) != templates {
		t.Errorf("%d templates used, want all %d", len(perTemplate), templates)
	}
	lo, hi := TaskCount/2/templates, (TaskCount/2+templates-1)/templates
	for id, n := range perTemplate {
		if n[true] != n[false] || n[true] < lo || n[true] > hi {
			t.Errorf("template %s: %d vulnerable, %d safe; want equal, in %d..%d", id, n[true], n[false], lo, hi)
		}
	}
}

// checkGroundTruth re-derives the label and location from the template: the
// task carries its own variant's marker and not its twin's, and the line at
// task.Line is the template's sink line with only identifiers substituted.
func checkGroundTruth(t *testing.T, task Task, tpl template) {
	t.Helper()
	if task.Class != tpl.class || task.Language != tpl.language {
		t.Errorf("%s: class/language %s/%s, template says %s/%s", task.ID, task.Class, task.Language, tpl.class, tpl.language)
	}
	own, twin := tpl.variant(task.Vulnerable), tpl.variant(!task.Vulnerable)
	if !strings.Contains(task.Code, own.marker) || strings.Contains(task.Code, twin.marker) {
		t.Errorf("%s (%s, vulnerable=%v): mutation changed the label", task.ID, task.Template, task.Vulnerable)
	}
	if strings.Contains(task.Code, placeholderMark) {
		t.Errorf("%s: unsubstituted placeholder", task.ID)
	}
	lines := splitLines(task.Code)
	if task.Line < 1 || task.Line > len(lines) {
		t.Fatalf("%s: line %d outside 1..%d", task.ID, task.Line, len(lines))
	}
	if !sinkPattern(own.lines[own.sinkLine-1]).MatchString(lines[task.Line-1]) {
		t.Errorf("%s: line %d is %q, not the template sink %q", task.ID, task.Line, lines[task.Line-1], own.lines[own.sinkLine-1])
	}
}

// sinkPattern matches a template line with each placeholder standing for one
// identifier.
func sinkPattern(line string) *regexp.Regexp {
	parts := placeholderRe.Split(line, -1)
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile("^" + strings.Join(parts, `[A-Za-z][A-Za-z0-9_]*`) + "$")
}

// Tasks go to whatever model the user configured, so they must not carry a
// real host, URL, IP address or anything shaped like a credential.
func TestGenerateHasNoHostsOrSecrets(t *testing.T) {
	forbidden := map[string]*regexp.Regexp{
		"URL":         regexp.MustCompile(`[a-z]+://`),
		"IPv4":        regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`),
		"public host": regexp.MustCompile(`\b[a-z0-9-]+\.(com|net|org|io|dev|app|cloud|internal|local)\b`),
		"long token":  regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`),
	}
	hostRe := regexp.MustCompile(`"[a-z0-9-]+(\.[a-z0-9-]+)+"`)
	for _, seed := range []uint64{0, 1, math.MaxUint64} {
		for _, task := range mustGenerate(t, seed) {
			for name, re := range forbidden {
				if m := re.FindString(task.Code); m != "" {
					t.Errorf("seed %d %s: %s %q", seed, task.ID, name, m)
				}
			}
			for _, host := range hostRe.FindAllString(task.Code, -1) {
				if !strings.HasSuffix(host, `.invalid"`) && !strings.HasSuffix(host, `.db"`) && !strings.HasSuffix(host, `.tgz"`) {
					t.Errorf("seed %d %s: host-like string %s outside .invalid", seed, task.ID, host)
				}
			}
		}
	}
}

func TestGenerateFailsWhenMutationsRunOut(t *testing.T) {
	cat, err := loadCatalog(testFS(nil))
	if err != nil {
		t.Fatal(err)
	}
	// One template with two names and one filler has far fewer distinct
	// tasks than the 50 per label a run needs.
	_, err = generate(cat, 0)
	if err == nil || !strings.Contains(err.Error(), "py-test") {
		t.Fatalf("err = %v, want exhaustion error naming the template", err)
	}
}

// fixedSource replays values, so intN's rejection path is reachable.
type fixedSource struct{ values []uint64 }

func (s *fixedSource) Uint64() uint64 {
	v := s.values[0]
	s.values = s.values[1:]
	return v
}

func TestIntN(t *testing.T) {
	tests := []struct {
		name   string
		n      int
		values []uint64
		want   int
	}{
		{"n=1 is always 0", 1, []uint64{math.MaxUint64}, 0},
		{"power of two keeps every value", 4, []uint64{math.MaxUint64}, 3},
		// 2^64 mod 3 = 1, so MaxUint64 is the one rejected value.
		{"biased top value is redrawn", 3, []uint64{math.MaxUint64, 5}, 2},
		{"value under the cut is kept", 3, []uint64{math.MaxUint64 - 1}, int((math.MaxUint64 - 1) % 3)},
		{"max int bound", math.MaxInt, []uint64{math.MaxUint64, 7}, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &fixedSource{values: tt.values}
			if got := intN(src, tt.n); got != tt.want {
				t.Errorf("intN = %d, want %d", got, tt.want)
			}
			if len(src.values) != 0 {
				t.Errorf("%d source values unused", len(src.values))
			}
		})
	}
}

func TestIntNRefusesEmptyRange(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("intN(%d) did not panic", n)
				}
			}()
			intN(&fixedSource{values: []uint64{1}}, n)
		}()
	}
}
