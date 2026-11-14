package calibrate

import (
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
)

// TaskCount is how many tasks Generate returns: half vulnerable, half safe.
const TaskCount = 100

const (
	// maxFillers caps the neutral lines a mutation inserts before the sink.
	maxFillers = 3
	// maxDraws bounds the redraws when a mutation repeats an earlier task.
	maxDraws = 64
	// pcgStream fixes the PCG stream ("creepv01"), so the seed alone picks
	// the sequence. Changing it changes every task.
	pcgStream = 0x6372656570763031
)

// mutation is one draw for a template: a value per slot and the filler
// lines to insert.
type mutation struct {
	values  map[string]string
	fillers []string
}

// Generate returns TaskCount calibration tasks for seed. The same seed gives
// the same tasks on every platform; different seeds give different
// mutations. Every template contributes vulnerable and safe tasks in equal
// numbers, and no two tasks have the same code.
func Generate(seed uint64) ([]Task, error) {
	cat, err := defaultCatalog()
	if err != nil {
		return nil, err
	}
	return generate(cat, seed)
}

func generate(cat catalog, seed uint64) ([]Task, error) {
	// Not for secrets: calibration must be reproducible from the seed.
	src := rand.NewPCG(seed, pcgStream)
	seen := make(map[string]bool, TaskCount)
	tasks := make([]Task, 0, TaskCount)
	for i := range TaskCount {
		tpl := cat.templates[(i/2)%len(cat.templates)]
		task, err := drawUnique(src, tpl, cat.fillers[tpl.language], i%2 == 0, seen)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	shuffle(src, tasks)
	for i := range tasks {
		tasks[i].ID = fmt.Sprintf("task-%03d", i)
	}
	return tasks, nil
}

// drawUnique renders mutations until one yields code no earlier task has.
func drawUnique(src rand.Source, tpl template, fillers []string, vulnerable bool, seen map[string]bool) (Task, error) {
	for range maxDraws {
		task := render(tpl, vulnerable, drawMutation(src, tpl, fillers))
		if !seen[task.Code] {
			seen[task.Code] = true
			return task, nil
		}
	}
	return Task{}, fmt.Errorf("calibration template %s: no new mutation after %d draws", tpl.id, maxDraws)
}

func drawMutation(src rand.Source, tpl template, fillers []string) mutation {
	m := mutation{values: make(map[string]string, len(tpl.slotNames))}
	for _, name := range tpl.slotNames {
		pool := tpl.slots[name]
		m.values[name] = pool[intN(src, len(pool))]
	}
	order := make([]int, len(fillers))
	for i := range order {
		order[i] = i
	}
	n := intN(src, min(maxFillers, len(fillers))+1)
	for i := range n {
		j := i + intN(src, len(order)-i)
		order[i], order[j] = order[j], order[i]
		m.fillers = append(m.fillers, fillers[order[i]])
	}
	return m
}

// render inserts the fillers after tpl.padAfter lines, which validation put
// before the sink, so the sink moves down by exactly len(m.fillers).
func render(tpl template, vulnerable bool, m mutation) Task {
	v := tpl.variant(vulnerable)
	lines := make([]string, 0, len(v.lines)+len(m.fillers))
	lines = append(lines, v.lines[:tpl.padAfter]...)
	lines = append(lines, m.fillers...)
	lines = append(lines, v.lines[tpl.padAfter:]...)
	pairs := make([]string, 0, 2*len(tpl.slotNames))
	for _, name := range tpl.slotNames {
		pairs = append(pairs, placeholderMark+name+placeholderMark, m.values[name])
	}
	return Task{
		Template:   tpl.id,
		Class:      tpl.class,
		Language:   tpl.language,
		Vulnerable: vulnerable,
		Line:       v.sinkLine + len(m.fillers),
		Code:       strings.NewReplacer(pairs...).Replace(strings.Join(lines, "\n") + "\n"),
	}
}

// shuffle is a Fisher-Yates shuffle over intN, so the order depends only on
// the source, not on rand.Shuffle's algorithm.
func shuffle(src rand.Source, tasks []Task) {
	for i := len(tasks) - 1; i > 0; i-- {
		j := intN(src, i+1)
		tasks[i], tasks[j] = tasks[j], tasks[i]
	}
}

// intN returns a uniform value in [0, n) for n > 0. It rejects the top
// 2^64 mod n source values instead of using rand.Rand.IntN, whose algorithm
// Go does not promise to keep across releases.
func intN(src rand.Source, n int) int {
	if n <= 0 {
		panic("calibrate: intN needs n > 0")
	}
	bound := uint64(n)
	reject := (math.MaxUint64%bound + 1) % bound // 2^64 mod n
	for {
		v := src.Uint64()
		if v <= math.MaxUint64-reject {
			return int(v % bound) //nolint:gosec // G115: v % bound < n, so it fits in int
		}
	}
}
