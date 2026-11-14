package calibrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

// PromptVersion names the prompts in prompts/ and the scoring rules. A
// change to either changes results, so it bumps this and needs the
// affects-results label.
const PromptVersion = 1

// lineTolerance is how far an answer's line may be from the task's sink
// line and still count: a model may point at the source line just above
// the sink rather than at the sink itself.
const lineTolerance = 2

// Purposes logged in egress.log for each kind of calibration call.
const (
	purposeTask    = "calibrate-task"
	purposeTool    = "calibrate-tool"
	purposeContext = "calibrate-context"
)

// ErrOptions means Run got an unusable Options.
var ErrOptions = errors.New("invalid calibration options")

// Options configures Run.
type Options struct {
	Seed uint64
	// Model sends every call through the gateway: in production its
	// SendFunc is models.Through(egressLog, client).
	Model *models.HTTP
	// Redactor is the run's redactor. Every prompt is passed whole through
	// its File before it is sent, like a repository file.
	Redactor *redact.Redactor
}

// Result is one model's calibration. Seed and TaskSet identify the tasks
// it was measured on, so a cached result is only reused for the same ones.
type Result struct {
	Seed          uint64          `json:"seed"`
	TaskSet       string          `json:"task_set"` // sha256 of the tasks as JSON
	PromptVersion int             `json:"prompt_version"`
	Tier          Tier            `json:"tier"`
	Overall       Score           `json:"overall"`
	Classes       []ClassScore    `json:"classes"`
	Structured    StructuredCheck `json:"structured_output"`
	Tools         ToolCheck       `json:"tool_calling"`
	Context       ContextCheck    `json:"effective_context"`
}

// Run generates the tasks for opts.Seed, asks the model about each, runs the
// tool-calling and context probes, and assigns a tier. Calls are made one at
// a time in a fixed order, so a recorded run replays exactly.
//
// A task reply that stays invalid after the model's retries counts as a
// wrong answer and against the structured-output check. Any other failure
// (consent, budget, transport, status, redaction, ctx) ends the run with an
// error and no Result: a partial calibration never yields a tier.
func Run(ctx context.Context, opts Options) (Result, error) {
	tasks, err := Generate(opts.Seed)
	if err != nil {
		return Result{}, err
	}
	return run(ctx, opts, tasks)
}

func run(ctx context.Context, opts Options, tasks []Task) (Result, error) {
	if opts.Model == nil || opts.Redactor == nil {
		return Result{}, fmt.Errorf("%w: model and redactor are required", ErrOptions)
	}
	if len(tasks) == 0 {
		return Result{}, fmt.Errorf("%w: no tasks", ErrOptions)
	}
	correct, invalid, err := answerTasks(ctx, opts, tasks)
	if err != nil {
		return Result{}, err
	}
	src := probeSource(opts.Seed)
	tools, err := runToolProbes(ctx, opts, toolProbes(src))
	if err != nil {
		return Result{}, err
	}
	effective, err := runContextProbes(ctx, opts, src)
	if err != nil {
		return Result{}, err
	}
	r := Result{
		Seed: opts.Seed, TaskSet: taskSetHash(tasks), PromptVersion: PromptVersion,
		Structured: newStructuredCheck(len(tasks), invalid),
		Tools:      tools,
		Context:    ContextCheck{EffectiveBytes: effective},
	}
	r.Classes, r.Overall = scoreClasses(tasks, correct)
	r.Tier = assignTier(r)
	return r, nil
}

// answerTasks asks about each task in order and judges every answer.
func answerTasks(ctx context.Context, opts Options, tasks []Task) ([]bool, int, error) {
	correct := make([]bool, len(tasks))
	invalid := 0
	for i, task := range tasks {
		req, err := newRequest(opts.Redactor, purposeTask, taskSystem, numberLines(task.Code))
		if err != nil {
			return nil, 0, fmt.Errorf("calibrate %s: %w", task.ID, err)
		}
		req.Schema, req.Grammar = taskSchema(), taskGrammar()
		a, err := models.Complete[taskAnswer](ctx, opts.Model, req)
		if errors.Is(err, models.ErrInvalidOutput) {
			invalid++
			continue
		}
		if err != nil {
			return nil, 0, fmt.Errorf("calibrate %s: %w", task.ID, err)
		}
		correct[i] = judge(task, a)
	}
	return correct, invalid, nil
}

// judge scores one answer. A safe twin is right only when the model calls
// it safe: a finding of any class there is a false positive (#162 keeps
// twins clean in every class). A vulnerable task needs the class and a line
// within lineTolerance of the sink.
func judge(task Task, a taskAnswer) bool {
	if !task.Vulnerable {
		return !a.Vulnerable
	}
	if !a.Vulnerable || Class(a.Class) != task.Class {
		return false
	}
	return a.Line >= task.Line-lineTolerance && a.Line <= task.Line+lineTolerance
}

func runToolProbes(ctx context.Context, opts Options, probes []toolProbe) (ToolCheck, error) {
	correct := 0
	for _, p := range probes {
		req, err := newRequest(opts.Redactor, purposeTool, toolsSystem, p.prompt)
		if err != nil {
			return ToolCheck{}, fmt.Errorf("calibrate tool probe: %w", err)
		}
		req.Schema, req.Grammar = toolSchema(), toolGrammar()
		a, err := models.Complete[toolAnswer](ctx, opts.Model, req)
		if errors.Is(err, models.ErrInvalidOutput) {
			continue
		}
		if err != nil {
			return ToolCheck{}, fmt.Errorf("calibrate tool probe: %w", err)
		}
		if a.Tool == p.tool && a.Argument == p.argument {
			correct++
		}
	}
	return newToolCheck(len(probes), correct), nil
}

// runContextProbes tries each size in order and stops at the first wrong or
// invalid answer, so a small model is not sent the largest inputs.
func runContextProbes(ctx context.Context, opts Options, src rand.Source) (int, error) {
	effective := 0
	for _, size := range contextSizes {
		p := newContextProbe(src, size)
		req, err := newRequest(opts.Redactor, purposeContext, contextSystem, p.prompt)
		if err != nil {
			return 0, fmt.Errorf("calibrate context probe: %w", err)
		}
		req.Schema, req.Grammar = contextSchema(), contextGrammar()
		a, err := models.Complete[contextAnswer](ctx, opts.Model, req)
		if errors.Is(err, models.ErrInvalidOutput) {
			return effective, nil
		}
		if err != nil {
			return 0, fmt.Errorf("calibrate context probe: %w", err)
		}
		if a.Value != p.value {
			return effective, nil
		}
		effective = size
	}
	return effective, nil
}

// newRequest redacts the whole prompt with File, as the gateway does with a
// repository file, and counts the markers for egress.log.
func newRequest(r *redact.Redactor, purpose, system, prompt string) (models.Request, error) {
	redacted, err := r.File([]byte(prompt))
	if err != nil {
		return models.Request{}, fmt.Errorf("redact prompt: %w", err)
	}
	return models.Request{
		Purpose: purpose, System: system, Prompt: redacted,
		Redactions: r.MarkerCounts(redacted),
	}, nil
}

// numberLines prefixes each line with its 1-based number, so the model can
// name the sink line. Only the code reaches the prompt: never the task's
// ID, template, class or label, which are the answer key.
func numberLines(code string) string {
	lines := strings.Split(strings.TrimSuffix(code, "\n"), "\n")
	var b strings.Builder
	for i, line := range lines {
		fmt.Fprintf(&b, "%d| %s\n", i+1, line)
	}
	return b.String()
}

func taskSetHash(tasks []Task) string {
	b, err := json.Marshal(tasks)
	if err != nil {
		panic(err) // Task holds only strings, bools and ints
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
