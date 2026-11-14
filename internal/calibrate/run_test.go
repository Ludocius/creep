package calibrate

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// Acceptance (#90): a recorded run replays to the same scores and tier,
// with no network and no key. The fixture is a tier-M model: it misses two
// prototype_pollution tasks, points one sqli answer three lines off, flags
// one safe idor twin, answers one ssrf twin invalidly twice, passes every
// tool probe and fails the 128 KiB context probe.
func TestRunReplayIsDeterministic(t *testing.T) {
	var first Result
	for i := range 2 {
		rep, n := fromFixture(t, "seed1_tier_m")
		r, err := Run(context.Background(), testOptions(t, 1, rep.send))
		if err != nil {
			t.Fatal(err)
		}
		if rep.replies != n || len(rep.calls) != n {
			t.Fatalf("run used %d of %d recorded replies in %d calls", rep.replies, n, len(rep.calls))
		}
		if i == 0 {
			first = r
			continue
		}
		if !reflect.DeepEqual(r, first) {
			t.Fatalf("replay differs:\n%+v\n%+v", r, first)
		}
	}
	checkFixtureResult(t, first)
}

func checkFixtureResult(t *testing.T, r Result) {
	t.Helper()
	if r.Tier != TierM {
		t.Errorf("tier = %s, want M", r.Tier)
	}
	if r.Overall.Correct != 95 || r.Overall.Total != 100 {
		t.Errorf("overall = %d/%d, want 95/100", r.Overall.Correct, r.Overall.Total)
	}
	want := map[Class][2]int{
		ClassSQLi: {13, 14}, ClassNoSQLInjection: {8, 8}, ClassCommandInjection: {14, 14},
		ClassPathTraversal: {14, 14}, ClassSSRF: {13, 14}, ClassIDOR: {13, 14},
		ClassMissingAuth: {14, 14}, ClassPrototypePollution: {6, 8},
	}
	for _, c := range r.Classes {
		if got := [2]int{c.Correct, c.Total}; got != want[c.Class] {
			t.Errorf("%s = %v, want %v", c.Class, got, want[c.Class])
		}
	}
	checks := r.Structured == StructuredCheck{Total: 100, Invalid: 1, Passed: true} &&
		r.Tools == ToolCheck{Probes: 3, Correct: 3, Passed: true} &&
		r.Context.EffectiveBytes == 32<<10
	if !checks {
		t.Errorf("checks = %+v %+v %+v", r.Structured, r.Tools, r.Context)
	}
	tasks, err := Generate(1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Seed != 1 || r.TaskSet != taskSetHash(tasks) || r.PromptVersion != PromptVersion {
		t.Errorf("result does not identify its tasks: %d %s %d", r.Seed, r.TaskSet, r.PromptVersion)
	}
}

// Calls go out one at a time in a fixed order (tasks, tool probes, context
// probes), each logged with its purpose, so a recording replays exactly.
func TestRunCallOrder(t *testing.T) {
	rep, _ := fromFixture(t, "seed1_tier_m")
	if _, err := Run(context.Background(), testOptions(t, 1, rep.send)); err != nil {
		t.Fatal(err)
	}
	var purposes []string
	for _, c := range rep.calls {
		if len(purposes) == 0 || purposes[len(purposes)-1] != c.Purpose {
			purposes = append(purposes, c.Purpose)
		}
	}
	want := []string{purposeTask, purposeTool, purposeContext}
	if !reflect.DeepEqual(purposes, want) {
		t.Errorf("purpose runs = %v, want %v", purposes, want)
	}
}

// Only the code reaches the model: the template name, task ID and class,
// which are the answer key, never appear in a task's user turn.
func TestTaskPromptHoldsNoAnswerKey(t *testing.T) {
	o := newOracle(t, 1)
	rep := answering(o.answer)
	if _, err := Run(context.Background(), testOptions(t, 1, rep.send)); err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.calls {
		if c.Purpose != purposeTask {
			continue
		}
		user := userTurn(c.Payload)
		for _, task := range o.tasks {
			for _, key := range []string{task.Template, task.ID} {
				if strings.Contains(user, key) {
					t.Fatalf("task prompt holds answer key %q", key)
				}
			}
		}
		// A class may be part of a word ("sqlite3"), never a word itself.
		for _, class := range Classes() {
			if regexp.MustCompile(`\b` + string(class) + `\b`).MatchString(user) {
				t.Fatalf("task prompt names class %q", class)
			}
		}
	}
}

func TestRunOutcomes(t *testing.T) {
	o := newOracle(t, 1)
	tests := []struct {
		name       string
		answer     func(user string) string
		tier       Tier
		correct    int
		structured StructuredCheck
		tools      int
		context    int
	}{
		{"perfect model", o.answer, TierL, 100, StructuredCheck{100, 0, true}, 3, 128 << 10},
		{"all wrong", func(user string) string { return opposite(o, user) }, TierS, 0, StructuredCheck{100, 0, true}, 0, 0},
		{"always safe", func(string) string { return taskJSON(false, "", 0) }, TierS, 50, StructuredCheck{100, 0, true}, 0, 0},
		{"invalid output", func(string) string { return `{"vulnerable":true,"class":"xss","line":1}` }, TierS, 0, StructuredCheck{100, 100, false}, 0, 0},
		{"not json", func(string) string { return "I think it is fine." }, TierS, 0, StructuredCheck{100, 100, false}, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Run(context.Background(), testOptions(t, 1, answering(tt.answer).send))
			if err != nil {
				t.Fatal(err)
			}
			if r.Tier != tt.tier || r.Overall.Correct != tt.correct || r.Structured != tt.structured {
				t.Errorf("tier %s, correct %d, structured %+v", r.Tier, r.Overall.Correct, r.Structured)
			}
			if r.Tools.Correct != tt.tools || r.Context.EffectiveBytes != tt.context {
				t.Errorf("tools %d, context %d", r.Tools.Correct, r.Context.EffectiveBytes)
			}
		})
	}
}

// opposite answers every call wrongly but validly.
func opposite(o oracle, user string) string {
	if task, ok := o.task(user); ok {
		return taskJSON(!task.Vulnerable, "idor", 1)
	}
	if strings.Contains(user, "what string is assigned") {
		return `{"value":"wrong"}`
	}
	return `{"tool":"list_dir","argument":"nowhere"}`
}

// A failure that is not the model's output ends the run with no Result: a
// partial calibration never gets a tier.
func TestRunFailures(t *testing.T) {
	o := newOracle(t, 1)
	statusAt := func(call int, status int) *replayer {
		return &replayer{next: func(n int, c gateway.Call) (recordedReply, bool) {
			if n == call {
				return recordedReply{Status: status, Body: openAIBody("")}, true
			}
			return recordedReply{Status: 200, Body: openAIBody(o.answer(userTurn(c.Payload)))}, true
		}}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		opts func(t *testing.T) Options
		want error
	}{
		{"status on a task", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, statusAt(0, 500).send) }, models.ErrStatus},
		{"status on a tool probe", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, statusAt(101, 429).send) }, models.ErrStatus},
		{"status on a context probe", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, statusAt(104, 503).send) }, models.ErrStatus},
		{"transport error", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, (&replayer{next: noReply}).send) }, nil},
		{"canceled", canceled, func(t *testing.T) Options { return testOptions(t, 1, contextSend) }, context.Canceled},
		{"no model", context.Background(), func(t *testing.T) Options { return Options{Seed: 1, Redactor: newRedactor(t)} }, ErrOptions},
		{"no redactor", context.Background(), func(t *testing.T) Options { return Options{Seed: 1, Model: newModel(t, contextSend)} }, ErrOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Run(tt.ctx, tt.opts(t))
			if err == nil {
				t.Fatal("run succeeded")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if !reflect.DeepEqual(r, Result{}) {
				t.Errorf("failed run returned a result: %+v", r)
			}
		})
	}
}

func noReply(int, gateway.Call) (recordedReply, bool) { return recordedReply{}, false }

// Replies are matched to their request hash: other tasks (another seed)
// with the same call count do not replay against the recording.
func TestReplayRefusesOtherRequests(t *testing.T) {
	rep, _ := fromFixture(t, "seed1_tier_m")
	if _, err := Run(context.Background(), testOptions(t, 2, rep.send)); err == nil {
		t.Fatal("seed 2 replayed against the seed 1 recording")
	}
	if rep.replies != 0 {
		t.Errorf("served %d replies to requests it was not recorded for", rep.replies)
	}
}

// failContextCall answers like o, except that context-probe call n (0 for
// 8 KiB, 1 for 32 KiB, 2 for 128 KiB) gets status, or err when set.
func failContextCall(o oracle, n, status int, err error) models.SendFunc {
	rep := answering(o.answer)
	seen := 0
	return func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		if call.Purpose == purposeContext {
			seen++
			if seen-1 == n && err != nil {
				return nil, err
			}
			if seen-1 == n {
				return &gateway.Reply{ID: "refused", Status: status, Body: openAIBody("")}, nil
			}
		}
		return rep.send(ctx, call)
	}
}

// A context probe refused for its size (400, 413, budget) measures the
// context: the smaller sizes' result stands and the run gets a tier. A
// refusal that is not about size still ends the run.
func TestContextProbeRefusals(t *testing.T) {
	o := newOracle(t, 1)
	tests := []struct {
		name      string
		send      models.SendFunc
		effective int
		tier      Tier
		want      error
	}{
		{"400 at 128 KiB", failContextCall(o, 2, 400, nil), 32 << 10, TierM, nil},
		{"413 at 32 KiB", failContextCall(o, 1, 413, nil), 8 << 10, TierS, nil},
		{"400 at 8 KiB", failContextCall(o, 0, 400, nil), 0, TierS, nil},
		{"budget at 128 KiB", failContextCall(o, 2, 0, &gateway.BudgetError{}), 32 << 10, TierM, nil},
		{"503 at 128 KiB", failContextCall(o, 2, 503, nil), 0, "", models.ErrStatus},
		{"not allowed at 128 KiB", failContextCall(o, 2, 0, gateway.ErrNotAllowed), 0, "", gateway.ErrNotAllowed},
		{"no consent at 128 KiB", failContextCall(o, 2, 0, gateway.ErrNoConsent), 0, "", gateway.ErrNoConsent},
		{"egress write at 128 KiB", failContextCall(o, 2, 0, gateway.ErrUnsafeLogPath), 0, "", gateway.ErrUnsafeLogPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Run(context.Background(), testOptions(t, 1, tt.send))
			if tt.want != nil {
				if !errors.Is(err, tt.want) || !reflect.DeepEqual(r, Result{}) {
					t.Fatalf("err = %v, result %+v; want %v and no result", err, r, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Context.EffectiveBytes != tt.effective || r.Tier != tt.tier {
				t.Errorf("effective %d tier %s, want %d %s", r.Context.EffectiveBytes, r.Tier, tt.effective, tt.tier)
			}
		})
	}
}

func TestRunRefusesNoTasks(t *testing.T) {
	_, err := run(context.Background(), testOptions(t, 1, contextSend), nil)
	if !errors.Is(err, ErrOptions) {
		t.Fatalf("err = %v, want ErrOptions", err)
	}
}
