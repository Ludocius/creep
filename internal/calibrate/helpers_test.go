package calibrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/redact"
)

// recordedReply is one provider reply in testdata/replay/<name>.json, a JSON
// array replayed in call order. A fixture holds exactly the replies a run
// consumes, so an extra or missing call fails the test.
type recordedReply struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// replayer is a SendFunc that answers each call, records it, and stops
// with an error when it has no answer left.
type replayer struct {
	mu      sync.Mutex
	next    func(n int, user string) (recordedReply, bool)
	calls   []gateway.Call
	replies int
}

func (r *replayer) send(_ context.Context, call gateway.Call) (*gateway.Reply, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.calls)
	r.calls = append(r.calls, call)
	rec, ok := r.next(n, userTurn(call.Payload))
	if !ok {
		return nil, errors.New("replay: no recorded reply left")
	}
	r.replies++
	return &gateway.Reply{ID: fmt.Sprintf("replay-%d", n), Status: rec.Status, Body: rec.Body}, nil
}

// fromFixture replays testdata/replay/<name>.json in order.
func fromFixture(t *testing.T, name string) (*replayer, int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "replay", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var recs []recordedReply
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return &replayer{next: func(n int, _ string) (recordedReply, bool) {
		if n >= len(recs) {
			return recordedReply{}, false
		}
		return recs[n], true
	}}, len(recs)
}

// answering replies 200 with the content answer returns for each user turn.
func answering(answer func(user string) string) *replayer {
	return &replayer{next: func(_ int, user string) (recordedReply, bool) {
		return recordedReply{Status: 200, Body: openAIBody(answer(user))}, true
	}}
}

// openAIBody is a chat completion whose message content is content.
func openAIBody(content string) json.RawMessage {
	body := map[string]any{
		"id": "chatcmpl-replay", "object": "chat.completion", "model": "replay-model",
		"choices": []any{map[string]any{
			"index": 0, "finish_reason": "stop",
			"message": map[string]any{"role": "assistant", "content": content},
		}},
		"usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 10},
	}
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return b
}

// userTurn returns the last message of an OpenAI-style payload.
func userTurn(payload []byte) string {
	var p struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(payload, &p) != nil || len(p.Messages) == 0 {
		return ""
	}
	return p.Messages[len(p.Messages)-1].Content
}

func newModel(t *testing.T, send models.SendFunc) *models.HTTP {
	t.Helper()
	h, err := models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "https://models.invalid/v1", Model: "replay-model",
		Structured: models.StructuredSchema, MaxOutputTokens: 64, Retries: 1, Send: send,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func newRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testOptions(t *testing.T, seed uint64, send models.SendFunc) Options {
	t.Helper()
	return Options{Seed: seed, Model: newModel(t, send), Redactor: newRedactor(t)}
}

var needlePattern = regexp.MustCompile(`let (marker_[a-z_]+) = "([a-z0-9-]+)";`)

// oracle answers every calibration call correctly for seed: it finds the
// task by its prompt as sent (numbered and redacted), the tool probe by its
// prompt and the context value by the needle line.
type oracle struct {
	tasks   []Task
	prompts []string
	tools   []toolProbe
}

func newOracle(t *testing.T, seed uint64) oracle {
	t.Helper()
	tasks, err := Generate(seed)
	if err != nil {
		t.Fatal(err)
	}
	r := newRedactor(t)
	prompts := make([]string, len(tasks))
	for i, task := range tasks {
		if prompts[i], err = r.File([]byte(numberLines(task.Code))); err != nil {
			t.Fatal(err)
		}
	}
	return oracle{tasks: tasks, prompts: prompts, tools: toolProbes(probeSource(seed))}
}

func (o oracle) task(user string) (Task, bool) {
	for i, task := range o.tasks {
		if strings.HasPrefix(user, o.prompts[i]) {
			return task, true
		}
	}
	return Task{}, false
}

func (o oracle) answer(user string) string {
	if task, ok := o.task(user); ok {
		return taskJSON(task.Vulnerable, string(task.Class), task.Line)
	}
	for _, p := range o.tools {
		if strings.HasPrefix(user, p.prompt) {
			return fmt.Sprintf(`{"tool":%q,"argument":%q}`, p.tool, p.argument)
		}
	}
	if m := needlePattern.FindStringSubmatch(user); m != nil {
		return fmt.Sprintf(`{"value":%q}`, m[2])
	}
	return `{"unexpected":true}`
}

// contextSend fails every call: with ctx's error once it is done.
func contextSend(ctx context.Context, _ gateway.Call) (*gateway.Reply, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("send: no endpoint")
}

func taskJSON(vulnerable bool, class string, line int) string {
	if !vulnerable {
		return `{"vulnerable":false,"class":"none","line":0}`
	}
	return fmt.Sprintf(`{"vulnerable":true,"class":%q,"line":%d}`, class, line)
}
