package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// recordedReply is one provider reply in testdata/replay/<name>.json, a JSON
// array replayed in order. Each fixture holds exactly the replies a test may
// consume, so an extra call fails the test.
type recordedReply struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// replayer is a SendFunc that answers from a fixture and records each call.
type replayer struct {
	mu      sync.Mutex
	replies []recordedReply
	calls   []gateway.Call
}

func loadReplay(t *testing.T, name string) *replayer {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "replay", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &replayer{}
	if err := json.Unmarshal(raw, &r.replies); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return r
}

// replyWith replays one inline body, for envelope shapes no real provider
// sends, such as a malformed reply.
func replyWith(status int, body string) *replayer {
	return &replayer{replies: []recordedReply{{Status: status, Body: json.RawMessage(body)}}}
}

func (r *replayer) send(_ context.Context, call gateway.Call) (*gateway.Reply, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.calls)
	r.calls = append(r.calls, call)
	if n >= len(r.replies) {
		return nil, errors.New("replay: no recorded reply left")
	}
	rec := r.replies[n]
	return &gateway.Reply{ID: fmt.Sprintf("replay-%d", n), Status: rec.Status, Body: rec.Body}, nil
}

// verdict is a closed output struct like the reader's.
type verdict struct {
	Vulnerable bool   `json:"vulnerable"`
	Class      string `json:"class"`
}

func (v *verdict) Validate() error {
	switch v.Class {
	case "sqli", "xss":
		return nil
	}
	// %s, not %q, so the test sees cleanReason scrub raw control bytes.
	return fmt.Errorf("class %s is not one of sqli, xss", v.Class)
}

const verdictSchema = `{"type":"object","properties":{"vulnerable":{"type":"boolean"},"class":{"type":"string","enum":["sqli","xss"]}},"required":["vulnerable","class"],"additionalProperties":false}`

const testMaxOutput = 64

func newTestHTTP(t *testing.T, contract string, s Structured, retries int, send SendFunc) *HTTP {
	t.Helper()
	endpoint := "https://api.openai.example/v1"
	if contract == "anthropic" {
		endpoint = "https://api.anthropic.example"
	}
	h, err := NewHTTP(Options{
		Contract: contract, Endpoint: endpoint, Model: "replay-model",
		Key: Key{value: "sk-test-NOT-A-REAL-KEY-0123456789"}, Structured: s,
		MaxOutputTokens: testMaxOutput, Retries: retries, Send: send,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testRequest() Request {
	return Request{
		Purpose: "reader", System: "You review code.",
		Prompt:     "Is this query injectable? db.execute(q + [REDACTED:password:1])",
		Redactions: map[string]int{"password": 1},
		Schema:     json.RawMessage(verdictSchema), Grammar: `root ::= "{" ws "}"`,
	}
}

// decodeJSON unmarshals a recorded payload for assertions.
func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	return m
}
