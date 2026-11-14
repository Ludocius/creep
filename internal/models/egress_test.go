package models

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// testOrigin is consented by policy. The client allowlists nothing, so the
// gateway logs each request and then refuses it before any DNS lookup or
// dial: these tests use the real gateway with no network.
const testOrigin = "https://models.invalid"

func gatewaySend(t *testing.T, maxTokens int) (SendFunc, string, func()) {
	t.Helper()
	dir := t.TempDir()
	consent, err := gateway.NewConsent(gateway.ConsentOptions{CI: true, Policy: []string{testOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	budget, err := gateway.NewBudget(gateway.BudgetOptions{MaxTokens: maxTokens, MaxCalls: 10})
	if err != nil {
		t.Fatal(err)
	}
	log, err := gateway.OpenEgressLog(dir, consent, budget)
	if err != nil {
		t.Fatal(err)
	}
	client, err := gateway.NewClient(gateway.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return Through(log, client), dir, func() { _ = log.Close() }
}

// The key travels only in headers, which the gateway never logs: neither
// egress.log nor any payload file holds it, for either contract.
func TestKeyNeverReachesEgressLog(t *testing.T) {
	for _, contract := range []string{"openai", "anthropic"} {
		t.Run(contract, func(t *testing.T) {
			send, dir, done := gatewaySend(t, 1_000_000)
			defer done()
			k, err := KeyFromEnv(env(fakeKey))
			if err != nil {
				t.Fatal(err)
			}
			h, err := NewHTTP(Options{
				Contract: contract, Endpoint: testOrigin + "/v1", Model: "m", Key: k,
				Structured: StructuredTools, MaxOutputTokens: 16, Send: send,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = Complete[verdict](context.Background(), h, testRequest())
			if !errors.Is(err, gateway.ErrNotAllowed) {
				t.Fatalf("err = %v, want the allowlist refusal after logging", err)
			}
			if bytes.Contains([]byte(err.Error()), []byte(fakeKey)) {
				t.Errorf("error quotes the key: %v", err)
			}
			files := runFiles(t, dir)
			if len(files) < 2 {
				t.Fatalf("want egress.log and a payload file, got %d files", len(files))
			}
			for name, data := range files {
				if bytes.Contains(data, []byte(fakeKey)) || bytes.Contains(data, []byte("Bearer")) {
					t.Errorf("%s holds the key", name)
				}
			}
		})
	}
}

// A run budget smaller than payload plus output cap refuses the call before
// anything is written, so in-flight calls cannot overspend.
func TestReservationIsEnforcedByGateway(t *testing.T) {
	send, dir, done := gatewaySend(t, 100)
	defer done()
	h, err := NewHTTP(Options{
		Contract: "openai", Endpoint: testOrigin + "/v1", Model: "m",
		Structured: StructuredPrompt, MaxOutputTokens: 99, Send: send,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Complete[verdict](context.Background(), h, testRequest())
	var be *gateway.BudgetError
	if !errors.As(err, &be) || be.Limit != gateway.LimitRunTokens {
		t.Fatalf("err = %v, want a run-token BudgetError", err)
	}
	for name, data := range runFiles(t, dir) {
		if len(data) > 0 {
			t.Errorf("%s written for a refused call", name)
		}
	}
}

// runFiles returns egress.log and every payload file, by relative path.
// The gateway creates both with 0600 in a TempDir only this test uses.
func runFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	names := []string{"egress.log"}
	entries, err := fs.ReadDir(root.FS(), "payloads")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		names = append(names, path.Join("payloads", e.Name()))
	}
	files := map[string][]byte{}
	for _, name := range names {
		data, err := fs.ReadFile(root.FS(), name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = data
	}
	return files
}
