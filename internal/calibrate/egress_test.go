package calibrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// gatewayModel sends through the real gateway: consented by policy, logged
// in egress.log, then refused by an allowlist that holds nothing, so no
// DNS lookup or dial happens.
func gatewayModel(t *testing.T) (*models.HTTP, string) {
	t.Helper()
	dir := t.TempDir()
	consent, err := gateway.NewConsent(gateway.ConsentOptions{CI: true, Policy: []string{"https://models.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	budget, err := gateway.NewBudget(gateway.BudgetOptions{MaxTokens: 1_000_000, MaxCalls: 10})
	if err != nil {
		t.Fatal(err)
	}
	log, err := gateway.OpenEgressLog(dir, consent, budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	client, err := gateway.NewClient(gateway.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return newModel(t, models.Through(log, client)), dir
}

// Acceptance (#90): calibration runs through the gateway. The prompt is
// redacted whole before the call, egress.log records the call and its
// redaction counts before anything is sent, and the payload holds no
// secret. A refused call ends the run with no Result.
func TestRunGoesThroughGateway(t *testing.T) {
	// Built at run time so no secret scanner flags this file.
	secret := "ghp_" + string(bytes.Repeat([]byte("aB3x"), 9))
	task := Task{
		ID: "task-000", Template: "test", Class: ClassSSRF, Vulnerable: true, Line: 2,
		Code: "const token = \"" + secret + "\";\nfetch(req.query.url);\n",
	}
	model, dir := gatewayModel(t)
	r, err := run(context.Background(), Options{Seed: 1, Model: model, Redactor: newRedactor(t)}, []Task{task})
	if !errors.Is(err, gateway.ErrNotAllowed) {
		t.Fatalf("err = %v, want the allowlist refusal", err)
	}
	if r.Tier != "" {
		t.Errorf("refused run got tier %q", r.Tier)
	}
	line := requestLine(t, dir)
	if line.Purpose != purposeTask || len(line.Redactions) == 0 {
		t.Errorf("egress.log request = %+v, want purpose %s with redactions", line, purposeTask)
	}
	payload, err := os.ReadFile(filepath.Join(dir, line.PayloadFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(secret)) {
		t.Error("payload holds the secret")
	}
}

type egressRequest struct {
	Type        string         `json:"type"`
	Purpose     string         `json:"purpose"`
	Redactions  map[string]int `json:"redactions"`
	PayloadFile string         `json:"payload_file"`
}

func requestLine(t *testing.T, dir string) egressRequest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "egress.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range bytes.Split(raw, []byte("\n")) {
		var e egressRequest
		if json.Unmarshal(l, &e) == nil && e.Type == "request" {
			return e
		}
	}
	t.Fatal("egress.log has no request line")
	return egressRequest{}
}
