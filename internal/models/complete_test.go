package models

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

func TestCompleteReplay(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		contract   string
		structured Structured
		retries    int
		want       verdict
		wantReason string // non-empty: expect *InvalidOutputError with this reason
		wantCalls  int
		wantUsage  gateway.Usage // reported by the first reply
	}{
		{"openai schema", "openai_content_ok", "openai", StructuredSchema, 2, verdict{true, "sqli"}, "", 1, gateway.Usage{InputTokens: 120, OutputTokens: 9}},
		{"openai grammar", "openai_content_ok", "openai", StructuredGrammar, 0, verdict{true, "sqli"}, "", 1, gateway.Usage{InputTokens: 120, OutputTokens: 9}},
		{"openai prompt", "openai_content_ok", "openai", StructuredPrompt, 0, verdict{true, "sqli"}, "", 1, gateway.Usage{InputTokens: 120, OutputTokens: 9}},
		{"openai tools", "openai_tools_ok", "openai", StructuredTools, 0, verdict{false, "xss"}, "", 1, gateway.Usage{InputTokens: 150, OutputTokens: 20}},
		{"openai retry fixes output", "openai_invalid_then_ok", "openai", StructuredPrompt, 1, verdict{true, "sqli"}, "", 2, gateway.Usage{InputTokens: 120, OutputTokens: 14}},
		{"openai invalid every time", "openai_invalid_always", "openai", StructuredPrompt, 2, verdict{}, "it had data after the JSON object", 3, gateway.Usage{InputTokens: 120, OutputTokens: 14}},
		{"openai invalid no retries", "openai_invalid_then_ok", "openai", StructuredPrompt, 0, verdict{}, "it was not a JSON object", 1, gateway.Usage{InputTokens: 120, OutputTokens: 14}},
		{"openai truncated", "openai_truncated", "openai", StructuredSchema, 0, verdict{}, reasonTruncated, 1, gateway.Usage{InputTokens: 120, OutputTokens: 64}},
		{"openai refusal", "openai_refusal", "openai", StructuredSchema, 0, verdict{}, reasonRefused, 1, gateway.Usage{InputTokens: 120, OutputTokens: 12}},
		{"openai unknown field", "openai_unknown_field", "openai", StructuredSchema, 0, verdict{}, "it had a field the schema does not allow", 1, gateway.Usage{InputTokens: 120, OutputTokens: 22}},
		{"openai validate fails", "openai_validate_fails", "openai", StructuredSchema, 0, verdict{}, "it broke a rule: class $(touch pwned)??[31m is not one of sqli, xss", 1, gateway.Usage{InputTokens: 120, OutputTokens: 15}},
		{"openai tools missing call", "openai_content_ok", "openai", StructuredTools, 0, verdict{}, reasonNoTool, 1, gateway.Usage{InputTokens: 120, OutputTokens: 9}},
		{"anthropic tools", "anthropic_tools_ok", "anthropic", StructuredTools, 0, verdict{true, "sqli"}, "", 1, gateway.Usage{InputTokens: 200, OutputTokens: 31}},
		{"anthropic text blocks joined", "anthropic_text_ok", "anthropic", StructuredPrompt, 0, verdict{false, "xss"}, "", 1, gateway.Usage{InputTokens: 180, OutputTokens: 14}},
		{"anthropic retry after no tool", "anthropic_no_tool_then_ok", "anthropic", StructuredTools, 1, verdict{true, "sqli"}, "", 2, gateway.Usage{InputTokens: 200, OutputTokens: 11}},
		{"anthropic max tokens", "anthropic_max_tokens", "anthropic", StructuredTools, 0, verdict{}, reasonTruncated, 1, gateway.Usage{InputTokens: 200, OutputTokens: 64}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := loadReplay(t, tt.fixture)
			h := newTestHTTP(t, tt.contract, tt.structured, tt.retries, rep.send)
			got, err := Complete[verdict](context.Background(), h, testRequest())
			checkOutcome(t, got, err, tt.want, tt.wantReason)
			if len(rep.calls) != tt.wantCalls {
				t.Fatalf("calls = %d, want %d", len(rep.calls), tt.wantCalls)
			}
			for _, call := range rep.calls {
				checkReservation(t, call)
			}
			if u, ok := rep.calls[0].Usage(rep.replies[0].Body); !ok || u != tt.wantUsage {
				t.Errorf("usage = %+v, %v; want %+v", u, ok, tt.wantUsage)
			}
		})
	}
}

func checkOutcome(t *testing.T, got verdict, err error, want verdict, wantReason string) {
	t.Helper()
	if wantReason == "" {
		if err != nil || got != want {
			t.Fatalf("got %+v, %v; want %+v", got, err, want)
		}
		return
	}
	var inv *InvalidOutputError
	if !errors.As(err, &inv) || !errors.Is(err, ErrInvalidOutput) {
		t.Fatalf("err = %v, want *InvalidOutputError", err)
	}
	want_ := strings.ReplaceAll(strings.ReplaceAll(wantReason, "\n", "?"), "\u001b", "?")
	if inv.Reason != want_ {
		t.Errorf("reason = %q, want %q", inv.Reason, want_)
	}
	if got != (verdict{}) {
		t.Errorf("invalid output returned a value: %+v", got)
	}
}

// checkReservation pins the auditor's #5 note: the reservation covers the
// payload plus exactly the output cap the request asks for.
func checkReservation(t *testing.T, call gateway.Call) {
	t.Helper()
	body := decodeJSON(t, call.Payload)
	if body["max_tokens"] != float64(testMaxOutput) {
		t.Errorf("max_tokens = %v, want %d", body["max_tokens"], testMaxOutput)
	}
	if call.ReserveTokens != len(call.Payload)+testMaxOutput {
		t.Errorf("ReserveTokens = %d, want %d", call.ReserveTokens, len(call.Payload)+testMaxOutput)
	}
}

// A retry carries creep's reason, never the rejected model text, and each
// attempt is its own logged, budgeted call.
func TestRetryPromptCarriesReasonNotModelText(t *testing.T) {
	rep := loadReplay(t, "openai_invalid_always")
	h := newTestHTTP(t, "openai", StructuredPrompt, 2, rep.send)
	_, err := Complete[verdict](context.Background(), h, testRequest())
	var inv *InvalidOutputError
	if !errors.As(err, &inv) || inv.Attempts != 3 {
		t.Fatalf("err = %v, want 3 attempts", err)
	}
	for i, call := range rep.calls {
		p := string(call.Payload)
		if strings.Contains(p, "Here is the JSON") || strings.Contains(p, "```") {
			t.Errorf("call %d echoes model output: %s", i, p)
		}
		if i > 0 && strings.Count(p, "previous reply was rejected") != 1 {
			t.Errorf("call %d: want exactly one rejection reason: %s", i, p)
		}
		if call.Purpose != "reader" || call.Redactions["password"] != 1 {
			t.Errorf("call %d lost purpose or redactions: %+v", i, call)
		}
	}
	if !strings.Contains(string(rep.calls[1].Payload), "it was not a JSON object") {
		t.Errorf("retry lacks the reason: %s", rep.calls[1].Payload)
	}
}

// Failures that are not the model's output return at once, unretried.
func TestCompleteDoesNotRetryEndpointFailures(t *testing.T) {
	budgetErr := &gateway.BudgetError{Endpoint: "https://api.openai.example:443", Limit: gateway.LimitRunTokens}
	tests := []struct {
		name     string
		contract string
		rep      *replayer
		sendErr  error
		want     error
	}{
		{"openai 429", "openai", nil, nil, ErrStatus},
		{"anthropic 529", "anthropic", nil, nil, ErrStatus},
		{"not json", "openai", replyWith(200, `"<html>proxy login</html>"`), nil, ErrMalformedReply},
		{"no choices", "openai", replyWith(200, `{"choices":[]}`), nil, ErrMalformedReply},
		{"anthropic wrong type", "anthropic", replyWith(200, `{"type":"error","content":[]}`), nil, ErrMalformedReply},
		{"budget refusal", "openai", nil, budgetErr, gateway.ErrBudgetExhausted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			send := func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
				calls++
				if tt.sendErr != nil {
					return nil, tt.sendErr
				}
				if tt.rep == nil {
					tt.rep = loadReplay(t, map[string]string{"openai": "openai_status_429", "anthropic": "anthropic_overloaded"}[tt.contract])
				}
				return tt.rep.send(ctx, call)
			}
			h := newTestHTTP(t, tt.contract, StructuredTools, MaxRetries, send)
			_, err := Complete[verdict](context.Background(), h, testRequest())
			if !errors.Is(err, tt.want) || calls != 1 {
				t.Fatalf("err = %v after %d calls, want %v after 1", err, calls, tt.want)
			}
			if strings.Contains(err.Error(), "Rate limit") || strings.Contains(err.Error(), "Overloaded") {
				t.Errorf("error quotes the reply body: %v", err)
			}
		})
	}
}
