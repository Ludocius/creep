package models

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// Each structured mode puts the schema or grammar where the API expects it,
// at the endpoint path the contract appends.
func TestRequestShape(t *testing.T) {
	tests := []struct {
		contract   string
		structured Structured
		wantURL    string
		wantKeys   []string // top-level keys that must be present
		absentKeys []string
	}{
		{"openai", StructuredSchema, "https://api.openai.example/v1/chat/completions", []string{"response_format"}, []string{"grammar", "tools"}},
		{"openai", StructuredGrammar, "https://api.openai.example/v1/chat/completions", []string{"grammar"}, []string{"response_format", "tools"}},
		{"openai", StructuredTools, "https://api.openai.example/v1/chat/completions", []string{"tools", "tool_choice"}, []string{"response_format", "grammar"}},
		{"openai", StructuredPrompt, "https://api.openai.example/v1/chat/completions", nil, []string{"response_format", "grammar", "tools"}},
		{"anthropic", StructuredTools, "https://api.anthropic.example/v1/messages", []string{"tools", "tool_choice", "system"}, nil},
		{"anthropic", StructuredPrompt, "https://api.anthropic.example/v1/messages", []string{"system"}, []string{"tools", "tool_choice"}},
	}
	for _, tt := range tests {
		t.Run(tt.contract+"/"+string(tt.structured), func(t *testing.T) {
			rep := replyWith(200, `{}`)
			h := newTestHTTP(t, tt.contract, tt.structured, 0, rep.send)
			_, _ = Complete[verdict](context.Background(), h, testRequest())
			call := rep.calls[0]
			if call.Endpoint != tt.wantURL || call.Model != "replay-model" {
				t.Errorf("endpoint %q model %q", call.Endpoint, call.Model)
			}
			body := decodeJSON(t, call.Payload)
			for _, k := range tt.wantKeys {
				if _, ok := body[k]; !ok {
					t.Errorf("missing %q in %s", k, call.Payload)
				}
			}
			for _, k := range tt.absentKeys {
				if _, ok := body[k]; ok {
					t.Errorf("unexpected %q in %s", k, call.Payload)
				}
			}
		})
	}
}

// The schema sent is the caller's schema, unchanged, and strict.
func TestSchemaIsSentStrict(t *testing.T) {
	rep := replyWith(200, `{}`)
	h := newTestHTTP(t, "openai", StructuredSchema, 0, rep.send)
	_, _ = Complete[verdict](context.Background(), h, testRequest())
	var body struct {
		ResponseFormat struct {
			Type       string `json:"type"`
			JSONSchema struct {
				Name   string          `json:"name"`
				Strict bool            `json:"strict"`
				Schema json.RawMessage `json:"schema"`
			} `json:"json_schema"`
		} `json:"response_format"`
	}
	if err := json.Unmarshal(rep.calls[0].Payload, &body); err != nil {
		t.Fatal(err)
	}
	rf := body.ResponseFormat
	if rf.Type != "json_schema" || !rf.JSONSchema.Strict || string(rf.JSONSchema.Schema) != verdictSchema {
		t.Errorf("response_format = %+v", rf)
	}
}

func TestHeaders(t *testing.T) {
	key := Key{value: "sk-hdr"}
	tests := []struct {
		contract string
		key      Key
		want     map[string]string
	}{
		{"openai", key, map[string]string{"Content-Type": "application/json", "Authorization": "Bearer sk-hdr"}},
		{"openai", Key{}, map[string]string{"Content-Type": "application/json"}},
		{"anthropic", key, map[string]string{"Content-Type": "application/json", "X-Api-Key": "sk-hdr", "Anthropic-Version": anthropicVersion}},
		{"anthropic", Key{}, map[string]string{"Content-Type": "application/json", "Anthropic-Version": anthropicVersion}},
	}
	for _, tt := range tests {
		w, err := wireFor(tt.contract, StructuredPrompt)
		if err != nil {
			t.Fatal(err)
		}
		got := w.headers(tt.key)
		if len(got) != len(tt.want) {
			t.Errorf("%s: headers %v, want %v", tt.contract, got, tt.want)
		}
		for k, v := range tt.want {
			if len(got[k]) != 1 || got[k][0] != v {
				t.Errorf("%s: %s = %v, want %q", tt.contract, k, got[k], v)
			}
		}
	}
}

func TestNewHTTPRejects(t *testing.T) {
	send := replyWith(200, `{}`).send
	good := Options{Contract: "openai", Endpoint: "https://api.example/v1", Model: "m", Structured: StructuredSchema, MaxOutputTokens: 1, Send: send}
	tests := []struct {
		name string
		edit func(*Options)
	}{
		{"command contract", func(o *Options) { o.Contract = "command" }},
		{"anthropic schema", func(o *Options) { o.Contract = "anthropic" }},
		{"anthropic grammar", func(o *Options) { o.Contract, o.Structured = "anthropic", StructuredGrammar }},
		{"unknown structured", func(o *Options) { o.Structured = "regex" }},
		{"no scheme", func(o *Options) { o.Endpoint = "api.example/v1" }},
		{"ftp", func(o *Options) { o.Endpoint = "ftp://api.example" }},
		{"userinfo", func(o *Options) { o.Endpoint = "https://user:sk-secret@api.example/v1" }},
		{"query key", func(o *Options) { o.Endpoint = "https://api.example/v1?key=sk-secret" }},
		{"fragment", func(o *Options) { o.Endpoint = "https://api.example/v1#x" }},
		{"newline", func(o *Options) { o.Endpoint = "https://api.example/v1\r\nX-Evil: 1" }},
		{"backslash", func(o *Options) { o.Endpoint = `https://api.example\@evil.example` }},
		{"empty model", func(o *Options) { o.Model = "" }},
		{"long model", func(o *Options) { o.Model = strings.Repeat("m", maxLabelBytes+1) }},
		{"zero output", func(o *Options) { o.MaxOutputTokens = 0 }},
		{"huge output", func(o *Options) { o.MaxOutputTokens = maxOutputTokens + 1 }},
		{"negative retries", func(o *Options) { o.Retries = -1 }},
		{"too many retries", func(o *Options) { o.Retries = MaxRetries + 1 }},
		{"no send", func(o *Options) { o.Send = nil }},
	}
	if _, err := NewHTTP(good); err != nil {
		t.Fatalf("good options: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := good
			tt.edit(&o)
			_, err := NewHTTP(o)
			if !errors.Is(err, ErrOptions) {
				t.Fatalf("err = %v, want ErrOptions", err)
			}
			if strings.Contains(err.Error(), "sk-secret") {
				t.Errorf("error quotes the endpoint's credentials: %v", err)
			}
		})
	}
}

// A bad request fails before anything is sent.
func TestCompleteRejectsRequest(t *testing.T) {
	tests := []struct {
		name       string
		structured Structured
		edit       func(*Request)
	}{
		{"no purpose", StructuredPrompt, func(r *Request) { r.Purpose = "" }},
		{"empty prompt", StructuredPrompt, func(r *Request) { r.Prompt = "" }},
		{"schema missing", StructuredSchema, func(r *Request) { r.Schema = nil }},
		{"schema not object", StructuredTools, func(r *Request) { r.Schema = json.RawMessage(`["x"]`) }},
		{"schema invalid", StructuredSchema, func(r *Request) { r.Schema = json.RawMessage(`{"type":`) }},
		{"grammar missing", StructuredGrammar, func(r *Request) { r.Grammar = "" }},
		{"payload too large", StructuredPrompt, func(r *Request) { r.Prompt = strings.Repeat("a", maxPayloadBytes) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := replyWith(200, `{}`)
			h := newTestHTTP(t, "openai", tt.structured, 0, rep.send)
			req := testRequest()
			tt.edit(&req)
			_, err := Complete[verdict](context.Background(), h, req)
			if !errors.Is(err, ErrRequest) || len(rep.calls) != 0 {
				t.Fatalf("err = %v after %d calls, want ErrRequest before any call", err, len(rep.calls))
			}
		})
	}
}

func TestDecodeOutput(t *testing.T) {
	tests := []struct {
		name, content, reason string
	}{
		{"ok with spaces", " \n{\"vulnerable\":true,\"class\":\"xss\"}\n", ""},
		{"empty", "  ", reasonEmpty},
		{"null", "null", "it was not a JSON object"},
		{"array", `[{"class":"xss"}]`, "it was not a JSON object"},
		{"wrong type", `{"vulnerable":"yes","class":"xss"}`, `field "vulnerable" must be a JSON boolean`},
		{"truncated", `{"vulnerable":true`, "it was truncated JSON"},
		{"syntax", `{"vulnerable":tru}`, "it was not valid JSON (error at byte 18)"},
		{"too large", `{"class":"` + strings.Repeat("x", maxOutputBytes) + `"}`, "it was over 1048576 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, reason := decodeOutput[verdict]([]byte(tt.content))
			if reason != tt.reason {
				t.Errorf("reason = %q, want %q", reason, tt.reason)
			}
		})
	}
}

func TestCleanReasonBounds(t *testing.T) {
	got := cleanReason(strings.Repeat(string([]rune{0xe9, 0x1b, 0x202e}), 200)) // e-acute, ESC, RTL override
	if len(got) != maxReasonBytes {
		t.Errorf("len = %d, want %d", len(got), maxReasonBytes)
	}
	for i := 0; i < len(got); i++ {
		if got[i] < ' ' || got[i] > '~' {
			t.Fatalf("byte %d = %#x is not printable ASCII", i, got[i])
		}
	}
}

// Reported usage the gateway could not settle is dropped, so the
// reservation stays spent.
func TestUsageRejectsImpossibleCounts(t *testing.T) {
	tests := []struct {
		contract, body string
		ok             bool
	}{
		{"openai", `{"usage":{"prompt_tokens":3,"completion_tokens":4}}`, true},
		{"openai", `{"usage":{"prompt_tokens":-1,"completion_tokens":4}}`, false},
		{"openai", `{"usage":{"prompt_tokens":3,"completion_tokens":4294967296}}`, false},
		{"openai", `{"choices":[]}`, false},
		{"openai", `not json`, false},
		{"anthropic", `{"usage":{"input_tokens":3,"output_tokens":4}}`, true},
		{"anthropic", `{"usage":{"input_tokens":3,"output_tokens":-4}}`, false},
		{"anthropic", `{"usage":null}`, false},
	}
	for _, tt := range tests {
		w, _ := wireFor(tt.contract, StructuredPrompt)
		u, ok := w.usage([]byte(tt.body))
		if ok != tt.ok || (ok && u != (gateway.Usage{InputTokens: 3, OutputTokens: 4})) {
			t.Errorf("%s %s: usage %+v, %v; want ok=%v", tt.contract, tt.body, u, ok, tt.ok)
		}
	}
}
