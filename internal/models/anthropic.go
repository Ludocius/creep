package models

import (
	"encoding/json"
	"strings"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// anthropicVersion is the Messages API version creep speaks.
const anthropicVersion = "2023-06-01"

// anthropic is the Anthropic Messages API. It has no JSON-schema response
// format or grammar, so structured output is a forced tool call.
type anthropic struct{}

type anthropicRequest struct {
	Model      string               `json:"model"`
	MaxTokens  int                  `json:"max_tokens"`
	System     string               `json:"system,omitempty"`
	Messages   []chatMessage        `json:"messages"`
	Tools      []anthropicTool      `json:"tools,omitempty"`
	ToolChoice *anthropicToolChoice `json:"tool_choice,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type anthropicToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// anthropicResponse holds only the fields creep reads; others are ignored.
type anthropicResponse struct {
	Type    string `json:"type"`
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
}

type anthropicUsage struct {
	Usage *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (anthropic) path() string { return "/v1/messages" }

func (anthropic) supports(s Structured) bool {
	return s == StructuredTools || s == StructuredPrompt
}

func (anthropic) headers(k Key) map[string][]string {
	h := map[string][]string{
		"Content-Type":      {"application/json"},
		"Anthropic-Version": {anthropicVersion},
	}
	if !k.IsZero() {
		h["X-Api-Key"] = []string{k.value}
	}
	return h
}

func (anthropic) body(h *HTTP, req Request, prompt string) ([]byte, error) {
	r := anthropicRequest{
		Model: h.model, MaxTokens: h.maxOutput, System: req.System,
		Messages: []chatMessage{{Role: "user", Content: prompt}},
	}
	if h.structured == StructuredTools {
		r.Tools = []anthropicTool{{Name: outputTool, InputSchema: req.Schema}}
		r.ToolChoice = &anthropicToolChoice{Type: "tool", Name: outputTool}
	}
	return marshalBody(r)
}

func (anthropic) parse(body []byte, s Structured) (reply, error) {
	var r anthropicResponse
	if err := json.Unmarshal(body, &r); err != nil || r.Type != "message" {
		return reply{}, ErrMalformedReply
	}
	switch r.StopReason {
	case "max_tokens":
		return reply{problem: reasonTruncated}, nil
	case "refusal":
		return reply{problem: reasonRefused}, nil
	}
	if s == StructuredTools {
		return findToolUse(r), nil
	}
	var text strings.Builder
	for _, b := range r.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	return reply{content: []byte(text.String())}, nil
}

// findToolUse returns the input of the first call to the output tool.
func findToolUse(r anthropicResponse) reply {
	for _, b := range r.Content {
		if b.Type == "tool_use" && b.Name == outputTool {
			return reply{content: b.Input}
		}
	}
	return reply{problem: reasonNoTool}
}

func (anthropic) usage(body []byte) (gateway.Usage, bool) {
	var r anthropicUsage
	if json.Unmarshal(body, &r) != nil || r.Usage == nil {
		return gateway.Usage{}, false
	}
	return validUsage(r.Usage.InputTokens, r.Usage.OutputTokens)
}
