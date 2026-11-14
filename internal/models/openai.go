package models

import (
	"encoding/json"
	"fmt"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// outputTool is the one tool a StructuredTools request offers and forces.
const outputTool = "output"

// wire is one HTTP contract's request and reply format.
type wire interface {
	path() string
	supports(Structured) bool
	headers(Key) map[string][]string
	body(h *HTTP, req Request, prompt string) ([]byte, error)
	parse(body []byte, s Structured) (reply, error)
	usage(body []byte) (gateway.Usage, bool)
}

// openAI is the OpenAI-compatible chat completions contract. max_tokens,
// not max_completion_tokens, because compatible servers know only it.
type openAI struct{}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model          string            `json:"model"`
	Messages       []chatMessage     `json:"messages"`
	MaxTokens      int               `json:"max_tokens"`
	ResponseFormat *responseFormat   `json:"response_format,omitempty"`
	Grammar        string            `json:"grammar,omitempty"`
	Tools          []openAITool      `json:"tools,omitempty"`
	ToolChoice     *openAIToolChoice `json:"tool_choice,omitempty"`
}

type responseFormat struct {
	Type       string     `json:"type"`
	JSONSchema namedShape `json:"json_schema"`
}

type namedShape struct {
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIFunction `json:"function"`
}

type openAIFunction struct {
	Name       string          `json:"name"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
}

type openAIToolChoice struct {
	Type     string         `json:"type"`
	Function openAIFunction `json:"function"`
}

// openAIResponse holds only the fields creep reads; others are ignored.
type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content   *string `json:"content"`
			Refusal   *string `json:"refusal"`
			ToolCalls []struct {
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

type openAIUsage struct {
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (openAI) path() string { return "/chat/completions" }

func (openAI) supports(s Structured) bool {
	return s == StructuredSchema || s == StructuredGrammar || s == StructuredTools || s == StructuredPrompt
}

func (openAI) headers(k Key) map[string][]string {
	h := map[string][]string{"Content-Type": {"application/json"}}
	if !k.IsZero() {
		h["Authorization"] = []string{"Bearer " + k.value}
	}
	return h
}

func (openAI) body(h *HTTP, req Request, prompt string) ([]byte, error) {
	r := openAIRequest{Model: h.model, MaxTokens: h.maxOutput}
	if req.System != "" {
		r.Messages = append(r.Messages, chatMessage{Role: "system", Content: req.System})
	}
	r.Messages = append(r.Messages, chatMessage{Role: "user", Content: prompt})
	switch h.structured {
	case StructuredSchema:
		r.ResponseFormat = &responseFormat{Type: "json_schema", JSONSchema: namedShape{Name: outputTool, Strict: true, Schema: req.Schema}}
	case StructuredGrammar:
		r.Grammar = req.Grammar
	case StructuredTools:
		r.Tools = []openAITool{{Type: "function", Function: openAIFunction{Name: outputTool, Parameters: req.Schema}}}
		r.ToolChoice = &openAIToolChoice{Type: "function", Function: openAIFunction{Name: outputTool}}
	}
	return marshalBody(r)
}

func (openAI) parse(body []byte, s Structured) (reply, error) {
	var r openAIResponse
	if err := json.Unmarshal(body, &r); err != nil || len(r.Choices) == 0 {
		return reply{}, ErrMalformedReply
	}
	c := r.Choices[0]
	switch {
	case c.FinishReason == "length":
		return reply{problem: reasonTruncated}, nil
	case c.Message.Refusal != nil && *c.Message.Refusal != "":
		return reply{problem: reasonRefused}, nil
	case s == StructuredTools:
		for _, call := range c.Message.ToolCalls {
			if call.Function.Name == outputTool {
				return reply{content: []byte(call.Function.Arguments)}, nil
			}
		}
		return reply{problem: reasonNoTool}, nil
	case c.Message.Content == nil:
		return reply{problem: reasonEmpty}, nil
	}
	return reply{content: []byte(*c.Message.Content)}, nil
}

func (openAI) usage(body []byte) (gateway.Usage, bool) {
	var r openAIUsage
	if json.Unmarshal(body, &r) != nil || r.Usage == nil {
		return gateway.Usage{}, false
	}
	return validUsage(r.Usage.PromptTokens, r.Usage.CompletionTokens)
}

// marshalBody encodes a request body. Schema bytes were checked by
// checkRequest, so an error here is a bug, reported without the payload.
func marshalBody(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: encode body: %w", ErrRequest, err)
	}
	return b, nil
}
