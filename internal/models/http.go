package models

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sneakercreepers/creep/internal/gateway"
)

const (
	// MaxRetries caps Options.Retries: each retry is a full, budgeted call.
	MaxRetries = 5
	// maxOutputTokens caps Options.MaxOutputTokens, which is also reserved
	// from the budget on every call.
	maxOutputTokens = 1 << 20
	// maxPayloadBytes caps one request body, so a reservation (payload bytes
	// plus output cap) always fits the gateway's 2^31-1 budget limits.
	maxPayloadBytes = 8 << 20
	// maxLabelBytes matches the gateway's limit on logged labels.
	maxLabelBytes = 256
)

// Structured is how a request constrains the model to the output schema.
type Structured string

const (
	StructuredSchema  Structured = "json_schema" // response_format json_schema (OpenAI-compatible)
	StructuredGrammar Structured = "gbnf"        // llama.cpp grammar (OpenAI-compatible)
	StructuredTools   Structured = "tools"       // a forced call to the "output" tool
	StructuredPrompt  Structured = "prompt"      // no constraint; the prompt asks for JSON
)

var (
	// ErrOptions means NewHTTP got an unusable option. Messages never quote
	// the endpoint, which may carry credentials.
	ErrOptions = errors.New("invalid model options")
	// ErrRequest means Complete got an unusable Request.
	ErrRequest = errors.New("invalid model request")
)

// SendFunc sends one call. In production it is Through(log, client); tests
// replay recorded replies.
type SendFunc func(ctx context.Context, call gateway.Call) (*gateway.Reply, error)

// Through sends every call with log.Send, so consent, budget, egress.log and
// the allowlisted client apply.
func Through(log *gateway.EgressLog, client *gateway.Client) SendFunc {
	return func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		return log.Send(ctx, client, call)
	}
}

// Options configures NewHTTP. Contract, Endpoint and Model come from the
// resolved config (model.contract, model.endpoint, model.name).
type Options struct {
	Contract string // "openai" or "anthropic"
	// Endpoint is the API base URL as the providers' SDKs take it:
	// "https://api.openai.com/v1" or "http://localhost:11434/v1" for
	// OpenAI-compatible APIs (/chat/completions is appended),
	// "https://api.anthropic.com" for Anthropic (/v1/messages is appended).
	// It may not carry userinfo, a query or a fragment.
	Endpoint        string
	Model           string
	Key             Key        // KeyFromEnv; zero sends no credentials
	Structured      Structured // what the endpoint supports
	MaxOutputTokens int        // request's max_tokens and per-call reservation; 1 to 2^20
	Retries         int        // retries after an invalid reply; 0 to MaxRetries
	Send            SendFunc
}

// HTTP is a configured client for one model endpoint. It is safe for
// concurrent use; the gateway bounds concurrency per endpoint.
type HTTP struct {
	wire       wire
	url        string
	model      string
	key        Key
	structured Structured
	maxOutput  int
	retries    int
	send       SendFunc
}

// NewHTTP validates opts and returns a client for them.
func NewHTTP(opts Options) (*HTTP, error) {
	w, err := wireFor(opts.Contract, opts.Structured)
	if err != nil {
		return nil, err
	}
	url, err := endpointURL(opts.Endpoint, w.path())
	if err != nil {
		return nil, err
	}
	if err := checkLimits(opts); err != nil {
		return nil, err
	}
	return &HTTP{
		wire: w, url: url, model: opts.Model, key: opts.Key,
		structured: opts.Structured, maxOutput: opts.MaxOutputTokens,
		retries: opts.Retries, send: opts.Send,
	}, nil
}

func wireFor(contract string, s Structured) (wire, error) {
	var w wire
	switch contract {
	case "openai":
		w = openAI{}
	case "anthropic":
		w = anthropic{}
	default:
		return nil, fmt.Errorf("%w: contract must be openai or anthropic", ErrOptions)
	}
	if !w.supports(s) {
		return nil, fmt.Errorf("%w: contract %s does not support structured output %q", ErrOptions, contract, s)
	}
	return w, nil
}

// endpointURL appends path to an http(s) base URL. The gateway parses and
// allowlists the result; here we only refuse what could carry credentials
// into the URL (userinfo, query) or change its meaning (fragment, spaces).
func endpointURL(base, path string) (string, error) {
	scheme := strings.HasPrefix(base, "https://") || strings.HasPrefix(base, "http://")
	if !scheme || strings.ContainsAny(base, "?#@\\") || hasControlOrSpace(base) {
		return "", fmt.Errorf("%w: endpoint must be an http(s) URL without userinfo, query or fragment", ErrOptions)
	}
	return strings.TrimRight(base, "/") + path, nil
}

func hasControlOrSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func checkLimits(opts Options) error {
	switch {
	case !validLabel(opts.Model):
		return fmt.Errorf("%w: model name must be 1-%d bytes", ErrOptions, maxLabelBytes)
	case opts.MaxOutputTokens < 1 || opts.MaxOutputTokens > maxOutputTokens:
		return fmt.Errorf("%w: max output tokens must be 1-%d", ErrOptions, maxOutputTokens)
	case opts.Retries < 0 || opts.Retries > MaxRetries:
		return fmt.Errorf("%w: retries must be 0-%d", ErrOptions, MaxRetries)
	case opts.Send == nil:
		return fmt.Errorf("%w: no SendFunc", ErrOptions)
	}
	return nil
}

func validLabel(s string) bool {
	return s != "" && len(s) <= maxLabelBytes
}
