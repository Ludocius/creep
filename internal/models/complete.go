package models

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/sneakercreepers/creep/internal/gateway"
)

var (
	// ErrInvalidOutput is wrapped by *InvalidOutputError.
	ErrInvalidOutput = errors.New("model output invalid")
	// ErrStatus is wrapped by *StatusError.
	ErrStatus = errors.New("model endpoint returned an error status")
	// ErrMalformedReply means the reply envelope is not the contract's
	// format: the endpoint is not the API it claims to be. Not retried.
	ErrMalformedReply = errors.New("model reply is not a valid API response")
)

// InvalidOutputError means every attempt returned output that did not decode
// into the requested struct or failed its Validate. Reason is creep's own
// description of the last failure, never model text.
type InvalidOutputError struct {
	Attempts int
	Reason   string
}

func (e *InvalidOutputError) Error() string {
	return fmt.Sprintf("model output invalid after %d attempts: %s", e.Attempts, e.Reason)
}

func (e *InvalidOutputError) Unwrap() error { return ErrInvalidOutput }

// StatusError is a non-2xx reply. The body is not kept: it may echo the
// request or come from a misconfigured endpoint.
type StatusError struct {
	Status int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("model endpoint returned HTTP %d", e.Status)
}

func (e *StatusError) Unwrap() error { return ErrStatus }

// Validator is implemented by output structs that check more than their
// JSON shape. Its error message is sent back to the model on a retry, so it
// should describe the rule, not quote the value.
type Validator interface {
	Validate() error
}

// Request is one model question.
type Request struct {
	Purpose string // logged in egress.log, e.g. "reader"
	System  string // creep's instructions
	// Prompt is the user turn. Repository text in it must come from
	// gateway.FileScan fragments, already redacted.
	Prompt     string
	Redactions map[string]int // marker label -> count in System and Prompt
	// Schema is the output's JSON schema object, required for
	// StructuredSchema and StructuredTools. With StructuredSchema it is sent
	// as strict, so it must close every object (additionalProperties false).
	Schema  json.RawMessage
	Grammar string // GBNF, required for StructuredGrammar
}

// Complete asks h's model for a JSON object and decodes it into a T. Output
// that is invalid (see InvalidOutputError) is retried up to h's Retries with
// the reason appended to the prompt; any other failure returns at once.
func Complete[T any](ctx context.Context, h *HTTP, req Request) (T, error) {
	var zero T
	if err := h.checkRequest(req); err != nil {
		return zero, err
	}
	reason := ""
	for attempt := 1; ; attempt++ {
		r, err := h.attempt(ctx, req, reason)
		if err != nil {
			return zero, err
		}
		out, invalid := decodeReply[T](r)
		if invalid == "" {
			return out, nil
		}
		if attempt > h.retries {
			return zero, &InvalidOutputError{Attempts: attempt, Reason: invalid}
		}
		reason = invalid
	}
}

func (h *HTTP) checkRequest(req Request) error {
	needsSchema := h.structured == StructuredSchema || h.structured == StructuredTools
	switch {
	case !validLabel(req.Purpose):
		return fmt.Errorf("%w: purpose must be 1-%d bytes", ErrRequest, maxLabelBytes)
	case req.Prompt == "":
		return fmt.Errorf("%w: empty prompt", ErrRequest)
	case needsSchema && !isJSONObject(req.Schema):
		return fmt.Errorf("%w: %s needs a JSON schema object", ErrRequest, h.structured)
	case h.structured == StructuredGrammar && req.Grammar == "":
		return fmt.Errorf("%w: gbnf needs a grammar", ErrRequest)
	}
	return nil
}

func isJSONObject(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && t[0] == '{' && json.Valid(t)
}

// attempt sends one call and returns the model's output, or a reply that
// says why there is none. Errors are the non-retryable failures.
func (h *HTTP) attempt(ctx context.Context, req Request, reason string) (reply, error) {
	payload, err := h.wire.body(h, req, withReason(req.Prompt, reason))
	if err != nil {
		return reply{}, err
	}
	if len(payload) > maxPayloadBytes {
		return reply{}, fmt.Errorf("%w: request body over %d bytes", ErrRequest, maxPayloadBytes)
	}
	r, err := h.send(ctx, h.call(req, payload))
	if err != nil {
		return reply{}, fmt.Errorf("model call: %w", err)
	}
	if r.Status < 200 || r.Status > 299 {
		return reply{}, &StatusError{Status: r.Status}
	}
	return h.wire.parse(r.Body, h.structured)
}

// call builds the gateway call. ReserveTokens is the payload's byte count,
// an upper bound on its tokens, plus the max_tokens the body asks for.
func (h *HTTP) call(req Request, payload []byte) gateway.Call {
	return gateway.Call{
		Endpoint:      h.url,
		Model:         h.model,
		Purpose:       req.Purpose,
		Payload:       payload,
		Redactions:    req.Redactions,
		Header:        h.wire.headers(h.key),
		ReserveTokens: len(payload) + h.maxOutput,
		Usage:         h.wire.usage,
	}
}

// withReason appends the last rejection to the prompt. The reason is our own
// text, so a retry never echoes model output back.
func withReason(prompt, reason string) string {
	if reason == "" {
		return prompt
	}
	return prompt + "\n\nYour previous reply was rejected: " + reason +
		". Reply again with only output that matches the required format."
}

// validUsage accepts token counts the gateway can settle.
func validUsage(in, out int) (gateway.Usage, bool) {
	if in < 0 || out < 0 || in > math.MaxInt32 || out > math.MaxInt32 {
		return gateway.Usage{}, false
	}
	return gateway.Usage{InputTokens: in, OutputTokens: out}, true
}
