package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxOutputBytes caps the model output decoded into the caller's struct.
const maxOutputBytes = 1 << 20

// maxReasonBytes caps a rejection reason, which goes back into the prompt.
const maxReasonBytes = 256

// Rejection reasons the wire parsers report. They are fixed text, so model
// output never reaches a retry prompt or an error.
const (
	reasonTruncated = "it was cut off at the output token limit"
	reasonRefused   = "it was a refusal"
	reasonEmpty     = "it was empty"
	reasonNoTool    = `it did not call the "output" tool`
)

// reply is a parsed envelope: the model's output, or why there is none.
type reply struct {
	content []byte
	problem string
}

// decodeReply returns the output as a T, or the reason it is invalid.
func decodeReply[T any](r reply) (T, string) {
	var zero T
	if r.problem != "" {
		return zero, r.problem
	}
	return decodeOutput[T](r.content)
}

// decodeOutput decodes one JSON object into a fresh T, refusing unknown
// fields and trailing data, then runs T's Validate if it has one.
func decodeOutput[T any](content []byte) (T, string) {
	var v T
	trimmed := bytes.TrimSpace(content)
	switch {
	case len(trimmed) == 0:
		return v, reasonEmpty
	case len(trimmed) > maxOutputBytes:
		return v, fmt.Sprintf("it was over %d bytes", maxOutputBytes)
	case trimmed[0] != '{':
		return v, "it was not a JSON object"
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, jsonReason(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return v, "it had data after the JSON object"
	}
	if val, ok := any(&v).(Validator); ok {
		if err := val.Validate(); err != nil {
			return v, "it broke a rule: " + cleanReason(err.Error())
		}
	}
	return v, ""
}

// jsonReason describes a decode error without quoting the input: field
// names come from the caller's struct tags, never from the model.
func jsonReason(err error) string {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return fmt.Sprintf("it was not valid JSON (error at byte %d)", syntax.Offset)
	case errors.As(err, &typ):
		return fmt.Sprintf("field %q must be a JSON %s", cleanReason(typ.Field), jsonKind(typ.Type.Kind().String()))
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "it was truncated JSON"
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "it had a field the schema does not allow"
	}
	return "it did not match the schema"
}

// jsonKind names a Go kind the way the schema does.
func jsonKind(kind string) string {
	switch {
	case kind == "bool":
		return "boolean"
	case strings.HasPrefix(kind, "int"), strings.HasPrefix(kind, "uint"), strings.HasPrefix(kind, "float"):
		return "number"
	case kind == "slice", kind == "array":
		return "array"
	case kind == "struct", kind == "map":
		return "object"
	}
	return kind
}

// cleanReason bounds a Validate message and keeps only printable ASCII, so
// a value it quotes cannot inject lines, escapes or bidi controls into the
// prompt or a terminal.
func cleanReason(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < maxReasonBytes; i++ {
		c := s[i]
		if c < ' ' || c > '~' {
			c = '?'
		}
		b.WriteByte(c)
	}
	return b.String()
}
