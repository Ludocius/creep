package calibrate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnswerValidate(t *testing.T) {
	long := strings.Repeat("a", maxArgumentBytes+1)
	tests := []struct {
		name string
		v    interface{ Validate() error }
		ok   bool
	}{
		{"safe", &taskAnswer{Class: classNone}, true},
		{"safe with a class", &taskAnswer{Class: "sqli"}, false},
		{"safe with a line", &taskAnswer{Class: classNone, Line: 3}, false},
		{"vulnerable", &taskAnswer{Vulnerable: true, Class: "idor", Line: 4}, true},
		{"vulnerable class none", &taskAnswer{Vulnerable: true, Class: classNone, Line: 4}, false},
		{"unknown class", &taskAnswer{Vulnerable: true, Class: "xss", Line: 4}, false},
		{"line 0", &taskAnswer{Vulnerable: true, Class: "idor"}, false},
		{"negative line", &taskAnswer{Vulnerable: true, Class: "idor", Line: -1}, false},
		{"line too large", &taskAnswer{Vulnerable: true, Class: "idor", Line: maxAnswerLine + 1}, false},
		{"tool", &toolAnswer{Tool: toolListDir, Argument: "lib/x"}, true},
		{"unknown tool", &toolAnswer{Tool: "exec", Argument: "ls"}, false},
		{"empty argument", &toolAnswer{Tool: toolReadFile}, false},
		{"long argument", &toolAnswer{Tool: toolReadFile, Argument: long}, false},
		{"value", &contextAnswer{Value: "amber-onyx-0001"}, true},
		{"empty value", &contextAnswer{}, false},
		{"long value", &contextAnswer{Value: long}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.v.Validate(); (err == nil) != tt.ok {
				t.Errorf("Validate() = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

// Schemas are sent strict, so each must be a closed JSON object; grammars
// must offer every answer the Validate accepts.
func TestSchemasAndGrammars(t *testing.T) {
	for _, s := range []json.RawMessage{taskSchema(), toolSchema(), contextSchema()} {
		var m map[string]any
		if err := json.Unmarshal(s, &m); err != nil {
			t.Fatalf("schema is not JSON: %v", err)
		}
		if m["additionalProperties"] != false {
			t.Errorf("schema is not closed: %s", s)
		}
	}
	for _, c := range answerClasses() {
		if !strings.Contains(string(taskSchema()), `"`+c+`"`) || !strings.Contains(taskGrammar(), `\"`+c+`\"`) {
			t.Errorf("class %s missing from the task schema or grammar", c)
		}
	}
	for _, tool := range probeTools {
		if !strings.Contains(toolGrammar(), tool) {
			t.Errorf("tool %s missing from the grammar", tool)
		}
	}
}

// Token budget: system prompts are sent on every call, so they stay small.
// A byte bounds a token, so the cap holds for every tokenizer. The task
// prompt names every class and the tools prompt every tool.
func TestSystemPrompts(t *testing.T) {
	const maxSystemBytes = 1024
	for name, p := range map[string]string{"task": taskSystem, "tools": toolsSystem, "context": contextSystem} {
		if p == "" || len(p) > maxSystemBytes {
			t.Errorf("%s prompt is %d bytes, want 1-%d", name, len(p), maxSystemBytes)
		}
	}
	for _, c := range Classes() {
		if !strings.Contains(taskSystem, string(c)) {
			t.Errorf("task prompt does not name %s", c)
		}
	}
	for _, tool := range probeTools {
		if !strings.Contains(toolsSystem, tool) {
			t.Errorf("tools prompt does not name %s", tool)
		}
	}
}
