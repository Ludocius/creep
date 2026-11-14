package calibrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// classNone is the answer class for code the model judges safe.
const classNone = "none"

// maxAnswerLine bounds the line a task answer may name; tasks are short.
const maxAnswerLine = 9999

// maxArgumentBytes bounds a tool argument or a context value.
const maxArgumentBytes = 128

// The tools the tool-calling probe offers. Only their names reach the model.
const (
	toolReadFile = "read_file"
	toolListDir  = "list_dir"
	toolSearch   = "search_code"
)

var probeTools = []string{toolReadFile, toolListDir, toolSearch}

// taskAnswer is the model's verdict on one task. It is a closed struct:
// models.Complete refuses unknown fields, then runs Validate.
type taskAnswer struct {
	Vulnerable bool   `json:"vulnerable"`
	Class      string `json:"class"`
	Line       int    `json:"line"`
}

func (a *taskAnswer) Validate() error {
	if !a.Vulnerable {
		if a.Class != classNone || a.Line != 0 {
			return errors.New("a safe verdict needs class none and line 0")
		}
		return nil
	}
	if !slices.Contains(Classes(), Class(a.Class)) {
		return fmt.Errorf("class must be one of %s", classList())
	}
	if a.Line < 1 || a.Line > maxAnswerLine {
		return fmt.Errorf("line must be 1-%d for a vulnerable verdict", maxAnswerLine)
	}
	return nil
}

// toolAnswer is the tool call the model chose.
type toolAnswer struct {
	Tool     string `json:"tool"`
	Argument string `json:"argument"`
}

func (a *toolAnswer) Validate() error {
	if !slices.Contains(probeTools, a.Tool) {
		return fmt.Errorf("tool must be one of %s", strings.Join(probeTools, ", "))
	}
	if a.Argument == "" || len(a.Argument) > maxArgumentBytes {
		return fmt.Errorf("argument must be 1-%d bytes", maxArgumentBytes)
	}
	return nil
}

// contextAnswer is the value the model found in a long input.
type contextAnswer struct {
	Value string `json:"value"`
}

func (a *contextAnswer) Validate() error {
	if a.Value == "" || len(a.Value) > maxArgumentBytes {
		return fmt.Errorf("value must be 1-%d bytes", maxArgumentBytes)
	}
	return nil
}

// answerClasses is classNone followed by every class, as answer strings.
func answerClasses() []string {
	names := []string{classNone}
	for _, c := range Classes() {
		names = append(names, string(c))
	}
	return names
}

func classList() string { return strings.Join(answerClasses(), ", ") }

// enumJSON renders names as a JSON array for a schema enum.
func enumJSON(names []string) string {
	b, err := json.Marshal(names)
	if err != nil {
		panic(err) // a []string always marshals
	}
	return string(b)
}

// gbnfAlternatives renders names as GBNF alternatives of JSON strings.
func gbnfAlternatives(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = `"\"` + n + `\""`
	}
	return strings.Join(quoted, " | ")
}

func taskSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` +
		`"vulnerable":{"type":"boolean"},` +
		`"class":{"type":"string","enum":` + enumJSON(answerClasses()) + `},` +
		`"line":{"type":"integer","minimum":0,"maximum":9999}},` +
		`"required":["vulnerable","class","line"],"additionalProperties":false}`)
}

func taskGrammar() string {
	return `root ::= "{" ws "\"vulnerable\":" ws ("true" | "false") ws "," ws "\"class\":" ws class ws "," ws "\"line\":" ws num ws "}"` + "\n" +
		`class ::= ` + gbnfAlternatives(answerClasses()) + "\n" +
		`num ::= [0-9] [0-9]? [0-9]? [0-9]?` + "\n" +
		`ws ::= [ \t\n]*` + "\n"
}

func toolSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` +
		`"tool":{"type":"string","enum":` + enumJSON(probeTools) + `},` +
		`"argument":{"type":"string","maxLength":128}},` +
		`"required":["tool","argument"],"additionalProperties":false}`)
}

func toolGrammar() string {
	return `root ::= "{" ws "\"tool\":" ws tool ws "," ws "\"argument\":" ws arg ws "}"` + "\n" +
		`tool ::= ` + gbnfAlternatives(probeTools) + "\n" +
		`arg ::= "\"" [a-zA-Z0-9_./-]+ "\""` + "\n" +
		`ws ::= [ \t\n]*` + "\n"
}

func contextSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` +
		`"value":{"type":"string","maxLength":128}},` +
		`"required":["value"],"additionalProperties":false}`)
}

func contextGrammar() string {
	return `root ::= "{" ws "\"value\":" ws "\"" [a-z0-9-]+ "\"" ws "}"` + "\n" +
		`ws ::= [ \t\n]*` + "\n"
}
