package testapps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

const (
	schemaVersion = 1
	maxAppLines   = 200 // per variant, issue #16
	expectedFile  = "expected.json"
)

// classes is the closed set of vulnerability classes an expected finding may
// name. Adding one is a schema change.
var classes = map[string]bool{
	"sqli": true, "nosql_injection": true, "command_injection": true,
	"ssrf": true, "path_traversal": true, "idor": true,
	"missing_auth": true, "prototype_pollution": true,
}

// languages maps each allowed language to the only source extension its apps may use.
var languages = map[string]string{"python": ".py", "javascript": ".js"}

type expectation struct {
	SchemaVersion int        `json:"schema_version"`
	App           string     `json:"app"`
	Language      string     `json:"language"`
	Framework     string     `json:"framework"`
	Vulnerable    []finding  `json:"vulnerable"`
	Safe          *[]finding `json:"safe"` // pointer: a missing list must fail, not read as empty
}

type finding struct {
	Class string `json:"class"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Route string `json:"route"`
	Sink  string `json:"sink"`
}

func decodeExpectation(data []byte) (expectation, error) {
	var e expectation
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, err
	}
	if dec.More() {
		return e, fmt.Errorf("trailing data after the object")
	}
	return e, nil
}

// checkApp reports every way the app directory dir of fsys disagrees with its
// expected.json.
func checkApp(fsys fs.FS, dir string) []string {
	data, err := fs.ReadFile(fsys, path.Join(dir, expectedFile))
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	e, err := decodeExpectation(data)
	if err != nil {
		return []string{fmt.Sprintf("%s/%s: %v", dir, expectedFile, err)}
	}
	problems := checkHeader(dir, e)
	if len(problems) > 0 {
		return problems
	}
	ext := languages[e.Language]
	problems = append(problems, checkVariants(fsys, dir, ext)...)
	for i, f := range e.Vulnerable {
		problems = append(problems, checkFinding(fsys, dir, i, f)...)
	}
	return problems
}

func checkHeader(dir string, e expectation) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("%s/%s: ", dir, expectedFile)+fmt.Sprintf(format, args...))
	}
	if e.SchemaVersion != schemaVersion {
		add("schema_version %d, want %d", e.SchemaVersion, schemaVersion)
	}
	if e.App != path.Base(dir) {
		add("app %q, want the directory name %q", e.App, path.Base(dir))
	}
	if languages[e.Language] == "" {
		add("language %q is not one of python, javascript", e.Language)
	}
	if e.Framework == "" {
		add("framework is empty")
	}
	if len(e.Vulnerable) == 0 {
		add("vulnerable lists no findings")
	}
	if e.Safe == nil || len(*e.Safe) > 0 {
		add("safe must be present and list zero findings")
	}
	return problems
}

func checkFinding(fsys fs.FS, dir string, i int, f finding) []string {
	where := fmt.Sprintf("%s/%s: vulnerable[%d]", dir, expectedFile, i)
	if !classes[f.Class] {
		return []string{fmt.Sprintf("%s: class %q is not in the closed set", where, f.Class)}
	}
	if f.Sink == "" || f.Route == "" {
		return []string{where + ": sink and route must be set"}
	}
	if !fs.ValidPath(f.File) || strings.Contains(f.File, "/") {
		return []string{fmt.Sprintf("%s: file %q must name a file in the variant directory", where, f.File)}
	}
	data, err := fs.ReadFile(fsys, path.Join(dir, "vulnerable", f.File))
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", where, err)}
	}
	lines := strings.Split(string(data), "\n")
	if f.Line < 1 || f.Line > len(lines) {
		return []string{fmt.Sprintf("%s: line %d is outside %s (%d lines)", where, f.Line, f.File, len(lines))}
	}
	var problems []string
	if !strings.Contains(lines[f.Line-1], f.Sink) {
		problems = append(problems, fmt.Sprintf("%s: line %d of %s does not contain sink %q", where, f.Line, f.File, f.Sink))
	}
	if !bytes.Contains(data, []byte(f.Route)) {
		problems = append(problems, fmt.Sprintf("%s: route %q does not appear in %s", where, f.Route, f.File))
	}
	return problems
}
