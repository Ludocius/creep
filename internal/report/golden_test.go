package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/state"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/golden")

// hostilePaths are file names a scanned repository can hold. Each must reach
// every format intact but inert.
var hostilePaths = []string{
	"app/`tick`|pipe.py",
	"www.evil.example/[link](http://x)<script>.js",
	"ok\x1b[31mred\nnewline.py",
	"bidi" + string(rune(0x202e)) + "gnp.exe", // right-to-left override
	"bad\xffutf8 #?%.py",
}

const sampleEgress = `{"v":1,"type":"request","id":"r1","time":"t","endpoint":"https://api.example.com/v1/messages","model":"m-large","purpose":"read","bytes":1200,"sha256":"x","redactions":{"AWS_KEY":2},"payload_file":"payloads/r1.payload"}
{"v":1,"type":"result","id":"r1","time":"t","outcome":"ok","status":200,"tokens":{"input":300,"output":40}}
{"v":1,"type":"request","id":"r2","time":"t","endpoint":"https://api.example.com/v1/messages","model":"m-small","purpose":"read","bytes":800,"sha256":"y","redactions":{"EMAIL":1,"AWS_KEY":1},"payload_file":"payloads/r2.payload"}
{"v":1,"type":"request","id":"r3","time":"t","endpoint":"http://127.0.0.1:8080/v1/chat/completions","model":"local|model","purpose":"calibrate","bytes":50,"sha256":"z","redactions":{},"payload_file":"payloads/r3.payload"}
{"v":1,"type":"result","id":"r3","time":"t","outcome":"http_error","status":500}
`

func sampleInput(t *testing.T, incomplete bool) Input {
	t.Helper()
	dh, err := SummarizeEgress(strings.NewReader(sampleEgress))
	if err != nil {
		t.Fatal(err)
	}
	in := Input{
		Run: state.Summary{Ended: true, Outcome: state.OutcomeComplete},
		Findings: []Finding{
			{ID: "f4", Class: "ssrf", Status: StatusNotEvaluated, Path: "svc/fetch.js", Line: 9},
			{ID: "f3", Class: "sqli", Status: StatusDiscarded, Path: "app/db.py", Line: 40},
			{ID: "f2", Class: "path_traversal", Status: StatusProbable, Path: hostilePaths[0], Line: 7},
			{ID: "f1", Class: "sqli", Status: StatusVerified, Path: "app/db.py", Line: 12},
			{ID: "f5", Class: "command_injection", Status: StatusProbable, Path: hostilePaths[4], Line: 0},
		},
		Classes: []ClassCoverage{
			{Class: "sqli", Status: ClassCovered, Detected: 9, Tasks: 10},
			{Class: "path_traversal", Status: ClassPartial, Detected: 3, Tasks: 6},
			{Class: "ssrf", Status: ClassNotEvaluated},
		},
		NotEvaluated: []NotEvaluated{
			{Path: hostilePaths[1], Reason: SkipTooLarge},
			{Path: hostilePaths[2], Reason: SkipLineTooLong},
			{Path: hostilePaths[3], Reason: SkipReadFailed},
		},
		DataHandling: dh,
	}
	if incomplete {
		in.ScanIncomplete = true
		in.Run = state.Summary{Ended: true, Outcome: state.OutcomeIncomplete, Reason: "redact_run_full"}
		in.NotEvaluated = append(in.NotEvaluated,
			NotEvaluated{Path: "lib/after.py", Reason: SkipRunFull},
			NotEvaluated{Path: "lib/later.py", Reason: SkipRunFull})
	}
	return in
}

// newTestReport builds a report with a fixed tool identity so golden files
// do not depend on how the test binary was built.
func newTestReport(t *testing.T, in Input) *Report {
	t.Helper()
	r, err := New(in)
	if err != nil {
		t.Fatal(err)
	}
	r.Tool = Tool{Name: "creep", Version: "v0.0.0-test", Commit: "0000000"}
	return r
}

type format struct {
	ext   string
	write func(*bytes.Buffer, *Report) error
}

var formats = []format{
	{"json", func(b *bytes.Buffer, r *Report) error { return WriteJSON(b, r) }},
	{"sarif", func(b *bytes.Buffer, r *Report) error { return WriteSARIF(b, r) }},
	{"md", func(b *bytes.Buffer, r *Report) error { return WriteMarkdown(b, r) }},
}

func render(t *testing.T, r *Report) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, f := range formats {
		var b bytes.Buffer
		if err := f.write(&b, r); err != nil {
			t.Fatal(err)
		}
		out[f.ext] = b.Bytes()
	}
	return out
}

func TestGolden(t *testing.T) {
	for _, name := range []string{"complete", "incomplete"} {
		r := newTestReport(t, sampleInput(t, name == "incomplete"))
		for ext, got := range render(t, r) {
			t.Run(name+"."+ext, func(t *testing.T) {
				path := filepath.Join("testdata", "golden", name+"."+ext)
				if *update {
					if err := os.WriteFile(path, got, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%v (run go test ./internal/report -update)", err)
				}
				if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
					t.Errorf("%s differs from golden; got:\n%s", path, got)
				}
			})
		}
	}
}

func TestSARIFValidatesAgainstOfficialSchema(t *testing.T) {
	schema := loadJSON(t, filepath.Join("testdata", "sarif-schema-2.1.0.json"))
	for _, incomplete := range []bool{false, true} {
		var b bytes.Buffer
		if err := WriteSARIF(&b, newTestReport(t, sampleInput(t, incomplete))); err != nil {
			t.Fatal(err)
		}
		assertValid(t, schema, b.Bytes())
	}
	var b bytes.Buffer
	if err := WriteSARIF(&b, newTestReport(t, Input{})); err != nil {
		t.Fatal(err)
	}
	assertValid(t, schema, b.Bytes())
}

func TestJSONValidatesAgainstPublishedSchema(t *testing.T) {
	schema := loadJSON(t, filepath.Join("..", "..", "docs", "schemas", "report-v1.json"))
	for _, in := range []Input{sampleInput(t, false), sampleInput(t, true), {}} {
		var b bytes.Buffer
		if err := WriteJSON(&b, newTestReport(t, in)); err != nil {
			t.Fatal(err)
		}
		assertValid(t, schema, b.Bytes())
	}
}

func assertValid(t *testing.T, schema any, doc []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatal(err)
	}
	for _, e := range validateSchema(schema, v) {
		t.Error(e)
	}
}
