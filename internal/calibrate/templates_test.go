package calibrate

import (
	"strings"
	"testing"
	"testing/fstest"
)

const (
	testFillers = `{"version": 1, "python": ["PAGE_SIZE = 50"], "javascript": ["const PAGE_SIZE = 50;"]}`
	testSpec    = `{
  "version": 1, "id": "py-test", "class": "sqli", "language": "python", "pad_after": 1,
  "slots": {"func": ["alpha", "beta"]},
  "vulnerable": {"sink_line": 3, "marker": "run(sql)"},
  "safe": {"sink_line": 3, "marker": "run(sql, ("}
}`
	testVuln = "import db\n\ndef @@func@@(sql): return db.run(sql)\n"
	testSafe = "import db\n\ndef @@func@@(sql): return db.run(sql, ())\n"
)

// testFS is a valid one-template catalog with edit applied to template.json.
func testFS(edit func(spec, vuln, safe string) (string, string, string)) fstest.MapFS {
	spec, vuln, safe := testSpec, testVuln, testSafe
	if edit != nil {
		spec, vuln, safe = edit(spec, vuln, safe)
	}
	return fstest.MapFS{
		"fillers.json":            {Data: []byte(testFillers)},
		"py-test/template.json":   {Data: []byte(spec)},
		"py-test/vulnerable.tmpl": {Data: []byte(vuln)},
		"py-test/safe.tmpl":       {Data: []byte(safe)},
	}
}

func specEdit(old, repl string) func(string, string, string) (string, string, string) {
	return func(spec, vuln, safe string) (string, string, string) {
		return strings.Replace(spec, old, repl, 1), vuln, safe
	}
}

func TestEmbeddedCatalogCoversEveryClassAndLanguage(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	classes := map[Class]bool{}
	langs := map[Language]bool{}
	for _, tpl := range cat.templates {
		classes[tpl.class] = true
		langs[tpl.language] = true
	}
	for _, c := range Classes() {
		if !classes[c] {
			t.Errorf("no template for class %s", c)
		}
	}
	for _, l := range []Language{LanguagePython, LanguageJavaScript} {
		if !langs[l] {
			t.Errorf("no template for language %s", l)
		}
	}
	// Every template must contribute at least one pair to a run.
	if 2*len(cat.templates) > TaskCount {
		t.Errorf("%d templates do not fit in %d tasks", len(cat.templates), TaskCount)
	}
}

func TestLoadCatalogAcceptsCRLF(t *testing.T) {
	fsys := testFS(func(spec, vuln, safe string) (string, string, string) {
		return spec, strings.ReplaceAll(vuln, "\n", "\r\n"), strings.ReplaceAll(safe, "\n", "\r\n")
	})
	crlf, err := loadCatalog(fsys)
	if err != nil {
		t.Fatal(err)
	}
	lf, err := loadCatalog(testFS(nil))
	if err != nil {
		t.Fatal(err)
	}
	m := mutation{values: map[string]string{"func": "alpha"}}
	if a, b := render(crlf.templates[0], true, m), render(lf.templates[0], true, m); a != b {
		t.Errorf("CRLF template renders differently:\n%q\n%q", a.Code, b.Code)
	}
}

func TestLoadCatalogRejects(t *testing.T) {
	tests := []struct {
		name string
		edit func(string, string, string) (string, string, string)
		want string
	}{
		{"unknown field", specEdit(`"version": 1,`, `"version": 1, "extra": 1,`), "unknown field"},
		{"wrong version", specEdit(`"version": 1`, `"version": 2`), "version 2"},
		{"id differs from directory", specEdit(`"py-test"`, `"py-other"`), "directory name"},
		{"unknown class", specEdit(`"sqli"`, `"xss"`), "unknown class"},
		{"unknown language", specEdit(`"python"`, `"go"`), "no fillers"},
		{"no slots", specEdit(`{"func": ["alpha", "beta"]}`, `{}`), "no slots"},
		{"pool of one", specEdit(`["alpha", "beta"]`, `["alpha"]`), "at least 2"},
		{"value not an identifier", specEdit(`"beta"`, `"be\"ta"`), "plain identifier"},
		{"value with a dot", specEdit(`"beta"`, `"os.system"`), "plain identifier"},
		{"value is a keyword", specEdit(`"beta"`, `"return"`), "keyword"},
		{"value aliases a template word", specEdit(`"beta"`, `"sql"`), "already appears"},
		{"value aliases a filler", specEdit(`"beta"`, `"PAGE_SIZE"`), "already appears"},
		{"value repeats across slots", func(spec, vuln, safe string) (string, string, string) {
			spec = strings.Replace(spec, `"func": ["alpha", "beta"]`, `"func": ["alpha", "beta"], "arg": ["gamma", "alpha"]`, 1)
			return spec, strings.Replace(vuln, "(sql)", "(sql, @@arg@@)", 1), safe
		}, "repeats in slot"},
		{"bad slot name", specEdit(`"func"`, `"Func"`), "lowercase"},
		{"placeholder without slot", func(spec, vuln, safe string) (string, string, string) {
			return spec, vuln + "@@other@@\n", safe
		}, "has no slot"},
		{"malformed placeholder", func(spec, vuln, safe string) (string, string, string) {
			return spec, vuln + "x = @@Func\n", safe
		}, "malformed placeholder"},
		{"unused slot", specEdit(`"func": ["alpha", "beta"]`, `"func": ["alpha", "beta"], "arg": ["gamma", "delta"]`), "never used"},
		{"sink line past the end", specEdit(`"sink_line": 3, "marker": "run(sql)"`, `"sink_line": 4, "marker": "run(sql)"`), "outside"},
		{"sink line zero", specEdit(`"sink_line": 3, "marker": "run(sql, ("`, `"sink_line": 0, "marker": "run(sql, ("`), "outside"},
		{"pad after the sink", specEdit(`"pad_after": 1`, `"pad_after": 3`), "pad_after"},
		{"negative pad", specEdit(`"pad_after": 1`, `"pad_after": -1`), "pad_after"},
		{"empty marker", specEdit(`"run(sql)"`, `""`), "literal"},
		{"marker with placeholder", specEdit(`"run(sql)"`, `"@@func@@"`), "literal"},
		{"marker missing from own code", specEdit(`"run(sql)"`, `"exec(sql)"`), "not in its code"},
		{"marker also in twin", specEdit(`"run(sql)"`, `"db.run(sql"`), "also in its twin"},
		{"empty code", func(spec, _, safe string) (string, string, string) { return spec, "\n\n", safe }, "empty"},
		{"trailing json", func(spec, vuln, safe string) (string, string, string) { return spec + "{}", vuln, safe }, "trailing data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadCatalog(testFS(tt.edit))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadCatalogRejectsBadFillers(t *testing.T) {
	tests := map[string]string{
		"wrong version":  `{"version": 2, "python": ["A = 1"], "javascript": ["const A = 1;"]}`,
		"multi-line":     `{"version": 1, "python": ["A = 1\nB = 2"], "javascript": ["const A = 1;"]}`,
		"empty line":     `{"version": 1, "python": [""], "javascript": ["const A = 1;"]}`,
		"placeholder":    `{"version": 1, "python": ["@@func@@ = 1"], "javascript": ["const A = 1;"]}`,
		"unknown field":  `{"version": 1, "go": ["x"], "python": ["A = 1"], "javascript": ["const A = 1;"]}`,
		"not json":       `version: 1`,
		"no python list": `{"version": 1, "javascript": ["const A = 1;"]}`,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			fsys := testFS(nil)
			fsys["fillers.json"] = &fstest.MapFile{Data: []byte(data)}
			if _, err := loadCatalog(fsys); err == nil {
				t.Fatal("loadCatalog accepted bad fillers")
			}
		})
	}
}

func TestLoadCatalogNeedsATemplate(t *testing.T) {
	fsys := fstest.MapFS{"fillers.json": {Data: []byte(testFillers)}}
	if _, err := loadCatalog(fsys); err == nil || !strings.Contains(err.Error(), "none found") {
		t.Fatalf("err = %v, want none found", err)
	}
}
