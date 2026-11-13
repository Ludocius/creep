package main

import (
	"strings"
	"testing"
)

// testLayers is a small layers block: mid and side share layer 1, top and
// peer share layer 2.
const testLayers = "# intro\n\n```layers\n" +
	"# layer package          may import\n" +
	"0       internal/base    -\n" +
	"1       internal/mid     base\n" +
	"1       internal/side    base\n" +
	"2       internal/top     *\n" +
	"2       internal/peer    mid\n" +
	"3       cmd/app          top\n" +
	"-       internal/tools/* (build tooling; never imported by the product)\n" +
	"```\n"

// imp returns a Go file in package pkg that imports each module-relative path.
func imp(pkg string, paths ...string) string {
	src := "package " + pkg + "\n"
	for _, p := range paths {
		src += "import _ \"example.com/m/" + p + "\"\n"
	}
	return src
}

// TestLayerTableFailsBudget runs the layer step of `make budget` over a
// throwaway module: each import outside its row must fail, and only that.
func TestLayerTableFailsBudget(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
		want string // substring of the single problem; "" means allowed
	}{
		{"listed lower import", "internal/mid/m.go", imp("mid", "internal/base"), ""},
		{"star row imports any lower layer", "internal/top/t.go", imp("top", "internal/mid", "internal/side", "internal/base"), ""},
		{"external test imports its own package", "internal/mid/m_test.go", imp("mid_test", "internal/mid"), ""},
		{"tooling imports the product", "internal/tools/gen/g.go", imp("gen", "cmd/app", "internal/top"), ""},
		{"package missing from the table", "internal/extra/e.go", "package extra\n", "package example.com/m/internal/extra has no row"},
		{"nested look-alike is missing too", "internal/top/internal/base/b.go", "package base\n", "internal/top/internal/base has no row"},
		{"upward import", "internal/base/b.go", imp("base", "internal/mid"), "layer 0 may import only lower layers, this is layer 1"},
		{"sideways import in one layer", "internal/mid/m.go", imp("mid", "internal/side"), "layer 1 may import only lower layers, this is layer 1"},
		{"star row still rejects its own layer", "internal/top/t.go", imp("top", "internal/peer"), "layer 2 may import only lower layers, this is layer 2"},
		{"lower layer not in the row", "cmd/app/main.go", imp("main", "internal/base"), "does not list it"},
		{"upward import from a test", "internal/base/b_test.go", imp("base", "internal/top"), "may import only lower layers"},
		{"product imports tooling", "internal/top/t.go", imp("top", "internal/tools/gen"), "build tooling is never imported by the product"},
		{"import of a package missing from the table", "internal/top/t.go", imp("top", "internal/ghost"), "it has no row"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"go.mod":               "module example.com/m\n\ngo 1.24\n",
				"docs/architecture.md": testLayers,
				tt.file:                tt.body,
			})
			got, err := layerProblems(config{root: root, architecture: "docs/architecture.md"})
			if err != nil {
				t.Fatal(err)
			}
			assertOneProblem(t, got, tt.want)
		})
	}
}

// A malformed table is an error, never an empty rule set that passes.
func TestParseLayersRejectsMalformedTables(t *testing.T) {
	block := func(rows string) string { return "```layers\n" + rows + "```\n" }
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"no block", "# architecture\n", "found 0"},
		{"second copy", block("0 internal/a -\n") + block("0 internal/a -\n"), "found 2"},
		{"unclosed block", "```layers\n0 internal/a -\n", "want one closed"},
		{"layer is not a number", block("x internal/a -\n"), `layers row "x internal/a -"`},
		{"negative layer", block("-1 internal/a -\n"), "want \"<layer|-> <package>"},
		{"row without imports", block("0 internal/a\n"), "want \"<layer|-> <package>"},
		{"unknown name", block("0 internal/a -\n1 internal/b typo\n"), `internal/b: "typo" is not a package in a lower layer`},
		{"name in the same layer", block("1 internal/a -\n1 internal/b a\n"), `"a" is not a package in a lower layer`},
		{"name of a higher layer", block("2 internal/a -\n1 internal/b a\n"), `"a" is not a package in a lower layer`},
		{"name of build tooling", block("- internal/tools/* x\n1 internal/b tools/gen\n"), `"tools/gen" is not a package in a lower layer`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := parseLayers(tt.doc)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("parseLayers() = %v, %v; want error containing %q", rows, err, tt.want)
			}
		})
	}
}

// The step fails, rather than passing, when the document is missing.
func TestLayerProblemsNeedsTheDocument(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module example.com/m\n\ngo 1.24\n"})
	if _, err := layerProblems(config{root: root, architecture: "docs/architecture.md"}); err == nil {
		t.Error("layerProblems() succeeded without docs/architecture.md")
	}
}
