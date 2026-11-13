package main

import (
	"os"
	"regexp"
	"testing"
)

// TestNetImportFailsBudget runs the import step of `make budget` over a
// throwaway module: a package that imports net/http, or any network package,
// outside internal/gateway must fail, whether the import sits in shipped code,
// an in-package test, an external _test package or dev tooling.
func TestNetImportFailsBudget(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
		want string // substring of the single problem; "" means allowed
	}{
		{"net/http in a package", "internal/probe/p.go", "package probe\nimport _ \"net/http\"\n", `internal/probe/p.go imports "net/http"`},
		{"net/http in a test", "internal/probe/p_test.go", "package probe\nimport _ \"net/http\"\n", `p_test.go imports "net/http"`},
		{"httptest in an external test", "internal/probe/x_test.go", "package probe_test\nimport _ \"net/http/httptest\"\n", `x_test.go imports "net/http/httptest"`},
		{"net/http in dev tooling", "internal/tools/fetch/f.go", "package fetch\nimport _ \"net/http\"\n", `internal/tools/fetch/f.go imports "net/http"`},
		{"net/http in cmd", "cmd/creep/main.go", "package main\nimport _ \"net/http\"\nfunc main() {}\n", `cmd/creep/main.go imports "net/http"`},
		{"net", "internal/probe/p.go", "package probe\nimport _ \"net\"\n", "network access"},
		{"net/rpc", "internal/probe/p.go", "package probe\nimport _ \"net/rpc\"\n", "network access"},
		{"net/smtp", "internal/probe/p.go", "package probe\nimport _ \"net/smtp\"\n", "network access"},
		{"crypto/tls", "internal/probe/p.go", "package probe\nimport _ \"crypto/tls\"\n", "network access"},
		{"gateway may use net/http", "internal/gateway/g.go", "package gateway\nimport _ \"net/http\"\n", ""},
		{"gateway tests may use httptest", "internal/gateway/g_test.go", "package gateway\nimport _ \"net/http/httptest\"\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"go.mod": "module example.com/m\n\ngo 1.24\n",
				tt.file:  tt.body,
			})
			got, err := importProblems(config{root: root})
			if err != nil {
				t.Fatal(err)
			}
			assertOneProblem(t, got, tt.want)
		})
	}
}

// TestMakeCheckRunsBudget pins the wiring the tests rely on: `make check`
// depends on the budget target, which runs this tool, and on tidy.
func TestMakeCheckRunsBudget(t *testing.T) {
	data, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^check:[^\n]*\sbudget(\s|$)`).Match(data) {
		t.Error("Makefile: check does not depend on budget")
	}
	if !regexp.MustCompile(`(?m)^budget:\r?\n\tgo run \./internal/tools/budget\s*$`).Match(data) {
		t.Error("Makefile: budget does not run ./internal/tools/budget")
	}
	// directModules trusts go.mod's // indirect marks only because tidy -diff checks them.
	if !regexp.MustCompile(`(?m)^check:[^\n]*\stidy(\s|$)`).Match(data) || !regexp.MustCompile(`(?m)^tidy:\r?\n\tgo mod tidy -diff\s*$`).Match(data) {
		t.Error("Makefile: check does not run go mod tidy -diff")
	}
}
