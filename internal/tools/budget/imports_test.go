package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

const testMod = "example.com/m"

// Each case is one way to reach the network outside the gateway; all must fail.
func TestCheckImports(t *testing.T) {
	tests := []struct {
		name string
		file string
		imp  string
		want string // substring of the single problem; "" means allowed
	}{
		{"gateway may use net/http", "internal/gateway/client.go", "net/http", ""},
		{"gateway subpackage may use net", "internal/gateway/tlsconf/t.go", "crypto/tls", ""},
		{"nested look-alike gateway", "internal/cli/internal/gateway/g.go", "net/http", "network access"},
		{"gateway name prefix look-alike", "internal/gatewayx/g.go", "net", "network access"},
		{"net outside gateway", "internal/cli/x.go", "net", "network access"},
		{"net/url outside gateway", "internal/cli/x.go", "net/url", "network access"},
		{"net/netip is pure values", "internal/cli/x.go", "net/netip", ""},
		{"crypto/tls dials", "internal/cli/x.go", "crypto/tls", "network access"},
		{"log/syslog dials", "internal/cli/x.go", "log/syslog", "network access"},
		{"x/net", "internal/cli/x.go", "golang.org/x/net/proxy", "network access"},
		{"syscall sockets", "internal/cli/x.go", "syscall", "raw system calls"},
		{"syscall/js", "internal/cli/x.go", "syscall/js", "raw system calls"},
		{"x/sys/unix", "internal/cli/x.go", "golang.org/x/sys/unix", "raw system calls"},
		{"x/sys root", "internal/cli/x.go", "golang.org/x/sys", "raw system calls"},
		{"cgo", "internal/cli/x.go", "C", "foreign or unchecked"},
		{"runtime/cgo", "internal/cli/x.go", "runtime/cgo", "foreign or unchecked"},
		{"plugin", "internal/cli/x.go", "plugin", "foreign or unchecked"},
		{"unsafe linkname", "internal/cli/x.go", "unsafe", "foreign or unchecked"},
		{"os/exec curl", "internal/cli/x.go", "os/exec", "running programs"},
		{"os/exec in cmd/creep non-test", "cmd/creep/main.go", "os/exec", "running programs"},
		{"os/exec in nested tools look-alike", "internal/cli/internal/tools/x.go", "os/exec", "running programs"},
		{"os/exec in dev tools", "internal/tools/budget/main.go", "os/exec", ""},
		{"os/exec in cmd/creep tests", "cmd/creep/main_test.go", "os/exec", ""},
		{"net in tests", "internal/cli/x_test.go", "net/http/httptest", "network access"},
		{"allowlisted syscall file", "internal/cli/open_unix.go", "syscall", ""},
		{"allowlisted file may not use x/sys", "internal/cli/open_unix.go", "golang.org/x/sys/unix", "raw system calls"},
		{"plain stdlib", "internal/cli/x.go", "os", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{tt.file: {Data: []byte("package x\nimport _ \"" + tt.imp + "\"\n")}}
			files, err := collectSources(fsys, testMod)
			if err != nil {
				t.Fatal(err)
			}
			assertOneProblem(t, checkImports(testMod, files), tt.want)
		})
	}
}

func TestCollectSourcesIgnoresBuildConstraints(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/a/dial_plan9.go": {Data: []byte("//go:build plan9\n\npackage a\nimport \"net\"\n")},
		"internal/a/testdata/x.go": {Data: []byte("package x\nimport \"net\"\n")},
	}
	files, err := collectSources(fsys, testMod)
	if err != nil {
		t.Fatal(err)
	}
	want := []sourceFile{{Name: "internal/a/dial_plan9.go", Pkg: testMod + "/internal/a", Imports: []string{"net"}}}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("got %+v, want %+v", files, want)
	}
}

// TestBypassModule runs the real checks over a throwaway module that tries
// each bypass, so go list and go mod edit behavior is covered too.
func TestBypassModule(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":                             "module example.com/m\n\ngo 1.24\n",
		"internal/gateway/g.go":              "package gateway\nimport _ \"net/http\"\n",
		"internal/cli/internal/gateway/g.go": "package gateway\nimport _ \"net/http\"\n",
		"internal/metrics/m.go":              "package metrics\nimport _ \"expvar\"\n",
		"internal/tlsdial/t.go":              "package tlsdial\nimport _ \"crypto/tls\"\n",
		"internal/shell/s.go":                "package shell\nimport _ \"os/exec\"\n",
		"internal/ok/ok.go":                  "package ok\nimport _ \"example.com/m/internal/gateway\"\n",
	})
	mf, err := readModFile(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := collectSources(os.DirFS(root), mf.Module.Path)
	if err != nil {
		t.Fatal(err)
	}
	wantImports := []string{"internal/cli/internal/gateway/g.go", "internal/shell/s.go", "internal/tlsdial/t.go"}
	assertMentions(t, checkImports(testMod, files), wantImports)

	reach, err := netReachProblems(config{root: root})
	if err != nil {
		t.Fatal(err)
	}
	wantReach := []string{"internal/cli/internal/gateway reaches", "internal/metrics reaches", "internal/tlsdial reaches"}
	assertMentions(t, reach, wantReach)
}

// A used dependency marked // indirect, in a block written as `require(`,
// must still count as direct.
func TestHiddenIndirectDependency(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.24\n\nrequire(\n\texample.com/dep v1.0.0 // indirect\n)\n",
		"main.go": "package main\nimport _ \"example.com/dep/x\"\nfunc main() {}\n",
	})
	mf, err := readModFile(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []modRequire{{Path: "example.com/dep", Indirect: true}}; !reflect.DeepEqual(mf.Require, want) {
		t.Fatalf("Require = %+v, want %+v", mf.Require, want)
	}
	files, err := collectSources(os.DirFS(root), mf.Module.Path)
	if err != nil {
		t.Fatal(err)
	}
	direct := directModules(mf.Require, allImports(files))
	assertOneProblem(t, checkDeps(direct, map[string]string{}, fileExists), "example.com/dep has no ADR")
}

func TestGoOutputIncludesStderr(t *testing.T) {
	_, err := goOutput(t.TempDir(), "list", "-m", "all")
	if err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("err = %v, want go's stderr explaining the missing go.mod", err)
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// assertMentions expects exactly len(want) problems, the i-th containing want[i].
func assertMentions(t *testing.T, problems, want []string) {
	t.Helper()
	if len(problems) != len(want) {
		t.Fatalf("problems = %q, want %d matching %q", problems, len(want), want)
	}
	for i := range want {
		if !strings.Contains(problems[i], want[i]) {
			t.Errorf("problem %d = %q, want it to mention %q", i, problems[i], want[i])
		}
	}
}
