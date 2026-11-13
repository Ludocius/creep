package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// The fixture trees are written to t.TempDir and only read and parsed (go list
// and go mod edit included); nothing in them is built or run.

// writeTree writes files (slash-separated path to contents) under a fresh
// temporary directory and returns its path.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestProcessUsesFixtures(t *testing.T) {
	root := writeTree(t, map[string]string{
		"internal/cli/alias.go":      "package cli\n\nimport o \"os\"\n\nfunc start() { o.StartProcess(\"/bin/sh\", nil, nil) }\n",
		"internal/cli/clean.go":      "package cli\n\nimport \"os\"\n\nfunc read() { os.Open(\"x\") }\n",
		"internal/cli/dot.go":        "package cli\n\nimport . \"os\"\n\nvar start = StartProcess\n",
		"internal/cli/exec_linux.go": "//go:build linux\n\npackage cli\n\nimport sc \"syscall\"\n\nfunc replace() { sc.Exec(\"/bin/sh\", nil, nil) }\n",
		"internal/cli/newfile.go":    "package cli\n\nimport \"os\"\n\nvar inherited = os.NewFile(3, \"socket\")\n",
		// The name matches a syscall allowlist entry, so only the call is reported.
		"internal/cli/open_unix.go":   "//go:build unix\n\npackage cli\n\nimport \"syscall\"\n\nfunc spawn() { syscall.ForkExec(\"/bin/sh\", nil, nil) }\n",
		"internal/cli/value.go":       "package cli\n\nimport \"os\"\n\nvar start = os.StartProcess\n",
		"internal/tools/run/fd.go":    "package run\n\nimport \"os\"\n\nvar fd = os.NewFile(3, \"fd\")\n",
		"internal/tools/run/start.go": "package run\n\nimport \"os\"\n\nfunc start() { os.StartProcess(\"go\", nil, nil) }\n",
	})
	files, err := collectSources(os.DirFS(root), testMod)
	if err != nil {
		t.Fatal(err)
	}
	problems := append(checkImports(testMod, files), checkProcessUses(testMod, files)...)
	tests := []struct {
		file string
		want []string // substrings of this file's problems, in order
	}{
		{"internal/cli/alias.go", []string{"uses os.StartProcess: running programs"}},
		{"internal/cli/newfile.go", []string{"uses os.NewFile: wrapping a raw descriptor"}},
		{"internal/cli/value.go", []string{"uses os.StartProcess: running programs"}},
		{"internal/cli/dot.go", []string{"uses os.*: dot imports"}},
		{"internal/cli/open_unix.go", []string{"uses syscall.ForkExec: raw system calls"}},
		{"internal/cli/exec_linux.go", []string{`imports "syscall"`, "uses syscall.Exec: raw system calls"}},
		{"internal/cli/clean.go", nil},
		{"internal/tools/run/start.go", nil},
		{"internal/tools/run/fd.go", []string{"uses os.NewFile: wrapping a raw descriptor"}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			assertMentions(t, problemsFor(problems, tt.file), tt.want)
		})
	}
}

func problemsFor(problems []string, file string) []string {
	var mine []string
	for _, p := range problems {
		if strings.HasPrefix(p, file+" ") {
			mine = append(mine, p)
		}
	}
	return mine
}

func TestForeignFixtures(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                 "module example.com/foreign\n\ngo 1.24\n",
		"asm/asm.go":             "package asm\n\nfunc f()\n",
		"asm/asm_amd64.s":        "TEXT ·f(SB), 0, $0\n\tRET\n",
		"asm/testdata/ignored.s": "; testdata is never built\n",
		"asm/upper_arm64.S":      "TEXT f(SB)\n",
		"bin/out.s":              "root bin/ holds build output and is skipped\n",
		"cgo/cgo.go":             "package cgo\n",
		"cgo/x.c":                "/* fixture */\n",
		"cgo/x.cc":               "/* fixture */\n",
		"cgo/x.cpp":              "/* fixture */\n",
		"cgo/x.f":                "/* fixture */\n",
		"cgo/x.h":                "/* fixture */\n",
		"cgo/x.m":                "/* fixture */\n",
		"cgo/x.swig":             "/* fixture */\n",
		"excluded/excluded.go":   "package excluded\n",
		"excluded/sys_plan9.s":   "//go:build plan9\n\nTEXT f(SB)\n",
		"internal/bin/b_amd64.s": "TEXT f(SB)\n",
		"syso/blob_amd64.syso":   "fixture: stands in for an object file, never linked\n",
		"syso/syso.go":           "package syso\n",
	})
	got, err := foreignProblems(config{root: root})
	if err != nil {
		t.Fatal(err)
	}
	// Nested testdata/ is never built; root bin/ and internal/bin are walked.
	want := []string{
		"asm/asm_amd64.s", "asm/upper_arm64.S", "bin/out.s",
		"cgo/x.c", "cgo/x.cc", "cgo/x.cpp", "cgo/x.f", "cgo/x.h", "cgo/x.m", "cgo/x.swig",
		"excluded/sys_plan9.s", "internal/bin/b_amd64.s", "syso/blob_amd64.syso",
	}
	assertMentions(t, got, want)
}

func TestCheckForeign(t *testing.T) {
	foreignAllowed["ok/a.s"] = "test entry"
	defer delete(foreignAllowed, "ok/a.s")
	tests := []struct {
		name  string
		names []string
		want  string
	}{
		{"reported", []string{"p/a.s"}, "p/a.s is a non-Go source"},
		{"allowlisted", []string{"ok/a.s"}, ""},
		{"none", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkForeign(tt.names), tt.want)
		})
	}
}

func TestWalkForeignFilesCase(t *testing.T) {
	fsys := fstest.MapFS{"p/A.SYSO": {}, "p/b.SX": {}, "p/c.go": {}, "p/d.txt": {}}
	got, err := walkForeignFiles(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"p/A.SYSO", "p/b.SX"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWorkspaceFixture(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":             "module example.com/ws\n\ngo 1.24\n\nreplace example.com/local => ../local\n\nreplace example.com/old => example.com/new v1.0.0\n",
		"go.work":            "go 1.24\n\nuse .\n",
		"go.work.sum":        "",
		"vendor/modules.txt": "# fixture\n",
	})
	got, err := workspaceProblems(config{root: root})
	if err != nil {
		t.Fatal(err)
	}
	assertMentions(t, got, []string{"go.work is forbidden", "go.work.sum is forbidden", "vendor is forbidden", `replaces example.com/local with local path "../local"`})
}

func TestCheckWorkspace(t *testing.T) {
	local := modReplace{}
	local.Old.Path, local.New.Path = "example.com/a", `C:\src\a`
	module := modReplace{}
	module.Old.Path, module.New.Path, module.New.Version = "example.com/a", "example.com/b", "v1.0.0"
	tests := []struct {
		name     string
		fsys     fstest.MapFS
		replaces []modReplace
		want     string
	}{
		{"clean", fstest.MapFS{"go.mod": {}}, nil, ""},
		{"go.work", fstest.MapFS{"go.work": {}}, nil, "go.work is forbidden"},
		{"go.work.sum", fstest.MapFS{"go.work.sum": {}}, nil, "go.work.sum is forbidden"},
		{"vendor dir", fstest.MapFS{"vendor/x/y.go": {}}, nil, "vendor is forbidden"},
		{"nested vendor is not the module's", fstest.MapFS{"internal/vendor/x.go": {}}, nil, ""},
		{"absolute local replace", fstest.MapFS{}, []modReplace{local}, "local path"},
		{"module replace", fstest.MapFS{}, []modReplace{module}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkWorkspace(tt.fsys, tt.replaces), tt.want)
		})
	}
}

// YAML shapes a line scan cannot resolve must fail; plain YAML must not.
func TestCheckWorkflowYAMLShapes(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{"hex escaped uses key", `    - "\x75ses": actions/checkout@v1` + "\n", []string{"w.yml:1: escape sequence in a quoted key"}},
		{"escaped key in flow map", `    - {"\u0075ses": a/b@v1}` + "\n", []string{"w.yml:1: escape sequence in a quoted key"}},
		{"escaped trigger key", "on:\n  \"pull_request\\u005Ftarget\":\n", []string{"w.yml:2: pull_request_target is forbidden", "w.yml:2: escape sequence in a quoted key"}},
		{"escaped line break in trigger", "on: [\"pull_request\\\n  _target\"]\n", []string{"w.yml:1: quoted scalar spans lines"}},
		{"single quoted trigger over lines", "on: ['pull_request\n  _target']\n", []string{"w.yml:1: quoted scalar spans lines"}},
		{"explicit key", "    - ? uses\n      : actions/checkout@v1\n", []string{"w.yml:1: explicit or alias key"}},
		{"alias key", "    - *k : actions/checkout@v1\n", []string{"w.yml:1: explicit or alias key"}},
		{"hash inside quotes is not a comment", "on: [\"a#\", pull_request_target]\n", []string{"w.yml:1: pull_request_target is forbidden"}},
		{"escapes in block text are shell", "  - run: |\n      printf \"%s\\n\" \"\\x75ses\": 'it''s\n", nil},
		{"key after block text is checked", "  - run: |\n      echo 'open\n    \"\\x75ses\": a\n", []string{"w.yml:3: escape sequence in a quoted key"}},
		{"crlf workflow", "on:\r\n  push:\r\n", nil},
		{"single quoted run", "        run: '\"$RUNNER_TEMP/x\" --flag'\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMentions(t, checkWorkflow("w.yml", []byte(tt.yaml)), tt.want)
		})
	}
}

// TestRepoPasses runs the static checks over this repository: the guards must
// not flag the code they protect. The binary cap is left to `make budget`.
func TestRepoPasses(t *testing.T) {
	cfg := config{root: "../../..", architecture: "docs/architecture.md", allowlist: "docs/adr/dependencies.txt", maxModules: defaultMaxModules}
	steps := map[string]func(config) ([]string, error){
		"workspace": workspaceProblems, "deps": depProblems, "imports": importProblems,
		"foreign": foreignProblems, "reach": netReachProblems, "modules": moduleProblems,
		"layers": layerProblems, "workflows": workflowProblems,
	}
	for name, step := range steps {
		t.Run(name, func(t *testing.T) {
			got, err := step(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertOneProblem(t, got, "")
		})
	}
}
