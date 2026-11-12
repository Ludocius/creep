package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// The fixtures under testdata are only read and parsed (go list and go mod
// edit included); nothing in them is built or run.

func TestProcessUsesFixtures(t *testing.T) {
	files, err := collectSources(os.DirFS("testdata/procs"), testMod)
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
	got, err := foreignProblems(config{root: "testdata/foreign"})
	if err != nil {
		t.Fatal(err)
	}
	// Root bin/ and nested testdata/ are never built; internal/bin is.
	want := []string{
		"asm/asm_amd64.s", "asm/upper_arm64.S",
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
		{"go list and walk agree", []string{"p/a.s", "p/a.s"}, "p/a.s is a non-Go source"},
		{"allowlisted", []string{"ok/a.s"}, ""},
		{"none", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkForeign(tt.names), tt.want)
		})
	}
}

func TestListedFilesRelNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "mod")
	inside := listedFiles{Dir: filepath.Join(root, "p"), SFiles: []string{"a.s"}, SysoFiles: []string{"b.syso"}, IgnoredOtherFiles: []string{"c_plan9.s"}}
	if got, want := inside.relNames(root), []string{"p/a.s", "p/b.syso", "p/c_plan9.s"}; !reflect.DeepEqual(got, want) {
		t.Errorf("inside root: got %q, want %q", got, want)
	}
	outside := listedFiles{Dir: filepath.Join(filepath.Dir(root), "other"), CFiles: []string{"x.c"}}
	if got := outside.relNames(root); len(got) != 1 || !strings.HasSuffix(got[0], "other/x.c") || strings.HasPrefix(got[0], "..") {
		t.Errorf("outside root: got %q, want an absolute path ending in other/x.c", got)
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
	got, err := workspaceProblems(config{root: "testdata/workspace"})
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
	cfg := config{root: "../../..", allowlist: "docs/adr/dependencies.txt", maxModules: defaultMaxModules, maxLines: defaultMaxLines}
	steps := map[string]func(config) ([]string, error){
		"workspace": workspaceProblems, "deps": depProblems, "imports": importProblems,
		"foreign": foreignProblems, "reach": netReachProblems, "modules": moduleProblems,
		"lines": lineProblems, "workflows": workflowProblems,
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
