package testapps

import (
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"testing/fstest"
)

// repoRoot is the module root as seen from this package directory.
const repoRoot = "../../.."

// requiredApps are the apps issue #16 asks for; the tree may hold more.
var requiredApps = []string{"flask", "fastapi", "express"}

func TestAppsMatchExpected(t *testing.T) {
	fsys := os.DirFS(path.Join(repoRoot, appsDir))
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			t.Errorf("%s/%s: only app directories belong here", appsDir, e.Name())
			continue
		}
		seen[e.Name()] = true
		for _, p := range checkApp(fsys, e.Name()) {
			t.Errorf("%s/%s", appsDir, p)
		}
	}
	for _, app := range requiredApps {
		if !seen[app] {
			t.Errorf("%s/%s is missing", appsDir, app)
		}
	}
}

func TestNothingExecutesApps(t *testing.T) {
	problems, err := checkNoExecution(os.DirFS(repoRoot))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

const (
	goodSource   = "@app.get(\"/a\")\ndef a():\n    db.execute(q)\n"
	goodExpected = `{"schema_version":1,"app":"x","language":"python","framework":"flask",
"vulnerable":[{"class":"sqli","file":"app.py","line":3,"route":"/a","sink":"execute(q)"}],"safe":[]}`
)

func appFS(expected string, extra fstest.MapFS) fstest.MapFS {
	fsys := fstest.MapFS{
		"x/expected.json":     {Data: []byte(expected)},
		"x/vulnerable/app.py": {Data: []byte(goodSource)},
		"x/safe/app.py":       {Data: []byte(goodSource)},
	}
	for k, v := range extra {
		if v == nil {
			delete(fsys, k)
			continue
		}
		fsys[k] = v
	}
	return fsys
}

func swap(old, repl string) string { return strings.Replace(goodExpected, old, repl, 1) }

func TestCheckAppReportsDrift(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		extra    fstest.MapFS
		want     string // substring of a problem; empty means no problems
	}{
		{"good", goodExpected, nil, ""},
		{"unknown field", swap(`"framework"`, `"severity":"high","framework"`), nil, "unknown field"},
		{"trailing data", goodExpected + "{}", nil, "trailing data"},
		{"schema version", swap(`"schema_version":1`, `"schema_version":2`), nil, "schema_version 2"},
		{"app name", swap(`"app":"x"`, `"app":"y"`), nil, "directory name"},
		{"language", swap(`"python"`, `"go"`), nil, "language"},
		{"no findings", swap(`[{"class":"sqli","file":"app.py","line":3,"route":"/a","sink":"execute(q)"}]`, `[]`), nil, "no findings"},
		{"safe missing", swap(`,"safe":[]`, ``), nil, "safe must be present"},
		{"safe lists a finding", swap(`"safe":[]`, `"safe":[{"class":"sqli"}]`), nil, "zero findings"},
		{"class outside set", swap(`"sqli"`, `"xss"`), nil, "closed set"},
		{"file outside variant", swap(`"app.py"`, `"../safe/app.py"`), nil, "variant directory"},
		{"file missing", swap(`"app.py"`, `"main.py"`), nil, "main.py"},
		{"line past end", swap(`"line":3`, `"line":9`), nil, "outside app.py"},
		{"stale line", swap(`"line":3`, `"line":2`), nil, "does not contain sink"},
		{"route absent", swap(`"route":"/a"`, `"route":"/b"`), nil, "route"},
		{"no safe twin", goodExpected, fstest.MapFS{"x/safe/app.py": nil}, "safe"},
		{"twin names differ", goodExpected, fstest.MapFS{"x/safe/app.py": nil, "x/safe/main.py": {Data: []byte(goodSource)}}, "same files"},
		{"manifest", goodExpected, fstest.MapFS{"x/vulnerable/requirements.txt": {Data: []byte("flask\n")}}, "only .py"},
		{"package.json", goodExpected, fstest.MapFS{"x/package.json": {Data: []byte("{}")}}, "an app holds only"},
		{"go file", goodExpected, fstest.MapFS{"x/safe/x.go": {Data: []byte("package x\n")}}, "only .py"},
		{"pytest file", goodExpected, fstest.MapFS{"x/vulnerable/test_app.py": {Data: []byte("\n")}, "x/safe/test_app.py": {Data: []byte("\n")}}, "test runner"},
		{"setup hook", goodExpected, fstest.MapFS{"x/safe/setup.py": {Data: []byte("\n")}}, "installer"},
		{"nested dir", goodExpected, fstest.MapFS{"x/safe/lib/a.py": {Data: []byte("\n")}}, "regular files"},
		{"symlink", goodExpected, fstest.MapFS{"x/safe/link.py": {Data: []byte("app.py"), Mode: fs.ModeSymlink}}, "regular files"},
		{"too long", goodExpected, fstest.MapFS{"x/safe/app.py": {Data: []byte(strings.Repeat("\n", maxAppLines))}}, "under 200"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems := checkApp(appFS(tt.expected, tt.extra), "x")
			assertProblems(t, problems, tt.want)
		})
	}
}

func TestCheckNoExecution(t *testing.T) {
	const execImport = "package p\nimport \"os/exec\"\n"
	tests := []struct {
		name string
		fsys fstest.MapFS
		want string
	}{
		{"make target", fstest.MapFS{"Makefile": {Data: []byte("run:\n\tpython testdata/apps/flask/vulnerable/app.py\n")}}, "Makefile"},
		{"workflow", fstest.MapFS{".github/workflows/ci.yml": {Data: []byte("run: node ./testdata/apps/express/vulnerable/app.js\n")}}, "ci.yml"},
		{"composite action", fstest.MapFS{"a/action.yml": {Data: []byte("run: cd testdata/apps\n")}}, "action.yml"},
		{"npm script", fstest.MapFS{"package.json": {Data: []byte(`{"scripts":{"start":"node testdata/apps/express/vulnerable/app.js"}}`)}}, "package.json"},
		{"docker compose", fstest.MapFS{"docker-compose.yml": {Data: []byte("volumes: [./testdata/apps/flask:/app]\n")}}, "docker-compose.yml"},
		{"compose override", fstest.MapFS{"deploy/compose.override.yaml": {Data: []byte("build: testdata/apps/fastapi\n")}}, "compose.override.yaml"},
		{"windows script", fstest.MapFS{"x.ps1": {Data: []byte(`python Testdata\Apps\flask\vulnerable\app.py`)}}, "x.ps1"},
		{"go exec path", fstest.MapFS{"p/a_test.go": {Data: []byte(execImport + "var _ = \"../testdata/apps/flask\"\n")}}, "a_test.go"},
		{"go exec join", fstest.MapFS{"p/a_test.go": {Data: []byte(execImport + "var _ = []string{\"testdata\", \"apps\"}\n")}}, "a_test.go"},
		{"go start process", fstest.MapFS{"p/a.go": {Data: []byte("package p\nimport \"os\"\nvar _ = os.StartProcess\nvar _ = \"testdata/apps\"\n")}}, "a.go"},
		{"go broken", fstest.MapFS{"p/a.go": {Data: []byte("package")}}, "cannot parse"},
		{"go reader is fine", fstest.MapFS{"p/a_test.go": {Data: []byte("package p\nimport \"os\"\nvar _ = os.DirFS(\"testdata/apps\")\n")}}, ""},
		{"exec without apps", fstest.MapFS{"p/a.go": {Data: []byte(execImport + "var _ = \"go\"\n")}}, ""},
		{"docs may mention", fstest.MapFS{"CONTRIBUTING.md": {Data: []byte("creep scan testdata/apps/flask\n")}, ".github/ISSUE_TEMPLATE/x.yml": {Data: []byte("testdata/apps\n")}}, ""},
		{"nested module skipped", fstest.MapFS{"w/go.mod": {Data: []byte("module w\n")}, "w/Makefile": {Data: []byte("run:\n\tpython testdata/apps/x\n")}}, ""},
		{"testdata skipped", fstest.MapFS{"testdata/apps/x/run.sh": {Data: []byte("node testdata/apps\n")}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, err := checkNoExecution(tt.fsys)
			if err != nil {
				t.Fatal(err)
			}
			assertProblems(t, problems, tt.want)
		})
	}
}

func assertProblems(t *testing.T, problems []string, want string) {
	t.Helper()
	if want == "" {
		if len(problems) > 0 {
			t.Fatalf("want no problems, got %q", problems)
		}
		return
	}
	for _, p := range problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("want a problem containing %q, got %q", want, problems)
}
