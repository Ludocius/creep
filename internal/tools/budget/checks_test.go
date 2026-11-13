package main

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestDirectModules(t *testing.T) {
	reqs := []modRequire{
		{Path: "example.com/a"},
		{Path: "example.com/b", Indirect: true},
		{Path: "example.com/c", Indirect: true},
		{Path: "example.com/c/v2", Indirect: true},
	}
	tests := []struct {
		name    string
		imports []string
		want    []string
	}{
		{"unused indirect stays indirect", []string{"fmt"}, []string{"example.com/a"}},
		{"used indirect becomes direct", []string{"example.com/b/pkg"}, []string{"example.com/a", "example.com/b"}},
		{"longest module path wins", []string{"example.com/c/v2/x"}, []string{"example.com/a", "example.com/c/v2"}},
		{"prefix look-alike is not the module", []string{"example.com/bb"}, []string{"example.com/a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := directModules(reqs, tt.imports); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("directModules() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    map[string]string
		wantErr bool
	}{
		{"comments only", "# header\n\n", map[string]string{}, false},
		{"entry with comment", "example.com/a docs/adr/0001-a.md # why\n", map[string]string{"example.com/a": "docs/adr/0001-a.md"}, false},
		{"missing adr", "example.com/a\n", nil, true},
		{"adr outside docs/adr", "example.com/a README.md\n", nil, true},
		{"adr path escapes", "example.com/a docs/adr/../../go.mod\n", nil, true},
		{"adr path with backslashes", `example.com/a docs/adr/x\..\..\go.mod` + "\n", nil, true},
		{"extra field", "example.com/a docs/adr/0001-a.md extra\n", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowlist([]byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckDeps(t *testing.T) {
	allow := map[string]string{"example.com/ok": "docs/adr/0001-ok.md", "example.com/gone": "docs/adr/0002-gone.md"}
	exists := func(p string) bool { return p == "docs/adr/0001-ok.md" }
	tests := []struct {
		name   string
		direct []string
		want   string // substring of the single problem; "" means no problem
	}{
		{"allowed", []string{"example.com/ok"}, ""},
		{"not listed", []string{"example.com/new"}, "has no ADR"},
		{"adr missing", []string{"example.com/gone"}, "does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkDeps(tt.direct, allow, exists), tt.want)
		})
	}
}

func TestCheckCap(t *testing.T) {
	assertOneProblem(t, checkCap("x", 10, 10, "u"), "")
	assertOneProblem(t, checkCap("x", 11, 10, "u"), "x is 11 u, cap is 10")
}

func TestCheckFileLines(t *testing.T) {
	fsys := fstest.MapFS{
		"ok.go":                 {Data: []byte(strings.Repeat("\n", 400))},
		"big.go":                {Data: []byte(strings.Repeat("\n", 401))},
		"big.txt":               {Data: []byte(strings.Repeat("\n", 900))},
		"testdata/gen/huge.go":  {Data: []byte(strings.Repeat("\n", 900))},
		"internal/x/deep_x.go":  {Data: []byte(strings.Repeat("\n", 401))},
		"vendor/example/big.go": {Data: []byte(strings.Repeat("\n", 900))},
	}
	got, err := checkFileLines(fsys, 400)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"big.go has 401 lines, cap is 400", "internal/x/deep_x.go has 401 lines, cap is 400"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// lineProblems must scan the configured root, not the working directory.
func TestLineProblemsUsesRoot(t *testing.T) {
	big := "package big\n" + strings.Repeat("// line\n", 400)
	got, err := lineProblems(config{root: writeTree(t, map[string]string{"big.go": big}), maxLines: 400})
	if err != nil {
		t.Fatal(err)
	}
	assertOneProblem(t, got, "big.go has 401 lines")
}

func TestCheckWorkflow(t *testing.T) {
	sha := "@3d3c42e5aac5ba805825da76410c181273ba90b1"
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"sha pinned", "    - uses: actions/checkout" + sha + " # v7.0.1\n", ""},
		{"local action", "    - uses: ./.github/actions/x\n", ""},
		{"tag pinned", "    - uses: actions/checkout@v7\n", "not pinned by commit SHA"},
		{"quoted branch", "      uses: 'evil/action@main'\n", "not pinned by commit SHA"},
		{"short sha", "    - uses: actions/checkout@3d3c42e\n", "not pinned by commit SHA"},
		{"pull_request_target", "on:\n  pull_request_target:\n", "pull_request_target is forbidden"},
		{"pull_request_target in list", "on: [push, pull_request_target]\n", "pull_request_target is forbidden"},
		{"mentioned in comment", "# never use pull_request_target\n", ""},
		{"quoted sha pinned", `    - uses: "actions/checkout` + sha + `"` + "\n", ""},
		{"reusable workflow by tag", "    uses: org/repo/.github/workflows/w.yml@v1\n", "not pinned by commit SHA"},
		{"quoted pull_request_target key", "on:\n  \"pull_request_target\":\n", "pull_request_target is forbidden"},
		{"flow style tag", "    - {name: x, uses: actions/checkout@v1}\n", "not pinned by commit SHA"},
		{"flow style sha pinned", "    - {uses: actions/checkout" + sha + "}\n", ""},
		{"double quoted key", `    - "uses": actions/checkout@v1` + "\n", "not pinned by commit SHA"},
		{"single quoted key and value", "    - 'uses': 'actions/checkout@main'\n", "not pinned by commit SHA"},
		{"docker tag", "    - uses: docker://alpine:3\n", "not pinned by @sha256 digest"},
		{"docker digest", "    - uses: docker://alpine@sha256:" + strings.Repeat("a", 64) + "\n", ""},
		{"block scalar value", "    - uses: >-\n", "not pinned by commit SHA"},
		{"hex escaped trigger", `on: ["pull\x5frequest_target"]` + "\n", "pull_request_target is forbidden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkWorkflow("w.yml", []byte(tt.yaml)), tt.want)
		})
	}
}

// assertOneProblem expects no problems when want is "", otherwise exactly one containing want.
func assertOneProblem(t *testing.T, problems []string, want string) {
	t.Helper()
	if want == "" {
		if len(problems) != 0 {
			t.Errorf("unexpected problems: %q", problems)
		}
		return
	}
	if len(problems) != 1 || !strings.Contains(problems[0], want) {
		t.Errorf("problems = %q, want one containing %q", problems, want)
	}
}
