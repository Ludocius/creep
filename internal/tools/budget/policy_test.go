package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

func policyFS() fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, phrases := range requiredPolicy {
		fsys[name] = &fstest.MapFile{Data: []byte(strings.Join(phrases, "\n"))}
	}
	return fsys
}

func TestCheckPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(fstest.MapFS)
		want   string
	}{
		{"complete policy passes", func(fstest.MapFS) {}, ""},
		{"missing file", func(f fstest.MapFS) { delete(f, "AGENTS.md") }, "AGENTS.md is missing"},
		{"loop removed", func(f fstest.MapFS) {
			f["CONTRIBUTING.md"] = &fstest.MapFile{Data: []byte("Changing or removing this loop needs an ADR")}
		}, `CONTRIBUTING.md must contain "developer → tester → pentester → auditor"`},
		{"auditor dropped from loop", func(f fstest.MapFS) {
			f[".github/PULL_REQUEST_TEMPLATE.md"] = &fstest.MapFile{Data: []byte("developer → tester → pentester")}
		}, "PULL_REQUEST_TEMPLATE.md must contain"},
		{"claude no longer loads agents", func(f fstest.MapFS) {
			f["CLAUDE.md"] = &fstest.MapFile{Data: []byte("")}
		}, `CLAUDE.md must contain "@AGENTS.md"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := policyFS()
			tt.mutate(fsys)
			problems, err := checkPolicy(fsys)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(problems, "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("unexpected problems: %s", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("problems %q do not mention %q", got, tt.want)
			}
		})
	}
}
