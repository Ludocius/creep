package main

import "testing"

func TestIsWorkflowFile(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"workflow yml", ".github/workflows/ci.yml", true},
		{"workflow yaml", ".github/workflows/ci.yaml", true},
		{"composite action at root of action dir", ".github/actions/x/action.yml", true},
		{"composite action yaml anywhere", "tools/deploy/action.yaml", true},
		{"nested dir under workflows is not run by GitHub", ".github/workflows/sub/ci.yml", false},
		{"dependabot config", ".github/dependabot.yml", false},
		{"other yaml", ".golangci.yml", false},
		{"workflow with other extension", ".github/workflows/README.md", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWorkflowFile(tt.path); got != tt.want {
				t.Errorf("isWorkflowFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// Shapes the regex cannot resolve must fail closed, never pass silently.
func TestCheckWorkflowFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"value on next line", "    - uses:\n        actions/checkout@v7\n", "not pinned by commit SHA"},
		{"yaml alias", "    - uses: *checkout\n", "not pinned by commit SHA"},
		{"literal block scalar", "    - uses: |\n", "not pinned by commit SHA"},
		{"flow style docker tag", "    - {uses: docker://alpine:3}\n", "not pinned by @sha256 digest"},
		{"docker short digest", "    - uses: docker://alpine@sha256:abc\n", "not pinned by @sha256 digest"},
		{"uppercase sha", "    - uses: a/b@3D3C42E5AAC5BA805825DA76410C181273BA90B1\n", "not pinned by commit SHA"},
		{"trigger with trailing comment", "on: pull_request_target # nope\n", "pull_request_target is forbidden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertOneProblem(t, checkWorkflow("w.yml", []byte(tt.yaml)), tt.want)
		})
	}
}
