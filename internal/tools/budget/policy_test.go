package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicy creates every policy file with all required phrases under a temp root.
func writePolicy(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, phrases := range requiredPolicy {
		writeFile(t, root, name, strings.Join(phrases, "\n"))
	}
	return root
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPolicyComplete(t *testing.T) {
	problems, err := checkPolicy(writePolicy(t), readPolicyFile)
	if err != nil || len(problems) > 0 {
		t.Fatalf("problems %v, err %v", problems, err)
	}
}

// Every required phrase must be enforced on its own, not just some of them.
func TestCheckPolicyEachPhrase(t *testing.T) {
	for name, phrases := range requiredPolicy {
		for i, phrase := range phrases {
			t.Run(name+"/"+phrase, func(t *testing.T) {
				root := writePolicy(t)
				rest := append(append([]string{}, phrases[:i]...), phrases[i+1:]...)
				hidden := "<!-- " + phrase + " -->"
				writeFile(t, root, name, strings.Join(append(rest, hidden), "\n"))
				problems, err := checkPolicy(root, readPolicyFile)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(strings.Join(problems, "\n"), name) {
					t.Fatalf("removing %q from %s was not reported: %v", phrase, name, problems)
				}
			})
		}
	}
}

func TestCheckPolicyMissingFile(t *testing.T) {
	root := writePolicy(t)
	if err := os.Remove(filepath.Join(root, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	problems, err := checkPolicy(root, readPolicyFile)
	if err != nil || !strings.Contains(strings.Join(problems, "\n"), "AGENTS.md is missing") {
		t.Fatalf("problems %v, err %v", problems, err)
	}
}

func TestCheckPolicyReadErrorFailsClosed(t *testing.T) {
	failing := func(string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := checkPolicy(writePolicy(t), failing); err == nil {
		t.Fatal("read error must fail the budget")
	}
}

func TestReadPolicyFileRejectsSymlink(t *testing.T) {
	root := writePolicy(t)
	link := filepath.Join(root, "link.md")
	if err := os.Symlink(filepath.Join(root, "AGENTS.md"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readPolicyFile(link); err == nil {
		t.Fatal("symlink must be rejected")
	}
}
