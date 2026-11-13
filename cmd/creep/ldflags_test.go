package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const buildinfoPkg = "github.com/sneakercreepers/creep/internal/buildinfo"

// TestVersionLinkTimeValues builds the real binary so a rename of the
// buildinfo variables, which the Makefile sets with -X, cannot go unnoticed.
func TestVersionLinkTimeValues(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not in PATH")
	}
	tests := []struct {
		name    string
		ldflags string
		want    []string
	}{
		{"with ldflags", "-X " + buildinfoPkg + ".version=v9.8.7 -X " + buildinfoPkg + ".commit=feedbee",
			[]string{"creep v9.8.7\n", "commit: feedbee\n", "go: go"}},
		{"without ldflags", "", []string{"creep ", "commit: ", "go: go"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "creep")
			if runtime.GOOS == "windows" {
				bin += ".exe"
			}
			build := exec.Command(goBin, "build", "-ldflags", tt.ldflags, "-o", bin, ".")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build: %v\n%s", err, out)
			}
			out, err := exec.Command(bin, "version").Output()
			if err != nil {
				t.Fatalf("creep version: %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
		})
	}
}
