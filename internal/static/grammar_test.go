package static

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
)

// TestEmbeddedGrammarsMatchSums fails when a .wasm file changes without
// SHA256SUMS, or the other way round, so a grammar swap shows in review.
func TestEmbeddedGrammarsMatchSums(t *testing.T) {
	sums, err := grammarFiles.ReadFile("grammars/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad SHA256SUMS line %q", line)
		}
		want["grammars/"+name] = sum
	}
	if len(want) != len(Languages) {
		t.Fatalf("SHA256SUMS lists %d files, want %d", len(want), len(Languages))
	}
	for _, l := range Languages {
		wasm, err := grammarFiles.ReadFile(l.wasmFile())
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(wasm)
		if hex.EncodeToString(got[:]) != want[l.wasmFile()] {
			t.Errorf("%s does not match SHA256SUMS; rebuild with grammars/build.sh", l.wasmFile())
		}
	}
}

// allowedImports are the WASI calls the C library links. None can reach a
// file or socket: module configs preopen no directories, stdout and stderr
// are discarded, and the clock is wazero's fake one (no WithSysNanotime).
var allowedImports = map[string]bool{
	"wasi_snapshot_preview1.clock_time_get": true,
	"wasi_snapshot_preview1.fd_close":       true,
	"wasi_snapshot_preview1.fd_seek":        true,
	"wasi_snapshot_preview1.fd_write":       true,
}

// TestGrammarImportsOnlyAllowedWASI catches a rebuilt module that links new
// host calls (path_open, sock_accept, clocks) so they get reviewed first.
func TestGrammarImportsOnlyAllowedWASI(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer func() { _ = rt.Close(ctx) }()
	for _, l := range Languages {
		wasm, err := grammarFiles.ReadFile(l.wasmFile())
		if err != nil {
			t.Fatal(err)
		}
		mod, err := rt.CompileModule(ctx, wasm)
		if err != nil {
			t.Fatal(err)
		}
		var extra []string
		for _, fn := range mod.ImportedFunctions() {
			module, name, _ := fn.Import()
			if !allowedImports[module+"."+name] {
				extra = append(extra, module+"."+name)
			}
		}
		sort.Strings(extra)
		if len(extra) > 0 {
			t.Errorf("%s imports %v", l, extra)
		}
	}
}

func TestLanguageForPath(t *testing.T) {
	tests := []struct {
		name string
		want Language
		ok   bool
	}{
		{"app/views.py", Python, true},
		{"stubs/a.pyi", Python, true},
		{"SRC/INDEX.JS", JavaScript, true},
		{"a.mjs", JavaScript, true},
		{"a.cjs", JavaScript, true},
		{"a.jsx", JavaScript, true},
		{"a.ts", TypeScript, true},
		{"types/a.d.ts", TypeScript, true},
		{"a.mts", TypeScript, true},
		{"a.tsx", TSX, true},
		{"a.go", 0, false},
		{"Makefile", 0, false},
		{"py", 0, false},
		{"a.py.txt", 0, false},
	}
	for _, tt := range tests {
		got, ok := LanguageForPath(tt.name)
		if got != tt.want || ok != tt.ok {
			t.Errorf("LanguageForPath(%q) = %v, %v; want %v, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestLanguageString(t *testing.T) {
	for _, l := range Languages {
		if l.String() == "unknown" {
			t.Errorf("Language(%d) has no name", l)
		}
	}
	if got := Language(0).String(); got != "unknown" {
		t.Errorf("Language(0) = %q", got)
	}
	if got := fmt.Sprint(Language(99)); got != "unknown" {
		t.Errorf("Language(99) = %q", got)
	}
}
