package redact

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeCapable lists imports through which the package could write the
// reverse map to a file, a socket, a log or another process, or encode it.
var writeCapable = []string{
	"os", "io", "bufio", "log", "net", "syscall", "unsafe", "plugin",
	"encoding", "runtime", "reflect", "path/filepath", "embed/fs",
}

// encodingMethods would let encoders or loggers serialize a Redactor.
var encodingMethods = map[string]bool{
	"MarshalJSON": true, "MarshalText": true, "MarshalBinary": true,
	"GobEncode": true, "String": true, "GoString": true, "MarshalYAML": true,
	"AppendText": true, "AppendBinary": true, "LogValue": true,
}

// productionFiles parses the package's non-test sources.
func productionFiles(t *testing.T) []*ast.File {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no production files found")
	}
	return files
}

func forbiddenWriteImport(imp string) bool {
	for _, p := range writeCapable {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return true
		}
	}
	return false
}

// The reverse map is never written to disk: the package cannot even reach an
// API that writes files, and it imports only "embed" for its read-only data.
func TestReverseMapNeverWrittenToDisk(t *testing.T) {
	for _, f := range productionFiles(t) {
		for _, spec := range f.Imports {
			imp, _ := strconv.Unquote(spec.Path.Value)
			if forbiddenWriteImport(imp) {
				t.Errorf("redact imports %q, which can write data out of the process", imp)
			}
		}
	}
}

func TestRedactorHasNoEncodingSurface(t *testing.T) {
	for _, f := range productionFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				if n.Recv != nil && encodingMethods[n.Name.Name] {
					t.Errorf("method %s lets the reverse map be serialized", n.Name.Name)
				}
			case *ast.Field:
				if n.Tag != nil {
					t.Errorf("struct tag %s invites encoding", n.Tag.Value)
				}
			}
			return true
		})
	}
}

// fmt.Print* and the print builtins write to stdout or stderr without
// importing os, so they are banned too.
func TestNoPrinting(t *testing.T) {
	for _, f := range productionFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := n.X.(*ast.Ident); ok && pkg.Name == "fmt" && strings.Contains(n.Sel.Name, "rint") && !strings.HasPrefix(n.Sel.Name, "Sprint") {
					t.Errorf("redact calls fmt.%s", n.Sel.Name)
				}
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && (id.Name == "print" || id.Name == "println") {
					t.Errorf("redact calls builtin %s", id.Name)
				}
			}
			return true
		})
	}
}

func TestForbiddenWriteImport(t *testing.T) {
	tests := map[string]bool{
		"os": true, "io/ioutil": true, "encoding/json": true, "net/http": true,
		"log/slog": true, "embed": false, "regexp": false, "strings": false, "fmt": false,
	}
	for imp, want := range tests {
		if got := forbiddenWriteImport(imp); got != want {
			t.Errorf("forbiddenWriteImport(%q) = %v, want %v", imp, got, want)
		}
	}
}
