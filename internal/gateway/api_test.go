package gateway

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// rawHTTPTypes would let a caller send a request without Send, skipping
// consent and egress.log.
var rawHTTPTypes = []string{"http.Client", "http.Transport", "http.RoundTripper"}

// No exported function or method returns a raw HTTP client, transport or
// round tripper, and no exported struct field holds one.
func TestNoRawHTTPClientExported(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			checkDecl(t, fset, d)
		}
	}
}

func checkDecl(t *testing.T, fset *token.FileSet, d ast.Decl) {
	t.Helper()
	switch d := d.(type) {
	case *ast.FuncDecl:
		if d.Name.IsExported() && d.Type.Results != nil {
			checkFields(t, fset, d.Name.Name+" result", d.Type.Results)
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				continue
			}
			if st, ok := ts.Type.(*ast.StructType); ok {
				checkExportedFields(t, fset, ts.Name.Name, st.Fields)
			}
		}
	}
}

func checkExportedFields(t *testing.T, fset *token.FileSet, owner string, fields *ast.FieldList) {
	t.Helper()
	for _, f := range fields.List {
		for _, n := range f.Names {
			if n.IsExported() {
				checkType(t, fset, owner+"."+n.Name, f.Type)
			}
		}
	}
}

func checkFields(t *testing.T, fset *token.FileSet, what string, fields *ast.FieldList) {
	t.Helper()
	for _, f := range fields.List {
		checkType(t, fset, what, f.Type)
	}
}

func checkType(t *testing.T, fset *token.FileSet, what string, expr ast.Expr) {
	t.Helper()
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, expr); err != nil {
		t.Fatal(err)
	}
	for _, raw := range rawHTTPTypes {
		if strings.Contains(b.String(), raw) {
			t.Errorf("%s exposes %s (%s); send only through EgressLog.Send", what, raw, b.String())
		}
	}
}
