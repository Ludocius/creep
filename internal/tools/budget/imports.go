package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// sourceFile is one .go file and the import paths it declares.
type sourceFile struct {
	Name    string // slash path relative to the module root
	Pkg     string // import path of its directory
	Test    bool
	Imports []string
	Uses    []string // watched calls such as "os.StartProcess"; see procs.go
}

// gatewayDir is the only package tree allowed to touch the network
// (AGENTS.md invariant 1). It is anchored at the module root, so a look-alike
// such as internal/cli/internal/gateway gets no exception.
const gatewayDir = "internal/gateway"

// execAllowed lists module-relative package trees whose shipped code may run
// other programs. Running curl or a shell is a way around the network ban.
var execAllowed = []string{
	"internal/tools", // dev tooling run by make; never part of the binary
	// "internal/models/command",  // future: model CLIs driven as subprocesses
	// "internal/static/external", // future: external static analyzers
}

// execAllowedInTests lists packages whose tests may run programs.
var execAllowedInTests = []string{
	"cmd/creep", // end-to-end tests build and run the creep binary
}

// syscallAllowed lists module-relative files that may import syscall, each
// with its reason. Files, not packages, so new socket code needs a review here.
var syscallAllowed = map[string]string{
	"internal/cli/open_unix.go":      "O_NONBLOCK open so a FIFO argument cannot hang the CLI",
	"internal/cli/fifo_unix_test.go": "creates a FIFO with syscall.Mkfifo",
}

// collectSources parses the imports and watched calls of every .go file under fsys, including
// files excluded by build constraints, so a foo_freebsd.go cannot hide one.
func collectSources(fsys fs.FS, modPath string) ([]sourceFile, error) {
	var files []sourceFile
	fset := token.NewFileSet()
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipDir(name, d) {
			return fs.SkipDir
		}
		if d.IsDir() || path.Ext(name) != ".go" {
			return nil
		}
		f, err := parseImports(fsys, fset, name)
		if err != nil {
			return err
		}
		f.Pkg = path.Join(modPath, path.Dir(name))
		files = append(files, f)
		return nil
	})
	return files, err
}

func parseImports(fsys fs.FS, fset *token.FileSet, name string) (sourceFile, error) {
	src, err := fs.ReadFile(fsys, name)
	if err != nil {
		return sourceFile{}, err
	}
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return sourceFile{}, fmt.Errorf("parse %s: %w", name, err)
	}
	f := sourceFile{Name: name, Test: strings.HasSuffix(name, "_test.go"), Uses: selectorUses(file)}
	for _, spec := range file.Imports {
		imp, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return sourceFile{}, fmt.Errorf("parse %s: import %s: %w", name, spec.Path.Value, err)
		}
		f.Imports = append(f.Imports, imp)
	}
	return f, nil
}

// checkImports reports imports that can reach the network outside the gateway.
func checkImports(modPath string, files []sourceFile) []string {
	var problems []string
	for _, f := range files {
		if underPath(f.Pkg, path.Join(modPath, gatewayDir)) {
			continue
		}
		for _, imp := range f.Imports {
			if why := forbiddenImport(modPath, f, imp); why != "" {
				problems = append(problems, fmt.Sprintf("%s imports %q: %s (AGENTS.md invariant 1)", f.Name, imp, why))
			}
		}
	}
	return problems
}

func forbiddenImport(modPath string, f sourceFile, imp string) string {
	switch {
	case imp == "net/netip":
		// Pure IP address value types: parsing and comparison, no I/O.
		return ""
	case underPath(imp, "net"), imp == "crypto/tls", imp == "log/syslog",
		underPath(imp, "golang.org/x/net"):
		return "network access lives only in " + gatewayDir
	case imp == "syscall" && syscallAllowed[f.Name] != "":
		return ""
	case underPath(imp, "syscall"), underPath(imp, "golang.org/x/sys"):
		return "raw system calls can open sockets"
	case imp == "C", imp == "runtime/cgo", imp == "plugin", imp == "unsafe":
		return "foreign or unchecked code can open sockets"
	case imp == "os/exec" && !execPermitted(modPath, f):
		return "running programs (curl, a shell) bypasses the network ban; add the package to execAllowed"
	}
	return ""
}

func execPermitted(modPath string, f sourceFile) bool {
	for _, dir := range execAllowed {
		if underPath(f.Pkg, path.Join(modPath, dir)) {
			return true
		}
	}
	if !f.Test {
		return false
	}
	for _, dir := range execAllowedInTests {
		if f.Pkg == path.Join(modPath, dir) {
			return true
		}
	}
	return false
}

// allImports returns every import path declared by files, for dependency checks.
func allImports(files []sourceFile) []string {
	var imps []string
	for _, f := range files {
		imps = append(imps, f.Imports...)
	}
	return imps
}
