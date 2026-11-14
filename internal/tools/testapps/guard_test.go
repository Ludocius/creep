package testapps

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

const appsDir = "testdata/apps"

// runnerExts are files a shell, make or a CI runner executes.
var runnerExts = map[string]bool{".sh": true, ".bash": true, ".ps1": true, ".bat": true, ".cmd": true, ".mk": true}

// processImports are the packages Go code can start a program with.
var processImports = map[string]bool{"os/exec": true, "syscall": true, "golang.org/x/sys/unix": true, "golang.org/x/sys/windows": true}

// checkNoExecution reports every file in fsys (a repository root) that could
// run the apps under appsDir: an executed file that mentions the directory,
// or Go code that can start programs and names it.
func checkNoExecution(fsys fs.FS) ([]string, error) {
	var problems []string
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return skipWalk(fsys, name, d)
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if why := executesApps(name, data); why != "" {
			problems = append(problems, fmt.Sprintf("%s: %s; the apps under %s run only in the sandbox", name, why, appsDir))
		}
		return nil
	})
	return problems, err
}

// skipWalk leaves out .git, every testdata tree (the apps themselves, data
// that nothing executes), the root build outputs and nested modules, such as
// a git worktree checked out inside the repository, which are not this
// repository's files.
func skipWalk(fsys fs.FS, name string, d fs.DirEntry) error {
	switch {
	case name == ".":
		return nil
	case d.Name() == ".git", d.Name() == "testdata":
		return fs.SkipDir
	case path.Dir(name) == "." && (d.Name() == "bin" || d.Name() == "dist"):
		return fs.SkipDir
	}
	if _, err := fs.Stat(fsys, path.Join(name, "go.mod")); err == nil {
		return fs.SkipDir
	}
	return nil
}

func executesApps(name string, data []byte) string {
	if path.Ext(name) == ".go" {
		return goExecutesApps(name, data)
	}
	if isRunnerFile(name) && mentionsApps(string(data)) {
		return "an executed file mentions the vulnerable apps"
	}
	return ""
}

func isRunnerFile(name string) bool {
	base := path.Base(name)
	switch {
	case base == "Makefile", base == "GNUmakefile", strings.HasPrefix(base, "Dockerfile"):
		return true
	case base == "action.yml", base == "action.yaml", path.Dir(name) == ".github/workflows":
		return true
	}
	return runnerExts[strings.ToLower(path.Ext(name))]
}

// mentionsApps matches the path with either separator, so a Windows script
// cannot spell it with backslashes to slip past.
func mentionsApps(s string) bool {
	s = strings.ToLower(strings.ReplaceAll(s, `\`, "/"))
	return strings.Contains(s, appsDir)
}

// goExecutesApps reports Go code that can start a program and has a string
// literal naming the apps: the whole path, or "apps" for a filepath.Join.
func goExecutesApps(name string, data []byte) string {
	file, err := parser.ParseFile(token.NewFileSet(), name, data, parser.SkipObjectResolution)
	if err != nil {
		return fmt.Sprintf("cannot parse: %v", err)
	}
	if !startsPrograms(file) {
		return ""
	}
	found := ""
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || found != "" {
			return found == ""
		}
		if s, err := strconv.Unquote(lit.Value); err == nil && (mentionsApps(s) || strings.Trim(s, `/\`) == "apps") {
			found = "Go code that can start programs names the vulnerable apps"
		}
		return true
	})
	return found
}

func startsPrograms(file *ast.File) bool {
	for _, spec := range file.Imports {
		if imp, err := strconv.Unquote(spec.Path.Value); err == nil && processImports[imp] {
			return true
		}
	}
	calls := false
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "StartProcess" {
			calls = true
		}
		return !calls
	})
	return calls
}
