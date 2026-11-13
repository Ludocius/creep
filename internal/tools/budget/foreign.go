package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// foreignExts are the non-Go sources and objects the go command compiles or
// links into a package. Assembly or a .syso can make system calls with no
// import, so the import rules cannot see them. Matched lowercased, so .S and
// .F count too.
var foreignExts = map[string]bool{
	".s": true, ".sx": true, ".syso": true,
	".c": true, ".h": true, ".hh": true, ".hpp": true, ".hxx": true,
	".cc": true, ".cpp": true, ".cxx": true, ".m": true,
	".f": true, ".for": true, ".f90": true, ".swig": true, ".swigcxx": true,
}

// foreignAllowed lists module-relative files that may be non-Go sources, each
// with its reason. Empty today.
var foreignAllowed = map[string]string{}

func foreignProblems(cfg config) ([]string, error) {
	names, err := walkForeignFiles(os.DirFS(cfg.root))
	if err != nil {
		return nil, fmt.Errorf("scan non-Go sources: %w", err)
	}
	return checkForeign(names), nil
}

// walkForeignFiles finds files by extension, including those excluded by
// build constraints. It covers every directory the go command could build, a
// superset of what `go list ./...` reports, so it also walks root bin/ and
// dist/, which skipDir leaves out of the other checks.
func walkForeignFiles(fsys fs.FS) ([]string, error) {
	var names []string
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipDir(name, d) && d.Name() != "bin" && d.Name() != "dist" {
			return fs.SkipDir
		}
		if !d.IsDir() && foreignExts[strings.ToLower(path.Ext(name))] {
			names = append(names, name)
		}
		return nil
	})
	return names, err
}

// checkForeign reports each non-Go source unless foreignAllowed names it.
func checkForeign(names []string) []string {
	var problems []string
	sort.Strings(names)
	for _, name := range names {
		if foreignAllowed[name] != "" {
			continue
		}
		problems = append(problems, fmt.Sprintf("%s is a non-Go source: it can make system calls with no import; add it to foreignAllowed with a reason", name))
	}
	return problems
}
