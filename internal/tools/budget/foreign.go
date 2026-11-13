package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
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

// listedFiles is the subset of `go list -json` naming a package's non-Go files.
type listedFiles struct {
	Dir                                        string
	SFiles, SysoFiles, CFiles, CXXFiles        []string
	HFiles, MFiles, FFiles                     []string
	SwigFiles, SwigCXXFiles, IgnoredOtherFiles []string
}

func foreignProblems(cfg config) ([]string, error) {
	walked, err := walkForeignFiles(os.DirFS(cfg.root))
	if err != nil {
		return nil, fmt.Errorf("scan non-Go sources: %w", err)
	}
	listed, err := listForeignFiles(cfg.root)
	if err != nil {
		return nil, err
	}
	return checkForeign(append(walked, listed...)), nil
}

// walkForeignFiles finds files by extension, including those excluded by
// build constraints, which go list does not report for this platform.
func walkForeignFiles(fsys fs.FS) ([]string, error) {
	var names []string
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipDir(name, d) {
			return fs.SkipDir
		}
		if !d.IsDir() && foreignExts[strings.ToLower(path.Ext(name))] {
			names = append(names, name)
		}
		return nil
	})
	return names, err
}

// listForeignFiles asks the go command which non-Go files each package uses.
// -e keeps packages whose C files are a build error without cgo.
func listForeignFiles(root string) ([]string, error) {
	out, err := goOutput(root, "list", "-e", "-json", "./...")
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", root, err)
	}
	var names []string
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedFiles
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse go list -json: %w", err)
		}
		names = append(names, p.relNames(abs)...)
	}
}

// relNames returns the package's non-Go files as slash paths relative to root;
// a directory outside root keeps its absolute path, so it is still reported.
func (p listedFiles) relNames(root string) []string {
	dir, err := filepath.Rel(root, p.Dir)
	if err != nil || strings.HasPrefix(dir, "..") {
		dir = p.Dir
	}
	var names []string
	for _, group := range [][]string{p.SFiles, p.SysoFiles, p.CFiles, p.CXXFiles, p.HFiles,
		p.MFiles, p.FFiles, p.SwigFiles, p.SwigCXXFiles, p.IgnoredOtherFiles} {
		for _, f := range group {
			names = append(names, filepath.ToSlash(filepath.Join(dir, f)))
		}
	}
	return names
}

// checkForeign reports each non-Go source once, unless foreignAllowed names it.
func checkForeign(names []string) []string {
	seen := map[string]bool{}
	var problems []string
	sort.Strings(names)
	for _, name := range names {
		if seen[name] || foreignAllowed[name] != "" {
			continue
		}
		seen[name] = true
		problems = append(problems, fmt.Sprintf("%s is a non-Go source: it can make system calls with no import; add it to foreignAllowed with a reason", name))
	}
	return problems
}
