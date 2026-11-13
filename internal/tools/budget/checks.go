package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// parseAllowlist reads "module docs/adr/NNNN-name.md" lines; '#' starts a comment.
func parseAllowlist(data []byte) (map[string]string, error) {
	allow := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || !isADRPath(fields[1]) {
			return nil, fmt.Errorf("allowlist line %d: want \"<module> docs/adr/<file>.md\"", n)
		}
		allow[fields[0]] = fields[1]
	}
	return allow, sc.Err()
}

// checkDeps reports direct dependencies without an allowlist entry or whose ADR is missing.
func checkDeps(direct []string, allow map[string]string, adrExists func(string) bool) []string {
	var problems []string
	for _, mod := range direct {
		adr, ok := allow[mod]
		if !ok {
			problems = append(problems, fmt.Sprintf("direct dependency %s has no ADR in the allowlist", mod))
			continue
		}
		if !adrExists(adr) {
			problems = append(problems, fmt.Sprintf("direct dependency %s: ADR %s does not exist", mod, adr))
		}
	}
	return problems
}

func checkCap(what string, got, limit int64, unit string) []string {
	if got <= limit {
		return nil
	}
	return []string{fmt.Sprintf("%s is %d %s, cap is %d", what, got, unit, limit)}
}

// skipDir reports directories the budget does not own: .git and testdata
// anywhere (the go command never builds testdata), and the build outputs and
// vendor tree only at the root, so a package named internal/bin is still
// checked. A root vendor/ fails the workspace check instead.
func skipDir(name string, d fs.DirEntry) bool {
	if !d.IsDir() || name == "." {
		return false
	}
	switch d.Name() {
	case ".git", "testdata":
		return true
	case "bin", "dist", "vendor":
		return path.Dir(name) == "."
	}
	return false
}

// checkFileLines reports .go files under root with more than maxLines lines.
func checkFileLines(fsys fs.FS, maxLines int) ([]string, error) {
	var problems []string
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipDir(name, d) {
			return fs.SkipDir
		}
		if d.IsDir() || filepath.Ext(name) != ".go" {
			return nil
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if n := bytes.Count(data, []byte("\n")); n > maxLines {
			problems = append(problems, fmt.Sprintf("%s has %d lines, cap is %d", name, n, maxLines))
		}
		return nil
	})
	return problems, err
}

// isADRPath accepts only clean slash paths inside docs/adr/, so an allowlist
// entry cannot point the existence check anywhere else.
func isADRPath(p string) bool {
	return strings.HasPrefix(p, "docs/adr/") && path.Clean(p) == p && !strings.Contains(p, "\\")
}
