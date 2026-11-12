package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
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

// skippedDirs hold generated or third-party files that the budget does not own.
var skippedDirs = map[string]bool{".git": true, "bin": true, "dist": true, "vendor": true, "testdata": true}

// checkFileLines reports .go files under root with more than maxLines lines.
func checkFileLines(fsys fs.FS, maxLines int) ([]string, error) {
	var problems []string
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && skippedDirs[d.Name()] {
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

var (
	// usesKey finds `uses:` in block or flow style, with or without quoted
	// keys, and captures the value up to whitespace, a quote, ',' or '}'.
	usesKey   = regexp.MustCompile(`(?:^|[\s{,\-])["']?uses["']?\s*:\s*["']?([^\s"',}#]*)`)
	shaPinned = regexp.MustCompile(`@[0-9a-f]{40}$`)
	digestPin = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	// yamlEscape matches YAML double-quoted escapes a trigger name could hide behind.
	yamlEscape = regexp.MustCompile(`\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})`)
)

// checkWorkflow reports pull_request_target triggers and actions or images not
// pinned immutably. It is a fast local backstop; zizmor in CI is the authority.
func checkWorkflow(name string, data []byte) []string {
	var problems []string
	for i, line := range strings.Split(string(data), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.Contains(unescapeYAML(code), "pull_request_target") {
			problems = append(problems, fmt.Sprintf("%s:%d: pull_request_target is forbidden", name, i+1))
		}
		for _, m := range usesKey.FindAllStringSubmatch(code, -1) {
			if why := unpinned(m[1]); why != "" {
				problems = append(problems, fmt.Sprintf("%s:%d: %s %s", name, i+1, m[1], why))
			}
		}
	}
	return problems
}

func unpinned(ref string) string {
	switch {
	case strings.HasPrefix(ref, "./"):
		return ""
	case strings.HasPrefix(ref, "docker://"):
		if digestPin.MatchString(ref) {
			return ""
		}
		return "is not pinned by @sha256 digest"
	case shaPinned.MatchString(ref):
		return ""
	}
	return "is not pinned by commit SHA"
}

func unescapeYAML(s string) string {
	return yamlEscape.ReplaceAllStringFunc(s, func(esc string) string {
		r, err := strconv.ParseUint(esc[2:], 16, 32)
		if err != nil || r > unicode.MaxRune {
			return esc
		}
		return string(rune(r))
	})
}

// isADRPath accepts only clean slash paths inside docs/adr/, so an allowlist
// entry cannot point the existence check anywhere else.
func isADRPath(p string) bool {
	return strings.HasPrefix(p, "docs/adr/") && path.Clean(p) == p && !strings.Contains(p, "\\")
}
