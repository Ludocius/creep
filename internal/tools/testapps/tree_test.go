package testapps

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

var variants = []string{"vulnerable", "safe"}

// checkVariants reports anything in an app directory besides expected.json
// and the two variant directories, and any variant that is not a flat set of
// source files of the app's language, under maxAppLines, with the same names
// in both variants.
func checkVariants(fsys fs.FS, dir, ext string) []string {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	var problems []string
	for _, e := range entries {
		want := e.Name() == expectedFile && e.Type().IsRegular() || slices.Contains(variants, e.Name()) && e.IsDir()
		if !want {
			problems = append(problems, fmt.Sprintf("%s/%s: an app holds only %s, vulnerable/ and safe/", dir, e.Name(), expectedFile))
		}
	}
	var names [][]string
	for _, v := range variants {
		got, p := checkVariant(fsys, path.Join(dir, v), ext)
		names, problems = append(names, got), append(problems, p...)
	}
	if !slices.Equal(names[0], names[1]) {
		problems = append(problems, fmt.Sprintf("%s: safe/ must hold the same files as vulnerable/ (%v vs %v)", dir, names[1], names[0]))
	}
	return problems
}

// checkVariant returns the sorted file names of one variant and its problems.
func checkVariant(fsys fs.FS, dir, ext string) ([]string, []string) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	var names, problems []string
	lines := 0
	for _, e := range entries {
		name := path.Join(dir, e.Name())
		if why := rejectSource(e, ext); why != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", name, why))
			continue
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, []string{fmt.Sprintf("%s: %v", name, err)}
		}
		names, lines = append(names, e.Name()), lines+bytes.Count(data, []byte("\n"))
	}
	if len(names) == 0 {
		problems = append(problems, dir+": no source files")
	}
	if lines >= maxAppLines {
		problems = append(problems, fmt.Sprintf("%s: %d lines, an app must stay under %d", dir, lines, maxAppLines))
	}
	return names, problems
}

// rejectSource says why a variant entry is not allowed. Only flat source
// files of the app's language pass, so a manifest, lockfile, install hook,
// script or Go file never lands next to the apps; names a test runner or
// installer picks up on its own are refused as well.
func rejectSource(e fs.DirEntry, ext string) string {
	name := e.Name()
	switch {
	case !e.Type().IsRegular():
		return "only regular files (no directories or symlinks)"
	case path.Ext(name) != ext:
		return fmt.Sprintf("only %s source files", ext)
	case runnerCollected(name):
		return "a test runner or installer would pick this file up"
	}
	return ""
}

func runnerCollected(name string) bool {
	base := strings.TrimSuffix(name, path.Ext(name))
	switch {
	case name == "setup.py", name == "conftest.py", name == "noxfile.py":
		return true
	case strings.HasPrefix(base, "test_"), strings.HasSuffix(base, "_test"):
		return true
	case strings.HasSuffix(base, ".test"), strings.HasSuffix(base, ".spec"):
		return true
	}
	return false
}
