package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// workspaceFiles change which code the go command builds without touching
// go.mod: a workspace pulls in other modules and vendor/ replaces module
// sources with copies the module checks never see.
var workspaceFiles = []string{"go.work", "go.work.sum", "vendor"}

func workspaceProblems(cfg config) ([]string, error) {
	mf, err := readModFile(cfg.root)
	if err != nil {
		return nil, err
	}
	return checkWorkspace(os.DirFS(cfg.root), mf.Replace), nil
}

// checkWorkspace reports workspace files and vendor/ at the root, and replace
// directives that point at local directories, whose code no ADR or go.sum covers.
func checkWorkspace(fsys fs.FS, replaces []modReplace) []string {
	var problems []string
	for _, name := range workspaceFiles {
		_, err := fs.Stat(fsys, name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			problems = append(problems, fmt.Sprintf("cannot check %s: %v", name, err))
		default:
			problems = append(problems, fmt.Sprintf("%s is forbidden: it changes what gets built behind go.mod", name))
		}
	}
	for _, r := range replaces {
		// A module replacement always carries a version; a directory never does.
		if r.New.Version == "" {
			problems = append(problems, fmt.Sprintf("go.mod replaces %s with local path %q", r.Old.Path, r.New.Path))
		}
	}
	return problems
}
