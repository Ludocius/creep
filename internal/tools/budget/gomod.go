package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// modFile is the subset of `go mod edit -json` the budget needs. Letting the
// go command parse go.mod avoids hand-parsing quirks such as `require(`.
type modFile struct {
	Module  struct{ Path string }
	Require []modRequire
	Replace []modReplace
}

type modReplace struct {
	Old, New struct{ Path, Version string }
}

type modRequire struct {
	Path     string
	Indirect bool
}

func readModFile(root string) (modFile, error) {
	out, err := goOutput(root, "mod", "edit", "-json")
	if err != nil {
		return modFile{}, err
	}
	var mf modFile
	if err := json.Unmarshal(out, &mf); err != nil {
		return modFile{}, fmt.Errorf("parse go mod edit -json: %w", err)
	}
	if mf.Module.Path == "" {
		return modFile{}, fmt.Errorf("go.mod has no module path")
	}
	return mf, nil
}

// directModules returns the required modules that are direct: those go.mod
// does not mark `// indirect`, plus any module whose packages our code imports.
// The comment is only a hint written by tidy, so it never hides a used module.
func directModules(reqs []modRequire, imports []string) []string {
	direct := map[string]bool{}
	for _, r := range reqs {
		if !r.Indirect {
			direct[r.Path] = true
		}
	}
	for _, imp := range imports {
		if mod := owningModule(reqs, imp); mod != "" {
			direct[mod] = true
		}
	}
	mods := make([]string, 0, len(direct))
	for m := range direct {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	return mods
}

// owningModule picks the longest required module path that contains imp,
// as the go command does when resolving an import.
func owningModule(reqs []modRequire, imp string) string {
	best := ""
	for _, r := range reqs {
		if underPath(imp, r.Path) && len(r.Path) > len(best) {
			best = r.Path
		}
	}
	return best
}

// underPath reports whether pkg is root or a package nested below it.
func underPath(pkg, root string) bool {
	return pkg == root || strings.HasPrefix(pkg, root+"/")
}
