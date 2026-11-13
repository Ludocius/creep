package main

import (
	"encoding/json"
	"fmt"
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

// directModules returns the required modules go.mod does not mark
// `// indirect`. The marks are exact because `make check` runs
// `go mod tidy -diff`, which fails when a used module is marked indirect.
func directModules(reqs []modRequire) []string {
	var mods []string
	for _, r := range reqs {
		if !r.Indirect {
			mods = append(mods, r.Path)
		}
	}
	return mods
}

// underPath reports whether pkg is root or a package nested below it.
func underPath(pkg, root string) bool {
	return pkg == root || strings.HasPrefix(pkg, root+"/")
}
