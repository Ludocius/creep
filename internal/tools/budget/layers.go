package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// layerRow is one row of the layers block in docs/architecture.md §3.
type layerRow struct {
	pkg   string   // module-relative; a trailing "/*" covers the whole tree
	layer int      // -1 ("-") marks build tooling, which the product never imports
	allow []string // package names without "internal/"; "*" is any lower layer
}

func layerProblems(cfg config) ([]string, error) {
	mf, files, err := loadSources(cfg)
	if err != nil {
		return nil, err
	}
	doc, err := os.ReadFile(filepath.Join(cfg.root, cfg.architecture))
	if err != nil {
		return nil, fmt.Errorf("read layer table: %w", err)
	}
	rows, err := parseLayers(string(doc))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.architecture, err)
	}
	return checkLayers(mf.Module.Path, rows, files), nil
}

// parseLayers reads the one ```layers block. A second copy is an error, so the
// table lives in one place, and so is a name that is not a lower row, so a
// typo cannot silently allow or forbid an import.
func parseLayers(doc string) ([]layerRow, error) {
	_, rest, _ := strings.Cut(doc, "```layers")
	block, _, closed := strings.Cut(rest, "```")
	if n := strings.Count(doc, "```layers"); n != 1 || !closed {
		return nil, fmt.Errorf("want one closed ```layers block, found %d", n)
	}
	var rows []layerRow
	for _, line := range strings.Split(block, "\n") {
		code, _, _ := strings.Cut(line, "#")
		f := strings.Fields(code)
		if len(f) == 0 {
			continue
		}
		layer, err := strconv.ParseUint(f[0], 10, 8)
		if (err != nil && f[0] != "-") || len(f) < 3 {
			return nil, fmt.Errorf("layers row %q: want \"<layer|-> <package> <imports|*|->\"", strings.TrimSpace(line))
		}
		row := layerRow{pkg: f[1], layer: int(layer), allow: f[2:]}
		if f[0] == "-" {
			row.layer, row.allow = -1, nil
		}
		rows = append(rows, row)
	}
	for _, row := range rows {
		for _, name := range row.allow {
			dst, ok := rowFor(rows, "internal/"+name)
			if name != "*" && name != "-" && (!ok || dst.layer < 0 || dst.layer >= row.layer) {
				return nil, fmt.Errorf("layers row %s: %q is not a package in a lower layer", row.pkg, name)
			}
		}
	}
	return rows, nil
}

func rowFor(rows []layerRow, pkg string) (layerRow, bool) {
	for _, r := range rows {
		tree, wild := strings.CutSuffix(r.pkg, "/*")
		if r.pkg == pkg || wild && underPath(pkg, tree) {
			return r, true
		}
	}
	return layerRow{}, false
}

// checkLayers reports module packages missing from the table and imports
// their row does not allow, in shipped code and tests alike.
func checkLayers(modPath string, rows []layerRow, files []sourceFile) []string {
	var problems []string
	for _, f := range files {
		src, ok := rowFor(rows, modRel(modPath, f.Pkg))
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: package %s has no row in the layers table", f.Name, f.Pkg))
			continue
		}
		for _, imp := range f.Imports {
			if !underPath(imp, modPath) || imp == f.Pkg || src.layer < 0 {
				continue
			}
			if why := layerViolation(rows, src, modRel(modPath, imp)); why != "" {
				problems = append(problems, fmt.Sprintf("%s imports %q: %s (docs/architecture.md §3)", f.Name, imp, why))
			}
		}
	}
	return problems
}

func layerViolation(rows []layerRow, src layerRow, to string) string {
	dst, ok := rowFor(rows, to)
	switch {
	case !ok:
		return "it has no row in the layers table"
	case dst.layer < 0:
		return "build tooling is never imported by the product"
	case dst.layer >= src.layer:
		return fmt.Sprintf("layer %d may import only lower layers, this is layer %d", src.layer, dst.layer)
	case slices.Contains(src.allow, "*") || slices.Contains(src.allow, strings.TrimPrefix(to, "internal/")):
		return ""
	}
	return "its row in the layers table does not list it"
}

func modRel(modPath, pkg string) string {
	return strings.TrimPrefix(strings.TrimPrefix(pkg, modPath), "/")
}
