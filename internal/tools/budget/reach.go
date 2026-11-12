package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// listedPackage is the subset of `go list -json` the reachability check needs.
type listedPackage struct {
	ImportPath   string
	Imports      []string
	TestImports  []string
	XTestImports []string
	Module       *struct {
		Path string
		Main bool
	}
}

// decodePackages reads the JSON stream `go list -json` prints, dropping the
// test variants ("p [p.test]", "p.test") that -test adds.
func decodePackages(data []byte) (map[string]listedPackage, error) {
	pkgs := map[string]listedPackage{}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var p listedPackage
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return pkgs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse go list -json: %w", err)
		}
		if strings.Contains(p.ImportPath, " ") || strings.HasSuffix(p.ImportPath, ".test") {
			continue
		}
		pkgs[p.ImportPath] = p
	}
}

// checkNetReach reports main-module packages outside the gateway whose code or
// tests pull in package net through any chain of imports, such as expvar or
// a third-party client. Main-module packages are checked on their own, so the
// walk stops at them.
func checkNetReach(modPath string, pkgs map[string]listedPackage) []string {
	gateway := path.Join(modPath, gatewayDir)
	var problems []string
	for _, p := range sortedMainPackages(pkgs) {
		if underPath(p.ImportPath, gateway) {
			continue
		}
		roots := append(append(append([]string{}, p.Imports...), p.TestImports...), p.XTestImports...)
		for _, root := range roots {
			if isMain(pkgs, root) {
				continue
			}
			if reachesNet(pkgs, root, map[string]bool{}) {
				problems = append(problems, fmt.Sprintf("%s reaches package net through %s (AGENTS.md invariant 1)", p.ImportPath, root))
			}
		}
	}
	return problems
}

func reachesNet(pkgs map[string]listedPackage, imp string, seen map[string]bool) bool {
	if imp == "net" {
		return true
	}
	if seen[imp] || isMain(pkgs, imp) {
		return false
	}
	seen[imp] = true
	for _, next := range pkgs[imp].Imports {
		if reachesNet(pkgs, next, seen) {
			return true
		}
	}
	return false
}

func isMain(pkgs map[string]listedPackage, imp string) bool {
	m := pkgs[imp].Module
	return m != nil && m.Main
}

func sortedMainPackages(pkgs map[string]listedPackage) []listedPackage {
	var mains []listedPackage
	for _, p := range pkgs {
		if p.Module != nil && p.Module.Main {
			mains = append(mains, p)
		}
	}
	sort.Slice(mains, func(i, j int) bool { return mains[i].ImportPath < mains[j].ImportPath })
	return mains
}
