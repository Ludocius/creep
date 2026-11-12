package main

import (
	"fmt"
	"go/ast"
	"strconv"
)

// watchedCalls lists functions that start processes or turn a raw descriptor
// (an inherited socket, say) into an *os.File without importing os/exec or net.
var watchedCalls = map[string]map[string]bool{
	"os": {"StartProcess": true, "NewFile": true},
	"syscall": {
		"Exec": true, "ForkExec": true, "StartProcess": true,
		"Socket": true, "Connect": true,
		"Syscall": true, "Syscall6": true, "RawSyscall": true, "RawSyscall6": true,
	},
}

// newFileAllowed lists module-relative files that may call os.NewFile, each
// with its reason. Empty today.
var newFileAllowed = map[string]string{}

// selectorUses returns "pkg.Name" for every selector on an import of a watched
// package, resolving aliases. A dot import hides the selector, so it is
// reported as "pkg.*".
func selectorUses(file *ast.File) []string {
	local := map[string]string{}
	var uses []string
	for _, spec := range file.Imports {
		imp, err := strconv.Unquote(spec.Path.Value)
		if err != nil || watchedCalls[imp] == nil {
			continue
		}
		name := imp
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." {
			uses = append(uses, imp+".*")
		}
		local[name] = imp
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && local[id.Name] != "" && watchedCalls[local[id.Name]][sel.Sel.Name] {
			uses = append(uses, local[id.Name]+"."+sel.Sel.Name)
		}
		return true
	})
	return uses
}

// checkProcessUses reports process starts and raw descriptor wrapping outside
// their allowlists. It complements the import rules for code that never
// imports os/exec.
func checkProcessUses(modPath string, files []sourceFile) []string {
	var problems []string
	for _, f := range files {
		for _, use := range f.Uses {
			if why := forbiddenUse(modPath, f, use); why != "" {
				problems = append(problems, fmt.Sprintf("%s uses %s: %s (AGENTS.md invariant 1)", f.Name, use, why))
			}
		}
	}
	return problems
}

func forbiddenUse(modPath string, f sourceFile, use string) string {
	switch use {
	case "os.*", "syscall.*":
		return "dot imports hide process and descriptor calls from the budget"
	case "os.StartProcess":
		if execPermitted(modPath, f) {
			return ""
		}
		return "running programs bypasses the network ban; add the package to execAllowed"
	case "os.NewFile":
		if newFileAllowed[f.Name] != "" {
			return ""
		}
		return "wrapping a raw descriptor can reach an inherited socket; add the file to newFileAllowed"
	}
	return "raw system calls can start programs or open sockets"
}
