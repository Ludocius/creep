package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// Caps are explained in the PR that introduced them (#18): the module graph
// cap leaves room for a handful of ADR-approved dependencies and their
// transitive modules; the binary cap is several times what a stdlib CLI with
// net/http and crypto/tls needs, so only a heavy dependency can trip it.
const (
	defaultMaxModules   = 30
	defaultMaxBinaryMiB = 16
)

type config struct {
	root         string
	allowlist    string
	maxModules   int
	maxBinaryMiB int
	architecture string // holds the layers block, the one copy of the layer table
}

func main() {
	cfg := config{root: "."}
	flag.StringVar(&cfg.allowlist, "allowlist", "docs/adr/dependencies.txt", "direct dependency allowlist")
	flag.IntVar(&cfg.maxModules, "max-modules", defaultMaxModules, "cap on `go list -m all` entries")
	flag.IntVar(&cfg.maxBinaryMiB, "max-binary-mib", defaultMaxBinaryMiB, "cap on the stripped linux/amd64 binary")
	flag.StringVar(&cfg.architecture, "architecture", "docs/architecture.md", "document holding the layers table")
	flag.Parse()
	os.Exit(run(cfg, os.Stdout))
}

func run(cfg config, out io.Writer) int {
	problems, err := collect(cfg)
	if err != nil {
		fmt.Fprintln(out, "budget:", err)
		return 2
	}
	for _, p := range problems {
		fmt.Fprintln(out, "budget:", p)
	}
	if len(problems) > 0 {
		return 1
	}
	fmt.Fprintln(out, "budget: ok")
	return 0
}

func collect(cfg config) ([]string, error) {
	var problems []string
	steps := []func(config) ([]string, error){
		workspaceProblems, depProblems, importProblems, layerProblems, foreignProblems,
		netReachProblems, moduleProblems, binaryProblems, workflowProblems, policyProblems,
	}
	for _, step := range steps {
		p, err := step(cfg)
		if err != nil {
			return nil, err
		}
		problems = append(problems, p...)
	}
	return problems, nil
}

// loadSources reads go.mod and the imports of every .go file in the module.
func loadSources(cfg config) (modFile, []sourceFile, error) {
	mf, err := readModFile(cfg.root)
	if err != nil {
		return modFile{}, nil, err
	}
	files, err := collectSources(os.DirFS(cfg.root), mf.Module.Path)
	if err != nil {
		return modFile{}, nil, fmt.Errorf("scan imports: %w", err)
	}
	return mf, files, nil
}

func depProblems(cfg config) ([]string, error) {
	mf, err := readModFile(cfg.root)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(cfg.root, cfg.allowlist))
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	allow, err := parseAllowlist(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.allowlist, err)
	}
	exists := func(p string) bool { return fileExists(filepath.Join(cfg.root, filepath.FromSlash(p))) }
	return checkDeps(directModules(mf.Require), allow, exists), nil
}

func importProblems(cfg config) ([]string, error) {
	mf, files, err := loadSources(cfg)
	if err != nil {
		return nil, err
	}
	return append(checkImports(mf.Module.Path, files), checkProcessUses(mf.Module.Path, files)...), nil
}

func netReachProblems(cfg config) ([]string, error) {
	mf, err := readModFile(cfg.root)
	if err != nil {
		return nil, err
	}
	out, err := goOutput(cfg.root, "list", "-deps", "-test", "-json", "./...")
	if err != nil {
		return nil, err
	}
	pkgs, err := decodePackages(out)
	if err != nil {
		return nil, err
	}
	return checkNetReach(mf.Module.Path, pkgs), nil
}

// goOutput runs the go command in dir and returns stdout; on failure the
// error carries stderr, which is where go explains what went wrong.
func goOutput(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...) //nolint:gosec // G204: callers pass fixed go subcommands, never user input
	cmd.Dir = dir
	// A go.work above the root must not change what the budget sees.
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(filepath.FromSlash(path)) //nolint:gosec // G703: allowlist paths are clean and under docs/adr/
	return err == nil && info.Mode().IsRegular()
}

func moduleProblems(cfg config) ([]string, error) {
	out, err := goOutput(cfg.root, "list", "-m", "all")
	if err != nil {
		return nil, err
	}
	n := bytes.Count(bytes.TrimSpace(out), []byte("\n")) + 1
	return checkCap("module graph", int64(n), int64(cfg.maxModules), "modules"), nil
}

func binaryProblems(cfg config) ([]string, error) {
	dir, err := os.MkdirTemp("", "creep-budget-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "creep")
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", bin, "./cmd/creep") //nolint:gosec // G204: bin is our own temp file
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build linux/amd64 binary: %w\n%s", err, out)
	}
	info, err := os.Stat(bin)
	if err != nil {
		return nil, fmt.Errorf("stat binary: %w", err)
	}
	const mib = 1 << 20
	return checkCap("stripped linux/amd64 binary", info.Size()/1024, int64(cfg.maxBinaryMiB)*mib/1024, "KiB"), nil
}

// workflowProblems checks workflows and composite actions (action.yml) anywhere in the repo.
func workflowProblems(cfg config) ([]string, error) {
	fsys := os.DirFS(cfg.root)
	var problems []string
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipDir(name, d) {
			return fs.SkipDir
		}
		if d.IsDir() || !isWorkflowFile(name) {
			return nil
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		problems = append(problems, checkWorkflow(name, data)...)
		return nil
	})
	return problems, err
}

func isWorkflowFile(name string) bool {
	base := path.Base(name)
	if base == "action.yml" || base == "action.yaml" {
		return true
	}
	ext := path.Ext(name)
	return path.Dir(name) == ".github/workflows" && (ext == ".yml" || ext == ".yaml")
}
