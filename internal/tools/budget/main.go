package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// Caps are explained in the PR that introduced them (#18): the module graph
// cap leaves room for a handful of ADR-approved dependencies and their
// transitive modules; the binary cap is several times what a stdlib CLI with
// net/http and crypto/tls needs, so only a heavy dependency can trip it.
const (
	defaultMaxModules   = 30
	defaultMaxBinaryMiB = 16
	defaultMaxLines     = 400
)

type config struct {
	allowlist    string
	maxModules   int
	maxBinaryMiB int
	maxLines     int
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.allowlist, "allowlist", "docs/adr/dependencies.txt", "direct dependency allowlist")
	flag.IntVar(&cfg.maxModules, "max-modules", defaultMaxModules, "cap on `go list -m all` entries")
	flag.IntVar(&cfg.maxBinaryMiB, "max-binary-mib", defaultMaxBinaryMiB, "cap on the stripped linux/amd64 binary")
	flag.IntVar(&cfg.maxLines, "max-lines", defaultMaxLines, "cap on lines per .go file")
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
	steps := []func(config) ([]string, error){depProblems, moduleProblems, binaryProblems, lineProblems, workflowProblems}
	for _, step := range steps {
		p, err := step(cfg)
		if err != nil {
			return nil, err
		}
		problems = append(problems, p...)
	}
	return problems, nil
}

func depProblems(cfg config) ([]string, error) {
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	data, err := os.ReadFile(cfg.allowlist)
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	allow, err := parseAllowlist(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.allowlist, err)
	}
	return checkDeps(directRequires(gomod), allow, fileExists), nil
}

func fileExists(path string) bool {
	info, err := os.Stat(filepath.FromSlash(path)) //nolint:gosec // G703: allowlist paths are clean and under docs/adr/
	return err == nil && info.Mode().IsRegular()
}

func moduleProblems(cfg config) ([]string, error) {
	out, err := exec.Command("go", "list", "-m", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("go list -m all: %w", err)
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

func lineProblems(cfg config) ([]string, error) {
	return checkFileLines(os.DirFS("."), cfg.maxLines)
}

func workflowProblems(_ config) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(".github", "workflows", "*.y*ml"))
	if err != nil {
		return nil, fmt.Errorf("list workflows: %w", err)
	}
	var problems []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		problems = append(problems, checkWorkflow(filepath.ToSlash(f), data)...)
	}
	return problems, nil
}
