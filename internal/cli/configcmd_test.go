package cli

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata golden files")

const goldenPolicy = `locked: [model.endpoint]
limits:
  gates:
    pr: probable:high
defaults:
  model:
    endpoint: https://models.corp.example/v1
  gates:
    pr: probable:high
`

const goldenUser = `model:
  name: local-model
  tier: large
scanners:
  enabled: [gitleaks, semgrep]
`

const goldenProject = `# committed in the repository
gates:
  pr: probable:medium
report:
  formats: [sarif]
calibration:
  cache_days: 7
`

// configEnv runs a test from a fresh directory with its own home, project
// file and policy, so the developer's real files never leak in.
func configEnv(t *testing.T, policy, user, project string) string {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	work := filepath.Join(dir, "work")
	mustMkdir(t, filepath.Join(home, ".creep"))
	mustMkdir(t, work)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(policyEnv, "")
	t.Chdir(work)
	if policy != "" {
		mustWrite(t, filepath.Join(work, "policy.yaml"), policy)
		t.Setenv(policyEnv, "policy.yaml")
	}
	if user != "" {
		mustWrite(t, filepath.Join(home, ".creep", "config.yaml"), user)
	}
	if project != "" {
		mustWrite(t, filepath.Join(work, projectFile), project)
	}
	return work
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestConfigExplainGolden covers acceptance criterion 4: every key, its
// final value and the layer it came from.
func TestConfigExplainGolden(t *testing.T) {
	golden, err := filepath.Abs(filepath.Join("testdata", "config_explain.golden"))
	if err != nil {
		t.Fatal(err)
	}
	configEnv(t, goldenPolicy, goldenUser, goldenProject)
	code, stdout, stderr := run("config", "explain", "--log-level", "debug")
	if code != exitcode.OK {
		t.Fatalf("exit code = %d\nstderr: %s", code, stderr)
	}
	if *updateGolden {
		mustWrite(t, golden, stdout)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout; got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("config explain output differs from %s (rerun with -update to accept):\n%s", golden, got)
	}
}

func TestConfigExplainJSON(t *testing.T) {
	configEnv(t, "", "", "output:\n  format: json\n")
	code, stdout, stderr := run("config", "explain")
	if code != exitcode.OK {
		t.Fatalf("exit code = %d\nstderr: %s", code, stderr)
	}
	var entries []struct{ Key, Source string }
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(entries) == 0 || entries[0].Key != "model.contract" || entries[0].Source != "default" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

func TestConfigExplainFailures(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		user    string
		project string
		args    []string
		want    []string
	}{
		{"locked key in project", "locked: [gates.pr]\n", "", "gates:\n  pr: none\n", nil, []string{`project "creep.yaml": key "gates.pr" is locked by policy "policy.yaml" and cannot be overridden`}},
		{"project chooses egress", goldenPolicy, "", "model:\n  name: x\negress:\n  allow: [a]\n", nil, []string{`key "egress.allow" cannot be set in the project file`}},
		{"locked key in user", goldenPolicy, "model:\n  endpoint: https://evil.example\n", "", nil, []string{`user "~/.creep/config.yaml": key "model.endpoint" is locked by policy "policy.yaml"`}},
		{"locked key by flag", "locked: [log.level]\n", "", "", []string{"--log-level", "warn"}, []string{`flag --log-level: key "log.level" is locked`}},
		{"gate looser than limit", goldenPolicy, "", "gates:\n  pr: verified:critical\n", nil, []string{`gates.pr "verified:critical" is looser than the limit "probable:high"`}},
		{"project disables pr gate", "", "", "gates:\n  pr: none\n", nil, []string{`project "creep.yaml": gates.pr "none" is looser than the built-in floor "probable:critical"`}},
		{"project disables nightly gate with policy", "locked: [log.level]\n", "", "gates:\n  nightly: none\n", nil, []string{`project "creep.yaml": gates.nightly "none" is looser than the built-in floor "verified:high"`}},
		{"fixed protection", "", "", "sandbox:\n  internet: true\n", nil, []string{`project "creep.yaml": line 2: unknown key "sandbox.internet"`}},
		{"unsupported format", "", "", "", []string{"--format", "sarif"}, []string{`output format "sarif" is not supported here`}},
		{"bad policy", "lockd: []\n", "", "", nil, []string{`policy "policy.yaml"`, `unknown key "lockd"`}},
		{"escaped key", "", "", "\"\\e[31mred\": 1\n", nil, []string{`unknown key "\x1b[31mred"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configEnv(t, tt.policy, tt.user, tt.project)
			code, stdout, stderr := run(append([]string{"config", "explain"}, tt.args...)...)
			if code != exitcode.ConfigError {
				t.Fatalf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, exitcode.ConfigError, stdout, stderr)
			}
			assertContains(t, "stderr", stderr, tt.want)
			assertNoControl(t, stderr)
		})
	}
}

func assertNoControl(t *testing.T, s string) {
	t.Helper()
	for _, r := range strings.TrimRight(s, "\n") {
		if r != '\n' && (r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0) {
			t.Fatalf("output contains control rune %U: %q", r, s)
		}
	}
}

func TestConfigFileLayers(t *testing.T) {
	t.Run("missing policy fails closed", func(t *testing.T) {
		configEnv(t, "", "", "")
		t.Setenv(policyEnv, "nope.yaml")
		code, _, stderr := run("config", "explain")
		if code != exitcode.ConfigError || !strings.Contains(stderr, `CREEP_POLICY "nope.yaml": file does not exist`) {
			t.Errorf("code = %d, stderr = %s", code, stderr)
		}
	})
	t.Run("--config replaces user and project", func(t *testing.T) {
		work := configEnv(t, "", "model:\n  name: user\n", "model:\n  name: project\n")
		mustWrite(t, filepath.Join(work, "ci.yaml"), "model:\n  tier: small\n")
		code, stdout, stderr := run("config", "explain", "--config", "ci.yaml")
		if code != exitcode.OK {
			t.Fatalf("code = %d, stderr = %s", code, stderr)
		}
		assertContains(t, "stdout", stdout, []string{`model.tier              "small"`, `--config "ci.yaml"`})
		if strings.Contains(stdout, "user") || strings.Contains(stdout, "project") {
			t.Errorf("user or project layer applied with --config:\n%s", stdout)
		}
	})
	t.Run("no files gives defaults", func(t *testing.T) {
		configEnv(t, "", "", "")
		code, stdout, stderr := run("config", "explain")
		if code != exitcode.OK || strings.Contains(stdout, "project") {
			t.Errorf("code = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
	})
}

// TestProjectConfigMustNotBeALink guards against a cloned repository whose
// creep.yaml points elsewhere (a UNC share on Windows, a secret on Unix).
func TestProjectConfigMustNotBeALink(t *testing.T) {
	work := configEnv(t, "", "", "")
	target := filepath.Join(t.TempDir(), "real.yaml")
	mustWrite(t, target, "model:\n  name: x\n")
	if err := os.Symlink(target, filepath.Join(work, projectFile)); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	code, _, stderr := run("config", "explain")
	if code != exitcode.ConfigError || !strings.Contains(stderr, "not a link") {
		t.Errorf("code = %d, stderr = %s", code, stderr)
	}
}

func TestConfigRejectsUnsafePaths(t *testing.T) {
	tests := []struct {
		name, path, goos, want string
	}{
		{"UNC share", `\\attacker.example\share\creep.yaml`, "windows", "UNC and device paths are not allowed"},
		{"UNC with slashes", "//attacker.example/share/creep.yaml", "windows", "UNC and device paths are not allowed"},
		{"NT namespace", `\??\UNC\attacker.example\share\x`, "windows", "UNC and device paths are not allowed"},
		{"proc environ", "/proc/self/environ", "unix", "not allowed"},
		{"proc mem", "/proc/self/mem", "unix", "not allowed"},
		{"sys file", "/sys/kernel/mm/transparent_hugepage/enabled", "unix", "not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipUnlessOS(t, tt.goos)
			configEnv(t, "", "", "")
			for _, args := range [][]string{{"--config", tt.path, "version"}, {"config", "explain", "--config", tt.path}} {
				code, _, stderr := run(args...)
				if code != exitcode.ConfigError || !strings.Contains(stderr, tt.want) {
					t.Errorf("%v: code = %d, stderr = %s", args, code, stderr)
				}
			}
			t.Setenv(policyEnv, tt.path)
			code, _, stderr := run("config", "explain")
			if code != exitcode.ConfigError || !strings.Contains(stderr, "CREEP_POLICY") {
				t.Errorf("policy: code = %d, stderr = %s", code, stderr)
			}
		})
	}
}

// TestConfigRejectsLinkToProc catches what a lexical check alone would miss.
func TestConfigRejectsLinkToProc(t *testing.T) {
	skipUnlessOS(t, "unix")
	link := filepath.Join(t.TempDir(), "env.yaml")
	if err := os.Symlink("/proc/self/environ", link); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run("--config", link, "version")
	if code != exitcode.ConfigError || !strings.Contains(stderr, "not allowed") {
		t.Errorf("code = %d, stderr = %s", code, stderr)
	}
}
