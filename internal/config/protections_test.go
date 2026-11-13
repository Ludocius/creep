package config

import (
	"strings"
	"testing"
)

// Protection tests for issue #2: policy locks, policy limits, keys the
// project file may not set, and fixed protections having no keys at all.

const lockingPolicy = `locked: [model.endpoint, gates.pr, output.format]
defaults:
  model:
    endpoint: https://models.corp.example
`

// TestLockedKeyCannotBeOverridden covers acceptance criterion 1 for every
// layer after the policy, including setting the same value.
func TestLockedKeyCannotBeOverridden(t *testing.T) {
	policy := file("org.yaml", lockingPolicy)
	tests := []struct {
		name string
		in   Inputs
		want string
	}{
		{"project", Inputs{Project: file("creep.yaml", "gates:\n  pr: none\n")}, `project "creep.yaml": key "gates.pr" is locked by policy "org.yaml"`},
		{"project same value", Inputs{Project: file("creep.yaml", "gates:\n  pr: probable:critical\n")}, `key "gates.pr" is locked`},
		{"user", Inputs{User: file("~/.creep/config.yaml", "model:\n  endpoint: https://evil.example\n")}, `user "~/.creep/config.yaml": key "model.endpoint" is locked`},
		{"--config", Inputs{Explicit: file("ci.yaml", "gates:\n  pr: verified:critical\n")}, `--config "ci.yaml": key "gates.pr" is locked`},
		{"flag", Inputs{Flags: []Flag{{Name: "--format", Key: "output.format", Value: "json"}}}, `flag --format: key "output.format" is locked`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.in.Policy = policy
			_, err := Load(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestLockedKeyKeepsPolicyValue(t *testing.T) {
	r, err := Load(Inputs{Policy: file("org.yaml", lockingPolicy), Project: file("creep.yaml", "model:\n  name: x\n")})
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.Model.Endpoint != "https://models.corp.example" || sourceOf(t, r, "model.endpoint") != `policy "org.yaml"` {
		t.Errorf("locked endpoint = %q from %s", r.Config.Model.Endpoint, sourceOf(t, r, "model.endpoint"))
	}
}

// TestGateLooserThanLimitIsRejected covers acceptance criterion 2.
func TestGateLooserThanLimitIsRejected(t *testing.T) {
	policy := "limits:\n  gates:\n    pr: probable:high\n    nightly: verified:medium\n"
	tests := []struct {
		name    string
		project string
		wantErr string
	}{
		{"default pr is looser", "", `default: gates.pr "probable:critical" is looser than the limit "probable:high"`},
		{"pr disabled", "gates:\n  pr: none\n", `project "creep.yaml": gates.pr "none" is looser`},
		{"pr looser status", "gates:\n  pr: verified:high\n", `gates.pr "verified:high" is looser`},
		{"pr looser severity", "gates:\n  pr: probable:critical\n", `gates.pr "probable:critical" is looser`},
		{"nightly looser", "gates:\n  pr: probable:high\n  nightly: verified:high\n", `gates.nightly "verified:high" is looser`},
		{"equal to limits", "gates:\n  pr: probable:high\n  nightly: verified:medium\n", ""},
		{"stricter than limits", "gates:\n  pr: probable:low\n  nightly: probable:info\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := Inputs{Policy: file("org.yaml", policy)}
			if tt.project != "" {
				in.Project = file("creep.yaml", tt.project)
			}
			_, err := Load(in)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestGateStrictness(t *testing.T) {
	tests := []struct {
		gate, limit string
		want        bool
	}{
		{"probable:critical", "none", true},
		{"none", "none", true},
		{"none", "verified:critical", false},
		{"verified:critical", "verified:critical", true},
		{"probable:critical", "verified:critical", true},
		{"verified:high", "verified:critical", true},
		{"verified:critical", "probable:critical", false},
		{"verified:info", "probable:critical", false},
		{"probable:critical", "verified:high", false},
		{"probable:info", "probable:low", true},
	}
	for _, tt := range tests {
		g, err := parseGate(tt.gate)
		if err != nil {
			t.Fatal(err)
		}
		l, err := parseGate(tt.limit)
		if err != nil {
			t.Fatal(err)
		}
		if got := g.atLeastAsStrict(l); got != tt.want {
			t.Errorf("%s at least as strict as %s = %v, want %v", tt.gate, tt.limit, got, tt.want)
		}
	}
}

// TestFixedProtectionsHaveNoKeys covers acceptance criterion 3: turning a
// fixed protection off is an unknown-key error in every layer.
func TestFixedProtectionsHaveNoKeys(t *testing.T) {
	attempts := []string{
		"sandbox:\n  internet: true\n",
		"sandbox:\n  network: host\n",
		"redact: false\n",
		"redaction:\n  enabled: false\n",
		"egress:\n  log: false\n",
		"egress_log: false\n",
		"model:\n  run_output: true\n",
		"execute_on_host: true\n",
		"planner:\n  read_code: true\n",
		"url: https://target.example\n",
		"target:\n  url: https://target.example\n",
	}
	for _, yaml := range attempts {
		t.Run(strings.SplitN(yaml, "\n", 2)[0], func(t *testing.T) {
			layers := []Inputs{
				{User: file("u", yaml)},
				{Project: file("creep.yaml", yaml)},
				{Explicit: file("ci.yaml", yaml)},
				{Policy: file("p", "defaults:\n  "+strings.ReplaceAll(strings.TrimSuffix(yaml, "\n"), "\n", "\n  ")+"\n")},
			}
			for _, in := range layers {
				_, err := Load(in)
				if err == nil || !strings.Contains(err.Error(), "unknown key") {
					t.Errorf("err = %v, want unknown key", err)
				}
			}
		})
	}
}

// TestNoKeyNamesAFixedProtection fails if someone adds a key that could
// switch a fixed protection, even before a test above names it.
func TestNoKeyNamesAFixedProtection(t *testing.T) {
	banned := []string{"internet", "network", "redact", "egress.log", "egress_log", "host", "exec", "run_", "url", "planner", "code"}
	for _, key := range Keys() {
		for _, word := range banned {
			if strings.Contains(key, word) {
				t.Errorf("key %q contains %q: fixed protections must not be configurable (docs/design.md)", key, word)
			}
		}
	}
}

func TestProjectCannotChooseWhereCodeGoes(t *testing.T) {
	for _, yaml := range []string{"model:\n  endpoint: https://attacker.example\n", "egress:\n  allow: [attacker.example]\n"} {
		_, err := Load(Inputs{Project: file("creep.yaml", yaml)})
		if err == nil || !strings.Contains(err.Error(), "cannot be set in the project file") {
			t.Errorf("project %q: err = %v", yaml, err)
		}
		if _, err := Load(Inputs{User: file("u", yaml)}); err != nil {
			t.Errorf("user %q: %v", yaml, err)
		}
	}
}
