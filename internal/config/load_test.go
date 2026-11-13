package config

import (
	"reflect"
	"strings"
	"testing"
)

func file(name, data string) *File {
	return &File{Name: name, Data: []byte(data)}
}

func sourceOf(t *testing.T, r *Resolved, key string) string {
	t.Helper()
	for _, e := range r.Explain() {
		if e.Key == key {
			return e.Source
		}
	}
	t.Fatalf("no key %q in Explain", key)
	return ""
}

func TestDefaultsAreValid(t *testing.T) {
	c := Defaults()
	if err := validate(&c); err != nil {
		t.Fatal(err)
	}
}

func TestLayerOrder(t *testing.T) {
	in := Inputs{
		Policy:  file("policy.yaml", "defaults:\n  model:\n    tier: small\n    name: p\n  budget:\n    max_calls: 10\n"),
		User:    file("~/.creep/config.yaml", "model:\n  name: u\n  endpoint: https://user.example\n"),
		Project: file("creep.yaml", "model:\n  name: proj\noutput:\n  format: json\n"),
		Flags:   []Flag{{Name: "--format", Key: "output.format", Value: "sarif"}},
	}
	r, err := Load(in)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ key, source string }{
		{"model.contract", "default"},
		{"model.tier", `policy "policy.yaml"`},
		{"budget.max_calls", `policy "policy.yaml"`},
		{"model.endpoint", `user "~/.creep/config.yaml"`},
		{"model.name", `project "creep.yaml"`},
		{"output.format", "flag --format"},
	}
	for _, tt := range tests {
		if got := sourceOf(t, r, tt.key); got != tt.source {
			t.Errorf("source of %s = %s, want %s", tt.key, got, tt.source)
		}
	}
	if r.Config.Model.Name != "proj" || r.Config.Output.Format != "sarif" || r.Config.Budget.MaxCalls != 10 {
		t.Errorf("unexpected config: %+v", r.Config)
	}
}

// TestExplicitReplacesUserAndProject documents the --config choice: the
// explicit file is read instead of both, and the policy still applies.
func TestExplicitReplacesUserAndProject(t *testing.T) {
	r, err := Load(Inputs{
		Policy:   file("p.yaml", "locked: [model.tier]\n"),
		User:     file("u", "model:\n  name: u\n"),
		Project:  file("creep.yaml", "model:\n  name: proj\n"),
		Explicit: file("ci.yaml", "budget:\n  max_tokens: 5\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.Model.Name != "" || r.Config.Budget.MaxTokens != 5 {
		t.Errorf("user or project applied with --config: %+v", r.Config)
	}
	if _, err := Load(Inputs{Policy: file("p.yaml", "locked: [model.tier]\n"), Explicit: file("ci.yaml", "model:\n  tier: large\n")}); err == nil {
		t.Error("--config overrode a locked key")
	}
}

func TestListsReplaceAndDoNotAlias(t *testing.T) {
	r, err := Load(Inputs{
		User:    file("u", "report:\n  formats: [json, sarif]\n"),
		Project: file("creep.yaml", "report:\n  formats: [markdown]\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Config.Report.Formats, []string{"markdown"}) {
		t.Errorf("formats = %v, want [markdown]", r.Config.Report.Formats)
	}
	d := Defaults()
	d.Report.Formats[0] = "changed"
	if Defaults().Report.Formats[0] == "changed" {
		t.Error("Defaults shares slices between calls")
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		in   Inputs
		want []string
	}{
		{"unknown top-level key", Inputs{Project: file("creep.yaml", "models:\n  name: x\n")}, []string{`project "creep.yaml"`, `unknown key "models"`, "line 1"}},
		{"unknown nested key", Inputs{User: file("u", "model:\n  named: x\n")}, []string{`unknown key "model.named"`, "line 2"}},
		{"wrong type", Inputs{User: file("u", "budget:\n  max_tokens: lots\n")}, []string{"decode", "line 2", "into int"}},
		{"section not a mapping", Inputs{User: file("u", "model: openai\n")}, []string{`key "model" must be a mapping`}},
		{"top level not a mapping", Inputs{User: file("u", "- a\n")}, []string{"the top level must be a mapping"}},
		{"null value", Inputs{User: file("u", "model:\n  name: ~\n")}, []string{`key "model.name" has no value`}},
		{"empty section", Inputs{User: file("u", "model:\n")}, []string{`key "model" has no value`}},
		{"two documents", Inputs{User: file("u", "model:\n  name: a\n---\nmodel:\n  name: b\n")}, []string{"only one YAML document"}},
		{"duplicate key", Inputs{User: file("u", "model:\n  name: a\n  name: b\n")}, []string{"already defined"}},
		{"bad enum", Inputs{User: file("u", "model:\n  contract: grpc\n")}, []string{"model.contract", `invalid value "grpc"`}},
		{"bad list enum", Inputs{User: file("u", "scanners:\n  enabled: [semgrep, curl]\n")}, []string{`invalid value "curl"`}},
		{"bad gate", Inputs{User: file("u", "gates:\n  pr: maybe:critical\n")}, []string{"gates.pr", `invalid gate "maybe:critical"`}},
		{"bad endpoint", Inputs{User: file("u", "model:\n  endpoint: file:///etc/passwd\n")}, []string{"model.endpoint", "http://"}},
		{"endpoint with control", Inputs{User: file("u", "model:\n  endpoint: \"https://x\\e[31m\"\n")}, []string{"control characters"}},
		{"bad host", Inputs{User: file("u", "egress:\n  allow: [\"a b\"]\n")}, []string{`invalid host "a b"`}},
		{"zero budget", Inputs{User: file("u", "budget:\n  max_calls: 0\n")}, []string{"budget.max_calls", "greater than 0"}},
		{"cache days range", Inputs{User: file("u", "calibration:\n  cache_days: 9999\n")}, []string{"calibration.cache_days", "1 to 365"}},
		{"bad flag value", Inputs{Flags: []Flag{{Name: "--format", Key: "output.format", Value: "xml"}}}, []string{"flag --format", `invalid value "xml"`}},
		{"policy unknown key", Inputs{Policy: file("p", "lock: [model.tier]\n")}, []string{`policy "p"`, `unknown key "lock"`}},
		{"policy unknown default", Inputs{Policy: file("p", "defaults:\n  sandbox:\n    internet: true\n")}, []string{`unknown key "defaults.sandbox.internet"`}},
		{"policy locks unknown key", Inputs{Policy: file("p", "locked: [model]\n")}, []string{`locked: unknown key "model"`}},
		{"policy bad limit", Inputs{Policy: file("p", "limits:\n  gates:\n    pr: everything\n")}, []string{"limits", `invalid gate "everything"`}},
		{"policy limit not a gate key", Inputs{Policy: file("p", "limits:\n  budget:\n    max_calls: 1\n")}, []string{`unknown key "limits.budget"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.in)
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestEmptyFilesSetNothing(t *testing.T) {
	for _, data := range []string{"", "# only a comment\n", "{}\n"} {
		r, err := Load(Inputs{User: file("u", data), Project: file("creep.yaml", data)})
		if err != nil {
			t.Fatalf("%q: %v", data, err)
		}
		if !reflect.DeepEqual(r.Config, Defaults()) {
			t.Errorf("%q changed the config: %+v", data, r.Config)
		}
	}
}

func TestAliasesAreResolved(t *testing.T) {
	r, err := Load(Inputs{User: file("u", "model: &m\n  name: a\ngates:\n  pr: &g probable:high\n  nightly: *g\n")})
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.Gates.Nightly != "probable:high" || r.Config.Model.Name != "a" {
		t.Errorf("aliases not applied: %+v", r.Config)
	}
}
