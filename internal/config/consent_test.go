package config

import (
	"slices"
	"strings"
	"testing"
)

func TestInCI(t *testing.T) {
	tests := []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"CI": "true"}, true},
		{map[string]string{"CI": "1"}, true},
		{map[string]string{"CI": "TRUE "}, true},
		{map[string]string{"CI": "false"}, false},
		{map[string]string{"CI": "0"}, false},
		{map[string]string{"CI": ""}, false},
		{map[string]string{"TF_BUILD": "True"}, true},
		{map[string]string{"JENKINS_URL": "https://ci.example/"}, true},
		{map[string]string{"TEAMCITY_VERSION": "2025.1"}, true},
		{map[string]string{"CODEBUILD_BUILD_ID": "proj:abc"}, true},
		{map[string]string{"bamboo_buildKey": "PROJ-PLAN-JOB1"}, true},
		{map[string]string{"BUILD_ID": "b1", "PROJECT_ID": "p1"}, true},
		{map[string]string{"BUILD_ID": "b1"}, false},
		{map[string]string{"PROJECT_ID": "p1"}, false},
	}
	for _, tt := range tests {
		got := InCI(func(k string) string { return tt.env[k] })
		if got != tt.want {
			t.Errorf("InCI(%v) = %v, want %v", tt.env, got, tt.want)
		}
	}
}

func TestPolicyConsent(t *testing.T) {
	r, err := Load(Inputs{Policy: file("p.yaml", "consent:\n  - https://api.example.com\n")})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.PolicyConsent(); !slices.Equal(got, []string{"https://api.example.com"}) {
		t.Fatalf("PolicyConsent = %q", got)
	}
	none, err := Load(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	if got := none.PolicyConsent(); len(got) != 0 {
		t.Fatalf("PolicyConsent without policy = %q, want none", got)
	}
}

// Only the policy can grant consent through configuration: the scanned
// repository's creep.yaml must never approve where its code is sent, and
// the user file, --config and policy defaults have no consent key either.
func TestConsentOnlyFromPolicy(t *testing.T) {
	const grant = "consent:\n  - https://evil.example\n"
	tests := []struct {
		name string
		in   Inputs
	}{
		{"project", Inputs{Project: file("creep.yaml", grant)}},
		{"user", Inputs{User: file("~/.creep/config.yaml", grant)}},
		{"--config", Inputs{Explicit: file("ci.yaml", grant)}},
		{"policy defaults", Inputs{Policy: file("p.yaml", "defaults:\n  "+strings.ReplaceAll(grant, "\n  ", "\n    "))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Load(tt.in)
			if err == nil || !strings.Contains(err.Error(), "unknown key") {
				t.Fatalf("Load = %v, want unknown key error", err)
			}
			if r != nil && len(r.PolicyConsent()) != 0 {
				t.Fatal("consent granted outside the policy")
			}
		})
	}
}
