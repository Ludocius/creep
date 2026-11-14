package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const fakeKey = "sk-ant-NOT-A-REAL-KEY-abcdef0123456789"

func env(v string) func(string) string {
	return func(name string) string {
		if name == KeyEnv {
			return v
		}
		return "sk-other-variable"
	}
}

func TestKeyFromEnv(t *testing.T) {
	tests := []struct {
		name, value, want string
		err               bool
	}{
		{"unset", "", "", false},
		{"blank", " \n", "", false},
		{"trimmed", "  " + fakeKey + "\n", fakeKey, false},
		{"header injection", fakeKey + "\r\nX-Evil: 1", "", true},
		{"inner space", "sk ant", "", true},
		{"non ascii", "sk-é", "", true},
		{"nul", "sk-\x00", "", true},
		{"too long", strings.Repeat("k", maxKeyBytes+1), "", true},
		{"max length", strings.Repeat("k", maxKeyBytes), strings.Repeat("k", maxKeyBytes), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := KeyFromEnv(env(tt.value))
			if tt.err != (err != nil) || k.value != tt.want {
				t.Fatalf("KeyFromEnv = %q, %v", k.value, err)
			}
			if err != nil && (!errors.Is(err, ErrInvalidKey) || strings.Contains(err.Error(), "sk")) {
				t.Errorf("error %q quotes the value or has the wrong type", err)
			}
		})
	}
}

// Only CREEP_API_KEY is read, never a provider's variable.
func TestKeyFromEnvReadsOnlyItsVariable(t *testing.T) {
	var asked []string
	_, _ = KeyFromEnv(func(name string) string { asked = append(asked, name); return "" })
	if len(asked) != 1 || asked[0] != KeyEnv {
		t.Errorf("read %v, want only %s", asked, KeyEnv)
	}
}

// A key printed or encoded by mistake, alone or inside Options, never shows.
func TestKeyNeverPrints(t *testing.T) {
	k, err := KeyFromEnv(env(fakeKey))
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Contract: "anthropic", Endpoint: "https://api.example", Key: k}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		out = append(out, fmt.Sprintf(verb, k), fmt.Sprintf(verb, opts), fmt.Sprintf(verb, &opts))
	}
	out = append(out, k.String(), fmt.Sprint(k), fmt.Sprintln(k))
	j, err := json.Marshal(struct{ Key Key }{k})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(j))
	for _, s := range out {
		if strings.Contains(s, fakeKey) || strings.Contains(s, fmt.Sprintf("%x", fakeKey)) {
			t.Errorf("key leaked: %s", s)
		}
	}
}
