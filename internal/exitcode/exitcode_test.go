package exitcode

import (
	"strings"
	"testing"
)

func TestValues(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"ok", OK, 0},
		{"gate exceeded", GateExceeded, 1},
		{"config error", ConfigError, 2},
		{"model or sandbox", ModelOrSandbox, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestHelpListsEveryCode(t *testing.T) {
	help := Help()
	tests := []string{
		"0  nothing blocking",
		"1  gate exceeded",
		"2  usage or configuration error",
		"3  model or sandbox error",
	}
	for _, want := range tests {
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(help, want) {
				t.Errorf("Help() missing %q:\n%s", want, help)
			}
		})
	}
}
