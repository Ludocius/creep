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
		{"incomplete", Incomplete, 4},
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
		"4  incomplete run",
	}
	for _, want := range tests {
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(help, want) {
				t.Errorf("Help() missing %q:\n%s", want, help)
			}
		})
	}
}

func TestForReportNeverCleanWhenIncomplete(t *testing.T) {
	tests := []struct {
		name              string
		incomplete, gated bool
		want              int
	}{
		{"clean", false, false, OK},
		{"gated", false, true, GateExceeded},
		{"incomplete", true, false, Incomplete},
		{"incomplete and gated", true, true, Incomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ForReport(tt.incomplete, tt.gated); got != tt.want {
				t.Errorf("ForReport(%v, %v) = %d, want %d", tt.incomplete, tt.gated, got, tt.want)
			}
		})
	}
}
