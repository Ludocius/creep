package buildinfo

import (
	"runtime"
	"runtime/debug"
	"testing"
)

func TestResolve(t *testing.T) {
	embedded := &debug.BuildInfo{
		GoVersion: "go1.99.0",
		Main:      debug.Module{Version: "v0.2.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "deadbeef"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	dirty := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "cafe"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	tests := []struct {
		name      string
		ldVersion string
		ldCommit  string
		bi        *debug.BuildInfo
		want      Info
	}{
		{"ldflags win", "v0.1.0", "abc1234", embedded, Info{"v0.1.0", "abc1234", "go1.99.0"}},
		{"embedded fallback", "", "", embedded, Info{"v0.2.0", "deadbeef", "go1.99.0"}},
		{"devel and dirty", "", "", dirty, Info{"dev", "cafe-dirty", runtime.Version()}},
		{"no build info", "", "", nil, Info{"dev", "unknown", runtime.Version()}},
		{"partial ldflags", "v1.0.0", "", embedded, Info{"v1.0.0", "deadbeef", "go1.99.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := func() (*debug.BuildInfo, bool) { return tt.bi, tt.bi != nil }
			got := resolve(tt.ldVersion, tt.ldCommit, read)
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
