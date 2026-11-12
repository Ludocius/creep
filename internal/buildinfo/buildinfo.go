package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Set at link time:
//
//	-ldflags "-X github.com/Ludocius/creep/internal/buildinfo.version=v0.1.0
//	          -X github.com/Ludocius/creep/internal/buildinfo.commit=abc1234"
var (
	version string
	commit  string
)

const unknown = "unknown"

// Info identifies a build.
type Info struct {
	Version   string
	Commit    string
	GoVersion string
}

// Get returns the build info of the running binary.
func Get() Info {
	return resolve(version, commit, debug.ReadBuildInfo)
}

// resolve prefers link-time values and falls back to embedded build info.
func resolve(ldVersion, ldCommit string, read func() (*debug.BuildInfo, bool)) Info {
	info := Info{Version: ldVersion, Commit: ldCommit, GoVersion: runtime.Version()}
	bi, ok := read()
	if ok && bi != nil {
		fillFromBuildInfo(&info, bi)
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = unknown
	}
	return info
}

func fillFromBuildInfo(info *Info, bi *debug.BuildInfo) {
	if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = bi.Main.Version
	}
	if bi.GoVersion != "" {
		info.GoVersion = bi.GoVersion
	}
	if info.Commit != "" {
		return
	}
	info.Commit = vcsCommit(bi.Settings)
}

func vcsCommit(settings []debug.BuildSetting) string {
	var revision, modified string
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return ""
	}
	if modified == "true" {
		return revision + "-dirty"
	}
	return revision
}
