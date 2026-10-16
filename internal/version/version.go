// Package version holds build metadata injected at link time and recovered from
// the module build info when it is not injected.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is overridden via -ldflags at build time (see Makefile). It is the
// value reported by "make build" / GoReleaser, i.e. the release tag. The
// built-in default is the current OmenHound release line, so a plain
// "go build" reports the real product version instead of a git pseudo-version.
var Version = "4.1.01-omenhound"

// String returns the best available version string. Precedence:
//
//  1. Version, when injected via -ldflags (make build, GoReleaser, distro builds).
//  2. The main module version from the build info, which "go install
//     github.com/krazybeastx1/omenhound/cmd/omenhound@v1.2.3" bakes in.
//  3. A "dev+<rev>" string derived from the embedded VCS revision for plain
//     "go build" runs inside a git checkout.
//
// It never returns an empty string.
func String() string {
	if v := strings.TrimSpace(Version); v != "" && v != "dev" {
		return v
	}
	if v := buildInfoVersion(); v != "" {
		return v
	}
	return "dev"
}

func buildInfoVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if v := strings.TrimSpace(info.Main.Version); v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return ""
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	out := "dev+" + rev
	if dirty {
		out += ".dirty"
	}
	return out
}
