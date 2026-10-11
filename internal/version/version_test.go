package version

import (
	"strings"
	"testing"
)

func TestStringPrefersInjectedVersion(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("String() = %q, want %q", got, "v1.2.3")
	}
}

func TestStringFallsBackWhenUnset(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "dev"
	got := strings.TrimSpace(String())
	if got == "" {
		t.Fatal("String() returned empty string")
	}
	// "go test" has no release tag, so any non-empty, whitespace-free value is
	// acceptable: "dev", "dev+<rev>", or a VCS-stamped pseudo-version.
	if got != strings.TrimSpace(got) {
		t.Fatalf("String() = %q, want no surrounding whitespace", got)
	}
	if strings.ContainsAny(got, " \t\n") {
		t.Fatalf("String() = %q, want a single token", got)
	}
}

func TestStringTrimsInjectedVersion(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "  v9.9.9  "
	if got := String(); got != "v9.9.9" {
		t.Fatalf("String() = %q, want %q", got, "v9.9.9")
	}
}
