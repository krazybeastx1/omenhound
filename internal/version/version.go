// Package version holds build metadata injected at link time.
package version

// Version is overridden via -ldflags at build time (see Makefile).
var Version = "dev"
