// Package web embeds OmenHound's static web UI so the server ships as a single
// binary. The UI is intentionally dependency-free vanilla JS with a small
// canvas force-layout engine — no framework, bundler or CDN.
package web

import "embed"

// FS holds the static assets served at "/".
//
//go:embed static
var FS embed.FS
