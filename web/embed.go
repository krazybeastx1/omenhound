// Package web embeds OmenHound's static web UI so the server ships as a single
// binary. The UI is intentionally dependency-free vanilla JS + Sigma.js from a
// CDN; a customized BloodHound CE frontend can replace web/static later.
package web

import "embed"

// FS holds the static assets served at "/".
//
//go:embed static
var FS embed.FS
