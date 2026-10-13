#!/usr/bin/env bash
# Rebuild the v0.4.0-style release assets from the current tree, mirroring the
# GoReleaser layout (projectName_Version_os_arch + checksums.txt). Uses the
# staged cross-compiled binaries in dist/stage and adds README/LICENSE/NOTICE.
#
# Usage: scripts/build_release_assets.sh <version>   e.g. v0.4.0
set -euo pipefail

V="${1:-v0.4.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$ROOT/dist/stage"
OUT="$ROOT/dist/release"
mkdir -p "$OUT"

pkg() { # pkg <os> <arch> <format> <binary>
  local os="$1" arch="$2" fmt="$3" bin="$4"
  local name="omenhound_${V#v}_${os}_${arch}.${fmt}"
  local dir="$OUT/work-${os}-${arch}"
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$STAGE/$bin" "$dir/omenhound"
  cp "$ROOT/README.md" "$ROOT/LICENSE" "$ROOT/NOTICE" "$dir/"
  if [ "$fmt" = "tar.gz" ]; then
    tar -C "$dir" -czf "$OUT/$name" omenhound README.md LICENSE NOTICE
  else
    (cd "$dir" && zip -qr "$OUT/$name" omenhound README.md LICENSE NOTICE)
  fi
  rm -rf "$dir"
  echo "packed $OUT/$name"
}

pkg linux   amd64 tar.gz omenhound-linux-amd64
pkg linux   arm64 tar.gz omenhound-linux-arm64
pkg darwin  amd64 tar.gz omenhound-darwin-amd64
pkg darwin  arm64 tar.gz omenhound-darwin-arm64
pkg windows amd64 zip    omenhound-windows-amd64.exe
pkg windows arm64 zip    omenhound-windows-arm64.exe

(cd "$OUT" && sha256sum omenhound_*.tar.gz omenhound_*.zip > checksums.txt)
echo "wrote $OUT/checksums.txt"