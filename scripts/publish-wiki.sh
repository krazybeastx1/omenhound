#!/usr/bin/env bash
# Publish wiki/*.md (and img/) to the project's GitHub wiki.
#
# GitHub creates the wiki git repository only *after the first page exists*.
# If cloning fails with "Repository not found", open
#   https://github.com/krazybeastx1/omenhound/wiki
# in a browser, click "Create the first page", save anything, then re-run this.
set -euo pipefail

REPO="${OMENHOUND_REPO:-krazybeastx1/omenhound}"
SLUG="${REPO#*/}"
SRC="$(cd "$(dirname "$0")/.." && pwd)/wiki"
WIKI_URL="git@github.com:${REPO}.wiki.git"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> syncing $SRC -> $WIKI_URL"
if ! git clone --quiet "$WIKI_URL" "$WORK/wiki" 2>/dev/null; then
  cat >&2 <<EOF
!! Could not clone ${WIKI_URL}

   The wiki git repo does not exist yet. GitHub only creates it once the first
   page is created in the web UI (there is no API for this).

   1. open https://github.com/${REPO}/wiki
   2. click "Create the first page", put "Home" as the title, save
   3. re-run: $0
EOF
  exit 1
fi

cd "$WORK/wiki"
# Markdown pages at the root; images under img/.
find . -maxdepth 1 -name '*.md' -delete
for f in "$SRC"/*.md; do
  [ "$(basename "$f")" = "README.md" ] && continue   # maintainer notes, not a page
  cp -f "$f" .
done
rm -rf img
if [ -d "$SRC/img" ]; then
  mkdir -p img
  cp -f "$SRC"/img/*.png img/ 2>/dev/null || true
fi

git add -A
if git diff --cached --quiet; then
  echo "==> wiki already up to date"
  exit 0
fi
git -c user.email="krazybeastx1@users.noreply.github.com" -c user.name="krazybeastx1" \
  commit --quiet -m "docs(wiki): sync guides, schema reference and WebUI screenshots"
git push --quiet origin HEAD
echo "==> wiki published: https://github.com/${REPO}/wiki"
