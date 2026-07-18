#!/usr/bin/env bash
# Detect a new xAI monorepo export (force-pushed orphan tip).
# Exit 0 = up to date with last import; 2 = new export available; 1 = error.
#
# Env:
#   UPSTREAM_REMOTE (default: xai-org or upstream)
#   UPSTREAM_URL
#   UPSTREAM_BRANCH (default: main)
#   IMPORT_LOG (default: docs/upstream-import-log.md)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMPORT_LOG="${IMPORT_LOG:-docs/upstream-import-log.md}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/xai-org/grok-build.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"

# Prefer remotes that already exist.
if git remote get-url xai-org >/dev/null 2>&1; then
  UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-xai-org}"
elif git remote get-url upstream >/dev/null 2>&1; then
  UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
else
  UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-xai-org}"
  echo "Adding remote '$UPSTREAM_REMOTE' -> $UPSTREAM_URL"
  git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

echo "Fetching $UPSTREAM_REMOTE/$UPSTREAM_BRANCH ..."
git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH" --force

TIP=$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")
TREE=$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH^{tree}")
PARENTS=$(git rev-list --parents -n1 "$TIP" | awk '{print NF-1}')

echo "xAI tip:    $TIP"
echo "xAI tree:   $TREE"
echo "parents:    $PARENTS (0 = orphan export root)"
echo "subject:    $(git log -1 --format=%s "$TIP")"
echo "author:     $(git log -1 --format='%an %ci' "$TIP")"

# Last imported tree from log (first 40-char hex tree after "seed" or import rows).
LAST_TREE=""
if [[ -f "$IMPORT_LOG" ]]; then
  # Rows look like: | date | `sha` | `tree` | ...
  LAST_TREE=$(
    grep -E '^\| [0-9]{4}-' "$IMPORT_LOG" \
      | grep -v 'pending' \
      | tail -1 \
      | sed -n 's/.*`\([0-9a-f]\{40\}\)`.*`\([0-9a-f]\{40\}\)`.*/\2/p' \
      || true
  )
  # Fallback: second code span on last completed row
  if [[ -z "$LAST_TREE" ]]; then
    LAST_TREE=$(
      grep -E '^\| 20' "$IMPORT_LOG" | grep -v pending | tail -1 \
        | grep -oE '`[0-9a-f]{40}`' | sed -n '2p' | tr -d '`' || true
    )
  fi
fi

if [[ -z "$LAST_TREE" ]]; then
  echo "WARN: no completed import tree in $IMPORT_LOG — treating as first pin needed"
  echo "NEW_EXPORT=1"
  echo "XAI_TIP=$TIP"
  echo "XAI_TREE=$TREE"
  exit 2
fi

echo "last imported tree: $LAST_TREE"

if [[ "$TREE" == "$LAST_TREE" ]]; then
  echo "OK: xAI export tree matches last import (no new export content)."
  echo "NEW_EXPORT=0"
  echo "XAI_TIP=$TIP"
  echo "XAI_TREE=$TREE"
  exit 0
fi

echo
echo "NEW EXPORT DETECTED (trees differ)."
echo "Content delta vs last import:"
# Diff by tree ids when possible
if git cat-file -e "$LAST_TREE^{tree}" 2>/dev/null; then
  git diff --stat "$LAST_TREE" "$TREE" | tail -20
else
  echo "(last tree not in local object store; fetch older export or rely on full tip diff)"
  git diff --stat "$TIP" 2>/dev/null | tail -5 || true
fi

echo
echo "Next: ./scripts/import-upstream-export.sh"
echo "NEW_EXPORT=1"
echo "XAI_TIP=$TIP"
echo "XAI_TREE=$TREE"
echo "LAST_TREE=$LAST_TREE"
exit 2
