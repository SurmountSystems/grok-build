#!/usr/bin/env bash
# Merge xai-org/grok-build into the current branch (usually main).
# See FORK.md for policy. Prefer merge over rebase for main.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/xai-org/grok-build.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"

if ! git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
  echo "Adding remote '$UPSTREAM_REMOTE' -> $UPSTREAM_URL"
  git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

echo "Fetching $UPSTREAM_REMOTE/$UPSTREAM_BRANCH ..."
git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH"

CURRENT="$(git branch --show-current)"
echo "Merging $UPSTREAM_REMOTE/$UPSTREAM_BRANCH into $CURRENT ..."
git merge "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" --no-edit \
  -m "Merge upstream $UPSTREAM_REMOTE/$UPSTREAM_BRANCH into $CURRENT"

echo "Done. Resolve any conflicts (often FORK branding files), then push."
echo "Update FORK.md divergences checklist if you keep new fork-only changes."
