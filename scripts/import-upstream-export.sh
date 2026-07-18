#!/usr/bin/env bash
# Create a review branch that imports a new xAI monorepo export as a normal
# Surmount commit (content import), without requiring shared git ancestry.
#
# Does NOT push. Does NOT update main. Does NOT touch your feature branch
# except to switch away temporarily (returns you when done unless --stay).
#
# Usage:
#   ./scripts/import-upstream-export.sh
#   ./scripts/import-upstream-export.sh <xai-tip-sha>
#   BASE_REF=origin/main ./scripts/import-upstream-export.sh
#   BASE_REF=feat/my-work ./scripts/import-upstream-export.sh   # only if you mean it
#
# Safety:
#   - Aborts if the worktree is dirty (uncommitted changes), unless ALLOW_DIRTY=1.
#   - Default base is origin/main (not HEAD), so in-flight feature branches are
#     not used as the import base by accident.
#   - Never uses `git add -A` after read-tree (that re-staged the old worktree
#     and produced a useless "only result symlink" commit).
#
# See docs/upstream-history.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STAY=0
if [[ "${1:-}" == "--stay" ]]; then
  STAY=1
  shift
fi

if git remote get-url xai-org >/dev/null 2>&1; then
  UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-xai-org}"
elif git remote get-url upstream >/dev/null 2>&1; then
  UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
else
  echo "error: add remote xai-org or upstream first" >&2
  exit 1
fi

UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
# Prefer published Surmount main — NOT the currently checked-out feature branch.
BASE_REF="${BASE_REF:-}"

ORIGINAL_BRANCH="$(git branch --show-current || true)"
ORIGINAL_HEAD="$(git rev-parse HEAD)"

# --- refuse dirty worktree (protects in-flight feature work) ---
if [[ -n "$(git status --porcelain)" ]]; then
  if [[ "${ALLOW_DIRTY:-}" == "1" ]]; then
    echo "WARN: dirty worktree allowed via ALLOW_DIRTY=1" >&2
  else
    echo "error: working tree is dirty. Commit, stash, or finish your feature branch first." >&2
    echo "  (This protects in-flight work like feat/rate-limit-*. Uncommitted changes" >&2
    echo "   would be left behind or confused by checkout.)" >&2
    echo "  git status --porcelain:" >&2
    git status --porcelain | head -40 >&2
    echo "  Override only if you know what you're doing: ALLOW_DIRTY=1 $0" >&2
    exit 1
  fi
fi

git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH" --force
git fetch origin main 2>/dev/null || true

if [[ $# -ge 1 ]]; then
  XAI_TIP=$(git rev-parse "$1")
else
  XAI_TIP=$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")
fi
XAI_TREE=$(git rev-parse "$XAI_TIP^{tree}")
XAI_SHORT=$(git rev-parse --short=12 "$XAI_TIP")

if [[ -z "$BASE_REF" ]]; then
  if git show-ref --verify --quiet refs/remotes/origin/main; then
    BASE_REF=origin/main
  elif git show-ref --verify --quiet refs/heads/main; then
    BASE_REF=main
  else
    echo "error: cannot find origin/main or main; set BASE_REF=" >&2
    exit 1
  fi
fi
BASE_REF=$(git rev-parse --verify "$BASE_REF")

# Warn if user is on a feature branch with commits not in base (likely in-flight).
if [[ -n "$ORIGINAL_BRANCH" ]] && [[ "$ORIGINAL_BRANCH" != "main" ]]; then
  ahead=$(git rev-list --count "${BASE_REF}..${ORIGINAL_HEAD}" 2>/dev/null || echo 0)
  if [[ "${ahead}" != "0" ]]; then
    echo "NOTE: you are on '$ORIGINAL_BRANCH' ($ahead commit(s) not in $BASE_REF)."
    echo "      Import will base on $BASE_REF only — your feature commits are NOT included."
    echo "      Typical order: merge feature → main (no rebase of published PRs), then import; or set"
    echo "      BASE_REF=$ORIGINAL_BRANCH if this import should sit on the feature tip."
    echo
  fi
fi

BRANCH="import/xai-export-$XAI_SHORT"
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  echo "error: branch $BRANCH already exists. Delete or rename it first:" >&2
  echo "  git branch -D $BRANCH" >&2
  exit 1
fi

echo "Original: $ORIGINAL_BRANCH ($ORIGINAL_HEAD)"
echo "Base:     $BASE_REF ($(git rev-parse --short "$BASE_REF"))"
echo "xAI tip:  $XAI_TIP ($XAI_SHORT)"
echo "xAI tree: $XAI_TREE"
echo "Branch:   $BRANCH"
echo

# Fork-only paths restored from BASE after applying xAI tree.
FORK_PATHS=(
  FORK.md
  CONTRIBUTING.md
  SECURITY.md
  justfile
  flake.nix
  flake.lock
  docs/upstream-history.md
  docs/upstream-import-log.md
  packaging
  scripts/detect-upstream-export.sh
  scripts/import-upstream-export.sh
  scripts/sync-upstream.sh
  .github/workflows/upstream-export.yml
  crates/codegen/grok-rate-limit
)

git checkout -B "$BRANCH" "$BASE_REF"

echo "Applying xAI export tree to index + worktree (read-tree -u --reset) ..."
# -u updates worktree; --reset replaces index. Do NOT `git add -A` afterward
# (that re-stages the pre-reset worktree and undoes the import).
git read-tree -u --reset "$XAI_TREE"

echo "Restoring Surmount fork-only paths from base ..."
for p in "${FORK_PATHS[@]}"; do
  if git cat-file -e "$BASE_REF:$p" 2>/dev/null \
    || git ls-tree -d --name-only "$BASE_REF" "$p" 2>/dev/null | grep -q .; then
    if git checkout "$BASE_REF" -- "$p" 2>/dev/null; then
      echo "  keep fork path: $p"
    fi
  fi
done

# Drop nix result symlink if it appeared (never commit build artifacts).
if [[ -e result ]] || [[ -L result ]]; then
  git rm -f --ignore-unmatch result 2>/dev/null || rm -f result
  echo "  removed result (nix build symlink)"
fi

echo
echo "NOTE: OpenRouter / binary rename / sampler rate-limit seams live inside"
echo "xai-grok-* crates and were taken from the xAI tree. Reconcile against base:"
echo "  git diff $BASE_REF -- crates/codegen/xai-grok-shell/src/auth/openrouter.rs"
echo "  git diff $BASE_REF -- crates/codegen/xai-grok-pager-bin/"
echo "  git diff $BASE_REF -- crates/codegen/xai-grok-sampler/"
echo "  git diff $BASE_REF -- crates/codegen/grok-rate-limit/"
echo

# Index already matches intended tree (read-tree + checkout overlays).
if git diff --cached --quiet && git diff --quiet; then
  echo "Nothing to commit (tree already matches base+export composition)."
  echo "Returning to $ORIGINAL_BRANCH ..."
  if [[ -n "$ORIGINAL_BRANCH" ]]; then
    git checkout "$ORIGINAL_BRANCH"
  fi
  exit 0
fi

# Stage only what is already in the index from read-tree/checkout — refresh only.
git update-index --refresh >/dev/null 2>&1 || true
# Ensure deleted/modified tracked paths are staged without scooping ignored junk.
git add -u
# Re-add fork paths in case update-index dropped something
for p in "${FORK_PATHS[@]}"; do
  [[ -e $p || -d $p ]] && git add -f -- "$p" 2>/dev/null || true
done

MSG="Import xAI monorepo export $XAI_SHORT

Source: xai-org/grok-build $XAI_TIP
Tree:   $XAI_TREE

Content-only import (orphan export has no merge-base with Surmount).
Fork-only paths restored from $BASE_REF where present.
Review: docs/upstream-history.md checklist; then append docs/upstream-import-log.md.
"

# User signs — do not force gpgsign false unless commit fails for other reasons.
if ! git commit -m "$MSG"; then
  echo "commit failed (signing?). Retry with: git -c commit.gpgsign=false commit ..." >&2
  echo "You are on $BRANCH with a staged import; original branch was $ORIGINAL_BRANCH" >&2
  exit 1
fi

NEW_SHA=$(git rev-parse HEAD)
echo
echo "Created commit $(git rev-parse --short "$NEW_SHA") on $BRANCH"
echo "  vs base:  git diff --stat $BASE_REF $NEW_SHA"
echo "  vs xAI:   git diff --stat $XAI_TREE $NEW_SHA^{tree}   # fork-only delta"
echo
echo "=== Review checklist ==="
echo "1. git diff $BASE_REF --stat"
echo "2. Re-apply / fix OpenRouter, grok-oss binary, grok-rate-limit if clobbered"
echo "3. just ci  (or cargo check -p xai-grok-pager-bin)"
echo "4. Append docs/upstream-import-log.md"
echo "5. Sign if needed: git commit --amend -S --no-edit"
echo "6. PR $BRANCH -> main  (do not force-push main to xAI)"
echo
echo "XAI_TIP=$XAI_TIP"
echo "XAI_TREE=$XAI_TREE"
echo "IMPORT_BRANCH=$BRANCH"
echo "BASE_REF=$BASE_REF"

if [[ "$STAY" -eq 0 && -n "$ORIGINAL_BRANCH" && "$ORIGINAL_BRANCH" != "$BRANCH" ]]; then
  echo
  echo "Returning to your previous branch: $ORIGINAL_BRANCH"
  echo "(import branch left in place: $BRANCH; use --stay to remain on it)"
  git checkout "$ORIGINAL_BRANCH"
fi
