#!/usr/bin/env bash
# Put Surmount commits ON TOP OF the current xAI export tip — for real.
#
# Does a real `git cherry-pick` chain onto xai-org/main (or given tip).
# Conflicts stop the script for you to resolve, then:
#   git add … && git cherry-pick --continue
#   # re-run this script with CONTINUE=1  OR finish remaining picks manually
#
# This is NOT commit-tree theater (same trees, fake parents). Parents are the
# xAI tip. Trees are 3-way merges of each Surmount commit onto that base.
#
# Does NOT push. Does NOT rewrite Surmount main/merge-2. Does NOT touch xai-org.
#
# Usage:
#   ./scripts/put-history-on-xai.sh              # stack current branch on xAI tip
#   ./scripts/put-history-on-xai.sh <xai-tip>
#   SURMOUNT_REF=merge-2 ./scripts/put-history-on-xai.sh
#   CONTINUE=1 ./scripts/put-history-on-xai.sh   # after resolving a conflict
#
# Env:
#   SURMOUNT_REF   tip to take commits from (default: current branch / HEAD)
#   SEED_REF       exclusive lower bound (default: seed from import log / b189869)
#   KEEP_EXISTING=1  refuse if onto-xai/* already exists
#   ALLOW_DIRTY=1    allow dirty worktree
#   FIRST_PARENT=1   only first-parent commits (default 0 = no-merges linear list)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if git remote get-url xai-org >/dev/null 2>&1; then
  UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-xai-org}"
elif git remote get-url upstream >/dev/null 2>&1; then
  UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
else
  echo "error: add remote xai-org or upstream first" >&2
  exit 1
fi

UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
SURMOUNT_REF="${SURMOUNT_REF:-}"
SEED_REF="${SEED_REF:-}"
IMPORT_LOG="${IMPORT_LOG:-docs/upstream-import-log.md}"
FIRST_PARENT="${FIRST_PARENT:-0}"
CONTINUE="${CONTINUE:-0}"

ORIGINAL_BRANCH="$(git branch --show-current || true)"
ORIGINAL_HEAD="$(git rev-parse HEAD)"

if [[ -n "$(git status --porcelain)" ]] && [[ "$CONTINUE" != "1" ]]; then
  # Mid cherry-pick is expected when CONTINUE=1
  if [[ -d .git/sequencer ]] || [[ -f .git/CHERRY_PICK_HEAD ]]; then
    echo "error: cherry-pick in progress. Resolve conflicts, then:" >&2
    echo "  git add -u && git cherry-pick --continue" >&2
    echo "  CONTINUE=1 $0" >&2
    exit 1
  fi
  if [[ "${ALLOW_DIRTY:-}" == "1" ]]; then
    echo "WARN: dirty worktree allowed via ALLOW_DIRTY=1" >&2
  else
    echo "error: working tree is dirty. Commit/stash first (or ALLOW_DIRTY=1)." >&2
    git status --porcelain | head -40 >&2
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
XAI_SHORT=$(git rev-parse --short=12 "$XAI_TIP")
BRANCH="onto-xai/$XAI_SHORT"

# Resolve Surmount tip
if [[ -z "$SURMOUNT_REF" ]]; then
  if [[ -n "$ORIGINAL_BRANCH" && "$ORIGINAL_BRANCH" != onto-xai/* && "$ORIGINAL_BRANCH" != import/* ]]; then
    SURMOUNT_REF="$ORIGINAL_HEAD"
    SURMOUNT_LABEL="$ORIGINAL_BRANCH"
  elif git show-ref --verify --quiet refs/remotes/origin/main; then
    SURMOUNT_REF=origin/main
    SURMOUNT_LABEL=origin/main
  else
    SURMOUNT_REF=main
    SURMOUNT_LABEL=main
  fi
else
  SURMOUNT_LABEL="$SURMOUNT_REF"
fi
SURMOUNT_REF=$(git rev-parse --verify "$SURMOUNT_REF")
SURMOUNT_SHORT=$(git rev-parse --short=12 "$SURMOUNT_REF")

if [[ -z "$SEED_REF" ]]; then
  if [[ -f "$IMPORT_LOG" ]]; then
    SEED_REF=$(
      grep -E '^\| 20' "$IMPORT_LOG" | grep -i seed | head -1 \
        | grep -oE '`[0-9a-f]{40}`' | head -1 | tr -d '`' || true
    )
  fi
  if [[ -z "$SEED_REF" ]]; then
    SEED_REF=b189869b7755d2b482969acf6c92da3ecfeffd36
  fi
fi
SEED_REF=$(git rev-parse "$SEED_REF")

if ! git merge-base --is-ancestor "$SEED_REF" "$SURMOUNT_REF" 2>/dev/null; then
  echo "error: SEED_REF not ancestor of SURMOUNT_REF" >&2
  exit 1
fi

# Commit list: non-merge chronological (real patches). FIRST_PARENT=1 for merge-only spine.
if [[ "$FIRST_PARENT" == "1" ]]; then
  mapfile -t COMMITS < <(git rev-list --reverse --first-parent "$SEED_REF..$SURMOUNT_REF")
else
  mapfile -t COMMITS < <(git rev-list --reverse --no-merges "$SEED_REF..$SURMOUNT_REF")
fi

if [[ ${#COMMITS[@]} -eq 0 ]]; then
  echo "error: no commits to cherry-pick between $SEED_REF and $SURMOUNT_REF" >&2
  exit 1
fi

echo "=== REAL cherry-pick: Surmount → on top of xAI ==="
echo "Checkout was: ${ORIGINAL_BRANCH:-detached} ($ORIGINAL_HEAD)"
echo "xAI tip:      $XAI_TIP ($XAI_SHORT)"
echo "Stacking:     $SURMOUNT_LABEL @ $SURMOUNT_SHORT"
echo "Seed:         $SEED_REF"
echo "Commits:      ${#COMMITS[@]}"
echo "Branch:       $BRANCH"
echo

if [[ "$CONTINUE" == "1" ]]; then
  if [[ -f .git/CHERRY_PICK_HEAD ]]; then
    echo "error: still mid cherry-pick. Finish with: git cherry-pick --continue" >&2
    exit 1
  fi
  if ! git show-ref --verify --quiet "refs/heads/$BRANCH"; then
    echo "error: $BRANCH missing; cannot CONTINUE" >&2
    exit 1
  fi
  git checkout "$BRANCH"
  # Find first commit not yet an ancestor of HEAD by matching Surmount-Commit trailer or subject+patch-id is hard;
  # instead: pick any commit from list whose tree change isn't already applied — simpler: skip commits already in log by original sha trailer.
  done_list=$(git log --format=%B "$XAI_TIP..HEAD" | grep -E '^Surmount-Commit: ' | awk '{print $2}' || true)
  remaining=()
  for c in "${COMMITS[@]}"; do
    if echo "$done_list" | grep -qx "$c"; then
      echo "  skip already applied: $(git rev-parse --short "$c") $(git log -1 --format=%s "$c")"
      continue
    fi
    # also skip if commit subject already appears and we're continuing after partial
    remaining+=("$c")
  done
  COMMITS=("${remaining[@]}")
  if [[ ${#COMMITS[@]} -eq 0 ]]; then
    echo "Nothing left to cherry-pick. Done."
    git log --oneline "$XAI_TIP..HEAD"
    exit 0
  fi
  echo "Continuing with ${#COMMITS[@]} remaining commit(s)"
else
  if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
    if [[ "${KEEP_EXISTING:-}" == "1" ]]; then
      echo "error: $BRANCH exists (KEEP_EXISTING=1)" >&2
      exit 1
    fi
    echo "Replacing disposable $BRANCH ($(git rev-parse --short "$BRANCH"))"
    if [[ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)" == "$BRANCH" ]]; then
      git checkout --detach HEAD
    fi
    git branch -D "$BRANCH"
  fi
  git checkout -B "$BRANCH" "$XAI_TIP"
fi

pick_failed=0
for c in "${COMMITS[@]}"; do
  subj=$(git log -1 --format=%s "$c")
  short=$(git rev-parse --short "$c")
  echo ">>> cherry-pick $short $subj"
  if git cherry-pick -x "$c"; then
    # annotate with clear trailer if -x didn't (it adds cherry picked from)
    echo "    ok → $(git rev-parse --short HEAD)"
  else
    pick_failed=1
    echo
    echo "CONFLICT while cherry-picking $short ($subj)"
    echo "Resolve every conflict, then:"
    echo "  git add -u"
    echo "  git cherry-pick --continue"
    echo "  CONTINUE=1 $0"
    echo "Or abort: git cherry-pick --abort && git checkout ${ORIGINAL_BRANCH:-main}"
    echo
    echo "Unmerged:"
    git diff --name-only --diff-filter=U || true
    exit 2
  fi
done

echo
echo "=== Done (real stack) ==="
echo "Branch: $BRANCH"
echo "Tip:    $(git rev-parse HEAD)"
echo "xAI is ancestor: $(git merge-base --is-ancestor "$XAI_TIP" HEAD && echo yes || echo NO)"
echo "Commits on top of xAI:"
git log --oneline "$XAI_TIP..HEAD"
echo
echo "Diff vs xAI tip:"
git diff --stat "$XAI_TIP" HEAD | tail -20
echo
echo "Your previous branch $ORIGINAL_BRANCH was NOT modified."
echo "Inspect: git checkout $BRANCH"
echo "Return:  git checkout $ORIGINAL_BRANCH"
echo
echo "XAI_TIP=$XAI_TIP"
echo "ONTO_BRANCH=$BRANCH"
echo "ONTO_TIP=$(git rev-parse HEAD)"
echo "SURMOUNT_REF=$SURMOUNT_REF"
