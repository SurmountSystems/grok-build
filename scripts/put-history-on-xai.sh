#!/usr/bin/env bash
# Put Surmount commit history ON TOP OF the current xAI export tip.
#
# THIS IS THE DIRECTION YOU WANT when GitHub says "entirely different commit
# histories" and you still want our work parented at their tip:
#
#   xai-org/main  ──►  onto-xai/<short>  (our commits stacked here)
#
# After they force-push a new orphan export, re-run this script (onto-xai/*
# branches are disposable and replaced by default).
# Surmount main is never rewritten. xai-org is never pushed to.
#
# Contrast (opposite direction — do NOT use for "history on theirs"):
#   ./scripts/import-upstream-export.sh
#     → absorbs *their tree into Surmount* as a content-import commit
#
# Modes:
#   history (default)  Stack Surmount first-parent commits on the xAI tip via
#                      commit-tree (same trees/messages; no cherry-pick).
#                      Final tree matches SURMOUNT_REF.
#   overlay            One commit on the xAI tip: their tree + our product seams
#                      (PR-shaped contribution to xAI).
#   both               history, then optional overlay tip if trees differ.
#
# Surmount tip (what gets stacked) — default is YOUR CURRENT BRANCH:
#   SURMOUNT_REF unset + on merge-2 / feat/…  →  that branch tip (HEAD)
#   SURMOUNT_REF unset + detached / onto-xai  →  origin/main
#   SURMOUNT_REF=origin/main                  →  published main only
#
# Usage:
#   ./scripts/put-history-on-xai.sh              # stack current branch on xAI tip
#   ./scripts/put-history-on-xai.sh <xai-tip>
#   SURMOUNT_REF=origin/main ./scripts/put-history-on-xai.sh
#   MODE=overlay ./scripts/put-history-on-xai.sh
#   KEEP_EXISTING=1 ./scripts/put-history-on-xai.sh
#   ./scripts/put-history-on-xai.sh --stay
#
# See docs/upstream-history.md § "Onto-xAI replay".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STAY=0
if [[ "${1:-}" == "--stay" ]]; then
  STAY=1
  shift
fi

MODE="${MODE:-history}" # history | overlay | both
case "$MODE" in
  history|overlay|both) ;;
  *)
    echo "error: MODE must be history|overlay|both (got $MODE)" >&2
    exit 1
    ;;
esac

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
SURMOUNT_LABEL=""
SEED_REF="${SEED_REF:-}"
IMPORT_LOG="${IMPORT_LOG:-docs/upstream-import-log.md}"
ONTO_LOG="${ONTO_LOG:-docs/upstream-onto-log.md}"

ORIGINAL_BRANCH="$(git branch --show-current || true)"
ORIGINAL_HEAD="$(git rev-parse HEAD)"

if [[ -n "$(git status --porcelain)" ]]; then
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
XAI_TREE=$(git rev-parse "$XAI_TIP^{tree}")
XAI_SHORT=$(git rev-parse --short=12 "$XAI_TIP")

# Resolve which Surmount tip to stack. Prefer the branch you are on so in-flight
# work (merge-2, feat/*, …) is included — not only origin/main.
if [[ -z "$SURMOUNT_REF" ]]; then
  use_head=0
  if [[ -n "$ORIGINAL_BRANCH" ]]; then
    case "$ORIGINAL_BRANCH" in
      onto-xai/*|import/*)
        echo "NOTE: on disposable branch '$ORIGINAL_BRANCH' — stacking origin/main instead of HEAD."
        ;;
      *)
        use_head=1
        ;;
    esac
  fi
  if [[ "$use_head" -eq 1 ]]; then
    SURMOUNT_REF="$ORIGINAL_HEAD"
    SURMOUNT_LABEL="$ORIGINAL_BRANCH"
  elif git show-ref --verify --quiet refs/remotes/origin/main; then
    SURMOUNT_REF=origin/main
    SURMOUNT_LABEL=origin/main
  elif git show-ref --verify --quiet refs/heads/main; then
    SURMOUNT_REF=main
    SURMOUNT_LABEL=main
  else
    echo "error: cannot resolve Surmount tip; set SURMOUNT_REF=" >&2
    exit 1
  fi
else
  SURMOUNT_LABEL="$SURMOUNT_REF"
fi
SURMOUNT_REF=$(git rev-parse --verify "$SURMOUNT_REF")
SURMOUNT_SHORT=$(git rev-parse --short=12 "$SURMOUNT_REF")
SURMOUNT_TREE=$(git rev-parse "$SURMOUNT_REF^{tree}")
if [[ -z "$SURMOUNT_LABEL" ]]; then
  SURMOUNT_LABEL="$SURMOUNT_SHORT"
fi

# Seed = first Surmount root / last shared export pin (from log or b189869).
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
if ! git cat-file -e "$SEED_REF^{commit}" 2>/dev/null; then
  echo "error: SEED_REF $SEED_REF not a local commit (fetch origin / seed)" >&2
  exit 1
fi
SEED_REF=$(git rev-parse "$SEED_REF")

if ! git merge-base --is-ancestor "$SEED_REF" "$SURMOUNT_REF" 2>/dev/null; then
  echo "error: SEED_REF ($SEED_REF) is not an ancestor of SURMOUNT_REF ($SURMOUNT_REF)" >&2
  exit 1
fi

BRANCH="onto-xai/$XAI_SHORT"
# onto-xai/* is disposable: default is rebuild in place. Set KEEP_EXISTING=1 to refuse.
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  if [[ "${KEEP_EXISTING:-}" == "1" ]]; then
    echo "error: branch $BRANCH already exists (KEEP_EXISTING=1)." >&2
    echo "  git branch -D $BRANCH   # or unset KEEP_EXISTING" >&2
    exit 1
  fi
  old=$(git rev-parse --short "$BRANCH")
  echo "Replacing existing $BRANCH ($old) — onto-xai/* is disposable"
  if [[ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)" == "$BRANCH" ]]; then
    git checkout --detach HEAD
  fi
  git branch -D "$BRANCH"
fi

# Paths that always come from Surmount when building an overlay contribution.
FORK_PATHS=(
  FORK.md
  CONTRIBUTING.md
  SECURITY.md
  justfile
  flake.nix
  flake.lock
  docs/upstream-history.md
  docs/upstream-import-log.md
  docs/upstream-onto-log.md
  docs/git-workflow.md
  packaging
  scripts/detect-upstream-export.sh
  scripts/import-upstream-export.sh
  scripts/sync-upstream.sh
  scripts/put-history-on-xai.sh
  scripts/replay-onto-upstream.sh
  .github/workflows/upstream-export.yml
  crates/codegen/grok-rate-limit
)

# Product seams that live inside xai-grok-* (import may clobber; overlay restores).
PRODUCT_SEAMS=(
  crates/codegen/xai-grok-shell/src/auth/openrouter.rs
  crates/codegen/xai-grok-shell/src/auth/credentials_store.rs
  crates/codegen/xai-grok-shell/src/auth/harness_secrets.rs
  crates/codegen/xai-grok-shell/src/auth/mod.rs
  crates/codegen/xai-grok-shell/src/agent/config.rs
  crates/codegen/xai-grok-shell/tests/openrouter_credentials.rs
  crates/codegen/xai-grok-shell/tests/openrouter_attribution.rs
  crates/codegen/xai-grok-shell/CHANGELOG.md
  crates/codegen/xai-grok-shell/README.md
  crates/codegen/xai-grok-shell/Cargo.toml
  crates/codegen/xai-grok-pager-bin
  crates/codegen/xai-grok-pager/src/app/cli.rs
  crates/codegen/xai-grok-sampler/src/request_task.rs
  Cargo.toml
  Cargo.lock
)

echo "=== Put Surmount history ON xAI tip (not import-into-Surmount) ==="
echo "Checkout:     ${ORIGINAL_BRANCH:-detached} ($ORIGINAL_HEAD)"
echo "xAI tip:      $XAI_TIP ($XAI_SHORT)"
echo "xAI tree:     $XAI_TREE"
echo "Stacking:     $SURMOUNT_LABEL @ $SURMOUNT_SHORT  (tree $SURMOUNT_TREE)"
echo "              full: $SURMOUNT_REF"
echo "Seed:         $SEED_REF"
echo "Mode:         $MODE"
echo "Branch:       $BRANCH"
echo
if git show-ref --verify --quiet refs/remotes/origin/main; then
  ahead=$(git rev-list --count "origin/main..$SURMOUNT_REF" 2>/dev/null || echo 0)
  if [[ "${ahead}" != "0" ]]; then
    echo "NOTE: stacking tip is $ahead commit(s) ahead of origin/main (includes local/branch work)."
    echo
  fi
fi

# --- helpers -----------------------------------------------------------------

commit_with_meta() {
  # Args: tree parent_sha subject_file body_extra
  # Uses original author when SURMOUNT_COMMIT is set in env.
  local tree="$1"
  local parent="$2"
  local msgfile="$3"
  local env_args=()
  if [[ -n "${SRC_COMMIT:-}" ]]; then
    local an ae ad cn ce cd
    an=$(git log -1 --format=%an "$SRC_COMMIT")
    ae=$(git log -1 --format=%ae "$SRC_COMMIT")
    ad=$(git log -1 --format=%ad --date=raw "$SRC_COMMIT")
    cn=$(git log -1 --format=%cn "$SRC_COMMIT")
    ce=$(git log -1 --format=%ce "$SRC_COMMIT")
    cd=$(git log -1 --format=%cd --date=raw "$SRC_COMMIT")
    env_args=(
      -c "user.name=$cn" -c "user.email=$ce"
    )
    # commit-tree reads GIT_* env for author/committer.
    GIT_AUTHOR_NAME="$an" \
      GIT_AUTHOR_EMAIL="$ae" \
      GIT_AUTHOR_DATE="$ad" \
      GIT_COMMITTER_NAME="${GIT_COMMITTER_NAME:-$cn}" \
      GIT_COMMITTER_EMAIL="${GIT_COMMITTER_EMAIL:-$ce}" \
      GIT_COMMITTER_DATE="${GIT_COMMITTER_DATE:-$cd}" \
      git "${env_args[@]}" commit-tree "$tree" -p "$parent" -F "$msgfile"
  else
    git commit-tree "$tree" -p "$parent" -F "$msgfile"
  fi
}

write_replay_msg() {
  local src="$1"
  local outfile="$2"
  {
    git log -1 --format=%B "$src" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
    echo
    echo "Surmount-Commit: $src"
    echo "Replayed-onto: $XAI_TIP"
    echo "Replay-Mode: history"
  } >"$outfile"
}

build_overlay_tree() {
  # Working-tree free: index = xAI tree, then overlay Surmount fork/product paths.
  local tmp_index
  tmp_index=$(mktemp "${TMPDIR:-/tmp}/onto-overlay-index.XXXXXX")
  rm -f "$tmp_index"
  export GIT_INDEX_FILE="$tmp_index"
  git read-tree "$XAI_TREE"

  local p
  for p in "${FORK_PATHS[@]}" "${PRODUCT_SEAMS[@]}"; do
    _stage_path_from_ref "$SURMOUNT_REF" "$p" || true
  done

  # New paths Surmount introduced since seed (fork crates, packaging, scripts, …).
  if [[ "${OVERLAY_INCLUDE_ADDED:-1}" == "1" ]]; then
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      _stage_path_from_ref "$SURMOUNT_REF" "$p" || true
    done < <(git diff --name-only --diff-filter=A "$SEED_REF" "$SURMOUNT_REF" || true)
  fi

  local tree
  tree=$(git write-tree)
  unset GIT_INDEX_FILE
  rm -f "$tmp_index"
  printf '%s\n' "$tree"
}

_stage_path_from_ref() {
  local ref="$1"
  local p="$2"
  # Directory in ref: replace all index blobs under that path.
  if [[ -n "$(git ls-tree -d "$ref" "$p" 2>/dev/null)" ]]; then
    git rm -r --cached -q --ignore-unmatch -- "$p" 2>/dev/null || true
    local meta relpath mode type sha
    while IFS=$'\t' read -r meta relpath; do
      [[ -z "${relpath:-}" ]] && continue
      mode=$(awk '{print $1}' <<<"$meta")
      type=$(awk '{print $2}' <<<"$meta")
      sha=$(awk '{print $3}' <<<"$meta")
      [[ "$type" == "blob" ]] || continue
      git update-index --add --cacheinfo "$mode,$sha,$relpath"
    done < <(git ls-tree -r "$ref" -- "$p")
    return 0
  fi
  # Single blob.
  if git cat-file -e "$ref:$p" 2>/dev/null; then
    local mode sha
    mode=$(git ls-tree "$ref" -- "$p" | awk '{print $1}')
    sha=$(git ls-tree "$ref" -- "$p" | awk '{print $3}')
    [[ -n "$mode" && -n "$sha" ]] || return 1
    git update-index --add --cacheinfo "$mode,$sha,$p"
    return 0
  fi
  return 1
}

# --- history mode: commit-tree chain -----------------------------------------

history_tip=""
if [[ "$MODE" == "history" || "$MODE" == "both" ]]; then
  parent="$XAI_TIP"
  mapfile -t COMMITS < <(git rev-list --reverse --first-parent "$SEED_REF..$SURMOUNT_REF")
  if [[ ${#COMMITS[@]} -eq 0 ]]; then
    echo "WARN: no first-parent commits between seed and Surmount ref"
  fi
  echo "Replaying ${#COMMITS[@]} Surmount first-parent commit(s) via commit-tree ..."
  msgtmp=$(mktemp)
  for src in "${COMMITS[@]}"; do
    tree=$(git rev-parse "$src^{tree}")
    write_replay_msg "$src" "$msgtmp"
    SRC_COMMIT="$src"
    new=$(commit_with_meta "$tree" "$parent" "$msgtmp")
    unset SRC_COMMIT
    echo "  $(git rev-parse --short "$src") -> $(git rev-parse --short "$new")  $(git log -1 --format=%s "$src")"
    parent="$new"
  done
  rm -f "$msgtmp"
  history_tip="$parent"
  # Point branch at chain (no worktree checkout required yet).
  git branch "$BRANCH" "$history_tip"
  echo "History tip: $history_tip on $BRANCH"
fi

# --- overlay mode ------------------------------------------------------------

overlay_tree=""
if [[ "$MODE" == "overlay" || "$MODE" == "both" ]]; then
  echo "Building overlay tree (xAI base + Surmount fork/product paths) ..."
  overlay_tree=$(build_overlay_tree)
  echo "Overlay tree: $overlay_tree"

  if [[ "$MODE" == "overlay" ]]; then
    msgtmp=$(mktemp)
    cat >"$msgtmp" <<EOF
Surmount product overlay on xAI export $XAI_SHORT

Source export:  $XAI_TIP
Surmount tip:   $SURMOUNT_REF ($SURMOUNT_SHORT)
Overlay tree:   $overlay_tree

Composes the current xAI export tree with Surmount fork-only paths and
product seams (OpenRouter, branding, rate-limit, packaging, import tooling).
New paths introduced on Surmount since seed are included when
OVERLAY_INCLUDE_ADDED=1 (default).

This branch is for archaeology / optional contribution PRs. Surmount main
remains the canonical product history (see docs/upstream-history.md).
EOF
    new=$(git commit-tree "$overlay_tree" -p "$XAI_TIP" -F "$msgtmp")
    rm -f "$msgtmp"
    git branch "$BRANCH" "$new"
    history_tip="$new"
    echo "Overlay commit: $new on $BRANCH"
  elif [[ "$MODE" == "both" ]]; then
    # If history already produced Surmount's full tree, overlay may still differ
    # (history final tree == Surmount; overlay == xAI+seams). Append only when
    # user wants a PR-shaped tip: BOTH_APPEND_OVERLAY=1 (default 1).
    if [[ "${BOTH_APPEND_OVERLAY:-1}" == "1" ]]; then
      final_hist_tree=$(git rev-parse "$history_tip^{tree}")
      if [[ "$overlay_tree" != "$final_hist_tree" ]]; then
        msgtmp=$(mktemp)
        cat >"$msgtmp" <<EOF
Reconcile: xAI export $XAI_SHORT + Surmount seams

History tip tree was pure Surmount ($final_hist_tree).
This commit composes xAI export tree with Surmount fork/product overlay
($overlay_tree) for contribution-shaped review.

Surmount-Tip: $SURMOUNT_REF
XAI-Tip: $XAI_TIP
EOF
        new=$(git commit-tree "$overlay_tree" -p "$history_tip" -F "$msgtmp")
        rm -f "$msgtmp"
        git branch -f "$BRANCH" "$new"
        history_tip="$new"
        echo "Appended reconcile overlay: $new"
      else
        echo "Overlay tree matches history tip; no extra reconcile commit."
      fi
    fi
  fi
fi

if ! git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  echo "error: branch $BRANCH was not created" >&2
  exit 1
fi

TIP=$(git rev-parse "$BRANCH")
TIP_TREE=$(git rev-parse "$TIP^{tree}")
COUNT=$(git rev-list --count "$XAI_TIP..$TIP")

echo
echo "=== Result ==="
echo "Branch:     $BRANCH"
echo "Tip:        $TIP"
echo "Tip tree:   $TIP_TREE"
echo "Commits on top of xAI tip: $COUNT"
echo "  git log --oneline $XAI_TIP..$BRANCH"
echo "  git diff --stat $XAI_TIP $BRANCH"
echo "  git diff --stat $SURMOUNT_REF $BRANCH   # empty tree ⇒ pure Surmount product on their tip"
echo
echo "Push (optional, to Surmount remote only — never force xai-org):"
echo "  git push -u origin $BRANCH"
echo "Open compare / PR *to* xai-org only if you intend to contribute (they may ignore):"
echo "  gh pr create --repo xai-org/grok-build --base main --head SurmountSystems:$(echo "$BRANCH" | tr '/' '-')  # may need push head name"
echo
echo "Append $ONTO_LOG after review:"
echo "  | $(date -u +%Y-%m-%d) | \`$XAI_TIP\` | \`$XAI_TREE\` | \`$SURMOUNT_REF\` | \`$TIP\` | $MODE |"
echo
echo "After next xAI force-export, just re-run:"
echo "  ./scripts/put-history-on-xai.sh"
echo
echo "XAI_TIP=$XAI_TIP"
echo "XAI_TREE=$XAI_TREE"
echo "SURMOUNT_REF=$SURMOUNT_REF"
echo "ONTO_BRANCH=$BRANCH"
echo "ONTO_TIP=$TIP"
echo "MODE=$MODE"

# Materialize branch in worktree only if --stay (history used commit-tree only).
if [[ "$STAY" -eq 1 ]]; then
  echo
  echo "Checking out $BRANCH (--stay) ..."
  git checkout "$BRANCH"
else
  if [[ -n "$ORIGINAL_BRANCH" ]]; then
    # Ensure we did not leave the user on onto-xai by accident.
    current=$(git branch --show-current || true)
    if [[ "$current" == "$BRANCH" ]]; then
      git checkout "$ORIGINAL_BRANCH"
    fi
    echo "Left branch $BRANCH in place; still on ${ORIGINAL_BRANCH:-$ORIGINAL_HEAD}"
  fi
fi
