#!/usr/bin/env bash
# Detect a new xAI export and point at the right workflow.
#
# Two opposite directions (do not confuse them):
#
#   put-history-on-xai.sh   OUR commits on THEIR tip  → onto-xai/*   (what you want
#                           when histories keep breaking and you want a stack
#                           parented at xai-org/main)
#
#   import-upstream-export.sh  THEIR tree into OUR main → import/*  (absorb export
#                           as reviewed content on Surmount; main stays archive)
#
# See docs/upstream-history.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== Grok OSS upstream sync (export-aware) ==="
echo "Surmount main = canonical product archive."
echo "xai-org/main  = disposable export tip (force-pushed)."
echo
echo "Directions:"
echo "  ./scripts/put-history-on-xai.sh     # our history ON their tip (onto-xai/*)"
echo "  ./scripts/import-upstream-export.sh # their tree INTO Surmount (import/*)"
echo

set +e
./scripts/detect-upstream-export.sh
code=$?
set -e

case $code in
  0)
    echo
    echo "No new export content vs last import log."
    if [[ "${PUT_ON_XAI:-${REPLAY_ONTO:-}}" == "1" ]]; then
      exec ./scripts/put-history-on-xai.sh
    fi
    if [[ "${IMPORT_NOW:-}" == "1" ]]; then
      exec ./scripts/import-upstream-export.sh
    fi
    echo "Still useful anytime (rebuild stack on current tip):"
    echo "  ./scripts/put-history-on-xai.sh"
    echo "  MODE=overlay ./scripts/put-history-on-xai.sh"
    exit 0
    ;;
  2)
    echo
    echo "New export available."
    if [[ "${PUT_ON_XAI:-${REPLAY_ONTO:-}}" == "1" ]]; then
      exec ./scripts/put-history-on-xai.sh
    fi
    if [[ "${IMPORT_NOW:-}" == "1" ]]; then
      exec ./scripts/import-upstream-export.sh
    fi
    echo "Put Surmount history on their tip (rebuildable after force-export):"
    echo "  ./scripts/put-history-on-xai.sh"
    echo "  PUT_ON_XAI=1 ./scripts/sync-upstream.sh"
    echo
    echo "Absorb export into Surmount main (separate, reviewed content import):"
    echo "  ./scripts/import-upstream-export.sh"
    echo "  IMPORT_NOW=1 ./scripts/sync-upstream.sh"
    exit 2
    ;;
  *)
    echo "detect-upstream-export failed (exit $code)" >&2
    exit "$code"
    ;;
esac
