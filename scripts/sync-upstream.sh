#!/usr/bin/env bash
# Entry point for "get latest xAI open-source export into Grok OSS".
#
# xAI force-pushes orphan monorepo snapshots — a plain `git merge` is wrong.
# This script detects new content and points you at the import workflow.
# See docs/upstream-history.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== Grok OSS upstream sync (export-aware) ==="
echo "Policy: Surmount history is canonical; xAI tip is a content feed."
echo

set +e
./scripts/detect-upstream-export.sh
code=$?
set -e

case $code in
  0)
    echo
    echo "No new export content. Nothing to import."
    exit 0
    ;;
  2)
    echo
    echo "New export available."
    if [[ "${IMPORT_NOW:-}" == "1" ]]; then
      exec ./scripts/import-upstream-export.sh
    fi
    echo "Review the delta, then run:"
    echo "  ./scripts/import-upstream-export.sh"
    echo "Or auto-create a review branch:"
    echo "  IMPORT_NOW=1 ./scripts/sync-upstream.sh"
    exit 2
    ;;
  *)
    echo "detect-upstream-export failed (exit $code)" >&2
    exit "$code"
    ;;
esac
