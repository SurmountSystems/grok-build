#!/usr/bin/env bash
# Compatibility wrapper — use put-history-on-xai.sh (same behavior).
#
# Direction: Surmount history → stacked on xai-org tip (onto-xai/*).
# Opposite:  import-upstream-export.sh (xAI tree → Surmount import/*).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "note: scripts/replay-onto-upstream.sh → scripts/put-history-on-xai.sh" >&2
exec "$ROOT/scripts/put-history-on-xai.sh" "$@"
