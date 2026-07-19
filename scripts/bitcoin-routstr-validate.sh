#!/usr/bin/env bash
# Validate Bitcoin-native Routstr + wallet foundations.
# Exit non-zero on any failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> cargo test -p grok-bitcoin-wallet"
cargo test -p grok-bitcoin-wallet --lib

echo "==> cargo test -p xai-grok-shell --lib routstr"
cargo test -p xai-grok-shell --lib routstr

echo "==> cargo test -p xai-grok-shell --lib openrouter (regression)"
cargo test -p xai-grok-shell --lib openrouter

echo "==> cargo fmt check (touched packages)"
cargo fmt -p grok-bitcoin-wallet -p xai-grok-shell -p xai-grok-sampling-types -p xai-grok-pager -- --check

echo "==> banned wording 'crypto' in Rust user-facing strings (new surfaces)"
# Scan production .rs (exclude #[cfg(test)] modules via path heuristics where easy).
# Docs/SECURITY and unit-test assertions that *guard* the ban are allowed.
FAIL=0
# Only flag non-test, non-doc-comment string literals that look user-facing.
# Heuristic: lines with .contains("crypto") in tests, or //! "crypto" ban notes, are OK.
mapfile -t hits < <(rg -n --ignore-case \
  -e '"[^"]*\bcrypto\b[^"]*"' \
  -e '"[^"]*cryptocurrency[^"]*"' \
  -e '"[^"]*\bWeb3\b[^"]*"' \
  crates/codegen/grok-bitcoin-wallet/src \
  crates/codegen/xai-grok-shell/src/auth/routstr.rs \
  2>/dev/null \
  | rg -v 'never|"crypto"\.|//\!|///|assert!|contains\("crypto"\)|ban|Ban|Language|must not say' \
  || true)
# Also scan routstr catalog description / name fields in config (description strings).
mapfile -t hits2 < <(rg -n --ignore-case \
  'name: Some\(|description: Some\(' -A 3 \
  crates/codegen/xai-grok-shell/src/agent/config.rs 2>/dev/null \
  | rg -i 'crypto|cryptocurrency|Web3' \
  | rg -v 'must not say|contains\("crypto"\)' \
  || true)

all_hits=$(printf '%s\n' "${hits[@]:-}" "${hits2[@]:-}" | sed '/^$/d' || true)
if [[ -n "${all_hits}" ]]; then
  echo "FAIL: banned wording in string literals:"
  echo "$all_hits"
  FAIL=1
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "Banned wording check failed."
  exit 1
fi
echo "Banned wording check OK."

echo "==> all bitcoin-routstr validation checks passed"
