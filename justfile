# Grok OSS local recipes.
# GitHub Actions runs the same `just ci` entrypoint -- keep this file the source of truth.
# Requires: just, nix (with flakes). No bash scripts -- just recipes + nix.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Host system for flake check attributes (e.g. x86_64-linux).
# Prefer CI_SYSTEM on GHA so a transient `nix eval` at just parse time cannot
# kill attribute expansion for mem-guard checks. Local default: impure eval.
# GHA must set CI_SYSTEM (ci.yml does). Attribute sinks use `{{ system }}` only
# after `require_system` (dependency) has allowlisted the value -- the guard
# body reads CI_SYSTEM / nix eval from the environment and never interpolates
# `{{ system }}` into quotes (avoids single-quote breakout).
system := env_var_or_default("CI_SYSTEM", `nix eval --impure --raw --expr 'builtins.currentSystem'`)

# Nix flags when CI_LOW_MEM=1: cap cores/jobs for pure nix steps.
nix_low_mem_opts := if env_var_or_default("CI_LOW_MEM", "") == "1" { "--option cores 2 --option max-jobs 1" } else { "" }

# Free GHA (~4 vCPU / 16GB) sets CI_LOW_MEM=1.
low_mem := env_var_or_default("CI_LOW_MEM", "")

# ---------------------------------------------------------------------------
# Transient network resilience (free GHA flake-input / binary-cache flakes)
#
# NIX_CONFIG knobs -- keep in sync with .github/workflows/ci.yml job env:
#   download-attempts          -- retry individual downloads (default 5)
#   connect-timeout            -- TCP connect timeout seconds
#   stalled-download-timeout   -- abort hung transfers
#   http-connections           -- parallel HTTP fetches (lower = less flaky)
#
# nix_retry wraps whole `nix ...` invocations when per-download knobs are not
# enough (e.g. flake metadata 503 HTML). Backoff: 5s, 15s, 45s.
#
# IMPORTANT: retries EVERY non-zero exit (not network-classified). Permanent
# eval failures pay the full attempt budget + backoff. Cargo payloads are
# intentionally OUTSIDE nix_retry so permanent compile fails once.
# Local fail-fast: NIX_RETRY_ATTEMPTS=1 just mem-guard
# Override attempts: NIX_RETRY_ATTEMPTS=5 just mem-guard
#
# Security: +cmd is expanded as shell (trusted recipes only). Never pass
# untrusted user input as the nix_retry command string.
# ---------------------------------------------------------------------------
export NIX_CONFIG := '''
download-attempts = 5
connect-timeout = 30
stalled-download-timeout = 100
http-connections = 4
'''

# Fail fast if the host system string is not safe for shell/attr interpolation.
# Reads CI_SYSTEM or impure nix eval inside bash only -- never `{{ system }}`
# into this recipe (single-quote in CI_SYSTEM must not break assignment).
# Recipes that expand `{{ system }}` into nix attr paths depend on this first.
[private]
require_system:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "${CI_SYSTEM:-}" ]]; then
      sys="${CI_SYSTEM}"
    else
      sys="$(nix eval --impure --raw --expr 'builtins.currentSystem')"
    fi
    case "${sys}" in
      x86_64-linux|aarch64-linux|x86_64-darwin|aarch64-darwin) exit 0 ;;
    esac
    if [[ "${sys}" =~ ^[a-zA-Z0-9_]+-[a-zA-Z0-9_]+$ ]]; then
      exit 0
    fi
    echo "==> invalid CI_SYSTEM / system (refuse shell interpolation): ${sys}" >&2
    echo "    expected e.g. x86_64-linux or ^[a-zA-Z0-9_]+-[a-zA-Z0-9_]+$" >&2
    exit 2

# Retry a nix (or other) command. Integer-validates NIX_RETRY_ATTEMPTS (default 4).
# Prints a clear banner per attempt. Permanent failures fail after all attempts.
# Retries every non-zero exit (not network-classified); use only around store
# realization / flake eval, never around host cargo compile payloads.
[private]
nix_retry +cmd:
    #!/usr/bin/env bash
    set -euo pipefail
    raw_attempts="${NIX_RETRY_ATTEMPTS:-4}"
    if [[ ! "${raw_attempts}" =~ ^[1-9][0-9]*$ ]]; then
      echo "==> nix_retry: NIX_RETRY_ATTEMPTS must be a positive integer, got: ${raw_attempts}" >&2
      exit 2
    fi
    attempts="${raw_attempts}"
    backoff=5
    n=1
    while true; do
      echo "==> nix attempt ${n}/${attempts}: {{ cmd }}"
      set +e
      {{ cmd }}
      status=$?
      set -e
      if [[ "${status}" -eq 0 ]]; then
        exit 0
      fi
      if [[ "${n}" -ge "${attempts}" ]]; then
        echo "==> nix FAILED after ${n} attempt(s) (exit ${status}): {{ cmd }}" >&2
        exit "${status}"
      fi
      echo "==> nix attempt ${n} failed (exit ${status}); retrying in ${backoff}s..." >&2
      sleep "${backoff}"
      backoff=$((backoff * 3))
      n=$((n + 1))
    done

default:
    @just --list

# ---------------------------------------------------------------------------
# CI vs release vs local quality
#
# CI never builds a release package (`nix build .#grok-oss`). That is optional
# packaging for humans (`just build` / `just smoke` / `just install-nix`).
#
# GHA (see .github/workflows/ci.yml): single `quality` job → just ci-prep && just test.
#
# `just test` = quality gate (fmt, clippy -D warnings, workspace unit/integration
# tests including offline openrouter_credentials, mem-guard). No separate
# OpenRouter GHA job — a second Nix cold-start for one cargo test target was
# redundant with `cargo test --workspace`.
#
# `just test-extra` = local-only extras CI does not run (cross-target clippy,
# nix_retry smoke).
#
# Free GHA: CI_LOW_MEM=1 so cargo runs under cargo-mem-guard + mold (no pure
# nix monorepo release build -- that OOMs on ~16GB runners).
# ---------------------------------------------------------------------------

# Optional single-shot local gate (matches GHA quality job).
ci: require_system
    just flake-meta
    just ci-prep
    just test
    @rm -f .ci-started
    @echo "CI passed"

# Store prep before cargo under CI_LOW_MEM (mem-guard + ci-tools + .ci-started).
# Permanent cargo failures must not re-enter the outer GHA bootstrap loop.
ci-prep: require_system mem-guard
    @echo "==> ci-prep: realize .#ci-tools (nix_retry)"
    just nix_retry nix build -L {{ nix_low_mem_opts }} .#ci-tools
    @touch .ci-started

# Prove the flake evaluates (cheap; fails fast on lock/input breakage).
flake-meta:
    @echo "==> flake-meta"
    just nix_retry nix flake metadata

# Optional pure-nix release package (NOT CI). For local packaging / install-nix.
build:
    @echo "==> build .#grok-oss{{ if low_mem == "1" { " (low-mem nix opts)" } else { "" } }} [not CI]"
    just nix_retry nix build -L {{ nix_low_mem_opts }} .#grok-oss

# Optional: binary exists and runs a version probe (depends on release build).
smoke: build
    @echo "==> smoke [not CI]"
    test -x ./result/bin/grok-oss
    ./result/bin/grok-oss --version

# Optional crane cargo-check of pager-bin (NOT CI quality; prefer just test).
cargo-check: require_system
    @echo "==> cargo-check [not CI quality]"
    just nix_retry nix build -L {{ nix_low_mem_opts }} ".#checks.{{ system }}.cargoCheck"

# Optional flake-only re-run of openrouter credential tests (offline; not a
# separate GHA job). Prefer `just test` / `cargo test -p xai-grok-shell --test
# openrouter_credentials` for the normal path.
openrouter-tests: require_system
    @echo "==> openrouter-tests (optional flake check; covered by just test)"
    just nix_retry nix build -L {{ nix_low_mem_opts }} ".#checks.{{ system }}.openrouter-credentials"

# Build cargo-mem-guard package + unit tests as flake check.
mem-guard: require_system
    @echo "==> build .#cargo-mem-guard{{ if low_mem == "1" { " (low-mem nix opts)" } else { "" } }}"
    just nix_retry nix build -L {{ nix_low_mem_opts }} .#cargo-mem-guard
    @echo "==> check .#cargo-mem-guard-tests"
    just nix_retry nix build -L {{ nix_low_mem_opts }} ".#checks.{{ system }}.cargo-mem-guard-tests"

# Run a cargo (or other) command; under CI_LOW_MEM=1 wrap with cargo-mem-guard
# via devShells.ci (mold + pressure defaults). Cargo payloads are never
# nix_retry'd (permanent compile fails once).
#
# RULES_RUST_RUNFILES_WORKSPACE_NAME: --all-features enables xai-test-utils'
# optional `bazel`/`runfiles` dep (Bazel-only). That crate needs this env at
# compile time; set a dummy so cargo/host gates are not blocked.
[private]
cargo-ci +cmd:
    #!/usr/bin/env bash
    set -euo pipefail
    export RULES_RUST_RUNFILES_WORKSPACE_NAME="${RULES_RUST_RUNFILES_WORKSPACE_NAME:-grok-oss}"
    # Theme/color unit tests need distinct SGR slots. Host shells (and the
    # agent runtime) often export NO_COLOR=1, which quantizes every theme
    # color to Reset and collapses accent_skill vs text_primary checks.
    # Match CI (no NO_COLOR) so local `just test` is deterministic.
    unset NO_COLOR
    # Developer machines often export OPENROUTER_API_KEY / have Zed keychain
    # entries; unit tests assert NotAuthenticated / empty stores. Match CI.
    # Developer machines often export OPENROUTER_API_KEY and/or have Zed
    # OpenRouter keys in the OS keychain; unit tests assert NotAuthenticated
    # and that default catalog entries lack live credentials. Match CI.
    unset OPENROUTER_API_KEY
    export GROK_DISABLE_SHARED_HARNESS_SECRETS="${GROK_DISABLE_SHARED_HARNESS_SECRETS:-1}"
    # Idle-resume e2e tests bind a loopback axum mock as cli-chat-proxy.
    export GROK_TRUST_LOOPBACK_CLI_CHAT_PROXY="${GROK_TRUST_LOOPBACK_CLI_CHAT_PROXY:-1}"
    if [[ "${CI_LOW_MEM:-}" == "1" ]]; then
      exec nix develop {{ nix_low_mem_opts }} .#ci -c cargo-mem-guard -- {{ cmd }}
    fi
    exec {{ cmd }}

# Enter the fenix/crane-aligned dev shell (interactive: no retry wrapper).
dev:
    nix develop

# Enter the free-GHA / low-mem host shell (interactive: no retry wrapper).
dev-ci:
    nix develop .#ci

# Quality gate (GHA `quality` job + local pre-push). No release build.
#
# Cargo host scope (not --all-features): Bazel-only features (default-bazel /
# runfiles) break plain cargo. Not --all-targets on clippy: unit/integration
# tests pull cross-crate `cfg(test)` seams that Bazel injects via default-bazel;
# those need per-crate test-support (partially wired). Clippy therefore lints
# production surfaces (--lib --bins). Tests run via cargo test (enables
# cfg(test) on the crate under test).
#
# Covers: fmt check, clippy -D warnings (lib+bins), workspace tests, doctests,
# cargo-mem-guard (workspace-excluded).
test: test-fmt test-clippy test-unit test-doc test-mem-guard
    @echo "just test passed"

# Local-only extras CI does not run.
test-extra: test-clippy-targets test-nix-retry-smoke
    @echo "just test-extra passed"

test-fmt:
    @echo "==> cargo fmt --all -- --check"
    just cargo-ci cargo fmt --all -- --check

test-clippy:
    @echo "==> cargo clippy --workspace --lib --bins (-D warnings)"
    just cargo-ci cargo clippy --workspace --lib --bins --locked -- -D warnings

test-unit:
    @echo "==> cargo test --workspace"
    just cargo-ci cargo test --workspace --locked

test-doc:
    @echo "==> cargo test --workspace --doc"
    just cargo-ci cargo test --workspace --doc --locked

# Standalone (Cargo.toml workspace exclude).
test-mem-guard:
    @echo "==> cargo test cargo-mem-guard (workspace-excluded)"
    just cargo-ci cargo test --manifest-path crates/codegen/cargo-mem-guard/Cargo.toml --locked

# Cross-target clippy (local / test-extra). Not on free GHA quality job.
# Override: EXTRA_CLIPPY_TARGETS="aarch64-unknown-linux-gnu ..."
test-clippy-targets:
    #!/usr/bin/env bash
    set -euo pipefail
    targets="${EXTRA_CLIPPY_TARGETS:-aarch64-unknown-linux-gnu}"
    host="$(rustc -vV | awk '/^host:/{print $2}')"
    for t in ${targets}; do
      if [[ "${t}" == "${host}" ]]; then
        echo "==> clippy target ${t}: skip (host, already in test-clippy)"
        continue
      fi
      echo "==> cargo clippy --target ${t} --workspace --lib --bins (-D warnings)"
      if [[ "${CI_LOW_MEM:-}" == "1" ]]; then
        nix develop {{ nix_low_mem_opts }} .#ci -c cargo-mem-guard -- \
          cargo clippy --workspace --lib --bins --locked --target "${t}" -- -D warnings
      else
        cargo clippy --workspace --lib --bins --locked --target "${t}" -- -D warnings
      fi
    done

# Smoke-test nix_retry: NIX_RETRY_ATTEMPTS=2 must fail after 2 attempts of
# `false` (proves banner + integer path). Also checks invalid attempts reject.
test-nix-retry-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    export NIX_RETRY_ATTEMPTS=2
    set +e
    out="$(just nix_retry false 2>&1)"
    status=$?
    set -e
    if [[ "${status}" -eq 0 ]]; then
      echo "test-nix-retry-smoke: expected false to fail" >&2
      exit 1
    fi
    if ! grep -qE 'attempt 2/2|2 attempt' <<<"${out}"; then
      echo "test-nix-retry-smoke: expected attempt 2/2 (or '2 attempt') in output:" >&2
      echo "${out}" >&2
      exit 1
    fi
    # Integer validation path (fail-fast, no retries of false).
    set +e
    bad_out="$(NIX_RETRY_ATTEMPTS=nope just nix_retry true 2>&1)"
    bad_status=$?
    set -e
    if [[ "${bad_status}" -eq 0 ]]; then
      echo "test-nix-retry-smoke: expected invalid NIX_RETRY_ATTEMPTS to fail" >&2
      exit 1
    fi
    if ! grep -q 'NIX_RETRY_ATTEMPTS must be a positive integer' <<<"${bad_out}"; then
      echo "test-nix-retry-smoke: expected integer validation message:" >&2
      echo "${bad_out}" >&2
      exit 1
    fi
    echo "test-nix-retry-smoke: ok (false failed after 2 attempts, exit ${status}; invalid attempts rejected)"

# Install grok-oss -> ~/.cargo/bin (Cargo.toml [[bin]] name = "grok-oss").
# Overrides host -fuse-ld=wild (breaks this link). See comments in recipe body.
install:
    # Host ~/.cargo/config often sets -fuse-ld=wild; wild fails this workspace
    # (undefined drop_in_place<serde_json::Value>). CLI --config rustflags wins.
    mkdir -p "${CARGO_HOME:-$HOME/.cargo}/bin"
    @echo "==> cargo build --release -p xai-grok-pager-bin (no wild linker)"
    cargo build --release -p xai-grok-pager-bin --locked \
      --config 'target.x86_64-unknown-linux-gnu.rustflags=["-C","force-unwind-tables=yes"]' \
      --config 'target.aarch64-unknown-linux-gnu.rustflags=["-C","force-unwind-tables=yes"]'
    @echo "==> install -> ${CARGO_HOME:-$HOME/.cargo}/bin/grok-oss"
    install -Dm755 target/release/grok-oss "${CARGO_HOME:-$HOME/.cargo}/bin/grok-oss"
    @echo "==> verify"
    "${CARGO_HOME:-$HOME/.cargo}/bin/grok-oss" --version

# Install from Nix result (matches just build / CI; no host cargo linker).
install-nix: build
    mkdir -p "${CARGO_HOME:-$HOME/.cargo}/bin"
    install -Dm755 ./result/bin/grok-oss "${CARGO_HOME:-$HOME/.cargo}/bin/grok-oss"
    "${CARGO_HOME:-$HOME/.cargo}/bin/grok-oss" --version

# Upstream monorepo export helpers (see docs/upstream-history.md).
upstream-detect:
    ./scripts/detect-upstream-export.sh

upstream-import *ARGS:
    ./scripts/import-upstream-export.sh {{ ARGS }}

upstream-sync *ARGS:
    ./scripts/sync-upstream.sh {{ ARGS }}
