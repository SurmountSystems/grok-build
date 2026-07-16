# Grok OSS local recipes.
# GitHub Actions runs the same `just ci` entrypoint — keep this file the source of truth.
# Requires: just, nix (with flakes).

set shell := ["bash", "-euo", "pipefail", "-c"]

# Host system for flake check attributes (e.g. x86_64-linux).
system := `nix eval --impure --raw --expr 'builtins.currentSystem'`

default:
    @just --list

# Full CI gate (local + GitHub Actions).
ci: flake-meta build smoke cargo-check openrouter-tests
    @echo "✓ CI passed"

# Prove the flake evaluates (cheap; fails fast on lock/input breakage).
flake-meta:
    @echo "==> flake-meta"
    nix flake metadata

# Primary package: release build of grok-oss.
build:
    @echo "==> build .#grok-oss"
    nix build -L .#grok-oss

# Binary exists and runs a lightweight version probe.
smoke: build
    @echo "==> smoke"
    test -x ./result/bin/grok-oss
    ./result/bin/grok-oss --version

# cargo check path (crane mkCargoDerivation for pager-bin).
cargo-check:
    @echo "==> cargo-check"
    nix build -L ".#checks.{{ system }}.cargoCheck"

# OpenRouter credential integration tests.
openrouter-tests:
    @echo "==> openrouter-tests"
    nix build -L ".#checks.{{ system }}.openrouter-credentials"

# Faster feedback without full release package (dev shell + cargo). Not used in CI.
ci-quick:
    nix develop -c cargo check -p xai-grok-pager-bin
    nix develop -c cargo test -p xai-grok-shell --test openrouter_credentials

# Enter the fenix/crane-aligned dev shell.
dev:
    nix develop

# Install binary with cargo (non-Nix path).
install:
    cargo install --path crates/codegen/xai-grok-pager-bin --locked --force
