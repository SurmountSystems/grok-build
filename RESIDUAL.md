# Residual work -- free-GHA CI reliability (2026-07-16 / impl d2b83de9 fix round)

## Done (uncommitted)

| Item | Status |
|------|--------|
| Drop flake-utils / systems; inline forAllSystems | Done |
| Dual-layer NIX_CONFIG + just nix_retry (every non-zero) | Done |
| Best-effort swap | Done |
| Host CI: mem-guard + ci-tools under nix_retry; cargo once | Done |
| cargo-mem-guard: mold via CARGO_TARGET_*; no RUSTFLAGS wipe of config.toml | Done (fix round) |
| Fortify-off on devShells (CARGO_MEM_* on devShells.ci env) | Done |
| CI_SYSTEM allowlist / regex guard (require_system; env-only, no `{{ system }}` in guard) | Done (R2) |
| plan_mold empty-encoded unit test; nix_retry smoke attempt banner assert | Done (R2) |
| permissions: contents: read | Done (fix round) |
| .ci-started after store work, before cargo | Done (fix round) |
| mem-guard uses nix_low_mem_opts when CI_LOW_MEM=1 | Done (fix round) |
| doCheck=false on package; tests only in cargo-mem-guard-tests | Done (fix round) |
| packages.just pin; GHA `nix shell .#just` | Done |
| with_jobs tests for -j8 and --jobs=16 | Done (fix round) |

**Not committed / not pushed.**

## Local validation

Human run (2026-07-17): unit tests + nix_retry smoke + flake-meta + mem-guard **green**.
`ci-host` **failed** linking with both `-fuse-ld=wild` and `-fuse-ld=mold` on the
rustc line (host `~/.cargo` injects wild via `build.rustflags`; we only set
`CARGO_TARGET_*`, so wild survived).

**Fix applied:** when mold is on, always set plain `RUSTFLAGS` to
`force_mold(parent_or_empty)` so host `build.rustflags` is replaced, and still
seed `CARGO_TARGET_*` for workspace force-unwind-tables.

Re-run:

```bash
cd /home/hunter/Projects/surmount/grok-build

cargo test --manifest-path crates/codegen/cargo-mem-guard/Cargo.toml --locked
just test-nix-retry-smoke
CI_LOW_MEM=1 CI_SYSTEM=x86_64-linux just ci-host
# or full:
CI_LOW_MEM=1 CI_SYSTEM=x86_64-linux just ci

git fetch origin && git merge origin/main   # no rebase / force-push
```
## Accuracy notes (review fix)

- **CARGO_MEM_*** and fortify-off live on **`devShells.ci` env** (`ciLowMemEnv`), not on `packages.ci-tools` alone. `ci-tools` is PATH (rustc, cargo-mem-guard, mold, just, …). Host cargo uses `nix develop .#ci`.
- **Cold `nix shell .#just`** still **evaluates full flake inputs** (nixpkgs/fenix/crane) once; realized package is just-only (not full rustc). Avoids unpinned registry `nixpkgs#just`.
- **nix_retry** retries **every non-zero exit**, not network-only. Cargo is outside the loop on purpose.
- **`.ci-started`**: touched after mem-guard + ci-tools (ci-host) or at start of ci-full heavy work; cleared by parent `ci` on success. Outer GHA may re-run if marker absent (bootstrap/store network flake).

## GHA watch checklist (after user push)

1. https://github.com/SurmountSystems/grok-oss/actions
2. Workflow has `permissions: contents: read`
3. Log: `nix shell .#just -c just ci` (not `nixpkgs#just`)
4. Store steps under `==> nix attempt ...`; cargo once after `.ci-started`
5. No pure `.#grok-oss` under `CI_LOW_MEM=1`
6. Green = job exit 0

## Branch / merge

| Ref | Tip (static `.git/refs`; no live fetch) |
|-----|------------------------------------------|
| feat/rate-limit-inter-process-coordination | `154db94…` |
| origin/main (last FETCH_HEAD) | `00b9a43…` |

User must `git fetch && git merge origin/main` before/with signed commit.

## Residual risks

1. github: tarballs for nixpkgs/fenix/crane can still 503 through retries.
2. Pure `.#grok-oss` OOMs on free GHA by design.
3. Agent shell outage blocked live validation this round.
4. Action major tags not SHA-pinned (accepted for this ship).
5. Feature may be behind origin/main until user merges.

## Commit / summary files

- `/tmp/grok-1000/grok-commit-msg-d2b83de9.txt`
- `/tmp/grok-1000/grok-impl-summary-d2b83de9.md`
