# Grok OSS fork notes

**Grok OSS** (`grok-oss`) is an **unofficial** open-source fork of
[xai-org/grok-build](https://github.com/xai-org/grok-build) (SpaceXAI’s Grok
Build CLI/TUI), maintained by [Surmount](https://github.com/SurmountSystems).

It is **not** affiliated with or endorsed by xAI / SpaceXAI. Trademarks and
product names belonging to xAI remain theirs.

## Why this fork exists

- Upstream publishes source under Apache-2.0 but **does not accept external PRs**.
- We want a public tree that tracks upstream **faithfully**, accepts community
  patches, and can ship security-relevant review and packaging (e.g. AUR).
- Config and session state remain under **`~/.grok`** so workflows stay
  compatible with upstream when both are used on the same machine.

## Vision

| Pillar | Practice |
|--------|----------|
| **Faithful** | Merge `upstream/main` regularly; keep crate layout and most package names |
| **Open** | Pull requests welcome **on this repository** |
| **Distinct** | Product name **Grok OSS**, binary **`grok-oss`**, clear unofficial labeling |
| **Secure process** | Public review, reproducible builds from source |

## Remotes

```bash
git remote add upstream https://github.com/xai-org/grok-build.git   # once
git remote -v
# origin   → SurmountSystems/grok-oss (or grok-build until renamed)
# upstream → xai-org/grok-build
```

Sync helper:

```bash
./scripts/sync-upstream.sh
```

Prefer **merge** of upstream into `main` (honest history). Rebase only short-lived
feature branches.

## What we change vs upstream

Keep diffs **small and product-facing** so merges stay tractable:

| Area | Fork choice |
|------|-------------|
| Binary name | `grok-oss` (crate package still `xai-grok-pager-bin`) |
| Branding / docs | README, FORK.md, CONTRIBUTING, version banner |
| Features | e.g. OpenRouter as a separate model option |
| Packaging | AUR sources under `packaging/aur/` |
| Internal crates | **Not** renamed (`xai-grok-*` paths stay for mergeability) |

## Divergences checklist (update when you add fork-only work)

- [x] OpenRouter Grok 4.5 model option + secret store / Zed credential probe
- [x] Binary name `grok-oss` and Grok OSS branding
- [x] AUR packaging sources (`packaging/aur/`)
- [x] CONTRIBUTING accepts PRs on this fork

## Nix & CI

- [`flake.nix`](flake.nix) — fenix (pinned via `rust-toolchain.toml`) + crane
  package `grok-oss`, `devShell`, and checks.
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — `nix build .#grok-oss`
  and focused cargo checks/tests on PRs to `main`.

```bash
nix develop
nix build .#grok-oss
nix flake check   # runs packages + checks (long)
just ci           # same steps as GitHub Actions (preferred before push)
just ci-quick     # faster cargo-only path inside nix develop
```

## Releases

- Upstream version strings (e.g. `0.1.220-alpha.4`) may still appear from
  `CARGO_PKG_VERSION` for lockstep with source.
- Optional Surmount tags: `v0.x.y-oss` when cutting AUR stable packages.
- Official `curl https://x.ai/cli/install.sh` installs **upstream** `grok`, not
  this fork.

## License

Same as upstream first-party code: **Apache License 2.0** — see [`LICENSE`](LICENSE).
Third-party notices: [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES).
