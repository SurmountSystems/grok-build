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
| **Faithful** | Absorb every xAI monorepo export **after review**; keep crate layout / `xai-grok-*` names for content alignment |
| **Complete history** | **Surmount is the continuous git archive**; xAI force-exports are a content feed, not our history root |
| **Open** | Pull requests welcome **on this repository** |
| **Distinct** | Product name **Grok OSS**, binary **`grok-oss`**, clear unofficial labeling |
| **Secure process** | Public review of **each** upstream contribution; reproducible builds from source |

## Remotes

```bash
git remote add xai-org https://github.com/xai-org/grok-build.git   # once
# optional alias:
git remote add upstream https://github.com/xai-org/grok-build.git
git remote -v
# origin   → SurmountSystems/grok-oss
# xai-org  → xai-org/grok-build
```

## Open PRs: merge `main` in — never rebase

Catching up a **published** feature branch with `main` is a **merge**, not a
rebase. Rebase rewrites SHAs and forces a force-push, which confuses in-flight
CI and is not acceptable on open Surmount PRs.

| Do | Don’t |
|----|--------|
| `git merge origin/main` on the feature branch | `git rebase origin/main` on a pushed PR branch |
| Normal `git push` after a merge commit | `git push --force` / `--force-with-lease` to “fix” conflicts |
| Reset local to `origin/<branch>` if you accidentally rebased, then merge | Force-push rebased SHAs while CI is running |

Full policy: **[`docs/git-workflow.md`](docs/git-workflow.md)**.

## Syncing with xAI (not a normal merge)

xAI publishes via **orphan force-pushes** (`grokkybara[bot]`, single-commit
`main`). GitHub will often say histories are “entirely different.” **Expected.**

| Do | Don’t |
|----|--------|
| Keep Surmount history forever | Reset `main` to `xai-org/main` |
| Diff **trees** / import log | Assume `git merge` has a merge-base |
| Review every file delta | Lazy bulk accept |
| Record imports in the log | Use GitHub “Sync fork” blindly |

```bash
./scripts/detect-upstream-export.sh   # exit 2 = new export
./scripts/import-upstream-export.sh   # review branch (no push)
# or: IMPORT_NOW=1 ./scripts/sync-upstream.sh
```

Full process: **[`docs/upstream-history.md`](docs/upstream-history.md)**  
Import ledger: **[`docs/upstream-import-log.md`](docs/upstream-import-log.md)**  
Agent skill: **`upstream-export-import`** (Surmount skills tree)

Novel Surmount crates use the **`grok-*`** name (no `xai-` prefix), e.g.
`grok-rate-limit`.

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

## Versioning, releases, and “am I up to date?”

Grok OSS deliberately does **not** run a formal product release process the way
upstream Grok Build does (no competing channel pointers, no Surmount-owned
semver track, no in-app binary swap from `x.ai/cli`).

### Model

| Idea | Practice |
|------|----------|
| **Superset, never subset** | Fork-only work (OpenRouter, branding, packaging, …) sits **on top of** upstream. We do not remove or hollow out core upstream behavior. |
| **Upstream owns the package version number** | When we **import** an export, keep their `CARGO_PKG_VERSION` lockstep strings. Import is content-reviewed, not a shared-history merge. |
| **Our identity is the git tree** | “What build is this?” is answered by **git revision** and **relation to `main`**, not by inventing `0.x.y-oss` for every change. |
| **Users install from source or OSS packaging** | Compile (`cargo` / Nix) or install packaged **grok-oss** (AUR, etc.). Official `curl https://x.ai/cli/install.sh` is **upstream `grok`**, not this fork. |

Conflict resolution: prefer **upstream behavior** for core agent logic; **re-apply**
fork seams (OpenRouter, branding, `grok-rate-limit`, …) on top. Superset, never
subset.

### What we do *not* do

- **No** Surmount “stable/alpha” release channel mirroring SpaceXAI.
- **No** in-app auto-update from `x.ai/cli` / `@xai-official/grok` (wrong product;
  would advertise official builds). Debug-only escape hatch:
  `GROK_OSS_ENABLE_XAI_UPDATER=1`.
- **No** expectation that end users wait for a Surmount “release day.” Tracking
  `main` (or a packaging recipe that builds from it) is the default.

Optional lightweight tags (`v…-oss`) may still appear for AUR/package recipes
when a distro needs a fixed ref—not as a second product version line.

### Build identity

Every build is labeled:

```text
<upstream package version> (<short git sha>)
```

Example: `0.1.220-alpha.4 (cfe4602abc12)`

- **Version** = lockstep with the upstream tree we last merged (`CARGO_PKG_VERSION`).
- **SHA** = commit this binary was built from (embedded at compile time; packaging
  can set `GROK_GIT_SHA` when `.git` is absent).

Package managers that demand a single numeric version can map that later
(e.g. epoch/revision); the product still speaks **upstream version + SHA**.

### Checking for updates (users)

```bash
grok-oss --version          # e.g. grok-oss 0.1.220-alpha.4 (cfe4602abc12)
grok-oss update --check     # compare embedded SHA to github.com/SurmountSystems/grok-oss main
grok-oss update --check --json
```

`--check` hits the public GitHub API (optional `GITHUB_TOKEN` / `GH_TOKEN` for
higher rate limits). It reports behind / ahead / up-to-date and does **not**
download a binary. If behind, rebuild or reinstall:

```bash
git pull && just install    # or just install-nix / AUR / your package
```

The CLI is the user interface for freshness — not a justfile recipe.

### Multi-session rate limits

Concurrent `grok-oss` processes share cooldowns under `~/.grok/rate_limits/`
(crate **`grok-rate-limit`**, no `xai-` prefix). On HTTP 429 / GitHub rate limits,
the **strictest** wait wins across processes so sessions coordinate instead of
stampeding the API. Transient retries stay **unlimited by default**; optional
`GROK_MAX_RETRIES` only. Disable shared coordination with
`GROK_DISABLE_SHARED_RATE_LIMIT=1`.

### Canonical repo

<https://github.com/SurmountSystems/grok-oss>

## License

Same as upstream first-party code: **Apache License 2.0** — see [`LICENSE`](LICENSE).
Third-party notices: [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES).
