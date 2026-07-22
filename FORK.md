# Grok OSS fork notes

**Grok OSS** (`grok-oss`) is an **unofficial** open-source fork of
[xai-org/grok-build](https://github.com/xai-org/grok-build) (SpaceXAI’s Grok
Build CLI/TUI), maintained by [Surmount](https://github.com/SurmountSystems).

It is **not** affiliated with or endorsed by xAI / SpaceXAI. Trademarks and
product names belonging to xAI remain theirs.

**Why the fork exists:** upstream publishes under Apache-2.0 but **does not
accept external pull requests**. This repo accepts community PRs. If upstream
ever opens to outside contributions, Surmount intends to **open a PR** and try
to land the useful fork work there.

## Vision

| Pillar | Practice |
|--------|----------|
| **Faithful** | Absorb xAI monorepo exports after review; keep `xai-grok-*` paths for alignment |
| **Complete history** | Surmount `main` is the continuous product archive; xAI is a content feed |
| **Open** | Pull requests welcome **here** |
| **Distinct** | Product **Grok OSS**, binary **`grok-oss`**, clear unofficial labeling |
| **Compatible** | Config and sessions under **`~/.grok`** (shared with upstream if both installed) |
| **Superset** | Fork features sit **on top of** upstream behavior — never hollow out core agent logic |

## Git flow

Normal feature branches → pull request → **`main`**. Temporary tool branches
(`import/*`, `onto-xai/*`) are not a second main; they land via PR.

On **open PRs**, catch up with `main` by **merge**, not rebase (no force-push
while CI runs). Detail: [`docs/git-workflow.md`](docs/git-workflow.md).

## Remotes

```bash
git remote add xai-org https://github.com/xai-org/grok-build.git   # once
# origin → SurmountSystems/grok-oss
# xai-org → xai-org/grok-build
```

## Syncing with xAI

xAI publishes force-pushed snapshots (bot author, often orphan roots, sometimes
short “Synced from monorepo” chains). GitHub may say histories are “entirely
different.” **Expected.** Treat them as a **tree feed**, not shared ancestry.

**Two maintainer jobs** (do not confuse them):

| Job | Script | Result |
|-----|--------|--------|
| **Import** — their tree into Surmount history | `./scripts/import-upstream-export.sh` | `import/*` review branch → PR to `main` |
| **Stack on tip** — our product commits on their tip | `./scripts/put-history-on-xai.sh` | `onto-xai/*` (real **cherry-pick**; no `MODE=overlay`) |

When histories keep breaking, prefer **stacking our product work on their
current tip** so one branch is a descendant of theirs **and** carries Grok OSS.
Detect: `./scripts/detect-upstream-export.sh` or `just upstream-detect`.

Full process: [`docs/upstream-history.md`](docs/upstream-history.md)  
Import log: [`docs/upstream-import-log.md`](docs/upstream-import-log.md)  
Onto log: [`docs/upstream-onto-log.md`](docs/upstream-onto-log.md)

**Never:** reset Surmount `main` to xAI; GitHub “Sync fork” that drops Surmount
commits; unsigned commits; bulk tree rewrites without review.

## What Grok OSS adds (divergence inventory)

Hierarchical: one line here → code or a linked doc for detail. Update this
list when you ship fork work.

### Product

- [x] **Binary / branding** — `grok-oss` (crate package still `xai-grok-pager-bin`); welcome and docs say Grok OSS
- [x] **OpenRouter** — separate model option (`openrouter-grok-4.5`); login/logout; secret store; optional Zed credential probe (read-only)
- [x] **Multi-key OpenRouter** — comma lists / failover keys for credit rotation
- [x] **Economic mode** — soft-cap effective context at the Grok 4.5 long-context price cliff (~200k); `/economic-mode`; settings default on
- [x] **Auto-run `/implement`** — after a successful turn, queue a follow-up implement block when present; **appends** after any already-queued prompts (does not drop them); economic mode can clamp implement `--effort`
- [x] **Shared rate limits** — crate `grok-rate-limit` (Surmount name, not `xai-`); cooldowns under `~/.grok/rate_limits/`; optional `GROK_DISABLE_SHARED_RATE_LIMIT=1`
- [x] **Updates** — no xAI auto-update channel by default (wrong product). `grok-oss update --check` compares to Surmount `main`. Escape hatch: `GROK_OSS_ENABLE_XAI_UPDATER=1`

### Packaging and build

- [x] **AUR** sources under `packaging/aur/`
- [x] **Nix flake** — `nix build .#grok-oss`, dev shells (human packaging, not GHA release artifacts)
- [x] **justfile** — `just check` / `just ci` full quality gate; `just test` for the cargo quality suite

### Process

- [x] **Upstream tooling** — detect / import / put-history / sync scripts; scheduled export watch workflow
- [x] **PRs accepted** — CONTRIBUTING / this fork

Novel Surmount crates use the **`grok-*`** prefix (example: `grok-rate-limit`).
Upstream crate paths stay **`xai-grok-*`** for mergeability.

## CI and local quality

**CI is for checks only** — never build a shippable release package in GitHub
Actions (supply-chain boundary). Humans package from a trusted tree when ready.

| Command | Role |
|---------|------|
| **`just check`** or **`just ci`** | Full local gate (flake-meta + prep + fmt/clippy/tests) — **run before push** |
| **`just test`** | Quality suite without re-running full flake prep |
| **`just build` / install** | Optional release-style package (not CI) |

GHA quality job: flake-meta → ci-prep → `just test` (see `.github/workflows/ci.yml`).
There is **no** `ci-quick` or `ci-host` recipe.

## Versioning and “am I up to date?”

| Idea | Practice |
|------|----------|
| **Upstream owns the package version number** | Keep lockstep with the upstream tree we track (`CARGO_PKG_VERSION`) |
| **Our identity is the git revision** | Binary shows **upstream version + short git SHA** |
| **No second release train** | No Surmount stable/alpha channel mirroring SpaceXAI |
| **No default xAI auto-update** | Would advertise official `grok` builds |

Illustrative only (not necessarily this checkout):

```text
grok-oss <upstream-version> (<short-sha>)
```

```bash
grok-oss --version
grok-oss update --check          # vs github.com/SurmountSystems/grok-oss main
grok-oss update --check --json
```

`SOURCE_REV` at the repo root is a **monorepo export pin** (full upstream-side
SHA recorded for the tree we absorbed), not a substitute for “what is HEAD.”

If behind: rebuild or reinstall from this repo / packaging — not the official
`curl https://x.ai/cli/install.sh` path (that installs upstream **`grok`**).

## Multi-session rate limits

Concurrent `grok-oss` processes share cooldowns under `~/.grok/rate_limits/`
(`grok-rate-limit`). On HTTP 429-style limits, the strictest wait wins across
processes. Disable shared coordination with `GROK_DISABLE_SHARED_RATE_LIMIT=1`.

## Canonical repo

<https://github.com/SurmountSystems/grok-oss>

## License

Apache License 2.0 — [`LICENSE`](LICENSE).  
Third-party: [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES).
