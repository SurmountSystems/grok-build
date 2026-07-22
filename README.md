<div align="center">

<h1>Grok OSS (<code>grok-oss</code>)</h1>

**Unofficial open-source fork** of [xAI Grok Build](https://github.com/xai-org/grok-build),
maintained by [Surmount](https://github.com/SurmountSystems).

Terminal AI coding agent: full-screen TUI, headless/CI mode, and ACP for editors.

**Not affiliated with or endorsed by xAI / SpaceXAI.**

[FORK.md](FORK.md) ·
[Contributing](#contributing) ·
[Install](#install) ·
[Build from source](#build-from-source) ·
[Upstream](#relationship-to-upstream)

</div>

---

## How Grok OSS differs (short)

Upstream does not accept external pull requests; this fork does. Product name
and binary are **`grok-oss`**. Config and sessions stay under **`~/.grok`**.

Fork additions include OpenRouter as a separate model option, shared rate
limits across processes, economic mode, and auto-run `/implement` follow-ups.
Detail: **[`FORK.md`](FORK.md)**.

If upstream ever accepts outside PRs, Surmount intends to contribute the useful
work back.

`SOURCE_REV` at the repo root is a **monorepo export pin** (full SHA recorded
for an absorbed upstream-side tree), not a substitute for `git rev-parse HEAD`.

## Vision

| Pillar | What we do |
|--------|------------|
| **Faithful** | Track [xai-org/grok-build](https://github.com/xai-org/grok-build); keep crate layout for clean content alignment |
| **Open** | Public source, **PRs accepted here**, security-conscious review |
| **Distinct** | Product **Grok OSS**, CLI **`grok-oss`**, clear unofficial labeling |
| **Compatible** | Config/session state still under **`~/.grok`** (shared with upstream CLI if both installed) |

## Install

### Arch Linux (AUR)

Sources live in-tree under [`packaging/aur/`](packaging/aur/). After the package
is published to the AUR:

```bash
yay -S grok-oss-git
# or: paru -S grok-oss-git
```

Until AUR publish is live, build with `makepkg` from `packaging/aur/grok-oss-git/`.

### Cargo (from this repo)

```bash
git clone https://github.com/SurmountSystems/grok-oss.git
cd grok-oss
cargo install --path crates/codegen/xai-grok-pager-bin --locked --force
# installs: ~/.cargo/bin/grok-oss
grok-oss --version
```

### Nix

```bash
nix develop          # fenix toolchain from rust-toolchain.toml + build deps
nix build .#grok-oss # → ./result/bin/grok-oss  (human packaging, not GHA)
```

**CI is for checks only** (no release package in GitHub Actions — supply chain).
Locally, the same quality gate:

```bash
just check     # or: just ci  — full gate; run before push
just test      # fmt / clippy / tests without redoing full flake prep
```

### Official upstream binary (not this fork)

```bash
curl -fsSL https://x.ai/cli/install.sh | bash   # installs official `grok`
```

That path is SpaceXAI’s release channel, **not** Grok OSS.

## Build from source

Requirements:

- **Rust** — pinned by [`rust-toolchain.toml`](rust-toolchain.toml);
  `rustup` installs on first build.
- **[DotSlash](https://dotslash-cli.com)** — hermetic tools under [`bin/`](bin/)
  (notably `bin/protoc`). Install and put `dotslash` on `PATH` before building.
- **protoc** — via DotSlash `bin/protoc`, or `PATH` / `$PROTOC`.
- macOS and Linux are supported; Windows is best-effort.

```bash
cargo run -p xai-grok-pager-bin                 # build + launch
cargo build -p xai-grok-pager-bin --release     # target/release/grok-oss
cargo check -p xai-grok-pager-bin
```

Package name remains `xai-grok-pager-bin` for upstream mergeability; the binary
artifact is **`grok-oss`**.

## Relationship to upstream

| | Upstream | Grok OSS |
|--|----------|----------|
| Repo | [xai-org/grok-build](https://github.com/xai-org/grok-build) | [SurmountSystems/grok-oss](https://github.com/SurmountSystems/grok-oss) |
| External PRs | Not accepted | **Welcome** |
| Binary | `grok` (official installer) | `grok-oss` |
| Releases | Official channels / installers | **No separate release train** — upstream version + git SHA; `grok-oss update --check` vs Surmount `main` |
| License | Apache-2.0 | Apache-2.0 |

Sync and versioning: [`FORK.md`](FORK.md), [`docs/upstream-history.md`](docs/upstream-history.md).  
Users: `grok-oss update --check`. Maintainers: `just upstream-detect` / import or put-history scripts (never blind-merge xAI force-exports).

## Documentation

- Fork process and divergences: [`FORK.md`](FORK.md)
- User guide (mostly upstream tree): [`crates/codegen/xai-grok-pager/docs/user-guide/`](crates/codegen/xai-grok-pager/docs/user-guide/)
- Online upstream docs may still say “Grok Build”; CLI name and fork features differ as above.

## Development

```bash
just check                    # full quality gate (preferred before push)
cargo check -p <crate>
cargo test -p xai-grok-shell --test openrouter_credentials
cargo clippy -p <crate>
cargo fmt --all
```

## Contributing

PRs against **this** repository are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).  
Normal git flow: feature branch → PR → `main`.

## License

First-party code: **Apache License 2.0** — [`LICENSE`](LICENSE).

Third-party: [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES) and
[`crates/codegen/xai-grok-tools/THIRD_PARTY_NOTICES.md`](crates/codegen/xai-grok-tools/THIRD_PARTY_NOTICES.md).
