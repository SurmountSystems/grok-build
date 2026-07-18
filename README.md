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

A small `SOURCE_REV` file at the root records the full monorepo commit SHA
for the version of the code present in this tree.

</div>

---

## Vision

| Pillar | What we do |
|--------|------------|
| **Faithful** | Track [xai-org/grok-build](https://github.com/xai-org/grok-build); keep crate layout for clean merges |
| **Open** | Public source, **PRs accepted here**, security-conscious review |
| **Distinct** | Product **Grok OSS**, CLI **`grok-oss`**, clear unofficial labeling |
| **Compatible** | Config/session state still under **`~/.grok`** (shared with upstream CLI if both installed) |

Fork features (examples): OpenRouter as a separate model option — see shell docs.

## Install

### Arch Linux (AUR)

Sources live in-tree under [`packaging/aur/`](packaging/aur/). After the package
is published to the AUR:

```bash
# VCS package tracking main (recommended while following upstream closely)
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

If the GitHub repo is still named `grok-build`, use that clone URL until rename.

### Nix

```bash
nix develop          # fenix toolchain from rust-toolchain.toml + build deps
nix build .#grok-oss # → ./result/bin/grok-oss
```

CI uses the same flake (see `.github/workflows/ci.yml`). Locally, mirror GH CI with:

```bash
just ci        # local mirror of GHA quality (flake-meta + ci-prep + just test)
just ci-quick  # faster cargo check/tests inside nix develop
```


### Official upstream binary (not this fork)

```bash
curl -fsSL https://x.ai/cli/install.sh | bash   # installs official `grok`
```

That path is SpaceXAI’s release channel, **not** Grok OSS.

## Build from source

Requirements:

- **Rust** — the toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml);
  `rustup` installs it automatically on first build.
- **[DotSlash](https://dotslash-cli.com)** — required so hermetic tools under
  [`bin/`](bin/) (notably [`bin/protoc`](bin/protoc)) can download and run.
  Install it and ensure `dotslash` is on your `PATH` **before** building:

  ```sh
  cargo install dotslash
  # or: prebuilt packages — https://dotslash-cli.com/docs/installation/
  /usr/bin/env dotslash --help   # sanity check
  ```

- **protoc** — proto codegen resolves [`bin/protoc`](bin/protoc) via DotSlash,
  or falls back to a `protoc` on `PATH` / `$PROTOC`.
- macOS and Linux are supported build hosts; Windows builds are best-effort
  and not currently tested from this tree.

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
| Releases | Official channels / installers | **No separate release train** — identity is **upstream version + git SHA**; `grok-oss update --check` vs Surmount `main` |
| License | Apache-2.0 | Apache-2.0 (same first-party terms) |

Sync and versioning: [`FORK.md`](FORK.md), [`docs/upstream-history.md`](docs/upstream-history.md).  
Users: `grok-oss update --check`. Maintainers: `just upstream-detect` / `just upstream-import` (never blind-merge xAI force-exports).
## Documentation

- Fork process & divergences: [`FORK.md`](FORK.md)
- User guide (upstream docs tree): [`crates/codegen/xai-grok-pager/docs/user-guide/`](crates/codegen/xai-grok-pager/docs/user-guide/)
- Online upstream docs may still say “Grok Build”; behavior is largely the same, CLI name differs.

## Development

```bash
cargo check -p <crate>        # prefer targeted crates; full workspace is slow
cargo test -p xai-grok-shell --test openrouter_credentials
cargo clippy -p <crate>
cargo fmt --all
```

## Contributing

PRs against **this** repository are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

First-party code: **Apache License 2.0** — [`LICENSE`](LICENSE).

Third-party: [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES) and
[`crates/codegen/xai-grok-tools/THIRD_PARTY_NOTICES.md`](crates/codegen/xai-grok-tools/THIRD_PARTY_NOTICES.md).
