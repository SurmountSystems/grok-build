# grok-bitcoin-cdk-mint

Out-of-process **Cashu CDK mint helper** for `grok-bitcoin-wallet` (feature
`cashu-cdk`): NUT-04 mint quote → (pay BOLT11) → proofs → `cashuA…` token.

## Why a separate binary?

`cdk-sqlite` pulls `rusqlite 0.31` / `libsqlite3-sys` (`links = "sqlite3"`). The
shell monorepo stays on `rusqlite 0.37` (FTS5 / sqlite-vec / CVE pins). Those
two pins **cannot** share one Cargo dependency graph — not even as separate
workspace members under resolver=2. This crate is therefore:

- **Excluded** from the root workspace (`Cargo.toml` `exclude`)
- Built with its **own** `--manifest-path` (own `Cargo.lock`)
- Talked to over **stdin/stdout JSON** (seed material never on argv/env/disk plaintext)

Do **not** add this crate as a workspace member. Do **not** link `cdk` /
`cdk-sqlite` into default CI packages.

## Build / install

### Nix / flake (recommended)

Isolated crane package — same fileset pattern as `grok-bitcoin-ldk-node`. Crane
**never** sees the monorepo `Cargo.toml`, so `cdk` / `cdk-sqlite` are not linked
into default `grok-oss` or monorepo `cargoArtifacts`.

```bash
# Build the helper only:
nix build .#grok-bitcoin-cdk-mint

# Put it on PATH for this shell:
nix shell .#grok-bitcoin-cdk-mint

# Or run once (stdin JSON IPC):
echo '{"v":1,"cmd":"ping"}' | nix run .#grok-bitcoin-cdk-mint

# Point product wallet at the result store path (or a copy on PATH):
export GROK_BITCOIN_CDK_MINT_BIN="$(nix build .#grok-bitcoin-cdk-mint --print-out-paths)/bin/grok-bitcoin-cdk-mint"

# Opt-in pure-nix package + unit tests (long; not default CI / not `just test`):
just cdk-mint
```

Flake exports:

| Attr | Role |
|------|------|
| `packages.<system>.grok-bitcoin-cdk-mint` | Install package (`meta.mainProgram`; `doCheck = false`; shared `cargoArtifacts`) |
| `checks.<system>.grok-bitcoin-cdk-mint-tests` | Helper unit tests only (same artifacts; **not** a second install package under checks) |
| `apps.<system>.grok-bitcoin-cdk-mint` | `nix run` |

The install package is **packages-only** so `nix flake check` does not
double-build the full CDK pure graph. Flake check still runs `…-tests` once —
that graph is heavy; prefer `just cdk-mint` or host cargo over casual flake
check as a pre-push gate.

Default monorepo packages / CI quality jobs still **do not** enable feature
`cashu-cdk` or pull `cdk` into the workspace graph. Optional GHA job (if
present) builds this excluded crate with cargo only.

### Cargo (dev)

```bash
# From monorepo root:
cargo build --manifest-path crates/codegen/grok-bitcoin-cdk-mint/Cargo.toml --release

# Binary:
#   crates/codegen/grok-bitcoin-cdk-mint/target/release/grok-bitcoin-cdk-mint
# or debug:
#   crates/codegen/grok-bitcoin-cdk-mint/target/debug/grok-bitcoin-cdk-mint

export GROK_BITCOIN_CDK_MINT_BIN="$(pwd)/crates/codegen/grok-bitcoin-cdk-mint/target/release/grok-bitcoin-cdk-mint"
```

## Environment

| Env | Role |
|-----|------|
| `GROK_BITCOIN_CDK_MINT_BIN` | Absolute path to this helper (preferred) |
| `GROK_BITCOIN_CDK_STORAGE` | Absolute base dir for CDK sqlite state (per-seed subdir appended by parent) |
| `GROK_BITCOIN_CASHU_MINT_URL` | Cashu mint base URL (parent also uses this for HTTP quote fallback) |

When `GROK_BITCOIN_CDK_MINT_BIN` is unset, the wallet looks for a sibling of the
current executable named `grok-bitcoin-cdk-mint`, then `PATH`.

## IPC (v1)

| cmd | Purpose |
|-----|---------|
| `ping` | Health; `cdk_linked=true` |
| `mint_quote` | Create NUT-04 BOLT11 quote via CDK wallet |
| `mint_after_paid` | Poll quote Paid → mint proofs → export `cashuA…` |
| `melt_token` | Melt bearer `cashuA…` to destination BOLT11; Success only when CDK state **PAID** |

Seed material: BIP-39 `mnemonic` + optional `passphrase` on stdin JSON only.
`storage_dir` must be absolute. Same seed + storage required across quote and
mint so NUT-20 signing keys stay consistent.

## Product wire

1. Build shell/pager with optional feature: `--features cashu-cdk` on
   `xai-grok-shell` / `xai-grok-pager-bin` (not default CI).
2. Install this helper and set `GROK_BITCOIN_CDK_MINT_BIN` (or PATH) +
   `GROK_BITCOIN_CASHU_MINT_URL`.
3. CLI `grok routstr mint` and TUI `/routstr mint` when `proofs_mint_live`:
   SeedVault unlock → NUT-04 mint quote BOLT11 → pay mint → second unlock →
   proofs (`cashuA…`) → redeem → float only if redeem succeeds.
4. On not-live / unlock cancel / any failure: residual + **P0** `grok routstr topup`.

## Product honesty

1. Paying the mint quote BOLT11 pays the **mint**, not Routstr float.
2. A successful `mint_after_paid` yields a real `cashuA…` token suitable for
   `grok routstr redeem` / live Routstr `balance/create|topup`.
3. **Never** claim Routstr prepaid float until redeem succeeds.
4. Melt: `melt_token` Success only when CDK reports melt state **PAID** (never
   invent). Wallet `spend_live` / `refund_live` gate on helper resolvable + mint
   URL; bare product `refund()` still needs token+bolt11+SeedVault.
5. Default monorepo CI does **not** enable `cashu-cdk` or build this helper.

## Tests

```bash
cargo test --manifest-path crates/codegen/grok-bitcoin-cdk-mint/Cargo.toml
echo '{"v":1,"cmd":"ping"}' | cargo run --manifest-path crates/codegen/grok-bitcoin-cdk-mint/Cargo.toml
```
