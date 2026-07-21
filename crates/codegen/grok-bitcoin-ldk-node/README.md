# grok-bitcoin-ldk-node

Out-of-process **LDK BOLT11 pay / receive-invoice helper** for `grok-bitcoin-wallet`
(feature `ldk`).

## Why a separate binary?

`ldk-node` pulls `rusqlite 0.31` / `libsqlite3-sys` (`links = "sqlite3"`). The
shell monorepo stays on `rusqlite 0.37` (FTS5 / sqlite-vec / CVE pins). Those
two pins **cannot** share one Cargo dependency graph — not even as separate
workspace members under resolver=2. This crate is therefore:

- **Excluded** from the root workspace (`Cargo.toml` `exclude`)
- Built with its **own** `--manifest-path` (own `Cargo.lock`)
- Talked to over **stdin/stdout JSON** (seed material never on argv/env/disk plaintext)

Do **not** add this crate as a workspace member. Do **not** link `ldk-node`
into default CI packages (`xai-grok-shell`, `xai-grok-pager`, …).

## Build / install

### Nix / flake (recommended)

Isolated crane package — same fileset pattern as `cargo-mem-guard`. Crane **never**
sees the monorepo `Cargo.toml`, so `ldk-node` is not linked into default `grok-oss`
or monorepo `cargoArtifacts`.

```bash
# Build the helper only:
nix build .#grok-bitcoin-ldk-node

# Put it on PATH for this shell:
nix shell .#grok-bitcoin-ldk-node

# Or run once (stdin JSON IPC):
echo '{"v":1,"cmd":"ping"}' | nix run .#grok-bitcoin-ldk-node

# Point product wallet at the result store path (or a copy on PATH):
export GROK_BITCOIN_LDK_NODE_BIN="$(nix build .#grok-bitcoin-ldk-node --print-out-paths)/bin/grok-bitcoin-ldk-node"

# Opt-in pure-nix package + unit tests (long; not default CI / not `just test`):
just ldk-node
```

Flake exports:

| Attr | Role |
|------|------|
| `packages.<system>.grok-bitcoin-ldk-node` | Install package (`meta.mainProgram`; `doCheck = false`; shared `cargoArtifacts`) |
| `checks.<system>.grok-bitcoin-ldk-node-tests` | Helper unit tests only (same artifacts; **not** a second install package under checks) |
| `apps.<system>.grok-bitcoin-ldk-node` | `nix run` |

The install package is **packages-only** (unlike tiny `cargo-mem-guard`) so
`nix flake check` does not double-build the full LDK pure graph. Flake check
still runs `…-tests` once — that graph is heavy; prefer `just ldk-node` or
host cargo over casual flake check as a pre-push gate.

Default monorepo packages / CI quality jobs still **do not** enable feature `ldk`
or pull `ldk-node` into the workspace graph. Optional GHA job `ldk-node-helper`
builds this excluded crate with cargo only.

### Cargo (dev)

```bash
# From monorepo root:
cargo build --manifest-path crates/codegen/grok-bitcoin-ldk-node/Cargo.toml --release

# Binary:
#   crates/codegen/grok-bitcoin-ldk-node/target/release/grok-bitcoin-ldk-node
# or debug:
#   crates/codegen/grok-bitcoin-ldk-node/target/debug/grok-bitcoin-ldk-node

# Optional install onto PATH:
install -m 755 \
  crates/codegen/grok-bitcoin-ldk-node/target/release/grok-bitcoin-ldk-node \
  ~/.local/bin/grok-bitcoin-ldk-node
```

## Environment

| Env | Role |
|-----|------|
| `GROK_BITCOIN_LDK_NODE_BIN` | Absolute path to this helper (preferred) |
| `GROK_BITCOIN_LDK_STORAGE` | Absolute base dir for LDK state (per-seed subdir appended) |
| `GROK_BITCOIN_LDK_ESPLORA_URL` / `GROK_BITCOIN_ESPLORA_URL` | Esplora REST base for chain sync |
| `GROK_BITCOIN_NETWORK` | Product network (`mainnet` / `signet` / `testnet` / `testnet4`) |

When `GROK_BITCOIN_LDK_NODE_BIN` is unset, the wallet looks for a sibling of the
current executable named `grok-bitcoin-ldk-node`, then `PATH`.

## Product wire

1. Build shell/pager with optional feature: `--features ldk` on
   `grok-bitcoin-wallet` / `xai-grok-shell` (not default CI).
2. Install this helper and set `GROK_BITCOIN_LDK_NODE_BIN` (or PATH).
3. CLI `grok routstr topup` and TUI `/routstr topup` attempt SeedVault auto-pay
   when `bolt11_pay_live`; on any failure, **P0 invoice QR + external pay** remains.
4. Successful pays still need **outbound channel liquidity** (honest Failed otherwise).
5. BOLT11 **receive invoice** (`create_bolt11_invoice` IPC) is available when
   `bolt11_invoice_live` (feature `ldk` + helper). Creating an invoice does **not**
   prove inbound liquidity; payers may fail to route. SeedVault BIP-39 required
   (same storage isolation as pay). This is a **local** receive path — Routstr
   prepaid float still uses the node `POST /lightning/invoice` path (P0).
6. BOLT12 stays false. Seed never uses CredentialsStore / `provider_credentials.json`.

## Tests (helper only)

```bash
cargo test --manifest-path crates/codegen/grok-bitcoin-ldk-node/Cargo.toml
# Smoke: ping IPC (no mainnet pay)
echo '{"v":1,"cmd":"ping"}' | \
  cargo run --manifest-path crates/codegen/grok-bitcoin-ldk-node/Cargo.toml --quiet
# IPC cmds: ping | pay_bolt11 | create_bolt11_invoice
# residual refuse: open_channel | connect_peer (ok:false residual:… — not unknown cmd)
```

Optional CI job builds **only** this excluded crate — it must not pull `ldk-node`
into the default monorepo quality job.

**Residual honesty:** this helper **recognizes** `open_channel` / `connect_peer`
and returns structured residual failure (`ok:false`, error starts with
`residual:`). It does **not** call ldk-node open/connect APIs and never returns
`ok:true` / a fabricated channel_id. Product keeps `channel_open_live` /
`connect_peer_live` false. Wallet channel wizard peer seed is pure/offline only.

## Security

- Seed / BIP-39 phrase on IPC stdin only; zeroize intermediate buffers.
- Storage dirs must be absolute; per-seed subdirs isolate channel monitors.
- Never invent pay Success without a real transport preimage.
- See `crates/codegen/grok-bitcoin-wallet/SECURITY.md` and
  `docs/bitcoin-routstr/AUTOMATIC_FUNDING.md` Phase C.
