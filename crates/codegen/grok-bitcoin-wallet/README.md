# grok-bitcoin-wallet

Surmount **Grok OSS** library for Bitcoin-native funding of **Routstr**
inference (headline: **Grok 4.5**), with rigorous local custody.

Reasoning: [`docs/bitcoin-routstr/`](../../../docs/bitcoin-routstr/README.md).

## Modules (current)

| Module | Role |
|--------|------|
| `mnemonic` | BIP-39 generate (`getrandom`) / import / validate / zeroize |
| `seed_vault` | OS keyring + AEAD file; `UnlockSession` TTL; `MnemonicBackupGate` |
| `nip06` | NIP-06 npub; nsec/hex only via controlled API |
| `nip98` | Pure NIP-98 `Nostr <base64>` Authorization build/parse + request-match (offline; not product Routstr wire — Bearer residual; product refuses NIP-98 store) |
| `onchain` | BIP84 receive address (bitcoin+bip32) |
| `descriptor_wallet` | BIP84 descriptors + **default** gap-limit UTXO sync/spend + fee-aware coin select + PSBT build/sign/finalize/extract + RBF/CPFP + broadcaster. **Structure:** wallet core (PR2) + `bare_tapscript/` families (PR3) + `finalize.rs` (PR4 Option A) + dual-hash `and_v` keep set only (PR5); `mod.rs` ~tree/re-exports; tests ~38k (see repo `RESIDUAL.md`) |
| `bdk_sync` | Real `bdk_wallet` BIP84 auto-sync (feature **`bdk`**, not default CI): spent-tx history + keychain index; injectable `BdkUpdateSource` + offline mock; Esplora/Electrum full_scan transport adapters; product list/spend-from-snapshot + `open_product_bdk_update_source`. Shell prefer-BDK via `GROK_BITCOIN_UTXO_SYNC=bdk` (default gap). |
| `chain_select` | Product env selector for live `ChainSource` **and** `TxBroadcaster` (`GROK_BITCOIN_CHAIN_SOURCE` = mempool\|esplora\|electrum; default mempool; feature-honest open; UTXO + push aligned) + `GROK_BITCOIN_UTXO_SYNC` = gap\|bdk (default gap) |
| `esplora` | Esplora REST `ChainSource` + `EsploraTxBroadcaster` (`POST /tx`) + pure path/join helpers; `MockEsploraTransport` offline fixtures; live `HttpEsploraTransport` behind feature `esplora` (not default CI) |
| `electrum` | Electrum JSON-RPC `ChainSource` + `ElectrumTxBroadcaster` (`blockchain.transaction.broadcast`) + scripthash/listunspent pure parse; `MockElectrumTransport` offline fixtures; live plaintext `TcpElectrumTransport` **and** TLS `TlsElectrumTransport` (rustls + WebPKI roots; no skip-verify) behind feature `electrum` (not default CI) |
| `address_ux` | PaymentDisplay, BIP21, mempool.space URLs, QR ascii |
| `explorer` | RateLimitedExplorer; `TxBroadcaster` + fee estimates parse; optional `explorer-http` MempoolHttpClient (GET + fees/recommended + POST `/api/tx`) |
| `watcher` | Address/tx poll → FundingWizard confirmations (injected producer) |
| `funding_cli` | Backup gate + unlock before ShowAddress; spend/RBF/CPFP/utxos parse + fee-ladder + gap-sync UTXO list CLI lines; topup/refund via `default_*_backend` seams; receive QR lines |
| `lightning` | `LightningCapability` + `default_lightning_backend()`; invoice/pay outcomes; channel wizard; `BOLT12_SUPPORTED=false` |
| `cashu` | CashuToken + `CashuBackend` + `default_cashu_backend()`; FundingWizard |

## Docs

- [`SECURITY.md`](./SECURITY.md): invariants for reviewers
- [`docs/bitcoin-routstr/`](../../../docs/bitcoin-routstr/): threat model,
  funding flow, address UX, derivation, Routstr inference, ADRs
- Repo root [`RESIDUAL.md`](../../../RESIDUAL.md): remaining BDK/LDK/CDK work

## Language

Bitcoin / Lightning / Cashu (Chaumian eCash). Never “crypto.”

## Status

| Phase | State |
|-------|--------|
| Reasoning docs | done |
| SeedVault + BIP-39 + NIP-06 | done (unit tested) |
| Unlock TTL + backup gate | done (unit tested) |
| Address UX + rate-limited explorer | done |
| mempool.space HTTP (`explorer-http`) | done (ignored live test) |
| Esplora / Electrum ChainSource + push | done (injectable mock transports + pure parsers always; live HTTP/TCP/TLS feature-gated `esplora` / `electrum`, not default CI; `POST /tx` + `blockchain.transaction.broadcast`; Electrum TLS via rustls + WebPKI) |
| Product chain select (shell spend) | done (`chain_select`: env `GROK_BITCOIN_CHAIN_SOURCE` + `GROK_BITCOIN_ESPLORA_URL` / `GROK_BITCOIN_ELECTRUM_ADDR` + optional `GROK_BITCOIN_ELECTRUM_TLS` or `ssl://host:port`; default mempool + electrum plaintext; UTXO + broadcaster aligned; feature-missing → runtime structured error; shell/pager-bin optional `esplora`/`electrum` not default) |
| Product gap-sync spend wire | done (`select_and_prepare_bip84_spend_with_gap_sync` → sync then select-from-snapshot; no post-sync list; `GapSyncSpendFailure::{Sync,AfterSync}` so hit-max / extend notices surface on select/prepare Err; shell `complete_routstr_spend_with_mnemonic`; RBF/CPFP explicit prevouts unchanged; default path — gap-limit, not BDK) |
| Product gap-sync UTXO list / balance | done (`list_bip84_utxos_with_gap_sync` + pure CLI format helpers; shell `grok routstr utxos` + TUI `/routstr utxos` staged unlock; snapshot authoritative — no extra list; wrong passphrase fail-closed; default path — gap-limit) |
| `bdk_wallet` auto-sync | **done (feature `bdk`, not default CI)** — pin `bdk_wallet` 2.4; library transports + product helpers; **shell prefer-BDK wire** (`GROK_BITCOIN_UTXO_SYNC=bdk`, shell/pager-bin feature `bdk`; default gap; mempool+bdk residual; without feature residual). Tests: `cargo test -p grok-bitcoin-wallet --lib --features bdk`; shell: `cargo test -p xai-grok-shell --lib --features bdk` |
| BIP84 receive address | done |
| Descriptor wallet + fee-aware UTXO select + PSBT + broadcast | **done (product)** for BIP84 gap-sync spend + sign/finalize/extract + TxBroadcaster; optional BDK sync under feature `bdk`. Offline finalize covers policy-shaped Taproot/script forms. Engineering unfuck PR0–PR5 **done** (finalize peeled; dual-hash `and_v` pruned to 5 canonical forms) — see repo `RESIDUAL.md` |
| RBF/CPFP fee planners + mempool fee ladder | done (pure BIP-125 / package guidance; product fee meta; live halfHour when `explorer-http`; CLI `grok routstr fees`) |
| RBF replacement rebuild/broadcast | done (same-input `prepare_rbf_replacement` + CLI `grok routstr rbf` + TUI `/routstr rbf` staged unlock; dry-run default; absolute BIP-125 fee; broadcast only after unlock + Accepted) |
| CPFP child rebuild/broadcast | done (`prepare_cpfp_child` + CLI `grok routstr cpfp` + TUI `/routstr cpfp` staged unlock; child only, never claims parent replaced; dry-run default; broadcast only after unlock + Accepted) |
| WatchSession persistence (no BIP-39) | done (`{GROK_HOME}/bitcoin/watch_session.json`; pager resume on restart) |
| LDK pay / BOLT12 | feature `ldk` → out-of-process `grok-bitcoin-ldk-node` (`bolt11_pay_live=true`); default CI stub; BOLT12 false; CLI+TUI SeedVault auto-pay when live |
| CDK Cashu mint/spend | capability seams + default backend factory; stubs never claim live mint/refund; optional `cashu-cdk` feature flag only |
