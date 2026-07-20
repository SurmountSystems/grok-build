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
| `onchain` | BIP84 receive address (bitcoin+bip32) |
| `descriptor_wallet` | BIP84 descriptors + `list_unspent` / gap-limit `sync_utxos` + `sync_with_gap_extend` + product `list_bip84_utxos_with_gap_sync` (snapshot-authoritative UTXO list/balance — no extra list) + product `select_and_prepare_bip84_spend_with_gap_sync` (select-from-snapshot after sync — no extra list; `GapSyncSpendFailure` AfterSync carries hit-max notices on Err; BIP44-style default stop-gap look-ahead 20; hard `MAX_ADDRESS_GAP` on construct+extend; not full bdk auto-sync) / `select_and_prepare_bip84_spend_from_utxos` / fee-aware `select_coins` + mock/`MempoolChainSource` (`explorer-http`); unsigned PSBT + BIP84 P2WPKH sign/finalize/extract; RBF/CPFP fee planners; RBF replacement rebuild; `TxBroadcaster` submit |
| `chain_select` | Product env selector for live `ChainSource` **and** `TxBroadcaster` (`GROK_BITCOIN_CHAIN_SOURCE` = mempool\|esplora\|electrum; default mempool; feature-honest open; UTXO + push aligned) |
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
| Product gap-sync spend wire | done (`select_and_prepare_bip84_spend_with_gap_sync` → sync then select-from-snapshot; no post-sync list; `GapSyncSpendFailure::{Sync,AfterSync}` so hit-max / extend notices surface on select/prepare Err; shell `complete_routstr_spend_with_mnemonic`; RBF/CPFP explicit prevouts unchanged; **not** full bdk auto-sync) |
| Product gap-sync UTXO list / balance | done (`list_bip84_utxos_with_gap_sync` + pure CLI format helpers; shell `grok routstr utxos` + TUI `/routstr utxos` staged unlock; snapshot authoritative — no extra list; wrong passphrase fail-closed; **not** full bdk auto-sync) |
| BIP84 receive address | done |
| Descriptor wallet + fee-aware UTXO select + PSBT + broadcast | done (sign/finalize/extract + TxBroadcaster; CLI/TUI dry-run default; **gap-limit ChainSource sync** via `sync_utxos` / `sync_with_gap_extend` / product gap-sync spend with hard `MAX_ADDRESS_GAP` — **not** full `bdk_wallet` auto-sync; offline finalize: P2WPKH/P2SH-P2WPKH/P2PKH/single-CHECKSIG P2WSH + bare m-of-n CHECKMULTISIG P2WSH when enough partial_sigs + Taproot **key-path** when `tap_key_sig` present + Taproot **script-path** bare x-only CHECKSIG / multi_a CHECKSIGADD / thresh SWAP-CHECKSIG-ADD k-of-n / and_v CHECKSIGVERIFY chain / or_i IF-ELSE / or_d IFDUP-NOTIF / and_n NOTIF-0 dual CHECKSIG / andor NOTIF-ELSE triple CHECKSIG / bare miniscript hash (sha256/hash256/hash160/ripemd160) when matching PSBT preimage / and_v(v:pk, hash) when sig+preimage present / older/CSV (`and_v(v:pk, older)` / `and_v(v:older, pk)` / bare `older`) when matching sig + already-present nSequence satisfies BIP-112 / after/CLTV (`and_v(v:pk, after)` / `and_v(v:after, pk)` / bare `after`) when matching sig + already-present nLockTime satisfies BIP-65 with non-final nSequence when present `tap_scripts` + material verify; preserve finals; insufficient threshold / other complex script-path miniscript (or_c/…) stay Partial; never invents nSequence/nLockTime) |
| RBF/CPFP fee planners + mempool fee ladder | done (pure BIP-125 / package guidance; product fee meta; live halfHour when `explorer-http`; CLI `grok routstr fees`) |
| RBF replacement rebuild/broadcast | done (same-input `prepare_rbf_replacement` + CLI `grok routstr rbf` + TUI `/routstr rbf` staged unlock; dry-run default; absolute BIP-125 fee; broadcast only after unlock + Accepted) |
| CPFP child rebuild/broadcast | done (`prepare_cpfp_child` + CLI `grok routstr cpfp` + TUI `/routstr cpfp` staged unlock; child only, never claims parent replaced; dry-run default; broadcast only after unlock + Accepted) |
| WatchSession persistence (no BIP-39) | done (`{GROK_HOME}/bitcoin/watch_session.json`; pager resume on restart) |
| LDK pay / BOLT12 | stub / deferred (`BOLT12_SUPPORTED=false`; optional `ldk` feature flag only) |
| CDK Cashu mint/spend | capability seams + default backend factory; stubs never claim live mint/refund; optional `cashu-cdk` feature flag only |
