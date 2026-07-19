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
| `descriptor_wallet` | BIP84 descriptors + `list_unspent` / fee-aware `select_coins` + mock/`MempoolChainSource` (`explorer-http`); unsigned PSBT + BIP84 P2WPKH sign/finalize/extract; `TxBroadcaster` submit |
| `address_ux` | PaymentDisplay, BIP21, mempool.space URLs, QR ascii |
| `explorer` | RateLimitedExplorer; `TxBroadcaster` + optional `explorer-http` MempoolHttpClient (GET + POST `/api/tx`) |
| `watcher` | Address/tx poll → FundingWizard confirmations (injected producer) |
| `funding_cli` | Backup gate + unlock before ShowAddress; spend parse helpers; topup/refund via `default_*_backend` seams; receive QR lines |
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
| BIP84 receive address | done |
| Descriptor wallet + fee-aware UTXO select + PSBT + broadcast | done (sign/finalize/extract + TxBroadcaster; CLI/TUI dry-run default; multi-sig/non-P2WPKH finalize is honest Partial only) |
| WatchSession persistence (no BIP-39) | done (`{GROK_HOME}/bitcoin/watch_session.json`; pager resume on restart) |
| LDK pay / BOLT12 | stub / deferred (`BOLT12_SUPPORTED=false`; optional `ldk` feature flag only) |
| CDK Cashu mint/spend | capability seams + default backend factory; stubs never claim live mint/refund; optional `cashu-cdk` feature flag only |
