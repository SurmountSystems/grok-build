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
| `onchain` | BIP84 receive address (bitcoin+bip32; full BDK residual) |
| `address_ux` | PaymentDisplay, BIP21, mempool.space URLs, QR ascii |
| `explorer` | RateLimitedExplorer; optional `explorer-http` MempoolHttpClient |
| `watcher` | Address/tx poll → FundingWizard confirmations (injected producer) |
| `funding_cli` | Backup gate + unlock session before ShowAddress (CLI product path) |
| `lightning` | `LightningCapability` trait + channel wizard; `BOLT12_SUPPORTED=false` |
| `cashu` | CashuToken + FundingWizard (backup gate before ShowAddress) |

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
| BIP84 receive address | done (not full BDK wallet) |
| LDK pay / BOLT12 | stub / deferred |
| CDK Cashu mint/spend | types + wizard only |
