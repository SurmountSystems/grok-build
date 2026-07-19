# grok-bitcoin-wallet

Surmount **Grok OSS** library for Bitcoin-native funding of **Routstr**
inference (headline: **Grok 4.5**), with rigorous local custody.

> **Pre-implementation:** reasoning lives in
> [`docs/bitcoin-routstr/`](../../../docs/bitcoin-routstr/README.md).
> This crate starts as docs + a minimal placeholder lib so the workspace path
> and security rules exist before heavy BDK/LDK deps land.

## Responsibilities (target)

| Module (planned) | Role |
|------------------|------|
| `seed_vault` | BIP-39 at rest (keyring / AEAD) — **not** plaintext JSON |
| `mnemonic` | Generate (`getrandom`) / import / zeroize |
| `nostr_nip06` | NIP-06 npub/nsec from same mnemonic |
| `onchain` | BDK receive/send; always-on address |
| `lightning` | LDK BOLT11; BOLT12 when available (else deferred) |
| `watchers` | Confirmation tracking; mempool.space RL-aware client |
| `cashu` / CDK | Chaumian eCash acquire/spend for Routstr |
| `address_ux` helpers | QR payload + clipboard string helpers |

## Docs

- [`SECURITY.md`](./SECURITY.md) — invariants for reviewers
- [`docs/bitcoin-routstr/`](../../../docs/bitcoin-routstr/) — threat model,
  funding flow, address UX, derivation, Routstr inference, ADRs

## Language

Bitcoin / Lightning / Cashu (Chaumian eCash) — never “crypto.”

## Status

| Phase | State |
|-------|--------|
| Reasoning docs | done (repo `docs/bitcoin-routstr`) |
| Placeholder crate | this package |
| SeedVault + BIP-39 + NIP-06 | next |
| BDK + watchers + QR | planned |
| LDK channel + CDK spend | planned |
| Routstr glue in shell/pager | planned (separate modules) |
