# Security rules — `grok-bitcoin-wallet`

**Read with** `docs/bitcoin-routstr/THREAT_MODEL.md`.

## SeedVault invariants

1. Mnemonic / seed bytes **never** written as plaintext to disk.
2. Primary store: **OS keyring** (service label dedicated to wallet seed —
   do not reuse OpenRouter Bearer JSON mirror behavior).
3. Fallback: **password-based AEAD** only (Argon2id + XChaCha20-Poly1305 or
   AES-256-GCM), with UX that states degraded portability / password loss =
   fund loss.
4. **Forbidden:** `$GROK_HOME/provider_credentials.json`, `config.toml`,
   session transcripts, debug logs, panic messages.
5. Types holding secrets: no `Debug`/`Display` of secret material; use
   `zeroize` on drop; prefer `secrecy` where ergonomic.
6. Unlock session: idle timeout; lock zeroizes derived key material.

## What may use shell `CredentialsStore`

- Routstr hot `sk-` / short-lived Cashu strings for inference HTTP only.
- **Never** BIP-39 or raw LDK seed.

## Payment UI

- Any address/invoice shown in product UI must support **QR + copy**
  (`docs/bitcoin-routstr/ADDRESS_UX.md`).
- txids: mempool.space (or configured explorer) links.

## Network

- Default **Bitcoin mainnet** for release.
- Dev: `GROK_BITCOIN_NETWORK=signet` (or testnet) explicit.
- Do not ship mainnet channel opens without amount confirmation.

## BOLT12

- Only expose BOLT12 UI when runtime peer + LDK pin support it.
- Otherwise defer; BOLT11 remains.

## Dependency discipline

- Pin `bip39`, `bdk_wallet`, `ldk-node`, `nostr`/`nostr-sdk`, `getrandom`,
  `cdk` versions in workspace; bump with smoke tests.
- Feature-gate heavy LN deps so unit tests of pure seed logic stay light.

## Review checklist (every PR touching this crate)

- [ ] No new plaintext secret path
- [ ] No `crypto` wording in user strings
- [ ] Cashu described as Chaumian eCash on first user-facing mention if added
- [ ] NIP-06 vector test still passes if derivation touched
- [ ] Rate-limit / backoff if mempool HTTP touched
- [ ] QR+copy for new payment displays
