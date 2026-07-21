# Security rules for `grok-bitcoin-wallet`

**Read with** `docs/bitcoin-routstr/THREAT_MODEL.md`.

## SeedVault invariants

1. Mnemonic / seed bytes **never** written as plaintext to disk.
2. Primary store: **OS keyring** (service label dedicated to wallet seed;
   do not reuse OpenRouter Bearer JSON mirror behavior).
3. Fallback: **password-based AEAD** only (Argon2id + XChaCha20-Poly1305 or
   AES-256-GCM), with UX that states degraded portability / password loss =
   fund loss.
4. **Forbidden AEAD / on-disk seed paths** (enforced by
   `assert_allowed_seed_storage_path` on constructor + `store_aead` /
   `store_aead_entropy` / `load_aead` / `delete_aead`):
   `provider_credentials.json`, `watch_session.json`, `config.toml`. Also
   never: session transcripts, debug logs, panic messages.
5. AEAD / keyring payload is **BIP-39 seed material only** — never a passphrase
   field. AEAD v1 = phrase UTF-8 (`store_aead`); AEAD v2 = raw entropy 16/32
   bytes (`store_aead_entropy`); `load_aead` accepts both. New AEAD writes
   bind format `v` as AAD; legacy pre-AAD v1 still loads. Keyring stays
   phrase string for OS UX. Optional BIP-39 **passphrase** is unlock-time only
   (`GROK_BITCOIN_BIP39_PASSPHRASE` / API `&str`) — **never** a SeedVault
   payload field or at-rest JSON key.
6. Types holding secrets: no `Debug`/`Display` of secret material (including
   `EntropyBytes`); use `zeroize` on drop; prefer `secrecy` where ergonomic.
7. Unlock session: idle timeout; lock zeroizes derived key material.

## What may use shell `CredentialsStore`

- Routstr hot `sk-` / short-lived Cashu strings for inference HTTP only.
- **Never** BIP-39, raw entropy, or LDK seed.

`CredentialsStore` is the hot API-key store (keyring `grok-build` **plus**
plaintext `$GROK_HOME/provider_credentials.json` mirror). It is **not** “the OS
keyring” in general. OpenRouter keys found in Zed use a **different** schema and
are read-only via shell `harness_secrets`. SeedVault has its own keyring service.
Product plan: `docs/bitcoin-routstr/AUTOMATIC_FUNDING.md`.

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

## Lightning auto-pay (Phase C)

- BOLT11 pay uses **SeedVault unlock** only (`pay_bolt11_with_seed`). Never
  BIP-39 / LDK seed via CredentialsStore or `provider_credentials.json`.
- Zeroize intermediate seed bytes after derive; no `Debug` of mnemonic/seed.
- Never invent `PayOutcome::Success` without a transport that reported a real
  send (mock OK for adapter unit tests; process helper must not fabricate).
- Feature `ldk` → `LdkLightning` with **`bolt11_pay_live=true`** via
  **out-of-process** helper `grok-bitcoin-ldk-node` (owns `ldk-node` +
  rusqlite 0.31). Shell stays on rusqlite 0.37; do not co-link both
  (`links=sqlite3`). Seed on IPC stdin only — never argv/env/disk plaintext.
- CLI + TUI topup auto-pay use SeedVault unlock only (`apply_local_bolt11_pay` /
  `complete_routstr_topup_local_pay_reentry_for_tui`). Liquidity honesty only
  after a real pay attempt — not unlock cancel / missing vault.
- Default builds (no `ldk`): stub, live flags false, invoice-first P0.
- Do not enable `ldk` in default CI until product packaging ships the helper.
  Optional CI may build the **excluded** helper crate alone (never workspace
  member). See `crates/codegen/grok-bitcoin-ldk-node/README.md` and
  `GROK_BITCOIN_LDK_NODE_BIN`.

## Dependency discipline

- Pin `bip39`, `bdk_wallet` (**2.4.x** behind feature `bdk`; bitcoin 0.32),
  `ldk-node` (helper crate), `nostr`/`nostr-sdk`, `getrandom`, `cdk` versions;
  bump with smoke tests.
- Feature-gate heavy LN / BDK deps so default unit tests stay light and offline.
- Keep `grok-bitcoin-ldk-node` **excluded** from the monorepo workspace
  (resolver would reintroduce the rusqlite conflict).
- Do not enable `ldk` / `cashu-cdk` / `bdk` in default CI until product packaging
  opts in (`bdk` is offline-proveable via mock updates + Esplora/Electrum
  transport fixtures; live HTTP/TCP only with composite `bdk`+`esplora`/`electrum`;
  still not default graph). Product prefer-BDK is opt-in env
  `GROK_BITCOIN_UTXO_SYNC=bdk` (default gap); never invent Success when feature
  or chain transport is missing.

## Review checklist (every PR touching this crate)

- [ ] No new plaintext secret path
- [ ] No `crypto` wording in user strings
- [ ] Cashu described as Chaumian eCash on first user-facing mention if added
- [ ] NIP-06 vector test still passes if derivation touched
- [ ] Rate-limit / backoff if mempool HTTP touched
- [ ] QR+copy for new payment displays
