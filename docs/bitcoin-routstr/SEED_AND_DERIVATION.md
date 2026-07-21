# Seed and derivation

## Single mnemonic policy

One **BIP-39** mnemonic (English, **12 words** default) is the root of:

| Child | Standard / stack | Purpose |
|-------|------------------|---------|
| On-chain keys | BDK descriptors (BIP84 or BIP86; pick at implement; document) | Receive/send mainnet Bitcoin |
| Lightning | LDK / `ldk-node` seed API from BIP-39 seed bytes | Channels, BOLT11 (BOLT12 when enabled) |
| Nostr | **NIP-06** `m/44'/1237'/0'/0/0` via `nostr` nip06 | `npub` public; `nsec` only when unlocked |

Do **not** generate a disconnected random `nsec` by default. Advanced
nsec-only import may exist later as an escape hatch.

## Entropy

- Generate with **`getrandom`** (Linux: `/dev/urandom` CSPRNG).
- **Honest limit:** we cannot guarantee another process is not observing
  entropy or memory at generation time.
- High-value users: generate offline and **import** mnemonic into SeedVault.
- We do not require `/dev/random` blocking reads; they do not fix local observers.

## SeedVault (storage)

| Allowed | Forbidden |
|---------|-----------|
| OS keyring with **dedicated** SeedVault service label (not Bearer `grok-build`) | Plaintext in `provider_credentials.json` |
| Password-wrapped AEAD blob (Argon2id + XChaCha20-Poly1305) with warning UX | `CredentialsStore` (mirrors API keys to JSON) |
| In-memory unlock with TTL + zeroize | Zed keyring / Dev credentials files |
| Payload = **BIP-39 seed material only** (phrase and/or entropy bytes) | `watch_session.json` (watch progress only; SeedVault refuses this filename) |
| | `config.toml`, session JSON, chat transcripts |
| | BIP-39 **passphrase** at rest (unlock env/API only) |
| | Debug-printing mnemonic / entropy |

**Path guard (offline-enforced):** `assert_allowed_seed_storage_path` refuses
AEAD paths whose final component is `provider_credentials.json`,
`watch_session.json`, or `config.toml` (constructor + `store_aead` /
`store_aead_entropy` / `load_aead` / `delete_aead`). Legacy alias:
`assert_not_credentials_store_path`.

**Not the same as OpenRouter/Zed keys:** Grok’s `CredentialsStore` uses service
`grok-build` and always mirrors secrets into `provider_credentials.json`. Zed
OpenRouter keys are **read-only** probed under a different schema
(`harness_secrets`). Seed must not use either path. See
[AUTOMATIC_FUNDING.md](./AUTOMATIC_FUNDING.md) “Secret stores.”

**AEAD encoding (landed):** BIP-39 words are a human backup encoding of
~128-bit (12-word) or ~256-bit (24-word) entropy.

| Version | Store API | Plaintext under AEAD |
|---------|-----------|----------------------|
| **v1** (legacy / default `store_aead`) | phrase UTF-8 string | space-separated English words |
| **v2** (`store_aead_entropy`) | raw entropy bytes | 16 bytes (12-word) or 32 bytes (24-word) |

`load_aead` accepts **both** v1 and v2 and reconstructs `MnemonicSecret` via
bip39. New AEAD writes bind format version as **AEAD AAD** (`v` little-endian)
so envelope `v` cannot be flipped without failing the tag. Pre-AAD **v1**
blobs still load (AAD decrypt first, then unbound fallback for `v == 1`
only). **v2** always requires AAD. Keyring remains **phrase string** for OS
password-field UX (entropy bytes would be opaque/binary). Neither encoding
embeds a BIP-39 passphrase field. Still **never** CredentialsStore /
`watch_session` / `provider_credentials`.

See crate `SECURITY.md` for API rules.

## NIP-06 test vector (mandatory unit test)

From [NIP-06](https://nips.nostr.com/6):

- Mnemonic: `leader monkey parrot ring guide accident before fence cannon height naive bean`
- Expected private key hex: `7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a`

Implementation: `nostr::Keys::from_mnemonic` / `FromMnemonic` with nip06 feature.

## Backup UX

1. Generate → show 12 words **once** (numbered).
2. Require re-entry of all words (or full phrase) before wallet is marked ready.
3. Never re-display without unlock + explicit “show recovery phrase” + warning.
4. State clearly: **lose the words ⇒ lose the funds; Grok cannot recover them.**

## Import

- Accept 12/24-word BIP-39 with checksum validation.
- Confirm destructive replace if a wallet already exists.
- Same derivation paths as generate.

## Passphrase (advanced)

Optional BIP-39 passphrase changes all children; must be backed up separately;
empty passphrase is the default path.

Product spend / RBF / CPFP / fund address paths accept a passphrase via the
process env **`GROK_BITCOIN_BIP39_PASSPHRASE`** at unlock/sign time only
(library `prepare_*` / `*_from_selection` and product prepares take
`passphrase: &str`). TUI private re-entry: `/routstr unlock pass …` opens a
masked modal (empty Enter = default path for that unlock; never chat history).
It is **never** stored in SeedVault (AEAD/keyring payload is seed material
only — phrase v1 or entropy v2; **no** passphrase field), CredentialsStore,
`watch_session.json`, or chat. Unit tests cover AEAD plaintext = phrase or
entropy bytes (never passphrase JSON) and watch-session JSON without
mnemonic/passphrase keys. Missing/empty env (and no modal override) → default
path.
