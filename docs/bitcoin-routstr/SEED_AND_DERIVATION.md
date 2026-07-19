# Seed and derivation

## Single mnemonic policy

One **BIP-39** mnemonic (English, **12 words** default) is the root of:

| Child | Standard / stack | Purpose |
|-------|------------------|---------|
| On-chain keys | BDK descriptors (BIP84 or BIP86 — pick at implement; document) | Receive/send mainnet Bitcoin |
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
| OS keyring (`grok-build` / dedicated service label for seed) | Plaintext in `provider_credentials.json` |
| Password-wrapped AEAD blob (Argon2id + XChaCha20-Poly1305) with warning UX | `config.toml`, session JSON, chat transcripts |
| In-memory unlock with TTL + zeroize | Debug-printing mnemonic |

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

## Passphrase (advanced, post-v1 ok)

Optional BIP-39 passphrase changes all children; must be backed up separately;
empty passphrase is the default path.
