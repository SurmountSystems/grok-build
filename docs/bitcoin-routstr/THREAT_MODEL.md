# Threat model — Bitcoin wallet + Routstr float

## Why this exists

Grok OSS will hold **user funds** (on-chain UTXOs, Lightning channels) and
**hot prepaid balance** on Routstr nodes (session keys / Cashu tokens used to
buy Grok 4.5 inference). Custody mistakes are irreversible. This document is
the source of truth for what we protect, what we refuse to claim, and how
components are separated.

## Assets

| Asset | Sensitivity | Storage rule |
|-------|-------------|--------------|
| BIP-39 mnemonic (12-word default) | **Critical** — roots BDK + LDK + NIP-06 | `SeedVault` only: OS keyring primary; optional password AEAD file; **never** plaintext JSON |
| BIP-39 passphrase (if used) | Critical | Same as mnemonic; never logged |
| BDK descriptors / wallet DB | High | `$GROK_HOME/bitcoin/…` mode 0600; not a substitute for seed protection |
| LDK channel state / keys_seed | Critical | Derived from seed; data dir locked |
| Nostr `nsec` (NIP-06) | Critical | Derived on unlock from mnemonic; npub is public |
| Routstr `sk-…` session key | Medium–high (hot float) | `CredentialsStore` keyring-first; file fallback is **degraded** and documented |
| Cashu tokens (`cashuA…`) | Medium–high (bearer) | Prefer brief hold → spend or vault; never logs/transcripts |
| BOLT11 strings / payment hashes | Medium | Ephemeral OK; don’t stick in chat history |
| On-chain addresses | Low (privacy) | Public; still pair with QR/copy UX |

## Trust boundaries

```
[ User host OS ] ─── SeedVault (keyring) ─── in-memory unlock session
        │                      │
        │                      ├── BDK wallet DB (chain data)
        │                      └── LDK node data dir
        │
        ├── mempool.space / Esplora (sees addresses + queries)     [privacy]
        ├── Routstr node api.routstr.com (sees inference + balance) [hot float]
        ├── Lightning peers (channel counterparties)
        └── Cashu mints (CDK) (see mint operations)
```

**Routstr prepaid balance is custodial float on a third party.** It is not cold
storage. Product copy and refund UX must say so.

## Adversaries and stance

| Threat | Full stop? | Our controls |
|--------|------------|--------------|
| Malware / root on user machine | No | Keyring, zeroize, no secret Debug, short unlock TTL — **cannot** stop host compromise |
| Entropy observation at seed gen | No | `getrandom` CSPRNG; honest docs; offline-import path for high value |
| Disk theft of `$GROK_HOME` | Partial | Seed not in plaintext file; hot `sk-` file fallback residual risk |
| Backup / cloud sync of home dir | Partial | Same; warn against syncing grok home with live wallet |
| Accidental logs / support paste | Yes aim | Redaction; forbid mnemonic in tracing; clipboard hygiene guidance |
| Supply-chain crate bug | Reduce | Pin BDK/LDK/nostr/bip39; feature-gate; tests on upgrade |
| Routstr node rug / drain float | Reduce | Small float; refund-first; don’t encourage large deposits to node |
| Fee grief / wrong network | Reduce | Mainnet default; amount confirms; signet via explicit env |
| mempool.space rate limit / outage | Degrade | Backoff, cache, optional self-hosted explorer later |
| BOLT12 unavailable | Accept | **Defer** BOLT12; BOLT11 + on-chain path required |

## Security properties we commit to

1. **Single BIP-39** derives on-chain (BDK), Lightning (LDK), and Nostr (NIP-06).
2. **Seed never plaintext on disk.**
3. **Explicit wallet create** — no silent mnemonic on first CLI launch.
4. **Backup ritual** — show words once; confirm re-entry; we cannot recover lost seeds.
5. **Every payment address UI** — text + **QR** + **copy**; txids link to mempool.space (or configured explorer).
6. **Hot vs local separation** — Routstr `sk-`/Cashu float ≠ SeedVault funds.
7. **Language honesty** — no “crypto”; Cashu = Chaumian eCash; no fake BOLT12.
8. **Entropy honesty** — OS CSPRNG; no claim of observer-free generation on a shared host.

## Non-claims (do not put in marketing)

- That Grok can protect funds on a compromised OS.
- That `/dev/random` blocking makes generation safe from local observers.
- That Routstr node balance is self-custodial cold storage.
- That public Esplora/mempool.space queries are private.
- That BOLT12 works before the peer + LDK pin are verified.

## Gap: existing `CredentialsStore`

`xai-grok-shell` `CredentialsStore` mirrors Bearer secrets to
`provider_credentials.json` in **plaintext** and uses that as fallback. That
path is **forbidden for BIP-39**. Hot Routstr keys may use it short-term with
documentation; a follow-up should stop plaintext mirrors for new secrets.

## Unlock session

- After unlock, seed-derived material may live in process memory for an idle
  TTL (configurable; conservative default).
- Lock drops zeroized buffers; LN/BDK may need re-hydrate from vault.
- Never write unlock cache to disk.

## Incident expectations

If seed material is logged or written plaintext: treat as **severity-0**, rotate
guidance (user must move funds to a new seed — we cannot rotate for them), and
fix the bug before further wallet features ship.
