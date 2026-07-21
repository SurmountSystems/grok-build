# Decisions (ADR-style)

Format: context → decision → consequences. Update when we change direction.

---

## ADR-001: Two-layer architecture (local wallet ≠ Routstr float)

**Context:** Users must pay Routstr for Grok 4.5 without confusing node prepaid
balance with self-custodial funds.

**Decision:** Layer 1 = OpenAI-compatible Routstr HTTP + hot `sk-`/Cashu.
Layer 2 = local BIP-39 SeedVault + BDK + LDK + NIP-06. Funding wizard bridges
them.

**Consequences:** More code; clearer threat model; refund UX required.

---

## ADR-002: SeedVault separate from CredentialsStore

**Context:** `CredentialsStore` is the OpenRouter-style hot API-key store:
OS keyring service `grok-build` **and** a plaintext mirror at
`$GROK_HOME/provider_credentials.json`. API is UTF-8 strings only. Zed’s
OpenRouter keys live under a **different** schema (`zed-github-account` /
platform keychain); Grok only **probes** them read-only via `harness_secrets`
and never writes Zed.

**Decision:** Wallet seed material (BIP-39 mnemonic, raw entropy, LDK seed)
**never** uses CredentialsStore or Zed stores. SeedVault uses a **dedicated**
keyring service plus optional password AEAD file. AEAD path must pass
`assert_allowed_seed_storage_path` (refuses `provider_credentials.json`,
`watch_session.json`, `config.toml`). Payload is **seed material only**
(AEAD v1 = phrase UTF-8; AEAD v2 = raw BIP-39 entropy 16/32 bytes via
`store_aead_entropy`; keyring stays phrase for OS UX). BIP-39 passphrase is
unlock env/API only (never SeedVault / watch session / CredentialsStore at
rest). Entropy encoding is **landed** for AEAD (still never CredentialsStore).

**Consequences:** Two secret APIs; contributors must not “just put seed in
CredentialsStore because OpenRouter is in the keyring.” See
[AUTOMATIC_FUNDING.md](./AUTOMATIC_FUNDING.md) secret-stores section.

---

## ADR-003: Single BIP-39 → BDK + LDK + NIP-06

**Context:** Multiple seeds destroy UX and backup discipline.

**Decision:** One mnemonic; NIP-06 for Nostr; no random nsec by default.

**Consequences:** NIP-06 is “unrecommended” in NIP text for some clients. Still
correct for our single-backup story; document advanced nsec import later.

---

## ADR-004: Seamless path = deposit → channel → CDK → inference

**Context:** Approval goal is out-of-the-box Routstr Grok 4.5 with local keys.

**Decision:** Default wizard automates on-chain deposit watch, channel to
Routstr-recommended peer, CDK Cashu acquire, then inference spend.

**Consequences:** Depends on Routstr peer quality and CDK mint availability;
escape hatches required.

---

## ADR-005: BOLT12 deferred when unsupported

**Context:** Not all peers/LDK pins support offer routing.

**Decision:** BOLT11 + on-chain are mandatory. BOLT12 is best-effort; **defer**
without blocking v1 if unsupported. Never label BOLT11-only as BOLT12.

**Consequences:** Honest UI; revisit when stack is ready.

---

## ADR-006: Every address gets QR + copy

**Context:** Payment UX fails if users retype bech32/bolt11.

**Decision:** Any shown payment endpoint includes QR + clipboard
([ADDRESS_UX.md](./ADDRESS_UX.md)).

**Consequences:** TUI QR dependency; narrow-terminal fallback.

---

## ADR-007: mempool.space watchers with rate limits

**Context:** Need confirmation UX and txid links without ban/outage fragility.

**Decision:** Default explorer mempool.space; shared rate-limited fetcher;
txid/address deep links; trait for future local node/index backends.

**Consequences:** Privacy tradeoff documented; local backends later.

---

## ADR-008: Routstr default on; wallet create explicit

**Context:** Discoverability vs silent seed generation.

**Decision:** `routstr_enabled` default true. Mnemonic only after explicit
“Create Bitcoin wallet” + backup confirm.

**Consequences:** Catalog visible before wallet exists; top up guides create the wallet.

---

## ADR-009: Banned “crypto” wording

**Context:** Product is Bitcoin-native.

**Decision:** Ban crypto/Web3 wording in feature surfaces; Cashu = Chaumian eCash.

**Consequences:** Copy review + grep gates.

---

## ADR-010: Grok 4.5 on Routstr as headline model

**Context:** Users already know Grok 4.5; Routstr is the Bitcoin payment path.

**Decision:** Curated catalog row targets Grok 4.5 on Routstr (slug from live
`/v1/models`). Not product-wide default model. Select via model picker /
`/model` / `-m` like OpenRouter and xAI — **no auto-switch** after funding.

**Consequences:** Must verify slug availability; fallback messaging if absent.

---

## ADR-011: Invoice-first automatic funding (no website)

**Context:** Full deposit → channel → CDK is residual (LDK/CDK not live). Users
should not need docs.routstr.com. Node OpenAPI already supports
`POST /lightning/invoice` + status `api_key` and Cashu balance create/topup/refund.

**Decision:** v1 product automation is **Routstr node HTTP first**: create/poll
invoice, store `sk-`, balance chrome, 402/low-balance topup when Routstr model
is active. Wire remaining balance APIs (Cashu create/topup/refund, recover)
before requiring LDK. Local LDK pay and CDK mint are later phases. Model stays
user-selected (ADR-010).

**Consequences:** External LN wallet still pays the in-app BOLT11 until Phase C.
North-star in FUNDING_FLOW remains long-term; see
[AUTOMATIC_FUNDING.md](./AUTOMATIC_FUNDING.md) for PR sequence.

---

## Rejected alternatives

| Idea | Why rejected |
|------|----------------|
| LN-only, no on-chain address | Fails when channels empty; approval requires address fallback |
| Seed in CredentialsStore / JSON mirror | Plaintext disk + wrong threat domain (hot API keys) |
| Seed in Zed keyring schema | Wrong owner; Grok must not write Zed stores |
| BOLT12 required for v1 | Blocks shipping if peer/LDK lack offers |
| Auto-generate seed on first `grok` launch | No backup consent |
| Full Nostr social client | Out of scope |
| Call it “crypto payments” | Language hard no |
| Plugin multi-provider framework | Premature; mirror OpenRouter module |
