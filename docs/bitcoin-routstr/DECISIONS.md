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

**Context:** `CredentialsStore` plaintext-mirrors to JSON.

**Decision:** BIP-39 never uses that mirror. New SeedVault: keyring / AEAD only.

**Consequences:** Two secret APIs; must educate contributors.

---

## ADR-003: Single BIP-39 → BDK + LDK + NIP-06

**Context:** Multiple seeds destroy UX and backup discipline.

**Decision:** One mnemonic; NIP-06 for Nostr; no random nsec by default.

**Consequences:** NIP-06 is “unrecommended” in NIP text for some clients — still
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

**Consequences:** Catalog visible before wallet exists; top-up guides create.

---

## ADR-009: Banned “crypto” wording

**Context:** Product is Bitcoin-native.

**Decision:** Ban crypto/Web3 wording in feature surfaces; Cashu = Chaumian eCash.

**Consequences:** Copy review + grep gates.

---

## ADR-010: Grok 4.5 on Routstr as headline model

**Context:** Users already know Grok 4.5; Routstr is the Bitcoin payment path.

**Decision:** Curated catalog row targets Grok 4.5 on Routstr (slug from live
`/v1/models`). Not product-wide default model.

**Consequences:** Must verify slug availability; fallback messaging if absent.

---

## Rejected alternatives

| Idea | Why rejected |
|------|----------------|
| LN-only, no on-chain address | Fails when channels empty; approval requires address fallback |
| Seed in CredentialsStore JSON | Plaintext disk |
| BOLT12 required for v1 | Blocks shipping if peer/LDK lack offers |
| Auto-generate seed on first `grok` launch | No backup consent |
| Full Nostr social client | Out of scope |
| Call it “crypto payments” | Language hard no |
| Plugin multi-provider framework | Premature; mirror OpenRouter module |
