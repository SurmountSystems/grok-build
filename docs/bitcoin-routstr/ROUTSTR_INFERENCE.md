# Routstr inference (Grok 4.5)

## Scope

**In:** OpenAI-compatible inference against Routstr nodes (default
`https://api.routstr.com/v1`), prepaid with Lightning/Cashu, catalog entry for
**Grok 4.5**, settings toggle default **on**.

**Out:** other Routstr products (provider ops dashboards, social, donate, etc.).

## Protocol

Routstr is a drop-in OpenAI-compatible gateway:

```text
BASE_URL  = https://api.routstr.com/v1   # or self-hosted node
API_KEY   = sk-…  or  cashuA…           # Authorization: Bearer
```

Primary calls: `POST /v1/chat/completions` (streaming supported).  
Models: `GET /v1/models` (confirm Grok 4.5 slug at implement time).

Live OpenAPI (verify often): `https://api.routstr.com/openapi.json`  
Balance/invoice paths observed: `/v1/balance/*`, `/lightning/invoice`. **Prefer
live OpenAPI over stale Mintlify names** (`/v1/wallet/*` in older docs).

## Auth material

| Material | Source | Store |
|----------|--------|-------|
| `sk-…` | Lightning invoice paid / Cashu create balance | `CredentialsStore` (hot) |
| `cashuA…` | CDK / user paste | Prefer spend; short-term store if needed |
| Local seed | BIP-39 | **SeedVault only.** Never CredentialsStore JSON |

Env: `ROUTSTR_API_KEY` / `ROUTSTR_API_KEYS` (multi-key failover, same pattern as
OpenRouter). Env wins; refuse store write when env set.

## Catalog

- Additive catalog id e.g. `routstr-grok-4.5` (final id at implement).
- Display: make **Routstr + Bitcoin/Lightning** obvious vs OpenRouter.
- **Not** the product default model (`grok-build` / SpaceXAI remains default).
- Preserve entry across remote `/v1/models` prefetch (OpenRouter twin).
- When `routstr_enabled = false`: omit from picker and balance chrome.

## Credentials resolution

For Routstr base URLs:

1. Model `api_key` / `env_key` lists  
2. `ROUTSTR_API_KEY(S)`  
3. CredentialsStore for Routstr URL  
4. **No** fallthrough to `XAI_API_KEY` / xAI session  

Sampler: existing Bearer + `failover_api_keys`; **402** ⇒ credit exhausted ⇒
top up UX (Cashu/LN wizard).

## Balance UI

- When active model is Routstr: show **sats** (msats in detail).
- Low balance → prompt funding flow ([FUNDING_FLOW.md](./FUNDING_FLOW.md)).
- Do not show Routstr float as “wallet cold balance.”

## Cashu (Chaumian eCash)

Routstr prepaid economics use **Cashu**. Grok will use **CDK** to mint/hold/spend
tokens toward inference so the path from local LN → eCash → completion is
automated. First docs mention: “Cashu (Chaumian eCash).”

## CLI

```bash
grok login --routstr          # paste sk- or cashuA
grok logout --routstr
grok routstr balance          # requires key; fetches /v1/balance/info
grok routstr topup --sats N   # live POST /lightning/invoice (default N=1000; min 1 max 1e6)
grok routstr topup --status ID  # after pay: store sk- when status returns api_key
grok routstr topup --no-poll  # print BOLT11+QR only (no wait)
grok routstr refund           # guidance until live refund / CDK path
grok routstr fund             # backup gate + unlock → BIP84 receive address (BIP21 QR)
```

**Model:** pick **Grok 4.5 on Routstr** in the model picker / `/model routstr-grok-4.5`
(same pattern as OpenRouter and xAI). Do not auto-switch after topup.

**Automatic funding (approved, implement gated):** invoice-first path, no website —
see [AUTOMATIC_FUNDING.md](./AUTOMATIC_FUNDING.md).

### Mainnet top-up amounts (live OpenAPI 2026-07-19)

| Bound | Sats | Notes |
|-------|------|--------|
| API minimum | **1** | `amount_sats` exclusiveMinimum 0; live API rejects 0 |
| API maximum | **1_000_000** | OpenAPI maximum |
| Product default / smoke | **1000** | docs.routstr.com example; good LN routing |
| Grok 4.5 pricing (approx) | ~0.002 sats/prompt token, 0.001/request | 1000 sats is enough for smoke completions |

**Lightning vs BIP21:** Routstr node float is funded with a **BOLT11** Lightning invoice (QR encodes `lnbc…`). BIP21 (`bitcoin:<addr>?amount=…`) is for **on-chain** `grok routstr fund` only — not for Routstr prepaid.

## References

- https://docs.routstr.com/ (client payments + integration)
- https://api.routstr.com/openapi.json
- OpenRouter mirror: `xai-grok-shell/src/auth/openrouter.rs`
