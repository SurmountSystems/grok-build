# Bitcoin-native Routstr inference (Grok OSS)

**Status:** design / pre-implementation reasoning.  
**Product goal:** pay for **Routstr Grok 4.5** inference using **locally generated
keys**, with a seamless out-of-the-box path from on-chain deposit → Lightning →
Cashu (Chaumian eCash) → chat completions.

This is **real money**. Read [`THREAT_MODEL.md`](./THREAT_MODEL.md) and the
crate docs under `crates/codegen/grok-bitcoin-wallet/` before changing custody
code.

## Language

| Use | Never use |
|-----|-----------|
| Bitcoin, Lightning, on-chain, sats/msats | “crypto”, “cryptocurrency”, “Web3” |
| Cashu, Cashu (Chaumian eCash) on first mention | bare “eCash” for non-Cashu systems |
| BOLT11, BOLT12 (when we claim it) | implying BOLT12 if deferred |
| BIP-39, NIP-06, BDK, LDK, CDK | casual “wallet seed file in config.toml” |

## North-star user journey

```
1. Enable Routstr (default on) + Create Bitcoin wallet (explicit)
2. Backup 12-word BIP-39 once (confirm re-entry)
3. Show receive address + QR + copy  →  user deposits (fee-aware amount)
4. Watcher tracks tx via mempool.space (rate-limit aware) + txid deep links
5. After confirmations: open Lightning channel toward Routstr-recommended peer
6. Mint/hold Cashu tokens via CDK; spend for inference (Bearer cashuA… or sk-)
7. Stream Grok 4.5 on https://api.routstr.com/v1
8. Prefer refunding unused Routstr float (hot) back to Cashu / local control
```

**BOLT12:** optional enhancement. If the recommended peer or our LDK pin cannot
do offer routing, **defer BOLT12** — do not block the path above. BOLT11 +
on-chain remain mandatory.

**Later:** optional integration with a **local Bitcoin node and indexes**
(user bitcoind / Electrum / custom Esplora) instead of public explorers.

## Doc map

| Doc | Contents |
|-----|----------|
| [THREAT_MODEL.md](./THREAT_MODEL.md) | Assets, adversaries, commitments, non-claims |
| [FUNDING_FLOW.md](./FUNDING_FLOW.md) | Deposit → channel → CDK → inference; fees; watchers |
| [ADDRESS_UX.md](./ADDRESS_UX.md) | Every address: QR + copy; mempool.space links |
| [SEED_AND_DERIVATION.md](./SEED_AND_DERIVATION.md) | BIP-39, BDK, LDK, NIP-06 single seed |
| [ROUTSTR_INFERENCE.md](./ROUTSTR_INFERENCE.md) | OpenAI-compatible path, Grok 4.5, 402 |
| [DECISIONS.md](./DECISIONS.md) | ADR-style decisions and rejected alternatives |
| Crate `grok-bitcoin-wallet/SECURITY.md` | Implementation security rules for SeedVault |

## Related code (planned / existing)

| Area | Location |
|------|----------|
| Wallet crate | `crates/codegen/grok-bitcoin-wallet/` |
| Hot Routstr API keys (OpenRouter pattern) | `xai-grok-shell/src/auth/` — **not** for BIP-39 |
| Sampler / 402 | `xai-grok-sampler`, `xai-grok-sampling-types` |
| Session plan (agent) | `~/.grok/sessions/.../plan.md` (Routstr + wallet plan) |

## Implementation phases (summary)

0. **Reasoning docs** (this tree) + SeedVault design — *in progress*  
1. SeedVault + BIP-39 + NIP-06 (no plaintext seed on disk)  
2. Routstr HTTP inference + catalog Grok 4.5 + default-on toggle  
3. BDK receive + QR/copy + mempool watchers  
4. LDK BOLT11; channel to Routstr-recommended peer; BOLT12 deferred if needed  
5. CDK Cashu mint/spend for inference  
6. Glue wizard + hardening + local-node backends  

Do not advertise “pay from Grok” until phases 1–3 meet the acceptance criteria
in the plan file.
