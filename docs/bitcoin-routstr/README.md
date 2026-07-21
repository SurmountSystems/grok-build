# Bitcoin-native Routstr inference (Grok OSS)

**Status:** design + **invoice-first automatic funding implemented** (Phase A/B);
Phase C **landed** (isolated `ldk-node` helper + `bolt11_pay_live=true` with
feature `ldk`; CLI + TUI SeedVault auto-pay when live; default CI stub remains
invoice-first). Helper ships via Nix (`nix build .#grok-bitcoin-ldk-node`);
default monorepo CI stays off `ldk`.  
**Product goal:** pay for **Routstr Grok 4.5** inference without a website.
**v1 path:** live Routstr Lightning invoice APIs → store `sk-` → pick model in
picker (like OpenRouter/xAI). **Long-term:** on-chain deposit → Lightning →
Cashu (Chaumian eCash) → chat with local keys (LDK live pay / CDK residual).

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
do offer routing, **defer BOLT12**. Do not block the path above. BOLT11 +
on-chain remain mandatory.

**Later:** optional integration with a **local Bitcoin node and indexes**
(user bitcoind / Electrum / custom Esplora) instead of public explorers.

## Doc map

| Doc | Contents |
|-----|----------|
| [AUTOMATIC_FUNDING.md](./AUTOMATIC_FUNDING.md) | **Approved plan:** invoice-first automation, PR sequence, secret stores |
| [THREAT_MODEL.md](./THREAT_MODEL.md) | Assets, adversaries, commitments, non-claims |
| [FUNDING_FLOW.md](./FUNDING_FLOW.md) | Long-term deposit → channel → CDK; fees; watchers |
| [ADDRESS_UX.md](./ADDRESS_UX.md) | Every address: QR + copy; mempool.space links |
| [SEED_AND_DERIVATION.md](./SEED_AND_DERIVATION.md) | BIP-39, BDK, LDK, NIP-06 single seed |
| [ROUTSTR_INFERENCE.md](./ROUTSTR_INFERENCE.md) | OpenAI-compatible path, Grok 4.5, 402 |
| [DECISIONS.md](./DECISIONS.md) | ADR-style decisions and rejected alternatives |
| Crate `grok-bitcoin-wallet/SECURITY.md` | Implementation security rules for SeedVault |

## Related code (planned / existing)

| Area | Location |
|------|----------|
| Wallet crate | `crates/codegen/grok-bitcoin-wallet/` |
| Hot Routstr API keys (OpenRouter pattern) | `xai-grok-shell/src/auth/` (**not** for BIP-39) |
| Sampler / 402 | `xai-grok-sampler`, `xai-grok-sampling-types` |
| Session plan (agent) | `~/.grok/sessions/.../plan.md` (Routstr + wallet plan) |

## Implementation phases (summary)

0. Reasoning docs + SeedVault design  
1. SeedVault + BIP-39 + NIP-06 (no plaintext seed in CredentialsStore JSON)  
2. Routstr HTTP inference + catalog Grok 4.5 + default-on toggle  
3. On-chain receive + QR/copy + mempool watchers + spend/RBF/CPFP (*shipped*)  
4. **Invoice-first automatic float** (node APIs; no website) — **done** (see AUTOMATIC_FUNDING)  
5. LDK BOLT11 pay of node invoice — **done via out-of-process helper**
   (`grok-bitcoin-ldk-node`; feature `ldk`; CLI + TUI SeedVault auto-pay when
   `bolt11_pay_live`; see AUTOMATIC_FUNDING Phase C). Nix package shipped;
   AUR/distro residual.  
6. CDK Cashu mint/spend (local) — node refund API already live  
7. Hardening + local-node backends  

Claim local auto-pay only with feature `ldk` + helper installed + outbound
liquidity. Default builds: invoice QR + external LN pay (P0).

Helper install: `nix build .#grok-bitcoin-ldk-node` / `nix shell .#grok-bitcoin-ldk-node`
(or cargo; see `crates/codegen/grok-bitcoin-ldk-node/README.md`).
Env: `GROK_BITCOIN_LDK_NODE_BIN`.
