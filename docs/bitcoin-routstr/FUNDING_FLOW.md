# Funding flow: deposit → channel → Cashu → Grok 4.5 inference

## Goal

**Seamless out-of-the-box:** user pays for **Routstr Grok 4.5** inference using
keys generated locally in Grok OSS, without manually juggling five wallets.

**v1 product path (approved):** use **Routstr node Lightning invoice APIs**
(create → pay QR → poll → store `sk-`) and pick Grok 4.5 on Routstr in the
model picker. Full deposit → channel → CDK below is the **long-term** path
(LDK/CDK residual). Canonical sequence:
[AUTOMATIC_FUNDING.md](./AUTOMATIC_FUNDING.md) (ADR-011).

## Happy path (long-term target)

```
                    ┌─────────────────────┐
                    │ BIP-39 SeedVault    │
                    │ BDK + LDK + NIP-06  │
                    └─────────┬───────────┘
                              │
         (1) show address+QR+copy (BDK)
                              ▼
                    User on-chain deposit
                              │
         (2) watcher (mempool.space, RL-aware)
              txid → https://mempool.space/tx/<txid>
                              ▼
              N confirmations (config; mainnet-safe default)
                              │
         (3) fee-efficient open LN channel
              peer = Routstr-recommended node (API/docs)
              BOLT11 path required; BOLT12 deferred if unsupported
                              ▼
         (4) CDK: obtain Cashu (Chaumian eCash) tokens
              mint/swap as Routstr payment path requires
                              ▼
         (5) Inference: OpenAI-compatible
              POST https://api.routstr.com/v1/chat/completions
              model = Grok 4.5 catalog id on Routstr
              Authorization: Bearer cashuA… or sk-…
                              ▼
         (6) Optional refund unused Routstr float → Cashu back to user control
```

## Step details

### 1. On-chain deposit (BDK)

- Always available **even with zero Lightning channels**.
- Address UI: see [ADDRESS_UX.md](./ADDRESS_UX.md).
- **Fee-efficient amount guidance:** suggest deposit size that covers:
  - open-channel on-chain fee reserve,
  - channel target capacity for expected inference budget,
  - dust / min-channel constraints from the recommended peer,
  - a small contingency. **Not** “send your entire stack.”
- Prefer consolidating guidance into one deposit rather than many tiny UTXOs
  when opening a channel (fee efficiency).

### 2. Watchers + mempool.space

- On broadcast or detected payment: register a **watcher** for txid/address.
- UI shows status: in mempool → N/M confirmations → confirmed.
- **txid links:** `https://mempool.space/tx/{txid}` (mainnet); signet/testnet
  use the matching mempool.space network prefix when network ≠ mainnet.
- **Rate limits:** mempool.space is a public API.
  - Cache address/tx responses with TTL.
  - Exponential backoff on 429 / 5xx.
  - Global client-side budget (e.g. max req/min) shared across watchers.
  - Coalesce multiple UI polls into one fetcher task.
  - Jitter; never tight-loop.
  - On persistent failure: show last-known state + “open in browser” link;
    optional manual refresh.
- **Future:** user-configured local bitcoind / Electrs / Esplora. Same watcher
  trait, different backend (see open questions).

### 3. Lightning channel (LDK)

- After sufficient confirmations and spendable balance: **automatically**
  (with user confirm once in wizard) open a channel to the **Routstr-recommended**
  peer (node id + addrs from Routstr info/providers API or documented default).
- If peer or our stack lacks **BOLT12 offer routing**, **skip BOLT12**. Do not
  block. Use BOLT11 for Routstr top up invoices and channel ops as required.
- If channel open fails (liquidity, offline peer): keep funds on-chain; allow
  retry; allow **external** pay of Routstr BOLT11 (QR) as escape hatch.

### 4. Cashu via CDK

- Routstr inference is paid with **Cashu** (Chaumian eCash) and/or session
  `sk-` balances funded from Lightning/Cashu.
- Use **CDK** (Cashu Development Kit) to:
  - receive/hold tokens,
  - produce `cashuA…` proofs for `Authorization: Bearer`,
  - handle change after spend where applicable.
- Prefer spending Cashu for inference over leaving large `sk-` float on the
  node long-term.

### 5. Inference

- Catalog entry for **Grok 4.5 on Routstr** (exact API model slug confirmed
  against `GET /v1/models` at implement time).
- Sampler stays OpenAI-compatible; no special protocol beyond base URL + bearer.
- **402** → top up wizard (more Cashu / invoice), not a dead-end error.

### 6. Refund

- First-class **refund** of unused Routstr balance to Cashu token.
- Encourage refund when ending a work session with leftover float.

## Escape hatches (still seamless-capable)

| Situation | Fallback |
|-----------|----------|
| User already has `sk-` or `cashuA…` | Paste login; skip deposit |
| User has external Lightning wallet | Show Routstr BOLT11 + QR; don’t force LDK pay |
| No channels yet | On-chain address always; external LN pay |
| BOLT12 unsupported | Defer; BOLT11 only |
| mempool.space limited | Backoff + browser link; later local node |
| Routstr disabled in settings | Hide catalog; wallet may remain for receive |

## Out of box defaults

- Routstr **enabled** (discoverability).
- Wallet **not** auto-created until user accepts backup flow.
- Network: **mainnet** for release builds; `GROK_BITCOIN_NETWORK=signet` for dev.
- Explorer / UTXO list (product spend): **mempool.space** by default.
  Override with `GROK_BITCOIN_CHAIN_SOURCE=mempool|esplora|electrum`
  (case-insensitive; empty/unset → mempool). When `esplora`, set
  `GROK_BITCOIN_ESPLORA_URL` (REST base, e.g. `https://blockstream.info/api`).
  When `electrum`, set `GROK_BITCOIN_ELECTRUM_ADDR` (`host:port` or `[ipv6]:port`,
  or `ssl://host:port` for TLS). Optional `GROK_BITCOIN_ELECTRUM_TLS=1|true|yes`
  enables TLS for bare `host:port` (default **plaintext** TCP for local/regtest).
  TLS uses rustls + WebPKI roots (no skip-verify). Selecting esplora/electrum
  requires rebuilding the product binary with matching optional features (not
  default CI): `cargo build -p xai-grok-pager-bin --features esplora` (or
  `electrum`). Missing feature → **runtime** structured error at open (no hang).
  `--broadcast` uses the **same** backend as the UTXO list when the matching
  feature is built (mempool `POST /api/tx`, Esplora `POST /tx`, Electrum
  `blockchain.transaction.broadcast`). Default remains mempool-only with no
  feature flip.
- Product on-chain **spend** UTXO discovery (**default**): gap-limit ChainSource
  sync (`sync_with_gap_extend` via `select_and_prepare_bip84_spend_with_gap_sync`)
  with BIP44-style default look-ahead 20 and hard `MAX_ADDRESS_GAP` **before**
  coin select/sign. Recovers deep receive/change indices when activity sits near
  the look-ahead tip of the current window. Coin select uses the final sync
  snapshot UTXOs (`select_and_prepare_bip84_spend_from_utxos`) — **no** extra
  full-window `list_unspent` after sync (N+1 sync lists only; snapshot
  authoritative as of that final list). On insufficient funds / no UTXOs
  after a successful extend, structured `GapSyncSpendFailure::AfterSync` still
  surfaces honest hit-max / extended-window notices (not success-path only).
  RBF/CPFP keep explicit prevouts and do not re-extend.
- Optional **`bdk_wallet` auto-sync** (feature `bdk`, not default CI): real BDK
  engine with spent-tx history + keychain index (`bdk_sync` module). Injectable
  `BdkUpdateSource` + Esplora/Electrum full_scan transport adapters (offline mock
  green; live HTTP/TCP compose `bdk`+`esplora` / `bdk`+`electrum`, not default CI).
  Product helpers `list_bip84_utxos_with_bdk_sync` /
  `select_and_prepare_bip84_spend_with_bdk_sync` feed the same prepare-from-snapshot
  path. **Shell/CLI prefer-BDK wire landed:** rebuild product with
  `--features bdk,esplora` (or `bdk,electrum`) and set
  `GROK_BITCOIN_UTXO_SYNC=bdk` (empty/unset → **gap**). Chain source must be
  esplora or electrum (mempool + bdk fails closed with residual guidance).
  Prefer-BDK without feature → structured residual. Default monorepo CI stays
  gap-limit only (`bdk` off).

## Non-goals for this flow

- Automatic free inbound liquidity markets (LSP shopping) beyond Routstr’s
  recommended peer. Can revisit.
- Hiding all fees. Surface estimates before channel open and before large pays.
- Other Routstr products beyond inference payment.
