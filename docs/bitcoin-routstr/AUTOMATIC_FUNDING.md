# Automatic Routstr funding (approved plan)

**Status:** Phase A + B **implemented** 2026-07-20 (invoice-first; no website).  
Phase C pay + invoice-create + pure Nix **landed** (feature `ldk` + helper IPC
`pay_bolt11` / `create_bolt11_invoice`; CLI/TUI SeedVault auto-pay; pure
`nix build .#grok-bitcoin-ldk-node` green). Phase D **NUT-04 mint quote** +
**isolated CDK proofs helper** + **product CLI/TUI mint wire** + **CDK Nix**
under optional `cashu-cdk` (`mint_live` when mint URL set; `proofs_mint_live`
when helper linked; `grok routstr mint` / `/routstr mint` → quote → pay →
proofs → redeem; float only after redeem; residual → P0 topup). Melt library
`spend_live` / `refund_live` when helper resolvable (Token→melt PAID only).
Product melt CLI/TUI green (`refund --token/--invoice`); live channel open /
connect peer still residual (helper recognizes `open_channel` / `connect_peer`
→ structured `ok:false` residual refuse, not live Success; live cmds remain
`ping` / `pay_bolt11` / `create_bolt11_invoice`). Prefer spend/melt cashuA…
over large hot sk- float (docs + product residual copy).
Draft AUR PKGBUILD for LDK helper exists (Nix remains primary ship path).

**Product residual (not miniscript):** product NIP-06/NIP-98/NDK-style Routstr
auth (live contract still Bearer-only); channel open/connect. Shell/CLI
prefer-BDK product wire **landed** (feature `bdk` + `GROK_BITCOIN_UTXO_SYNC=bdk`;
default gap; not default CI). BIP-39 / passphrase **policy enforcement offline**
(forbidden path guards + passphrase never-at-rest tests); optional entropy-bytes
encoding still open. Engineering unfuck **PR0–PR5 done** (`descriptor_wallet`
peeled; dual-hash `and_v` keep set only). See root `RESIDUAL.md`.

## Goal

Make **Routstr Grok 4.5** usable end-to-end inside Grok CLI/TUI **without
docs.routstr.com or any web dashboard**. Prefer **actual Routstr node HTTP**
first; add local Lightning (LDK) / Cashu (CDK) only where the node API cannot
pay or mint for us.

### Model selection (unchanged)

Pick **Grok 4.5 on Routstr** the same way as OpenRouter or first-party xAI:

- Model picker / `/model routstr-grok-4.5` / `-m routstr-grok-4.5`

Catalog entry already exists. **Do not** auto-switch models after funding.
Automation is **credentials + prepaid float only**.

### Success bar

1. No key yet → one command or TUI action creates a mainnet BOLT11, shows QR,
   polls until paid, stores `sk-`; balance chrome works when the Routstr model
   is selected.
2. Low/zero float or **402** while on Routstr model → same topup flow; no
   website.
3. Optional Cashu path (`cashuA…`) → `balance/create` or `balance/topup` via API.
4. Refund unused float via live `POST /v1/balance/refund` when possible.
5. Residual “go to docs.routstr.com” copy **gone** from happy paths.
6. Zero external wallet only after LDK can pay the node BOLT11 (Phase C); until
   then, **one** external LN pay of the in-app invoice is the honest minimum.

---

## Live Routstr APIs (node OpenAPI ~0.4.4)

Prefer live `https://api.routstr.com/openapi.json` over stale Mintlify paths.

| Endpoint | Role | Product status |
|----------|------|----------------|
| `POST /lightning/invoice` | `purpose=create\|topup`, `amount_sats` | **Live** (`create_routstr_lightning_invoice`) |
| `GET /lightning/invoice/{id}/status` | `status` + optional `api_key` | **Live** (CLI poll + TUI `RoutstrInvoicePoll`) |
| `POST /lightning/recover` | Status from BOLT11 string | **Live** (`grok routstr topup --recover`) |
| `GET /v1/balance/info` | Prepaid float | **Live** |
| `GET /v1/balance/create?initial_balance_token=` | Cashu → new balance | **Live** (`grok routstr redeem`) |
| `POST /v1/balance/topup` | Cashu into existing key | **Live** (`grok routstr redeem` with key) |
| `POST /v1/balance/refund` | Refund → Cashu | **Live** (token once; residual if fail) |
| `POST /v1/chat/completions` | Inference | **Live** via `routstr-grok-4.5` |
| `GET /v1/models` | Catalog check | Test-only |

**Design correction:** Routstr does **not** expose “open a channel to us and we
mint you credit.” Prepaid is (1) pay **their** BOLT11, or (2) redeem **Cashu**.
Local on-chain `fund` / LDK is for **our** ability to pay that BOLT11 later,
not a substitute for the node invoice API.

**v1 automatic path is invoice-first** (APIs already work). Deposit → channel →
CDK remains the long-term self-custody story (Phases C–D).

Already works without website (external LN pay still required):

```bash
grok routstr topup --sats 1000
grok routstr balance
# pick Routstr Grok 4.5 in the model picker
grok -m routstr-grok-4.5 -p "hi"
```

---

## Architecture

```text
Layer 1 — Routstr node (hot float)
  sk- / cashuA in CredentialsStore or ROUTSTR_API_KEY(S)
  Live HTTP: invoice, status, balance, create, topup, refund
        ▲
        │ pay BOLT11 / redeem Cashu
Layer 2 — Local SeedVault (optional for Phase A float funding)
  BIP-39 → on-chain fund/watch/spend (shipped)
  LDK pay_bolt11 (Phase C) · CDK mint (Phase D)
```

Float funding must work **without** a local wallet (ADR-008: wallet create is
explicit). Product copy: “Routstr fund float,” not “create Bitcoin wallet.”

---

## Secret stores (why seed ≠ OpenRouter/Zed keys)

This section answers: *“If CredentialsStore uses the OS keyring, how do we
read Zed OpenRouter credentials, and why can’t seed live there?”*

### Three separate systems

| Store | Service / location | What it holds | Write policy |
|-------|--------------------|---------------|--------------|
| **Grok `CredentialsStore`** | OS keyring service `grok-build` (account = API base URL) **plus always** `$GROK_HOME/provider_credentials.json` plaintext mirror | Hot Bearer API keys (`sk-`, OpenRouter, Routstr) as **UTF-8 strings** | Grok writes |
| **Zed (OpenRouter probe)** | **Different** OS layout: Linux Secret Service **label** `zed-github-account` + `url`/`username` attrs; macOS Internet Password; Windows `zed:url=…`; plus Zed Dev file `development_credentials` | Zed’s API keys (incl. OpenRouter) | Grok **read-only** via `harness_secrets` — never writes Zed |
| **SeedVault** | Dedicated keyring service `SEED_VAULT_SERVICE` (user `bip39-mnemonic`); optional password AEAD file (never `provider_credentials.json` / `watch_session.json` / `config.toml` — `assert_allowed_seed_storage_path`) | Wallet root (**mnemonic phrase only** today; BIP-39 passphrase unlock-only, never at rest) | Grok writes; **never** CredentialsStore |

### How OpenRouter “from Zed” works

1. Env `OPENROUTER_API_KEY` (portable).  
2. Grok’s own `CredentialsStore` for `https://openrouter.ai/api/v1`.  
3. **Read-only** `probe_shared_openrouter_key` in `xai-grok-shell/src/auth/harness_secrets.rs` — looks up Zed’s **separate** keyring schema / Dev file. Schemas do **not** interoperate with `grok-build`; we probe Zed deliberately.

OpenRouter keys are **rotatable API secrets**. Seed material is **fund loss if
leaked or mirrored to disk**. CredentialsStore’s JSON mirror is fine for hot
`sk-` risk domain; it is **forbidden** for BIP-39 / raw entropy (ADR-002,
`SECURITY.md`).

### Doing seed storage “right” (consideration; not Phase A implement)

| Today | Prefer long-term (optional follow-up) |
|-------|----------------------------------------|
| SeedVault keyring stores **mnemonic phrase string** (human backup encoding) | Store **16-byte entropy** (or versioned payload) in dedicated keyring entry; materialize BIP-39 words only for show-once backup / re-entry UX |
| BIP-39 12 words = 128 bits entropy + checksum (inefficient as storage encoding; correct for backup) | Same entropy; tighter OS payload |
| BIP-32 master seed = 64-byte PBKDF2(mnemonic, passphrase) | Do not confuse with 16-byte entropy; passphrase stays out of storage (unlock env/modal only) |
| CredentialsStore API is `&str` only | Irrelevant for seed — do not route seed through it even base64-wrapped |

**Implement stance:** Phases A–B do not change SeedVault encoding. Phase C
unlocks SeedVault for LDK. Entropy-bytes storage is a **separate** SeedVault
hardening PR if we want it — still never CredentialsStore / Zed / JSON mirror.

---

## Phase A — API automation UX (no new heavy deps) — **done**

### A1. `ensure_routstr_ready` orchestrator (shell) — **done**

In `xai-grok-shell/src/auth/routstr.rs`:

1. `routstr_enabled` gate.  
2. Load key (env → store).  
3. If key → `GET /v1/balance/info`; ready if float ≥ threshold (or not 402 path).  
4. Else create invoice (`create` vs `topup`) → `NeedsPayment`.  
5. Poll until `api_key` or timeout; `store_paid_routstr_key`.  
6. Re-fetch balance → **Ready { msats }**.

CLI: `topup` kept; `setup` alias calls the same orchestrator.

### A2. TUI poll + toast (no model hijack) — **done**

- Effect `RoutstrInvoicePoll` (mirror watch loop).  
- On paid: store key, toast, refresh credit chrome if Routstr model active.  
- **Never** auto-change selected model. Optional hint only if not on Routstr:
  “Select Routstr Grok 4.5 in the model picker to use this float.”  
- Persist pending invoice id for resume. QR + copy on create (ADR-006).

### A3. 402 / low-balance (Routstr model only) — **done**

When active model is Routstr base URL / `routstr-grok-4.5`: offer topup
(`/routstr topup`). Keep first-party Grok API failover as escape hatch.
Credit bar low-sats line hints `/routstr topup`.

### A4. Residual copy — **done**

Removed “pay from docs.routstr.com” from happy residual paths; point at
`grok routstr topup` / network errors only.

### A5. `POST /lightning/recover` — **done**

CLI: `grok routstr topup --recover <bolt11>` → same status parse → store key.

### A6. Offline tests — **done**

Orchestrator decision unit tests; parsers; residual language gate; invoice poll
generation drop.

**Deliverable:** never open a website; pay in-app QR with any LN wallet; pick
Routstr model in picker; chat.

---

## Phase B — Remaining balance APIs (no LDK/CDK) — **done**

| Item | API | Status |
|------|-----|--------|
| B1 Cashu → new balance | `GET /v1/balance/create?initial_balance_token=` | **Live** (`grok routstr redeem`) |
| B2 Cashu topup existing | `POST /v1/balance/topup` | **Live** (redeem with existing key) |
| B3 Live refund | `POST /v1/balance/refund` (token once, redacted Debug) | **Live** |
| B4 Bearer Cashu | Confirm live; store like `sk-` if node accepts | **Live** via login / create |

Flexible parsers (OpenAPI `additionalProperties`); offline unit tests.

---

## Phase C — LDK pays node invoice (no other wallet)

**Status (2026-07-20):** product seams + shell orchestration + **isolated
`ldk-node` helper** landed. Feature `ldk` flips `bolt11_pay_live=true` on
`LdkLightning` (IPC to helper). Default CI stays off `ldk` (stub / P0 QR).

| Item | Status |
|------|--------|
| Feature `ldk` (optional; not default CI) | **On** — enables `lightning_ldk` adapter (`bolt11_pay_live=true`) |
| Real `ldk-node` / LDK stack linked | **Out-of-process** — excluded crate `grok-bitcoin-ldk-node` owns `ldk-node` + rusqlite 0.31 (workspace co-membership still hits `links=sqlite3` with shell 0.37) |
| `bolt11_pay_live` | **true** on `LdkLightning` (feature `ldk`); **false** on stub / default CI |
| `pay_bolt11_with_seed` | SeedVault BIP-39 → IPC helper → `ldk-node` send; zeroizes seed/phrase; Success only from transport |
| Shell auto-pay (CLI / `ensure_routstr_ready`) | `run_routstr_topup_with_lightning` / `maybe_auto_pay_routstr_bolt11`: if live → unlock SeedVault → pay → poll; else P0 QR + external pay. Injectable `LightningCapability` for tests |
| TUI `/routstr topup` auto-pay | **Done** — when `bolt11_pay_live`: stage pending + `/routstr unlock` (password/phrase re-entry, spend/utxos pattern) → `complete_routstr_topup_local_pay_reentry_for_tui` / `apply_local_bolt11_pay`. Invoice poll + QR always arm immediately (P0). Injectable Lightning for shell unit tests |
| Liquidity honesty | Outbound liquidity required; **not** “must channel to Routstr” (only after a real local pay attempt — not unlock failures) |
| BOLT12 | still `BOLT12_SUPPORTED=false` |
| P0 invoice-first | unchanged fallback when not live / pay fails / helper missing / unlock cancel |
| Helper packaging (Nix/flake export) | **Done** — `packages.<system>.grok-bitcoin-ldk-node` (isolated fileset/crane; never monorepo graph; packages-only, not under `checks`); `checks…-tests`; `just ldk-node`; docs + optional CI job |
| `bolt11_invoice_live` | **true** on `LdkLightning` when transport linked (feature `ldk`); SeedVault `create_bolt11_invoice_with_seed`; bare create honest Failed; **not** Routstr float |
| Helper packaging residual | Pure `nix build` **confirmed green**; AUR / distro still open; default monorepo CI still **no** `ldk` feature |

- Nix: `nix build .#grok-bitcoin-ldk-node` · `nix shell .#grok-bitcoin-ldk-node` · `nix run .#grok-bitcoin-ldk-node` · `just ldk-node`
- Cargo: `cargo build --manifest-path crates/codegen/grok-bitcoin-ldk-node/Cargo.toml`
- Env: `GROK_BITCOIN_LDK_NODE_BIN`, `GROK_BITCOIN_LDK_STORAGE`, `GROK_BITCOIN_LDK_ESPLORA_URL` / `GROK_BITCOIN_ESPLORA_URL`, `GROK_BITCOIN_NETWORK`.
- Default monorepo CI stays off `ldk` (stub / P0 QR). Optional CI job builds the **excluded** helper only. Product packaging ships the helper via Nix without enabling monorepo `ldk`.
- Product still needs outbound channel liquidity for successful pays (honest Failed otherwise). Local LDK receive invoice is **not** prepaid float.

---

## Phase D — CDK Cashu mint

| Item | Status |
|------|--------|
| Feature `cashu-cdk` (optional; not default CI) | **On** — NUT-04 mint **quote** (`Nut04MintCashu` + reqwest) + pure quote-state / mint-response parsers + process IPC to excluded helper |
| Isolated helper `grok-bitcoin-cdk-mint` | **On** — workspace-excluded; owns `cdk` + `cdk-sqlite` + rusqlite 0.31; IPC `mint_quote` / `mint_after_paid` → `cashuA…` + **`melt_token` → PAID** |
| `mint_live` | **true** only when mint URL configured (`GROK_BITCOIN_CASHU_MINT_URL`); else false / Failed |
| `proofs_mint_live` | **true** when mint URL set **and** CDK helper transport linked; Token only from helper IPC after pay (SeedVault seed); never fabricated |
| `spend_live` / `refund_live` | **true** under same helper gate as `proofs_mint_live`; melt Completed only from IPC state=PAID via `melt_token_to_bolt11_with_seed` (token + destination BOLT11 + SeedVault); bare `refund()` Failed without token context |
| Redeem path | Live Routstr `balance/create` / `balance/topup` for `cashuA…` (Phase B) unchanged — **float only after redeem** |
| Prefer Cashu over hot `sk-` | **Guidance on** — mint+redeem+melt green end-to-end; residual/product copy prefers spend/melt cashuA… over large hot sk- float; node refund still preferred for existing sk- float |
| Product CLI/TUI mint wire | **On** — `grok routstr mint` / `/routstr mint`: SeedVault unlock → quote BOLT11 → pay mint → unlock → proofs → redeem; float only after redeem; residual → P0 topup |
| Product CLI/TUI melt spend | **On** — `grok routstr refund --token <cashuA…> --invoice <BOLT11>` + TUI `/routstr refund token=… invoice=…` (alias melt); Paid only; never sk- float claim |
| Live channel open / connect peer | **Residual (explicit refuse)** — helper recognizes `open_channel` / `connect_peer` → structured `ok:false` residual (not `unknown cmd`); product `channel_open_live` / `connect_peer_live` always false; API Unsupported residual never channel_id Success; wizard peer seed pure |
| NIP-06 library derive | **On** — `grok_bitcoin_wallet::nip06` / SeedVault mnemonic; official vectors; nsec controlled API only |
| NIP-98 pure Authorization helpers | **On (library)** — `grok_bitcoin_wallet::nip98` build/parse `Nostr <base64>` + request-match offline; NIP-06 vector roundtrip + reject Bearer/cashu; **not** product wire |
| Product NIP-06 / Nostr-signed Routstr auth | **Residual (dual honesty; offline-proveable refuse e2e)** — re-verified 2026-07-20 + hardened IMPL `d1de2faf`: live Routstr Bearer `sk-` / `cashu…` only (`validate_bearer_key` / docs.routstr.com). Product classify/validate + login/store/env/inference refuse NIP-98 + nsec/BIP-39/hex-seed (`ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false`; residual error variants + honesty lines; never CredentialsStore / provider_credentials / watch_session); pure helpers not wired as Success; never invent signed-auth Success |
| Offline Taproot script-path finalize (library) | **Frozen / partial green** — policy-shaped forms offline (thresh, nested or_c/or_i, multi-key, vault, inheritance, HTLC, dual-hash **or_i**, dual-timeout, single-hash combined, dual-hash `and_v` **PR5 keep set only**). Other dual-hash orderings pruned; **no further orderings**. Bare top-level `or_c` stays Partial. Peel complete (`finalize.rs` + `bare_tapscript/`); engineering unfuck PR0–PR5 **done**. Product next steps in root `RESIDUAL.md`. |
| Helper Nix package | **On** — `packages.<sys>.grok-bitcoin-cdk-mint` + `checks…-tests` + `apps` + `just cdk-mint`; never monorepo `commonArgs` / default `grok-oss` |

- Build helper: `cargo build --manifest-path crates/codegen/grok-bitcoin-cdk-mint/Cargo.toml`  
  or `nix build .#grok-bitcoin-cdk-mint` / `just cdk-mint`
- Env: `GROK_BITCOIN_CDK_MINT_BIN`, `GROK_BITCOIN_CDK_STORAGE`, `GROK_BITCOIN_CASHU_MINT_URL`
- Product feature: `cargo build -p xai-grok-pager-bin --features cashu-cdk` (not default CI)
- Melt Success only when helper reports PAID (never invent).

---

## PR-sized order

| PR | Scope | Risk |
|----|--------|------|
| **PR1** | `ensure_routstr_ready` + topup/setup refactor + recover; residual copy; unit tests | Low |
| **PR2** | TUI invoice poll + resume + toast (no auto model); low-balance when Routstr active | Medium |
| **PR3** | 402 → topup orchestrator (Routstr model only); keep Grok failover | Medium |
| **PR4** | Live Cashu create/topup parsers + ignored live tests | Low–med |
| **PR5** | Live refund + token hygiene | Low–med |
| **PR6** | Docs north-star invoice-first; RESIDUAL checkboxes | Low |
| **PR7+** | LDK pay path (Phase C) | High |
| **PR8+** | CDK mint (Phase D) | High |

Do **not** block PR1–6 on LDK/CDK.

---

## Non-goals

- Enable `ldk` / `cashu-cdk` in default CI before green.  
- Flip `*_live` without real success paths.  
- Store wallet seed in CredentialsStore, Zed stores, or `provider_credentials.json`.  
- Claim BOLT12.  
- Auto-create SeedVault on first chat.  
- Open browser to routstr.com for funding.  
- Auto-select `routstr-grok-4.5` after topup.  

---

## Key code

| Area | Path |
|------|------|
| Live Routstr HTTP | `xai-grok-shell/src/auth/routstr.rs` |
| Grok API-key store | `xai-grok-shell/src/auth/credentials_store.rs` |
| Zed OpenRouter probe | `xai-grok-shell/src/auth/harness_secrets.rs` |
| Invoice pure types | `grok-bitcoin-wallet/src/routstr_invoice.rs` |
| SeedVault | `grok-bitcoin-wallet/src/seed_vault.rs` |
| Residual copy | `grok-bitcoin-wallet/src/funding_cli.rs` |
| TUI slash | `xai-grok-pager/src/app/dispatch/routstr.rs` |
| Credit bar | `xai-grok-pager/src/views/credit_bar.rs` |
| 402 / failover | `xai-grok-sampler` + shell agent config |

## Validation (when implementing)

```bash
cargo test -p xai-grok-shell --lib routstr
cargo test -p xai-grok-pager --lib routstr
cargo test -p grok-bitcoin-wallet
./scripts/bitcoin-routstr-validate.sh
```

## Implement gate

Phases A–B + PR6 docs landed 2026-07-20. Phases C–D (LDK pay, CDK mint) stay
gated on real capability flags and separate implement prompts.
