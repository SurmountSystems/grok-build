# Residual work: Bitcoin-native Routstr + wallet (2026-07-20)

**North star:** L1 → pay mint → Cashu proofs → redeem → Routstr float (and
later real Nostr/NIP-06/NIP-98 product auth when the live contract allows).
Not combinatorial miniscript.

**Honest post-mortem:** A residual `/implement` treadmill spent a large amount
of work on hand-rolled Taproot bare-tapscript finalize permutations (dual-hash
`and_v` orderings, etc.) that **no product descriptor path needs**. That work
inflated `descriptor_wallet` and this document. NIP-06 **library** + NIP-98
**pure helpers** landed; **product** NIP-06/NDK-style Routstr auth did **not**
— live Routstr is still Bearer `sk-` / `cashu…` only. That priority inversion
is debt. Engineering unfuck **PR0–PR5 is complete**; next work is **product**
residual only.

Historical Done-pass / Validation tables: **deleted from this file** (git
history retains them). Do not re-add per-fragment clone tables.

---

## Current residual (product)

| Item | Status |
|------|--------|
| **Product NIP-06 / NIP-98 / NDK-style Routstr auth** | **Residual (offline-proveable refuse e2e)** — pure `nip06` + `nip98` library green offline; live Routstr `validate_bearer_key` accepts **Bearer `sk-` / `cashu…` only**. Product `classify_routstr_product_auth_material` + `validate_routstr_product_bearer_key` + login/store/env/inference (`collect_own_credentials`) **refuse** NIP-98 / nsec / BIP-39 / hex-seed (`ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false`; residual error variants + honesty lines; never CredentialsStore / provider_credentials / watch_session). Wire product Success **only** under an offline-proveable live contract. Never invent signed-auth Success. |
| **Live channel open / connect peer** | **Residual (explicit refuse)** — live open/connect still not landed; helper **recognizes** `open_channel` / `connect_peer` and returns structured `ok:false` residual error text (distinct from `unknown cmd` typo); product caps `channel_open_live` / `connect_peer_live` always false (even when BOLT11 pay/invoice live); product API `open_channel*` / `connect_peer*` return Unsupported residual — never channel_id Success. Wizard peer seed pure. Offline-proveable residual IPC/API. |
| **Full `bdk_wallet` auto-sync** | **Landed (feature `bdk`, not default CI)** — library + **shell/CLI prefer-BDK product wire**. Real `bdk_wallet` 2.4 pin; injectable `BdkUpdateSource` + Esplora/Electrum full_scan transports; product list/spend-from-snapshot helpers. Shell/pager-bin optional feature `bdk` (forwards wallet; **not** default CI). Env `GROK_BITCOIN_UTXO_SYNC=gap\|bdk` (empty/unset → **gap**; single parser). Prefer-BDK + feature → `open_product_bdk_update_source` (esplora/electrum live; **mempool fails closed** with residual guidance). Prefer-BDK without feature → structured residual (not hang / invent Success). BDK notice lines on CLI (never gap-limit residual when BDK ran). **Default product path remains gap-limit** ChainSource. |
| **BIP-39 / passphrase persistence** | **Landed (policy + AEAD entropy encoding)** — `assert_allowed_seed_storage_path` refuses `provider_credentials.json` / `watch_session.json` / `config.toml` (constructor + AEAD store/load/entropy); AEAD v1 phrase + v2 entropy bytes (`store_aead_entropy`); keyring stays phrase for OS UX; passphrase never at rest (unlock env/API); watch-session JSON has no mnemonic/passphrase fields. Still never CredentialsStore. |
| **BOLT12** | **Still false** (`BOLT12_SUPPORTED=false`). |
| **Bare top-level `or_c` finalize** | **Residual forever** unless CLEANSTACK story changes — honest Partial. |
| **AUR / distro helper packages** | Open (Nix packages green). |
| **Default monorepo CI** | Must stay **off** `ldk` / `cashu-cdk` / `bdk`. |

### Preserved product greens (do not regress)

- Phase A–B invoice-first Routstr float (create/topup/refund, ensure_ready, 402).
- Phase C LDK pay + invoice create (feature `ldk` + helper IPC); P0 QR fallback.
- Phase D CDK mint + melt product CLI/TUI; prefer cashuA over large hot `sk-`.
- SeedVault; NIP-06 library; NIP-98 pure Authorization helpers (not product wire).
- Offline finalize for **policy-shaped** forms (P2WPKH/P2WSH/Taproot key-path,
  multi_a, thresh, nested or_c/or_i, multi-key, vault, inheritance, HTLC,
  dual-hash **or_i**, dual-timeout, single-hash combined triples, dual-hash
  `and_v` **PR5 keep set** only — see below).

### Engineering unfuck (PR0–PR5) — **done**

| Debt | Reality |
|------|---------|
| **`descriptor_wallet` god-module** | PR1 tests peel; PR2 wallet core; PR3 bare_tapscript families; PR4 finalize → `finalize.rs` (Option A); PR5 dual-hash prune |
| **Dual-hash `and_v` permutation farm** | **PR5 done** — keep set only in `bare_tapscript/and_v_dual_hash.rs` (~0.7k LOC, 5 templates); 10 exotic orderings deleted with matching finalize arms + tests |
| **Test megablob** | Still `tests.rs` (~38k after PR5); optional later split by family — **not** product residual |
| **`finalize_taproot_script_path`** | Still one large fn in `finalize.rs` — optional thin dispatch later; **not** product residual |

**Forbidden:** new dual-hash `and_v` fragment orderings; new bare_tapscript
permutation templates; “Done this pass” clone tables; residual prompts that
steer miniscript matrix work.

#### PR5 dual-hash `and_v` keep set

| Keep | Template |
|------|----------|
| pk + dual-hash + lock | `bare_tapscript_and_v_pk_dual_hash_lock_template` |
| pk + dual-hash | `bare_tapscript_and_v_pk_dual_hash_template` |
| dual-hash + pk | `bare_tapscript_and_v_dual_hash_pk_template` |
| sandwich hash+pk+hash | `bare_tapscript_and_v_hash_pk_hash_template` |
| reverse dual-hash + pk + lock | `bare_tapscript_and_v_dual_hash_pk_lock_template` |

Pruned (no product consumer): lock-first / middle-lock / exotic H1–H2
interleavings (`hash_pk_hash_lock`, `hash_pk_lock_hash`, `pk_hash_lock_hash`,
`pk_lock_dual_hash`, `lock_pk_dual_hash`, `lock_dual_hash_pk`,
`hash_lock_hash_pk`, `dual_hash_lock_pk`, `hash_lock_pk_hash`,
`lock_hash_pk_hash`).

Canonical plan: `docs/bitcoin-routstr/AUTOMATIC_FUNDING.md` + session
`.agents`/session plan **Unfuck descriptor_wallet**.

---

## Landed offline finalize (classes only)

Hand-rolled bare-tapscript library finalize (offline Complete when material
present; never invents sigs/preimages/nSequence/nLockTime). **Frozen** —
extend only for a real product descriptor demand.

- Key-path; bare CHECKSIG; multi_a; thresh s:/a: / mixed + hash arms
- Nested `and_v(or_c|or_i, older|after|hash)` + multi-arm
- Multi-key pk ± lock/hash (incl. reverse + sandwich)
- Vault + inheritance
- HTLC + reverse HTLC; dual-hash **or_i**; dual-timeout **or_i**
- Single-hash combined (six {pk, hash, lock} and_v triples)
- Dual-hash `and_v` **PR5 keep set** (5 forms above) — not a roadmap to re-expand

---

## Next `/implement` prompt (copy)

```text
Product residual (NOT miniscript / NOT more dual-hash and_v):

North star: L1 → Cashu → Routstr float; real NIP-06/NIP-98/NDK product auth
only when live contract allows. Engineering unfuck PR0–PR5 is complete
(descriptor_wallet peeled; dual-hash and_v pruned to 5 canonical forms).

Pick ONE product slice (do not invent signed-auth Success):

1. Product NIP-98 / NIP-06 Routstr auth — **residual refuse hardened**
   (classify/validate/login/store/inference; ROUTSTR_PRODUCT_NIP98_AUTH_LIVE
   stays false). Land product Success ONLY if live contract offline-proveable;
   never invent signed-auth Success.
2. Live channel open / connect peer — **residual hardened** (explicit helper
   residual IPC + product caps/API Unsupported); only land live Success under
   an offline-proveable open/connect contract (not yet).
3. ~~Shell/CLI prefer-BDK product wire~~ **landed** (feature `bdk` + env
   `GROK_BITCOIN_UTXO_SYNC`; default gap; CI still off `bdk`).
4. ~~Optional SeedVault entropy-bytes encoding upgrade~~ **landed** (AEAD v2
   entropy via `store_aead_entropy`; load accepts v1+v2; keyring phrase; never
   CredentialsStore / watch_session / provider_credentials; passphrase unlock-only).

Do NOT: new dual-hash and_v orderings; enable ldk/cashu-cdk/bdk default CI;
BOLT12 true; seed in CredentialsStore; invent NIP-98/channel Success;
re-add Done-pass clone tables. Prefer NIP-98 when contract exists; channel
stays residual until live open/connect contract.

Hard gates: cargo test -p grok-bitcoin-wallet --lib; clippy -D warnings; fmt.
```

---

## Hard invariants

- Never invent product Success (auth, channel, pay, mint, melt).
- Live Routstr auth shapes today: Bearer `sk-` / `cashu…` only.
- Seed / nsec never CredentialsStore / provider_credentials / watch_session.
- `BOLT12_SUPPORTED=false` until real support.
- Default monorepo CI free of `ldk` / `cashu-cdk` / `bdk`.
- No new dual-hash `and_v` permutation templates.
- Language: Bitcoin / Lightning / Cashu — never “crypto.”
