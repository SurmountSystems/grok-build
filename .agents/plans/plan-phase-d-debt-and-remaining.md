# Plan: Unfuck `descriptor_wallet` — BitMask-scale modules + stop residual debt

## Context

**Trigger:** Dual-hash combinatorial grind was already technical debt. On inspection
the real horror is larger: **`descriptor_wallet.rs` is ~64 380 lines** — not a
descriptor wallet, a monorepo in one file. At DIBA/BitMask, descriptor code was
on the order of **a few hundred lines per file**. This is structural failure.

**Zone map (current file):**

| Lines | ~LOC | Zone |
|------:|-----:|------|
| 1–2 365 | 2.4k | Types, gap, coin select, fee/RBF/CPFP plans, `DescriptorWallet`, build/sign BIP84 |
| 2 366–11 004 | **8.6k** | Hand-rolled `bare_tapscript_*` template parsers (~76 fns) |
| 11 005–11 356 | 0.4k | `finalize_taproot_key_path` |
| 11 357–16 416 | **5.1k** | **`finalize_taproot_script_path` dispatch mega-fn** |
| 16 417–18 177 | 1.8k | Public `finalize_psbt`, extract/broadcast, prepare spend / RBF / CPFP |
| 18 178–64 380 | **46.2k** | **In-file `#[cfg(test)] mod tests`** |

Also: `RESIDUAL.md` ~2.9k lines with ~89 clone “Done this pass” tables;
AUTOMATIC_FUNDING + README one-line miniscript encyclopedias; next-prompt still
steers permutation grind; lock+H1 already in code while residual lags.

**Goal (revised, aggressive):**

1. **Stop bleeding** — freeze dual-hash `and_v` permutation treadmill.
2. **Unfuck structure** — split into BitMask-scale modules (**target ≤ ~400–600
   LOC production per file**; tests co-located or under `tests/` / sibling
   modules, not one 46k block).
3. **Delete pure permutation debt** — dual-hash `and_v` orderings with no
   product descriptor consumer; keep policy-shaped forms (HTLC, vault, multi-key,
   dual-hash **or_i**, dual-timeout, single-hash combined).
4. **Collapse residual docs** so true product residual is visible.
5. **Only then** resume product residual (channel IPC, NIP-98 if live contract,
   bdk auto-sync, BIP-39 persistence).

**Constraints (unchanged product laws):**

- Live Routstr Bearer `sk-` / `cashu…` only — never invent product NIP-98 Success.
- Seed never CredentialsStore / provider_credentials / watch_session.
- `BOLT12_SUPPORTED=false`; default CI off `ldk` / `cashu-cdk`.
- No invented Success on channel / pay / mint / melt.
- Dual residual honesty after every structural PR.
- **Behavior-preserving mechanical moves first**; prune is explicit second pass
  with full green tests.

**Non-goals:**

- Finishing every CLEANSTACK dual-hash ordering.
- Bare top-level `or_c` Complete (stays Partial).
- Full rust-miniscript rewrite in the first unfuck stack (open longer-term option).
- Product residual PRs until structure is under control (except freeze/docs).

**Success metric:**

- No single file in `descriptor_wallet/` over **~800 LOC production** without a
  written exception (dispatch table may need a thin router + per-arm modules).
- Tests not living as one 46k blob inside the production module.
- Residual next-prompt no longer mentions dual-hash orderings as work.
- `cargo test -p grok-bitcoin-wallet --lib` fail=0 after each PR.

**Assumptions:**

- User wants **serious unfuck**, not freeze-only lipstick.
- Prefer several small behavior-preserving PRs over one 64k rewrite.
- Prune dual-hash `and_v` permutations **yes** (default), after split so
  deletes are reviewable.

---

## Debt inventory

| Id | Debt | Scale | Fix |
|----|------|------:|-----|
| **B0** | Single mega-file | 64k LOC | Module tree (**primary**) |
| **B1** | In-file test megablob | 46k LOC | Extract tests per module / integration |
| **B2** | `finalize_taproot_script_path` | 5.1k LOC one fn | Thin match → per-family finalizers |
| **B3** | bare_tapscript template farm | 8.6k / ~76 fns | One family per file (~200–400 LOC) |
| **B4** | Dual-hash `and_v` permutations | ~22 parsers + tests | **Delete** non-canonical; freeze forever |
| **B5** | Residual Done-pass spam | ~89 tables / 2.9k lines | Collapse to current residual |
| **B6** | AUTOMATIC_FUNDING / README catalogs | encyclopedia cells | Class-level summary |
| **B7** | Next-prompt treadmill | permutation steering | Product residual only + forbid |
| **B8** | Honesty lag (e.g. lock+H1) | code vs residual | Fix during collapse; prune may remove form |

**Keep (policy-shaped offline finalize):** multi_a / thresh s:/a: / mixed+hash;
nested or_c/or_i + multi-arm; multi-key ± lock/hash; vault; inheritance; HTLC +
reverse HTLC; dual-hash **or_i**; dual-timeout **or_i**; all six single-hash
{pk,hash,lock} and_v triples; **one** representative dual-hash+timeout AND
(e.g. pk-first) if still wanted — **not** the full ordering matrix.

---

## Approach

### Recommended: **split → prune → docs freeze → product**

BitMask lesson: **many small files, clear ownership**, not one god-module.

```
crates/codegen/grok-bitcoin-wallet/src/descriptor_wallet/
  mod.rs                 # re-exports; thin (~150–300)
  types.rs               # UTXO, balance, outcomes, constants
  gap.rs                 # gap extend math + snapshot types
  coin_select.rs
  fee.rs                 # vbytes, RBF/CPFP plan pure math
  chain_source.rs        # trait + mock + mempool
  wallet.rs              # DescriptorWallet core
  psbt_build.rs
  sign_bip84.rs
  spend_prepare.rs       # prepare / gap-sync spend / RBF / CPFP product paths
  broadcast.rs           # extract + broadcast helpers
  finalize/
    mod.rs               # pub finalize_psbt router
    outcome.rs
    p2wpkh.rs
    p2wsh.rs
    taproot_key.rs
    taproot_script/
      mod.rs             # thin dispatch only
      multi_a.rs
      thresh.rs
      nested_or.rs
      multi_key.rs
      vault_inheritance.rs
      htlc.rs            # HTLC + reverse + dual-hash or_i + dual-timeout
      combined_hash_lock.rs  # single-hash six triples + optional one dual-hash AND
  bare_tapscript/
    mod.rs
    common.rs            # shared instruction helpers / parts structs
    checksig_basic.rs
    older_after.rs
    hash_pk.rs
    or_c.rs
    or_i.rs
    multi_key.rs
    vault_htlc.rs
    dual_hash_or_i.rs
    combined_and_v.rs    # policy-shaped only after prune
```

**Target sizes:** production module **≤ ~400–600 LOC**; if a family still exceeds
~800, split again. Co-located tests OK if total file ≤ ~1.5–2k; otherwise
sibling `*_tests` / `tests/` files.

### Rejected

- **Freeze-only / docs-only** — leaves 64k god-file; user correctly rejected.
- **One giant PR** — unreviewable; stack of mechanical PRs instead.
- **rust-miniscript full replace first** — high risk; optional Track M later once
  modules exist and surface is small enough to compare.
- **Continue permutation implement** — forbidden.

### PR stack (Graphite-friendly)

| PR | Name | Risk | Exit criteria |
|----|------|------|----------------|
| **PR0** | Freeze + residual collapse + forbid next-prompt | Low (docs) | No permutation work items; 1 current residual table; name the 64k unfuck |
| **PR1** | `descriptor_wallet/` module dir + **extract 46k tests** out of production path | Med | No longer one 64k file; tests green |
| **PR2** | Extract wallet core: types, gap, coin_select, fee, chain, wallet, psbt_build, sign, spend_prepare, broadcast | Low–med | Core files few-hundred LOC each |
| **PR3** | Extract `bare_tapscript/` by family (no deletes yet) | Med | Templates not one 8.6k slab |
| **PR4** | Extract `finalize/` + **split** 5.1k `finalize_taproot_script_path` into per-family finalizers + thin dispatch | High | No 5k-line function |
| **PR5** | **Prune** dual-hash `and_v` permutation templates + tests; keep canonical set; honesty docs | Med–high | Dead orderings gone; lib tests green |
| **PR6+** | Product residual: channel IPC → (NIP-98 if contract) → bdk sync → BIP-39 | Product | Only after PR0–PR5 |

---

## Critical files

| Path | Why |
|------|-----|
| `crates/codegen/grok-bitcoin-wallet/src/descriptor_wallet.rs` | **Source of pain** — becomes dir or thin re-export |
| `crates/codegen/grok-bitcoin-wallet/src/lib.rs` | `mod descriptor_wallet` path |
| `RESIDUAL.md` | Collapse; freeze next-prompt; name modularization debt |
| `docs/bitcoin-routstr/AUTOMATIC_FUNDING.md` | Phase D cell; mark offline finalize frozen/pruned |
| `crates/codegen/grok-bitcoin-wallet/README.md` | Class-level finalize summary |
| New `descriptor_wallet/**` | Target BitMask-scale modules |
| `crates/codegen/grok-bitcoin-ldk-node/` | Later product residual only |
| Shell Routstr auth | NIP-98 residual only; no invent |

---

## Reuse

| Symbol | How |
|--------|-----|
| Existing `bare_tapscript_*` + finalize arms | **Move first**, prune second — cut-paste with re-exports |
| Public API (`finalize_psbt`, `DescriptorWallet`, select/prepare) | Stable via `descriptor_wallet::` re-exports |
| Sibling reject tests | Keep for canonical forms; delete with pruned forms |
| Implement memory | Anti-pattern: no new dual-hash and_v orderings; no growing god-files |

---

## Steps (detailed)

### Phase 0 — Stop the bleeding (docs + policy)

1. Collapse `RESIDUAL.md` to **Current residual** (product only) + **Landed
   offline finalize (classes)** + forbid permutation next-prompt.
2. Shorten AUTOMATIC_FUNDING Phase D miniscript cell; README class-level.
3. Explicitly name **64k god-file modularization** as active engineering debt
   (BitMask-scale target).

### Phase 1 — Mechanical modularization (behavior-preserving)

4. **PR1 shell:** `src/descriptor_wallet/mod.rs`; move content; keep `pub use`
   surface identical.
5. **PR1 tests:** extract 46k test module into `descriptor_wallet/tests/` or
   multiple files so production is reviewable. Group tests by family matching
   future modules.
6. **PR2:** peel types / gap / coin_select / fee / chain / wallet / psbt / sign /
   spend / broadcast — each few hundred LOC.
7. **PR3:** peel `bare_tapscript/*` by family (names above).
8. **PR4:** replace 5.1k `finalize_taproot_script_path` with thin dispatch
   calling `finalize_<family>(…)` in sibling modules. **No logic change** —
   cut arms only.

### Phase 2 — Prune permutation debt

9. Canonical set freeze list in `bare_tapscript/mod.rs` / residual.
10. Delete non-canonical dual-hash `and_v` templates, finalize arms, tests.
11. Align residual/README/AUTOMATIC_FUNDING honesty.

### Phase 3 — Product residual (only after Phase 0–2)

12. Channel `open_channel` / `connect_peer` real IPC.
13. NIP-98 product Success only on live-contract proof.
14. bdk auto-sync; BIP-39 persistence (SeedVault only).

### Phase 4 — Guardrails

15. Implement-memory anti-patterns (god-file + permutation).
16. Optional CI: fail if any file under `descriptor_wallet/` exceeds N lines
    (e.g. warn 1500 / fail 2500) without allowlist.
17. Optional Track M: rust-miniscript spike later — not default in this stack.

---

## Risks

| Risk | Mitigation |
|------|------------|
| Move breaks `pub use` / external callers | Re-export from `mod.rs`; workspace grep |
| Finalize split match-order bugs | Cut-paste arms only; full lib test each PR |
| Prune deletes something product needs | No product descriptor consumer for dual-hash and_v matrix; keep or_i + HTLC |
| PR1 test move visibility | `pub(crate)` helpers as needed |
| Scope creep to miniscript rewrite | Explicit non-goal until Track M |

---

## Verification

Each PR:

```bash
cargo test -p grok-bitcoin-wallet --lib
cargo clippy -p grok-bitcoin-wallet --lib -- -D warnings
cargo fmt -p grok-bitcoin-wallet -- --check
find crates/codegen/grok-bitcoin-wallet/src/descriptor_wallet -name '*.rs' | xargs wc -l
```

- No new `bare_tapscript_and_v_*dual_hash*` siblings after freeze.
- Residual next-prompt: product residual only (or “continue unfuck PR N”).
- After PR5: permutation symbols gone; canonical forms green.

---

## Open questions

1. **Test layout:** co-located per module vs `tests/*.rs`? **Recommend hybrid** —
   unit tests co-located; heavy PSBT fixtures in `tests/finalize_*.rs`.
2. **Prune timing:** after full split (safer) vs before (less code to move)?
   **Recommend PR1–4 then PR5.**
3. **Hard LOC ceiling** for CI? Propose warn 1500 / fail 2500 under
   `descriptor_wallet/`.
4. **Track M (rust-miniscript)** in this stack? **Later.**

---

## Suggested first implement prompt (after approval)

```text
Phase D UNFUCK — PR0 only (docs/policy; no structure move yet):

1. Collapse RESIDUAL.md to one Current residual table (product NIP-98,
   channel open/connect, bdk auto-sync, BIP-39 persistence, BOLT12 false,
   bare top-level or_c Partial) + short Landed offline finalize by CLASS
   (not every ordering). Drop Done-pass clone tables.
2. Next /implement prompt: FORBID new dual-hash and_v orderings and further
   bare_tapscript permutation templates. Point next real code work at
   modularizing descriptor_wallet (PR1+), not miniscript fragments.
3. Shorten AUTOMATIC_FUNDING Phase D miniscript cell; mark fragment matrix
   as debt under unfuck, not roadmap.
4. Trim wallet README finalize catalog to classes.
5. Note in residual that descriptor_wallet.rs ~64k LOC modularization is
   active debt (BitMask-scale target: few hundred LOC/file).

Do not add templates. Do not invent NIP-98 Success. Do not enable default
CI ldk/cashu-cdk. Seed never CredentialsStore. Prefer docs-only; keep tests
green if any code touch.
```

After PR0: **PR1 mechanical module shell + extract 46k tests**.
