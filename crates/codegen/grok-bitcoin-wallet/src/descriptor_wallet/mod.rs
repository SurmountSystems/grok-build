//! Descriptor-shaped BIP84 wallet surface: list UTXOs + coin selection + PSBT.
//!
//! Default product UTXO path: **lightweight gap-limit** sync over injectable
//! [`ChainSource`] (list + optional bounded window extend). Real
//! `bdk_wallet` auto-sync (spent-tx history + keychain) lives in
//! [`crate::bdk_sync`] behind optional feature `bdk` (not default CI).
//! Injectable electrum/esplora backends live in [`crate::electrum`] /
//! [`crate::esplora`] (mock always; live HTTP/TCP feature-gated). Product env
//! selection is [`crate::chain_select`] (default mempool). This module provides:
//! - BIP84 external/internal descriptor **strings** (wpkh account xpub)
//! - injectable [`ChainSource`] (mock for tests; live mempool UTXO behind
//!   `explorer-http`; electrum/esplora via sibling modules)
//! - [`list_unspent`], balance, gap-limit [`DescriptorWallet::sync_utxos`] /
//!   [`DescriptorWallet::sync_with_gap_extend`], product
//!   [`list_bip84_utxos_with_gap_sync`] (snapshot-authoritative list/balance —
//!   no extra list) + [`select_and_prepare_bip84_spend_with_gap_sync`]
//!   (select-from-snapshot after sync — no extra list; [`GapSyncSpendFailure`]
//!   AfterSync keeps hit-max notices on select/prepare Err),
//!   [`select_and_prepare_bip84_spend_from_utxos`], and fee-aware
//!   [`select_coins`] APIs
//! - unsigned PSBT build from [`CoinSelection`] ([`build_unsigned_psbt`])
//! - BIP84 P2WPKH sign + offline finalize ([`finalize_psbt`]) for completeable
//!   single-key paths, bare m-of-n CHECKMULTISIG P2WSH when enough
//!   `partial_sigs` are present, **Taproot key-path** when `tap_key_sig` is
//!   already present, and **Taproot script-path** bare single-key x-only
//!   CHECKSIG, bare multi_a (`CHECKSIG`/`CHECKSIGADD`/`NUMEQUAL`), bare
//!   thresh (`CHECKSIG` + `SWAP CHECKSIG ADD`… + `k EQUAL` = s:pk form,
//!   `CHECKSIG` + `TOALTSTACK CHECKSIG FROMALTSTACK ADD`… + `k EQUAL` =
//!   a:pk / non-s:pk form, mixed s:/a: interleaving of SWAP and
//!   TOALTSTACK arms with both kinds present, `n ≥ 3`, and one **or more**
//!   pure **s:hash** / pure **a:hash** non-pk arms
//!   `thresh(k, pk…, s:hash|a:hash(H), …)` (trailing/middle/multi-hash pure
//!   form) when matching preimage(s) + `k − n_hash` pk sigs are present, and
//!   **mixed s:/a: with hash** (both SWAP and TOALTSTACK wrappers plus one+
//!   hash arm) under the same preimage + `k − n_hash` pk-sig policy), bare
//!   and_v CHECKSIGVERIFY…CHECKSIG chains, bare or_i IF/ELSE dual CHECKSIG,
//!   bare or_d CHECKSIG IFDUP NOTIF dual CHECKSIG, bare and_n CHECKSIG
//!   NOTIF 0 ELSE CHECKSIG, bare andor CHECKSIG NOTIF CHECKSIG ELSE
//!   CHECKSIG, bare miniscript hash (`SIZE 32 EQUALVERIFY HASHOP digest
//!   EQUAL`) when matching PSBT preimage maps are present, or
//!   `and_v(v:pk, hash)` / `and_v(v:hash, pk)` when both matching
//!   `tap_script_sigs` + preimage are present, or **older/CSV** forms
//!   (`and_v(v:pk, older(n))` / `and_v(v:older(n), pk)` / bare `older(n)`)
//!   when matching sigs (if any) and the **already-present** unsigned-tx
//!   nSequence satisfies BIP-112 CSV, or nested CLEANSTACK-valid
//!   **`and_v(or_c(pk(A), v:pk(B)), older(n))`** / **`and_v(or_c(pk(A), v:pk(B)), after(n))`**
//!   / **`and_v(or_c(pk(A), v:pk(B)), hash(H))`** when a matching sig for A
//!   and/or B is present and the **already-present** nSequence (older/CSV),
//!   nLockTime+nSequence (after/CLTV), or PSBT preimage (hash) satisfies the
//!   trailing fragment (bare top-level `or_c` stays residual), or nested
//!   CLEANSTACK-valid **`and_v(or_i(v:pk(A), v:pk(B)), hash(H))`**
//!   (`IF CHECKSIGVERIFY ELSE CHECKSIGVERIFY ENDIF SIZE 32 EQUALVERIFY HASHOP
//!   digest EQUAL`) when a matching IF and/or ELSE sig + PSBT preimage are
//!   present (IF preferred; never invents), or nested CLEANSTACK-valid
//!   **`and_v(or_i(v:pk(A), v:pk(B)), older(n))`** /
//!   **`and_v(or_i(v:pk(A), v:pk(B)), after(n))`**
//!   (`IF CHECKSIGVERIFY ELSE CHECKSIGVERIFY ENDIF <n> CSV|CLTV`) when a
//!   matching IF and/or ELSE sig + already-present nSequence (older) or
//!   nLockTime+nSequence (after) satisfy the trailing fragment (IF preferred;
//!   never invents), or nested CLEANSTACK-valid multi-arm
//!   **`and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), older(n)|after(n)|hash(H))`**
//!   (`CHECKSIG NOTIF CHECKSIG NOTIF CHECKSIGVERIFY ENDIF ENDIF <n> CSV|CLTV`
//!   or trailing bare hash fragment) when a matching A and/or B and/or C sig +
//!   already-present locktime material (older/after) or matching 32-byte PSBT
//!   preimage (hash) satisfy the trailing fragment (A preferred over B over C;
//!   never invents), or nested CLEANSTACK-valid multi-arm
//!   **`and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), older(n)|after(n)|hash(H))`**
//!   (`IF CHECKSIGVERIFY ELSE IF CHECKSIGVERIFY ELSE CHECKSIGVERIFY ENDIF ENDIF
//!   <n> CSV|CLTV` or trailing bare hash fragment) when a matching A and/or B
//!   and/or C sig + already-present locktime material (older/after) or matching
//!   32-byte PSBT preimage (hash) satisfy the trailing fragment (A preferred
//!   over B over C; never invents), or nested CLEANSTACK-valid multi-key
//!   **`and_v(and_v(v:pk…), older(n)|after(n)|hash(H))`** (n ≥ 2 all-`v:pk`
//!   CHECKSIGVERIFY chain + trailing CSV|CLTV|bare hash) when **all** n
//!   matching `tap_script_sigs` + already-present nSequence (older) /
//!   nLockTime+nSequence (after) / matching 32-byte PSBT preimage (hash) are
//!   present (never invents; no empty placeholders), or nested CLEANSTACK-valid
//!   multi-key reverse **`and_v(v:older|after|hash, and_v(v:pk…))`** (CSV|CLTV|
//!   v:hash VERIFY prefix + CHECKSIGVERIFY…CHECKSIG n ≥ 2) when **all** n
//!   matching `tap_script_sigs` + locktime/preimage material are present
//!   (never invents), or nested CLEANSTACK-valid multi-key **sandwich**
//!   **`and_v(v:pk…, and_v(v:older|after|hash, pk…))`** (left CHECKSIGVERIFY
//!   chain + middle CSV|CLTV|v:hash VERIFY + right CHECKSIG tail; left ≥ 1,
//!   right ≥ 1) when **all** left+right sigs + locktime/preimage material are
//!   present (never invents), or nested CLEANSTACK-valid vault
//!   **`or_i(and_v(v:pk…)|pk, older|after|hash)`** (IF multi-pk CHECKSIGVERIFY…
//!   CHECKSIG ≥ 1; ELSE CSV|CLTV|bare hash) when **all** IF-arm sigs present
//!   (IF preferred) **or** ELSE timeout/hash material (already-present
//!   nSequence / nLockTime+nSequence / 32-byte PSBT preimage) is present
//!   (never invents), or nested CLEANSTACK-valid delayed-recovery inheritance
//!   **`or_i(and_v(v:pk…)|pk, and_v(v:pk…, older|after|hash))`** (IF hot ≥ 1;
//!   ELSE cold ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV|bare hash) when **all**
//!   IF-arm sigs present (IF preferred) **or** all ELSE cold sigs + locktime/
//!   preimage material are present (never invents), or nested CLEANSTACK-valid
//!   HTLC dual-path
//!   **`or_i(and_v(v:pk…, hash(H)), and_v(v:pk…, older(n)|after(n)))`** (IF
//!   claim ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash; ELSE refund ≥ 1 all-`v:pk`
//!   CHECKSIGVERIFY + CSV|CLTV) when **all** IF claim sigs + matching 32-byte
//!   PSBT preimage present (IF preferred) **or** all ELSE refund sigs +
//!   already-present nSequence (older) / nLockTime+nSequence (after) are
//!   present (never invents), or nested CLEANSTACK-valid reverse HTLC
//!   **`or_i(and_v(v:pk…, older(n)|after(n)), and_v(v:pk…, hash(H)))`** (IF
//!   timeout ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV; ELSE claim ≥ 1
//!   all-`v:pk` CHECKSIGVERIFY + bare hash — arms swapped vs classic HTLC)
//!   when **all** IF timeout sigs + already-present nSequence (older) /
//!   nLockTime+nSequence (after) present (IF preferred) **or** all ELSE claim
//!   sigs + matching 32-byte PSBT preimage are present (never invents), or
//!   nested CLEANSTACK-valid dual-hash
//!   **`or_i(and_v(v:pk…, hash(H1)), and_v(v:pk…, hash(H2)))`** (IF claim ≥ 1
//!   all-`v:pk` CHECKSIGVERIFY + bare hash; ELSE claim ≥ 1 all-`v:pk`
//!   CHECKSIGVERIFY + bare hash — dual claim paths, no CSV|CLTV) when **all**
//!   IF claim sigs + matching 32-byte PSBT preimage for H1 present (IF
//!   preferred) **or** all ELSE claim sigs + matching 32-byte PSBT preimage
//!   for H2 are present (never invents), or nested CLEANSTACK-valid dual-timeout
//!   **`or_i(and_v(v:pk…, older(n1)|after(n1)), and_v(v:pk…, older(n2)|after(n2)))`**
//!   (IF timeout ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV; ELSE timeout ≥ 1
//!   all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual timeout paths, no hash) when
//!   **all** IF timeout sigs + already-present nSequence (older) /
//!   nLockTime+nSequence (after) present (IF preferred) **or** all ELSE
//!   timeout sigs + matching locktime material are present (never invents), or
//!   nested CLEANSTACK-valid combined hash+timeout
//!   **`and_v(v:pk…, and_v(v:hash(H), older(n)|after(n)))`** (≥ 1 all-`v:pk`
//!   CHECKSIGVERIFY + v:hash VERIFY + CSV|CLTV — single path requiring **both**
//!   preimage and locktime, not OR like HTLC) when **all** key sigs + matching
//!   32-byte PSBT preimage + already-present nSequence (older) /
//!   nLockTime+nSequence (after) are present (never invents), or nested
//!   CLEANSTACK-valid reverse combined hash+timeout
//!   **`and_v(v:hash(H), and_v(v:pk…, older(n)|after(n)))`** (v:hash VERIFY +
//!   ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual of pk-first form; same
//!   both-required material gate; witness preimage top) when **all** key sigs +
//!   matching 32-byte PSBT preimage + already-present nSequence (older) /
//!   nLockTime+nSequence (after) are present (never invents), or nested
//!   CLEANSTACK-valid lock-first combined hash+timeout
//!   **`and_v(v:older(n)|after(n), and_v(v:pk…, hash(H)))`** (CSV|CLTV VERIFY
//!   prefix + ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL — lock-order dual;
//!   same both-required material gate; witness preimage deepest) when **all**
//!   key sigs + matching 32-byte PSBT preimage + already-present nSequence
//!   (older) / nLockTime+nSequence (after) are present (never invents), or
//!   nested CLEANSTACK-valid pk+middle-lock+trailing-hash combined hash+timeout
//!   **`and_v(v:pk…, and_v(v:older(n)|after(n), hash(H)))`** (≥ 1 all-`v:pk`
//!   CHECKSIGVERIFY + middle CSV|CLTV VERIFY + bare hash EQUAL — keys-before-lock
//!   dual of lock-first; same both-required material gate; witness preimage
//!   deepest) when **all** key sigs + matching 32-byte PSBT preimage +
//!   already-present nSequence (older) / nLockTime+nSequence (after) are
//!   present (never invents), or nested CLEANSTACK-valid
//!   hash+middle-lock+trailing-pk combined hash+timeout
//!   **`and_v(v:hash(H), and_v(v:older(n)|after(n), pk…))`** (v:hash VERIFY +
//!   middle CSV|CLTV VERIFY + ≥ 1 trailing keys ending CHECKSIG — hash/pk dual
//!   of pk+lock+hash; same both-required material gate; witness preimage top)
//!   when **all** key sigs + matching 32-byte PSBT preimage + already-present
//!   nSequence (older) / nLockTime+nSequence (after) are present (never invents),
//!   or nested CLEANSTACK-valid lock+middle-hash+trailing-pk combined
//!   hash+timeout **`and_v(v:older(n)|after(n), and_v(v:hash(H), pk…))`**
//!   (CSV|CLTV VERIFY prefix + v:hash VERIFY + ≥ 1 trailing keys ending
//!   CHECKSIG — lock-order dual of hash+lock+pk; same both-required material
//!   gate; witness preimage top) when **all** key sigs + matching 32-byte PSBT
//!   preimage + already-present nSequence (older) / nLockTime+nSequence (after)
//!   are present (never invents), or nested CLEANSTACK-valid dual-hash+timeout
//!   combined **`and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older(n)|after(n))))`**
//!   (≥ 1 all-`v:pk` CHECKSIGVERIFY + two v:hash VERIFY + CSV|CLTV — single path
//!   requiring **both** matching 32-byte PSBT preimages **and** already-present
//!   nSequence (older) / nLockTime+nSequence (after); distinct from dual-hash
//!   or_i OR dual-path / single-hash combined; witness preimage2 deepest) when
//!   **all** key sigs + both matching preimages + already-present locktime
//!   material are present (never invents), or nested CLEANSTACK-valid hash-first
//!   dual-hash+timeout
//!   **`and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older(n)|after(n))))`**
//!   (two v:hash VERIFY + ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual of
//!   pk-first dual-hash+timeout; both matching preimages + locktime + all key
//!   sigs; witness reverse(keys)+preimage2+preimage1 preimage1 top) when
//!   **all** key sigs + both matching preimages + already-present locktime
//!   material are present (never invents), or nested CLEANSTACK-valid dual-hash
//!   AND without lock **`and_v(v:pk…, and_v(v:hash(H1), hash(H2)))`** (≥ 1
//!   all-`v:pk` CHECKSIGVERIFY + v:hash VERIFY + bare hash EQUAL — single path
//!   requiring **both** matching 32-byte PSBT preimages, no locktime; distinct
//!   from dual-hash+timeout / dual-hash or_i / multi-pk single-hash; witness
//!   preimage2 deepest) when **all** key sigs + both matching preimages are
//!   present (never invents), or nested CLEANSTACK-valid hash-first dual-hash
//!   AND without lock **`and_v(v:hash(H1), and_v(v:hash(H2), pk…))`** (two
//!   v:hash VERIFY + ≥ 1 trailing keys ending CHECKSIG — dual of pk-first
//!   dual-hash AND; both matching preimages + all key sigs; witness preimage1
//!   top) when **all** key sigs + both matching preimages are present (never
//!   invents), or nested CLEANSTACK-valid hash+pk+hash sandwich dual-hash AND
//!   without lock **`and_v(v:hash(H1), and_v(v:pk…, hash(H2)))`** (leading
//!   v:hash VERIFY + ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL — both
//!   matching preimages + all key sigs; witness preimage1 top / preimage2
//!   deepest) when **all** key sigs + both matching preimages are present
//!   (never invents). **PR5 dual-hash `and_v` keep set only** (see
//!   `bare_tapscript/and_v_dual_hash.rs`): pk+dual-hash±lock, dual-hash+pk±lock,
//!   hash+pk+hash sandwich; other dual-hash orderings pruned (no product consumer).
//!   or
//!   **after/CLTV**
//!   forms (`and_v(v:pk, after(n))` / `and_v(v:after(n), pk)` / bare `after(n)`)
//!   when matching sigs (if any) and the **already-present** unsigned-tx
//!   nLockTime + nSequence satisfy BIP-65 CLTV (never invents missing
//!   signatures, control blocks, leaves, preimages, or nSequence/nLockTime)
//! - extract + raw-hex helpers; network broadcast via [`crate::explorer::TxBroadcaster`]
//! - pure RBF / CPFP fee planners ([`plan_rbf_fee_bump`], [`plan_cpfp_child_fee`])
//! - same-input RBF replacement ([`prepare_rbf_replacement`],
//!   [`prepare_rbf_replacement_from_selection`], [`selection_with_rbf_fee`])
//! - CPFP child prepare ([`prepare_cpfp_child`], [`coin_selection_for_cpfp`])
//!
//! Seed material stays in [`crate::mnemonic::MnemonicSecret`] / SeedVault only;
//! this module never persists BIP-39. Signing zeroizes intermediate seed bytes
//! and never `Debug`-prints key material.

// Test-compat imports re-exposed into the child `tests` module via
// `use super::*` (monolith parity). Production code lives in peeled modules.
#[allow(unused_imports)]
use crate::error::{Result, WalletError};
#[allow(unused_imports)]
use bitcoin::Network;
#[allow(unused_imports)]
use bitcoin::absolute::LockTime;
#[allow(unused_imports)]
use bitcoin::psbt::{Input as PsbtInput, Psbt};
#[allow(unused_imports)]
use bitcoin::secp256k1::Secp256k1;
#[allow(unused_imports)]
use bitcoin::{OutPoint, ScriptBuf, Sequence, Witness, transaction};
#[allow(unused_imports)]
use std::collections::BTreeMap;

// --- peeled wallet-core modules (PR2) ---
mod broadcast;
mod chain_source;
mod coin_select;
mod fee;
mod gap;
mod psbt_build;
mod sign_bip84;
mod spend_prepare;
mod types;
mod wallet;

pub use broadcast::{
    broadcast_raw_tx, extract_and_broadcast, extract_finalized_tx, transaction_to_raw_hex,
    transaction_txid_hex,
};
#[cfg(feature = "explorer-http")]
pub use chain_source::MempoolChainSource;
pub use chain_source::{ChainSource, MockChainSource, parse_mempool_address_utxos};
pub use coin_select::{
    CoinSelectOptions, CoinSelectStrategy, CoinSelection, balance_from_utxos, select_coins,
    select_coins_ex, select_coins_with_fee, select_coins_with_options,
};
pub use fee::{
    CpfpFeePlan, DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB, DUST_P2WPKH_SATS, FeeBumpPlanError,
    P2WPKH_INPUT_VB, P2WPKH_OUTPUT_VB, RbfFeePlan, TX_OVERHEAD_VB, div_ceil_u64,
    effective_fee_rate_sat_vb, estimate_cpfp_child_vbytes, estimate_fee_sats, estimate_tx_vbytes,
    plan_cpfp_child_fee, plan_rbf_fee_bump, rbf_min_fee_increase_sats,
};
pub use gap::{
    DEFAULT_GAP_EXTEND_STEP, DEFAULT_GAP_LOOKAHEAD, DEFAULT_RECEIVE_GAP, GapExtendOptions,
    GapExtendReport, MAX_ADDRESS_GAP, PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP, WalletSyncSnapshot,
    address_window_needs_extend, highest_used_address_index, next_gap_after_extend,
};
pub use psbt_build::{BuiltPsbt, SpendParams, build_unsigned_psbt};
pub use sign_bip84::{SignOutcome, sign_psbt_bip84_p2wpkh};
pub use spend_prepare::{
    CpfpChildSpend, GapSyncSpendFailure, GapSyncedPreparedSpend, PreparedSpend,
    RbfReplacementSpend, bip125_min_replacement_fee_sats, build_sign_extract_bip84_p2wpkh,
    coin_selection_for_cpfp, coin_selection_from_rbf_inputs, gap_sync_spend_notice_lines,
    list_bip84_utxos_with_gap_sync, prepare_bip84_p2wpkh_spend, prepare_cpfp_child,
    prepare_cpfp_child_from_selection, prepare_rbf_replacement,
    prepare_rbf_replacement_from_selection, select_and_prepare_bip84_spend,
    select_and_prepare_bip84_spend_from_utxos, select_and_prepare_bip84_spend_with_gap_sync,
    selection_with_rbf_fee, transaction_vbytes, validate_cpfp_child_fee,
    validate_rbf_replacement_fee,
};
pub use types::{OutPointRef, WalletBalance, WalletUtxo};
pub use wallet::DescriptorWallet;

// Test-visible private helpers (monolith parity via `use super::*` in tests).
#[allow(unused_imports)]
use psbt_build::parse_network_address;
#[allow(unused_imports)]
use wallet::derive_bip84_change_address_with_passphrase;

// --- bare_tapscript template parsers (PR3) ---
mod bare_tapscript;
// Template parsers + shared helpers into parent scope so `finalize` (via
// `super::bare_tapscript`) and `tests` (`use super::*`) resolve the same
// names as the pre-peel monomod.
#[allow(unused_imports)]
use bare_tapscript::*;

// --- offline finalize surface (PR4) ---
mod finalize;
pub use finalize::{
    FinalizeOutcome, finalize_p2wpkh_psbt, finalize_psbt, input_is_finalized,
    psbt_is_broadcast_ready,
};
// Test-visible helpers (monolith parity via `use super::*` in tests).
#[allow(unused_imports)]
pub(crate) use finalize::{p2tr_output_key, single_tapscript_checksig_xonly};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
