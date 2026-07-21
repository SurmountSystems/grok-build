//! Offline PSBT finalize surface (behavior-preserving peel from `mod.rs`, PR4).
//!
//! Hosts [`FinalizeOutcome`], [`finalize_psbt`], Taproot key/script-path
//! finalize, and P2WSH helpers. Template parsers live in [`super::bare_tapscript`];
//! this module only assembles witnesses from material already on the PSBT.
//! Dual-hash `and_v` is PR5 keep set only (see `bare_tapscript/and_v_dual_hash.rs`);
//! other orderings pruned.

use bitcoin::absolute::LockTime;
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{OutPoint, ScriptBuf, Sequence, Witness, transaction};

use crate::error::{Result, WalletError};

// Template parsers + shared helpers (PR3 peel).
use super::bare_tapscript::*;

/// Outcome of offline PSBT finalize (honest Complete vs Partial gates).
///
/// # Complete only when every input has real final material
///
/// [`Self::Complete`] requires every input to already carry (or receive from
/// offline finalize) **non-empty** [`PsbtInput::final_script_witness`] and/or
/// **non-empty** [`PsbtInput::final_script_sig`]. Empty witnesses / empty
/// script_sigs are never counted.
///
/// Offline finalize fills final material only for cases that need **no
/// invention**:
/// - already-present non-empty finals (preserved)
/// - single-key **P2WPKH** (`partial_sigs` + matching `witness_utxo`)
/// - single-key **P2SH-P2WPKH** (redeem_script is P2WPKH + matching sig)
/// - single-key **P2PKH** (legacy; matching `partial_sigs` → `final_script_sig`)
/// - single-key **P2WSH** whose `witness_script` is bare `<pubkey> OP_CHECKSIG`
/// - bare **m-of-n CHECKMULTISIG** P2WSH / nested P2SH-P2WSH when the PSBT
///   already has ≥ m matching `partial_sigs` for script pubkeys; the
///   assembler builds BIP147 NULLDUMMY + sigs in witness_script pubkey
///   order (never invents; callers need not pre-order `partial_sigs`)
/// - **Taproot key-path** P2TR when `tap_key_sig` is already present
///   ([`Witness::p2tr_key_spend`]; never invents a Schnorr sig)
/// - **Taproot script-path** P2TR when a present `tap_scripts` entry is bare
///   `<x-only pk> OP_CHECKSIG`, bare multi_a
///   (`<pk1> CHECKSIG <pk2> CHECKSIGADD … <k> NUMEQUAL`), bare thresh
///   (`<pk1> CHECKSIG (SWAP <pki> CHECKSIG ADD)+ <k> EQUAL` =
///   miniscript `thresh(k, pk, s:pk, …)` — distinct from multi_a), bare
///   **a:pk / non-s:pk thresh**
///   (`<pk1> CHECKSIG (TOALTSTACK <pki> CHECKSIG FROMALTSTACK ADD)+ <k> EQUAL`
///   = miniscript `thresh(k, pk, a:pk, …)` — same witness policy as s:pk;
///   distinct from SWAP form and multi_a), bare **mixed s:/a: thresh**
///   (`<pk1> CHECKSIG` + interleaving of SWAP and TOALTSTACK arms with both
///   kinds present, `n ≥ 3` = miniscript `thresh(k, pk, s:pk…, a:pk…)`; pure
///   s: / pure a: / mixed templates never cross-match; same reverse-key +
///   empty-placeholder policy), bare **thresh pure s:hash** (trailing, middle,
///   or multi-hash type-W positions:
///   `<pk1> CHECKSIG` + interleaving of `SWAP <pki> CHECKSIG ADD` and one-or-more
///   `SWAP SIZE 32 EQUALVERIFY HASHOP digest EQUAL ADD` + `<k> EQUAL` =
///   miniscript `thresh(k, pk…, s:hash…, s:pk…)` — hash arms not
///   empty-dissatisfiable; Complete only with matching 32-byte preimage(s) +
///   exactly `k − n_hash` pk sigs; never cross-matches pure pk thresh or mixed
///   s:/a: with hash), bare **thresh pure a:hash** (TOALTSTACK dual of s:hash —
///   same multi-hash witness policy), bare **thresh mixed s:/a: with hash**
///   (both SWAP and TOALTSTACK wrappers present plus one-or-more s:hash /
///   a:hash arms — same preimage + `k − n_hash` pk-sig policy; never
///   cross-matches pure s:/a: hash or mixed pk-only), bare and_v
///   (`(<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG`, all n sigs present), bare
///   or_i (`IF <pkA> CHECKSIG ELSE <pkB> CHECKSIG ENDIF` with a matching sig
///   for A and/or B — IF/A preferred when both; ELSE when only B; neither →
///   Partial), bare or_d
///   (`<pkA> CHECKSIG IFDUP NOTIF <pkB> CHECKSIG ENDIF` — A preferred when
///   both; empty BIP-342 dissatisfaction for A when only B), bare and_n
///   (`<pkA> CHECKSIG NOTIF 0 ELSE <pkB> CHECKSIG ENDIF` — both sigs
///   required), or bare andor
///   (`<pkA> CHECKSIG NOTIF <pkC> CHECKSIG ELSE <pkB> CHECKSIG ENDIF` —
///   AB preferred when both A+B present; else C with empty BIP-342
///   dissatisfaction of A), bare miniscript **hash**
///   (`SIZE 32 EQUALVERIFY HASHOP digest EQUAL` for sha256/hash256/
///   ripemd160/hash160 when a matching 32-byte PSBT preimage is present),
///   or bare **and_v(v:pk, hash)** (`<A> CHECKSIGVERIFY` + hash fragment
///   when both matching `tap_script_sig` and preimage are present), or bare
///   **and_v(v:hash, pk)** (hash fragment with EQUALVERIFY + `<A> CHECKSIG`
///   when both matching preimage and `tap_script_sig` are present), or
///   **older/CSV** forms (`and_v(v:pk, older(n))` =
///   `<A> CHECKSIGVERIFY <n> CSV`; `and_v(v:older(n), pk)` =
///   `<n> CSV VERIFY <A> CHECKSIG`; bare `older(n)` = `<n> CSV`) when matching
///   `tap_script_sig` (if required) is present **and** the unsigned-tx input
///   nSequence already satisfies BIP-112 CSV for `n` (tx version ≥ 2; never
///   invents nSequence), or nested CLEANSTACK-valid
///   **`and_v(or_c(pk(A), v:pk(B)), older(n))`**
///   (`<A> CHECKSIG NOTIF <B> CHECKSIGVERIFY ENDIF <n> CSV` — A preferred when
///   both; only-B uses empty BIP-342 dissatisfaction of A; never invents
///   nSequence; bare top-level `or_c` stays residual), or nested
///   CLEANSTACK-valid **`and_v(or_c(pk(A), v:pk(B)), after(n))`**
///   (`<A> CHECKSIG NOTIF <B> CHECKSIGVERIFY ENDIF <n> CLTV` — same branch
///   policy; never invents nLockTime/nSequence), or nested CLEANSTACK-valid
///   **`and_v(or_c(pk(A), v:pk(B)), hash(H))`**
///   (`<A> CHECKSIG NOTIF <B> CHECKSIGVERIFY ENDIF SIZE 32 EQUALVERIFY HASHOP
///   digest EQUAL` — same branch policy + matching 32-byte PSBT preimage;
///   never invents preimages), or nested CLEANSTACK-valid
///   **`and_v(or_i(v:pk(A), v:pk(B)), hash(H))`**
///   (`IF <A> CHECKSIGVERIFY ELSE <B> CHECKSIGVERIFY ENDIF SIZE 32 EQUALVERIFY
///   HASHOP digest EQUAL` — IF preferred when both; ELSE when only B; matching
///   32-byte PSBT preimage required; never invents), or nested CLEANSTACK-valid
///   **`and_v(or_i(v:pk(A), v:pk(B)), older(n))`** /
///   **`and_v(or_i(v:pk(A), v:pk(B)), after(n))`**
///   (`IF <A> CHECKSIGVERIFY ELSE <B> CHECKSIGVERIFY ENDIF <n> CSV|CLTV` — IF
///   preferred when both; ELSE when only B; never invents nSequence/nLockTime),
///   or nested CLEANSTACK-valid multi-arm
///   **`and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), older(n)|after(n)|hash(H))`**
///   (`<A> CHECKSIG NOTIF <B> CHECKSIG NOTIF <C> CHECKSIGVERIFY ENDIF ENDIF
///   <n> CSV|CLTV` or trailing bare hash — A preferred over B over C; B uses
///   empty dissat of A; C uses empty dissat of A and B; never invents
///   nSequence/nLockTime/preimages),
///   or nested CLEANSTACK-valid multi-arm
///   **`and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), older(n)|after(n)|hash(H))`**
///   (`IF <A> CHECKSIGVERIFY ELSE IF <B> CHECKSIGVERIFY ELSE <C>
///   CHECKSIGVERIFY ENDIF ENDIF <n> CSV|CLTV` or trailing bare hash — A
///   preferred over B over C; B uses empty outer + true inner; C uses empty
///   outer + empty inner; never invents nSequence/nLockTime/preimages),
///   or nested CLEANSTACK-valid multi-key
///   **`and_v(and_v(v:pk…), older(n)|after(n)|hash(H))`** (n ≥ 2 all-`v:pk`
///   CHECKSIGVERIFY chain + trailing CSV|CLTV|bare hash — all n sigs required;
///   never invents nSequence/nLockTime/preimages),
///   or nested CLEANSTACK-valid multi-key reverse
///   **`and_v(v:older|after|hash, and_v(v:pk…))`** (CSV|CLTV|v:hash VERIFY
///   prefix + CHECKSIGVERIFY…CHECKSIG n ≥ 2 — all n sigs required; never
///   invents nSequence/nLockTime/preimages),
///   or nested CLEANSTACK-valid multi-key sandwich
///   **`and_v(v:pk…, and_v(v:older|after|hash, pk…))`** (left CHECKSIGVERIFY
///   + middle CSV|CLTV|v:hash VERIFY + right CHECKSIG; left ≥ 1, right ≥ 1 —
///   all left+right sigs required; never invents nSequence/nLockTime/preimages),
///   or nested CLEANSTACK-valid vault
///   **`or_i(and_v(v:pk…)|pk, older|after|hash)`** (IF multi-pk ≥ 1; ELSE
///   CSV|CLTV|bare hash — IF preferred when all sigs present; ELSE timeout/
///   hash when locktime/preimage material present; never invents),
///   or nested CLEANSTACK-valid delayed-recovery inheritance
///   **`or_i(and_v(v:pk…)|pk, and_v(v:pk…, older|after|hash))`** (IF hot ≥ 1;
///   ELSE cold ≥ 1 all-`v:pk` + CSV|CLTV|hash — IF preferred when all hot
///   sigs present; ELSE all cold sigs + locktime/preimage; never invents),
///   or nested CLEANSTACK-valid HTLC dual-path
///   **`or_i(and_v(v:pk…, hash(H)), and_v(v:pk…, older(n)|after(n)))`** (IF
///   claim ≥ 1 all-`v:pk` + bare hash; ELSE refund ≥ 1 all-`v:pk` + CSV|CLTV —
///   IF preferred when all claim sigs + matching 32-byte PSBT preimage present;
///   ELSE all refund sigs + locktime material; never invents),
///   or nested CLEANSTACK-valid reverse HTLC
///   **`or_i(and_v(v:pk…, older(n)|after(n)), and_v(v:pk…, hash(H)))`** (IF
///   timeout ≥ 1 all-`v:pk` + CSV|CLTV; ELSE claim ≥ 1 all-`v:pk` + bare hash —
///   IF preferred when all timeout sigs + locktime material present; ELSE all
///   claim sigs + matching 32-byte PSBT preimage; never invents),
///   or nested CLEANSTACK-valid dual-hash
///   **`or_i(and_v(v:pk…, hash(H1)), and_v(v:pk…, hash(H2)))`** (IF claim ≥ 1
///   all-`v:pk` + bare hash; ELSE claim ≥ 1 all-`v:pk` + bare hash — dual
///   claim paths; IF preferred when all IF sigs + matching preimage for H1;
///   ELSE all ELSE sigs + matching preimage for H2; never invents),
///   or nested CLEANSTACK-valid dual-timeout
///   **`or_i(and_v(v:pk…, older(n1)|after(n1)), and_v(v:pk…, older(n2)|after(n2)))`**
///   (IF timeout ≥ 1 all-`v:pk` + CSV|CLTV; ELSE timeout ≥ 1 all-`v:pk` +
///   CSV|CLTV — dual timeout paths; IF preferred when all IF sigs + already-
///   present locktime material; ELSE all ELSE sigs + locktime material; never
///   invents nSequence/nLockTime),
///   or nested CLEANSTACK-valid combined hash+timeout
///   **`and_v(v:pk…, and_v(v:hash(H), older(n)|after(n)))`** (≥ 1 all-`v:pk`
///   CHECKSIGVERIFY + v:hash VERIFY + CSV|CLTV — single path requiring both
///   matching 32-byte PSBT preimage and already-present nSequence (older) /
///   nLockTime+nSequence (after); never invents),
///   or nested CLEANSTACK-valid reverse combined hash+timeout
///   **`and_v(v:hash(H), and_v(v:pk…, older(n)|after(n)))`** (v:hash VERIFY +
///   ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual of pk-first; same
///   both-required material gate; witness preimage top; never invents),
///   or nested CLEANSTACK-valid lock-first combined hash+timeout
///   **`and_v(v:older(n)|after(n), and_v(v:pk…, hash(H)))`** (CSV|CLTV VERIFY
///   prefix + ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL — lock-order dual;
///   same both-required material gate; witness preimage deepest; never invents),
///   or nested CLEANSTACK-valid pk+middle-lock+trailing-hash combined hash+timeout
///   **`and_v(v:pk…, and_v(v:older(n)|after(n), hash(H)))`** (≥ 1 all-`v:pk`
///   CHECKSIGVERIFY + middle CSV|CLTV VERIFY + bare hash EQUAL — keys-before-lock
///   dual of lock-first; same both-required material gate; witness preimage
///   deepest; never invents),
///   or nested CLEANSTACK-valid hash+middle-lock+trailing-pk combined hash+timeout
///   **`and_v(v:hash(H), and_v(v:older(n)|after(n), pk…))`** (v:hash VERIFY +
///   middle CSV|CLTV VERIFY + ≥ 1 trailing keys ending CHECKSIG — hash/pk dual of
///   pk+lock+hash; same both-required material gate; witness preimage top; never
///   invents),
///   or nested CLEANSTACK-valid lock+middle-hash+trailing-pk combined hash+timeout
///   **`and_v(v:older(n)|after(n), and_v(v:hash(H), pk…))`** (CSV|CLTV VERIFY
///   prefix + v:hash VERIFY + ≥ 1 trailing keys ending CHECKSIG — lock-order dual
///   of hash+lock+pk; same both-required material gate; witness preimage top;
///   never invents),
///   or nested CLEANSTACK-valid dual-hash+timeout combined
///   **`and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older(n)|after(n))))`**
///   (≥ 1 all-`v:pk` CHECKSIGVERIFY + two v:hash VERIFY + CSV|CLTV — single path
///   requiring both matching 32-byte PSBT preimages and already-present
///   nSequence (older) / nLockTime+nSequence (after); distinct from dual-hash
///   or_i OR dual-path / single-hash combined; witness preimage2 deepest; never
///   invents),
///   or nested CLEANSTACK-valid hash-first dual-hash+timeout
///   **`and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older(n)|after(n))))`**
///   (two v:hash VERIFY + ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual of
///   pk-first dual-hash+timeout; both matching preimages + locktime + all key
///   sigs; witness reverse(keys)+preimage2+preimage1 preimage1 top; never
///   invents),
///   or nested CLEANSTACK-valid dual-hash AND without lock
///   **`and_v(v:pk…, and_v(v:hash(H1), hash(H2)))`** (≥ 1 all-`v:pk`
///   CHECKSIGVERIFY + v:hash VERIFY + bare hash EQUAL — single path requiring
///   both matching 32-byte PSBT preimages, no locktime; distinct from
///   dual-hash+timeout / dual-hash or_i / multi-pk single-hash; witness
///   preimage2 deepest; never invents),
///   or nested CLEANSTACK-valid hash-first dual-hash AND without lock
///   **`and_v(v:hash(H1), and_v(v:hash(H2), pk…))`** (two v:hash VERIFY + ≥ 1
///   trailing keys ending CHECKSIG — dual of pk-first dual-hash AND; both
///   matching preimages + all key sigs; witness preimage1 top; never invents),
///   or nested CLEANSTACK-valid hash+pk+hash sandwich dual-hash AND without lock
///   **`and_v(v:hash(H1), and_v(v:pk…, hash(H2)))`** (leading v:hash VERIFY +
///   ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL — both matching preimages
///   + all key sigs; witness preimage1 top / preimage2 deepest; never invents).
///   **PR5:** other dual-hash `and_v` orderings (lock-first / middle-lock /
///   exotic H1–H2 interleavings) are **not** finalized here — Partial residual.
///   or **after/CLTV** forms
///   (`and_v(v:pk, after(n))` = `<A> CHECKSIGVERIFY <n> CLTV`;
///   `and_v(v:after(n), pk)` = `<n> CLTV VERIFY <A> CHECKSIG`; bare `after(n)` =
///   `<n> CLTV`) when matching `tap_script_sig` (if required) is present **and**
///   the unsigned-tx nLockTime already satisfies BIP-65 for `n` with an
///   nSequence that enables absolute locktime (never invents
///   nLockTime/nSequence), matching `tap_script_sigs` / preimage maps cover the
///   template (multi_a / thresh unused keys get empty BIP-342 placeholders
///   only), and the present control block verifies against the prevout (never
///   invents control blocks / leaves / signatures / preimages / locktimes)
///
/// # Residual (Partial — not broadcast-ready)
///
/// Incomplete CHECKMULTISIG / multi_a / thresh / and_v / and_n thresholds,
/// or_i / or_d with neither branch sig, incomplete andor (neither AB nor C
/// completeable), missing hash preimage / incomplete and_v(v:pk, hash) /
/// and_v(v:hash, pk) / thresh(s:hash|a:hash|mixed s:/a:+hash) missing
/// preimage(s) or `k − n_hash` pk sigs,
/// older/CSV with missing sig or nSequence that does not
/// satisfy BIP-112, nested `and_v(or_c, older)` / `and_v(or_c, after)` /
/// `and_v(or_c, hash)` / `and_v(or_i, hash)` / `and_v(or_i, older)` /
/// `and_v(or_i, after)` / multi-arm
/// `and_v(or_c(pk, or_c(pk, v:pk)), older|after|hash)` / multi-arm
/// `and_v(or_i(v:pk, or_i(v:pk, v:pk)), older|after|hash)` /
/// multi-key `and_v(and_v(v:pk…), older|after|hash)` /
/// multi-key reverse `and_v(v:older|after|hash, and_v(v:pk…))` /
/// multi-key sandwich `and_v(v:pk…, and_v(v:older|after|hash, pk…))` /
/// vault `or_i(and_v(v:pk…)|pk, older|after|hash)` /
/// inheritance `or_i(and_v(v:pk…)|pk, and_v(v:pk…, older|after|hash))` /
/// HTLC dual-path
/// `or_i(and_v(v:pk…, hash), and_v(v:pk…, older|after))` /
/// reverse HTLC
/// `or_i(and_v(v:pk…, older|after), and_v(v:pk…, hash))` /
/// dual-hash
/// `or_i(and_v(v:pk…, hash(H1)), and_v(v:pk…, hash(H2)))` /
/// dual-timeout
/// `or_i(and_v(v:pk…, older|after), and_v(v:pk…, older|after))` /
/// combined hash+timeout
/// `and_v(v:pk…, and_v(v:hash, older|after))` /
/// reverse combined hash+timeout
/// `and_v(v:hash, and_v(v:pk…, older|after))` /
/// lock-first combined hash+timeout
/// `and_v(v:older|after, and_v(v:pk…, hash))` /
/// pk+middle-lock+trailing-hash combined hash+timeout
/// `and_v(v:pk…, and_v(v:older|after, hash))` /
/// hash+middle-lock+trailing-pk combined hash+timeout
/// `and_v(v:hash, and_v(v:older|after, pk…))` /
/// lock+middle-hash+trailing-pk combined hash+timeout
/// `and_v(v:older|after, and_v(v:hash, pk…))` /
/// dual-hash keep set (PR5): pk+dual-hash+lock / dual-hash+pk+lock /
/// pk+dual-hash / dual-hash+pk / hash+pk+hash sandwich (no lock) —
/// Partial when material incomplete; other dual-hash `and_v` orderings
/// remain residual Partial (pruned, no product consumer)
/// with no branch sig or missing
/// preimage / unsatisfying locktime material, after/CLTV with
/// missing sig or nLockTime/nSequence that does not satisfy BIP-65, Taproot
/// **other complex script-path** / miniscript (bare top-level or_c /
/// other nested complex /…) /
/// non-standard
/// leaves, missing UTXO/scripts/ `tap_key_sig` / incomplete script-path maps,
/// and unsigned inputs stay [`Self::Partial`]. Product prepare still refuses
/// Partial before any broadcast claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeOutcome {
    /// Every input has non-empty final spend material (witness and/or script_sig).
    Complete { finalized_inputs: usize },
    /// Some inputs finalized; others residual (unsigned, multi-sig, unsupported).
    ///
    /// Not broadcast-ready. Callers must not extract/broadcast as a success.
    Partial {
        finalized_inputs: usize,
        residual_inputs: usize,
        detail: String,
    },
}

impl FinalizeOutcome {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    /// Alias for product copy: only [`Self::Complete`] is broadcast-ready.
    pub fn is_broadcast_ready(&self) -> bool {
        self.is_complete()
    }

    pub fn finalized_inputs(&self) -> usize {
        match self {
            Self::Complete { finalized_inputs } => *finalized_inputs,
            Self::Partial {
                finalized_inputs, ..
            } => *finalized_inputs,
        }
    }
}

/// True when a single PSBT input has **non-empty** final spend material.
///
/// Accepts non-empty `final_script_witness` and/or non-empty `final_script_sig`.
/// Empty stacks are **not** final — multi-sig must not be marked complete without
/// real finals.
pub fn input_is_finalized(input: &PsbtInput) -> bool {
    let has_witness = input
        .final_script_witness
        .as_ref()
        .is_some_and(|w| !w.is_empty());
    let has_script_sig = input
        .final_script_sig
        .as_ref()
        .is_some_and(|s| !s.is_empty());
    has_witness || has_script_sig
}

/// True when every PSBT input has non-empty final spend material.
///
/// Empty witnesses, empty script_sigs, and missing finals are **not** complete.
/// Never use this alone to invent multi-sig success — only real
/// `final_script_witness` / `final_script_sig` count.
pub fn psbt_is_broadcast_ready(psbt: &Psbt) -> bool {
    !psbt.inputs.is_empty() && psbt.inputs.iter().all(input_is_finalized)
}

/// Per-input offline finalize result (shared Complete vs Partial gate).
#[derive(Debug)]
enum FinalizeInputStep {
    /// Input already had or received non-empty final material.
    Finalized,
    /// Could not finalize offline without inventing material.
    Residual(String),
}

/// Clear empty final fields so residual partial_sigs can still produce real finals.
fn clear_empty_final_fields(input: &mut PsbtInput) {
    if input
        .final_script_witness
        .as_ref()
        .is_some_and(|w| w.is_empty())
    {
        input.final_script_witness = None;
    }
    if input
        .final_script_sig
        .as_ref()
        .is_some_and(|s| s.is_empty())
    {
        input.final_script_sig = None;
    }
}

/// Resolve prevout scriptPubKey from `witness_utxo` or `non_witness_utxo`.
fn input_prevout_script_pubkey(input: &PsbtInput, prevout: OutPoint) -> Option<ScriptBuf> {
    if let Some(utxo) = input.witness_utxo.as_ref() {
        return Some(utxo.script_pubkey.clone());
    }
    if let Some(tx) = input.non_witness_utxo.as_ref() {
        let vout = prevout.vout as usize;
        return tx.output.get(vout).map(|o| o.script_pubkey.clone());
    }
    None
}

/// Push bytes into a script builder helper (bounded by bitcoin push limits).
fn script_push_bytes(data: &[u8]) -> Result<bitcoin::script::PushBytesBuf> {
    bitcoin::script::PushBytesBuf::try_from(data.to_vec())
        .map_err(|e| WalletError::Onchain(format!("script data push rejected: {e}")))
}

/// Detect bare single-key `<pubkey> OP_CHECKSIG` witness/redeem scripts.
///
/// Returns the pubkey when the script is exactly that template; otherwise
/// `None` (CHECKMULTISIG is handled separately via
/// [`bare_checkmultisig_template`]).
fn single_checksig_pubkey(script: &bitcoin::Script) -> Option<bitcoin::PublicKey> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CHECKSIG;

    let mut iter = script.instructions();
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    bitcoin::PublicKey::from_slice(push.as_bytes()).ok()
}

/// Detect bare Taproot leaf `<32-byte x-only pk> OP_CHECKSIG`.
///
/// Tapscript leaves use x-only (BIP-340) pubkeys, not compressed ECDSA.
/// Returns `None` for empty / multi-op / non-32-byte pushes / CHECKMULTISIG
/// or miniscript templates (those stay residual). multi_a leaves are handled
/// separately via [`bare_tapscript_checksigadd_multi_template`].
pub(crate) fn single_tapscript_checksig_xonly(
    script: &bitcoin::Script,
) -> Option<bitcoin::secp256k1::XOnlyPublicKey> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CHECKSIG;

    let mut iter = script.instructions();
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()
}

/// Look up a miniscript hash preimage already present on the PSBT input map.
///
/// Returns:
/// - `Ok(Some(preimage))` when the matching map has a **32-byte** preimage
///   whose hash equals `digest` (BIP-174 key consistency)
/// - `Ok(None)` when the preimage is absent (honest Partial residual)
/// - `Err` when a map entry is present but corrupt (wrong hash / not 32 bytes
///   for miniscript SIZE) — tamper/corrupt, not silent finalize
fn lookup_miniscript_hash_preimage(
    idx: usize,
    input: &PsbtInput,
    kind: TapscriptHashKind,
    digest: &[u8],
) -> Result<Option<Vec<u8>>> {
    use bitcoin::hashes::{Hash, hash160, ripemd160, sha256, sha256d};

    let preimage = match kind {
        TapscriptHashKind::Sha256 => {
            let key = sha256::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: sha256 digest in leaf is not 32 bytes: {e}"
                ))
            })?;
            input.sha256_preimages.get(&key).cloned()
        }
        TapscriptHashKind::Hash256 => {
            let key = sha256d::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: hash256 digest in leaf is not 32 bytes: {e}"
                ))
            })?;
            input.hash256_preimages.get(&key).cloned()
        }
        TapscriptHashKind::Ripemd160 => {
            let key = ripemd160::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: ripemd160 digest in leaf is not 20 bytes: {e}"
                ))
            })?;
            input.ripemd160_preimages.get(&key).cloned()
        }
        TapscriptHashKind::Hash160 => {
            let key = hash160::Hash::from_slice(digest).map_err(|e| {
                WalletError::Onchain(format!(
                    "input {idx}: hash160 digest in leaf is not 20 bytes: {e}"
                ))
            })?;
            input.hash160_preimages.get(&key).cloned()
        }
    };

    let Some(preimage) = preimage else {
        return Ok(None);
    };

    // Miniscript SIZE <32> EQUALVERIFY — preimage must be exactly 32 bytes.
    if preimage.len() != 32 {
        return Err(WalletError::Onchain(format!(
            "input {idx}: {} preimage present but length {} (miniscript requires 32; \
             corrupt/tamper; not broadcast-ready)",
            kind.name(),
            preimage.len()
        )));
    }

    // BIP-174: map key must be the hash of the preimage value.
    let computed: Vec<u8> = match kind {
        TapscriptHashKind::Sha256 => sha256::Hash::hash(&preimage).to_byte_array().to_vec(),
        TapscriptHashKind::Hash256 => sha256d::Hash::hash(&preimage).to_byte_array().to_vec(),
        TapscriptHashKind::Ripemd160 => ripemd160::Hash::hash(&preimage).to_byte_array().to_vec(),
        TapscriptHashKind::Hash160 => hash160::Hash::hash(&preimage).to_byte_array().to_vec(),
    };
    if computed.as_slice() != digest {
        return Err(WalletError::Onchain(format!(
            "input {idx}: {} preimage does not hash to leaf digest (tamper/corrupt; \
             not broadcast-ready)",
            kind.name()
        )));
    }
    Ok(Some(preimage))
}

/// Extract the 32-byte output key from a native P2TR scriptPubKey.
pub(crate) fn p2tr_output_key(spk: &bitcoin::Script) -> Option<bitcoin::secp256k1::XOnlyPublicKey> {
    if !spk.is_p2tr() {
        return None;
    }
    // P2TR: OP_PUSHNUM_1 (0x51) + OP_PUSHBYTES_32 (0x20) + 32-byte key.
    let bytes = spk.as_bytes();
    if bytes.len() != 34 {
        return None;
    }
    bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes[2..34]).ok()
}
/// Parse bare standard `OP_m <pk1>…<pkn> OP_n OP_CHECKMULTISIG` (m,n ∈ 1..=16).
///
/// Returns `(threshold m, pubkeys in script order)` when the script is exactly
/// that template; otherwise `None` (non-standard / miniscript stay residual).
fn bare_checkmultisig_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::PublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CHECKMULTISIG;

    let mut iter = script.instructions();
    let m = match iter.next()? {
        Ok(Instruction::Op(op)) => small_pushnum(op)?,
        _ => return None,
    };
    if m == 0 {
        return None;
    }

    let mut pubkeys = Vec::new();
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let pk = bitcoin::PublicKey::from_slice(b.as_bytes()).ok()?;
                pubkeys.push(pk);
            }
            Ok(Instruction::Op(op)) => {
                let n = small_pushnum(op)?;
                if n as usize != pubkeys.len() {
                    return None;
                }
                break;
            }
            Err(_) => return None,
        }
    }

    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKMULTISIG => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    if pubkeys.is_empty() || (m as usize) > pubkeys.len() {
        return None;
    }
    Some((m as usize, pubkeys))
}

/// Try to finalize one input offline without inventing witnesses.
///
/// # Completeable offline
/// - Already-present non-empty finals (preserved)
/// - Single-key P2WPKH
/// - Single-key P2SH-P2WPKH (redeem_script is P2WPKH)
/// - Single-key P2PKH → `final_script_sig`
/// - Single-key P2WSH with bare CHECKSIG `witness_script`
/// - Bare m-of-n CHECKMULTISIG P2WSH / nested P2SH-P2WSH when ≥ m matching
///   `partial_sigs` for script pubkeys are present (assembler adds BIP147
///   NULLDUMMY + script-order sigs; never invents)
/// - Taproot **key-path** P2TR when `tap_key_sig` is already present
/// - Taproot **script-path** P2TR when present `tap_scripts` + matching
///   `tap_script_sigs` / PSBT preimage maps cover a bare x-only CHECKSIG leaf,
///   bare multi_a CHECKSIGADD k-of-n leaf, bare thresh (s:pk SWAP/CHECKSIG/ADD
///   + k EQUAL, a:pk TOALTSTACK/CHECKSIG/FROMALTSTACK/ADD + k EQUAL, mixed
///   s:/a: interleaving of both arm kinds with `n ≥ 3`, pure s:hash /
///   a:hash `thresh(k, pk…, s:hash|a:hash…, …)` trailing/middle/multi-hash, or
///   mixed s:/a:+hash with matching preimage(s) + `k − n_hash` pk sigs)
///   k-of-n leaf, bare and_v CHECKSIGVERIFY chain, bare or_i IF/ELSE dual
///   CHECKSIG, bare or_d IFDUP NOTIF dual CHECKSIG, bare and_n NOTIF 0 ELSE
///   dual CHECKSIG, bare andor NOTIF/ELSE triple CHECKSIG, bare miniscript
///   hash leaf, and_v(v:pk, hash) / and_v(v:hash, pk), older/CSV forms
///   (`and_v(v:pk, older)` / `and_v(v:older, pk)` / bare `older` when
///   nSequence on the unsigned tx already satisfies BIP-112; never invented),
///   nested CLEANSTACK-valid `and_v(or_c(pk(A), v:pk(B)), older(n))` /
///   `and_v(or_c(pk(A), v:pk(B)), after(n))` /
///   `and_v(or_c(pk(A), v:pk(B)), hash(H))` when a branch sig + satisfying
///   nSequence (older), nLockTime+nSequence (after), or PSBT preimage (hash)
///   are present (bare top-level or_c stays residual), nested CLEANSTACK-valid
///   `and_v(or_i(v:pk(A), v:pk(B)), hash(H))` when an IF and/or ELSE sig +
///   PSBT preimage are present (IF preferred), nested CLEANSTACK-valid
///   `and_v(or_i(v:pk(A), v:pk(B)), older(n))` /
///   `and_v(or_i(v:pk(A), v:pk(B)), after(n))` when an IF and/or ELSE sig +
///   satisfying nSequence (older) or nLockTime+nSequence (after) are present
///   (IF preferred), multi-arm CLEANSTACK-valid
///   `and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), older|after|hash)` when an
///   A/B/C branch sig + satisfying locktime material or PSBT preimage are
///   present (A preferred over B over C), multi-arm CLEANSTACK-valid
///   `and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), older|after|hash)` when an
///   A/B/C branch sig + satisfying locktime material or PSBT preimage are
///   present (A preferred over B over C), or after/CLTV forms
///   (`and_v(v:pk, after)` / `and_v(v:after, pk)` / bare `after` when nLockTime
///   on the unsigned tx already satisfies BIP-65 with a non-final nSequence;
///   never invented)
///
/// # Residual
/// - CHECKMULTISIG / multi_a / thresh / and_v / and_n with fewer than threshold matching sigs
/// - or_i / or_d with neither branch matching `tap_script_sig`
/// - andor with neither AB nor C completeable from present sigs
/// - bare hash / and_v(v:pk, hash) / thresh(s:hash|a:hash|mixed s:/a:+hash)
///   missing preimage or missing pk sig
/// - older/CSV with missing sig or nSequence that does not satisfy BIP-112
/// - nested `and_v(or_c, older)` / `and_v(or_c, after)` / `and_v(or_c, hash)` /
///   `and_v(or_i, hash)` / `and_v(or_i, older)` / `and_v(or_i, after)` /
///   multi-arm `and_v(or_c(pk, or_c(pk, v:pk)), older|after|hash)` /
///   multi-arm `and_v(or_i(v:pk, or_i(v:pk, v:pk)), older|after|hash)` with
///   neither branch sig, missing preimage, or unsatisfying locktime material
/// - after/CLTV with missing sig or nLockTime/nSequence that does not satisfy BIP-65
/// - Taproot other complex script-path / miniscript (bare top-level or_c /
///   other nested complex /…) / bare legacy P2SH multi-sig /
///   non-standard templates / incomplete maps
/// - Missing UTXO / scripts / partial_sigs / `tap_key_sig` / control block
///
/// Hard errors: pubkey HASH160 / witness_script hash mismatch against a
/// matching template; Taproot `tap_internal_key` (+ optional merkle root)
/// mismatch against P2TR scriptPubKey; control block that fails taproot
/// commitment verify (tamper/corrupt), not silent skip.
fn try_finalize_input(
    idx: usize,
    input: &mut PsbtInput,
    prevout: OutPoint,
    sequence: Sequence,
    tx_version: transaction::Version,
    lock_time: LockTime,
) -> Result<FinalizeInputStep> {
    clear_empty_final_fields(input);
    if input_is_finalized(input) {
        return Ok(FinalizeInputStep::Finalized);
    }

    let Some(spk) = input_prevout_script_pubkey(input, prevout) else {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: missing witness_utxo / non_witness_utxo (not broadcast-ready)"
        )));
    };

    // --- Taproot key-path (uses tap_key_sig, not ECDSA partial_sigs) ---
    if spk.is_p2tr() {
        return finalize_taproot_key_path(idx, input, &spk, sequence, tx_version, lock_time);
    }

    if input.partial_sigs.is_empty() {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: no partial_sigs (unsigned residual; not broadcast-ready)"
        )));
    }

    // --- Single-key P2WPKH ---
    if spk.is_p2wpkh() {
        if input.partial_sigs.len() != 1 {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: multi-sig / multi-key residual ({} partial_sigs on P2WPKH; \
                 not broadcast-ready)",
                input.partial_sigs.len()
            )));
        }
        let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
        let wpkh = match pk.wpubkey_hash() {
            Ok(h) => h,
            Err(e) => {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: partial_sig pubkey is not compressed P2WPKH: {e}"
                )));
            }
        };
        let expected = ScriptBuf::new_p2wpkh(&wpkh);
        if spk != expected {
            return Err(WalletError::Onchain(format!(
                "input {idx}: partial_sig pubkey HASH160 does not match witness_utxo P2WPKH script"
            )));
        }
        input.final_script_witness = Some(Witness::from_slice(&[sig.to_vec(), pk.to_bytes()]));
        return Ok(FinalizeInputStep::Finalized);
    }

    // --- Single-key P2PKH (legacy) ---
    if spk.is_p2pkh() {
        if input.partial_sigs.len() != 1 {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: multi-sig / multi-key residual ({} partial_sigs on P2PKH; \
                 not broadcast-ready)",
                input.partial_sigs.len()
            )));
        }
        let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
        let expected = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
        if spk != expected {
            return Err(WalletError::Onchain(format!(
                "input {idx}: partial_sig pubkey HASH160 does not match P2PKH script"
            )));
        }
        let sig_pb = script_push_bytes(&sig.to_vec())?;
        let pk_pb = script_push_bytes(&pk.to_bytes())?;
        input.final_script_sig = Some(
            bitcoin::script::Builder::new()
                .push_slice(sig_pb)
                .push_slice(pk_pb)
                .into_script(),
        );
        return Ok(FinalizeInputStep::Finalized);
    }

    // --- P2SH: nested P2WPKH only when redeem_script is present and matches ---
    if spk.is_p2sh() {
        let Some(redeem) = input.redeem_script.clone() else {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: P2SH residual missing redeem_script (not broadcast-ready)"
            )));
        };
        if redeem.to_p2sh() != spk {
            return Err(WalletError::Onchain(format!(
                "input {idx}: redeem_script HASH160 does not match P2SH scriptPubKey"
            )));
        }
        if redeem.is_p2wpkh() {
            if input.partial_sigs.len() != 1 {
                return Ok(FinalizeInputStep::Residual(format!(
                    "input {idx}: multi-sig / multi-key residual ({} partial_sigs on \
                     P2SH-P2WPKH; not broadcast-ready)",
                    input.partial_sigs.len()
                )));
            }
            let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
            let wpkh = match pk.wpubkey_hash() {
                Ok(h) => h,
                Err(e) => {
                    return Err(WalletError::Onchain(format!(
                        "input {idx}: partial_sig pubkey is not compressed P2WPKH: {e}"
                    )));
                }
            };
            let expected_redeem = ScriptBuf::new_p2wpkh(&wpkh);
            if redeem != expected_redeem {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: partial_sig pubkey HASH160 does not match P2SH-P2WPKH redeem_script"
                )));
            }
            // Clone sig/pk bytes before mutating input (partial_sigs borrow).
            let sig_bytes = sig.to_vec();
            let pk_bytes = pk.to_bytes();
            let redeem_pb = script_push_bytes(redeem.as_bytes())?;
            input.final_script_sig = Some(
                bitcoin::script::Builder::new()
                    .push_slice(redeem_pb)
                    .into_script(),
            );
            input.final_script_witness = Some(Witness::from_slice(&[sig_bytes, pk_bytes.to_vec()]));
            return Ok(FinalizeInputStep::Finalized);
        }
        // Nested P2WSH: bare CHECKSIG or bare CHECKMULTISIG witness_script.
        if redeem.is_p2wsh() {
            let Some(wscript) = input.witness_script.clone() else {
                return Ok(FinalizeInputStep::Residual(format!(
                    "input {idx}: P2SH-P2WSH residual missing witness_script \
                     (not broadcast-ready)"
                )));
            };
            if wscript.to_p2wsh() != redeem {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: witness_script hash does not match P2SH-P2WSH redeem_script"
                )));
            }
            return finalize_p2wsh_witness_script(
                idx,
                input,
                &wscript,
                /* also set script_sig with redeem push */ Some(redeem),
            );
        }
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: P2SH non-P2WPKH / multi-sig residual (not broadcast-ready)"
        )));
    }

    // --- Native P2WSH: bare CHECKSIG or bare CHECKMULTISIG witness_script ---
    if spk.is_p2wsh() {
        let Some(wscript) = input.witness_script.clone() else {
            return Ok(FinalizeInputStep::Residual(format!(
                "input {idx}: non-P2WPKH P2WSH residual missing witness_script \
                 (not broadcast-ready)"
            )));
        };
        if wscript.to_p2wsh() != spk {
            return Err(WalletError::Onchain(format!(
                "input {idx}: witness_script hash does not match P2WSH scriptPubKey"
            )));
        }
        return finalize_p2wsh_witness_script(idx, input, &wscript, None);
    }

    Ok(FinalizeInputStep::Residual(format!(
        "input {idx}: unsupported script residual (only single-key P2WPKH / P2PKH / \
         P2SH-P2WPKH / single-CHECKSIG or bare CHECKMULTISIG P2WSH / Taproot key-path \
         or bare script-path CHECKSIG / multi_a / thresh (s:pk|a:pk|mixed|s:hash|a:hash|\
         mixed s:/a:+hash) / \
         and_v / or_i / or_d / and_n / andor / hash / older / after finalize; \
         not broadcast-ready)"
    )))
}

/// Finalize native P2TR: key-path first, then bare script-path subset.
///
/// # Key-path
/// Uses [`Witness::p2tr_key_spend`] when `tap_key_sig` is already present —
/// never invents a Schnorr signature.
///
/// # Script-path (subset)
/// When key-path is absent, assembles a script-path witness **only** when a
/// present `tap_scripts` entry is:
/// - bare `<x-only pk> OP_CHECKSIG` with a matching `tap_script_sig`, or
/// - bare multi_a (`CHECKSIG`/`CHECKSIGADD`/`NUMEQUAL`) with ≥ k matching
///   `tap_script_sigs` (empty BIP-342 placeholders for unused keys only), or
/// - bare thresh (`CHECKSIG` + `SWAP CHECKSIG ADD`… + `k EQUAL` = s:pk, or
///   `CHECKSIG` + `TOALTSTACK CHECKSIG FROMALTSTACK ADD`… + `k EQUAL` = a:pk,
///   or mixed s:/a: interleaving with both kinds, pure s:hash / a:hash
///   `thresh(k, pk…, s:hash|a:hash…, …)` trailing/middle/multi-hash, or
///   mixed s:/a:+hash with matching preimage(s) + `k − n_hash` pk sigs)
///   with ≥ k matching `tap_script_sigs` for pure/mixed pk forms (empty
///   BIP-342 placeholders for unused keys), or
/// - bare and_v (`CHECKSIGVERIFY`…`CHECKSIG`) with **all** n matching
///   `tap_script_sigs` (no empty placeholders — CHECKSIGVERIFY rejects empty), or
/// - bare or_i (`IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF`) with a matching
///   sig for A (IF) and/or B (ELSE); when both present, IF/A wins, or
/// - bare or_d (`<A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF`) with a matching
///   sig for A and/or B; when both present, A wins; only-B uses empty A
///   dissatisfaction (BIP-342), or
/// - bare and_n (`<A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF`) with **both**
///   matching sigs (A false short-circuits to 0 — no partial B-only path), or
/// - bare andor (`<A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF`)
///   with A+B (AB preferred) or C alone (empty BIP-342 dissatisfaction of A),
/// - bare miniscript hash (`SIZE 32 EQUALVERIFY HASHOP digest EQUAL`) with a
///   matching 32-byte PSBT preimage (sha256/hash256/ripemd160/hash160 maps),
/// - bare and_v(v:pk, hash) (`<A> CHECKSIGVERIFY` + hash fragment) with both
///   matching `tap_script_sig` and PSBT preimage,
/// - older/CSV forms (`and_v(v:pk, older)` / `and_v(v:older, pk)` / bare
///   `older`) with matching sig (if any) **and** present nSequence that
///   satisfies BIP-112 for `n` (never invents nSequence),
/// - nested CLEANSTACK-valid `and_v(or_c(pk(A), v:pk(B)), older(n))` with a
///   matching sig for A and/or B **and** present nSequence that satisfies
///   BIP-112 (A preferred when both; only-B uses empty BIP-342 dissatisfaction
///   of A; bare top-level or_c never assembled),
/// - nested CLEANSTACK-valid `and_v(or_c(pk(A), v:pk(B)), after(n))` with a
///   matching sig for A and/or B **and** present nLockTime/nSequence that
///   satisfy BIP-65 (same branch policy; bare top-level or_c never assembled),
/// - nested CLEANSTACK-valid `and_v(or_c(pk(A), v:pk(B)), hash(H))` with a
///   matching sig for A and/or B **and** matching 32-byte PSBT preimage
///   (same branch policy; never invents preimages; bare top-level or_c never
///   assembled),
/// - nested CLEANSTACK-valid `and_v(or_i(v:pk(A), v:pk(B)), hash(H))` with a
///   matching sig for IF/A and/or ELSE/B **and** matching 32-byte PSBT
///   preimage (IF preferred when both; never invents preimages),
/// - nested CLEANSTACK-valid `and_v(or_i(v:pk(A), v:pk(B)), older(n))` with a
///   matching sig for IF/A and/or ELSE/B **and** present nSequence that
///   satisfies BIP-112 (IF preferred; never invents nSequence),
/// - nested CLEANSTACK-valid `and_v(or_i(v:pk(A), v:pk(B)), after(n))` with a
///   matching sig for IF/A and/or ELSE/B **and** present nLockTime/nSequence
///   that satisfy BIP-65 (IF preferred; never invents nLockTime/nSequence),
/// - multi-arm CLEANSTACK-valid
///   `and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), older|after|hash)` with a
///   matching A and/or B and/or C sig **and** present nSequence (older),
///   nLockTime+nSequence (after), or 32-byte PSBT preimage (hash) (A preferred
///   over B over C; never invents),
/// - multi-arm CLEANSTACK-valid
///   `and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), older|after|hash)` with a
///   matching A and/or B and/or C sig **and** present nSequence (older),
///   nLockTime+nSequence (after), or 32-byte PSBT preimage (hash) (A preferred
///   over B over C; IF/ELSE nested selectors; never invents),
/// - after/CLTV forms (`and_v(v:pk, after)` / `and_v(v:after, pk)` / bare
///   `after`) with matching sig (if any) **and** present nLockTime that
///   satisfies BIP-65 for `n` with non-final nSequence (never invents
///   nLockTime/nSequence),
/// and the **already-present** control block verifies against the prevout P2TR.
///
/// Never invents control blocks, leaves, signatures, preimages, or
/// nSequence/nLockTime. Other miniscript / incomplete maps stay Partial.
///
/// When `tap_internal_key` is set, verifies it (+ optional `tap_merkle_root`)
/// reproduces the prevout P2TR scriptPubKey (tamper/corrupt → hard error).
/// Control-block commitment failure is also a hard error (tamper).
fn finalize_taproot_key_path(
    idx: usize,
    input: &mut PsbtInput,
    spk: &ScriptBuf,
    sequence: Sequence,
    tx_version: transaction::Version,
    lock_time: LockTime,
) -> Result<FinalizeInputStep> {
    debug_assert!(spk.is_p2tr());

    if let Some(internal) = input.tap_internal_key {
        let secp = Secp256k1::verification_only();
        let expected = ScriptBuf::new_p2tr(&secp, internal, input.tap_merkle_root);
        if expected != *spk {
            return Err(WalletError::Onchain(format!(
                "input {idx}: tap_internal_key (+ merkle root) does not match P2TR \
                 scriptPubKey (tamper/corrupt; not broadcast-ready)"
            )));
        }
    }

    if let Some(sig) = input.tap_key_sig {
        // Key-path witness is a single Schnorr sig element (BIP-341).
        // Prefer key-path even when script-path maps are also present.
        input.final_script_witness = Some(Witness::p2tr_key_spend(&sig));
        return Ok(FinalizeInputStep::Finalized);
    }

    // --- Script-path: bare CHECKSIG / multi_a / and_v / or_i / or_d / and_n / andor / older / after ---
    if !input.tap_scripts.is_empty() {
        return finalize_taproot_script_path(idx, input, spk, sequence, tx_version, lock_time);
    }

    // Script-path sigs without any leaf/control-block map → residual (no invent).
    if !input.tap_script_sigs.is_empty() {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: Taproot script-path residual missing tap_scripts \
             (control block + leaf; not broadcast-ready)"
        )));
    }

    // ECDSA partial_sigs alone cannot finalize P2TR (BIP-341 needs Schnorr
    // tap_key_sig for key-path). Acknowledge alternate material when present.
    if !input.partial_sigs.is_empty() {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: Taproot key-path residual: ECDSA partial_sigs are insufficient \
             for P2TR (key-path requires tap_key_sig; not broadcast-ready)"
        )));
    }

    Ok(FinalizeInputStep::Residual(format!(
        "input {idx}: Taproot key-path residual missing tap_key_sig \
         (not broadcast-ready)"
    )))
}

/// Assemble Taproot script-path witness from present PSBT fields only.
///
/// Completes when a `tap_scripts` entry is:
/// - bare `<x-only pk> OP_CHECKSIG` with matching `tap_script_sigs`, or
/// - bare multi_a CHECKSIGADD k-of-n with ≥ k matching `tap_script_sigs`
///   (exactly k keys contribute present sigs in script order; remaining
///   keys get empty BIP-342 placeholders — not invented signatures), or
/// - bare thresh (`CHECKSIG` + `SWAP CHECKSIG ADD`… + `k EQUAL` = s:pk;
///   a:pk TOALTSTACK form; mixed s:/a:; pure s:hash / a:hash
///   `thresh(k, pk…, s:hash|a:hash…, …)` trailing/middle/multi-hash; or
///   mixed s:/a:+hash with matching preimage(s) + `k − n_hash` pk sigs)
///   with ≥ k matching `tap_script_sigs` for pure/mixed pk forms (same
///   reverse-key + empty-placeholder policy as multi_a; distinct opcode
///   template), or
/// - bare and_v CHECKSIGVERIFY…CHECKSIG n-of-n with **all** n matching
///   `tap_script_sigs` (no empty placeholders — CHECKSIGVERIFY rejects empty), or
/// - bare or_i IF/ELSE dual CHECKSIG with a matching sig for A and/or B
///   (IF/A preferred when both; branch selector is standard OP_IF encoding,
///   not an invented control path), or
/// - bare or_d IFDUP NOTIF dual CHECKSIG with a matching sig for A and/or B
///   (A preferred when both; only-B uses empty BIP-342 dissatisfaction of A),
///   or
/// - bare and_n NOTIF 0 ELSE dual CHECKSIG with **both** matching sigs
///   (`<sigB> <sigA>`; never invents a B-only path — and_n short-circuits),
///   or
/// - bare andor NOTIF/ELSE triple CHECKSIG with A+B (AB preferred) or C
///   (`<sigC> <empty>`; empty = BIP-342 dissatisfaction of A only),
/// - bare miniscript hash (`SIZE 32 EQUALVERIFY HASHOP digest EQUAL`) with a
///   matching 32-byte PSBT preimage (never invents preimages),
/// - bare and_v(v:pk, hash) with both matching `tap_script_sig` and preimage
///   (`<preimage> <sigA>`),
/// - older/CSV: `and_v(v:pk, older(n))` / `and_v(v:older(n), pk)` /
///   bare `older(n)` when matching sig (if required) is present **and**
///   `sequence` on the unsigned tx already satisfies BIP-112 for `n`
///   (never invents nSequence),
/// - nested CLEANSTACK-valid `and_v(or_c(pk(A), v:pk(B)), older(n))`
///   (`CHECKSIG NOTIF CHECKSIGVERIFY ENDIF <n> CSV`) when a matching sig for
///   A and/or B is present **and** `sequence` satisfies BIP-112 (A preferred;
///   only-B uses empty BIP-342 dissatisfaction of A; bare top-level or_c
///   never assembled),
/// - nested CLEANSTACK-valid `and_v(or_c(pk(A), v:pk(B)), after(n))`
///   (`CHECKSIG NOTIF CHECKSIGVERIFY ENDIF <n> CLTV`) when a matching sig for
///   A and/or B is present **and** `lock_time`/`sequence` satisfy BIP-65 (same
///   branch policy; bare top-level or_c never assembled),
/// - nested CLEANSTACK-valid `and_v(or_c(pk(A), v:pk(B)), hash(H))`
///   (`CHECKSIG NOTIF CHECKSIGVERIFY ENDIF SIZE 32 EQUALVERIFY HASHOP digest
///   EQUAL`) when a matching sig for A and/or B is present **and** a matching
///   32-byte PSBT preimage is present (A preferred; only-B uses empty BIP-342
///   dissatisfaction of A; never invents preimages; bare top-level or_c never
///   assembled),
/// - nested CLEANSTACK-valid `and_v(or_i(v:pk(A), v:pk(B)), hash(H))`
///   (`IF CHECKSIGVERIFY ELSE CHECKSIGVERIFY ENDIF SIZE 32 EQUALVERIFY HASHOP
///   digest EQUAL`) when a matching sig for IF/A and/or ELSE/B is present
///   **and** a matching 32-byte PSBT preimage is present (IF preferred; never
///   invents preimages),
/// - nested CLEANSTACK-valid `and_v(or_i(v:pk(A), v:pk(B)), older(n))`
///   (`IF CHECKSIGVERIFY ELSE CHECKSIGVERIFY ENDIF <n> CSV`) when a matching
///   sig for IF/A and/or ELSE/B is present **and** `sequence` satisfies
///   BIP-112 (IF preferred; never invents nSequence),
/// - nested CLEANSTACK-valid `and_v(or_i(v:pk(A), v:pk(B)), after(n))`
///   (`IF CHECKSIGVERIFY ELSE CHECKSIGVERIFY ENDIF <n> CLTV`) when a matching
///   sig for IF/A and/or ELSE/B is present **and** `lock_time`/`sequence`
///   satisfy BIP-65 (IF preferred; never invents nLockTime/nSequence),
/// - multi-arm CLEANSTACK-valid
///   `and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), older|after|hash)` when a
///   matching A and/or B and/or C sig is present **and** locktime material
///   (older/after) or a matching 32-byte PSBT preimage (hash) is present
///   (A preferred over B over C; empty BIP-342 dissat chain; never invents),
/// - multi-arm CLEANSTACK-valid
///   `and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), older|after|hash)` when a
///   matching A and/or B and/or C sig is present **and** locktime material
///   (older/after) or a matching 32-byte PSBT preimage (hash) is present
///   (A preferred over B over C; nested IF/ELSE selectors; never invents),
/// - nested CLEANSTACK-valid multi-key
///   `and_v(and_v(v:pk…), older|after|hash)` (n ≥ 2 all-`v:pk` CHECKSIGVERIFY
///   chain + trailing CSV|CLTV|bare hash) when **all** n matching
///   `tap_script_sigs` are present **and** locktime material (older/after) or
///   a matching 32-byte PSBT preimage (hash) is present (no empty
///   placeholders; never invents),
/// - nested CLEANSTACK-valid multi-key reverse
///   `and_v(v:older|after|hash, and_v(v:pk…))` (CSV|CLTV|v:hash VERIFY prefix
///   + CHECKSIGVERIFY…CHECKSIG, n ≥ 2) when **all** n matching
///   `tap_script_sigs` are present **and** locktime material (older/after) or
///   a matching 32-byte PSBT preimage (hash) is present (never invents),
/// - nested CLEANSTACK-valid multi-key sandwich
///   `and_v(v:pk…, and_v(v:older|after|hash, pk…))` (left CHECKSIGVERIFY +
///   middle CSV|CLTV|v:hash VERIFY + right CHECKSIG; left ≥ 1, right ≥ 1)
///   when **all** left+right matching `tap_script_sigs` are present **and**
///   locktime material (older/after) or a matching 32-byte PSBT preimage
///   (hash) is present (never invents),
/// - nested CLEANSTACK-valid vault
///   `or_i(and_v(v:pk…)|pk, older|after|hash)` (IF multi-pk CHECKSIGVERIFY…
///   CHECKSIG ≥ 1; ELSE CSV|CLTV|bare hash) when **all** IF-arm sigs are
///   present (IF preferred) **or** ELSE timeout/hash material
///   (already-present nSequence / nLockTime+nSequence / 32-byte PSBT
///   preimage) is present (never invents),
/// - nested CLEANSTACK-valid delayed-recovery inheritance
///   `or_i(and_v(v:pk…)|pk, and_v(v:pk…, older|after|hash))` (IF hot ≥ 1;
///   ELSE cold ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV|bare hash) when
///   **all** IF-arm sigs are present (IF preferred) **or** all ELSE cold
///   sigs + locktime/preimage material are present (never invents),
/// - nested CLEANSTACK-valid HTLC dual-path
///   `or_i(and_v(v:pk…, hash(H)), and_v(v:pk…, older(n)|after(n)))` (IF
///   claim ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash; ELSE refund ≥ 1
///   all-`v:pk` CHECKSIGVERIFY + CSV|CLTV) when **all** IF claim sigs +
///   matching 32-byte PSBT preimage are present (IF preferred) **or** all
///   ELSE refund sigs + already-present nSequence (older) /
///   nLockTime+nSequence (after) are present (never invents),
/// - nested CLEANSTACK-valid reverse HTLC
///   `or_i(and_v(v:pk…, older(n)|after(n)), and_v(v:pk…, hash(H)))` (IF
///   timeout ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV; ELSE claim ≥ 1
///   all-`v:pk` CHECKSIGVERIFY + bare hash) when **all** IF timeout sigs +
///   already-present nSequence (older) / nLockTime+nSequence (after) are
///   present (IF preferred) **or** all ELSE claim sigs + matching 32-byte
///   PSBT preimage are present (never invents),
/// - nested CLEANSTACK-valid dual-hash
///   `or_i(and_v(v:pk…, hash(H1)), and_v(v:pk…, hash(H2)))` (IF claim ≥ 1
///   all-`v:pk` CHECKSIGVERIFY + bare hash; ELSE claim ≥ 1 all-`v:pk`
///   CHECKSIGVERIFY + bare hash) when **all** IF claim sigs + matching
///   32-byte PSBT preimage for H1 are present (IF preferred) **or** all
///   ELSE claim sigs + matching 32-byte PSBT preimage for H2 are present
///   (never invents),
/// - nested CLEANSTACK-valid dual-timeout
///   `or_i(and_v(v:pk…, older(n1)|after(n1)), and_v(v:pk…, older(n2)|after(n2)))`
///   (IF timeout ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV; ELSE timeout ≥ 1
///   all-`v:pk` CHECKSIGVERIFY + CSV|CLTV) when **all** IF timeout sigs +
///   already-present nSequence (older) / nLockTime+nSequence (after) are
///   present (IF preferred) **or** all ELSE timeout sigs + matching locktime
///   material are present (never invents),
/// - nested CLEANSTACK-valid combined hash+timeout
///   `and_v(v:pk…, and_v(v:hash(H), older(n)|after(n)))` (≥ 1 all-`v:pk`
///   CHECKSIGVERIFY + v:hash VERIFY + CSV|CLTV) when **all** key sigs +
///   matching 32-byte PSBT preimage + already-present nSequence (older) /
///   nLockTime+nSequence (after) are present (never invents),
/// - nested CLEANSTACK-valid reverse combined hash+timeout
///   `and_v(v:hash(H), and_v(v:pk…, older(n)|after(n)))` (v:hash VERIFY +
///   ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual of pk-first) when **all**
///   key sigs + matching 32-byte PSBT preimage + already-present nSequence
///   (older) / nLockTime+nSequence (after) are present (never invents),
/// - nested CLEANSTACK-valid lock-first combined hash+timeout
///   `and_v(v:older(n)|after(n), and_v(v:pk…, hash(H)))` (CSV|CLTV VERIFY
///   prefix + ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL — lock-order dual)
///   when **all** key sigs + matching 32-byte PSBT preimage + already-present
///   nSequence (older) / nLockTime+nSequence (after) are present (never invents),
/// - nested CLEANSTACK-valid pk+middle-lock+trailing-hash combined hash+timeout
///   `and_v(v:pk…, and_v(v:older(n)|after(n), hash(H)))` (≥ 1 all-`v:pk`
///   CHECKSIGVERIFY + middle CSV|CLTV VERIFY + bare hash EQUAL — keys-before-lock
///   dual of lock-first) when **all** key sigs + matching 32-byte PSBT preimage
///   + already-present nSequence (older) / nLockTime+nSequence (after) are
///   present (never invents),
/// - nested CLEANSTACK-valid hash+middle-lock+trailing-pk combined hash+timeout
///   `and_v(v:hash(H), and_v(v:older(n)|after(n), pk…))` (v:hash VERIFY + middle
///   CSV|CLTV VERIFY + ≥ 1 trailing keys ending CHECKSIG — hash/pk dual of
///   pk+lock+hash) when **all** key sigs + matching 32-byte PSBT preimage +
///   already-present nSequence (older) / nLockTime+nSequence (after) are present
///   (never invents),
/// - nested CLEANSTACK-valid lock+middle-hash+trailing-pk combined hash+timeout
///   `and_v(v:older(n)|after(n), and_v(v:hash(H), pk…))` (CSV|CLTV VERIFY prefix
///   + v:hash VERIFY + ≥ 1 trailing keys ending CHECKSIG — lock-order dual of
///   hash+lock+pk) when **all** key sigs + matching 32-byte PSBT preimage +
///   already-present nSequence (older) / nLockTime+nSequence (after) are present
///   (never invents),
/// - nested CLEANSTACK-valid dual-hash+timeout combined
///   `and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older(n)|after(n))))`
///   (≥ 1 all-`v:pk` CHECKSIGVERIFY + two v:hash VERIFY + CSV|CLTV — both
///   preimages and locktime required; distinct from dual-hash or_i / single-
///   hash combined) when **all** key sigs + both matching 32-byte PSBT
///   preimages + already-present nSequence (older) / nLockTime+nSequence
///   (after) are present (never invents),
/// - nested CLEANSTACK-valid hash-first dual-hash+timeout
///   `and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older(n)|after(n))))`
///   (two v:hash VERIFY + ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual of
///   pk-first dual-hash+timeout; both preimages + locktime + all key sigs;
///   witness reverse(keys)+preimage2+preimage1 preimage1 top) when **all**
///   key sigs + both matching 32-byte PSBT preimages + already-present
///   nSequence (older) / nLockTime+nSequence (after) are present (never
///   invents),
/// - nested CLEANSTACK-valid dual-hash AND without lock
///   `and_v(v:pk…, and_v(v:hash(H1), hash(H2)))` (≥ 1 all-`v:pk`
///   CHECKSIGVERIFY + v:hash VERIFY + bare hash EQUAL — both preimages
///   required, no locktime; distinct from dual-hash+timeout / dual-hash or_i /
///   multi-pk single-hash) when **all** key sigs + both matching 32-byte PSBT
///   preimages are present (never invents),
/// - nested CLEANSTACK-valid hash-first dual-hash AND without lock
///   `and_v(v:hash(H1), and_v(v:hash(H2), pk…))` (two v:hash VERIFY + ≥ 1
///   trailing keys ending CHECKSIG — dual of pk-first dual-hash AND; both
///   preimages + all key sigs; witness preimage1 top) when **all** key sigs +
///   both matching 32-byte PSBT preimages are present (never invents),
/// - nested CLEANSTACK-valid hash+pk+hash sandwich dual-hash AND without lock
///   `and_v(v:hash(H1), and_v(v:pk…, hash(H2)))` (leading v:hash VERIFY +
///   ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL — both preimages + all
///   key sigs; witness preimage1 top / preimage2 deepest) when **all** key
///   sigs + both matching 32-byte PSBT preimages are present (never invents),
///   **PR5 dual-hash `and_v` keep set only** (pk+dual-hash±lock, dual-hash+pk±lock,
///   hash+pk+hash sandwich); other dual-hash orderings are residual Partial.
/// - after/CLTV: `and_v(v:pk, after(n))` / `and_v(v:after(n), pk)` /
///   bare `after(n)` when matching sig (if required) is present **and**
///   `lock_time` on the unsigned tx already satisfies BIP-65 for `n` with
///   non-final `sequence` (never invents nLockTime/nSequence),
/// and the present control block verifies against the prevout output key.
///
/// # Selection / failure policy
/// - First **completeable** entry in `tap_scripts` [`BTreeMap`](std::collections::BTreeMap)
///   order (`ControlBlock` `Ord`) wins (deterministic; skips incomplete earlier
///   entries; never invents a preference among incomplete leaves).
/// - If an entry is completeable (known template + enough material) but its control
///   block fails commitment verify, that is **hard error for the whole input**
///   — later map entries are **not** tried. Tamper must not be silently
///   skipped even when another leaf would verify.
/// - Complex / non-template leaves and incomplete maps stay residual (Partial).
/// - Multi-leaf residual detail joins unique incompleteness reasons (not
///   first-only), so multi-path PSBTs do not mis-attribute the dominant gap.
fn finalize_taproot_script_path(
    idx: usize,
    input: &mut PsbtInput,
    spk: &ScriptBuf,
    sequence: Sequence,
    tx_version: transaction::Version,
    lock_time: LockTime,
) -> Result<FinalizeInputStep> {
    use bitcoin::taproot::TapLeafHash;

    let Some(output_key) = p2tr_output_key(spk) else {
        return Err(WalletError::Onchain(format!(
            "input {idx}: P2TR scriptPubKey is malformed (cannot extract output key)"
        )));
    };

    let secp = Secp256k1::verification_only();
    // Unique residual reasons in encounter order (multi-leaf honesty).
    let mut residual_reasons: Vec<&'static str> = Vec::new();
    let mut push_reason = |r: &'static str| {
        if !residual_reasons.contains(&r) {
            residual_reasons.push(r);
        }
    };
    // Script-input stack items + leaf + control block (owned; no input borrow).
    let mut chosen: Option<(Vec<Vec<u8>>, ScriptBuf, Vec<u8>)> = None;

    for (control_block, (leaf_script, leaf_ver)) in &input.tap_scripts {
        if *leaf_ver != control_block.leaf_version {
            push_reason("leaf_version mismatch between control block and tap_scripts value");
            continue;
        }

        let leaf_hash = TapLeafHash::from_script(leaf_script, *leaf_ver);

        // --- Bare single-key x-only CHECKSIG ---
        if let Some(xonly) = single_tapscript_checksig_xonly(leaf_script) {
            let Some(sig) = input.tap_script_sigs.get(&(xonly, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for bare CHECKSIG leaf");
                continue;
            };

            // Present control block must commit to this leaf + output key.
            // Failure is tamper/corrupt — hard error for the whole input.
            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                vec![sig.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare multi_a: CHECKSIG + CHECKSIGADD… + k NUMEQUAL ---
        if let Some((threshold, pubkeys)) = bare_tapscript_checksigadd_multi_template(leaf_script) {
            // Collect present sigs; take first `threshold` keys in script order
            // that already have tap_script_sigs (never invent signatures).
            // Empty Vec = BIP-342 unused-key placeholder (not an invented Schnorr).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut filled = 0usize;
            for pk in &pubkeys {
                if filled < threshold {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        sig_slots.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                // Unused key slot (or past threshold): empty BIP-342 placeholder.
                sig_slots.push(Vec::new());
            }
            if filled < threshold {
                push_reason("insufficient tap_script_sigs for multi_a CHECKSIGADD threshold");
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness script inputs: reverse key order (last key's slot first).
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare thresh: CHECKSIG + (SWAP CHECKSIG ADD)+ + k EQUAL ---
        // miniscript thresh(k, pk, s:pk, …) — distinct from multi_a.
        if let Some((threshold, pubkeys)) = bare_tapscript_thresh_checksig_template(leaf_script) {
            // Same selection policy as multi_a: first `threshold` keys in
            // script order that already have tap_script_sigs; empty BIP-342
            // placeholders for the rest (never invent signatures).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut filled = 0usize;
            for pk in &pubkeys {
                if filled < threshold {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        sig_slots.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                sig_slots.push(Vec::new());
            }
            if filled < threshold {
                push_reason("insufficient tap_script_sigs for thresh k-of-n threshold");
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness script inputs: reverse key order (last key's slot first).
            // SWAP arms need later keys' material deeper so earlier keys run first.
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare a:pk thresh: CHECKSIG + (TOALTSTACK CHECKSIG FROMALTSTACK ADD)+ + k EQUAL ---
        // miniscript thresh(k, pk, a:pk, …) — non-s:pk dual of SWAP thresh.
        if let Some((threshold, pubkeys)) =
            bare_tapscript_thresh_a_pk_checksig_template(leaf_script)
        {
            // Same selection + reverse-order witness policy as s:pk thresh
            // (ADD is commutative; empty BIP-342 placeholders for unused keys).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut filled = 0usize;
            for pk in &pubkeys {
                if filled < threshold {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        sig_slots.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                sig_slots.push(Vec::new());
            }
            if filled < threshold {
                push_reason("insufficient tap_script_sigs for a:pk thresh k-of-n threshold");
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness script inputs: reverse key order (last key's slot first).
            // a:pk arms TOALTSTACK the running sum so later keys' sigs sit deeper.
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare mixed s:/a: thresh: CHECKSIG + mix(SWAP|TOALTSTACK arms) + k EQUAL ---
        // miniscript thresh(k, pk, s:pk…, a:pk…) — both type-W wrappers present.
        if let Some((threshold, pubkeys)) =
            bare_tapscript_thresh_mixed_sa_checksig_template(leaf_script)
        {
            // Same selection + reverse-order witness policy as pure s:/a: thresh
            // (ADD commutative; empty BIP-342 placeholders; never invent sigs).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut filled = 0usize;
            for pk in &pubkeys {
                if filled < threshold {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        sig_slots.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                sig_slots.push(Vec::new());
            }
            if filled < threshold {
                push_reason("insufficient tap_script_sigs for mixed s:/a: thresh k-of-n threshold");
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness script inputs: reverse key order (last key's slot first).
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare thresh with one+ pure s:hash (trailing/middle/multi): CHECKSIG + SWAP + k EQUAL ---
        // miniscript thresh(k, pk…, s:hash…, s:pk…) — each hash arm always contributes 1.
        if let Some(tmpl) = bare_tapscript_thresh_s_hash_template(leaf_script) {
            let n_hash = tmpl.n_hash();
            // Resolve every hash arm preimage first (all required — not empty-dissatisfiable).
            let mut preimages: Vec<(usize, Vec<u8>)> = Vec::with_capacity(n_hash);
            let mut missing_preimage = false;
            for h in &tmpl.hash_arms {
                match lookup_miniscript_hash_preimage(idx, input, h.kind, h.digest.as_slice())? {
                    Some(preimage) => preimages.push((h.arm_idx, preimage)),
                    None => {
                        missing_preimage = true;
                        break;
                    }
                }
            }
            if missing_preimage {
                push_reason(
                    "missing matching PSBT preimage for thresh(s:hash) leaf \
                     (all hash arms required)",
                );
                continue;
            }
            // Hash arms contribute n_hash → need exactly (k − n_hash) pk sigs.
            // Parser invariant: k >= n_hash; fail closed if that ever regresses.
            let Some(pk_needed) = tmpl.threshold.checked_sub(n_hash) else {
                push_reason("thresh(s:hash) unsatisfiable: k < n_hash (parser invariant violated)");
                continue;
            };
            let n = tmpl.pubkeys.len() + n_hash;
            let mut arm_inputs: Vec<Vec<u8>> = Vec::with_capacity(n);
            let mut filled = 0usize;
            let mut pk_i = 0usize;
            let mut hash_i = 0usize;
            for arm_i in 0..n {
                if hash_i < preimages.len() && preimages[hash_i].0 == arm_i {
                    arm_inputs.push(preimages[hash_i].1.clone());
                    hash_i += 1;
                    continue;
                }
                let pk = &tmpl.pubkeys[pk_i];
                pk_i += 1;
                if filled < pk_needed {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        arm_inputs.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                // Unused pk slot (or past pk_needed): empty BIP-342 placeholder.
                // Even present sigs past (k−n_hash) stay empty so EQUAL sees sum k.
                arm_inputs.push(Vec::new());
            }
            if filled < pk_needed {
                push_reason(
                    "insufficient tap_script_sigs for thresh(s:hash) k-of-n \
                     (need k-n_hash pk sigs with present preimages)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: reverse arm order (last arm deepest) — preimages at each arm_idx.
            arm_inputs.reverse();
            chosen = Some((arm_inputs, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare thresh with one+ pure a:hash (TOALTSTACK dual of s:hash) ---
        // miniscript thresh(k, pk…, a:hash…, a:pk…) — same witness policy as s:hash.
        if let Some(tmpl) = bare_tapscript_thresh_a_hash_template(leaf_script) {
            let n_hash = tmpl.n_hash();
            let mut preimages: Vec<(usize, Vec<u8>)> = Vec::with_capacity(n_hash);
            let mut missing_preimage = false;
            for h in &tmpl.hash_arms {
                match lookup_miniscript_hash_preimage(idx, input, h.kind, h.digest.as_slice())? {
                    Some(preimage) => preimages.push((h.arm_idx, preimage)),
                    None => {
                        missing_preimage = true;
                        break;
                    }
                }
            }
            if missing_preimage {
                push_reason(
                    "missing matching PSBT preimage for thresh(a:hash) leaf \
                     (all hash arms required)",
                );
                continue;
            }
            // Parser invariant: k >= n_hash; fail closed if that ever regresses.
            let Some(pk_needed) = tmpl.threshold.checked_sub(n_hash) else {
                push_reason("thresh(a:hash) unsatisfiable: k < n_hash (parser invariant violated)");
                continue;
            };
            let n = tmpl.pubkeys.len() + n_hash;
            let mut arm_inputs: Vec<Vec<u8>> = Vec::with_capacity(n);
            let mut filled = 0usize;
            let mut pk_i = 0usize;
            let mut hash_i = 0usize;
            for arm_i in 0..n {
                if hash_i < preimages.len() && preimages[hash_i].0 == arm_i {
                    arm_inputs.push(preimages[hash_i].1.clone());
                    hash_i += 1;
                    continue;
                }
                let pk = &tmpl.pubkeys[pk_i];
                pk_i += 1;
                if filled < pk_needed {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        arm_inputs.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                arm_inputs.push(Vec::new());
            }
            if filled < pk_needed {
                push_reason(
                    "insufficient tap_script_sigs for thresh(a:hash) k-of-n \
                     (need k-n_hash pk sigs with present preimages)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            arm_inputs.reverse();
            chosen = Some((arm_inputs, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare thresh mixed s:/a: with one+ hash arms ---
        // miniscript thresh(k, pk…, s:|a: pk/hash…) with both wrappers + n_hash ≥ 1.
        // Same witness policy as pure multi-hash s:/a:hash.
        if let Some(tmpl) = bare_tapscript_thresh_mixed_sa_hash_template(leaf_script) {
            let n_hash = tmpl.n_hash();
            let mut preimages: Vec<(usize, Vec<u8>)> = Vec::with_capacity(n_hash);
            let mut missing_preimage = false;
            for h in &tmpl.hash_arms {
                match lookup_miniscript_hash_preimage(idx, input, h.kind, h.digest.as_slice())? {
                    Some(preimage) => preimages.push((h.arm_idx, preimage)),
                    None => {
                        missing_preimage = true;
                        break;
                    }
                }
            }
            if missing_preimage {
                push_reason(
                    "missing matching PSBT preimage for thresh(mixed s:/a:+hash) leaf \
                     (all hash arms required)",
                );
                continue;
            }
            // Parser invariant: k >= n_hash; fail closed if that ever regresses.
            let Some(pk_needed) = tmpl.threshold.checked_sub(n_hash) else {
                push_reason(
                    "thresh(mixed s:/a:+hash) unsatisfiable: k < n_hash \
                     (parser invariant violated)",
                );
                continue;
            };
            let n = tmpl.pubkeys.len() + n_hash;
            let mut arm_inputs: Vec<Vec<u8>> = Vec::with_capacity(n);
            let mut filled = 0usize;
            let mut pk_i = 0usize;
            let mut hash_i = 0usize;
            for arm_i in 0..n {
                if hash_i < preimages.len() && preimages[hash_i].0 == arm_i {
                    arm_inputs.push(preimages[hash_i].1.clone());
                    hash_i += 1;
                    continue;
                }
                let pk = &tmpl.pubkeys[pk_i];
                pk_i += 1;
                if filled < pk_needed {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        arm_inputs.push(sig.to_vec());
                        filled += 1;
                        continue;
                    }
                }
                // Unused pk slot (or past pk_needed): empty BIP-342 placeholder.
                arm_inputs.push(Vec::new());
            }
            if filled < pk_needed {
                push_reason(
                    "insufficient tap_script_sigs for thresh(mixed s:/a:+hash) k-of-n \
                     (need k-n_hash pk sigs with present preimages)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            arm_inputs.reverse();
            chosen = Some((arm_inputs, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare and_v: (<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG (n-of-n) ---
        if let Some(pubkeys) = bare_tapscript_and_v_checksigverify_template(leaf_script) {
            // All n keys require present sigs — no empty placeholders
            // (CHECKSIGVERIFY fails on empty BIP-342 unused-key vectors).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Reverse key order: last key's sig is first witness element (bottom).
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- Bare or_i: IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b)) = bare_tapscript_or_i_checksig_template(leaf_script) {
            // Prefer IF/A when both present; else ELSE/B. Never invent a branch
            // when neither sig is present.
            let script_inputs =
                if let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() {
                    // OP_IF true: non-empty branch selector (standard 0x01).
                    vec![sig_a.to_vec(), vec![1u8]]
                } else if let Some(sig_b) = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied() {
                    // OP_IF false: empty branch selector.
                    vec![sig_b.to_vec(), Vec::new()]
                } else {
                    push_reason("missing tap_script_sig for both or_i IF/ELSE branches");
                    continue;
                };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare or_d: <A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b)) = bare_tapscript_or_d_checksig_template(leaf_script) {
            // Prefer A when both present; else B with empty BIP-342 dissatisfaction
            // of A. Never invent a branch when neither sig is present.
            let script_inputs =
                if let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() {
                    // A path: single sig; IFDUP keeps CHECKSIG true for CLEANSTACK.
                    vec![sig_a.to_vec()]
                } else if let Some(sig_b) = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied() {
                    // B path: <sigB> <empty> — empty is BIP-342 CHECKSIG dissatisfaction
                    // of A (not an invented Schnorr).
                    vec![sig_b.to_vec(), Vec::new()]
                } else {
                    push_reason("missing tap_script_sig for both or_d A/B branches");
                    continue;
                };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare and_n: <A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b)) = bare_tapscript_and_n_checksig_template(leaf_script) {
            // Both keys required — and_n short-circuits to 0 when A is false,
            // so a B-only path cannot complete (never invent empty A + sigB).
            // Distinct residual reasons so multi-leaf join can name which key
            // was absent (not a single shared "both required" string).
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("insufficient tap_script_sigs for and_n (missing A)");
                continue;
            };
            let Some(sig_b) = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied() else {
                push_reason("insufficient tap_script_sigs for and_n (missing B)");
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <sigB> <sigA> — A is top-of-stack first (executed first).
            chosen = Some((
                vec![sig_b.to_vec(), sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare andor: <A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF ---
        if let Some((pk_a, pk_b, pk_c)) = bare_tapscript_andor_checksig_template(leaf_script) {
            // Prefer AB when both A+B present; else C with empty BIP-342
            // dissatisfaction of A. Never invent empty A without present C,
            // never invent B when only A is present, never invent A for C path.
            let script_inputs = if let (Some(sig_a), Some(sig_b)) = (
                input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied(),
                input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied(),
            ) {
                // AB path: <sigB> <sigA> — A top-of-stack first (executed first).
                vec![sig_b.to_vec(), sig_a.to_vec()]
            } else if let Some(sig_c) = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied() {
                // C path: <sigC> <empty> — empty = BIP-342 dissat of A only.
                vec![sig_c.to_vec(), Vec::new()]
            } else {
                // Neither AB nor C completeable — name the gap distinctly.
                let has_a = input.tap_script_sigs.contains_key(&(pk_a, leaf_hash));
                let has_b = input.tap_script_sigs.contains_key(&(pk_b, leaf_hash));
                if has_a && !has_b {
                    push_reason(
                        "insufficient tap_script_sigs for andor (missing B for AB; missing C)",
                    );
                } else if has_b && !has_a {
                    push_reason(
                        "insufficient tap_script_sigs for andor (missing A for AB; missing C)",
                    );
                } else {
                    push_reason("missing tap_script_sig for andor A/B/C paths");
                }
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- Bare miniscript hash: SIZE 32 EQUALVERIFY HASHOP digest EQUAL ---
        if let Some((kind, digest)) = bare_tapscript_hash_preimage_template(leaf_script) {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason("missing matching PSBT preimage for bare hash leaf");
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: single preimage (SIZE 32 already enforced in lookup).
            chosen = Some((
                vec![preimage],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:pk(A), hash(H)): <A> CHECKSIGVERIFY + hash fragment ---
        if let Some((pk_a, kind, digest)) = bare_tapscript_and_v_pk_hash_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("insufficient tap_script_sigs for and_v(v:pk, hash) (missing A)");
                continue;
            };
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason("missing matching PSBT preimage for and_v(v:pk, hash) leaf");
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <preimage> <sigA> — A/sig is top-of-stack (CHECKSIGVERIFY first).
            chosen = Some((
                vec![preimage, sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:hash(H), pk(A)): v:hash EQUALVERIFY + <A> CHECKSIG ---
        if let Some((pk_a, kind, digest)) = bare_tapscript_and_v_hash_pk_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("insufficient tap_script_sigs for and_v(v:hash, pk) (missing A)");
                continue;
            };
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason("missing matching PSBT preimage for and_v(v:hash, pk) leaf");
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <sigA> <preimage> — preimage top-of-stack (hash fragment first).
            chosen = Some((
                vec![sig_a.to_vec(), preimage],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:pk(A), older(n)): <A> CHECKSIGVERIFY <n> CSV ---
        if let Some((pk_a, older_n)) = bare_tapscript_and_v_pk_older_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:pk, older) leaf");
                continue;
            };
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                // Never invent nSequence — residual when present sequence is
                // disabled / type-mismatch / below required / tx version < 2.
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <sigA> only (CSV reads nSequence, not the witness).
            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:older(n), pk(A)): <n> CSV VERIFY <A> CHECKSIG ---
        if let Some((older_n, pk_a)) = bare_tapscript_and_v_older_pk_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:older, pk) leaf");
                continue;
            };
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- bare older(n): <n> CSV (empty script-input stack) ---
        if let Some(older_n) = bare_tapscript_older_template(leaf_script) {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: empty script inputs — only leaf + control block.
            chosen = Some((Vec::new(), leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- and_v(v:pk(A), after(n)): <A> CHECKSIGVERIFY <n> CLTV ---
        if let Some((pk_a, after_n)) = bare_tapscript_and_v_pk_after_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:pk, after) leaf");
                continue;
            };
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                // Never invent nLockTime/nSequence — residual when present
                // locktime is below required / type-mismatch / sequence final.
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: <sigA> only (CLTV reads nLockTime, not the witness).
            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(v:after(n), pk(A)): <n> CLTV VERIFY <A> CHECKSIG ---
        if let Some((after_n, pk_a)) = bare_tapscript_and_v_after_pk_template(leaf_script) {
            let Some(sig_a) = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied() else {
                push_reason("missing matching tap_script_sig for and_v(v:after, pk) leaf");
                continue;
            };
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                vec![sig_a.to_vec()],
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- bare after(n): <n> CLTV (empty script-input stack) ---
        if let Some(after_n) = bare_tapscript_after_template(leaf_script) {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime \
                     (present on unsigned_tx; not invented)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness: empty script inputs — only leaf + control block.
            chosen = Some((Vec::new(), leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- and_v(or_c(pk(A), v:pk(B)), older(n)): nested CLEANSTACK-valid ---
        // Must run before bare or_c residual (distinct template: CHECKSIGVERIFY + CSV).
        if let Some((pk_a, pk_b, older_n)) = bare_tapscript_and_v_or_c_older_template(leaf_script) {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     and_v(or_c, older) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b) {
                (Some(sig_a), _) => {
                    // A preferred when both — deterministic; no invented branch.
                    vec![sig_a.to_vec()]
                }
                (None, Some(sig_b)) => {
                    // B only: empty BIP-342 dissatisfaction of A + sigB.
                    vec![sig_b.to_vec(), Vec::new()]
                }
                (None, None) => {
                    push_reason("missing tap_script_sig for both and_v(or_c, older) A/B branches");
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(or_c(pk(A), v:pk(B)), after(n)): nested CLEANSTACK-valid ---
        // Dual of older path; must run before bare or_c residual
        // (distinct template: CHECKSIGVERIFY + CLTV).
        if let Some((pk_a, pk_b, after_n)) = bare_tapscript_and_v_or_c_after_template(leaf_script) {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     and_v(or_c, after) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b) {
                (Some(sig_a), _) => {
                    // A preferred when both — deterministic; no invented branch.
                    vec![sig_a.to_vec()]
                }
                (None, Some(sig_b)) => {
                    // B only: empty BIP-342 dissatisfaction of A + sigB.
                    vec![sig_b.to_vec(), Vec::new()]
                }
                (None, None) => {
                    push_reason("missing tap_script_sig for both and_v(or_c, after) A/B branches");
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(or_c(pk(A), v:pk(B)), hash(H)): nested CLEANSTACK-valid ---
        // Dual of older/after with trailing bare hash; must run before bare or_c
        // residual (distinct template: CHECKSIGVERIFY + SIZE/HASHOP/EQUAL).
        if let Some((pk_a, pk_b, kind, digest)) =
            bare_tapscript_and_v_or_c_hash_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(or_c, hash) leaf \
                     (never invents preimages)",
                );
                continue;
            };
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b) {
                (Some(sig_a), _) => {
                    // A preferred when both — deterministic; no invented branch.
                    // <preimage> <sigA> — sig top for CHECKSIG first; preimage deeper.
                    vec![preimage, sig_a.to_vec()]
                }
                (None, Some(sig_b)) => {
                    // B only: <preimage> <sigB> <empty> — empty BIP-342 dissat of A.
                    vec![preimage, sig_b.to_vec(), Vec::new()]
                }
                (None, None) => {
                    push_reason("missing tap_script_sig for both and_v(or_c, hash) A/B branches");
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(or_i(v:pk(A), v:pk(B)), hash(H)): nested CLEANSTACK-valid ---
        // Dual of or_c+hash with IF/ELSE + CHECKSIGVERIFY arms; must run before
        // bare or_c residual (distinct template: OP_IF + VERIFY + hash tail).
        if let Some((pk_a, pk_b, kind, digest)) =
            bare_tapscript_and_v_or_i_hash_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(or_i, hash) leaf \
                     (never invents preimages)",
                );
                continue;
            };
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b) {
                (Some(sig_a), _) => {
                    // IF/A preferred when both — deterministic; no invented branch.
                    // <preimage> <sigA> <0x01> — preimage deepest; IF selector top.
                    vec![preimage, sig_a.to_vec(), vec![1u8]]
                }
                (None, Some(sig_b)) => {
                    // ELSE/B only: <preimage> <sigB> <empty> — empty = false IF selector.
                    vec![preimage, sig_b.to_vec(), Vec::new()]
                }
                (None, None) => {
                    push_reason(
                        "missing tap_script_sig for both and_v(or_i, hash) IF/ELSE branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(or_i(v:pk(A), v:pk(B)), older(n)): nested CLEANSTACK-valid ---
        // Dual of or_c+older with IF/ELSE + CHECKSIGVERIFY arms; dual of or_i+hash
        // with trailing CSV. Must run before bare or_c residual.
        if let Some((pk_a, pk_b, older_n)) = bare_tapscript_and_v_or_i_older_template(leaf_script) {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     and_v(or_i, older) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b) {
                (Some(sig_a), _) => {
                    // IF/A preferred when both — deterministic; no invented branch.
                    // <sigA> <0x01> — IF selector top.
                    vec![sig_a.to_vec(), vec![1u8]]
                }
                (None, Some(sig_b)) => {
                    // ELSE/B only: <sigB> <empty> — empty = false IF selector.
                    vec![sig_b.to_vec(), Vec::new()]
                }
                (None, None) => {
                    push_reason(
                        "missing tap_script_sig for both and_v(or_i, older) IF/ELSE branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- and_v(or_i(v:pk(A), v:pk(B)), after(n)): nested CLEANSTACK-valid ---
        // Dual of or_c+after / or_i+older with trailing CLTV. Must run before
        // bare or_c residual.
        if let Some((pk_a, pk_b, after_n)) = bare_tapscript_and_v_or_i_after_template(leaf_script) {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     and_v(or_i, after) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b) {
                (Some(sig_a), _) => {
                    // IF/A preferred when both — deterministic; no invented branch.
                    // <sigA> <0x01> — IF selector top.
                    vec![sig_a.to_vec(), vec![1u8]]
                }
                (None, Some(sig_b)) => {
                    // ELSE/B only: <sigB> <empty> — empty = false IF selector.
                    vec![sig_b.to_vec(), Vec::new()]
                }
                (None, None) => {
                    push_reason(
                        "missing tap_script_sig for both and_v(or_i, after) IF/ELSE branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-arm and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), older(n)) ---
        // Distinct from dual-key and_v(or_c, older): nested NOTIF + intermediate
        // CHECKSIG (B) + CHECKSIGVERIFY (C). Must run before bare or_c residual.
        if let Some((pk_a, pk_b, pk_c, older_n)) =
            bare_tapscript_and_v_or_c_multi_older_template(leaf_script)
        {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     and_v(or_c multi-arm, older) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let sig_c = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b, sig_c) {
                (Some(sig_a), _, _) => {
                    // A preferred when present — deterministic; no invented branch.
                    vec![sig_a.to_vec()]
                }
                (None, Some(sig_b), _) => {
                    // B only (or B+C): empty BIP-342 dissatisfaction of A + sigB.
                    vec![sig_b.to_vec(), Vec::new()]
                }
                (None, None, Some(sig_c)) => {
                    // C only: empty dissat of B then A + sigC (deepest).
                    vec![sig_c.to_vec(), Vec::new(), Vec::new()]
                }
                (None, None, None) => {
                    push_reason(
                        "missing tap_script_sig for all and_v(or_c multi-arm, older) A/B/C branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-arm and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), after(n)) ---
        // Dual of multi-arm older with trailing CLTV. Must run before bare or_c.
        if let Some((pk_a, pk_b, pk_c, after_n)) =
            bare_tapscript_and_v_or_c_multi_after_template(leaf_script)
        {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     and_v(or_c multi-arm, after) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let sig_c = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b, sig_c) {
                (Some(sig_a), _, _) => {
                    // A preferred when present — deterministic; no invented branch.
                    vec![sig_a.to_vec()]
                }
                (None, Some(sig_b), _) => {
                    // B only (or B+C): empty BIP-342 dissatisfaction of A + sigB.
                    vec![sig_b.to_vec(), Vec::new()]
                }
                (None, None, Some(sig_c)) => {
                    // C only: empty dissat of B then A + sigC (deepest).
                    vec![sig_c.to_vec(), Vec::new(), Vec::new()]
                }
                (None, None, None) => {
                    push_reason(
                        "missing tap_script_sig for all and_v(or_c multi-arm, after) A/B/C branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-arm and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), hash(H)) ---
        // Dual of multi-arm older/after with trailing bare hash; dual of dual-key
        // and_v(or_c, hash) with nested NOTIF + intermediate CHECKSIG (B).
        // Must run before bare or_c residual.
        if let Some((pk_a, pk_b, pk_c, kind, digest)) =
            bare_tapscript_and_v_or_c_multi_hash_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(or_c multi-arm, hash) leaf \
                     (never invents preimages)",
                );
                continue;
            };
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let sig_c = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b, sig_c) {
                (Some(sig_a), _, _) => {
                    // A preferred when present — deterministic; no invented branch.
                    // <preimage> <sigA> — sig top for CHECKSIG first; preimage deeper.
                    vec![preimage, sig_a.to_vec()]
                }
                (None, Some(sig_b), _) => {
                    // B only (or B+C): <preimage> <sigB> <empty> — empty BIP-342 dissat of A.
                    vec![preimage, sig_b.to_vec(), Vec::new()]
                }
                (None, None, Some(sig_c)) => {
                    // C only: <preimage> <sigC> <empty> <empty> — empty dissat of B then A.
                    vec![preimage, sig_c.to_vec(), Vec::new(), Vec::new()]
                }
                (None, None, None) => {
                    push_reason(
                        "missing tap_script_sig for all and_v(or_c multi-arm, hash) A/B/C branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-arm and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), older(n)) ---
        // Distinct from dual-key and_v(or_i, older): nested IF/ELSE + three
        // CHECKSIGVERIFY arms. Dual of multi-arm or_c older. Must run before
        // bare or_c residual.
        if let Some((pk_a, pk_b, pk_c, older_n)) =
            bare_tapscript_and_v_or_i_multi_older_template(leaf_script)
        {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     and_v(or_i multi-arm, older) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let sig_c = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b, sig_c) {
                (Some(sig_a), _, _) => {
                    // A preferred when present — deterministic; no invented branch.
                    // <sigA> <0x01> — outer IF selector top.
                    vec![sig_a.to_vec(), vec![1u8]]
                }
                (None, Some(sig_b), _) => {
                    // B only (or B+C): <sigB> <0x01> <empty> — empty outer false;
                    // 0x01 = true inner IF.
                    vec![sig_b.to_vec(), vec![1u8], Vec::new()]
                }
                (None, None, Some(sig_c)) => {
                    // C only: <sigC> <empty> <empty> — empty outer + empty inner.
                    vec![sig_c.to_vec(), Vec::new(), Vec::new()]
                }
                (None, None, None) => {
                    push_reason(
                        "missing tap_script_sig for all and_v(or_i multi-arm, older) A/B/C branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-arm and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), after(n)) ---
        // Dual of multi-arm or_i older with trailing CLTV. Must run before bare or_c.
        if let Some((pk_a, pk_b, pk_c, after_n)) =
            bare_tapscript_and_v_or_i_multi_after_template(leaf_script)
        {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     and_v(or_i multi-arm, after) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let sig_c = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b, sig_c) {
                (Some(sig_a), _, _) => {
                    // A preferred when present — deterministic; no invented branch.
                    vec![sig_a.to_vec(), vec![1u8]]
                }
                (None, Some(sig_b), _) => {
                    // B only (or B+C): <sigB> <0x01> <empty>.
                    vec![sig_b.to_vec(), vec![1u8], Vec::new()]
                }
                (None, None, Some(sig_c)) => {
                    // C only: <sigC> <empty> <empty>.
                    vec![sig_c.to_vec(), Vec::new(), Vec::new()]
                }
                (None, None, None) => {
                    push_reason(
                        "missing tap_script_sig for all and_v(or_i multi-arm, after) A/B/C branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-arm and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), hash(H)) ---
        // Dual of multi-arm or_i older/after with trailing bare hash; dual of
        // dual-key and_v(or_i, hash) with nested IF/ELSE. Must run before bare or_c.
        if let Some((pk_a, pk_b, pk_c, kind, digest)) =
            bare_tapscript_and_v_or_i_multi_hash_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(or_i multi-arm, hash) leaf \
                     (never invents preimages)",
                );
                continue;
            };
            let sig_a = input.tap_script_sigs.get(&(pk_a, leaf_hash)).copied();
            let sig_b = input.tap_script_sigs.get(&(pk_b, leaf_hash)).copied();
            let sig_c = input.tap_script_sigs.get(&(pk_c, leaf_hash)).copied();
            let script_inputs = match (sig_a, sig_b, sig_c) {
                (Some(sig_a), _, _) => {
                    // A preferred when present — deterministic; no invented branch.
                    // <preimage> <sigA> <0x01> — preimage deepest; outer IF top.
                    vec![preimage, sig_a.to_vec(), vec![1u8]]
                }
                (None, Some(sig_b), _) => {
                    // B only (or B+C): <preimage> <sigB> <0x01> <empty>.
                    vec![preimage, sig_b.to_vec(), vec![1u8], Vec::new()]
                }
                (None, None, Some(sig_c)) => {
                    // C only: <preimage> <sigC> <empty> <empty>.
                    vec![preimage, sig_c.to_vec(), Vec::new(), Vec::new()]
                }
                (None, None, None) => {
                    push_reason(
                        "missing tap_script_sig for all and_v(or_i multi-arm, hash) A/B/C branches",
                    );
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-key and_v(and_v(v:pk…), older(n)): CLEANSTACK-valid ---
        // (≥2 CHECKSIGVERIFY + CSV). Distinct from single-key and_v(v:pk, older).
        if let Some((pubkeys, older_n)) = bare_tapscript_and_v_multi_pk_older_template(leaf_script)
        {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     and_v(multi-pk, older) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            // All n keys require present sigs — no empty placeholders
            // (CHECKSIGVERIFY fails on empty BIP-342 unused-key vectors).
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(multi-pk, older) \
                     CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Reverse key order: last key's sig is first witness element (bottom);
            // first key's sig is top for the first CHECKSIGVERIFY.
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- multi-key and_v(and_v(v:pk…), after(n)): CLEANSTACK-valid ---
        // Dual of multi-pk older with BIP-65 CLTV.
        if let Some((pubkeys, after_n)) = bare_tapscript_and_v_multi_pk_after_template(leaf_script)
        {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     and_v(multi-pk, after) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(multi-pk, after) \
                     CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- multi-key and_v(and_v(v:pk…), hash(H)): CLEANSTACK-valid ---
        // Dual of multi-pk older/after with trailing bare hash fragment.
        if let Some((pubkeys, kind, digest)) =
            bare_tapscript_and_v_multi_pk_hash_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(multi-pk, hash) leaf \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(multi-pk, hash) \
                     CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <preimage> <sig_last> … <sig_first> — preimage deepest; first
            // key's sig top so CHECKSIGVERIFY runs before the hash fragment.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.push(preimage);
            script_inputs.extend(sig_slots);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- combined hash+timeout and_v(v:pk…, and_v(v:hash, older|after)) ---
        // ≥1 CHECKSIGVERIFY + v:hash VERIFY + CSV|CLTV — single path requiring
        // BOTH preimage and locktime (AND, not HTLC OR dual-path). Distinct
        // from and_v(v:pk, hash) / multi-pk hash (no lock) / sandwich (right
        // keys) / classic HTLC or_i.
        if let Some((pubkeys, kind, digest, lock)) =
            bare_tapscript_and_v_pk_hash_lock_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(v:pk…, and_v(v:hash, older|after)) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:pk…, and_v(v:hash, older|after)) \
                     CHECKSIGVERIFY chain (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:pk…, and_v(v:hash, older)) (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                         and_v(v:pk…, and_v(v:hash, after)) (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <preimage> <sig_last> … <sig_first> — same witness shape as multi-pk
            // hash; CSV|CLTV consumes no witness elements.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.push(preimage);
            script_inputs.extend(sig_slots);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- reverse combined hash+timeout and_v(v:hash, and_v(v:pk…, older|after)) ---
        // v:hash VERIFY + ≥1 CHECKSIGVERIFY + CSV|CLTV — dual of pk-first
        // combined; single path requiring BOTH preimage and locktime.
        // Distinct from reverse multi-hash (ends CHECKSIG) / and_v(v:hash, pk).
        if let Some((pubkeys, kind, digest, lock)) =
            bare_tapscript_and_v_hash_pk_lock_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(v:hash, and_v(v:pk…, older|after)) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:hash, and_v(v:pk…, older|after)) \
                     CHECKSIGVERIFY chain (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:hash, and_v(v:pk…, older)) (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                         and_v(v:hash, and_v(v:pk…, after)) (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <sig_last> … <sig_first> <preimage> — preimage top for v:hash;
            // reverse-key sigs feed CHECKSIGVERIFY chain; CSV|CLTV no witness.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.extend(sig_slots);
            script_inputs.push(preimage);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- lock-first combined hash+timeout
        // and_v(v:older|after, and_v(v:pk…, hash)) ---
        // CSV|CLTV VERIFY prefix + ≥1 CHECKSIGVERIFY + bare hash EQUAL —
        // single path requiring BOTH preimage and locktime. Distinct from
        // reverse multi older/after (ends CHECKSIG) / multi-pk hash (no lock)
        // / pk-first combined (keys+hash VERIFY+CSV) / reverse combined /
        // pk+middle-lock+trailing-hash.
        if let Some((pubkeys, kind, digest, lock)) =
            bare_tapscript_and_v_lock_pk_hash_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(v:older|after, and_v(v:pk…, hash)) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:older|after, and_v(v:pk…, hash)) \
                     CHECKSIGVERIFY chain (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:older, and_v(v:pk…, hash)) (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                         and_v(v:after, and_v(v:pk…, hash)) (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <preimage> <sig_last> … <sig_first> — same witness shape as multi-pk
            // hash; CSV|CLTV VERIFY consumes no witness elements.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.push(preimage);
            script_inputs.extend(sig_slots);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- pk + middle lock + trailing hash combined hash+timeout
        // and_v(v:pk…, and_v(v:older|after, hash)) ---
        // ≥1 CHECKSIGVERIFY + middle CSV|CLTV VERIFY + bare hash EQUAL —
        // single path requiring BOTH preimage and locktime. Distinct from
        // sandwich (right keys after lock) / pk-first combined (hash then
        // terminal lock) / multi-pk hash (no lock) / lock-first (lock prefix).
        if let Some((pubkeys, kind, digest, lock)) =
            bare_tapscript_and_v_pk_lock_hash_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(v:pk…, and_v(v:older|after, hash)) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:pk…, and_v(v:older|after, hash)) \
                     CHECKSIGVERIFY chain (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:pk…, and_v(v:older, hash)) (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                         and_v(v:pk…, and_v(v:after, hash)) (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <preimage> <sig_last> … <sig_first> — same witness shape as multi-pk
            // hash / lock-first combined; middle CSV|CLTV VERIFY consumes no
            // witness elements.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.push(preimage);
            script_inputs.extend(sig_slots);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- hash + middle lock + trailing pk combined hash+timeout
        // and_v(v:hash, and_v(v:older|after, pk…)) ---
        // v:hash VERIFY + middle CSV|CLTV VERIFY + ≥1 trailing keys ending
        // CHECKSIG — single path requiring BOTH preimage and locktime.
        // Distinct from reverse multi-hash (no lock) / reverse combined
        // (keys then terminal bare CSV|CLTV) / sandwich / lock-first combined.
        if let Some((pubkeys, kind, digest, lock)) =
            bare_tapscript_and_v_hash_lock_pk_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(v:hash, and_v(v:older|after, pk…)) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:hash, and_v(v:older|after, pk…)) \
                     trailing CHECKSIG chain (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:hash, and_v(v:older, pk…)) (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                         and_v(v:hash, and_v(v:after, pk…)) (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <sig_last> … <sig_first> <preimage> — preimage top for v:hash;
            // reverse-key sigs for trailing CHECKSIG chain; middle lock no witness.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.extend(sig_slots);
            script_inputs.push(preimage);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- lock + middle hash + trailing pk combined hash+timeout
        // and_v(v:older|after, and_v(v:hash, pk…)) ---
        // CSV|CLTV VERIFY prefix + v:hash VERIFY + ≥1 trailing keys ending
        // CHECKSIG — single path requiring BOTH preimage and locktime.
        // Distinct from reverse multi older/after (no hash) / lock-first
        // combined (keys + bare hash EQUAL) / hash+middle-lock+trailing-pk.
        if let Some((pubkeys, kind, digest, lock)) =
            bare_tapscript_and_v_lock_hash_pk_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(v:older|after, and_v(v:hash, pk…)) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:older|after, and_v(v:hash, pk…)) \
                     trailing CHECKSIG chain (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:older, and_v(v:hash, pk…)) (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                         and_v(v:after, and_v(v:hash, pk…)) (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <sig_last> … <sig_first> <preimage> — preimage top for v:hash after
            // lock VERIFY; reverse-key sigs for trailing CHECKSIG chain.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.extend(sig_slots);
            script_inputs.push(preimage);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- dual-hash+timeout combined
        // and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after))) ---
        // ≥1 CHECKSIGVERIFY + two v:hash VERIFY + CSV|CLTV — single path
        // requiring BOTH matching 32-byte PSBT preimages AND locktime (AND,
        // not dual-hash or_i OR). Distinct from single-hash combined /
        // multi-pk hash / dual-hash or_i / HTLC.
        if let Some((pubkeys, kind1, digest1, kind2, digest2, lock)) =
            bare_tapscript_and_v_pk_dual_hash_lock_template(leaf_script)
        {
            let Some(preimage1) =
                lookup_miniscript_hash_preimage(idx, input, kind1, digest1.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H1 in \
                     and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after))) \
                     (never invents preimages)",
                );
                continue;
            };
            let Some(preimage2) =
                lookup_miniscript_hash_preimage(idx, input, kind2, digest2.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H2 in \
                     and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after))) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for \
                     and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after))) \
                     CHECKSIGVERIFY chain (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older))) \
                         (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute \
                         locktime for and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), after))) \
                         (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <preimage2> <preimage1> <sig_last> … <sig_first> — preimage2
            // deepest; H1 then H2 VERIFY after CHECKSIGVERIFY chain; CSV|CLTV
            // consumes no witness elements.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 2);
            script_inputs.push(preimage2);
            script_inputs.push(preimage1);
            script_inputs.extend(sig_slots);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- hash-first dual-hash+timeout
        // and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older|after))) ---
        // two v:hash VERIFY + ≥1 CHECKSIGVERIFY + CSV|CLTV — dual of pk-first
        // dual-hash+timeout; both matching 32-byte PSBT preimages AND locktime
        // required (AND, not dual-hash or_i OR). Distinct from hash-first
        // dual-hash AND (ends CHECKSIG, no lock) / reverse combined (one hash)
        // / sandwich dual-hash / HTLC.
        if let Some((pubkeys, kind1, digest1, kind2, digest2, lock)) =
            bare_tapscript_and_v_dual_hash_pk_lock_template(leaf_script)
        {
            let Some(preimage1) =
                lookup_miniscript_hash_preimage(idx, input, kind1, digest1.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H1 in \
                     and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older|after))) \
                     hash-first dual-hash+timeout (never invents preimages)",
                );
                continue;
            };
            let Some(preimage2) =
                lookup_miniscript_hash_preimage(idx, input, kind2, digest2.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H2 in \
                     and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older|after))) \
                     hash-first dual-hash+timeout (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for \
                     and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older|after))) \
                     hash-first dual-hash+timeout CHECKSIGVERIFY chain \
                     (all keys required)",
                );
                continue;
            }
            if !dual_timeout_lock_satisfied(lock, tx_version, sequence, lock_time) {
                match lock {
                    DualTimeoutLock::Older(_) => push_reason(
                        "nSequence does not satisfy older/CSV relative locktime for \
                         and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older))) \
                         hash-first dual-hash+timeout \
                         (present on unsigned_tx; not invented)",
                    ),
                    DualTimeoutLock::After(_) => push_reason(
                        "nLockTime/nSequence does not satisfy after/CLTV absolute \
                         locktime for \
                         and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, after))) \
                         hash-first dual-hash+timeout \
                         (present on unsigned_tx; not invented)",
                    ),
                }
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // reverse(keys)+preimage2+preimage1 — preimage1 top so H1 VERIFY
            // runs first, then H2 VERIFY, then CHECKSIGVERIFY chain; CSV|CLTV
            // consumes no witness elements.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 2);
            script_inputs.extend(sig_slots);
            script_inputs.push(preimage2);
            script_inputs.push(preimage1);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- dual-hash AND without lock
        // and_v(v:pk…, and_v(v:hash(H1), hash(H2))) ---
        // ≥1 CHECKSIGVERIFY + v:hash VERIFY + bare hash EQUAL — single path
        // requiring BOTH matching 32-byte PSBT preimages (AND, not dual-hash
        // or_i OR). Distinct from dual-hash+timeout / multi-pk single-hash /
        // single and_v(v:pk, hash) / HTLC.
        if let Some((pubkeys, kind1, digest1, kind2, digest2)) =
            bare_tapscript_and_v_pk_dual_hash_template(leaf_script)
        {
            let Some(preimage1) =
                lookup_miniscript_hash_preimage(idx, input, kind1, digest1.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H1 in \
                     and_v(v:pk…, and_v(v:hash(H1), hash(H2))) \
                     (never invents preimages)",
                );
                continue;
            };
            let Some(preimage2) =
                lookup_miniscript_hash_preimage(idx, input, kind2, digest2.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H2 in \
                     and_v(v:pk…, and_v(v:hash(H1), hash(H2))) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for \
                     and_v(v:pk…, and_v(v:hash(H1), hash(H2))) \
                     CHECKSIGVERIFY chain (all keys required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <preimage2> <preimage1> <sig_last> … <sig_first> — preimage2
            // deepest; H1 VERIFY then bare H2 EQUAL after CHECKSIGVERIFY chain.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 2);
            script_inputs.push(preimage2);
            script_inputs.push(preimage1);
            script_inputs.extend(sig_slots);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- hash-first dual-hash AND without lock
        // and_v(v:hash(H1), and_v(v:hash(H2), pk…)) ---
        // two v:hash VERIFY + ≥1 trailing keys ending CHECKSIG — single path
        // requiring BOTH matching 32-byte PSBT preimages + all key sigs
        // (AND, not dual-hash or_i OR). Dual of pk-first dual-hash AND;
        // distinct from reverse multi-hash (one hash) / dual-hash+timeout /
        // sandwich single-hash / HTLC.
        if let Some((pubkeys, kind1, digest1, kind2, digest2)) =
            bare_tapscript_and_v_dual_hash_pk_template(leaf_script)
        {
            let Some(preimage1) =
                lookup_miniscript_hash_preimage(idx, input, kind1, digest1.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H1 in \
                     and_v(v:hash(H1), and_v(v:hash(H2), pk…)) \
                     (never invents preimages)",
                );
                continue;
            };
            let Some(preimage2) =
                lookup_miniscript_hash_preimage(idx, input, kind2, digest2.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H2 in \
                     and_v(v:hash(H1), and_v(v:hash(H2), pk…)) \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for \
                     and_v(v:hash(H1), and_v(v:hash(H2), pk…)) \
                     CHECKSIG tail (all keys required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // reverse(keys)+preimage2+preimage1 — preimage1 top so H1 VERIFY
            // runs first, then H2 VERIFY, then CHECKSIG tail.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 2);
            script_inputs.extend(sig_slots);
            script_inputs.push(preimage2);
            script_inputs.push(preimage1);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- hash+pk+hash sandwich dual-hash AND without lock
        // and_v(v:hash(H1), and_v(v:pk…, hash(H2))) ---
        // leading v:hash VERIFY + ≥1 all-v:pk CHECKSIGVERIFY + bare hash EQUAL
        // — single path requiring BOTH matching 32-byte PSBT preimages + all
        // key sigs (AND, not dual-hash or_i OR). Distinct from hash-first
        // dual-hash AND (two v:hash then CHECKSIG) / pk-first dual-hash AND /
        // reverse multi-hash (one hash) / sandwich single-hash / HTLC.
        if let Some((pubkeys, kind1, digest1, kind2, digest2)) =
            bare_tapscript_and_v_hash_pk_hash_template(leaf_script)
        {
            let Some(preimage1) =
                lookup_miniscript_hash_preimage(idx, input, kind1, digest1.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H1 in \
                     and_v(v:hash(H1), and_v(v:pk…, hash(H2))) sandwich dual-hash \
                     (never invents preimages)",
                );
                continue;
            };
            let Some(preimage2) =
                lookup_miniscript_hash_preimage(idx, input, kind2, digest2.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for H2 in \
                     and_v(v:hash(H1), and_v(v:pk…, hash(H2))) sandwich dual-hash \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for \
                     and_v(v:hash(H1), and_v(v:pk…, hash(H2))) sandwich dual-hash \
                     CHECKSIGVERIFY chain (all keys required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // preimage2 + reverse(keys) + preimage1 — preimage1 top so H1
            // VERIFY runs first; after CHECKSIGVERIFY chain bare H2 EQUAL
            // consumes preimage2 deepest.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 2);
            script_inputs.push(preimage2);
            script_inputs.extend(sig_slots);
            script_inputs.push(preimage1);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-key reverse and_v(v:older(n), and_v(v:pk…)): CLEANSTACK ---
        // CSV+VERIFY prefix then CHECKSIGVERIFY…CHECKSIG (n ≥ 2). Dual of
        // pk-first multi-pk older; distinct from single and_v(v:older, pk).
        if let Some((older_n, pubkeys)) = bare_tapscript_and_v_older_multi_pk_template(leaf_script)
        {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     and_v(v:older, multi-pk) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:older, multi-pk) \
                     CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Reverse key order (CSV VERIFY consumes no stack elements).
            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- multi-key reverse and_v(v:after(n), and_v(v:pk…)): CLEANSTACK ---
        if let Some((after_n, pubkeys)) = bare_tapscript_and_v_after_multi_pk_template(leaf_script)
        {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     and_v(v:after, multi-pk) (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:after, multi-pk) \
                     CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            sig_slots.reverse();
            chosen = Some((sig_slots, leaf_script.clone(), control_block.serialize()));
            break;
        }

        // --- multi-key reverse and_v(v:hash(H), and_v(v:pk…)): CLEANSTACK ---
        // v:hash EQUALVERIFY prefix then CHECKSIGVERIFY…CHECKSIG (n ≥ 2).
        if let Some((pubkeys, kind, digest)) =
            bare_tapscript_and_v_hash_multi_pk_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(v:hash, multi-pk) leaf \
                     (never invents preimages)",
                );
                continue;
            };
            let mut sig_slots: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut missing = false;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    sig_slots.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(v:hash, multi-pk) \
                     CHECKSIGVERIFY chain (all n required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // <sig_last> … <sig_first> <preimage> — preimage top for v:hash;
            // then reverse-key sigs feed the CHECKSIGVERIFY…CHECKSIG tail.
            sig_slots.reverse();
            let mut script_inputs = Vec::with_capacity(sig_slots.len() + 1);
            script_inputs.extend(sig_slots);
            script_inputs.push(preimage);
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-key sandwich and_v(v:pk…, and_v(v:older(n), pk…)): CLEANSTACK ---
        // Left CHECKSIGVERIFY chain, middle CSV+VERIFY, right CHECKSIG tail.
        // Distinct from pk-first multi (trailing CSV no VERIFY) and reverse
        // multi (CSV VERIFY prefix, zero left keys).
        if let Some((left, older_n, right)) =
            bare_tapscript_and_v_multi_pk_older_multi_pk_template(leaf_script)
        {
            if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     and_v(pk…, older, pk…) sandwich (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let mut left_sigs: Vec<Vec<u8>> = Vec::with_capacity(left.len());
            let mut missing = false;
            for pk in &left {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    left_sigs.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            let mut right_sigs: Vec<Vec<u8>> = Vec::with_capacity(right.len());
            if !missing {
                for pk in &right {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        right_sigs.push(sig.to_vec());
                    } else {
                        missing = true;
                        break;
                    }
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(pk…, older, pk…) sandwich \
                     (all left+right required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness bottom→top: reverse(right) then reverse(left) so left[0]
            // is top (CHECKSIGVERIFY first). CSV VERIFY consumes no stack.
            let mut script_inputs = Vec::with_capacity(left_sigs.len() + right_sigs.len());
            for s in right_sigs.into_iter().rev() {
                script_inputs.push(s);
            }
            for s in left_sigs.into_iter().rev() {
                script_inputs.push(s);
            }
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-key sandwich and_v(v:pk…, and_v(v:after(n), pk…)): CLEANSTACK ---
        if let Some((left, after_n, right)) =
            bare_tapscript_and_v_multi_pk_after_multi_pk_template(leaf_script)
        {
            if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     and_v(pk…, after, pk…) sandwich (present on unsigned_tx; not invented)",
                );
                continue;
            }
            let mut left_sigs: Vec<Vec<u8>> = Vec::with_capacity(left.len());
            let mut missing = false;
            for pk in &left {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    left_sigs.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            let mut right_sigs: Vec<Vec<u8>> = Vec::with_capacity(right.len());
            if !missing {
                for pk in &right {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        right_sigs.push(sig.to_vec());
                    } else {
                        missing = true;
                        break;
                    }
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(pk…, after, pk…) sandwich \
                     (all left+right required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            let mut script_inputs = Vec::with_capacity(left_sigs.len() + right_sigs.len());
            for s in right_sigs.into_iter().rev() {
                script_inputs.push(s);
            }
            for s in left_sigs.into_iter().rev() {
                script_inputs.push(s);
            }
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- multi-key sandwich and_v(v:pk…, and_v(v:hash(H), pk…)): CLEANSTACK ---
        // Left CHECKSIGVERIFY, middle v:hash EQUALVERIFY, right CHECKSIG tail.
        if let Some((left, kind, digest, right)) =
            bare_tapscript_and_v_multi_pk_hash_multi_pk_template(leaf_script)
        {
            let Some(preimage) =
                lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?
            else {
                push_reason(
                    "missing matching PSBT preimage for and_v(pk…, hash, pk…) sandwich \
                     (never invents preimages)",
                );
                continue;
            };
            let mut left_sigs: Vec<Vec<u8>> = Vec::with_capacity(left.len());
            let mut missing = false;
            for pk in &left {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    left_sigs.push(sig.to_vec());
                } else {
                    missing = true;
                    break;
                }
            }
            let mut right_sigs: Vec<Vec<u8>> = Vec::with_capacity(right.len());
            if !missing {
                for pk in &right {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        right_sigs.push(sig.to_vec());
                    } else {
                        missing = true;
                        break;
                    }
                }
            }
            if missing {
                push_reason(
                    "insufficient tap_script_sigs for and_v(pk…, hash, pk…) sandwich \
                     (all left+right required)",
                );
                continue;
            }

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            // Witness bottom→top: reverse(right) + preimage + reverse(left)
            // so left[0] is top; after left VERIFY chain, preimage is top for
            // v:hash; then right sigs feed the CHECKSIG tail.
            let mut script_inputs = Vec::with_capacity(left_sigs.len() + right_sigs.len() + 1);
            for s in right_sigs.into_iter().rev() {
                script_inputs.push(s);
            }
            script_inputs.push(preimage);
            for s in left_sigs.into_iter().rev() {
                script_inputs.push(s);
            }
            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- HTLC dual-path or_i(and_v(pk…, hash), and_v(pk…, older(n))) ---
        // IF: ≥1 CHECKSIGVERIFY + bare hash; ELSE: ≥1 CHECKSIGVERIFY + CSV.
        // Distinct from inheritance (IF ends with CHECKSIG, no hash on IF) /
        // vault (ELSE no keys) / and_v(or_i, …) (condition outside ENDIF).
        // Prefer IF when all claim sigs + matching preimage present.
        if let Some((if_keys, else_keys, kind, digest, older_n)) =
            bare_tapscript_or_i_hash_and_v_pk_older_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_sigs_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_sigs_complete = false;
                    break;
                }
            }
            let preimage_if = lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?;
            let script_inputs = if if_sigs_complete {
                if let Some(preimage) = preimage_if {
                    // bottom→top: preimage, reverse(claim sigs), 0x01
                    let mut inputs = Vec::with_capacity(if_sigs.len() + 2);
                    inputs.push(preimage);
                    for s in if_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(vec![1u8]);
                    inputs
                } else {
                    // IF incomplete (no preimage) — try ELSE refund+CSV.
                    let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                    let mut else_complete = true;
                    for pk in &else_keys {
                        if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                            else_sigs.push(sig.to_vec());
                        } else {
                            else_complete = false;
                            break;
                        }
                    }
                    if else_complete && sequence_satisfies_csv_older(tx_version, sequence, older_n)
                    {
                        let mut inputs = Vec::with_capacity(else_sigs.len() + 1);
                        for s in else_sigs.into_iter().rev() {
                            inputs.push(s);
                        }
                        inputs.push(Vec::new());
                        inputs
                    } else {
                        // IF had all claim sigs but no preimage; ELSE incomplete.
                        push_reason(
                            "missing matching PSBT preimage for or_i(and_v(pk, hash), …) IF \
                             (never invents preimages)",
                        );
                        if !else_complete {
                            push_reason(
                                "insufficient tap_script_sigs for or_i(…, and_v(pk, older)) \
                                 ELSE arm (all refund keys required)",
                            );
                        }
                        if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                            push_reason(
                                "nSequence does not satisfy older/CSV relative locktime for \
                                 or_i(…, and_v(pk, older)) ELSE (present on unsigned_tx; not invented)",
                            );
                        }
                        continue;
                    }
                }
            } else {
                // IF incomplete (missing claim sigs) — try ELSE.
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                if else_complete && sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                    let mut inputs = Vec::with_capacity(else_sigs.len() + 1);
                    for s in else_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(Vec::new());
                    inputs
                } else {
                    push_reason(
                        "insufficient tap_script_sigs for or_i(and_v(pk, hash), \
                         and_v(pk, older)) IF arm (all claim keys required)",
                    );
                    if preimage_if.is_none() {
                        push_reason(
                            "missing matching PSBT preimage for or_i(and_v(pk, hash), …) IF \
                             (never invents preimages)",
                        );
                    }
                    if !else_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(…, and_v(pk, older)) \
                             ELSE arm (all refund keys required)",
                        );
                    }
                    if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                        push_reason(
                            "nSequence does not satisfy older/CSV relative locktime for \
                             or_i(…, and_v(pk, older)) ELSE (present on unsigned_tx; not invented)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- HTLC dual-path or_i(and_v(pk…, hash), and_v(pk…, after(n))) ---
        if let Some((if_keys, else_keys, kind, digest, after_n)) =
            bare_tapscript_or_i_hash_and_v_pk_after_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_sigs_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_sigs_complete = false;
                    break;
                }
            }
            let preimage_if = lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?;
            let script_inputs = if if_sigs_complete {
                if let Some(preimage) = preimage_if {
                    let mut inputs = Vec::with_capacity(if_sigs.len() + 2);
                    inputs.push(preimage);
                    for s in if_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(vec![1u8]);
                    inputs
                } else {
                    let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                    let mut else_complete = true;
                    for pk in &else_keys {
                        if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                            else_sigs.push(sig.to_vec());
                        } else {
                            else_complete = false;
                            break;
                        }
                    }
                    if else_complete && locktime_satisfies_cltv_after(lock_time, sequence, after_n)
                    {
                        let mut inputs = Vec::with_capacity(else_sigs.len() + 1);
                        for s in else_sigs.into_iter().rev() {
                            inputs.push(s);
                        }
                        inputs.push(Vec::new());
                        inputs
                    } else {
                        push_reason(
                            "missing matching PSBT preimage for or_i(and_v(pk, hash), …) IF \
                             (never invents preimages)",
                        );
                        if !else_complete {
                            push_reason(
                                "insufficient tap_script_sigs for or_i(…, and_v(pk, after)) \
                                 ELSE arm (all refund keys required)",
                            );
                        }
                        if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                            push_reason(
                                "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                                 or_i(…, and_v(pk, after)) ELSE (present on unsigned_tx; not invented)",
                            );
                        }
                        continue;
                    }
                }
            } else {
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                if else_complete && locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                    let mut inputs = Vec::with_capacity(else_sigs.len() + 1);
                    for s in else_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(Vec::new());
                    inputs
                } else {
                    push_reason(
                        "insufficient tap_script_sigs for or_i(and_v(pk, hash), \
                         and_v(pk, after)) IF arm (all claim keys required)",
                    );
                    if preimage_if.is_none() {
                        push_reason(
                            "missing matching PSBT preimage for or_i(and_v(pk, hash), …) IF \
                             (never invents preimages)",
                        );
                    }
                    if !else_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(…, and_v(pk, after)) \
                             ELSE arm (all refund keys required)",
                        );
                    }
                    if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                        push_reason(
                            "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                             or_i(…, and_v(pk, after)) ELSE (present on unsigned_tx; not invented)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- reverse HTLC or_i(and_v(pk…, older(n)), and_v(pk…, hash)) ---
        // IF: ≥1 CHECKSIGVERIFY + CSV; ELSE: ≥1 CHECKSIGVERIFY + bare hash.
        // Arms-swapped mirror of classic HTLC (hash on IF). Prefer IF when all
        // timeout sigs + already-present nSequence present.
        if let Some((if_keys, else_keys, kind, digest, older_n)) =
            bare_tapscript_or_i_older_and_v_pk_hash_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_sigs_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_sigs_complete = false;
                    break;
                }
            }
            let if_lock_ok = sequence_satisfies_csv_older(tx_version, sequence, older_n);
            let script_inputs = if if_sigs_complete && if_lock_ok {
                // bottom→top: reverse(timeout sigs), 0x01
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else {
                // IF incomplete — try ELSE claim+preimage.
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                let preimage_else =
                    lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?;
                if else_complete {
                    if let Some(preimage) = preimage_else {
                        // bottom→top: preimage, reverse(claim sigs), empty
                        let mut inputs = Vec::with_capacity(else_sigs.len() + 2);
                        inputs.push(preimage);
                        for s in else_sigs.into_iter().rev() {
                            inputs.push(s);
                        }
                        inputs.push(Vec::new());
                        inputs
                    } else {
                        if !if_sigs_complete {
                            push_reason(
                                "insufficient tap_script_sigs for or_i(and_v(pk, older), \
                                 and_v(pk, hash)) IF arm (all timeout keys required)",
                            );
                        }
                        if !if_lock_ok {
                            push_reason(
                                "nSequence does not satisfy older/CSV relative locktime for \
                                 or_i(and_v(pk, older), …) IF (present on unsigned_tx; not invented)",
                            );
                        }
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) ELSE \
                             (never invents preimages)",
                        );
                        continue;
                    }
                } else {
                    if !if_sigs_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(and_v(pk, older), \
                             and_v(pk, hash)) IF arm (all timeout keys required)",
                        );
                    }
                    if !if_lock_ok {
                        push_reason(
                            "nSequence does not satisfy older/CSV relative locktime for \
                             or_i(and_v(pk, older), …) IF (present on unsigned_tx; not invented)",
                        );
                    }
                    push_reason(
                        "insufficient tap_script_sigs for or_i(…, and_v(pk, hash)) \
                         ELSE arm (all claim keys required)",
                    );
                    if preimage_else.is_none() {
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) ELSE \
                             (never invents preimages)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- reverse HTLC or_i(and_v(pk…, after(n)), and_v(pk…, hash)) ---
        if let Some((if_keys, else_keys, kind, digest, after_n)) =
            bare_tapscript_or_i_after_and_v_pk_hash_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_sigs_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_sigs_complete = false;
                    break;
                }
            }
            let if_lock_ok = locktime_satisfies_cltv_after(lock_time, sequence, after_n);
            let script_inputs = if if_sigs_complete && if_lock_ok {
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else {
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                let preimage_else =
                    lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?;
                if else_complete {
                    if let Some(preimage) = preimage_else {
                        let mut inputs = Vec::with_capacity(else_sigs.len() + 2);
                        inputs.push(preimage);
                        for s in else_sigs.into_iter().rev() {
                            inputs.push(s);
                        }
                        inputs.push(Vec::new());
                        inputs
                    } else {
                        if !if_sigs_complete {
                            push_reason(
                                "insufficient tap_script_sigs for or_i(and_v(pk, after), \
                                 and_v(pk, hash)) IF arm (all timeout keys required)",
                            );
                        }
                        if !if_lock_ok {
                            push_reason(
                                "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                                 or_i(and_v(pk, after), …) IF (present on unsigned_tx; not invented)",
                            );
                        }
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) ELSE \
                             (never invents preimages)",
                        );
                        continue;
                    }
                } else {
                    if !if_sigs_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(and_v(pk, after), \
                             and_v(pk, hash)) IF arm (all timeout keys required)",
                        );
                    }
                    if !if_lock_ok {
                        push_reason(
                            "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                             or_i(and_v(pk, after), …) IF (present on unsigned_tx; not invented)",
                        );
                    }
                    push_reason(
                        "insufficient tap_script_sigs for or_i(…, and_v(pk, hash)) \
                         ELSE arm (all claim keys required)",
                    );
                    if preimage_else.is_none() {
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) ELSE \
                             (never invents preimages)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- dual-hash or_i(and_v(pk…, hash(H1)), and_v(pk…, hash(H2))) ---
        // IF: ≥1 CHECKSIGVERIFY + bare hash; ELSE: ≥1 CHECKSIGVERIFY + bare hash.
        // Distinct from classic HTLC (ELSE CSV|CLTV) / reverse HTLC (IF CSV|CLTV)
        // / inheritance (IF ends CHECKSIG) / vault (ELSE no keys). Prefer IF when
        // all IF claim sigs + matching preimage for H1 present.
        if let Some((if_keys, else_keys, if_kind, if_digest, else_kind, else_digest)) =
            bare_tapscript_or_i_hash_and_v_pk_hash_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_sigs_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_sigs_complete = false;
                    break;
                }
            }
            let preimage_if =
                lookup_miniscript_hash_preimage(idx, input, if_kind, if_digest.as_slice())?;
            let script_inputs = if if_sigs_complete {
                if let Some(preimage) = preimage_if {
                    // bottom→top: preimage1, reverse(if keys), 0x01
                    let mut inputs = Vec::with_capacity(if_sigs.len() + 2);
                    inputs.push(preimage);
                    for s in if_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(vec![1u8]);
                    inputs
                } else {
                    // IF incomplete (no H1 preimage) — try ELSE H2.
                    let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                    let mut else_complete = true;
                    for pk in &else_keys {
                        if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                            else_sigs.push(sig.to_vec());
                        } else {
                            else_complete = false;
                            break;
                        }
                    }
                    let preimage_else = lookup_miniscript_hash_preimage(
                        idx,
                        input,
                        else_kind,
                        else_digest.as_slice(),
                    )?;
                    if else_complete {
                        if let Some(preimage) = preimage_else {
                            let mut inputs = Vec::with_capacity(else_sigs.len() + 2);
                            inputs.push(preimage);
                            for s in else_sigs.into_iter().rev() {
                                inputs.push(s);
                            }
                            inputs.push(Vec::new());
                            inputs
                        } else {
                            push_reason(
                                "missing matching PSBT preimage for or_i(and_v(pk, hash), \
                                 and_v(pk, hash)) IF arm H1 (never invents preimages)",
                            );
                            push_reason(
                                "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) \
                                 ELSE arm H2 (never invents preimages)",
                            );
                            continue;
                        }
                    } else {
                        push_reason(
                            "missing matching PSBT preimage for or_i(and_v(pk, hash), \
                             and_v(pk, hash)) IF arm H1 (never invents preimages)",
                        );
                        push_reason(
                            "insufficient tap_script_sigs for or_i(…, and_v(pk, hash)) \
                             ELSE arm (all claim keys required)",
                        );
                        if preimage_else.is_none() {
                            push_reason(
                                "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) \
                                 ELSE arm H2 (never invents preimages)",
                            );
                        }
                        continue;
                    }
                }
            } else {
                // IF incomplete (missing claim sigs) — try ELSE.
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                let preimage_else =
                    lookup_miniscript_hash_preimage(idx, input, else_kind, else_digest.as_slice())?;
                if else_complete {
                    if let Some(preimage) = preimage_else {
                        let mut inputs = Vec::with_capacity(else_sigs.len() + 2);
                        inputs.push(preimage);
                        for s in else_sigs.into_iter().rev() {
                            inputs.push(s);
                        }
                        inputs.push(Vec::new());
                        inputs
                    } else {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(and_v(pk, hash), \
                             and_v(pk, hash)) IF arm (all claim keys required)",
                        );
                        if preimage_if.is_none() {
                            push_reason(
                                "missing matching PSBT preimage for or_i(and_v(pk, hash), …) \
                                 IF arm H1 (never invents preimages)",
                            );
                        }
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) \
                             ELSE arm H2 (never invents preimages)",
                        );
                        continue;
                    }
                } else {
                    push_reason(
                        "insufficient tap_script_sigs for or_i(and_v(pk, hash), \
                         and_v(pk, hash)) IF arm (all claim keys required)",
                    );
                    if preimage_if.is_none() {
                        push_reason(
                            "missing matching PSBT preimage for or_i(and_v(pk, hash), …) \
                             IF arm H1 (never invents preimages)",
                        );
                    }
                    push_reason(
                        "insufficient tap_script_sigs for or_i(…, and_v(pk, hash)) \
                         ELSE arm (all claim keys required)",
                    );
                    if preimage_else.is_none() {
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(pk, hash)) \
                             ELSE arm H2 (never invents preimages)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- dual-timeout or_i(and_v(pk…, older|after), and_v(pk…, older|after)) ---
        // IF: ≥1 CHECKSIGVERIFY + CSV|CLTV; ELSE: ≥1 CHECKSIGVERIFY + CSV|CLTV.
        // Distinct from reverse HTLC (ELSE hash) / classic HTLC (IF hash) /
        // dual-hash (both hash) / inheritance (IF CHECKSIG) / vault (ELSE no keys).
        // Prefer IF when all IF sigs + already-present locktime material.
        if let Some((if_keys, else_keys, if_lock, else_lock)) =
            bare_tapscript_or_i_lock_and_v_pk_lock_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_sigs_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_sigs_complete = false;
                    break;
                }
            }
            let if_lock_ok = dual_timeout_lock_satisfied(if_lock, tx_version, sequence, lock_time);
            let script_inputs = if if_sigs_complete && if_lock_ok {
                // bottom→top: reverse(if keys), 0x01
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else {
                // IF incomplete — try ELSE timeout.
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                let else_lock_ok =
                    dual_timeout_lock_satisfied(else_lock, tx_version, sequence, lock_time);
                if else_complete && else_lock_ok {
                    // bottom→top: reverse(else keys), empty
                    let mut inputs = Vec::with_capacity(else_sigs.len() + 1);
                    for s in else_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(Vec::new());
                    inputs
                } else {
                    if !if_sigs_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(and_v(pk, older|after), \
                             and_v(pk, older|after)) IF arm (all timeout keys required)",
                        );
                    }
                    if !if_lock_ok {
                        match if_lock {
                            DualTimeoutLock::Older(_) => push_reason(
                                "nSequence does not satisfy older/CSV relative locktime for \
                                 or_i(and_v(pk, older), …) IF (present on unsigned_tx; not invented)",
                            ),
                            DualTimeoutLock::After(_) => push_reason(
                                "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                                 or_i(and_v(pk, after), …) IF (present on unsigned_tx; not invented)",
                            ),
                        }
                    }
                    if !else_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(…, and_v(pk, older|after)) \
                             ELSE arm (all timeout keys required)",
                        );
                    }
                    if !else_lock_ok {
                        match else_lock {
                            DualTimeoutLock::Older(_) => push_reason(
                                "nSequence does not satisfy older/CSV relative locktime for \
                                 or_i(…, and_v(pk, older)) ELSE (present on unsigned_tx; not invented)",
                            ),
                            DualTimeoutLock::After(_) => push_reason(
                                "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                                 or_i(…, and_v(pk, after)) ELSE (present on unsigned_tx; not invented)",
                            ),
                        }
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- inheritance or_i(hot, and_v(cold, older(n))): hot OR cold+CSV ---
        // IF: CHECKSIGVERIFY…CHECKSIG (≥1); ELSE: ≥1 CHECKSIGVERIFY + CSV.
        // Distinct from bare vault (ELSE no keys) and and_v(or_i, older)
        // (CSV outside ENDIF). Prefer IF when all hot sigs present.
        if let Some((if_keys, else_keys, older_n)) =
            bare_tapscript_or_i_pk_and_v_pk_older_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_complete = false;
                    break;
                }
            }
            let script_inputs = if if_complete {
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else {
                // ELSE: all cold sigs + already-present nSequence.
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                if else_complete && sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                    let mut inputs = Vec::with_capacity(else_sigs.len() + 1);
                    for s in else_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(Vec::new()); // false IF selector
                    inputs
                } else {
                    if !if_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(hot, and_v(cold, older)) IF arm \
                             (all hot keys required)",
                        );
                    }
                    if !else_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(hot, and_v(cold, older)) ELSE arm \
                             (all cold keys required)",
                        );
                    }
                    if !sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                        push_reason(
                            "nSequence does not satisfy older/CSV relative locktime for \
                             or_i(…, and_v(cold, older)) ELSE (present on unsigned_tx; not invented)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- inheritance or_i(hot, and_v(cold, after(n))): hot OR cold+CLTV ---
        if let Some((if_keys, else_keys, after_n)) =
            bare_tapscript_or_i_pk_and_v_pk_after_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_complete = false;
                    break;
                }
            }
            let script_inputs = if if_complete {
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else {
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                if else_complete && locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                    let mut inputs = Vec::with_capacity(else_sigs.len() + 1);
                    for s in else_sigs.into_iter().rev() {
                        inputs.push(s);
                    }
                    inputs.push(Vec::new());
                    inputs
                } else {
                    if !if_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(hot, and_v(cold, after)) IF arm \
                             (all hot keys required)",
                        );
                    }
                    if !else_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(hot, and_v(cold, after)) ELSE arm \
                             (all cold keys required)",
                        );
                    }
                    if !locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                        push_reason(
                            "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                             or_i(…, and_v(cold, after)) ELSE (present on unsigned_tx; not invented)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- inheritance or_i(hot, and_v(cold, hash(H))): hot OR cold+hashlock ---
        if let Some((if_keys, else_keys, kind, digest)) =
            bare_tapscript_or_i_pk_and_v_pk_hash_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(if_keys.len());
            let mut if_complete = true;
            for pk in &if_keys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_complete = false;
                    break;
                }
            }
            let script_inputs = if if_complete {
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else {
                let mut else_sigs: Vec<Vec<u8>> = Vec::with_capacity(else_keys.len());
                let mut else_complete = true;
                for pk in &else_keys {
                    if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                        else_sigs.push(sig.to_vec());
                    } else {
                        else_complete = false;
                        break;
                    }
                }
                let preimage =
                    lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())?;
                if else_complete {
                    if let Some(preimage) = preimage {
                        // bottom→top: preimage, reverse(cold sigs), empty selector
                        let mut inputs = Vec::with_capacity(else_sigs.len() + 2);
                        inputs.push(preimage);
                        for s in else_sigs.into_iter().rev() {
                            inputs.push(s);
                        }
                        inputs.push(Vec::new());
                        inputs
                    } else {
                        if !if_complete {
                            push_reason(
                                "insufficient tap_script_sigs for or_i(hot, and_v(cold, hash)) IF arm \
                                 (all hot keys required)",
                            );
                        }
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(cold, hash)) ELSE \
                             (never invents preimages)",
                        );
                        continue;
                    }
                } else {
                    if !if_complete {
                        push_reason(
                            "insufficient tap_script_sigs for or_i(hot, and_v(cold, hash)) IF arm \
                             (all hot keys required)",
                        );
                    }
                    push_reason(
                        "insufficient tap_script_sigs for or_i(hot, and_v(cold, hash)) ELSE arm \
                         (all cold keys required)",
                    );
                    if preimage.is_none() {
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, and_v(cold, hash)) ELSE \
                             (never invents preimages)",
                        );
                    }
                    continue;
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- vault or_i(and_v(v:pk…)|pk, older(n)): multi-sig OR timeout ---
        // IF arm: CHECKSIGVERIFY…CHECKSIG (≥1); ELSE: bare CSV inside ENDIF.
        // Distinct from and_v(or_i, older) (CSV outside ENDIF; both arms keys).
        if let Some((pubkeys, older_n)) = bare_tapscript_or_i_and_v_pk_older_template(leaf_script) {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut if_complete = true;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_complete = false;
                    break;
                }
            }
            let script_inputs = if if_complete {
                // IF preferred when all keys present — no invented branch.
                // reverse-key sigs + <0x01> selector top.
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else if sequence_satisfies_csv_older(tx_version, sequence, older_n) {
                // ELSE timeout: empty false IF selector only (CSV from script).
                vec![Vec::new()]
            } else {
                if !if_complete {
                    push_reason(
                        "insufficient tap_script_sigs for or_i(and_v|pk, older) IF arm \
                         (all keys required)",
                    );
                }
                push_reason(
                    "nSequence does not satisfy older/CSV relative locktime for \
                     or_i(…, older) ELSE timeout (present on unsigned_tx; not invented)",
                );
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- vault or_i(and_v(v:pk…)|pk, after(n)): multi-sig OR absolute lock ---
        if let Some((pubkeys, after_n)) = bare_tapscript_or_i_and_v_pk_after_template(leaf_script) {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut if_complete = true;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_complete = false;
                    break;
                }
            }
            let script_inputs = if if_complete {
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else if locktime_satisfies_cltv_after(lock_time, sequence, after_n) {
                vec![Vec::new()]
            } else {
                if !if_complete {
                    push_reason(
                        "insufficient tap_script_sigs for or_i(and_v|pk, after) IF arm \
                         (all keys required)",
                    );
                }
                push_reason(
                    "nLockTime/nSequence does not satisfy after/CLTV absolute locktime for \
                     or_i(…, after) ELSE timeout (present on unsigned_tx; not invented)",
                );
                continue;
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // --- vault or_i(and_v(v:pk…)|pk, hash(H)): multi-sig OR hashlock ---
        if let Some((pubkeys, kind, digest)) =
            bare_tapscript_or_i_and_v_pk_hash_template(leaf_script)
        {
            let mut if_sigs: Vec<Vec<u8>> = Vec::with_capacity(pubkeys.len());
            let mut if_complete = true;
            for pk in &pubkeys {
                if let Some(sig) = input.tap_script_sigs.get(&(*pk, leaf_hash)).copied() {
                    if_sigs.push(sig.to_vec());
                } else {
                    if_complete = false;
                    break;
                }
            }
            let script_inputs = if if_complete {
                let mut inputs = Vec::with_capacity(if_sigs.len() + 1);
                for s in if_sigs.into_iter().rev() {
                    inputs.push(s);
                }
                inputs.push(vec![1u8]);
                inputs
            } else {
                match lookup_miniscript_hash_preimage(idx, input, kind, digest.as_slice())? {
                    Some(preimage) => {
                        // ELSE hashlock: <preimage> <empty> — empty = false IF
                        // selector top; preimage deeper for SIZE.
                        vec![preimage, Vec::new()]
                    }
                    None => {
                        if !if_complete {
                            push_reason(
                                "insufficient tap_script_sigs for or_i(and_v|pk, hash) IF arm \
                                 (all keys required)",
                            );
                        }
                        push_reason(
                            "missing matching PSBT preimage for or_i(…, hash) ELSE hashlock \
                             (never invents preimages)",
                        );
                        continue;
                    }
                }
            };

            if !control_block.verify_taproot_commitment(&secp, output_key, leaf_script) {
                return Err(WalletError::Onchain(format!(
                    "input {idx}: Taproot control block does not verify against P2TR \
                     output key / leaf (tamper/corrupt; not broadcast-ready)"
                )));
            }

            chosen = Some((
                script_inputs,
                leaf_script.clone(),
                control_block.serialize(),
            ));
            break;
        }

        // Bare or_c (no IFDUP / no ELSE): detect for a distinct residual reason.
        // Never assemble — CLEANSTACK-invalid as a top-level leaf.
        if bare_tapscript_or_c_checksig_template(leaf_script).is_some() {
            push_reason(
                "bare or_c leaf (CHECKSIG NOTIF … CHECKSIG ENDIF without IFDUP) \
                 is CLEANSTACK-invalid as top-level spend; not assembled offline",
            );
            continue;
        }

        push_reason(
            "leaf is not bare x-only CHECKSIG / multi_a CHECKSIGADD / thresh \
             SWAP-CHECKSIG-ADD / thresh a:pk TOALTSTACK-CHECKSIG-FROMALTSTACK-ADD / \
             thresh mixed s:/a: / thresh s:hash / thresh a:hash / \
             thresh mixed s:/a:+hash / \
             and_v CHECKSIGVERIFY / or_i IF-ELSE / or_d \
             IFDUP-NOTIF / and_n NOTIF-0 / andor NOTIF-ELSE / bare hash / \
             and_v(v:pk, hash) / and_v(v:hash, pk) / and_v(v:pk, older) / \
             and_v(v:older, pk) / bare older / and_v(or_c, older) / \
             and_v(or_c, after) / and_v(or_c, hash) / and_v(or_i, hash) / \
             and_v(or_i, older) / and_v(or_i, after) / \
             and_v(or_c multi-arm, older) / and_v(or_c multi-arm, after) / \
             and_v(or_c multi-arm, hash) / \
             and_v(or_i multi-arm, older) / and_v(or_i multi-arm, after) / \
             and_v(or_i multi-arm, hash) / \
             and_v(multi-pk, older) / and_v(multi-pk, after) / \
             and_v(multi-pk, hash) / \
             and_v(v:older, multi-pk) / and_v(v:after, multi-pk) / \
             and_v(v:hash, multi-pk) / \
             and_v(pk…, older, pk…) / and_v(pk…, after, pk…) / \
             and_v(pk…, hash, pk…) sandwich / \
             or_i(and_v(pk, hash), and_v(pk, older|after)) HTLC dual-path / \
             or_i(and_v(pk, older|after), and_v(pk, hash)) reverse HTLC / \
             or_i(and_v(pk, hash(H1)), and_v(pk, hash(H2))) dual-hash / \
             or_i(and_v(pk, older|after), and_v(pk, older|after)) dual-timeout / \
             and_v(v:pk…, and_v(v:hash, older|after)) hash+timeout / \
             and_v(v:hash, and_v(v:pk…, older|after)) reverse hash+timeout / \
             and_v(v:older|after, and_v(v:pk…, hash)) lock-first hash+timeout / \
             and_v(v:pk…, and_v(v:older|after, hash)) pk+lock+hash / \
             and_v(v:hash, and_v(v:older|after, pk…)) hash+lock+pk / \
             and_v(v:older|after, and_v(v:hash, pk…)) lock+hash+pk / \
             and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after))) dual-hash+timeout / \
             and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older|after))) hash-first dual-hash+timeout / \
             and_v(v:pk…, and_v(v:hash(H1), hash(H2))) dual-hash AND / \
             and_v(v:hash(H1), and_v(v:hash(H2), pk…)) hash-first dual-hash AND / \
             and_v(v:hash(H1), and_v(v:pk…, hash(H2))) sandwich dual-hash \
             (PR5 keep set only; other dual-hash and_v orderings pruned/unsupported offline) / \
             or_i(hot, and_v(cold, older|after|hash)) inheritance / \
             or_i(and_v|pk, older) / or_i(and_v|pk, after) / \
             or_i(and_v|pk, hash) vault / \
             and_v(v:pk, after) / \
             and_v(v:after, pk) / bare after (complex/miniscript not assembled offline)",
        );
    }

    if let Some((script_inputs, leaf_script, cb_bytes)) = chosen {
        // BIP-341 script-path witness: <script inputs...> <script> <control block>
        let mut witness_parts: Vec<&[u8]> = script_inputs.iter().map(|s| s.as_slice()).collect();
        witness_parts.push(leaf_script.as_bytes());
        witness_parts.push(cb_bytes.as_slice());
        input.final_script_witness = Some(Witness::from_slice(&witness_parts));
        return Ok(FinalizeInputStep::Finalized);
    }

    let detail = if residual_reasons.is_empty() {
        format!(
            "input {idx}: Taproot script-path residual (no completeable bare \
             CHECKSIG / multi_a / thresh (s:pk|a:pk|mixed|s:hash|a:hash|\
             mixed s:/a:+hash) / and_v / \
             or_i / or_d / and_n / andor / hash / and_v(v:pk, hash) / \
             and_v(v:hash, pk) / older/CSV / and_v(or_c, older) / \
             and_v(or_c, after) / and_v(or_c, hash) / and_v(or_i, hash) / \
             and_v(or_i, older) / and_v(or_i, after) / \
             and_v(or_c multi-arm, older) / and_v(or_c multi-arm, after) / \
             and_v(or_c multi-arm, hash) / \
             and_v(or_i multi-arm, older) / and_v(or_i multi-arm, after) / \
             and_v(or_i multi-arm, hash) / \
             and_v(multi-pk, older) / and_v(multi-pk, after) / \
             and_v(multi-pk, hash) / \
             and_v(v:older, multi-pk) / and_v(v:after, multi-pk) / \
             and_v(v:hash, multi-pk) / \
             and_v(pk…, older, pk…) / and_v(pk…, after, pk…) / \
             and_v(pk…, hash, pk…) sandwich / \
             or_i(and_v(pk, hash), and_v(pk, older|after)) HTLC dual-path / \
             or_i(and_v(pk, older|after), and_v(pk, hash)) reverse HTLC / \
             or_i(and_v(pk, hash(H1)), and_v(pk, hash(H2))) dual-hash / \
             or_i(and_v(pk, older|after), and_v(pk, older|after)) dual-timeout / \
             and_v(v:pk…, and_v(v:hash, older|after)) hash+timeout / \
             and_v(v:hash, and_v(v:pk…, older|after)) reverse hash+timeout / \
             and_v(v:older|after, and_v(v:pk…, hash)) lock-first hash+timeout / \
             and_v(v:pk…, and_v(v:older|after, hash)) pk+lock+hash / \
             and_v(v:hash, and_v(v:older|after, pk…)) hash+lock+pk / \
             and_v(v:older|after, and_v(v:hash, pk…)) lock+hash+pk / \
             and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after))) dual-hash+timeout / \
             and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older|after))) hash-first dual-hash+timeout / \
             and_v(v:pk…, and_v(v:hash(H1), hash(H2))) dual-hash AND / \
             and_v(v:hash(H1), and_v(v:hash(H2), pk…)) hash-first dual-hash AND / \
             and_v(v:hash(H1), and_v(v:pk…, hash(H2))) sandwich dual-hash \
             (PR5 keep set only; other dual-hash and_v orderings pruned/unsupported offline) / \
             or_i(hot, and_v(cold, older|after|hash)) inheritance / \
             or_i(and_v|pk, older) / or_i(and_v|pk, after) / \
             or_i(and_v|pk, hash) vault / \
             after/CLTV leaf with \
             present control block + material; not broadcast-ready)"
        )
    } else {
        format!(
            "input {idx}: Taproot script-path residual: {}; not broadcast-ready",
            residual_reasons.join("; ")
        )
    };
    Ok(FinalizeInputStep::Residual(detail))
}

/// Finalize P2WSH when `witness_script` is bare CHECKSIG or bare CHECKMULTISIG.
///
/// Optional nested P2SH redeem push sets `final_script_sig`. Never invents
/// signatures that are not already present in `partial_sigs`.
fn finalize_p2wsh_witness_script(
    idx: usize,
    input: &mut PsbtInput,
    wscript: &ScriptBuf,
    nested_redeem: Option<ScriptBuf>,
) -> Result<FinalizeInputStep> {
    if let Some(expected_pk) = single_checksig_pubkey(wscript) {
        return finalize_single_checksig_p2wsh(idx, input, wscript, nested_redeem, expected_pk);
    }
    if let Some((threshold, pubkeys)) = bare_checkmultisig_template(wscript) {
        return finalize_checkmultisig_p2wsh(
            idx,
            input,
            wscript,
            nested_redeem,
            threshold,
            &pubkeys,
        );
    }
    // Complex miniscript / Taproot leaves / non-standard templates.
    Ok(FinalizeInputStep::Residual(format!(
        "input {idx}: script-path P2WSH residual (witness_script is not bare single-key \
         CHECKSIG or standard bare CHECKMULTISIG; not broadcast-ready)"
    )))
}

/// Finalize bare single-key CHECKSIG P2WSH (optional nested P2SH redeem push).
fn finalize_single_checksig_p2wsh(
    idx: usize,
    input: &mut PsbtInput,
    wscript: &ScriptBuf,
    nested_redeem: Option<ScriptBuf>,
    expected_pk: bitcoin::PublicKey,
) -> Result<FinalizeInputStep> {
    if input.partial_sigs.len() != 1 {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: multi-sig / multi-key residual ({} partial_sigs; single-key \
             CHECKSIG P2WSH needs exactly one; not broadcast-ready)",
            input.partial_sigs.len()
        )));
    }
    let (pk, sig) = input.partial_sigs.iter().next().expect("len checked == 1");
    if *pk != expected_pk {
        return Err(WalletError::Onchain(format!(
            "input {idx}: partial_sig pubkey does not match single-CHECKSIG witness_script"
        )));
    }
    // Clone before mutating input (partial_sigs borrow).
    let sig_bytes = sig.to_vec();
    apply_nested_redeem_script_sig(input, nested_redeem)?;
    // Witness: <sig> <witnessScript> (pubkey lives in the script).
    input.final_script_witness = Some(Witness::from_slice(&[sig_bytes, wscript.to_bytes()]));
    Ok(FinalizeInputStep::Finalized)
}

/// Finalize bare m-of-n CHECKMULTISIG P2WSH when enough matching `partial_sigs`
/// exist.
///
/// Builds witness stack as BIP147 **NULLDUMMY** (empty element) + up to
/// `threshold` sigs selected in **witness_script pubkey order** + witnessScript.
/// Callers need not pre-order `partial_sigs`. Never invents missing signatures:
/// fewer than `threshold` matching keys → [`FinalizeInputStep::Residual`].
/// Extra unrelated `partial_sigs` are ignored.
fn finalize_checkmultisig_p2wsh(
    idx: usize,
    input: &mut PsbtInput,
    wscript: &ScriptBuf,
    nested_redeem: Option<ScriptBuf>,
    threshold: usize,
    pubkeys: &[bitcoin::PublicKey],
) -> Result<FinalizeInputStep> {
    // Collect up to `threshold` signatures in witness_script pubkey order.
    // CHECKMULTISIG requires sigs ordered relative to the key list; we never
    // reorder or invent.
    let mut ordered_sig_bytes: Vec<Vec<u8>> = Vec::with_capacity(threshold);
    for pk in pubkeys {
        if let Some(sig) = input.partial_sigs.get(pk) {
            ordered_sig_bytes.push(sig.to_vec());
            if ordered_sig_bytes.len() == threshold {
                break;
            }
        }
    }
    if ordered_sig_bytes.len() < threshold {
        return Ok(FinalizeInputStep::Residual(format!(
            "input {idx}: CHECKMULTISIG threshold residual \
             ({}/{} matching partial_sigs for {}-of-{}; not broadcast-ready)",
            ordered_sig_bytes.len(),
            threshold,
            threshold,
            pubkeys.len()
        )));
    }

    apply_nested_redeem_script_sig(input, nested_redeem)?;

    // BIP147 witness stack: OP_0 dummy, then m sigs (script order), then script.
    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(threshold + 2);
    stack.push(Vec::new());
    stack.append(&mut ordered_sig_bytes);
    stack.push(wscript.to_bytes());
    input.final_script_witness = Some(Witness::from_slice(&stack));
    Ok(FinalizeInputStep::Finalized)
}

/// Optional nested P2SH-P2WSH: push redeem_script as final_script_sig.
fn apply_nested_redeem_script_sig(
    input: &mut PsbtInput,
    nested_redeem: Option<ScriptBuf>,
) -> Result<()> {
    if let Some(redeem) = nested_redeem {
        let redeem_pb = script_push_bytes(redeem.as_bytes())?;
        input.final_script_sig = Some(
            bitcoin::script::Builder::new()
                .push_slice(redeem_pb)
                .into_script(),
        );
    }
    Ok(())
}

/// Offline PSBT finalize with shared Complete vs Partial gates.
///
/// Expands beyond bare P2WPKH where material already present on the PSBT is
/// enough — never invents multi-sig witnesses. See [`FinalizeOutcome`].
///
/// Product paths must require [`FinalizeOutcome::is_complete`] before extract
/// or broadcast.
pub fn finalize_psbt(psbt: &mut Psbt) -> Result<FinalizeOutcome> {
    let total = psbt.inputs.len();
    if total == 0 {
        return Err(WalletError::Onchain(
            "PSBT has no inputs to finalize".into(),
        ));
    }
    if total != psbt.unsigned_tx.input.len() {
        return Err(WalletError::Onchain(format!(
            "PSBT input map length ({total}) does not match unsigned_tx.input length ({}); \
             corrupt or malformed PSBT",
            psbt.unsigned_tx.input.len()
        )));
    }
    let mut finalized = 0usize;
    let mut residual_reasons: Vec<String> = Vec::new();

    let tx_version = psbt.unsigned_tx.version;
    let lock_time = psbt.unsigned_tx.lock_time;
    for idx in 0..total {
        let prevout = psbt.unsigned_tx.input[idx].previous_output;
        let sequence = psbt.unsigned_tx.input[idx].sequence;
        match try_finalize_input(
            idx,
            &mut psbt.inputs[idx],
            prevout,
            sequence,
            tx_version,
            lock_time,
        )? {
            FinalizeInputStep::Finalized => {
                debug_assert!(input_is_finalized(&psbt.inputs[idx]));
                finalized += 1;
            }
            FinalizeInputStep::Residual(reason) => residual_reasons.push(reason),
        }
    }

    let residual = total.saturating_sub(finalized);
    if residual == 0 {
        debug_assert!(psbt_is_broadcast_ready(psbt));
        Ok(FinalizeOutcome::Complete {
            finalized_inputs: finalized,
        })
    } else {
        let detail = if residual_reasons.is_empty() {
            format!("finalized {finalized}/{total} inputs; residual not broadcast-ready")
        } else {
            format!(
                "finalized {finalized}/{total} inputs (not broadcast-ready): {}",
                residual_reasons.join("; ")
            )
        };
        Ok(FinalizeOutcome::Partial {
            finalized_inputs: finalized,
            residual_inputs: residual,
            detail,
        })
    }
}

/// Convert ECDSA `partial_sigs` into final spend material where offline-safe.
///
/// Alias of [`finalize_psbt`] (historical name; still used by product BIP84
/// prepare). Supports single-key P2WPKH plus additional completeable cases
/// documented on [`FinalizeOutcome`] — incomplete CHECKMULTISIG / multi_a
/// thresholds, complex Taproot script-path, and other unsupported scripts
/// stay [`FinalizeOutcome::Partial`].
pub fn finalize_p2wpkh_psbt(psbt: &mut Psbt) -> Result<FinalizeOutcome> {
    finalize_psbt(psbt)
}
