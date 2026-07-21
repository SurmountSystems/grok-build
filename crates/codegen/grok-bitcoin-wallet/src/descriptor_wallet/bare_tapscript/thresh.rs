//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

use super::{TapscriptHashKind, small_pushnum};

/// Parse bare Taproot thresh-of-pks leaf (miniscript
/// `thresh(k, pk(A), s:pk(B), …, s:pk(N))`):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// OP_SWAP <xonly2> OP_CHECKSIG OP_ADD
/// …
/// OP_SWAP <xonlyn> OP_CHECKSIG OP_ADD
/// <k> OP_EQUAL
/// ```
///
/// Returns `(threshold k, pubkeys in script order)` when the script is exactly
/// that template with `n ≥ 2` and `k ∈ 1..=n` via `OP_1..=OP_16`. Otherwise
/// `None`.
///
/// Distinct from [`bare_tapscript_checksigadd_multi_template`] (`multi_a`
/// uses `CHECKSIGADD` + `NUMEQUAL`, no `SWAP`/`ADD`), pure a:pk
/// [`bare_tapscript_thresh_a_pk_checksig_template`], and mixed s:/a:
/// [`bare_tapscript_thresh_mixed_sa_checksig_template`]. Policy compilers often
/// emit multi_a for all-key thresholds on Taproot; this form is the explicit
/// miniscript `thresh` encoding with **only** `s:` (SWAP) wrappers on
/// subsequent keys.
///
/// Witness stack is n elements in **reverse key order** (sig for last key
/// first), with empty BIP-342 vectors for unused keys when `k < n` — same
/// policy as multi_a (first k keys **that already have** `tap_script_sigs`
/// in script order; never invents signatures).
pub(crate) fn bare_tapscript_thresh_checksig_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_EQUAL, OP_SWAP};

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG (type B; no SWAP).
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];

    // Remaining: (OP_SWAP <xonly> OP_CHECKSIG OP_ADD)+ then <k> OP_EQUAL.
    // After the first CHECKSIG the next opcode is either SWAP (another key)
    // or a small pushnum k followed by EQUAL (end). multi_a would push a key
    // next (no SWAP) — rejected here.
    loop {
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_SWAP => {
                let push_i = match iter.next()? {
                    Ok(Instruction::PushBytes(b)) => b,
                    _ => return None,
                };
                let kb = push_i.as_bytes();
                if kb.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                    _ => return None,
                }
                match iter.next()? {
                    Ok(Instruction::Op(op3)) if op3 == OP_ADD => {
                        pubkeys.push(pk);
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_EQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                // thresh-of-pks requires at least one SWAP arm (n ≥ 2).
                if pubkeys.len() < 2 {
                    return None;
                }
                if (k as usize) > pubkeys.len() {
                    return None;
                }
                return Some((k as usize, pubkeys));
            }
            Ok(Instruction::PushBytes(_)) | Err(_) => return None,
        }
    }
}

/// Parse bare Taproot thresh-of-pks leaf with **a:** (altstack) wrappers
/// (miniscript `thresh(k, pk(A), a:pk(B), …, a:pk(N))` — the non-s:pk dual
/// of [`bare_tapscript_thresh_checksig_template`]):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// OP_TOALTSTACK <xonly2> OP_CHECKSIG OP_FROMALTSTACK OP_ADD
/// …
/// OP_TOALTSTACK <xonlyn> OP_CHECKSIG OP_FROMALTSTACK OP_ADD
/// <k> OP_EQUAL
/// ```
///
/// Returns `(threshold k, pubkeys in script order)` when the script is exactly
/// that template with `n ≥ 2` and `k ∈ 1..=n` via `OP_1..=OP_16`. Otherwise
/// `None`.
///
/// # Why this is completeable (vs non-pk thresh residual)
///
/// Pure a:pk thresh (all type-W arms use TOALTSTACK/FROMALTSTACK) leaves a
/// running sum of CHECKSIG bools; ADD is commutative so the witness policy
/// matches s:pk and mixed s:/a: thresh: n reverse-order slots, empty BIP-342
/// placeholders for unused keys, first `k` present `tap_script_sigs` in
/// script order — never invents signatures. Mixed s:/a: arms are a sibling
/// completeable template ([`bare_tapscript_thresh_mixed_sa_checksig_template`]),
/// not residual.
///
/// Distinct from:
/// - [`bare_tapscript_thresh_checksig_template`] (SWAP form; no altstack)
/// - [`bare_tapscript_thresh_mixed_sa_checksig_template`] (both s: and a: arms)
/// - [`bare_tapscript_checksigadd_multi_template`] (CHECKSIGADD + NUMEQUAL)
/// - [`bare_tapscript_thresh_s_hash_template`] (pure s:hash arm(s))
/// - [`bare_tapscript_thresh_a_hash_template`] (pure a:hash arm(s))
/// - [`bare_tapscript_thresh_mixed_sa_hash_template`] (mixed s:/a: + hash)
pub(crate) fn bare_tapscript_thresh_a_pk_checksig_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_EQUAL, OP_FROMALTSTACK, OP_TOALTSTACK};

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG (type B; no a: wrapper).
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];

    // Remaining: (OP_TOALTSTACK <xonly> OP_CHECKSIG OP_FROMALTSTACK OP_ADD)+
    // then <k> OP_EQUAL. After the first CHECKSIG the next opcode is either
    // TOALTSTACK (another a:pk arm) or a small pushnum k + EQUAL (end).
    // s:pk / mixed would use SWAP next — rejected here (sibling parsers).
    loop {
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_TOALTSTACK => {
                let push_i = match iter.next()? {
                    Ok(Instruction::PushBytes(b)) => b,
                    _ => return None,
                };
                let kb = push_i.as_bytes();
                if kb.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                    _ => return None,
                }
                match iter.next()? {
                    Ok(Instruction::Op(op3)) if op3 == OP_FROMALTSTACK => {}
                    _ => return None,
                }
                match iter.next()? {
                    Ok(Instruction::Op(op4)) if op4 == OP_ADD => {
                        pubkeys.push(pk);
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_EQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                // a:pk thresh requires at least one altstack arm (n ≥ 2).
                if pubkeys.len() < 2 {
                    return None;
                }
                if (k as usize) > pubkeys.len() {
                    return None;
                }
                return Some((k as usize, pubkeys));
            }
            Ok(Instruction::PushBytes(_)) | Err(_) => return None,
        }
    }
}

/// Parse bare Taproot thresh-of-pks leaf with **mixed** s: (SWAP) and a:
/// (altstack) type-W arms (miniscript `thresh(k, pk(A), s:pk(B), a:pk(C), …)`
/// or any interleaving of s:/a: after the type-B first key):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// ( OP_SWAP <xonlyi> OP_CHECKSIG OP_ADD
/// | OP_TOALTSTACK <xonlyi> OP_CHECKSIG OP_FROMALTSTACK OP_ADD )+
/// <k> OP_EQUAL
/// ```
///
/// Returns `(threshold k, pubkeys in script order)` only when **both** arm
/// kinds appear at least once (`n ≥ 3`, `k ∈ 1..=n`). Pure-s: and pure-a:
/// scripts stay with their sibling parsers; this never cross-matches them.
///
/// # Why this is completeable offline
///
/// Type-W thresh arms leave a running sum of CHECKSIG bools; ADD is
/// commutative, so witness policy matches pure s:pk / a:pk thresh: n reverse-
/// order slots, empty BIP-342 placeholders for unused keys, first `k` present
/// `tap_script_sigs` in script order — never invents signatures.
///
/// Distinct from:
/// - [`bare_tapscript_thresh_checksig_template`] (all SWAP; no altstack)
/// - [`bare_tapscript_thresh_a_pk_checksig_template`] (all altstack; no SWAP)
/// - [`bare_tapscript_checksigadd_multi_template`] (CHECKSIGADD + NUMEQUAL)
/// - [`bare_tapscript_thresh_s_hash_template`] (pure s:hash arm(s))
/// - [`bare_tapscript_thresh_a_hash_template`] (pure a:hash arm(s))
/// - [`bare_tapscript_thresh_mixed_sa_hash_template`] (mixed s:/a: + hash)
pub(crate) fn bare_tapscript_thresh_mixed_sa_checksig_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_ADD, OP_CHECKSIG, OP_EQUAL, OP_FROMALTSTACK, OP_SWAP, OP_TOALTSTACK,
    };

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG (type B; no wrapper).
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];
    let mut saw_swap = false;
    let mut saw_alt = false;

    // Remaining: any non-empty mix of s: (SWAP) and a: (TOALTSTACK…) arms,
    // then <k> OP_EQUAL. Pure forms (only SWAP or only alt) reject at end.
    loop {
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_SWAP => {
                let push_i = match iter.next()? {
                    Ok(Instruction::PushBytes(b)) => b,
                    _ => return None,
                };
                let kb = push_i.as_bytes();
                if kb.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                    _ => return None,
                }
                match iter.next()? {
                    Ok(Instruction::Op(op3)) if op3 == OP_ADD => {
                        pubkeys.push(pk);
                        saw_swap = true;
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_TOALTSTACK => {
                let push_i = match iter.next()? {
                    Ok(Instruction::PushBytes(b)) => b,
                    _ => return None,
                };
                let kb = push_i.as_bytes();
                if kb.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                    _ => return None,
                }
                match iter.next()? {
                    Ok(Instruction::Op(op3)) if op3 == OP_FROMALTSTACK => {}
                    _ => return None,
                }
                match iter.next()? {
                    Ok(Instruction::Op(op4)) if op4 == OP_ADD => {
                        pubkeys.push(pk);
                        saw_alt = true;
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_EQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                // Mixed requires both arm kinds → at least two W arms (n ≥ 3).
                if !(saw_swap && saw_alt) {
                    return None;
                }
                if pubkeys.len() < 3 {
                    return None;
                }
                if (k as usize) > pubkeys.len() {
                    return None;
                }
                return Some((k as usize, pubkeys));
            }
            Ok(Instruction::PushBytes(_)) | Err(_) => return None,
        }
    }
}

/// One s:hash / a:hash type-W arm inside a bare thresh leaf.
pub(crate) struct ThreshHashArm {
    /// Arm index among all `n = n_pk + n_hash` arms (`1..n`; 0 is type-B first pk).
    pub(crate) arm_idx: usize,
    pub(crate) kind: TapscriptHashKind,
    pub(crate) digest: Vec<u8>,
}

/// Parsed bare thresh with one **or more** pure s:hash or pure a:hash type-W arms.
///
/// `hash_arms` is non-empty and ordered by ascending `arm_idx`. Single-hash is
/// `hash_arms.len() == 1`; multi-hash is `len ≥ 2`. Pure s: / pure a: parsers
/// never produce mixed s:/a: with hash (that is
/// [`bare_tapscript_thresh_mixed_sa_hash_template`]).
pub(crate) struct ThreshHashArmTemplate {
    pub(crate) threshold: usize,
    pub(crate) pubkeys: Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    pub(crate) hash_arms: Vec<ThreshHashArm>,
}

impl ThreshHashArmTemplate {
    /// Number of hash arms (`≥ 1`).
    pub(crate) fn n_hash(&self) -> usize {
        self.hash_arms.len()
    }

    /// Single-hash convenience for unit tests when `n_hash == 1`.
    #[cfg(test)]
    pub(crate) fn single_hash(&self) -> Option<&ThreshHashArm> {
        if self.hash_arms.len() == 1 {
            Some(&self.hash_arms[0])
        } else {
            None
        }
    }
}

/// Parse bare Taproot thresh leaf with **one or more pure s:hash** arms at any
/// type-W position (trailing, middle, or multi-hash — miniscript shape
/// `thresh(k, pk…, s:hash(H), s:pk…, s:hash(H2), …)`):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// ( OP_SWAP <xonlyi> OP_CHECKSIG OP_ADD
/// | OP_SWAP OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL OP_ADD )+
/// <k> OP_EQUAL
/// ```
///
/// Returns [`ThreshHashArmTemplate`] when the script has `n_pk ≥ 1`, `n_hash ≥ 1`
/// pure s:hash type-W arms (`n = n_pk + n_hash ≥ 2`, each `arm_idx ∈ 1..n`,
/// first arm is always the type-B pk), and `k ∈ n_hash..=n` (each hash arm
/// always contributes 1 when its preimage is present — not empty-dissatisfiable).
/// Otherwise `None`.
///
/// # Why this is completeable offline
///
/// Hash fragments always run (SIZE 32 EQUALVERIFY) — they are **not**
/// BIP-342-dissatisfiable with empty. With present 32-byte PSBT preimage(s) the
/// hash arms contribute **`n_hash`** to the thresh sum, so finalize needs exactly
/// `k − n_hash` matching `tap_script_sigs` among the pk arms (first
/// `k − n_hash` present in script order; empty placeholders for the rest) so
/// `EQUAL` sees sum `k`. Witness slots follow reverse arm order with each
/// preimage at its `arm_idx`. Never invents preimages or sigs. Missing any
/// preimage or too few pk sigs → honest Partial.
///
/// Distinct from pure s:/a:/mixed pk-only thresh (no SIZE/HASHOP arm), bare
/// hash / `and_v(v:pk, hash)` / `and_v(v:hash, pk)` (no thresh ADD/k), multi_a
/// (CHECKSIGADD/NUMEQUAL), a:hash (TOALTSTACK form), and mixed s:/a: with
/// hash ([`bare_tapscript_thresh_mixed_sa_hash_template`] — pure s: form only
/// here).
pub(crate) fn bare_tapscript_thresh_s_hash_template(
    script: &bitcoin::Script,
) -> Option<ThreshHashArmTemplate> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE, OP_SWAP};

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG (type B — never a hash arm).
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];
    // Hash arms in encounter order (arm index = pks so far + hashes so far).
    let mut hash_arms: Vec<ThreshHashArm> = Vec::new();

    // Remaining: any interleaving of s:pk and one-or-more s:hash type-W arms,
    // then <k> EQUAL. Pure s: form only — TOALTSTACK (a:) rejected.
    loop {
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_SWAP => {
                match iter.next()? {
                    // s:pk arm: SWAP <xonly> CHECKSIG ADD (before or after hash)
                    Ok(Instruction::PushBytes(b)) => {
                        let kb = b.as_bytes();
                        if kb.len() != 32 {
                            return None;
                        }
                        let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                        match iter.next()? {
                            Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op3)) if op3 == OP_ADD => {
                                pubkeys.push(pk);
                            }
                            _ => return None,
                        }
                    }
                    // s:hash arm: SWAP SIZE 32 EQUALVERIFY HASHOP digest EQUAL ADD
                    Ok(Instruction::Op(op_size)) if op_size == OP_SIZE => {
                        match iter.next()? {
                            Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_ev)) if op_ev == OP_EQUALVERIFY => {}
                            _ => return None,
                        }
                        let kind = match iter.next()? {
                            Ok(Instruction::Op(hop)) => TapscriptHashKind::from_hash_op(hop)?,
                            _ => return None,
                        };
                        let digest_push = match iter.next()? {
                            Ok(Instruction::PushBytes(b)) => b,
                            _ => return None,
                        };
                        let digest = digest_push.as_bytes();
                        if digest.len() != kind.expected_digest_len() {
                            return None;
                        }
                        let digest = digest.to_vec();
                        match iter.next()? {
                            Ok(Instruction::Op(op_eq)) if op_eq == OP_EQUAL => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_add)) if op_add == OP_ADD => {
                                // Arm index among all arms so far (pk + prior hashes).
                                let arm_idx = pubkeys.len() + hash_arms.len();
                                hash_arms.push(ThreshHashArm {
                                    arm_idx,
                                    kind,
                                    digest,
                                });
                            }
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                // Threshold push + EQUAL — only valid after ≥1 hash arm.
                if hash_arms.is_empty() {
                    return None;
                }
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_EQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                let n_hash = hash_arms.len();
                let n = pubkeys.len() + n_hash;
                if pubkeys.is_empty() || n_hash < 1 || n < 2 {
                    return None;
                }
                // Every hash arm is type-W (not first arm).
                for h in &hash_arms {
                    if h.arm_idx == 0 || h.arm_idx >= n {
                        return None;
                    }
                }
                // k must be ≥ n_hash (hash arms always contribute 1 each) and ≤ n.
                if (k as usize) < n_hash || (k as usize) > n {
                    return None;
                }
                return Some(ThreshHashArmTemplate {
                    threshold: k as usize,
                    pubkeys,
                    hash_arms,
                });
            }
            Ok(Instruction::PushBytes(_)) | Err(_) => return None,
        }
    }
}

/// Parse bare Taproot thresh leaf with **one or more pure a:hash** arms
/// (TOALTSTACK dual of [`bare_tapscript_thresh_s_hash_template`] — miniscript
/// shape `thresh(k, pk…, a:sha256|hash256|hash160|ripemd160(H), a:pk…, …)`):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// ( OP_TOALTSTACK <xonlyi> OP_CHECKSIG OP_FROMALTSTACK OP_ADD
/// | OP_TOALTSTACK OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
///   OP_FROMALTSTACK OP_ADD )+
/// <k> OP_EQUAL
/// ```
///
/// Returns [`ThreshHashArmTemplate`] when the script has `n_pk ≥ 1`, `n_hash ≥ 1`
/// pure a:hash arms (`n = n_pk + n_hash ≥ 2`, each `arm_idx ∈ 1..n`), and
/// `k ∈ n_hash..=n`. Otherwise `None`.
///
/// # Why this is completeable offline
///
/// Same policy as s:hash: each preimage contributes 1; need `k − n_hash` pk
/// `tap_script_sigs` (first `k − n_hash` present in script order; empty for
/// rest); reverse-arm witness with each preimage at its `arm_idx`. Never invents.
/// Distinct from pure a:pk (no SIZE/HASHOP), s:hash (SWAP), mixed s:/a: with
/// hash ([`bare_tapscript_thresh_mixed_sa_hash_template`]), multi_a.
pub(crate) fn bare_tapscript_thresh_a_hash_template(
    script: &bitcoin::Script,
) -> Option<ThreshHashArmTemplate> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_ADD, OP_CHECKSIG, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_SIZE, OP_TOALTSTACK,
    };

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG (type B — never a hash arm).
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];
    let mut hash_arms: Vec<ThreshHashArm> = Vec::new();

    // Remaining: any interleaving of a:pk and one-or-more a:hash type-W arms,
    // then <k> EQUAL. SWAP (s:) arms rejected — pure a: form only.
    loop {
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_TOALTSTACK => {
                match iter.next()? {
                    // a:pk arm: TOALTSTACK <xonly> CHECKSIG FROMALTSTACK ADD
                    Ok(Instruction::PushBytes(b)) => {
                        let kb = b.as_bytes();
                        if kb.len() != 32 {
                            return None;
                        }
                        let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                        match iter.next()? {
                            Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op3)) if op3 == OP_FROMALTSTACK => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op4)) if op4 == OP_ADD => {
                                pubkeys.push(pk);
                            }
                            _ => return None,
                        }
                    }
                    // a:hash arm: TOALTSTACK SIZE 32 EV HASH digest EQ FROMALTSTACK ADD
                    Ok(Instruction::Op(op_size)) if op_size == OP_SIZE => {
                        match iter.next()? {
                            Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_ev)) if op_ev == OP_EQUALVERIFY => {}
                            _ => return None,
                        }
                        let kind = match iter.next()? {
                            Ok(Instruction::Op(hop)) => TapscriptHashKind::from_hash_op(hop)?,
                            _ => return None,
                        };
                        let digest_push = match iter.next()? {
                            Ok(Instruction::PushBytes(b)) => b,
                            _ => return None,
                        };
                        let digest = digest_push.as_bytes();
                        if digest.len() != kind.expected_digest_len() {
                            return None;
                        }
                        let digest = digest.to_vec();
                        match iter.next()? {
                            Ok(Instruction::Op(op_eq)) if op_eq == OP_EQUAL => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_from)) if op_from == OP_FROMALTSTACK => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_add)) if op_add == OP_ADD => {
                                let arm_idx = pubkeys.len() + hash_arms.len();
                                hash_arms.push(ThreshHashArm {
                                    arm_idx,
                                    kind,
                                    digest,
                                });
                            }
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                if hash_arms.is_empty() {
                    return None;
                }
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_EQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                let n_hash = hash_arms.len();
                let n = pubkeys.len() + n_hash;
                if pubkeys.is_empty() || n_hash < 1 || n < 2 {
                    return None;
                }
                for h in &hash_arms {
                    if h.arm_idx == 0 || h.arm_idx >= n {
                        return None;
                    }
                }
                if (k as usize) < n_hash || (k as usize) > n {
                    return None;
                }
                return Some(ThreshHashArmTemplate {
                    threshold: k as usize,
                    pubkeys,
                    hash_arms,
                });
            }
            Ok(Instruction::PushBytes(_)) | Err(_) => return None,
        }
    }
}

/// Parse bare Taproot thresh with **mixed s:/a: wrappers and one+ hash arms**
/// (miniscript shape `thresh(k, pk…, s:pk|a:pk|s:hash|a:hash, …)` with both
/// SWAP and TOALTSTACK present and `n_hash ≥ 1`):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// ( OP_SWAP <xonlyi> OP_CHECKSIG OP_ADD
/// | OP_SWAP OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL OP_ADD
/// | OP_TOALTSTACK <xonlyi> OP_CHECKSIG OP_FROMALTSTACK OP_ADD
/// | OP_TOALTSTACK OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
///   OP_FROMALTSTACK OP_ADD )+
/// <k> OP_EQUAL
/// ```
///
/// Returns [`ThreshHashArmTemplate`] when:
/// - type-B first arm is pk (`n_pk ≥ 1`)
/// - both s: (SWAP) and a: (TOALTSTACK) wrappers appear among type-W arms
/// - `n_hash ≥ 1` pure hash arms (s:hash and/or a:hash)
/// - `n = n_pk + n_hash ≥ 3` (mixed requires both wrappers → ≥2 type-W arms)
/// - `k ∈ n_hash..=n`
///
/// # Why this is completeable offline
///
/// Same witness policy as pure multi-hash s:/a:hash: each matching 32-byte
/// PSBT preimage contributes 1; need exactly `k − n_hash` pk `tap_script_sigs`
/// (first present in script order; empty BIP-342 for unused pks); reverse-arm
/// witness with each preimage at its `arm_idx`. Never invents preimages/sigs.
/// Missing any preimage or too few pk sigs → honest Partial.
///
/// Distinct from:
/// - pure s:hash ([`bare_tapscript_thresh_s_hash_template`] — SWAP only)
/// - pure a:hash ([`bare_tapscript_thresh_a_hash_template`] — TOALTSTACK only)
/// - mixed s:/a: pk-only ([`bare_tapscript_thresh_mixed_sa_checksig_template`] —
///   no SIZE/HASHOP)
/// - pure s:pk / a:pk / multi_a
pub(crate) fn bare_tapscript_thresh_mixed_sa_hash_template(
    script: &bitcoin::Script,
) -> Option<ThreshHashArmTemplate> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_ADD, OP_CHECKSIG, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_SIZE, OP_SWAP,
        OP_TOALTSTACK,
    };

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG (type B — never a hash arm).
    let push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes = push.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let first = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }

    let mut pubkeys = vec![first];
    let mut hash_arms: Vec<ThreshHashArm> = Vec::new();
    let mut saw_swap = false;
    let mut saw_alt = false;

    loop {
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_SWAP => {
                match iter.next()? {
                    // s:pk arm: SWAP <xonly> CHECKSIG ADD
                    Ok(Instruction::PushBytes(b)) => {
                        let kb = b.as_bytes();
                        if kb.len() != 32 {
                            return None;
                        }
                        let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                        match iter.next()? {
                            Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op3)) if op3 == OP_ADD => {
                                pubkeys.push(pk);
                                saw_swap = true;
                            }
                            _ => return None,
                        }
                    }
                    // s:hash arm: SWAP SIZE 32 EV HASH dig EQ ADD
                    Ok(Instruction::Op(op_size)) if op_size == OP_SIZE => {
                        match iter.next()? {
                            Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_ev)) if op_ev == OP_EQUALVERIFY => {}
                            _ => return None,
                        }
                        let kind = match iter.next()? {
                            Ok(Instruction::Op(hop)) => TapscriptHashKind::from_hash_op(hop)?,
                            _ => return None,
                        };
                        let digest_push = match iter.next()? {
                            Ok(Instruction::PushBytes(b)) => b,
                            _ => return None,
                        };
                        let digest = digest_push.as_bytes();
                        if digest.len() != kind.expected_digest_len() {
                            return None;
                        }
                        let digest = digest.to_vec();
                        match iter.next()? {
                            Ok(Instruction::Op(op_eq)) if op_eq == OP_EQUAL => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_add)) if op_add == OP_ADD => {
                                let arm_idx = pubkeys.len() + hash_arms.len();
                                hash_arms.push(ThreshHashArm {
                                    arm_idx,
                                    kind,
                                    digest,
                                });
                                saw_swap = true;
                            }
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_TOALTSTACK => {
                match iter.next()? {
                    // a:pk arm: TOALTSTACK <xonly> CHECKSIG FROMALTSTACK ADD
                    Ok(Instruction::PushBytes(b)) => {
                        let kb = b.as_bytes();
                        if kb.len() != 32 {
                            return None;
                        }
                        let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                        match iter.next()? {
                            Ok(Instruction::Op(op2)) if op2 == OP_CHECKSIG => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op3)) if op3 == OP_FROMALTSTACK => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op4)) if op4 == OP_ADD => {
                                pubkeys.push(pk);
                                saw_alt = true;
                            }
                            _ => return None,
                        }
                    }
                    // a:hash arm: TOALTSTACK SIZE 32 EV HASH dig EQ FROMALTSTACK ADD
                    Ok(Instruction::Op(op_size)) if op_size == OP_SIZE => {
                        match iter.next()? {
                            Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_ev)) if op_ev == OP_EQUALVERIFY => {}
                            _ => return None,
                        }
                        let kind = match iter.next()? {
                            Ok(Instruction::Op(hop)) => TapscriptHashKind::from_hash_op(hop)?,
                            _ => return None,
                        };
                        let digest_push = match iter.next()? {
                            Ok(Instruction::PushBytes(b)) => b,
                            _ => return None,
                        };
                        let digest = digest_push.as_bytes();
                        if digest.len() != kind.expected_digest_len() {
                            return None;
                        }
                        let digest = digest.to_vec();
                        match iter.next()? {
                            Ok(Instruction::Op(op_eq)) if op_eq == OP_EQUAL => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_from)) if op_from == OP_FROMALTSTACK => {}
                            _ => return None,
                        }
                        match iter.next()? {
                            Ok(Instruction::Op(op_add)) if op_add == OP_ADD => {
                                let arm_idx = pubkeys.len() + hash_arms.len();
                                hash_arms.push(ThreshHashArm {
                                    arm_idx,
                                    kind,
                                    digest,
                                });
                                saw_alt = true;
                            }
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) => {
                // Mixed s:/a: + hash requires both wrappers and ≥1 hash arm.
                if hash_arms.is_empty() || !(saw_swap && saw_alt) {
                    return None;
                }
                let k = small_pushnum(op)?;
                if k == 0 {
                    return None;
                }
                match iter.next()? {
                    Ok(Instruction::Op(op2)) if op2 == OP_EQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                let n_hash = hash_arms.len();
                let n = pubkeys.len() + n_hash;
                // type-B pk + ≥2 type-W arms (both wrapper kinds) → n ≥ 3.
                if pubkeys.is_empty() || n_hash < 1 || n < 3 {
                    return None;
                }
                for h in &hash_arms {
                    if h.arm_idx == 0 || h.arm_idx >= n {
                        return None;
                    }
                }
                if (k as usize) < n_hash || (k as usize) > n {
                    return None;
                }
                return Some(ThreshHashArmTemplate {
                    threshold: k as usize,
                    pubkeys,
                    hash_arms,
                });
            }
            Ok(Instruction::PushBytes(_)) | Err(_) => return None,
        }
    }
}
