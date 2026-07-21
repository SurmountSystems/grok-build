//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

use super::small_pushnum;

/// Parse bare Taproot multi_a leaf (BIP-342 CHECKSIGADD k-of-n):
///
/// ```text
/// <xonly1> OP_CHECKSIG
/// <xonly2> OP_CHECKSIGADD
/// …
/// <xonlyn> OP_CHECKSIGADD
/// <k> OP_NUMEQUAL
/// ```
///
/// Returns `(threshold k, pubkeys in script order)` when the script is exactly
/// that template with `n ≥ 2` and `k ∈ 1..=n` via `OP_1..=OP_16`. Otherwise
/// `None` (single-key CHECKSIG, other miniscript, non-standard stays residual).
///
/// Witness stack for this template is n elements in **reverse key order**
/// (sig for last key first), with empty vectors for unused keys when `k < n`.
pub(crate) fn bare_tapscript_checksigadd_multi_template(
    script: &bitcoin::Script,
) -> Option<(usize, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};

    let mut iter = script.instructions();

    // First key: <xonly> OP_CHECKSIG
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

    // Remaining: (<xonly> OP_CHECKSIGADD)+ then <k> OP_NUMEQUAL.
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let kb = b.as_bytes();
                if kb.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(kb).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGADD => {
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
                    Ok(Instruction::Op(op2)) if op2 == OP_NUMEQUAL => {}
                    _ => return None,
                }
                if iter.next().is_some() {
                    return None;
                }
                // multi_a requires at least one CHECKSIGADD (n ≥ 2).
                if pubkeys.len() < 2 {
                    return None;
                }
                if (k as usize) > pubkeys.len() {
                    return None;
                }
                return Some((k as usize, pubkeys));
            }
            Err(_) => return None,
        }
    }
}
