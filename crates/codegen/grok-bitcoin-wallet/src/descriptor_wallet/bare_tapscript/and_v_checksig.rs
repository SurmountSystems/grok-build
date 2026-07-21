//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

/// Parse bare Taproot and_v n-of-n leaf (CHECKSIGVERIFY chain):
///
/// ```text
/// <xonly1> OP_CHECKSIGVERIFY
/// <xonly2> OP_CHECKSIGVERIFY
/// …
/// <xonly{n-1}> OP_CHECKSIGVERIFY
/// <xonlyn> OP_CHECKSIG
/// ```
///
/// Returns pubkeys in script order when the script is exactly that template
/// with `n ≥ 2`. Otherwise `None` (single-key CHECKSIG, multi_a, other
/// miniscript stays residual).
///
/// All n signatures are required (CHECKSIGVERIFY rejects empty placeholders).
/// Witness stack is n elements in **reverse key order** (sig for last key
/// first) — same order as multi_a full-threshold stacks.
pub(crate) fn bare_tapscript_and_v_checksigverify_template(
    script: &bitcoin::Script,
) -> Option<Vec<bitcoin::secp256k1::XOnlyPublicKey>> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    // Require at least one CHECKSIGVERIFY then a final CHECKSIG (n ≥ 2).
    // Pattern: (<xonly> CHECKSIGVERIFY)+ <xonly> CHECKSIG
    loop {
        let push = match iter.next()? {
            Ok(Instruction::PushBytes(b)) => b,
            _ => return None,
        };
        let bytes = push.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                pubkeys.push(pk);
                // Continue for more CSV pairs or the final CHECKSIG key.
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                pubkeys.push(pk);
                if iter.next().is_some() {
                    return None;
                }
                // Need ≥ 1 CHECKSIGVERIFY before this final CHECKSIG ⇒ n ≥ 2.
                if pubkeys.len() < 2 {
                    return None;
                }
                return Some(pubkeys);
            }
            _ => return None,
        }
    }
}
