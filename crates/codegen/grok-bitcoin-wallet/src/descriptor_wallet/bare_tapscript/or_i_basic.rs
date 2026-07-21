//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

/// Parse bare Taproot or_i dual-key leaf (miniscript `or_i(pk(A), pk(B))`):
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIG
/// OP_ELSE
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_if, pk_else)` when the script is exactly that template.
/// Otherwise `None`.
///
/// Witness script inputs (before leaf + control block):
/// - IF branch (A): `<sigA> <0x01>`
/// - ELSE branch (B): `<sigB> <empty>`
///
/// Policy when both sigs present: prefer IF branch (A) — deterministic, no
/// invented branch selector beyond the standard OP_IF encoding of present
/// material.
pub(crate) fn bare_tapscript_or_i_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_IF};

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let push_a = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_a = push_a.as_bytes();
    if bytes_a.len() != 32 {
        return None;
    }
    let pk_a = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_a).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let push_b = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_b = push_b.as_bytes();
    if bytes_b.len() != 32 {
        return None;
    }
    let pk_b = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_b).ok()?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b))
}
