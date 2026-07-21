//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

/// Parse bare Taproot or_c dual-key leaf (miniscript `or_c(pk(A), pk(B))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b)` when the script is exactly that template.
/// Otherwise `None`.
///
/// **Honesty:** bare top-level `or_c` is **CLEANSTACK-invalid** as a spend leaf
/// (A path leaves an empty stack after CHECKSIG consumes the sig — no IFDUP to
/// re-push the result). Detection exists only so finalize can emit a distinct
/// residual reason; **never assemble** a final witness for this template.
/// Prefer nested CLEANSTACK-valid forms only when offline-proved (not invented).
pub(crate) fn bare_tapscript_or_c_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_NOTIF};

    let mut iter = script.instructions();
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
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
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
