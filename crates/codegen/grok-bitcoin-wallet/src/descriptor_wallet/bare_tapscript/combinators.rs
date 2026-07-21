//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

/// Parse bare Taproot or_d dual-key leaf (miniscript `or_d(pk(A), pk(B))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_IFDUP
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b)` when the script is exactly that template.
/// Otherwise `None`.
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA>` (IFDUP keeps the CHECKSIG true for CLEANSTACK)
/// - B branch: `<sigB> <empty>` (empty = BIP-342 dissatisfaction of A;
///   never an invented Schnorr)
///
/// Policy when both sigs present: prefer A — deterministic, no invented
/// branch beyond present material. Bare `or_c` (CHECKSIG NOTIF … without
/// IFDUP) is **not** a valid top-level spend leaf under CLEANSTACK (A path
/// leaves empty stack) and stays residual.
pub(crate) fn bare_tapscript_or_d_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IFDUP, OP_NOTIF};

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
        Ok(Instruction::Op(op)) if op == OP_IFDUP => {}
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

/// Parse bare Taproot and_n dual-key leaf (miniscript `and_n(pk(A), pk(B))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   OP_0
/// OP_ELSE
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b)` when the script is exactly that template.
/// Otherwise `None`.
///
/// Both signatures are required (when A is false the script pushes 0 and
/// never evaluates B). Witness script inputs: `<sigB> <sigA>` (B then A;
/// reverse of script evaluation order so A is top-of-stack first).
/// Never invents empty dissatisfaction slots for a partial and_n spend.
pub(crate) fn bare_tapscript_and_n_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_NOTIF};

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
    // OP_0 / OP_FALSE is encoded as empty PushBytes (OP_PUSHBYTES_0).
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes().is_empty() => {}
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

/// Parse bare Taproot andor triple-key leaf
/// (miniscript `andor(pk(A), pk(B), pk(C))`):
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyC> OP_CHECKSIG
/// OP_ELSE
///   <xonlyB> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// Returns `(pk_a, pk_b, pk_c)` when the script is exactly that template.
/// Otherwise `None`. Distinct from [`bare_tapscript_and_n_checksig_template`]
/// (which pushes OP_0 in the NOTIF branch, not a third key).
///
/// Witness script inputs (before leaf + control block):
/// - AB path: `<sigB> <sigA>` (A true → ELSE evaluates B; both required)
/// - C path: `<sigC> <empty>` (empty = BIP-342 dissatisfaction of A;
///   never an invented Schnorr)
///
/// Policy when material allows both: prefer AB when A+B are present;
/// otherwise C when sigC is present. Never invents a third key, empty
/// dissatisfaction without a present C, or AB when either A or B is missing.
pub(crate) fn bare_tapscript_andor_checksig_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ELSE, OP_ENDIF, OP_NOTIF};

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
    // NOTIF branch: third key C (not OP_0 — that is and_n).
    let push_c = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_c = push_c.as_bytes();
    if bytes_c.len() != 32 {
        return None;
    }
    let pk_c = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_c).ok()?;
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
    Some((pk_a, pk_b, pk_c))
}
