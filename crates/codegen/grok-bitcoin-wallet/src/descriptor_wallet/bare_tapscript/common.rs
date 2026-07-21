//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

/// Decode OP_1..=OP_16 small integer push (standard bare multisig m/n).
pub(crate) fn small_pushnum(op: bitcoin::opcodes::Opcode) -> Option<u8> {
    use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16};
    let code = op.to_u8();
    let start = OP_PUSHNUM_1.to_u8();
    let end = OP_PUSHNUM_16.to_u8();
    if (start..=end).contains(&code) {
        Some(code - start + 1)
    } else {
        None
    }
}
