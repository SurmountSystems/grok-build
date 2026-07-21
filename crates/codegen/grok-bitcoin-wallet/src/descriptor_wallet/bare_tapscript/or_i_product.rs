//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

use super::{DualTimeoutLock, TapscriptHashKind, parse_cltv_after_n, parse_csv_older_n};

/// Parse nested CLEANSTACK-valid vault
/// `or_i(and_v(v:pk…)|pk, older(n))` leaf (keys ≥ 1 on IF arm):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)*   // 0+
///   <xonly> OP_CHECKSIG            // ≥ 1 total
/// OP_ELSE
///   <n> OP_CSV
/// OP_ENDIF
/// ```
///
/// Classic vault: multi-sig (or single `pk`) **or** relative timeout with no
/// second key. Distinct from `and_v(or_i(v:pk, v:pk), older)` (CSV **outside**
/// ENDIF; both arms keys) and bare or_i (CHECKSIG on both arms).
///
/// Witness:
/// - IF/keys (preferred when all sigs present): reverse-key sigs + `<0x01>`
/// - ELSE/timeout: `<empty>` false selector only (needs already-present
///   nSequence satisfying BIP-112 — never invents)
pub(crate) fn bare_tapscript_or_i_and_v_pk_older_template(
    script: &bitcoin::Script,
) -> Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_ELSE, OP_ENDIF, OP_IF};

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    // IF arm: (≥0 CHECKSIGVERIFY) + final CHECKSIG, n ≥ 1.
    let mut pubkeys = Vec::new();
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
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                pubkeys.push(pk);
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let older_n = parse_csv_older_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pubkeys, older_n))
}

/// Parse nested CLEANSTACK-valid vault
/// `or_i(and_v(v:pk…)|pk, after(n))` leaf (keys ≥ 1 on IF arm):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)*
///   <xonly> OP_CHECKSIG
/// OP_ELSE
///   <n> OP_CLTV
/// OP_ENDIF
/// ```
///
/// Dual of [`bare_tapscript_or_i_and_v_pk_older_template`] with BIP-65 CLTV.
/// IF preferred when all sigs present; ELSE needs already-present
/// nLockTime/nSequence that satisfy BIP-65 — never invents either.
pub(crate) fn bare_tapscript_or_i_and_v_pk_after_template(
    script: &bitcoin::Script,
) -> Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_ELSE, OP_ENDIF, OP_IF,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let mut pubkeys = Vec::new();
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
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                pubkeys.push(pk);
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let after_n = parse_cltv_after_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pubkeys, after_n))
}

/// Parse nested CLEANSTACK-valid vault
/// `or_i(and_v(v:pk…)|pk, hash(H))` leaf (keys ≥ 1 on IF arm):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)*
///   <xonly> OP_CHECKSIG
/// OP_ELSE
///   OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// OP_ENDIF
/// ```
///
/// Dual of vault older/after with bare hash on ELSE. IF preferred when all
/// sigs present; ELSE needs matching 32-byte PSBT preimage — never invents.
pub(crate) fn bare_tapscript_or_i_and_v_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let mut pubkeys = Vec::new();
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
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                pubkeys.push(pk);
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    // Bare hash fragment: SIZE 32 EQUALVERIFY HASHOP digest EQUAL
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
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
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pubkeys, kind, digest))
}

/// Parse nested CLEANSTACK-valid delayed-recovery / inheritance vault
/// `or_i(and_v(v:pk…)|pk, and_v(v:pk…, older(n)))` leaf
/// (IF hot keys ≥ 1; ELSE cold keys ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)*   // 0+
///   <xonly> OP_CHECKSIG            // ≥ 1 total IF (hot)
/// OP_ELSE
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 cold (all VERIFY)
///   <n> OP_CSV
/// OP_ENDIF
/// ```
///
/// Classic inheritance: spend with hot multi/single **or** cold multi/single
/// after relative timeout. Distinct from bare vault
/// [`bare_tapscript_or_i_and_v_pk_older_template`] (ELSE has **no** keys —
/// anyone can timeout) and from `and_v(or_i, older)` (CSV **outside** ENDIF).
///
/// Witness:
/// - IF/hot (preferred when all IF sigs present): reverse(if_keys)+`<0x01>`
/// - ELSE/cold+timeout: reverse(else_keys)+`<empty>` (needs already-present
///   nSequence satisfying BIP-112 — never invents)
pub(crate) fn bare_tapscript_or_i_pk_and_v_pk_older_template(
    script: &bitcoin::Script,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_ELSE, OP_ENDIF, OP_IF};

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    // IF arm: (≥0 CHECKSIGVERIFY) + final CHECKSIG, n ≥ 1.
    let mut if_keys = Vec::new();
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
                if_keys.push(pk);
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                if_keys.push(pk);
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    // ELSE arm: ≥1 CHECKSIGVERIFY (all v:pk) then CSV. Distinct from bare vault
    // ELSE (no keys) and from bare or_i (CHECKSIG not VERIFY on ELSE).
    let mut else_keys = Vec::new();
    loop {
        let instr = iter.next()?.ok()?;
        // 32-byte push + CHECKSIGVERIFY → another cold key.
        if let Instruction::PushBytes(b) = instr {
            let bytes = b.as_bytes();
            if bytes.len() == 32 {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        else_keys.push(pk);
                        continue;
                    }
                    // CHECKSIG (not VERIFY) on ELSE → bare or_i, not inheritance.
                    _ => return None,
                }
            }
        }
        // After ≥1 VERIFY keys, this instruction is the CSV argument (OP_n or
        // scriptnum push — including multi-byte n that is not 32 bytes).
        if else_keys.is_empty() {
            return None;
        }
        let older_n = parse_csv_older_n(instr)?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CSV => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
            _ => return None,
        }
        if iter.next().is_some() {
            return None;
        }
        return Some((if_keys, else_keys, older_n));
    }
}

/// Parse nested CLEANSTACK-valid delayed-recovery / inheritance vault
/// `or_i(and_v(v:pk…)|pk, and_v(v:pk…, after(n)))` leaf
/// (IF hot ≥ 1; ELSE cold ≥ 1 all-`v:pk` CHECKSIGVERIFY + CLTV).
///
/// Dual of [`bare_tapscript_or_i_pk_and_v_pk_older_template`] with BIP-65 CLTV.
/// IF preferred when all IF sigs present; ELSE needs already-present
/// nLockTime/nSequence that satisfy BIP-65 — never invents either.
pub(crate) fn bare_tapscript_or_i_pk_and_v_pk_after_template(
    script: &bitcoin::Script,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_ELSE, OP_ENDIF, OP_IF,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let mut if_keys = Vec::new();
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
                if_keys.push(pk);
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                if_keys.push(pk);
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let mut else_keys = Vec::new();
    loop {
        let instr = iter.next()?.ok()?;
        if let Instruction::PushBytes(b) = instr {
            let bytes = b.as_bytes();
            if bytes.len() == 32 {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        else_keys.push(pk);
                        continue;
                    }
                    _ => return None,
                }
            }
        }
        if else_keys.is_empty() {
            return None;
        }
        let after_n = parse_cltv_after_n(instr)?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CLTV => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
            _ => return None,
        }
        if iter.next().is_some() {
            return None;
        }
        return Some((if_keys, else_keys, after_n));
    }
}

/// (if_keys, else_keys, hash_kind, digest) for inheritance hash template.
pub(crate) type InheritanceOrIPkAndVPkHashParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
);

/// Parse nested CLEANSTACK-valid delayed-recovery / inheritance vault
/// `or_i(and_v(v:pk…)|pk, and_v(v:pk…, hash(H)))` leaf
/// (IF hot ≥ 1; ELSE cold ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash).
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)*
///   <xonly> OP_CHECKSIG
/// OP_ELSE
///   (<xonly> OP_CHECKSIGVERIFY)+
///   OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// OP_ENDIF
/// ```
///
/// Dual of inheritance older/after with bare hash on ELSE after cold VERIFY
/// chain. IF preferred when all IF sigs present; ELSE needs all cold sigs +
/// matching 32-byte PSBT preimage — never invents. Distinct from bare vault
/// hash (no cold keys on ELSE) and `and_v(or_i, hash)` (hash outside ENDIF).
pub(crate) fn bare_tapscript_or_i_pk_and_v_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<InheritanceOrIPkAndVPkHashParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let mut if_keys = Vec::new();
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
                if_keys.push(pk);
            }
            Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {
                if_keys.push(pk);
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let mut else_keys = Vec::new();
    // Cold VERIFY chain then bare hash fragment (SIZE starts the hash arm).
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let bytes = b.as_bytes();
                if bytes.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        else_keys.push(pk);
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !else_keys.is_empty() => {
                break;
            }
            _ => return None,
        }
    }
    // Bare hash fragment after SIZE already consumed: 32 EQUALVERIFY HASHOP digest EQUAL
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
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
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((if_keys, else_keys, kind, digest))
}

/// (if_keys, else_keys, hash_kind, digest, lock_n) for HTLC dual-path templates.
pub(crate) type HtlcOrIHashAndLockParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
    u32,
);

/// Parse nested CLEANSTACK-valid HTLC-style dual-path
/// `or_i(and_v(v:pk…, hash(H)), and_v(v:pk…, older(n)))` leaf
/// (IF claim ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash; ELSE refund ≥ 1
/// all-`v:pk` CHECKSIGVERIFY + CSV):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 claim keys
///   OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// OP_ELSE
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 refund keys
///   <n> OP_CSV
/// OP_ENDIF
/// ```
///
/// Classic HTLC-like: claim with preimage + claim key(s) **or** refund with
/// refund key(s) after relative timeout. Distinct from inheritance
/// [`bare_tapscript_or_i_pk_and_v_pk_older_template`] (IF ends with CHECKSIG,
/// no hash) / inheritance hash (ELSE has hash, IF bare keys) / bare vault
/// (ELSE no keys) / `and_v(or_i, …)` (condition outside ENDIF).
///
/// Witness:
/// - IF/claim (preferred when all IF sigs + matching preimage present):
///   preimage + reverse(if_keys) + `<0x01>`
/// - ELSE/refund+timeout: reverse(else_keys) + `<empty>` (needs already-present
///   nSequence satisfying BIP-112 — never invents)
pub(crate) fn bare_tapscript_or_i_hash_and_v_pk_older_template(
    script: &bitcoin::Script,
) -> Option<HtlcOrIHashAndLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_CSV, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    // IF arm: ≥1 CHECKSIGVERIFY then bare hash (SIZE starts hash fragment).
    let mut if_keys = Vec::new();
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let bytes = b.as_bytes();
                if bytes.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        if_keys.push(pk);
                    }
                    // CHECKSIG (not VERIFY) → inheritance-style IF, not HTLC.
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !if_keys.is_empty() => {
                break;
            }
            _ => return None,
        }
    }
    // Bare hash fragment after SIZE already consumed.
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
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
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    // ELSE arm: ≥1 CHECKSIGVERIFY then CSV.
    let mut else_keys = Vec::new();
    loop {
        let instr = iter.next()?.ok()?;
        if let Instruction::PushBytes(b) = instr {
            let bytes = b.as_bytes();
            if bytes.len() == 32 {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        else_keys.push(pk);
                        continue;
                    }
                    _ => return None,
                }
            }
        }
        if else_keys.is_empty() {
            return None;
        }
        let older_n = parse_csv_older_n(instr)?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CSV => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
            _ => return None,
        }
        if iter.next().is_some() {
            return None;
        }
        return Some((if_keys, else_keys, kind, digest, older_n));
    }
}

/// Parse nested CLEANSTACK-valid HTLC-style dual-path
/// `or_i(and_v(v:pk…, hash(H)), and_v(v:pk…, after(n)))` leaf
/// (IF claim ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash; ELSE refund ≥ 1
/// all-`v:pk` CHECKSIGVERIFY + CLTV).
///
/// Dual of [`bare_tapscript_or_i_hash_and_v_pk_older_template`] with BIP-65
/// CLTV on ELSE. IF preferred when all IF sigs + matching preimage present;
/// ELSE needs already-present nLockTime/nSequence that satisfy BIP-65 —
/// never invents either.
pub(crate) fn bare_tapscript_or_i_hash_and_v_pk_after_template(
    script: &bitcoin::Script,
) -> Option<HtlcOrIHashAndLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_CLTV, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let mut if_keys = Vec::new();
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let bytes = b.as_bytes();
                if bytes.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        if_keys.push(pk);
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !if_keys.is_empty() => {
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
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
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    let mut else_keys = Vec::new();
    loop {
        let instr = iter.next()?.ok()?;
        if let Instruction::PushBytes(b) = instr {
            let bytes = b.as_bytes();
            if bytes.len() == 32 {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        else_keys.push(pk);
                        continue;
                    }
                    _ => return None,
                }
            }
        }
        if else_keys.is_empty() {
            return None;
        }
        let after_n = parse_cltv_after_n(instr)?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CLTV => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
            _ => return None,
        }
        if iter.next().is_some() {
            return None;
        }
        return Some((if_keys, else_keys, kind, digest, after_n));
    }
}

/// Parse nested CLEANSTACK-valid reverse HTLC
/// `or_i(and_v(v:pk…, older(n)), and_v(v:pk…, hash(H)))` leaf
/// (IF timeout ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV; ELSE claim ≥ 1
/// all-`v:pk` CHECKSIGVERIFY + bare hash):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 timeout keys
///   <n> OP_CSV
/// OP_ELSE
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 claim keys
///   OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// OP_ENDIF
/// ```
///
/// Arms-swapped mirror of [`bare_tapscript_or_i_hash_and_v_pk_older_template`].
/// Distinct from inheritance (IF ends with CHECKSIG, no CSV on IF) / classic
/// HTLC (hash on IF) / bare vault (ELSE no keys) / `and_v(or_i, …)` (CSV
/// outside ENDIF).
///
/// Witness:
/// - IF/timeout (preferred when all IF sigs + already-present nSequence):
///   reverse(if_keys) + `<0x01>`
/// - ELSE/claim+preimage: preimage + reverse(else_keys) + `<empty>`
pub(crate) fn bare_tapscript_or_i_older_and_v_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<HtlcOrIHashAndLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_CSV, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    // IF arm: ≥1 CHECKSIGVERIFY then CSV (not hash / not bare CHECKSIG).
    let mut if_keys = Vec::new();
    loop {
        let instr = iter.next()?.ok()?;
        if let Instruction::PushBytes(b) = instr {
            let bytes = b.as_bytes();
            if bytes.len() == 32 {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        if_keys.push(pk);
                        continue;
                    }
                    // CHECKSIG (not VERIFY) → inheritance-style IF, not reverse HTLC.
                    _ => return None,
                }
            }
        }
        if if_keys.is_empty() {
            return None;
        }
        let older_n = parse_csv_older_n(instr)?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CSV => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ELSE => {}
            _ => return None,
        }
        // ELSE arm: ≥1 CHECKSIGVERIFY then bare hash (SIZE starts fragment).
        let mut else_keys = Vec::new();
        loop {
            match iter.next()? {
                Ok(Instruction::PushBytes(b)) => {
                    let bytes = b.as_bytes();
                    if bytes.len() != 32 {
                        return None;
                    }
                    let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                    match iter.next()? {
                        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                            else_keys.push(pk);
                        }
                        _ => return None,
                    }
                }
                Ok(Instruction::Op(op)) if op == OP_SIZE && !else_keys.is_empty() => {
                    break;
                }
                _ => return None,
            }
        }
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
            _ => return None,
        }
        let kind = match iter.next()? {
            Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
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
            Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
            _ => return None,
        }
        if iter.next().is_some() {
            return None;
        }
        return Some((if_keys, else_keys, kind, digest, older_n));
    }
}

/// Parse nested CLEANSTACK-valid reverse HTLC
/// `or_i(and_v(v:pk…, after(n)), and_v(v:pk…, hash(H)))` leaf
/// (IF timeout ≥ 1 all-`v:pk` CHECKSIGVERIFY + CLTV; ELSE claim ≥ 1
/// all-`v:pk` CHECKSIGVERIFY + bare hash).
///
/// Dual of [`bare_tapscript_or_i_older_and_v_pk_hash_template`] with BIP-65
/// CLTV on IF. IF preferred when all IF sigs + already-present
/// nLockTime/nSequence that satisfy BIP-65; ELSE needs matching 32-byte PSBT
/// preimage + all claim sigs — never invents.
pub(crate) fn bare_tapscript_or_i_after_and_v_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<HtlcOrIHashAndLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_CLTV, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    let mut if_keys = Vec::new();
    loop {
        let instr = iter.next()?.ok()?;
        if let Instruction::PushBytes(b) = instr {
            let bytes = b.as_bytes();
            if bytes.len() == 32 {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        if_keys.push(pk);
                        continue;
                    }
                    _ => return None,
                }
            }
        }
        if if_keys.is_empty() {
            return None;
        }
        let after_n = parse_cltv_after_n(instr)?;
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_CLTV => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ELSE => {}
            _ => return None,
        }
        let mut else_keys = Vec::new();
        loop {
            match iter.next()? {
                Ok(Instruction::PushBytes(b)) => {
                    let bytes = b.as_bytes();
                    if bytes.len() != 32 {
                        return None;
                    }
                    let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                    match iter.next()? {
                        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                            else_keys.push(pk);
                        }
                        _ => return None,
                    }
                }
                Ok(Instruction::Op(op)) if op == OP_SIZE && !else_keys.is_empty() => {
                    break;
                }
                _ => return None,
            }
        }
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
            _ => return None,
        }
        let kind = match iter.next()? {
            Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
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
            Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
            _ => return None,
        }
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
            _ => return None,
        }
        if iter.next().is_some() {
            return None;
        }
        return Some((if_keys, else_keys, kind, digest, after_n));
    }
}

/// (if_keys, else_keys, if_kind, if_digest, else_kind, else_digest) for dual-hash
/// `or_i(and_v(pk…, hash), and_v(pk…, hash))` templates.
pub(crate) type DualHashOrIParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
    TapscriptHashKind,
    Vec<u8>,
);

/// Parse nested CLEANSTACK-valid dual-hash
/// `or_i(and_v(v:pk…, hash(H1)), and_v(v:pk…, hash(H2)))` leaf
/// (IF claim ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash; ELSE claim ≥ 1
/// all-`v:pk` CHECKSIGVERIFY + bare hash):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 claim keys (H1 path)
///   OP_SIZE <32> OP_EQUALVERIFY <HASHOP1> <digest1> OP_EQUAL
/// OP_ELSE
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 claim keys (H2 path)
///   OP_SIZE <32> OP_EQUALVERIFY <HASHOP2> <digest2> OP_EQUAL
/// OP_ENDIF
/// ```
///
/// Dual claim paths (e.g. atomic-swap style). Distinct from classic HTLC
/// (ELSE has CSV|CLTV, not hash) / reverse HTLC (IF has CSV|CLTV) /
/// inheritance (IF ends with CHECKSIG) / bare vault (ELSE no keys) /
/// inheritance hash (IF bare keys ending CHECKSIG) / `and_v(or_i, hash)`
/// (hash outside ENDIF).
///
/// Witness:
/// - IF/H1 (preferred when all IF sigs + matching 32-byte PSBT preimage for
///   H1): preimage1 + reverse(if_keys) + `<0x01>`
/// - ELSE/H2: preimage2 + reverse(else_keys) + `<empty>`
///
/// Never invents sigs or preimages. H1 and H2 may use different hash ops /
/// digests.
pub(crate) fn bare_tapscript_or_i_hash_and_v_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<DualHashOrIParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    // IF arm: ≥1 CHECKSIGVERIFY then bare hash (SIZE starts fragment).
    let mut if_keys = Vec::new();
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let bytes = b.as_bytes();
                if bytes.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        if_keys.push(pk);
                    }
                    // CHECKSIG (not VERIFY) → inheritance-style IF, not dual-hash.
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !if_keys.is_empty() => {
                break;
            }
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let if_kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let if_digest_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let if_digest = if_digest_push.as_bytes();
    if if_digest.len() != if_kind.expected_digest_len() {
        return None;
    }
    let if_digest = if_digest.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    // ELSE arm: ≥1 CHECKSIGVERIFY then bare hash (not CSV|CLTV).
    let mut else_keys = Vec::new();
    loop {
        match iter.next()? {
            Ok(Instruction::PushBytes(b)) => {
                let bytes = b.as_bytes();
                if bytes.len() != 32 {
                    return None;
                }
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        else_keys.push(pk);
                    }
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !else_keys.is_empty() => {
                break;
            }
            // CSV / CLTV / bare CHECKSIG / empty → classic HTLC / reverse /
            // inheritance / vault, not dual-hash.
            _ => return None,
        }
    }
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let else_kind = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let else_digest_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let else_digest = else_digest_push.as_bytes();
    if else_digest.len() != else_kind.expected_digest_len() {
        return None;
    }
    let else_digest = else_digest.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((
        if_keys,
        else_keys,
        if_kind,
        if_digest,
        else_kind,
        else_digest,
    ))
}

/// (if_keys, else_keys, if_lock, else_lock) for dual-timeout
/// `or_i(and_v(pk…, older|after), and_v(pk…, older|after))` templates.
pub(crate) type DualTimeoutOrIParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    DualTimeoutLock,
    DualTimeoutLock,
);

/// Parse nested CLEANSTACK-valid dual-timeout
/// `or_i(and_v(v:pk…, older(n1)|after(n1)), and_v(v:pk…, older(n2)|after(n2)))`
/// leaf (IF timeout ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV; ELSE timeout ≥ 1
/// all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — dual timeout paths, no hash):
///
/// ```text
/// OP_IF
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 timeout keys (path 1)
///   <n1> OP_CSV | OP_CLTV
/// OP_ELSE
///   (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1 timeout keys (path 2)
///   <n2> OP_CSV | OP_CLTV
/// OP_ENDIF
/// ```
///
/// Dual timeout paths (e.g. two relative/absolute recovery windows). Distinct
/// from reverse HTLC (ELSE has bare hash, not CSV|CLTV) / classic HTLC (IF has
/// bare hash) / dual-hash (both arms hash) / inheritance (IF ends CHECKSIG) /
/// bare vault (ELSE no keys) / `and_v(or_i, …)` (lock outside ENDIF).
///
/// Witness:
/// - IF (preferred when all IF sigs + already-present nSequence / nLockTime
///   that satisfy the IF lock): reverse(if_keys) + `<0x01>`
/// - ELSE: reverse(else_keys) + `<empty>`
///
/// Never invents sigs or nSequence/nLockTime. IF/ELSE may use different
/// older/after kinds and different `n`.
pub(crate) fn bare_tapscript_or_i_lock_and_v_pk_lock_template(
    script: &bitcoin::Script,
) -> Option<DualTimeoutOrIParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_ELSE, OP_ENDIF, OP_IF};

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
        _ => return None,
    }
    // IF arm: ≥1 CHECKSIGVERIFY then CSV|CLTV (not hash / not bare CHECKSIG).
    let mut if_keys = Vec::new();
    loop {
        let instr = iter.next()?.ok()?;
        if let Instruction::PushBytes(b) = instr {
            let bytes = b.as_bytes();
            if bytes.len() == 32 {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        if_keys.push(pk);
                        continue;
                    }
                    // CHECKSIG (not VERIFY) → inheritance-style IF, not dual-timeout.
                    _ => return None,
                }
            }
        }
        if if_keys.is_empty() {
            return None;
        }
        // `instr` is the locktime number; next opcode disambiguates CSV vs CLTV.
        let lock_op = match iter.next()? {
            Ok(Instruction::Op(op)) => op,
            _ => return None,
        };
        let if_lock = if lock_op == OP_CSV {
            DualTimeoutLock::Older(parse_csv_older_n(instr)?)
        } else if lock_op == OP_CLTV {
            DualTimeoutLock::After(parse_cltv_after_n(instr)?)
        } else {
            return None;
        };
        match iter.next()? {
            Ok(Instruction::Op(op)) if op == OP_ELSE => {}
            _ => return None,
        }
        // ELSE arm: ≥1 CHECKSIGVERIFY then CSV|CLTV (not bare hash).
        let mut else_keys = Vec::new();
        loop {
            let else_instr = iter.next()?.ok()?;
            if let Instruction::PushBytes(b) = else_instr {
                let bytes = b.as_bytes();
                if bytes.len() == 32 {
                    let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes).ok()?;
                    match iter.next()? {
                        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                            else_keys.push(pk);
                            continue;
                        }
                        _ => return None,
                    }
                }
            }
            if else_keys.is_empty() {
                return None;
            }
            let else_lock_op = match iter.next()? {
                Ok(Instruction::Op(op)) => op,
                _ => return None,
            };
            let else_lock = if else_lock_op == OP_CSV {
                DualTimeoutLock::Older(parse_csv_older_n(else_instr)?)
            } else if else_lock_op == OP_CLTV {
                DualTimeoutLock::After(parse_cltv_after_n(else_instr)?)
            } else {
                // SIZE / hash / bare CHECKSIG → reverse HTLC / classic / vault, not dual-timeout.
                return None;
            };
            match iter.next()? {
                Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
                _ => return None,
            }
            if iter.next().is_some() {
                return None;
            }
            return Some((if_keys, else_keys, if_lock, else_lock));
        }
    }
}
