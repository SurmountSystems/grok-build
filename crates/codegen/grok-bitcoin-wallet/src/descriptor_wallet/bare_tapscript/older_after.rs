//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

use bitcoin::Sequence;
use bitcoin::absolute::LockTime;
use bitcoin::transaction;

/// Parse a miniscript `older(n)` / BIP-112 CSV argument from a script instruction.
///
/// Accepts OP_1..=OP_16 and minimal scriptnum pushes. Rejects 0, negatives,
/// and values with the relative-locktime **disable** flag set (bit 31).
/// Returns the consensus `u32` used as both the script push and the BIP-68
/// relative locktime encoding (height or time-interval bits).
pub(crate) fn parse_csv_older_n(instr: bitcoin::blockdata::script::Instruction<'_>) -> Option<u32> {
    let n = instr.script_num()?;
    if n <= 0 || n > i64::from(u32::MAX) {
        return None;
    }
    let n = n as u32;
    // BIP-112 disable flag on the stack item → relative locktime not enforced.
    if n & 0x8000_0000 != 0 {
        return None;
    }
    let seq = Sequence::from_consensus(n);
    if !seq.is_relative_lock_time() {
        return None;
    }
    // Miniscript older requires non-zero value bits (height or 512s intervals).
    if n & 0xffff == 0 {
        return None;
    }
    // Must decode as a relative::LockTime (type bits consistent).
    let _ = seq.to_relative_lock_time()?;
    Some(n)
}

/// True when BIP-112 `CHECKSEQUENCEVERIFY` for miniscript `older(n)` would pass
/// given the **already-present** tx version and input nSequence.
///
/// Does **not** check chain age (BIP-68 mempool/consensus finality) — only that
/// the unsigned tx already encodes a compatible nSequence ≥ required. Never
/// invents or mutates nSequence / nLockTime / version.
pub(crate) fn sequence_satisfies_csv_older(
    tx_version: transaction::Version,
    sequence: Sequence,
    older_n: u32,
) -> bool {
    // BIP-112: when the stack item's disable flag is unset, tx version must be ≥ 2.
    if tx_version.0 < 2 {
        return false;
    }
    let Some(required) = Sequence::from_consensus(older_n).to_relative_lock_time() else {
        return false;
    };
    required.is_implied_by_sequence(sequence)
}

/// Parse bare Taproot `and_v(v:pk(A), older(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIGVERIFY
/// <n> OP_CSV
/// ```
///
/// Returns `(pk_a, older_n)` when the script is exactly that template.
/// Witness script inputs: `<sigA>` (sig alone; CSV uses nSequence, not the
/// witness). Requires matching `tap_script_sig` **and** unsigned-tx nSequence
/// that satisfies BIP-112 for `n` — never invents either.
pub(crate) fn bare_tapscript_and_v_pk_older_template(
    script: &bitcoin::Script,
) -> Option<(bitcoin::secp256k1::XOnlyPublicKey, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV};

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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    let older_n = match iter.next()? {
        Ok(instr) => parse_csv_older_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, older_n))
}

/// Parse bare Taproot `and_v(v:older(n), pk(A))` leaf:
///
/// ```text
/// <n> OP_CSV OP_VERIFY
/// <xonlyA> OP_CHECKSIG
/// ```
///
/// (`v:older` encodes as CSV + OP_VERIFY — CSV is not a combined VERIFY opcode.)
/// Returns `(older_n, pk_a)` when the script is exactly that template.
/// Witness: `<sigA>`. Requires matching sig + satisfying nSequence.
pub(crate) fn bare_tapscript_and_v_older_pk_template(
    script: &bitcoin::Script,
) -> Option<(u32, bitcoin::secp256k1::XOnlyPublicKey)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_VERIFY};

    let mut iter = script.instructions();
    let older_n = match iter.next()? {
        Ok(instr) => parse_csv_older_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
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
    if iter.next().is_some() {
        return None;
    }
    Some((older_n, pk_a))
}

/// Parse bare Taproot miniscript `older(n)` leaf:
///
/// ```text
/// <n> OP_CSV
/// ```
///
/// Returns `older_n` when the script is exactly that template. Witness script
/// inputs are empty (CSV uses nSequence only). Completes only when unsigned-tx
/// nSequence already satisfies BIP-112 for `n`.
pub(crate) fn bare_tapscript_older_template(script: &bitcoin::Script) -> Option<u32> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CSV;

    let mut iter = script.instructions();
    let older_n = match iter.next()? {
        Ok(instr) => parse_csv_older_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some(older_n)
}

/// Parse a miniscript `after(n)` / BIP-65 CLTV argument from a script instruction.
///
/// Accepts OP_1..=OP_16 and minimal scriptnum pushes. Rejects 0, negatives, and
/// values above miniscript's absolute-locktime max (`0x7FFF_FFFF`). Returns the
/// consensus `u32` used as both the script push and the BIP-65 absolute
/// locktime encoding (height if `< LOCK_TIME_THRESHOLD`, else UNIX time).
pub(crate) fn parse_cltv_after_n(
    instr: bitcoin::blockdata::script::Instruction<'_>,
) -> Option<u32> {
    let n = instr.script_num()?;
    // Miniscript AbsLockTime: 1..=0x7FFF_FFFF (0 is boolean-abused; high bit
    // would be negative as a CScriptNum / is outside miniscript after range).
    if n < 1 || n > i64::from(0x7FFF_FFFFu32) {
        return None;
    }
    Some(n as u32)
}

/// True when BIP-65 `CHECKLOCKTIMEVERIFY` for miniscript `after(n)` would pass
/// given the **already-present** tx nLockTime and input nSequence.
///
/// Does **not** check chain height/time (mempool/consensus finality) — only that
/// the unsigned tx already encodes a compatible nLockTime ≥ required with the
/// same unit, and that nSequence enables absolute locktime
/// (`!= Sequence::MAX`). Never invents or mutates nLockTime / nSequence.
pub(crate) fn locktime_satisfies_cltv_after(
    lock_time: LockTime,
    sequence: Sequence,
    after_n: u32,
) -> bool {
    // BIP-65: final sequence (0xffffffff) disables nLockTime for this input → CLTV fails.
    if !sequence.enables_absolute_lock_time() {
        return false;
    }
    let required = LockTime::from_consensus(after_n);
    // required.is_implied_by(lock_time) ⇔ same unit and required ≤ lock_time.
    required.is_implied_by(lock_time)
}

/// Parse bare Taproot `and_v(v:pk(A), after(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIGVERIFY
/// <n> OP_CLTV
/// ```
///
/// Returns `(pk_a, after_n)` when the script is exactly that template.
/// Witness script inputs: `<sigA>` (sig alone; CLTV uses nLockTime, not the
/// witness). Requires matching `tap_script_sig` **and** unsigned-tx nLockTime
/// that satisfies BIP-65 for `n` with a non-final nSequence — never invents either.
pub(crate) fn bare_tapscript_and_v_pk_after_template(
    script: &bitcoin::Script,
) -> Option<(bitcoin::secp256k1::XOnlyPublicKey, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV};

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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    let after_n = match iter.next()? {
        Ok(instr) => parse_cltv_after_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, after_n))
}

/// Parse bare Taproot `and_v(v:after(n), pk(A))` leaf:
///
/// ```text
/// <n> OP_CLTV OP_VERIFY
/// <xonlyA> OP_CHECKSIG
/// ```
///
/// (`v:after` encodes as CLTV + OP_VERIFY — CLTV is not a combined VERIFY opcode.)
/// Returns `(after_n, pk_a)` when the script is exactly that template.
/// Witness: `<sigA>`. Requires matching sig + satisfying nLockTime/nSequence.
pub(crate) fn bare_tapscript_and_v_after_pk_template(
    script: &bitcoin::Script,
) -> Option<(u32, bitcoin::secp256k1::XOnlyPublicKey)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_VERIFY};

    let mut iter = script.instructions();
    let after_n = match iter.next()? {
        Ok(instr) => parse_cltv_after_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
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
    if iter.next().is_some() {
        return None;
    }
    Some((after_n, pk_a))
}

/// Parse bare Taproot miniscript `after(n)` leaf:
///
/// ```text
/// <n> OP_CLTV
/// ```
///
/// Returns `after_n` when the script is exactly that template. Witness script
/// inputs are empty (CLTV uses nLockTime only). Completes only when unsigned-tx
/// nLockTime already satisfies BIP-65 for `n` with a non-final nSequence.
pub(crate) fn bare_tapscript_after_template(script: &bitcoin::Script) -> Option<u32> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CLTV;

    let mut iter = script.instructions();
    let after_n = match iter.next()? {
        Ok(instr) => parse_cltv_after_n(instr)?,
        Err(_) => return None,
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some(after_n)
}

/// Shared older/after lock kind for combined hash+timeout `and_v` templates and
/// dual-timeout `or_i` arms (not or_i-specific; lives with CSV/CLTV helpers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DualTimeoutLock {
    /// BIP-112 relative locktime (`older(n)` / CSV).
    Older(u32),
    /// BIP-65 absolute locktime (`after(n)` / CLTV).
    After(u32),
}

/// True when the dual-timeout arm's already-present locktime material
/// satisfies BIP-112 (older) or BIP-65 (after). Never invents.
pub(crate) fn dual_timeout_lock_satisfied(
    lock: DualTimeoutLock,
    tx_version: transaction::Version,
    sequence: Sequence,
    lock_time: LockTime,
) -> bool {
    match lock {
        DualTimeoutLock::Older(n) => sequence_satisfies_csv_older(tx_version, sequence, n),
        DualTimeoutLock::After(n) => locktime_satisfies_cltv_after(lock_time, sequence, n),
    }
}
