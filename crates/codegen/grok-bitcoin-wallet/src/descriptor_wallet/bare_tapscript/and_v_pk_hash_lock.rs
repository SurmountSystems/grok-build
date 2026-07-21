//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

use super::{
    DualTimeoutLock, TapscriptHashKind, parse_and_v_left_checksigverify_keys,
    parse_and_v_pk_checksig_tail_n1, parse_cltv_after_n, parse_csv_older_n,
};

/// (keys, kind, digest, lock) for combined hash+timeout
/// `and_v(v:pk…, and_v(v:hash(H), older(n)|after(n)))` templates.
pub(crate) type PkHashLockParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
    DualTimeoutLock,
);

/// Parse nested CLEANSTACK-valid combined hash+timeout
/// `and_v(v:pk…, and_v(v:hash(H), older(n)|after(n)))` leaf
/// (≥ 1 all-`v:pk` CHECKSIGVERIFY + v:hash VERIFY + CSV|CLTV — single path
/// requiring **both** preimage and locktime, not OR like HTLC):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUALVERIFY
/// <n> OP_CSV | OP_CLTV
/// ```
///
/// Classic delayed-claim AND: key(s) + matching 32-byte PSBT preimage +
/// already-present nSequence (older) / nLockTime+nSequence (after). Distinct
/// from single `and_v(v:pk, hash)` (ends EQUAL, no CSV|CLTV) / multi-pk hash
/// (ends EQUAL, no lock) / `and_v(v:pk, older|after)` (no hash) / sandwich
/// `and_v(v:pk…, and_v(v:hash, pk…))` (right keys after hash, no lock) /
/// classic HTLC `or_i(and_v(pk, hash), and_v(pk, older))` (OR dual-path, bare
/// EQUAL hash on IF) / reverse HTLC / dual-hash / dual-timeout.
///
/// Witness: `<preimage> <sig_last> … <sig_first>` (preimage deepest; first
/// key's sig top so CHECKSIGVERIFY runs first, then hash VERIFY, then
/// CSV|CLTV). Never invents sigs, preimages, or nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_pk_hash_lock_template(
    script: &bitcoin::Script,
) -> Option<PkHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    // ≥1 CHECKSIGVERIFY keys, then OP_SIZE starts v:hash.
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
                        pubkeys.push(pk);
                    }
                    // CHECKSIG (not VERIFY) or other → not this template.
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !pubkeys.is_empty() => {
                break;
            }
            _ => return None,
        }
    }
    // v:hash fragment after SIZE already consumed: 32 EQUALVERIFY HASHOP digest EQUALVERIFY
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
    // Type-V hash (EQUALVERIFY) — trailing lock needs VERIFY form, not bare EQUAL.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    // Trailing CSV|CLTV (type B older|after).
    let lock_instr = iter.next()?.ok()?;
    let lock_op = match iter.next()? {
        Ok(Instruction::Op(op)) => op,
        _ => return None,
    };
    let lock = if lock_op == OP_CSV {
        DualTimeoutLock::Older(parse_csv_older_n(lock_instr)?)
    } else if lock_op == OP_CLTV {
        DualTimeoutLock::After(parse_cltv_after_n(lock_instr)?)
    } else {
        // Right keys / bare end / other → sandwich / multi-pk hash / etc.
        return None;
    };
    if iter.next().is_some() {
        return None;
    }
    Some((pubkeys, kind, digest, lock))
}

/// Parse nested CLEANSTACK-valid reverse combined hash+timeout
/// `and_v(v:hash(H), and_v(v:pk…, older(n)|after(n)))` leaf
/// (v:hash VERIFY + ≥ 1 all-`v:pk` CHECKSIGVERIFY + CSV|CLTV — single path
/// requiring **both** preimage and locktime; dual of pk-first combined
/// [`bare_tapscript_and_v_pk_hash_lock_template`]):
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUALVERIFY
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// <n> OP_CSV | OP_CLTV
/// ```
///
/// Distinct from reverse multi-key `and_v(v:hash, and_v(v:pk…))` (ends
/// CHECKSIG, no lock) / single `and_v(v:hash, pk)` (one CHECKSIG) /
/// pk-first combined `and_v(v:pk…, and_v(v:hash, older|after))` (keys
/// before hash) / sandwich (right keys after hash) / classic HTLC OR
/// dual-path / dual-timeout.
///
/// Witness: `<sig_last> … <sig_first> <preimage>` (preimage top so v:hash
/// runs first; reverse-key sigs for CHECKSIGVERIFY chain; CSV|CLTV consumes
/// no witness). Never invents sigs, preimages, or nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_hash_pk_lock_template(
    script: &bitcoin::Script,
) -> Option<PkHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    // v:hash fragment: SIZE 32 EQUALVERIFY HASHOP digest EQUALVERIFY
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
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }

    // ≥1 CHECKSIGVERIFY keys, then bare CSV|CLTV (type B terminal lock).
    // Disambiguate lock by *following* opcode: many `after(n)` heights also
    // parse as valid `older(n)` script nums — commit only when next is CSV or
    // CLTV (32-byte key pushes fail script_num and fall through as keys).
    let mut pubkeys = Vec::new();
    loop {
        let next = iter.next()?;
        if !pubkeys.is_empty() {
            if let Ok(instr) = next {
                let maybe_older = parse_csv_older_n(instr);
                let maybe_after = parse_cltv_after_n(instr);
                if maybe_older.is_some() || maybe_after.is_some() {
                    match iter.next()? {
                        Ok(Instruction::Op(op)) if op == OP_CSV => {
                            let older_n = maybe_older?;
                            if iter.next().is_some() {
                                return None;
                            }
                            return Some((pubkeys, kind, digest, DualTimeoutLock::Older(older_n)));
                        }
                        Ok(Instruction::Op(op)) if op == OP_CLTV => {
                            let after_n = maybe_after?;
                            if iter.next().is_some() {
                                return None;
                            }
                            return Some((pubkeys, kind, digest, DualTimeoutLock::After(after_n)));
                        }
                        // Not a terminal lock — not this template (do not treat
                        // lock-sized pushes as keys; keys are 32-byte x-only).
                        _ => return None,
                    }
                }
            }
        }
        let push = match next {
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
            // CHECKSIG (not VERIFY) → reverse multi-hash / and_v(v:hash, pk);
            // not this combined form.
            _ => return None,
        }
    }
}

/// Parse nested CLEANSTACK-valid lock-first combined hash+timeout
/// `and_v(v:older(n)|after(n), and_v(v:pk…, hash(H)))` leaf
/// (CSV|CLTV VERIFY prefix + ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL —
/// single path requiring **both** preimage and locktime; lock-order dual of
/// pk-first combined [`bare_tapscript_and_v_pk_hash_lock_template`]):
///
/// ```text
/// <n> OP_CSV OP_VERIFY | <n> OP_CLTV OP_VERIFY
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Distinct from reverse multi-key `and_v(v:older|after, and_v(v:pk…))` (ends
/// CHECKSIG, no hash) / single `and_v(v:older, pk)` / multi-pk hash (no lock
/// prefix) / pk-first combined `and_v(v:pk…, and_v(v:hash, older|after))`
/// (keys + hash VERIFY + terminal CSV|CLTV) / reverse combined
/// `and_v(v:hash, and_v(v:pk…, older|after))` (hash VERIFY prefix) /
/// pk+middle-lock+trailing-hash `and_v(v:pk…, and_v(v:older|after, hash))`
/// (keys before middle lock) / sandwich (right keys after middle lock) /
/// classic HTLC OR dual-path.
///
/// Witness: `<preimage> <sig_last> … <sig_first>` (preimage deepest; first
/// key's sig top so CHECKSIGVERIFY runs before bare hash EQUAL; CSV|CLTV
/// VERIFY consumes no witness). Never invents sigs, preimages, or
/// nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_lock_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<PkHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE, OP_VERIFY,
    };

    let mut iter = script.instructions();
    // Prefix v:older|after: <n> CSV|CLTV VERIFY
    let lock_instr = iter.next()?.ok()?;
    let lock_op = match iter.next()? {
        Ok(Instruction::Op(op)) => op,
        _ => return None,
    };
    let lock = if lock_op == OP_CSV {
        DualTimeoutLock::Older(parse_csv_older_n(lock_instr)?)
    } else if lock_op == OP_CLTV {
        DualTimeoutLock::After(parse_cltv_after_n(lock_instr)?)
    } else {
        return None;
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        _ => return None,
    }

    // ≥1 CHECKSIGVERIFY keys, then bare hash EQUAL (type B terminal).
    let mut pubkeys = Vec::new();
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
                        pubkeys.push(pk);
                    }
                    // CHECKSIG (not VERIFY) → reverse multi older/after (no hash).
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !pubkeys.is_empty() => {
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
    // Type B bare hash (EQUAL) — not EQUALVERIFY (would leave empty / wrong form).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pubkeys, kind, digest, lock))
}

/// Parse nested CLEANSTACK-valid pk + middle lock + trailing hash combined
/// hash+timeout `and_v(v:pk…, and_v(v:older(n)|after(n), hash(H)))` leaf
/// (≥ 1 all-`v:pk` CHECKSIGVERIFY + middle CSV|CLTV VERIFY + bare hash EQUAL —
/// single path requiring **both** preimage and locktime; lock-order dual of
/// lock-first combined [`bare_tapscript_and_v_lock_pk_hash_template`]):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// <n> OP_CSV OP_VERIFY | <n> OP_CLTV OP_VERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Distinct from sandwich `and_v(v:pk…, and_v(v:older|after|hash, pk…))`
/// (right keys after middle lock, no terminal bare hash) / pk-first combined
/// `and_v(v:pk…, and_v(v:hash, older|after))` (hash VERIFY then terminal
/// CSV|CLTV, no middle VERIFY) / multi-pk hash (no lock) /
/// `and_v(v:pk, older|after)` (no hash) / lock-first combined (lock prefix) /
/// reverse combined (hash VERIFY prefix) / classic HTLC OR dual-path.
///
/// Witness: `<preimage> <sig_last> … <sig_first>` (preimage deepest; first
/// key's sig top so CHECKSIGVERIFY runs before middle CSV|CLTV VERIFY then
/// bare hash EQUAL; lock consumes no witness). Never invents sigs, preimages,
/// or nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_pk_lock_hash_template(
    script: &bitcoin::Script,
) -> Option<PkHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CLTV, OP_CSV, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE, OP_VERIFY};

    let mut iter = script.instructions();
    let (pubkeys, first_after_left) = parse_and_v_left_checksigverify_keys(&mut iter)?;
    debug_assert!(!pubkeys.is_empty());

    // Middle v:older|after: <n> CSV|CLTV VERIFY (same shape as sandwich middle,
    // but terminal is bare hash EQUAL — not right keys).
    let maybe_older = parse_csv_older_n(first_after_left);
    let maybe_after = parse_cltv_after_n(first_after_left);
    if maybe_older.is_none() && maybe_after.is_none() {
        // OP_SIZE / key push / other → multi-pk hash / sandwich-hash / etc.
        return None;
    }
    let lock_op = match iter.next()? {
        Ok(Instruction::Op(op)) => op,
        _ => return None,
    };
    let lock = if lock_op == OP_CSV {
        DualTimeoutLock::Older(maybe_older?)
    } else if lock_op == OP_CLTV {
        DualTimeoutLock::After(maybe_after?)
    } else {
        return None;
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        // Terminal CSV|CLTV without VERIFY → multi-pk older/after / pk-first
        // combined (hash then bare lock) — not this middle-VERIFY form.
        _ => return None,
    }

    // Bare hash EQUAL terminal (type B).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        // Right keys after middle lock → sandwich, not this template.
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
        // EQUALVERIFY would leave wrong residual / non-type-B terminal.
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pubkeys, kind, digest, lock))
}

/// Parse nested CLEANSTACK-valid hash + middle lock + trailing pk combined
/// hash+timeout `and_v(v:hash(H), and_v(v:older(n)|after(n), pk…))` leaf
/// (v:hash VERIFY + middle CSV|CLTV VERIFY + ≥ 1 trailing keys ending
/// CHECKSIG — single path requiring **both** preimage and locktime; dual of
/// pk+middle-lock+trailing-hash with hash/pk order swapped):
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUALVERIFY
/// <n> OP_CSV OP_VERIFY | <n> OP_CLTV OP_VERIFY
/// (<xonly> OP_CHECKSIGVERIFY)*
/// <xonly> OP_CHECKSIG
/// ```
///
/// Distinct from reverse multi-hash `and_v(v:hash, and_v(v:pk…))` (no middle
/// lock) / single `and_v(v:hash, pk)` / reverse combined
/// `and_v(v:hash, and_v(v:pk…, older|after))` (keys then terminal bare CSV|
/// CLTV, all keys CHECKSIGVERIFY) / sandwich (left keys first) / lock-first
/// combined (lock prefix + keys + bare hash EQUAL) / classic HTLC OR.
///
/// Witness: `<sig_last> … <sig_first> <preimage>` (preimage top so v:hash
/// runs first; middle CSV|CLTV VERIFY consumes no witness; reverse-key sigs
/// for trailing CHECKSIG chain). Never invents sigs, preimages, or
/// nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_hash_lock_pk_template(
    script: &bitcoin::Script,
) -> Option<PkHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CLTV, OP_CSV, OP_EQUALVERIFY, OP_SIZE, OP_VERIFY};

    let mut iter = script.instructions();
    // v:hash fragment: SIZE 32 EQUALVERIFY HASHOP digest EQUALVERIFY
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
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }

    // Middle v:older|after: <n> CSV|CLTV VERIFY (not bare terminal CSV|CLTV —
    // that is reverse combined with keys before lock).
    let lock_instr = iter.next()?.ok()?;
    let maybe_older = parse_csv_older_n(lock_instr);
    let maybe_after = parse_cltv_after_n(lock_instr);
    if maybe_older.is_none() && maybe_after.is_none() {
        // Key push / other → reverse multi-hash / and_v(v:hash, pk) / reverse
        // combined keys-before-lock — not this middle-lock form.
        return None;
    }
    let lock_op = match iter.next()? {
        Ok(Instruction::Op(op)) => op,
        _ => return None,
    };
    let lock = if lock_op == OP_CSV {
        DualTimeoutLock::Older(maybe_older?)
    } else if lock_op == OP_CLTV {
        DualTimeoutLock::After(maybe_after?)
    } else {
        return None;
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        // Bare CSV|CLTV without VERIFY after hash → not this form (and reverse
        // combined has keys between hash and lock anyway).
        _ => return None,
    }

    // Trailing keys: n ≥ 1 ending CHECKSIG (type B terminal).
    let pubkeys = parse_and_v_pk_checksig_tail_n1(&mut iter)?;
    debug_assert!(!pubkeys.is_empty());
    Some((pubkeys, kind, digest, lock))
}

/// Parse nested CLEANSTACK-valid lock + middle hash + trailing pk combined
/// hash+timeout `and_v(v:older(n)|after(n), and_v(v:hash(H), pk…))` leaf
/// (CSV|CLTV VERIFY prefix + v:hash VERIFY + ≥ 1 trailing keys ending
/// CHECKSIG — single path requiring **both** preimage and locktime; lock-
/// order dual of hash+middle-lock+trailing-pk):
///
/// ```text
/// <n> OP_CSV OP_VERIFY | <n> OP_CLTV OP_VERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUALVERIFY
/// (<xonly> OP_CHECKSIGVERIFY)*
/// <xonly> OP_CHECKSIG
/// ```
///
/// Distinct from reverse multi older/after `and_v(v:older|after, and_v(v:pk…))`
/// (no hash) / lock-first combined `and_v(v:older|after, and_v(v:pk…, hash))`
/// (keys then bare hash EQUAL) / reverse multi-hash (no lock) / sandwich
/// (left keys first) / hash+middle-lock+trailing-pk (hash prefix) / classic
/// HTLC OR.
///
/// Witness: `<sig_last> … <sig_first> <preimage>` (preimage top so v:hash
/// runs after lock VERIFY; reverse-key sigs for trailing CHECKSIG chain).
/// Never invents sigs, preimages, or nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_lock_hash_pk_template(
    script: &bitcoin::Script,
) -> Option<PkHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CLTV, OP_CSV, OP_EQUALVERIFY, OP_SIZE, OP_VERIFY};

    let mut iter = script.instructions();
    // Prefix v:older|after: <n> CSV|CLTV VERIFY
    let lock_instr = iter.next()?.ok()?;
    let lock_op = match iter.next()? {
        Ok(Instruction::Op(op)) => op,
        _ => return None,
    };
    let lock = if lock_op == OP_CSV {
        DualTimeoutLock::Older(parse_csv_older_n(lock_instr)?)
    } else if lock_op == OP_CLTV {
        DualTimeoutLock::After(parse_cltv_after_n(lock_instr)?)
    } else {
        return None;
    };
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        _ => return None,
    }

    // Middle v:hash VERIFY (not keys → reverse multi older/after).
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
    // Type-V hash (EQUALVERIFY) then trailing keys — not bare EQUAL (that is
    // lock-first combined with keys before hash).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }

    let pubkeys = parse_and_v_pk_checksig_tail_n1(&mut iter)?;
    debug_assert!(!pubkeys.is_empty());
    Some((pubkeys, kind, digest, lock))
}
