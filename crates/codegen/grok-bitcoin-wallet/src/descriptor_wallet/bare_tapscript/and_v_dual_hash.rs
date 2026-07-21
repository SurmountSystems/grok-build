//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.
//!
//! **PR5 keep set (canonical dual-hash `and_v` only — no product consumer for the
//! full permutation farm):**
//! - `pk + dual-hash + lock` — [`bare_tapscript_and_v_pk_dual_hash_lock_template`]
//! - `pk + dual-hash` — [`bare_tapscript_and_v_pk_dual_hash_template`]
//! - `dual-hash + pk` — [`bare_tapscript_and_v_dual_hash_pk_template`]
//! - sandwich `hash + pk + hash` — [`bare_tapscript_and_v_hash_pk_hash_template`]
//! - reverse `dual-hash + pk + lock` — [`bare_tapscript_and_v_dual_hash_pk_lock_template`]
//!
//! Pruned: lock-first / middle-lock / exotic H1–H2 interleavings
//! (`hash_pk_hash_lock`, `hash_pk_lock_hash`, `pk_hash_lock_hash`,
//! `pk_lock_dual_hash`, `lock_pk_dual_hash`, `lock_dual_hash_pk`,
//! `hash_lock_hash_pk`, `dual_hash_lock_pk`, `hash_lock_pk_hash`,
//! `lock_hash_pk_hash`).

use super::{
    DualTimeoutLock, TapscriptHashKind, parse_and_v_pk_checksig_tail_n1, parse_cltv_after_n,
    parse_csv_older_n,
};

/// (keys, kind1, digest1, kind2, digest2, lock) for dual-hash+timeout
/// `and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after)))`.
pub(crate) type PkDualHashLockParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
    TapscriptHashKind,
    Vec<u8>,
    DualTimeoutLock,
);

/// Parse nested CLEANSTACK-valid dual-hash+timeout combined
/// `and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older(n)|after(n))))` leaf
/// (≥ 1 all-`v:pk` CHECKSIGVERIFY + v:hash VERIFY + v:hash VERIFY + CSV|CLTV —
/// single path requiring **both** matching 32-byte PSBT preimages **and**
/// already-present locktime, not OR like dual-hash `or_i` / HTLC):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP1> <digest1> OP_EQUALVERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP2> <digest2> OP_EQUALVERIFY
/// <n> OP_CSV | OP_CLTV
/// ```
///
/// Distinct from single-hash combined `and_v(v:pk…, and_v(v:hash, older|after))`
/// (one hash only) / multi-pk hash (one hash, no lock) / dual-hash or_i
/// (OR dual-path, bare EQUAL) / sandwich / classic HTLC / reverse combined /
/// dual-hash AND without lock
/// (`and_v(v:pk…, and_v(v:hash, hash))` ends bare EQUAL — see
/// [`bare_tapscript_and_v_pk_dual_hash_template`]).
///
/// Witness: `<preimage2> <preimage1> <sig_last> … <sig_first>` (preimage2
/// deepest; first key's sig top so CHECKSIGVERIFY runs first, then H1 VERIFY,
/// then H2 VERIFY, then CSV|CLTV). Never invents sigs, preimages, or
/// nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_pk_dual_hash_lock_template(
    script: &bitcoin::Script,
) -> Option<PkDualHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    // ≥1 CHECKSIGVERIFY keys, then OP_SIZE starts first v:hash.
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

    // First v:hash (SIZE already consumed): 32 EQUALVERIFY HASHOP dig EQUALVERIFY
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind1 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest1_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest1 = digest1_push.as_bytes();
    if digest1.len() != kind1.expected_digest_len() {
        return None;
    }
    let digest1 = digest1.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL after first hash → dual-hash AND without lock / multi-pk
        // hash shape — not this dual-hash+lock form.
        _ => return None,
    }

    // Second v:hash VERIFY (required — single-hash combined has lock here).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        // CSV|CLTV after one hash → single-hash combined pk+hash+lock.
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
    let kind2 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest2_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest2 = digest2_push.as_bytes();
    if digest2.len() != kind2.expected_digest_len() {
        return None;
    }
    let digest2 = digest2.to_vec();
    // Type-V second hash (EQUALVERIFY) — trailing lock needs VERIFY form.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL → dual-hash AND without lock (no lock terminal).
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
        // Third hash / right keys / other → not this template.
        return None;
    };
    if iter.next().is_some() {
        return None;
    }
    Some((pubkeys, kind1, digest1, kind2, digest2, lock))
}

/// (keys, kind1, digest1, kind2, digest2) for dual-hash AND without lock
/// `and_v(v:pk…, and_v(v:hash(H1), hash(H2)))`.
pub(crate) type PkDualHashParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
    TapscriptHashKind,
    Vec<u8>,
);

/// Parse nested CLEANSTACK-valid dual-hash AND without lock
/// `and_v(v:pk…, and_v(v:hash(H1), hash(H2)))` leaf (≥ 1 all-`v:pk`
/// CHECKSIGVERIFY + v:hash VERIFY + bare hash EQUAL — single path requiring
/// **both** matching 32-byte PSBT preimages, no locktime; not OR like dual-hash
/// `or_i` / HTLC):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP1> <digest1> OP_EQUALVERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP2> <digest2> OP_EQUAL
/// ```
///
/// Distinct from dual-hash+timeout
/// `and_v(v:pk…, and_v(v:hash(H1), and_v(v:hash(H2), older|after)))` (second
/// hash VERIFY + CSV|CLTV) / single-hash `and_v(v:pk, hash)` / multi-pk hash
/// (one hash) / dual-hash or_i (OR dual-path) / sandwich / classic HTLC.
///
/// Witness: `<preimage2> <preimage1> <sig_last> … <sig_first>` (preimage2
/// deepest; first key's sig top so CHECKSIGVERIFY runs first, then H1 VERIFY,
/// then bare H2 EQUAL). Never invents sigs or preimages.
pub(crate) fn bare_tapscript_and_v_pk_dual_hash_template(
    script: &bitcoin::Script,
) -> Option<PkDualHashParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    // ≥1 CHECKSIGVERIFY keys, then OP_SIZE starts first v:hash.
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

    // First v:hash (SIZE already consumed): 32 EQUALVERIFY HASHOP dig EQUALVERIFY
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind1 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest1_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest1 = digest1_push.as_bytes();
    if digest1.len() != kind1.expected_digest_len() {
        return None;
    }
    let digest1 = digest1.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL after first hash → single-hash and_v(v:pk…, hash) /
        // multi-pk hash — not dual-hash AND.
        _ => return None,
    }

    // Second bare hash (type B EQUAL terminal).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        // CSV|CLTV / right keys after one hash → other templates.
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
    let kind2 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest2_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest2 = digest2_push.as_bytes();
    if digest2.len() != kind2.expected_digest_len() {
        return None;
    }
    let digest2 = digest2.to_vec();
    // Type-B second hash (EQUAL) — dual-hash AND without lock terminal.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        // EQUALVERIFY → dual-hash+timeout (needs trailing lock) / wrong form.
        _ => return None,
    }
    if iter.next().is_some() {
        // Trailing lock / right keys / third hash → not this template.
        return None;
    }
    Some((pubkeys, kind1, digest1, kind2, digest2))
}

/// Parse nested CLEANSTACK-valid hash-first dual-hash AND without lock
/// `and_v(v:hash(H1), and_v(v:hash(H2), pk…))` leaf (two v:hash VERIFY +
/// ≥ 1 trailing keys ending CHECKSIG — single path requiring **both**
/// matching 32-byte PSBT preimages + all key sigs, no locktime; not OR like
/// dual-hash `or_i` / HTLC):
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP1> <digest1> OP_EQUALVERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP2> <digest2> OP_EQUALVERIFY
/// (<xonly> OP_CHECKSIGVERIFY)*   // intermediate keys
/// <xonly> OP_CHECKSIG            // ≥ 1 total
/// ```
///
/// Dual of pk-first dual-hash AND
/// [`bare_tapscript_and_v_pk_dual_hash_template`] (`and_v(v:pk…, and_v(v:hash,
/// hash))` — keys then hashes). Distinct from reverse multi-hash
/// `and_v(v:hash, and_v(v:pk…))` (one hash only) / single `and_v(v:hash, pk)` /
/// dual-hash+timeout / sandwich single-hash / hash+pk+hash sandwich dual-hash /
/// dual-hash or_i.
///
/// Witness: reverse(keys)+preimage2+preimage1 (preimage1 top so H1 VERIFY
/// runs first, then H2 VERIFY, then CHECKSIG tail). Never invents sigs or
/// preimages.
pub(crate) fn bare_tapscript_and_v_dual_hash_pk_template(
    script: &bitcoin::Script,
) -> Option<PkDualHashParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();

    // First v:hash: SIZE 32 EQUALVERIFY HASHOP dig EQUALVERIFY
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
    let kind1 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest1_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest1 = digest1_push.as_bytes();
    if digest1.len() != kind1.expected_digest_len() {
        return None;
    }
    let digest1 = digest1.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL → single bare hash leaf, not dual-hash.
        _ => return None,
    }

    // Second v:hash: SIZE 32 EQUALVERIFY HASHOP dig EQUALVERIFY
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        // Key push / CSV|CLTV after one hash → reverse multi-hash /
        // reverse combined / hash+lock+pk / hash+pk+hash sandwich dual-hash
        // — not dual-hash hash-first.
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
    let kind2 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest2_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest2 = digest2_push.as_bytes();
    if digest2.len() != kind2.expected_digest_len() {
        return None;
    }
    let digest2 = digest2.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL after second hash → no trailing keys (not this form).
        _ => return None,
    }

    // Trailing keys ending CHECKSIG (n ≥ 1).
    let pubkeys = parse_and_v_pk_checksig_tail_n1(&mut iter)?;
    Some((pubkeys, kind1, digest1, kind2, digest2))
}

/// Parse nested CLEANSTACK-valid hash+pk+hash sandwich dual-hash AND without
/// lock **`and_v(v:hash(H1), and_v(v:pk…, hash(H2)))`** leaf (leading v:hash
/// VERIFY + ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare hash EQUAL — single path
/// requiring **both** matching 32-byte PSBT preimages + all key sigs, no
/// locktime; not OR like dual-hash `or_i` / HTLC):
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP1> <digest1> OP_EQUALVERIFY
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP2> <digest2> OP_EQUAL
/// ```
///
/// Distinct from hash-first dual-hash AND
/// [`bare_tapscript_and_v_dual_hash_pk_template`] (two v:hash then CHECKSIG
/// tail) / pk-first dual-hash AND (keys then two hashes) / reverse multi-hash
/// `and_v(v:hash, and_v(v:pk…))` (one hash, ends CHECKSIG) / single
/// `and_v(v:hash, pk)` / multi-key sandwich single-hash
/// `and_v(v:pk…, and_v(v:hash, pk…))` / dual-hash+timeout / dual-hash or_i.
///
/// Witness: preimage2 + reverse(keys) + preimage1 (preimage1 top so H1 VERIFY
/// runs first; preimage2 deepest for bare H2 EQUAL after keys). Never invents
/// sigs or preimages.
pub(crate) fn bare_tapscript_and_v_hash_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<PkDualHashParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();

    // Leading v:hash(H1): SIZE 32 EQUALVERIFY HASHOP dig EQUALVERIFY
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
    let kind1 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest1_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest1 = digest1_push.as_bytes();
    if digest1.len() != kind1.expected_digest_len() {
        return None;
    }
    let digest1 = digest1.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL → single bare hash leaf, not this form.
        _ => return None,
    }

    // Middle ≥1 all-v:pk CHECKSIGVERIFY keys, then OP_SIZE starts bare H2.
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
                    // CHECKSIG (not VERIFY) → reverse multi-hash / single
                    // and_v(v:hash, pk) ending CHECKSIG — not sandwich dual-hash.
                    _ => return None,
                }
            }
            Ok(Instruction::Op(op)) if op == OP_SIZE && !pubkeys.is_empty() => {
                break;
            }
            // Second hash VERIFY (SIZE already would have matched) / CSV|CLTV
            // / other after no keys → hash-first dual-hash / reverse combined.
            _ => return None,
        }
    }

    // Trailing bare hash(H2): 32 EQUALVERIFY HASHOP dig EQUAL (SIZE consumed).
    match iter.next()? {
        Ok(Instruction::PushBytes(b)) if b.as_bytes() == [32u8] => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        _ => return None,
    }
    let kind2 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest2_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest2 = digest2_push.as_bytes();
    if digest2.len() != kind2.expected_digest_len() {
        return None;
    }
    let digest2 = digest2.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUAL => {}
        // EQUALVERIFY → sandwich dual-hash+timeout (needs trailing lock) /
        // wrong form.
        _ => return None,
    }
    if iter.next().is_some() {
        // Trailing lock / right keys / third hash → not this template.
        return None;
    }
    Some((pubkeys, kind1, digest1, kind2, digest2))
}

/// Parse nested CLEANSTACK-valid hash-first dual-hash+timeout
/// **`and_v(v:hash(H1), and_v(v:hash(H2), and_v(v:pk…, older(n)|after(n))))`**
/// leaf (two v:hash VERIFY + ≥ 1 all-`v:pk` CHECKSIGVERIFY + bare CSV|CLTV —
/// dual of pk-first dual-hash+timeout; single path requiring **both** matching
/// 32-byte PSBT preimages **and** already-present locktime, not OR like
/// dual-hash `or_i` / HTLC):
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP1> <digest1> OP_EQUALVERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP2> <digest2> OP_EQUALVERIFY
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// <n> OP_CSV | OP_CLTV
/// ```
///
/// Distinct from pk-first dual-hash+timeout
/// [`bare_tapscript_and_v_pk_dual_hash_lock_template`] (keys then two hashes
/// then lock) / hash-first dual-hash AND without lock
/// [`bare_tapscript_and_v_dual_hash_pk_template`] (ends CHECKSIG, no lock) /
/// reverse combined single-hash
/// [`bare_tapscript_and_v_hash_pk_lock_template`] (one hash only) / sandwich
/// dual-hash (bare EQUAL, no lock) / sandwich dual-hash+timeout
/// `bare_tapscript_and_v_hash_pk_hash_lock_template` (pruned) (hash+pk+hash+lock) /
/// hash+pk+lock+hash sandwich dual-hash+timeout
/// `bare_tapscript_and_v_hash_pk_lock_hash_template` (pruned) (middle lock VERIFY +
/// trailing H2 EQUAL) / dual-hash or_i / HTLC.
///
/// Witness: reverse(keys)+preimage2+preimage1 (preimage1 top so H1 VERIFY
/// runs first, then H2 VERIFY, then CHECKSIGVERIFY chain, then CSV|CLTV).
/// Never invents sigs, preimages, or nSequence/nLockTime.
pub(crate) fn bare_tapscript_and_v_dual_hash_pk_lock_template(
    script: &bitcoin::Script,
) -> Option<PkDualHashLockParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV, OP_CSV, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();

    // First v:hash: SIZE 32 EQUALVERIFY HASHOP dig EQUALVERIFY
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
    let kind1 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest1_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest1 = digest1_push.as_bytes();
    if digest1.len() != kind1.expected_digest_len() {
        return None;
    }
    let digest1 = digest1.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL → single bare hash leaf, not dual-hash.
        _ => return None,
    }

    // Second v:hash: SIZE 32 EQUALVERIFY HASHOP dig EQUALVERIFY
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        // Key push / CSV|CLTV after one hash → reverse multi-hash /
        // reverse combined / hash+lock+pk / sandwich dual-hash — not this form.
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
    let kind2 = match iter.next()? {
        Ok(Instruction::Op(op)) => TapscriptHashKind::from_hash_op(op)?,
        _ => return None,
    };
    let digest2_push = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let digest2 = digest2_push.as_bytes();
    if digest2.len() != kind2.expected_digest_len() {
        return None;
    }
    let digest2 = digest2.to_vec();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
        // Bare EQUAL after second hash → no trailing keys (not this form).
        _ => return None,
    }

    // ≥1 CHECKSIGVERIFY keys, then bare CSV|CLTV (type B terminal lock).
    // Disambiguate lock by *following* opcode (same as reverse combined /
    // hash+pk+lock): many after(n) heights also parse as older(n).
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
                            return Some((
                                pubkeys,
                                kind1,
                                digest1,
                                kind2,
                                digest2,
                                DualTimeoutLock::Older(older_n),
                            ));
                        }
                        Ok(Instruction::Op(op)) if op == OP_CLTV => {
                            let after_n = maybe_after?;
                            if iter.next().is_some() {
                                return None;
                            }
                            return Some((
                                pubkeys,
                                kind1,
                                digest1,
                                kind2,
                                digest2,
                                DualTimeoutLock::After(after_n),
                            ));
                        }
                        // Not a terminal lock — not this template.
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
            // CHECKSIG (not VERIFY) → hash-first dual-hash AND without lock
            // (ends CHECKSIG, no lock) — not this dual-hash+timeout form.
            _ => return None,
        }
    }
}
