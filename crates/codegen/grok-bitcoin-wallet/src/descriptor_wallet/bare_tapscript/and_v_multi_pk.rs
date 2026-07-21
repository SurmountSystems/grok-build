//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

use super::{TapscriptHashKind, parse_cltv_after_n, parse_csv_older_n};

/// Parse nested CLEANSTACK-valid multi-key
/// `and_v(and_v(v:pk…), older(n))` leaf (n ≥ 2 keys, all `v:pk`):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 2
/// <n> OP_CSV
/// ```
///
/// Returns `(pubkeys, older_n)` when the script is exactly that template.
/// Otherwise `None`.
///
/// # Why this is completeable
///
/// Each `v:pk` is CHECKSIGVERIFY (leaves nothing). Trailing bare `older(n)`
/// is type-B CSV and leaves a single bool — CLEANSTACK-valid. Distinct from
/// single-key `and_v(v:pk, older)` (exactly one CHECKSIGVERIFY), bare
/// and_v n-of-n (trailing CHECKSIG, no CSV), and nested or_c/or_i+older
/// (control-flow opcodes).
///
/// Witness script inputs (before leaf + control block): reverse key order
/// — last key's sig first (bottom), first key's sig top so the first
/// CHECKSIGVERIFY consumes it. Requires **all** n matching `tap_script_sigs`
/// **and** unsigned-tx nSequence that satisfies BIP-112 for `n` — never
/// invents either (CHECKSIGVERIFY rejects empty BIP-342 placeholders).
pub(crate) fn bare_tapscript_and_v_multi_pk_older_template(
    script: &bitcoin::Script,
) -> Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    // Collect ≥ 2 `<xonly> CHECKSIGVERIFY` pairs, then `<n> CSV`.
    loop {
        let next = iter.next()?;
        // After ≥ 2 keys, the next non-key instruction starts older(n).
        if pubkeys.len() >= 2 {
            if let Ok(instr) = next {
                if let Some(older_n) = parse_csv_older_n(instr) {
                    match iter.next()? {
                        Ok(Instruction::Op(op)) if op == OP_CSV => {}
                        _ => return None,
                    }
                    if iter.next().is_some() {
                        return None;
                    }
                    return Some((pubkeys, older_n));
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
            _ => return None,
        }
    }
}

/// Parse nested CLEANSTACK-valid multi-key
/// `and_v(and_v(v:pk…), after(n))` leaf (n ≥ 2 keys, all `v:pk`):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 2
/// <n> OP_CLTV
/// ```
///
/// Dual of [`bare_tapscript_and_v_multi_pk_older_template`] with BIP-65 CLTV.
/// Returns `(pubkeys, after_n)` when the script is exactly that template.
/// Witness: reverse-key sigs. Requires all n sigs + already-present
/// nLockTime/nSequence that satisfy BIP-65 — never invents either.
pub(crate) fn bare_tapscript_and_v_multi_pk_after_template(
    script: &bitcoin::Script,
) -> Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, u32)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    loop {
        let next = iter.next()?;
        if pubkeys.len() >= 2 {
            if let Ok(instr) = next {
                if let Some(after_n) = parse_cltv_after_n(instr) {
                    match iter.next()? {
                        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
                        _ => return None,
                    }
                    if iter.next().is_some() {
                        return None;
                    }
                    return Some((pubkeys, after_n));
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
            _ => return None,
        }
    }
}

/// Parse nested CLEANSTACK-valid multi-key
/// `and_v(and_v(v:pk…), hash(H))` leaf (n ≥ 2 keys, all `v:pk`):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 2
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Dual of multi-key older/after with trailing bare hash. Returns
/// `(pubkeys, kind, digest)` when the script is exactly that template.
///
/// Witness script inputs: `<preimage> <sig_last> … <sig_first>` (preimage
/// deepest; first key's sig top so CHECKSIGVERIFY runs first). Requires
/// **all** n matching `tap_script_sigs` **and** a matching 32-byte PSBT
/// preimage — never invents either. Distinct from single-key
/// `and_v(v:pk, hash)`, bare multi and_v (trailing CHECKSIG), and
/// nested or_c/or_i+hash.
pub(crate) fn bare_tapscript_and_v_multi_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    let mut pubkeys = Vec::new();

    loop {
        let next = iter.next()?;
        // After ≥ 2 keys, bare hash fragment starts with OP_SIZE.
        if pubkeys.len() >= 2 {
            if let Ok(Instruction::Op(op)) = next {
                if op == OP_SIZE {
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
                    if iter.next().is_some() {
                        return None;
                    }
                    return Some((pubkeys, kind, digest));
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
            _ => return None,
        }
    }
}

/// Parse trailing multi-key `and_v(v:pk…, pk)` fragment: ≥1 CHECKSIGVERIFY +
/// final CHECKSIG (`n ≥ 2` keys total). Returns pubkeys in script order.
///
/// Shared by reverse multi-key
/// `and_v(v:older|after|hash, and_v(v:pk…))` templates.
pub(crate) fn parse_and_v_multi_pk_checksig_tail(
    iter: &mut bitcoin::blockdata::script::Instructions<'_>,
) -> Option<Vec<bitcoin::secp256k1::XOnlyPublicKey>> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};

    let mut pubkeys = Vec::new();
    // Pattern: (<xonly> CHECKSIGVERIFY)+ <xonly> CHECKSIG  with n ≥ 2.
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
                if iter.next().is_some() {
                    return None;
                }
                // Need ≥ 1 CHECKSIGVERIFY before final CHECKSIG ⇒ n ≥ 2.
                if pubkeys.len() < 2 {
                    return None;
                }
                return Some(pubkeys);
            }
            _ => return None,
        }
    }
}

/// Parse nested CLEANSTACK-valid multi-key reverse
/// `and_v(v:older(n), and_v(v:pk…, pk))` leaf (n ≥ 2 keys):
///
/// ```text
/// <n> OP_CSV OP_VERIFY
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// <xonly> OP_CHECKSIG
/// ```
///
/// Dual of pk-first multi-key
/// [`bare_tapscript_and_v_multi_pk_older_template`] (CSV trailing, all
/// CHECKSIGVERIFY). Distinct from single-key `and_v(v:older, pk)` (one
/// CHECKSIG, no CHECKSIGVERIFY) and bare multi and_v (no CSV prefix).
///
/// Witness: reverse-key sigs (last key deepest). Requires **all** n sigs +
/// already-present nSequence satisfying BIP-112 — never invents either.
pub(crate) fn bare_tapscript_and_v_older_multi_pk_template(
    script: &bitcoin::Script,
) -> Option<(u32, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CSV, OP_VERIFY};

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
    let pubkeys = parse_and_v_multi_pk_checksig_tail(&mut iter)?;
    Some((older_n, pubkeys))
}

/// Parse nested CLEANSTACK-valid multi-key reverse
/// `and_v(v:after(n), and_v(v:pk…, pk))` leaf (n ≥ 2 keys):
///
/// ```text
/// <n> OP_CLTV OP_VERIFY
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// <xonly> OP_CHECKSIG
/// ```
///
/// Dual of pk-first multi-key
/// [`bare_tapscript_and_v_multi_pk_after_template`] with BIP-65 CLTV + VERIFY
/// prefix. Distinct from single-key `and_v(v:after, pk)`.
///
/// Witness: reverse-key sigs. Requires all n sigs + already-present
/// nLockTime/nSequence that satisfy BIP-65 — never invents either.
pub(crate) fn bare_tapscript_and_v_after_multi_pk_template(
    script: &bitcoin::Script,
) -> Option<(u32, Vec<bitcoin::secp256k1::XOnlyPublicKey>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CLTV, OP_VERIFY};

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
    let pubkeys = parse_and_v_multi_pk_checksig_tail(&mut iter)?;
    Some((after_n, pubkeys))
}

/// Parse nested CLEANSTACK-valid multi-key reverse
/// `and_v(v:hash(H), and_v(v:pk…, pk))` leaf (n ≥ 2 keys):
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUALVERIFY
/// (<xonly> OP_CHECKSIGVERIFY)+   // ≥ 1
/// <xonly> OP_CHECKSIG
/// ```
///
/// Dual of pk-first multi-key
/// [`bare_tapscript_and_v_multi_pk_hash_template`] (hash trailing EQUAL) and
/// multi-key dual of single-key [`bare_tapscript_and_v_hash_pk_template`].
///
/// Witness: `<sig_last> … <sig_first> <preimage>` (preimage top so v:hash
/// runs first; reverse-key sigs for CHECKSIGVERIFY chain). Requires all n
/// sigs + matching 32-byte PSBT preimage — never invents either.
pub(crate) fn bare_tapscript_and_v_hash_multi_pk_template(
    script: &bitcoin::Script,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_EQUALVERIFY, OP_SIZE};

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
    let pubkeys = parse_and_v_multi_pk_checksig_tail(&mut iter)?;
    Some((pubkeys, kind, digest))
}

/// Parse a right-side multi-pk checksig tail allowing **n ≥ 1** keys:
/// optional `(CHECKSIGVERIFY)+` then final `CHECKSIG`. Dual of
/// [`parse_and_v_multi_pk_checksig_tail`] which requires n ≥ 2.
///
/// Shared by sandwich multi-key
/// `and_v(v:pk…, and_v(v:older|after|hash, pk…))` right arms (right may be a
/// single bare CHECKSIG after the middle VERIFY fragment).
pub(crate) fn parse_and_v_pk_checksig_tail_n1(
    iter: &mut bitcoin::blockdata::script::Instructions<'_>,
) -> Option<Vec<bitcoin::secp256k1::XOnlyPublicKey>> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};

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
                if iter.next().is_some() {
                    return None;
                }
                // n ≥ 1 (single bare CHECKSIG is valid for sandwich right).
                return Some(pubkeys);
            }
            _ => return None,
        }
    }
}

/// Parse one-or-more leading `v:pk` CHECKSIGVERIFY keys until a non-key
/// instruction. Returns `(left_keys, next_instruction)`. Used by sandwich
/// templates that place CSV|CLTV|hash VERIFY between left and right keys.
pub(crate) fn parse_and_v_left_checksigverify_keys<'a>(
    iter: &mut bitcoin::blockdata::script::Instructions<'a>,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    bitcoin::blockdata::script::Instruction<'a>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::OP_CHECKSIGVERIFY;

    let mut left = Vec::new();
    loop {
        let next = iter.next()?;
        match next {
            // Continue left arm: 32-byte x-only + CHECKSIGVERIFY.
            Ok(Instruction::PushBytes(b)) if b.as_bytes().len() == 32 => {
                let pk = bitcoin::secp256k1::XOnlyPublicKey::from_slice(b.as_bytes()).ok()?;
                match iter.next()? {
                    Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                        left.push(pk);
                    }
                    // Left arm must be VERIFY chain only — final CHECKSIG means
                    // bare and_v (no middle lock/hash), not sandwich.
                    _ => return None,
                }
            }
            // After ≥ 1 left key, non-key instruction starts middle fragment
            // (locktime push / OP_SIZE for hash).
            Ok(instr) if !left.is_empty() => return Some((left, instr)),
            _ => return None,
        }
    }
}

/// Parse nested CLEANSTACK-valid multi-key **sandwich**
/// `and_v(v:pk…, and_v(v:older(n), pk…))` leaf (left ≥ 1, right ≥ 1):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // left ≥ 1
/// <n> OP_CSV OP_VERIFY
/// (<xonly> OP_CHECKSIGVERIFY)*   // right intermediate
/// <xonly> OP_CHECKSIG            // right ≥ 1 total
/// ```
///
/// Classic 2-of-2: `and_v(v:pk(A), and_v(v:older(n), pk(B)))`. Distinct from
/// pk-first multi (`… CSV` trailing, no VERIFY, all keys left) and reverse
/// multi (CSV VERIFY prefix, zero left keys).
///
/// Witness: reverse(right) then reverse(left) so left[0] is top (executed
/// first). Requires **all** left+right sigs + already-present nSequence
/// satisfying BIP-112 — never invents either.
pub(crate) fn bare_tapscript_and_v_multi_pk_older_multi_pk_template(
    script: &bitcoin::Script,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    u32,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CSV, OP_VERIFY};

    let mut iter = script.instructions();
    let (left, first_after_left) = parse_and_v_left_checksigverify_keys(&mut iter)?;
    // Helpers already require ≥1 key per arm; debug-only invariants.
    debug_assert!(!left.is_empty());
    let older_n = parse_csv_older_n(first_after_left)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        _ => return None,
    }
    let right = parse_and_v_pk_checksig_tail_n1(&mut iter)?;
    debug_assert!(!right.is_empty());
    Some((left, older_n, right))
}

/// Parse nested CLEANSTACK-valid multi-key sandwich
/// `and_v(v:pk…, and_v(v:after(n), pk…))` leaf (left ≥ 1, right ≥ 1):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // left ≥ 1
/// <n> OP_CLTV OP_VERIFY
/// (<xonly> OP_CHECKSIGVERIFY)*
/// <xonly> OP_CHECKSIG
/// ```
///
/// Dual of [`bare_tapscript_and_v_multi_pk_older_multi_pk_template`] with
/// BIP-65 CLTV. Distinct from pk-first multi-after and reverse multi-after.
///
/// Witness: reverse(right)+reverse(left). Requires all sigs + already-present
/// nLockTime/nSequence that satisfy BIP-65 — never invents either.
pub(crate) fn bare_tapscript_and_v_multi_pk_after_multi_pk_template(
    script: &bitcoin::Script,
) -> Option<(
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    u32,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CLTV, OP_VERIFY};

    let mut iter = script.instructions();
    let (left, first_after_left) = parse_and_v_left_checksigverify_keys(&mut iter)?;
    debug_assert!(!left.is_empty());
    let after_n = parse_cltv_after_n(first_after_left)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_VERIFY => {}
        _ => return None,
    }
    let right = parse_and_v_pk_checksig_tail_n1(&mut iter)?;
    debug_assert!(!right.is_empty());
    Some((left, after_n, right))
}

/// Sandwich multi-hash parse result: `(left_keys, kind, digest, right_keys)`.
pub(crate) type SandwichMultiPkHashParts = (
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    TapscriptHashKind,
    Vec<u8>,
    Vec<bitcoin::secp256k1::XOnlyPublicKey>,
);

/// Parse nested CLEANSTACK-valid multi-key sandwich
/// `and_v(v:pk…, and_v(v:hash(H), pk…))` leaf (left ≥ 1, right ≥ 1):
///
/// ```text
/// (<xonly> OP_CHECKSIGVERIFY)+   // left ≥ 1
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUALVERIFY
/// (<xonly> OP_CHECKSIGVERIFY)*
/// <xonly> OP_CHECKSIG
/// ```
///
/// Dual of sandwich older/after with middle v:hash. Distinct from reverse
/// multi-hash (hash prefix, zero left) and pk-first multi-hash (trailing
/// bare EQUAL hash, all keys left).
///
/// Witness: `<sig_right_last>…<sig_right_first> <preimage>
/// <sig_left_last>…<sig_left_first>` so left[0] is top (runs first), then
/// preimage after left VERIFY chain, then right sigs. Requires all sigs +
/// matching 32-byte PSBT preimage — never invents either.
pub(crate) fn bare_tapscript_and_v_multi_pk_hash_multi_pk_template(
    script: &bitcoin::Script,
) -> Option<SandwichMultiPkHashParts> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    let (left, first_after_left) = parse_and_v_left_checksigverify_keys(&mut iter)?;
    debug_assert!(!left.is_empty());
    // Middle v:hash: SIZE 32 EQUALVERIFY HASHOP digest EQUALVERIFY
    match first_after_left {
        Instruction::Op(op) if op == OP_SIZE => {}
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
    let right = parse_and_v_pk_checksig_tail_n1(&mut iter)?;
    debug_assert!(!right.is_empty());
    Some((left, kind, digest, right))
}
