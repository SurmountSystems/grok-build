//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

use super::{TapscriptHashKind, parse_cltv_after_n, parse_csv_older_n};

/// Parse nested CLEANSTACK-valid
/// `and_v(or_c(pk(A), v:pk(B)), older(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIGVERIFY
/// OP_ENDIF
/// <n> OP_CSV
/// ```
///
/// Returns `(pk_a, pk_b, older_n)` when the script is exactly that template.
/// Otherwise `None`.
///
/// # Why this is completeable (vs bare or_c)
///
/// Bare top-level `or_c` (`CHECKSIG NOTIF CHECKSIG ENDIF`) is CLEANSTACK-invalid
/// on the A path (empty stack after NOTIF consumes the bool). Nesting under
/// `and_v(…, older(n))` with **B as `v:pk`** (`CHECKSIGVERIFY`) makes both
/// branches leave a single CSV bool:
/// - **A path:** CHECKSIG → 1, NOTIF skips B, CSV pushes 1 → stack `[1]`
/// - **B path:** empty dissatisfaction of A → 0, NOTIF runs CHECKSIGVERIFY
///   (leaves nothing), CSV pushes 1 → stack `[1]`
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA>` (preferred when both sigs present)
/// - B branch: `<sigB> <empty>` (empty = BIP-342 dissatisfaction of A)
///
/// Requires matching `tap_script_sig`(s) **and** unsigned-tx nSequence that
/// satisfies BIP-112 for `n` — never invents either. Distinct from bare or_c
/// (B uses CHECKSIGVERIFY + trailing CSV), or_d (IFDUP; both CHECKSIG), and
/// `and_v(v:pk, older)` (single key).
pub(crate) fn bare_tapscript_and_v_or_c_older_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_ENDIF, OP_NOTIF};

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
    // v:pk(B) — CHECKSIGVERIFY (not bare-or_c CHECKSIG) so B path leaves nothing
    // before trailing CSV (CLEANSTACK-valid).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let older_n = parse_csv_older_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, older_n))
}

/// Parse nested CLEANSTACK-valid
/// `and_v(or_c(pk(A), v:pk(B)), after(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIGVERIFY
/// OP_ENDIF
/// <n> OP_CLTV
/// ```
///
/// Returns `(pk_a, pk_b, after_n)` when the script is exactly that template.
/// Otherwise `None`.
///
/// # Why this is completeable (vs bare or_c)
///
/// Same CLEANSTACK argument as [`bare_tapscript_and_v_or_c_older_template`]:
/// bare top-level `or_c` is CLEANSTACK-invalid on the A path; nesting under
/// `and_v(…, after(n))` with **B as `v:pk`** (`CHECKSIGVERIFY`) makes both
/// branches leave a single CLTV-peeked absolute-locktime bool:
/// - **A path:** CHECKSIG → 1, NOTIF consumes bool + skips B, CLTV peeks n →
///   stack `[n]`
/// - **B path:** empty dissatisfaction of A → 0, NOTIF runs CHECKSIGVERIFY
///   (leaves nothing), CLTV peeks n → stack `[n]`
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA>` (preferred when both sigs present)
/// - B branch: `<sigB> <empty>` (empty = BIP-342 dissatisfaction of A)
///
/// Requires matching `tap_script_sig`(s) **and** unsigned-tx nLockTime that
/// satisfies BIP-65 for `n` with a non-final nSequence — never invents either.
/// Distinct from bare or_c (B uses CHECKSIGVERIFY + trailing CLTV), or_d
/// (IFDUP; both CHECKSIG), `and_v(v:pk, after)` (single key), and
/// `and_v(or_c, older)` (CSV not CLTV).
pub(crate) fn bare_tapscript_and_v_or_c_after_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_ENDIF, OP_NOTIF};

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
    // v:pk(B) — CHECKSIGVERIFY (not bare-or_c CHECKSIG) so B path leaves nothing
    // before trailing CLTV (CLEANSTACK-valid).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let after_n = parse_cltv_after_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, after_n))
}

/// Parse nested CLEANSTACK-valid
/// `and_v(or_c(pk(A), v:pk(B)), hash(H))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIGVERIFY
/// OP_ENDIF
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(pk_a, pk_b, kind, digest)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable (vs bare or_c)
///
/// Same CLEANSTACK argument as [`bare_tapscript_and_v_or_c_older_template`]:
/// bare top-level `or_c` is CLEANSTACK-invalid on the A path; nesting under
/// `and_v(…, hash(H))` with **B as `v:pk`** (`CHECKSIGVERIFY`) makes both
/// branches leave a single hash-bool:
/// - **A path:** CHECKSIG → 1, NOTIF skips B, hash fragment → 1 → stack `[1]`
/// - **B path:** empty dissatisfaction of A → 0, NOTIF runs CHECKSIGVERIFY
///   (leaves nothing), hash fragment → 1 → stack `[1]`
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<preimage> <sigA>` (preimage deeper; sig top for CHECKSIG first)
/// - B branch: `<preimage> <sigB> <empty>` (empty = BIP-342 dissatisfaction of A)
///
/// Requires matching `tap_script_sig`(s) **and** a matching 32-byte PSBT
/// preimage — never invents either. Distinct from bare or_c (B uses
/// CHECKSIGVERIFY + trailing hash), bare/`and_v` hash (no or_c), and
/// `and_v(or_c, older|after)` (CSV/CLTV not hash).
pub(crate) fn bare_tapscript_and_v_or_c_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_NOTIF, OP_SIZE,
    };

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
    // v:pk(B) — CHECKSIGVERIFY (not bare-or_c CHECKSIG) so B path leaves nothing
    // before trailing hash (CLEANSTACK-valid).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    // Trailing bare hash fragment: SIZE 32 EQUALVERIFY HASHOP digest EQUAL
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
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, kind, digest))
}

/// Parse nested CLEANSTACK-valid
/// `and_v(or_i(v:pk(A), v:pk(B)), hash(H))` leaf:
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIGVERIFY
/// OP_ELSE
///   <xonlyB> OP_CHECKSIGVERIFY
/// OP_ENDIF
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(pk_a, pk_b, kind, digest)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable
///
/// Bare top-level `or_i` uses CHECKSIG (leaves a bool) and is already
/// completeable as a leaf. Nesting under `and_v(…, hash(H))` with **both**
/// arms as `v:pk` (`CHECKSIGVERIFY`) makes both IF/ELSE paths leave void
/// before the trailing hash fragment, which then leaves a single hash-bool:
/// - **IF/A path:** selector true → CHECKSIGVERIFY leaves nothing → hash → 1
/// - **ELSE/B path:** selector false → CHECKSIGVERIFY leaves nothing → hash → 1
///
/// Witness script inputs (before leaf + control block):
/// - IF/A branch: `<preimage> <sigA> <0x01>` (preimage deepest; IF selector top)
/// - ELSE/B branch: `<preimage> <sigB> <empty>` (empty = false IF selector)
///
/// Policy when both sigs present: prefer IF/A — deterministic, no invented
/// branch. Requires matching `tap_script_sig`(s) **and** a matching 32-byte
/// PSBT preimage — never invents either. Distinct from bare or_i (CHECKSIG not
/// VERIFY; no hash tail), `and_v(or_c, hash)` (NOTIF/or_c shape), bare/`and_v`
/// hash (no or_i), `and_v(or_c, older|after)`, and `and_v(or_i, older|after)`
/// (CSV/CLTV not hash).
pub(crate) fn bare_tapscript_and_v_or_i_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

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
    // v:pk(A) — CHECKSIGVERIFY so IF path leaves nothing before trailing hash.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
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
    // v:pk(B) — CHECKSIGVERIFY so ELSE path leaves nothing before trailing hash.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    // Trailing bare hash fragment: SIZE 32 EQUALVERIFY HASHOP digest EQUAL
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
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, kind, digest))
}

/// Parse nested CLEANSTACK-valid
/// `and_v(or_i(v:pk(A), v:pk(B)), older(n))` leaf:
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIGVERIFY
/// OP_ELSE
///   <xonlyB> OP_CHECKSIGVERIFY
/// OP_ENDIF
/// <n> OP_CSV
/// ```
///
/// Returns `(pk_a, pk_b, older_n)` when the script is exactly that template.
/// Otherwise `None`.
///
/// # Why this is completeable
///
/// Same CLEANSTACK argument as [`bare_tapscript_and_v_or_i_hash_template`]:
/// both arms as `v:pk` (`CHECKSIGVERIFY`) leave void before the trailing CSV
/// fragment, which then leaves a single relative-locktime bool:
/// - **IF/A path:** selector true → CHECKSIGVERIFY leaves nothing → CSV → 1
/// - **ELSE/B path:** selector false → CHECKSIGVERIFY leaves nothing → CSV → 1
///
/// Witness script inputs (before leaf + control block):
/// - IF/A branch: `<sigA> <0x01>` (IF selector top)
/// - ELSE/B branch: `<sigB> <empty>` (empty = false IF selector)
///
/// Policy when both sigs present: prefer IF/A — deterministic, no invented
/// branch. Requires matching `tap_script_sig`(s) **and** unsigned-tx nSequence
/// that satisfies BIP-112 for `n` — never invents either. Distinct from bare
/// or_i (CHECKSIG not VERIFY; no CSV), `and_v(or_c, older)` (NOTIF/or_c shape),
/// `and_v(v:pk, older)` (single key), and `and_v(or_i, hash|after)`.
pub(crate) fn bare_tapscript_and_v_or_i_older_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV, OP_ELSE, OP_ENDIF, OP_IF};

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
    // v:pk(A) — CHECKSIGVERIFY so IF path leaves nothing before trailing CSV.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
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
    // v:pk(B) — CHECKSIGVERIFY so ELSE path leaves nothing before trailing CSV.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let older_n = parse_csv_older_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, older_n))
}

/// Parse nested CLEANSTACK-valid
/// `and_v(or_i(v:pk(A), v:pk(B)), after(n))` leaf:
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIGVERIFY
/// OP_ELSE
///   <xonlyB> OP_CHECKSIGVERIFY
/// OP_ENDIF
/// <n> OP_CLTV
/// ```
///
/// Returns `(pk_a, pk_b, after_n)` when the script is exactly that template.
/// Otherwise `None`.
///
/// # Why this is completeable
///
/// Same CLEANSTACK argument as [`bare_tapscript_and_v_or_i_older_template`]:
/// both arms as `v:pk` (`CHECKSIGVERIFY`) leave void before the trailing CLTV
/// fragment, which then leaves a single absolute-locktime bool:
/// - **IF/A path:** selector true → CHECKSIGVERIFY leaves nothing → CLTV peeks n
/// - **ELSE/B path:** selector false → CHECKSIGVERIFY leaves nothing → CLTV peeks n
///
/// Witness script inputs (before leaf + control block):
/// - IF/A branch: `<sigA> <0x01>` (IF selector top)
/// - ELSE/B branch: `<sigB> <empty>` (empty = false IF selector)
///
/// Policy when both sigs present: prefer IF/A — deterministic, no invented
/// branch. Requires matching `tap_script_sig`(s) **and** unsigned-tx nLockTime
/// that satisfies BIP-65 for `n` with a non-final nSequence — never invents
/// either. Distinct from bare or_i, `and_v(or_c, after)` (NOTIF/or_c shape),
/// `and_v(v:pk, after)` (single key), and `and_v(or_i, older|hash)`.
pub(crate) fn bare_tapscript_and_v_or_i_after_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV, OP_ELSE, OP_ENDIF, OP_IF};

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
    // v:pk(A) — CHECKSIGVERIFY so IF path leaves nothing before trailing CLTV.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
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
    // v:pk(B) — CHECKSIGVERIFY so ELSE path leaves nothing before trailing CLTV.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let after_n = parse_cltv_after_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, after_n))
}

/// Parse nested CLEANSTACK-valid multi-arm
/// `and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), older(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIG
///   OP_NOTIF
///     <xonlyC> OP_CHECKSIGVERIFY
///   OP_ENDIF
/// OP_ENDIF
/// <n> OP_CSV
/// ```
///
/// Returns `(pk_a, pk_b, pk_c, older_n)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable (vs bare or_c / dual-key nested)
///
/// Dual-key `and_v(or_c(pk(A), v:pk(B)), older)` is already completeable.
/// Multi-arm nests a second `or_c` so three keys can satisfy the same trailing
/// CSV. Intermediate arms use plain `CHECKSIG` (leave a bool for the next
/// NOTIF); only the innermost C is `v:pk` (`CHECKSIGVERIFY`) so every branch
/// leaves a single CSV bool:
/// - **A path:** CHECKSIG → 1, outer NOTIF skips rest, CSV → `[1]`
/// - **B path:** empty dissat of A → 0, NOTIF runs B CHECKSIG → 1, inner
///   NOTIF skips C, CSV → `[1]`
/// - **C path:** empty A + empty B → nested NOTIFs run CHECKSIGVERIFY, CSV →
///   `[1]`
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA>` (preferred when A present)
/// - B branch: `<sigB> <empty>` (empty = BIP-342 dissatisfaction of A)
/// - C branch: `<sigC> <empty> <empty>` (empty dissat of B then A)
///
/// Policy when multiple sigs present: A preferred over B over C —
/// deterministic, no invented branch. Requires matching `tap_script_sig`(s)
/// **and** unsigned-tx nSequence that satisfies BIP-112 for `n` — never invents
/// either. Distinct from dual-key `and_v(or_c, older)` (B is CHECKSIGVERIFY +
/// single NOTIF; multi-arm B is CHECKSIG + nested NOTIF), bare or_c, and
/// multi-arm after (CLTV not CSV).
pub(crate) fn bare_tapscript_and_v_or_c_multi_older_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_ENDIF, OP_NOTIF};

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
    // Intermediate or_c arm: CHECKSIG (not VERIFY) so the bool feeds the next NOTIF.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
        _ => return None,
    }
    let push_c = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_c = push_c.as_bytes();
    if bytes_c.len() != 32 {
        return None;
    }
    let pk_c = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_c).ok()?;
    // Innermost v:pk(C) — CHECKSIGVERIFY leaves nothing before trailing CSV.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let older_n = parse_csv_older_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, pk_c, older_n))
}

/// Parse nested CLEANSTACK-valid multi-arm
/// `and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), after(n))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIG
///   OP_NOTIF
///     <xonlyC> OP_CHECKSIGVERIFY
///   OP_ENDIF
/// OP_ENDIF
/// <n> OP_CLTV
/// ```
///
/// Returns `(pk_a, pk_b, pk_c, after_n)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable
///
/// Same multi-arm CLEANSTACK argument as
/// [`bare_tapscript_and_v_or_c_multi_older_template`]: intermediate B is
/// `CHECKSIG`, innermost C is `v:pk` (`CHECKSIGVERIFY`); trailing CLTV leaves
/// a single absolute-locktime bool on every branch.
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA>` (preferred when A present)
/// - B branch: `<sigB> <empty>` (empty = BIP-342 dissatisfaction of A)
/// - C branch: `<sigC> <empty> <empty>` (empty dissat of B then A)
///
/// Policy when multiple sigs present: A preferred over B over C. Requires
/// matching `tap_script_sig`(s) **and** unsigned-tx nLockTime that satisfies
/// BIP-65 for `n` with a non-final nSequence — never invents either. Distinct
/// from dual-key `and_v(or_c, after)`, multi-arm older (CSV not CLTV), and bare
/// or_c.
pub(crate) fn bare_tapscript_and_v_or_c_multi_after_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_ENDIF, OP_NOTIF};

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
    // Intermediate or_c arm: CHECKSIG (not VERIFY) so the bool feeds the next NOTIF.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
        _ => return None,
    }
    let push_c = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_c = push_c.as_bytes();
    if bytes_c.len() != 32 {
        return None;
    }
    let pk_c = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_c).ok()?;
    // Innermost v:pk(C) — CHECKSIGVERIFY leaves nothing before trailing CLTV.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let after_n = parse_cltv_after_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, pk_c, after_n))
}

/// Parse nested CLEANSTACK-valid multi-arm
/// `and_v(or_c(pk(A), or_c(pk(B), v:pk(C))), hash(H))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIG
/// OP_NOTIF
///   <xonlyB> OP_CHECKSIG
///   OP_NOTIF
///     <xonlyC> OP_CHECKSIGVERIFY
///   OP_ENDIF
/// OP_ENDIF
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(pk_a, pk_b, pk_c, kind, digest)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable
///
/// Same multi-arm CLEANSTACK argument as
/// [`bare_tapscript_and_v_or_c_multi_older_template`]: intermediate B is
/// `CHECKSIG`, innermost C is `v:pk` (`CHECKSIGVERIFY`); trailing bare hash
/// fragment leaves a single hash-bool on every branch:
/// - **A path:** CHECKSIG → 1, outer NOTIF skips rest, hash → `[1]`
/// - **B path:** empty dissat of A → 0, NOTIF runs B CHECKSIG → 1, inner
///   NOTIF skips C, hash → `[1]`
/// - **C path:** empty A + empty B → nested NOTIFs run CHECKSIGVERIFY, hash →
///   `[1]`
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<preimage> <sigA>` (preimage deeper; sig top for CHECKSIG first)
/// - B branch: `<preimage> <sigB> <empty>` (empty = BIP-342 dissatisfaction of A)
/// - C branch: `<preimage> <sigC> <empty> <empty>` (empty dissat of B then A)
///
/// Policy when multiple sigs present: A preferred over B over C —
/// deterministic, no invented branch. Requires matching `tap_script_sig`(s)
/// **and** a matching 32-byte PSBT preimage — never invents either. Distinct
/// from dual-key `and_v(or_c, hash)` (B is CHECKSIGVERIFY + single NOTIF;
/// multi-arm B is CHECKSIG + nested NOTIF), multi-arm older/after (CSV/CLTV
/// not hash), and bare or_c.
pub(crate) fn bare_tapscript_and_v_or_c_multi_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_NOTIF, OP_SIZE,
    };

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
    // Intermediate or_c arm: CHECKSIG (not VERIFY) so the bool feeds the next NOTIF.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_NOTIF => {}
        _ => return None,
    }
    let push_c = match iter.next()? {
        Ok(Instruction::PushBytes(b)) => b,
        _ => return None,
    };
    let bytes_c = push_c.as_bytes();
    if bytes_c.len() != 32 {
        return None;
    }
    let pk_c = bitcoin::secp256k1::XOnlyPublicKey::from_slice(bytes_c).ok()?;
    // Innermost v:pk(C) — CHECKSIGVERIFY leaves nothing before trailing hash.
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    // Trailing bare hash fragment: SIZE 32 EQUALVERIFY HASHOP digest EQUAL
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
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, pk_c, kind, digest))
}

/// Parse nested CLEANSTACK-valid multi-arm
/// `and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), older(n))` leaf:
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIGVERIFY
/// OP_ELSE
///   OP_IF
///     <xonlyB> OP_CHECKSIGVERIFY
///   OP_ELSE
///     <xonlyC> OP_CHECKSIGVERIFY
///   OP_ENDIF
/// OP_ENDIF
/// <n> OP_CSV
/// ```
///
/// Returns `(pk_a, pk_b, pk_c, older_n)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable
///
/// Dual-key `and_v(or_i(v:pk(A), v:pk(B)), older)` is already completeable.
/// Multi-arm nests a second `or_i` so three keys can satisfy the same trailing
/// CSV. Every arm is `v:pk` (`CHECKSIGVERIFY`) so every branch leaves void
/// before CSV, which then leaves a single relative-locktime bool:
/// - **A path:** outer IF true → CHECKSIGVERIFY A → CSV → `[1]`
/// - **B path:** outer ELSE + inner IF true → CHECKSIGVERIFY B → CSV → `[1]`
/// - **C path:** outer ELSE + inner ELSE → CHECKSIGVERIFY C → CSV → `[1]`
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA> <0x01>` (outer IF selector top; preferred when A present)
/// - B branch: `<sigB> <0x01> <empty>` (empty = false outer; 0x01 = true inner)
/// - C branch: `<sigC> <empty> <empty>` (empty outer + empty inner)
///
/// Policy when multiple sigs present: A preferred over B over C —
/// deterministic, no invented branch. Requires matching `tap_script_sig`(s)
/// **and** unsigned-tx nSequence that satisfies BIP-112 for `n` — never invents
/// either. Distinct from dual-key `and_v(or_i, older)` (single IF/ELSE, no
/// nested IF), multi-arm `and_v(or_c, older)` (NOTIF/or_c shape), multi-arm
/// after (CLTV not CSV), and bare or_c.
pub(crate) fn bare_tapscript_and_v_or_i_multi_older_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV, OP_ELSE, OP_ENDIF, OP_IF};

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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    // Nested or_i: second OP_IF (not a key push — that would be dual-key or_i).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let older_n = parse_csv_older_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CSV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, pk_c, older_n))
}

/// Parse nested CLEANSTACK-valid multi-arm
/// `and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), after(n))` leaf:
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIGVERIFY
/// OP_ELSE
///   OP_IF
///     <xonlyB> OP_CHECKSIGVERIFY
///   OP_ELSE
///     <xonlyC> OP_CHECKSIGVERIFY
///   OP_ENDIF
/// OP_ENDIF
/// <n> OP_CLTV
/// ```
///
/// Returns `(pk_a, pk_b, pk_c, after_n)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable
///
/// Same multi-arm CLEANSTACK argument as
/// [`bare_tapscript_and_v_or_i_multi_older_template`]: every arm is `v:pk`
/// (`CHECKSIGVERIFY`); trailing CLTV leaves a single absolute-locktime bool
/// on every branch.
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<sigA> <0x01>` (outer IF selector top; preferred when A present)
/// - B branch: `<sigB> <0x01> <empty>` (empty = false outer; 0x01 = true inner)
/// - C branch: `<sigC> <empty> <empty>` (empty outer + empty inner)
///
/// Policy when multiple sigs present: A preferred over B over C. Requires
/// matching `tap_script_sig`(s) **and** unsigned-tx nLockTime that satisfies
/// BIP-65 for `n` with a non-final nSequence — never invents either. Distinct
/// from dual-key `and_v(or_i, after)`, multi-arm older (CSV not CLTV), and
/// multi-arm `and_v(or_c, after)`.
pub(crate) fn bare_tapscript_and_v_or_i_multi_after_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    u32,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV, OP_ELSE, OP_ENDIF, OP_IF};

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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    let after_n = parse_cltv_after_n(iter.next()?.ok()?)?;
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_CLTV => {}
        _ => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, pk_c, after_n))
}

/// Parse nested CLEANSTACK-valid multi-arm
/// `and_v(or_i(v:pk(A), or_i(v:pk(B), v:pk(C))), hash(H))` leaf:
///
/// ```text
/// OP_IF
///   <xonlyA> OP_CHECKSIGVERIFY
/// OP_ELSE
///   OP_IF
///     <xonlyB> OP_CHECKSIGVERIFY
///   OP_ELSE
///     <xonlyC> OP_CHECKSIGVERIFY
///   OP_ENDIF
/// OP_ENDIF
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(pk_a, pk_b, pk_c, kind, digest)` when the script is exactly that
/// template. Otherwise `None`.
///
/// # Why this is completeable
///
/// Same multi-arm CLEANSTACK argument as
/// [`bare_tapscript_and_v_or_i_multi_older_template`]: every arm is `v:pk`
/// (`CHECKSIGVERIFY`); trailing bare hash fragment leaves a single hash-bool
/// on every branch.
///
/// Witness script inputs (before leaf + control block):
/// - A branch: `<preimage> <sigA> <0x01>` (preimage deepest; outer IF top)
/// - B branch: `<preimage> <sigB> <0x01> <empty>` (empty outer; 0x01 inner)
/// - C branch: `<preimage> <sigC> <empty> <empty>`
///
/// Policy when multiple sigs present: A preferred over B over C —
/// deterministic, no invented branch. Requires matching `tap_script_sig`(s)
/// **and** a matching 32-byte PSBT preimage — never invents either. Distinct
/// from dual-key `and_v(or_i, hash)`, multi-arm `and_v(or_c, hash)`, and
/// multi-arm older/after (CSV/CLTV not hash).
pub(crate) fn bare_tapscript_and_v_or_i_multi_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    bitcoin::secp256k1::XOnlyPublicKey,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{
        OP_CHECKSIGVERIFY, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_IF, OP_SIZE,
    };

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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_IF => {}
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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ELSE => {}
        _ => return None,
    }
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
        Ok(Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_ENDIF => {}
        _ => return None,
    }
    // Trailing bare hash fragment: SIZE 32 EQUALVERIFY HASHOP digest EQUAL
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
    if iter.next().is_some() {
        return None;
    }
    Some((pk_a, pk_b, pk_c, kind, digest))
}
