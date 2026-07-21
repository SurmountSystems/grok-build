//! Bare tapscript leaf template parsers (behavior-preserving peel from monomod).
//!
//! Offline finalize in the parent module still owns dispatch; these parsers only
//! recognize exact script templates and never invent witness material.

/// Miniscript hash fragment kind (sha256 / hash256 / ripemd160 / hash160).
///
/// All four encode as `SIZE <32> EQUALVERIFY <HASHOP> <digest> EQUAL` with a
/// **32-byte** preimage (SIZE check is always 32, even for 20-byte digests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TapscriptHashKind {
    Sha256,
    Hash256,
    Ripemd160,
    Hash160,
}

impl TapscriptHashKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Hash256 => "hash256",
            Self::Ripemd160 => "ripemd160",
            Self::Hash160 => "hash160",
        }
    }

    pub(crate) fn from_hash_op(op: bitcoin::opcodes::Opcode) -> Option<Self> {
        use bitcoin::opcodes::all::{OP_HASH160, OP_HASH256, OP_RIPEMD160, OP_SHA256};
        if op == OP_SHA256 {
            Some(Self::Sha256)
        } else if op == OP_HASH256 {
            Some(Self::Hash256)
        } else if op == OP_RIPEMD160 {
            Some(Self::Ripemd160)
        } else if op == OP_HASH160 {
            Some(Self::Hash160)
        } else {
            None
        }
    }

    pub(crate) fn expected_digest_len(self) -> usize {
        match self {
            Self::Sha256 | Self::Hash256 => 32,
            Self::Ripemd160 | Self::Hash160 => 20,
        }
    }
}

/// Parse bare Taproot miniscript hash leaf:
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(kind, digest bytes)` when the script is exactly that template.
/// Witness: single 32-byte preimage already present in the matching PSBT
/// preimage map (never invented).
pub(crate) fn bare_tapscript_hash_preimage_template(
    script: &bitcoin::Script,
) -> Option<(TapscriptHashKind, Vec<u8>)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_EQUAL, OP_EQUALVERIFY, OP_SIZE};

    let mut iter = script.instructions();
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_SIZE => {}
        _ => return None,
    }
    // Miniscript always SIZE-checks 32 (even for 20-byte digests).
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
    Some((kind, digest))
}

/// Parse bare Taproot `and_v(v:pk(A), hash(H))` leaf:
///
/// ```text
/// <xonlyA> OP_CHECKSIGVERIFY
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUAL
/// ```
///
/// Returns `(pk_a, kind, digest)` when the script is exactly that template.
/// Witness script inputs: `<preimage> <sigA>` (sig on top so CHECKSIGVERIFY
/// runs first; preimage deeper for the hash fragment). Never invents sigs or
/// preimages — both must already be present on the PSBT.
pub(crate) fn bare_tapscript_and_v_pk_hash_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_EQUAL, OP_EQUALVERIFY, OP_SIZE};

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
    // Remainder must be the bare hash fragment.
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
    Some((pk_a, kind, digest))
}

/// Parse bare Taproot `and_v(v:hash(H), pk(A))` leaf (hash-first dual of
/// [`bare_tapscript_and_v_pk_hash_template`]):
///
/// ```text
/// OP_SIZE <32> OP_EQUALVERIFY <HASHOP> <digest> OP_EQUALVERIFY
/// <xonlyA> OP_CHECKSIG
/// ```
///
/// Returns `(pk_a, kind, digest)` when the script is exactly that template.
/// Witness script inputs: `<sigA> <preimage>` (preimage on top so the hash
/// fragment runs first; sig deeper for CHECKSIG). Never invents sigs or
/// preimages — both must already be present on the PSBT.
///
/// Distinct from bare hash (ends in EQUAL, no trailing CHECKSIG) and from
/// `and_v(v:pk, hash)` (CHECKSIGVERIFY-first + EQUAL hash tail).
pub(crate) fn bare_tapscript_and_v_hash_pk_template(
    script: &bitcoin::Script,
) -> Option<(
    bitcoin::secp256k1::XOnlyPublicKey,
    TapscriptHashKind,
    Vec<u8>,
)> {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_SIZE};

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
    // v: wrapper: EQUALVERIFY (not bare-hash EQUAL).
    match iter.next()? {
        Ok(Instruction::Op(op)) if op == OP_EQUALVERIFY => {}
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
    Some((pk_a, kind, digest))
}
