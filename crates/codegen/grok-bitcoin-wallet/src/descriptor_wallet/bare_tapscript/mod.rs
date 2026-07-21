//! Bare tapscript leaf template family parsers.
//!
//! Behavior-preserving peel from `descriptor_wallet/mod.rs` (PR3). Parent
//! `finalize_taproot_script_path` still dispatches; these modules only parse
//! exact leaf templates. Dual-hash `and_v` keep set only (PR5 pruned matrix).

mod and_v_checksig;
mod and_v_dual_hash;
mod and_v_multi_pk;
mod and_v_or;
mod and_v_pk_hash_lock;
mod combinators;
mod common;
mod hash;
mod multi_a;
mod older_after;
mod or_c;
mod or_i_basic;
mod or_i_product;
mod thresh;

// Shared helpers / types re-exported for sibling modules (`use super::…`)
// and for the parent finalize + tests surface.
pub(crate) use and_v_multi_pk::*;
pub(crate) use common::*;
pub(crate) use hash::*;
pub(crate) use older_after::*;
pub(crate) use or_i_product::*;

pub(crate) use and_v_checksig::*;
pub(crate) use and_v_dual_hash::*;
pub(crate) use and_v_or::*;
pub(crate) use and_v_pk_hash_lock::*;
pub(crate) use combinators::*;
pub(crate) use multi_a::*;
pub(crate) use or_c::*;
pub(crate) use or_i_basic::*;
pub(crate) use thresh::*;
