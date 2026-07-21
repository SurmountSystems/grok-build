//! P2WPKH fee heuristics and pure RBF/CPFP fee planners.

/// Conservative P2WPKH size estimates used for fee-aware selection (vbytes).
///
/// Not a full weight calculator; good enough for selection before PSBT build.
pub const TX_OVERHEAD_VB: u64 = 11;
/// Typical signed P2WPKH input size in vbytes.
pub const P2WPKH_INPUT_VB: u64 = 68;
/// Typical P2WPKH output size in vbytes.
pub const P2WPKH_OUTPUT_VB: u64 = 31;
/// Dust threshold: change below this is folded into the fee (no change output).
pub const DUST_P2WPKH_SATS: u64 = 294;

/// Estimate transaction vbytes for `input_count` P2WPKH inputs and
/// `output_count` P2WPKH outputs (payment + optional change).
pub fn estimate_tx_vbytes(input_count: usize, output_count: usize) -> u64 {
    TX_OVERHEAD_VB
        .saturating_add((input_count as u64).saturating_mul(P2WPKH_INPUT_VB))
        .saturating_add((output_count as u64).saturating_mul(P2WPKH_OUTPUT_VB))
}

/// `estimate_tx_vbytes(...) * fee_rate_sat_vb`.
pub fn estimate_fee_sats(input_count: usize, output_count: usize, fee_rate_sat_vb: u64) -> u64 {
    estimate_tx_vbytes(input_count, output_count).saturating_mul(fee_rate_sat_vb)
}

/// Bitcoin Core default incremental relay fee (sat/vB) used for BIP-125 RBF
/// absolute fee floor guidance. Not network-fetched; product may override.
pub const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB: u64 = 1;

/// Floor division fee rate in sat/vB. Returns 0 when `vbytes == 0`.
pub fn effective_fee_rate_sat_vb(fee_sats: u64, vbytes: u64) -> u64 {
    if vbytes == 0 {
        return 0;
    }
    fee_sats / vbytes
}

/// Ceiling division (`num / den`, rounding up). Returns 0 when `den == 0`.
pub fn div_ceil_u64(num: u64, den: u64) -> u64 {
    if den == 0 {
        return 0;
    }
    num.div_ceil(den)
}

/// Minimum absolute fee increase (sats) for a same-size BIP-125 replacement:
/// `replacement_vbytes * incremental_relay_sat_vb` (at least 1 sat when sizes > 0).
pub fn rbf_min_fee_increase_sats(replacement_vbytes: u64, incremental_relay_sat_vb: u64) -> u64 {
    let inc = if incremental_relay_sat_vb == 0 {
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB
    } else {
        incremental_relay_sat_vb
    };
    let raw = replacement_vbytes.saturating_mul(inc);
    if replacement_vbytes > 0 {
        raw.max(1)
    } else {
        0
    }
}

/// Errors from RBF / CPFP pure fee planners (offline; no network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeBumpPlanError {
    /// Transaction virtual size must be > 0.
    ZeroVbytes,
    /// Target fee rate must be > 0 sat/vB.
    ZeroTargetRate,
    /// Child vbytes must be > 0 for CPFP.
    ZeroChildVbytes,
}

impl std::fmt::Display for FeeBumpPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroVbytes => write!(f, "vbytes must be > 0"),
            Self::ZeroTargetRate => write!(f, "target fee rate must be > 0 sat/vB"),
            Self::ZeroChildVbytes => write!(f, "child vbytes must be > 0"),
        }
    }
}

impl std::error::Error for FeeBumpPlanError {}

/// BIP-125-style RBF fee bump plan for a **same-size** single-tx replacement.
///
/// Does not rebuild a PSBT. Product uses this to pick a higher fee rate / absolute
/// fee before re-selecting coins and rebuilding. Inputs already signal RBF via
/// [`Sequence::ENABLE_RBF_NO_LOCKTIME`] on [`build_unsigned_psbt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbfFeePlan {
    pub original_fee_sats: u64,
    pub original_vbytes: u64,
    /// Floor sat/vB of the original tx.
    pub original_fee_rate_sat_vb: u64,
    /// Minimum absolute fee for a same-size replacement (increment + higher rate).
    pub min_replacement_fee_sats: u64,
    /// Floor sat/vB at [`Self::min_replacement_fee_sats`].
    pub min_replacement_fee_rate_sat_vb: u64,
    /// Recommended absolute fee meeting target rate and BIP-125 floors.
    pub recommended_fee_sats: u64,
    /// Floor sat/vB at [`Self::recommended_fee_sats`].
    pub recommended_fee_rate_sat_vb: u64,
    /// `recommended_fee_sats - original_fee_sats`.
    pub fee_delta_sats: u64,
    pub target_fee_rate_sat_vb: u64,
    pub incremental_relay_sat_vb: u64,
}

/// Plan a same-size RBF fee bump.
///
/// Ensures the recommended fee:
/// 1. Is strictly greater than `original_fee_sats`
/// 2. Pays at least `vbytes * incremental_relay` extra (BIP-125 bandwidth)
/// 3. Has a strictly higher floor fee rate than the original when possible
/// 4. Meets `target_fee_rate_sat_vb * vbytes`
///
/// `incremental_relay_sat_vb == 0` uses [`DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB`].
pub fn plan_rbf_fee_bump(
    original_fee_sats: u64,
    original_vbytes: u64,
    target_fee_rate_sat_vb: u64,
    incremental_relay_sat_vb: u64,
) -> std::result::Result<RbfFeePlan, FeeBumpPlanError> {
    if original_vbytes == 0 {
        return Err(FeeBumpPlanError::ZeroVbytes);
    }
    if target_fee_rate_sat_vb == 0 {
        return Err(FeeBumpPlanError::ZeroTargetRate);
    }
    let incremental = if incremental_relay_sat_vb == 0 {
        DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB
    } else {
        incremental_relay_sat_vb
    };
    let original_fee_rate_sat_vb = effective_fee_rate_sat_vb(original_fee_sats, original_vbytes);
    let min_increase = rbf_min_fee_increase_sats(original_vbytes, incremental);
    let min_by_increment = original_fee_sats.saturating_add(min_increase);
    // Strictly higher absolute fee.
    let min_by_absolute = original_fee_sats.saturating_add(1);
    // Strictly higher floor feerate: (orig_rate + 1) * vb (at least 1 sat/vB).
    let higher_rate = original_fee_rate_sat_vb.saturating_add(1).max(1);
    let min_by_rate = higher_rate.saturating_mul(original_vbytes);
    let by_target = original_vbytes.saturating_mul(target_fee_rate_sat_vb);

    // BIP-125 floor (no target): increment bandwidth + absolute + higher rate.
    let min_replacement_fee_sats = min_by_increment.max(min_by_absolute).max(min_by_rate);
    // Recommended also meets the caller's target mempool rate.
    let mut recommended = by_target.max(min_replacement_fee_sats);
    // Defensive: never recommend ≤ original absolute fee.
    if recommended <= original_fee_sats {
        recommended = original_fee_sats.saturating_add(min_increase.max(1));
    }

    let recommended_fee_rate_sat_vb = effective_fee_rate_sat_vb(recommended, original_vbytes);
    let min_replacement_fee_rate_sat_vb =
        effective_fee_rate_sat_vb(min_replacement_fee_sats, original_vbytes);
    let fee_delta_sats = recommended.saturating_sub(original_fee_sats);

    Ok(RbfFeePlan {
        original_fee_sats,
        original_vbytes,
        original_fee_rate_sat_vb,
        min_replacement_fee_sats,
        min_replacement_fee_rate_sat_vb,
        recommended_fee_sats: recommended,
        recommended_fee_rate_sat_vb,
        fee_delta_sats,
        target_fee_rate_sat_vb,
        incremental_relay_sat_vb: incremental,
    })
}

/// CPFP child fee plan: child pays enough so parent+child package meets a target rate.
///
/// Pure guidance (does not build the child PSBT). Typical child is 1-in (parent
/// output) + 1–2 P2WPKH outs — use [`estimate_tx_vbytes`] / [`estimate_cpfp_child_vbytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpfpFeePlan {
    pub parent_fee_sats: u64,
    pub parent_vbytes: u64,
    pub child_vbytes: u64,
    pub target_fee_rate_sat_vb: u64,
    /// Minimum child absolute fee so package rate ≥ target (and child meets min relay).
    pub min_child_fee_sats: u64,
    /// Floor sat/vB of the child alone at [`Self::min_child_fee_sats`].
    pub min_child_fee_rate_sat_vb: u64,
    /// Package fee rate after paying [`Self::min_child_fee_sats`].
    pub package_fee_rate_sat_vb: u64,
    pub package_vbytes: u64,
    pub package_fee_sats: u64,
}

/// Estimate vbytes for a typical CPFP child spending one P2WPKH parent output
/// with `output_count` P2WPKH outputs (payment and/or change). `output_count`
/// of 0 is treated as 1.
pub fn estimate_cpfp_child_vbytes(output_count: usize) -> u64 {
    estimate_tx_vbytes(1, output_count.max(1))
}

/// Plan CPFP child fee so `(parent_fee + child_fee) / (parent_vb + child_vb) ≥ target`.
///
/// Also enforces a minimum child fee of `child_vbytes * 1` sat (min-relay style)
/// so a fully overpaying parent still yields a relayable child.
pub fn plan_cpfp_child_fee(
    parent_fee_sats: u64,
    parent_vbytes: u64,
    child_vbytes: u64,
    target_fee_rate_sat_vb: u64,
) -> std::result::Result<CpfpFeePlan, FeeBumpPlanError> {
    if parent_vbytes == 0 {
        return Err(FeeBumpPlanError::ZeroVbytes);
    }
    if child_vbytes == 0 {
        return Err(FeeBumpPlanError::ZeroChildVbytes);
    }
    if target_fee_rate_sat_vb == 0 {
        return Err(FeeBumpPlanError::ZeroTargetRate);
    }
    let package_vbytes = parent_vbytes.saturating_add(child_vbytes);
    let needed_package_fee = package_vbytes.saturating_mul(target_fee_rate_sat_vb);
    let for_package = needed_package_fee.saturating_sub(parent_fee_sats);
    // Child must pay at least min-relay for its own size (1 sat/vB).
    let min_relay_child = child_vbytes
        .saturating_mul(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_VB)
        .max(1);
    let min_child_fee_sats = for_package.max(min_relay_child);
    let package_fee_sats = parent_fee_sats.saturating_add(min_child_fee_sats);
    let package_fee_rate_sat_vb = effective_fee_rate_sat_vb(package_fee_sats, package_vbytes);
    let min_child_fee_rate_sat_vb = effective_fee_rate_sat_vb(min_child_fee_sats, child_vbytes);

    Ok(CpfpFeePlan {
        parent_fee_sats,
        parent_vbytes,
        child_vbytes,
        target_fee_rate_sat_vb,
        min_child_fee_sats,
        min_child_fee_rate_sat_vb,
        package_fee_rate_sat_vb,
        package_vbytes,
        package_fee_sats,
    })
}
