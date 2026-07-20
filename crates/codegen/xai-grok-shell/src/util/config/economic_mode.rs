//! Economic mode: soft-cap effective context to stay under pricing tiers.
//!
//! Grok 4.5 doubles input / output / cache-read prices once a request exceeds
//! [`GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS`] (200K; catalog context remains
//! 500K). When economic mode is on, the session treats the model as a 200K-window
//! model for compaction, the context bar, and related budgets so turns stay on
//! the cheap tier. Auto-queued `/implement` loops also clamp `--effort` to 1
//! (pager-side) so multi-reviewer fan-out does not burn the cheaper window.
//!
//! Default: **on** (`None` in `[ui].economic_mode`). Override globally via
//! settings / `config.toml`, or per conversation with `/economic-mode`.

use toml::Value as TomlValue;

/// Pricing-tier soft cap (tokens). Same value as
/// [`xai_grok_compaction::GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS`] and the
/// settings modal's `200k` auto-compact preset — one source of truth for the
/// cliff.
pub const ECONOMIC_CONTEXT_CAP: u64 =
    xai_grok_compaction::GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS;

/// Client default when `[ui].economic_mode` is unset.
pub const ECONOMIC_MODE_DEFAULT: bool = true;

/// Resolve economic mode from an optional config value (`None` → default on).
pub fn resolve_economic_mode(user: Option<bool>) -> bool {
    user.unwrap_or(ECONOMIC_MODE_DEFAULT)
}

/// Cap `context_window` at [`ECONOMIC_CONTEXT_CAP`] when economic mode is on.
pub fn apply_economic_context_cap(context_window: u64, economic_mode: bool) -> u64 {
    if economic_mode {
        context_window.min(ECONOMIC_CONTEXT_CAP)
    } else {
        context_window
    }
}

/// Read `[ui].economic_mode` from disk-merged config. Default on when unset.
pub fn economic_mode_from_disk() -> bool {
    let root = match crate::config::load_effective_config() {
        Ok(v) => v,
        Err(_) => return ECONOMIC_MODE_DEFAULT,
    };
    economic_mode_from_toml(&root)
}

/// Parse `[ui].economic_mode` from a TOML root. Default on when missing/invalid.
pub fn economic_mode_from_toml(root: &TomlValue) -> bool {
    match root
        .get("ui")
        .and_then(|u| u.get("economic_mode"))
        .and_then(|v| v.as_bool())
    {
        Some(b) => b,
        None => ECONOMIC_MODE_DEFAULT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults_on() {
        assert!(resolve_economic_mode(None));
        assert!(resolve_economic_mode(Some(true)));
        assert!(!resolve_economic_mode(Some(false)));
    }

    #[test]
    fn apply_cap_when_on_clamps_above_threshold() {
        assert_eq!(
            apply_economic_context_cap(500_000, true),
            ECONOMIC_CONTEXT_CAP
        );
        assert_eq!(
            apply_economic_context_cap(200_000, true),
            ECONOMIC_CONTEXT_CAP
        );
        assert_eq!(apply_economic_context_cap(100_000, true), 100_000);
    }

    #[test]
    fn apply_cap_when_off_is_identity() {
        assert_eq!(apply_economic_context_cap(500_000, false), 500_000);
        assert_eq!(apply_economic_context_cap(1, false), 1);
    }

    #[test]
    fn from_toml_defaults_and_reads_bool() {
        let empty: TomlValue = toml::from_str("").unwrap();
        assert!(economic_mode_from_toml(&empty));

        let on: TomlValue = toml::from_str("[ui]\neconomic_mode = true\n").unwrap();
        assert!(economic_mode_from_toml(&on));

        let off: TomlValue = toml::from_str("[ui]\neconomic_mode = false\n").unwrap();
        assert!(!economic_mode_from_toml(&off));
    }

    #[test]
    fn economic_cap_matches_grok_45_price_cliff_and_auto_compact_200k_preset() {
        assert_eq!(
            ECONOMIC_CONTEXT_CAP,
            xai_grok_compaction::GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS
        );
        assert_eq!(ECONOMIC_CONTEXT_CAP, 200_000);
        // Absolute auto-compact at the cliff is a no-op once economic mode
        // already soft-caps the window to the same value.
        let cliff = xai_grok_compaction::AutoCompactThreshold::Tokens(ECONOMIC_CONTEXT_CAP);
        assert_eq!(
            cliff.absolute_tokens(ECONOMIC_CONTEXT_CAP),
            ECONOMIC_CONTEXT_CAP
        );
        assert_eq!(
            cliff.absolute_tokens(xai_grok_compaction::GROK_45_CONTEXT_WINDOW_TOKENS),
            ECONOMIC_CONTEXT_CAP
        );
    }
}
