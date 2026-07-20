//! grok-build compaction configuration.
//!
//! Holds the [`FullReplaceConfig`] tunables struct (mirroring
//! [`IntraCompactionConfig`](crate::intra_compaction::IntraCompactionConfig) /
//! [`InterCompactionConfig`](crate::inter_compaction::InterCompactionConfig),
//! which also live in their module's `config.rs`) plus the shared default
//! values. Trigger *wiring* (pre-sampling checks, preflight overflow,
//! model-switch, suppression) stays per-host.

/// Default auto-compact threshold (% of context window) when no other source
/// (env var, user config, remote per-model/global flags) sets it. Shared by
/// grok-build and Grok chat (~95% trigger on both sides).
pub const DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT: u8 = 95;

// ---------------------------------------------------------------------------
// Grok 4.5 model-card reference (docs.x.ai, mid-2026).
//
// Used as the token-count preset baseline in settings and docs. The live gate
// still uses each session's actual `context_window`; these constants only
// label the presets and the long-context price cliff.
// ---------------------------------------------------------------------------

/// Grok 4.5 maximum context window (tokens).
pub const GROK_45_CONTEXT_WINDOW_TOKENS: u64 = 500_000;

/// Prompt length (tokens) above which Grok 4.5 bills the **entire** request at
/// long-context rates (2× input / cached-input / output). Staying at or below
/// this cliff keeps short-context pricing.
pub const GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS: u64 = 200_000;

/// 95% of [`GROK_45_CONTEXT_WINDOW_TOKENS`] — the token equivalent of the
/// default percent threshold on the Grok 4.5 card.
pub const GROK_45_DEFAULT_AUTO_COMPACT_TOKENS: u64 =
    GROK_45_CONTEXT_WINDOW_TOKENS * (DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT as u64) / 100;

/// How the user expresses the auto-compact trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoCompactThreshold {
    /// Fraction of the active model's context window (0–100).
    Percent(u8),
    /// Absolute token count (independent of window size).
    Tokens(u64),
}

impl AutoCompactThreshold {
    /// Built-in default: 95% of the context window.
    pub const fn default_percent() -> Self {
        Self::Percent(DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT)
    }

    /// Absolute token count at which compaction should fire for `context_window`.
    ///
    /// Percent mode scales with the window; tokens mode uses the configured
    /// count (clamped to the window so a 200k preset still fires on a smaller
    /// model before overflow).
    pub fn absolute_tokens(self, context_window: u64) -> u64 {
        match self {
            Self::Percent(p) => {
                if context_window == 0 {
                    0
                } else {
                    context_window.saturating_mul(u64::from(p.min(100))) / 100
                }
            }
            Self::Tokens(t) => {
                if context_window == 0 {
                    t
                } else {
                    t.min(context_window)
                }
            }
        }
    }

    /// Effective percent of `context_window` (for UIs that only show %).
    pub fn as_percent_of(self, context_window: u64) -> u8 {
        match self {
            Self::Percent(p) => p.min(100),
            Self::Tokens(t) => {
                if context_window == 0 {
                    0
                } else {
                    ((t.saturating_mul(100)) / context_window).min(100) as u8
                }
            }
        }
    }
}

impl Default for AutoCompactThreshold {
    fn default() -> Self {
        Self::default_percent()
    }
}

#[cfg(test)]
mod auto_compact_threshold_tests {
    use super::*;

    /// Product contract: the built-in default is 95% of the context window.
    #[test]
    fn default_auto_compact_threshold_is_95_percent() {
        assert_eq!(DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT, 95);
        assert_eq!(
            AutoCompactThreshold::default(),
            AutoCompactThreshold::Percent(95)
        );
        assert_eq!(
            AutoCompactThreshold::default_percent(),
            AutoCompactThreshold::Percent(95)
        );
        // Grok 4.5 card: 95% of 500k = 475k tokens.
        assert_eq!(GROK_45_CONTEXT_WINDOW_TOKENS, 500_000);
        assert_eq!(GROK_45_DEFAULT_AUTO_COMPACT_TOKENS, 475_000);
        assert_eq!(
            AutoCompactThreshold::Percent(95).absolute_tokens(GROK_45_CONTEXT_WINDOW_TOKENS),
            GROK_45_DEFAULT_AUTO_COMPACT_TOKENS
        );
    }

    #[test]
    fn tokens_mode_clamps_to_window_and_preserves_price_cliff() {
        assert_eq!(GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS, 200_000);
        let cliff = AutoCompactThreshold::Tokens(GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS);
        // On Grok 4.5, 200k is 40% of the 500k window.
        assert_eq!(cliff.as_percent_of(GROK_45_CONTEXT_WINDOW_TOKENS), 40);
        assert_eq!(
            cliff.absolute_tokens(GROK_45_CONTEXT_WINDOW_TOKENS),
            200_000
        );
        // On a smaller window the absolute preset still fires before overflow.
        assert_eq!(cliff.absolute_tokens(128_000), 128_000);
    }

    #[test]
    fn percent_mode_scales_with_window() {
        let t = AutoCompactThreshold::Percent(90);
        assert_eq!(t.absolute_tokens(100_000), 90_000);
        assert_eq!(t.absolute_tokens(500_000), 450_000);
        assert_eq!(t.as_percent_of(500_000), 90);
    }
}

/// Minimum character count for a cleaned summary seed.
///
/// grok-build retries when the cleaned summary is shorter than this — the
/// smallest healthy prod summary observed was ~3,242 chars; anything under
/// 500 is treated as degenerate and retried like a transient failure.
pub const MIN_SUMMARY_SEED_CHARS: usize = 500;

/// Tunables for the full-replace pass.
#[derive(Debug, Clone)]
pub struct FullReplaceConfig {
    /// Total LLM attempts (first try + retries) on transient failures.
    pub max_attempts: u32,
    /// Delay between transient retries.
    pub retry_delay_secs: u64,
    /// End-to-end timeout for each compaction LLM call.
    pub sampling_timeout_secs: u64,
}

impl Default for FullReplaceConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            retry_delay_secs: 3,
            sampling_timeout_secs: 120,
        }
    }
}
