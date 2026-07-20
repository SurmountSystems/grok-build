/// Default auto-compact threshold (% of context window) when no source sets it.
///
/// Kept in lockstep with
/// [`xai_grok_compaction::DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT`].
pub const DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT: u8 =
    xai_grok_compaction::DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT;

// Re-export Grok 4.5 card reference constants for settings/docs callers.
pub use xai_grok_compaction::{
    AutoCompactThreshold, GROK_45_CONTEXT_WINDOW_TOKENS, GROK_45_DEFAULT_AUTO_COMPACT_TOKENS,
    GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CompactionToolChoice {
    #[default]
    Auto,
    None,
}

impl std::str::FromStr for CompactionToolChoice {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "none" => Ok(Self::None),
            _ => Err(()),
        }
    }
}

pub(crate) const ENV_COMPACTION_TOOL_CHOICE: &str = "GROK_COMPACTION_TOOL_CHOICE";

pub fn resolve_compaction_tool_choice_from(
    env: Option<&str>,
    config: Option<&str>,
    remote: Option<&str>,
) -> CompactionToolChoice {
    env.and_then(|s| s.parse().ok())
        .or_else(|| config.and_then(|s| s.parse().ok()))
        .or_else(|| remote.and_then(|s| s.parse().ok()))
        .unwrap_or_default()
}

/// Env-var override for `auto_compact_threshold_percent`. Parsed as `u8`;
/// out-of-range or unparseable values are ignored.
pub(crate) const ENV_AUTO_COMPACT_THRESHOLD_PERCENT: &str = "GROK_AUTO_COMPACT_THRESHOLD_PERCENT";

/// Env-var override for absolute-token auto-compact. When set and valid, wins
/// over percent tiers (including `GROK_AUTO_COMPACT_THRESHOLD_PERCENT`).
pub(crate) const ENV_AUTO_COMPACT_THRESHOLD_TOKENS: &str = "GROK_AUTO_COMPACT_THRESHOLD_TOKENS";

/// Resolve auto-compact threshold percent (0-100) for the given model.
///
/// Prefer [`resolve_auto_compact_threshold`] when absolute-token preferences
/// must be honored. This percent-only form ignores
/// `[session].auto_compact_threshold_tokens` (legacy call sites / tests).
///
/// Two scopes (per-model and global) across two tiers (user TOML and
/// remote settings). User-tier always wins over remote; within a tier, per-model
/// wins over global. Env var sits on top as a per-process override.
///
/// Precedence (highest first):
///   1. env `GROK_AUTO_COMPACT_THRESHOLD_PERCENT`
///   2. user TOML `[model.<id>].auto_compact_threshold_percent`
///      (read from `cfg.config_models`; the effective merge of user +
///      managed `[model.<id>]` sections)
///   3. user TOML `[session].auto_compact_threshold_percent`
///      (read from `cfg.session.auto_compact_threshold_percent: Option<u8>`)
///   4. remote settings per-model `ModelInfo.auto_compact_threshold_percent`
///      (populated from `grok_build_models[i].auto_compact_threshold_percent`;
///      intentionally NOT collapsed via `ConfigModelOverride::apply` so the
///      user-vs-GB per-model distinction is preserved)
///   5. remote settings global `RemoteSettings.auto_compact_threshold_percent`
///      (populated from `grok_build_settings.auto_compact_threshold_percent`)
///   6. default `DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT` (95)
///
/// Values outside `0..=100` from the env var are ignored with a debug log and
/// the resolver falls through to the next tier. TOML/remote fields are typed
/// `u8` and so naturally constrained.
pub fn resolve_auto_compact_threshold_percent(
    cfg: &crate::agent::config::Config,
    model_id: &str,
    model: Option<&crate::agent::config::ModelInfo>,
) -> u8 {
    resolve_auto_compact_threshold_percent_from_tiers(
        cfg.config_models
            .get(model_id)
            .and_then(|m| m.auto_compact_threshold_percent),
        cfg.session.auto_compact_threshold_percent,
        model.and_then(|m| m.auto_compact_threshold_percent),
        cfg.remote_settings
            .as_ref()
            .and_then(|r| r.auto_compact_threshold_percent),
    )
}

/// Resolve the full auto-compact preference (percent **or** absolute tokens).
///
/// Precedence (highest first):
///   1. env `GROK_AUTO_COMPACT_THRESHOLD_TOKENS` (absolute)
///   2. env `GROK_AUTO_COMPACT_THRESHOLD_PERCENT`
///   3. user TOML `[session].auto_compact_threshold_tokens` (absolute;
///      wins over session percent when both set)
///   4. percent tiers from [`resolve_auto_compact_threshold_percent`]
///      (model / session percent / remote / default 95)
///
/// Absolute-token mode is session-scoped only (no per-model remote tier yet);
/// percent mode keeps the full 6-tier chain.
pub fn resolve_auto_compact_threshold(
    cfg: &crate::agent::config::Config,
    model_id: &str,
    model: Option<&crate::agent::config::ModelInfo>,
) -> AutoCompactThreshold {
    if let Some(t) = std::env::var(ENV_AUTO_COMPACT_THRESHOLD_TOKENS)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&t| t > 0)
    {
        return AutoCompactThreshold::Tokens(t);
    }
    // Percent env still wins over session tokens so ops can force %.
    if std::env::var(ENV_AUTO_COMPACT_THRESHOLD_PERCENT).is_ok() {
        return AutoCompactThreshold::Percent(resolve_auto_compact_threshold_percent(
            cfg, model_id, model,
        ));
    }
    if let Some(t) = cfg.session.auto_compact_threshold_tokens.filter(|&t| t > 0) {
        return AutoCompactThreshold::Tokens(t);
    }
    AutoCompactThreshold::Percent(resolve_auto_compact_threshold_percent(cfg, model_id, model))
}

/// Lower-level form of [`resolve_auto_compact_threshold_percent`] that takes
/// the four tiers as plain `Option<u8>` values rather than reaching into a
/// `Config`. Useful from sites that don't hold a `Config` reference (e.g.,
/// subagent spawn paths where the parent's config tiers are plumbed in
/// explicitly and the per-model lookup uses the SUBAGENT's resolved model id,
/// not the parent's).
///
/// Precedence: env > `user_per_model` > `user_global` > `gb_per_model`
/// > `gb_global` > `DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT`.
pub fn resolve_auto_compact_threshold_percent_from_tiers(
    user_per_model: Option<u8>,
    user_global: Option<u8>,
    gb_per_model: Option<u8>,
    gb_global: Option<u8>,
) -> u8 {
    fn clamp_env(raw: i64) -> Option<u8> {
        if (0..=100).contains(&raw) {
            Some(raw as u8)
        } else {
            tracing::debug!(
                source = "env",
                value = raw,
                "auto_compact_threshold_percent out of range 0..=100; ignoring"
            );
            None
        }
    }
    let from_env = || -> Option<u8> {
        std::env::var(ENV_AUTO_COMPACT_THRESHOLD_PERCENT)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(clamp_env)
    };

    from_env()
        .or(user_per_model)
        .or(user_global)
        .or(gb_per_model)
        .or(gb_global)
        .unwrap_or(DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT)
}

/// Client default per-compaction wall-clock budget (seconds). Fleet p99 of
/// successful compactions is ~181s (≈225s at 400K+ input), so 300s clears the
/// legit tail with margin while cutting a runaway from the ~600s deadline.
pub const DEFAULT_COMPACTION_WALL_CLOCK_BUDGET_SECS: u64 = 300;

/// Below this, a configured budget is almost certainly a misconfig (fleet
/// success p99 ~181s); logged at `warn`, not clamped.
const COMPACTION_WALL_CLOCK_BUDGET_WARN_SECS: u64 = 120;

/// Env override for the compaction wall-clock budget (seconds). Parsed as
/// `u64`; unparseable values fall through.
const ENV_COMPACTION_WALL_CLOCK_BUDGET_SECS: &str = "GROK_COMPACTION_WALL_CLOCK_SECS";

/// Resolve the per-compaction wall-clock budget (seconds). Precedence: env
/// `GROK_COMPACTION_WALL_CLOCK_SECS` > remote settings global
/// `RemoteSettings.compaction_wall_clock_budget_secs` >
/// [`DEFAULT_COMPACTION_WALL_CLOCK_BUDGET_SECS`] (a per-model `ModelInfo` tier
/// would slot in ahead of the global one).
///
/// `0` **disables** it. Low values are warned, not clamped — any "safe" clamp
/// (e.g. 30s) would itself cut legit compactions, trading one silent failure for
/// another; ops own the value.
pub fn resolve_compaction_wall_clock_budget_secs(gb_global: Option<u64>) -> u64 {
    let from_env = std::env::var(ENV_COMPACTION_WALL_CLOCK_BUDGET_SECS)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    let resolved = from_env
        .or(gb_global)
        .unwrap_or(DEFAULT_COMPACTION_WALL_CLOCK_BUDGET_SECS);
    if resolved > 0 && resolved < COMPACTION_WALL_CLOCK_BUDGET_WARN_SECS {
        tracing::warn!(
            budget_secs = resolved,
            "compaction wall-clock budget {resolved}s is below {COMPACTION_WALL_CLOCK_BUDGET_WARN_SECS}s \
             and may cut legitimate compactions (fleet success p99 ~181s); set 0 to disable"
        );
    }
    resolved
}

#[cfg(test)]
mod compaction_wall_clock_budget_tests {
    use super::resolve_compaction_wall_clock_budget_secs as resolve;

    // Assumes GROK_COMPACTION_WALL_CLOCK_SECS is unset in the test env.
    #[test]
    fn default_global_disable_and_no_clamp() {
        assert_eq!(resolve(None), 300); // client default
        assert_eq!(resolve(Some(450)), 450); // server global wins
        assert_eq!(resolve(Some(0)), 0); // 0 explicitly disables (no clamp)
        assert_eq!(resolve(Some(5)), 5); // low values pass through (warned, not clamped)
    }
}

#[cfg(test)]
mod resolve_auto_compact_threshold_dual_mode_tests {
    use super::*;
    use crate::agent::config::{Config, SessionConfig};

    fn bare_cfg() -> Config {
        Config::default()
    }

    /// Product contract: when nothing is configured, preference is 95%.
    #[test]
    fn default_is_95_percent() {
        let cfg = bare_cfg();
        assert_eq!(DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT, 95);
        assert_eq!(
            resolve_auto_compact_threshold(&cfg, "any", None),
            AutoCompactThreshold::Percent(95)
        );
        assert_eq!(GROK_45_DEFAULT_AUTO_COMPACT_TOKENS, 475_000);
        assert_eq!(GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS, 200_000);
    }

    #[test]
    fn session_tokens_win_over_session_percent() {
        let mut cfg = bare_cfg();
        cfg.session = SessionConfig {
            auto_compact_threshold_percent: Some(98),
            auto_compact_threshold_tokens: Some(GROK_45_LONG_CONTEXT_PRICE_THRESHOLD_TOKENS),
            load_envrc: None,
        };
        assert_eq!(
            resolve_auto_compact_threshold(&cfg, "any", None),
            AutoCompactThreshold::Tokens(200_000)
        );
    }

    #[test]
    fn session_percent_when_tokens_unset() {
        let mut cfg = bare_cfg();
        cfg.session = SessionConfig {
            auto_compact_threshold_percent: Some(90),
            auto_compact_threshold_tokens: None,
            load_envrc: None,
        };
        assert_eq!(
            resolve_auto_compact_threshold(&cfg, "any", None),
            AutoCompactThreshold::Percent(90)
        );
    }
}
