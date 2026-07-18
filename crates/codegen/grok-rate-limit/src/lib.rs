//! Cross-process shared rate-limit cooldowns for Grok OSS.
//!
//! Multiple `grok-oss` processes coordinate via flock + JSON under
//! `$GROK_HOME/rate_limits/` so concurrent sessions do not stampede a
//! rate-limited API. See Surmount FORK.md.
//!
//! # Semantics
//!
//! - **Attempt budget**: not this crate’s concern (sampler stays unlimited by default).
//! - **When to call**: `not_before` is the earliest unix-ms any process may issue a request.
//! - **Merge rule**: on observe, `not_before = max(existing, now + wait)` (strictest wins).
//! - **Disable**: `GROK_DISABLE_SHARED_RATE_LIMIT=1` makes all ops no-ops.

mod store;

pub use store::{
    ProviderKey, RateLimitMeta, RateLimitSnapshot, SharedRateLimitStore, fingerprint_secret,
    shared_rate_limits_disabled,
};

/// Well-known provider key strings (stable identifiers for callers).
pub mod keys {
    pub const XAI: &str = "xai";
    pub const OPENROUTER: &str = "openrouter";
    pub const GITHUB: &str = "github";
}
