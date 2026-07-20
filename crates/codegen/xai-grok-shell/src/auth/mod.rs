pub(crate) mod attribution;
mod auth_provider;
mod config;
pub mod credential_provider;
pub mod credentials_store;
#[path = "devbox_login_stub.rs"]
pub(crate) mod devbox_login;
pub mod device_code;
pub mod error;
mod external_auth;
mod flow;
pub mod harness_secrets;
mod jwt;
pub(crate) mod manager;
mod model;
pub mod oidc;
pub mod openrouter;
pub(crate) mod recovery;
pub(crate) mod refresh;
pub(crate) mod single_flight;
mod storage;
mod token_output;
pub(crate) mod token_type;
pub use auth_provider::{AuthProviderConfig, AuthProviderRef};
pub(crate) use auth_provider::{
    PROVIDER_TIMEOUT_CEILING_SECS, PROVIDER_TOKEN_EXPIRY_SKEW_SECS, ProviderRefreshOutcome,
};
#[cfg(test)]
pub(crate) use auth_provider::{test_backdate_provider_mint, test_counting_provider};
pub(crate) use config::LEGACY_AUTH_SCOPE;
pub use config::{
    ForceLoginTeam, GrokComConfig, OAuth2ProviderConfig, OidcAuthConfig, PreferredAuthMethod,
    XAI_OAUTH2_ISSUER, is_xai_oauth2_issuer, xai_oauth2_issuer,
};
pub(crate) use external_auth::{parse_output, refresh_with_command};
pub(crate) use flow::{
    AuthChannels, run_auth_flow, run_auth_flow_with_stderr_bridge,
    try_ensure_session_noninteractive,
};
pub use flow::{
    AuthUrlInfo, AuthUrlMode, LoginTransportOverride, LogoutResult, ensure_authenticated,
    ensure_authenticated_or_noninteractive, ensure_authenticated_with_override, perform_logout,
    run_cli_login, run_cli_logout, try_ensure_fresh_auth,
};
pub use jwt::{is_jwt_expired_or_near, parse_jwt_expiration};
mod meta;
pub use error::{AuthError, RefreshTokenError, RefreshTokenFailedReason};
pub use harness_secrets::{
    DISABLE_SHARED_HARNESS_ENV, GROK_ZED_CONFIG_DIR_ENV, SharedKeySource,
    probe_shared_openrouter_key, probe_shared_openrouter_key_default,
};
pub use manager::{AuthManager, shared_api_key_provider};
pub use meta::{AuthMeta, GateInfo};
pub use model::{AuthMode, GrokAuth, lookup_auth};
pub(crate) use model::{
    TOKEN_TTL, UserInfo, default_coding_data_retention_opt_out, is_expired, token_suffix,
};
pub(crate) use refresh::DiagnosticUploader;
pub use harness_secrets::{
    GROK_ZED_CONFIG_DIR_ENV, SharedKeySource, probe_shared_openrouter_key,
    probe_shared_openrouter_key_default,
};
pub use openrouter::{
    OPENROUTER_API_KEY_ENV, OPENROUTER_API_KEYS_ENV, OPENROUTER_API_URL,
    OPENROUTER_GROK_45_CATALOG_ID, OpenRouterAuthError, OpenRouterCreditsData,
    OpenRouterCreditsResponse, clear_openrouter_api_key, fetch_openrouter_credit_balance_cents,
    fetch_openrouter_credit_balance_cents_with_key, has_openrouter_api_key,
    is_openrouter_catalog_id, load_openrouter_api_key, load_openrouter_api_key_default,
    openrouter_balance_usd_from_credits, run_openrouter_login, run_openrouter_logout,
    store_openrouter_api_key, usd_to_cents,
};
pub(crate) use refresh::DiagnosticUploader;
pub use storage::{
    clear_api_key, read_api_key, read_auth_json, read_token_by_scope, store_api_key,
};
