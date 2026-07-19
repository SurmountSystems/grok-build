pub(crate) mod attribution;
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
pub mod routstr;
pub(crate) mod single_flight;
mod storage;
pub(crate) mod token_type;
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
pub(crate) use model::{TOKEN_TTL, UserInfo, is_expired, token_suffix};
pub use openrouter::{
    OPENROUTER_API_KEY_ENV, OPENROUTER_API_KEYS_ENV, OPENROUTER_API_URL,
    OPENROUTER_GROK_45_CATALOG_ID, OpenRouterAuthError, OpenRouterCreditsData,
    OpenRouterCreditsResponse, clear_openrouter_api_key, fetch_openrouter_credit_balance_cents,
    fetch_openrouter_credit_balance_cents_with_key, has_openrouter_api_key,
    is_openrouter_catalog_id, load_openrouter_api_key, load_openrouter_api_key_default,
    openrouter_balance_usd_from_credits, run_openrouter_login, run_openrouter_logout,
    should_fetch_openrouter_balance, should_fetch_openrouter_balance_for_model_id,
    store_openrouter_api_key, usd_to_cents,
};
pub(crate) use refresh::DiagnosticUploader;
pub use routstr::{
    ROUTSTR_API_KEY_ENV, ROUTSTR_API_KEYS_ENV, ROUTSTR_API_URL, ROUTSTR_GROK_45_CATALOG_ID,
    ROUTSTR_GROK_45_MODEL, RoutstrAuthError, RoutstrBalanceInfo, RoutstrCliError, RoutstrFundProbe,
    RoutstrFundSuccess, RoutstrRbfSuccess, RoutstrSpendSuccess, clear_routstr_api_key,
    complete_routstr_fund_reentry_for_tui, complete_routstr_rbf_with_mnemonic,
    complete_routstr_spend_reentry_for_tui, complete_routstr_spend_with_mnemonic,
    fetch_routstr_balance_msats, fetch_routstr_balance_msats_with_key, format_routstr_balance_line,
    has_routstr_api_key, is_routstr_base_url, is_routstr_catalog_id, load_routstr_api_key,
    load_routstr_api_key_default, parse_routstr_balance_msats, probe_routstr_fund_for_tui,
    resolve_spend_fee_rate_for_product, resolve_spend_fee_rate_with_estimates,
    routstr_balance_fetch_enabled_from_disk, routstr_balance_msats_from_info,
    routstr_enabled_from_raw_config, routstr_seed_aead_path, run_routstr_balance, run_routstr_fund,
    run_routstr_login, run_routstr_logout, run_routstr_rbf, run_routstr_refund, run_routstr_spend,
    run_routstr_topup, should_fetch_routstr_balance, store_routstr_api_key,
    try_fetch_live_fee_estimates,
};
pub use storage::{
    clear_api_key, read_api_key, read_auth_json, read_token_by_scope, store_api_key,
};
