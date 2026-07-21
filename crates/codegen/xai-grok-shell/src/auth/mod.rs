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
    ROUTSTR_GROK_45_MODEL, ROUTSTR_NODE_ORIGIN, ROUTSTR_READY_MIN_MSATS, RoutstrAuthError,
    RoutstrBalanceInfo, RoutstrCliError, RoutstrCpfpSuccess, RoutstrFundProbe, RoutstrFundSuccess,
    RoutstrMeltSuccess, RoutstrMintAfterPaySuccess, RoutstrMintOutcome, RoutstrMintQuoteSuccess,
    RoutstrRbfSuccess, RoutstrReadyDecision, RoutstrReadyOutcome, RoutstrRefundOutcome,
    RoutstrSpendSuccess, RoutstrTopupLocalPaySuccess, RoutstrTopupOutcome, RoutstrUtxosSuccess,
    clear_routstr_api_key, complete_routstr_cpfp_reentry_for_tui,
    complete_routstr_cpfp_with_mnemonic, complete_routstr_fund_reentry_for_tui,
    complete_routstr_melt_reentry_for_tui, complete_routstr_melt_reentry_for_tui_with_cashu,
    complete_routstr_mint_after_pay_reentry_for_tui,
    complete_routstr_mint_after_pay_reentry_for_tui_with_cashu,
    complete_routstr_mint_quote_reentry_for_tui,
    complete_routstr_mint_quote_reentry_for_tui_with_cashu, complete_routstr_rbf_reentry_for_tui,
    complete_routstr_rbf_with_mnemonic, complete_routstr_spend_reentry_for_tui,
    complete_routstr_spend_with_mnemonic, complete_routstr_topup_local_pay_reentry_for_tui,
    complete_routstr_topup_local_pay_reentry_for_tui_with_lightning,
    complete_routstr_utxos_reentry_for_tui, complete_routstr_utxos_with_mnemonic,
    create_routstr_balance_with_cashu, create_routstr_lightning_invoice, decide_routstr_ready,
    ensure_routstr_ready, ensure_routstr_ready_with_options, fees_command_lines,
    fetch_routstr_balance_msats, fetch_routstr_balance_msats_with_key,
    fetch_routstr_invoice_status, format_routstr_balance_line, format_routstr_http_error,
    has_routstr_api_key, is_routstr_base_url, is_routstr_catalog_id, load_routstr_api_key,
    load_routstr_api_key_default, parse_routstr_api_key_from_body, parse_routstr_balance_msats,
    parse_routstr_msats_flexible, parse_routstr_refund_cashu_token, probe_routstr_fund_for_tui,
    recover_routstr_invoice_status, redact_secret_preview, refund_routstr_balance_live,
    resolve_fees_network, resolve_product_complete_network, resolve_product_entry_network,
    resolve_spend_fee_rate_for_product, resolve_spend_fee_rate_with_estimates,
    routstr_balance_fetch_enabled_from_disk, routstr_balance_msats_from_info,
    routstr_enabled_from_raw_config, routstr_seed_aead_path, run_routstr_balance, run_routstr_cpfp,
    run_routstr_fees, run_routstr_fund, run_routstr_login, run_routstr_logout,
    run_routstr_melt_with_cashu, run_routstr_mint, run_routstr_mint_with_cashu, run_routstr_rbf,
    run_routstr_redeem, run_routstr_refund, run_routstr_spend, run_routstr_topup,
    run_routstr_topup_recover, run_routstr_topup_status, run_routstr_topup_with_lightning,
    run_routstr_topup_with_options, run_routstr_utxos, should_fetch_routstr_balance,
    store_paid_routstr_key, store_routstr_api_key, topup_routstr_balance_with_cashu,
    try_fetch_live_fee_estimates, try_fetch_live_fee_estimates_for_network, utxos_command_lines,
};
pub use storage::{
    clear_api_key, read_api_key, read_auth_json, read_token_by_scope, store_api_key,
};
