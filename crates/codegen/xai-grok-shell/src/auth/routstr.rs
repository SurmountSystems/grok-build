//! Routstr provider helpers: constants, key load/store, login CLI, balance.
//!
//! Mirrors [`super::openrouter`] for the Bitcoin-native inference path.
//! Hot `sk-` / short-lived Cashu bearer strings may use [`CredentialsStore`];
//! BIP-39 seed material must **never** land here (see `grok-bitcoin-wallet`).

use std::io::{self, Write};
use std::path::Path;

use super::credentials_store::{BEARER_USERNAME, CredentialsStore, CredentialsStoreError};

/// Default Routstr OpenAI-compatible API base URL.
pub const ROUTSTR_API_URL: &str = "https://api.routstr.com/v1";

/// Routstr node origin (Lightning invoice paths are **not** under `/v1`).
pub const ROUTSTR_NODE_ORIGIN: &str = "https://api.routstr.com";

/// Environment variable for the Routstr API key (env wins over secret store).
///
/// May hold a single key or a comma-/newline-separated list; additional keys
/// are used as credit-exhaustion failover (see also [`ROUTSTR_API_KEYS_ENV`]).
pub const ROUTSTR_API_KEY_ENV: &str = "ROUTSTR_API_KEY";

/// Optional extra Routstr keys for multi-account credit failover.
/// Comma- or newline-separated. Merged after [`ROUTSTR_API_KEY_ENV`].
pub const ROUTSTR_API_KEYS_ENV: &str = "ROUTSTR_API_KEYS";

/// Catalog key shown in the model picker (separate from native xAI / OpenRouter).
pub const ROUTSTR_GROK_45_CATALOG_ID: &str = "routstr-grok-4.5";

/// Model slug sent to the Routstr API (OpenAI-compatible).
///
/// Confirmed against live `GET https://api.routstr.com/v1/models` (2026-07-18):
/// catalog entry `id: "grok-4.5"`, name `xAI: Grok 4.5`,
/// `canonical_slug: "x-ai/grok-4.5-20260708"`. The OpenAI-compatible request
/// model field uses the short `id` (`grok-4.5`), not the canonical slug.
/// Re-check with the `#[ignore]` live test when the catalog drifts.
pub const ROUTSTR_GROK_45_MODEL: &str = "grok-4.5";

/// Context window for Grok 4.5 on Routstr (aligned with other Grok 4.5 entries).
pub const ROUTSTR_GROK_45_CONTEXT_WINDOW: u64 = 500_000;

/// HTTP-Referer for Routstr logs / app attribution.
pub const ROUTSTR_HTTP_REFERER: &str = "https://github.com/SurmountSystems/grok-oss";

/// Display title for Routstr request attribution.
pub const ROUTSTR_X_TITLE: &str = "Grok OSS";

#[cfg(test)]
mod attribution_tests {
    use super::*;

    #[test]
    fn referer_is_surmount() {
        assert!(ROUTSTR_HTTP_REFERER.contains("SurmountSystems/grok-oss"));
    }

    #[test]
    fn model_slug_and_catalog() {
        assert_eq!(ROUTSTR_GROK_45_MODEL, "grok-4.5");
        assert_eq!(ROUTSTR_GROK_45_CATALOG_ID, "routstr-grok-4.5");
        assert_eq!(ROUTSTR_API_URL, "https://api.routstr.com/v1");
    }

    /// Live catalog check. Default CI stays offline-safe (`#[ignore]`).
    /// Run: `cargo test -p xai-grok-shell --lib live_routstr_grok_45_model_in_catalog -- --ignored`
    #[test]
    #[ignore = "network: live GET https://api.routstr.com/v1/models"]
    fn live_routstr_grok_45_model_in_catalog() {
        let url = format!("{ROUTSTR_API_URL}/models");
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("http client");
        let resp = client
            .get(&url)
            .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
            .header("X-Title", ROUTSTR_X_TITLE)
            .send()
            .expect("routstr /v1/models reachable");
        assert!(
            resp.status().is_success(),
            "models status {}",
            resp.status()
        );
        let body: serde_json::Value = resp.json().expect("models json");
        let items = body
            .get("data")
            .and_then(|d| d.as_array())
            .expect("data array");
        let found = items.iter().any(|m| {
            m.get("id")
                .and_then(|id| id.as_str())
                .is_some_and(|id| id == ROUTSTR_GROK_45_MODEL)
        });
        assert!(
            found,
            "ROUTSTR_GROK_45_MODEL={ROUTSTR_GROK_45_MODEL} missing from live catalog; update constant"
        );
    }
}

/// Whether `base_url` targets Routstr (host is `routstr.com` or a subdomain).
pub fn is_routstr_base_url(base_url: &str) -> bool {
    url::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .is_some_and(|host| host == "routstr.com" || host.ends_with(".routstr.com"))
}

/// Normalize the credential URL used as the store key.
pub fn routstr_credential_url(base_url: Option<&str>) -> String {
    let url = base_url.unwrap_or(ROUTSTR_API_URL).trim_end_matches('/');
    if url.is_empty() {
        ROUTSTR_API_URL.to_owned()
    } else {
        url.to_owned()
    }
}

/// Non-empty `ROUTSTR_API_KEY` from the process environment.
pub fn routstr_api_key_from_env() -> Option<String> {
    std::env::var(ROUTSTR_API_KEY_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Load Routstr API key: env → Grok store (no Zed harness for Routstr).
pub fn load_routstr_api_key(
    store: &CredentialsStore,
) -> Result<Option<String>, CredentialsStoreError> {
    if let Some(key) = routstr_api_key_from_env() {
        return Ok(Some(key));
    }
    let url = routstr_credential_url(None);
    if let Some((_, secret)) = store.read(&url)? {
        return Ok(Some(secret));
    }
    Ok(None)
}

/// Load Routstr API key using the default store under `$GROK_HOME`.
pub fn load_routstr_api_key_default() -> Result<Option<String>, CredentialsStoreError> {
    load_routstr_api_key(&CredentialsStore::default_store())
}

/// Whether any Routstr credential is available (env or Grok store).
pub fn has_routstr_api_key() -> bool {
    load_routstr_api_key_default().ok().flatten().is_some()
}

/// Store a Routstr API key. Refuses when `ROUTSTR_API_KEY` is set.
pub fn store_routstr_api_key(
    store: &CredentialsStore,
    api_key: &str,
) -> Result<(), RoutstrAuthError> {
    if routstr_api_key_from_env().is_some() {
        return Err(RoutstrAuthError::EnvVarSet);
    }
    let key = api_key.trim();
    if key.is_empty() {
        return Err(RoutstrAuthError::EmptyKey);
    }
    let url = routstr_credential_url(None);
    store
        .write(&url, BEARER_USERNAME, key)
        .map_err(RoutstrAuthError::Store)
}

/// Clear the stored Routstr API key (does not unset env).
pub fn clear_routstr_api_key(store: &CredentialsStore) -> Result<(), CredentialsStoreError> {
    store.delete(&routstr_credential_url(None))
}

/// Whether a catalog / model id is the Routstr-backed Grok entry (or a
/// future `routstr-*` catalog id).
pub fn is_routstr_catalog_id(model_id: &str) -> bool {
    let id = model_id.trim();
    id == ROUTSTR_GROK_45_CATALOG_ID || id.starts_with("routstr-")
}

/// Account balance payload from `GET /v1/balance/info` (flexible fields).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RoutstrBalanceInfo {
    #[serde(default)]
    pub msats: Option<u64>,
    #[serde(default)]
    pub balance_msats: Option<u64>,
    #[serde(default)]
    pub balance: Option<u64>,
    #[serde(default)]
    pub sats: Option<u64>,
    #[serde(default)]
    pub balance_sats: Option<u64>,
}

/// Remaining balance in millisatoshis from a balance-info body.
///
/// Uses explicit unit fields only (`msats`, `balance_msats`, `sats`,
/// `balance_sats`). Bare `balance` is ignored (unit ambiguous). Aligned with
/// `grok_bitcoin_wallet::cashu::parse_balance_msats_from_json`.
pub fn routstr_balance_msats_from_info(info: &RoutstrBalanceInfo) -> Option<u64> {
    if let Some(m) = info.msats.or(info.balance_msats) {
        return Some(m);
    }
    if let Some(s) = info.sats.or(info.balance_sats) {
        return Some(s.saturating_mul(1000));
    }
    let _ = info.balance; // ignored until API documents unit
    None
}

/// Parse msats from a raw JSON body (unit-testable without HTTP).
pub fn parse_routstr_balance_msats(body: &str) -> Option<u64> {
    // Try direct struct, then nested `data`.
    if let Ok(info) = serde_json::from_str::<RoutstrBalanceInfo>(body)
        && let Some(m) = routstr_balance_msats_from_info(&info)
    {
        return Some(m);
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if let Some(data) = v.get("data") {
        let info: RoutstrBalanceInfo = serde_json::from_value(data.clone()).ok()?;
        return routstr_balance_msats_from_info(&info);
    }
    None
}

/// Whether product code should attempt a Routstr balance network fetch.
///
/// When `[features] routstr_enabled = false`, the catalog entry is omitted and
/// balance chrome must not hit the Routstr API either. Pure helper for tests
/// and call sites that already know the feature flag.
pub fn should_fetch_routstr_balance(routstr_enabled: bool) -> bool {
    routstr_enabled
}

/// Read `[features].routstr_enabled` from a raw TOML config root (default true).
///
/// Mirrors [`crate::agent::config::routstr_catalog_enabled`] without needing a
/// fully parsed [`crate::agent::config::Config`].
pub fn routstr_enabled_from_raw_config(root: &toml::Value) -> bool {
    root.get("features")
        .and_then(|f| f.get("routstr_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// Load disk config and return whether Routstr balance fetches are allowed.
///
/// Defaults to **enabled** when config is unreadable so a missing/broken file
/// never silently disables a configured key path.
pub fn routstr_balance_fetch_enabled_from_disk() -> bool {
    match crate::config::load_effective_config_disk_only() {
        Ok(root) => should_fetch_routstr_balance(routstr_enabled_from_raw_config(&root)),
        Err(_) => true,
    }
}

/// Fetch remaining Routstr balance (msats) for the configured key.
///
/// Returns `None` when Routstr is disabled in config, no key is available, the
/// request fails, or the body cannot be parsed.
pub async fn fetch_routstr_balance_msats() -> Option<u64> {
    if !routstr_balance_fetch_enabled_from_disk() {
        tracing::debug!("routstr balance: skipped (features.routstr_enabled=false)");
        return None;
    }
    let key = load_routstr_api_key_default().ok().flatten()?;
    fetch_routstr_balance_msats_with_key(&key).await
}

/// Fetch Routstr balance with an explicit API key.
///
/// **Ungated:** does **not** consult `[features] routstr_enabled`. Use only from
/// tests or callers that already decided a network hit is allowed.
/// Product paths must use [`fetch_routstr_balance_msats`], which applies the
/// feature gate (and key load) before calling this helper.
pub async fn fetch_routstr_balance_msats_with_key(api_key: &str) -> Option<u64> {
    let key = api_key.trim();
    if key.is_empty() {
        return None;
    }
    let url = format!("{ROUTSTR_API_URL}/balance/info");
    let client = crate::http::shared_client();
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        tracing::debug!(
            status = response.status().as_u16(),
            "routstr balance: non-success status"
        );
        return None;
    }
    let body = response.text().await.ok()?;
    parse_routstr_balance_msats(&body)
}

#[derive(Debug, thiserror::Error)]
pub enum RoutstrAuthError {
    #[error("{ROUTSTR_API_KEY_ENV} is set; unset it before storing a key in the secret store")]
    EnvVarSet,
    #[error("Routstr API key must not be empty")]
    EmptyKey,
    #[error(transparent)]
    Store(#[from] CredentialsStoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// `grok login --routstr`: store a Routstr API key (`sk-` or `cashuA…`).
///
/// When `api_key` is `Some`, use it; otherwise prompt on stdin (TTY).
pub fn run_routstr_login(grok_home: &Path, api_key: Option<&str>) -> Result<(), RoutstrAuthError> {
    let store = CredentialsStore::at_grok_home(grok_home);
    let key = if let Some(k) = api_key {
        k.to_owned()
    } else if let Some(_k) = routstr_api_key_from_env() {
        eprintln!(
            "{ROUTSTR_API_KEY_ENV} is set; Routstr will use the environment variable \
             (not writing to the secret store)."
        );
        eprintln!("Routstr authentication ready via {ROUTSTR_API_KEY_ENV}.");
        return Ok(());
    } else {
        eprint!("Enter your Routstr API key (sk-… or cashuA…; https://docs.routstr.com/): ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim().to_owned()
    };

    store_routstr_api_key(&store, &key)?;
    eprintln!("Routstr API key saved to the secret store.");
    eprintln!(
        "Select the model with `/model {ROUTSTR_GROK_45_CATALOG_ID}` or \
         `grok -m {ROUTSTR_GROK_45_CATALOG_ID}`."
    );
    Ok(())
}

/// `grok logout --routstr`: remove stored Routstr key.
pub fn run_routstr_logout(grok_home: &Path) -> Result<(), RoutstrAuthError> {
    let store = CredentialsStore::at_grok_home(grok_home);
    clear_routstr_api_key(&store)?;
    if routstr_api_key_from_env().is_some() {
        eprintln!(
            "Cleared stored Routstr key. {ROUTSTR_API_KEY_ENV} is still set and will be used."
        );
    } else {
        eprintln!("Cleared stored Routstr API key.");
    }
    Ok(())
}

/// Format msats as a short human balance line (sats + msats remainder).
pub fn format_routstr_balance_line(msats: u64) -> String {
    let sats = msats / 1000;
    let rem = msats % 1000;
    if rem == 0 {
        format!("{sats} sats ({msats} msats)")
    } else {
        format!("{sats} sats + {rem} msats ({msats} msats total)")
    }
}

/// `grok routstr balance`: fetch remaining prepaid float when a key is present.
pub async fn run_routstr_balance() -> Result<(), RoutstrCliError> {
    // Config-disabled is not a network/key failure — surface that before fetch.
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    if !has_routstr_api_key() {
        return Err(RoutstrCliError::NoApiKey);
    }
    match fetch_routstr_balance_msats().await {
        Some(msats) => {
            println!("Routstr balance: {}", format_routstr_balance_line(msats));
            println!(
                "This is hot prepaid float on the Routstr node, not your local Bitcoin wallet."
            );
            Ok(())
        }
        None => Err(RoutstrCliError::BalanceUnavailable),
    }
}

/// `grok routstr topup`: create a live Routstr Lightning invoice (mainnet node)
/// and print BOLT11 + QR. Falls back to residual copy if the network create fails.
///
/// - No existing key → `purpose=create` (status returns `sk-…` after pay).
/// - Existing key → `purpose=topup` with `Authorization: Bearer`.
/// - Does **not** spend local Bitcoin; user pays the invoice from any LN wallet.
/// - Optional short poll after create; use [`run_routstr_topup_status`] to re-check.
pub fn run_routstr_topup(sats: Option<u64>) -> Result<(), RoutstrCliError> {
    run_routstr_topup_with_options(sats, true)
}

/// Like [`run_routstr_topup`] with optional post-create poll (TTY-friendly).
pub fn run_routstr_topup_with_options(
    sats: Option<u64>,
    poll_after_create: bool,
) -> Result<(), RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let amount = grok_bitcoin_wallet::routstr_invoice::resolve_topup_amount_sats(sats)
        .map_err(RoutstrCliError::Message)?;

    match create_routstr_lightning_invoice(amount) {
        Ok(created) => {
            for line in
                grok_bitcoin_wallet::routstr_invoice::live_invoice_display_lines(&created, true)
            {
                eprintln!("{line}");
            }
            if poll_after_create {
                eprintln!();
                eprintln!(
                    "Polling payment status for up to ~90s (Ctrl-C to stop; re-check later with \
                     `grok routstr topup --status {}`)…",
                    created.invoice_id
                );
                match poll_routstr_invoice_until_paid(&created.invoice_id, 18, 5) {
                    Ok(Some(key)) => {
                        store_paid_routstr_key(&key)?;
                    }
                    Ok(None) => {
                        eprintln!(
                            "Still unpaid or no api_key yet. Pay the BOLT11, then:\n  \
                             grok routstr topup --status {}",
                            created.invoice_id
                        );
                    }
                    Err(e) => {
                        eprintln!("Status poll error: {e}");
                        eprintln!(
                            "Re-check with: grok routstr topup --status {}",
                            created.invoice_id
                        );
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Routstr live invoice create failed: {e}");
            eprintln!("Falling back to residual next-steps (no fabricated invoice).");
            for line in grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(sats) {
                eprintln!("{line}");
            }
            Ok(())
        }
    }
}

/// Poll a previously created invoice; store `api_key` when paid.
pub fn run_routstr_topup_status(invoice_id: &str) -> Result<(), RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let id = invoice_id.trim();
    if id.is_empty() {
        return Err(RoutstrCliError::Message("invoice id must not be empty".into()));
    }
    let status = fetch_routstr_invoice_status(id).map_err(RoutstrCliError::Message)?;
    eprintln!(
        "Invoice {id}: status={} amount_sats={}",
        status.status, status.amount_sats
    );
    if let Some(key) = status.api_key_if_paid() {
        store_paid_routstr_key(key)?;
        return Ok(());
    }
    if status.is_paid() {
        eprintln!("Paid, but no api_key in status body — check Routstr docs / recover endpoint.");
    } else {
        eprintln!("Not paid yet (status={}). Pay the BOLT11, then re-run this command.", status.status);
    }
    Ok(())
}

fn store_paid_routstr_key(key: &str) -> Result<(), RoutstrCliError> {
    let redacted = if key.len() > 12 {
        format!("{}…{}", &key[..4], &key[key.len().saturating_sub(4)..])
    } else {
        "(key)".to_owned()
    };
    if routstr_api_key_from_env().is_some() {
        eprintln!(
            "Payment credited. {ROUTSTR_API_KEY_ENV} is set — not writing to the secret store. \
             Key from node (redacted): {redacted}"
        );
        return Ok(());
    }
    let store = CredentialsStore::default_store();
    store_routstr_api_key(&store, key).map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    eprintln!("Payment confirmed. Routstr API key saved to the secret store ({redacted}).");
    eprintln!(
        "Run `grok routstr balance` and select `/model {ROUTSTR_GROK_45_CATALOG_ID}`."
    );
    Ok(())
}

/// Origin used for `/lightning/*` (strip trailing `/v1` from API URL).
pub fn routstr_node_origin() -> String {
    let base = ROUTSTR_API_URL.trim_end_matches('/');
    if let Some(stripped) = base.strip_suffix("/v1") {
        if stripped.is_empty() {
            ROUTSTR_NODE_ORIGIN.to_owned()
        } else {
            stripped.to_owned()
        }
    } else {
        ROUTSTR_NODE_ORIGIN.to_owned()
    }
}

/// Create a Lightning invoice on the Routstr node (blocking HTTP).
pub fn create_routstr_lightning_invoice(
    amount_sats: u64,
) -> Result<grok_bitcoin_wallet::routstr_invoice::InvoiceCreateResponse, String> {
    use grok_bitcoin_wallet::routstr_invoice::{
        InvoicePurpose, ROUTSTR_LIGHTNING_INVOICE_PATH, invoice_create_request_json,
        parse_invoice_create_response, validate_invoice_amount_sats,
    };

    let amount_sats = validate_invoice_amount_sats(amount_sats)?;
    let existing = load_routstr_api_key_default().ok().flatten();
    let purpose = if existing.is_some() {
        InvoicePurpose::Topup
    } else {
        InvoicePurpose::Create
    };
    let body = invoice_create_request_json(amount_sats, purpose)?;
    let url = format!("{}{ROUTSTR_LIGHTNING_INVOICE_PATH}", routstr_node_origin());

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .body(body);

    if let Some(key) = existing.as_deref() {
        req = req.header("Authorization", format!("Bearer {key}"));
    }

    let resp = req.send().map_err(|e| format!("invoice create request: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| format!("invoice create body: {e}"))?;
    if !status.is_success() {
        return Err(format!("invoice create HTTP {status}: {text}"));
    }
    parse_invoice_create_response(&text)
}

/// Fetch invoice status (blocking HTTP).
pub fn fetch_routstr_invoice_status(
    invoice_id: &str,
) -> Result<grok_bitcoin_wallet::routstr_invoice::InvoiceStatusResponse, String> {
    use grok_bitcoin_wallet::routstr_invoice::{
        ROUTSTR_LIGHTNING_INVOICE_PATH, parse_invoice_status_response,
    };

    let id = invoice_id.trim();
    if id.is_empty() {
        return Err("empty invoice id".into());
    }
    let url = format!(
        "{}{ROUTSTR_LIGHTNING_INVOICE_PATH}/{id}/status",
        routstr_node_origin()
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(&url)
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .send()
        .map_err(|e| format!("invoice status request: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| format!("invoice status body: {e}"))?;
    if !status.is_success() {
        return Err(format!("invoice status HTTP {status}: {text}"));
    }
    parse_invoice_status_response(&text)
}

/// Poll status until paid (returns api_key), attempts exhausted, or error.
fn poll_routstr_invoice_until_paid(
    invoice_id: &str,
    attempts: u32,
    sleep_secs: u64,
) -> Result<Option<String>, String> {
    for i in 0..attempts {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
        }
        let st = fetch_routstr_invoice_status(invoice_id)?;
        if let Some(key) = st.api_key_if_paid() {
            return Ok(Some(key.to_owned()));
        }
        if st.is_paid() {
            return Ok(None);
        }
        eprint!(".");
        let _ = io::stderr().flush();
    }
    eprintln!();
    Ok(None)
}

/// `grok routstr refund`: next steps until CDK refund path lands.
///
/// Honest stub: does **not** claim a completed refund.
pub fn run_routstr_refund() -> Result<(), RoutstrCliError> {
    for line in grok_bitcoin_wallet::funding_cli::refund_next_steps_lines() {
        eprintln!("{line}");
    }
    Ok(())
}

/// Successful local prepare (+ optional broadcast) for on-chain spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrSpendSuccess {
    pub payment_address: String,
    pub payment_sats: u64,
    pub fee_sats: u64,
    pub change_sats: u64,
    pub txid: String,
    pub raw_hex: String,
    /// Set only when a broadcaster accepted the tx (never invented).
    pub broadcast_txid: Option<String>,
    pub network_label: String,
    pub lines: Vec<String>,
}

/// Successful TUI UTXO list (observational; never includes BIP-39 / passphrase).
///
/// `lines` are the same product format as CLI `grok routstr utxos` (balance,
/// outpoints, gap notices). Not a spend/broadcast path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrUtxosSuccess {
    pub network_label: String,
    pub lines: Vec<String>,
}

/// Successful local RBF replacement prepare (+ optional broadcast).
///
/// `broadcast_txid` is set **only** when a broadcaster returned Accepted with a
/// parseable txid — never invented from the local replacement txid alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrRbfSuccess {
    pub payment_address: String,
    pub payment_sats: u64,
    pub original_fee_sats: u64,
    pub fee_sats: u64,
    pub change_sats: u64,
    pub txid: String,
    pub raw_hex: String,
    /// Set only when a broadcaster accepted the replacement (never invented).
    pub broadcast_txid: Option<String>,
    pub network_label: String,
    pub fee_rate_sat_vb: u64,
    pub lines: Vec<String>,
}

/// Successful local CPFP **child** prepare (+ optional broadcast).
///
/// Does **not** replace the parent. `broadcast_txid` is set **only** when a
/// broadcaster returned Accepted with a parseable txid — never invented from
/// the local child txid alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrCpfpSuccess {
    pub payment_address: String,
    pub payment_sats: u64,
    pub parent_fee_sats: u64,
    /// Child absolute fee (not package).
    pub fee_sats: u64,
    pub change_sats: u64,
    pub txid: String,
    pub raw_hex: String,
    /// Set only when a broadcaster accepted the child (never invented).
    pub broadcast_txid: Option<String>,
    pub network_label: String,
    pub fee_rate_sat_vb: u64,
    pub lines: Vec<String>,
}

/// Resolve product spend fee rate (sat/vB) with an injected estimate ladder.
///
/// Pure / offline-testable: no network. Order: explicit override (>0) →
/// estimates halfHour (>0) →
/// [`grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB`].
/// Never returns 0. Callers that treat explicit `0` as invalid must reject
/// before calling (see [`run_routstr_spend`] / `parse_spend_request`).
pub fn resolve_spend_fee_rate_with_estimates(
    user_override: Option<u64>,
    estimates: Option<&grok_bitcoin_wallet::explorer::FeeEstimates>,
) -> u64 {
    use grok_bitcoin_wallet::explorer::{FeePriority, resolve_spend_fee_rate_sat_vb};
    use grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB;

    resolve_spend_fee_rate_sat_vb(
        user_override,
        estimates,
        FeePriority::HalfHour,
        DEFAULT_SPEND_FEE_RATE_SAT_VB,
    )
}

/// Try live mempool.space fee ladder for `network` (`explorer-http`).
///
/// Returns `None` on any failure — never invents rates. Blocking; call from
/// CLI / effect worker, not slash-command parse.
pub fn try_fetch_live_fee_estimates_for_network(
    network: grok_bitcoin_wallet::address_ux::BitcoinNetwork,
) -> Option<grok_bitcoin_wallet::explorer::FeeEstimates> {
    grok_bitcoin_wallet::explorer::MempoolHttpClient::with_defaults(network)
        .ok()
        .and_then(|mut c| c.fetch_fee_estimates())
}

/// Try live mempool.space halfHour ladder (`explorer-http`). Returns `None`
/// on any failure — never invents rates. Blocking; call from CLI / effect
/// worker, not slash-command parse.
///
/// Network from `GROK_BITCOIN_NETWORK` (default mainnet).
pub fn try_fetch_live_fee_estimates() -> Option<grok_bitcoin_wallet::explorer::FeeEstimates> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let btc_net =
        BitcoinNetwork::from_env_str(network_str.trim()).unwrap_or(BitcoinNetwork::Mainnet);
    try_fetch_live_fee_estimates_for_network(btc_net)
}

/// Resolve Bitcoin network for `grok routstr fees`.
///
/// Order: explicit CLI `--network` → `GROK_BITCOIN_NETWORK` → mainnet.
/// Rejects unknown network strings (does not silently fall back when the
/// user passed an explicit invalid value).
pub fn resolve_fees_network(
    cli_network: Option<&str>,
) -> Result<grok_bitcoin_wallet::address_ux::BitcoinNetwork, RoutstrCliError> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    if let Some(raw) = cli_network {
        let t = raw.trim();
        if t.is_empty() {
            return Err(RoutstrCliError::Message(
                "invalid --network: empty (use mainnet|signet|testnet|testnet4)".into(),
            ));
        }
        return BitcoinNetwork::from_env_str(t).ok_or_else(|| {
            RoutstrCliError::Message(format!(
                "unknown --network '{t}' (use mainnet|signet|testnet|testnet4)"
            ))
        });
    }
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let t = network_str.trim();
    if t.is_empty() {
        return Ok(BitcoinNetwork::Mainnet);
    }
    // Env path keeps prior soft-default for unknown labels; product complete
    // fund/spend/rbf/cpfp/utxos use [`resolve_product_complete_network`] /
    // [`resolve_product_entry_network`] (hard error).
    Ok(BitcoinNetwork::from_env_str(t).unwrap_or(BitcoinNetwork::Mainnet))
}

/// Single product-network resolve for complete fund/spend/rbf/cpfp/utxos paths.
///
/// - Empty / whitespace → [`BitcoinNetwork::Mainnet`] (env default).
/// - Known labels (`mainnet|signet|testnet|testnet4` and aliases) → enum.
/// - Unknown (incl. `regtest`) → hard error — **never** silent Mainnet.
///
/// Wallet construction / receive derive must use
/// [`grok_bitcoin_wallet::onchain::bitcoin_network_to_network`] on the result
/// (not a second string parse with a different acceptance set — e.g. do not
/// call env-string derive helpers that still accept `regtest`).
pub fn resolve_product_complete_network(
    network_str: &str,
) -> Result<grok_bitcoin_wallet::address_ux::BitcoinNetwork, RoutstrCliError> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    let t = network_str.trim();
    if t.is_empty() {
        return Ok(BitcoinNetwork::Mainnet);
    }
    BitcoinNetwork::from_env_str(t).ok_or_else(|| {
        RoutstrCliError::Message(format!(
            "unknown network '{t}' (use mainnet|signet|testnet|testnet4)"
        ))
    })
}

/// Product entry network for fund/utxos/spend/rbf/cpfp CLI + TUI (fail-closed).
///
/// Order: explicit CLI/slash `--network` → `GROK_BITCOIN_NETWORK` → mainnet.
/// - Explicit empty → hard error (invalid flag).
/// - Explicit or env unknown (incl. `regtest`) → hard error — **never** silent
///   Mainnet (unlike [`resolve_fees_network`] env soft-default, which is fees-only).
/// - Empty env → Mainnet.
///
/// Call **before** vault unlock so poisoned network fails without touching seed.
/// Fund uses env-only (`cli_network = None`); same acceptance as spend entry.
pub fn resolve_product_entry_network(
    cli_network: Option<&str>,
) -> Result<grok_bitcoin_wallet::address_ux::BitcoinNetwork, RoutstrCliError> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    if let Some(raw) = cli_network {
        let t = raw.trim();
        if t.is_empty() {
            return Err(RoutstrCliError::Message(
                "invalid --network: empty (use mainnet|signet|testnet|testnet4)".into(),
            ));
        }
        return BitcoinNetwork::from_env_str(t).ok_or_else(|| {
            RoutstrCliError::Message(format!(
                "unknown --network '{t}' (use mainnet|signet|testnet|testnet4)"
            ))
        });
    }
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    resolve_product_complete_network(&network_str)
}

/// Pure product lines for `grok routstr fees` (inject estimates; offline tests).
pub fn fees_command_lines(
    estimates: Option<&grok_bitcoin_wallet::explorer::FeeEstimates>,
    network_label: &str,
) -> Vec<String> {
    grok_bitcoin_wallet::funding_cli::fees_cli_result_lines(estimates, network_label)
}

/// `grok routstr fees [--network …]`: print mempool fee estimate ladder only.
///
/// Live fetch via rate-limited mempool.space (`explorer-http`). Never invents
/// rates when fetch fails — prints honest unavailable copy. Not RBF/CPFP.
pub fn run_routstr_fees(cli_network: Option<&str>) -> Result<(), RoutstrCliError> {
    let btc_net = resolve_fees_network(cli_network)?;
    let network_label = btc_net.as_str();
    let estimates = try_fetch_live_fee_estimates_for_network(btc_net);
    let lines = fees_command_lines(estimates.as_ref(), network_label);
    for line in &lines {
        println!("{line}");
    }
    // Exit 0 with unavailable copy is intentional (honest offline): CLI still
    // succeeds so scripts can print guidance; rates were not fabricated.
    Ok(())
}

/// Pure product lines for `grok routstr utxos` from a gap-sync snapshot
/// (offline-testable; inject mock snapshot — no network).
pub fn utxos_command_lines(
    snap: &grok_bitcoin_wallet::descriptor_wallet::WalletSyncSnapshot,
    network_label: &str,
) -> Vec<String> {
    grok_bitcoin_wallet::funding_cli::format_gap_sync_utxos_cli_lines(snap, network_label)
}

/// Core UTXO list after vault unlock + re-entry (shared CLI path).
///
/// Gap-limit ChainSource sync via
/// [`grok_bitcoin_wallet::descriptor_wallet::list_bip84_utxos_with_gap_sync`]
/// (default [`GapExtendOptions`]; not full bdk auto-sync). Snapshot UTXOs are
/// authoritative — no post-sync re-list. Product chain selector (default
/// mempool; env selectable). Wrong passphrase fail-closed.
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Never
/// log / format the secret.
pub fn complete_routstr_utxos_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<Vec<String>, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        open_product_chain_source, product_chain_source_config_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, GapExtendOptions, list_bip84_utxos_with_gap_sync,
    };
    use grok_bitcoin_wallet::funding_cli::bip39_passphrase_active_notice_lines;
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (no dual string parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str();
    // Shared Testnet4 → Testnet mapping for descriptors (matches chain_select / Electrum).
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    let mut wallet = DescriptorWallet::from_mnemonic_with_passphrase(
        mnemonic,
        pass,
        rust_net,
        DEFAULT_RECEIVE_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    let chain_cfg = product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
    let chain = open_product_chain_source(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;

    let snap = list_bip84_utxos_with_gap_sync(
        &mut wallet,
        chain.as_ref(),
        mnemonic,
        pass,
        GapExtendOptions::default(),
    )
    .map_err(RoutstrCliError::Wallet)?;

    let mut lines = utxos_command_lines(&snap, network_label);
    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }
    Ok(lines)
}

/// `grok routstr utxos [--network …]`: list local wallet UTXOs + on-chain balance.
///
/// Requires SeedVault unlock + recovery-phrase re-entry (same gate as spend/fund).
/// Gap-limit ChainSource sync (product chain selector; default mempool). Never
/// invents UTXOs. Not a spend/broadcast path.
pub fn run_routstr_utxos(
    grok_home: &Path,
    cli_network: Option<&str>,
) -> Result<(), RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Fail-closed product network before unlock (not fees soft-default).
    let btc_net = resolve_product_entry_network(cli_network)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal utxos path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    eprintln!("Authorize UTXO list: re-enter your recovery phrase (words are not re-displayed).");
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        if let Err(e) = gate.begin_reentry_without_display(unlocked) {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not listing UTXOs".into(),
            ));
        }
        if let Err(e) = gate.confirm_reentry(&reentry) {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    }

    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };

    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or chain/sync failure) so seed material
    // does not linger until the stack frame ends.
    let result = complete_routstr_utxos_with_mnemonic(unlocked, &network_str, &bip39_pass);
    session.lock();
    let lines = result?;

    for line in &lines {
        println!("{line}");
    }
    Ok(())
}

/// TUI UTXO list after unlock re-entry (no BIP-39 in returned payload).
///
/// Same SeedVault + recovery-phrase gates as [`run_routstr_utxos`] / spend.
/// Observational only — never broadcasts. Product chain selector (default
/// mempool; env selectable). Gap notices still shown on success lines.
///
/// `cli_network`: explicit slash `--network` / `None` →
/// [`resolve_product_entry_network`] (env `GROK_BITCOIN_NETWORK` or mainnet;
/// unknown labels fail closed — never silent Mainnet).
///
/// `bip39_passphrase`: `Some` from private TUI modal (empty = default path for
/// this unlock); `None` loads env. Never persisted.
///
/// **Locks session on all paths** (Ok and Err after unlock) so seed material
/// does not linger on post-unlock failure.
pub fn complete_routstr_utxos_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    cli_network: Option<&str>,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrUtxosSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before unlock (not fees soft-default).
    let btc_net = resolve_product_entry_network(cli_network)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal utxos path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let mut gate = MnemonicBackupGate::new();
    if let Err(e) = gate.begin_reentry_without_display(unlocked) {
        session.lock();
        return Err(RoutstrCliError::Wallet(e));
    }
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not listing UTXOs".into(),
        ));
    }
    if let Err(e) = gate.confirm_reentry(reentry_phrase) {
        session.lock();
        return Err(RoutstrCliError::Wallet(e));
    }
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or chain/sync failure).
    let result = complete_routstr_utxos_with_mnemonic(unlocked, &network_str, &bip39_pass);
    session.lock();
    let lines = result?;
    Ok(RoutstrUtxosSuccess {
        network_label: network_str,
        lines,
    })
}

/// Resolve product spend fee rate (sat/vB).
///
/// Order: explicit user override (>0) → live mempool.space halfHour estimates
/// (`explorer-http`) → [`grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB`].
/// Never invents a rate from a failed fetch; never returns 0.
///
/// **Product paths must reject explicit `0` before calling** (CLI uses
/// `parse_spend_request` first). A `Some(0)` here is treated as unset by the
/// pure ladder helper — not a product validation substitute.
///
/// Blocking network when override is absent; prefer
/// [`resolve_spend_fee_rate_with_estimates`] in unit tests.
pub fn resolve_spend_fee_rate_for_product(user_override: Option<u64>) -> u64 {
    if let Some(n) = user_override
        && n > 0
    {
        return n;
    }
    resolve_spend_fee_rate_with_estimates(None, try_fetch_live_fee_estimates().as_ref())
}

/// `grok routstr spend <address> <sats> [--broadcast] [--fee-rate N]`.
///
/// **Dry-run by default** (build/sign/extract only). Explicit `--broadcast`
/// submits via the product chain selector
/// ([`grok_bitcoin_wallet::chain_select`]; default **mempool** `POST /api/tx`
/// when `GROK_BITCOIN_CHAIN_SOURCE` is unset; Esplora `POST /tx` or Electrum
/// `blockchain.transaction.broadcast` when env + optional features match).
/// Requires SeedVault unlock + full recovery-phrase re-entry (same gate as fund).
/// Never mints a new wallet; keyring errors never mint.
///
/// When `fee_rate_sat_vb` is `None`, uses explorer halfHour estimates when the
/// HTTP client can fetch them; otherwise the wallet default (5 sat/vB).
/// Explicit `--fee-rate 0` is rejected (same as TUI `fee=0`).
pub fn run_routstr_spend(
    grok_home: &Path,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        parse_spend_request, password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Parse with the *user* option first so:
    // - explicit `Some(0)` is rejected (parity with TUI `fee=0`)
    // - `fee_rate_explicit` reflects whether the user passed --fee-rate
    let mut req = parse_spend_request(payment_address, amount_sats, broadcast, fee_rate_sat_vb)
        .map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    if !req.fee_rate_explicit {
        // Blocking fetch only when user omitted fee; not on slash parse.
        req.fee_rate_sat_vb = resolve_spend_fee_rate_for_product(None);
    }

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal spend path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    // Re-entry gate (same as fund): authorize spend without re-displaying words.
    eprintln!(
        "Authorize on-chain spend: re-enter your recovery phrase (words are not re-displayed)."
    );
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    // Confirm re-entry matches vault material (begin_reentry + confirm).
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(unlocked)
            .map_err(RoutstrCliError::Wallet)?;
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not spending".into(),
            ));
        }
        gate.confirm_reentry(&reentry).map_err(|e| {
            session.lock();
            RoutstrCliError::Wallet(e)
        })?;
    }

    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;

    // Optional BIP-39 passphrase from env at unlock time only (never persisted).
    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_spend_with_mnemonic(
        unlocked,
        &network_str,
        &req.payment_address,
        req.amount_sats,
        req.broadcast,
        req.fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    let success = result?;

    for line in &success.lines {
        // Prepared summary on stderr; keep the full raw-hex block off stderr so
        // dry-run can put hex alone on stdout for pipes (filter label + body +
        // copy note, not just the "Raw tx hex" prefix).
        if grok_bitcoin_wallet::funding_cli::is_spend_raw_hex_output_line(line, &success.raw_hex) {
            continue;
        }
        eprintln!("{line}");
    }
    if success.broadcast_txid.is_none() && !req.broadcast {
        println!("{}", success.raw_hex);
        eprintln!("(Full raw tx hex written to stdout above for inspection / external broadcast.)");
    } else if let Some(ref txid) = success.broadcast_txid {
        println!("{txid}");
    }

    Ok(success)
}

/// Load optional BIP-39 passphrase for product unlock/sign paths.
///
/// Always via [`Bip39Passphrase::from_env`] — never hardcoded empty at the
/// entrypoint (empty env → default path). Wrapper keeps Debug redacted.
fn product_bip39_passphrase_from_env() -> grok_bitcoin_wallet::mnemonic::Bip39Passphrase {
    grok_bitcoin_wallet::mnemonic::Bip39Passphrase::from_env()
}

/// Resolve product BIP-39 passphrase: explicit TUI modal value wins over env.
///
/// - `Some(s)` → use `s` for this unlock only (empty string = default path).
///   Never falls back to env when explicit is provided (modal owns the secret).
/// - `None` → [`product_bip39_passphrase_from_env`] (CLI / unlock without
///   private passphrase prompt).
///
/// Never persists. Never log / format the secret.
fn product_bip39_passphrase(
    explicit: Option<&str>,
) -> grok_bitcoin_wallet::mnemonic::Bip39Passphrase {
    match explicit {
        Some(s) => grok_bitcoin_wallet::mnemonic::Bip39Passphrase::new(s.to_owned()),
        None => product_bip39_passphrase_from_env(),
    }
}

/// Core spend after vault unlock + re-entry (shared by CLI and TUI complete path).
///
/// Does **not** print or return BIP-39. Uses the product chain selector
/// ([`grok_bitcoin_wallet::chain_select`]; default **mempool** when
/// `GROK_BITCOIN_CHAIN_SOURCE` is unset) for both UTXO list and `--broadcast`
/// (mempool `POST /api/tx`, Esplora `POST /tx`, Electrum
/// `blockchain.transaction.broadcast`). Optional shell features `esplora` /
/// `electrum` forward to the wallet crate (not default CI).
///
/// UTXO discovery uses gap-limit ChainSource sync
/// (`select_and_prepare_bip84_spend_with_gap_sync` + default
/// `GapExtendOptions` — BIP44-style look-ahead 20, hard `MAX_ADDRESS_GAP`)
/// **before** coin select/sign. Not full `bdk_wallet` auto-sync. RBF/CPFP
/// sibling paths take explicit prevouts and do **not** re-fetch or re-extend;
/// their broadcast path uses the same product broadcaster selector.
///
/// On select/prepare failure **after** successful gap-extend, surfaces the
/// cause plus honest hit-max / extended-window notices from
/// `gap_sync_spend_notice_lines` (not success-path only). Sync-stage
/// failures (wrong passphrase, chain list error) map to
/// `RoutstrCliError::Wallet` without fabricated notices.
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Product
/// callers load it via [`product_bip39_passphrase_from_env`] at unlock time —
/// never CredentialsStore / watch_session / chat. Never log / format the secret.
pub fn complete_routstr_spend_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: u64,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        open_product_chain_source, open_product_tx_broadcaster,
        product_chain_source_config_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, GapExtendOptions, broadcast_raw_tx,
        gap_sync_spend_notice_lines, select_and_prepare_bip84_spend_with_gap_sync,
    };
    use grok_bitcoin_wallet::funding_cli::{
        bip39_passphrase_active_notice_lines, format_spend_broadcast_failed_lines,
        format_spend_broadcast_success_lines, format_spend_fee_meta_lines,
        format_spend_prepared_lines, format_spend_rbf_input_lines, spend_broadcast_claimed_txid,
    };
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (same as utxos; no dual parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    let mut wallet = DescriptorWallet::from_mnemonic_with_passphrase(
        mnemonic,
        pass,
        rust_net,
        DEFAULT_RECEIVE_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    // Live chain + matching broadcaster via product selector (default mempool).
    let chain_cfg = product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
    let chain = open_product_chain_source(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;

    // Gap-limit ChainSource sync (BIP44-style look-ahead) before coin select —
    // recovers deep indices near the window tip. Not full bdk_wallet auto-sync.
    // RBF/CPFP keep explicit prevouts and do not re-extend.
    // AfterSync failures keep hit-max / extend notices (not success-path only).
    let synced = select_and_prepare_bip84_spend_with_gap_sync(
        &mut wallet,
        chain.as_ref(),
        mnemonic,
        payment_address,
        amount_sats,
        fee_rate_sat_vb,
        pass,
        GapExtendOptions::default(),
    )
    .map_err(map_gap_sync_spend_failure)?;
    let prepared = &synced.prepared;

    let raw_hex = prepared.raw_hex();
    let txid = prepared.txid_hex();
    let mut lines = format_spend_prepared_lines(
        payment_address,
        prepared.payment_sats,
        prepared.fee_sats,
        prepared.change_sats,
        &txid,
        &raw_hex,
        broadcast,
    );
    // RBF-aware fee meta (effective rate + BIP-125 signal note). Uses weight vB
    // when available; never claims a replacement was broadcast.
    lines.extend(format_spend_fee_meta_lines(
        prepared.fee_sats,
        prepared.weight_vbytes(),
        fee_rate_sat_vb,
    ));
    // Same-input RBF needs original prevouts; print --input lines for copy into rbf CLI.
    lines.extend(format_spend_rbf_input_lines(&prepared.selected_inputs));
    // Honest gap-extend meta only when the window grew or max gap blocked further growth.
    lines.extend(gap_sync_spend_notice_lines(&synced.sync));
    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }

    let broadcast_txid = if broadcast {
        // Same ProductChainSourceConfig as UTXO list (aligned push backend).
        let mut broadcaster =
            open_product_tx_broadcaster(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;
        match broadcast_raw_tx(broadcaster.as_mut(), &raw_hex) {
            Ok(res) => {
                lines.extend(format_spend_broadcast_success_lines(
                    &res.txid,
                    &network_label,
                ));
                spend_broadcast_claimed_txid(true, Some(&res.txid))
            }
            Err(e) => {
                // Failure after local prepare: append full hex so CLI/TUI can
                // external-broadcast without re-running unlock (never claims accept).
                lines.extend(format_spend_broadcast_failed_lines(
                    &e.to_string(),
                    &raw_hex,
                ));
                return Err(RoutstrCliError::Message(lines.join("\n")));
            }
        }
    } else {
        None
    };

    Ok(RoutstrSpendSuccess {
        payment_address: payment_address.to_owned(),
        payment_sats: prepared.payment_sats,
        fee_sats: prepared.fee_sats,
        change_sats: prepared.change_sats,
        txid,
        raw_hex,
        broadcast_txid,
        network_label,
        lines,
    })
}

/// `grok routstr rbf <address> <sats> --original-fee N --original-vbytes V --input ... [--broadcast] [--fee-rate N]`.
///
/// Rebuilds a **same-input** BIP-125 RBF replacement at a higher absolute fee.
/// Requires original prevouts (`--input txid:vout:amount:address` from spend
/// dry-run meta) — does **not** re-select confirmed UTXOs (those disappear once
/// the stuck tx is in the mempool).
/// **Dry-run by default.** Explicit `--broadcast` submits via the product chain
/// selector (default mempool; Esplora/Electrum when env + optional features match —
/// same as spend). Same SeedVault unlock + recovery-phrase re-entry as spend.
/// Never claims broadcast without Accepted + parseable txid.
///
/// When `fee_rate_sat_vb` is `None`, uses explorer halfHour estimates when
/// available; otherwise the wallet default. Explicit `Some(0)` is rejected.
/// Product uses plan_rbf_fee_bump recommended absolute fee (not floor rate).
pub fn run_routstr_rbf(
    grok_home: &Path,
    payment_address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    input_specs: &[String],
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Result<RoutstrRbfSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        parse_rbf_replace_request, password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    let mut req = parse_rbf_replace_request(
        payment_address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        input_specs,
        broadcast,
        fee_rate_sat_vb,
    )
    .map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    if !req.fee_rate_explicit {
        req.fee_rate_sat_vb = resolve_spend_fee_rate_for_product(None);
    }

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal rbf path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    eprintln!(
        "Authorize RBF replacement spend: re-enter your recovery phrase (words are not re-displayed)."
    );
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(unlocked)
            .map_err(RoutstrCliError::Wallet)?;
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not building RBF replacement".into(),
            ));
        }
        gate.confirm_reentry(&reentry).map_err(|e| {
            session.lock();
            RoutstrCliError::Wallet(e)
        })?;
    }

    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;

    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_rbf_with_mnemonic(
        unlocked,
        &network_str,
        &req.payment_address,
        req.amount_sats,
        req.original_fee_sats,
        req.original_vbytes,
        &req.inputs,
        req.broadcast,
        req.fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    let success = result?;

    for line in &success.lines {
        if grok_bitcoin_wallet::funding_cli::is_spend_raw_hex_output_line(line, &success.raw_hex) {
            continue;
        }
        eprintln!("{line}");
    }
    if success.broadcast_txid.is_none() && !req.broadcast {
        println!("{}", success.raw_hex);
        eprintln!(
            "(Full raw replacement hex written to stdout above for inspection / external broadcast.)"
        );
    } else if let Some(ref txid) = success.broadcast_txid {
        println!("{txid}");
    }

    Ok(success)
}

/// Core same-input RBF replacement after vault unlock + re-entry (CLI path).
///
/// Does **not** print or return BIP-39. Does **not** re-select from chain or
/// gap-extend — uses `original_inputs` only. BIP84 **signing** scan is
/// `PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP` (`MAX_ADDRESS_GAP`) so deep indices
/// recovered by product gap-sync spend still match keys (not
/// `DEFAULT_RECEIVE_GAP`). Optional broadcast via product chain selector
/// (mempool / Esplora / Electrum, same env as spend UTXO).
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Load via
/// [`product_bip39_passphrase_from_env`] at unlock — never persist. Never log it.
pub fn complete_routstr_rbf_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    payment_address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    original_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<RoutstrRbfSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        open_product_tx_broadcaster, product_chain_source_config_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP, broadcast_raw_tx,
        prepare_rbf_replacement,
    };
    use grok_bitcoin_wallet::funding_cli::{
        bip39_passphrase_active_notice_lines, format_rbf_replacement_prepared_lines,
        format_spend_broadcast_failed_lines, format_spend_broadcast_success_lines,
        format_spend_fee_meta_lines, spend_broadcast_claimed_txid,
    };
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (same as utxos/spend; no dual parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    // Wallet construction gap is for change address only; explicit prevouts
    // carry spend UTXOs. Signing uses PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP so
    // deep indices recovered by product gap-sync spend still match keys.
    let wallet = DescriptorWallet::from_mnemonic_with_passphrase(
        mnemonic,
        pass,
        rust_net,
        DEFAULT_RECEIVE_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    if original_inputs.is_empty() {
        return Err(RoutstrCliError::Message(
            "RBF requires at least one --input txid:vout:amount:address (same prevouts as stuck tx)"
                .into(),
        ));
    }
    let utxos: Vec<_> = original_inputs.iter().map(|s| s.to_wallet_utxo()).collect();

    // Same-input absolute-fee path: no chain re-select / no gap re-extend
    // (confirmed UTXOs vanish in mempool). Signing scan covers hard max so
    // deep gap-sync recovered prevouts still sign (not DEFAULT_RECEIVE_GAP).
    let rbf = prepare_rbf_replacement(
        &wallet,
        mnemonic,
        &utxos,
        payment_address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        fee_rate_sat_vb,
        pass,
        PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    let prepared = &rbf.prepared;
    let raw_hex = prepared.raw_hex();
    let txid = prepared.txid_hex();
    let mut lines = format_rbf_replacement_prepared_lines(
        payment_address,
        prepared.payment_sats,
        rbf.original_fee_sats,
        prepared.fee_sats,
        prepared.change_sats,
        &txid,
        &raw_hex,
        broadcast,
        &rbf.plan,
    );
    lines.extend(format_spend_fee_meta_lines(
        prepared.fee_sats,
        prepared.weight_vbytes(),
        rbf.fee_rate_sat_vb,
    ));
    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }

    let broadcast_txid = if broadcast {
        let chain_cfg = product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
        let mut broadcaster =
            open_product_tx_broadcaster(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;
        match broadcast_raw_tx(broadcaster.as_mut(), &raw_hex) {
            Ok(res) => {
                lines.extend(format_spend_broadcast_success_lines(
                    &res.txid,
                    &network_label,
                ));
                spend_broadcast_claimed_txid(true, Some(&res.txid))
            }
            Err(e) => {
                lines.extend(format_spend_broadcast_failed_lines(
                    &e.to_string(),
                    &raw_hex,
                ));
                return Err(RoutstrCliError::Message(lines.join("\n")));
            }
        }
    } else {
        spend_broadcast_claimed_txid(false, None)
    };

    Ok(RoutstrRbfSuccess {
        payment_address: payment_address.to_owned(),
        payment_sats: prepared.payment_sats,
        original_fee_sats: rbf.original_fee_sats,
        fee_sats: prepared.fee_sats,
        change_sats: prepared.change_sats,
        txid,
        raw_hex,
        broadcast_txid,
        network_label,
        fee_rate_sat_vb: rbf.fee_rate_sat_vb,
        lines,
    })
}

/// `grok routstr cpfp <address> <sats> --parent-fee N --parent-vbytes V --parent ... [--extra-input ...] [--broadcast] [--fee-rate N]`.
///
/// Builds a CPFP **child** spending wallet-owned parent output(s) so the
/// parent+child package meets the target fee rate. Optional `--extra-input`
/// confirmed UTXOs fund the child fee when the parent alone is short.
/// **Dry-run by default.** Explicit `--broadcast` submits via the product chain
/// selector (default mempool; Esplora/Electrum when env + optional features match —
/// same as spend). Same SeedVault unlock + recovery-phrase re-entry as spend.
/// Never claims the parent was replaced. Never claims broadcast without
/// Accepted + parseable txid.
///
/// When `fee_rate_sat_vb` is `None`, uses explorer halfHour estimates when
/// available; otherwise the wallet default. Explicit `Some(0)` is rejected.
pub fn run_routstr_cpfp(
    grok_home: &Path,
    payment_address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parent_specs: &[String],
    extra_specs: &[String],
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Result<RoutstrCpfpSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        parse_cpfp_child_request, password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    let mut req = parse_cpfp_child_request(
        payment_address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        parent_specs,
        extra_specs,
        broadcast,
        fee_rate_sat_vb,
    )
    .map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    if !req.fee_rate_explicit {
        req.fee_rate_sat_vb = resolve_spend_fee_rate_for_product(None);
    }

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal cpfp path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    eprintln!(
        "Authorize CPFP child spend: re-enter your recovery phrase (words are not re-displayed)."
    );
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(unlocked)
            .map_err(RoutstrCliError::Wallet)?;
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not building CPFP child".into(),
            ));
        }
        gate.confirm_reentry(&reentry).map_err(|e| {
            session.lock();
            RoutstrCliError::Wallet(e)
        })?;
    }

    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;

    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_cpfp_with_mnemonic(
        unlocked,
        &network_str,
        &req.payment_address,
        req.amount_sats,
        req.parent_fee_sats,
        req.parent_vbytes,
        &req.parents,
        &req.extra_inputs,
        req.broadcast,
        req.fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    let success = result?;

    for line in &success.lines {
        if grok_bitcoin_wallet::funding_cli::is_spend_raw_hex_output_line(line, &success.raw_hex) {
            continue;
        }
        eprintln!("{line}");
    }
    if success.broadcast_txid.is_none() && !req.broadcast {
        println!("{}", success.raw_hex);
        eprintln!(
            "(Full raw child hex written to stdout above for inspection / external broadcast.)"
        );
    } else if let Some(ref txid) = success.broadcast_txid {
        println!("{txid}");
    }

    Ok(success)
}

/// Core CPFP child prepare after vault unlock + re-entry (CLI path).
///
/// Does **not** print or return BIP-39. Uses parent + optional extra inputs only
/// (no chain re-select / no gap re-extend). BIP84 **signing** scan is
/// `PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP` so deep gap-sync recovered addresses
/// still sign. Optional broadcast via product chain selector (same env as
/// spend). Never claims the parent was replaced.
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Load via
/// [`product_bip39_passphrase_from_env`] at unlock — never persist. Never log it.
pub fn complete_routstr_cpfp_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    payment_address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parents: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    extra_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<RoutstrCpfpSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        open_product_tx_broadcaster, product_chain_source_config_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP, broadcast_raw_tx,
        prepare_cpfp_child,
    };
    use grok_bitcoin_wallet::funding_cli::{
        bip39_passphrase_active_notice_lines, format_cpfp_child_fee_meta_lines,
        format_cpfp_child_prepared_lines, format_spend_broadcast_failed_lines,
        format_spend_broadcast_success_lines, spend_broadcast_claimed_txid,
    };
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (same as utxos/spend/rbf; no dual parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    // Construction gap for change only; parents/extras are explicit prevouts.
    // Sign with PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP (deep gap-sync recovery).
    let wallet = DescriptorWallet::from_mnemonic_with_passphrase(
        mnemonic,
        pass,
        rust_net,
        DEFAULT_RECEIVE_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    if parents.is_empty() {
        return Err(RoutstrCliError::Message(
            "CPFP requires at least one --parent txid:vout:amount:address (wallet-owned parent output)"
                .into(),
        ));
    }
    let parent_utxos: Vec<_> = parents.iter().map(|s| s.to_wallet_utxo()).collect();
    let extra_utxos: Vec<_> = extra_inputs.iter().map(|s| s.to_wallet_utxo()).collect();

    // Explicit prevouts only — no chain re-select / no gap re-extend. Signing
    // scan = hard max so deep recovered parent/extra addresses still match.
    let cpfp = prepare_cpfp_child(
        &wallet,
        mnemonic,
        &parent_utxos,
        &extra_utxos,
        payment_address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        fee_rate_sat_vb,
        pass,
        PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    let prepared = &cpfp.prepared;
    let raw_hex = prepared.raw_hex();
    let txid = prepared.txid_hex();
    let mut lines = format_cpfp_child_prepared_lines(
        payment_address,
        prepared.payment_sats,
        cpfp.parent_fee_sats,
        prepared.fee_sats,
        prepared.change_sats,
        &txid,
        &raw_hex,
        broadcast,
        &cpfp.plan,
    );
    // Package target vs child/package effective — not spend "requested vs effective"
    // on the child alone (which misreads min-relay children under overpaying parents).
    lines.extend(format_cpfp_child_fee_meta_lines(
        cpfp.parent_fee_sats,
        cpfp.parent_vbytes,
        prepared.fee_sats,
        prepared.weight_vbytes(),
        cpfp.fee_rate_sat_vb,
    ));
    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }

    let broadcast_txid = if broadcast {
        let chain_cfg = product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
        let mut broadcaster =
            open_product_tx_broadcaster(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;
        match broadcast_raw_tx(broadcaster.as_mut(), &raw_hex) {
            Ok(res) => {
                lines.extend(format_spend_broadcast_success_lines(
                    &res.txid,
                    &network_label,
                ));
                spend_broadcast_claimed_txid(true, Some(&res.txid))
            }
            Err(e) => {
                lines.extend(format_spend_broadcast_failed_lines(
                    &e.to_string(),
                    &raw_hex,
                ));
                return Err(RoutstrCliError::Message(lines.join("\n")));
            }
        }
    } else {
        spend_broadcast_claimed_txid(false, None)
    };

    Ok(RoutstrCpfpSuccess {
        payment_address: payment_address.to_owned(),
        payment_sats: prepared.payment_sats,
        parent_fee_sats: cpfp.parent_fee_sats,
        fee_sats: prepared.fee_sats,
        change_sats: prepared.change_sats,
        txid,
        raw_hex,
        broadcast_txid,
        network_label,
        fee_rate_sat_vb: cpfp.fee_rate_sat_vb,
        lines,
    })
}

/// TUI spend after unlock re-entry (no BIP-39 in returned payload).
///
/// `bip39_passphrase`: `Some` from private TUI modal (empty = default path for
/// this unlock); `None` loads [`GROK_BITCOIN_BIP39_PASSPHRASE`](grok_bitcoin_wallet::mnemonic::BIP39_PASSPHRASE_ENV)
/// when set. Never persisted.
pub fn complete_routstr_spend_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: u64,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal spend path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let mut gate = MnemonicBackupGate::new();
    gate.begin_reentry_without_display(unlocked)
        .map_err(RoutstrCliError::Wallet)?;
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not spending".into(),
        ));
    }
    gate.confirm_reentry(reentry_phrase).map_err(|e| {
        session.lock();
        RoutstrCliError::Wallet(e)
    })?;
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_spend_with_mnemonic(
        unlocked,
        &network_str,
        payment_address,
        amount_sats,
        broadcast,
        fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    result
}

/// TUI same-input RBF after unlock re-entry (no BIP-39 in returned payload).
///
/// Uses original prevouts only — never re-selects confirmed UTXOs. Fee rate
/// must already be resolved by the caller (effect worker); this path does not
/// fetch estimates.
///
/// `bip39_passphrase`: `Some` from private TUI modal; `None` → env. Never persisted.
pub fn complete_routstr_rbf_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    payment_address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    original_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrRbfSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal rbf path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let mut gate = MnemonicBackupGate::new();
    gate.begin_reentry_without_display(unlocked)
        .map_err(RoutstrCliError::Wallet)?;
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not building RBF replacement".into(),
        ));
    }
    gate.confirm_reentry(reentry_phrase).map_err(|e| {
        session.lock();
        RoutstrCliError::Wallet(e)
    })?;
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_rbf_with_mnemonic(
        unlocked,
        &network_str,
        payment_address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        original_inputs,
        broadcast,
        fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    result
}

/// TUI CPFP child after unlock re-entry (no BIP-39 in returned payload).
///
/// Uses parent + optional extra inputs only — never re-selects as RBF.
/// Fee rate must already be resolved by the caller (effect worker); this path
/// does not fetch estimates. Never claims the parent was replaced.
///
/// `bip39_passphrase`: `Some` from private TUI modal; `None` → env. Never persisted.
pub fn complete_routstr_cpfp_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    payment_address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parents: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    extra_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrCpfpSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal cpfp path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let mut gate = MnemonicBackupGate::new();
    gate.begin_reentry_without_display(unlocked)
        .map_err(RoutstrCliError::Wallet)?;
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not building CPFP child".into(),
        ));
    }
    gate.confirm_reentry(reentry_phrase).map_err(|e| {
        session.lock();
        RoutstrCliError::Wallet(e)
    })?;
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_cpfp_with_mnemonic(
        unlocked,
        &network_str,
        payment_address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        parents,
        extra_inputs,
        broadcast,
        fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    result
}

/// AEAD seed blob path under grok home (never `provider_credentials.json`).
pub fn routstr_seed_aead_path(grok_home: &Path) -> std::path::PathBuf {
    grok_home.join("bitcoin").join("seed.aead")
}

/// Read a password from the TTY with echo disabled when possible.
///
/// Falls back to line-read (echo on) for non-TTY stdin (tests / pipes).
fn read_secret_prompt(prompt: &str) -> Result<String, RoutstrCliError> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    #[cfg(unix)]
    {
        use std::io::BufRead;
        use std::os::fd::AsRawFd;
        let stdin = io::stdin();
        let fd = stdin.as_raw_fd();
        // isatty: 1 = TTY
        let is_tty = unsafe { libc::isatty(fd) == 1 };
        if is_tty {
            let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
            let rc = unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) };
            if rc == 0 {
                let old = unsafe { term.assume_init() };
                let mut neo = old;
                neo.c_lflag &= !libc::ECHO;
                if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &neo) } == 0 {
                    let mut line = String::new();
                    let read_res = stdin.lock().read_line(&mut line);
                    // Always restore terminal echo.
                    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
                    eprintln!(); // newline after hidden input
                    read_res?;
                    return Ok(line.trim_end_matches(['\r', '\n']).to_owned());
                }
            }
        }
    }
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Store mnemonic in SeedVault (keyring, else password-wrapped AEAD).
fn store_seed_in_vault(
    vault: &grok_bitcoin_wallet::seed_vault::SeedVault,
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    aead_path: &Path,
) -> Result<(), RoutstrCliError> {
    use grok_bitcoin_wallet::seed_vault::VaultPassword;

    match vault.store(mnemonic, None) {
        Ok(backend) => {
            eprintln!("Seed stored via {backend:?}.");
            Ok(())
        }
        Err(_) => {
            eprintln!(
                "Keyring unavailable. Seed will be password-wrapped at:\n  {}",
                aead_path.display()
            );
            let pw_raw = read_secret_prompt("Set a password to wrap the seed file: ")?;
            let pw = VaultPassword::new(pw_raw);
            if pw.expose().is_empty() {
                return Err(RoutstrCliError::Message(
                    "password required when keyring is unavailable; seed was NOT saved".into(),
                ));
            }
            vault.store(mnemonic, Some(&pw)).map_err(|e| {
                RoutstrCliError::Message(format!(
                    "failed to save seed ({e}); seed was NOT saved. \
                         Do not send funds until `grok routstr fund` completes successfully. \
                         Re-run fund and complete backup again if needed."
                ))
            })?;
            eprintln!("Seed stored as password-wrapped AEAD file.");
            Ok(())
        }
    }
}

fn print_fund_success(
    address: &str,
    step_label: &str,
    network_label: &str,
    saved: bool,
    bip39_passphrase_active: bool,
) {
    println!();
    for line in grok_bitcoin_wallet::funding_cli::format_fund_success_lines_with_passphrase_flag(
        address,
        step_label,
        network_label,
        saved,
        bip39_passphrase_active,
    ) {
        println!("{line}");
    }
}

/// `grok routstr fund`: backup gate + unlock, then print BIP84 receive address.
///
/// Creates a wallet when none exists:
/// generate → show-once + re-entry → **durable store** → print address.
///
/// Existing wallets unlock and print the receive address without re-displaying
/// the recovery phrase.
///
/// Network via [`resolve_product_entry_network`] **before** vault unlock /
/// seed touch (env `GROK_BITCOIN_NETWORK` or mainnet; unknown/`regtest` fail
/// closed — same acceptance as spend/utxos). Derive uses
/// [`bitcoin_network_to_network`] +
/// [`derive_bip84_receive_address_with_passphrase`] (not env-string helpers
/// that still accept regtest).
///
/// BIP-39 is stored only in SeedVault (keyring and/or AEAD file under
/// `$GROK_HOME/bitcoin/seed.aead`). Hard keyring errors never mint a new wallet.
pub fn run_routstr_fund(grok_home: &Path) -> Result<(), RoutstrCliError> {
    use grok_bitcoin_wallet::BOLT12_SUPPORTED;
    use grok_bitcoin_wallet::funding_cli::{
        generate_new_wallet_mnemonic, run_backup_gate_to_show_address_stdio,
    };
    use grok_bitcoin_wallet::onchain::{
        bitcoin_network_to_network, derive_bip84_receive_address_with_passphrase,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Compile-time honesty: BOLT12 must stay false until offer routing lands.
    const _: () = assert!(!BOLT12_SUPPORTED);

    // Fail-closed product network before vault unlock / seed touch (not fees
    // soft-default; not env-string derive that accepts regtest).
    let btc_net = resolve_product_entry_network(None)?;
    let network_label = btc_net.as_str();
    let rust_net = bitcoin_network_to_network(btc_net);

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    // Prefer keyring; AEAD may need a password. Never treat Keyring errors as empty.
    // Shared classify with TUI fund path (`funding_cli::fund_path_decision_from_load`).
    let existing = match vault.load(None) {
        Ok(m) => Some(m),
        Err(e) => {
            use grok_bitcoin_wallet::funding_cli::{
                FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
                password_required_message,
            };
            match fund_path_decision_from_load::<()>(Err(e)) {
                FundPathDecision::NewWallet => None,
                FundPathDecision::NeedPassword => {
                    let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                    let pw = VaultPassword::new(pw_raw);
                    if pw.expose().is_empty() {
                        return Err(RoutstrCliError::Message(password_required_message().into()));
                    }
                    Some(vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?)
                }
                FundPathDecision::KeyringBlocked { reason } => {
                    return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
                }
                FundPathDecision::LoadError { message } => {
                    return Err(RoutstrCliError::Message(message));
                }
                FundPathDecision::ReturningUnlock => {
                    // Unreachable: we only classify Err here.
                    return Err(RoutstrCliError::Message(
                        "internal fund path: unexpected ReturningUnlock on load error".into(),
                    ));
                }
            }
        }
    };

    if let Some(mnemonic) = existing {
        // Returning user: re-entry without re-displaying words (shared with TUI).
        eprintln!(
            "Local wallet found. Re-enter your recovery phrase to unlock the receive address."
        );
        eprintln!("(Words are not re-displayed.)");
        eprint!("Recovery phrase: ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;

        let mut session = UnlockSession::unlock_default(mnemonic);
        let now = Instant::now();
        let unlocked = match session.mnemonic(now) {
            Ok(m) => m,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        // Optional BIP-39 passphrase from env at unlock (never stored in SeedVault).
        let bip39_pass = product_bip39_passphrase_from_env();
        let address = match derive_bip84_receive_address_with_passphrase(
            unlocked,
            bip39_pass.expose(),
            rust_net,
            0,
        ) {
            Ok(a) => a,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        // Re-borrow for re-entry gate (same material; no clone of phrase).
        let unlocked = match session.mnemonic(Instant::now()) {
            Ok(m) => m,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        let reveal = match grok_bitcoin_wallet::funding_cli::returning_user_reveal_after_reentry(
            unlocked, &line, address,
        ) {
            Ok(r) => r,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        session.lock();

        // Returning unlock: vault already held the seed; do not claim "Wallet saved."
        // When env passphrase is non-empty, success lines warn (value never printed).
        print_fund_success(
            &reveal.address,
            reveal.wizard.step.user_label(),
            network_label,
            false,
            !bip39_pass.is_empty(),
        );
        return Ok(());
    }

    // New wallet: generate → backup confirm → store → only then print address.
    // Network already resolved fail-closed above (no seed touch on poisoned env).
    eprintln!("No local Bitcoin wallet found. Generating a new recovery phrase.");
    eprintln!("The phrase is stored in the OS keyring when available, otherwise in:");
    eprintln!("  {}", aead_path.display());
    eprintln!("Never in provider_credentials.json.");

    let mnemonic = generate_new_wallet_mnemonic().map_err(RoutstrCliError::Wallet)?;
    // Optional passphrase for new wallets: set GROK_BITCOIN_BIP39_PASSPHRASE before fund
    // if using a non-empty BIP-39 passphrase (advanced; never stored).
    let bip39_pass = product_bip39_passphrase_from_env();
    let address =
        derive_bip84_receive_address_with_passphrase(&mnemonic, bip39_pass.expose(), rust_net, 0)
            .map_err(RoutstrCliError::Wallet)?;

    // Backup confirm without printing address yet.
    let reveal = run_backup_gate_to_show_address_stdio(&mnemonic, address.clone(), false)
        .map_err(RoutstrCliError::Wallet)?;

    // Durable store before any address print so a failed store cannot leave the
    // user believing a fundable wallet exists.
    if let Err(e) = store_seed_in_vault(&vault, &mnemonic, &aead_path) {
        eprintln!();
        eprintln!("ERROR: wallet was NOT saved. Do not send funds to any address from this run.");
        eprintln!("{e}");
        eprintln!(
            "Your recovery phrase was shown above during backup. Keep those words offline \
             and re-run `grok routstr fund` after fixing storage (keyring or disk)."
        );
        return Err(e);
    }

    // New wallet: durable store succeeded above.
    print_fund_success(
        &reveal.address,
        reveal.wizard.step.user_label(),
        network_label,
        true,
        !bip39_pass.is_empty(),
    );
    Ok(())
}

/// TUI probe after vault load (no secrets). Drives pager fund UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutstrFundProbe {
    /// No seed: recovery phrase must be shown once. Prefer private terminal CLI.
    NeedCliNewWallet { aead_hint: String },
    /// AEAD present; need password before re-entry.
    NeedPassword,
    /// Keyring hard error: do not mint.
    KeyringBlocked { message: String },
    /// Seed available (keyring): collect re-entry phrase in TUI (not re-displayed).
    NeedReentry,
    /// Other load failure.
    Error { message: String },
}

/// Successful TUI fund reveal (address only; never includes BIP-39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrFundSuccess {
    pub address: String,
    pub network_label: String,
    pub step_label: String,
    pub lines: Vec<String>,
}

/// Probe seed vault for TUI `/routstr fund` without minting or printing seeds.
pub fn probe_routstr_fund_for_tui(grok_home: &Path) -> RoutstrFundProbe {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
    };
    use grok_bitcoin_wallet::seed_vault::SeedVault;

    let aead_path = routstr_seed_aead_path(grok_home);
    let aead_hint = aead_path.display().to_string();
    let vault = match SeedVault::with_aead_path(&aead_path) {
        Ok(v) => v,
        Err(e) => {
            return RoutstrFundProbe::Error {
                message: e.to_string(),
            };
        }
    };
    match fund_path_decision_from_load(vault.load(None)) {
        FundPathDecision::NewWallet => RoutstrFundProbe::NeedCliNewWallet { aead_hint },
        FundPathDecision::ReturningUnlock => RoutstrFundProbe::NeedReentry,
        FundPathDecision::NeedPassword => RoutstrFundProbe::NeedPassword,
        FundPathDecision::KeyringBlocked { reason } => RoutstrFundProbe::KeyringBlocked {
            message: keyring_blocked_message(&reason),
        },
        FundPathDecision::LoadError { message } => RoutstrFundProbe::Error { message },
    }
}

/// Complete TUI fund for returning wallet: password (optional) + re-entry + address.
///
/// Never mints a new wallet. Never puts BIP-39 in the returned success payload.
///
/// Network via [`resolve_product_entry_network`] **before** vault unlock
/// (env `GROK_BITCOIN_NETWORK` or mainnet; unknown/`regtest` fail closed —
/// same acceptance as spend/utxos). Derive uses
/// [`bitcoin_network_to_network`] +
/// [`derive_bip84_receive_address_with_passphrase`].
///
/// `bip39_passphrase`: `Some` from private TUI modal; `None` → env. Never persisted.
///
/// **Locks session on all paths** (Ok and Err after unlock) so seed material
/// does not linger on post-unlock failure.
pub fn complete_routstr_fund_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrFundSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message, returning_user_reveal_after_reentry,
    };
    use grok_bitcoin_wallet::onchain::{
        bitcoin_network_to_network, derive_bip84_receive_address_with_passphrase,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Fail-closed product network before unlock (not fees soft-default; not
    // env-string derive that accepts regtest).
    let btc_net = resolve_product_entry_network(None)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal \
                     to create one (recovery phrase is shown only once)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal fund path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    // Optional BIP-39 passphrase: TUI modal override or env; never persisted.
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    let address = match derive_bip84_receive_address_with_passphrase(
        unlocked,
        bip39_pass.expose(),
        rust_net,
        0,
    ) {
        Ok(a) => a,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let reveal = match returning_user_reveal_after_reentry(unlocked, reentry_phrase, address) {
        Ok(r) => r,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    session.lock();

    let step_label = reveal.wizard.step.user_label().to_owned();
    // TUI re-entry never stores again; avoid "Wallet saved." copy.
    // Non-empty resolved passphrase → non-secret notice on success lines.
    let lines = grok_bitcoin_wallet::funding_cli::format_fund_success_lines_with_passphrase_flag(
        &reveal.address,
        &step_label,
        &network_label,
        false,
        !bip39_pass.is_empty(),
    );
    Ok(RoutstrFundSuccess {
        address: reveal.address,
        network_label,
        step_label,
        lines,
    })
}

/// Errors from `grok routstr` product subcommands.
#[derive(Debug, thiserror::Error)]
pub enum RoutstrCliError {
    #[error("No Routstr API key. Set {ROUTSTR_API_KEY_ENV} or run `grok login --routstr`.")]
    NoApiKey,
    #[error("Could not fetch Routstr balance. Check network access and that the key is valid.")]
    BalanceUnavailable,
    /// `[features] routstr_enabled = false` — network fetch intentionally skipped.
    #[error("Routstr is disabled (`[features] routstr_enabled = false`). Balance fetch skipped.")]
    FeatureDisabled,
    #[error(transparent)]
    Wallet(#[from] grok_bitcoin_wallet::error::WalletError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Message(String),
}

/// Map product gap-sync spend failure to CLI error (pure; offline-testable).
///
/// - [`GapSyncSpendFailure::Sync`] → [`RoutstrCliError::Wallet`] (no notices).
/// - Quiet AfterSync (empty notices) → [`RoutstrCliError::Wallet`](cause).
/// - AfterSync with hit-max / extend notices → multi-line
///   [`RoutstrCliError::Message`] via `display_lines` (not success-path only).
///
/// Callers must not convert via bare `WalletError` / `?` that drops the snapshot.
fn map_gap_sync_spend_failure(
    fail: grok_bitcoin_wallet::descriptor_wallet::GapSyncSpendFailure,
) -> RoutstrCliError {
    use grok_bitcoin_wallet::descriptor_wallet::GapSyncSpendFailure;
    match fail {
        GapSyncSpendFailure::Sync(e) => RoutstrCliError::Wallet(e),
        fail @ GapSyncSpendFailure::AfterSync { .. } => {
            if fail.notice_lines().is_empty() {
                RoutstrCliError::Wallet(fail.into_cause())
            } else {
                RoutstrCliError::Message(fail.display_lines().join("\n"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;
    use xai_grok_test_support::EnvGuard;

    #[test]
    fn detects_routstr_urls() {
        assert!(is_routstr_base_url(ROUTSTR_API_URL));
        assert!(is_routstr_base_url("https://api.routstr.com/v1/"));
        assert!(is_routstr_base_url("https://my.routstr.com/v1"));
        assert!(!is_routstr_base_url("https://api.x.ai/v1"));
        assert!(!is_routstr_base_url("https://openrouter.ai/api/v1"));
        assert!(!is_routstr_base_url("https://evil.example/routstr.com"));
        assert!(!is_routstr_base_url("https://notroutstr.com.attacker"));
    }

    /// Shell UX mapping for gap-sync spend dual-error (no chain/mnemonic).
    #[test]
    fn map_gap_sync_spend_failure_three_arms() {
        use grok_bitcoin_wallet::descriptor_wallet::{
            GapSyncSpendFailure, WalletBalance, WalletSyncSnapshot,
        };
        use grok_bitcoin_wallet::error::WalletError;

        // Sync-stage → structured Wallet; no fabricated notices.
        let sync_err = map_gap_sync_spend_failure(GapSyncSpendFailure::Sync(WalletError::Onchain(
            "passphrase mismatch during gap extend".into(),
        )));
        match sync_err {
            RoutstrCliError::Wallet(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                assert!(msg.contains("passphrase"), "{e}");
            }
            other => panic!("Sync must map to Wallet, got: {other}"),
        }

        // Quiet AfterSync (no grow / no max) → Wallet(cause).
        let quiet = map_gap_sync_spend_failure(GapSyncSpendFailure::AfterSync {
            sync: WalletSyncSnapshot {
                utxos: vec![],
                balance: WalletBalance::default(),
                receive_gap: 5,
                change_gap: 5,
                highest_used_receive: None,
                highest_used_change: None,
                extended_receive_by: 0,
                extended_change_by: 0,
                hit_max_gap: false,
            },
            cause: WalletError::Onchain(
                "insufficient funds: need 100000 sats, have 1000 sats in 1 UTXOs".into(),
            ),
        });
        match quiet {
            RoutstrCliError::Wallet(e) => {
                assert!(
                    e.to_string().to_ascii_lowercase().contains("insufficient"),
                    "{e}"
                );
            }
            other => panic!("quiet AfterSync must map to Wallet, got: {other}"),
        }

        // AfterSync with hit_max notices → multi-line Message (not bare Wallet).
        let hit_max = map_gap_sync_spend_failure(GapSyncSpendFailure::AfterSync {
            sync: WalletSyncSnapshot {
                utxos: vec![],
                balance: WalletBalance::default(),
                receive_gap: 20,
                change_gap: 20,
                highest_used_receive: Some(19),
                highest_used_change: None,
                extended_receive_by: 5,
                extended_change_by: 0,
                hit_max_gap: true,
            },
            cause: WalletError::Onchain(
                "insufficient funds: need 50000 sats, have 1000 sats in 1 UTXOs".into(),
            ),
        });
        match hit_max {
            RoutstrCliError::Message(payload) => {
                let lower = payload.to_ascii_lowercase();
                assert!(
                    lower.contains("insufficient"),
                    "Message must include cause: {payload}"
                );
                assert!(
                    lower.contains("max") || lower.contains("gap"),
                    "Message must include hit-max / gap notice: {payload}"
                );
                assert!(
                    payload.contains('\n'),
                    "multi-line Message expected, got single line: {payload}"
                );
            }
            other => panic!("hit_max AfterSync must map to Message, got: {other}"),
        }
    }

    /// Product entrypoints must load passphrase via `from_env` wrapper (not hardcode `""`).
    #[test]
    #[serial]
    fn product_bip39_passphrase_from_env_is_non_empty_aware() {
        use grok_bitcoin_wallet::mnemonic::{BIP39_PASSPHRASE_ENV, Bip39Passphrase};

        let secret = "unit-test-passphrase-not-for-prod";
        let _env = EnvGuard::set(BIP39_PASSPHRASE_ENV, secret);
        let from_product = product_bip39_passphrase_from_env();
        let from_direct = Bip39Passphrase::from_env();
        assert!(!from_product.is_empty());
        assert_eq!(from_product.expose(), secret);
        assert_eq!(from_direct.expose(), secret);
        // Debug must not dump the secret (shell boundary keeps the wrapper).
        let dbg = format!("{from_product:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(secret));
        // Complete APIs accept &Bip39Passphrase (compile-time boundary); empty is default path.
        let empty = Bip39Passphrase::default();
        assert!(empty.is_empty());
        assert_eq!(format!("{empty:?}"), "Bip39Passphrase([REDACTED])");
    }

    #[test]
    #[serial]
    fn product_bip39_passphrase_from_env_empty_when_unset() {
        use grok_bitcoin_wallet::mnemonic::BIP39_PASSPHRASE_ENV;

        let _env = EnvGuard::unset(BIP39_PASSPHRASE_ENV);
        let p = product_bip39_passphrase_from_env();
        assert!(p.is_empty());
        assert_eq!(p.expose(), "");
    }

    /// Explicit TUI modal override must not fall back to env (empty explicit = default path).
    #[test]
    #[serial]
    fn product_bip39_passphrase_explicit_overrides_env() {
        use grok_bitcoin_wallet::mnemonic::BIP39_PASSPHRASE_ENV;

        let env_secret = "env-passphrase-should-not-win";
        let _env = EnvGuard::set(BIP39_PASSPHRASE_ENV, env_secret);
        let modal = product_bip39_passphrase(Some("modal-only-pass"));
        assert_eq!(modal.expose(), "modal-only-pass");
        let dbg = format!("{modal:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("modal-only-pass"));
        assert!(!dbg.contains(env_secret));
        // Explicit empty does not read env.
        let empty_explicit = product_bip39_passphrase(Some(""));
        assert!(empty_explicit.is_empty());
        assert_eq!(empty_explicit.expose(), "");
        // None still uses env.
        let from_env = product_bip39_passphrase(None);
        assert_eq!(from_env.expose(), env_secret);
    }

    #[test]
    fn catalog_id_detection() {
        assert!(is_routstr_catalog_id(ROUTSTR_GROK_45_CATALOG_ID));
        assert!(is_routstr_catalog_id("routstr-other"));
        assert!(!is_routstr_catalog_id("grok-4.5"));
        assert!(!is_routstr_catalog_id("openrouter-grok-4.5"));
    }

    #[test]
    fn should_fetch_routstr_balance_respects_feature_flag() {
        assert!(should_fetch_routstr_balance(true));
        assert!(!should_fetch_routstr_balance(false));
    }

    #[test]
    fn feature_disabled_cli_error_is_not_network_or_key_wording() {
        let msg = RoutstrCliError::FeatureDisabled.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("disabled") && lower.contains("routstr_enabled"),
            "expected feature-disabled wording: {msg}"
        );
        assert!(
            !lower.contains("network") && !lower.contains("key is valid"),
            "must not look like BalanceUnavailable: {msg}"
        );
        // BalanceUnavailable remains the transport/key failure path.
        let unavail = RoutstrCliError::BalanceUnavailable
            .to_string()
            .to_ascii_lowercase();
        assert!(unavail.contains("network") || unavail.contains("key"));
    }

    #[test]
    fn routstr_enabled_from_raw_config_defaults_true() {
        let empty: toml::Value = toml::from_str("").unwrap();
        assert!(routstr_enabled_from_raw_config(&empty));

        let on: toml::Value = toml::from_str(
            r#"
[features]
routstr_enabled = true
"#,
        )
        .unwrap();
        assert!(routstr_enabled_from_raw_config(&on));

        let off: toml::Value = toml::from_str(
            r#"
[features]
routstr_enabled = false
"#,
        )
        .unwrap();
        assert!(!routstr_enabled_from_raw_config(&off));
        assert!(!should_fetch_routstr_balance(
            routstr_enabled_from_raw_config(&off)
        ));
    }

    #[test]
    fn format_balance_line_sats_and_remainder() {
        assert_eq!(
            format_routstr_balance_line(2_100_000),
            "2100 sats (2100000 msats)"
        );
        assert_eq!(
            format_routstr_balance_line(2_100_001),
            "2100 sats + 1 msats (2100001 msats total)"
        );
    }

    #[test]
    fn seed_aead_path_not_credentials_store() {
        let p = routstr_seed_aead_path(std::path::Path::new("/tmp/grok-home"));
        assert!(p.ends_with("bitcoin/seed.aead"));
        assert!(!p.ends_with("provider_credentials.json"));
    }

    #[test]
    fn topup_and_refund_stubs_do_not_claim_live_pay() {
        // Shared copy with TUI (`funding_cli`); CLI must stay honest.
        let top = grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(Some(1000))
            .join(" ")
            .to_ascii_lowercase();
        assert!(top.contains("not wired") || top.contains("not available"));
        assert!(!top.contains("invoice created"));
        let refnd = grok_bitcoin_wallet::funding_cli::refund_next_steps_lines()
            .join(" ")
            .to_ascii_lowercase();
        assert!(refnd.contains("not wired") || refnd.contains("not available"));
        assert!(!refnd.contains("refund completed"));
    }

    #[test]
    fn balance_msats_from_info() {
        let info = RoutstrBalanceInfo {
            msats: Some(2_500_000),
            balance_msats: None,
            balance: None,
            sats: None,
            balance_sats: None,
        };
        assert_eq!(routstr_balance_msats_from_info(&info), Some(2_500_000));
        let info = RoutstrBalanceInfo {
            msats: None,
            balance_msats: None,
            balance: None,
            sats: Some(100),
            balance_sats: None,
        };
        assert_eq!(routstr_balance_msats_from_info(&info), Some(100_000));
        let info = RoutstrBalanceInfo {
            msats: None,
            balance_msats: None,
            balance: None,
            sats: None,
            balance_sats: Some(250),
        };
        assert_eq!(routstr_balance_msats_from_info(&info), Some(250_000));
    }

    #[test]
    fn parse_balance_json_variants() {
        assert_eq!(parse_routstr_balance_msats(r#"{"msats":42}"#), Some(42));
        assert_eq!(
            parse_routstr_balance_msats(r#"{"data":{"balance_msats":99}}"#),
            Some(99)
        );
        assert_eq!(
            parse_routstr_balance_msats(r#"{"balance_sats":10}"#),
            Some(10_000)
        );
        assert_eq!(
            parse_routstr_balance_msats(r#"{"data":{"balance_sats":3}}"#),
            Some(3_000)
        );
        // Bare balance is ambiguous.
        assert_eq!(parse_routstr_balance_msats(r#"{"balance":1000}"#), None);
        assert_eq!(parse_routstr_balance_msats("not-json"), None);
    }

    #[test]
    #[serial]
    fn load_prefers_env_over_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store.write_bearer(ROUTSTR_API_URL, "from-store").unwrap();

        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "from-env");
        let key = load_routstr_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "from-env");
    }

    #[test]
    #[serial]
    fn load_falls_back_to_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store.write_bearer(ROUTSTR_API_URL, "from-store").unwrap();

        let _env = EnvGuard::unset(ROUTSTR_API_KEY_ENV);
        let key = load_routstr_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "from-store");
    }

    #[test]
    #[serial]
    fn store_refuses_when_env_set() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "env-key");
        let err = store_routstr_api_key(&store, "store-key").unwrap_err();
        assert!(matches!(err, RoutstrAuthError::EnvVarSet));
    }

    #[test]
    #[serial]
    fn store_and_clear() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        let _env = EnvGuard::unset(ROUTSTR_API_KEY_ENV);
        store_routstr_api_key(&store, "sk-routstr-test").unwrap();
        assert_eq!(
            load_routstr_api_key(&store).unwrap().as_deref(),
            Some("sk-routstr-test")
        );
        clear_routstr_api_key(&store).unwrap();
        assert!(load_routstr_api_key(&store).unwrap().is_none());
    }

    #[test]
    fn resolve_spend_fee_rate_override_skips_network() {
        // Explicit override never needs explorer; must not return 0.
        assert_eq!(resolve_spend_fee_rate_for_product(Some(12)), 12);
        assert_eq!(resolve_spend_fee_rate_for_product(Some(1)), 1);
    }

    #[test]
    fn resolve_fees_network_explicit_and_rejects_unknown() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

        assert_eq!(
            resolve_fees_network(Some("signet")).unwrap(),
            BitcoinNetwork::Signet
        );
        assert_eq!(
            resolve_fees_network(Some("testnet4")).unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_fees_network(Some("main")).unwrap(),
            BitcoinNetwork::Mainnet
        );
        let err = resolve_fees_network(Some("regtest")).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("unknown") || msg.contains("network"), "{msg}");
        let err = resolve_fees_network(Some("   ")).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("empty"));
    }

    /// Product complete paths share one network resolve (empty → Mainnet;
    /// testnet4 accepted; unknown/regtest fail closed — never silent Mainnet).
    #[test]
    fn resolve_product_complete_network_parity_and_fail_closed() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
        use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

        assert_eq!(
            resolve_product_complete_network("").unwrap(),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            resolve_product_complete_network("   ").unwrap(),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            resolve_product_complete_network("testnet4").unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_product_complete_network("Testnet4").unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_product_complete_network("testnet").unwrap(),
            BitcoinNetwork::Testnet
        );
        // testnet4 → same rust Network as testnet (utxos / Electrum parity).
        assert_eq!(
            bitcoin_network_to_network(resolve_product_complete_network("testnet4").unwrap()),
            bitcoin_network_to_network(resolve_product_complete_network("testnet").unwrap())
        );
        assert_ne!(
            bitcoin_network_to_network(resolve_product_complete_network("signet").unwrap()),
            bitcoin_network_to_network(resolve_product_complete_network("mainnet").unwrap())
        );

        for bad in ["regtest", "mainet", "not-a-network", "testnet5"] {
            let err = resolve_product_complete_network(bad).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "expected fail-closed for {bad:?}: {err}"
            );
            // Must not claim mainnet success path.
            assert!(!matches!(err, RoutstrCliError::Wallet(_)));
        }
    }

    /// complete_routstr_{utxos,spend,rbf,cpfp}_with_mnemonic reject unknown
    /// network before wallet/chain work (no silent Mainnet).
    #[test]
    fn complete_utxos_spend_rbf_cpfp_unknown_network_fail_closed() {
        use grok_bitcoin_wallet::mnemonic::{Bip39Passphrase, import_mnemonic};

        const VECTOR: &str =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = Bip39Passphrase::default();

        for bad in ["regtest", "mainet", "bogus"] {
            let err = complete_routstr_utxos_with_mnemonic(&m, bad, &pass).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "utxos must fail-closed on {bad:?}: {err}"
            );

            let err =
                complete_routstr_spend_with_mnemonic(&m, bad, "bc1qtest", 1000, false, 10, &pass)
                    .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "spend must fail-closed on {bad:?}: {err}"
            );

            let err = complete_routstr_rbf_with_mnemonic(
                &m,
                bad,
                "bc1qtest",
                1000,
                500,
                141,
                &[],
                false,
                10,
                &pass,
            )
            .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "rbf must fail-closed on {bad:?}: {err}"
            );

            let err = complete_routstr_cpfp_with_mnemonic(
                &m,
                bad,
                "bc1qtest",
                1000,
                500,
                141,
                &[],
                &[],
                false,
                10,
                &pass,
            )
            .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "cpfp must fail-closed on {bad:?}: {err}"
            );
        }
    }

    /// Product entry (CLI/TUI) fail-closed on poisoned env — never soft-Mainnet
    /// like fees. Empty env → Mainnet; explicit empty `--network` still rejected.
    #[test]
    #[serial]
    fn resolve_product_entry_network_fail_closed_env() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

        // Unset → Mainnet.
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        assert_eq!(
            resolve_product_entry_network(None).unwrap(),
            BitcoinNetwork::Mainnet
        );

        // Empty env value → Mainnet.
        let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", "   ");
        assert_eq!(
            resolve_product_entry_network(None).unwrap(),
            BitcoinNetwork::Mainnet
        );

        // Poisoned env must hard-error (utxos/spend entry contract).
        for bad in ["regtest", "mainet", "bogus"] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", bad);
            let err = resolve_product_entry_network(None).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "env-only entry must fail-closed on {bad:?}: {err}"
            );
            // Contrast: fees soft-defaults unknown env (intentionally different).
            assert_eq!(
                resolve_fees_network(None).unwrap(),
                BitcoinNetwork::Mainnet,
                "fees soft-default still Mainnet for env {bad:?}"
            );
        }

        // Explicit CLI still rejects empty / unknown (parity with fees CLI).
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        let err = resolve_product_entry_network(Some("   ")).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("empty"));
        let err = resolve_product_entry_network(Some("regtest")).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("unknown"));
        assert_eq!(
            resolve_product_entry_network(Some("testnet4")).unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_product_entry_network(Some("signet")).unwrap(),
            BitcoinNetwork::Signet
        );
    }

    /// Fund CLI/TUI use the same product entry resolve + enum→Network map as
    /// spend/utxos (canonical labels; regtest/unknown fail closed). Pure pin
    /// for derive path: resolve → `as_str` label → `bitcoin_network_to_network`
    /// → `derive_bip84_receive_address_with_passphrase` (not env-string helper).
    #[test]
    #[serial]
    fn fund_product_network_resolve_and_derive_parity() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
        use grok_bitcoin_wallet::mnemonic::import_mnemonic;
        use grok_bitcoin_wallet::onchain::{
            bitcoin_network_to_network, derive_bip84_receive_address_with_passphrase,
        };

        const VECTOR: &str =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let m = import_mnemonic(VECTOR).unwrap();

        // Empty / unset → Mainnet (fund calls resolve_product_entry_network(None)).
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        let btc_net = resolve_product_entry_network(None).unwrap();
        assert_eq!(btc_net, BitcoinNetwork::Mainnet);
        assert_eq!(btc_net.as_str(), "mainnet");
        let addr = derive_bip84_receive_address_with_passphrase(
            &m,
            "",
            bitcoin_network_to_network(btc_net),
            0,
        )
        .unwrap();
        assert!(addr.starts_with("bc1q"), "mainnet receive: {addr}");

        for (label, expected, prefix) in [
            ("signet", BitcoinNetwork::Signet, "tb1"),
            ("testnet", BitcoinNetwork::Testnet, "tb1"),
            ("testnet4", BitcoinNetwork::Testnet4, "tb1"),
            ("mainnet", BitcoinNetwork::Mainnet, "bc1q"),
        ] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", label);
            let btc_net = resolve_product_entry_network(None).unwrap();
            assert_eq!(btc_net, expected, "fund entry for {label}");
            // Canonical label for success lines (not raw env string / regtest).
            assert_eq!(btc_net.as_str(), expected.as_str());
            let addr = derive_bip84_receive_address_with_passphrase(
                &m,
                "",
                bitcoin_network_to_network(btc_net),
                0,
            )
            .unwrap();
            assert!(
                addr.starts_with(prefix),
                "fund derive {label}: expected prefix {prefix}, got {addr}"
            );
        }

        // testnet4 and testnet share rust Network / same BIP84 receive.
        let a = derive_bip84_receive_address_with_passphrase(
            &m,
            "",
            bitcoin_network_to_network(BitcoinNetwork::Testnet4),
            0,
        )
        .unwrap();
        let b = derive_bip84_receive_address_with_passphrase(
            &m,
            "",
            bitcoin_network_to_network(BitcoinNetwork::Testnet),
            0,
        )
        .unwrap();
        assert_eq!(a, b);

        // Poisoned env: fund must fail closed before unlock (same helper as spend).
        for bad in ["regtest", "mainet", "bogus"] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", bad);
            let err = resolve_product_entry_network(None).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "fund entry must fail-closed on {bad:?}: {err}"
            );
            // Must not be a Wallet error from low-level env-string derive
            // (that path still accepts regtest for tests/dev).
            assert!(
                matches!(err, RoutstrCliError::Message(_)),
                "fund network reject should be Message, got {err:?}"
            );
        }
    }

    /// Full TUI fund re-entry hits product entry resolve first: poisoned env
    /// fails closed as Message network reject **before** no-wallet / password /
    /// re-entry gates (empty temp home proves resolve order — not pure-helper only).
    #[test]
    #[serial]
    fn fund_reentry_for_tui_rejects_poisoned_network_before_wallet() {
        // Empty home: if resolve were after vault load, we'd get "no local wallet".
        let empty_home = TempDir::new().unwrap();

        for bad in ["regtest", "bogus"] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", bad);
            let err =
                complete_routstr_fund_reentry_for_tui(empty_home.path(), "any phrase", None, None)
                    .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "fund TUI re-entry must network-reject {bad:?} before no-wallet: {err}"
            );
            assert!(
                !msg.contains("no local wallet")
                    && !msg.contains("password")
                    && !msg.contains("re-enter")
                    && !msg.contains("recovery phrase"),
                "must not be vault/re-entry gate: {err}"
            );
            assert!(
                matches!(err, RoutstrCliError::Message(_)),
                "expected Message network reject, got {err:?}"
            );
        }

        // Sanitized env: empty home then reaches no-wallet (proves only network
        // gate was the early fail for poisoned labels).
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        let err =
            complete_routstr_fund_reentry_for_tui(empty_home.path(), "any phrase", None, None)
                .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("no local wallet") || msg.contains("fund"),
            "empty home + mainnet should hit no-wallet, not network: {err}"
        );
        assert!(!msg.contains("unknown network"));
    }

    /// testnet4 constructs a descriptor wallet (same rust Network as testnet)
    /// on RBF/CPFP complete paths; empty inputs then fail with product copy
    /// (proves resolve + from_mnemonic_with_passphrase accepted testnet4).
    #[test]
    fn complete_rbf_cpfp_testnet4_wallet_constructs_like_utxos() {
        use grok_bitcoin_wallet::descriptor_wallet::{DEFAULT_RECEIVE_GAP, DescriptorWallet};
        use grok_bitcoin_wallet::mnemonic::{Bip39Passphrase, import_mnemonic};
        use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

        const VECTOR: &str =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = Bip39Passphrase::default();

        // Parity with utxos: single resolve → bitcoin_network_to_network → wallet.
        let btc_net = resolve_product_complete_network("testnet4").unwrap();
        let rust_net = bitcoin_network_to_network(btc_net);
        let w = DescriptorWallet::from_mnemonic_with_passphrase(
            &m,
            pass.expose(),
            rust_net,
            DEFAULT_RECEIVE_GAP,
        )
        .expect("testnet4 wallet construction");
        // testnet label maps to the same rust Network (descriptor parity).
        let w_tn = DescriptorWallet::from_mnemonic_with_passphrase(
            &m,
            pass.expose(),
            bitcoin_network_to_network(resolve_product_complete_network("testnet").unwrap()),
            DEFAULT_RECEIVE_GAP,
        )
        .unwrap();
        assert_eq!(w.network(), w_tn.network());
        assert_eq!(w.receive_addresses()[0], w_tn.receive_addresses()[0]);
        assert!(
            w.receive_addresses()[0].starts_with("tb1")
                || w.receive_addresses()[0].starts_with("bcrt"),
            "testnet4 BIP84 receive should be testnet-class: {}",
            w.receive_addresses()[0]
        );

        // complete RBF/CPFP: testnet4 accepted past network resolve; empty inputs
        // is the next gate (wallet already built).
        let err = complete_routstr_rbf_with_mnemonic(
            &m,
            "testnet4",
            "tb1qtest",
            1000,
            500,
            141,
            &[],
            false,
            10,
            &pass,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("input") || msg.contains("rbf"),
            "testnet4 rbf should reach empty-input gate, not network reject: {err}"
        );
        assert!(!msg.contains("unknown network"));

        let err = complete_routstr_cpfp_with_mnemonic(
            &m,
            "testnet4",
            "tb1qtest",
            1000,
            500,
            141,
            &[],
            &[],
            false,
            10,
            &pass,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("parent") || msg.contains("cpfp"),
            "testnet4 cpfp should reach empty-parent gate, not network reject: {err}"
        );
        assert!(!msg.contains("unknown network"));
    }

    /// Pure utxos CLI formatter via shell wrapper (mock snapshot; no network).
    #[test]
    fn utxos_command_lines_from_mock_snapshot() {
        use grok_bitcoin_wallet::descriptor_wallet::{
            OutPointRef, WalletBalance, WalletSyncSnapshot, WalletUtxo,
        };

        let utxo = WalletUtxo {
            outpoint: OutPointRef::new("cd".repeat(32), 0),
            amount_sats: 50_000,
            address: "bc1qtest".into(),
            confirmations: 3,
            is_change: false,
        };
        let snap = WalletSyncSnapshot {
            utxos: vec![utxo],
            balance: WalletBalance {
                confirmed_sats: 50_000,
                unconfirmed_sats: 1_000,
            },
            receive_gap: 25,
            change_gap: 20,
            highest_used_receive: Some(0),
            highest_used_change: None,
            extended_receive_by: 5,
            extended_change_by: 0,
            hit_max_gap: false,
        };
        let lines = utxos_command_lines(&snap, "mainnet");
        let j = lines.join("\n");
        let lower = j.to_ascii_lowercase();
        assert!(j.contains("50000") || j.contains("confirmed"));
        assert!(j.contains("unconfirmed"));
        assert!(j.contains("--input"));
        assert!(j.contains(&"cd".repeat(32)));
        assert!(lower.contains("extended") || lower.contains("gap"));
        assert!(lower.contains("gap-limit") || lower.contains("not full"));
        assert!(!lower.contains("crypto"));

        // Empty: honest zero, no invented UTXOs.
        let empty = WalletSyncSnapshot {
            utxos: vec![],
            balance: WalletBalance::default(),
            receive_gap: 20,
            change_gap: 20,
            highest_used_receive: None,
            highest_used_change: None,
            extended_receive_by: 0,
            extended_change_by: 0,
            hit_max_gap: false,
        };
        let empty_j = utxos_command_lines(&empty, "signet").join("\n");
        let empty_l = empty_j.to_ascii_lowercase();
        assert!(empty_l.contains("signet"));
        assert!(empty_l.contains("0 sats") || empty_l.contains("confirmed"));
        assert!(empty_l.contains("none") || !empty_l.contains("--input"));
        assert!(!empty_l.contains("crypto"));
    }

    /// TUI utxos re-entry: cancel / wrong phrase / no wallet / bad network
    /// (offline; never reaches chain). Session is locked on every Err path.
    #[test]
    fn utxos_reentry_for_tui_gates_offline() {
        use grok_bitcoin_wallet::mnemonic::generate_mnemonic;
        use grok_bitcoin_wallet::seed_vault::{SeedVault, VaultPassword};

        // No wallet at empty grok home.
        let empty_home = TempDir::new().unwrap();
        let err = complete_routstr_utxos_reentry_for_tui(
            empty_home.path(),
            "leader monkey parrot ring guide accident before fence cannon height naive bean",
            None,
            None,
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("no local wallet") || msg.contains("fund"),
            "expected no-wallet guidance: {err}"
        );

        // Unknown network fails before unlock (bad flag never touches seed).
        let err = complete_routstr_utxos_reentry_for_tui(
            empty_home.path(),
            "any phrase",
            None,
            Some("regtest"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("unknown") || msg.contains("network"),
            "expected network reject: {err}"
        );

        // AEAD vault: empty re-entry → cancel (session locked).
        let home = TempDir::new().unwrap();
        let aead = routstr_seed_aead_path(home.path());
        let vault = SeedVault::with_aead_path(&aead).unwrap();
        let mnemonic = generate_mnemonic().unwrap();
        let phrase = mnemonic.expose().to_owned();
        vault
            .store_aead(&mnemonic, &VaultPassword::new("test-pw"))
            .unwrap();

        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            "   ",
            Some("test-pw"),
            Some("signet"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("cancelled") || msg.contains("not listing"),
            "expected re-entry cancel: {err}"
        );

        // Wrong phrase → gate error (session locked; no chain).
        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Some("test-pw"),
            Some("mainnet"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            !msg.contains("cancelled"),
            "wrong phrase is not cancel: {err}"
        );
        // Confirm correct phrase would pass the gate — but stop before live chain
        // by using an invalid network after re-entry would run. Network is checked
        // first, so re-use wrong-password to prove password gate.
        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            &phrase,
            Some("wrong-password"),
            None,
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("password")
                || msg.contains("decrypt")
                || msg.contains("aead")
                || msg.contains("seed")
                || msg.contains("vault")
                || msg.contains("incorrect")
                || msg.contains("invalid"),
            "expected password/decrypt failure: {err}"
        );

        // AEAD present + password: None → NeedPassword (no unlock, no chain).
        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            &phrase,
            None,
            Some("signet"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("password required") || msg.contains("password"),
            "expected NeedPassword guidance: {err}"
        );
        // Phrase kept only for gate correctness; never returned in success payload.
        let _ = phrase;
    }

    fn fees_command_lines_offline_ladder_and_unavailable() {
        let est = grok_bitcoin_wallet::explorer::FeeEstimates {
            fastest_sat_vb: 30,
            half_hour_sat_vb: 12,
            hour_sat_vb: 8,
            economy_sat_vb: 3,
            minimum_sat_vb: 1,
        };
        let ok = fees_command_lines(Some(&est), "mainnet").join("\n");
        let ok_l = ok.to_ascii_lowercase();
        assert!(ok.contains("fastest: 30"));
        assert!(ok.contains("halfHour: 12"));
        assert!(ok_l.contains("product default when live"));
        assert!(ok_l.contains("mainnet"));
        assert!(ok_l.contains("rbf") && ok_l.contains("cpfp"));
        assert!(!ok_l.contains("crypto"));
        // Ladder only — no broadcast claim.
        assert!(!ok_l.contains("broadcast accepted"));

        // Zero halfHour: product ignores 0 estimates — do not label as live default.
        let zero_hh = grok_bitcoin_wallet::explorer::FeeEstimates {
            fastest_sat_vb: 30,
            half_hour_sat_vb: 0,
            hour_sat_vb: 8,
            economy_sat_vb: 3,
            minimum_sat_vb: 1,
        };
        let zero_lines = fees_command_lines(Some(&zero_hh), "mainnet").join("\n");
        let zero_l = zero_lines.to_ascii_lowercase();
        assert!(zero_lines.contains("halfHour: 0"));
        assert!(!zero_l.contains("product default when live"));
        assert!(zero_l.contains("ignored") || zero_l.contains("fall"));

        let miss = fees_command_lines(None, "signet").join("\n");
        let miss_l = miss.to_ascii_lowercase();
        assert!(miss_l.contains("unavailable") || miss_l.contains("not inventing"));
        assert!(miss_l.contains("signet"));
        assert!(
            miss_l.contains("rate-limit") || miss_l.contains("rate limit"),
            "unavailable must cover rate-limit, not only reachability: {miss}"
        );
        assert!(!miss_l.contains("fastest:"));
        assert!(!miss_l.contains("crypto"));
    }

    #[test]
    fn resolve_spend_fee_rate_offline_fallback_is_default() {
        use grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB;
        // No estimates → product default; no network.
        assert_eq!(
            resolve_spend_fee_rate_with_estimates(None, None),
            DEFAULT_SPEND_FEE_RATE_SAT_VB
        );
        assert_eq!(
            resolve_spend_fee_rate_with_estimates(Some(0), None),
            DEFAULT_SPEND_FEE_RATE_SAT_VB
        );
        let est = grok_bitcoin_wallet::explorer::FeeEstimates {
            fastest_sat_vb: 20,
            half_hour_sat_vb: 15,
            hour_sat_vb: 10,
            economy_sat_vb: 5,
            minimum_sat_vb: 1,
        };
        assert_eq!(resolve_spend_fee_rate_with_estimates(None, Some(&est)), 15);
        assert_eq!(
            resolve_spend_fee_rate_with_estimates(Some(9), Some(&est)),
            9
        );
    }

    #[test]
    fn run_routstr_spend_parse_rejects_explicit_zero_fee_like_tui() {
        use grok_bitcoin_wallet::funding_cli::{SpendParseError, parse_spend_request};
        // CLI path now parse_spend_request's first: same rejection as TUI fee=0.
        assert!(matches!(
            parse_spend_request("bc1qtest", 100, false, Some(0)),
            Err(SpendParseError::InvalidFeeRate(_))
        ));
        // None is allowed (resolved later to estimate/default).
        let req = parse_spend_request("bc1qtest", 100, false, None).unwrap();
        assert!(!req.fee_rate_explicit);
        assert_eq!(
            req.fee_rate_sat_vb,
            grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB
        );
        let req = parse_spend_request("bc1qtest", 100, false, Some(8)).unwrap();
        assert!(req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, 8);
    }

    #[test]
    fn run_routstr_rbf_parse_rejects_zero_fee_and_zero_vbytes() {
        use grok_bitcoin_wallet::funding_cli::{RbfReplaceParseError, parse_rbf_replace_request};
        let input = format!("{}:0:100000:bc1qrecv", "ab".repeat(32));
        let inputs = vec![input];
        assert!(matches!(
            parse_rbf_replace_request("bc1qtest", 100, 500, 141, &inputs, false, Some(0)),
            Err(RbfReplaceParseError::InvalidFeeRate(_))
        ));
        assert_eq!(
            parse_rbf_replace_request("bc1qtest", 100, 500, 0, &inputs, false, Some(10)),
            Err(RbfReplaceParseError::ZeroOriginalVbytes)
        );
        assert_eq!(
            parse_rbf_replace_request("bc1qtest", 0, 500, 141, &inputs, false, None),
            Err(RbfReplaceParseError::ZeroAmount)
        );
        assert_eq!(
            parse_rbf_replace_request("bc1qtest", 100, 500, 141, &[], false, None),
            Err(RbfReplaceParseError::MissingInputs)
        );
        let req =
            parse_rbf_replace_request("bc1qtest", 100, 705, 141, &inputs, false, None).unwrap();
        assert!(!req.fee_rate_explicit);
        assert!(!req.broadcast);
        assert_eq!(req.inputs.len(), 1);
        let req =
            parse_rbf_replace_request("bc1qtest", 100, 705, 141, &inputs, true, Some(12)).unwrap();
        assert!(req.fee_rate_explicit);
        assert!(req.broadcast);
        assert_eq!(req.fee_rate_sat_vb, 12);
        assert_eq!(req.original_fee_sats, 705);
        assert_eq!(req.original_vbytes, 141);
    }

    #[test]
    fn rbf_broadcast_claim_helper_matches_product_gate() {
        use grok_bitcoin_wallet::funding_cli::spend_broadcast_claimed_txid;
        let txid = "cd".repeat(32);
        assert!(spend_broadcast_claimed_txid(true, Some(&txid)).is_some());
        assert!(spend_broadcast_claimed_txid(false, Some(&txid)).is_none());
        assert!(spend_broadcast_claimed_txid(true, Some("bad")).is_none());
    }

    #[test]
    fn run_routstr_cpfp_parse_rejects_zero_fee_and_zero_vbytes() {
        use grok_bitcoin_wallet::funding_cli::{CpfpChildParseError, parse_cpfp_child_request};
        let parent = format!("{}:1:80000:bc1qchange", "ab".repeat(32));
        let parents = vec![parent];
        assert!(matches!(
            parse_cpfp_child_request("bc1qtest", 100, 200, 200, &parents, &[], false, Some(0)),
            Err(CpfpChildParseError::InvalidFeeRate(_))
        ));
        assert_eq!(
            parse_cpfp_child_request("bc1qtest", 100, 200, 0, &parents, &[], false, Some(10)),
            Err(CpfpChildParseError::ZeroParentVbytes)
        );
        assert_eq!(
            parse_cpfp_child_request("bc1qtest", 0, 200, 200, &parents, &[], false, None),
            Err(CpfpChildParseError::ZeroAmount)
        );
        assert_eq!(
            parse_cpfp_child_request("bc1qtest", 100, 200, 200, &[], &[], false, None),
            Err(CpfpChildParseError::MissingParents)
        );
        let req = parse_cpfp_child_request("bc1qtest", 100, 200, 200, &parents, &[], false, None)
            .unwrap();
        assert!(!req.fee_rate_explicit);
        assert!(!req.broadcast);
        assert_eq!(req.parents.len(), 1);
        let req =
            parse_cpfp_child_request("bc1qtest", 100, 200, 200, &parents, &[], true, Some(12))
                .unwrap();
        assert!(req.fee_rate_explicit);
        assert!(req.broadcast);
        assert_eq!(req.fee_rate_sat_vb, 12);
        assert_eq!(req.parent_fee_sats, 200);
        assert_eq!(req.parent_vbytes, 200);
    }
}
