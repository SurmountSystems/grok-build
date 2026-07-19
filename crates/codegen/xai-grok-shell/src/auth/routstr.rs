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

/// `grok routstr topup`: next steps until CDK/LN pay path lands.
///
/// Honest stub: does **not** create invoices or spend Bitcoin.
pub fn run_routstr_topup(sats: Option<u64>) -> Result<(), RoutstrCliError> {
    for line in grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(sats) {
        eprintln!("{line}");
    }
    Ok(())
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

/// Resolve product spend fee rate (sat/vB).
///
/// Order: explicit user override → live mempool.space halfHour estimates
/// (`explorer-http`) → [`grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB`].
/// Never invents a rate from a failed fetch; never returns 0.
pub fn resolve_spend_fee_rate_for_product(user_override: Option<u64>) -> u64 {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
    use grok_bitcoin_wallet::explorer::{FeePriority, resolve_spend_fee_rate_sat_vb};
    use grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB;

    if let Some(n) = user_override
        && n > 0
    {
        return n;
    }

    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let btc_net = BitcoinNetwork::from_env_str(network_str.trim()).unwrap_or(BitcoinNetwork::Mainnet);
    let estimates = grok_bitcoin_wallet::explorer::MempoolHttpClient::with_defaults(btc_net)
        .ok()
        .and_then(|mut c| c.fetch_fee_estimates());
    resolve_spend_fee_rate_sat_vb(
        None,
        estimates.as_ref(),
        FeePriority::HalfHour,
        DEFAULT_SPEND_FEE_RATE_SAT_VB,
    )
}

/// `grok routstr spend <address> <sats> [--broadcast] [--fee-rate N]`.
///
/// **Dry-run by default** (build/sign/extract only). Explicit `--broadcast`
/// submits via rate-limited mempool.space. Requires SeedVault unlock + full
/// recovery-phrase re-entry (same gate as fund). Never mints a new wallet;
/// keyring errors never mint.
///
/// When `fee_rate_sat_vb` is `None`, uses explorer halfHour estimates when the
/// HTTP client can fetch them; otherwise the wallet default (5 sat/vB).
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

    // Resolve fee: explicit override → live mempool halfHour estimates → default.
    let resolved_fee_rate = resolve_spend_fee_rate_for_product(fee_rate_sat_vb);
    let req = parse_spend_request(payment_address, amount_sats, broadcast, Some(resolved_fee_rate))
        .map_err(|e| RoutstrCliError::Message(e.to_string()))?;

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let network_label = {
        let t = network_str.trim();
        if t.is_empty() { "mainnet" } else { t }
    }
    .to_owned();

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

    let success = complete_routstr_spend_with_mnemonic(
        unlocked,
        &network_str,
        &req.payment_address,
        req.amount_sats,
        req.broadcast,
        req.fee_rate_sat_vb,
    )?;
    session.lock();

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

    let _ = network_label; // success.network_label already set
    Ok(success)
}

/// Core spend after vault unlock + re-entry (shared by CLI and TUI complete path).
///
/// Does **not** print or return BIP-39. Uses live mempool ChainSource + optional
/// broadcast when `explorer-http` is compiled in (shell enables it).
pub fn complete_routstr_spend_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: u64,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, broadcast_raw_tx, select_and_prepare_bip84_spend,
    };
    use grok_bitcoin_wallet::funding_cli::{
        format_spend_broadcast_failed_lines, format_spend_broadcast_success_lines,
        format_spend_fee_meta_lines, format_spend_prepared_lines,
    };

    let network_label = {
        let t = network_str.trim();
        if t.is_empty() { "mainnet" } else { t }
    }
    .to_owned();
    let btc_net = BitcoinNetwork::from_env_str(&network_label).unwrap_or(BitcoinNetwork::Mainnet);

    let wallet =
        DescriptorWallet::from_mnemonic_env_network(mnemonic, &network_label, DEFAULT_RECEIVE_GAP)
            .map_err(RoutstrCliError::Wallet)?;

    // Live chain: MempoolChainSource (shell/pager enable explorer-http).
    let chain = grok_bitcoin_wallet::descriptor_wallet::MempoolChainSource::with_defaults(btc_net)
        .map_err(RoutstrCliError::Wallet)?;

    let prepared = select_and_prepare_bip84_spend(
        &wallet,
        &chain,
        mnemonic,
        payment_address,
        amount_sats,
        fee_rate_sat_vb,
        DEFAULT_RECEIVE_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

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

    let broadcast_txid = if broadcast {
        let mut client = grok_bitcoin_wallet::explorer::MempoolHttpClient::with_defaults(btc_net)
            .map_err(RoutstrCliError::Wallet)?;
        match broadcast_raw_tx(&mut client, &raw_hex) {
            Ok(res) => {
                lines.extend(format_spend_broadcast_success_lines(
                    &res.txid,
                    &network_label,
                ));
                Some(res.txid)
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

/// TUI spend after unlock re-entry (no BIP-39 in returned payload).
pub fn complete_routstr_spend_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: u64,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());

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
    let success = complete_routstr_spend_with_mnemonic(
        unlocked,
        &network_str,
        payment_address,
        amount_sats,
        broadcast,
        fee_rate_sat_vb,
    )?;
    session.lock();
    Ok(success)
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

fn print_fund_success(address: &str, step_label: &str, network_label: &str, saved: bool) {
    println!();
    for line in grok_bitcoin_wallet::funding_cli::format_fund_success_lines(
        address,
        step_label,
        network_label,
        saved,
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
/// BIP-39 is stored only in SeedVault (keyring and/or AEAD file under
/// `$GROK_HOME/bitcoin/seed.aead`). Hard keyring errors never mint a new wallet.
pub fn run_routstr_fund(grok_home: &Path) -> Result<(), RoutstrCliError> {
    use grok_bitcoin_wallet::BOLT12_SUPPORTED;
    use grok_bitcoin_wallet::funding_cli::{
        generate_new_wallet_mnemonic, run_backup_gate_to_show_address_stdio,
    };
    use grok_bitcoin_wallet::onchain::derive_bip84_receive_address_env_network;
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Compile-time honesty: BOLT12 must stay false until offer routing lands.
    const _: () = assert!(!BOLT12_SUPPORTED);

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let network_label = {
        let t = network_str.trim();
        if t.is_empty() { "mainnet" } else { t }
    };

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
        let unlocked = session.mnemonic(now).map_err(RoutstrCliError::Wallet)?;
        let address = derive_bip84_receive_address_env_network(unlocked, &network_str, 0)
            .map_err(RoutstrCliError::Wallet)?;
        // Re-borrow for re-entry gate (same material; no clone of phrase).
        let unlocked = session
            .mnemonic(Instant::now())
            .map_err(RoutstrCliError::Wallet)?;
        let reveal = grok_bitcoin_wallet::funding_cli::returning_user_reveal_after_reentry(
            unlocked, &line, address,
        )
        .map_err(RoutstrCliError::Wallet)?;
        session.lock();

        // Returning unlock: vault already held the seed; do not claim "Wallet saved."
        print_fund_success(
            &reveal.address,
            reveal.wizard.step.user_label(),
            network_label,
            false,
        );
        return Ok(());
    }

    // New wallet: generate → backup confirm → store → only then print address.
    eprintln!("No local Bitcoin wallet found. Generating a new recovery phrase.");
    eprintln!("The phrase is stored in the OS keyring when available, otherwise in:");
    eprintln!("  {}", aead_path.display());
    eprintln!("Never in provider_credentials.json.");

    let mnemonic = generate_new_wallet_mnemonic().map_err(RoutstrCliError::Wallet)?;
    let address = derive_bip84_receive_address_env_network(&mnemonic, &network_str, 0)
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
pub fn complete_routstr_fund_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
) -> Result<RoutstrFundSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message, returning_user_reveal_after_reentry,
    };
    use grok_bitcoin_wallet::onchain::derive_bip84_receive_address_env_network;
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let network_label = {
        let t = network_str.trim();
        if t.is_empty() { "mainnet" } else { t }
    }
    .to_owned();

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
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let address = derive_bip84_receive_address_env_network(unlocked, &network_str, 0)
        .map_err(RoutstrCliError::Wallet)?;
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let reveal = returning_user_reveal_after_reentry(unlocked, reentry_phrase, address)
        .map_err(RoutstrCliError::Wallet)?;
    session.lock();

    let step_label = reveal.wizard.step.user_label().to_owned();
    // TUI re-entry never stores again; avoid "Wallet saved." copy.
    let lines = grok_bitcoin_wallet::funding_cli::format_fund_success_lines(
        &reveal.address,
        &step_label,
        &network_label,
        false,
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
        // Zero / None → default or live halfHour estimate; never 0.
        let resolved_zero = resolve_spend_fee_rate_for_product(Some(0));
        let resolved_none = resolve_spend_fee_rate_for_product(None);
        assert!(resolved_zero >= 1, "got {resolved_zero}");
        assert!(resolved_none >= 1, "got {resolved_none}");
    }
}
