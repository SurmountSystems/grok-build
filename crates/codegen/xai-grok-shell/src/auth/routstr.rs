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

/// Fetch remaining Routstr balance (msats) for the configured key.
///
/// Returns `None` when no key is available, the request fails, or the body
/// cannot be parsed.
pub async fn fetch_routstr_balance_msats() -> Option<u64> {
    let key = load_routstr_api_key_default().ok().flatten()?;
    fetch_routstr_balance_msats_with_key(&key).await
}

/// Same as [`fetch_routstr_balance_msats`] with an explicit API key.
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
pub fn run_routstr_topup(sats: Option<u64>) -> Result<(), RoutstrCliError> {
    eprintln!("Routstr top up (Lightning / Cashu pay path is not wired yet).");
    if let Some(s) = sats {
        eprintln!("Requested amount: {s} sats.");
    }
    eprintln!("Next steps:");
    eprintln!("  1. `grok login --routstr` with a sk- or cashuA… bearer if you have one.");
    eprintln!("  2. `grok routstr fund` to create a local wallet and show a receive address.");
    eprintln!("  3. Pay a Routstr BOLT11 invoice from docs.routstr.com when you need node float.");
    eprintln!("  4. `grok routstr balance` to verify prepaid float after funding.");
    eprintln!("Local LDK pay and CDK mint/spend remain residual (see RESIDUAL.md).");
    Ok(())
}

/// `grok routstr refund`: next steps until CDK refund path lands.
pub fn run_routstr_refund() -> Result<(), RoutstrCliError> {
    eprintln!("Routstr refund (Cashu return path is not wired yet).");
    eprintln!("Next steps:");
    eprintln!(
        "  1. Prefer spending down hot float rather than leaving large balances on the node."
    );
    eprintln!(
        "  2. Use Routstr account tools / docs.routstr.com for manual Cashu export if available."
    );
    eprintln!("  3. `grok routstr balance` to check remaining float.");
    eprintln!("Automated refund via CDK remains residual (see RESIDUAL.md).");
    Ok(())
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

fn print_fund_success(address: &str, step_label: &str, network_label: &str) {
    println!();
    println!("Backup confirmed. Wallet saved. Receive address ({network_label}):");
    println!("{address}");
    println!("Funding status: {step_label}");
    println!(
        "Send only Bitcoin to this address. After you broadcast a deposit, confirmation \
         watching uses the rate-limited mempool.space client."
    );
    println!("BOLT12 offers are not supported in this build.");
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
    use grok_bitcoin_wallet::cashu::FundingWizard;
    use grok_bitcoin_wallet::error::WalletError;
    use grok_bitcoin_wallet::funding_cli::{
        generate_new_wallet_mnemonic, run_backup_gate_to_show_address_stdio,
    };
    use grok_bitcoin_wallet::onchain::derive_bip84_receive_address_env_network;
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    debug_assert!(
        !BOLT12_SUPPORTED,
        "BOLT12 must stay false until offer routing lands"
    );

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let network_label = {
        let t = network_str.trim();
        if t.is_empty() { "mainnet" } else { t }
    };

    // Prefer keyring; AEAD may need a password. Never treat Keyring errors as empty.
    let existing = match vault.load(None) {
        Ok(m) => Some(m),
        Err(WalletError::NotFound) => None,
        Err(WalletError::PasswordRequired) => {
            let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
            let pw = VaultPassword::new(pw_raw);
            if pw.expose().is_empty() {
                return Err(RoutstrCliError::Message(
                    "password required to unlock existing seed file".into(),
                ));
            }
            Some(vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?)
        }
        Err(WalletError::Keyring(e)) => {
            return Err(RoutstrCliError::Message(format!(
                "could not read seed vault ({e}); not creating a new wallet. \
                 Fix keyring access or unlock the AEAD seed file, then retry."
            )));
        }
        Err(e) => return Err(RoutstrCliError::Wallet(e)),
    };

    if let Some(mnemonic) = existing {
        // Returning user: re-entry without re-displaying words.
        eprintln!(
            "Local wallet found. Re-enter your recovery phrase to unlock the receive address."
        );
        eprintln!("(Words are not re-displayed.)");

        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(&mnemonic)
            .map_err(RoutstrCliError::Wallet)?;
        eprint!("Recovery phrase: ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        gate.confirm_reentry(&line)
            .map_err(RoutstrCliError::Wallet)?;

        let mut session = UnlockSession::unlock_default(mnemonic);
        let now = Instant::now();
        let unlocked = session.mnemonic(now).map_err(RoutstrCliError::Wallet)?;
        let address = derive_bip84_receive_address_env_network(unlocked, &network_str, 0)
            .map_err(RoutstrCliError::Wallet)?;
        session.lock();

        let mut wizard = FundingWizard::new();
        wizard
            .show_address_with_backup_gate(address.clone(), &gate)
            .map_err(RoutstrCliError::Wallet)?;

        print_fund_success(&address, wizard.step.user_label(), network_label);
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

    print_fund_success(
        &reveal.address,
        reveal.wizard.step.user_label(),
        network_label,
    );
    Ok(())
}

/// Errors from `grok routstr` product subcommands.
#[derive(Debug, thiserror::Error)]
pub enum RoutstrCliError {
    #[error("No Routstr API key. Set {ROUTSTR_API_KEY_ENV} or run `grok login --routstr`.")]
    NoApiKey,
    #[error("Could not fetch Routstr balance. Check network access and that the key is valid.")]
    BalanceUnavailable,
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
}
