//! OpenRouter provider helpers: constants, key load/store, login CLI.
//!
//! # Credential resolution order
//!
//! 1. `OPENROUTER_API_KEY` environment variable (portable; shared with Zed and others)
//! 2. Grok OSS secret store (`CredentialsStore` — OS keyring service `grok-build`
//!    or `$GROK_HOME/provider_credentials.json`)
//! 3. Shared harness probes ([`super::harness_secrets`]) — **read-only**, including
//!    Zed's development credentials file and Zed's OS keychain layouts
//!
//! Grok never writes into Zed's stores. See `harness_secrets` for how other
//! harness authors should document their locations.

use std::io::{self, Write};
use std::path::Path;

use super::credentials_store::{BEARER_USERNAME, CredentialsStore, CredentialsStoreError};
use super::harness_secrets;

/// Default OpenRouter OpenAI-compatible API base URL.
pub const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1";

/// Environment variable for the OpenRouter API key (env wins over secret store).
///
/// May hold a single key or a comma-/newline-separated list; additional keys
/// are used as credit-exhaustion failover (see also [`OPENROUTER_API_KEYS_ENV`]).
pub const OPENROUTER_API_KEY_ENV: &str = "OPENROUTER_API_KEY";

/// Optional extra OpenRouter keys for multi-account credit failover.
/// Comma- or newline-separated. Merged after [`OPENROUTER_API_KEY_ENV`].
pub const OPENROUTER_API_KEYS_ENV: &str = "OPENROUTER_API_KEYS";

/// Catalog key shown in the model picker (separate from native xAI models).
pub const OPENROUTER_GROK_45_CATALOG_ID: &str = "openrouter-grok-4.5";

/// Model slug sent to the OpenRouter API.
pub const OPENROUTER_GROK_45_MODEL: &str = "x-ai/grok-4.5";

/// Context window for Grok 4.5 on OpenRouter.
pub const OPENROUTER_GROK_45_CONTEXT_WINDOW: u64 = 500_000;

/// HTTP-Referer: OpenRouter's **primary app id** (must be unique per product).
/// Do not use `https://x.ai` — that URL is already claimed by other apps and
/// shows up as "WebSummarizer" (etc.) in OpenRouter Logs → App.
pub const OPENROUTER_HTTP_REFERER: &str = "https://github.com/SurmountSystems/grok-oss";

/// Display name for OpenRouter rankings / Logs → App column.
pub const OPENROUTER_X_TITLE: &str = "Grok OSS";

/// Preferred OpenRouter title header (docs: `X-OpenRouter-Title`; `X-Title` kept for compat).
pub const OPENROUTER_X_OPENROUTER_TITLE_HEADER: &str = "X-OpenRouter-Title";

/// Legacy title header still accepted by OpenRouter.
pub const OPENROUTER_X_TITLE_HEADER: &str = "X-Title";

/// Optional marketplace categories (cli coding agent).
pub const OPENROUTER_CATEGORIES: &str = "cli-agent";

#[cfg(test)]
mod attribution_tests {
    use super::*;

    #[test]
    fn referer_is_surmount_not_xai() {
        assert!(OPENROUTER_HTTP_REFERER.contains("SurmountSystems/grok-oss"));
        assert_ne!(OPENROUTER_HTTP_REFERER, "https://x.ai");
        assert!(!OPENROUTER_HTTP_REFERER.contains("x.ai/cli"));
    }

    #[test]
    fn title_is_grok_oss() {
        assert_eq!(OPENROUTER_X_TITLE, "Grok OSS");
        assert_eq!(OPENROUTER_X_OPENROUTER_TITLE_HEADER, "X-OpenRouter-Title");
        assert_eq!(OPENROUTER_X_TITLE_HEADER, "X-Title");
        assert_eq!(OPENROUTER_CATEGORIES, "cli-agent");
    }

    #[test]
    fn model_slug_is_openrouter_xai_path() {
        assert_eq!(OPENROUTER_GROK_45_MODEL, "x-ai/grok-4.5");
        assert_eq!(OPENROUTER_GROK_45_CATALOG_ID, "openrouter-grok-4.5");
    }
}

/// Whether `base_url` targets OpenRouter (host contains `openrouter.ai`).
pub fn is_openrouter_base_url(base_url: &str) -> bool {
    url::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .is_some_and(|host| host == "openrouter.ai" || host.ends_with(".openrouter.ai"))
        || base_url.contains("openrouter.ai")
}

/// Normalize the credential URL used as the store key.
pub fn openrouter_credential_url(base_url: Option<&str>) -> String {
    let url = base_url.unwrap_or(OPENROUTER_API_URL).trim_end_matches('/');
    if url.is_empty() {
        OPENROUTER_API_URL.to_owned()
    } else {
        url.to_owned()
    }
}

/// Non-empty `OPENROUTER_API_KEY` from the process environment.
pub fn openrouter_api_key_from_env() -> Option<String> {
    std::env::var(OPENROUTER_API_KEY_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Load OpenRouter API key: env → Grok store → shared harness (Zed, …).
pub fn load_openrouter_api_key(
    store: &CredentialsStore,
) -> Result<Option<String>, CredentialsStoreError> {
    if let Some(key) = openrouter_api_key_from_env() {
        return Ok(Some(key));
    }
    let url = openrouter_credential_url(None);
    if let Some((_, secret)) = store.read(&url)? {
        return Ok(Some(secret));
    }
    Ok(harness_secrets::probe_shared_openrouter_key(&url).map(|(k, _)| k))
}

/// Load OpenRouter API key using the default store under `$GROK_HOME`.
pub fn load_openrouter_api_key_default() -> Result<Option<String>, CredentialsStoreError> {
    load_openrouter_api_key(&CredentialsStore::default_store())
}

/// Whether any OpenRouter credential is available (env, Grok store, or Zed/shared).
pub fn has_openrouter_api_key() -> bool {
    load_openrouter_api_key_default().ok().flatten().is_some()
}

/// Store an OpenRouter API key. Refuses when `OPENROUTER_API_KEY` is set
/// (Zed parity: env-sourced keys are not written to the secret store).
pub fn store_openrouter_api_key(
    store: &CredentialsStore,
    api_key: &str,
) -> Result<(), OpenRouterAuthError> {
    if openrouter_api_key_from_env().is_some() {
        return Err(OpenRouterAuthError::EnvVarSet);
    }
    let key = api_key.trim();
    if key.is_empty() {
        return Err(OpenRouterAuthError::EmptyKey);
    }
    let url = openrouter_credential_url(None);
    store
        .write(&url, BEARER_USERNAME, key)
        .map_err(OpenRouterAuthError::Store)
}

/// Clear the stored OpenRouter API key (does not unset env).
pub fn clear_openrouter_api_key(store: &CredentialsStore) -> Result<(), CredentialsStoreError> {
    store.delete(&openrouter_credential_url(None))
}

/// Whether a catalog / model id is the OpenRouter-backed Grok entry (or a
/// future `openrouter-*` catalog id).
pub fn is_openrouter_catalog_id(model_id: &str) -> bool {
    let id = model_id.trim();
    id == OPENROUTER_GROK_45_CATALOG_ID || id.starts_with("openrouter-")
}

/// Account-wide credits payload from `GET /api/v1/credits`.
///
/// Works with regular user API keys (not only management keys). Balance is
/// `total_credits - total_usage` in USD.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OpenRouterCreditsData {
    pub total_credits: f64,
    pub total_usage: f64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OpenRouterCreditsResponse {
    pub data: OpenRouterCreditsData,
}

/// Remaining account balance in USD from a `/credits` response body.
pub fn openrouter_balance_usd_from_credits(data: &OpenRouterCreditsData) -> f64 {
    data.total_credits - data.total_usage
}

/// Convert a USD balance to whole cents (rounded half away from zero).
pub fn usd_to_cents(usd: f64) -> i64 {
    if !usd.is_finite() {
        return 0;
    }
    (usd * 100.0).round() as i64
}

/// Fetch remaining OpenRouter account credits (USD cents) for the configured key.
///
/// Returns `None` when no key is available, the request fails, or the body
/// cannot be parsed. Callers treat that as "keep last known / hide OR line".
pub async fn fetch_openrouter_credit_balance_cents() -> Option<i64> {
    let key = load_openrouter_api_key_default().ok().flatten()?;
    fetch_openrouter_credit_balance_cents_with_key(&key).await
}

/// Same as [`fetch_openrouter_credit_balance_cents`] with an explicit API key.
pub async fn fetch_openrouter_credit_balance_cents_with_key(api_key: &str) -> Option<i64> {
    let key = api_key.trim();
    if key.is_empty() {
        return None;
    }
    let url = format!("{OPENROUTER_API_URL}/credits");
    let client = crate::http::shared_client();
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("HTTP-Referer", OPENROUTER_HTTP_REFERER)
        .header(OPENROUTER_X_OPENROUTER_TITLE_HEADER, OPENROUTER_X_TITLE)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        tracing::debug!(
            status = response.status().as_u16(),
            "openrouter credits: non-success status"
        );
        return None;
    }
    let parsed: OpenRouterCreditsResponse = response.json().await.ok()?;
    Some(usd_to_cents(openrouter_balance_usd_from_credits(
        &parsed.data,
    )))
}

#[derive(Debug, thiserror::Error)]
pub enum OpenRouterAuthError {
    #[error("{OPENROUTER_API_KEY_ENV} is set; unset it before storing a key in the secret store")]
    EnvVarSet,
    #[error("OpenRouter API key must not be empty")]
    EmptyKey,
    #[error(transparent)]
    Store(#[from] CredentialsStoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// `grok login --openrouter` — store an OpenRouter API key.
///
/// When `api_key` is `Some`, use it; otherwise prompt on stdin (TTY).
pub fn run_openrouter_login(
    grok_home: &Path,
    api_key: Option<&str>,
) -> Result<(), OpenRouterAuthError> {
    let store = CredentialsStore::at_grok_home(grok_home);
    let key = if let Some(k) = api_key {
        k.to_owned()
    } else if let Some(k) = openrouter_api_key_from_env() {
        eprintln!(
            "{OPENROUTER_API_KEY_ENV} is set; OpenRouter will use the environment variable \
             (not writing to the secret store)."
        );
        eprintln!("OpenRouter authentication ready via {OPENROUTER_API_KEY_ENV}.");
        return Ok(());
    } else {
        eprint!("Enter your OpenRouter API key (https://openrouter.ai/keys): ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim().to_owned()
    };

    store_openrouter_api_key(&store, &key)?;
    eprintln!("OpenRouter API key saved to the secret store.");
    eprintln!(
        "Select the model with `/model {OPENROUTER_GROK_45_CATALOG_ID}` or \
         `grok -m {OPENROUTER_GROK_45_CATALOG_ID}`."
    );
    Ok(())
}

/// `grok logout --openrouter` — remove stored OpenRouter key.
pub fn run_openrouter_logout(grok_home: &Path) -> Result<(), OpenRouterAuthError> {
    let store = CredentialsStore::at_grok_home(grok_home);
    clear_openrouter_api_key(&store)?;
    if openrouter_api_key_from_env().is_some() {
        eprintln!(
            "Cleared stored OpenRouter key. {OPENROUTER_API_KEY_ENV} is still set and will be used."
        );
    } else {
        eprintln!("Cleared stored OpenRouter API key.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;
    use xai_grok_test_support::EnvGuard;

    #[test]
    fn detects_openrouter_urls() {
        assert!(is_openrouter_base_url(OPENROUTER_API_URL));
        assert!(is_openrouter_base_url("https://openrouter.ai/api/v1/"));
        assert!(!is_openrouter_base_url("https://api.x.ai/v1"));
        assert!(!is_openrouter_base_url(
            "https://cli-chat-proxy.grok.com/v1"
        ));
    }

    #[test]
    fn catalog_id_detection() {
        assert!(is_openrouter_catalog_id(OPENROUTER_GROK_45_CATALOG_ID));
        assert!(is_openrouter_catalog_id("openrouter-other"));
        assert!(!is_openrouter_catalog_id("grok-4.5"));
        assert!(!is_openrouter_catalog_id("x-ai/grok-4.5"));
    }

    #[test]
    fn credits_balance_usd_and_cents() {
        let data = OpenRouterCreditsData {
            total_credits: 2600.0,
            total_usage: 2468.488674684,
        };
        let usd = openrouter_balance_usd_from_credits(&data);
        assert!((usd - 131.511325316).abs() < 1e-9);
        assert_eq!(usd_to_cents(usd), 13151);
        assert_eq!(usd_to_cents(63.86), 6386);
        assert_eq!(usd_to_cents(10.0), 1000);
        assert_eq!(usd_to_cents(f64::NAN), 0);
    }

    #[test]
    #[serial]
    fn load_prefers_env_over_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store
            .write_bearer(OPENROUTER_API_URL, "from-store")
            .unwrap();

        let _env = EnvGuard::set(OPENROUTER_API_KEY_ENV, "from-env");
        let key = load_openrouter_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "from-env");
    }

    #[test]
    #[serial]
    fn load_falls_back_to_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store
            .write_bearer(OPENROUTER_API_URL, "from-store")
            .unwrap();

        let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);
        // Isolate shared harness probes (empty zed config).
        let zed_dir = TempDir::new().unwrap();
        let _zed = EnvGuard::set(
            harness_secrets::GROK_ZED_CONFIG_DIR_ENV,
            zed_dir.path().to_str().unwrap(),
        );
        let key = load_openrouter_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "from-store");
    }

    #[test]
    #[serial]
    fn load_falls_back_to_zed_development_credentials() {
        let grok_dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(grok_dir.path().join("creds.json"));
        // No Grok key, no env. Re-enable shared harness probes (cargo-ci disables
        // them so host Zed keychain does not pollute other tests).
        let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);
        let _enable_harness = EnvGuard::unset(harness_secrets::DISABLE_SHARED_HARNESS_ENV);

        let zed_dir = TempDir::new().unwrap();
        let path = zed_dir
            .path()
            .join(harness_secrets::ZED_DEVELOPMENT_CREDENTIALS_FILE);
        let secret: Vec<u8> = b"from-zed-dev".to_vec();
        let map = std::collections::HashMap::from([(
            OPENROUTER_API_URL.to_owned(),
            (BEARER_USERNAME.to_owned(), secret),
        )]);
        std::fs::write(&path, serde_json::to_vec(&map).unwrap()).unwrap();
        let _zed = EnvGuard::set(
            harness_secrets::GROK_ZED_CONFIG_DIR_ENV,
            zed_dir.path().to_str().unwrap(),
        );

        let key = load_openrouter_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "from-zed-dev");
    }

    #[test]
    #[serial]
    fn store_refuses_when_env_set() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        let _env = EnvGuard::set(OPENROUTER_API_KEY_ENV, "env-key");
        let err = store_openrouter_api_key(&store, "store-key").unwrap_err();
        assert!(matches!(err, OpenRouterAuthError::EnvVarSet));
    }

    #[test]
    #[serial]
    fn store_and_clear() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        let zed_empty = dir.path().join("no-zed");
        let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);
        let _zed = EnvGuard::set(
            harness_secrets::GROK_ZED_CONFIG_DIR_ENV,
            zed_empty.to_str().unwrap(),
        );
        let _no_shared = EnvGuard::set(harness_secrets::DISABLE_SHARED_HARNESS_ENV, "1");
        store_openrouter_api_key(&store, "sk-or-test").unwrap();
        assert_eq!(
            load_openrouter_api_key(&store).unwrap().as_deref(),
            Some("sk-or-test")
        );
        clear_openrouter_api_key(&store).unwrap();
        assert!(load_openrouter_api_key(&store).unwrap().is_none());
    }
}
