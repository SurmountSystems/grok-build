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
pub const OPENROUTER_API_KEY_ENV: &str = "OPENROUTER_API_KEY";

/// Catalog key shown in the model picker (separate from native xAI models).
pub const OPENROUTER_GROK_45_CATALOG_ID: &str = "openrouter-grok-4.5";

/// Model slug sent to the OpenRouter API.
pub const OPENROUTER_GROK_45_MODEL: &str = "x-ai/grok-4.5";

/// Context window for Grok 4.5 on OpenRouter.
pub const OPENROUTER_GROK_45_CONTEXT_WINDOW: u64 = 500_000;

/// HTTP-Referer value OpenRouter uses for app attribution.
pub const OPENROUTER_HTTP_REFERER: &str = "https://x.ai";

/// X-Title value OpenRouter uses for app attribution.
pub const OPENROUTER_X_TITLE: &str = "Grok OSS";

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
    load_openrouter_api_key_default()
        .ok()
        .flatten()
        .is_some()
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

#[derive(Debug, thiserror::Error)]
pub enum OpenRouterAuthError {
    #[error(
        "{OPENROUTER_API_KEY_ENV} is set; unset it before storing a key in the secret store"
    )]
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
        assert!(!is_openrouter_base_url("https://cli-chat-proxy.grok.com/v1"));
    }

    #[test]
    #[serial]
    fn load_prefers_env_over_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store.write_bearer(OPENROUTER_API_URL, "from-store").unwrap();

        let _env = EnvGuard::set(OPENROUTER_API_KEY_ENV, "from-env");
        let key = load_openrouter_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "from-env");
    }

    #[test]
    #[serial]
    fn load_falls_back_to_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store.write_bearer(OPENROUTER_API_URL, "from-store").unwrap();

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
        // No Grok key, no env.
        let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);

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
        let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);
        store_openrouter_api_key(&store, "sk-or-test").unwrap();
        assert_eq!(
            load_openrouter_api_key(&store).unwrap().as_deref(),
            Some("sk-or-test")
        );
        clear_openrouter_api_key(&store).unwrap();
        assert!(load_openrouter_api_key(&store).unwrap().is_none());
    }
}
