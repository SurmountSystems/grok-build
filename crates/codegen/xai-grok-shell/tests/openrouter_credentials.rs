//! Integration tests for OpenRouter credentials + Zed harness interop.
//!
//! These run against the **production** library (not `cfg(test)` on lib), so they
//! stay green even when other shell unit-test helpers are mid-migration.
//!
//! Run: `cargo test -p xai-grok-shell --test openrouter_credentials`

use std::collections::HashMap;
use std::fs;

use serial_test::serial;
use tempfile::TempDir;
use xai_grok_shell::auth::credentials_store::{
    BEARER_USERNAME, CredentialsStore, FORCE_FILE_ENV, SERVICE_NAME,
};
use xai_grok_shell::auth::harness_secrets::{
    GROK_ZED_CONFIG_DIR_ENV, ZED_DEVELOPMENT_CREDENTIALS_FILE, parse_zed_development_credentials,
    probe_shared_openrouter_key, read_zed_development_credentials_at, zed_config_dir,
    zed_development_credentials_path, zed_windows_credential_target,
};
use xai_grok_shell::auth::openrouter::{
    OPENROUTER_API_KEY_ENV, OPENROUTER_API_URL, clear_openrouter_api_key, is_openrouter_base_url,
    load_openrouter_api_key, store_openrouter_api_key, OpenRouterAuthError,
};
use xai_grok_test_support::EnvGuard;

fn force_file_store(dir: &TempDir) -> CredentialsStore {
    CredentialsStore::at_path(dir.path().join("provider_credentials.json"))
}

#[test]
fn service_name_is_grok_not_zed() {
    assert_eq!(SERVICE_NAME, "grok-build");
    assert_ne!(SERVICE_NAME, "zed-github-account");
}

#[test]
fn openrouter_url_detection() {
    assert!(is_openrouter_base_url(OPENROUTER_API_URL));
    assert!(is_openrouter_base_url("https://openrouter.ai/api/v1/"));
    assert!(!is_openrouter_base_url("https://api.x.ai/v1"));
}

#[test]
fn credentials_store_roundtrip() {
    let dir = TempDir::new().unwrap();
    let store = force_file_store(&dir);
    store
        .write_bearer(OPENROUTER_API_URL, "sk-or-test")
        .unwrap();
    let (user, secret) = store.read(OPENROUTER_API_URL).unwrap().unwrap();
    assert_eq!(user, BEARER_USERNAME);
    assert_eq!(secret, "sk-or-test");
    store.delete(OPENROUTER_API_URL).unwrap();
    assert!(store.read(OPENROUTER_API_URL).unwrap().is_none());
}

#[test]
fn parse_zed_development_credentials_format() {
    // "sk" as UTF-8 byte codes — matches Zed's HashMap<url,(user,Vec<u8>)> JSON
    let json = br#"{"https://openrouter.ai/api/v1":["Bearer",[115,107]]}"#;
    assert_eq!(
        parse_zed_development_credentials(json, OPENROUTER_API_URL).as_deref(),
        Some("sk")
    );
    assert_eq!(
        parse_zed_development_credentials(json, "https://openrouter.ai/api/v1/").as_deref(),
        Some("sk")
    );
    assert!(parse_zed_development_credentials(json, "https://api.x.ai/v1").is_none());
}

#[test]
fn zed_windows_target_matches_gpui() {
    assert_eq!(
        zed_windows_credential_target(OPENROUTER_API_URL),
        format!("zed:url={OPENROUTER_API_URL}")
    );
}

#[test]
#[serial]
fn load_prefers_env_over_store_and_zed() {
    let dir = TempDir::new().unwrap();
    let store = force_file_store(&dir);
    store
        .write_bearer(OPENROUTER_API_URL, "from-store")
        .unwrap();

    let zed_dir = TempDir::new().unwrap();
    let zed_path = zed_dir.path().join(ZED_DEVELOPMENT_CREDENTIALS_FILE);
    let map = HashMap::from([(
        OPENROUTER_API_URL.to_owned(),
        (BEARER_USERNAME.to_owned(), b"from-zed".to_vec()),
    )]);
    fs::write(&zed_path, serde_json::to_vec(&map).unwrap()).unwrap();

    let _force = EnvGuard::set(FORCE_FILE_ENV, "1");
    let _zed = EnvGuard::set(GROK_ZED_CONFIG_DIR_ENV, zed_dir.path().to_str().unwrap());
    let _env = EnvGuard::set(OPENROUTER_API_KEY_ENV, "from-env");

    assert_eq!(
        load_openrouter_api_key(&store).unwrap().as_deref(),
        Some("from-env")
    );
}

#[test]
#[serial]
fn load_prefers_grok_store_over_zed() {
    let dir = TempDir::new().unwrap();
    let store = force_file_store(&dir);
    store
        .write_bearer(OPENROUTER_API_URL, "from-store")
        .unwrap();

    let zed_dir = TempDir::new().unwrap();
    let zed_path = zed_dir.path().join(ZED_DEVELOPMENT_CREDENTIALS_FILE);
    let map = HashMap::from([(
        OPENROUTER_API_URL.to_owned(),
        (BEARER_USERNAME.to_owned(), b"from-zed".to_vec()),
    )]);
    fs::write(&zed_path, serde_json::to_vec(&map).unwrap()).unwrap();

    let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);
    let _zed = EnvGuard::set(GROK_ZED_CONFIG_DIR_ENV, zed_dir.path().to_str().unwrap());

    assert_eq!(
        load_openrouter_api_key(&store).unwrap().as_deref(),
        Some("from-store")
    );
}

#[test]
#[serial]
fn load_falls_back_to_zed_development_credentials() {
    let dir = TempDir::new().unwrap();
    let store = force_file_store(&dir);

    let zed_dir = TempDir::new().unwrap();
    let zed_path = zed_dir.path().join(ZED_DEVELOPMENT_CREDENTIALS_FILE);
    let map = HashMap::from([(
        OPENROUTER_API_URL.to_owned(),
        (BEARER_USERNAME.to_owned(), b"from-zed-dev".to_vec()),
    )]);
    fs::write(&zed_path, serde_json::to_vec(&map).unwrap()).unwrap();

    let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);
    let _zed = EnvGuard::set(GROK_ZED_CONFIG_DIR_ENV, zed_dir.path().to_str().unwrap());

    assert_eq!(
        load_openrouter_api_key(&store).unwrap().as_deref(),
        Some("from-zed-dev")
    );
    let (key, source) = probe_shared_openrouter_key(OPENROUTER_API_URL).unwrap();
    assert_eq!(key, "from-zed-dev");
    assert_eq!(
        source,
        xai_grok_shell::auth::harness_secrets::SharedKeySource::ZedDevelopmentCredentials
    );
}

#[test]
#[serial]
fn store_refuses_when_env_set() {
    let dir = TempDir::new().unwrap();
    let store = force_file_store(&dir);
    let _env = EnvGuard::set(OPENROUTER_API_KEY_ENV, "env-key");
    let err = store_openrouter_api_key(&store, "store-key").unwrap_err();
    assert!(matches!(err, OpenRouterAuthError::EnvVarSet));
}

#[test]
#[serial]
fn store_and_clear_grok_only() {
    let dir = TempDir::new().unwrap();
    let store = force_file_store(&dir);
    let zed_dir = TempDir::new().unwrap();
    // Seed a Zed key — clear_openrouter must not remove it.
    let zed_path = zed_dir.path().join(ZED_DEVELOPMENT_CREDENTIALS_FILE);
    let map = HashMap::from([(
        OPENROUTER_API_URL.to_owned(),
        (BEARER_USERNAME.to_owned(), b"zed-stays".to_vec()),
    )]);
    fs::write(&zed_path, serde_json::to_vec(&map).unwrap()).unwrap();

    let _env = EnvGuard::unset(OPENROUTER_API_KEY_ENV);
    let _zed = EnvGuard::set(GROK_ZED_CONFIG_DIR_ENV, zed_dir.path().to_str().unwrap());

    store_openrouter_api_key(&store, "sk-or-grok").unwrap();
    assert_eq!(
        load_openrouter_api_key(&store).unwrap().as_deref(),
        Some("sk-or-grok")
    );
    clear_openrouter_api_key(&store).unwrap();
    // After Grok clear, Zed dev credentials remain.
    assert_eq!(
        load_openrouter_api_key(&store).unwrap().as_deref(),
        Some("zed-stays")
    );
    assert_eq!(
        read_zed_development_credentials_at(&zed_path, OPENROUTER_API_URL).as_deref(),
        Some("zed-stays")
    );
}

#[test]
#[serial]
fn zed_config_dir_override() {
    let dir = TempDir::new().unwrap();
    let _g = EnvGuard::set(GROK_ZED_CONFIG_DIR_ENV, dir.path().to_str().unwrap());
    assert_eq!(zed_config_dir().as_deref(), Some(dir.path()));
    assert_eq!(
        zed_development_credentials_path().as_deref(),
        Some(dir.path().join(ZED_DEVELOPMENT_CREDENTIALS_FILE).as_path())
    );
}
