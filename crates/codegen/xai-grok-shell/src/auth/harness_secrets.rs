//! Shared / cross-harness secret probes for third-party provider API keys.
//!
//! Grok Build owns its write path (`CredentialsStore` under `$GROK_HOME` and
//! the OS keyring service label [`crate::auth::credentials_store::SERVICE_NAME`]).
//! This module is **read-only**: it looks for keys that other AI harnesses may
//! already have stored so users are not forced to re-enter the same OpenRouter
//! key in every tool.
//!
//! # Adding another harness
//!
//! Other product owners should document their storage here and, when practical,
//! add a best-effort probe in [`probe_shared_openrouter_key`]:
//!
//! | Field | What to document |
//! |-------|------------------|
//! | Env | Prefer the portable `OPENROUTER_API_KEY` (checked before this module). |
//! | File | Absolute path pattern (e.g. `$XDG_CONFIG_HOME/<app>/…`). |
//! | OS store | Platform schema: Secret Service attributes/label, macOS Keychain class + server/account, Windows Credential Manager target name. |
//! | Write policy | Whether this harness may *write* those locations (Grok only writes its own store). |
//!
//! # Known OpenRouter layouts
//!
//! ## Grok Build (this process — written elsewhere)
//! - Env: `OPENROUTER_API_KEY`
//! - File: `$GROK_HOME/provider_credentials.json` (see `credentials_store`)
//! - OS: keyring service `grok-build`, account = API base URL, secret = key
//!
//! ## Zed Editor (read-only probe)
//! - Env: `OPENROUTER_API_KEY` (same portable channel)
//! - Dev file: `{zed_config_dir}/development_credentials`  
//!   JSON map `url → (username, password_bytes)`.  
//!   `zed_config_dir` defaults to:
//!   - Linux/FreeBSD: `$XDG_CONFIG_HOME/zed` (or `$FLATPAK_XDG_CONFIG_HOME/zed`)
//!   - macOS: `~/.config/zed`
//!   - Windows: `%APPDATA%\Zed`  
//!   Override with `GROK_ZED_CONFIG_DIR` for tests / custom installs.
//! - OS keychain (same URL key `https://openrouter.ai/api/v1`, username `"Bearer"`):
//!   - **Linux:** Secret Service item **label** `zed-github-account`, attributes
//!     `url` + `username` (oo7 / GPUI)
//!   - **macOS:** Internet Password, `kSecAttrServer` = URL, `kSecAttrAccount` = `Bearer`
//!   - **Windows:** Generic credential target `zed:url={url}`
//!
//! Grok's keyring schema is **not** identical to Zed's (different service label /
//! attributes), so we explicitly probe Zed's layout rather than assuming
//! `keyring` crate entries interoperate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::credentials_store::BEARER_USERNAME;
use super::openrouter::OPENROUTER_API_URL;

/// Zed Secret Service / historical GPUI credential item label (Linux).
///
/// Zed reuses this label for all credentials (including LLM API keys); distinction
/// is by the `url` attribute.
pub const ZED_SECRET_SERVICE_LABEL: &str = "zed-github-account";

/// Env var that overrides where we look for Zed's config directory
/// (contains `development_credentials` in Dev channel).
pub const GROK_ZED_CONFIG_DIR_ENV: &str = "GROK_ZED_CONFIG_DIR";

/// File name under Zed's config dir for the development credentials provider.
pub const ZED_DEVELOPMENT_CREDENTIALS_FILE: &str = "development_credentials";

/// Which shared harness supplied a key (for logging / diagnostics only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedKeySource {
    /// Zed Dev-channel file `development_credentials`.
    ZedDevelopmentCredentials,
    /// Zed OS keychain / Credential Manager / Secret Service.
    ZedOsKeychain,
}

/// Best-effort OpenRouter key from other harnesses. Never writes.
///
/// Order: Zed development credentials file → Zed OS store.
pub fn probe_shared_openrouter_key(api_url: &str) -> Option<(String, SharedKeySource)> {
    let url = api_url.trim_end_matches('/');
    if url.is_empty() {
        return None;
    }

    if let Some(key) = read_zed_development_credentials(url) {
        tracing::debug!(
            source = "zed_development_credentials",
            "using OpenRouter API key from shared harness store"
        );
        return Some((key, SharedKeySource::ZedDevelopmentCredentials));
    }

    if let Some(key) = read_zed_os_keychain(url) {
        tracing::debug!(
            source = "zed_os_keychain",
            "using OpenRouter API key from shared harness store"
        );
        return Some((key, SharedKeySource::ZedOsKeychain));
    }

    // --- Extension point for other harnesses ---
    // if let Some(key) = read_other_harness_openrouter_key(url) {
    //     return Some((key, SharedKeySource::…));
    // }

    None
}

/// Default OpenRouter URL probe.
pub fn probe_shared_openrouter_key_default() -> Option<(String, SharedKeySource)> {
    probe_shared_openrouter_key(OPENROUTER_API_URL)
}

/// Resolve Zed's config directory the same way Zed's `paths::config_dir` does
/// (without depending on Zed crates).
pub fn zed_config_dir() -> Option<PathBuf> {
    if let Ok(override_dir) = std::env::var(GROK_ZED_CONFIG_DIR_ENV) {
        let p = PathBuf::from(override_dir);
        if !p.as_os_str().is_empty() {
            return Some(p);
        }
    }

    #[cfg(target_os = "windows")]
    {
        return dirs::config_dir().map(|d| d.join("Zed"));
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        if let Ok(flatpak) = std::env::var("FLATPAK_XDG_CONFIG_HOME") {
            let p = PathBuf::from(flatpak).join("zed");
            return Some(p);
        }
        return dirs::config_dir().map(|d| d.join("zed"));
    }

    #[cfg(target_os = "macos")]
    {
        #[allow(deprecated)]
        let home = std::env::home_dir()?;
        return Some(home.join(".config").join("zed"));
    }

    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos"
    )))]
    {
        dirs::config_dir().map(|d| d.join("zed"))
    }
}

/// Path to Zed's development credentials file, if the config dir resolves.
pub fn zed_development_credentials_path() -> Option<PathBuf> {
    zed_config_dir().map(|d| d.join(ZED_DEVELOPMENT_CREDENTIALS_FILE))
}

/// Parse Zed `development_credentials` JSON: `HashMap<url, (username, password_bytes)>`.
pub fn parse_zed_development_credentials(
    json: &[u8],
    url: &str,
) -> Option<String> {
    let map: HashMap<String, (String, Vec<u8>)> = serde_json::from_slice(json).ok()?;
    let (username, secret) = map.get(url).or_else(|| {
        // Tolerate trailing-slash mismatch between settings and store key.
        let trimmed = url.trim_end_matches('/');
        map.iter().find_map(|(k, v)| {
            (k.trim_end_matches('/') == trimmed).then_some(v)
        })
    })?;
    if !username.is_empty() && username != BEARER_USERNAME {
        tracing::debug!(
            username = %username,
            "Zed development credential username is not Bearer; still using secret"
        );
    }
    let key = String::from_utf8(secret.clone()).ok()?;
    let key = key.trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_owned())
    }
}

fn read_zed_development_credentials(url: &str) -> Option<String> {
    let path = zed_development_credentials_path()?;
    read_zed_development_credentials_at(&path, url)
}

/// Testable path-based reader for Zed's development credentials file.
pub fn read_zed_development_credentials_at(path: &Path, url: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    parse_zed_development_credentials(&bytes, url)
}

/// Windows Credential Manager target name used by Zed GPUI.
pub fn zed_windows_credential_target(url: &str) -> String {
    format!("zed:url={url}")
}

fn read_zed_os_keychain(url: &str) -> Option<String> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        return read_zed_secret_service(url);
    }
    #[cfg(target_os = "windows")]
    {
        return read_zed_windows_credential(url);
    }
    #[cfg(target_os = "macos")]
    {
        return read_zed_macos_internet_password(url);
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "windows",
        target_os = "macos"
    )))]
    {
        let _ = url;
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn read_zed_secret_service(url: &str) -> Option<String> {
    use std::collections::HashMap as Map;

    let ss = dbus_secret_service::SecretService::connect(
        dbus_secret_service::EncryptionType::Dh,
    )
    .or_else(|_| {
        dbus_secret_service::SecretService::connect(dbus_secret_service::EncryptionType::Plain)
    })
    .ok()?;

    let attrs: Map<&str, &str> = Map::from([("url", url)]);
    let search = ss.search_items(attrs).ok()?;

    let mut candidates: Vec<_> = search.unlocked;
    candidates.extend(search.locked);

    for item in candidates {
        if item.ensure_unlocked().is_err() {
            continue;
        }
        let label = item.get_label().unwrap_or_default();
        if label != ZED_SECRET_SERVICE_LABEL {
            continue;
        }
        let secret = match item.get_secret() {
            Ok(s) if !s.is_empty() => s,
            _ => continue,
        };
        if let Ok(key) = String::from_utf8(secret) {
            let key = key.trim();
            if !key.is_empty() {
                return Some(key.to_owned());
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn read_zed_windows_credential(url: &str) -> Option<String> {
    use std::ptr;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    let target = zed_windows_credential_target(url);
    let target_w: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();
    let mut credential: *mut CREDENTIALW = ptr::null_mut();

    let result = unsafe {
        CredReadW(
            PCWSTR::from_raw(target_w.as_ptr()),
            CRED_TYPE_GENERIC,
            None,
            &mut credential,
        )
    };

    if let Err(err) = result {
        if err.code() == ERROR_NOT_FOUND.to_hresult() {
            return None;
        }
        tracing::debug!(error = %err, "Zed Windows credential read failed");
        return None;
    }
    if credential.is_null() {
        return None;
    }

    let blob = unsafe {
        std::slice::from_raw_parts(
            (*credential).CredentialBlob,
            (*credential).CredentialBlobSize as usize,
        )
    };
    let key = String::from_utf8(blob.to_vec()).ok();
    unsafe {
        CredFree(credential as *const _ as *const std::ffi::c_void);
    }
    key.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

#[cfg(target_os = "macos")]
fn read_zed_macos_internet_password(url: &str) -> Option<String> {
    // Zed stores Internet Passwords with kSecAttrServer = url.
    // Use the `security` CLI as a dependency-free probe so we do not pull
    // security-framework into every Linux CI graph. Empty / missing → None.
    //
    // `security find-internet-password -s <server> -w` prints the password.
    let output = std::process::Command::new("security")
        .args(["find-internet-password", "-s", url, "-w"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let key = String::from_utf8(output.stdout).ok()?;
    let key = key.trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn parse_zed_dev_credentials_bearer_key() {
        // "sk" as UTF-8 bytes
        let json = br#"{"https://openrouter.ai/api/v1":["Bearer",[115,107]]}"#;
        let key = parse_zed_development_credentials(json, OPENROUTER_API_URL).unwrap();
        assert_eq!(key, "sk");
    }

    #[test]
    fn parse_zed_dev_credentials_trailing_slash_tolerant() {
        let json = br#"{"https://openrouter.ai/api/v1":["Bearer",[97,98,99]]}"#;
        let key =
            parse_zed_development_credentials(json, "https://openrouter.ai/api/v1/").unwrap();
        assert_eq!(key, "abc");
    }

    #[test]
    fn parse_zed_dev_credentials_missing_url() {
        let json = br#"{"https://api.openai.com/v1":["Bearer",[115,107]]}"#;
        assert!(parse_zed_development_credentials(json, OPENROUTER_API_URL).is_none());
    }

    #[test]
    fn read_zed_dev_credentials_from_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(ZED_DEVELOPMENT_CREDENTIALS_FILE);
        // password bytes for "from-zed"
        let secret: Vec<u8> = b"from-zed".to_vec();
        let map = HashMap::from([(
            OPENROUTER_API_URL.to_owned(),
            (BEARER_USERNAME.to_owned(), secret),
        )]);
        fs::write(&path, serde_json::to_vec(&map).unwrap()).unwrap();
        assert_eq!(
            read_zed_development_credentials_at(&path, OPENROUTER_API_URL).as_deref(),
            Some("from-zed")
        );
    }

    #[test]
    fn windows_target_name_matches_zed() {
        assert_eq!(
            zed_windows_credential_target(OPENROUTER_API_URL),
            format!("zed:url={OPENROUTER_API_URL}")
        );
    }

    #[test]
    #[serial_test::serial]
    fn zed_config_dir_respects_override() {
        let dir = TempDir::new().unwrap();
        let _g = xai_grok_test_support::EnvGuard::set(
            GROK_ZED_CONFIG_DIR_ENV,
            dir.path().to_str().unwrap(),
        );
        assert_eq!(zed_config_dir().as_deref(), Some(dir.path()));
        assert_eq!(
            zed_development_credentials_path().as_deref(),
            Some(dir.path().join(ZED_DEVELOPMENT_CREDENTIALS_FILE).as_path())
        );
    }
}
