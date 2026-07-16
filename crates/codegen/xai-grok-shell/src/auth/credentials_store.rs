//! URL-keyed secret storage for third-party provider API keys (**Grok-owned**).
//!
//! Conceptually matches Zed's API-key model (lookup by API base URL, username
//! `"Bearer"`, secret = raw key bytes) without depending on GPUI. **Storage
//! layouts differ** from Zed's OS keychain (different service label /
//! attributes), so reading Zed-saved keys is handled separately in
//! [`crate::auth::harness_secrets`].
//!
//! 1. **OS keyring** (service label [`SERVICE_NAME`] = `grok-build`) when available
//! 2. **File fallback** `$GROK_HOME/provider_credentials.json` (mode 0600 on Unix)
//!
//! Environment variables for specific providers (e.g. `OPENROUTER_API_KEY`) are
//! checked by the provider helpers, not this store. When an env key is set,
//! callers should refuse to write the store (Zed parity).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Keyring / file service label. Distinct from Zed's historical
/// `zed-github-account` so Grok credentials do not collide with Zed's.
pub const SERVICE_NAME: &str = "grok-build";

/// Username role stored with Bearer API keys (matches Zed's `ApiKeyState`).
pub const BEARER_USERNAME: &str = "Bearer";

const FILE_NAME: &str = "provider_credentials.json";

/// Set to `1`/`true` to skip the OS keyring and use the file store only
/// (tests, headless CI without a Secret Service).
pub const FORCE_FILE_ENV: &str = "GROK_CREDENTIALS_FORCE_FILE";

#[derive(Debug, thiserror::Error)]
pub enum CredentialsStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("keyring error: {0}")]
    Keyring(String),
}

/// One stored credential: URL → (username, secret).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredCredential {
    username: String,
    /// Secret as a UTF-8 string (API keys are always text).
    secret: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileStore {
    /// Map of API base URL → credential.
    #[serde(default)]
    credentials: HashMap<String, StoredCredential>,
}

/// URL-keyed provider credential store.
#[derive(Debug, Clone)]
pub struct CredentialsStore {
    file_path: PathBuf,
    force_file: bool,
}

impl CredentialsStore {
    /// Store under `$GROK_HOME/provider_credentials.json`.
    pub fn default_store() -> Self {
        Self::at_grok_home(&crate::util::grok_home::grok_home())
    }

    /// Store under `{grok_home}/provider_credentials.json`.
    pub fn at_grok_home(grok_home: &Path) -> Self {
        Self {
            file_path: grok_home.join(FILE_NAME),
            force_file: force_file_backend(),
        }
    }

    /// Explicit path (tests).
    pub fn at_path(file_path: PathBuf) -> Self {
        Self {
            file_path,
            force_file: true,
        }
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Read `(username, secret)` for `url`, if present.
    ///
    /// Prefer OS keyring; fall back to the file store.
    pub fn read(&self, url: &str) -> Result<Option<(String, String)>, CredentialsStoreError> {
        if url.is_empty() {
            return Ok(None);
        }
        if !self.force_file
            && let Some(cred) = keyring_read(url)?
        {
            return Ok(Some(cred));
        }
        let store = self.load_file()?;
        Ok(store
            .credentials
            .get(url)
            .map(|c| (c.username.clone(), c.secret.clone())))
    }

    /// Write a Bearer API key for `url`.
    pub fn write_bearer(&self, url: &str, secret: &str) -> Result<(), CredentialsStoreError> {
        self.write(url, BEARER_USERNAME, secret)
    }

    /// Write credentials for `url`.
    pub fn write(
        &self,
        url: &str,
        username: &str,
        secret: &str,
    ) -> Result<(), CredentialsStoreError> {
        if url.is_empty() {
            return Err(CredentialsStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "credential URL must not be empty",
            )));
        }
        if !self.force_file {
            match keyring_write(url, username, secret) {
                Ok(()) => {
                    // Keep file in sync so logout/read still work if keyring
                    // later becomes unavailable; ignore file errors after a
                    // successful keyring write.
                    let _ = self.write_file(url, username, secret);
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!(error = %e, "keyring write failed; using file store");
                }
            }
        }
        self.write_file(url, username, secret)
    }

    /// Delete credentials for `url` from keyring and file.
    pub fn delete(&self, url: &str) -> Result<(), CredentialsStoreError> {
        if url.is_empty() {
            return Ok(());
        }
        if !self.force_file {
            let _ = keyring_delete(url);
        }
        let mut store = self.load_file()?;
        if store.credentials.remove(url).is_some() {
            self.save_file(&store)?;
        }
        Ok(())
    }

    fn load_file(&self) -> Result<FileStore, CredentialsStoreError> {
        if !self.file_path.exists() {
            return Ok(FileStore::default());
        }
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let trimmed = contents.trim();
        if trimmed.is_empty() {
            return Ok(FileStore::default());
        }
        Ok(serde_json::from_str(trimmed)?)
    }

    fn write_file(
        &self,
        url: &str,
        username: &str,
        secret: &str,
    ) -> Result<(), CredentialsStoreError> {
        let mut store = self.load_file()?;
        store.credentials.insert(
            url.to_owned(),
            StoredCredential {
                username: username.to_owned(),
                secret: secret.to_owned(),
            },
        );
        self.save_file(&store)
    }

    fn save_file(&self, store: &FileStore) -> Result<(), CredentialsStoreError> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(store)?;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.file_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.file_path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

fn force_file_backend() -> bool {
    std::env::var(FORCE_FILE_ENV)
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

fn keyring_read(url: &str) -> Result<Option<(String, String)>, CredentialsStoreError> {
    let entry = keyring::Entry::new(SERVICE_NAME, url)
        .map_err(|e| CredentialsStoreError::Keyring(e.to_string()))?;
    match entry.get_password() {
        Ok(secret) if !secret.is_empty() => Ok(Some((BEARER_USERNAME.to_owned(), secret))),
        Ok(_) => Ok(None),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(CredentialsStoreError::Keyring(e.to_string())),
    }
}

fn keyring_write(url: &str, _username: &str, secret: &str) -> Result<(), CredentialsStoreError> {
    let entry = keyring::Entry::new(SERVICE_NAME, url)
        .map_err(|e| CredentialsStoreError::Keyring(e.to_string()))?;
    entry
        .set_password(secret)
        .map_err(|e| CredentialsStoreError::Keyring(e.to_string()))
}

fn keyring_delete(url: &str) -> Result<(), CredentialsStoreError> {
    let entry = keyring::Entry::new(SERVICE_NAME, url)
        .map_err(|e| CredentialsStoreError::Keyring(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(CredentialsStoreError::Keyring(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_store() -> (TempDir, CredentialsStore) {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join(FILE_NAME));
        (dir, store)
    }

    #[test]
    fn roundtrip_bearer_key() {
        let (_dir, store) = temp_store();
        let url = "https://openrouter.ai/api/v1";
        store.write_bearer(url, "sk-or-test").unwrap();
        let got = store.read(url).unwrap().expect("key present");
        assert_eq!(got.0, BEARER_USERNAME);
        assert_eq!(got.1, "sk-or-test");
    }

    #[test]
    fn delete_removes_key() {
        let (_dir, store) = temp_store();
        let url = "https://openrouter.ai/api/v1";
        store.write_bearer(url, "sk-or-test").unwrap();
        store.delete(url).unwrap();
        assert!(store.read(url).unwrap().is_none());
    }

    #[test]
    fn missing_url_returns_none() {
        let (_dir, store) = temp_store();
        assert!(store.read("https://example.com/v1").unwrap().is_none());
    }

    #[test]
    fn empty_url_read_is_none() {
        let (_dir, store) = temp_store();
        assert!(store.read("").unwrap().is_none());
    }

    #[test]
    fn overwrite_replaces_secret() {
        let (_dir, store) = temp_store();
        let url = "https://openrouter.ai/api/v1";
        store.write_bearer(url, "first").unwrap();
        store.write_bearer(url, "second").unwrap();
        assert_eq!(store.read(url).unwrap().unwrap().1, "second");
    }
}
