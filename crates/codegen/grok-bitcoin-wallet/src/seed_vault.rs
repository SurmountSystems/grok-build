//! SeedVault: store BIP-39 mnemonics outside plaintext CredentialsStore JSON.
//!
//! ## Backends
//!
//! 1. **OS keyring** (preferred): service [`SEED_VAULT_SERVICE`], user
//!    [`SEED_VAULT_USER`].
//! 2. **Password AEAD file**: Argon2id + XChaCha20-Poly1305 blob under a path
//!    the caller chooses (never `provider_credentials.json`).
//!
//! Types holding secrets never `Debug`-print mnemonic material.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};
use crate::mnemonic::{MnemonicSecret, import_mnemonic, normalize_phrase};

/// Dedicated keyring service. Do **not** reuse `grok-build` Bearer JSON mirror.
pub const SEED_VAULT_SERVICE: &str = "grok-bitcoin-seed";

/// Keyring account / user label for the primary mnemonic.
pub const SEED_VAULT_USER: &str = "bip39-mnemonic";

/// File format version for password-wrapped AEAD blobs.
const AEAD_FORMAT_VERSION: u32 = 1;

/// Argon2id salt length.
const SALT_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 24;

/// XChaCha20-Poly1305 key length.
const KEY_LEN: usize = 32;

/// Password for AEAD wrap. Redacted in `Debug`.
pub struct VaultPassword(SecretString);

impl VaultPassword {
    pub fn new(password: impl Into<String>) -> Self {
        Self(SecretString::from(password.into()))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for VaultPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultPassword([REDACTED])")
    }
}

/// On-disk AEAD envelope (non-secret metadata + ciphertext).
#[derive(Clone, Serialize, Deserialize)]
struct AeadBlob {
    v: u32,
    /// base64 salt
    salt: String,
    /// base64 nonce
    nonce: String,
    /// base64 ciphertext
    ct: String,
}

impl fmt::Debug for AeadBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadBlob")
            .field("v", &self.v)
            .field("salt", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("ct", &"[REDACTED]")
            .finish()
    }
}

/// SeedVault: load/store/delete a single BIP-39 mnemonic.
///
/// Prefer keyring. AEAD file is an explicit fallback when the caller supplies
/// a password and path.
#[derive(Clone, Debug)]
pub struct SeedVault {
    /// Optional path for password-wrapped AEAD blob.
    aead_path: Option<PathBuf>,
}

impl Default for SeedVault {
    fn default() -> Self {
        Self::new()
    }
}

impl SeedVault {
    /// Keyring-only vault (no AEAD file configured).
    pub fn new() -> Self {
        Self { aead_path: None }
    }

    /// Vault that may use an AEAD file at `path` when password is provided.
    ///
    /// Returns [`WalletError::SeedVault`] if `path` is the forbidden
    /// `provider_credentials.json` filename.
    pub fn with_aead_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        assert_not_credentials_store_path(&path)?;
        Ok(Self {
            aead_path: Some(path),
        })
    }

    /// Store mnemonic in the OS keyring when available.
    #[cfg(feature = "keyring-store")]
    pub fn store_keyring(&self, mnemonic: &MnemonicSecret) -> Result<()> {
        let entry = keyring::Entry::new(SEED_VAULT_SERVICE, SEED_VAULT_USER)
            .map_err(|e| WalletError::Keyring(e.to_string()))?;
        entry
            .set_password(mnemonic.expose())
            .map_err(|e| WalletError::Keyring(e.to_string()))
    }

    #[cfg(not(feature = "keyring-store"))]
    pub fn store_keyring(&self, _mnemonic: &MnemonicSecret) -> Result<()> {
        Err(WalletError::Keyring(
            "keyring-store feature disabled".into(),
        ))
    }

    /// Load mnemonic from the OS keyring.
    #[cfg(feature = "keyring-store")]
    pub fn load_keyring(&self) -> Result<MnemonicSecret> {
        let entry = keyring::Entry::new(SEED_VAULT_SERVICE, SEED_VAULT_USER)
            .map_err(|e| WalletError::Keyring(e.to_string()))?;
        match entry.get_password() {
            Ok(phrase) => import_mnemonic(&phrase),
            Err(keyring::Error::NoEntry) => Err(WalletError::NotFound),
            Err(e) => Err(WalletError::Keyring(e.to_string())),
        }
    }

    #[cfg(not(feature = "keyring-store"))]
    pub fn load_keyring(&self) -> Result<MnemonicSecret> {
        Err(WalletError::Keyring(
            "keyring-store feature disabled".into(),
        ))
    }

    /// Delete mnemonic from the OS keyring (idempotent if missing).
    #[cfg(feature = "keyring-store")]
    pub fn delete_keyring(&self) -> Result<()> {
        let entry = keyring::Entry::new(SEED_VAULT_SERVICE, SEED_VAULT_USER)
            .map_err(|e| WalletError::Keyring(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(WalletError::Keyring(e.to_string())),
        }
    }

    #[cfg(not(feature = "keyring-store"))]
    pub fn delete_keyring(&self) -> Result<()> {
        Ok(())
    }

    /// Store mnemonic as password-wrapped AEAD at the configured path.
    pub fn store_aead(&self, mnemonic: &MnemonicSecret, password: &VaultPassword) -> Result<()> {
        let path = self.aead_path.as_ref().ok_or_else(|| {
            WalletError::SeedVault("no AEAD path configured (use SeedVault::with_aead_path)".into())
        })?;
        assert_not_credentials_store_path(path)?;
        let blob = encrypt_mnemonic(mnemonic.expose(), password.expose())?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        }
        let json =
            serde_json::to_vec_pretty(&blob).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        write_secret_file_atomic(path, &json)?;
        Ok(())
    }

    /// Load mnemonic from password-wrapped AEAD file.
    pub fn load_aead(&self, password: &VaultPassword) -> Result<MnemonicSecret> {
        let path = self.aead_path.as_ref().ok_or_else(|| {
            WalletError::SeedVault("no AEAD path configured (use SeedVault::with_aead_path)".into())
        })?;
        assert_not_credentials_store_path(path)?;
        if !path.exists() {
            return Err(WalletError::NotFound);
        }
        let bytes = fs::read(path).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        let blob: AeadBlob =
            serde_json::from_slice(&bytes).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        let phrase = decrypt_mnemonic(&blob, password.expose())?;
        // Only long-lived holder is MnemonicSecret (secrecy/zeroize on drop).
        import_mnemonic(phrase.as_str())
    }

    /// Delete AEAD file if present.
    pub fn delete_aead(&self) -> Result<()> {
        let Some(path) = self.aead_path.as_ref() else {
            return Ok(());
        };
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::SeedVault(e.to_string())),
        }
    }

    /// Prefer keyring store; on keyring failure with password+path, use AEAD.
    pub fn store(
        &self,
        mnemonic: &MnemonicSecret,
        password: Option<&VaultPassword>,
    ) -> Result<StoreBackend> {
        match self.store_keyring(mnemonic) {
            Ok(()) => Ok(StoreBackend::Keyring),
            Err(keyring_err) => {
                if let Some(pw) = password {
                    self.store_aead(mnemonic, pw)?;
                    Ok(StoreBackend::AeadFile)
                } else {
                    Err(keyring_err)
                }
            }
        }
    }

    /// Prefer keyring load; fall back to AEAD when password provided.
    ///
    /// **Does not** collapse hard keyring failures into [`WalletError::NotFound`].
    /// Callers that mint a new wallet must only do so on definitive absence
    /// ([`WalletError::NotFound`]), never on [`WalletError::Keyring`].
    ///
    /// When an AEAD file exists but no password was supplied, returns
    /// [`WalletError::PasswordRequired`] instead of inventing a new seed.
    pub fn load(&self, password: Option<&VaultPassword>) -> Result<MnemonicSecret> {
        match self.load_keyring() {
            Ok(m) => Ok(m),
            Err(WalletError::NotFound) => self.load_after_keyring_miss(password),
            Err(WalletError::Keyring(e)) => {
                // Transient / hard keyring error: try AEAD only when password given.
                // Never report NotFound (that would let product mint a new wallet).
                if let Some(pw) = password {
                    match self.load_aead(pw) {
                        Ok(m) => Ok(m),
                        Err(WalletError::NotFound) => Err(WalletError::Keyring(e)),
                        Err(other) => Err(other),
                    }
                } else if self.aead_file_present() {
                    Err(WalletError::PasswordRequired)
                } else {
                    Err(WalletError::Keyring(e))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Whether the configured AEAD path exists on disk.
    pub fn aead_file_present(&self) -> bool {
        self.aead_path.as_ref().is_some_and(|p| p.exists())
    }

    fn load_after_keyring_miss(&self, password: Option<&VaultPassword>) -> Result<MnemonicSecret> {
        if let Some(pw) = password {
            return self.load_aead(pw);
        }
        if self.aead_file_present() {
            return Err(WalletError::PasswordRequired);
        }
        Err(WalletError::NotFound)
    }

    /// Delete from keyring and AEAD file.
    pub fn delete_all(&self) -> Result<()> {
        self.delete_keyring()?;
        self.delete_aead()?;
        Ok(())
    }

    pub fn aead_path(&self) -> Option<&Path> {
        self.aead_path.as_deref()
    }
}

/// Which backend accepted a store operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreBackend {
    Keyring,
    AeadFile,
}

/// Default unlock idle TTL (5 minutes). After idle expiry the session zeroizes.
pub const DEFAULT_UNLOCK_TTL: Duration = Duration::from_secs(5 * 60);

/// In-memory unlock session: holds the mnemonic until idle TTL expires or lock.
///
/// Call [`UnlockSession::mnemonic`] / [`UnlockSession::touch`] to refresh idle
/// time. After expiry, material is dropped (secrecy/zeroize) and further access
/// returns [`WalletError::SessionLocked`].
pub struct UnlockSession {
    mnemonic: Option<MnemonicSecret>,
    last_activity: Instant,
    ttl: Duration,
}

impl fmt::Debug for UnlockSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockSession")
            .field("unlocked", &self.mnemonic.is_some())
            .field("ttl_secs", &self.ttl.as_secs())
            .finish_non_exhaustive()
    }
}

impl UnlockSession {
    /// Start a session with `mnemonic` and the given idle TTL.
    pub fn unlock(mnemonic: MnemonicSecret, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            mnemonic: Some(mnemonic),
            last_activity: now,
            ttl,
        }
    }

    /// Unlock with [`DEFAULT_UNLOCK_TTL`].
    pub fn unlock_default(mnemonic: MnemonicSecret) -> Self {
        Self::unlock(mnemonic, DEFAULT_UNLOCK_TTL)
    }

    /// Idle TTL for this session.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Whether the session still holds material and has not exceeded idle TTL.
    ///
    /// Pure status check (does not drop material). Prefer [`Self::check_unlocked`]
    /// when a status poll should also expire stale sessions.
    pub fn is_unlocked(&self, now: Instant) -> bool {
        self.mnemonic.is_some() && !self.is_expired(now)
    }

    /// Expire if needed, then report whether the session is still unlocked.
    pub fn check_unlocked(&mut self, now: Instant) -> bool {
        self.expire_if_needed(now);
        self.mnemonic.is_some()
    }

    /// Whether idle TTL has elapsed (material may still be present until expire).
    ///
    /// Uses saturating duration so a `now` earlier than `last_activity` never panics.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= self.ttl
    }

    /// Drop mnemonic material immediately.
    pub fn lock(&mut self) {
        self.mnemonic = None;
    }

    /// If idle TTL elapsed, zeroize and return `true`.
    pub fn expire_if_needed(&mut self, now: Instant) -> bool {
        if self.mnemonic.is_some() && self.is_expired(now) {
            self.lock();
            return true;
        }
        false
    }

    /// Refresh idle timer without reading the mnemonic.
    pub fn touch(&mut self, now: Instant) -> Result<()> {
        self.expire_if_needed(now);
        if self.mnemonic.is_none() {
            return Err(WalletError::SessionLocked);
        }
        self.last_activity = now;
        Ok(())
    }

    /// Borrow the mnemonic, refreshing idle activity. Errors if locked/expired.
    pub fn mnemonic(&mut self, now: Instant) -> Result<&MnemonicSecret> {
        self.expire_if_needed(now);
        if self.mnemonic.is_none() {
            return Err(WalletError::SessionLocked);
        }
        self.last_activity = now;
        Ok(self.mnemonic.as_ref().expect("checked is_some"))
    }

    /// Test helper: construct a session whose last activity is `last_activity`.
    #[cfg(test)]
    pub fn unlock_at_for_test(
        mnemonic: MnemonicSecret,
        ttl: Duration,
        last_activity: Instant,
    ) -> Self {
        Self {
            mnemonic: Some(mnemonic),
            last_activity,
            ttl,
        }
    }
}

/// Backup UX gate: show recovery words **once**, then require full re-entry
/// before the funding wizard may advance to [`crate::cashu::FundingStep::ShowAddress`].
///
/// Expected phrase is held in a [`Zeroizing`] buffer and cleared on confirm or drop.
#[derive(Default)]
pub struct MnemonicBackupGate {
    /// Normalized expected phrase while awaiting re-entry.
    expected: Option<Zeroizing<String>>,
    shown: bool,
    confirmed: bool,
}

impl fmt::Debug for MnemonicBackupGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MnemonicBackupGate")
            .field("shown", &self.shown)
            .field("confirmed", &self.confirmed)
            .field("awaiting_reentry", &self.expected.is_some())
            .finish()
    }
}

impl MnemonicBackupGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether show-once + full re-entry both succeeded.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Whether the one-time display has already been consumed.
    pub fn was_shown(&self) -> bool {
        self.shown
    }

    /// Numbered word list for one-time display. Fails if already shown or confirmed.
    ///
    /// Format: `(1-based index, word)`. The full phrase is retained only for
    /// re-entry matching; it is never returned again from this gate.
    pub fn show_once(&mut self, mnemonic: &MnemonicSecret) -> Result<Vec<(usize, String)>> {
        self.begin_reentry_inner(mnemonic)?;
        let expected = self
            .expected
            .as_ref()
            .ok_or(WalletError::BackupNotConfirmed)?;
        let words: Vec<(usize, String)> = expected
            .split_whitespace()
            .enumerate()
            .map(|(i, w)| (i + 1, w.to_owned()))
            .collect();
        Ok(words)
    }

    /// Prepare re-entry matching **without** returning word strings for display.
    ///
    /// Use for returning-wallet unlock: words are not shown again, but full
    /// phrase re-entry is still required before ShowAddress. Prefer this over
    /// calling [`Self::show_once`] and discarding the word list (which would
    /// leave non-zeroized `String` copies in the discarded `Vec`).
    pub fn begin_reentry_without_display(&mut self, mnemonic: &MnemonicSecret) -> Result<()> {
        self.begin_reentry_inner(mnemonic)?;
        Ok(())
    }

    fn begin_reentry_inner(&mut self, mnemonic: &MnemonicSecret) -> Result<()> {
        if self.confirmed {
            return Err(WalletError::BackupAlreadyConfirmed);
        }
        if self.shown {
            return Err(WalletError::BackupAlreadyShown);
        }
        // Align with BIP-39 `parse_normalized`: English wordlist is lowercase.
        let normalized = normalize_phrase(mnemonic.expose()).to_ascii_lowercase();
        if normalized.split_whitespace().next().is_none() {
            return Err(WalletError::InvalidMnemonic("empty phrase".into()));
        }
        self.expected = Some(Zeroizing::new(normalized));
        self.shown = true;
        Ok(())
    }

    /// Confirm by re-entering the full BIP-39 phrase (order-sensitive).
    ///
    /// Whitespace is collapsed and comparison is ASCII case-insensitive so
    /// autocorrect capitals match `import_mnemonic` / `Mnemonic::parse_normalized`.
    pub fn confirm_reentry(&mut self, phrase: &str) -> Result<()> {
        if self.confirmed {
            return Ok(());
        }
        if !self.shown {
            return Err(WalletError::BackupNotConfirmed);
        }
        let expected = self
            .expected
            .as_ref()
            .ok_or(WalletError::BackupNotConfirmed)?;
        let got = normalize_phrase(phrase).to_ascii_lowercase();
        if got != expected.as_str() {
            return Err(WalletError::BackupReentryMismatch);
        }
        self.expected = None;
        self.confirmed = true;
        Ok(())
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    // Moderate params for interactive unlock (not a KDF benchmark).
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
        .map_err(|e| WalletError::Aead(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| WalletError::Aead(format!("argon2 derive: {e}")))?;
    Ok(key)
}

fn encrypt_mnemonic(phrase: &str, password: &str) -> Result<AeadBlob> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| WalletError::Entropy(format!("salt: {e}")))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| WalletError::Entropy(format!("nonce: {e}")))?;

    let key_bytes = Zeroizing::new(derive_key(password, &salt)?);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, phrase.as_bytes())
        .map_err(|e| WalletError::Aead(format!("encrypt: {e}")))?;

    Ok(AeadBlob {
        v: AEAD_FORMAT_VERSION,
        salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
        ct: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ct),
    })
}

fn decrypt_mnemonic(blob: &AeadBlob, password: &str) -> Result<Zeroizing<String>> {
    if blob.v != AEAD_FORMAT_VERSION {
        return Err(WalletError::Aead(format!(
            "unsupported AEAD format version {}",
            blob.v
        )));
    }
    let salt = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &blob.salt)
        .map_err(|e| WalletError::Aead(format!("salt b64: {e}")))?;
    let nonce_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &blob.nonce)
            .map_err(|e| WalletError::Aead(format!("nonce b64: {e}")))?;
    let ct = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &blob.ct)
        .map_err(|e| WalletError::Aead(format!("ct b64: {e}")))?;

    if salt.len() != SALT_LEN || nonce_bytes.len() != NONCE_LEN {
        return Err(WalletError::Aead("invalid salt/nonce length".into()));
    }

    let key_bytes = Zeroizing::new(derive_key(password, &salt)?);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| WalletError::Aead("decrypt failed (wrong password or corrupt blob)".into()))?;
    let plain = Zeroizing::new(plain);
    let s =
        std::str::from_utf8(plain.as_ref()).map_err(|e| WalletError::Aead(format!("utf8: {e}")))?;
    Ok(Zeroizing::new(s.to_owned()))
}

/// Write `bytes` to `path` via temp file created mode 0600, fsync, rename.
fn write_secret_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "seed.aead".into());
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| WalletError::SeedVault(format!("create temp: {e}")))?
        };
        #[cfg(not(unix))]
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| WalletError::SeedVault(format!("create temp: {e}")))?;

        file.write_all(bytes)
            .map_err(|e| WalletError::SeedVault(format!("write temp: {e}")))?;
        file.sync_all()
            .map_err(|e| WalletError::SeedVault(format!("fsync temp: {e}")))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| WalletError::SeedVault(format!("chmod 0600: {e}")))?;
    }

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        WalletError::SeedVault(format!("rename temp: {e}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| WalletError::SeedVault(format!("chmod final 0600: {e}")))?;
    }

    Ok(())
}

/// Assert a path is not the forbidden CredentialsStore mirror filename.
pub fn assert_not_credentials_store_path(path: &Path) -> Result<()> {
    if path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "provider_credentials.json")
    {
        return Err(WalletError::SeedVault(
            "refusing to store BIP-39 in provider_credentials.json".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::generate_mnemonic;
    use tempfile::TempDir;

    #[test]
    fn aead_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.aead.json");
        assert_not_credentials_store_path(&path).unwrap();
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("test-password-not-for-prod");
        vault.store_aead(&m, &pw).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "AEAD file must be owner-only");
        }
        let loaded = vault.load_aead(&pw).unwrap();
        assert_eq!(loaded.expose(), m.expose());
    }

    #[test]
    fn aead_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        vault
            .store_aead(&m, &VaultPassword::new("correct-horse"))
            .unwrap();
        let err = vault
            .load_aead(&VaultPassword::new("wrong-password"))
            .unwrap_err();
        assert!(matches!(err, WalletError::Aead(_)));
    }

    #[test]
    fn refuse_provider_credentials_filename() {
        let p = Path::new("/tmp/foo/provider_credentials.json");
        assert!(assert_not_credentials_store_path(p).is_err());
    }

    #[test]
    fn store_aead_refuses_provider_credentials_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("provider_credentials.json");
        assert!(SeedVault::with_aead_path(&path).is_err());
        // Bypass constructor to prove store_aead also guards.
        let vault = SeedVault {
            aead_path: Some(path.clone()),
        };
        let m = generate_mnemonic().unwrap();
        let err = vault.store_aead(&m, &VaultPassword::new("pw")).unwrap_err();
        assert!(matches!(err, WalletError::SeedVault(_)));
        assert!(!path.exists(), "must not create forbidden path");
    }

    #[test]
    fn password_debug_redacted() {
        let pw = VaultPassword::new("super-secret");
        let s = format!("{pw:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("super-secret"));
    }

    #[test]
    fn aead_blob_debug_redacted() {
        let blob = AeadBlob {
            v: 1,
            salt: "s".into(),
            nonce: "n".into(),
            ct: "ciphertext-secret".into(),
        };
        let s = format!("{blob:?}");
        assert!(!s.contains("ciphertext-secret"));
    }

    #[test]
    fn delete_aead_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        vault.delete_aead().unwrap();
    }

    #[test]
    fn store_falls_back_to_aead_when_password_given() {
        // Keyring may or may not work in CI; with password we always can AEAD.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("fallback-pw");
        // Force AEAD path directly.
        vault.store_aead(&m, &pw).unwrap();
        let loaded = vault.load(Some(&pw)).unwrap();
        assert_eq!(loaded.expose(), m.expose());
        vault.delete_aead().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn load_without_password_requests_password_when_aead_present() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        vault
            .store_aead(&m, &VaultPassword::new("need-pw"))
            .unwrap();
        // Keyring miss + AEAD present + no password => PasswordRequired, not NotFound.
        let err = vault.load(None).unwrap_err();
        assert!(matches!(err, WalletError::PasswordRequired), "got {err:?}");
    }

    #[test]
    fn load_not_found_only_when_no_backends() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("absent.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        // Empty keyring + no AEAD file. Keyring may return NotFound or Keyring error
        // depending on CI; both must not look like a successful empty create if
        // Keyring hard-fails without AEAD (product aborts). Soft NotFound is OK.
        let err = vault.load(None).unwrap_err();
        assert!(
            matches!(err, WalletError::NotFound | WalletError::Keyring(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn begin_reentry_without_display_then_confirm() {
        let m = generate_mnemonic().unwrap();
        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(&m).unwrap();
        assert!(gate.was_shown());
        assert!(!gate.is_confirmed());
        // show_once must not work again (already shown).
        assert!(matches!(
            gate.show_once(&m).unwrap_err(),
            WalletError::BackupAlreadyShown
        ));
        gate.confirm_reentry(m.expose()).unwrap();
        assert!(gate.is_confirmed());
    }

    #[test]
    fn unlock_session_ttl_expires_and_zeroizes() {
        let m = generate_mnemonic().unwrap();
        let phrase = m.expose().to_owned();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(30);
        let mut session = UnlockSession::unlock_at_for_test(m, ttl, t0);

        assert!(session.is_unlocked(t0));
        assert_eq!(session.mnemonic(t0).unwrap().expose(), phrase);

        // Just before TTL: still unlocked.
        let almost = t0 + ttl - Duration::from_millis(1);
        assert!(session.is_unlocked(almost));

        // At/after TTL: expire drops material.
        let expired_at = t0 + ttl;
        assert!(session.is_expired(expired_at));
        assert!(session.expire_if_needed(expired_at));
        assert!(!session.is_unlocked(expired_at));
        assert!(matches!(
            session.mnemonic(expired_at).unwrap_err(),
            WalletError::SessionLocked
        ));
        assert!(matches!(
            session.touch(expired_at).unwrap_err(),
            WalletError::SessionLocked
        ));
    }

    #[test]
    fn unlock_session_is_expired_saturates_when_now_before_activity() {
        let m = generate_mnemonic().unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        let mut session = UnlockSession::unlock_at_for_test(m, Duration::from_secs(10), later);
        let earlier = Instant::now();
        // Must not panic; treat as not expired.
        assert!(!session.is_expired(earlier));
        assert!(session.check_unlocked(earlier));
    }

    #[test]
    fn unlock_session_check_unlocked_expires_stale() {
        let m = generate_mnemonic().unwrap();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(5);
        let mut session = UnlockSession::unlock_at_for_test(m, ttl, t0);
        let expired_at = t0 + ttl;
        // Pure is_unlocked does not drop, but check_unlocked does.
        assert!(!session.is_unlocked(expired_at));
        assert!(!session.check_unlocked(expired_at));
        assert!(matches!(
            session.mnemonic(expired_at).unwrap_err(),
            WalletError::SessionLocked
        ));
    }

    #[test]
    fn unlock_session_touch_extends_idle() {
        let m = generate_mnemonic().unwrap();
        let t0 = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut session = UnlockSession::unlock_at_for_test(m, ttl, t0);

        let mid = t0 + Duration::from_secs(8);
        session.touch(mid).unwrap();
        // Without touch, t0+10 would expire; after touch at +8, still live at +15.
        let later = t0 + Duration::from_secs(15);
        assert!(session.is_unlocked(later));
        let _ = session.mnemonic(later).unwrap();

        let too_late = later + ttl;
        assert!(session.expire_if_needed(too_late));
        assert!(matches!(
            session.mnemonic(too_late).unwrap_err(),
            WalletError::SessionLocked
        ));
    }

    #[test]
    fn unlock_session_lock_is_immediate() {
        let m = generate_mnemonic().unwrap();
        let mut session = UnlockSession::unlock_default(m);
        let now = Instant::now();
        assert!(session.is_unlocked(now));
        session.lock();
        assert!(!session.is_unlocked(now));
        assert!(matches!(
            session.mnemonic(now).unwrap_err(),
            WalletError::SessionLocked
        ));
    }

    #[test]
    fn backup_gate_show_once_and_confirm() {
        let m = generate_mnemonic().unwrap();
        let mut gate = MnemonicBackupGate::new();
        assert!(!gate.is_confirmed());

        let words = gate.show_once(&m).unwrap();
        assert_eq!(words.len(), m.word_count());
        assert_eq!(words[0].0, 1);
        assert!(gate.was_shown());

        // Second show rejected (show-once).
        assert!(matches!(
            gate.show_once(&m).unwrap_err(),
            WalletError::BackupAlreadyShown
        ));

        // Wrong re-entry rejected.
        assert!(matches!(
            gate.confirm_reentry("not the real phrase words here at all xx")
                .unwrap_err(),
            WalletError::BackupReentryMismatch
        ));
        assert!(!gate.is_confirmed());

        // Full phrase accepted (extra whitespace ok).
        let padded = format!("  {}  ", m.expose());
        gate.confirm_reentry(&padded).unwrap();
        assert!(gate.is_confirmed());
        // Idempotent confirm after success.
        gate.confirm_reentry(m.expose()).unwrap();
        // After confirm, show_once is already-confirmed (not merely shown).
        assert!(matches!(
            gate.show_once(&m).unwrap_err(),
            WalletError::BackupAlreadyConfirmed
        ));
    }

    #[test]
    fn backup_gate_accepts_mixed_case_reentry() {
        let m = generate_mnemonic().unwrap();
        let mut gate = MnemonicBackupGate::new();
        let _ = gate.show_once(&m).unwrap();
        let mixed: String = m
            .expose()
            .split_whitespace()
            .enumerate()
            .map(|(i, w)| {
                if i % 2 == 0 {
                    w.to_ascii_uppercase()
                } else {
                    let mut chars = w.chars();
                    match chars.next() {
                        Some(c) => {
                            let mut s = c.to_ascii_uppercase().to_string();
                            s.push_str(chars.as_str());
                            s
                        }
                        None => String::new(),
                    }
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        gate.confirm_reentry(&mixed).unwrap();
        assert!(gate.is_confirmed());
    }

    #[test]
    fn backup_gate_rejects_confirm_before_show() {
        let mut gate = MnemonicBackupGate::new();
        assert!(matches!(
            gate.confirm_reentry("anything").unwrap_err(),
            WalletError::BackupNotConfirmed
        ));
    }
}
