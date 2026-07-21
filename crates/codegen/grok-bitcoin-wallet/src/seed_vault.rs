//! SeedVault: store BIP-39 mnemonics outside plaintext CredentialsStore JSON.
//!
//! ## Backends
//!
//! 1. **OS keyring** (preferred): service [`SEED_VAULT_SERVICE`], user
//!    [`SEED_VAULT_USER`]. Payload is the **phrase string** (human-readable
//!    OS UX; entropy bytes would be opaque/binary in many keyrings).
//! 2. **Password AEAD file**: Argon2id + XChaCha20-Poly1305 blob under a path
//!    the caller chooses. Path must pass [`assert_allowed_seed_storage_path`]
//!    (never `provider_credentials.json`, `watch_session.json`, or
//!    `config.toml`; match is ASCII case-insensitive).
//!
//! ## What is stored (seed material only — never passphrase)
//!
//! AEAD and keyring payloads hold **BIP-39 seed material only**. They are
//! **not** a JSON object and do **not** embed a BIP-39 **passphrase** field.
//!
//! | Channel | Encoding |
//! |---------|----------|
//! | Keyring | Phrase string (v1-equivalent; OS password field UX) |
//! | AEAD `store_aead` | Format **v1**: UTF-8 phrase string (legacy / default) |
//! | AEAD `store_aead_entropy` | Format **v2**: raw entropy bytes (16 / 32) |
//! | AEAD `load_aead` | Accepts **v1 and v2** |
//!
//! New AEAD writes bind the format version as AEAD AAD (`v` little-endian).
//! Legacy **v1** blobs written before AAD binding still load (decrypt tries
//! AAD first, then unbound for `v == 1` only). **v2** always requires AAD.
//!
//! Optional BIP-39 passphrase (unlock-time only via env
//! `GROK_BITCOIN_BIP39_PASSPHRASE` / library `&str`) is **never** a SeedVault
//! payload field, never written to AEAD, keyring, CredentialsStore, or
//! `watch_session.json`. Missing/empty → default derivation path.
//!
//! Types holding secrets never `Debug`-print mnemonic or entropy material
//! ([`crate::mnemonic::EntropyBytes`] is redacted).

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
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

/// AEAD envelope **v1**: ciphertext plaintext = UTF-8 BIP-39 phrase string.
const AEAD_FORMAT_VERSION_PHRASE: u32 = 1;

/// AEAD envelope **v2**: ciphertext plaintext = raw BIP-39 entropy bytes
/// (16 for 12-word, 32 for 24-word). No passphrase field.
const AEAD_FORMAT_VERSION_ENTROPY: u32 = 2;

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
    /// Returns [`WalletError::SeedVault`] if `path` is a forbidden seed-storage
    /// filename (see [`assert_allowed_seed_storage_path`]).
    pub fn with_aead_path(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        assert_allowed_seed_storage_path(&path)?;
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
    ///
    /// Writes format **v1** (UTF-8 phrase string). Prefer
    /// [`Self::store_aead_entropy`] for new installs that want compact entropy
    /// encoding. Does **not** accept or persist a BIP-39 passphrase.
    pub fn store_aead(&self, mnemonic: &MnemonicSecret, password: &VaultPassword) -> Result<()> {
        self.write_aead_blob(encrypt_payload(
            mnemonic.expose().as_bytes(),
            password.expose(),
            AEAD_FORMAT_VERSION_PHRASE,
        )?)
    }

    /// Store mnemonic as password-wrapped AEAD using **entropy-bytes** encoding
    /// (format **v2**: 16 bytes for 12-word, 32 for 24-word).
    ///
    /// Load via [`Self::load_aead`] (accepts v1 phrase and v2 entropy). Keyring
    /// paths still store the phrase string for OS UX. Does **not** accept or
    /// persist a BIP-39 passphrase.
    pub fn store_aead_entropy(
        &self,
        mnemonic: &MnemonicSecret,
        password: &VaultPassword,
    ) -> Result<()> {
        let entropy = mnemonic.to_entropy()?;
        let blob = encrypt_payload(
            entropy.as_ref(),
            password.expose(),
            AEAD_FORMAT_VERSION_ENTROPY,
        )?;
        // `entropy` zeroizes on drop after encrypt copies plaintext into AEAD.
        drop(entropy);
        self.write_aead_blob(blob)
    }

    /// Load mnemonic from password-wrapped AEAD file.
    ///
    /// Accepts format **v1** (phrase UTF-8) and **v2** (raw entropy bytes).
    /// Reconstructs [`MnemonicSecret`] via bip39; does **not** recover or store
    /// a BIP-39 passphrase (unlock env/API only).
    pub fn load_aead(&self, password: &VaultPassword) -> Result<MnemonicSecret> {
        let path = self.aead_path.as_ref().ok_or_else(|| {
            WalletError::SeedVault("no AEAD path configured (use SeedVault::with_aead_path)".into())
        })?;
        assert_allowed_seed_storage_path(path)?;
        if !path.exists() {
            return Err(WalletError::NotFound);
        }
        let bytes = fs::read(path).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        let blob: AeadBlob =
            serde_json::from_slice(&bytes).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        decrypt_to_mnemonic(&blob, password.expose())
    }

    /// Write an encrypted envelope to the configured AEAD path (path guards).
    fn write_aead_blob(&self, blob: AeadBlob) -> Result<()> {
        let path = self.aead_path.as_ref().ok_or_else(|| {
            WalletError::SeedVault("no AEAD path configured (use SeedVault::with_aead_path)".into())
        })?;
        assert_allowed_seed_storage_path(path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        }
        let json =
            serde_json::to_vec_pretty(&blob).map_err(|e| WalletError::SeedVault(e.to_string()))?;
        write_secret_file_atomic(path, &json)?;
        Ok(())
    }

    /// Delete AEAD file if present.
    ///
    /// Refuses forbidden seed-storage path filenames (same guard as store/load)
    /// so a same-crate struct-literal bypass cannot unlink product files such
    /// as `watch_session.json` or `provider_credentials.json`.
    pub fn delete_aead(&self) -> Result<()> {
        let Some(path) = self.aead_path.as_ref() else {
            return Ok(());
        };
        assert_allowed_seed_storage_path(path)?;
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

/// Derive AEAD key material; buffer is always zeroized on drop (incl. Err paths).
fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    // Moderate params for interactive unlock (not a KDF benchmark).
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
        .map_err(|e| WalletError::Aead(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| WalletError::Aead(format!("argon2 derive: {e}")))?;
    Ok(key)
}

/// AAD for format-version binding: little-endian `v` (authenticated, not secret).
fn version_aad(version: u32) -> [u8; 4] {
    version.to_le_bytes()
}

/// Encrypt `plaintext` under Argon2id + XChaCha20-Poly1305 with format `version`.
///
/// Binds `version` as AEAD AAD so envelope `v` cannot be flipped without
/// invalidating the Poly1305 tag.
fn encrypt_payload(plaintext: &[u8], password: &str, version: u32) -> Result<AeadBlob> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| WalletError::Entropy(format!("salt: {e}")))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| WalletError::Entropy(format!("nonce: {e}")))?;

    let key_bytes = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = version_aad(version);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| WalletError::Aead(format!("encrypt: {e}")))?;

    Ok(AeadBlob {
        v: version,
        salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
        ct: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ct),
    })
}

/// Decrypt AEAD ciphertext to zeroizing plaintext bytes (version-checked).
///
/// New writes bind `v` as AAD. Legacy **v1** blobs (pre-AAD) still load via a
/// single no-AAD fallback when AAD decrypt fails and `v == 1` only. **v2**
/// always requires matching AAD (fail closed if version is flipped).
fn decrypt_payload(blob: &AeadBlob, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    if blob.v != AEAD_FORMAT_VERSION_PHRASE && blob.v != AEAD_FORMAT_VERSION_ENTROPY {
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

    let key_bytes = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = version_aad(blob.v);
    let plain = match cipher.decrypt(
        nonce,
        Payload {
            msg: ct.as_ref(),
            aad: &aad,
        },
    ) {
        Ok(p) => p,
        Err(_) if blob.v == AEAD_FORMAT_VERSION_PHRASE => {
            // Legacy v1: ciphertext not bound to version (written before AAD).
            cipher.decrypt(nonce, ct.as_ref()).map_err(|_| {
                WalletError::Aead("decrypt failed (wrong password or corrupt blob)".into())
            })?
        }
        Err(_) => {
            return Err(WalletError::Aead(
                "decrypt failed (wrong password or corrupt blob)".into(),
            ));
        }
    };
    Ok(Zeroizing::new(plain))
}

/// Decrypt envelope → [`MnemonicSecret`] (v1 phrase or v2 entropy).
fn decrypt_to_mnemonic(blob: &AeadBlob, password: &str) -> Result<MnemonicSecret> {
    let plain = decrypt_payload(blob, password)?;
    match blob.v {
        AEAD_FORMAT_VERSION_PHRASE => {
            let s = std::str::from_utf8(plain.as_ref())
                .map_err(|e| WalletError::Aead(format!("utf8: {e}")))?;
            // Only long-lived holder is MnemonicSecret (secrecy/zeroize on drop).
            import_mnemonic(s)
        }
        AEAD_FORMAT_VERSION_ENTROPY => {
            // Reconstruct phrase from entropy; plain buffer zeroizes on drop.
            MnemonicSecret::from_entropy(plain.as_ref())
        }
        other => Err(WalletError::Aead(format!(
            "unsupported AEAD format version {other}"
        ))),
    }
}

/// Decrypt v1 phrase plaintext as UTF-8 string (tests / phrase-only probes).
#[cfg(test)]
fn decrypt_mnemonic_phrase(blob: &AeadBlob, password: &str) -> Result<Zeroizing<String>> {
    if blob.v != AEAD_FORMAT_VERSION_PHRASE {
        return Err(WalletError::Aead(format!(
            "expected phrase format v{AEAD_FORMAT_VERSION_PHRASE}, got v{}",
            blob.v
        )));
    }
    let plain = decrypt_payload(blob, password)?;
    let s =
        std::str::from_utf8(plain.as_ref()).map_err(|e| WalletError::Aead(format!("utf8: {e}")))?;
    Ok(Zeroizing::new(s.to_owned()))
}

/// Test-only: encrypt like pre-AAD v1 writers (no version AAD).
#[cfg(test)]
fn encrypt_payload_legacy_no_aad(
    plaintext: &[u8],
    password: &str,
    version: u32,
) -> Result<AeadBlob> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| WalletError::Entropy(format!("salt: {e}")))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| WalletError::Entropy(format!("nonce: {e}")))?;
    let key_bytes = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| WalletError::Aead(format!("encrypt: {e}")))?;
    Ok(AeadBlob {
        v: version,
        salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
        ct: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ct),
    })
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

/// Filenames SeedVault must never use for AEAD (or any on-disk seed) storage.
///
/// Kept small and explicit: product hot-key mirror, durable watch progress,
/// and shell config — not a sprawling denylist.
const FORBIDDEN_SEED_STORAGE_FILENAMES: &[&str] = &[
    "provider_credentials.json",
    "watch_session.json",
    "config.toml",
];

/// Assert `path` is allowed for SeedVault AEAD / on-disk seed storage.
///
/// Refuses known product files that must never hold BIP-39 (CredentialsStore
/// mirror, watch-session progress, shell config). Matches on the final path
/// component only (any directory), with **ASCII case-insensitive** comparison
/// so case-insensitive filesystems (macOS APFS default, Windows) cannot bypass
/// the denylist via `Config.toml` / `PROVIDER_CREDENTIALS.JSON` aliases.
///
/// Prefer this over ad-hoc filename checks at call sites.
pub fn assert_allowed_seed_storage_path(path: &Path) -> Result<()> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(());
    };
    if FORBIDDEN_SEED_STORAGE_FILENAMES
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
    {
        return Err(WalletError::SeedVault(format!(
            "refusing to store BIP-39 in forbidden path filename {name}"
        )));
    }
    Ok(())
}

/// Legacy alias for [`assert_allowed_seed_storage_path`].
///
/// Historically refused only `provider_credentials.json`; the helper now
/// refuses the full forbidden-filename set. Prefer the new name at call sites.
#[inline]
pub fn assert_not_credentials_store_path(path: &Path) -> Result<()> {
    assert_allowed_seed_storage_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::{generate_mnemonic, generate_mnemonic_with_word_count};
    use tempfile::TempDir;

    #[test]
    fn aead_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.aead.json");
        assert_allowed_seed_storage_path(&path).unwrap();
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
    fn aead_plaintext_is_mnemonic_phrase_only_not_passphrase_json() {
        // Policy: AEAD encrypts the BIP-39 word string alone. Decrypt must not
        // yield JSON (or any structure) that embeds a separate passphrase field.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("aead-plain-check");
        vault.store_aead(&m, &pw).unwrap();

        let bytes = fs::read(&path).unwrap();
        let blob: AeadBlob = serde_json::from_slice(&bytes).unwrap();
        // On-disk envelope metadata only — no mnemonic/passphrase keys at rest
        // in cleartext JSON fields.
        let envelope = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        let env_obj = envelope.as_object().expect("envelope object");
        for forbidden_key in ["mnemonic", "passphrase", "bip39_passphrase", "seed"] {
            assert!(
                !env_obj.contains_key(forbidden_key),
                "AEAD envelope must not have cleartext key {forbidden_key}"
            );
        }

        let plain = decrypt_mnemonic_phrase(&blob, pw.expose()).unwrap();
        let plain_s = plain.as_str();
        // Plaintext is the phrase string, not a JSON document.
        assert!(
            !plain_s.trim_start().starts_with('{'),
            "AEAD plaintext must not be JSON: {plain_s:?}"
        );
        assert!(
            !plain_s.to_ascii_lowercase().contains("passphrase"),
            "AEAD plaintext must not embed passphrase field: {plain_s:?}"
        );
        assert_eq!(plain_s, m.expose());
        // Round-trip through BIP-39 import proves it is a phrase, not a bag of keys.
        let reimported = import_mnemonic(plain_s).unwrap();
        assert_eq!(reimported.expose(), m.expose());
        // store_aead has no passphrase parameter — only VaultPassword (wrap KDF).
        // Documented: BIP-39 passphrase is unlock env/API only, never payload.
    }

    #[test]
    fn aead_entropy_encoding_roundtrip_twelve_words() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.entropy.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        assert_eq!(m.word_count(), 12);
        let pw = VaultPassword::new("entropy-encode-pw");
        vault.store_aead_entropy(&m, &pw).unwrap();

        let bytes = fs::read(&path).unwrap();
        let blob: AeadBlob = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(blob.v, AEAD_FORMAT_VERSION_ENTROPY);

        let loaded = vault.load_aead(&pw).unwrap();
        assert_eq!(loaded.expose(), m.expose());
        assert_eq!(loaded.word_count(), 12);
    }

    #[test]
    fn aead_entropy_encoding_roundtrip_twenty_four_words() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.entropy24.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic_with_word_count(24).unwrap();
        assert_eq!(m.word_count(), 24);
        assert_eq!(m.to_entropy().unwrap().len(), 32);
        let pw = VaultPassword::new("entropy-24-pw");
        vault.store_aead_entropy(&m, &pw).unwrap();
        let loaded = vault.load_aead(&pw).unwrap();
        assert_eq!(loaded.expose(), m.expose());
        assert_eq!(loaded.word_count(), 24);
    }

    #[test]
    fn aead_entropy_load_via_product_load_fallback() {
        // Product entry: keyring miss → AEAD; v2 entropy blob via load(Some(pw)).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.entropy.product_load.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("product-load-entropy-pw");
        vault.store_aead_entropy(&m, &pw).unwrap();
        let loaded = vault.load(Some(&pw)).unwrap();
        assert_eq!(loaded.expose(), m.expose());
    }

    #[test]
    fn aead_legacy_v1_no_aad_still_loads() {
        // Pre-AAD v1 blobs must keep working (migration fallback).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.legacy_no_aad.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("legacy-no-aad-pw");
        let blob = encrypt_payload_legacy_no_aad(
            m.expose().as_bytes(),
            pw.expose(),
            AEAD_FORMAT_VERSION_PHRASE,
        )
        .unwrap();
        vault.write_aead_blob(blob).unwrap();
        let loaded = vault.load_aead(&pw).unwrap();
        assert_eq!(loaded.expose(), m.expose());
    }

    #[test]
    fn aead_version_aad_rejects_flipped_envelope_v() {
        // AAD binds format version: flipping cleartext `v` must fail closed.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.aad_flip.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("aad-flip-pw");
        vault.store_aead_entropy(&m, &pw).unwrap();

        let bytes = fs::read(&path).unwrap();
        let mut blob: AeadBlob = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(blob.v, AEAD_FORMAT_VERSION_ENTROPY);
        blob.v = AEAD_FORMAT_VERSION_PHRASE; // attacker flips version
        let tampered = serde_json::to_vec_pretty(&blob).expect("serialize tampered envelope");
        write_secret_file_atomic(&path, &tampered).unwrap();

        let err = vault.load_aead(&pw).unwrap_err();
        assert!(
            matches!(err, WalletError::Aead(_)),
            "flipped v must fail closed, got {err:?}"
        );
    }

    #[test]
    fn aead_load_legacy_v1_phrase_after_entropy_upgrade() {
        // v1 phrase blobs written before the encoding upgrade must still load.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.legacy.aead.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("legacy-v1-pw");
        vault.store_aead(&m, &pw).unwrap();

        let bytes = fs::read(&path).unwrap();
        let blob: AeadBlob = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(blob.v, AEAD_FORMAT_VERSION_PHRASE);

        let loaded = vault.load_aead(&pw).unwrap();
        assert_eq!(loaded.expose(), m.expose());
    }

    #[test]
    fn aead_entropy_plaintext_is_raw_bytes_not_passphrase_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.entropy.plain.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("entropy-plain-check");
        vault.store_aead_entropy(&m, &pw).unwrap();

        let bytes = fs::read(&path).unwrap();
        let envelope = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        let env_obj = envelope.as_object().expect("envelope object");
        for forbidden_key in ["mnemonic", "passphrase", "bip39_passphrase", "seed"] {
            assert!(
                !env_obj.contains_key(forbidden_key),
                "AEAD envelope must not have cleartext key {forbidden_key}"
            );
        }
        assert_eq!(
            env_obj.get("v").and_then(|v| v.as_u64()),
            Some(u64::from(AEAD_FORMAT_VERSION_ENTROPY))
        );

        let blob: AeadBlob = serde_json::from_slice(&bytes).unwrap();
        let plain = decrypt_payload(&blob, pw.expose()).unwrap();
        let plain_bytes: &[u8] = plain.as_ref();
        // Entropy plaintext is raw bytes (16 for 12-word) — not UTF-8 JSON.
        assert_eq!(plain_bytes.len(), 16);
        // Never a JSON object / passphrase field document.
        if let Ok(s) = std::str::from_utf8(plain_bytes) {
            assert!(
                !s.trim_start().starts_with('{'),
                "entropy plaintext must not be JSON"
            );
            assert!(
                !s.to_ascii_lowercase().contains("passphrase"),
                "entropy plaintext must not embed passphrase"
            );
        }
        let rebuilt = MnemonicSecret::from_entropy(plain_bytes).unwrap();
        assert_eq!(rebuilt.expose(), m.expose());
    }

    #[test]
    fn aead_entropy_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.entropy.wrong.json");
        let vault = SeedVault::with_aead_path(&path).unwrap();
        let m = generate_mnemonic().unwrap();
        vault
            .store_aead_entropy(&m, &VaultPassword::new("correct-horse"))
            .unwrap();
        let err = vault
            .load_aead(&VaultPassword::new("wrong-password"))
            .unwrap_err();
        assert!(matches!(err, WalletError::Aead(_)));
    }

    #[test]
    fn aead_entropy_store_refuses_forbidden_paths() {
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("pw");
        for name in [
            "provider_credentials.json",
            "watch_session.json",
            "config.toml",
        ] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join(name);
            let vault = SeedVault {
                aead_path: Some(path.clone()),
            };
            let err = vault.store_aead_entropy(&m, &pw).unwrap_err();
            assert!(
                matches!(err, WalletError::SeedVault(_)),
                "{name} store_aead_entropy: {err:?}"
            );
            assert!(!path.exists(), "{name}: must not create forbidden path");
        }
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
    fn refuse_forbidden_seed_storage_filenames() {
        for name in [
            "provider_credentials.json",
            "watch_session.json",
            "config.toml",
        ] {
            let p = Path::new("/tmp/foo").join(name);
            let err = assert_allowed_seed_storage_path(&p).unwrap_err();
            assert!(matches!(err, WalletError::SeedVault(_)), "{name}: {err:?}");
            // Legacy alias must refuse the same set.
            assert!(assert_not_credentials_store_path(&p).is_err(), "{name}");
        }
        // Allowed AEAD-style names still pass.
        assert_allowed_seed_storage_path(Path::new("/tmp/foo/seed.aead.json")).unwrap();
        assert_allowed_seed_storage_path(Path::new("/tmp/foo/bip39.aead")).unwrap();
    }

    #[test]
    fn refuse_forbidden_seed_storage_filenames_case_insensitive() {
        // Case-insensitive FS (macOS/Windows) aliases must not bypass denylist.
        for name in [
            "Provider_Credentials.json",
            "PROVIDER_CREDENTIALS.JSON",
            "Watch_Session.json",
            "WATCH_SESSION.JSON",
            "Config.toml",
            "CONFIG.TOML",
            "config.TOML",
        ] {
            let p = Path::new("/tmp/foo").join(name);
            let err = assert_allowed_seed_storage_path(&p).unwrap_err();
            assert!(
                matches!(err, WalletError::SeedVault(_)),
                "{name} must refuse: {err:?}"
            );
            assert!(
                SeedVault::with_aead_path(&p).is_err(),
                "{name} ctor must refuse"
            );
        }
    }

    /// Ctor + store + planted load + delete all refuse every forbidden basename.
    #[test]
    fn aead_ops_refuse_all_forbidden_basenames_including_planted_load() {
        let m = generate_mnemonic().unwrap();
        let pw = VaultPassword::new("pw");
        for name in [
            "provider_credentials.json",
            "watch_session.json",
            "config.toml",
        ] {
            let dir = TempDir::new().unwrap();
            let path = if name == "watch_session.json" {
                dir.path().join("bitcoin").join(name)
            } else {
                dir.path().join(name)
            };

            let ctor_err = SeedVault::with_aead_path(&path).unwrap_err();
            assert!(
                matches!(ctor_err, WalletError::SeedVault(_)),
                "{name} ctor: {ctor_err:?}"
            );

            // Same-crate bypass: store / load / delete must still refuse.
            let vault = SeedVault {
                aead_path: Some(path.clone()),
            };
            let store_err = vault.store_aead(&m, &pw).unwrap_err();
            assert!(
                matches!(store_err, WalletError::SeedVault(_)),
                "{name} store: {store_err:?}"
            );
            assert!(
                !path.exists(),
                "{name}: store must not create forbidden path"
            );

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, b"{}").unwrap();
            assert!(path.exists(), "{name}: plant for load/delete");

            let load_err = vault.load_aead(&pw).unwrap_err();
            assert!(
                matches!(load_err, WalletError::SeedVault(_)),
                "{name} planted load: {load_err:?}"
            );

            let delete_err = vault.delete_aead().unwrap_err();
            assert!(
                matches!(delete_err, WalletError::SeedVault(_)),
                "{name} delete: {delete_err:?}"
            );
            // Forbidden delete must not unlink the planted product file.
            assert!(
                path.exists(),
                "{name}: delete_aead must refuse, not remove planted file"
            );
            let _ = fs::remove_file(&path);
        }
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
