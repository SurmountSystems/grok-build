//! NIP-06 Nostr key derivation from BIP-39.
//!
//! Path: `m/44'/1237'/0'/0/0` via `nostr::Keys::from_mnemonic`.
//!
//! `npub` is exportable; `nsec` / secret hex only through controlled APIs that
//! return redacted secret wrappers.
//!
//! # Product residual
//!
//! Library derive + official vectors are green. Pure NIP-98 Authorization
//! build/parse + request-match live in [`crate::nip98`] (offline-proveable
//! against the NIP). **Product** Routstr API auth via this identity remains
//! residual — live Routstr (OpenAPI / routstr-core `validate_bearer_key`)
//! accepts Bearer `sk-` / `cashu…` only (re-verified 2026-07-20); never invent
//! signed-auth Success, and never put nsec/seed into CredentialsStore /
//! `provider_credentials` / watch_session.

use std::fmt;

use nostr::Keys;
use nostr::ToBech32;
use nostr::nips::nip06::FromMnemonic;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;

/// Official NIP-06 test mnemonic (English, 12 words).
pub const NIP06_TEST_MNEMONIC: &str =
    "leader monkey parrot ring guide accident before fence cannon height naive bean";

/// Expected secret key hex for [`NIP06_TEST_MNEMONIC`] (empty passphrase).
pub const NIP06_TEST_SECRET_KEY_HEX: &str =
    "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";

/// Derived Nostr identity. Secret material is not shown in `Debug`.
pub struct NostrIdentity {
    npub: String,
    /// Hex-encoded secret key. Only exposed via [`Self::secret_key_hex`].
    secret_hex: SecretString,
    /// bech32 nsec. Only exposed via [`Self::nsec`].
    nsec: SecretString,
}

impl fmt::Debug for NostrIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NostrIdentity")
            .field("npub", &self.npub)
            .field("secret_hex", &"[REDACTED]")
            .field("nsec", &"[REDACTED]")
            .finish()
    }
}

impl NostrIdentity {
    /// Public key in bech32 `npub1…` form.
    pub fn npub(&self) -> &str {
        &self.npub
    }

    /// Secret key hex (controlled API; do not log).
    pub fn secret_key_hex(&self) -> &str {
        self.secret_hex.expose_secret()
    }

    /// bech32 `nsec1…` (controlled API; do not log).
    pub fn nsec(&self) -> &str {
        self.nsec.expose_secret()
    }
}

/// Derive Nostr keys from a mnemonic (optional BIP-39 passphrase).
pub fn derive_nostr_identity(
    mnemonic: &MnemonicSecret,
    passphrase: Option<&str>,
) -> Result<NostrIdentity> {
    let pass = passphrase.filter(|p| !p.is_empty());
    let keys = Keys::from_mnemonic(mnemonic.expose(), pass)
        .map_err(|e| WalletError::Nip06(e.to_string()))?;
    let npub = keys
        .public_key()
        .to_bech32()
        .map_err(|e| WalletError::Nip06(format!("npub encode: {e}")))?;
    let secret_hex = keys.secret_key().to_secret_hex();
    let nsec = keys
        .secret_key()
        .to_bech32()
        .map_err(|e| WalletError::Nip06(format!("nsec encode: {e}")))?;
    Ok(NostrIdentity {
        npub,
        secret_hex: SecretString::from(secret_hex),
        nsec: SecretString::from(nsec),
    })
}

/// Convenience: derive from phrase string (validates BIP-39 first).
pub fn derive_nostr_identity_from_phrase(
    phrase: &str,
    passphrase: Option<&str>,
) -> Result<NostrIdentity> {
    let m = crate::mnemonic::import_mnemonic(phrase)?;
    derive_nostr_identity(&m, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::import_mnemonic;

    #[test]
    fn nip06_official_vector_secret_key_hex() {
        let m = import_mnemonic(NIP06_TEST_MNEMONIC).expect("valid mnemonic");
        let id = derive_nostr_identity(&m, None).expect("derive");
        assert_eq!(
            id.secret_key_hex(),
            NIP06_TEST_SECRET_KEY_HEX,
            "NIP-06 official vector must match"
        );
        assert!(id.npub().starts_with("npub1"));
        assert!(id.nsec().starts_with("nsec1"));
    }

    #[test]
    fn debug_redacts_secrets() {
        let m = import_mnemonic(NIP06_TEST_MNEMONIC).unwrap();
        let id = derive_nostr_identity(&m, None).unwrap();
        let dbg = format!("{id:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(NIP06_TEST_SECRET_KEY_HEX));
        assert!(!dbg.contains("nsec1"));
        assert!(dbg.contains("npub"));
    }

    #[test]
    fn npub_stable_for_vector() {
        let a = derive_nostr_identity_from_phrase(NIP06_TEST_MNEMONIC, None).unwrap();
        let b = derive_nostr_identity_from_phrase(NIP06_TEST_MNEMONIC, None).unwrap();
        assert_eq!(a.npub(), b.npub());
        assert_eq!(a.secret_key_hex(), b.secret_key_hex());
    }
}
