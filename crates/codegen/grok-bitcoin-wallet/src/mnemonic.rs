//! BIP-39 mnemonic generate / import / validate.
//!
//! Entropy comes from [`getrandom`] (OS CSPRNG). Default word count is **12**.

use std::fmt;
use std::str::FromStr;

use bip39::Mnemonic;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use crate::error::{Result, WalletError};

/// Default BIP-39 word count for new wallets.
pub const DEFAULT_WORD_COUNT: usize = 12;

/// Process env var for an optional BIP-39 passphrase at product unlock/sign time.
///
/// **Never persist** this value: not CredentialsStore / `provider_credentials.json`,
/// not `watch_session.json`, not chat history, not SeedVault AEAD (seed only).
/// Missing or empty → default BIP-39 path (`""`). Prefer setting only for the
/// duration of a CLI unlock session. TUI also supports a private masked modal
/// via `/routstr unlock pass …` (never CredentialsStore / watch_session).
pub const BIP39_PASSPHRASE_ENV: &str = "GROK_BITCOIN_BIP39_PASSPHRASE";

/// Secret BIP-39 mnemonic. Does **not** implement `Debug`/`Display` of words.
///
/// Drop zeroizes the underlying secret string via [`secrecy`].
pub struct MnemonicSecret(SecretString);

/// Optional BIP-39 passphrase for product derive/sign paths.
///
/// Debug is redacted. Drop zeroizes via [`secrecy`]. Never log [`Self::expose`].
pub struct Bip39Passphrase(SecretString);

impl Bip39Passphrase {
    /// Wrap a passphrase (empty string = default BIP-39 path).
    pub fn new(passphrase: impl Into<String>) -> Self {
        Self(SecretString::from(passphrase.into()))
    }

    /// Read [`BIP39_PASSPHRASE_ENV`] (missing → empty / default path).
    pub fn from_env() -> Self {
        Self::new(std::env::var(BIP39_PASSPHRASE_ENV).unwrap_or_default())
    }

    /// Expose for derivation / signing only. Never log or format into messages.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Whether a non-empty passphrase is set.
    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
}

impl fmt::Debug for Bip39Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bip39Passphrase([REDACTED])")
    }
}

impl Default for Bip39Passphrase {
    fn default() -> Self {
        Self::new(String::new())
    }
}

impl MnemonicSecret {
    /// Wrap an already-validated phrase (crate-internal only).
    ///
    /// External callers must use [`import_mnemonic`] / [`generate_mnemonic`].
    pub(crate) fn from_validated(phrase: String) -> Self {
        Self(SecretString::from(phrase))
    }

    /// Expose the phrase for derivation / backup UX only.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Number of space-separated words.
    pub fn word_count(&self) -> usize {
        self.expose().split_whitespace().count()
    }

    /// BIP-39 seed bytes (64) with optional passphrase (empty = default path).
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let m = Mnemonic::parse_normalized(self.expose())
            .expect("MnemonicSecret always holds a validated phrase");
        m.to_seed(passphrase)
    }

    /// Consume into owned phrase string (caller must zeroize when done).
    pub fn into_phrase(self) -> String {
        self.0.expose_secret().to_owned()
    }
}

impl fmt::Debug for MnemonicSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MnemonicSecret([REDACTED])")
    }
}

/// Generate a new English BIP-39 mnemonic (default 12 words).
///
/// Uses `bip39`'s `rand` feature which draws from the OS CSPRNG (`getrandom`).
pub fn generate_mnemonic() -> Result<MnemonicSecret> {
    generate_mnemonic_with_word_count(DEFAULT_WORD_COUNT)
}

/// Generate with explicit word count (12 or 24).
pub fn generate_mnemonic_with_word_count(word_count: usize) -> Result<MnemonicSecret> {
    if word_count != 12 && word_count != 24 {
        return Err(WalletError::InvalidWordCount(word_count));
    }
    let mnemonic = Mnemonic::generate(word_count).map_err(|e| {
        WalletError::Entropy(format!("BIP-39 generate failed ({word_count} words): {e}"))
    })?;
    Ok(MnemonicSecret::from_validated(mnemonic.to_string()))
}

/// Parse and validate a BIP-39 phrase (checksum + wordlist).
pub fn import_mnemonic(phrase: &str) -> Result<MnemonicSecret> {
    let normalized = normalize_phrase(phrase);
    let word_count = normalized.split_whitespace().count();
    if word_count != 12 && word_count != 24 {
        return Err(WalletError::InvalidWordCount(word_count));
    }
    let mnemonic = Mnemonic::parse_normalized(&normalized)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
    Ok(MnemonicSecret::from_validated(mnemonic.to_string()))
}

/// Validate without allocating a [`MnemonicSecret`].
pub fn validate_mnemonic(phrase: &str) -> Result<()> {
    import_mnemonic(phrase).map(|_| ())
}

/// Collapse whitespace and trim for backup re-entry comparison.
pub fn normalize_phrase(phrase: &str) -> String {
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Zeroize a mutable phrase buffer after backup confirmation.
pub fn zeroize_phrase(phrase: &mut String) {
    phrase.zeroize();
}

impl FromStr for MnemonicSecret {
    type Err = WalletError;

    fn from_str(s: &str) -> Result<Self> {
        import_mnemonic(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_twelve_words() {
        let m = generate_mnemonic().expect("generate");
        assert_eq!(m.word_count(), 12);
        validate_mnemonic(m.expose()).expect("generated must validate");
    }

    #[test]
    fn generate_twenty_four_words() {
        let m = generate_mnemonic_with_word_count(24).expect("generate 24");
        assert_eq!(m.word_count(), 24);
        validate_mnemonic(m.expose()).expect("generated 24 must validate");
    }

    #[test]
    fn reject_invalid_word_count() {
        assert!(matches!(
            generate_mnemonic_with_word_count(15),
            Err(WalletError::InvalidWordCount(15))
        ));
    }

    #[test]
    fn import_valid_known_mnemonic() {
        // NIP-06 vector mnemonic (valid BIP-39 checksum).
        let phrase =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let m = import_mnemonic(phrase).expect("import");
        assert_eq!(m.word_count(), 12);
        assert_eq!(m.expose(), phrase);
    }

    #[test]
    fn reject_invalid_checksum() {
        // Flip last word to break checksum while keeping wordlist words.
        let bad =
            "leader monkey parrot ring guide accident before fence cannon height naive abandon";
        let err = import_mnemonic(bad).expect_err("checksum must fail");
        assert!(matches!(err, WalletError::InvalidMnemonic(_)));
    }

    #[test]
    fn reject_unknown_words() {
        let bad =
            "notaword monkey parrot ring guide accident before fence cannon height naive bean";
        assert!(import_mnemonic(bad).is_err());
    }

    #[test]
    fn reject_wrong_count_on_import() {
        let bad = "leader monkey parrot";
        assert!(matches!(
            import_mnemonic(bad),
            Err(WalletError::InvalidWordCount(3))
        ));
    }

    #[test]
    fn debug_redacts_secret() {
        let m = import_mnemonic(
            "leader monkey parrot ring guide accident before fence cannon height naive bean",
        )
        .unwrap();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("leader"));
        assert!(!dbg.contains("monkey"));
    }

    #[test]
    fn bip39_passphrase_debug_redacts_and_env_default_empty() {
        let secret = Bip39Passphrase::new("correct-horse-battery");
        let dbg = format!("{secret:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("correct-horse"));
        assert!(!dbg.contains("battery"));
        assert_eq!(secret.expose(), "correct-horse-battery");
        assert!(!secret.is_empty());

        // Default / empty are default BIP-39 path.
        assert!(Bip39Passphrase::default().is_empty());
        assert_eq!(Bip39Passphrase::new("").expose(), "");
        assert_eq!(BIP39_PASSPHRASE_ENV, "GROK_BITCOIN_BIP39_PASSPHRASE");
    }

    #[test]
    fn normalize_whitespace_on_import() {
        let phrase =
            "  leader   monkey parrot ring guide accident before fence cannon height naive bean  ";
        let m = import_mnemonic(phrase).unwrap();
        assert_eq!(
            m.expose(),
            "leader monkey parrot ring guide accident before fence cannon height naive bean"
        );
    }
}
