//! Shared error types for the wallet crate.

use thiserror::Error;

/// Errors from BIP-39 / SeedVault / derivation / payment helpers.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid BIP-39 mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("BIP-39 word count must be 12 or 24, got {0}")]
    InvalidWordCount(usize),

    #[error("entropy generation failed: {0}")]
    Entropy(String),

    #[error("seed vault: {0}")]
    SeedVault(String),

    #[error("keyring unavailable or failed: {0}")]
    Keyring(String),

    #[error("AEAD encrypt/decrypt failed: {0}")]
    Aead(String),

    #[error("password required for AEAD seed vault")]
    PasswordRequired,

    #[error("no seed stored")]
    NotFound,

    #[error("seed vault unlock session expired or locked")]
    SessionLocked,

    #[error("BIP-39 backup not confirmed (show once + full re-entry required)")]
    BackupNotConfirmed,

    #[error("BIP-39 backup already shown; re-entry required (phrase is not re-displayed)")]
    BackupAlreadyShown,

    #[error("BIP-39 backup already confirmed")]
    BackupAlreadyConfirmed,

    #[error("BIP-39 backup re-entry does not match")]
    BackupReentryMismatch,

    #[error("NIP-06 derivation failed: {0}")]
    Nip06(String),

    #[error("on-chain derivation failed: {0}")]
    Onchain(String),

    #[error("invalid Cashu token: {0}")]
    Cashu(String),

    #[error("invalid funding wizard transition: {from:?} -> {to:?}")]
    InvalidTransition {
        from: crate::cashu::FundingStep,
        to: crate::cashu::FundingStep,
    },

    #[error("channel wizard: {0}")]
    ChannelWizard(String),

    #[error("BOLT12 is not supported in this build")]
    Bolt12Unsupported,

    #[error("explorer HTTP: {0}")]
    Explorer(String),
}

pub type Result<T> = std::result::Result<T, WalletError>;
