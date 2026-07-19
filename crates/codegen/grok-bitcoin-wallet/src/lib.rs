//! Bitcoin wallet foundations for Grok OSS (Surmount).
//!
//! **Real money.** Read `SECURITY.md` and `docs/bitcoin-routstr/` before
//! extending this crate. Seed material must never use plaintext JSON stores.
//!
//! User-facing language: Bitcoin, Lightning, Cashu (Chaumian eCash) — never
//! "crypto".
//!
//! Implementation is phased. This crate currently documents intent and exposes
//! a stable package name for upcoming SeedVault / BDK / LDK / CDK work.

#![forbid(unsafe_code)]

/// Crate version (for diagnostics).
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short pointer for logs and `grok --version` style diagnostics.
pub fn security_doc_hint() -> &'static str {
    "see crates/codegen/grok-bitcoin-wallet/SECURITY.md and docs/bitcoin-routstr/"
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_metadata_present() {
        assert!(!super::CRATE_VERSION.is_empty());
        assert!(super::security_doc_hint().contains("bitcoin-routstr"));
    }
}
