//! Cashu (Chaumian eCash) token newtype + funding wizard state machine.
//!
//! Full CDK mint/spend is residual; this module provides safe types, the
//! wizard transitions that glue deposit → channel → Cashu → inference, and
//! honest [`CashuBackend`] capability seams so stubs never claim a live mint
//! invoice or completed refund.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};

use crate::error::{Result, WalletError};

/// Capability flags for a Cashu backend (CDK mint/wallet when live).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CashuCapabilities {
    /// Can request a mint quote / BOLT11 to acquire Cashu tokens.
    pub mint_live: bool,
    /// Can spend Cashu tokens against a Routstr (or other) mint.
    pub spend_live: bool,
    /// Can return / melt Cashu back to Lightning or on-chain.
    pub refund_live: bool,
}

/// Pre-CDK stub: nothing live.
pub const STUB_CASHU_CAPABILITIES: CashuCapabilities = CashuCapabilities {
    mint_live: false,
    spend_live: false,
    refund_live: false,
};

/// Outcome of requesting a Cashu mint (top-up) invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintQuoteOutcome {
    /// Live mint quote with a real BOLT11 (only when `mint_live`).
    Invoice {
        bolt11: String,
        quote_id: String,
    },
    /// Backend cannot mint in this build.
    Unsupported(&'static str),
    Failed(String),
}

/// Outcome of a Cashu refund / melt attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CashuRefundOutcome {
    /// Live refund completed (only when `refund_live`).
    Completed {
        detail: String,
    },
    Unsupported(&'static str),
    Failed(String),
}

/// Cashu mint/spend/refund surface for Routstr top up / refund product paths.
///
/// Stubs **must** report false capability flags and return
/// [`MintQuoteOutcome::Unsupported`] / [`CashuRefundOutcome::Unsupported`].
pub trait CashuBackend {
    fn capabilities(&self) -> CashuCapabilities {
        STUB_CASHU_CAPABILITIES
    }

    /// Request a mint invoice for approximately `amount_sats`.
    ///
    /// Must not return a fabricated `lnbc…` string when `mint_live` is false.
    fn request_mint_invoice(&self, amount_sats: Option<u64>) -> Result<MintQuoteOutcome>;

    /// Attempt to refund / melt held Cashu balance.
    fn refund(&self) -> Result<CashuRefundOutcome>;
}

/// Pre-CDK Cashu backend: honest unsupported outcomes only.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubCashu;

impl CashuBackend for StubCashu {
    fn capabilities(&self) -> CashuCapabilities {
        STUB_CASHU_CAPABILITIES
    }

    fn request_mint_invoice(&self, _amount_sats: Option<u64>) -> Result<MintQuoteOutcome> {
        Ok(MintQuoteOutcome::Unsupported(
            "CDK mint path not wired (stub CashuBackend)",
        ))
    }

    fn refund(&self) -> Result<CashuRefundOutcome> {
        Ok(CashuRefundOutcome::Unsupported(
            "CDK refund / melt path not wired (stub CashuBackend)",
        ))
    }
}

/// Product default Cashu backend for top up / refund CLI+TUI paths.
///
/// Returns an opaque [`CashuBackend`] so a future live CDK type can replace
/// the body without changing the public signature (keep `impl CashuBackend`,
/// or switch to a private owned enum if multiple concrete types are needed).
///
/// Today this is always [`StubCashu`] (`mint_live` / `spend_live` /
/// `refund_live` all false). The optional Cargo feature `cashu-cdk` is a
/// **reservation only** until real deps land (RESIDUAL.md P4); enabling it
/// does not change this factory. Product copy routes through
/// [`crate::funding_cli::topup_next_steps_for_backends`].
pub fn default_cashu_backend() -> impl CashuBackend {
    StubCashu
}

/// Bearer Cashu token (`cashuA…`). Never `Debug`-prints the full token.
pub struct CashuToken(SecretString);

impl CashuToken {
    /// Parse a Cashu token string. Requires `cashuA` prefix (v4/v3 common form).
    pub fn parse(token: &str) -> Result<Self> {
        let t = token.trim();
        if t.is_empty() {
            return Err(WalletError::Cashu("empty token".into()));
        }
        if !t.starts_with("cashuA") && !t.starts_with("cashuB") {
            return Err(WalletError::Cashu(
                "token must start with cashuA (or cashuB)".into(),
            ));
        }
        if t.len() < 16 {
            return Err(WalletError::Cashu("token too short".into()));
        }
        Ok(Self(SecretString::from(t.to_owned())))
    }

    /// Controlled expose for Authorization header construction.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Redacted preview (actual prefix + ellipsis + last 4).
    pub fn redacted(&self) -> String {
        let s = self.expose();
        let prefix = if s.starts_with("cashuB") {
            "cashuB"
        } else {
            "cashuA"
        };
        let tail = s
            .char_indices()
            .rev()
            .nth(3)
            .map(|(i, _)| &s[i..])
            .unwrap_or("");
        format!("{prefix}…{tail}")
    }
}

impl fmt::Debug for CashuToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CashuToken").field(&self.redacted()).finish()
    }
}

/// Funding wizard steps (deposit → channel → Cashu → inference).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FundingStep {
    NeedWallet,
    ShowAddress,
    WatchingTx,
    OpenChannel,
    AcquireCashu,
    ReadyForInference,
    RefundOptional,
}

impl FundingStep {
    /// Stable user-facing label (not Rust Debug).
    pub fn user_label(self) -> &'static str {
        match self {
            Self::NeedWallet => "need wallet",
            Self::ShowAddress => "showing receive address",
            Self::WatchingTx => "watching transaction",
            Self::OpenChannel => "open channel",
            Self::AcquireCashu => "acquire Cashu",
            Self::ReadyForInference => "ready for inference",
            Self::RefundOptional => "refund optional",
        }
    }

    /// Stable wire name for persistence (snake_case; not user copy).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::NeedWallet => "need_wallet",
            Self::ShowAddress => "show_address",
            Self::WatchingTx => "watching_tx",
            Self::OpenChannel => "open_channel",
            Self::AcquireCashu => "acquire_cashu",
            Self::ReadyForInference => "ready_for_inference",
            Self::RefundOptional => "refund_optional",
        }
    }

    /// Parse [`Self::as_wire_str`] (and a few aliases). Unknown → `None`.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "need_wallet" => Some(Self::NeedWallet),
            "show_address" => Some(Self::ShowAddress),
            "watching_tx" => Some(Self::WatchingTx),
            "open_channel" => Some(Self::OpenChannel),
            "acquire_cashu" => Some(Self::AcquireCashu),
            "ready_for_inference" => Some(Self::ReadyForInference),
            "refund_optional" => Some(Self::RefundOptional),
            _ => None,
        }
    }
}

/// Funding wizard state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingWizard {
    pub step: FundingStep,
    pub receive_address: Option<String>,
    pub watched_txid: Option<String>,
    pub confirmations: u32,
    pub required_confirmations: u32,
    /// BIP-39 show-once + full re-entry completed (required before ShowAddress).
    backup_confirmed: bool,
}

impl Default for FundingWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl FundingWizard {
    pub fn new() -> Self {
        Self {
            step: FundingStep::NeedWallet,
            receive_address: None,
            watched_txid: None,
            confirmations: 0,
            required_confirmations: 3,
            backup_confirmed: false,
        }
    }

    /// Whether backup show-once + re-entry has been marked complete.
    pub fn backup_confirmed(&self) -> bool {
        self.backup_confirmed
    }

    /// Test-only: mark backup complete without a [`crate::seed_vault::MnemonicBackupGate`].
    ///
    /// Product code must use [`Self::show_address_with_backup_gate`] so show-once
    /// + full re-entry cannot be skipped.
    #[cfg(test)]
    pub(crate) fn mark_backup_confirmed_for_test(&mut self) {
        self.backup_confirmed = true;
    }

    /// Resume at ShowAddress after the gated fund path already finished.
    ///
    /// **Invariant:** call only once `grok routstr fund` (or TUI equivalent)
    /// completed backup confirm + durable SeedVault store + address reveal.
    /// This constructor does **not** display BIP-39 and must never be used to
    /// skip the fund path for a new wallet.
    pub fn for_watch_after_fund(address: impl Into<String>, required_confirmations: u32) -> Self {
        Self {
            step: FundingStep::ShowAddress,
            receive_address: Some(address.into()),
            watched_txid: None,
            confirmations: 0,
            required_confirmations: required_confirmations.max(1),
            backup_confirmed: true,
        }
    }

    /// Resume funding-wizard watch progress after a process restart.
    ///
    /// **No BIP-39 / seed material.** Address + txid + confirmation counts only.
    /// Call only when the original fund path already confirmed backup (watch
    /// sessions never re-display recovery words).
    ///
    /// Invalid for `NeedWallet` (would skip backup gates).
    pub fn resume_watch(
        address: impl Into<String>,
        required_confirmations: u32,
        step: FundingStep,
        watched_txid: Option<String>,
        confirmations: u32,
    ) -> Result<Self> {
        if matches!(step, FundingStep::NeedWallet) {
            return Err(WalletError::Onchain(
                "cannot resume watch at need_wallet (backup gate not skippable)".into(),
            ));
        }
        Ok(Self {
            step,
            receive_address: Some(address.into()),
            watched_txid,
            confirmations,
            required_confirmations: required_confirmations.max(1),
            backup_confirmed: true,
        })
    }

    /// After BIP-39 backup confirmed and address derived.
    ///
    /// Requires a prior successful [`Self::show_address_with_backup_gate`] (or
    /// the test-only mark helper). Without backup confirmation returns
    /// [`WalletError::BackupNotConfirmed`].
    pub fn show_address(&mut self, address: impl Into<String>) -> Result<()> {
        if !self.backup_confirmed {
            return Err(WalletError::BackupNotConfirmed);
        }
        self.transition(FundingStep::NeedWallet, FundingStep::ShowAddress)?;
        self.receive_address = Some(address.into());
        Ok(())
    }

    /// Advance to ShowAddress only when `gate` has completed show-once + re-entry.
    ///
    /// Supported product path for funding UX wire-up.
    pub fn show_address_with_backup_gate(
        &mut self,
        address: impl Into<String>,
        gate: &crate::seed_vault::MnemonicBackupGate,
    ) -> Result<()> {
        if !gate.is_confirmed() {
            return Err(WalletError::BackupNotConfirmed);
        }
        self.backup_confirmed = true;
        self.show_address(address)
    }

    /// User broadcast / watcher saw a tx paying the address.
    pub fn watch_tx(&mut self, txid: impl Into<String>) -> Result<()> {
        self.transition(FundingStep::ShowAddress, FundingStep::WatchingTx)?;
        self.watched_txid = Some(txid.into());
        self.confirmations = 0;
        Ok(())
    }

    /// Update confirmation count; auto-advance when threshold met.
    pub fn set_confirmations(&mut self, n: u32) -> Result<()> {
        if self.step != FundingStep::WatchingTx {
            return Err(WalletError::InvalidTransition {
                from: self.step,
                to: FundingStep::WatchingTx,
            });
        }
        self.confirmations = n;
        if n >= self.required_confirmations {
            self.step = FundingStep::OpenChannel;
        }
        Ok(())
    }

    pub fn channel_opened(&mut self) -> Result<()> {
        self.transition(FundingStep::OpenChannel, FundingStep::AcquireCashu)
    }

    pub fn cashu_acquired(&mut self) -> Result<()> {
        self.transition(FundingStep::AcquireCashu, FundingStep::ReadyForInference)
    }

    pub fn begin_refund(&mut self) -> Result<()> {
        self.transition(FundingStep::ReadyForInference, FundingStep::RefundOptional)
    }

    /// Escape hatch: skip channel and go acquire Cashu externally funded.
    pub fn skip_channel_for_external_cashu(&mut self) -> Result<()> {
        match self.step {
            FundingStep::OpenChannel | FundingStep::WatchingTx | FundingStep::ShowAddress => {
                self.step = FundingStep::AcquireCashu;
                Ok(())
            }
            other => Err(WalletError::InvalidTransition {
                from: other,
                to: FundingStep::AcquireCashu,
            }),
        }
    }

    fn transition(&mut self, from: FundingStep, to: FundingStep) -> Result<()> {
        if self.step != from {
            return Err(WalletError::InvalidTransition {
                from: self.step,
                to,
            });
        }
        self.step = to;
        Ok(())
    }
}

/// HTTP-shaped helper: Routstr balance info body to msats.
///
/// Accepts explicit unit fields only: `msats`, `balance_msats`, `sats`,
/// `balance_sats`, and the same under nested `data`. Bare `balance` is ignored
/// (unit is ambiguous).
pub fn parse_balance_msats_from_json(body: &str) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    read_msats(&v)
}

fn read_msats(v: &serde_json::Value) -> Option<u64> {
    // Prefer explicit unit fields only (avoid guessing bare `balance` units).
    if let Some(n) = v.get("msats").and_then(as_u64) {
        return Some(n);
    }
    if let Some(n) = v.get("balance_msats").and_then(as_u64) {
        return Some(n);
    }
    if let Some(n) = v.get("sats").and_then(as_u64) {
        return Some(n.saturating_mul(1000));
    }
    if let Some(n) = v.get("balance_sats").and_then(as_u64) {
        return Some(n.saturating_mul(1000));
    }
    if let Some(data) = v.get("data") {
        return read_msats(data);
    }
    None
}

fn as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
        .or_else(|| {
            v.as_f64()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        })
        .or_else(|| v.as_str()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_cashu_never_claims_live_mint_or_refund() {
        let c = StubCashu;
        let caps = c.capabilities();
        assert!(!caps.mint_live);
        assert!(!caps.spend_live);
        assert!(!caps.refund_live);

        let mint = c.request_mint_invoice(Some(21_000)).unwrap();
        assert!(
            matches!(mint, MintQuoteOutcome::Unsupported(_)),
            "stub must not invent mint invoice: {mint:?}"
        );
        if let MintQuoteOutcome::Invoice { bolt11, .. } = mint {
            panic!("stub fabricated bolt11: {bolt11}");
        }

        let refnd = c.refund().unwrap();
        assert!(
            matches!(refnd, CashuRefundOutcome::Unsupported(_)),
            "stub must not claim refund completed: {refnd:?}"
        );
        assert!(!matches!(refnd, CashuRefundOutcome::Completed { .. }));
    }

    #[test]
    fn default_cashu_backend_is_stub_with_live_flags_false() {
        let c = default_cashu_backend();
        let caps = c.capabilities();
        assert!(!caps.mint_live);
        assert!(!caps.spend_live);
        assert!(!caps.refund_live);
        assert!(matches!(
            c.request_mint_invoice(Some(1)).unwrap(),
            MintQuoteOutcome::Unsupported(_)
        ));
        assert!(matches!(
            c.refund().unwrap(),
            CashuRefundOutcome::Unsupported(_)
        ));
    }

    #[test]
    fn parse_cashu_token() {
        let t = CashuToken::parse("cashuAabcdefghijklmnopqrstuvwxyz").unwrap();
        assert!(t.expose().starts_with("cashuA"));
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(dbg.contains("cashuA"));
    }

    #[test]
    fn reject_non_cashu() {
        assert!(CashuToken::parse("sk-not-a-token").is_err());
        assert!(CashuToken::parse("cashuAshort").is_err());
    }

    #[test]
    fn funding_step_user_labels_are_stable() {
        assert_eq!(
            FundingStep::ShowAddress.user_label(),
            "showing receive address"
        );
        assert_eq!(FundingStep::WatchingTx.user_label(), "watching transaction");
        // Must not look like Debug.
        assert!(
            !FundingStep::ShowAddress
                .user_label()
                .contains("ShowAddress")
        );
    }

    #[test]
    fn funding_wizard_happy_path() {
        let mut w = FundingWizard::new();
        assert_eq!(w.step, FundingStep::NeedWallet);
        w.mark_backup_confirmed_for_test();
        w.show_address("bc1q…").unwrap();
        w.watch_tx("txid").unwrap();
        w.set_confirmations(1).unwrap();
        assert_eq!(w.step, FundingStep::WatchingTx);
        w.set_confirmations(3).unwrap();
        assert_eq!(w.step, FundingStep::OpenChannel);
        w.channel_opened().unwrap();
        w.cashu_acquired().unwrap();
        assert_eq!(w.step, FundingStep::ReadyForInference);
        w.begin_refund().unwrap();
        assert_eq!(w.step, FundingStep::RefundOptional);
    }

    #[test]
    fn funding_wizard_invalid_skip() {
        let mut w = FundingWizard::new();
        assert!(w.watch_tx("x").is_err());
    }

    #[test]
    fn funding_wizard_show_address_requires_backup() {
        let mut w = FundingWizard::new();
        let err = w.show_address("bc1qtest").unwrap_err();
        assert!(matches!(err, WalletError::BackupNotConfirmed));
        assert_eq!(w.step, FundingStep::NeedWallet);
        assert!(w.receive_address.is_none());
    }

    #[test]
    fn funding_wizard_backup_gate_accept_and_reject() {
        use crate::mnemonic::generate_mnemonic;
        use crate::seed_vault::MnemonicBackupGate;

        let m = generate_mnemonic().unwrap();
        let mut gate = MnemonicBackupGate::new();
        let mut w = FundingWizard::new();

        // Unconfirmed gate rejected.
        assert!(matches!(
            w.show_address_with_backup_gate("bc1qtest", &gate)
                .unwrap_err(),
            WalletError::BackupNotConfirmed
        ));

        let _words = gate.show_once(&m).unwrap();
        // Shown but not re-entered yet.
        assert!(matches!(
            w.show_address_with_backup_gate("bc1qtest", &gate)
                .unwrap_err(),
            WalletError::BackupNotConfirmed
        ));

        // Wrong re-entry still blocked.
        assert!(gate.confirm_reentry("wrong words only").is_err());
        assert!(matches!(
            w.show_address_with_backup_gate("bc1qtest", &gate)
                .unwrap_err(),
            WalletError::BackupNotConfirmed
        ));

        gate.confirm_reentry(m.expose()).unwrap();
        w.show_address_with_backup_gate("bc1qaccepted", &gate)
            .unwrap();
        assert_eq!(w.step, FundingStep::ShowAddress);
        assert_eq!(w.receive_address.as_deref(), Some("bc1qaccepted"));
        assert!(w.backup_confirmed());
    }

    #[test]
    fn parse_balance_msats() {
        assert_eq!(
            parse_balance_msats_from_json(r#"{"msats": 1500000}"#),
            Some(1_500_000)
        );
        assert_eq!(
            parse_balance_msats_from_json(r#"{"data":{"sats":1000}}"#),
            Some(1_000_000)
        );
        // Bare `balance` is ambiguous; do not guess.
        assert_eq!(
            parse_balance_msats_from_json(r#"{"data":{"balance":1000}}"#),
            None
        );
        assert_eq!(parse_balance_msats_from_json("nope"), None);
    }
}
