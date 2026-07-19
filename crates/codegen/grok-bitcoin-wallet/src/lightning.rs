//! Lightning capability trait and stubs.
//!
//! Full LDK / `ldk-node` integration is residual. This module defines the
//! surface the funding wizard and Routstr top up will call, with honest
//! BOLT12 support flags.

use crate::BOLT12_SUPPORTED;
use crate::error::{Result, WalletError};

/// BOLT11 pay request (invoice string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bolt11Invoice(pub String);

/// Result of a pay attempt (stub).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayOutcome {
    /// Stub success with preimage hex (tests).
    Success {
        preimage_hex: String,
    },
    /// Not implemented / deferred.
    Unsupported(&'static str),
    Failed(String),
}

/// Lightning operations the wallet exposes to upper layers.
pub trait LightningCapability {
    /// Pay a BOLT11 invoice (may be stubbed).
    fn pay_bolt11(&self, invoice: &Bolt11Invoice) -> Result<PayOutcome>;

    /// Whether BOLT12 offers are supported in this build/runtime.
    fn bolt12_supported(&self) -> bool {
        BOLT12_SUPPORTED
    }

    /// Pay a BOLT12 offer. Default rejects when unsupported.
    fn pay_bolt12_offer(&self, _offer: &str) -> Result<PayOutcome> {
        if !self.bolt12_supported() {
            return Err(WalletError::Bolt12Unsupported);
        }
        Ok(PayOutcome::Unsupported("BOLT12 pay not implemented"))
    }
}

/// No-op Lightning backend for unit tests and pre-LDK builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubLightning;

impl LightningCapability for StubLightning {
    fn pay_bolt11(&self, invoice: &Bolt11Invoice) -> Result<PayOutcome> {
        if invoice.0.trim().is_empty() {
            return Ok(PayOutcome::Failed("empty invoice".into()));
        }
        Ok(PayOutcome::Unsupported(
            "LDK BOLT11 pay not wired (stub LightningCapability)",
        ))
    }
}

/// Channel-open wizard steps toward a Routstr-recommended peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelWizardStep {
    /// Need on-chain funds confirmed.
    NeedConfirmedFunds,
    /// Peer URI / node id resolved from Routstr.
    PeerResolved,
    /// User confirmed capacity + fees.
    UserConfirmed,
    /// Funding transaction broadcast.
    FundingBroadcast,
    /// Channel active / ready for LN payments.
    ChannelActive,
    /// Failed; funds remain on-chain.
    Failed,
}

/// Minimal state machine for channel-to-Routstr-peer flow (no live LN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelWizard {
    pub step: ChannelWizardStep,
    pub peer_id: Option<String>,
    pub capacity_sats: Option<u64>,
    pub funding_txid: Option<String>,
    pub last_error: Option<String>,
}

impl Default for ChannelWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelWizard {
    pub fn new() -> Self {
        Self {
            step: ChannelWizardStep::NeedConfirmedFunds,
            peer_id: None,
            capacity_sats: None,
            funding_txid: None,
            last_error: None,
        }
    }

    pub fn resolve_peer(&mut self, peer_id: impl Into<String>) -> Result<()> {
        self.ensure(ChannelWizardStep::NeedConfirmedFunds)?;
        self.peer_id = Some(peer_id.into());
        self.step = ChannelWizardStep::PeerResolved;
        Ok(())
    }

    pub fn confirm(&mut self, capacity_sats: u64) -> Result<()> {
        self.ensure(ChannelWizardStep::PeerResolved)?;
        if capacity_sats == 0 {
            return Err(WalletError::Onchain("capacity must be > 0".into()));
        }
        self.capacity_sats = Some(capacity_sats);
        self.step = ChannelWizardStep::UserConfirmed;
        Ok(())
    }

    pub fn mark_funding_broadcast(&mut self, txid: impl Into<String>) -> Result<()> {
        self.ensure(ChannelWizardStep::UserConfirmed)?;
        self.funding_txid = Some(txid.into());
        self.step = ChannelWizardStep::FundingBroadcast;
        Ok(())
    }

    pub fn mark_active(&mut self) -> Result<()> {
        self.ensure(ChannelWizardStep::FundingBroadcast)?;
        self.step = ChannelWizardStep::ChannelActive;
        Ok(())
    }

    pub fn fail(&mut self, err: impl Into<String>) {
        self.last_error = Some(err.into());
        self.step = ChannelWizardStep::Failed;
    }

    fn ensure(&self, expected: ChannelWizardStep) -> Result<()> {
        if self.step != expected {
            return Err(WalletError::ChannelWizard(format!(
                "expected {expected:?}, at {:?}",
                self.step
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolt12_flag_false() {
        let ln = StubLightning;
        assert!(!ln.bolt12_supported());
        assert!(matches!(
            ln.pay_bolt12_offer("lno1…"),
            Err(WalletError::Bolt12Unsupported)
        ));
    }

    #[test]
    fn stub_bolt11_unsupported() {
        let ln = StubLightning;
        let out = ln.pay_bolt11(&Bolt11Invoice("lnbc1…".into())).unwrap();
        assert!(matches!(out, PayOutcome::Unsupported(_)));
    }

    #[test]
    fn channel_wizard_happy_path() {
        let mut w = ChannelWizard::new();
        w.resolve_peer("02abc").unwrap();
        w.confirm(100_000).unwrap();
        w.mark_funding_broadcast("txid").unwrap();
        w.mark_active().unwrap();
        assert_eq!(w.step, ChannelWizardStep::ChannelActive);
    }

    #[test]
    fn channel_wizard_rejects_skip() {
        let mut w = ChannelWizard::new();
        assert!(w.confirm(1).is_err());
    }
}
