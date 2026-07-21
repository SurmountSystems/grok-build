//! Lightning capability trait and stubs.
//!
//! Product LDK backend lives behind optional Cargo feature `ldk`
//! ([`crate::lightning_ldk`]). Live send uses an **out-of-process**
//! `grok-bitcoin-ldk-node` helper (isolated `ldk-node` / rusqlite 0.31) so
//! shell can keep rusqlite 0.37. This module defines the surface the funding
//! wizard and Routstr top-up call, with honest BOLT12 support flags and
//! seed-aware pay orchestration for auto-pay of Routstr node invoices when
//! `bolt11_pay_live` is true.
//!
//! Capability flags (`bolt11_pay_live`, `bolt11_invoice_live`, `bolt12_supported`,
//! `channel_open_live`, `connect_peer_live`) must stay accurate: stubs never
//! claim live pay; feature `ldk` sets `bolt11_pay_live` /
//! `bolt11_invoice_live` on [`crate::lightning_ldk::LdkLightning`] only.
//! **Channel open / connect peer stay residual** (`channel_open_live` /
//! `connect_peer_live` always false) even when BOLT11 pay/invoice are live.

use crate::BOLT12_SUPPORTED;
use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;

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

/// Result of attempting to create a BOLT11 receive invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvoiceOutcome {
    /// Live invoice string (only when `bolt11_invoice_live` is true).
    Created {
        bolt11: String,
    },
    /// Backend cannot create invoices in this build.
    Unsupported(&'static str),
    Failed(String),
}

/// Result of attempting to open a Lightning channel.
///
/// **Residual in this build:** backends must return
/// [`ChannelOpenOutcome::Unsupported`] or [`ChannelOpenOutcome::Failed`] —
/// never [`ChannelOpenOutcome::Success`] (no live channel-open contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelOpenOutcome {
    /// Live open with a real channel id — **never** returned until a live
    /// open contract lands (do not fabricate `channel_id`).
    Success {
        channel_id: String,
    },
    /// Known residual / not wired (honest; preferred for open/connect residual).
    Unsupported(&'static str),
    Failed(String),
}

/// Result of attempting to connect a Lightning peer.
///
/// **Residual in this build:** never [`ConnectPeerOutcome::Success`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectPeerOutcome {
    /// Live connect — **never** returned until a live connect contract lands.
    Success {
        peer_id: String,
    },
    /// Known residual / not wired.
    Unsupported(&'static str),
    Failed(String),
}

/// Honest residual copy for channel open (product + stub default).
pub const CHANNEL_OPEN_RESIDUAL: &str = "\
LDK open_channel residual (no live channel-open IPC contract; helper returns \
ok:false residual — never invents channel_id Success)";

/// Honest residual copy for peer connect (product + stub default).
pub const CONNECT_PEER_RESIDUAL: &str = "\
LDK connect_peer residual (no live peer-connect IPC contract; helper returns \
ok:false residual — never invents peer Success)";

/// Static capability snapshot for UI / CLI honesty copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LightningCapabilities {
    /// Can pay a BOLT11 invoice end-to-end (LDK path live).
    pub bolt11_pay_live: bool,
    /// Can create a BOLT11 receive invoice (LDK path live).
    pub bolt11_invoice_live: bool,
    /// BOLT12 offers supported (must match [`crate::BOLT12_SUPPORTED`]).
    pub bolt12_supported: bool,
    /// Live channel open via LDK helper — **always false** until a live contract.
    pub channel_open_live: bool,
    /// Live peer connect via LDK helper — **always false** until a live contract.
    pub connect_peer_live: bool,
}

/// Default pre-LDK capabilities: nothing live; BOLT12 never claimed.
pub const STUB_LIGHTNING_CAPABILITIES: LightningCapabilities = LightningCapabilities {
    bolt11_pay_live: false,
    bolt11_invoice_live: false,
    bolt12_supported: BOLT12_SUPPORTED,
    channel_open_live: false,
    connect_peer_live: false,
};

/// Lightning operations the wallet exposes to upper layers.
pub trait LightningCapability {
    /// Capability flags for this backend (must not over-claim).
    fn capabilities(&self) -> LightningCapabilities {
        STUB_LIGHTNING_CAPABILITIES
    }

    /// Pay a BOLT11 invoice (may be stubbed).
    ///
    /// Seed-holding backends that require BIP-39 should fail honestly here and
    /// implement [`Self::pay_bolt11_with_seed`] instead (SeedVault unlock path).
    fn pay_bolt11(&self, invoice: &Bolt11Invoice) -> Result<PayOutcome>;

    /// Pay a BOLT11 using unlocked BIP-39 material from SeedVault.
    ///
    /// **Never** route mnemonic/seed through CredentialsStore. Default falls
    /// back to [`Self::pay_bolt11`] (stubs ignore seed). Live LDK overrides and
    /// zeroizes intermediate seed bytes.
    fn pay_bolt11_with_seed(
        &self,
        invoice: &Bolt11Invoice,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<PayOutcome> {
        let _ = (mnemonic, passphrase);
        self.pay_bolt11(invoice)
    }

    /// Create a BOLT11 invoice for receiving `amount_sats` (may be stubbed).
    ///
    /// Stubs **must** return [`InvoiceOutcome::Unsupported`] and never a
    /// fabricated `lnbc…` string that looks pay-able.
    ///
    /// Seed-holding backends that require BIP-39 should fail honestly here and
    /// implement [`Self::create_bolt11_invoice_with_seed`] instead.
    fn create_bolt11_invoice(&self, _amount_sats: Option<u64>) -> Result<InvoiceOutcome> {
        Ok(InvoiceOutcome::Unsupported(
            "LDK BOLT11 invoice create not wired (stub LightningCapability)",
        ))
    }

    /// Create a BOLT11 receive invoice using unlocked BIP-39 material from SeedVault.
    ///
    /// **Never** route mnemonic/seed through CredentialsStore. Default falls
    /// back to [`Self::create_bolt11_invoice`] (stubs ignore seed). Live LDK
    /// overrides and zeroizes intermediate seed bytes.
    fn create_bolt11_invoice_with_seed(
        &self,
        amount_sats: Option<u64>,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<InvoiceOutcome> {
        let _ = (mnemonic, passphrase);
        self.create_bolt11_invoice(amount_sats)
    }

    /// Whether BOLT12 offers are supported in this build/runtime.
    fn bolt12_supported(&self) -> bool {
        self.capabilities().bolt12_supported
    }

    /// Pay a BOLT12 offer. Default rejects when unsupported.
    fn pay_bolt12_offer(&self, _offer: &str) -> Result<PayOutcome> {
        if !self.bolt12_supported() {
            return Err(WalletError::Bolt12Unsupported);
        }
        Ok(PayOutcome::Unsupported("BOLT12 pay not implemented"))
    }

    /// Open a channel to `peer_node_id` for `capacity_sats`.
    ///
    /// **Residual:** default and product LDK return
    /// [`ChannelOpenOutcome::Unsupported`] — never Success / fabricated channel_id.
    /// `channel_open_live` remains false even when BOLT11 pay/invoice are live.
    fn open_channel(&self, _peer_node_id: &str, _capacity_sats: u64) -> Result<ChannelOpenOutcome> {
        Ok(ChannelOpenOutcome::Unsupported(CHANNEL_OPEN_RESIDUAL))
    }

    /// Open a channel using unlocked BIP-39 (SeedVault path).
    ///
    /// Default ignores seed and returns residual Unsupported. Live path (when
    /// it exists) must zeroize intermediate seed buffers; never CredentialsStore.
    fn open_channel_with_seed(
        &self,
        peer_node_id: &str,
        capacity_sats: u64,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<ChannelOpenOutcome> {
        let _ = (mnemonic, passphrase);
        self.open_channel(peer_node_id, capacity_sats)
    }

    /// Connect a Lightning peer (`node_id@host:port` or similar).
    ///
    /// **Residual:** never [`ConnectPeerOutcome::Success`] in this build.
    fn connect_peer(&self, _peer_uri: &str) -> Result<ConnectPeerOutcome> {
        Ok(ConnectPeerOutcome::Unsupported(CONNECT_PEER_RESIDUAL))
    }

    /// Connect peer using unlocked BIP-39 (SeedVault path). Residual default.
    fn connect_peer_with_seed(
        &self,
        peer_uri: &str,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<ConnectPeerOutcome> {
        let _ = (mnemonic, passphrase);
        self.connect_peer(peer_uri)
    }
}

/// No-op Lightning backend for unit tests and pre-LDK builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubLightning;

impl LightningCapability for StubLightning {
    fn capabilities(&self) -> LightningCapabilities {
        STUB_LIGHTNING_CAPABILITIES
    }

    fn pay_bolt11(&self, invoice: &Bolt11Invoice) -> Result<PayOutcome> {
        if invoice.0.trim().is_empty() {
            return Ok(PayOutcome::Failed("empty invoice".into()));
        }
        // Never Success: stub must not claim a completed payment.
        Ok(PayOutcome::Unsupported(
            "LDK BOLT11 pay not wired (stub LightningCapability)",
        ))
    }

    fn create_bolt11_invoice(&self, _amount_sats: Option<u64>) -> Result<InvoiceOutcome> {
        Ok(InvoiceOutcome::Unsupported(
            "LDK BOLT11 invoice create not wired (stub LightningCapability)",
        ))
    }
}

/// Product default Lightning backend for top up / pay CLI+TUI paths.
///
/// - **Default features / CI:** [`StubLightning`] (`bolt11_pay_live` /
///   `bolt11_invoice_live` false; `bolt12_supported` matches
///   [`crate::BOLT12_SUPPORTED`]).
/// - **Feature `ldk`:** [`crate::lightning_ldk::LdkLightning`] product default
///   with **`bolt11_pay_live=true`** and **`bolt11_invoice_live=true`**
///   (out-of-process `ldk-node` helper; see `lightning_ldk` module docs).
///   Missing helper → honest Failed at pay/create time; P0 Routstr QR fallback
///   still applies for float funding. BOLT12 remains false.
///
/// Product copy routes through [`crate::funding_cli::topup_next_steps_for_backends`].
pub fn default_lightning_backend() -> impl LightningCapability {
    #[cfg(feature = "ldk")]
    {
        crate::lightning_ldk::LdkLightning::product_default()
    }
    #[cfg(not(feature = "ldk"))]
    {
        StubLightning
    }
}

// ---------------------------------------------------------------------------
// Auto-pay orchestration (pure; injectable LightningCapability)
// ---------------------------------------------------------------------------

/// Whether product flow should attempt local LDK pay of a Routstr node BOLT11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalBolt11PayPath {
    /// `bolt11_pay_live`: unlock SeedVault → pay → poll node status.
    AutoPayFromSeedVault,
    /// External wallet QR + poll (P0 invoice-first path).
    ExternalWalletQr,
}

/// Decide auto-pay vs external QR from capability flags only (no network).
pub fn decide_local_bolt11_pay_path(caps: LightningCapabilities) -> LocalBolt11PayPath {
    if caps.bolt11_pay_live {
        LocalBolt11PayPath::AutoPayFromSeedVault
    } else {
        LocalBolt11PayPath::ExternalWalletQr
    }
}

/// Result of applying a local pay attempt for a Routstr node invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalPayApplyResult {
    /// Local backend paid successfully (preimage known or placeholder).
    Paid { preimage_hex: String },
    /// Capability says not live — use external QR (no local attempt).
    SkippedExternal,
    /// Local attempt failed or unsupported; fall back to external QR + reason.
    FailedFallback { reason: String },
}

/// Apply local BOLT11 pay when `bolt11_pay_live`, else skip to external QR.
///
/// Uses [`LightningCapability::pay_bolt11_with_seed`] so seed material stays on
/// the SeedVault unlock path (never CredentialsStore). Injectable for tests.
pub fn apply_local_bolt11_pay(
    ln: &dyn LightningCapability,
    invoice: &Bolt11Invoice,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
) -> LocalPayApplyResult {
    if !ln.capabilities().bolt11_pay_live {
        return LocalPayApplyResult::SkippedExternal;
    }
    match ln.pay_bolt11_with_seed(invoice, mnemonic, passphrase) {
        Ok(PayOutcome::Success { preimage_hex }) => LocalPayApplyResult::Paid { preimage_hex },
        Ok(PayOutcome::Failed(reason)) => LocalPayApplyResult::FailedFallback { reason },
        Ok(PayOutcome::Unsupported(reason)) => LocalPayApplyResult::FailedFallback {
            // Live flag was true — do not claim "not wired" residual for stubs.
            reason: format!("local pay returned unsupported despite bolt11_pay_live: {reason}"),
        },
        Err(e) => LocalPayApplyResult::FailedFallback {
            reason: e.to_string(),
        },
    }
}

/// User-facing lines after a local pay attempt (honest; no fabricated success).
pub fn local_pay_result_lines(result: &LocalPayApplyResult) -> Vec<String> {
    match result {
        LocalPayApplyResult::Paid { .. } => vec![
            "Local Lightning pay submitted successfully.".to_owned(),
            "Polling Routstr invoice status for the API key…".to_owned(),
        ],
        LocalPayApplyResult::SkippedExternal => Vec::new(),
        LocalPayApplyResult::FailedFallback { reason } => {
            let mut lines = vec![
                "Local Lightning pay did not complete; falling back to external wallet.".to_owned(),
                format!("Detail: {reason}"),
            ];
            lines.extend(outbound_liquidity_honesty_lines());
            lines.push(
                "Pay the BOLT11 QR / string with any Lightning wallet, then wait for poll \
                 or `grok routstr topup --status <invoice_id>`."
                    .to_owned(),
            );
            lines
        }
    }
}

/// Honest liquidity copy: outbound liquidity needed; Routstr peer channel not required.
pub fn outbound_liquidity_honesty_lines() -> Vec<String> {
    vec![
        "Outbound channel liquidity is required for local BOLT11 pay (any peer/LSP route)."
            .to_owned(),
        "A channel specifically to Routstr is not required — only a route that can pay their invoice."
            .to_owned(),
    ]
}

/// Honest copy for local BOLT11 **receive** invoices (inbound path residual).
pub fn inbound_liquidity_honesty_lines() -> Vec<String> {
    vec![
        "Creating a local receive invoice does not prove inbound liquidity exists.".to_owned(),
        "Payers may fail to route until channels / an LSP provide inbound capacity.".to_owned(),
    ]
}

// ---------------------------------------------------------------------------
// Channel wizard (unchanged product seam)
// ---------------------------------------------------------------------------

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

    /// Resolve peer from Routstr `/v1/info` when a peer/LSP field is present.
    ///
    /// Returns `Ok(true)` when a peer was applied, `Ok(false)` when the node
    /// does not advertise a peer (current api.routstr.com shape) — **does not**
    /// invent connectivity or mark the channel active. Live open/connect is
    /// residual (no fake Success).
    pub fn try_resolve_peer_from_routstr_info(
        &mut self,
        info: &crate::routstr_invoice::RoutstrNodeInfo,
    ) -> Result<bool> {
        match info.channel_peer_hint() {
            Some(peer) => {
                self.resolve_peer(peer)?;
                Ok(true)
            }
            None => Ok(false),
        }
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

/// Result of seeding the channel wizard from Routstr node info (pure; offline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelWizardPeerSeed {
    /// Peer URI / id available for user confirmation (not connected yet).
    PeerAvailable { peer: String },
    /// Live node does not advertise LN peer/LSP fields.
    NoPeerAdvertised,
}

/// Pure peer seed from parsed `/v1/info` (never claims a channel was opened).
pub fn channel_wizard_peer_seed_from_info(
    info: &crate::routstr_invoice::RoutstrNodeInfo,
) -> ChannelWizardPeerSeed {
    match info.channel_peer_hint() {
        Some(peer) => ChannelWizardPeerSeed::PeerAvailable {
            peer: peer.to_owned(),
        },
        None => ChannelWizardPeerSeed::NoPeerAdvertised,
    }
}

/// Honest next-step lines for channel wizard residual (no invented Success).
pub fn channel_wizard_next_steps(seed: &ChannelWizardPeerSeed) -> Vec<String> {
    match seed {
        ChannelWizardPeerSeed::PeerAvailable { peer } => vec![
            format!("Routstr node advertises a peer/LSP hint: {peer}"),
            "Channel open / connect is residual in this build — do not claim \
             the peer is connected or the channel is active."
                .to_owned(),
            "Product API `open_channel` / `connect_peer` and helper IPC return \
             structured residual failure (ok:false residual:…); never channel_id Success."
                .to_owned(),
            "Outbound liquidity for local BOLT11 pay can use any peer/LSP route; \
             a channel specifically to Routstr is not required."
                .to_owned(),
            "When ready: confirm capacity in the channel wizard; funding broadcast \
             and active state require a live LDK/LSP path (not fabricated)."
                .to_owned(),
        ],
        ChannelWizardPeerSeed::NoPeerAdvertised => vec![
            "Routstr /v1/info does not advertise a Lightning peer or LSP \
             (mints-only shape is normal today)."
                .to_owned(),
            "No channel peer to resolve — channel wizard stays at need-funds / \
             residual; do not invent peer connectivity."
                .to_owned(),
            "Helper `open_channel` / `connect_peer` IPC still refuse with residual \
             (not unknown-cmd typo); product capabilities keep channel_open_live \
             and connect_peer_live false."
                .to_owned(),
            "Local BOLT11 pay still needs outbound liquidity on some route \
             (not specifically Routstr)."
                .to_owned(),
        ],
    }
}

/// Whether an outcome claims a live channel open (must stay false for residual).
pub fn channel_open_outcome_is_success(out: &ChannelOpenOutcome) -> bool {
    matches!(out, ChannelOpenOutcome::Success { .. })
}

/// Whether an outcome claims a live peer connect (must stay false for residual).
pub fn connect_peer_outcome_is_success(out: &ConnectPeerOutcome) -> bool {
    matches!(out, ConnectPeerOutcome::Success { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::generate_mnemonic;

    #[test]
    fn bolt12_flag_false() {
        let ln = StubLightning;
        assert!(!ln.bolt12_supported());
        assert!(!ln.capabilities().bolt12_supported);
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
    fn stub_never_claims_live_invoice_or_pay() {
        let ln = StubLightning;
        let caps = ln.capabilities();
        assert!(!caps.bolt11_pay_live);
        assert!(!caps.bolt11_invoice_live);
        assert!(!caps.bolt12_supported);
        assert!(!caps.channel_open_live);
        assert!(!caps.connect_peer_live);

        let inv = ln.create_bolt11_invoice(Some(21_000)).unwrap();
        assert!(
            matches!(inv, InvoiceOutcome::Unsupported(_)),
            "stub must not invent a BOLT11: {inv:?}"
        );
        if let InvoiceOutcome::Created { bolt11 } = inv {
            panic!("stub fabricated invoice: {bolt11}");
        }
        let pay = ln
            .pay_bolt11(&Bolt11Invoice("lnbc1reallooking".into()))
            .unwrap();
        assert!(
            !matches!(pay, PayOutcome::Success { .. }),
            "stub must not claim payment success: {pay:?}"
        );
    }

    #[test]
    fn stub_open_channel_and_connect_peer_are_residual_never_success() {
        let ln = StubLightning;
        let caps = ln.capabilities();
        assert!(
            !caps.channel_open_live && !caps.connect_peer_live,
            "stub must never claim live channel open/connect"
        );
        let open = ln.open_channel("02abc", 100_000).unwrap();
        assert!(!channel_open_outcome_is_success(&open));
        match &open {
            ChannelOpenOutcome::Unsupported(s) => {
                assert!(s.to_ascii_lowercase().contains("residual"));
                assert!(!s.to_ascii_lowercase().contains("channel active"));
            }
            ChannelOpenOutcome::Success { channel_id } => {
                panic!("stub fabricated channel_id: {channel_id}");
            }
            other => panic!("open_channel residual must be Unsupported: {other:?}"),
        }
        let connect = ln.connect_peer("02abc@host:9735").unwrap();
        assert!(
            matches!(connect, ConnectPeerOutcome::Unsupported(_)),
            "connect_peer residual must be Unsupported: {connect:?}"
        );
        assert!(!connect_peer_outcome_is_success(&connect));
        let m = generate_mnemonic().unwrap();
        let open_seed = ln.open_channel_with_seed("02abc", 50_000, &m, "").unwrap();
        assert!(!channel_open_outcome_is_success(&open_seed));
        let connect_seed = ln
            .connect_peer_with_seed("02abc@host:9735", &m, "")
            .unwrap();
        assert!(!connect_peer_outcome_is_success(&connect_seed));
    }

    #[test]
    fn default_lightning_backend_honest_live_flags() {
        let ln = default_lightning_backend();
        let caps = ln.capabilities();
        // Feature `ldk` → LdkLightning claims bolt11_pay_live (IPC → ldk-node).
        // Default CI (no feature) → stub keeps live false.
        #[cfg(feature = "ldk")]
        assert!(
            caps.bolt11_pay_live,
            "feature ldk default backend must claim live BOLT11 pay"
        );
        #[cfg(not(feature = "ldk"))]
        assert!(
            !caps.bolt11_pay_live,
            "stub default backend must not claim live BOLT11 pay"
        );
        #[cfg(feature = "ldk")]
        assert!(
            caps.bolt11_invoice_live,
            "feature ldk default backend must claim live BOLT11 invoice create"
        );
        #[cfg(not(feature = "ldk"))]
        assert!(!caps.bolt11_invoice_live);
        assert!(!caps.bolt12_supported);
        assert_eq!(caps.bolt12_supported, crate::BOLT12_SUPPORTED);
        // Channel open / connect remain residual even when feature `ldk` live-pay.
        assert!(
            !caps.channel_open_live,
            "channel_open_live must stay false (no live open contract)"
        );
        assert!(
            !caps.connect_peer_live,
            "connect_peer_live must stay false (no live connect contract)"
        );
        let pay = ln.pay_bolt11(&Bolt11Invoice("lnbc1…".into())).unwrap();
        assert!(
            !matches!(pay, PayOutcome::Success { .. }),
            "default backend bare pay_bolt11 must not invent success: {pay:?}"
        );
        let open = ln.open_channel("02peer", 21_000).unwrap();
        assert!(
            !channel_open_outcome_is_success(&open),
            "default backend open_channel must not invent Success: {open:?}"
        );
        let connect = ln.connect_peer("02peer@n:9735").unwrap();
        assert!(
            !connect_peer_outcome_is_success(&connect),
            "default backend connect_peer must not invent Success: {connect:?}"
        );
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

    #[test]
    fn channel_wizard_from_routstr_info_peer_optional() {
        use crate::routstr_invoice::parse_routstr_node_info;

        let no_peer = parse_routstr_node_info(
            r#"{"name":"n","mints":["https://mint.example/"],"version":"1"}"#,
        )
        .unwrap();
        assert_eq!(
            channel_wizard_peer_seed_from_info(&no_peer),
            ChannelWizardPeerSeed::NoPeerAdvertised
        );
        let lines = channel_wizard_next_steps(&ChannelWizardPeerSeed::NoPeerAdvertised);
        let joined = lines.join("\n");
        assert!(joined.contains("does not advertise") || joined.contains("mints-only"));
        assert!(!joined.to_ascii_lowercase().contains("channel active"));
        assert!(
            !joined
                .to_ascii_lowercase()
                .contains("connected successfully")
        );

        let mut w = ChannelWizard::new();
        assert!(!w.try_resolve_peer_from_routstr_info(&no_peer).unwrap());
        assert_eq!(w.step, ChannelWizardStep::NeedConfirmedFunds);

        let with_peer =
            parse_routstr_node_info(r#"{"mints":[],"peer_uri":"02abc@lsp.example:9735"}"#).unwrap();
        assert_eq!(
            channel_wizard_peer_seed_from_info(&with_peer),
            ChannelWizardPeerSeed::PeerAvailable {
                peer: "02abc@lsp.example:9735".into()
            }
        );
        let mut w2 = ChannelWizard::new();
        assert!(w2.try_resolve_peer_from_routstr_info(&with_peer).unwrap());
        assert_eq!(w2.step, ChannelWizardStep::PeerResolved);
        assert_eq!(w2.peer_id.as_deref(), Some("02abc@lsp.example:9735"));
        // Still not active — user must confirm + broadcast (residual live open).
        assert_ne!(w2.step, ChannelWizardStep::ChannelActive);
        let steps = channel_wizard_next_steps(&channel_wizard_peer_seed_from_info(&with_peer));
        let j = steps.join("\n");
        assert!(j.contains("02abc@lsp.example:9735"));
        assert!(j.contains("residual") || j.contains("do not claim"));
        assert!(
            j.contains("open_channel") || j.contains("connect_peer") || j.contains("ok:false"),
            "wizard next-steps should mention residual open/connect IPC honesty: {j}"
        );
        let jl = j.to_ascii_lowercase();
        // Must not claim a live open completed (residual copy may say "never … Success").
        assert!(!jl.contains("channel active"));
        assert!(!jl.contains("connected successfully"));
        assert!(
            jl.contains("residual") || jl.contains("never"),
            "must keep residual honesty: {j}"
        );
    }

    #[test]
    fn decide_local_pay_path_from_caps() {
        assert_eq!(
            decide_local_bolt11_pay_path(STUB_LIGHTNING_CAPABILITIES),
            LocalBolt11PayPath::ExternalWalletQr
        );
        assert_eq!(
            decide_local_bolt11_pay_path(LightningCapabilities {
                bolt11_pay_live: true,
                bolt11_invoice_live: false,
                bolt12_supported: false,
                channel_open_live: false,
                connect_peer_live: false,
            }),
            LocalBolt11PayPath::AutoPayFromSeedVault
        );
    }

    /// Mock backend: live pay flag + Success (product orchestration only).
    struct MockLivePayOk;
    impl LightningCapability for MockLivePayOk {
        fn capabilities(&self) -> LightningCapabilities {
            LightningCapabilities {
                bolt11_pay_live: true,
                bolt11_invoice_live: false,
                bolt12_supported: false,
                channel_open_live: false,
                connect_peer_live: false,
            }
        }
        fn pay_bolt11(&self, _invoice: &Bolt11Invoice) -> Result<PayOutcome> {
            Ok(PayOutcome::Failed("use with_seed".into()))
        }
        fn pay_bolt11_with_seed(
            &self,
            invoice: &Bolt11Invoice,
            _mnemonic: &MnemonicSecret,
            _passphrase: &str,
        ) -> Result<PayOutcome> {
            if invoice.0.trim().is_empty() {
                return Ok(PayOutcome::Failed("empty".into()));
            }
            Ok(PayOutcome::Success {
                preimage_hex: "ab".repeat(32),
            })
        }
    }

    /// Mock: live flag but pay fails (liquidity) — must not invent Success.
    struct MockLivePayFail;
    impl LightningCapability for MockLivePayFail {
        fn capabilities(&self) -> LightningCapabilities {
            LightningCapabilities {
                bolt11_pay_live: true,
                bolt11_invoice_live: false,
                bolt12_supported: false,
                channel_open_live: false,
                connect_peer_live: false,
            }
        }
        fn pay_bolt11(&self, _invoice: &Bolt11Invoice) -> Result<PayOutcome> {
            Ok(PayOutcome::Failed("n/a".into()))
        }
        fn pay_bolt11_with_seed(
            &self,
            _invoice: &Bolt11Invoice,
            _mnemonic: &MnemonicSecret,
            _passphrase: &str,
        ) -> Result<PayOutcome> {
            Ok(PayOutcome::Failed("no outbound liquidity".into()))
        }
    }

    /// Mock: live flag but returns Unsupported — orchestration rewrites reason.
    struct MockLivePayUnsupported;
    impl LightningCapability for MockLivePayUnsupported {
        fn capabilities(&self) -> LightningCapabilities {
            LightningCapabilities {
                bolt11_pay_live: true,
                bolt11_invoice_live: false,
                bolt12_supported: false,
                channel_open_live: false,
                connect_peer_live: false,
            }
        }
        fn pay_bolt11(&self, _invoice: &Bolt11Invoice) -> Result<PayOutcome> {
            Ok(PayOutcome::Unsupported("broken backend"))
        }
        fn pay_bolt11_with_seed(
            &self,
            invoice: &Bolt11Invoice,
            mnemonic: &MnemonicSecret,
            passphrase: &str,
        ) -> Result<PayOutcome> {
            let _ = (mnemonic, passphrase);
            self.pay_bolt11(invoice)
        }
    }

    #[test]
    fn apply_local_pay_skipped_when_not_live() {
        let m = generate_mnemonic().unwrap();
        let r = apply_local_bolt11_pay(&StubLightning, &Bolt11Invoice("lnbc1x".into()), &m, "");
        assert_eq!(r, LocalPayApplyResult::SkippedExternal);
        assert!(local_pay_result_lines(&r).is_empty());
    }

    #[test]
    fn apply_local_pay_success_with_mock() {
        let m = generate_mnemonic().unwrap();
        let r = apply_local_bolt11_pay(&MockLivePayOk, &Bolt11Invoice("lnbc1x".into()), &m, "");
        assert!(matches!(r, LocalPayApplyResult::Paid { .. }));
        let lines = local_pay_result_lines(&r).join("\n").to_ascii_lowercase();
        assert!(lines.contains("successfully"));
        assert!(!lines.contains("not wired"));
    }

    #[test]
    fn apply_local_pay_failure_falls_back_honestly() {
        let m = generate_mnemonic().unwrap();
        let r = apply_local_bolt11_pay(&MockLivePayFail, &Bolt11Invoice("lnbc1x".into()), &m, "");
        match &r {
            LocalPayApplyResult::FailedFallback { reason } => {
                assert!(reason.contains("outbound liquidity"));
            }
            other => panic!("expected FailedFallback, got {other:?}"),
        }
        let lines = local_pay_result_lines(&r).join("\n").to_ascii_lowercase();
        assert!(lines.contains("falling back") || lines.contains("external"));
        assert!(lines.contains("outbound"));
        assert!(
            !lines.contains("not wired yet"),
            "live-flag failure must not use residual stub copy: {lines}"
        );
        // Must not claim success.
        assert!(!lines.contains("pay submitted successfully"));
    }

    #[test]
    fn apply_local_pay_unsupported_despite_live_is_honest() {
        let m = generate_mnemonic().unwrap();
        let r = apply_local_bolt11_pay(
            &MockLivePayUnsupported,
            &Bolt11Invoice("lnbc1x".into()),
            &m,
            "",
        );
        match &r {
            LocalPayApplyResult::FailedFallback { reason } => {
                assert!(reason.contains("despite bolt11_pay_live"), "{reason}");
            }
            other => panic!("expected FailedFallback, got {other:?}"),
        }
    }

    #[test]
    fn liquidity_honesty_no_routstr_channel_requirement() {
        let joined = outbound_liquidity_honesty_lines()
            .join("\n")
            .to_ascii_lowercase();
        assert!(joined.contains("outbound"));
        assert!(
            joined.contains("not required") || joined.contains("specifically to routstr"),
            "{joined}"
        );
        assert!(!joined.contains("crypto"));
        assert!(!joined.contains("web3"));
    }

    #[test]
    fn stub_pay_with_seed_does_not_claim_success() {
        let m = generate_mnemonic().unwrap();
        let out = StubLightning
            .pay_bolt11_with_seed(&Bolt11Invoice("lnbc1x".into()), &m, "pass")
            .unwrap();
        assert!(matches!(out, PayOutcome::Unsupported(_)));
    }
}
