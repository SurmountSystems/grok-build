//! CLI funding path: backup gate + unlock session before ShowAddress.
//!
//! Product surface for `grok routstr fund` (and any TUI that reuses the same
//! steps). IO is injected so unit tests stay offline and non-interactive.
//!
//! Invariants:
//! - BIP-39 never goes to CredentialsStore / `provider_credentials.json`
//! - ShowAddress only via [`FundingWizard::show_address_with_backup_gate`]
//! - Unlock session holds material only after successful vault load / generate
//! - Product should durable-store **after** backup confirm and **before**
//!   printing the receive address (see shell `run_routstr_fund`)

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::cashu::FundingWizard;
use crate::error::{Result, WalletError};
use crate::mnemonic::{MnemonicSecret, generate_mnemonic, import_mnemonic};
use crate::seed_vault::{MnemonicBackupGate, UnlockSession};

/// Successful backup confirm + gated ShowAddress (address may or may not be printed).
#[derive(Debug)]
pub struct FundingAddressReveal {
    pub address: String,
    pub wizard: FundingWizard,
}

/// Inputs for the pure funding reveal (no vault IO).
pub struct FundingRevealInput<'a> {
    /// Mnemonic already loaded or freshly generated (not stored by this helper).
    pub mnemonic: &'a MnemonicSecret,
    /// BIP84 (or other) receive address string already derived under unlock.
    pub address: String,
    /// Idle TTL for the unlock session created around backup + reveal.
    pub unlock_ttl: Duration,
    /// When true, print "Backup confirmed. Receive address:" lines after gate.
    /// Product fund path sets this false so store can complete before print.
    pub print_address: bool,
}

/// Drive show-once backup + full re-entry, then gate ShowAddress.
///
/// `write_line` receives user-facing lines (no trailing newline required).
/// `read_line` returns one line of stdin (re-entry phrase). Empty line after
/// prompt is treated as cancel → [`WalletError::BackupNotConfirmed`].
///
/// Does **not** durable-store the seed. Callers must store after success and
/// only then tell the user it is safe to fund the address (`print_address`
/// false + explicit print after store is the recommended product order).
pub fn run_backup_gate_to_show_address<W, R>(
    input: FundingRevealInput<'_>,
    mut write_line: W,
    mut read_line: R,
) -> Result<FundingAddressReveal>
where
    W: FnMut(&str) -> Result<()>,
    R: FnMut(&str) -> Result<String>,
{
    let now = Instant::now();
    let mut session =
        UnlockSession::unlock(import_mnemonic(input.mnemonic.expose())?, input.unlock_ttl);
    // Touch via mnemonic borrow so idle clock starts from active use.
    let _ = session.mnemonic(now)?;

    let mut gate = MnemonicBackupGate::new();
    let words = gate.show_once(input.mnemonic)?;

    write_line("Write down your Bitcoin recovery phrase. It is shown only once.")?;
    write_line("Anyone with these words can spend your funds. Store them offline.")?;
    write_line("")?;
    for (i, word) in &words {
        write_line(&format!("{i:>2}. {word}"))?;
    }
    write_line("")?;
    write_line("When you have saved the words, re-enter the full recovery phrase below.")?;

    let reentry = read_line("Recovery phrase: ")?;
    if reentry.trim().is_empty() {
        session.lock();
        return Err(WalletError::BackupNotConfirmed);
    }
    gate.confirm_reentry(&reentry).inspect_err(|_| {
        session.lock();
    })?;

    // Confirm session still live before advancing wizard.
    let now = Instant::now();
    let _ = session.mnemonic(now)?;

    let mut wizard = FundingWizard::new();
    wizard.show_address_with_backup_gate(input.address.clone(), &gate)?;

    if input.print_address {
        write_line("")?;
        write_line("Backup confirmed. Receive address:")?;
        write_line(&input.address)?;
        write_line(
            "Send only Bitcoin to this address. Open the explorer link from the fund UI when watching confirmations.",
        )?;
    } else {
        write_line("")?;
        write_line("Backup confirmed. Saving the wallet before showing the receive address…")?;
    }

    // Lock session after reveal: address is derived; keep seed out of idle RAM.
    session.lock();

    Ok(FundingAddressReveal {
        address: input.address,
        wizard,
    })
}

/// Stdin/stderr interactive wrapper around [`run_backup_gate_to_show_address`].
///
/// `print_address`: when false, only confirms backup (product stores then prints).
pub fn run_backup_gate_to_show_address_stdio(
    mnemonic: &MnemonicSecret,
    address: String,
    print_address: bool,
) -> Result<FundingAddressReveal> {
    fn eprint_line(line: &str) -> Result<()> {
        let mut stderr = io::stderr();
        writeln!(stderr, "{line}").map_err(|e| WalletError::SeedVault(e.to_string()))?;
        stderr
            .flush()
            .map_err(|e| WalletError::SeedVault(e.to_string()))?;
        Ok(())
    }
    fn prompt_line(prompt: &str) -> Result<String> {
        let mut stderr = io::stderr();
        write!(stderr, "{prompt}").map_err(|e| WalletError::SeedVault(e.to_string()))?;
        stderr
            .flush()
            .map_err(|e| WalletError::SeedVault(e.to_string()))?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| WalletError::SeedVault(e.to_string()))?;
        Ok(line)
    }

    run_backup_gate_to_show_address(
        FundingRevealInput {
            mnemonic,
            address,
            unlock_ttl: crate::seed_vault::DEFAULT_UNLOCK_TTL,
            print_address,
        },
        eprint_line,
        prompt_line,
    )
}

/// Generate a new mnemonic for first-time funding (caller stores via SeedVault).
pub fn generate_new_wallet_mnemonic() -> Result<MnemonicSecret> {
    generate_mnemonic()
}

/// Import words the user typed (caller stores via SeedVault).
pub fn import_wallet_mnemonic(phrase: &str) -> Result<MnemonicSecret> {
    import_mnemonic(phrase)
}

// ── Shared product gates (CLI + TUI) ─────────────────────────────────────────

/// Classification of a failed [`crate::seed_vault::SeedVault::load`] for fund paths.
///
/// Product code must only mint a **new** wallet on [`VaultLoadClass::NotFound`].
/// Keyring / password / other failures never authorize minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultLoadClass {
    /// Definitive absence of seed material. Only this class may mint a new wallet.
    NotFound,
    /// AEAD seed file present (or keyring miss + file) but no password supplied.
    PasswordRequired,
    /// Hard keyring / backend failure. Must not mint; surface and retry unlock.
    DoNotMint { reason: String },
    /// Any other load error. Must not mint.
    Error { message: String },
}

/// Classify a vault load error without collapsing keyring failures into absence.
pub fn classify_vault_load_err(err: &WalletError) -> VaultLoadClass {
    match err {
        WalletError::NotFound => VaultLoadClass::NotFound,
        WalletError::PasswordRequired => VaultLoadClass::PasswordRequired,
        WalletError::Keyring(e) => VaultLoadClass::DoNotMint { reason: e.clone() },
        other => VaultLoadClass::Error {
            message: other.to_string(),
        },
    }
}

/// Whether product may generate and show a new recovery phrase.
pub fn may_mint_new_wallet(class: &VaultLoadClass) -> bool {
    matches!(class, VaultLoadClass::NotFound)
}

/// User-facing lines when keyring is blocked (CLI stderr / TUI system block).
pub fn keyring_blocked_message(reason: &str) -> String {
    format!(
        "could not read seed vault ({reason}); not creating a new wallet. \
         Fix keyring access or unlock the AEAD seed file, then retry."
    )
}

/// User-facing lines when password is required for AEAD unlock.
pub fn password_required_message() -> &'static str {
    "password required to unlock existing seed file"
}

/// Product invariant: durable store must complete **before** the receive
/// address is printed (new-wallet path). Tests and TUI assert this order.
pub const STORE_BEFORE_ADDRESS_PRINT: bool = true;

/// After backup gate is confirmed, advance wizard to ShowAddress (no vault IO).
///
/// Shared by CLI and TUI after re-entry or show-once flow.
pub fn reveal_address_after_backup(
    gate: &MnemonicBackupGate,
    address: String,
) -> Result<FundingAddressReveal> {
    let mut wizard = FundingWizard::new();
    wizard.show_address_with_backup_gate(address.clone(), gate)?;
    Ok(FundingAddressReveal { address, wizard })
}

/// Returning-user path: re-entry without re-displaying words, then gated reveal.
///
/// Does **not** durable-store (seed already stored). Caller may print address.
pub fn returning_user_reveal_after_reentry(
    mnemonic: &MnemonicSecret,
    reentry_phrase: &str,
    address: String,
) -> Result<FundingAddressReveal> {
    let mut gate = MnemonicBackupGate::new();
    gate.begin_reentry_without_display(mnemonic)?;
    if reentry_phrase.trim().is_empty() {
        return Err(WalletError::BackupNotConfirmed);
    }
    gate.confirm_reentry(reentry_phrase)?;
    reveal_address_after_backup(&gate, address)
}

/// New-wallet path: show-once + re-entry via injected IO, then gated reveal.
///
/// `print_address` should be **false** for product paths that store before print.
pub fn new_wallet_backup_and_reveal<W, R>(
    mnemonic: &MnemonicSecret,
    address: String,
    print_address: bool,
    write_line: W,
    read_line: R,
) -> Result<FundingAddressReveal>
where
    W: FnMut(&str) -> Result<()>,
    R: FnMut(&str) -> Result<String>,
{
    run_backup_gate_to_show_address(
        FundingRevealInput {
            mnemonic,
            address,
            unlock_ttl: crate::seed_vault::DEFAULT_UNLOCK_TTL,
            print_address,
        },
        write_line,
        read_line,
    )
}

/// Outcome of a pure fund-path decision after vault probe (no secrets).
///
/// TUI and CLI map this to prompts / system messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundPathDecision {
    /// No seed: generate new mnemonic, backup gate, store, then show address.
    NewWallet,
    /// Seed present: re-entry without display, then show address.
    ReturningUnlock,
    /// Need password for AEAD; do not mint.
    NeedPassword,
    /// Keyring blocked; do not mint.
    KeyringBlocked { reason: String },
    /// Other error; do not mint.
    LoadError { message: String },
}

/// Map vault load result into a product decision (secrets stay with caller).
pub fn fund_path_decision_from_load<T>(
    load: std::result::Result<T, WalletError>,
) -> FundPathDecision {
    match load {
        Ok(_) => FundPathDecision::ReturningUnlock,
        Err(e) => match classify_vault_load_err(&e) {
            VaultLoadClass::NotFound => FundPathDecision::NewWallet,
            VaultLoadClass::PasswordRequired => FundPathDecision::NeedPassword,
            VaultLoadClass::DoNotMint { reason } => FundPathDecision::KeyringBlocked { reason },
            VaultLoadClass::Error { message } => FundPathDecision::LoadError { message },
        },
    }
}

/// Short success lines after fund (CLI print / TUI system block). No mnemonic.
///
/// `saved` is true only after a durable store in this run (new wallet). Returning-user
/// unlock already has a vault entry, so use `saved: false` ("Backup confirmed. Receive…").
pub fn format_fund_success_lines(
    address: &str,
    step_label: &str,
    network_label: &str,
    saved: bool,
) -> Vec<String> {
    let head = if saved {
        format!("Backup confirmed. Wallet saved. Receive address ({network_label}):")
    } else {
        format!("Backup confirmed. Receive address ({network_label}):")
    };
    vec![
        head,
        address.to_owned(),
        format!("Funding status: {step_label}"),
        "Send only Bitcoin to this address. After you broadcast a deposit, confirmation \
         watching uses the rate-limited mempool.space client."
            .to_owned(),
        "BOLT12 offers are not supported in this build.".to_owned(),
    ]
}

/// Next-steps copy for top up while CDK/LN pay is residual (honest stubs).
///
/// Routes through [`crate::cashu::default_cashu_backend`] +
/// [`crate::lightning::default_lightning_backend`] so a future live CDK/LDK
/// impl plugs in at the factory without forking CLI/TUI copy.
pub fn topup_next_steps_lines(sats: Option<u64>) -> Vec<String> {
    topup_next_steps_for_backends(
        &crate::cashu::default_cashu_backend(),
        &crate::lightning::default_lightning_backend(),
        sats,
    )
}

/// Capability-aware top-up lines. Live mint invoice only when Cashu reports
/// `mint_live` **and** returns [`crate::cashu::MintQuoteOutcome::Invoice`].
///
/// Never fabricates a BOLT11 from a stub outcome.
pub fn topup_next_steps_for_backends(
    cashu: &dyn crate::cashu::CashuBackend,
    ln: &dyn crate::lightning::LightningCapability,
    sats: Option<u64>,
) -> Vec<String> {
    let cashu_caps = cashu.capabilities();
    let ln_caps = ln.capabilities();

    // Prefer a real Cashu mint quote when the backend is live.
    if cashu_caps.mint_live {
        match cashu.request_mint_invoice(sats) {
            Ok(crate::cashu::MintQuoteOutcome::Invoice { bolt11, quote_id }) => {
                let mut lines = vec![
                    "Routstr top up: Cashu mint invoice ready.".to_owned(),
                    format!("Quote id: {quote_id}"),
                    format!("BOLT11: {bolt11}"),
                    "Pay the invoice, then `grok routstr balance` to verify float.".to_owned(),
                ];
                if let Some(s) = sats {
                    lines.insert(1, format!("Requested amount: {s} sats."));
                }
                return lines;
            }
            Ok(crate::cashu::MintQuoteOutcome::Unsupported(reason)) => {
                return vec![
                    "Routstr top up: mint backend reported live but returned unsupported."
                        .to_owned(),
                    format!("Detail: {reason}"),
                    "No invoice was created.".to_owned(),
                ];
            }
            Ok(crate::cashu::MintQuoteOutcome::Failed(e)) => {
                return vec![
                    "Routstr top up: mint quote failed.".to_owned(),
                    format!("Detail: {e}"),
                    "No invoice was created.".to_owned(),
                ];
            }
            Err(e) => {
                return vec![
                    "Routstr top up: mint quote error.".to_owned(),
                    format!("Detail: {e}"),
                    "No invoice was created.".to_owned(),
                ];
            }
        }
    }

    // Optional LDK receive invoice when LN invoice path is live (no Cashu mint).
    // When the flag is true, failures must not fall through to "not wired yet".
    if ln_caps.bolt11_invoice_live {
        match ln.create_bolt11_invoice(sats) {
            Ok(crate::lightning::InvoiceOutcome::Created { bolt11 }) => {
                let mut lines = vec![
                    "Routstr top up: Lightning invoice ready (local node).".to_owned(),
                    format!("BOLT11: {bolt11}"),
                    "This is a local receive invoice; Routstr node float may still need a separate path."
                        .to_owned(),
                ];
                if let Some(s) = sats {
                    lines.insert(1, format!("Requested amount: {s} sats."));
                }
                return lines;
            }
            Ok(crate::lightning::InvoiceOutcome::Unsupported(reason)) => {
                return vec![
                    "Routstr top up: Lightning invoice backend reported live but returned unsupported."
                        .to_owned(),
                    format!("Detail: {reason}"),
                    "No invoice was created.".to_owned(),
                ];
            }
            Ok(crate::lightning::InvoiceOutcome::Failed(e)) => {
                return vec![
                    "Routstr top up: Lightning invoice create failed.".to_owned(),
                    format!("Detail: {e}"),
                    "No invoice was created.".to_owned(),
                ];
            }
            Err(e) => {
                return vec![
                    "Routstr top up: Lightning invoice create error.".to_owned(),
                    format!("Detail: {e}"),
                    "No invoice was created.".to_owned(),
                ];
            }
        }
    }

    // Residual honest stub copy only when neither Cashu mint nor LN invoice is live.
    let mut lines =
        vec!["Routstr top up (Lightning / Cashu pay path is not wired yet).".to_owned()];
    if let Some(s) = sats {
        lines.push(format!("Requested amount: {s} sats."));
    }
    lines.push("Next steps:".to_owned());
    lines.push(
        "  1. `grok login --routstr` with a sk- or cashuA… bearer if you have one.".to_owned(),
    );
    lines.push(
        "  2. `grok routstr fund` (or /routstr fund in the TUI) to create a local wallet \
         and show a receive address."
            .to_owned(),
    );
    lines.push(
        "  3. Pay a Routstr BOLT11 invoice from docs.routstr.com when you need node float."
            .to_owned(),
    );
    lines.push(
        "  4. `grok routstr balance` (or /routstr balance) to verify prepaid float after funding."
            .to_owned(),
    );
    lines.push("This command does not spend Bitcoin or create a live mint invoice yet.".to_owned());
    lines
}

/// Next-steps copy for refund while CDK return is residual.
pub fn refund_next_steps_lines() -> Vec<String> {
    refund_next_steps_for_backend(&crate::cashu::default_cashu_backend())
}

/// Capability-aware refund lines. Live completion only when Cashu reports
/// `refund_live` **and** returns [`crate::cashu::CashuRefundOutcome::Completed`].
pub fn refund_next_steps_for_backend(cashu: &dyn crate::cashu::CashuBackend) -> Vec<String> {
    let caps = cashu.capabilities();
    if caps.refund_live {
        match cashu.refund() {
            Ok(crate::cashu::CashuRefundOutcome::Completed { detail }) => {
                return vec![
                    "Routstr refund completed.".to_owned(),
                    format!("Detail: {detail}"),
                ];
            }
            Ok(crate::cashu::CashuRefundOutcome::Unsupported(reason)) => {
                return vec![
                    "Routstr refund: backend reported live but returned unsupported.".to_owned(),
                    format!("Detail: {reason}"),
                    "No refund was completed.".to_owned(),
                ];
            }
            Ok(crate::cashu::CashuRefundOutcome::Failed(e)) => {
                return vec![
                    "Routstr refund failed.".to_owned(),
                    format!("Detail: {e}"),
                    "No refund was completed.".to_owned(),
                ];
            }
            Err(e) => {
                return vec![
                    "Routstr refund error.".to_owned(),
                    format!("Detail: {e}"),
                    "No refund was completed.".to_owned(),
                ];
            }
        }
    }

    vec![
        "Routstr refund (Cashu return path is not wired yet).".to_owned(),
        "Next steps:".to_owned(),
        "  1. Prefer spending down hot float rather than leaving large balances on the node."
            .to_owned(),
        "  2. Use Routstr account tools / docs.routstr.com for manual Cashu export if available."
            .to_owned(),
        "  3. `grok routstr balance` (or /routstr balance) to check remaining float.".to_owned(),
        "Automated refund via CDK is not available in this build.".to_owned(),
    ]
}

/// System-block lines for a receive address: text + optional QR matrix + copy hint.
///
/// Used by TUI fund success / `/routstr qr`. Does **not** invent BOLT11.
/// `include_qr` is ignored when the `qr` feature is off (address-only lines).
///
/// Does **not** claim the clipboard was updated — callers (CLI vs TUI) own
/// copy UX; the shared text only hints the user can copy the address/BIP21.
pub fn receive_address_display_lines(address: &str, include_qr: bool) -> Vec<String> {
    let display =
        crate::address_ux::onchain_payment_display(address, None, Some("Grok OSS Routstr"));
    let mut lines = vec![
        "Receive address (Bitcoin):".to_owned(),
        display.text.clone(),
        format!("BIP21: {}", display.qr_payload),
        "QR encodes the BIP21 URI. Copy the address or BIP21 URI from the lines above \
         (the TUI also attempts a clipboard copy with a toast)."
            .to_owned(),
    ];
    if include_qr {
        #[cfg(feature = "qr")]
        {
            match crate::address_ux::qr_matrix_lines(&display.qr_payload) {
                Ok(matrix) => {
                    lines.push(String::new());
                    lines.push("QR (scan with a Bitcoin wallet):".to_owned());
                    lines.extend(matrix);
                }
                Err(e) => {
                    lines.push(format!("QR unavailable: {e}"));
                }
            }
        }
        #[cfg(not(feature = "qr"))]
        {
            lines.push(
                "QR feature not enabled in this build; copy the address or BIP21 URI.".to_owned(),
            );
        }
    }
    lines
}

/// Clipboard payload for an on-chain receive address (address only, no amount).
pub fn receive_address_clipboard(address: &str) -> String {
    crate::address_ux::onchain_payment_display(address, None, None).clipboard
}

// ── On-chain PSBT spend (CLI / TUI pure helpers) ─────────────────────────────

/// Default fee rate (sat/vB) for product spend when the user does not override.
pub const DEFAULT_SPEND_FEE_RATE_SAT_VB: u64 = 5;

/// Parsed spend request (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendRequest {
    pub payment_address: String,
    pub amount_sats: u64,
    /// When false (product default), build/sign/extract only — do not broadcast.
    pub broadcast: bool,
    pub fee_rate_sat_vb: u64,
    /// True when the user supplied `fee=` / `--fee-rate` (not product default).
    /// Product may replace non-explicit rates with live explorer estimates.
    pub fee_rate_explicit: bool,
}

/// Pure parse errors for spend args (CLI positional / TUI tokens).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendParseError {
    MissingAddress,
    MissingAmount,
    InvalidAmount(String),
    /// Fee rate missing, non-integer, or zero.
    InvalidFeeRate(String),
    ZeroAmount,
    EmptyAddress,
}

impl std::fmt::Display for SpendParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAddress => write!(f, "missing payment address"),
            Self::MissingAmount => write!(f, "missing amount in sats"),
            Self::InvalidAmount(s) => write!(f, "invalid amount {s:?} (expected integer sats)"),
            Self::InvalidFeeRate(s) => write!(f, "invalid fee rate: {s}"),
            Self::ZeroAmount => write!(f, "amount must be > 0 sats"),
            Self::EmptyAddress => write!(f, "payment address must not be empty"),
        }
    }
}

/// Parse address + amount + broadcast flag into a [`SpendRequest`].
///
/// `fee_rate_sat_vb: None` → default rate and `fee_rate_explicit = false`.
/// `Some(n)` with `n > 0` → explicit rate.
pub fn parse_spend_request(
    address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> std::result::Result<SpendRequest, SpendParseError> {
    let payment_address = address.trim().to_owned();
    if payment_address.is_empty() {
        return Err(SpendParseError::EmptyAddress);
    }
    if amount_sats == 0 {
        return Err(SpendParseError::ZeroAmount);
    }
    let fee_rate_explicit = fee_rate_sat_vb.is_some();
    let fee_rate_sat_vb = fee_rate_sat_vb.unwrap_or(DEFAULT_SPEND_FEE_RATE_SAT_VB);
    if fee_rate_sat_vb == 0 {
        return Err(SpendParseError::InvalidFeeRate(
            "fee rate must be > 0 sat/vB".into(),
        ));
    }
    Ok(SpendRequest {
        payment_address,
        amount_sats,
        broadcast,
        fee_rate_sat_vb,
        fee_rate_explicit,
    })
}

/// Parse TUI/CLI free-form tokens after `spend`:
/// ` <address> <sats> [broadcast] [fee=<n>|fee-rate=<n>] `
///
/// Address is the first token; amount the second; remaining tokens set flags.
/// Order of optional tokens does not matter. Unknown tokens fail closed.
pub fn parse_spend_tokens(tokens: &[&str]) -> std::result::Result<SpendRequest, SpendParseError> {
    let mut iter = tokens.iter().copied().filter(|t| !t.is_empty());
    let address = iter.next().ok_or(SpendParseError::MissingAddress)?;
    let amount_raw = iter.next().ok_or(SpendParseError::MissingAmount)?;
    let amount_sats: u64 = amount_raw
        .parse()
        .map_err(|_| SpendParseError::InvalidAmount(amount_raw.to_owned()))?;
    let mut broadcast = false;
    let mut fee_rate = None;
    for t in iter {
        let lower = t.to_ascii_lowercase();
        if lower == "broadcast" || lower == "--broadcast" {
            broadcast = true;
            continue;
        }
        if let Some(rest) = lower
            .strip_prefix("fee=")
            .or_else(|| lower.strip_prefix("fee-rate="))
            .or_else(|| lower.strip_prefix("--fee-rate="))
        {
            let n: u64 = rest
                .parse()
                .map_err(|_| SpendParseError::InvalidFeeRate(format!("not an integer: {rest}")))?;
            fee_rate = Some(n);
            continue;
        }
        // Unknown token: fail closed so typos do not silently dry-run.
        return Err(SpendParseError::InvalidAmount(format!(
            "unknown spend token {t:?} (use broadcast and/or fee=<sat/vB>)"
        )));
    }
    parse_spend_request(address, amount_sats, broadcast, fee_rate)
}

/// Whether product may attempt network broadcast for this request.
///
/// Broadcast requires both an explicit user flag **and** a live broadcaster
/// feature / injection. This pure helper only encodes the user intent gate.
pub fn spend_wants_broadcast(req: &SpendRequest) -> bool {
    req.broadcast
}

/// Honest residual when chain UTXO fetch / broadcast HTTP is unavailable.
pub fn spend_chain_unavailable_lines(wants_broadcast: bool) -> Vec<String> {
    let mut lines = vec![
        "On-chain UTXO fetch / broadcast needs the explorer-http client (mempool.space)."
            .to_owned(),
        "This build or environment cannot reach a live chain source right now.".to_owned(),
        "Dry-run with injected MockChainSource works in tests; product path needs network + unlock."
            .to_owned(),
    ];
    if wants_broadcast {
        lines.push(
            "Not broadcasting: never claim broadcast success without a successful explorer response."
                .to_owned(),
        );
    }
    lines
}

/// Label + full signed hex + external-broadcast note.
///
/// Shared by dry-run prepare and broadcast-failure recovery so CLI/TUI never
/// leave the user without hex after unlock + re-entry. Hex is not a recovery
/// phrase. Callers that write hex alone on stdout (CLI dry-run pipes) should
/// filter these lines out of stderr (see shell spend CLI).
pub fn format_spend_raw_hex_lines(raw_hex: &str) -> Vec<String> {
    vec![
        format!("Raw tx hex ({} hex chars):", raw_hex.len()),
        raw_hex.to_owned(),
        "Copy the hex above for inspection or external broadcast.".to_owned(),
    ]
}

/// Whether a prepared-spend line is part of the raw-hex block (label, body, or
/// copy note). Used by CLI to keep full hex off stderr when piping stdout.
pub fn is_spend_raw_hex_output_line(line: &str, raw_hex: &str) -> bool {
    line.starts_with("Raw tx hex")
        || line == raw_hex
        || line.starts_with("Copy the hex above for inspection or external broadcast")
}

/// Lines after a successful local prepare (dry-run default).
pub fn format_spend_prepared_lines(
    payment_address: &str,
    payment_sats: u64,
    fee_sats: u64,
    change_sats: u64,
    txid: &str,
    raw_hex: &str,
    broadcast: bool,
) -> Vec<String> {
    let mut lines = vec![
        format!("Prepared on-chain spend: {payment_sats} sats → {payment_address}"),
        format!("Fee: {fee_sats} sats; change: {change_sats} sats"),
        format!("Txid (local): {txid}"),
    ];
    if broadcast {
        lines.push("Broadcast requested — submitting via rate-limited explorer…".to_owned());
    } else {
        lines.push(
            "Dry-run only (not broadcast). Re-run with --broadcast (CLI) or `broadcast` (TUI) \
             to submit. Accidental mainnet spend is intentionally hard."
                .to_owned(),
        );
        // Full signed hex: TUI system block + CLI summary (CLI also prints hex
        // alone on stdout for pipes after filtering this block from stderr).
        lines.extend(format_spend_raw_hex_lines(raw_hex));
    }
    lines
}

/// Fee / RBF meta lines appended after a successful local prepare.
///
/// Reports requested vs effective rate and notes that inputs signal BIP-125 RBF
/// (`Sequence::ENABLE_RBF_NO_LOCKTIME`). Does not claim a replacement was broadcast.
#[cfg(feature = "onchain-address")]
pub fn format_spend_fee_meta_lines(
    fee_sats: u64,
    vbytes: u64,
    requested_fee_rate_sat_vb: u64,
) -> Vec<String> {
    let effective = crate::descriptor_wallet::effective_fee_rate_sat_vb(fee_sats, vbytes);
    vec![
        format!(
            "Fee rate: requested {requested_fee_rate_sat_vb} sat/vB; effective ~{effective} sat/vB \
             ({fee_sats} sats / {vbytes} vB)."
        ),
        "Inputs signal RBF (BIP-125). To bump later, rebuild at a higher fee rate (see RBF plan \
         helpers) or CPFP a child that spends a change output."
            .to_owned(),
    ]
}

/// Human lines for an [`crate::descriptor_wallet::RbfFeePlan`].
#[cfg(feature = "onchain-address")]
pub fn format_rbf_fee_plan_lines(plan: &crate::descriptor_wallet::RbfFeePlan) -> Vec<String> {
    vec![
        format!(
            "RBF fee bump plan (same-size replacement, {} vB):",
            plan.original_vbytes
        ),
        format!(
            "  Original: {} sats ({} sat/vB floor)",
            plan.original_fee_sats, plan.original_fee_rate_sat_vb
        ),
        format!(
            "  BIP-125 minimum replacement: {} sats ({} sat/vB floor; +{} sat/vB incremental)",
            plan.min_replacement_fee_sats,
            plan.min_replacement_fee_rate_sat_vb,
            plan.incremental_relay_sat_vb
        ),
        format!(
            "  Recommended for {} sat/vB target: {} sats ({} sat/vB floor; +{} sats)",
            plan.target_fee_rate_sat_vb,
            plan.recommended_fee_sats,
            plan.recommended_fee_rate_sat_vb,
            plan.fee_delta_sats
        ),
        "  Rebuild the spend at the recommended fee rate (or higher). Does not broadcast."
            .to_owned(),
    ]
}

/// Human lines for an [`crate::descriptor_wallet::CpfpFeePlan`].
#[cfg(feature = "onchain-address")]
pub fn format_cpfp_fee_plan_lines(plan: &crate::descriptor_wallet::CpfpFeePlan) -> Vec<String> {
    vec![
        format!(
            "CPFP child fee plan (package {} vB = parent {} + child {}):",
            plan.package_vbytes, plan.parent_vbytes, plan.child_vbytes
        ),
        format!(
            "  Parent fee: {} sats; target package rate: {} sat/vB",
            plan.parent_fee_sats, plan.target_fee_rate_sat_vb
        ),
        format!(
            "  Minimum child fee: {} sats (~{} sat/vB child alone)",
            plan.min_child_fee_sats, plan.min_child_fee_rate_sat_vb
        ),
        format!(
            "  Package after child: {} sats (~{} sat/vB)",
            plan.package_fee_sats, plan.package_fee_rate_sat_vb
        ),
        "  Child must spend a confirmed-or-unconfirmed parent output you control. Guidance only."
            .to_owned(),
    ]
}

/// Human lines for mempool-shaped [`crate::explorer::FeeEstimates`].
pub fn format_fee_estimates_lines(est: &crate::explorer::FeeEstimates) -> Vec<String> {
    vec![
        "Explorer fee estimates (sat/vB):".to_owned(),
        format!("  fastest: {}", est.fastest_sat_vb),
        format!("  halfHour: {}", est.half_hour_sat_vb),
        format!("  hour: {}", est.hour_sat_vb),
        format!("  economy: {}", est.economy_sat_vb),
        format!("  minimum: {}", est.minimum_sat_vb),
        "Use fee=<n> / --fee-rate <n> to override; product default priority is halfHour when live estimates are available."
            .to_owned(),
    ]
}

/// Pure RBF guidance from original fee/size + target rate (product / CLI helper).
#[cfg(feature = "onchain-address")]
pub fn rbf_fee_bump_guidance_lines(
    original_fee_sats: u64,
    original_vbytes: u64,
    target_fee_rate_sat_vb: u64,
) -> std::result::Result<Vec<String>, String> {
    let plan = crate::descriptor_wallet::plan_rbf_fee_bump(
        original_fee_sats,
        original_vbytes,
        target_fee_rate_sat_vb,
        0,
    )
    .map_err(|e| e.to_string())?;
    Ok(format_rbf_fee_plan_lines(&plan))
}

/// Pure CPFP guidance; `child_output_count` defaults to 1 when 0.
#[cfg(feature = "onchain-address")]
pub fn cpfp_fee_guidance_lines(
    parent_fee_sats: u64,
    parent_vbytes: u64,
    child_output_count: usize,
    target_fee_rate_sat_vb: u64,
) -> std::result::Result<Vec<String>, String> {
    let child_vb = crate::descriptor_wallet::estimate_cpfp_child_vbytes(child_output_count);
    let plan = crate::descriptor_wallet::plan_cpfp_child_fee(
        parent_fee_sats,
        parent_vbytes,
        child_vb,
        target_fee_rate_sat_vb,
    )
    .map_err(|e| e.to_string())?;
    Ok(format_cpfp_fee_plan_lines(&plan))
}

/// Lines after explorer accepted a broadcast (txid from broadcaster only).
pub fn format_spend_broadcast_success_lines(txid: &str, network_label: &str) -> Vec<String> {
    vec![
        format!("Broadcast accepted ({network_label})."),
        format!("Txid: {txid}"),
        "Explorer accepted the transaction; confirmation watching is separate (`/routstr watch`)."
            .to_owned(),
    ]
}

/// Lines when broadcast was requested but the broadcaster failed.
///
/// Always appends the full signed hex so the user can external-broadcast without
/// re-running unlock. Never claims explorer acceptance.
pub fn format_spend_broadcast_failed_lines(detail: &str, raw_hex: &str) -> Vec<String> {
    let mut lines = vec![
        "Broadcast failed — transaction was NOT accepted by the explorer.".to_owned(),
        format!("Detail: {detail}"),
        "Local signed hex was prepared; funds are not spent until a broadcaster accepts the tx."
            .to_owned(),
    ];
    lines.extend(format_spend_raw_hex_lines(raw_hex));
    lines
}

/// Usage blurb for CLI / TUI.
pub fn spend_usage_lines() -> Vec<String> {
    vec![
        "Usage:".to_owned(),
        "  grok routstr spend <address> <sats> [--broadcast] [--fee-rate <n>]".to_owned(),
        "  /routstr spend <address> <sats> [broadcast] [fee=<n>]".to_owned(),
        "Default is dry-run (build/sign/extract only). SeedVault unlock + recovery-phrase \
         re-entry required; BIP-39 never goes to chat history or CredentialsStore."
            .to_owned(),
        "Dry-run shows full signed hex in the CLI summary and TUI system block; CLI also \
         writes the hex alone on stdout for piping. Broadcast-requested path does not dump \
         hex before explorer acceptance; on broadcast failure the signed hex is shown for \
         external broadcast."
            .to_owned(),
        "Fee: omit --fee-rate to use explorer halfHour estimates when available, else \
         default 5 sat/vB. Inputs signal RBF (BIP-125); use RBF/CPFP plan helpers to size \
         a fee bump without inventing witnesses."
            .to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cashu::FundingStep;
    use crate::mnemonic::generate_mnemonic;
    use crate::seed_vault::DEFAULT_UNLOCK_TTL;

    #[test]
    fn backup_gate_flow_accepts_matching_reentry() {
        let m = generate_mnemonic().unwrap();
        let addr = "bc1qfundingtest0000000000000000000000000";
        let mut lines = Vec::new();
        let phrase = m.expose().to_owned();
        let reveal = run_backup_gate_to_show_address(
            FundingRevealInput {
                mnemonic: &m,
                address: addr.into(),
                unlock_ttl: DEFAULT_UNLOCK_TTL,
                print_address: true,
            },
            |l| {
                lines.push(l.to_owned());
                Ok(())
            },
            |_prompt| Ok(phrase.clone()),
        )
        .unwrap();

        assert_eq!(reveal.address, addr);
        assert_eq!(reveal.wizard.step, FundingStep::ShowAddress);
        assert!(reveal.wizard.backup_confirmed());
        assert_eq!(reveal.wizard.receive_address.as_deref(), Some(addr));
        assert!(lines.iter().any(|l| l.contains("Write down")));
        assert!(lines.iter().any(|l| l.contains(addr)));
        // Must not echo full mnemonic in write_line after show (words are numbered lines).
        assert!(
            !lines.iter().any(|l| l == &phrase),
            "full phrase must not be printed as a single line after numbered show"
        );
    }

    #[test]
    fn backup_gate_without_print_does_not_emit_address() {
        let m = generate_mnemonic().unwrap();
        let addr = "bc1qdeferprint000000000000000000000000";
        let mut lines = Vec::new();
        let phrase = m.expose().to_owned();
        let reveal = run_backup_gate_to_show_address(
            FundingRevealInput {
                mnemonic: &m,
                address: addr.into(),
                unlock_ttl: DEFAULT_UNLOCK_TTL,
                print_address: false,
            },
            |l| {
                lines.push(l.to_owned());
                Ok(())
            },
            |_prompt| Ok(phrase.clone()),
        )
        .unwrap();
        assert_eq!(reveal.wizard.step, FundingStep::ShowAddress);
        assert!(
            !lines.iter().any(|l| l.contains(addr)),
            "address must not print before durable store"
        );
        assert!(lines.iter().any(|l| l.contains("Saving the wallet")));
    }

    #[test]
    fn backup_gate_flow_rejects_wrong_reentry() {
        let m = generate_mnemonic().unwrap();
        let err = run_backup_gate_to_show_address(
            FundingRevealInput {
                mnemonic: &m,
                address: "bc1qnope".into(),
                unlock_ttl: DEFAULT_UNLOCK_TTL,
                print_address: false,
            },
            |_| Ok(()),
            |_| Ok("abandon abandon abandon".into()),
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::BackupReentryMismatch));
    }

    #[test]
    fn backup_gate_flow_empty_reentry_is_not_confirmed() {
        let m = generate_mnemonic().unwrap();
        let err = run_backup_gate_to_show_address(
            FundingRevealInput {
                mnemonic: &m,
                address: "bc1qnope".into(),
                unlock_ttl: DEFAULT_UNLOCK_TTL,
                print_address: false,
            },
            |_| Ok(()),
            |_| Ok("   ".into()),
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::BackupNotConfirmed));
    }

    #[test]
    fn cannot_skip_gate_via_wizard_directly_in_product_path() {
        // Document invariant: product uses show_address_with_backup_gate only.
        let mut w = FundingWizard::new();
        assert!(matches!(
            w.show_address("bc1q"),
            Err(WalletError::BackupNotConfirmed)
        ));
    }

    #[test]
    fn vault_load_class_keyring_must_not_mint() {
        let class = classify_vault_load_err(&WalletError::Keyring("secret-service down".into()));
        assert!(!may_mint_new_wallet(&class));
        assert!(matches!(class, VaultLoadClass::DoNotMint { .. }));
        let msg = keyring_blocked_message("secret-service down");
        assert!(msg.contains("not creating a new wallet"));
        assert!(!msg.contains("Generating a new"));
    }

    #[test]
    fn vault_load_class_only_not_found_may_mint() {
        assert!(may_mint_new_wallet(&VaultLoadClass::NotFound));
        assert!(!may_mint_new_wallet(&VaultLoadClass::PasswordRequired));
        assert!(!may_mint_new_wallet(&VaultLoadClass::Error {
            message: "x".into()
        }));
    }

    #[test]
    fn fund_path_decision_from_load_variants() {
        assert_eq!(
            fund_path_decision_from_load::<()>(Ok(())),
            FundPathDecision::ReturningUnlock
        );
        assert_eq!(
            fund_path_decision_from_load::<()>(Err(WalletError::NotFound)),
            FundPathDecision::NewWallet
        );
        assert_eq!(
            fund_path_decision_from_load::<()>(Err(WalletError::PasswordRequired)),
            FundPathDecision::NeedPassword
        );
        assert!(matches!(
            fund_path_decision_from_load::<()>(Err(WalletError::Keyring("e".into()))),
            FundPathDecision::KeyringBlocked { .. }
        ));
    }

    #[test]
    fn returning_user_reveal_requires_matching_reentry() {
        let m = generate_mnemonic().unwrap();
        let addr = "bc1qreturn0000000000000000000000000000";
        let phrase = m.expose().to_owned();
        let reveal = returning_user_reveal_after_reentry(&m, &phrase, addr.into()).unwrap();
        assert_eq!(reveal.wizard.step, FundingStep::ShowAddress);
        assert!(reveal.wizard.backup_confirmed());
        assert_eq!(reveal.address, addr);

        let bad = returning_user_reveal_after_reentry(&m, "abandon abandon", addr.into());
        assert!(matches!(bad, Err(WalletError::BackupReentryMismatch)));

        let empty = returning_user_reveal_after_reentry(&m, "   ", addr.into());
        assert!(matches!(empty, Err(WalletError::BackupNotConfirmed)));
    }

    #[test]
    fn store_before_address_print_invariant_holds() {
        // Product constant + new-wallet helper default order in CLI/TUI.
        assert!(STORE_BEFORE_ADDRESS_PRINT);
        let m = generate_mnemonic().unwrap();
        let addr = "bc1qstorefirst00000000000000000000000";
        let phrase = m.expose().to_owned();
        let mut lines = Vec::new();
        let reveal = new_wallet_backup_and_reveal(
            &m,
            addr.into(),
            false, // product: defer print until after durable store
            |l| {
                lines.push(l.to_owned());
                Ok(())
            },
            |_| Ok(phrase.clone()),
        )
        .unwrap();
        assert!(
            !lines.iter().any(|l| l.contains(addr)),
            "address must not appear in backup IO when print_address=false"
        );
        assert_eq!(reveal.wizard.step, FundingStep::ShowAddress);
        // After store, product prints via format_fund_success_lines(saved=true).
        let printed =
            format_fund_success_lines(&reveal.address, "showing receive address", "mainnet", true);
        assert!(printed.iter().any(|l| l.contains(addr)));
        assert!(printed.iter().any(|l| l.contains("Wallet saved")));
        let unlocked =
            format_fund_success_lines(&reveal.address, "showing receive address", "mainnet", false);
        assert!(
            !unlocked.iter().any(|l| l.contains("Wallet saved")),
            "returning-user path must not claim a fresh save"
        );
        assert!(unlocked.iter().any(|l| l.contains("Backup confirmed")));
    }

    #[test]
    fn topup_refund_copy_is_honest_no_live_mint_claim() {
        let top = topup_next_steps_lines(Some(21_000));
        let joined = top.join("\n").to_ascii_lowercase();
        assert!(joined.contains("not wired yet") || joined.contains("not available"));
        assert!(joined.contains("21000"));
        assert!(!joined.contains("invoice created"));
        assert!(!joined.contains("payment sent"));
        assert!(!joined.contains("bolt11:"));
        assert!(!joined.contains("mint invoice ready"));

        let refnd = refund_next_steps_lines().join("\n").to_ascii_lowercase();
        assert!(refnd.contains("not wired yet") || refnd.contains("not available"));
        assert!(!refnd.contains("refund completed"));
    }

    #[test]
    fn topup_with_stub_backends_never_emits_live_invoice() {
        let lines = topup_next_steps_for_backends(
            &crate::cashu::StubCashu,
            &crate::lightning::StubLightning,
            Some(100),
        );
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(joined.contains("not wired yet"));
        assert!(!joined.contains("lnbc"));
        assert!(!joined.contains("invoice ready"));
    }

    /// LN backend that advertises live invoices but fails create — must not say "not wired".
    struct LiveInvoiceFailLn;
    impl crate::lightning::LightningCapability for LiveInvoiceFailLn {
        fn capabilities(&self) -> crate::lightning::LightningCapabilities {
            crate::lightning::LightningCapabilities {
                bolt11_pay_live: false,
                bolt11_invoice_live: true,
                bolt12_supported: false,
            }
        }
        fn pay_bolt11(
            &self,
            _invoice: &crate::lightning::Bolt11Invoice,
        ) -> crate::error::Result<crate::lightning::PayOutcome> {
            Ok(crate::lightning::PayOutcome::Unsupported("n/a"))
        }
        fn create_bolt11_invoice(
            &self,
            _amount_sats: Option<u64>,
        ) -> crate::error::Result<crate::lightning::InvoiceOutcome> {
            Ok(crate::lightning::InvoiceOutcome::Failed(
                "node offline".into(),
            ))
        }
    }

    #[test]
    fn topup_live_ln_invoice_failure_is_honest_not_not_wired() {
        let lines = topup_next_steps_for_backends(
            &crate::cashu::StubCashu,
            &LiveInvoiceFailLn,
            Some(21_000),
        );
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(
            joined.contains("failed") || joined.contains("no invoice was created"),
            "expected failure wording: {joined}"
        );
        assert!(
            !joined.contains("not wired yet"),
            "must not claim residual stub when bolt11_invoice_live: {joined}"
        );
        assert!(!joined.contains("lnbc"));
    }

    /// Cashu backend with live mint that returns a real-shaped invoice (flip-path proof).
    struct LiveMintOkCashu;
    impl crate::cashu::CashuBackend for LiveMintOkCashu {
        fn capabilities(&self) -> crate::cashu::CashuCapabilities {
            crate::cashu::CashuCapabilities {
                mint_live: true,
                spend_live: false,
                refund_live: false,
            }
        }
        fn request_mint_invoice(
            &self,
            _amount_sats: Option<u64>,
        ) -> crate::error::Result<crate::cashu::MintQuoteOutcome> {
            Ok(crate::cashu::MintQuoteOutcome::Invoice {
                bolt11: "lnbc210u1ptestquote-test".into(),
                quote_id: "quote-test-1".into(),
            })
        }
        fn refund(&self) -> crate::error::Result<crate::cashu::CashuRefundOutcome> {
            Ok(crate::cashu::CashuRefundOutcome::Unsupported("n/a"))
        }
    }

    /// Cashu mint live but Failed — must not fall through to residual "not wired".
    struct LiveMintFailCashu;
    impl crate::cashu::CashuBackend for LiveMintFailCashu {
        fn capabilities(&self) -> crate::cashu::CashuCapabilities {
            crate::cashu::CashuCapabilities {
                mint_live: true,
                spend_live: false,
                refund_live: false,
            }
        }
        fn request_mint_invoice(
            &self,
            _amount_sats: Option<u64>,
        ) -> crate::error::Result<crate::cashu::MintQuoteOutcome> {
            Ok(crate::cashu::MintQuoteOutcome::Failed(
                "mint unreachable".into(),
            ))
        }
        fn refund(&self) -> crate::error::Result<crate::cashu::CashuRefundOutcome> {
            Ok(crate::cashu::CashuRefundOutcome::Unsupported("n/a"))
        }
    }

    /// Cashu refund live + completed (flip-path proof).
    struct LiveRefundOkCashu;
    impl crate::cashu::CashuBackend for LiveRefundOkCashu {
        fn capabilities(&self) -> crate::cashu::CashuCapabilities {
            crate::cashu::CashuCapabilities {
                mint_live: false,
                spend_live: false,
                refund_live: true,
            }
        }
        fn request_mint_invoice(
            &self,
            _amount_sats: Option<u64>,
        ) -> crate::error::Result<crate::cashu::MintQuoteOutcome> {
            Ok(crate::cashu::MintQuoteOutcome::Unsupported("n/a"))
        }
        fn refund(&self) -> crate::error::Result<crate::cashu::CashuRefundOutcome> {
            Ok(crate::cashu::CashuRefundOutcome::Completed {
                detail: "melted 1000 sats to lnbc…".into(),
            })
        }
    }

    /// Cashu refund live but Failed — honest failure, not residual stub copy.
    struct LiveRefundFailCashu;
    impl crate::cashu::CashuBackend for LiveRefundFailCashu {
        fn capabilities(&self) -> crate::cashu::CashuCapabilities {
            crate::cashu::CashuCapabilities {
                mint_live: false,
                spend_live: false,
                refund_live: true,
            }
        }
        fn request_mint_invoice(
            &self,
            _amount_sats: Option<u64>,
        ) -> crate::error::Result<crate::cashu::MintQuoteOutcome> {
            Ok(crate::cashu::MintQuoteOutcome::Unsupported("n/a"))
        }
        fn refund(&self) -> crate::error::Result<crate::cashu::CashuRefundOutcome> {
            Ok(crate::cashu::CashuRefundOutcome::Failed(
                "melt quote expired".into(),
            ))
        }
    }

    /// LN invoice live + Created (flip-path proof when Cashu mint is off).
    struct LiveInvoiceOkLn;
    impl crate::lightning::LightningCapability for LiveInvoiceOkLn {
        fn capabilities(&self) -> crate::lightning::LightningCapabilities {
            crate::lightning::LightningCapabilities {
                bolt11_pay_live: false,
                bolt11_invoice_live: true,
                bolt12_supported: false,
            }
        }
        fn pay_bolt11(
            &self,
            _invoice: &crate::lightning::Bolt11Invoice,
        ) -> crate::error::Result<crate::lightning::PayOutcome> {
            Ok(crate::lightning::PayOutcome::Unsupported("n/a"))
        }
        fn create_bolt11_invoice(
            &self,
            _amount_sats: Option<u64>,
        ) -> crate::error::Result<crate::lightning::InvoiceOutcome> {
            Ok(crate::lightning::InvoiceOutcome::Created {
                bolt11: "lnbc100n1ptestlocal-test".into(),
            })
        }
    }

    #[test]
    fn topup_live_cashu_mint_success_emits_invoice_copy() {
        let lines = topup_next_steps_for_backends(
            &LiveMintOkCashu,
            &crate::lightning::StubLightning,
            Some(21_000),
        );
        let joined = lines.join("\n");
        let lower = joined.to_ascii_lowercase();
        assert!(
            lower.contains("mint invoice ready"),
            "live mint success must claim ready: {joined}"
        );
        assert!(joined.contains("lnbc210u1ptestquote-test"));
        assert!(joined.contains("quote-test-1"));
        assert!(joined.contains("21000"));
        assert!(
            !lower.contains("not wired yet"),
            "must not use residual stub copy when mint_live succeeds: {joined}"
        );
    }

    #[test]
    fn topup_live_cashu_mint_failure_is_honest_not_not_wired() {
        let lines = topup_next_steps_for_backends(
            &LiveMintFailCashu,
            &crate::lightning::StubLightning,
            Some(100),
        );
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(
            joined.contains("failed") || joined.contains("no invoice was created"),
            "expected failure wording: {joined}"
        );
        assert!(
            !joined.contains("not wired yet"),
            "must not claim residual stub when mint_live: {joined}"
        );
        assert!(!joined.contains("lnbc"));
        assert!(!joined.contains("invoice ready"));
    }

    #[test]
    fn topup_live_ln_invoice_success_emits_bolt11() {
        let lines =
            topup_next_steps_for_backends(&crate::cashu::StubCashu, &LiveInvoiceOkLn, Some(100));
        let joined = lines.join("\n");
        let lower = joined.to_ascii_lowercase();
        assert!(
            lower.contains("lightning invoice ready"),
            "live LN invoice must claim ready: {joined}"
        );
        assert!(joined.contains("lnbc100n1ptestlocal-test"));
        assert!(!lower.contains("not wired yet"));
    }

    #[test]
    fn refund_live_success_claims_completed() {
        let lines = refund_next_steps_for_backend(&LiveRefundOkCashu);
        let joined = lines.join("\n");
        let lower = joined.to_ascii_lowercase();
        assert!(
            lower.contains("refund completed"),
            "live refund success must claim completed: {joined}"
        );
        assert!(joined.contains("melted 1000 sats"));
        assert!(
            !lower.contains("not wired yet") && !lower.contains("not available"),
            "must not use residual stub copy when refund_live succeeds: {joined}"
        );
    }

    #[test]
    fn refund_live_failure_is_honest_not_not_wired() {
        let lines = refund_next_steps_for_backend(&LiveRefundFailCashu);
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(
            joined.contains("failed") || joined.contains("no refund was completed"),
            "expected failure wording: {joined}"
        );
        assert!(
            !joined.contains("not wired yet") && !joined.contains("not available in this build"),
            "must not claim residual stub when refund_live: {joined}"
        );
        assert!(!joined.contains("refund completed"));
    }

    #[test]
    fn default_backends_are_honest_stubs() {
        let cashu = crate::cashu::default_cashu_backend();
        let ln = crate::lightning::default_lightning_backend();
        let c = crate::cashu::CashuBackend::capabilities(&cashu);
        let l = crate::lightning::LightningCapability::capabilities(&ln);
        assert!(!c.mint_live && !c.spend_live && !c.refund_live);
        assert!(!l.bolt11_pay_live && !l.bolt11_invoice_live && !l.bolt12_supported);
        // Product entry points must still resolve to residual copy today.
        let top = topup_next_steps_lines(None).join("\n").to_ascii_lowercase();
        assert!(top.contains("not wired yet"));
        assert!(!top.contains("lnbc"));
        let refnd = refund_next_steps_lines().join("\n").to_ascii_lowercase();
        assert!(refnd.contains("not wired yet") || refnd.contains("not available"));
        assert!(!refnd.contains("refund completed"));
    }

    #[test]
    fn receive_address_display_includes_address_and_optional_qr() {
        let addr = "bc1q8zxz5kl6q30y2mzhx86gcwcz0t0hgzl2f2jpm5";
        let lines = receive_address_display_lines(addr, false);
        let joined = lines.join("\n");
        assert!(joined.contains(addr));
        assert!(joined.contains("bitcoin:"));
        assert!(!joined.to_ascii_lowercase().contains("lnbc"));

        let with_qr = receive_address_display_lines(addr, true);
        let qr_joined = with_qr.join("\n");
        assert!(qr_joined.contains(addr));
        #[cfg(feature = "qr")]
        {
            assert!(
                qr_joined.contains("QR") || with_qr.len() > lines.len(),
                "expected QR matrix when qr feature on: {qr_joined}"
            );
        }
        assert_eq!(receive_address_clipboard(addr), addr);
    }

    #[test]
    fn parse_spend_tokens_dry_run_default_and_broadcast_flag() {
        let req = parse_spend_tokens(&["bc1qtest", "21000"]).unwrap();
        assert_eq!(req.payment_address, "bc1qtest");
        assert_eq!(req.amount_sats, 21_000);
        assert!(!req.broadcast);
        assert_eq!(req.fee_rate_sat_vb, DEFAULT_SPEND_FEE_RATE_SAT_VB);
        assert!(!req.fee_rate_explicit);
        assert!(!spend_wants_broadcast(&req));

        let req = parse_spend_tokens(&["bc1qtest", "100", "broadcast", "fee=8"]).unwrap();
        assert!(req.broadcast);
        assert_eq!(req.fee_rate_sat_vb, 8);
        assert!(req.fee_rate_explicit);
        assert!(spend_wants_broadcast(&req));

        assert!(matches!(
            parse_spend_tokens(&["bc1qtest", "0"]),
            Err(SpendParseError::ZeroAmount)
        ));
        assert!(matches!(
            parse_spend_tokens(&[]),
            Err(SpendParseError::MissingAddress)
        ));
        assert!(matches!(
            parse_spend_tokens(&["bc1qtest"]),
            Err(SpendParseError::MissingAmount)
        ));
        assert!(matches!(
            parse_spend_tokens(&["bc1qtest", "nope"]),
            Err(SpendParseError::InvalidAmount(_))
        ));
        // Unknown token fail-closed.
        assert!(matches!(
            parse_spend_tokens(&["bc1qtest", "10", "typo-flag"]),
            Err(SpendParseError::InvalidAmount(_))
        ));
        // Fee rate zero / non-integer use InvalidFeeRate (not amount overload).
        assert!(matches!(
            parse_spend_request("bc1qtest", 100, false, Some(0)),
            Err(SpendParseError::InvalidFeeRate(_))
        ));
        assert!(matches!(
            parse_spend_tokens(&["bc1qtest", "100", "fee=0"]),
            Err(SpendParseError::InvalidFeeRate(_))
        ));
        assert!(matches!(
            parse_spend_tokens(&["bc1qtest", "100", "fee=nope"]),
            Err(SpendParseError::InvalidFeeRate(_))
        ));
    }

    #[test]
    fn spend_copy_never_claims_broadcast_without_flag() {
        let full_hex = "ab".repeat(40);
        let lines = format_spend_prepared_lines(
            "bc1qdest",
            1000,
            50,
            200,
            &"a".repeat(64),
            &full_hex,
            false,
        );
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(joined.contains("dry-run"));
        assert!(joined.contains("not broadcast"));
        assert!(!joined.contains("broadcast accepted"));
        // Dry-run includes the full raw hex (TUI + CLI share this copy).
        assert!(
            lines.iter().any(|l| l == &full_hex),
            "expected full raw hex line: {lines:?}"
        );
        assert!(
            joined.contains("raw tx hex"),
            "expected raw hex label: {joined}"
        );
        // Broadcast path must not dump hex as if broadcast succeeded.
        let broadcast_lines = format_spend_prepared_lines(
            "bc1qdest",
            1000,
            50,
            200,
            &"a".repeat(64),
            &full_hex,
            true,
        );
        assert!(
            !broadcast_lines.iter().any(|l| l == &full_hex),
            "broadcast-requested copy must not dump raw hex before acceptance"
        );

        let ok = format_spend_broadcast_success_lines(&"b".repeat(64), "mainnet");
        assert!(ok.iter().any(|l| l.contains("Broadcast accepted")));
        let fail = format_spend_broadcast_failed_lines("HTTP 400: bad-tx", &full_hex);
        let fail_j = fail.join("\n").to_ascii_lowercase();
        assert!(fail_j.contains("not accepted") || fail_j.contains("failed"));
        assert!(fail_j.contains("not spent"));
        // Broadcast failure must still surface full hex for external broadcast.
        assert!(
            fail.iter().any(|l| l == &full_hex),
            "expected full raw hex on broadcast failure: {fail:?}"
        );
        assert!(
            !fail_j.contains("broadcast accepted"),
            "failure copy must never claim acceptance: {fail_j}"
        );

        // Usage blurb matches runtime (full hex on dry-run CLI+TUI, not "preview only").
        let usage = spend_usage_lines().join("\n").to_ascii_lowercase();
        assert!(
            !usage.contains("short preview") && !usage.contains("not full hex"),
            "stale preview-only wording: {usage}"
        );
        assert!(
            usage.contains("full signed hex") && usage.contains("tui") && usage.contains("stdout"),
            "usage should describe full hex on CLI+TUI and stdout pipe: {usage}"
        );

        // CLI stderr filter helper: label + body + copy note are hex-block lines.
        let hex_block = format_spend_raw_hex_lines(&full_hex);
        assert_eq!(hex_block.len(), 3);
        for line in &hex_block {
            assert!(
                is_spend_raw_hex_output_line(line, &full_hex),
                "hex-block line should be filtered from CLI stderr: {line}"
            );
        }
        assert!(!is_spend_raw_hex_output_line(
            "Prepared on-chain spend: 1000 sats → bc1qdest",
            &full_hex
        ));

        let residual = spend_chain_unavailable_lines(true);
        let r = residual.join("\n").to_ascii_lowercase();
        assert!(r.contains("not broadcasting") || r.contains("never claim"));
    }

    #[test]
    fn format_fee_estimates_lines_lists_ladder() {
        let est = crate::explorer::FeeEstimates {
            fastest_sat_vb: 20,
            half_hour_sat_vb: 15,
            hour_sat_vb: 10,
            economy_sat_vb: 5,
            minimum_sat_vb: 1,
        };
        let joined = format_fee_estimates_lines(&est).join("\n");
        assert!(joined.contains("fastest: 20"));
        assert!(joined.contains("halfHour: 15"));
        assert!(joined.contains("economy: 5"));
        assert!(!joined.to_ascii_lowercase().contains("crypto"));
    }

    #[cfg(feature = "onchain-address")]
    #[test]
    fn format_spend_fee_meta_and_rbf_cpfp_guidance() {
        let meta = format_spend_fee_meta_lines(705, 141, 5);
        let meta_j = meta.join("\n").to_ascii_lowercase();
        assert!(meta_j.contains("fee rate"));
        assert!(meta_j.contains("rbf"));
        assert!(meta_j.contains("5 sat/vb"));
        assert!(!meta_j.contains("broadcast accepted"));

        let rbf = rbf_fee_bump_guidance_lines(705, 141, 10).unwrap();
        let rbf_j = rbf.join("\n").to_ascii_lowercase();
        assert!(rbf_j.contains("rbf fee bump"));
        assert!(rbf_j.contains("recommended"));
        assert!(rbf_j.contains("does not broadcast"));

        let cpfp = cpfp_fee_guidance_lines(200, 200, 1, 10).unwrap();
        let cpfp_j = cpfp.join("\n").to_ascii_lowercase();
        assert!(cpfp_j.contains("cpfp"));
        assert!(cpfp_j.contains("minimum child fee"));
        assert!(cpfp_j.contains("guidance only"));

        assert!(rbf_fee_bump_guidance_lines(100, 0, 10).is_err());
        assert!(cpfp_fee_guidance_lines(100, 100, 1, 0).is_err());
    }

    #[test]
    fn spend_usage_mentions_rbf_and_fee_estimates() {
        let usage = spend_usage_lines().join("\n").to_ascii_lowercase();
        assert!(usage.contains("rbf") || usage.contains("bip-125"));
        assert!(usage.contains("fee"));
        assert!(!usage.contains("crypto"));
    }
}
