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
///
/// When `bip39_passphrase_active` is true (non-empty resolved BIP-39 passphrase
/// used for derivation — env and/or private TUI modal), appends a non-secret
/// notice. Never includes the passphrase value or falsely attributes source.
pub fn format_fund_success_lines(
    address: &str,
    step_label: &str,
    network_label: &str,
    saved: bool,
) -> Vec<String> {
    format_fund_success_lines_with_passphrase_flag(address, step_label, network_label, saved, false)
}

/// Same as [`format_fund_success_lines`] with optional BIP-39 passphrase-active notice.
pub fn format_fund_success_lines_with_passphrase_flag(
    address: &str,
    step_label: &str,
    network_label: &str,
    saved: bool,
    bip39_passphrase_active: bool,
) -> Vec<String> {
    let head = if saved {
        format!("Backup confirmed. Wallet saved. Receive address ({network_label}):")
    } else {
        format!("Backup confirmed. Receive address ({network_label}):")
    };
    let mut lines = vec![
        head,
        address.to_owned(),
        format!("Funding status: {step_label}"),
        "Send only Bitcoin to this address. After you broadcast a deposit, confirmation \
         watching uses the rate-limited mempool.space client."
            .to_owned(),
        "BOLT12 offers are not supported in this build.".to_owned(),
    ];
    if bip39_passphrase_active {
        lines.extend(bip39_passphrase_active_notice_lines());
    }
    lines
}

/// Where a non-empty BIP-39 passphrase was resolved from (product notice only).
///
/// Never includes the secret. Used so success copy does not claim env when the
/// TUI private modal supplied the value (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip39PassphraseNoticeSource {
    /// Resolved from [`crate::mnemonic::BIP39_PASSPHRASE_ENV`].
    ProcessEnv,
    /// Resolved from private TUI modal re-entry for this unlock only.
    PrivateModal,
    /// Non-empty resolved passphrase without attributing a single source
    /// (preferred when callers cannot distinguish env vs modal).
    Active,
}

/// Non-secret product notice when a BIP-39 passphrase was used for derive/sign.
///
/// Never includes the passphrase value. Defaults to [`Bip39PassphraseNoticeSource::Active`]
/// (neutral wording — does not claim env when the modal may have supplied the value).
/// Used on fund address reveal and spend/RBF/CPFP prepare summaries.
pub fn bip39_passphrase_active_notice_lines() -> Vec<String> {
    bip39_passphrase_active_notice_lines_for(Bip39PassphraseNoticeSource::Active)
}

/// Same as [`bip39_passphrase_active_notice_lines`] with an explicit source label.
pub fn bip39_passphrase_active_notice_lines_for(
    source: Bip39PassphraseNoticeSource,
) -> Vec<String> {
    let source_clause = match source {
        Bip39PassphraseNoticeSource::ProcessEnv => {
            format!("from {} ", crate::mnemonic::BIP39_PASSPHRASE_ENV)
        }
        Bip39PassphraseNoticeSource::PrivateModal => "from private modal re-entry ".to_owned(),
        Bip39PassphraseNoticeSource::Active => String::new(),
    };
    vec![format!(
        "BIP-39 passphrase {source_clause}is active (value not shown; never stored; \
         re-supply at unlock via {} or `/routstr unlock pass`). \
         Lose the passphrase ⇒ lose access even with the recovery phrase.",
        crate::mnemonic::BIP39_PASSPHRASE_ENV
    )]
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

/// Capability-aware top-up lines. Live mint **quote** only when Cashu reports
/// `mint_live` **and** returns [`crate::cashu::MintQuoteOutcome::Invoice`].
///
/// Never fabricates a BOLT11 from a stub outcome. NUT-04 quote success is
/// **not** Routstr float credit. When `proofs_mint_live`, product copy points
/// at paid-quote → `cashuA` via CDK helper then **redeem** (float only after
/// redeem). Mint Failed/Unsupported falls through to the P0 Routstr node
/// invoice path.
pub fn topup_next_steps_for_backends(
    cashu: &dyn crate::cashu::CashuBackend,
    ln: &dyn crate::lightning::LightningCapability,
    sats: Option<u64>,
) -> Vec<String> {
    let cashu_caps = cashu.capabilities();
    let ln_caps = ln.capabilities();
    // Honest mint-failure preamble; always fall through to P0 residual so float
    // funding remains discoverable (mirror LDK bare-create fail-through).
    let mut mint_failure_preamble: Vec<String> = Vec::new();

    // Prefer a real Cashu mint quote when the backend is live.
    if cashu_caps.mint_live {
        match cashu.request_mint_invoice(sats) {
            Ok(crate::cashu::MintQuoteOutcome::Invoice { bolt11, quote_id }) => {
                let mut lines = vec![
                    "Cashu mint quote invoice (NUT-04) — not a Routstr node invoice.".to_owned(),
                    format!("Quote id: {quote_id}"),
                    format!("BOLT11: {bolt11}"),
                    "Paying this invoice pays the mint for a quote only.".to_owned(),
                ];
                if cashu_caps.proofs_mint_live {
                    lines.push(
                        "After pay: complete proofs mint via CDK helper (SeedVault) to \
                         obtain a cashuA… token — still not Routstr float until redeem."
                            .to_owned(),
                    );
                    lines.push(
                        "Then redeem: `grok routstr redeem <cashuA…>` (or login paste) to \
                         fund Routstr float."
                            .to_owned(),
                    );
                } else {
                    lines.push(
                        "Mint completion (proofs → cashuA token) needs the \
                         grok-bitcoin-cdk-mint helper (build + GROK_BITCOIN_CDK_MINT_BIN) \
                         or an external Cashu wallet."
                            .to_owned(),
                    );
                    lines.push(
                        "When you have a cashuA… token, redeem with `grok routstr redeem` \
                         (or login) to fund Routstr float."
                            .to_owned(),
                    );
                }
                lines.push(
                    "For prepaid float now without Cashu: `grok routstr topup` (Routstr \
                     node BOLT11)."
                        .to_owned(),
                );
                if let Some(s) = sats {
                    lines.insert(1, format!("Requested amount: {s} sats."));
                }
                return lines;
            }
            Ok(crate::cashu::MintQuoteOutcome::Unsupported(reason)) => {
                mint_failure_preamble = vec![
                    "Cashu mint quote: backend reported live but returned unsupported.".to_owned(),
                    format!("Detail: {reason}"),
                    "No mint quote invoice was created.".to_owned(),
                ];
            }
            Ok(crate::cashu::MintQuoteOutcome::Failed(e)) => {
                mint_failure_preamble = vec![
                    "Cashu mint quote failed.".to_owned(),
                    format!("Detail: {e}"),
                    "No mint quote invoice was created.".to_owned(),
                ];
            }
            Err(e) => {
                mint_failure_preamble = vec![
                    "Cashu mint quote error.".to_owned(),
                    format!("Detail: {e}"),
                    "No mint quote invoice was created.".to_owned(),
                ];
            }
        }
        // fall through: P0 Routstr float path remains available after mint fail
    }

    // Optional local LDK receive invoice when live **and** bare create yields a
    // real bolt11. Local receive is **not** Routstr prepaid float funding — on
    // Failed/Unsupported (e.g. SeedVault required for LdkLightning bare create)
    // fall through to the residual Routstr node invoice-first path (P0). Never
    // claim residual "not wired yet" language for a live-flag backend.
    if ln_caps.bolt11_invoice_live {
        if let Ok(crate::lightning::InvoiceOutcome::Created { bolt11 }) =
            ln.create_bolt11_invoice(sats)
        {
            let b = bolt11.trim();
            if !b.is_empty() && crate::routstr_invoice::looks_like_bolt11(b) {
                let mut lines = mint_failure_preamble;
                if !lines.is_empty() {
                    lines.push(String::new());
                }
                lines.push("Local Lightning receive invoice ready (LDK).".to_owned());
                if let Some(s) = sats {
                    lines.push(format!("Requested amount: {s} sats."));
                }
                lines.push(format!("BOLT11: {b}"));
                lines.push(
                    "This is a **local** receive invoice — it does not fund Routstr \
                     prepaid float by itself. Prefer `grok routstr topup` for node float."
                        .to_owned(),
                );
                lines.extend(crate::lightning::inbound_liquidity_honesty_lines());
                return lines;
            }
        }
        // else: fall through to residual Routstr invoice-first (primary float path)
    }

    // Residual when local CDK/LDK mint+invoice are not usable for float. Prefer
    // live node invoice via `grok routstr topup` (no website).
    let mut lines = mint_failure_preamble;
    if !lines.is_empty() {
        lines.push(String::new());
        lines.push("Falling back to Routstr node float (invoice-first; no website).".to_owned());
    }
    lines.push("Routstr node float: create a Lightning invoice in-app (no website).".to_owned());
    if let Some(s) = sats {
        lines.push(format!("Requested amount: {s} sats."));
    }
    lines.push("Next steps:".to_owned());
    lines.push(
        "  1. `grok routstr topup` (or /routstr topup) — creates a mainnet BOLT11 on the \
         Routstr node; pay with any Lightning wallet."
            .to_owned(),
    );
    lines.push(
        "  2. After pay: `grok routstr topup --status <invoice_id>` (or wait for the poll) \
         then `grok routstr balance`."
            .to_owned(),
    );
    lines.push(
        "  3. Optional: `grok login --routstr` / `grok routstr redeem <cashuA…>` if you \
         already have a key or Cashu token."
            .to_owned(),
    );
    lines.push(
        "  4. Local on-chain deposit: `grok routstr fund` (does not mint node float by itself)."
            .to_owned(),
    );
    lines.push(
        "If live invoice create failed, check network access to api.routstr.com and retry \
         `grok routstr topup`. No fabricated invoice is shown."
            .to_owned(),
    );
    lines
}

/// Next-steps copy for refund while CDK return is residual.
pub fn refund_next_steps_lines() -> Vec<String> {
    refund_next_steps_for_backend(&crate::cashu::default_cashu_backend())
}

/// True when bare `refund()` Failed means melt capability is available but the
/// call has no token+bolt11+seed — not a product float refund that already ran.
fn bare_refund_needs_token_context(detail: &str) -> bool {
    let d = detail.to_ascii_lowercase();
    d.contains("token context")
        || d.contains("melt_token_to_bolt11")
        || d.contains("bare refund has no token")
}

/// Residual product refund guide (node float preferred; library melt when wired).
///
/// Guidance: prefer spend/melt of held `cashuA…` over parking large hot `sk-`
/// float; node refund remains the product path for existing prepaid float.
fn refund_residual_next_steps() -> Vec<String> {
    vec![
        "Routstr refund: prefer live node API `grok routstr refund` (POST /v1/balance/refund) \
         for existing sk- float."
            .to_owned(),
        "Next steps:".to_owned(),
        "  1. With a stored key: `grok routstr refund` — returns a Cashu token once when the \
         node succeeds (copy it; it is not re-logged)."
            .to_owned(),
        "  2. Prefer spend/melt of cashuA… you already hold over parking large hot sk- float."
            .to_owned(),
        "  3. Prefer spending down remaining hot sk- float rather than leaving large balances \
         on the node."
            .to_owned(),
        "  4. `grok routstr balance` (or /routstr balance) to check remaining float.".to_owned(),
        "Local CDK melt (Cashu → destination BOLT11; never sk- float credit): when feature \
         `cashu-cdk` + mint URL + resolvable grok-bitcoin-cdk-mint helper, \
         `grok routstr refund --token <cashuA…> --invoice <BOLT11>` (or TUI \
         `/routstr refund token=… invoice=…`) unlocks SeedVault and melts via helper IPC \
         (Paid only). Bare refund without token+invoice has no melt context."
            .to_owned(),
        "Node refund remains the product path for Routstr prepaid float when the network \
         is reachable."
            .to_owned(),
    ]
}

/// Capability-aware refund lines. Live completion only when Cashu reports
/// `refund_live` **and** returns [`crate::cashu::CashuRefundOutcome::Completed`].
///
/// When `refund_live` but bare `refund()` returns Failed because melt needs
/// token+bolt11+seed (Nut04MintCashu), show residual next-steps — not
/// "Routstr refund failed." (capability available ≠ bare refund executed).
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
                // Melt live does not mean bare refund ran — guide product paths.
                if bare_refund_needs_token_context(&e) {
                    let mut lines = vec![
                        "Local CDK melt is available but bare refund has no token context \
                         (needs cashuA… + destination BOLT11 + SeedVault)."
                            .to_owned(),
                        "Use: `grok routstr refund --token <cashuA…> --invoice <BOLT11>` \
                         (or TUI `/routstr refund token=… invoice=…`)."
                            .to_owned(),
                        "Melt never credits Routstr sk- float. No refund was completed.".to_owned(),
                        String::new(),
                    ];
                    lines.extend(refund_residual_next_steps());
                    return lines;
                }
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

    refund_residual_next_steps()
}

/// System-block lines for a receive address: text + optional QR matrix + copy hint.
///
/// Used by TUI fund success / `/routstr qr`. Does **not** invent BOLT11.
/// `include_qr` is ignored when the `qr` feature is off (address-only lines).
///
/// Does **not** claim the clipboard was updated — callers (CLI vs TUI) own
/// copy UX; the shared text only hints the user can copy the address/BIP21.
///
/// When `amount_sats` is `Some`, the QR encodes a BIP21 URI with `amount=`
/// (on-chain only — not a Lightning invoice).
pub fn receive_address_display_lines(address: &str, include_qr: bool) -> Vec<String> {
    receive_address_display_lines_with_amount(address, None, include_qr)
}

/// Like [`receive_address_display_lines`] with optional BIP21 amount (sats).
pub fn receive_address_display_lines_with_amount(
    address: &str,
    amount_sats: Option<u64>,
    include_qr: bool,
) -> Vec<String> {
    let mut lines =
        crate::routstr_invoice::bip21_receive_display_lines(address, amount_sats, include_qr);
    lines.push(
        "Copy the address or BIP21 URI from the lines above (the TUI also attempts a \
         clipboard copy with a toast)."
            .to_owned(),
    );
    lines
}

/// Clipboard payload for an on-chain receive address.
///
/// When `amount_sats` is set, clipboard prefers the BIP21 URI (amount locked).
pub fn receive_address_clipboard(address: &str) -> String {
    receive_address_clipboard_with_amount(address, None)
}

/// Clipboard payload with optional BIP21 amount.
pub fn receive_address_clipboard_with_amount(address: &str, amount_sats: Option<u64>) -> String {
    crate::address_ux::onchain_payment_display(address, amount_sats, Some("Grok OSS Routstr"))
        .clipboard
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
        "Inputs signal RBF (BIP-125). To bump a stuck spend, use `grok routstr rbf` or \
         `/routstr rbf` with original-fee / original-vbytes from this meta and each input \
         line below (same prevouts). Dry-run fee+vB alone is not enough for a true replace-by-fee. \
         To fee-bump via a child (without replacing the parent), use `grok routstr cpfp` or \
         `/routstr cpfp` with parent-fee / parent-vbytes and a wallet-owned parent output as \
         --parent / parent=."
            .to_owned(),
    ]
}

/// Printable `--input txid:vout:amount:address` lines for same-input RBF rebuild.
///
/// Call after prepare so the user can copy prevouts into `grok routstr rbf`.
/// Not secret material (outpoints + amounts + addresses only).
#[cfg(feature = "onchain-address")]
pub fn format_spend_rbf_input_lines(
    inputs: &[crate::descriptor_wallet::WalletUtxo],
) -> Vec<String> {
    if inputs.is_empty() {
        return vec![
            "RBF inputs: (none recorded — cannot rebuild same-input RBF from this prepare)."
                .to_owned(),
        ];
    }
    let mut lines = vec![
        "RBF inputs (pass each line to `grok routstr rbf`; required for stuck-tx replace):"
            .to_owned(),
    ];
    for u in inputs {
        lines.push(format_rbf_input_cli_flag(u));
    }
    lines
}

/// Single CLI flag form: `--input txid:vout:amount_sats:address`.
#[cfg(feature = "onchain-address")]
pub fn format_rbf_input_cli_flag(utxo: &crate::descriptor_wallet::WalletUtxo) -> String {
    format!(
        "  --input {}:{}:{}:{}",
        utxo.outpoint.txid, utxo.outpoint.vout, utxo.amount_sats, utxo.address
    )
}

/// Short clap `about` for `grok routstr utxos` (UTXO list / balance).
pub const UTXOS_CLI_ABOUT: &str =
    "List local wallet UTXOs and on-chain balance (default gap-limit ChainSource sync)";

/// Longer honesty blurb for `grok routstr utxos`.
pub const UTXOS_CLI_LONG_ABOUT: &str = "\
List confirmed/unconfirmed on-chain balance and each UTXO for the local SeedVault wallet. \
Default discovery is gap-limit ChainSource sync (BIP44-style look-ahead). \
Optional prefer-BDK (`GROK_BITCOIN_UTXO_SYNC=bdk`) when the product binary is built with \
feature `bdk` (not default CI) and chain source is esplora or electrum. \
Requires SeedVault unlock + recovery-phrase re-entry (same gate as spend/fund). \
Chain backend via GROK_BITCOIN_CHAIN_SOURCE (default mempool). \
Never invents UTXOs; empty wallet prints zero balance. \
Per-UTXO lines are RBF-friendly `--input` flags for copy into `grok routstr rbf`.";

/// Usage blurb for `grok routstr utxos`.
pub fn utxos_usage_lines() -> Vec<String> {
    vec![
        "Usage:".to_owned(),
        "  grok routstr utxos [--network mainnet|signet|testnet|testnet4]".to_owned(),
        UTXOS_CLI_ABOUT.to_owned(),
        "Default: gap-limit ChainSource sync. Optional GROK_BITCOIN_UTXO_SYNC=bdk when \
         built with feature bdk + esplora|electrum (not default CI). Requires \
         SeedVault unlock + recovery-phrase re-entry."
            .to_owned(),
        "Omit --network to use GROK_BITCOIN_NETWORK (default mainnet). Chain source via \
         GROK_BITCOIN_CHAIN_SOURCE (default mempool)."
            .to_owned(),
    ]
}

/// Pure balance lines from a [`crate::descriptor_wallet::WalletBalance`].
///
/// Never invents amounts — only formats the provided snapshot fields.
#[cfg(feature = "onchain-address")]
pub fn format_utxos_balance_lines(
    balance: &crate::descriptor_wallet::WalletBalance,
    network_label: &str,
) -> Vec<String> {
    let net = network_label.trim();
    let net = if net.is_empty() { "mainnet" } else { net };
    vec![
        format!("On-chain balance ({net}):"),
        format!("  confirmed:   {} sats", balance.confirmed_sats),
        format!("  unconfirmed: {} sats", balance.unconfirmed_sats),
        format!("  total:       {} sats", balance.total_sats()),
    ]
}

/// Pure per-UTXO lines (RBF-friendly `--input` flags when non-empty).
///
/// Empty slice → one honest empty-state line (does not invent coins).
#[cfg(feature = "onchain-address")]
pub fn format_utxos_list_lines(utxos: &[crate::descriptor_wallet::WalletUtxo]) -> Vec<String> {
    if utxos.is_empty() {
        return vec![
            "UTXOs: (none in watched gap window — fund a receive address, or extend may \
             have hit max gap)."
                .to_owned(),
        ];
    }
    let mut lines = vec![format!(
        "UTXOs ({}): RBF-friendly --input lines for `grok routstr rbf`:",
        utxos.len()
    )];
    for u in utxos {
        let conf = if u.confirmations == 0 {
            "unconfirmed".to_owned()
        } else {
            format!("{} conf", u.confirmations)
        };
        let chain = if u.is_change { "change" } else { "receive" };
        lines.push(format!(
            "{}  # {} sats, {conf}, {chain}",
            format_rbf_input_cli_flag(u),
            u.amount_sats
        ));
    }
    lines
}

/// Pure product CLI lines for a gap-sync UTXO snapshot (offline-testable).
///
/// Balance + per-UTXO + shared gap notices ([`crate::descriptor_wallet::gap_sync_spend_notice_lines`]).
/// Never invents balance/UTXO counts — only formats `snap`.
/// **Do not** use for the BDK path — see [`format_bdk_sync_utxos_cli_lines`].
#[cfg(feature = "onchain-address")]
pub fn format_gap_sync_utxos_cli_lines(
    snap: &crate::descriptor_wallet::WalletSyncSnapshot,
    network_label: &str,
) -> Vec<String> {
    let mut lines = format_utxos_balance_lines(&snap.balance, network_label);
    lines.extend(format_utxos_list_lines(&snap.utxos));
    lines.extend(crate::descriptor_wallet::gap_sync_spend_notice_lines(snap));
    lines.push(
        "Gap-limit ChainSource sync only — not full bdk_wallet auto-sync. \
         Snapshot authoritative as of final sync list (no extra list). \
         Prefer-BDK: GROK_BITCOIN_UTXO_SYNC=bdk (feature bdk + esplora|electrum)."
            .to_owned(),
    );
    lines
}

/// Pure product CLI lines for a BDK-sync UTXO snapshot (offline-testable).
///
/// Balance + per-UTXO + BDK notices ([`crate::bdk_sync::bdk_sync_notice_lines`]).
/// Never invents balance/UTXO counts — only formats `snap`.
/// **Do not** use gap-limit residual copy when the BDK path ran.
#[cfg(all(feature = "onchain-address", feature = "bdk"))]
pub fn format_bdk_sync_utxos_cli_lines(
    snap: &crate::descriptor_wallet::WalletSyncSnapshot,
    network_label: &str,
) -> Vec<String> {
    let mut lines = format_utxos_balance_lines(&snap.balance, network_label);
    lines.extend(format_utxos_list_lines(&snap.utxos));
    lines.extend(crate::bdk_sync::bdk_sync_notice_lines(snap));
    lines.push(
        "Snapshot authoritative as of BDK full_scan apply_update (no extra list).".to_owned(),
    );
    lines
}

/// Format one input as the value part of `--input` (no flag prefix).
pub fn format_rbf_input_spec_value(spec: &RbfInputSpec) -> String {
    format!(
        "{}:{}:{}:{}",
        spec.txid, spec.vout, spec.amount_sats, spec.address
    )
}

/// Human lines for an [`crate::descriptor_wallet::RbfFeePlan`].
///
/// When `include_rebuild_hint` is false (already inside an RBF prepare/broadcast
/// flow), omits the trailing “Rebuild with grok routstr rbf / Does not broadcast”
/// sentence that would contradict an in-progress `--broadcast` request.
#[cfg(feature = "onchain-address")]
pub fn format_rbf_fee_plan_lines(plan: &crate::descriptor_wallet::RbfFeePlan) -> Vec<String> {
    format_rbf_fee_plan_lines_inner(plan, true)
}

/// Same as [`format_rbf_fee_plan_lines`] with optional rebuild/broadcast disclaimer.
#[cfg(feature = "onchain-address")]
pub fn format_rbf_fee_plan_lines_inner(
    plan: &crate::descriptor_wallet::RbfFeePlan,
    include_rebuild_hint: bool,
) -> Vec<String> {
    let mut lines = vec![
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
    ];
    if include_rebuild_hint {
        lines.push(
            "  Rebuild with `grok routstr rbf` using the same --input prevouts and this fee plan. \
             Does not broadcast."
                .to_owned(),
        );
    }
    lines
}

/// Human lines for an [`crate::descriptor_wallet::CpfpFeePlan`].
///
/// When `include_rebuild_hint` is false (already inside a CPFP prepare/broadcast
/// flow), omits the trailing “Build with grok routstr cpfp / Does not broadcast”
/// sentence that would contradict an in-progress `--broadcast` request.
#[cfg(feature = "onchain-address")]
pub fn format_cpfp_fee_plan_lines(plan: &crate::descriptor_wallet::CpfpFeePlan) -> Vec<String> {
    format_cpfp_fee_plan_lines_inner(plan, true)
}

/// Same as [`format_cpfp_fee_plan_lines`] with optional rebuild/broadcast disclaimer.
#[cfg(feature = "onchain-address")]
pub fn format_cpfp_fee_plan_lines_inner(
    plan: &crate::descriptor_wallet::CpfpFeePlan,
    include_rebuild_hint: bool,
) -> Vec<String> {
    let mut lines = vec![
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
    ];
    if include_rebuild_hint {
        lines.push(
            "  Child must spend a parent output you control (`--parent` / parent=). Build with \
             `grok routstr cpfp` or `/routstr cpfp`. Does not replace the parent; does not \
             broadcast."
                .to_owned(),
        );
    }
    lines
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

/// Short clap `about` line for `grok routstr fees` (keep in sync with
/// [`fees_usage_lines`] / pager `RoutstrCommand::Fees` — tested for honesty).
pub const FEES_CLI_ABOUT: &str =
    "Print mempool.space recommended fee estimate ladder (sat/vB only)";

/// Longer honesty blurb shared by pure usage lines and clap long_about intent.
///
/// Ladder only — not RBF/CPFP rebuild. Never invents rates when unavailable.
pub const FEES_CLI_LONG_ABOUT: &str = "\
Print the mempool.space recommended fee estimate ladder (sat/vB).
Ladder only — does not rebuild transactions. RBF: `grok routstr rbf` / `/routstr rbf`. \
CPFP: `grok routstr cpfp` / `/routstr cpfp`.
Omit --network to use GROK_BITCOIN_NETWORK (default mainnet). Never invents rates when \
the explorer is unavailable (network error, rate-limit, or parse failure).";

/// Usage blurb for `grok routstr fees` (ladder only — not RBF/CPFP rebuild).
pub fn fees_usage_lines() -> Vec<String> {
    vec![
        "Usage:".to_owned(),
        "  grok routstr fees [--network mainnet|signet|testnet|testnet4]".to_owned(),
        FEES_CLI_ABOUT.to_owned(),
        "Ladder only — does not rebuild transactions. RBF: `grok routstr rbf` / \
         `/routstr rbf`. CPFP: `grok routstr cpfp` / `/routstr cpfp`."
            .to_owned(),
        "Omit --network to use GROK_BITCOIN_NETWORK (default mainnet). Never invents \
         rates when the explorer is unavailable (network error, rate-limit, or parse \
         failure)."
            .to_owned(),
    ]
}

/// Product lines when live fee estimates could not be fetched.
///
/// Covers **any** failure mapped to `None` (HTTP/network error, rate-limit gate,
/// client build failure, JSON parse reject) — not only offline. Does **not**
/// invent a ladder. Mentions product default used by spend/rbf/cpfp when
/// estimates are missing.
pub fn fees_unavailable_lines(network_label: &str) -> Vec<String> {
    let net = network_label.trim();
    let net = if net.is_empty() { "mainnet" } else { net };
    vec![
        format!(
            "Fee estimates unavailable for {net} (explorer fetch failed: network, \
             rate-limit, or invalid response)."
        ),
        "Not inventing rates. Retry later, or pass --fee-rate / fee=<n> on spend, rbf, \
         or cpfp."
            .to_owned(),
        format!(
            "When estimates are missing, product paths fall back to {DEFAULT_SPEND_FEE_RATE_SAT_VB} sat/vB \
             (never 0)."
        ),
        "RBF rebuild: `grok routstr rbf` / `/routstr rbf`. CPFP child: `grok routstr cpfp` / \
         `/routstr cpfp`."
            .to_owned(),
    ]
}

/// halfHour rung annotation for product spend/rbf/cpfp default selection.
///
/// Product [`crate::explorer::resolve_spend_fee_rate_sat_vb`] only uses a live
/// halfHour rate when it is **> 0**; a zero rung is ignored and falls through
/// to [`DEFAULT_SPEND_FEE_RATE_SAT_VB`].
fn half_hour_ladder_label(half_hour_sat_vb: u64) -> String {
    if half_hour_sat_vb > 0 {
        format!("  halfHour: {half_hour_sat_vb} (product default when live)")
    } else {
        format!(
            "  halfHour: {half_hour_sat_vb} (ignored when 0; product falls back to \
             {DEFAULT_SPEND_FEE_RATE_SAT_VB} sat/vB)"
        )
    }
}

/// Product CLI lines for a successful fee-ladder fetch (pure; no network).
///
/// Includes network label and points at RBF/CPFP subcommands without claiming
/// broadcast or rebuild. halfHour is labeled as product default **only** when
/// the rung is > 0 (aligned with estimate resolution).
pub fn format_fees_command_lines(
    est: &crate::explorer::FeeEstimates,
    network_label: &str,
) -> Vec<String> {
    let net = network_label.trim();
    let net = if net.is_empty() { "mainnet" } else { net };
    let mut lines = vec![
        format!("mempool.space fee estimates ({net}, sat/vB):"),
        format!("  fastest: {}", est.fastest_sat_vb),
        half_hour_ladder_label(est.half_hour_sat_vb),
        format!("  hour: {}", est.hour_sat_vb),
        format!("  economy: {}", est.economy_sat_vb),
        format!("  minimum: {}", est.minimum_sat_vb),
        "Use --fee-rate <n> / fee=<n> on spend, rbf, or cpfp to override (must be > 0).".to_owned(),
        "This command prints the ladder only. RBF: `grok routstr rbf`. CPFP: `grok routstr cpfp`."
            .to_owned(),
    ];
    // Keep a stable trailing note aligned with format_fee_estimates_lines consumers.
    lines.push("Source: GET /api/v1/fees/recommended (rate-limited explorer client).".to_owned());
    lines
}

/// Pure product result for `grok routstr fees`: ladder lines or honest unavailable.
///
/// Offline-testable. Callers inject live estimates (or `None` after failed fetch).
pub fn fees_cli_result_lines(
    estimates: Option<&crate::explorer::FeeEstimates>,
    network_label: &str,
) -> Vec<String> {
    match estimates {
        Some(est) => format_fees_command_lines(est, network_label),
        None => fees_unavailable_lines(network_label),
    }
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

/// Product claim for broadcast success: only when broadcast was requested **and**
/// a broadcaster returned a parseable 64-hex txid. Never invents from local prepare.
///
/// Unit-testable without network. Returns `None` for dry-run or invalid/missing txid.
pub fn spend_broadcast_claimed_txid(
    broadcast_requested: bool,
    broadcaster_txid: Option<&str>,
) -> Option<String> {
    if !broadcast_requested {
        return None;
    }
    let t = broadcaster_txid?.trim();
    if !crate::explorer::is_valid_txid_hex(t) {
        return None;
    }
    Some(t.to_ascii_lowercase())
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
        "  grok routstr rbf <address> <sats> --original-fee <sats> --original-vbytes <n> \
         --input <txid:vout:amount:address> [...] [--fee-rate <n>] [--broadcast]"
            .to_owned(),
        "  grok routstr cpfp <address> <sats> --parent-fee <sats> --parent-vbytes <n> \
         --parent <txid:vout:amount:address> [...] [--extra-input <…>] [--fee-rate <n>] \
         [--broadcast]"
            .to_owned(),
        "  /routstr spend <address> <sats> [broadcast] [fee=<n>]".to_owned(),
        "  /routstr rbf <address> <sats> original-fee=<n> original-vbytes=<n> \
         input=<txid:vout:amount:address> [...] [broadcast] [fee=<n>]"
            .to_owned(),
        "  /routstr cpfp <address> <sats> parent-fee=<n> parent-vbytes=<n> \
         parent=<txid:vout:amount:address> [...] [extra-input=<…>] [broadcast] [fee=<n>]"
            .to_owned(),
        "Default is dry-run (build/sign/extract only). SeedVault unlock + recovery-phrase \
         re-entry required; BIP-39 never goes to chat history or CredentialsStore."
            .to_owned(),
        "Optional BIP-39 passphrase: set GROK_BITCOIN_BIP39_PASSPHRASE in the process env \
         at unlock/sign time only (never stored in SeedVault, CredentialsStore, or \
         watch_session). Empty/unset = default path. Do not put the passphrase on CLI/TUI lines."
            .to_owned(),
        "Dry-run shows full signed hex in the CLI summary and TUI system block; CLI also \
         writes the hex alone on stdout for piping. Broadcast-requested path does not dump \
         hex before explorer acceptance; on broadcast failure the signed hex is shown for \
         external broadcast."
            .to_owned(),
        "Fee: omit --fee-rate / fee= to use explorer halfHour estimates when available, else \
         default 5 sat/vB. Print the full ladder with `grok routstr fees`. Inputs signal \
         RBF (BIP-125). To replace a stuck spend, use `grok routstr rbf` or `/routstr rbf` \
         with original-fee/original-vbytes and each input= from the prior dry-run meta \
         (same prevouts; never invents witnesses). To fee-bump without replacing the \
         parent, use `grok routstr cpfp` or `/routstr cpfp` (child spends a wallet-owned \
         parent output)."
            .to_owned(),
        "UTXO discovery default: gap-limit ChainSource. Optional prefer-BDK: \
         GROK_BITCOIN_UTXO_SYNC=bdk when built with feature bdk + esplora|electrum \
         (not default CI; mempool+bdk fails closed). Empty/unset = gap."
            .to_owned(),
    ]
}

/// One original prevout for same-input BIP-125 RBF (no secrets).
///
/// Wire form: `txid:vout:amount_sats:address` (see [`parse_rbf_input_spec`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbfInputSpec {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub address: String,
}

impl RbfInputSpec {
    /// Convert to a [`crate::descriptor_wallet::WalletUtxo`] for prepare.
    #[cfg(feature = "onchain-address")]
    pub fn to_wallet_utxo(&self) -> crate::descriptor_wallet::WalletUtxo {
        crate::descriptor_wallet::WalletUtxo {
            outpoint: crate::descriptor_wallet::OutPointRef::new(self.txid.clone(), self.vout),
            amount_sats: self.amount_sats,
            address: self.address.clone(),
            // Confirmations unused for same-input RBF (inputs are already known).
            confirmations: 0,
            is_change: false,
        }
    }
}

/// Parsed RBF replace request (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbfReplaceRequest {
    pub payment_address: String,
    pub amount_sats: u64,
    /// Absolute fee of the original (stuck) transaction in sats.
    pub original_fee_sats: u64,
    /// Virtual size of the original transaction (from prior prepare meta / weight).
    pub original_vbytes: u64,
    /// Original prevouts for same-input replace (required; at least one).
    pub inputs: Vec<RbfInputSpec>,
    /// When false (product default), build/sign/extract only — do not broadcast.
    pub broadcast: bool,
    pub fee_rate_sat_vb: u64,
    /// True when the user supplied `--fee-rate` (not product default / estimates).
    pub fee_rate_explicit: bool,
}

/// Pure parse errors for RBF replace args.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbfReplaceParseError {
    InvalidFeeRate(String),
    ZeroAmount,
    ZeroOriginalVbytes,
    EmptyAddress,
    /// No `--input` specs (true stuck-tx RBF requires original prevouts).
    MissingInputs,
    /// Malformed `--input txid:vout:amount:address`.
    InvalidInput(String),
    /// TUI/token parse: missing payment address.
    MissingAddress,
    /// TUI/token parse: missing amount.
    MissingAmount,
    /// TUI/token parse: amount not an integer.
    InvalidAmount(String),
    /// TUI/token parse: `original-fee=` omitted.
    MissingOriginalFee,
    /// TUI/token parse: `original-vbytes=` omitted.
    MissingOriginalVbytes,
    /// TUI/token parse: unknown token (fail closed).
    UnknownToken(String),
}

impl std::fmt::Display for RbfReplaceParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFeeRate(s) => write!(f, "invalid fee rate: {s}"),
            Self::ZeroAmount => write!(f, "amount must be > 0 sats"),
            Self::ZeroOriginalVbytes => write!(f, "--original-vbytes must be > 0"),
            Self::EmptyAddress => write!(f, "payment address must not be empty"),
            Self::MissingInputs => write!(
                f,
                "RBF requires at least one --input txid:vout:amount:address \
                 (same prevouts as the stuck tx; from prior spend dry-run meta)"
            ),
            Self::InvalidInput(s) => write!(f, "invalid --input: {s}"),
            Self::MissingAddress => write!(f, "missing payment address"),
            Self::MissingAmount => write!(f, "missing amount in sats"),
            Self::InvalidAmount(s) => write!(f, "invalid amount {s:?} (expected integer sats)"),
            Self::MissingOriginalFee => write!(
                f,
                "missing original-fee=<sats> (absolute fee of the stuck tx)"
            ),
            Self::MissingOriginalVbytes => write!(
                f,
                "missing original-vbytes=<n> (virtual size of the stuck tx)"
            ),
            Self::UnknownToken(s) => write!(
                f,
                "unknown rbf token {s:?} (use original-fee=, original-vbytes=, \
                 input=<txid:vout:amount:address>, broadcast, fee=<sat/vB>)"
            ),
        }
    }
}

/// Parse one `--input` value: `txid:vout:amount_sats:address`.
///
/// `txid` must be 64 hex; `vout` and `amount` decimal integers; address is the
/// remainder after the third colon (bech32 has no colons).
pub fn parse_rbf_input_spec(raw: &str) -> std::result::Result<RbfInputSpec, RbfReplaceParseError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(RbfReplaceParseError::InvalidInput(
            "empty --input (expected txid:vout:amount:address)".into(),
        ));
    }
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() != 4 {
        return Err(RbfReplaceParseError::InvalidInput(format!(
            "expected txid:vout:amount:address, got {raw:?}"
        )));
    }
    let txid = parts[0].trim().to_ascii_lowercase();
    if !crate::explorer::is_valid_txid_hex(&txid) {
        return Err(RbfReplaceParseError::InvalidInput(format!(
            "txid must be 64 hex characters, got len {}",
            txid.len()
        )));
    }
    let vout: u32 = parts[1].trim().parse().map_err(|_| {
        RbfReplaceParseError::InvalidInput(format!("invalid vout {:?}", parts[1].trim()))
    })?;
    let amount_sats: u64 = parts[2].trim().parse().map_err(|_| {
        RbfReplaceParseError::InvalidInput(format!(
            "invalid amount {:?} (expected integer sats)",
            parts[2].trim()
        ))
    })?;
    if amount_sats == 0 {
        return Err(RbfReplaceParseError::InvalidInput(
            "input amount must be > 0 sats".into(),
        ));
    }
    let address = parts[3].trim().to_owned();
    if address.is_empty() {
        return Err(RbfReplaceParseError::InvalidInput(
            "input address must not be empty".into(),
        ));
    }
    Ok(RbfInputSpec {
        txid,
        vout,
        amount_sats,
        address,
    })
}

/// Parse RBF replace args into a [`RbfReplaceRequest`].
///
/// `fee_rate_sat_vb: None` → default rate and `fee_rate_explicit = false`.
/// `Some(n)` with `n > 0` → explicit target rate. `Some(0)` is rejected.
/// `original_fee_sats` may be 0 (BIP-125 still bumps). `original_vbytes` must be > 0.
/// `input_specs` must contain at least one valid `txid:vout:amount:address`.
pub fn parse_rbf_replace_request(
    address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    input_specs: &[String],
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> std::result::Result<RbfReplaceRequest, RbfReplaceParseError> {
    let payment_address = address.trim().to_owned();
    if payment_address.is_empty() {
        return Err(RbfReplaceParseError::EmptyAddress);
    }
    if amount_sats == 0 {
        return Err(RbfReplaceParseError::ZeroAmount);
    }
    if original_vbytes == 0 {
        return Err(RbfReplaceParseError::ZeroOriginalVbytes);
    }
    if input_specs.is_empty() {
        return Err(RbfReplaceParseError::MissingInputs);
    }
    let mut inputs = Vec::with_capacity(input_specs.len());
    let mut seen = std::collections::HashSet::new();
    for raw in input_specs {
        let spec = parse_rbf_input_spec(raw)?;
        let key = (spec.txid.clone(), spec.vout);
        if !seen.insert(key) {
            return Err(RbfReplaceParseError::InvalidInput(format!(
                "duplicate input {}:{}",
                spec.txid, spec.vout
            )));
        }
        inputs.push(spec);
    }
    let fee_rate_explicit = fee_rate_sat_vb.is_some();
    let fee_rate_sat_vb = fee_rate_sat_vb.unwrap_or(DEFAULT_SPEND_FEE_RATE_SAT_VB);
    if fee_rate_sat_vb == 0 {
        return Err(RbfReplaceParseError::InvalidFeeRate(
            "fee rate must be > 0 sat/vB".into(),
        ));
    }
    Ok(RbfReplaceRequest {
        payment_address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        inputs,
        broadcast,
        fee_rate_sat_vb,
        fee_rate_explicit,
    })
}

/// Whether product may attempt network broadcast for this RBF request.
pub fn rbf_wants_broadcast(req: &RbfReplaceRequest) -> bool {
    req.broadcast
}

/// Parse TUI free-form tokens after `rbf`:
/// ```text
/// <address> <sats> original-fee=<n> original-vbytes=<n>
///   input=<txid:vout:amount:address> [...] [broadcast] [fee=<n>]
/// ```
///
/// Address is the first token; amount the second; remaining tokens set flags.
/// Order of optional/required key=value tokens after amount does not matter.
/// Accepts CLI-style `--original-fee=`, `--input=`, etc. Unknown tokens fail
/// closed. **No network I/O** — pure offline parse (fee estimates resolve later
/// at authorize, same as spend).
pub fn parse_rbf_tokens(
    tokens: &[&str],
) -> std::result::Result<RbfReplaceRequest, RbfReplaceParseError> {
    let mut iter = tokens.iter().copied().filter(|t| !t.is_empty());
    let address = iter.next().ok_or(RbfReplaceParseError::MissingAddress)?;
    let amount_raw = iter.next().ok_or(RbfReplaceParseError::MissingAmount)?;
    let amount_sats: u64 = amount_raw
        .parse()
        .map_err(|_| RbfReplaceParseError::InvalidAmount(amount_raw.to_owned()))?;

    let mut broadcast = false;
    let mut fee_rate: Option<u64> = None;
    let mut original_fee: Option<u64> = None;
    let mut original_vbytes: Option<u64> = None;
    let mut input_specs: Vec<String> = Vec::new();

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
            let n: u64 = rest.parse().map_err(|_| {
                RbfReplaceParseError::InvalidFeeRate(format!("not an integer: {rest}"))
            })?;
            fee_rate = Some(n);
            continue;
        }
        // Case-insensitive key match but preserve the value part from the original
        // token so bech32 addresses in input= keep mixed case if present.
        let (key, value) = if let Some(eq) = t.find('=') {
            (&t[..eq], &t[eq + 1..])
        } else {
            return Err(RbfReplaceParseError::UnknownToken(t.to_owned()));
        };
        let key_lower = key.to_ascii_lowercase();
        match key_lower.as_str() {
            "original-fee" | "original_fee" | "--original-fee" => {
                let n: u64 = value.trim().parse().map_err(|_| {
                    RbfReplaceParseError::InvalidInput(format!(
                        "original-fee must be integer sats, got {value:?}"
                    ))
                })?;
                original_fee = Some(n);
            }
            "original-vbytes" | "original_vbytes" | "--original-vbytes" => {
                let n: u64 = value.trim().parse().map_err(|_| {
                    RbfReplaceParseError::InvalidInput(format!(
                        "original-vbytes must be integer, got {value:?}"
                    ))
                })?;
                original_vbytes = Some(n);
            }
            "input" | "--input" => {
                if value.trim().is_empty() {
                    return Err(RbfReplaceParseError::InvalidInput(
                        "empty input= value (expected txid:vout:amount:address)".into(),
                    ));
                }
                input_specs.push(value.trim().to_owned());
            }
            _ => {
                return Err(RbfReplaceParseError::UnknownToken(t.to_owned()));
            }
        }
    }

    let original_fee_sats = original_fee.ok_or(RbfReplaceParseError::MissingOriginalFee)?;
    let original_vbytes = original_vbytes.ok_or(RbfReplaceParseError::MissingOriginalVbytes)?;
    parse_rbf_replace_request(
        address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        &input_specs,
        broadcast,
        fee_rate,
    )
}

/// Lines after a successful local RBF replacement prepare (dry-run default).
#[cfg(feature = "onchain-address")]
pub fn format_rbf_replacement_prepared_lines(
    payment_address: &str,
    payment_sats: u64,
    original_fee_sats: u64,
    replacement_fee_sats: u64,
    change_sats: u64,
    txid: &str,
    raw_hex: &str,
    broadcast: bool,
    plan: &crate::descriptor_wallet::RbfFeePlan,
) -> Vec<String> {
    let mut lines = vec![
        format!("Prepared RBF replacement spend: {payment_sats} sats → {payment_address}"),
        format!(
            "Original fee: {original_fee_sats} sats → replacement fee: {replacement_fee_sats} sats \
             (+{} sats)",
            replacement_fee_sats.saturating_sub(original_fee_sats)
        ),
        format!("Change: {change_sats} sats"),
        format!("Txid (local): {txid}"),
        "Same-input BIP-125 replacement (original prevouts reused; not a fresh coin select)."
            .to_owned(),
    ];
    // Inside prepare/broadcast: omit rebuild disclaimer (avoids contradicting --broadcast).
    lines.extend(format_rbf_fee_plan_lines_inner(plan, false));
    if broadcast {
        lines.push(
            "Broadcast requested — submitting RBF replacement via rate-limited explorer…"
                .to_owned(),
        );
    } else {
        lines.push(
            "Dry-run only (not broadcast). Re-run with --broadcast (CLI) or `broadcast` (TUI) \
             to submit the replacement. The original stuck tx is not cancelled until a \
             higher-fee replacement is accepted."
                .to_owned(),
        );
        lines.extend(format_spend_raw_hex_lines(raw_hex));
    }
    lines
}

/// Usage blurb for `grok routstr rbf` / `/routstr rbf`.
pub fn rbf_usage_lines() -> Vec<String> {
    vec![
        "Usage:".to_owned(),
        "  grok routstr rbf <address> <sats> --original-fee <sats> --original-vbytes <n> \
         --input <txid:vout:amount:address> [...] [--fee-rate <n>] [--broadcast]"
            .to_owned(),
        "  /routstr rbf <address> <sats> original-fee=<n> original-vbytes=<n> \
         input=<txid:vout:amount:address> [...] [broadcast] [fee=<n>]"
            .to_owned(),
        "Rebuilds a BIP-125 same-input RBF replacement (higher absolute fee) that conflicts \
         with the stuck mempool tx. Take original-fee, original-vbytes, and each input from a \
         prior `spend` dry-run meta. Dry-run by default; --broadcast (CLI) or `broadcast` (TUI) \
         only after unlock + re-entry."
            .to_owned(),
        "Omit --fee-rate / fee= to use explorer halfHour estimates when available, else default \
         5 sat/vB; product uses plan recommended absolute fee (not floor-rate re-select). \
         Never claims broadcast without explorer Accepted + parseable txid. BIP-39 never \
         on CLI/TUI lines (SeedVault unlock / `/routstr unlock`). Optional BIP-39 passphrase \
         via GROK_BITCOIN_BIP39_PASSPHRASE at unlock (never persisted)."
            .to_owned(),
    ]
}

/// Parsed CPFP child request (no secrets).
///
/// Wire form for parent/extra matches [`RbfInputSpec`] (`txid:vout:amount:address`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpfpChildRequest {
    pub payment_address: String,
    pub amount_sats: u64,
    /// Absolute fee of the underpaying parent transaction in sats.
    pub parent_fee_sats: u64,
    /// Virtual size of the parent transaction.
    pub parent_vbytes: u64,
    /// Parent output(s) the child must spend (wallet-owned; at least one).
    pub parents: Vec<RbfInputSpec>,
    /// Optional confirmed inputs to fund child fee when parent alone is short.
    pub extra_inputs: Vec<RbfInputSpec>,
    /// When false (product default), build/sign/extract only — do not broadcast.
    pub broadcast: bool,
    pub fee_rate_sat_vb: u64,
    /// True when the user supplied `--fee-rate` (not product default / estimates).
    pub fee_rate_explicit: bool,
}

/// Pure parse errors for CPFP child args.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpfpChildParseError {
    InvalidFeeRate(String),
    ZeroAmount,
    ZeroParentVbytes,
    EmptyAddress,
    /// No `--parent` specs (child must spend parent output).
    MissingParents,
    /// Malformed `--parent` / `--extra-input`.
    InvalidInput(String),
    /// TUI/token parse: missing payment address.
    MissingAddress,
    /// TUI/token parse: missing amount.
    MissingAmount,
    /// TUI/token parse: amount not an integer.
    InvalidAmount(String),
    /// TUI/token parse: `parent-fee=` omitted.
    MissingParentFee,
    /// TUI/token parse: `parent-vbytes=` omitted.
    MissingParentVbytes,
    /// TUI/token parse: unknown token (fail closed).
    UnknownToken(String),
}

impl std::fmt::Display for CpfpChildParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFeeRate(s) => write!(f, "invalid fee rate: {s}"),
            Self::ZeroAmount => write!(f, "amount must be > 0 sats"),
            Self::ZeroParentVbytes => write!(f, "--parent-vbytes must be > 0"),
            Self::EmptyAddress => write!(f, "payment address must not be empty"),
            Self::MissingParents => write!(
                f,
                "CPFP requires at least one --parent txid:vout:amount:address \
                 (wallet-owned output of the stuck parent)"
            ),
            Self::InvalidInput(s) => write!(f, "invalid parent/extra input: {s}"),
            Self::MissingAddress => write!(f, "missing payment address"),
            Self::MissingAmount => write!(f, "missing amount in sats"),
            Self::InvalidAmount(s) => write!(f, "invalid amount {s:?} (expected integer sats)"),
            Self::MissingParentFee => write!(
                f,
                "missing parent-fee=<sats> (absolute fee of the underpaying parent)"
            ),
            Self::MissingParentVbytes => write!(
                f,
                "missing parent-vbytes=<n> (virtual size of the underpaying parent)"
            ),
            Self::UnknownToken(s) => write!(
                f,
                "unknown cpfp token {s:?} (use parent-fee=, parent-vbytes=, \
                 parent=<txid:vout:amount:address>, extra-input=<…>, broadcast, fee=<sat/vB>)"
            ),
        }
    }
}

/// Parse one CPFP parent/extra value (same wire form as RBF `--input`).
pub fn parse_cpfp_input_spec(raw: &str) -> std::result::Result<RbfInputSpec, CpfpChildParseError> {
    parse_rbf_input_spec(raw).map_err(|e| match e {
        RbfReplaceParseError::InvalidInput(s) => CpfpChildParseError::InvalidInput(s),
        other => CpfpChildParseError::InvalidInput(other.to_string()),
    })
}

/// Parse CPFP child args into a [`CpfpChildRequest`].
///
/// `fee_rate_sat_vb: None` → default rate and `fee_rate_explicit = false`.
/// `Some(n)` with `n > 0` → explicit target package rate. `Some(0)` is rejected.
/// `parent_fee_sats` may be 0. `parent_vbytes` must be > 0.
/// `parent_specs` must contain at least one valid `txid:vout:amount:address`.
pub fn parse_cpfp_child_request(
    address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parent_specs: &[String],
    extra_specs: &[String],
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> std::result::Result<CpfpChildRequest, CpfpChildParseError> {
    let payment_address = address.trim().to_owned();
    if payment_address.is_empty() {
        return Err(CpfpChildParseError::EmptyAddress);
    }
    if amount_sats == 0 {
        return Err(CpfpChildParseError::ZeroAmount);
    }
    if parent_vbytes == 0 {
        return Err(CpfpChildParseError::ZeroParentVbytes);
    }
    if parent_specs.is_empty() {
        return Err(CpfpChildParseError::MissingParents);
    }
    let mut seen = std::collections::HashSet::new();
    let mut parents = Vec::with_capacity(parent_specs.len());
    for raw in parent_specs {
        let spec = parse_cpfp_input_spec(raw)?;
        let key = (spec.txid.clone(), spec.vout);
        if !seen.insert(key) {
            return Err(CpfpChildParseError::InvalidInput(format!(
                "duplicate input {}:{}",
                spec.txid, spec.vout
            )));
        }
        parents.push(spec);
    }
    let mut extra_inputs = Vec::with_capacity(extra_specs.len());
    for raw in extra_specs {
        let spec = parse_cpfp_input_spec(raw)?;
        let key = (spec.txid.clone(), spec.vout);
        if !seen.insert(key) {
            return Err(CpfpChildParseError::InvalidInput(format!(
                "duplicate input {}:{}",
                spec.txid, spec.vout
            )));
        }
        extra_inputs.push(spec);
    }
    let fee_rate_explicit = fee_rate_sat_vb.is_some();
    let fee_rate_sat_vb = fee_rate_sat_vb.unwrap_or(DEFAULT_SPEND_FEE_RATE_SAT_VB);
    if fee_rate_sat_vb == 0 {
        return Err(CpfpChildParseError::InvalidFeeRate(
            "fee rate must be > 0 sat/vB".into(),
        ));
    }
    Ok(CpfpChildRequest {
        payment_address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        parents,
        extra_inputs,
        broadcast,
        fee_rate_sat_vb,
        fee_rate_explicit,
    })
}

/// Whether product may attempt network broadcast for this CPFP request.
pub fn cpfp_wants_broadcast(req: &CpfpChildRequest) -> bool {
    req.broadcast
}

/// Parse TUI free-form tokens after `cpfp`:
/// ```text
/// <address> <sats> parent-fee=<n> parent-vbytes=<n>
///   parent=<txid:vout:amount:address> [...] [extra-input=<…>] [broadcast] [fee=<n>]
/// ```
///
/// Address is the first token; amount the second; remaining tokens set flags.
/// Order of optional/required key=value tokens after amount does not matter.
/// Accepts CLI-style `--parent-fee=`, `--parent=`, etc. Unknown tokens fail
/// closed. **No network I/O** — pure offline parse (fee estimates resolve later
/// at authorize, same as spend/rbf).
pub fn parse_cpfp_tokens(
    tokens: &[&str],
) -> std::result::Result<CpfpChildRequest, CpfpChildParseError> {
    let mut iter = tokens.iter().copied().filter(|t| !t.is_empty());
    let address = iter.next().ok_or(CpfpChildParseError::MissingAddress)?;
    let amount_raw = iter.next().ok_or(CpfpChildParseError::MissingAmount)?;
    let amount_sats: u64 = amount_raw
        .parse()
        .map_err(|_| CpfpChildParseError::InvalidAmount(amount_raw.to_owned()))?;

    let mut broadcast = false;
    let mut fee_rate: Option<u64> = None;
    let mut parent_fee: Option<u64> = None;
    let mut parent_vbytes: Option<u64> = None;
    let mut parent_specs: Vec<String> = Vec::new();
    let mut extra_specs: Vec<String> = Vec::new();

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
            let n: u64 = rest.parse().map_err(|_| {
                CpfpChildParseError::InvalidFeeRate(format!("not an integer: {rest}"))
            })?;
            fee_rate = Some(n);
            continue;
        }
        // Case-insensitive key match but preserve the value part from the original
        // token so bech32 addresses in parent=/extra-input= keep mixed case if present.
        let (key, value) = if let Some(eq) = t.find('=') {
            (&t[..eq], &t[eq + 1..])
        } else {
            return Err(CpfpChildParseError::UnknownToken(t.to_owned()));
        };
        let key_lower = key.to_ascii_lowercase();
        match key_lower.as_str() {
            "parent-fee" | "parent_fee" | "--parent-fee" => {
                let n: u64 = value.trim().parse().map_err(|_| {
                    CpfpChildParseError::InvalidInput(format!(
                        "parent-fee must be integer sats, got {value:?}"
                    ))
                })?;
                parent_fee = Some(n);
            }
            "parent-vbytes" | "parent_vbytes" | "--parent-vbytes" => {
                let n: u64 = value.trim().parse().map_err(|_| {
                    CpfpChildParseError::InvalidInput(format!(
                        "parent-vbytes must be integer, got {value:?}"
                    ))
                })?;
                parent_vbytes = Some(n);
            }
            "parent" | "--parent" => {
                if value.trim().is_empty() {
                    return Err(CpfpChildParseError::InvalidInput(
                        "empty parent= value (expected txid:vout:amount:address)".into(),
                    ));
                }
                parent_specs.push(value.trim().to_owned());
            }
            "extra-input" | "extra_input" | "--extra-input" => {
                if value.trim().is_empty() {
                    return Err(CpfpChildParseError::InvalidInput(
                        "empty extra-input= value (expected txid:vout:amount:address)".into(),
                    ));
                }
                extra_specs.push(value.trim().to_owned());
            }
            _ => {
                return Err(CpfpChildParseError::UnknownToken(t.to_owned()));
            }
        }
    }

    let parent_fee_sats = parent_fee.ok_or(CpfpChildParseError::MissingParentFee)?;
    let parent_vbytes = parent_vbytes.ok_or(CpfpChildParseError::MissingParentVbytes)?;
    parse_cpfp_child_request(
        address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        &parent_specs,
        &extra_specs,
        broadcast,
        fee_rate,
    )
}

/// Format one parent as CLI flag form.
#[cfg(feature = "onchain-address")]
pub fn format_cpfp_parent_cli_flag(utxo: &crate::descriptor_wallet::WalletUtxo) -> String {
    format!(
        "  --parent {}:{}:{}:{}",
        utxo.outpoint.txid, utxo.outpoint.vout, utxo.amount_sats, utxo.address
    )
}

/// CPFP-specific fee meta after a successful child prepare.
///
/// Unlike [`format_spend_fee_meta_lines`], this labels **package** target rate vs
/// **child alone** effective rate (and package effective), so a min-relay child
/// under an overpaying parent is not misread as underpay.
///
/// Does not claim broadcast or parent replacement.
#[cfg(feature = "onchain-address")]
pub fn format_cpfp_child_fee_meta_lines(
    parent_fee_sats: u64,
    parent_vbytes: u64,
    child_fee_sats: u64,
    child_vbytes: u64,
    package_target_fee_rate_sat_vb: u64,
) -> Vec<String> {
    let package_fee = parent_fee_sats.saturating_add(child_fee_sats);
    let package_vb = parent_vbytes.saturating_add(child_vbytes);
    let package_eff = crate::descriptor_wallet::effective_fee_rate_sat_vb(package_fee, package_vb);
    let child_eff =
        crate::descriptor_wallet::effective_fee_rate_sat_vb(child_fee_sats, child_vbytes);
    vec![
        format!(
            "CPFP package fee rate: target {package_target_fee_rate_sat_vb} sat/vB; \
             effective ~{package_eff} sat/vB ({package_fee} sats / {package_vb} vB = \
             parent {parent_fee_sats}/{parent_vbytes} + child {child_fee_sats}/{child_vbytes})."
        ),
        format!(
            "Child alone: ~{child_eff} sat/vB ({child_fee_sats} sats / {child_vbytes} vB). \
             Child rate may be low when the parent already overpays the package target."
        ),
        "CPFP does not replace the parent. Inputs still signal RBF (BIP-125) on the child."
            .to_owned(),
    ]
}

/// Lines after a successful local CPFP child prepare (dry-run default).
///
/// Never claims the parent was replaced or cancelled.
#[cfg(feature = "onchain-address")]
pub fn format_cpfp_child_prepared_lines(
    payment_address: &str,
    payment_sats: u64,
    parent_fee_sats: u64,
    child_fee_sats: u64,
    change_sats: u64,
    txid: &str,
    raw_hex: &str,
    broadcast: bool,
    plan: &crate::descriptor_wallet::CpfpFeePlan,
) -> Vec<String> {
    let package_fee = parent_fee_sats.saturating_add(child_fee_sats);
    let mut lines = vec![
        format!("Prepared CPFP child spend: {payment_sats} sats → {payment_address}"),
        format!(
            "Parent fee: {parent_fee_sats} sats; child fee: {child_fee_sats} sats; \
             package fee: {package_fee} sats"
        ),
        format!("Change: {change_sats} sats"),
        format!("Txid (local child): {txid}"),
        "CPFP child (spends parent output; does NOT replace the parent tx). \
         Miners may take parent+child as a package when package rate is high enough."
            .to_owned(),
    ];
    lines.extend(format_cpfp_fee_plan_lines_inner(plan, false));
    if broadcast {
        lines.push(
            "Broadcast requested — submitting CPFP child via rate-limited explorer…".to_owned(),
        );
    } else {
        lines.push(
            "Dry-run only (not broadcast). Re-run with --broadcast (CLI) or `broadcast` (TUI) \
             to submit the child. The parent remains in the mempool until confirmed or dropped; \
             this child does not cancel or replace it."
                .to_owned(),
        );
        lines.extend(format_spend_raw_hex_lines(raw_hex));
    }
    lines
}

/// Usage blurb for `grok routstr cpfp` / `/routstr cpfp`.
pub fn cpfp_usage_lines() -> Vec<String> {
    vec![
        "Usage:".to_owned(),
        "  grok routstr cpfp <address> <sats> --parent-fee <sats> --parent-vbytes <n> \
         --parent <txid:vout:amount:address> [...] [--extra-input <txid:vout:amount:address>] \
         [--fee-rate <n>] [--broadcast]"
            .to_owned(),
        "  /routstr cpfp <address> <sats> parent-fee=<n> parent-vbytes=<n> \
         parent=<txid:vout:amount:address> [...] [extra-input=<…>] [broadcast] [fee=<n>]"
            .to_owned(),
        "Builds a CPFP **child** that spends a wallet-owned parent output so the parent+child \
         package meets the target fee rate. Take parent-fee / parent-vbytes from the stuck \
         parent (or prior prepare meta) and each --parent / parent= from a wallet-owned output \
         of that parent. Optional --extra-input / extra-input= confirmed UTXOs fund the child \
         fee when the parent output alone is short. Dry-run by default; --broadcast (CLI) or \
         `broadcast` (TUI) only after unlock + re-entry."
            .to_owned(),
        "Omit --fee-rate / fee= to use explorer halfHour estimates when available, else default \
         5 sat/vB; product uses plan_cpfp_child_fee minimum absolute child fee (package rate). \
         Never claims the parent was replaced. Never claims broadcast without explorer \
         Accepted + parseable txid. BIP-39 never on CLI/TUI lines (SeedVault unlock / \
         `/routstr unlock`). Optional BIP-39 passphrase via GROK_BITCOIN_BIP39_PASSPHRASE \
         at unlock (never persisted)."
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
    fn bip39_passphrase_active_notice_never_includes_secret_and_fund_flag() {
        let notice = bip39_passphrase_active_notice_lines().join("\n");
        let lower = notice.to_ascii_lowercase();
        assert!(lower.contains("passphrase"));
        // Neutral default: re-supply methods may mention the env var, but must
        // not claim "from GROK_… is active" (modal may have supplied the value).
        assert!(
            !lower.contains("from grok_bitcoin_bip39_passphrase is active"),
            "default notice must not falsely attribute env: {notice}"
        );
        assert!(lower.contains("never stored") || lower.contains("not shown"));
        // Must not look like it embeds a sample secret value.
        assert!(!notice.contains("correct-horse"));
        assert!(!notice.contains("secret-value"));

        let env_notice =
            bip39_passphrase_active_notice_lines_for(Bip39PassphraseNoticeSource::ProcessEnv)
                .join("\n")
                .to_ascii_lowercase();
        assert!(
            env_notice.contains("from grok_bitcoin_bip39_passphrase"),
            "ProcessEnv source must name the env var: {env_notice}"
        );
        let modal_notice =
            bip39_passphrase_active_notice_lines_for(Bip39PassphraseNoticeSource::PrivateModal)
                .join("\n")
                .to_ascii_lowercase();
        assert!(
            modal_notice.contains("private modal"),
            "PrivateModal source must say modal: {modal_notice}"
        );
        assert!(
            !modal_notice.contains("from grok_bitcoin_bip39_passphrase is active"),
            "modal notice must not claim env as source: {modal_notice}"
        );

        let plain =
            format_fund_success_lines("bc1qtest", "showing receive address", "mainnet", true);
        let plain_j = plain.join("\n").to_ascii_lowercase();
        assert!(
            !plain_j.contains("passphrase"),
            "default fund lines omit passphrase note"
        );

        let active = format_fund_success_lines_with_passphrase_flag(
            "bc1qtest",
            "showing receive address",
            "mainnet",
            true,
            true,
        );
        let active_j = active.join("\n").to_ascii_lowercase();
        assert!(
            active_j.contains("passphrase")
                && (active_j.contains("never stored") || active_j.contains("not shown")),
            "active fund lines must warn without echoing secret: {active_j}"
        );
        assert!(
            !active_j.contains("from grok_bitcoin_bip39_passphrase is active"),
            "fund flag notice stays source-neutral: {active_j}"
        );
        assert!(active_j.contains("bc1qtest"));
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
        // Residual points at in-app `grok routstr topup`, never a website.
        assert!(joined.contains("grok routstr topup") || joined.contains("routstr topup"));
        assert!(joined.contains("21000"));
        assert!(!joined.contains("docs.routstr.com"));
        assert!(!joined.contains("invoice created"));
        assert!(!joined.contains("payment sent"));
        assert!(!joined.contains("bolt11:"));
        assert!(!joined.contains("mint invoice ready"));

        let refnd = refund_next_steps_lines().join("\n").to_ascii_lowercase();
        assert!(refnd.contains("grok routstr refund") || refnd.contains("balance/refund"));
        assert!(!refnd.contains("docs.routstr.com"));
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
        assert!(joined.contains("grok routstr topup") || joined.contains("no website"));
        assert!(!joined.contains("docs.routstr.com"));
        assert!(!joined.contains("lnbc"));
        assert!(!joined.contains("invoice ready"));
    }

    #[test]
    fn residual_topup_refund_copy_has_no_website() {
        let top = topup_next_steps_lines(None).join("\n");
        let refnd = refund_next_steps_lines().join("\n");
        assert!(
            !top.to_ascii_lowercase().contains("docs.routstr.com"),
            "topup residual must not mention docs.routstr.com: {top}"
        );
        assert!(
            !refnd.to_ascii_lowercase().contains("docs.routstr.com"),
            "refund residual must not mention docs.routstr.com: {refnd}"
        );
    }

    /// LN backend that advertises live invoices but fails bare create — product
    /// falls through to residual Routstr invoice-first (local receive ≠ float).
    struct LiveInvoiceFailLn;
    impl crate::lightning::LightningCapability for LiveInvoiceFailLn {
        fn capabilities(&self) -> crate::lightning::LightningCapabilities {
            crate::lightning::LightningCapabilities {
                bolt11_pay_live: false,
                bolt11_invoice_live: true,
                bolt12_supported: false,
                channel_open_live: false,
                connect_peer_live: false,
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
    fn topup_live_ln_invoice_failure_falls_through_to_routstr_residual() {
        let lines = topup_next_steps_for_backends(
            &crate::cashu::StubCashu,
            &LiveInvoiceFailLn,
            Some(21_000),
        );
        let joined = lines.join("\n").to_ascii_lowercase();
        // Primary float path remains Routstr node invoice-first.
        assert!(
            joined.contains("grok routstr topup") || joined.contains("no website"),
            "expected residual Routstr topup path: {joined}"
        );
        assert!(
            !joined.contains("not wired yet"),
            "must not claim residual stub wording: {joined}"
        );
        assert!(!joined.contains("lnbc"));
        assert!(!joined.contains("docs.routstr.com"));
    }

    /// Cashu backend with live mint that returns a real-shaped invoice (flip-path proof).
    struct LiveMintOkCashu;
    impl crate::cashu::CashuBackend for LiveMintOkCashu {
        fn capabilities(&self) -> crate::cashu::CashuCapabilities {
            crate::cashu::CashuCapabilities {
                mint_live: true,
                proofs_mint_live: false,
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

    /// Cashu mint live but Failed — honest failure + fall through to P0 residual.
    struct LiveMintFailCashu;
    impl crate::cashu::CashuBackend for LiveMintFailCashu {
        fn capabilities(&self) -> crate::cashu::CashuCapabilities {
            crate::cashu::CashuCapabilities {
                mint_live: true,
                proofs_mint_live: false,
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
                proofs_mint_live: false,
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
                proofs_mint_live: false,
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
                channel_open_live: false,
                connect_peer_live: false,
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
    fn topup_live_cashu_mint_success_emits_quote_honest_copy() {
        let lines = topup_next_steps_for_backends(
            &LiveMintOkCashu,
            &crate::lightning::StubLightning,
            Some(21_000),
        );
        let joined = lines.join("\n");
        let lower = joined.to_ascii_lowercase();
        assert!(
            lower.contains("mint quote") || lower.contains("nut-04"),
            "live mint success must name mint quote: {joined}"
        );
        assert!(
            lower.contains("not a routstr node invoice")
                || lower.contains("pays the mint for a quote"),
            "must not claim Routstr float from mint pay alone: {joined}"
        );
        assert!(
            lower.contains("proofs") || lower.contains("residual"),
            "must note proofs→token residual: {joined}"
        );
        assert!(
            lower.contains("redeem") || lower.contains("cashua"),
            "must point at redeem for cashuA: {joined}"
        );
        assert!(
            lower.contains("grok routstr topup"),
            "must still offer P0 node topup for float: {joined}"
        );
        // Must not claim float is ready after pay alone.
        assert!(
            !lower.contains("pay the invoice, then `grok routstr balance`")
                && !lower.contains("verify float"),
            "must not claim balance/float after mint pay alone: {joined}"
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
    fn topup_live_cashu_mint_failure_falls_through_to_routstr_residual() {
        let lines = topup_next_steps_for_backends(
            &LiveMintFailCashu,
            &crate::lightning::StubLightning,
            Some(100),
        );
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(
            joined.contains("failed") || joined.contains("no mint quote"),
            "expected mint failure wording: {joined}"
        );
        assert!(
            joined.contains("grok routstr topup") || joined.contains("no website"),
            "mint fail must fall through to Routstr float path: {joined}"
        );
        assert!(
            !joined.contains("not wired yet"),
            "must not claim residual stub when mint_live: {joined}"
        );
        assert!(!joined.contains("lnbc"));
        // Local LDK "invoice ready" only on Created — not on mint fail residual.
        assert!(!joined.contains("local lightning receive invoice ready"));
        assert!(!joined.contains("docs.routstr.com"));
    }

    #[test]
    fn topup_live_ln_invoice_success_emits_bolt11() {
        let lines =
            topup_next_steps_for_backends(&crate::cashu::StubCashu, &LiveInvoiceOkLn, Some(100));
        let joined = lines.join("\n");
        let lower = joined.to_ascii_lowercase();
        assert!(
            lower.contains("local") && lower.contains("invoice ready"),
            "live LN invoice must claim local ready: {joined}"
        );
        assert!(joined.contains("lnbc100n1ptestlocal-test"));
        assert!(
            lower.contains("does not fund routstr") || lower.contains("routstr topup"),
            "must clarify local ≠ Routstr float: {joined}"
        );
        assert!(!lower.contains("not wired yet"));
        assert!(!lower.contains("docs.routstr.com"));
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

    /// Cashu melt capability live but bare refund needs token+bolt11 — not
    /// "Routstr refund failed." (product next-steps must stay residual-style).
    struct LiveRefundNeedsTokenContextCashu;
    impl crate::cashu::CashuBackend for LiveRefundNeedsTokenContextCashu {
        fn capabilities(&self) -> crate::cashu::CashuCapabilities {
            crate::cashu::CashuCapabilities {
                mint_live: true,
                proofs_mint_live: true,
                spend_live: true,
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
                "CDK melt requires cashuA token + destination BOLT11 + SeedVault \
                 (use melt_token_to_bolt11_with_seed); bare refund has no token context. \
                 For Routstr node float use `grok routstr refund`."
                    .into(),
            ))
        }
    }

    #[test]
    fn refund_live_bare_token_context_is_residual_not_failed_headline() {
        let lines = refund_next_steps_for_backend(&LiveRefundNeedsTokenContextCashu);
        let joined = lines.join("\n");
        let lower = joined.to_ascii_lowercase();
        assert!(
            !lower.contains("routstr refund failed"),
            "token-context bare refund must not headline as executed failure: {joined}"
        );
        assert!(
            lower.contains("token context")
                || lower.contains("melt_token_to_bolt11")
                || lower.contains("--token")
                || lower.contains("invoice"),
            "must explain bare refund needs token: {joined}"
        );
        assert!(
            lower.contains("grok routstr refund") || lower.contains("balance/refund"),
            "must still prefer node refund path: {joined}"
        );
        assert!(!lower.contains("refund completed"));
        assert!(
            lower.contains("no refund was completed"),
            "honest: nothing completed: {joined}"
        );
    }

    #[test]
    fn default_backends_are_honest_stubs() {
        let cashu = crate::cashu::default_cashu_backend();
        let ln = crate::lightning::default_lightning_backend();
        let c = crate::cashu::CashuBackend::capabilities(&cashu);
        let l = crate::lightning::LightningCapability::capabilities(&ln);
        assert!(!c.mint_live && !c.spend_live && !c.refund_live);
        // Feature `ldk` → LdkLightning claims bolt11_pay_live (IPC helper).
        // Default CI (no feature) → stub keeps pay live false.
        #[cfg(feature = "ldk")]
        assert!(
            l.bolt11_pay_live,
            "feature ldk default LN backend must claim live BOLT11 pay"
        );
        #[cfg(not(feature = "ldk"))]
        assert!(!l.bolt11_pay_live);
        #[cfg(feature = "ldk")]
        assert!(
            l.bolt11_invoice_live,
            "feature ldk default LN backend must claim live BOLT11 invoice create"
        );
        #[cfg(not(feature = "ldk"))]
        assert!(!l.bolt11_invoice_live);
        assert!(!l.bolt12_supported);
        // Residual topup copy (invoice-first): bare LDK create needs SeedVault so
        // product falls through to Routstr node path (no fabricated lnbc).
        let top = topup_next_steps_lines(None).join("\n").to_ascii_lowercase();
        assert!(top.contains("grok routstr topup") || top.contains("no website"));
        assert!(!top.contains("docs.routstr.com"));
        assert!(!top.contains("lnbc"));
        let refnd = refund_next_steps_lines().join("\n").to_ascii_lowercase();
        assert!(refnd.contains("grok routstr refund") || refnd.contains("balance/refund"));
        assert!(!refnd.contains("docs.routstr.com"));
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

    #[test]
    fn fees_cli_result_lines_ladder_or_unavailable() {
        let est = crate::explorer::FeeEstimates {
            fastest_sat_vb: 20,
            half_hour_sat_vb: 15,
            hour_sat_vb: 10,
            economy_sat_vb: 5,
            minimum_sat_vb: 1,
        };
        let ok = fees_cli_result_lines(Some(&est), "signet").join("\n");
        let ok_l = ok.to_ascii_lowercase();
        assert!(ok.contains("fastest: 20"));
        assert!(ok.contains("halfHour: 15"));
        assert!(
            ok_l.contains("product default when live"),
            "halfHour > 0 must be labeled product default: {ok}"
        );
        assert!(ok_l.contains("signet"));
        assert!(ok_l.contains("ladder only") || ok_l.contains("rbf"));
        assert!(ok_l.contains("cpfp"));
        assert!(!ok_l.contains("crypto"));
        assert!(!ok_l.contains("broadcast accepted"));

        let miss = fees_cli_result_lines(None, "mainnet").join("\n");
        let miss_l = miss.to_ascii_lowercase();
        assert!(miss_l.contains("unavailable") || miss_l.contains("not inventing"));
        assert!(miss_l.contains("mainnet"));
        assert!(miss_l.contains(&format!("{DEFAULT_SPEND_FEE_RATE_SAT_VB}")));
        // Broad failure modes — not only "network unreachable".
        assert!(
            miss_l.contains("rate-limit") || miss_l.contains("rate limit"),
            "unavailable copy must cover rate-limit, not only reachability: {miss}"
        );
        assert!(
            miss_l.contains("retry later") || miss_l.contains("retry"),
            "unavailable copy should invite retry without implying only offline: {miss}"
        );
        // Must not invent a fake ladder of rates when fetch failed.
        assert!(!miss_l.contains("fastest:"));
        assert!(!miss_l.contains("crypto"));
    }

    #[test]
    fn fees_command_zero_half_hour_not_labeled_product_default() {
        let est = crate::explorer::FeeEstimates {
            fastest_sat_vb: 10,
            half_hour_sat_vb: 0,
            hour_sat_vb: 5,
            economy_sat_vb: 2,
            minimum_sat_vb: 1,
        };
        let lines = format_fees_command_lines(&est, "mainnet").join("\n");
        let lower = lines.to_ascii_lowercase();
        assert!(lines.contains("halfHour: 0"));
        assert!(
            !lower.contains("product default when live"),
            "zero halfHour must not claim product default: {lines}"
        );
        assert!(
            lower.contains("ignored") && lower.contains("fall"),
            "zero halfHour must note product fallback: {lines}"
        );
        assert!(lower.contains(&format!("{DEFAULT_SPEND_FEE_RATE_SAT_VB}")));
    }

    #[test]
    fn fees_usage_mentions_ladder_only_not_rbf_rebuild() {
        let usage = fees_usage_lines().join("\n").to_ascii_lowercase();
        assert!(usage.contains("fees"));
        assert!(usage.contains("ladder") || usage.contains("estimate"));
        assert!(usage.contains("rbf"));
        assert!(usage.contains("cpfp"));
        assert!(usage.contains("network") || usage.contains("mainnet"));
        assert!(usage.contains("unavailable") || usage.contains("never invents"));
        assert!(!usage.contains("crypto"));
        // Fees is not a rebuild/broadcast path.
        assert!(!usage.contains("--broadcast"));
        // Shared about constants stay aligned with usage honesty.
        assert!(FEES_CLI_ABOUT.to_ascii_lowercase().contains("ladder"));
        assert!(!FEES_CLI_ABOUT.to_ascii_lowercase().contains("broadcast"));
        let long = FEES_CLI_LONG_ABOUT.to_ascii_lowercase();
        assert!(long.contains("ladder"));
        assert!(long.contains("never invents"));
        assert!(long.contains("rbf") && long.contains("cpfp"));
        assert!(!long.contains("broadcast"));
    }

    #[test]
    fn fees_unavailable_empty_network_defaults_mainnet() {
        let lines = fees_unavailable_lines("  ").join("\n").to_ascii_lowercase();
        assert!(lines.contains("mainnet"));
        assert!(lines.contains("not inventing") || lines.contains("unavailable"));
        assert!(
            lines.contains("rate-limit") || lines.contains("rate limit"),
            "must not imply only network reachability: {lines}"
        );
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
        assert!(rbf_j.contains("grok routstr rbf") || rbf_j.contains("rbf"));

        let cpfp = cpfp_fee_guidance_lines(200, 200, 1, 10).unwrap();
        let cpfp_j = cpfp.join("\n").to_ascii_lowercase();
        assert!(cpfp_j.contains("cpfp"));
        assert!(cpfp_j.contains("minimum child fee"));
        assert!(
            cpfp_j.contains("grok routstr cpfp") || cpfp_j.contains("does not replace"),
            "{cpfp_j}"
        );
        assert!(meta_j.contains("cpfp") || meta_j.contains("parent"));

        assert!(rbf_fee_bump_guidance_lines(100, 0, 10).is_err());
        assert!(cpfp_fee_guidance_lines(100, 100, 1, 0).is_err());
    }

    #[test]
    fn spend_usage_mentions_rbf_and_fee_estimates() {
        let usage = spend_usage_lines().join("\n").to_ascii_lowercase();
        assert!(usage.contains("rbf") || usage.contains("bip-125"));
        assert!(usage.contains("fee"));
        assert!(usage.contains("routstr rbf"));
        assert!(usage.contains("routstr cpfp"));
        assert!(usage.contains("routstr fees"));
        assert!(
            usage.contains("grok_bitcoin_bip39_passphrase"),
            "usage should document optional passphrase env: {usage}"
        );
        // Prefer-BDK opt-in honesty (same env as utxos / shell spend branch).
        assert!(
            usage.contains("utxo_sync") || usage.contains("bdk"),
            "usage should document prefer-BDK opt-in: {usage}"
        );
        assert!(
            usage.contains("gap") || usage.contains("default"),
            "usage should note default gap-limit: {usage}"
        );
        assert!(!usage.contains("crypto"));
    }

    fn sample_rbf_input() -> String {
        format!("{}:0:100000:bc1qrecv", "ab".repeat(32))
    }

    #[test]
    fn parse_rbf_input_spec_roundtrip() {
        let raw = sample_rbf_input();
        let spec = parse_rbf_input_spec(&raw).unwrap();
        assert_eq!(spec.txid, "ab".repeat(32));
        assert_eq!(spec.vout, 0);
        assert_eq!(spec.amount_sats, 100_000);
        assert_eq!(spec.address, "bc1qrecv");
        assert_eq!(format_rbf_input_spec_value(&spec), raw);

        assert!(matches!(
            parse_rbf_input_spec("short:0:1:bc1q").unwrap_err(),
            RbfReplaceParseError::InvalidInput(_)
        ));
        assert!(matches!(
            parse_rbf_input_spec(&format!("{}:x:1:bc1q", "ab".repeat(32))).unwrap_err(),
            RbfReplaceParseError::InvalidInput(_)
        ));
        assert!(matches!(
            parse_rbf_input_spec(&format!("{}:0:0:bc1q", "ab".repeat(32))).unwrap_err(),
            RbfReplaceParseError::InvalidInput(_)
        ));
    }

    #[test]
    fn parse_rbf_replace_request_explicit_and_default() {
        let inputs = vec![sample_rbf_input()];
        let req =
            parse_rbf_replace_request("bc1qdest", 21_000, 705, 141, &inputs, false, None).unwrap();
        assert_eq!(req.payment_address, "bc1qdest");
        assert_eq!(req.amount_sats, 21_000);
        assert_eq!(req.original_fee_sats, 705);
        assert_eq!(req.original_vbytes, 141);
        assert_eq!(req.inputs.len(), 1);
        assert!(!req.broadcast);
        assert!(!req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, DEFAULT_SPEND_FEE_RATE_SAT_VB);

        let req =
            parse_rbf_replace_request("bc1qdest", 100, 500, 100, &inputs, true, Some(20)).unwrap();
        assert!(req.broadcast);
        assert!(req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, 20);
        assert!(rbf_wants_broadcast(&req));
    }

    #[test]
    fn parse_rbf_replace_rejects_zero_and_empty() {
        let inputs = vec![sample_rbf_input()];
        assert_eq!(
            parse_rbf_replace_request("", 100, 50, 100, &inputs, false, None).unwrap_err(),
            RbfReplaceParseError::EmptyAddress
        );
        assert_eq!(
            parse_rbf_replace_request("bc1q", 0, 50, 100, &inputs, false, None).unwrap_err(),
            RbfReplaceParseError::ZeroAmount
        );
        assert_eq!(
            parse_rbf_replace_request("bc1q", 100, 50, 0, &inputs, false, None).unwrap_err(),
            RbfReplaceParseError::ZeroOriginalVbytes
        );
        assert_eq!(
            parse_rbf_replace_request("bc1q", 100, 50, 100, &[], false, None).unwrap_err(),
            RbfReplaceParseError::MissingInputs
        );
        assert!(matches!(
            parse_rbf_replace_request("bc1q", 100, 50, 100, &inputs, false, Some(0)).unwrap_err(),
            RbfReplaceParseError::InvalidFeeRate(_)
        ));
        // original_fee_sats = 0 is allowed (plan still bumps).
        let req = parse_rbf_replace_request("bc1q", 100, 0, 100, &inputs, false, Some(5)).unwrap();
        assert_eq!(req.original_fee_sats, 0);
        // duplicate inputs rejected
        let dup = vec![sample_rbf_input(), sample_rbf_input()];
        assert!(matches!(
            parse_rbf_replace_request("bc1q", 100, 50, 100, &dup, false, None).unwrap_err(),
            RbfReplaceParseError::InvalidInput(_)
        ));
    }

    #[test]
    fn parse_rbf_tokens_dry_run_default_and_broadcast() {
        let inp = sample_rbf_input();
        let input_tok = format!("input={inp}");
        let req = parse_rbf_tokens(&[
            "bc1qdest",
            "21000",
            "original-fee=705",
            "original-vbytes=141",
            &input_tok,
        ])
        .unwrap();
        assert_eq!(req.payment_address, "bc1qdest");
        assert_eq!(req.amount_sats, 21_000);
        assert_eq!(req.original_fee_sats, 705);
        assert_eq!(req.original_vbytes, 141);
        assert_eq!(req.inputs.len(), 1);
        assert!(!req.broadcast);
        assert!(!req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, DEFAULT_SPEND_FEE_RATE_SAT_VB);

        let req = parse_rbf_tokens(&[
            "bc1qdest",
            "100",
            "original_fee=500",
            "--original-vbytes=100",
            &format!("--input={inp}"),
            "broadcast",
            "fee=20",
        ])
        .unwrap();
        assert!(req.broadcast);
        assert!(req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, 20);
        assert_eq!(req.original_fee_sats, 500);
        assert_eq!(req.original_vbytes, 100);
    }

    #[test]
    fn parse_rbf_tokens_rejects_fee_zero_missing_inputs_zero_vbytes() {
        let inp = sample_rbf_input();
        let input_tok = format!("input={inp}");
        // Explicit fee=0 is rejected offline (parity with spend fee=0).
        assert!(matches!(
            parse_rbf_tokens(&[
                "bc1qdest",
                "100",
                "original-fee=50",
                "original-vbytes=100",
                &input_tok,
                "fee=0",
            ])
            .unwrap_err(),
            RbfReplaceParseError::InvalidFeeRate(_)
        ));
        // Missing inputs.
        assert_eq!(
            parse_rbf_tokens(&["bc1qdest", "100", "original-fee=50", "original-vbytes=100",])
                .unwrap_err(),
            RbfReplaceParseError::MissingInputs
        );
        // Zero original-vbytes.
        assert_eq!(
            parse_rbf_tokens(&[
                "bc1qdest",
                "100",
                "original-fee=50",
                "original-vbytes=0",
                &input_tok,
            ])
            .unwrap_err(),
            RbfReplaceParseError::ZeroOriginalVbytes
        );
        // Missing original-fee / original-vbytes.
        assert_eq!(
            parse_rbf_tokens(&["bc1qdest", "100", "original-vbytes=100", &input_tok]).unwrap_err(),
            RbfReplaceParseError::MissingOriginalFee
        );
        assert_eq!(
            parse_rbf_tokens(&["bc1qdest", "100", "original-fee=50", &input_tok]).unwrap_err(),
            RbfReplaceParseError::MissingOriginalVbytes
        );
        // original_fee=0 allowed when vbytes/inputs present.
        let req = parse_rbf_tokens(&[
            "bc1qdest",
            "100",
            "original-fee=0",
            "original-vbytes=100",
            &input_tok,
            "fee=5",
        ])
        .unwrap();
        assert_eq!(req.original_fee_sats, 0);
        // Unknown token fail closed.
        assert!(matches!(
            parse_rbf_tokens(&[
                "bc1qdest",
                "100",
                "original-fee=50",
                "original-vbytes=100",
                &input_tok,
                "typo-flag",
            ])
            .unwrap_err(),
            RbfReplaceParseError::UnknownToken(_)
        ));
        // Missing address / amount / zero amount.
        assert_eq!(
            parse_rbf_tokens(&[]).unwrap_err(),
            RbfReplaceParseError::MissingAddress
        );
        assert_eq!(
            parse_rbf_tokens(&["bc1qdest"]).unwrap_err(),
            RbfReplaceParseError::MissingAmount
        );
        assert_eq!(
            parse_rbf_tokens(&[
                "bc1qdest",
                "0",
                "original-fee=50",
                "original-vbytes=100",
                &input_tok,
            ])
            .unwrap_err(),
            RbfReplaceParseError::ZeroAmount
        );
    }

    #[test]
    fn spend_broadcast_claimed_txid_only_on_accepted() {
        let good = "ab".repeat(32);
        assert_eq!(
            spend_broadcast_claimed_txid(true, Some(&good)).as_deref(),
            Some(good.as_str())
        );
        assert_eq!(spend_broadcast_claimed_txid(false, Some(&good)), None);
        assert_eq!(spend_broadcast_claimed_txid(true, None), None);
        assert_eq!(spend_broadcast_claimed_txid(true, Some("not-a-txid")), None);
        assert_eq!(spend_broadcast_claimed_txid(true, Some("")), None);
    }

    #[cfg(feature = "onchain-address")]
    #[test]
    fn format_rbf_replacement_prepared_lines_dry_run_and_broadcast() {
        let plan = crate::descriptor_wallet::plan_rbf_fee_bump(705, 141, 15, 0).unwrap();
        let hex = "deadbeef";
        let dry = format_rbf_replacement_prepared_lines(
            "bc1qdest",
            25_000,
            705,
            plan.recommended_fee_sats,
            70_000,
            "aa".repeat(32).as_str(),
            hex,
            false,
            &plan,
        );
        let dry_j = dry.join("\n").to_ascii_lowercase();
        assert!(dry_j.contains("rbf replacement"));
        assert!(dry_j.contains("dry-run"));
        assert!(dry_j.contains(hex));
        assert!(!dry_j.contains("broadcast accepted"));
        // CLI/TUI parity with spend dry-run guidance.
        assert!(
            dry_j.contains("--broadcast"),
            "dry-run must mention CLI --broadcast: {dry_j}"
        );
        assert!(
            dry_j.contains("tui") && dry_j.contains("broadcast"),
            "dry-run must mention TUI broadcast path: {dry_j}"
        );
        assert!(
            dry_j.contains("cli"),
            "dry-run must label --broadcast as CLI: {dry_j}"
        );
        assert!(dry.iter().any(|l| is_spend_raw_hex_output_line(l, hex)));

        let live = format_rbf_replacement_prepared_lines(
            "bc1qdest",
            25_000,
            705,
            plan.recommended_fee_sats,
            70_000,
            "bb".repeat(32).as_str(),
            hex,
            true,
            &plan,
        );
        let live_j = live.join("\n").to_ascii_lowercase();
        assert!(live_j.contains("broadcast requested"));
        // Broadcast path must not dump hex before accept.
        assert!(!live.iter().any(|l| l == hex));
        // Plan rebuild disclaimer must not appear inside prepared (broadcast) flow.
        assert!(
            !live_j.contains("does not broadcast"),
            "rebuild disclaimer should be omitted inside rbf prepare: {live_j}"
        );
        assert!(live_j.contains("same-input"));
    }

    #[test]
    fn rbf_usage_mentions_original_fee_and_dry_run() {
        let usage = rbf_usage_lines().join("\n").to_ascii_lowercase();
        assert!(usage.contains("original-fee"));
        assert!(usage.contains("original-vbytes"));
        assert!(usage.contains("--input") || usage.contains("input"));
        assert!(usage.contains("dry-run") || usage.contains("broadcast"));
        assert!(
            usage.contains("grok_bitcoin_bip39_passphrase"),
            "usage should document optional passphrase env: {usage}"
        );
        // CLI + TUI surfaces (parity with spend_usage_lines).
        assert!(
            usage.contains("grok routstr rbf"),
            "CLI usage line missing: {usage}"
        );
        assert!(
            usage.contains("/routstr rbf"),
            "TUI usage line missing: {usage}"
        );
        assert!(
            usage.contains("fee=") || usage.contains("[fee="),
            "TUI fee= form should appear in usage: {usage}"
        );
        assert!(!usage.contains("crypto"));
        assert!(!usage.contains("bip-39 on cli") || usage.contains("never"));
    }

    #[cfg(feature = "onchain-address")]
    #[test]
    fn format_spend_rbf_input_lines_emits_cli_flags() {
        let utxo = crate::descriptor_wallet::WalletUtxo {
            outpoint: crate::descriptor_wallet::OutPointRef::new("ab".repeat(32), 1),
            amount_sats: 50_000,
            address: "bc1qtest".into(),
            confirmations: 3,
            is_change: false,
        };
        let lines = format_spend_rbf_input_lines(&[utxo]);
        let j = lines.join("\n");
        assert!(j.contains("--input"));
        assert!(j.contains(&"ab".repeat(32)));
        assert!(j.contains(":1:50000:bc1qtest"));
    }

    /// Pure utxos CLI formatter: balance + RBF flags + gap notices (mock snapshot).
    #[cfg(feature = "onchain-address")]
    #[test]
    fn format_gap_sync_utxos_cli_lines_balance_and_inputs() {
        use crate::descriptor_wallet::{
            OutPointRef, WalletBalance, WalletSyncSnapshot, WalletUtxo,
        };

        let utxo = WalletUtxo {
            outpoint: OutPointRef::new("ab".repeat(32), 2),
            amount_sats: 21_000,
            address: "bc1qrecv".into(),
            confirmations: 6,
            is_change: false,
        };
        let snap = WalletSyncSnapshot {
            utxos: vec![utxo],
            balance: WalletBalance {
                confirmed_sats: 21_000,
                unconfirmed_sats: 0,
            },
            receive_gap: 20,
            change_gap: 20,
            highest_used_receive: Some(0),
            highest_used_change: None,
            extended_receive_by: 0,
            extended_change_by: 0,
            hit_max_gap: false,
        };
        let lines = format_gap_sync_utxos_cli_lines(&snap, "signet");
        let j = lines.join("\n");
        let lower = j.to_ascii_lowercase();
        assert!(j.contains("signet"));
        assert!(
            j.contains("21000")
                || j.contains("21_000")
                || j.contains("21,000")
                || j.contains("21 000")
                || j.contains("confirmed")
        );
        assert!(j.contains("confirmed:"));
        assert!(j.contains("unconfirmed:"));
        assert!(j.contains("total:"));
        assert!(j.contains("--input"));
        assert!(j.contains(&"ab".repeat(32)));
        assert!(j.contains(":2:21000:bc1qrecv") || j.contains("21000"));
        assert!(lower.contains("gap-limit") || lower.contains("not full"));
        // Quiet snapshot: no extend / hit-max notices.
        assert!(!lower.contains("gap extended"));
        assert!(!lower.contains("stopped at max"));
        assert!(!lower.contains("crypto"));
    }

    #[cfg(feature = "onchain-address")]
    #[test]
    fn format_gap_sync_utxos_cli_lines_empty_and_notices() {
        use crate::descriptor_wallet::{WalletBalance, WalletSyncSnapshot};

        let empty = WalletSyncSnapshot {
            utxos: vec![],
            balance: WalletBalance::default(),
            receive_gap: 20,
            change_gap: 20,
            highest_used_receive: None,
            highest_used_change: None,
            extended_receive_by: 0,
            extended_change_by: 0,
            hit_max_gap: false,
        };
        let empty_j = format_gap_sync_utxos_cli_lines(&empty, "mainnet").join("\n");
        let empty_l = empty_j.to_ascii_lowercase();
        assert!(empty_l.contains("none") || empty_l.contains("0 sats"));
        assert!(empty_l.contains("confirmed"));
        assert!(!empty_l.contains("--input"));

        let hit = WalletSyncSnapshot {
            utxos: vec![],
            balance: WalletBalance::default(),
            receive_gap: 200,
            change_gap: 20,
            highest_used_receive: Some(199),
            highest_used_change: None,
            extended_receive_by: 10,
            extended_change_by: 0,
            hit_max_gap: true,
        };
        let hit_j = format_gap_sync_utxos_cli_lines(&hit, "mainnet").join("\n");
        let hit_l = hit_j.to_ascii_lowercase();
        assert!(hit_l.contains("extended") || hit_l.contains("gap extend"));
        assert!(hit_l.contains("max"));
        assert!(!hit_l.contains("crypto"));
    }

    /// BDK CLI formatter must use BDK notice copy, never gap-limit residual.
    #[cfg(all(feature = "onchain-address", feature = "bdk"))]
    #[test]
    fn format_bdk_sync_utxos_cli_lines_uses_bdk_notices() {
        use crate::descriptor_wallet::{
            OutPointRef, WalletBalance, WalletSyncSnapshot, WalletUtxo,
        };

        let utxo = WalletUtxo {
            outpoint: OutPointRef::new("ef".repeat(32), 0),
            amount_sats: 9_000,
            address: "bc1qbdk".into(),
            confirmations: 2,
            is_change: false,
        };
        let snap = WalletSyncSnapshot {
            utxos: vec![utxo],
            balance: WalletBalance {
                confirmed_sats: 9_000,
                unconfirmed_sats: 0,
            },
            receive_gap: 1,
            change_gap: 1,
            highest_used_receive: Some(0),
            highest_used_change: None,
            extended_receive_by: 1,
            extended_change_by: 0,
            hit_max_gap: false,
        };
        let lines = format_bdk_sync_utxos_cli_lines(&snap, "signet");
        let j = lines.join("\n");
        let lower = j.to_ascii_lowercase();
        assert!(j.contains("signet"));
        assert!(j.contains("9000") || j.contains("confirmed"));
        assert!(j.contains("--input"));
        assert!(lower.contains("bdk"), "must label BDK path: {j}");
        // Gap residual says "Gap-limit ChainSource sync only — not full bdk…".
        // BDK notice may say "not gap-limit ChainSource" (honest contrast) — allow that.
        assert!(
            !lower.contains("gap-limit chainsource sync only")
                && !lower.contains("not full bdk_wallet"),
            "must not emit gap residual when BDK path ran: {j}"
        );
        assert!(!lower.contains("crypto"));
    }

    #[test]
    fn utxos_usage_is_honest_gap_sync_list() {
        let usage = utxos_usage_lines().join("\n").to_ascii_lowercase();
        assert!(usage.contains("utxos"));
        assert!(usage.contains("network") || usage.contains("mainnet"));
        assert!(usage.contains("gap") || usage.contains("chain"));
        assert!(
            usage.contains("seedvault") || usage.contains("unlock") || usage.contains("recovery")
        );
        assert!(!usage.contains("crypto"));
        assert!(!usage.contains("--broadcast"));
        assert!(UTXOS_CLI_ABOUT.to_ascii_lowercase().contains("utxo"));
        let long = UTXOS_CLI_LONG_ABOUT.to_ascii_lowercase();
        assert!(long.contains("gap") || long.contains("default"));
        assert!(long.contains("never invents") || long.contains("empty"));
        // Prefer-BDK honesty (env name) without inventing live Success.
        assert!(
            long.contains("utxo_sync") || long.contains("bdk") || usage.contains("bdk"),
            "usage should document prefer-BDK opt-in"
        );
    }

    fn sample_cpfp_parent() -> String {
        format!("{}:1:80000:bc1qchange", "cd".repeat(32))
    }

    fn sample_cpfp_extra() -> String {
        format!("{}:0:50000:bc1qextra", "ef".repeat(32))
    }

    #[test]
    fn parse_cpfp_child_request_explicit_and_default() {
        let parents = vec![sample_cpfp_parent()];
        let req =
            parse_cpfp_child_request("bc1qdest", 40_000, 200, 200, &parents, &[], false, None)
                .unwrap();
        assert_eq!(req.payment_address, "bc1qdest");
        assert_eq!(req.amount_sats, 40_000);
        assert_eq!(req.parent_fee_sats, 200);
        assert_eq!(req.parent_vbytes, 200);
        assert_eq!(req.parents.len(), 1);
        assert!(req.extra_inputs.is_empty());
        assert!(!req.broadcast);
        assert!(!req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, DEFAULT_SPEND_FEE_RATE_SAT_VB);
        assert!(!cpfp_wants_broadcast(&req));

        let extras = vec![sample_cpfp_extra()];
        let req = parse_cpfp_child_request(
            "bc1qdest",
            30_000,
            100,
            141,
            &parents,
            &extras,
            true,
            Some(20),
        )
        .unwrap();
        assert!(req.broadcast);
        assert!(req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, 20);
        assert_eq!(req.extra_inputs.len(), 1);
        assert!(cpfp_wants_broadcast(&req));
    }

    #[test]
    fn parse_cpfp_child_rejects_zero_and_empty() {
        let parents = vec![sample_cpfp_parent()];
        assert_eq!(
            parse_cpfp_child_request("", 100, 50, 100, &parents, &[], false, None).unwrap_err(),
            CpfpChildParseError::EmptyAddress
        );
        assert_eq!(
            parse_cpfp_child_request("bc1q", 0, 50, 100, &parents, &[], false, None).unwrap_err(),
            CpfpChildParseError::ZeroAmount
        );
        assert_eq!(
            parse_cpfp_child_request("bc1q", 100, 50, 0, &parents, &[], false, None).unwrap_err(),
            CpfpChildParseError::ZeroParentVbytes
        );
        assert_eq!(
            parse_cpfp_child_request("bc1q", 100, 50, 100, &[], &[], false, None).unwrap_err(),
            CpfpChildParseError::MissingParents
        );
        assert!(matches!(
            parse_cpfp_child_request("bc1q", 100, 50, 100, &parents, &[], false, Some(0))
                .unwrap_err(),
            CpfpChildParseError::InvalidFeeRate(_)
        ));
        // parent_fee_sats = 0 is allowed.
        let req =
            parse_cpfp_child_request("bc1q", 100, 0, 100, &parents, &[], false, Some(5)).unwrap();
        assert_eq!(req.parent_fee_sats, 0);
        // duplicate parent
        let dup = vec![sample_cpfp_parent(), sample_cpfp_parent()];
        assert!(matches!(
            parse_cpfp_child_request("bc1q", 100, 50, 100, &dup, &[], false, None).unwrap_err(),
            CpfpChildParseError::InvalidInput(_)
        ));
        // parent/extra collision
        let same = sample_cpfp_parent();
        assert!(matches!(
            parse_cpfp_child_request("bc1q", 100, 50, 100, &[same.clone()], &[same], false, None)
                .unwrap_err(),
            CpfpChildParseError::InvalidInput(_)
        ));
    }

    #[test]
    fn parse_cpfp_tokens_dry_run_default_and_broadcast() {
        let parent = sample_cpfp_parent();
        let parent_tok = format!("parent={parent}");
        let req = parse_cpfp_tokens(&[
            "bc1qdest",
            "40000",
            "parent-fee=200",
            "parent-vbytes=200",
            &parent_tok,
        ])
        .unwrap();
        assert_eq!(req.payment_address, "bc1qdest");
        assert_eq!(req.amount_sats, 40_000);
        assert_eq!(req.parent_fee_sats, 200);
        assert_eq!(req.parent_vbytes, 200);
        assert_eq!(req.parents.len(), 1);
        assert!(req.extra_inputs.is_empty());
        assert!(!req.broadcast);
        assert!(!req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, DEFAULT_SPEND_FEE_RATE_SAT_VB);

        let extra = sample_cpfp_extra();
        let req = parse_cpfp_tokens(&[
            "bc1qdest",
            "100",
            "parent_fee=500",
            "--parent-vbytes=100",
            &format!("--parent={parent}"),
            &format!("extra-input={extra}"),
            "broadcast",
            "fee=20",
        ])
        .unwrap();
        assert!(req.broadcast);
        assert!(req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, 20);
        assert_eq!(req.parent_fee_sats, 500);
        assert_eq!(req.parent_vbytes, 100);
        assert_eq!(req.extra_inputs.len(), 1);
    }

    #[test]
    fn parse_cpfp_tokens_rejects_fee_zero_missing_parents_zero_vbytes() {
        let parent = sample_cpfp_parent();
        let parent_tok = format!("parent={parent}");
        // Explicit fee=0 is rejected offline (parity with spend/rbf fee=0).
        assert!(matches!(
            parse_cpfp_tokens(&[
                "bc1qdest",
                "100",
                "parent-fee=50",
                "parent-vbytes=100",
                &parent_tok,
                "fee=0",
            ])
            .unwrap_err(),
            CpfpChildParseError::InvalidFeeRate(_)
        ));
        // Missing parents.
        assert_eq!(
            parse_cpfp_tokens(&["bc1qdest", "100", "parent-fee=50", "parent-vbytes=100",])
                .unwrap_err(),
            CpfpChildParseError::MissingParents
        );
        // Zero parent-vbytes.
        assert_eq!(
            parse_cpfp_tokens(&[
                "bc1qdest",
                "100",
                "parent-fee=50",
                "parent-vbytes=0",
                &parent_tok,
            ])
            .unwrap_err(),
            CpfpChildParseError::ZeroParentVbytes
        );
        // Missing parent-fee / parent-vbytes.
        assert_eq!(
            parse_cpfp_tokens(&["bc1qdest", "100", "parent-vbytes=100", &parent_tok]).unwrap_err(),
            CpfpChildParseError::MissingParentFee
        );
        assert_eq!(
            parse_cpfp_tokens(&["bc1qdest", "100", "parent-fee=50", &parent_tok]).unwrap_err(),
            CpfpChildParseError::MissingParentVbytes
        );
        // parent_fee=0 allowed when vbytes/parents present.
        let req = parse_cpfp_tokens(&[
            "bc1qdest",
            "100",
            "parent-fee=0",
            "parent-vbytes=100",
            &parent_tok,
            "fee=5",
        ])
        .unwrap();
        assert_eq!(req.parent_fee_sats, 0);
        // Unknown token fail closed.
        assert!(matches!(
            parse_cpfp_tokens(&[
                "bc1qdest",
                "100",
                "parent-fee=50",
                "parent-vbytes=100",
                &parent_tok,
                "typo-flag",
            ])
            .unwrap_err(),
            CpfpChildParseError::UnknownToken(_)
        ));
        // Missing address / amount / zero amount.
        assert_eq!(
            parse_cpfp_tokens(&[]).unwrap_err(),
            CpfpChildParseError::MissingAddress
        );
        assert_eq!(
            parse_cpfp_tokens(&["bc1qdest"]).unwrap_err(),
            CpfpChildParseError::MissingAmount
        );
        assert_eq!(
            parse_cpfp_tokens(&[
                "bc1qdest",
                "0",
                "parent-fee=50",
                "parent-vbytes=100",
                &parent_tok,
            ])
            .unwrap_err(),
            CpfpChildParseError::ZeroAmount
        );
        // Empty parent= value.
        assert!(matches!(
            parse_cpfp_tokens(&[
                "bc1qdest",
                "100",
                "parent-fee=50",
                "parent-vbytes=100",
                "parent=",
            ])
            .unwrap_err(),
            CpfpChildParseError::InvalidInput(_)
        ));
    }

    #[cfg(feature = "onchain-address")]
    #[test]
    fn format_cpfp_child_fee_meta_labels_package_vs_child() {
        // Overpaying parent + min-relay child: package target 10, child alone ~1.
        // Must not reuse spend "requested vs effective" on the child alone.
        let lines = format_cpfp_child_fee_meta_lines(
            5_000, // parent fee (overpays package)
            200,   // parent vb
            110,   // child fee (min-relay-ish)
            110,   // child vb
            10,    // package target sat/vB
        );
        let j = lines.join("\n").to_ascii_lowercase();
        assert!(j.contains("package"), "must label package rate: {j}");
        assert!(j.contains("target 10"), "must show package target: {j}");
        assert!(j.contains("child alone") || j.contains("child"), "{j}");
        assert!(
            j.contains("does not replace") || j.contains("not replace"),
            "must stress CPFP does not replace parent: {j}"
        );
        // Must not mislead with bare spend-style "requested 10; effective ~1" only.
        assert!(
            !j.contains("requested 10") || j.contains("package"),
            "if mentioning requested rate, package context required: {j}"
        );
        // Package effective should be high (parent overpays).
        assert!(
            j.contains("effective") && (j.contains("parent") || j.contains("package")),
            "{j}"
        );
    }

    #[cfg(feature = "onchain-address")]
    #[test]
    fn format_cpfp_child_prepared_lines_dry_run_and_broadcast() {
        let plan = crate::descriptor_wallet::plan_cpfp_child_fee(200, 200, 110, 10).unwrap();
        let hex = "cafebabe";
        let dry = format_cpfp_child_prepared_lines(
            "bc1qdest",
            40_000,
            200,
            plan.min_child_fee_sats,
            30_000,
            "aa".repeat(32).as_str(),
            hex,
            false,
            &plan,
        );
        let dry_j = dry.join("\n").to_ascii_lowercase();
        assert!(dry_j.contains("cpfp child"));
        assert!(dry_j.contains("dry-run"));
        assert!(dry_j.contains(hex));
        assert!(dry_j.contains("does not") && dry_j.contains("replace"));
        assert!(!dry_j.contains("broadcast accepted"));
        assert!(dry_j.contains("--broadcast"));
        assert!(dry.iter().any(|l| is_spend_raw_hex_output_line(l, hex)));

        let live = format_cpfp_child_prepared_lines(
            "bc1qdest",
            40_000,
            200,
            plan.min_child_fee_sats,
            30_000,
            "bb".repeat(32).as_str(),
            hex,
            true,
            &plan,
        );
        let live_j = live.join("\n").to_ascii_lowercase();
        assert!(live_j.contains("broadcast requested"));
        assert!(!live.iter().any(|l| l == hex));
        // Plan rebuild disclaimer must not appear inside prepare (broadcast) flow.
        assert!(
            !live_j.contains("does not broadcast"),
            "rebuild disclaimer should be omitted inside cpfp prepare: {live_j}"
        );
        // Never claim parent replaced.
        assert!(!live_j.contains("parent was replaced") && !live_j.contains("replacement spend"));
    }

    #[test]
    fn cpfp_usage_mentions_parent_and_dry_run() {
        let usage = cpfp_usage_lines().join("\n").to_ascii_lowercase();
        assert!(usage.contains("parent-fee"));
        assert!(usage.contains("parent-vbytes"));
        assert!(usage.contains("--parent"));
        assert!(usage.contains("extra-input") || usage.contains("--extra-input"));
        assert!(usage.contains("dry-run") || usage.contains("broadcast"));
        assert!(
            usage.contains("grok_bitcoin_bip39_passphrase"),
            "usage should document optional passphrase env: {usage}"
        );
        assert!(
            usage.contains("grok routstr cpfp"),
            "CLI usage line missing: {usage}"
        );
        assert!(
            usage.contains("/routstr cpfp"),
            "TUI usage line missing: {usage}"
        );
        assert!(
            usage.contains("fee=") || usage.contains("[fee="),
            "TUI fee= form should appear in usage: {usage}"
        );
        assert!(
            usage.contains("never claims the parent was replaced")
                || (usage.contains("does not")
                    && (usage.contains("replace") || usage.contains("replaced"))),
            "must stress CPFP does not replace parent: {usage}"
        );
        assert!(!usage.contains("crypto"));
    }
}
