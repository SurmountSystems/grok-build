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
}
