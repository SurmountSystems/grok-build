//! BIP84 [`DescriptorWallet`] construction and gap-limit UTXO sync.

use bitcoin::Network;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;
use crate::onchain::{derive_bip84_receive_address_with_passphrase, network_from_str};

use super::chain_source::ChainSource;
use super::coin_select::balance_from_utxos;
use super::gap::{
    GapExtendOptions, GapExtendReport, MAX_ADDRESS_GAP, WalletSyncSnapshot,
    address_window_needs_extend, highest_used_address_index, next_gap_after_extend,
};
use super::types::{WalletBalance, WalletUtxo};

/// BIP84 account descriptors + derived receive/change address windows.
///
/// UTXO discovery is via an injectable [`ChainSource`] (mock, mempool,
/// [`crate::esplora::EsploraChainSource`], or [`crate::electrum::ElectrumChainSource`]).
/// Gap-limit helpers ([`Self::sync_utxos`], [`Self::sync_with_gap_extend`]) list
/// UTXOs for the current window and optionally extend it when the tip is used,
/// bounded by [`MAX_ADDRESS_GAP`]. For spent-tx history + BDK keychain auto-sync
/// see feature-gated [`crate::bdk_sync`] (not default CI).
///
/// The struct never stores BIP-39 or passphrase; extend APIs take
/// [`MnemonicSecret`] ephemerally (same pattern as signing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorWallet {
    network: Network,
    /// `wpkh(<account_xpub>/0/*)` external.
    pub receive_descriptor: String,
    /// `wpkh(<account_xpub>/1/*)` internal/change.
    pub change_descriptor: String,
    /// Account-level xpub string (no origin fingerprint in this pass).
    pub account_xpub: String,
    /// Derived receive window (`m/84'/…/0/*`). `pub(super)` for in-crate tests.
    pub(super) receive_addresses: Vec<String>,
    /// Derived change window (`m/84'/…/1/*`). `pub(super)` for in-crate tests.
    pub(super) change_addresses: Vec<String>,
}

impl DescriptorWallet {
    /// Build BIP84 descriptors and a receive/change address gap from mnemonic.
    pub fn from_mnemonic(
        mnemonic: &MnemonicSecret,
        network: Network,
        receive_gap: u32,
    ) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(mnemonic, "", network, receive_gap)
    }

    /// Same with BIP-39 passphrase.
    ///
    /// `receive_gap` is clamped to `1..=`[`MAX_ADDRESS_GAP`] (same hard cap as
    /// extend). Both receive and change windows use this length at construction.
    pub fn from_mnemonic_with_passphrase(
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        network: Network,
        receive_gap: u32,
    ) -> Result<Self> {
        let gap = receive_gap.clamp(1, MAX_ADDRESS_GAP);
        let (account_xpub, origin) = account_xpub_and_origin(mnemonic, passphrase, network)?;
        // BIP380-style origin `[fingerprint/84h/coin'h/0h]` so BDK importers
        // can resolve the account path. Wildcard children stay `/0/*` `/1/*`.
        let receive_descriptor = format!("wpkh([{origin}]{account_xpub}/0/*)");
        let change_descriptor = format!("wpkh([{origin}]{account_xpub}/1/*)");

        let mut receive_addresses = Vec::with_capacity(gap as usize);
        for i in 0..gap {
            receive_addresses.push(derive_bip84_receive_address_with_passphrase(
                mnemonic, passphrase, network, i,
            )?);
        }
        // Change chain: m/84'/coin'/0'/1/{i} — derive via same path helper style.
        let mut change_addresses = Vec::with_capacity(gap as usize);
        for i in 0..gap {
            change_addresses.push(derive_bip84_change_address_with_passphrase(
                mnemonic, passphrase, network, i,
            )?);
        }

        Ok(Self {
            network,
            receive_descriptor,
            change_descriptor,
            account_xpub,
            receive_addresses,
            change_addresses,
        })
    }

    /// Convenience: parse `GROK_BITCOIN_NETWORK` style string (empty → mainnet).
    ///
    /// Uses empty BIP-39 passphrase (default path). Prefer
    /// [`Self::from_mnemonic_env_network_with_passphrase`] for passphrase wallets.
    pub fn from_mnemonic_env_network(
        mnemonic: &MnemonicSecret,
        network_str: &str,
        receive_gap: u32,
    ) -> Result<Self> {
        Self::from_mnemonic_env_network_with_passphrase(mnemonic, "", network_str, receive_gap)
    }

    /// Same as [`Self::from_mnemonic_env_network`] with BIP-39 passphrase.
    ///
    /// Passphrase must match the one used at funding/signing. Never log it.
    pub fn from_mnemonic_env_network_with_passphrase(
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        network_str: &str,
        receive_gap: u32,
    ) -> Result<Self> {
        let trimmed = network_str.trim();
        let network = if trimmed.is_empty() {
            Network::Bitcoin
        } else {
            network_from_str(trimmed).ok_or_else(|| {
                WalletError::Onchain(format!(
                    "unknown GROK_BITCOIN_NETWORK value {trimmed:?}; \
                     use mainnet, signet, testnet, testnet4, or regtest"
                ))
            })?
        };
        Self::from_mnemonic_with_passphrase(mnemonic, passphrase, network, receive_gap)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn receive_addresses(&self) -> &[String] {
        &self.receive_addresses
    }

    pub fn change_addresses(&self) -> &[String] {
        &self.change_addresses
    }

    /// Current receive address window length (gap).
    pub fn receive_gap(&self) -> u32 {
        self.receive_addresses.len() as u32
    }

    /// Current change address window length (gap).
    pub fn change_gap(&self) -> u32 {
        self.change_addresses.len() as u32
    }

    /// First receive address (index 0), if the gap window is non-empty.
    pub fn primary_receive_address(&self) -> Option<&str> {
        self.receive_addresses.first().map(String::as_str)
    }

    /// All watched addresses (receive then change).
    pub fn watched_addresses(&self) -> Vec<String> {
        let mut all = self.receive_addresses.clone();
        all.extend(self.change_addresses.iter().cloned());
        all
    }

    /// List UTXOs known to `chain` for this wallet's address window.
    pub fn list_unspent(&self, chain: &dyn ChainSource) -> Result<Vec<WalletUtxo>> {
        let addrs = self.watched_addresses();
        let mut utxos = chain.list_unspent_for_addresses(&addrs)?;
        // Annotate change vs receive when the chain source left is_change false
        // but the address is in our change set.
        for u in &mut utxos {
            if self.change_addresses.iter().any(|a| a == &u.address) {
                u.is_change = true;
            }
        }
        Ok(utxos)
    }

    /// Sum confirmed (confs ≥ 1) and unconfirmed balances from chain UTXOs.
    pub fn balance(&self, chain: &dyn ChainSource) -> Result<WalletBalance> {
        let utxos = self.list_unspent(chain)?;
        balance_from_utxos(&utxos)
    }

    /// Fixed-window UTXO sync: list + balance + gap meta (no address growth).
    ///
    /// Only returns UTXOs the chain source provides for the current receive +
    /// change windows. Does **not** extend the gap (even when the tip is hot);
    /// use [`Self::sync_with_gap_extend`] when stop-gap / look-ahead should grow
    /// the watched set (bounded by [`MAX_ADDRESS_GAP`]).
    ///
    /// Propagates [`ChainSource`] errors unchanged.
    pub fn sync_utxos(&self, chain: &dyn ChainSource) -> Result<WalletSyncSnapshot> {
        let utxos = self.list_unspent(chain)?;
        self.snapshot_from_utxos(utxos, 0, 0, false)
    }

    /// One pass: list current window; if receive and/or change needs look-ahead
    /// room, append one extend step (independent chains).
    ///
    /// Does not loop. Call [`Self::sync_with_gap_extend`] for re-list until
    /// stable. Derivation failures and wrong passphrase (mismatch vs stored
    /// index 0) surface as [`WalletError::Onchain`]. Propagates chain errors.
    /// Never stores `mnemonic` / passphrase on `self`.
    ///
    /// **Chain calls:** one `list_unspent` for this pass (no final re-list).
    pub fn extend_gap_if_needed(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        chain: &dyn ChainSource,
        opts: GapExtendOptions,
    ) -> Result<GapExtendReport> {
        let max_gap = opts.effective_max_gap();
        let step = opts.effective_extend_step();
        let lookahead = opts.effective_lookahead();

        let receive_before = self.receive_gap();
        let change_before = self.change_gap();
        let utxos = self.list_unspent(chain)?;
        let hi_recv = highest_used_address_index(&self.receive_addresses, &utxos);
        let hi_chg = highest_used_address_index(&self.change_addresses, &utxos);

        let need_recv = address_window_needs_extend(hi_recv, receive_before, lookahead);
        let need_chg = address_window_needs_extend(hi_chg, change_before, lookahead);

        let mut hit_max_gap = false;
        let mut receive_extended = false;
        let mut change_extended = false;

        if need_recv {
            match next_gap_after_extend(receive_before, step, max_gap) {
                Some(new_gap) => {
                    self.extend_receive_window_to(mnemonic, passphrase, new_gap)?;
                    receive_extended = self.receive_gap() > receive_before;
                }
                None => hit_max_gap = true,
            }
        }
        if need_chg {
            match next_gap_after_extend(change_before, step, max_gap) {
                Some(new_gap) => {
                    self.extend_change_window_to(mnemonic, passphrase, new_gap)?;
                    change_extended = self.change_gap() > change_before;
                }
                None => hit_max_gap = true,
            }
        }

        Ok(GapExtendReport {
            receive_before,
            receive_after: self.receive_gap(),
            change_before,
            change_after: self.change_gap(),
            receive_extended,
            change_extended,
            hit_max_gap,
        })
    }

    /// Gap-limit ChainSource sync with bounded auto-extend of receive/change windows.
    ///
    /// Algorithm:
    /// 1. List UTXOs for the current receive + change windows.
    /// 2. If highest used receive (or change) index is within `lookahead` of
    ///    the window end (default look-ahead is BIP44-style stop-gap 20), append
    ///    `extend_step` addresses (capped by `max_gap` and hard [`MAX_ADDRESS_GAP`]).
    /// 3. Re-list; repeat until stable or no further growth is possible.
    ///
    /// **Chain calls:** each extend step performs one list; after the loop a
    /// final list builds the snapshot (stable sync ≈ N+1 lists where N is the
    /// number of extend steps, including a terminal no-grow probe). Live
    /// Esplora/Electrum backends are rate-limited separately.
    ///
    /// **Honesty:** only UTXOs returned by `chain`; unconfirmed (0-conf) UTXOs
    /// count as activity for gap (they appear in the list). Not full
    /// `bdk_wallet` auto-sync (no script history / spent-tx gap, no SPV). BIP-39
    /// is not retained on the wallet. Wrong passphrase → hard error before
    /// mutate (see [`Self::extend_receive_window_to`]).
    pub fn sync_with_gap_extend(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        chain: &dyn ChainSource,
        opts: GapExtendOptions,
    ) -> Result<WalletSyncSnapshot> {
        let max_gap = opts.effective_max_gap();
        // Each successful step grows a window by ≥1; bound iterations tightly.
        let max_iters = (max_gap as usize).saturating_mul(2).saturating_add(2);

        let mut extended_receive_by = 0u32;
        let mut extended_change_by = 0u32;
        let mut hit_max_gap = false;

        for _ in 0..max_iters {
            let report = self.extend_gap_if_needed(mnemonic, passphrase, chain, opts)?;
            if report.hit_max_gap {
                hit_max_gap = true;
            }
            if report.receive_extended {
                extended_receive_by = extended_receive_by
                    .saturating_add(report.receive_after.saturating_sub(report.receive_before));
            }
            if report.change_extended {
                extended_change_by = extended_change_by
                    .saturating_add(report.change_after.saturating_sub(report.change_before));
            }
            if !report.grew() {
                break;
            }
        }

        // Final list for snapshot (see method docs: one extra round-trip after
        // the terminal no-grow extend_gap_if_needed list).
        let utxos = self.list_unspent(chain)?;
        // If look-ahead still hot after stop, surface max-gap honesty even if
        // last extend_gap_if_needed returned grew=false only because max blocked.
        if !hit_max_gap {
            let hi_recv = highest_used_address_index(&self.receive_addresses, &utxos);
            let hi_chg = highest_used_address_index(&self.change_addresses, &utxos);
            let la = opts.effective_lookahead();
            if (address_window_needs_extend(hi_recv, self.receive_gap(), la)
                && next_gap_after_extend(self.receive_gap(), opts.effective_extend_step(), max_gap)
                    .is_none())
                || (address_window_needs_extend(hi_chg, self.change_gap(), la)
                    && next_gap_after_extend(
                        self.change_gap(),
                        opts.effective_extend_step(),
                        max_gap,
                    )
                    .is_none())
            {
                hit_max_gap = true;
            }
        }

        self.snapshot_from_utxos(utxos, extended_receive_by, extended_change_by, hit_max_gap)
    }

    /// Append receive addresses until the window length is `new_gap` (no shrink).
    ///
    /// Errors if derivation fails or if `mnemonic`/`passphrase` do not re-derive
    /// the existing window (index 0 check) — wrong passphrase must not silently
    /// append foreign addresses. Caps at [`MAX_ADDRESS_GAP`].
    pub fn extend_receive_window_to(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        new_gap: u32,
    ) -> Result<()> {
        let target = new_gap.min(MAX_ADDRESS_GAP);
        let current = self.receive_gap();
        if target <= current {
            return Ok(());
        }
        self.verify_receive_material(mnemonic, passphrase)?;
        for i in current..target {
            self.receive_addresses
                .push(derive_bip84_receive_address_with_passphrase(
                    mnemonic,
                    passphrase,
                    self.network,
                    i,
                )?);
        }
        Ok(())
    }

    /// Append change addresses until the window length is `new_gap` (no shrink).
    ///
    /// Same passphrase/material check as [`Self::extend_receive_window_to`].
    pub fn extend_change_window_to(
        &mut self,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
        new_gap: u32,
    ) -> Result<()> {
        let target = new_gap.min(MAX_ADDRESS_GAP);
        let current = self.change_gap();
        if target <= current {
            return Ok(());
        }
        self.verify_change_material(mnemonic, passphrase)?;
        for i in current..target {
            self.change_addresses
                .push(derive_bip84_change_address_with_passphrase(
                    mnemonic,
                    passphrase,
                    self.network,
                    i,
                )?);
        }
        Ok(())
    }

    /// Re-derive receive index 0; fail closed if material does not match the wallet.
    fn verify_receive_material(&self, mnemonic: &MnemonicSecret, passphrase: &str) -> Result<()> {
        let Some(stored) = self.receive_addresses.first() else {
            return Ok(());
        };
        let derived =
            derive_bip84_receive_address_with_passphrase(mnemonic, passphrase, self.network, 0)?;
        if derived != *stored {
            return Err(WalletError::Onchain(
                "gap extend aborted: mnemonic/passphrase does not re-derive wallet receive \
                 address index 0 (wrong passphrase or seed?); window left unchanged"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Re-derive change index 0; fail closed if material does not match the wallet.
    fn verify_change_material(&self, mnemonic: &MnemonicSecret, passphrase: &str) -> Result<()> {
        let Some(stored) = self.change_addresses.first() else {
            return Ok(());
        };
        let derived =
            derive_bip84_change_address_with_passphrase(mnemonic, passphrase, self.network, 0)?;
        if derived != *stored {
            return Err(WalletError::Onchain(
                "gap extend aborted: mnemonic/passphrase does not re-derive wallet change \
                 address index 0 (wrong passphrase or seed?); window left unchanged"
                    .into(),
            ));
        }
        Ok(())
    }

    fn snapshot_from_utxos(
        &self,
        utxos: Vec<WalletUtxo>,
        extended_receive_by: u32,
        extended_change_by: u32,
        hit_max_gap: bool,
    ) -> Result<WalletSyncSnapshot> {
        let highest_used_receive = highest_used_address_index(&self.receive_addresses, &utxos);
        let highest_used_change = highest_used_address_index(&self.change_addresses, &utxos);
        let balance = balance_from_utxos(&utxos)?;
        Ok(WalletSyncSnapshot {
            utxos,
            balance,
            receive_gap: self.receive_gap(),
            change_gap: self.change_gap(),
            highest_used_receive,
            highest_used_change,
            extended_receive_by,
            extended_change_by,
            hit_max_gap,
        })
    }
}

/// BIP84 account path `m/84'/coin'/0'`.
pub(super) fn account_path(network: Network) -> DerivationPath {
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84"),
        ChildNumber::from_hardened_idx(coin).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
    ])
}

/// Account-level xpub and BIP380 origin body `fingerprint/84h/{coin}h/0h`
/// (without surrounding brackets).
pub(super) fn account_xpub_and_origin(
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
) -> Result<(String, String)> {
    // Zeroizing wipes seed on drop — including `new_master` Err paths.
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, seed.as_ref())
        .map_err(|e| WalletError::Onchain(format!("master: {e}")))?;
    drop(seed);
    let fingerprint = master.fingerprint(&secp);
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    // BIP380 uses `h` for hardened; keep ASCII so descriptors stay portable.
    let origin = format!("{fingerprint}/84h/{coin}h/0h");
    let path = account_path(network);
    let account = master
        .derive_priv(&secp, &path)
        .map_err(|e| WalletError::Onchain(format!("account derive: {e}")))?;
    let xpub = Xpub::from_priv(&secp, &account);
    Ok((xpub.to_string(), origin))
}

/// BIP84 change address: `m/84'/coin'/0'/1/{index}`.
pub(super) fn derive_bip84_change_address_with_passphrase(
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
    index: u32,
) -> Result<String> {
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::{Address, KnownHrp};

    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, seed.as_ref())
        .map_err(|e| WalletError::Onchain(format!("master: {e}")))?;
    drop(seed);
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84"),
        ChildNumber::from_hardened_idx(coin).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
        ChildNumber::from_normal_idx(1).expect("change"),
        ChildNumber::from_normal_idx(index)
            .map_err(|e| WalletError::Onchain(format!("index: {e}")))?,
    ]);
    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| WalletError::Onchain(format!("derive: {e}")))?;
    let pubkey = child.private_key.public_key(&secp);
    let compressed = CompressedPublicKey(pubkey);
    let hrp = match network {
        Network::Bitcoin => KnownHrp::Mainnet,
        Network::Testnet | Network::Signet => KnownHrp::Testnets,
        Network::Regtest => KnownHrp::Regtest,
        _ => KnownHrp::Testnets,
    };
    let addr = Address::p2wpkh(&compressed, hrp);
    Ok(addr.to_string())
}
