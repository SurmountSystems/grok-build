//! BIP84 P2WPKH PSBT signing.

use std::collections::BTreeMap;

use bitcoin::bip32::{ChildNumber, DerivationPath, KeySource, Xpriv};
use bitcoin::key::CompressedPublicKey;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, ScriptBuf};
use zeroize::Zeroizing;

use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;

/// Outcome of BIP84 P2WPKH signing (honest about partial coverage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    /// Every input received a partial signature.
    AllSigned { signed_inputs: usize },
    /// Some inputs signed; others could not be resolved within the address gap.
    ///
    /// Not broadcast-ready. Callers must not treat this as a complete spend.
    Partial {
        signed_inputs: usize,
        unsigned_inputs: usize,
        detail: String,
    },
}

impl SignOutcome {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::AllSigned { .. })
    }

    /// True only when every input was signed — never true for multi-sig residual.
    pub fn is_broadcast_ready(&self) -> bool {
        self.is_complete()
    }

    pub fn signed_inputs(&self) -> usize {
        match self {
            Self::AllSigned { signed_inputs } => *signed_inputs,
            Self::Partial { signed_inputs, .. } => *signed_inputs,
        }
    }
}

/// Attach BIP84 derivation metadata and ECDSA-sign P2WPKH inputs owned by
/// `mnemonic` within `address_gap` receive + change indices.
///
/// Uses `bitcoin::psbt::Psbt::sign` with the master [`Xpriv`] (never logged).
/// Intermediate seed bytes are held in [`Zeroizing`] and wiped on drop
/// (including `new_master` Err paths).
///
/// # Residual
/// - Does **not** finalize witnesses or extract a transaction.
/// - Inputs whose script_pubkey is not a BIP84 P2WPKH address in the scanned
///   gap are left unsigned ([`SignOutcome::Partial`]) — not a complete spend.
/// - Network broadcast is not implemented in this crate.
pub fn sign_psbt_bip84_p2wpkh(
    psbt: &mut Psbt,
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
    address_gap: u32,
) -> Result<SignOutcome> {
    if psbt.inputs.is_empty() {
        return Err(WalletError::Onchain("PSBT has no inputs to sign".into()));
    }
    let gap = address_gap.max(1);
    let secp = Secp256k1::new();

    // Zeroizing wipes seed on drop — including `new_master` Err (no early `?` leak).
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let master = Xpriv::new_master(network, seed.as_ref())
        .map_err(|e| WalletError::Onchain(format!("master for sign: {e}")))?;
    drop(seed);

    let fingerprint = master.fingerprint(&secp);
    let lookup = bip84_script_lookup(mnemonic, passphrase, network, gap)?;

    for input in &mut psbt.inputs {
        let Some(utxo) = input.witness_utxo.as_ref() else {
            continue;
        };
        if let Some((pubkey, path)) = lookup.get(&utxo.script_pubkey) {
            let key_source: KeySource = (fingerprint, path.clone());
            input.bip32_derivation.insert(*pubkey, key_source);
        }
    }

    // Sign with master xpriv; GetKey derives via bip32_derivation paths.
    // `Psbt::sign` may report an input as "used" even when bip32_derivation was
    // empty (no sigs written) — count real partial_sigs instead.
    // Note: `Xpriv` is `Copy` in bitcoin 0.32, so we cannot rely on Drop zeroize;
    // seed bytes above were wiped via Zeroizing before sign.
    let _ = psbt.sign(&master, &secp);
    let _ = master; // end of use; avoid lingering named binding past this point

    let signed = psbt
        .inputs
        .iter()
        .filter(|i| !i.partial_sigs.is_empty())
        .count();
    let total = psbt.inputs.len();
    let unsigned = total.saturating_sub(signed);

    if signed == total {
        Ok(SignOutcome::AllSigned {
            signed_inputs: signed,
        })
    } else if signed == 0 {
        // Prefer a clear residual over a hard error when keys simply don't cover
        // the inputs (foreign UTXO / gap miss) — callers decide whether to abort.
        Ok(SignOutcome::Partial {
            signed_inputs: 0,
            unsigned_inputs: unsigned,
            detail: format!(
                "signed 0/{total} inputs; no BIP84 P2WPKH keys matched within gap {gap} \
                 (not broadcast-ready)"
            ),
        })
    } else {
        Ok(SignOutcome::Partial {
            signed_inputs: signed,
            unsigned_inputs: unsigned,
            detail: format!(
                "signed {signed}/{total} inputs; unresolved inputs not in BIP84 gap {gap} \
                 (not broadcast-ready)"
            ),
        })
    }
}

pub(super) fn bip84_script_lookup(
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
    gap: u32,
) -> Result<BTreeMap<ScriptBuf, (bitcoin::secp256k1::PublicKey, DerivationPath)>> {
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, seed.as_ref())
        .map_err(|e| WalletError::Onchain(format!("master for lookup: {e}")))?;
    drop(seed);

    let hrp = hrp_for_network(network);
    let mut map = BTreeMap::new();
    for is_change in [false, true] {
        for index in 0..gap {
            let path = bip84_full_path(network, is_change, index)?;
            let child = master
                .derive_priv(&secp, &path)
                .map_err(|e| WalletError::Onchain(format!("derive for lookup: {e}")))?;
            let pk = child.private_key.public_key(&secp);
            let compressed = CompressedPublicKey(pk);
            let addr = Address::p2wpkh(&compressed, hrp);
            map.insert(addr.script_pubkey(), (pk, path));
        }
    }
    Ok(map)
}

pub(super) fn bip84_full_path(
    network: Network,
    is_change: bool,
    index: u32,
) -> Result<DerivationPath> {
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    let chain = if is_change { 1u32 } else { 0u32 };
    Ok(DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84"),
        ChildNumber::from_hardened_idx(coin).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
        ChildNumber::from_normal_idx(chain).expect("chain"),
        ChildNumber::from_normal_idx(index)
            .map_err(|e| WalletError::Onchain(format!("index: {e}")))?,
    ]))
}

pub(super) fn hrp_for_network(network: Network) -> bitcoin::KnownHrp {
    match network {
        Network::Bitcoin => bitcoin::KnownHrp::Mainnet,
        Network::Testnet | Network::Signet => bitcoin::KnownHrp::Testnets,
        Network::Regtest => bitcoin::KnownHrp::Regtest,
        _ => bitcoin::KnownHrp::Testnets,
    }
}
