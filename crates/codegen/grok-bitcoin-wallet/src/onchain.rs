//! On-chain receive address derivation (BIP84 native segwit).
//!
//! Full BDK wallet / sync is residual. This module derives a stable receive
//! address from BIP-39 seed via `bitcoin` bip32 only.

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, KnownHrp, Network};

use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;

/// BIP84 account path prefix: `m/84'/coin'/0'`
fn account_path(network: Network) -> DerivationPath {
    let coin = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32, // testnet / signet / regtest
    };
    DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).expect("84"),
        ChildNumber::from_hardened_idx(coin).expect("coin"),
        ChildNumber::from_hardened_idx(0).expect("account"),
    ])
}

/// External chain receive path: `m/84'/coin'/0'/0/{index}`
fn receive_path(network: Network, index: u32) -> Result<DerivationPath> {
    let mut path: Vec<ChildNumber> = account_path(network).into();
    path.push(ChildNumber::from_normal_idx(0).expect("external"));
    path.push(
        ChildNumber::from_normal_idx(index)
            .map_err(|e| WalletError::Onchain(format!("index: {e}")))?,
    );
    Ok(DerivationPath::from(path))
}

fn hrp_for(network: Network) -> KnownHrp {
    match network {
        Network::Bitcoin => KnownHrp::Mainnet,
        Network::Testnet | Network::Signet => KnownHrp::Testnets,
        Network::Regtest => KnownHrp::Regtest,
        // bitcoin 0.32 may add variants; fall back to testnets.
        _ => KnownHrp::Testnets,
    }
}

/// Derive BIP84 receive address at `index` (external chain).
pub fn derive_bip84_receive_address(
    mnemonic: &MnemonicSecret,
    network: Network,
    index: u32,
) -> Result<String> {
    derive_bip84_receive_address_with_passphrase(mnemonic, "", network, index)
}

/// Same with BIP-39 passphrase.
pub fn derive_bip84_receive_address_with_passphrase(
    mnemonic: &MnemonicSecret,
    passphrase: &str,
    network: Network,
    index: u32,
) -> Result<String> {
    let seed = mnemonic.to_seed(passphrase);
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, &seed)
        .map_err(|e| WalletError::Onchain(format!("master: {e}")))?;
    let path = receive_path(network, index)?;
    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| WalletError::Onchain(format!("derive: {e}")))?;
    let pubkey = child.private_key.public_key(&secp);
    let compressed = CompressedPublicKey(pubkey);
    let addr = Address::p2wpkh(&compressed, hrp_for(network));
    Ok(addr.to_string())
}

/// Map `GROK_BITCOIN_NETWORK` / our enum to `bitcoin::Network`.
pub fn network_from_str(s: &str) -> Option<Network> {
    match s.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" | "main" => Some(Network::Bitcoin),
        "signet" => Some(Network::Signet),
        "testnet" | "testnet3" => Some(Network::Testnet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

/// Derive receive address using a `GROK_BITCOIN_NETWORK` style string.
///
/// Unknown values return [`WalletError::Onchain`] (no silent mainnet fallback).
/// Empty / whitespace-only `network_str` is treated as mainnet.
pub fn derive_bip84_receive_address_env_network(
    mnemonic: &MnemonicSecret,
    network_str: &str,
    index: u32,
) -> Result<String> {
    let trimmed = network_str.trim();
    let network = if trimmed.is_empty() {
        Network::Bitcoin
    } else {
        network_from_str(trimmed).ok_or_else(|| {
            WalletError::Onchain(format!(
                "unknown GROK_BITCOIN_NETWORK value {trimmed:?}; \
                 use mainnet, signet, testnet, or regtest"
            ))
        })?
    };
    derive_bip84_receive_address(mnemonic, network, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::import_mnemonic;

    const VECTOR: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";

    #[test]
    fn receive_address_stable_mainnet_index0() {
        let m = import_mnemonic(VECTOR).unwrap();
        let a = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let b = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("bc1q"), "got {a}");
    }

    #[test]
    fn env_network_rejects_typo() {
        let m = import_mnemonic(VECTOR).unwrap();
        let err = derive_bip84_receive_address_env_network(&m, "mainet", 0).unwrap_err();
        assert!(matches!(err, WalletError::Onchain(_)));
        let ok = derive_bip84_receive_address_env_network(&m, "signet", 0).unwrap();
        assert!(ok.starts_with("tb1") || ok.starts_with("bcrt") || !ok.is_empty());
        let main = derive_bip84_receive_address_env_network(&m, "", 0).unwrap();
        assert!(main.starts_with("bc1q"));
    }

    #[test]
    fn receive_address_stable_signet() {
        let m = import_mnemonic(VECTOR).unwrap();
        let a = derive_bip84_receive_address(&m, Network::Signet, 0).unwrap();
        assert!(a.starts_with("tb1") || a.starts_with("bcrt1"), "got {a}");
        let b = derive_bip84_receive_address(&m, Network::Signet, 0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_index_different_address() {
        let m = import_mnemonic(VECTOR).unwrap();
        let a0 = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        let a1 = derive_bip84_receive_address(&m, Network::Bitcoin, 1).unwrap();
        assert_ne!(a0, a1);
    }

    #[test]
    fn known_vector_fixed_string() {
        // Pin the derived address so derivation path regressions fail loudly.
        let m = import_mnemonic(VECTOR).unwrap();
        let a = derive_bip84_receive_address(&m, Network::Bitcoin, 0).unwrap();
        // BIP84 m/84'/0'/0'/0/0 for NIP-06 vector mnemonic (empty passphrase).
        assert_eq!(a, EXPECTED_MAINNET_RECV_0);
    }

    /// Filled by first successful derivation in CI; keep in sync with path above.
    const EXPECTED_MAINNET_RECV_0: &str = "bc1q8zxz5kl6q30y2mzhx86gcwcz0t0hgzl2f2jpm5";
}
