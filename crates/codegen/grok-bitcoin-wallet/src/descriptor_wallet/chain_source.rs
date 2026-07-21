//! Injectable [`ChainSource`] trait and built-in adapters.

use crate::error::{Result, WalletError};
use crate::explorer::is_valid_txid_hex;

use super::types::{OutPointRef, WalletUtxo};

#[cfg(feature = "explorer-http")]
use std::cell::RefCell;

/// Injectable chain / explorer backend for UTXO discovery.
///
/// Built-in impls: [`MockChainSource`] (tests); [`MempoolChainSource`]
/// (`explorer-http`); [`crate::esplora::EsploraChainSource`] (mock always,
/// live HTTP behind `esplora`); [`crate::electrum::ElectrumChainSource`]
/// (mock always, live TCP behind `electrum`).
pub trait ChainSource {
    /// List UTXOs for the given addresses (any order).
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>>;
}

/// In-memory chain source for unit tests and offline demos.
#[derive(Debug, Clone, Default)]
pub struct MockChainSource {
    utxos: Vec<WalletUtxo>,
}

impl MockChainSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_utxos(utxos: Vec<WalletUtxo>) -> Self {
        Self { utxos }
    }

    pub fn push(&mut self, utxo: WalletUtxo) {
        self.utxos.push(utxo);
    }
}

impl ChainSource for MockChainSource {
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>> {
        Ok(self
            .utxos
            .iter()
            .filter(|u| addresses.iter().any(|a| a == &u.address))
            .cloned()
            .collect())
    }
}

/// Live [`ChainSource`] backed by mempool.space address UTXO REST API.
///
/// Only available with feature `explorer-http`. All fetches go through
/// [`crate::explorer::MempoolHttpClient`] / [`crate::explorer::RateLimitedExplorer`]
/// gates (never bypassed). Default CI builds without the feature stay offline.
///
/// **Tip height:** one tip probe runs per `list_unspent_for_addresses` call.
/// If tip is missing (gated/error/unparseable), API-`confirmed:true` UTXOs still
/// get `confirmations = 1` via [`parse_mempool_address_utxos`] — they are
/// spend-eligible under the default `confirmed_only` filter, but confirmation
/// *depth* is untrusted (not the same as [`crate::watcher::AddressWatcher`],
/// which marks incomplete and leaves conf at 0 when tip is gated). Product
/// paths that require N>1 confs must not treat that `1` as authoritative depth.
#[cfg(feature = "explorer-http")]
#[derive(Debug)]
pub struct MempoolChainSource {
    client: RefCell<crate::explorer::MempoolHttpClient>,
}

#[cfg(feature = "explorer-http")]
impl MempoolChainSource {
    pub fn new(client: crate::explorer::MempoolHttpClient) -> Self {
        Self {
            client: RefCell::new(client),
        }
    }

    pub fn with_defaults(network: crate::address_ux::BitcoinNetwork) -> Result<Self> {
        Ok(Self::new(
            crate::explorer::MempoolHttpClient::with_defaults(network)?,
        ))
    }

    pub fn network(&self) -> crate::address_ux::BitcoinNetwork {
        self.client.borrow().network()
    }
}

#[cfg(feature = "explorer-http")]
impl ChainSource for MempoolChainSource {
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>> {
        let mut client = self.client.borrow_mut();
        // One tip-height probe for confirmation math across all address UTXOs.
        let tip = client
            .fetch_tip_height()
            .and_then(|b| crate::watcher::parse_tip_height(&b));

        let mut out = Vec::new();
        for addr in addresses {
            let body = client.fetch_address_utxos(addr).ok_or_else(|| {
                WalletError::Explorer(
                    "failed to fetch UTXOs for address (rate-limited or network error)".into(),
                )
            })?;
            let parsed = parse_mempool_address_utxos(&body, addr, tip)?;
            out.extend(parsed);
        }
        Ok(out)
    }
}

/// Parse mempool.space `GET /api/address/{addr}/utxo` JSON into [`WalletUtxo`]s.
///
/// Pure / offline-testable. `tip_height` (when known) yields accurate
/// confirmations via [`crate::watcher::confirmations_from_heights`]; when tip
/// is missing, API-confirmed UTXOs get `confirmations = 1` so they remain
/// spend-eligible under `confirmed_only`, but **depth is untrusted** (not a
/// claim of exactly one confirmation). Live mempool ChainSource documents the
/// same tip-miss policy.
///
/// Each `txid` must be 64 ASCII hex characters (fail-closed against empty /
/// truncated explorer bodies).
///
/// Expected item shape:
/// ```json
/// { "txid": "...", "vout": 0, "value": 12345,
///   "status": { "confirmed": true, "block_height": 800000 } }
/// ```
pub fn parse_mempool_address_utxos(
    body: &str,
    address: &str,
    tip_height: Option<u64>,
) -> Result<Vec<WalletUtxo>> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| WalletError::Explorer(format!("mempool address utxo JSON: {e}")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| WalletError::Explorer("mempool address utxo JSON: expected array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let txid = item
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::Explorer("utxo missing txid".into()))?;
        if !is_valid_txid_hex(txid) {
            return Err(WalletError::Explorer(format!(
                "utxo txid must be 64 hex chars, got len {} / non-hex",
                txid.len()
            )));
        }
        let txid = txid.to_owned();
        let vout = item
            .get("vout")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
            })
            .ok_or_else(|| WalletError::Explorer("utxo missing vout".into()))?;
        let vout = u32::try_from(vout)
            .map_err(|_| WalletError::Explorer("utxo vout out of range".into()))?;
        let amount_sats = item
            .get("value")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
            })
            .ok_or_else(|| WalletError::Explorer("utxo missing value".into()))?;

        let status = item.get("status");
        let confirmed = status
            .and_then(|s| s.get("confirmed"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let block_height = status.and_then(|s| s.get("block_height")).and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
        });

        let confirmations = if !confirmed {
            0
        } else {
            match (block_height, tip_height) {
                (Some(bh), Some(tip)) => crate::watcher::confirmations_from_heights(tip, bh),
                // Confirmed without tip/height: spend-eligible conf=1; depth untrusted.
                _ => 1,
            }
        };

        out.push(WalletUtxo {
            outpoint: OutPointRef::new(txid, vout),
            amount_sats,
            address: address.to_owned(),
            confirmations,
            is_change: false,
        });
    }
    Ok(out)
}
