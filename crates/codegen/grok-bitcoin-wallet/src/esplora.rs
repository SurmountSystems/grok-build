//! Esplora REST-shaped [`ChainSource`] + [`TxBroadcaster`] (Blockstream, electrs REST, …).
//!
//! Offline by default: pure URL helpers + [`parse_esplora_address_utxos`] +
//! [`MockEsploraTransport`] fixtures. Live HTTP is opt-in behind feature
//! `esplora` ([`HttpEsploraTransport`]) and is **not** enabled in default CI.
//!
//! Esplora address UTXO JSON matches mempool.space
//! (`GET /address/{addr}/utxo`); parsing reuses
//! [`crate::descriptor_wallet::parse_mempool_address_utxos`].
//!
//! Script-history paths used by BDK full_scan (feature `bdk`):
//! - `GET /address/{addr}/txs` — tx summaries for a script/address
//! - `GET /tx/{txid}/hex` — raw transaction hex for apply_update
//!
//! Broadcast: `POST /tx` with raw transaction hex body (Esplora REST convention;
//! same shape as mempool.space `POST /api/tx`). Response body is a 64-hex txid.

use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::descriptor_wallet::{ChainSource, WalletUtxo, parse_mempool_address_utxos};
use crate::error::{Result, WalletError};
#[cfg(feature = "esplora")]
use crate::explorer::{BroadcastHttpOutcome, broadcast_outcome_from_http};
use crate::explorer::{
    BroadcastResult, TxBroadcaster, is_valid_txid_hex, parse_broadcast_txid_body,
    validate_raw_tx_hex,
};
use crate::watcher::parse_tip_height;

/// Injectable Esplora REST transport (path relative to API root → body text).
///
/// Paths are absolute-from-root forms such as `/address/{addr}/utxo`,
/// `/blocks/tip/height`, and `/tx` (leading `/` required). Implementations must
/// not invent UTXO / broadcast bodies on failure — return [`Err`].
pub trait EsploraTransport {
    /// GET `path` and return the response body as text.
    fn get_text(&mut self, path: &str) -> Result<String>;

    /// POST `body` to `path` and return the response body as text.
    ///
    /// Default: hard error (GET-only transports). Broadcast uses this for
    /// [`esplora_broadcast_tx_path`]. Live HTTP overrides with rate-limited POST.
    fn post_text(&mut self, path: &str, body: &str) -> Result<String> {
        let _ = body;
        Err(WalletError::Explorer(format!(
            "esplora POST not supported by this transport (path {path})"
        )))
    }
}

/// In-memory Esplora transport for unit tests (offline fixtures only).
///
/// Maps exact paths to fixture bodies. Missing paths and scripted failures are
/// hard errors — never silently invent empty UTXO lists or broadcast success.
///
/// **BDK full_scan helpers:** set [`Self::default_empty_address_txs`] so missing
/// `GET /address/.../txs` paths return `"[]"` (empty history) without pre-seeding
/// every stop-gap look-ahead address. Explicit `fail_paths` / `fixtures` still
/// win. Missing tip / tx-hex / utxo paths remain hard errors.
#[derive(Debug, Default)]
pub struct MockEsploraTransport {
    /// Exact path → response body (GET).
    pub fixtures: BTreeMap<String, String>,
    /// Exact path → error message (GET; checked before fixtures).
    pub fail_paths: BTreeMap<String, String>,
    /// Recorded GET paths (order preserved).
    pub calls: Vec<String>,
    /// Exact path → response body (POST).
    pub post_fixtures: BTreeMap<String, String>,
    /// Exact path → error message (POST; checked before post_fixtures).
    pub post_fail_paths: BTreeMap<String, String>,
    /// Recorded POST `(path, body)` pairs (order preserved).
    pub post_calls: Vec<(String, String)>,
    /// When true, missing `/address/{addr}/txs` GETs return `"[]"` (BDK full_scan).
    pub default_empty_address_txs: bool,
}

impl MockEsploraTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable empty default for missing address-txs paths (BDK full_scan tests).
    pub fn with_default_empty_address_txs(mut self) -> Self {
        self.default_empty_address_txs = true;
        self
    }

    /// Insert a successful GET fixture body for `path`.
    pub fn insert_fixture(&mut self, path: impl Into<String>, body: impl Into<String>) {
        self.fixtures.insert(path.into(), body.into());
    }

    /// Script a hard error for GET `path`.
    pub fn fail_path(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.fail_paths.insert(path.into(), message.into());
    }

    /// Insert a successful POST fixture body for `path`.
    pub fn insert_post_fixture(&mut self, path: impl Into<String>, body: impl Into<String>) {
        self.post_fixtures.insert(path.into(), body.into());
    }

    /// Script a hard error for POST `path`.
    pub fn fail_post_path(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.post_fail_paths.insert(path.into(), message.into());
    }
}

impl EsploraTransport for MockEsploraTransport {
    fn get_text(&mut self, path: &str) -> Result<String> {
        self.calls.push(path.to_owned());
        if let Some(msg) = self.fail_paths.get(path) {
            return Err(WalletError::Explorer(msg.clone()));
        }
        if let Some(body) = self.fixtures.get(path) {
            return Ok(body.clone());
        }
        if self.default_empty_address_txs && is_esplora_address_txs_path(path) {
            return Ok("[]".to_owned());
        }
        Err(WalletError::Explorer(format!(
            "mock esplora: no fixture for path {path}"
        )))
    }

    fn post_text(&mut self, path: &str, body: &str) -> Result<String> {
        self.post_calls.push((path.to_owned(), body.to_owned()));
        if let Some(msg) = self.post_fail_paths.get(path) {
            return Err(WalletError::Explorer(msg.clone()));
        }
        self.post_fixtures.get(path).cloned().ok_or_else(|| {
            WalletError::Explorer(format!("mock esplora: no POST fixture for path {path}"))
        })
    }
}

/// Fail-closed path-segment check before interpolating an address into an
/// Esplora REST path.
///
/// Rejects empty strings and any character outside the Base58/bech32 address
/// alphabet (ASCII alphanumeric only). That blocks `/`, `..`, `?`, `#`, `%`,
/// spaces, and other path/query escapes that could rewrite
/// `/address/{addr}/utxo` once joined to a base URL.
///
/// This is a **path-safety** gate, not full Bitcoin address validation (product
/// wallets still derive real addresses). Invalid charset → hard error.
pub fn validate_esplora_address_path_segment(address: &str) -> Result<&str> {
    if address.is_empty() {
        return Err(WalletError::Explorer(
            "esplora address path segment must not be empty".into(),
        ));
    }
    if !address.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(WalletError::Explorer(format!(
            "esplora address path segment rejected (non-alphanumeric / path-unsafe): {address:?}"
        )));
    }
    Ok(address)
}

/// Build Esplora path for address UTXOs: `/address/{addr}/utxo`.
///
/// Validates the address as a single path segment (see
/// [`validate_esplora_address_path_segment`]) so untrusted strings cannot
/// inject extra path components.
pub fn esplora_address_utxo_path(address: &str) -> Result<String> {
    let address = validate_esplora_address_path_segment(address)?;
    Ok(format!("/address/{address}/utxo"))
}

/// Esplora confirmed-history page size (Blockstream / electrs REST convention).
///
/// Full address history paginates with [`esplora_address_txs_chain_path`] while
/// each page returns this many items.
pub const ESPLORA_TXS_PAGE_SIZE: usize = 25;

/// Hard cap on Esplora history pages per address (first page + chain pages).
///
/// ~25 × 40 = 1000 txs. Hitting the cap with a full last page is a hard error
/// (never silently truncates history).
pub const ESPLORA_MAX_TX_PAGES: usize = 40;

/// Build Esplora path for address transaction history: `/address/{addr}/txs`.
///
/// First page: mempool txs + up to [`ESPLORA_TXS_PAGE_SIZE`] confirmed (newest
/// first). Same path-segment gate as [`esplora_address_utxo_path`]. Used by BDK
/// full_scan (feature `bdk`); continue with [`esplora_address_txs_chain_path`].
pub fn esplora_address_txs_path(address: &str) -> Result<String> {
    let address = validate_esplora_address_path_segment(address)?;
    Ok(format!("/address/{address}/txs"))
}

/// Build Esplora confirmed-history continuation:
/// `/address/{addr}/txs/chain/{last_txid}`.
///
/// `last_txid` is the oldest txid from the previous page (Esplora pagination
/// cursor). Path-segment gates on address and 64-hex txid.
pub fn esplora_address_txs_chain_path(address: &str, last_txid: &str) -> Result<String> {
    let address = validate_esplora_address_path_segment(address)?;
    let t = last_txid.trim();
    if !is_valid_txid_hex(t) {
        return Err(WalletError::Explorer(format!(
            "esplora address txs chain path: last_txid must be 64 hex chars, got len {} / non-hex",
            t.len()
        )));
    }
    Ok(format!(
        "/address/{address}/txs/chain/{}",
        t.to_ascii_lowercase()
    ))
}

/// Build Esplora path for raw transaction hex: `/tx/{txid}/hex`.
///
/// `txid` must be 64 ASCII hex chars (path-safe). Rejects injection.
pub fn esplora_tx_hex_path(txid: &str) -> Result<String> {
    let t = txid.trim();
    if !is_valid_txid_hex(t) {
        return Err(WalletError::Explorer(format!(
            "esplora tx hex path: txid must be 64 hex chars, got len {} / non-hex",
            t.len()
        )));
    }
    Ok(format!("/tx/{}/hex", t.to_ascii_lowercase()))
}

/// True when `path` is an Esplora address history path:
/// `/address/{seg}/txs` or `/address/{seg}/txs/chain[/{txid}]`.
///
/// Used by mock default-empty behavior and offline path classification.
pub fn is_esplora_address_txs_path(path: &str) -> bool {
    let p = path.trim();
    let Some(rest) = p.strip_prefix("/address/") else {
        return false;
    };
    let Some((seg, tail)) = rest.split_once('/') else {
        return false;
    };
    if seg.is_empty() || !seg.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if tail == "txs" {
        return true;
    }
    // txs/chain or txs/chain/{64hex}
    let Some(after) = tail.strip_prefix("txs/chain") else {
        return false;
    };
    if after.is_empty() {
        return true;
    }
    let Some(txid) = after.strip_prefix('/') else {
        return false;
    };
    is_valid_txid_hex(txid)
}

/// One item from Esplora `GET /address/{addr}/txs` (or chain page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsploraTxHistoryEntry {
    pub txid: String,
    /// Confirmed block height when `status.confirmed` and height present.
    /// `None` = unconfirmed / mempool (or confirmed without height — treated
    /// as unconfirmed for confirmation math honesty).
    pub block_height: Option<u32>,
}

/// Build Esplora path for chain tip height: `/blocks/tip/height`.
pub fn esplora_tip_height_path() -> &'static str {
    "/blocks/tip/height"
}

/// Build Esplora path for transaction broadcast: `POST /tx`.
///
/// Body is raw transaction hex (no `0x` prefix). Success body is a 64-hex txid
/// (same parse as mempool.space `POST /api/tx`).
pub fn esplora_broadcast_tx_path() -> &'static str {
    "/tx"
}

/// Parse Esplora / mempool.space address txs JSON into ordered unique entries
/// (first-seen order), including confirmation height when present.
///
/// Item shape: `{"txid":"…", "status":{"confirmed":bool,"block_height":N}, …}`.
/// Empty array → empty vec (honest "no history"). Malformed JSON / non-array /
/// missing/invalid txid → hard error (never invents empty Success from garbage).
pub fn parse_esplora_address_txs_entries(body: &str) -> Result<Vec<EsploraTxHistoryEntry>> {
    let v: serde_json::Value = serde_json::from_str(body.trim())
        .map_err(|e| WalletError::Explorer(format!("esplora address txs JSON parse: {e}")))?;
    let arr = v
        .as_array()
        .ok_or_else(|| WalletError::Explorer("esplora address txs: expected JSON array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    let mut seen = std::collections::BTreeSet::new();
    for item in arr {
        let txid = item
            .get("txid")
            .and_then(|t| t.as_str())
            .ok_or_else(|| WalletError::Explorer("esplora address txs item missing txid".into()))?
            .trim();
        if !is_valid_txid_hex(txid) {
            return Err(WalletError::Explorer(format!(
                "esplora address txs txid must be 64 hex chars, got len {} / non-hex",
                txid.len()
            )));
        }
        let lower = txid.to_ascii_lowercase();
        if !seen.insert(lower.clone()) {
            continue;
        }
        let block_height = parse_esplora_tx_status_block_height(item);
        out.push(EsploraTxHistoryEntry {
            txid: lower,
            block_height,
        });
    }
    Ok(out)
}

/// Parse Esplora address txs JSON into ordered unique txids (first-seen order).
///
/// Convenience over [`parse_esplora_address_txs_entries`] when only ids matter.
pub fn parse_esplora_address_txs_txids(body: &str) -> Result<Vec<String>> {
    Ok(parse_esplora_address_txs_entries(body)?
        .into_iter()
        .map(|e| e.txid)
        .collect())
}

/// Extract confirmed block height from one Esplora address-txs item.
///
/// Requires `status.confirmed == true` **and** a present `block_height`.
/// Otherwise returns `None` (mempool / unconfirmed / incomplete status).
fn parse_esplora_tx_status_block_height(item: &serde_json::Value) -> Option<u32> {
    let status = item.get("status")?;
    let confirmed = status.get("confirmed").and_then(|c| c.as_bool())?;
    if !confirmed {
        return None;
    }
    let h = status.get("block_height")?;
    let n = h
        .as_u64()
        .or_else(|| h.as_i64().and_then(|i| u64::try_from(i).ok()))
        .or_else(|| h.as_str()?.parse().ok())?;
    if n == 0 {
        return None;
    }
    u32::try_from(n).ok()
}

/// Join `base_url` (no trailing slash required) with an absolute `path`
/// (`/address/…`). Pure / offline-testable.
pub fn esplora_join_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if path.is_empty() {
        return base.to_owned();
    }
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

/// Parse Esplora / mempool.space `GET /address/{addr}/utxo` JSON into
/// [`WalletUtxo`]s. Alias of
/// [`crate::descriptor_wallet::parse_mempool_address_utxos`] (same schema).
pub fn parse_esplora_address_utxos(
    body: &str,
    address: &str,
    tip_height: Option<u64>,
) -> Result<Vec<WalletUtxo>> {
    parse_mempool_address_utxos(body, address, tip_height)
}

/// Esplora REST [`ChainSource`] over an injectable transport.
///
/// **Tip height:** one tip probe per `list_unspent_for_addresses` call. When
/// tip is missing (transport error / unparseable), API-confirmed UTXOs still
/// get `confirmations = 1` via the shared parser — spend-eligible under
/// `confirmed_only`, but depth is untrusted (same policy as
/// [`crate::descriptor_wallet::MempoolChainSource`]).
///
/// Default unit tests inject [`MockEsploraTransport`]; live network requires
/// feature `esplora` + [`HttpEsploraTransport`].
#[derive(Debug)]
pub struct EsploraChainSource<T: EsploraTransport> {
    transport: RefCell<T>,
}

impl<T: EsploraTransport> EsploraChainSource<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport: RefCell::new(transport),
        }
    }

    /// Borrow the inner transport (tests inspect recorded calls).
    pub fn transport(&self) -> std::cell::Ref<'_, T> {
        self.transport.borrow()
    }

    /// Mutable borrow of the inner transport.
    pub fn transport_mut(&self) -> std::cell::RefMut<'_, T> {
        self.transport.borrow_mut()
    }
}

impl<T: EsploraTransport> ChainSource for EsploraChainSource<T> {
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>> {
        let mut transport = self.transport.borrow_mut();
        // One tip probe for confirmation math across all address UTXOs.
        // Missing tip is non-fatal (parser falls back to conf=1 for confirmed).
        let tip = transport
            .get_text(esplora_tip_height_path())
            .ok()
            .and_then(|b| parse_tip_height(&b));

        let mut out = Vec::new();
        for addr in addresses {
            // Path-segment gate before any transport call (blocks injection).
            let path = esplora_address_utxo_path(addr)?;
            let body = transport.get_text(&path).map_err(|e| {
                WalletError::Explorer(format!(
                    "failed to fetch Esplora UTXOs for address (transport error): {e}"
                ))
            })?;
            let parsed = parse_esplora_address_utxos(&body, addr, tip)?;
            out.extend(parsed);
        }
        Ok(out)
    }
}

/// Live HTTP Esplora transport (reqwest blocking + rate limiter).
///
/// Only available with feature `esplora`. Default CI builds stay offline-safe.
#[cfg(feature = "esplora")]
#[derive(Debug)]
pub struct HttpEsploraTransport {
    base_url: String,
    explorer: crate::explorer::RateLimitedExplorer,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "esplora")]
impl HttpEsploraTransport {
    /// `base_url` is the Esplora API root, e.g. `https://blockstream.info/api`
    /// or `https://mempool.space/api` (no trailing path segment beyond `/api`).
    pub fn new(base_url: impl Into<String>, cfg: crate::explorer::ExplorerConfig) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if base_url.is_empty() {
            return Err(WalletError::Explorer(
                "esplora base_url must not be empty".into(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent(concat!(
                "grok-bitcoin-wallet/",
                env!("CARGO_PKG_VERSION"),
                " (Routstr Esplora; +https://github.com/SurmountSystems/grok-oss)"
            ))
            .build()
            .map_err(|e| WalletError::Explorer(format!("http client: {e}")))?;
        Ok(Self {
            base_url,
            explorer: crate::explorer::RateLimitedExplorer::new(cfg),
            client,
        })
    }

    pub fn with_defaults(base_url: impl Into<String>) -> Result<Self> {
        Self::new(base_url, crate::explorer::ExplorerConfig::default())
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn explorer(&self) -> &crate::explorer::RateLimitedExplorer {
        &self.explorer
    }

    pub fn explorer_mut(&mut self) -> &mut crate::explorer::RateLimitedExplorer {
        &mut self.explorer
    }
}

#[cfg(feature = "esplora")]
impl EsploraTransport for HttpEsploraTransport {
    fn get_text(&mut self, path: &str) -> Result<String> {
        let url = esplora_join_url(&self.base_url, path);
        let client = &self.client;
        self.explorer
            .get_or_fetch_blocking(&url, || match client.get(&url).send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().unwrap_or_default();
                    crate::explorer::fetch_result_from_http(status, body)
                }
                Err(_) => crate::explorer::FetchResult::Error,
            })
            .ok_or_else(|| {
                WalletError::Explorer(format!("esplora GET failed or rate-limited: {url}"))
            })
    }

    fn post_text(&mut self, path: &str, body: &str) -> Result<String> {
        let url = esplora_join_url(&self.base_url, path);
        let client = &self.client;
        let body_owned = body.to_owned();
        let last_status = std::cell::Cell::new(0u16);
        let last_body = std::cell::RefCell::new(String::new());
        let maybe = self.explorer.post_no_cache_blocking(|| {
            match client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "text/plain")
                .body(body_owned.clone())
                .send()
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().unwrap_or_default();
                    last_status.set(status);
                    *last_body.borrow_mut() = text.clone();
                    crate::explorer::fetch_result_from_http(status, text)
                }
                Err(e) => {
                    last_status.set(0);
                    *last_body.borrow_mut() = e.to_string();
                    crate::explorer::FetchResult::Error
                }
            }
        });
        match maybe {
            Some(text) => Ok(text),
            None => {
                let status = last_status.get();
                let text = last_body.into_inner();
                match broadcast_outcome_from_http(if status == 0 { 503 } else { status }, text) {
                    BroadcastHttpOutcome::RateLimited => Err(WalletError::Explorer(
                        "esplora POST rate-limited (or gated) after retries".into(),
                    )),
                    BroadcastHttpOutcome::Rejected { message, .. } => Err(WalletError::Explorer(
                        format!("esplora POST failed: {message}"),
                    )),
                    BroadcastHttpOutcome::Accepted { .. } => Err(WalletError::Explorer(
                        "esplora POST returned empty after rate-limit gate".into(),
                    )),
                }
            }
        }
    }
}

#[cfg(feature = "esplora")]
impl EsploraChainSource<HttpEsploraTransport> {
    /// Convenience: Esplora chain source with live HTTP transport.
    pub fn with_http_base_url(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self::new(HttpEsploraTransport::with_defaults(base_url)?))
    }
}

/// Esplora REST [`TxBroadcaster`] over an injectable transport (`POST /tx`).
///
/// Validates raw hex **before** any transport call. Never claims success without
/// a parseable 64-hex txid body ([`parse_broadcast_txid_body`]).
#[derive(Debug)]
pub struct EsploraTxBroadcaster<T: EsploraTransport> {
    transport: T,
}

impl<T: EsploraTransport> EsploraTxBroadcaster<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the inner transport (tests inspect recorded POST calls).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutable borrow of the inner transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: EsploraTransport> TxBroadcaster for EsploraTxBroadcaster<T> {
    fn broadcast_raw_tx_hex(&mut self, raw_tx_hex: &str) -> Result<BroadcastResult> {
        let trimmed = validate_raw_tx_hex(raw_tx_hex)?;
        let path = esplora_broadcast_tx_path();
        let body = self.transport.post_text(path, trimmed).map_err(|e| {
            WalletError::Explorer(format!("esplora broadcast transport error: {e}"))
        })?;
        // Pure parse: same gate as mempool POST /api/tx (never invent txid).
        match parse_broadcast_txid_body(&body) {
            Ok(txid) => Ok(BroadcastResult { txid }),
            Err(message) => Err(WalletError::Explorer(format!(
                "esplora broadcast rejected: {message}"
            ))),
        }
    }
}

#[cfg(feature = "esplora")]
impl EsploraTxBroadcaster<HttpEsploraTransport> {
    /// Convenience: Esplora broadcaster with live HTTP transport.
    pub fn with_http_base_url(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self::new(HttpEsploraTransport::with_defaults(base_url)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor_wallet::{MockChainSource, OutPointRef, WalletUtxo};

    const TXID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TXID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sample_utxo_json(txid: &str, vout: u32, value: u64, confirmed: bool, height: u64) -> String {
        format!(
            r#"[{{"txid":"{txid}","vout":{vout},"value":{value},"status":{{"confirmed":{confirmed},"block_height":{height}}}}}]"#,
            confirmed = if confirmed { "true" } else { "false" },
        )
    }

    #[test]
    fn join_url_trims_and_prefixes() {
        assert_eq!(
            esplora_join_url("https://example.com/api/", "/address/x/utxo"),
            "https://example.com/api/address/x/utxo"
        );
        assert_eq!(
            esplora_join_url("https://example.com/api", "blocks/tip/height"),
            "https://example.com/api/blocks/tip/height"
        );
        assert_eq!(
            esplora_join_url("https://example.com/api", ""),
            "https://example.com/api"
        );
    }

    #[test]
    fn path_helpers_stable() {
        assert_eq!(
            esplora_address_utxo_path("bc1qtest").unwrap(),
            "/address/bc1qtest/utxo"
        );
        assert_eq!(
            esplora_address_txs_path("bc1qtest").unwrap(),
            "/address/bc1qtest/txs"
        );
        assert_eq!(
            esplora_address_txs_chain_path("bc1qtest", TXID_A).unwrap(),
            format!("/address/bc1qtest/txs/chain/{TXID_A}")
        );
        assert_eq!(
            esplora_tx_hex_path(TXID_A).unwrap(),
            format!("/tx/{TXID_A}/hex")
        );
        assert_eq!(esplora_tip_height_path(), "/blocks/tip/height");
        assert_eq!(esplora_broadcast_tx_path(), "/tx");
        // Join broadcast path under a fixed base (no path injection).
        assert_eq!(
            esplora_join_url("https://blockstream.info/api", esplora_broadcast_tx_path()),
            "https://blockstream.info/api/tx"
        );
        assert!(is_esplora_address_txs_path("/address/bc1qtest/txs"));
        assert!(is_esplora_address_txs_path(&format!(
            "/address/bc1qtest/txs/chain/{TXID_A}"
        )));
        assert!(!is_esplora_address_txs_path("/address/bc1qtest/utxo"));
        assert!(!is_esplora_address_txs_path("/tx/abc/hex"));
        assert!(esplora_address_txs_chain_path("bc1qtest", "short").is_err());
    }

    #[test]
    fn parse_address_txs_txids_and_tx_hex_path_gates() {
        let body = format!(
            r#"[{{"txid":"{TXID_A}","status":{{"confirmed":true,"block_height":100}}}},{{"txid":"{TXID_B}","status":{{"confirmed":false}}}}]"#
        );
        let ids = parse_esplora_address_txs_txids(&body).unwrap();
        assert_eq!(ids, vec![TXID_A.to_owned(), TXID_B.to_owned()]);
        let entries = parse_esplora_address_txs_entries(&body).unwrap();
        assert_eq!(entries[0].block_height, Some(100));
        assert_eq!(entries[1].block_height, None);
        assert!(parse_esplora_address_txs_txids("[]").unwrap().is_empty());
        assert!(parse_esplora_address_txs_txids("not-json").is_err());
        assert!(parse_esplora_address_txs_txids(r#"{"txid":"x"}"#).is_err());
        assert!(parse_esplora_address_txs_txids(r#"[{"txid":"zz"}]"#).is_err());
        // Uppercase txid path normalizes.
        let upper = TXID_A.to_ascii_uppercase();
        assert_eq!(
            esplora_tx_hex_path(&upper).unwrap(),
            format!("/tx/{TXID_A}/hex")
        );
        assert!(esplora_tx_hex_path("short").is_err());
        assert!(esplora_tx_hex_path("../evil").is_err());
    }

    #[test]
    fn mock_default_empty_address_txs() {
        let mock = MockEsploraTransport::new().with_default_empty_address_txs();
        let mut t = mock;
        assert_eq!(t.get_text("/address/bc1qempty/txs").unwrap(), "[]");
        assert_eq!(
            t.get_text(&format!("/address/bc1qempty/txs/chain/{TXID_A}"))
                .unwrap(),
            "[]"
        );
        // Non-txs paths still hard-error without fixture.
        assert!(t.get_text("/blocks/tip/height").is_err());
        assert!(t.get_text(&format!("/tx/{TXID_A}/hex")).is_err());
    }

    #[test]
    fn address_path_rejects_injection_and_non_alphanumeric() {
        for bad in [
            "../admin",
            "bc1q/../utxo",
            "bc1q?x=1",
            "bc1q#frag",
            "bc1q%2e%2e",
            "bc1q test",
            "bc1q/extra",
            "",
            "bc1q.with.dots",
        ] {
            let err = esplora_address_utxo_path(bad).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("path segment")
                    || msg.contains("path-unsafe")
                    || msg.contains("empty"),
                "expected path rejection for {bad:?}, got {msg}"
            );
            // Must not produce a joinable escaped path under a fixed base.
            assert!(
                !msg.contains("/address/../") || bad.is_empty(),
                "error must not echo a successful path for {bad:?}: {msg}"
            );
        }
        // Slash / dots never appear in a successful path build.
        let err = esplora_address_utxo_path("evil/../../etc").unwrap_err();
        assert!(!err.to_string().contains("/address/evil/"));
        let joined_base = "https://example.com/api";
        // Even if a caller ignored validation, charset gate is the contract;
        // assert join of a *validated* path stays under /address/.../utxo.
        let ok = esplora_address_utxo_path("bc1qsafeaddr").unwrap();
        let url = esplora_join_url(joined_base, &ok);
        assert_eq!(url, "https://example.com/api/address/bc1qsafeaddr/utxo");
        assert!(!url.contains(".."));
    }

    #[test]
    fn chain_source_rejects_path_injection_before_transport() {
        let mock = MockEsploraTransport::new();
        let chain = EsploraChainSource::new(mock);
        let err = chain
            .list_unspent_for_addresses(&["bc1q/../escape".into()])
            .unwrap_err();
        assert!(
            err.to_string().contains("path") || err.to_string().contains("path-unsafe"),
            "{err}"
        );
        // Transport never called for the malicious address (tip may still run).
        let t = chain.transport();
        assert!(
            t.calls
                .iter()
                .all(|p| !p.contains("..") && !p.contains("/escape")),
            "calls: {:?}",
            t.calls
        );
    }

    #[test]
    fn parse_esplora_reuses_mempool_schema() {
        let body = sample_utxo_json(TXID_A, 1, 50_000, true, 100);
        let utxos = parse_esplora_address_utxos(&body, "bc1qabc", Some(102)).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].outpoint.txid, TXID_A);
        assert_eq!(utxos[0].outpoint.vout, 1);
        assert_eq!(utxos[0].amount_sats, 50_000);
        assert_eq!(utxos[0].confirmations, 3);
        assert_eq!(utxos[0].address, "bc1qabc");
    }

    #[test]
    fn mock_transport_records_calls_and_serves_fixtures() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_fixture("/blocks/tip/height", "200");
        mock.insert_fixture(
            "/address/bc1qa/utxo",
            sample_utxo_json(TXID_A, 0, 10_000, true, 190),
        );
        let chain = EsploraChainSource::new(mock);
        let utxos = chain.list_unspent_for_addresses(&["bc1qa".into()]).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount_sats, 10_000);
        assert_eq!(utxos[0].confirmations, 11); // tip 200, height 190
        let t = chain.transport();
        assert_eq!(
            t.calls,
            vec![
                "/blocks/tip/height".to_owned(),
                "/address/bc1qa/utxo".to_owned()
            ]
        );
    }

    #[test]
    fn missing_tip_falls_back_to_conf_one_for_confirmed() {
        let mut mock = MockEsploraTransport::new();
        // No tip fixture → tip probe errors → tip = None.
        mock.insert_fixture(
            "/address/bc1qb/utxo",
            sample_utxo_json(TXID_B, 2, 99, true, 50),
        );
        let chain = EsploraChainSource::new(mock);
        let utxos = chain.list_unspent_for_addresses(&["bc1qb".into()]).unwrap();
        assert_eq!(utxos[0].confirmations, 1);
    }

    #[test]
    fn address_utxo_transport_error_is_hard_error() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_fixture("/blocks/tip/height", "1");
        mock.fail_path("/address/bc1qfail/utxo", "simulated 503");
        let chain = EsploraChainSource::new(mock);
        let err = chain
            .list_unspent_for_addresses(&["bc1qfail".into()])
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("failed to fetch Esplora UTXOs") || msg.contains("simulated 503"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn missing_fixture_is_hard_error_not_empty_list() {
        let mock = MockEsploraTransport::new();
        let chain = EsploraChainSource::new(mock);
        let err = chain
            .list_unspent_for_addresses(&["bc1qnone".into()])
            .unwrap_err();
        assert!(
            err.to_string().contains("no fixture") || err.to_string().contains("failed to fetch"),
            "{}",
            err
        );
    }

    #[test]
    fn multi_address_aggregates_and_filters_like_mock_chain() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_fixture("/blocks/tip/height", "1000");
        mock.insert_fixture(
            "/address/bc1qrecv/utxo",
            sample_utxo_json(TXID_A, 0, 40_000, true, 990),
        );
        mock.insert_fixture("/address/bc1qchange/utxo", "[]");
        let chain = EsploraChainSource::new(mock);
        let utxos = chain
            .list_unspent_for_addresses(&["bc1qrecv".into(), "bc1qchange".into()])
            .unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].address, "bc1qrecv");

        // Sanity: MockChainSource still filters by address set (regression).
        let mock_chain = MockChainSource::with_utxos(vec![WalletUtxo {
            outpoint: OutPointRef::new(TXID_A, 0),
            amount_sats: 40_000,
            address: "bc1qrecv".into(),
            confirmations: 11,
            is_change: false,
        }]);
        let filtered = mock_chain
            .list_unspent_for_addresses(&["bc1qrecv".into()])
            .unwrap();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn unconfirmed_utxo_has_zero_confirmations() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_fixture("/blocks/tip/height", "500");
        mock.insert_fixture(
            "/address/bc1qunconf/utxo",
            sample_utxo_json(TXID_A, 0, 1, false, 0),
        );
        let chain = EsploraChainSource::new(mock);
        let utxos = chain
            .list_unspent_for_addresses(&["bc1qunconf".into()])
            .unwrap();
        assert_eq!(utxos[0].confirmations, 0);
    }

    #[test]
    fn corrupt_utxo_json_is_hard_error() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_fixture("/blocks/tip/height", "1");
        mock.insert_fixture("/address/bc1qbad/utxo", r#"{"not":"array"}"#);
        let chain = EsploraChainSource::new(mock);
        let err = chain
            .list_unspent_for_addresses(&["bc1qbad".into()])
            .unwrap_err();
        assert!(
            err.to_string().contains("expected array") || err.to_string().contains("JSON"),
            "{err}"
        );
    }

    #[test]
    fn empty_utxo_array_is_ok() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_fixture("/blocks/tip/height", "1");
        mock.insert_fixture("/address/bc1qempty/utxo", "[]");
        let chain = EsploraChainSource::new(mock);
        let utxos = chain
            .list_unspent_for_addresses(&["bc1qempty".into()])
            .unwrap();
        assert!(utxos.is_empty());
    }

    // --- Esplora TxBroadcaster (POST /tx) ---

    #[test]
    fn broadcaster_accepts_valid_txid_body() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_post_fixture("/tx", TXID_A);
        let mut b = EsploraTxBroadcaster::new(mock);
        let res = b.broadcast_raw_tx_hex("deadbeef").unwrap();
        assert_eq!(res.txid, TXID_A);
        let t = b.transport();
        assert_eq!(t.post_calls.len(), 1);
        assert_eq!(t.post_calls[0].0, "/tx");
        assert_eq!(t.post_calls[0].1, "deadbeef");
        // GET fixtures unused for broadcast.
        assert!(t.calls.is_empty());
    }

    #[test]
    fn broadcaster_normalizes_mixed_case_txid() {
        let mut mock = MockEsploraTransport::new();
        let upper = TXID_A.to_ascii_uppercase();
        mock.insert_post_fixture("/tx", format!("  {upper}\n"));
        let mut b = EsploraTxBroadcaster::new(mock);
        let res = b.broadcast_raw_tx_hex("aabb").unwrap();
        assert_eq!(res.txid, TXID_A);
    }

    #[test]
    fn broadcaster_rejects_empty_and_non_hex_before_transport() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_post_fixture("/tx", TXID_A);
        let mut b = EsploraTxBroadcaster::new(mock);
        let err_empty = b.broadcast_raw_tx_hex("").unwrap_err().to_string();
        assert!(
            err_empty.contains("empty") || err_empty.contains("hex"),
            "{err_empty}"
        );
        let err_odd = b.broadcast_raw_tx_hex("abc").unwrap_err().to_string();
        assert!(
            err_odd.contains("hex") || err_odd.contains("even"),
            "{err_odd}"
        );
        let err_non = b.broadcast_raw_tx_hex("zzzz").unwrap_err().to_string();
        assert!(err_non.contains("hex"), "{err_non}");
        // No POST should have been recorded for invalid hex.
        assert!(b.transport().post_calls.is_empty());
    }

    #[test]
    fn broadcaster_rejects_non_txid_response_body() {
        let mut mock = MockEsploraTransport::new();
        mock.insert_post_fixture("/tx", "not-a-txid");
        let mut b = EsploraTxBroadcaster::new(mock);
        let err = b.broadcast_raw_tx_hex("00").unwrap_err().to_string();
        assert!(
            err.contains("rejected") || err.contains("64-hex") || err.contains("txid"),
            "{err}"
        );
        // Transport was called (body was bad, not hex gate).
        assert_eq!(b.transport().post_calls.len(), 1);
    }

    #[test]
    fn broadcaster_transport_error_is_hard() {
        let mut mock = MockEsploraTransport::new();
        mock.fail_post_path("/tx", "simulated 400 sendrawtransaction");
        let mut b = EsploraTxBroadcaster::new(mock);
        let err = b.broadcast_raw_tx_hex("00aa").unwrap_err().to_string();
        assert!(
            err.contains("transport error") || err.contains("simulated 400"),
            "{err}"
        );
    }

    #[test]
    fn broadcaster_missing_post_fixture_is_hard_error() {
        let mock = MockEsploraTransport::new();
        let mut b = EsploraTxBroadcaster::new(mock);
        let err = b.broadcast_raw_tx_hex("00").unwrap_err().to_string();
        assert!(
            err.contains("no POST fixture") || err.contains("transport error"),
            "{err}"
        );
    }

    #[test]
    fn get_only_transport_default_post_errors() {
        // Exercise default trait method via a GET-only stub.
        struct GetOnly;
        impl EsploraTransport for GetOnly {
            fn get_text(&mut self, _path: &str) -> Result<String> {
                Ok(String::new())
            }
        }
        let mut b = EsploraTxBroadcaster::new(GetOnly);
        let err = b.broadcast_raw_tx_hex("00").unwrap_err().to_string();
        assert!(
            err.contains("POST not supported") || err.contains("transport error"),
            "{err}"
        );
    }
}
