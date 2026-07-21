//! Electrum JSON-RPC-shaped [`ChainSource`] + [`TxBroadcaster`] (electrs, Fulcrum, …).
//!
//! Offline by default: pure scripthash + request/response helpers +
//! [`MockElectrumTransport`] fixtures. Live transports are opt-in behind feature
//! `electrum` ([`TcpElectrumTransport`] plaintext, [`TlsElectrumTransport`] rustls
//! + WebPKI roots) and are **not** enabled in default CI.
//!
//! Protocol (subset used here):
//! - `blockchain.scripthash.listunspent` — UTXOs for an address script hash
//! - `blockchain.scripthash.get_history` — spent-tx history for BDK full_scan
//! - `blockchain.transaction.get` — raw tx hex (verbose=false) for BDK apply_update
//! - `blockchain.headers.subscribe` — tip height for confirmation math
//! - `blockchain.transaction.broadcast` — push raw tx hex; result is txid string
//!
//! Electrum **script hash** = reverse(SHA256(scriptPubKey)) as hex
//! (Electrum protocol, not BIP).
//!
//! ## TLS
//!
//! [`TlsElectrumTransport`] wraps TCP with **rustls** (WebPKI roots; no skip-verify).
//! Product wire: `GROK_BITCOIN_ELECTRUM_TLS=1|true|yes` or `ssl://host:port` in
//! [`crate::chain_select`]. Default remains plaintext TCP for local/regtest.
//!
//! **SNI / cert name:** hostname is taken from `host:port` (or the host inside
//! `[ipv6]:port`). IP-literal addresses use an IP server name (no DNS SNI
//! hostname). Public Electrum TLS servers typically need a DNS name that matches
//! the certificate — IP-only endpoints will fail cert verification honestly as a
//! structured Explorer error.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::str::FromStr;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Address, Network, ScriptBuf};
use serde_json::{Value, json};

use crate::descriptor_wallet::{ChainSource, OutPointRef, WalletUtxo};
use crate::error::{Result, WalletError};
use crate::explorer::{BroadcastResult, TxBroadcaster, is_valid_txid_hex, validate_raw_tx_hex};
use crate::watcher::confirmations_from_heights;

/// Injectable Electrum JSON-RPC transport.
///
/// Implementations must not invent listunspent results on failure — return
/// [`Err`]. Unit tests use [`MockElectrumTransport`]; live TCP/TLS is feature-gated.
pub trait ElectrumTransport {
    /// Call `method` with JSON-RPC `params`; return the `result` value.
    fn call(&mut self, method: &str, params: &[Value]) -> Result<Value>;
}

/// Max Electrum JSON-RPC **response** line size (bytes) for live TCP/TLS transports.
///
/// Bounds allocation against a misbehaving peer (unbounded `read_line` is not safe on
/// public TLS endpoints). 1 MiB is well above normal headers/listunspent replies while
/// still fail-closed on pathological streams.
#[cfg(feature = "electrum")]
pub const ELECTRUM_MAX_RESPONSE_LINE_BYTES: usize = 1_048_576;

/// Shared Electrum JSON-RPC line framing over any [`Read`](std::io::Read)+[`Write`](std::io::Write).
///
/// Writes one request line, reads one response line (capped at
/// [`ELECTRUM_MAX_RESPONSE_LINE_BYTES`]), then requires matching `id`.
/// Used by plaintext TCP and TLS live transports (feature `electrum`).
#[cfg(feature = "electrum")]
fn electrum_jsonrpc_call_over_stream<S: std::io::Read + std::io::Write>(
    mut stream: S,
    id: u64,
    method: &str,
    params: &[Value],
    transport_label: &str,
) -> Result<Value> {
    use std::io::BufReader;

    let line = electrum_request_line(id, method, params);
    // `S: Write` bound — write_all resolves without importing Write.
    std::io::Write::write_all(&mut stream, line.as_bytes())
        .map_err(|e| WalletError::Explorer(format!("electrum {transport_label} write: {e}")))?;

    let mut reader = BufReader::new(stream);
    let resp = electrum_read_response_line(
        &mut reader,
        ELECTRUM_MAX_RESPONSE_LINE_BYTES,
        transport_label,
    )?;
    if resp.trim().is_empty() {
        return Err(WalletError::Explorer(format!(
            "electrum {transport_label} empty response line"
        )));
    }
    parse_electrum_response_result_for_id(&resp, Some(id))
}

/// Read one newline-terminated response line with a hard byte cap (no unbounded grow).
///
/// Stops with [`WalletError::Explorer`] if more than `max_bytes` would be stored before
/// a `\n` (or EOF without newline beyond the cap). Shared by TCP and TLS framers.
#[cfg(feature = "electrum")]
fn electrum_read_response_line<R: std::io::BufRead>(
    reader: &mut R,
    max_bytes: usize,
    transport_label: &str,
) -> Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|e| WalletError::Explorer(format!("electrum {transport_label} read: {e}")))?;
        if available.is_empty() {
            break;
        }
        let nl = available.iter().position(|&b| b == b'\n');
        let chunk = match nl {
            Some(i) => &available[..=i],
            None => available,
        };
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(WalletError::Explorer(format!(
                "electrum {transport_label} response line exceeds {max_bytes} bytes \
                 (refusing unbounded allocation)"
            )));
        }
        buf.extend_from_slice(chunk);
        let consume = chunk.len();
        reader.consume(consume);
        if nl.is_some() {
            break;
        }
    }
    String::from_utf8(buf).map_err(|e| {
        WalletError::Explorer(format!(
            "electrum {transport_label} response line is not valid UTF-8: {e}"
        ))
    })
}

/// Host portion of an Electrum `host:port` or `[ipv6]:port` endpoint (no scheme).
///
/// Offline pure parse; does not validate port range (callers that need full
/// product shape checks use `chain_select`). Used for TLS SNI / cert name.
#[cfg(feature = "electrum")]
pub fn electrum_host_from_addr(addr: &str) -> Result<String> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Explorer(
            "electrum addr empty (expected host:port or [ipv6]:port)".into(),
        ));
    }
    if trimmed.contains("://") {
        return Err(WalletError::Explorer(format!(
            "electrum host extract: unexpected URI scheme in {trimmed:?}; pass host:port only"
        )));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some((host, _port)) = rest.split_once("]:") else {
            return Err(WalletError::Explorer(format!(
                "electrum host extract: expected [ipv6]:port, got {trimmed:?}"
            )));
        };
        if host.is_empty() {
            return Err(WalletError::Explorer(
                "electrum host extract: empty IPv6 host".into(),
            ));
        }
        return Ok(host.to_owned());
    }
    let Some((host, _port)) = trimmed.split_once(':') else {
        return Err(WalletError::Explorer(format!(
            "electrum host extract: expected host:port, got {trimmed:?}"
        )));
    };
    if host.is_empty() {
        return Err(WalletError::Explorer(
            "electrum host extract: empty host".into(),
        ));
    }
    Ok(host.to_owned())
}

/// TLS server name (SNI / cert identity) from `host:port` / `[ipv6]:port`.
///
/// DNS hostnames become DNS names; IPv4/IPv6 literals become IP names (no DNS SNI).
/// Never skips certificate verification.
#[cfg(feature = "electrum")]
pub fn electrum_tls_server_name(addr: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    let host = electrum_host_from_addr(addr)?;
    rustls::pki_types::ServerName::try_from(host.clone())
        .map(|n| n.to_owned())
        .map_err(|e| {
            WalletError::Explorer(format!(
                "electrum TLS invalid server name for SNI/cert from {addr:?} (host {host:?}): {e}"
            ))
        })
}

/// Shared rustls client config (WebPKI roots; no client auth; no skip-verify).
#[cfg(feature = "electrum")]
fn electrum_tls_client_config() -> Result<std::sync::Arc<rustls::ClientConfig>> {
    use std::sync::{Arc, OnceLock};

    // rustls 0.23 requires an explicit crypto provider when multiple are linked.
    static PROVIDER: OnceLock<()> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        // Ignore AlreadyInstalled — another crate in the process may have set one.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    static CONFIG: OnceLock<std::result::Result<Arc<rustls::ClientConfig>, String>> =
        OnceLock::new();
    let stored = CONFIG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    });
    match stored {
        Ok(cfg) => Ok(cfg.clone()),
        Err(msg) => Err(WalletError::Explorer(format!(
            "electrum TLS client config: {msg}"
        ))),
    }
}

/// In-memory Electrum transport for unit tests (offline fixtures only).
///
/// Keys for listunspent / get_history fixtures are Electrum script hashes
/// (64 hex chars). Missing fixtures and scripted failures are hard errors
/// unless [`Self::default_empty_history`] is set for BDK full_scan look-ahead.
#[derive(Debug, Default)]
pub struct MockElectrumTransport {
    /// script_hash (hex) → JSON array body for `listunspent` result.
    pub listunspent: BTreeMap<String, Value>,
    /// script_hash (hex) → JSON array for `get_history` result.
    pub history: BTreeMap<String, Value>,
    /// txid (lowercase hex) → raw tx hex for `blockchain.transaction.get`.
    pub transactions: BTreeMap<String, String>,
    /// Optional tip height returned by `blockchain.headers.subscribe`.
    pub tip_height: Option<u64>,
    /// When true, headers.subscribe returns an error.
    pub fail_headers: bool,
    /// Script hashes that hard-error on listunspent.
    pub fail_scripthashes: BTreeMap<String, String>,
    /// Script hashes that hard-error on get_history.
    pub fail_history: BTreeMap<String, String>,
    /// Scripted `blockchain.transaction.broadcast` results (pop front).
    ///
    /// `Ok(Value)` is returned as the JSON-RPC result; `Err(msg)` is a transport
    /// hard error. Empty queue → exhausted error (never invents a txid).
    pub broadcast_results: VecDeque<std::result::Result<Value, String>>,
    /// Recorded (method, params) calls.
    pub calls: Vec<(String, Vec<Value>)>,
    /// When true, missing get_history fixtures return `[]` (BDK full_scan).
    pub default_empty_history: bool,
}

impl MockElectrumTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tip_height(mut self, height: u64) -> Self {
        self.tip_height = Some(height);
        self
    }

    /// Enable empty default for missing get_history (BDK full_scan tests).
    pub fn with_default_empty_history(mut self) -> Self {
        self.default_empty_history = true;
        self
    }

    /// Insert listunspent result for a script hash (accepts JSON array value).
    pub fn insert_listunspent(&mut self, script_hash: impl Into<String>, result: Value) {
        self.listunspent.insert(script_hash.into(), result);
    }

    /// Insert get_history result for a script hash.
    pub fn insert_history(&mut self, script_hash: impl Into<String>, result: Value) {
        self.history.insert(script_hash.into(), result);
    }

    /// Insert raw tx hex for `blockchain.transaction.get` (txid key normalized).
    pub fn insert_transaction(&mut self, txid: impl AsRef<str>, raw_hex: impl Into<String>) {
        self.transactions
            .insert(txid.as_ref().trim().to_ascii_lowercase(), raw_hex.into());
    }

    pub fn fail_listunspent(&mut self, script_hash: impl Into<String>, message: impl Into<String>) {
        self.fail_scripthashes
            .insert(script_hash.into(), message.into());
    }

    pub fn fail_get_history(&mut self, script_hash: impl Into<String>, message: impl Into<String>) {
        self.fail_history.insert(script_hash.into(), message.into());
    }

    /// Queue a successful broadcast result (typically a JSON string txid).
    pub fn push_broadcast_ok(&mut self, result: Value) {
        self.broadcast_results.push_back(Ok(result));
    }

    /// Queue a transport-level broadcast failure.
    pub fn push_broadcast_err(&mut self, message: impl Into<String>) {
        self.broadcast_results.push_back(Err(message.into()));
    }
}

impl ElectrumTransport for MockElectrumTransport {
    fn call(&mut self, method: &str, params: &[Value]) -> Result<Value> {
        self.calls.push((method.to_owned(), params.to_vec()));
        match method {
            "blockchain.headers.subscribe" => {
                if self.fail_headers {
                    return Err(WalletError::Explorer(
                        "mock electrum: headers.subscribe failed".into(),
                    ));
                }
                match self.tip_height {
                    Some(h) => Ok(json!({ "height": h, "hex": "" })),
                    None => Err(WalletError::Explorer(
                        "mock electrum: no tip_height configured".into(),
                    )),
                }
            }
            "blockchain.scripthash.listunspent" => {
                let sh = params.first().and_then(|v| v.as_str()).ok_or_else(|| {
                    WalletError::Explorer(
                        "mock electrum: listunspent missing scripthash param".into(),
                    )
                })?;
                if let Some(msg) = self.fail_scripthashes.get(sh) {
                    return Err(WalletError::Explorer(msg.clone()));
                }
                self.listunspent.get(sh).cloned().ok_or_else(|| {
                    WalletError::Explorer(format!(
                        "mock electrum: no listunspent fixture for scripthash {sh}"
                    ))
                })
            }
            "blockchain.scripthash.get_history" => {
                let sh = params.first().and_then(|v| v.as_str()).ok_or_else(|| {
                    WalletError::Explorer(
                        "mock electrum: get_history missing scripthash param".into(),
                    )
                })?;
                if let Some(msg) = self.fail_history.get(sh) {
                    return Err(WalletError::Explorer(msg.clone()));
                }
                if let Some(v) = self.history.get(sh) {
                    return Ok(v.clone());
                }
                if self.default_empty_history {
                    return Ok(json!([]));
                }
                Err(WalletError::Explorer(format!(
                    "mock electrum: no get_history fixture for scripthash {sh}"
                )))
            }
            "blockchain.transaction.get" => {
                let txid = params.first().and_then(|v| v.as_str()).ok_or_else(|| {
                    WalletError::Explorer(
                        "mock electrum: transaction.get missing txid param".into(),
                    )
                })?;
                let key = txid.trim().to_ascii_lowercase();
                self.transactions
                    .get(&key)
                    .map(|h| Value::String(h.clone()))
                    .ok_or_else(|| {
                        WalletError::Explorer(format!(
                            "mock electrum: no transaction.get fixture for txid {key}"
                        ))
                    })
            }
            "blockchain.transaction.broadcast" => {
                // Require a string hex param (shape only; full validate is in broadcaster).
                let _hex = params.first().and_then(|v| v.as_str()).ok_or_else(|| {
                    WalletError::Explorer(
                        "mock electrum: broadcast missing raw tx hex param".into(),
                    )
                })?;
                match self.broadcast_results.pop_front() {
                    Some(Ok(v)) => Ok(v),
                    Some(Err(msg)) => Err(WalletError::Explorer(msg)),
                    None => Err(WalletError::Explorer(
                        "mock electrum: broadcast exhausted (no scripted response)".into(),
                    )),
                }
            }
            other => Err(WalletError::Explorer(format!(
                "mock electrum: unsupported method {other}"
            ))),
        }
    }
}

/// Electrum script hash for a raw `scriptPubKey`: reverse(SHA256(spk)) hex.
pub fn electrum_script_hash_from_script(script: &ScriptBuf) -> String {
    let hash = sha256::Hash::hash(script.as_bytes());
    let mut bytes = hash.to_byte_array();
    bytes.reverse();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Electrum script hash for a Bitcoin address string on `network`.
///
/// Fail-closed on invalid/unparseable addresses (never invents a hash).
pub fn electrum_script_hash_for_address(address: &str, network: Network) -> Result<String> {
    let addr = Address::from_str(address)
        .map_err(|e| WalletError::Onchain(format!("invalid address for electrum: {e}")))?
        .require_network(network)
        .map_err(|e| {
            WalletError::Onchain(format!(
                "address network mismatch for electrum ({network}): {e}"
            ))
        })?;
    Ok(electrum_script_hash_from_script(&addr.script_pubkey()))
}

/// Build a JSON-RPC request object (id, method, params). Pure / offline.
pub fn electrum_request(id: u64, method: &str, params: &[Value]) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

/// Serialize a JSON-RPC request line (trailing `\n` for Electrum wire).
pub fn electrum_request_line(id: u64, method: &str, params: &[Value]) -> String {
    let mut line = electrum_request(id, method, params).to_string();
    line.push('\n');
    line
}

/// Whether a JSON-RPC response `id` matches the request id we sent.
///
/// Accepts numeric ids and decimal string forms (`"7"`); rejects other shapes.
pub fn electrum_json_rpc_id_matches(id: &Value, expected: u64) -> bool {
    if let Some(n) = id.as_u64() {
        return n == expected;
    }
    if let Some(n) = id.as_i64() {
        return u64::try_from(n).ok() == Some(expected);
    }
    if let Some(s) = id.as_str() {
        return s.parse::<u64>().ok() == Some(expected);
    }
    false
}

/// Parse a JSON-RPC response body into the `result` value.
///
/// Fail-closed on JSON-RPC `error`, missing result, or malformed body.
/// Does **not** check response `id` — prefer
/// [`parse_electrum_response_result_for_id`] on live request/response pairs.
pub fn parse_electrum_response_result(body: &str) -> Result<Value> {
    parse_electrum_response_result_for_id(body, None)
}

/// Parse a JSON-RPC response, optionally requiring `id` to match `expected_id`.
///
/// When `expected_id` is `Some`, fail-closed on:
/// - missing `id`
/// - `id` that does not match (numeric or decimal-string forms)
/// - notification-shaped bodies (`method` present without a matching response id)
///
/// Always fail-closed on non-null `error`, missing `result`, or malformed JSON.
pub fn parse_electrum_response_result_for_id(
    body: &str,
    expected_id: Option<u64>,
) -> Result<Value> {
    let v: Value = serde_json::from_str(body.trim())
        .map_err(|e| WalletError::Explorer(format!("electrum JSON-RPC response parse: {e}")))?;

    // Notifications are method-bearing frames without a response id.
    if v.get("method").is_some() && v.get("id").is_none_or(|id| id.is_null()) {
        return Err(WalletError::Explorer(
            "electrum JSON-RPC notification (method without id) is not a valid response".into(),
        ));
    }

    if let Some(expected) = expected_id {
        match v.get("id") {
            None | Some(Value::Null) => {
                return Err(WalletError::Explorer(
                    "electrum JSON-RPC response missing id".into(),
                ));
            }
            Some(id) if electrum_json_rpc_id_matches(id, expected) => {}
            Some(id) => {
                return Err(WalletError::Explorer(format!(
                    "electrum JSON-RPC response id mismatch: expected {expected}, got {id}"
                )));
            }
        }
    }

    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(WalletError::Explorer(format!(
            "electrum JSON-RPC error: {err}"
        )));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| WalletError::Explorer("electrum JSON-RPC response missing result".into()))
}

/// Extract tip height from `blockchain.headers.subscribe` result.
///
/// Accepts `{"height": N, ...}` or a bare number.
pub fn parse_electrum_headers_subscribe_height(result: &Value) -> Option<u64> {
    if let Some(n) = result.as_u64() {
        return Some(n);
    }
    result.get("height").and_then(|h| {
        h.as_u64()
            .or_else(|| h.as_i64().and_then(|i| u64::try_from(i).ok()))
    })
}

/// Parse `blockchain.scripthash.listunspent` result array into [`WalletUtxo`]s.
///
/// Expected item shape:
/// ```json
/// { "tx_hash": "...", "tx_pos": 0, "value": 12345, "height": 800000 }
/// ```
/// `height` ≤ 0 → unconfirmed (`confirmations = 0`). When tip is known and
/// height > 0, confirmations use [`confirmations_from_heights`]; when tip is
/// missing, confirmed UTXOs get `confirmations = 1` (depth untrusted — same
/// honesty policy as mempool/Esplora tip-miss).
pub fn parse_electrum_listunspent(
    result: &Value,
    address: &str,
    tip_height: Option<u64>,
) -> Result<Vec<WalletUtxo>> {
    let arr = result
        .as_array()
        .ok_or_else(|| WalletError::Explorer("electrum listunspent: expected JSON array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let txid = item
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::Explorer("electrum utxo missing tx_hash".into()))?;
        if !is_valid_txid_hex_local(txid) {
            return Err(WalletError::Explorer(format!(
                "electrum utxo tx_hash must be 64 hex chars, got len {} / non-hex",
                txid.len()
            )));
        }
        let vout = item
            .get("tx_pos")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
            })
            .ok_or_else(|| WalletError::Explorer("electrum utxo missing tx_pos".into()))?;
        let vout = u32::try_from(vout)
            .map_err(|_| WalletError::Explorer("electrum utxo tx_pos out of range".into()))?;
        let amount_sats = item
            .get("value")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
            })
            .ok_or_else(|| WalletError::Explorer("electrum utxo missing value".into()))?;

        // height: >0 confirmed; 0 mempool; -1 unconfirmed parent (treat as 0 conf).
        let height_i = item.get("height").and_then(|v| v.as_i64()).unwrap_or(0);
        let confirmations = if height_i <= 0 {
            0
        } else {
            let block_height = u64::try_from(height_i).unwrap_or(0);
            match tip_height {
                Some(tip) => confirmations_from_heights(tip, block_height),
                None => 1,
            }
        };

        out.push(WalletUtxo {
            outpoint: OutPointRef::new(txid.to_owned(), vout),
            amount_sats,
            address: address.to_owned(),
            confirmations,
            is_change: false,
        });
    }
    Ok(out)
}

fn is_valid_txid_hex_local(s: &str) -> bool {
    is_valid_txid_hex(s)
}

/// Parse Electrum `blockchain.transaction.broadcast` JSON-RPC `result`.
///
/// Expects a string 64-hex txid (mixed case accepted; normalized lowercase).
/// Non-string / non-hex / wrong length → hard error (never invents success).
pub fn parse_electrum_broadcast_result(result: &Value) -> Result<String> {
    let s = result.as_str().ok_or_else(|| {
        WalletError::Explorer(format!(
            "electrum broadcast result must be a txid string, got {result}"
        ))
    })?;
    let t = s.trim();
    if !is_valid_txid_hex(t) {
        let preview: String = t.chars().take(80).collect();
        return Err(WalletError::Explorer(format!(
            "electrum broadcast result is not a 64-hex txid (len {}); starts: {preview:?}",
            t.len()
        )));
    }
    Ok(t.to_ascii_lowercase())
}

/// One item from Electrum `blockchain.scripthash.get_history`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectrumHistoryEntry {
    pub txid: String,
    /// Electrum height: `>0` confirmed, `0` mempool, `-1` unconfirmed parent.
    pub height: i64,
}

/// Parse `blockchain.scripthash.get_history` into ordered unique entries.
///
/// Item shape: `{"tx_hash":"…","height":N}`. Empty array → empty vec. Malformed
/// / non-array / invalid tx_hash → hard error (never invents history).
pub fn parse_electrum_get_history_entries(result: &Value) -> Result<Vec<ElectrumHistoryEntry>> {
    let arr = result
        .as_array()
        .ok_or_else(|| WalletError::Explorer("electrum get_history: expected JSON array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    let mut seen = std::collections::BTreeSet::new();
    for item in arr {
        let txid = item
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WalletError::Explorer("electrum get_history item missing tx_hash".into())
            })?
            .trim();
        if !is_valid_txid_hex(txid) {
            return Err(WalletError::Explorer(format!(
                "electrum get_history tx_hash must be 64 hex chars, got len {} / non-hex",
                txid.len()
            )));
        }
        let lower = txid.to_ascii_lowercase();
        if !seen.insert(lower.clone()) {
            continue;
        }
        // height missing → treat as unconfirmed (0); do not invent confirmed depth.
        let height = item
            .get("height")
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok()))
            })
            .unwrap_or(0);
        out.push(ElectrumHistoryEntry {
            txid: lower,
            height,
        });
    }
    Ok(out)
}

/// Parse `blockchain.scripthash.get_history` result into ordered unique txids.
///
/// Convenience over [`parse_electrum_get_history_entries`] when only ids matter.
pub fn parse_electrum_get_history_txids(result: &Value) -> Result<Vec<String>> {
    Ok(parse_electrum_get_history_entries(result)?
        .into_iter()
        .map(|e| e.txid)
        .collect())
}

/// Parse `blockchain.transaction.get` (verbose=false) result as raw tx hex.
///
/// Expects a string of even-length ASCII hex. Never invents a body.
pub fn parse_electrum_transaction_get_hex(result: &Value) -> Result<String> {
    let s = result.as_str().ok_or_else(|| {
        WalletError::Explorer(format!(
            "electrum transaction.get result must be a hex string, got {result}"
        ))
    })?;
    let t = s.trim();
    if t.is_empty() {
        return Err(WalletError::Explorer(
            "electrum transaction.get result is empty".into(),
        ));
    }
    if !t.bytes().all(|b| b.is_ascii_hexdigit()) || !t.len().is_multiple_of(2) {
        return Err(WalletError::Explorer(
            "electrum transaction.get result must be even-length ASCII hex".into(),
        ));
    }
    Ok(t.to_owned())
}

/// Electrum JSON-RPC [`ChainSource`] over an injectable transport.
///
/// Requires `network` so addresses can be converted to scriptPubKey → script
/// hash. Never invents UTXOs or hashes for unparseable addresses.
#[derive(Debug)]
pub struct ElectrumChainSource<T: ElectrumTransport> {
    transport: RefCell<T>,
    network: Network,
}

impl<T: ElectrumTransport> ElectrumChainSource<T> {
    pub fn new(transport: T, network: Network) -> Self {
        Self {
            transport: RefCell::new(transport),
            network,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn transport(&self) -> std::cell::Ref<'_, T> {
        self.transport.borrow()
    }

    pub fn transport_mut(&self) -> std::cell::RefMut<'_, T> {
        self.transport.borrow_mut()
    }
}

impl<T: ElectrumTransport> ChainSource for ElectrumChainSource<T> {
    fn list_unspent_for_addresses(&self, addresses: &[String]) -> Result<Vec<WalletUtxo>> {
        let mut transport = self.transport.borrow_mut();
        // One tip probe per call; missing tip is non-fatal for conf math.
        let tip = transport
            .call("blockchain.headers.subscribe", &[])
            .ok()
            .and_then(|v| parse_electrum_headers_subscribe_height(&v));

        let mut out = Vec::new();
        for addr in addresses {
            let sh = electrum_script_hash_for_address(addr, self.network)?;
            let result = transport
                .call(
                    "blockchain.scripthash.listunspent",
                    &[Value::String(sh.clone())],
                )
                .map_err(|e| {
                    WalletError::Explorer(format!(
                        "failed to fetch Electrum UTXOs for address (transport error): {e}"
                    ))
                })?;
            let parsed = parse_electrum_listunspent(&result, addr, tip)?;
            out.extend(parsed);
        }
        Ok(out)
    }
}

/// Live plaintext TCP Electrum transport (JSON-RPC lines).
///
/// Connect TCP with [`TcpStream::connect_timeout`] for each resolved address.
///
/// Shared by plaintext and TLS live transports. DNS lookup (`ToSocketAddrs`) is
/// not separately timed — only the TCP handshake uses `timeout`.
#[cfg(feature = "electrum")]
fn electrum_tcp_connect_with_timeout(
    addr: &str,
    timeout: std::time::Duration,
) -> Result<std::net::TcpStream> {
    use std::net::{TcpStream, ToSocketAddrs};

    let addrs = addr.to_socket_addrs().map_err(|e| {
        WalletError::Explorer(format!(
            "electrum DNS/resolve {addr}: {e} (DNS not separately timed)"
        ))
    })?;
    let mut last_err: Option<std::io::Error> = None;
    let mut attempted = 0u32;
    for sa in addrs {
        attempted = attempted.saturating_add(1);
        match TcpStream::connect_timeout(&sa, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    if attempted == 0 {
        return Err(WalletError::Explorer(format!(
            "electrum resolve {addr}: no socket addresses"
        )));
    }
    let detail = last_err
        .map(|e| e.to_string())
        .unwrap_or_else(|| "unknown".into());
    Err(WalletError::Explorer(format!(
        "electrum TCP connect-timeout after {attempted} addr(s) to {addr} (budget {timeout:?}): {detail}"
    )))
}

/// Plaintext TCP Electrum JSON-RPC transport (feature `electrum`).
///
/// Prefer [`TlsElectrumTransport`] for public servers. Local/regtest may use this
/// without TLS. Default CI builds stay offline-safe (feature off).
///
/// **Timeouts:** each `call` resolves `host:port`, then
/// [`std::net::TcpStream::connect_timeout`] with the configured budget per
/// resolved address (not unbounded `connect`). Read/write also use the same
/// budget. DNS lookup is still best-effort without a separate resolver timeout.
#[cfg(feature = "electrum")]
#[derive(Debug)]
pub struct TcpElectrumTransport {
    addr: String,
    next_id: u64,
    timeout: std::time::Duration,
}

#[cfg(feature = "electrum")]
impl TcpElectrumTransport {
    /// `addr` is `host:port` (e.g. `127.0.0.1:50001`). No URI scheme.
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            next_id: 1,
            timeout: std::time::Duration::from_secs(15),
        }
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.timeout
    }
}

#[cfg(feature = "electrum")]
impl ElectrumTransport for TcpElectrumTransport {
    fn call(&mut self, method: &str, params: &[Value]) -> Result<Value> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let stream = electrum_tcp_connect_with_timeout(&self.addr, self.timeout)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| WalletError::Explorer(format!("electrum set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| WalletError::Explorer(format!("electrum set_write_timeout: {e}")))?;
        electrum_jsonrpc_call_over_stream(stream, id, method, params, "TCP")
    }
}

/// TLS (rustls + WebPKI roots) Electrum JSON-RPC transport (feature `electrum`).
///
/// **No skip-verify** path: certificate verification always uses Mozilla WebPKI
/// roots. Failures surface as structured [`WalletError::Explorer`] (never panic).
///
/// **Timeouts:** TCP connect uses [`TcpStream::connect_timeout`]; read/write
/// timeouts are set on the TCP stream **before** the TLS handshake so handshake
/// I/O is bounded by the same budget (not unbounded connect then late timeouts).
///
/// **SNI:** see [`electrum_tls_server_name`] / module docs (DNS hostname preferred;
/// IP-literal addresses use IP server names and often fail public-cert verify).
#[cfg(feature = "electrum")]
#[derive(Debug)]
pub struct TlsElectrumTransport {
    addr: String,
    next_id: u64,
    timeout: std::time::Duration,
}

#[cfg(feature = "electrum")]
impl TlsElectrumTransport {
    /// `addr` is `host:port` (e.g. `electrum.example:50002`). No URI scheme
    /// (product layer strips `ssl://` before construction).
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            next_id: 1,
            timeout: std::time::Duration::from_secs(15),
        }
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    /// Build TLS stream: timed TCP connect → R/W timeouts → rustls client.
    ///
    /// Does not complete the handshake until first I/O (JSON-RPC write); that
    /// I/O inherits the TCP read/write timeouts set here.
    fn connect_tls(
        &self,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>> {
        // Validate SNI/server name before any network I/O so pure bad names fail offline.
        let server_name = electrum_tls_server_name(&self.addr)?;
        let config = electrum_tls_client_config()?;

        let stream = electrum_tcp_connect_with_timeout(&self.addr, self.timeout)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| WalletError::Explorer(format!("electrum TLS set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| WalletError::Explorer(format!("electrum TLS set_write_timeout: {e}")))?;

        let conn = rustls::ClientConnection::new(config, server_name).map_err(|e| {
            WalletError::Explorer(format!(
                "electrum TLS ClientConnection for {}: {e}",
                self.addr
            ))
        })?;
        Ok(rustls::StreamOwned::new(conn, stream))
    }
}

#[cfg(feature = "electrum")]
impl ElectrumTransport for TlsElectrumTransport {
    fn call(&mut self, method: &str, params: &[Value]) -> Result<Value> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        // connect_tls / JSON-RPC I/O map failures to WalletError::Explorer (cert
        // verify, handshake, timeout) — never panic or invent results.
        let stream = self.connect_tls()?;
        electrum_jsonrpc_call_over_stream(stream, id, method, params, "TLS")
    }
}

#[cfg(feature = "electrum")]
impl ElectrumChainSource<TcpElectrumTransport> {
    /// Convenience: Electrum chain source over plaintext TCP.
    pub fn with_tcp(addr: impl Into<String>, network: Network) -> Self {
        Self::new(TcpElectrumTransport::new(addr), network)
    }
}

#[cfg(feature = "electrum")]
impl ElectrumChainSource<TlsElectrumTransport> {
    /// Convenience: Electrum chain source over TLS (rustls + WebPKI roots).
    pub fn with_tls(addr: impl Into<String>, network: Network) -> Self {
        Self::new(TlsElectrumTransport::new(addr), network)
    }
}

/// Electrum JSON-RPC [`TxBroadcaster`] (`blockchain.transaction.broadcast`).
///
/// Validates raw hex **before** any transport call. Never claims success without
/// a parseable 64-hex txid string result ([`parse_electrum_broadcast_result`]).
#[derive(Debug)]
pub struct ElectrumTxBroadcaster<T: ElectrumTransport> {
    transport: T,
}

impl<T: ElectrumTransport> ElectrumTxBroadcaster<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the inner transport (tests inspect recorded method/params).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutable borrow of the inner transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: ElectrumTransport> TxBroadcaster for ElectrumTxBroadcaster<T> {
    fn broadcast_raw_tx_hex(&mut self, raw_tx_hex: &str) -> Result<BroadcastResult> {
        let trimmed = validate_raw_tx_hex(raw_tx_hex)?;
        let result = self
            .transport
            .call(
                "blockchain.transaction.broadcast",
                &[Value::String(trimmed.to_owned())],
            )
            .map_err(|e| {
                WalletError::Explorer(format!("electrum broadcast transport error: {e}"))
            })?;
        let txid = parse_electrum_broadcast_result(&result)?;
        Ok(BroadcastResult { txid })
    }
}

#[cfg(feature = "electrum")]
impl ElectrumTxBroadcaster<TcpElectrumTransport> {
    /// Convenience: Electrum broadcaster over plaintext TCP (`host:port`).
    ///
    /// Prefer [`Self::with_tls`] for public servers; local/regtest may stay plaintext.
    pub fn with_tcp(addr: impl Into<String>) -> Self {
        Self::new(TcpElectrumTransport::new(addr))
    }
}

#[cfg(feature = "electrum")]
impl ElectrumTxBroadcaster<TlsElectrumTransport> {
    /// Convenience: Electrum broadcaster over TLS (rustls + WebPKI roots).
    pub fn with_tls(addr: impl Into<String>) -> Self {
        Self::new(TlsElectrumTransport::new(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::CompressedPublicKey;
    use bitcoin::{KnownHrp, secp256k1};

    const TXID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TXID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Deterministic P2WPKH address on regtest for scripthash tests.
    fn sample_regtest_p2wpkh() -> (String, String) {
        // Compressed pubkey from a well-known test vector (not a funded key).
        let pk = secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let compressed = CompressedPublicKey(pk);
        let addr = Address::p2wpkh(&compressed, KnownHrp::Regtest);
        let addr_str = addr.to_string();
        let sh = electrum_script_hash_from_script(&addr.script_pubkey());
        (addr_str, sh)
    }

    #[test]
    fn script_hash_is_reversed_sha256_hex() {
        let script = ScriptBuf::from_hex("0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let sh = electrum_script_hash_from_script(&script);
        assert_eq!(sh.len(), 64);
        assert!(sh.bytes().all(|b| b.is_ascii_hexdigit()));
        // Recompute manually for stability.
        let hash = sha256::Hash::hash(script.as_bytes());
        let mut bytes = hash.to_byte_array();
        bytes.reverse();
        let expect: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sh, expect);
    }

    #[test]
    fn script_hash_for_address_network_mismatch_errors() {
        let (addr, _) = sample_regtest_p2wpkh();
        let err = electrum_script_hash_for_address(&addr, Network::Bitcoin).unwrap_err();
        assert!(
            err.to_string().contains("network mismatch") || err.to_string().contains("invalid"),
            "{err}"
        );
    }

    #[test]
    fn script_hash_for_garbage_address_errors() {
        let err = electrum_script_hash_for_address("not-an-address", Network::Bitcoin).unwrap_err();
        assert!(err.to_string().contains("invalid address"), "{err}");
    }

    #[test]
    fn request_line_is_json_with_newline() {
        let line = electrum_request_line(
            7,
            "blockchain.scripthash.listunspent",
            &[Value::String("ab".into())],
        );
        assert!(line.ends_with('\n'));
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["id"], 7);
        assert_eq!(v["method"], "blockchain.scripthash.listunspent");
        assert_eq!(v["params"][0], "ab");
    }

    #[test]
    fn parse_response_result_ok_and_error() {
        let ok = parse_electrum_response_result(r#"{"jsonrpc":"2.0","id":1,"result":[]}"#).unwrap();
        assert!(ok.as_array().unwrap().is_empty());

        let err = parse_electrum_response_result(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"bad"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("JSON-RPC error"), "{err}");

        let missing = parse_electrum_response_result(r#"{"jsonrpc":"2.0","id":1}"#).unwrap_err();
        assert!(missing.to_string().contains("missing result"), "{missing}");
    }

    #[test]
    fn parse_response_requires_matching_id_when_expected() {
        let ok = parse_electrum_response_result_for_id(
            r#"{"jsonrpc":"2.0","id":7,"result":[]}"#,
            Some(7),
        )
        .unwrap();
        assert!(ok.as_array().unwrap().is_empty());

        // String form of the same id is accepted.
        let ok_str = parse_electrum_response_result_for_id(
            r#"{"jsonrpc":"2.0","id":"7","result":[1]}"#,
            Some(7),
        )
        .unwrap();
        assert_eq!(ok_str.as_array().unwrap().len(), 1);

        let mismatch = parse_electrum_response_result_for_id(
            r#"{"jsonrpc":"2.0","id":99,"result":[]}"#,
            Some(7),
        )
        .unwrap_err();
        assert!(mismatch.to_string().contains("id mismatch"), "{mismatch}");

        let missing_id =
            parse_electrum_response_result_for_id(r#"{"jsonrpc":"2.0","result":[]}"#, Some(1))
                .unwrap_err();
        assert!(
            missing_id.to_string().contains("missing id"),
            "{missing_id}"
        );

        let notification = parse_electrum_response_result_for_id(
            r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":[]}"#,
            Some(1),
        )
        .unwrap_err();
        assert!(
            notification.to_string().contains("notification"),
            "{notification}"
        );
    }

    #[test]
    fn parse_headers_subscribe_height() {
        assert_eq!(
            parse_electrum_headers_subscribe_height(&json!({"height": 840_000, "hex": "00"})),
            Some(840_000)
        );
        assert_eq!(
            parse_electrum_headers_subscribe_height(&json!(42)),
            Some(42)
        );
        assert_eq!(parse_electrum_headers_subscribe_height(&json!({})), None);
    }

    #[test]
    fn parse_listunspent_confirmed_and_unconfirmed() {
        let result = json!([
            {
                "tx_hash": TXID_A,
                "tx_pos": 1,
                "value": 50_000,
                "height": 100
            },
            {
                "tx_hash": TXID_B,
                "tx_pos": 0,
                "value": 1,
                "height": 0
            }
        ]);
        let utxos = parse_electrum_listunspent(&result, "bcrt1qtest", Some(102)).unwrap();
        assert_eq!(utxos.len(), 2);
        assert_eq!(utxos[0].outpoint.txid, TXID_A);
        assert_eq!(utxos[0].outpoint.vout, 1);
        assert_eq!(utxos[0].amount_sats, 50_000);
        assert_eq!(utxos[0].confirmations, 3);
        assert_eq!(utxos[1].confirmations, 0);
    }

    #[test]
    fn parse_listunspent_tip_miss_conf_one() {
        let result = json!([{
            "tx_hash": TXID_A,
            "tx_pos": 0,
            "value": 9,
            "height": 50
        }]);
        let utxos = parse_electrum_listunspent(&result, "bcrt1q", None).unwrap();
        assert_eq!(utxos[0].confirmations, 1);
    }

    #[test]
    fn parse_listunspent_rejects_bad_txid_and_non_array() {
        let bad = json!([{"tx_hash": "short", "tx_pos": 0, "value": 1, "height": 1}]);
        let err_short = parse_electrum_listunspent(&bad, "a", Some(1)).unwrap_err();
        assert!(
            err_short.to_string().contains("64 hex chars")
                && err_short.to_string().contains("non-hex"),
            "{err_short}"
        );
        // 64-char non-hex must mention non-hex (not only "got len 64").
        let non_hex = "z".repeat(64);
        let bad64 = json!([{"tx_hash": non_hex, "tx_pos": 0, "value": 1, "height": 1}]);
        let err64 = parse_electrum_listunspent(&bad64, "a", Some(1)).unwrap_err();
        assert!(
            err64.to_string().contains("non-hex") && err64.to_string().contains("len 64"),
            "{err64}"
        );
        assert!(parse_electrum_listunspent(&json!({}), "a", Some(1)).is_err());
        let missing_pos = json!([{"tx_hash": TXID_A, "value": 1, "height": 1}]);
        assert!(parse_electrum_listunspent(&missing_pos, "a", Some(1)).is_err());
    }

    #[test]
    fn parse_listunspent_height_minus_one_is_unconfirmed() {
        // Electrum: height -1 = unconfirmed with unconfirmed parent → conf 0.
        let result = json!([{
            "tx_hash": TXID_A,
            "tx_pos": 0,
            "value": 42,
            "height": -1
        }]);
        let utxos = parse_electrum_listunspent(&result, "bcrt1q", Some(100)).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].confirmations, 0);
        assert_eq!(utxos[0].amount_sats, 42);
    }

    #[test]
    fn chain_source_lists_utxos_via_mock_transport() {
        let (addr, sh) = sample_regtest_p2wpkh();
        let mut mock = MockElectrumTransport::new().with_tip_height(200);
        mock.insert_listunspent(
            sh.clone(),
            json!([{
                "tx_hash": TXID_A,
                "tx_pos": 0,
                "value": 12_345,
                "height": 190
            }]),
        );
        let chain = ElectrumChainSource::new(mock, Network::Regtest);
        let utxos = chain.list_unspent_for_addresses(&[addr.clone()]).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount_sats, 12_345);
        assert_eq!(utxos[0].confirmations, 11);
        assert_eq!(utxos[0].address, addr);

        let t = chain.transport();
        assert_eq!(t.calls[0].0, "blockchain.headers.subscribe");
        assert_eq!(t.calls[1].0, "blockchain.scripthash.listunspent");
        assert_eq!(t.calls[1].1[0], Value::String(sh));
    }

    #[test]
    fn chain_source_listunspent_error_is_hard() {
        let (addr, sh) = sample_regtest_p2wpkh();
        let mut mock = MockElectrumTransport::new().with_tip_height(1);
        mock.fail_listunspent(sh, "server down");
        let chain = ElectrumChainSource::new(mock, Network::Regtest);
        let err = chain.list_unspent_for_addresses(&[addr]).unwrap_err();
        assert!(
            err.to_string().contains("failed to fetch Electrum")
                || err.to_string().contains("server down"),
            "{err}"
        );
    }

    #[test]
    fn chain_source_invalid_address_errors_before_rpc() {
        let mock = MockElectrumTransport::new().with_tip_height(1);
        let chain = ElectrumChainSource::new(mock, Network::Regtest);
        let err = chain
            .list_unspent_for_addresses(&["not-valid".into()])
            .unwrap_err();
        assert!(err.to_string().contains("invalid address"), "{err}");
        // headers.subscribe still runs first; no listunspent for bad addr.
        let t = chain.transport();
        assert!(
            t.calls
                .iter()
                .all(|(m, _)| m != "blockchain.scripthash.listunspent")
        );
    }

    #[test]
    fn missing_tip_still_returns_confirmed_utxos() {
        let (addr, sh) = sample_regtest_p2wpkh();
        let mut mock = MockElectrumTransport::new();
        mock.fail_headers = true;
        mock.insert_listunspent(
            sh,
            json!([{
                "tx_hash": TXID_B,
                "tx_pos": 3,
                "value": 7,
                "height": 10
            }]),
        );
        let chain = ElectrumChainSource::new(mock, Network::Regtest);
        let utxos = chain.list_unspent_for_addresses(&[addr]).unwrap();
        assert_eq!(utxos[0].confirmations, 1);
        assert_eq!(utxos[0].outpoint.vout, 3);
    }

    #[test]
    fn empty_listunspent_ok() {
        let (addr, sh) = sample_regtest_p2wpkh();
        let mut mock = MockElectrumTransport::new().with_tip_height(1);
        mock.insert_listunspent(sh, json!([]));
        let chain = ElectrumChainSource::new(mock, Network::Regtest);
        let utxos = chain.list_unspent_for_addresses(&[addr]).unwrap();
        assert!(utxos.is_empty());
    }

    #[test]
    fn missing_listunspent_fixture_is_hard_error_not_empty_list() {
        let (addr, _sh) = sample_regtest_p2wpkh();
        // Tip configured; no insert_listunspent for the derived scripthash.
        let mock = MockElectrumTransport::new().with_tip_height(1);
        let chain = ElectrumChainSource::new(mock, Network::Regtest);
        let err = chain.list_unspent_for_addresses(&[addr]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no listunspent fixture") || msg.contains("failed to fetch Electrum"),
            "expected hard error, not Ok([]): {msg}"
        );
        assert!(!msg.is_empty());
    }

    // --- Electrum TxBroadcaster (blockchain.transaction.broadcast) ---

    #[test]
    fn parse_broadcast_result_accepts_txid_string() {
        assert_eq!(
            parse_electrum_broadcast_result(&Value::String(TXID_A.to_owned())).unwrap(),
            TXID_A
        );
        let upper = TXID_A.to_ascii_uppercase();
        assert_eq!(
            parse_electrum_broadcast_result(&Value::String(format!("  {upper}\n"))).unwrap(),
            TXID_A
        );
    }

    #[test]
    fn parse_broadcast_result_rejects_non_hex_and_non_string() {
        let err = parse_electrum_broadcast_result(&Value::String("short".into()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("64-hex") || err.contains("txid"), "{err}");

        let non_hex = "g".repeat(64);
        let err_g = parse_electrum_broadcast_result(&Value::String(non_hex))
            .unwrap_err()
            .to_string();
        assert!(
            err_g.contains("64-hex") || err_g.contains("txid"),
            "{err_g}"
        );

        let err_num = parse_electrum_broadcast_result(&json!(42))
            .unwrap_err()
            .to_string();
        assert!(
            err_num.contains("string") || err_num.contains("txid"),
            "{err_num}"
        );

        let err_obj = parse_electrum_broadcast_result(&json!({"txid": TXID_A}))
            .unwrap_err()
            .to_string();
        assert!(err_obj.contains("string"), "{err_obj}");
    }

    #[test]
    fn broadcaster_success_records_method_and_params() {
        let mut mock = MockElectrumTransport::new();
        mock.push_broadcast_ok(Value::String(TXID_A.to_owned()));
        let mut b = ElectrumTxBroadcaster::new(mock);
        let res = b.broadcast_raw_tx_hex("deadbeef").unwrap();
        assert_eq!(res.txid, TXID_A);
        let t = b.transport();
        assert_eq!(t.calls.len(), 1);
        assert_eq!(t.calls[0].0, "blockchain.transaction.broadcast");
        assert_eq!(t.calls[0].1, vec![Value::String("deadbeef".into())]);
    }

    #[test]
    fn broadcaster_rejects_empty_and_non_hex_before_rpc() {
        let mut mock = MockElectrumTransport::new();
        mock.push_broadcast_ok(Value::String(TXID_A.to_owned()));
        let mut b = ElectrumTxBroadcaster::new(mock);
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
        let err_non = b.broadcast_raw_tx_hex("not-hex!!").unwrap_err().to_string();
        assert!(err_non.contains("hex"), "{err_non}");
        // No RPC call for invalid input.
        assert!(b.transport().calls.is_empty());
    }

    #[test]
    fn broadcaster_rpc_error_is_hard() {
        let mut mock = MockElectrumTransport::new();
        mock.push_broadcast_err("the transaction was rejected by network rules");
        let mut b = ElectrumTxBroadcaster::new(mock);
        let err = b.broadcast_raw_tx_hex("00aa").unwrap_err().to_string();
        assert!(
            err.contains("transport error") || err.contains("rejected"),
            "{err}"
        );
        assert_eq!(b.transport().calls.len(), 1);
        assert_eq!(b.transport().calls[0].0, "blockchain.transaction.broadcast");
    }

    #[test]
    fn broadcaster_bad_result_shape_is_hard() {
        let mut mock = MockElectrumTransport::new();
        mock.push_broadcast_ok(json!({"not": "a string"}));
        let mut b = ElectrumTxBroadcaster::new(mock);
        let err = b.broadcast_raw_tx_hex("00").unwrap_err().to_string();
        assert!(err.contains("string") || err.contains("txid"), "{err}");
    }

    #[test]
    fn broadcaster_exhausted_script_is_hard_error() {
        let mock = MockElectrumTransport::new();
        let mut b = ElectrumTxBroadcaster::new(mock);
        let err = b.broadcast_raw_tx_hex("00").unwrap_err().to_string();
        assert!(
            err.contains("exhausted") || err.contains("transport error"),
            "{err}"
        );
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn tls_transport_construction_stores_addr_no_network() {
        let t = TlsElectrumTransport::new("electrum.example:50002");
        assert_eq!(t.addr(), "electrum.example:50002");
        assert_eq!(t.timeout(), std::time::Duration::from_secs(15));
        let t = t.with_timeout(std::time::Duration::from_millis(50));
        assert_eq!(t.timeout(), std::time::Duration::from_millis(50));
        // with_tls / with_tcp chain+broadcast constructors do not connect.
        let _cs = ElectrumChainSource::with_tls("electrum.example:50002", Network::Bitcoin);
        let _bc = ElectrumTxBroadcaster::with_tls("electrum.example:50002");
        let _cs_tcp = ElectrumChainSource::with_tcp("127.0.0.1:50001", Network::Regtest);
        let _bc_tcp = ElectrumTxBroadcaster::with_tcp("127.0.0.1:50001");
    }

    /// In-memory `Read + Write` double for offline framer tests (no network).
    #[cfg(feature = "electrum")]
    struct ScriptedElectrumStream {
        write_err: Option<std::io::ErrorKind>,
        /// Bytes returned by successive `read` calls (concatenated).
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    #[cfg(feature = "electrum")]
    impl ScriptedElectrumStream {
        fn with_response(body: impl Into<Vec<u8>>) -> Self {
            Self {
                write_err: None,
                read_data: body.into(),
                read_pos: 0,
                written: Vec::new(),
            }
        }

        fn write_fails(kind: std::io::ErrorKind) -> Self {
            Self {
                write_err: Some(kind),
                read_data: Vec::new(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    #[cfg(feature = "electrum")]
    impl std::io::Write for ScriptedElectrumStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(kind) = self.write_err {
                return Err(std::io::Error::new(kind, "scripted electrum write fail"));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "electrum")]
    impl std::io::Read for ScriptedElectrumStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let rest = &self.read_data[self.read_pos..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.read_pos += n;
            Ok(n)
        }
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn jsonrpc_framer_happy_path_returns_result_with_matching_id() {
        let body = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"height\":42}}\n";
        let stream = ScriptedElectrumStream::with_response(body.to_vec());
        let v = electrum_jsonrpc_call_over_stream(
            stream,
            7,
            "blockchain.headers.subscribe",
            &[],
            "mock",
        )
        .expect("happy path");
        assert_eq!(v.get("height").and_then(|h| h.as_u64()), Some(42));
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn jsonrpc_framer_empty_response_line_is_explorer_error() {
        // Newline-only and fully empty both count as empty after trim.
        for body in [b"\n".as_slice(), b"".as_slice(), b"   \n".as_slice()] {
            let stream = ScriptedElectrumStream::with_response(body.to_vec());
            let err = electrum_jsonrpc_call_over_stream(stream, 1, "m", &[], "mock")
                .expect_err("empty must fail")
                .to_string();
            assert!(
                err.contains("empty response line"),
                "body={body:?} err={err}"
            );
        }
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn jsonrpc_framer_write_error_is_explorer_error() {
        let stream = ScriptedElectrumStream::write_fails(std::io::ErrorKind::BrokenPipe);
        let err = electrum_jsonrpc_call_over_stream(stream, 1, "m", &[], "TCP")
            .expect_err("write fail")
            .to_string();
        assert!(err.contains("write"), "err={err}");
        assert!(err.contains("electrum"), "err={err}");
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn jsonrpc_framer_oversized_response_line_is_explorer_error() {
        // No newline until past the cap — must refuse unbounded allocation.
        let mut huge = vec![b'x'; ELECTRUM_MAX_RESPONSE_LINE_BYTES + 64];
        huge.push(b'\n');
        let stream = ScriptedElectrumStream::with_response(huge);
        let err = electrum_jsonrpc_call_over_stream(stream, 1, "m", &[], "TLS")
            .expect_err("oversize must fail")
            .to_string();
        assert!(
            err.contains("exceeds") || err.contains("unbounded"),
            "err={err}"
        );
        assert!(err.contains("TLS"), "err={err}");
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn read_response_line_cap_allows_exact_max_with_newline() {
        use std::io::Cursor;
        // max_bytes includes the trailing newline byte.
        let max = 16;
        let mut line = vec![b'a'; max - 1];
        line.push(b'\n');
        let mut cur = Cursor::new(line);
        let s = electrum_read_response_line(&mut cur, max, "mock").unwrap();
        assert_eq!(s.len(), max);
        assert!(s.ends_with('\n'));
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn electrum_host_from_addr_dns_and_ip() {
        assert_eq!(
            electrum_host_from_addr("electrum.blockstream.info:50002").unwrap(),
            "electrum.blockstream.info"
        );
        assert_eq!(
            electrum_host_from_addr("127.0.0.1:50001").unwrap(),
            "127.0.0.1"
        );
        assert_eq!(electrum_host_from_addr("[::1]:50001").unwrap(), "::1");
        assert!(electrum_host_from_addr("ssl://host:1").is_err());
        assert!(electrum_host_from_addr("noscheme").is_err());
        assert!(electrum_host_from_addr("").is_err());
        assert!(electrum_host_from_addr("[]:50001").is_err());
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn electrum_tls_server_name_dns_and_ip_literals() {
        use rustls::pki_types::ServerName;
        let dns = electrum_tls_server_name("fulcrum.example:50002").unwrap();
        assert!(matches!(dns, ServerName::DnsName(_)));
        let v4 = electrum_tls_server_name("192.0.2.1:50002").unwrap();
        assert!(matches!(v4, ServerName::IpAddress(_)));
        let v6 = electrum_tls_server_name("[2001:db8::1]:50002").unwrap();
        assert!(matches!(v6, ServerName::IpAddress(_)));
        // Bracketed loopback used after product strips ssl://[::1]:port.
        let loopback = electrum_tls_server_name("[::1]:50002").unwrap();
        assert!(matches!(loopback, ServerName::IpAddress(_)));
        assert_eq!(electrum_host_from_addr("[::1]:50002").unwrap(), "::1");
        // Empty / scheme must fail offline (no network).
        assert!(electrum_tls_server_name("").is_err());
        assert!(electrum_tls_server_name("ssl://x:1").is_err());
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn tls_client_config_builds_with_webpki_roots() {
        // Offline: config construction must not hit network.
        let cfg = electrum_tls_client_config().expect("webpki roots client config");
        // Second call reuses OnceLock cache.
        let cfg2 = electrum_tls_client_config().expect("cached config");
        assert!(std::sync::Arc::ptr_eq(&cfg, &cfg2));
    }

    #[cfg(feature = "electrum")]
    #[test]
    fn tls_connect_to_closed_local_port_is_explorer_error_not_panic() {
        // Local connect only (127.0.0.1); short timeout; no live public network.
        let mut t = TlsElectrumTransport::new("127.0.0.1:1")
            .with_timeout(std::time::Duration::from_millis(200));
        let err = t
            .call("blockchain.headers.subscribe", &[])
            .expect_err("closed port must not succeed")
            .to_string();
        assert!(
            err.contains("electrum")
                && (err.contains("connect")
                    || err.contains("timeout")
                    || err.contains("Connection refused")
                    || err.contains("TLS")
                    || err.to_ascii_lowercase().contains("refused")),
            "err={err}"
        );
        // Must not look like a successful JSON-RPC result.
        assert!(!err.contains("\"result\""), "{err}");
    }
}
