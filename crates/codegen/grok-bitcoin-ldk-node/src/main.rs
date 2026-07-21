//! Out-of-process LDK BOLT11 pay / receive-invoice helper.
//!
//! ## Why a separate binary
//!
//! `ldk-node` pulls `rusqlite 0.31` / `libsqlite3-sys` (`links = "sqlite3"`).
//! The monorepo shell uses `rusqlite 0.37` for FTS5 / sqlite-vec / CVE pins.
//! Cargo forbids both in one dependency graph (even across workspace members).
//! This crate is **excluded** from the monorepo workspace so it resolves and
//! links its own sqlite independently.
//!
//! ## Protocol (stdin → stdout JSON, v1)
//!
//! Request (single JSON object; may be multiline):
//! ```json
//! {
//!   "v": 1,
//!   "cmd": "pay_bolt11",
//!   "invoice": "lnbc…",
//!   "mnemonic": "twelve or twenty four words …",
//!   "passphrase": "",
//!   "network": "signet",
//!   "storage_dir": "/absolute/path/for/ldk/state",
//!   "esplora_url": "https://…",
//!   "timeout_secs": 120
//! }
//! ```
//!
//! Create receive invoice:
//! ```json
//! {
//!   "v": 1,
//!   "cmd": "create_bolt11_invoice",
//!   "amount_sats": 1000,
//!   "description": "grok receive",
//!   "expiry_secs": 3600,
//!   "mnemonic": "…",
//!   "passphrase": "",
//!   "network": "signet",
//!   "storage_dir": "/absolute/path",
//!   "esplora_url": "https://…"
//! }
//! ```
//! (`amount_sats` omitted / null → zero-amount invoice.)
//!
//! Or health check: `{ "v": 1, "cmd": "ping" }`.
//!
//! Explicit **residual** cmds (recognized, never Success, never call LDK open/connect):
//! - `{ "v": 1, "cmd": "open_channel", … }` → `ok:false` with residual error text
//! - `{ "v": 1, "cmd": "connect_peer", … }` → `ok:false` with residual error text
//!
//! Residual errors are **distinct** from `unknown cmd: …` so product can tell
//! residual-vs-typo. Live channel open / peer connect remains product residual
//! until an offline-proveable live contract exists.
//!
//! Response:
//! - pay success: `{ "v":1, "ok":true, "preimage_hex":"<64 hex>", "payment_id_hex":"…" }`
//! - create success: `{ "v":1, "ok":true, "bolt11":"lnbc…" }`
//! - failure: `{ "v":1, "ok":false, "error":"…" }`
//! - residual open/connect: `{ "v":1, "ok":false, "error":"residual: open_channel|connect_peer …" }`
//!
//! ## Security
//! - Mnemonic/passphrase arrive only on stdin (never argv/env/disk plaintext).
//! - Buffers holding phrase material are zeroized after use.
//! - Do not log request bodies (contain seed material). `Request` has no `Debug`.
//! - `storage_dir` **must be absolute** (parent scopes per-seed under grok home).
//! - Residual: `bip39::Mnemonic` / builder entropy live until `build()` returns
//!   (ldk-node types do not implement Zeroize); prefer short-lived process.
//! - Creating an invoice does **not** prove inbound liquidity exists; payers may
//!   fail to route. Product must not claim funded channels from a create alone.
//! - `open_channel` / `connect_peer` **never** invent `ok:true` or a channel_id.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use ldk_node::bip39::Mnemonic;
use ldk_node::bitcoin::Network;
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ldk_node::{Builder, Event, Node};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const PROTOCOL_V: u32 = 1;
const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_INVOICE_EXPIRY_SECS: u32 = 3600;
const DEFAULT_INVOICE_DESCRIPTION: &str = "grok-bitcoin-ldk-node receive";

/// Request body — **no Debug** (mnemonic/passphrase must never print).
#[derive(Deserialize)]
struct Request {
    #[serde(default = "default_v")]
    v: u32,
    cmd: String,
    #[serde(default)]
    invoice: Option<String>,
    #[serde(default)]
    mnemonic: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    storage_dir: Option<String>,
    #[serde(default)]
    esplora_url: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    /// Optional amount for `create_bolt11_invoice` (sats). None → zero-amount.
    #[serde(default)]
    amount_sats: Option<u64>,
    /// Optional description for `create_bolt11_invoice`.
    #[serde(default)]
    description: Option<String>,
    /// Optional invoice expiry (seconds) for `create_bolt11_invoice`.
    #[serde(default)]
    expiry_secs: Option<u32>,
    /// Optional peer node id / URI for residual `open_channel` / `connect_peer`
    /// (accepted for IPC shape only — never used to invent Success).
    #[serde(default)]
    peer_node_id: Option<String>,
    /// Optional peer URI (host:port or node_id@host:port) for residual cmds.
    #[serde(default)]
    peer_uri: Option<String>,
    /// Optional capacity (sats) for residual `open_channel` (shape only).
    #[serde(default)]
    capacity_sats: Option<u64>,
}

/// Distinct residual error for `open_channel` (not `unknown cmd`).
pub(crate) const RESIDUAL_OPEN_CHANNEL_ERROR: &str = "\
residual: open_channel not implemented in this helper \
(product residual; no live channel-open contract; never invents channel_id Success)";

/// Distinct residual error for `connect_peer` (not `unknown cmd`).
pub(crate) const RESIDUAL_CONNECT_PEER_ERROR: &str = "\
residual: connect_peer not implemented in this helper \
(product residual; no live peer-connect contract; never invents peer Success)";

/// Classify helper error text as known residual channel cmd (vs typo / unknown).
/// Offline unit-test contract (mirrors wallet `is_helper_residual_channel_cmd_error`).
#[cfg(test)]
fn is_residual_channel_cmd_error(error: &str) -> bool {
    let e = error.trim();
    e.starts_with("residual:") && (e.contains("open_channel") || e.contains("connect_peer"))
}

fn default_v() -> u32 {
    PROTOCOL_V
}

#[derive(Debug, Serialize)]
struct Response {
    v: u32,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preimage_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bolt11: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ldk_node_linked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pong: Option<bool>,
}

impl Response {
    fn ok_ping() -> Self {
        Self {
            v: PROTOCOL_V,
            ok: true,
            error: None,
            preimage_hex: None,
            payment_id_hex: None,
            bolt11: None,
            ldk_node_linked: Some(true),
            pong: Some(true),
        }
    }

    fn ok_pay(preimage_hex: String, payment_id_hex: Option<String>) -> Self {
        Self {
            v: PROTOCOL_V,
            ok: true,
            error: None,
            preimage_hex: Some(preimage_hex),
            payment_id_hex,
            bolt11: None,
            ldk_node_linked: None,
            pong: None,
        }
    }

    fn ok_invoice(bolt11: String) -> Self {
        Self {
            v: PROTOCOL_V,
            ok: true,
            error: None,
            preimage_hex: None,
            payment_id_hex: None,
            bolt11: Some(bolt11),
            ldk_node_linked: None,
            pong: None,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_V,
            ok: false,
            error: Some(msg.into()),
            preimage_hex: None,
            payment_id_hex: None,
            bolt11: None,
            ldk_node_linked: None,
            pong: None,
        }
    }
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(()) => 1,
    };
    std::process::exit(code);
}

fn run() -> Result<(), ()> {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        emit(&Response::err(format!("read stdin: {e}")));
        return Err(());
    }

    let req: Request = match serde_json::from_str(raw.trim()) {
        Ok(r) => r,
        Err(e) => {
            raw.zeroize();
            emit(&Response::err(format!("invalid JSON request: {e}")));
            return Err(());
        }
    };
    // Drop raw stdin buffer (may contain mnemonic) ASAP.
    raw.zeroize();

    if req.v != PROTOCOL_V {
        emit(&Response::err(format!(
            "unsupported protocol v={} (want {PROTOCOL_V})",
            req.v
        )));
        return Err(());
    }

    match req.cmd.as_str() {
        "ping" => {
            emit(&Response::ok_ping());
            Ok(())
        }
        "pay_bolt11" => handle_pay(req),
        "create_bolt11_invoice" => handle_create_invoice(req),
        // Explicit residual: recognized cmds, structured ok:false, never Success,
        // never call ldk-node open_channel / connect APIs.
        "open_channel" => handle_residual_channel_cmd(req, ResidualChannelCmd::OpenChannel),
        "connect_peer" => handle_residual_channel_cmd(req, ResidualChannelCmd::ConnectPeer),
        other => {
            emit(&Response::err(format!("unknown cmd: {other}")));
            Err(())
        }
    }
}

/// Known residual channel IPC cmds (honest refuse; no LDK open/connect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResidualChannelCmd {
    OpenChannel,
    ConnectPeer,
}

impl ResidualChannelCmd {
    fn error_text(self) -> &'static str {
        match self {
            Self::OpenChannel => RESIDUAL_OPEN_CHANNEL_ERROR,
            Self::ConnectPeer => RESIDUAL_CONNECT_PEER_ERROR,
        }
    }
}

/// Refuse residual channel cmds with structured failure; zeroize any secrets.
///
/// **Never** starts the node, **never** returns `ok: true` / channel_id.
fn handle_residual_channel_cmd(mut req: Request, cmd: ResidualChannelCmd) -> Result<(), ()> {
    zeroize_request_secrets(&mut req);
    // Drop residual shape fields (not secret, but avoid retaining peer material).
    req.peer_node_id = None;
    req.peer_uri = None;
    req.capacity_sats = None;
    emit(&Response::err(cmd.error_text()));
    Err(())
}

/// Shared BIP-39 + storage bootstrap for pay / create-invoice.
///
/// On success returns `(node, network_label, network, timeout_secs)`.
/// On failure emits an error response and returns `Err(())` (secrets zeroized).
fn bootstrap_node(mut req: Request) -> Result<(Node, String, Network, u64), ()> {
    let mut mnemonic_s = match req.mnemonic.take() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err("missing mnemonic"));
            return Err(());
        }
    };
    let mut passphrase_s = req.passphrase.take().unwrap_or_default();
    let network_label = req
        .network
        .as_deref()
        .unwrap_or("mainnet")
        .to_ascii_lowercase();

    let storage_dir = match req.storage_dir.take() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            mnemonic_s.zeroize();
            passphrase_s.zeroize();
            zeroize_request_secrets(&mut req);
            emit(&Response::err(
                "storage_dir required (absolute path; parent scopes per-seed under grok home)",
            ));
            return Err(());
        }
    };
    let storage_path = PathBuf::from(&storage_dir);
    if !storage_path.is_absolute() {
        mnemonic_s.zeroize();
        passphrase_s.zeroize();
        zeroize_request_secrets(&mut req);
        emit(&Response::err(format!(
            "storage_dir must be absolute (got relative: {storage_dir})"
        )));
        return Err(());
    }

    let esplora_url = req
        .esplora_url
        .clone()
        .unwrap_or_else(|| default_esplora_for_label(&network_label));
    let timeout_secs = req.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1);

    let mnemonic = match Mnemonic::parse_normalized(mnemonic_s.trim()) {
        Ok(m) => m,
        Err(e) => {
            mnemonic_s.zeroize();
            passphrase_s.zeroize();
            zeroize_request_secrets(&mut req);
            emit(&Response::err(format!("invalid mnemonic: {e}")));
            return Err(());
        }
    };
    mnemonic_s.zeroize();

    let network = match parse_network(&network_label) {
        Ok(n) => n,
        Err(e) => {
            passphrase_s.zeroize();
            zeroize_request_secrets(&mut req);
            emit(&Response::err(e));
            return Err(());
        }
    };

    if let Err(e) = std::fs::create_dir_all(Path::new(&storage_path)) {
        passphrase_s.zeroize();
        zeroize_request_secrets(&mut req);
        emit(&Response::err(format!("create storage_dir: {e}")));
        return Err(());
    }

    let passphrase_opt = if passphrase_s.is_empty() {
        None
    } else {
        Some(std::mem::take(&mut passphrase_s))
    };
    passphrase_s.zeroize();
    // Drop remaining secret fields (invoice string is not secret seed material).
    zeroize_request_secrets(&mut req);

    let mut builder = Builder::new();
    builder.set_network(network);
    builder.set_storage_dir_path(storage_path.display().to_string());
    builder.set_chain_source_esplora(esplora_url, None);
    builder.set_entropy_bip39_mnemonic(mnemonic, passphrase_opt);

    // Build consumes builder config (incl. entropy). Residual: Mnemonic /
    // passphrase Option live inside builder until this call returns; ldk-node
    // types do not implement Zeroize. Process exit bounds lifetime.
    let node = match builder.build() {
        Ok(n) => n,
        Err(e) => {
            emit(&Response::err(format!("ldk-node build failed: {e}")));
            return Err(());
        }
    };

    if let Err(e) = node.start() {
        emit(&Response::err(format!("ldk-node start failed: {e}")));
        return Err(());
    }

    Ok((node, network_label, network, timeout_secs))
}

fn handle_pay(mut req: Request) -> Result<(), ()> {
    let invoice_s = match req
        .invoice
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_owned(),
        None => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err("empty invoice"));
            return Err(());
        }
    };

    // Parse invoice before node start so network mismatch is cheap.
    let invoice = match Bolt11Invoice::from_str(&invoice_s) {
        Ok(i) => i,
        Err(e) => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err(format!("invalid bolt11 invoice: {e}")));
            return Err(());
        }
    };

    let configured_label = req
        .network
        .as_deref()
        .unwrap_or("mainnet")
        .to_ascii_lowercase();
    let configured_network = match parse_network(&configured_label) {
        Ok(n) => n,
        Err(e) => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err(e));
            return Err(());
        }
    };
    let inv_net = invoice.network();
    if !invoice_network_matches(configured_network, inv_net) {
        zeroize_request_secrets(&mut req);
        emit(&Response::err(format!(
            "invoice network mismatch: node={configured_label} ({configured_network:?}), invoice={inv_net:?}"
        )));
        return Err(());
    }

    let (node, _network_label, _network, timeout_secs) = bootstrap_node(req)?;

    let pay_result = (|| {
        let payment_id = match node.bolt11_payment().send(&invoice, None) {
            Ok(id) => id,
            Err(e) => {
                return Err(format!(
                    "bolt11 send failed: {e} (outbound liquidity / route required; \
                     a channel specifically to Routstr is not required)"
                ));
            }
        };

        let payment_id_hex = bytes_to_hex(&payment_id.0);
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "timeout after {timeout_secs}s waiting for payment settlement \
                     (payment_id={payment_id_hex})"
                ));
            }

            match node.next_event() {
                Some(Event::PaymentSuccessful {
                    payment_id: ev_id,
                    payment_preimage,
                    ..
                }) => {
                    let _ = node.event_handled();
                    let matches = match ev_id {
                        Some(id) => id == payment_id,
                        None => true,
                    };
                    if !matches {
                        continue;
                    }
                    // Honesty: Success requires a real preimage (payment receipt).
                    let Some(preimage) = payment_preimage else {
                        return Err(format!(
                            "payment settled without preimage (payment_id={payment_id_hex}); \
                             cannot claim Success"
                        ));
                    };
                    let preimage_hex = bytes_to_hex(&preimage.0);
                    return Ok((preimage_hex, Some(payment_id_hex)));
                }
                Some(Event::PaymentFailed {
                    payment_id: ev_id,
                    reason,
                    ..
                }) => {
                    let _ = node.event_handled();
                    let matches = match ev_id {
                        Some(id) => id == payment_id,
                        None => true,
                    };
                    if !matches {
                        continue;
                    }
                    let why = reason
                        .map(|r| format!("{r:?}"))
                        .unwrap_or_else(|| "unknown".into());
                    return Err(format!(
                        "payment failed: {why} (payment_id={payment_id_hex})"
                    ));
                }
                Some(_other) => {
                    let _ = node.event_handled();
                }
                None => {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    })();

    let _ = node.stop();

    match pay_result {
        Ok((preimage_hex, payment_id_hex)) => {
            emit(&Response::ok_pay(preimage_hex, payment_id_hex));
            Ok(())
        }
        Err(e) => {
            emit(&Response::err(e));
            Err(())
        }
    }
}

fn handle_create_invoice(mut req: Request) -> Result<(), ()> {
    // Capture create-specific fields before bootstrap consumes the request.
    let amount_sats = req.amount_sats;
    let description_raw = req
        .description
        .take()
        .unwrap_or_else(|| DEFAULT_INVOICE_DESCRIPTION.to_owned());
    let expiry_secs = req
        .expiry_secs
        .unwrap_or(DEFAULT_INVOICE_EXPIRY_SECS)
        .max(60);

    // Reject absurd amounts early (defensive; ldk-node also validates).
    if let Some(sats) = amount_sats {
        if sats == 0 {
            zeroize_request_secrets(&mut req);
            emit(&Response::err(
                "amount_sats must be > 0 when set (omit for zero-amount invoice)",
            ));
            return Err(());
        }
        // ~21e6 BTC in sats is the absolute chain supply; refuse larger.
        if sats > 2_100_000_000_000_000 {
            zeroize_request_secrets(&mut req);
            emit(&Response::err("amount_sats exceeds maximum"));
            return Err(());
        }
    }

    let description = match Description::new(description_raw) {
        Ok(d) => d,
        Err(e) => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err(format!("invalid invoice description: {e}")));
            return Err(());
        }
    };
    let invoice_description = Bolt11InvoiceDescription::Direct(description);

    let (node, _network_label, _network, _timeout) = bootstrap_node(req)?;

    let create_result = (|| {
        let inv = match amount_sats {
            Some(sats) => {
                let amount_msat = sats.saturating_mul(1000);
                node.bolt11_payment()
                    .receive(amount_msat, &invoice_description, expiry_secs)
            }
            None => node
                .bolt11_payment()
                .receive_variable_amount(&invoice_description, expiry_secs),
        };
        match inv {
            Ok(i) => {
                let bolt11 = i.to_string();
                if bolt11.trim().is_empty() {
                    return Err("ldk-node returned empty bolt11 (cannot claim Created)".to_owned());
                }
                // BOLT11 HRP (not lnurl / bare ln…). Keep in sync with wallet
                // `looks_like_bolt11` (common prefixes).
                let lower = bolt11.to_ascii_lowercase();
                let looks_bolt11 = lower.starts_with("lnbc")
                    || lower.starts_with("lntb")
                    || lower.starts_with("lnbcrt")
                    || lower.starts_with("lntbs")
                    || lower.starts_with("lnsb")
                    || lower.starts_with("lnbs");
                if !looks_bolt11 {
                    return Err(
                        "ldk-node returned non-bolt11 string (cannot claim Created)".to_owned()
                    );
                }
                Ok(bolt11)
            }
            Err(e) => Err(format!(
                "bolt11 receive invoice failed: {e} (node may lack channels / \
                 inbound liquidity configuration; invoice create is not a funded-channel proof)"
            )),
        }
    })();

    let _ = node.stop();

    match create_result {
        Ok(bolt11) => {
            emit(&Response::ok_invoice(bolt11));
            Ok(())
        }
        Err(e) => {
            emit(&Response::err(e));
            Err(())
        }
    }
}

fn zeroize_request_secrets(req: &mut Request) {
    if let Some(ref mut m) = req.mnemonic {
        m.zeroize();
    }
    if let Some(ref mut p) = req.passphrase {
        p.zeroize();
    }
}

fn parse_network(label: &str) -> Result<Network, String> {
    match label {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unknown network: {other}")),
    }
}

/// BOLT11 currency does not distinguish testnet3 vs testnet4; both map to
/// [`Network::Testnet`]. Accept that pair either way.
fn invoice_network_matches(configured: Network, invoice: Network) -> bool {
    match configured {
        Network::Testnet | Network::Testnet4 => {
            matches!(invoice, Network::Testnet | Network::Testnet4)
        }
        other => other == invoice,
    }
}

fn default_esplora_for_label(network_label: &str) -> String {
    match network_label {
        "testnet" | "testnet3" => "https://blockstream.info/testnet/api".into(),
        // No dedicated public testnet4 Esplora in product defaults; same API
        // host as testnet until a product URL is configured via env.
        "testnet4" => "https://blockstream.info/testnet/api".into(),
        "signet" => "https://mempool.space/signet/api".into(),
        "regtest" => "http://127.0.0.1:3002".into(),
        _ => "https://blockstream.info/api".into(),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn emit(resp: &Response) {
    // Responses must never include mnemonic/seed.
    match serde_json::to_string(resp) {
        Ok(s) => {
            let mut out = io::stdout();
            let _ = writeln!(out, "{s}");
            let _ = out.flush();
        }
        Err(e) => {
            let fallback = format!(
                "{{\"v\":{PROTOCOL_V},\"ok\":false,\"error\":\"serialize response: {e}\"}}"
            );
            let _ = writeln!(io::stdout(), "{fallback}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ping_shape() {
        let s = serde_json::to_string(&Response::ok_ping()).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("ldk_node_linked"));
        assert!(!s.contains("mnemonic"));
    }

    #[test]
    fn protocol_invoice_create_shape() {
        let s = serde_json::to_string(&Response::ok_invoice("lnbc1testinvoice".into())).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("lnbc1testinvoice"));
        assert!(s.contains("bolt11"));
        assert!(!s.contains("preimage"));
        assert!(!s.contains("mnemonic"));
    }

    #[test]
    fn create_invoice_request_deserializes_optional_amount() {
        let with_amt: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"create_bolt11_invoice","amount_sats":1000,"mnemonic":"x","storage_dir":"/tmp/x"}"#,
        )
        .unwrap();
        assert_eq!(with_amt.cmd, "create_bolt11_invoice");
        assert_eq!(with_amt.amount_sats, Some(1000));
        let zero_amt: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"create_bolt11_invoice","mnemonic":"x","storage_dir":"/tmp/x"}"#,
        )
        .unwrap();
        assert_eq!(zero_amt.amount_sats, None);
        // Request must not implement Debug (secrets).
        let _ = with_amt.cmd;
    }

    #[test]
    fn parse_networks() {
        assert!(parse_network("mainnet").is_ok());
        assert!(parse_network("signet").is_ok());
        assert!(parse_network("regtest").is_ok());
        assert!(matches!(parse_network("testnet4"), Ok(Network::Testnet4)));
        assert!(parse_network("nope").is_err());
    }

    #[test]
    fn invoice_network_match_testnet_family() {
        assert!(invoice_network_matches(Network::Testnet, Network::Testnet));
        assert!(invoice_network_matches(Network::Testnet4, Network::Testnet));
        assert!(invoice_network_matches(Network::Testnet, Network::Testnet4));
        assert!(!invoice_network_matches(Network::Bitcoin, Network::Testnet));
        assert!(!invoice_network_matches(Network::Signet, Network::Bitcoin));
    }

    #[test]
    fn hex_encode_round_trip_len() {
        let h = bytes_to_hex(&[0xab, 0xcd]);
        assert_eq!(h, "abcd");
    }

    #[test]
    fn request_has_no_debug_impl() {
        // Coherence guard: if `Request` implements `Debug`, both impls of
        // `AssertNotDebug` apply → E0119 conflicting implementations.
        // (A blanket `impl<T> Trait for T` is a no-op and does NOT detect Debug.)
        trait AssertNotDebug {}
        impl AssertNotDebug for Request {}
        impl<T: std::fmt::Debug + ?Sized> AssertNotDebug for T {}

        fn _needs_assert_not_debug<T: AssertNotDebug>() {}
        _needs_assert_not_debug::<Request>();
        let _ = std::mem::size_of::<Request>();
    }

    #[test]
    fn absolute_storage_required_docs() {
        // Relative paths must be rejected by handle_pay (exercised via product
        // parent always sending absolute scoped dirs).
        assert!(!PathBuf::from("grok-bitcoin-ldk").is_absolute());
        assert!(PathBuf::from("/tmp/grok-bitcoin-ldk").is_absolute());
    }

    #[test]
    fn residual_open_channel_response_shape() {
        let resp = Response::err(RESIDUAL_OPEN_CHANNEL_ERROR);
        assert!(!resp.ok);
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("residual:"));
        assert!(s.contains("open_channel"));
        assert!(!s.contains("\"ok\":true"));
        // Live pay/invoice fields stay absent (error text may mention channel_id deny).
        assert!(resp.preimage_hex.is_none());
        assert!(resp.payment_id_hex.is_none());
        assert!(resp.bolt11.is_none());
        assert!(!s.contains("preimage_hex"));
        assert!(!s.contains("mnemonic"));
        assert!(is_residual_channel_cmd_error(RESIDUAL_OPEN_CHANNEL_ERROR));
    }

    #[test]
    fn residual_connect_peer_response_shape() {
        let resp = Response::err(RESIDUAL_CONNECT_PEER_ERROR);
        assert!(!resp.ok);
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("residual:"));
        assert!(s.contains("connect_peer"));
        assert!(!s.contains("\"ok\":true"));
        assert!(resp.preimage_hex.is_none());
        assert!(resp.bolt11.is_none());
        assert!(is_residual_channel_cmd_error(RESIDUAL_CONNECT_PEER_ERROR));
    }

    #[test]
    fn residual_error_distinct_from_unknown_cmd() {
        let residual_open = RESIDUAL_OPEN_CHANNEL_ERROR;
        let residual_connect = RESIDUAL_CONNECT_PEER_ERROR;
        let unknown = "unknown cmd: open_chanel";
        assert!(is_residual_channel_cmd_error(residual_open));
        assert!(is_residual_channel_cmd_error(residual_connect));
        assert!(
            !is_residual_channel_cmd_error(unknown),
            "typo unknown cmd must not classify as residual"
        );
        assert!(!is_residual_channel_cmd_error(
            "bolt11 send failed: no route"
        ));
        // Residual copy is refuse language (may mention channel_id/Success to deny them).
        assert!(residual_open.starts_with("residual:"));
        assert!(residual_connect.starts_with("residual:"));
        assert!(residual_open.to_ascii_lowercase().contains("never invents"));
        assert!(residual_connect
            .to_ascii_lowercase()
            .contains("never invents"));
        assert!(!residual_open.contains("\"ok\":true"));
    }

    #[test]
    fn residual_channel_cmds_deserialize_shape_fields() {
        let open: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"open_channel","peer_node_id":"02abc","capacity_sats":100000,"mnemonic":"x","storage_dir":"/tmp/x"}"#,
        )
        .unwrap();
        assert_eq!(open.cmd, "open_channel");
        assert_eq!(open.peer_node_id.as_deref(), Some("02abc"));
        assert_eq!(open.capacity_sats, Some(100_000));
        let connect: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"connect_peer","peer_uri":"02abc@host:9735","mnemonic":"x","storage_dir":"/tmp/x"}"#,
        )
        .unwrap();
        assert_eq!(connect.cmd, "connect_peer");
        assert_eq!(connect.peer_uri.as_deref(), Some("02abc@host:9735"));
        // Residual handlers use distinct error text (not unknown cmd).
        assert_eq!(
            ResidualChannelCmd::OpenChannel.error_text(),
            RESIDUAL_OPEN_CHANNEL_ERROR
        );
        assert_eq!(
            ResidualChannelCmd::ConnectPeer.error_text(),
            RESIDUAL_CONNECT_PEER_ERROR
        );
    }

    #[test]
    fn residual_handlers_emit_ok_false_never_channel_id() {
        // Pure classification of residual Response (no ldk-node open/connect call).
        for cmd in [
            ResidualChannelCmd::OpenChannel,
            ResidualChannelCmd::ConnectPeer,
        ] {
            let resp = Response::err(cmd.error_text());
            assert!(!resp.ok);
            assert!(resp.error.is_some());
            assert!(resp.preimage_hex.is_none());
            assert!(resp.payment_id_hex.is_none());
            assert!(resp.bolt11.is_none());
            // No success payload fields — only v/ok/error (error may mention channel_id deny).
            let json = serde_json::to_string(&resp).unwrap();
            assert!(!json.contains("\"ok\":true"));
            assert!(!json.contains("preimage_hex"));
            assert!(!json.contains("\"bolt11\""));
            assert!(json.contains("\"ok\":false"));
            assert!(is_residual_channel_cmd_error(
                resp.error.as_deref().unwrap()
            ));
        }
    }
}
