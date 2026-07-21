//! LDK BOLT11 pay backend (feature `ldk` only) — out-of-process `ldk-node`.
//!
//! ## Architecture (rusqlite isolation)
//!
//! Preferred stack is [`ldk-node`](https://crates.io/crates/ldk-node) (BIP-39 →
//! `set_entropy_bip39_mnemonic` → `bolt11_payment().send`). That crate depends
//! on `rusqlite 0.31` / `libsqlite3-sys`, which **cannot** share a Cargo
//! dependency graph with `xai-grok-shell`'s `rusqlite 0.37` (`links = "sqlite3"`)
//! — verified both as co-deps of one package **and** as separate workspace
//! members under resolver=2.
//!
//! Live send therefore runs in the **excluded** helper binary
//! `grok-bitcoin-ldk-node` (see `crates/codegen/grok-bitcoin-ldk-node/`). This
//! module is the in-process adapter: SeedVault BIP-39 → stdin/stdout JSON IPC
//! → map to [`PayOutcome`]. Seed material never uses CredentialsStore /
//! provider_credentials.json / watch_session; intermediate phrase buffers are
//! zeroized after the child is fed.
//!
//! ## Capability honesty
//!
//! - [`LdkLightning`] sets **`bolt11_pay_live = true`** and
//!   **`bolt11_invoice_live = true`** when the transport is linked: real send +
//!   receive-invoice paths via helper + `ldk-node`. Unit tests exercise Success /
//!   Created via an injectable [`LdkPayTransport`] mock; product uses
//!   [`ProcessLdkPayTransport`].
//! - **`channel_open_live` / `connect_peer_live` stay false** even when BOLT11
//!   pay/invoice are live. Helper `open_channel` / `connect_peer` IPC return
//!   structured residual `ok:false` (never `channel_id` Success). Product
//!   [`LightningCapability::open_channel`] /
//!   [`LightningCapability::connect_peer`] return Unsupported residual.
//! - Default / non-`ldk` builds still use [`crate::lightning::StubLightning`]
//!   with live flags false (default CI).
//! - [`PayOutcome::Success`] is returned **only** when the transport reports
//!   success with a non-empty preimage hex (never fabricated on missing helper /
//!   non-zero exit / missing preimage).
//! - [`InvoiceOutcome::Created`] is returned **only** when the transport reports
//!   a non-empty `ln…` bolt11 (never fabricated). Bare
//!   [`LightningCapability::create_bolt11_invoice`] without seed fails honestly
//!   (SeedVault path: [`LightningCapability::create_bolt11_invoice_with_seed`]).
//! - Creating an invoice does **not** prove inbound liquidity.
//! - BOLT12 stays false.
//!
//! ## Storage isolation
//!
//! Product default base dir is absolute under `$GROK_HOME/bitcoin/ldk` (or
//! `~/.grok/bitcoin/ldk`). Each pay scopes to
//! `<base>/<seed-fingerprint>/` so multi-wallet / re-entry with a different
//! BIP-39 never reuses another seed's channel monitors. Helper requires an
//! absolute `storage_dir`.
//!
//! ## Helper binary
//!
//! | Env | Role |
//! |-----|------|
//! | [`LDK_NODE_BIN_ENV`] | Absolute path to `grok-bitcoin-ldk-node` |
//! | [`LDK_STORAGE_ENV`] | Absolute base dir (per-seed subdir appended at pay) |
//! | (default bin) | `current_exe` sibling, then `PATH` |
//!
//! Build helper:  
//! `cargo build --manifest-path crates/codegen/grok-bitcoin-ldk-node/Cargo.toml`

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::BOLT12_SUPPORTED;
use crate::error::Result;
use crate::lightning::{
    Bolt11Invoice, CHANNEL_OPEN_RESIDUAL, CONNECT_PEER_RESIDUAL, ChannelOpenOutcome,
    ConnectPeerOutcome, InvoiceOutcome, LightningCapabilities, LightningCapability, PayOutcome,
};
use crate::mnemonic::MnemonicSecret;

/// Helper residual error prefix (must match `grok-bitcoin-ldk-node`).
pub const LDK_HELPER_RESIDUAL_PREFIX: &str = "residual:";

/// Classify helper stdout error as known residual open/connect (vs unknown cmd typo).
pub fn is_helper_residual_channel_cmd_error(error: &str) -> bool {
    let e = error.trim();
    e.starts_with(LDK_HELPER_RESIDUAL_PREFIX)
        && (e.contains("open_channel") || e.contains("connect_peer"))
}

/// Env: storage **base** directory for LDK node state (per-seed subdir appended).
pub const LDK_STORAGE_ENV: &str = "GROK_BITCOIN_LDK_STORAGE";

/// Env: Esplora REST base for LDK chain sync.
pub const LDK_ESPLORA_URL_ENV: &str = "GROK_BITCOIN_LDK_ESPLORA_URL";

/// Env: absolute path to the out-of-process pay helper binary.
pub const LDK_NODE_BIN_ENV: &str = "GROK_BITCOIN_LDK_NODE_BIN";

/// Default helper binary file name (PATH / sibling lookup).
pub const LDK_NODE_BIN_NAME: &str = "grok-bitcoin-ldk-node";

/// IPC protocol version (must match helper).
pub const LDK_IPC_PROTOCOL_V: u32 = 1;

/// Marker file written under per-seed storage (detects path reuse bugs).
pub const LDK_SEED_ID_MARKER: &str = "GROK_LDK_SEED_ID";

/// Honest detail when the helper cannot be spawned / is missing.
pub const LDK_HELPER_MISSING: &str = "\
grok-bitcoin-ldk-node helper not available (build with \
`cargo build --manifest-path crates/codegen/grok-bitcoin-ldk-node/Cargo.toml` \
and set GROK_BITCOIN_LDK_NODE_BIN or PATH); pay Routstr BOLT11 with external wallet QR";

// ---------------------------------------------------------------------------
// Transport (injectable for unit tests; product = process IPC)
// ---------------------------------------------------------------------------

/// Inputs for one out-of-process (or mock) BOLT11 pay.
///
/// Contains BIP-39 material — **never** log or `Debug` this struct.
pub struct LdkPayRequest {
    pub invoice: String,
    pub mnemonic_phrase: String,
    pub passphrase: String,
    pub network_label: String,
    pub storage_dir: PathBuf,
    pub esplora_url: String,
    pub timeout_secs: u64,
}

impl Drop for LdkPayRequest {
    fn drop(&mut self) {
        self.mnemonic_phrase.zeroize();
        self.passphrase.zeroize();
    }
}

/// Inputs for one out-of-process (or mock) BOLT11 receive-invoice create.
///
/// Contains BIP-39 material — **never** log or `Debug` this struct.
pub struct LdkCreateInvoiceRequest {
    pub amount_sats: Option<u64>,
    pub description: String,
    pub expiry_secs: u32,
    pub mnemonic_phrase: String,
    pub passphrase: String,
    pub network_label: String,
    pub storage_dir: PathBuf,
    pub esplora_url: String,
    pub timeout_secs: u64,
}

impl Drop for LdkCreateInvoiceRequest {
    fn drop(&mut self) {
        self.mnemonic_phrase.zeroize();
        self.passphrase.zeroize();
    }
}

/// Inputs for residual `open_channel` IPC (shape only — never invents Success).
///
/// Contains BIP-39 material — **never** log or `Debug` this struct.
pub struct LdkOpenChannelRequest {
    pub peer_node_id: String,
    pub capacity_sats: u64,
    pub mnemonic_phrase: String,
    pub passphrase: String,
    pub network_label: String,
    pub storage_dir: PathBuf,
    pub esplora_url: String,
    pub timeout_secs: u64,
}

impl Drop for LdkOpenChannelRequest {
    fn drop(&mut self) {
        self.mnemonic_phrase.zeroize();
        self.passphrase.zeroize();
    }
}

/// Inputs for residual `connect_peer` IPC (shape only — never invents Success).
///
/// Contains BIP-39 material — **never** log or `Debug` this struct.
pub struct LdkConnectPeerRequest {
    pub peer_uri: String,
    pub mnemonic_phrase: String,
    pub passphrase: String,
    pub network_label: String,
    pub storage_dir: PathBuf,
    pub esplora_url: String,
    pub timeout_secs: u64,
}

impl Drop for LdkConnectPeerRequest {
    fn drop(&mut self) {
        self.mnemonic_phrase.zeroize();
        self.passphrase.zeroize();
    }
}

/// Parsed residual open/connect helper response (never Success).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdkResidualChannelTransportResult {
    /// Helper recognized residual cmd and refused with residual:… error.
    Residual { reason: String },
    /// Non-residual failure (typo unknown cmd, parse error, etc.).
    Failed { reason: String },
}

/// Outcome from a pay transport (mapped to [`PayOutcome`] by [`LdkLightning`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdkPayTransportResult {
    /// Linked path reported success with a real preimage hex (payment receipt).
    Success {
        preimage_hex: String,
        payment_id_hex: Option<String>,
    },
    Failed {
        reason: String,
    },
}

/// Outcome from a create-invoice transport (mapped to [`InvoiceOutcome`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdkCreateInvoiceTransportResult {
    /// Linked path returned a real BOLT11 string.
    Created {
        bolt11: String,
    },
    Failed {
        reason: String,
    },
}

/// Abstraction over the isolated LDK pay / create-invoice path (process or mock).
pub trait LdkPayTransport: Send + Sync {
    /// Whether this transport is the real linked helper path (vs residual).
    fn node_linked(&self) -> bool;

    /// Execute one BOLT11 pay. Must not invent Success without a real send.
    fn pay_bolt11(&self, request: &LdkPayRequest) -> LdkPayTransportResult;

    /// Create one BOLT11 receive invoice. Must not invent Created without a real
    /// helper/mock invoice string.
    fn create_bolt11_invoice(
        &self,
        request: &LdkCreateInvoiceRequest,
    ) -> LdkCreateInvoiceTransportResult;
}

/// Product transport: spawn `grok-bitcoin-ldk-node`, JSON on stdin/stdout.
#[derive(Debug, Clone, Default)]
pub struct ProcessLdkPayTransport {
    /// Override binary path (tests / injectors). `None` → env / PATH resolve.
    pub bin_override: Option<PathBuf>,
}

impl ProcessLdkPayTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bin(bin: impl Into<PathBuf>) -> Self {
        Self {
            bin_override: Some(bin.into()),
        }
    }

    /// Resolve helper binary path (override → env → sibling of current_exe → PATH name).
    pub fn resolve_bin(&self) -> PathBuf {
        if let Some(ref p) = self.bin_override {
            return p.clone();
        }
        if let Ok(p) = std::env::var(LDK_NODE_BIN_ENV) {
            let pb = PathBuf::from(p);
            if !pb.as_os_str().is_empty() {
                return pb;
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sibling = dir.join(LDK_NODE_BIN_NAME);
                if sibling.is_file() {
                    return sibling;
                }
            }
        }
        PathBuf::from(LDK_NODE_BIN_NAME)
    }
}

impl ProcessLdkPayTransport {
    fn run_helper_ipc(
        &self,
        payload: &mut String,
        timeout_secs: u64,
    ) -> std::result::Result<(Vec<u8>, bool), String> {
        let bin = self.resolve_bin();
        let mut child = match Command::new(&bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return Err(format!("{LDK_HELPER_MISSING} (spawn {bin:?}: {e})"));
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            let write_res = stdin
                .write_all(payload.as_bytes())
                .and_then(|_| stdin.flush());
            // Zeroize JSON (contains mnemonic) before waiting on child.
            payload.zeroize();
            if let Err(e) = write_res {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("write helper stdin: {e}"));
            }
        } else {
            payload.zeroize();
            let _ = child.kill();
            let _ = child.wait();
            return Err("helper stdin not piped".into());
        }

        let timeout = Duration::from_secs(timeout_secs.saturating_add(30).max(60));
        let output =
            wait_child_with_timeout(child, timeout).map_err(|e| format!("helper wait: {e}"))?;
        Ok((output.stdout, output.status.success()))
    }
}

impl LdkPayTransport for ProcessLdkPayTransport {
    fn node_linked(&self) -> bool {
        true
    }

    fn pay_bolt11(&self, request: &LdkPayRequest) -> LdkPayTransportResult {
        if !request.storage_dir.is_absolute() {
            return LdkPayTransportResult::Failed {
                reason: format!(
                    "storage_dir must be absolute (got {})",
                    request.storage_dir.display()
                ),
            };
        }

        let mut payload = match build_pay_ipc_payload(request) {
            Ok(p) => p,
            Err(e) => {
                return LdkPayTransportResult::Failed {
                    reason: format!("ipc encode: {e}"),
                };
            }
        };

        match self.run_helper_ipc(&mut payload, request.timeout_secs) {
            Ok((stdout, exit_ok)) => parse_helper_pay_stdout(&stdout, exit_ok),
            Err(reason) => {
                payload.zeroize();
                LdkPayTransportResult::Failed { reason }
            }
        }
    }

    fn create_bolt11_invoice(
        &self,
        request: &LdkCreateInvoiceRequest,
    ) -> LdkCreateInvoiceTransportResult {
        if !request.storage_dir.is_absolute() {
            return LdkCreateInvoiceTransportResult::Failed {
                reason: format!(
                    "storage_dir must be absolute (got {})",
                    request.storage_dir.display()
                ),
            };
        }

        let mut payload = match build_create_invoice_ipc_payload(request) {
            Ok(p) => p,
            Err(e) => {
                return LdkCreateInvoiceTransportResult::Failed {
                    reason: format!("ipc encode: {e}"),
                };
            }
        };

        match self.run_helper_ipc(&mut payload, request.timeout_secs) {
            Ok((stdout, exit_ok)) => parse_helper_invoice_stdout(&stdout, exit_ok),
            Err(reason) => {
                payload.zeroize();
                LdkCreateInvoiceTransportResult::Failed { reason }
            }
        }
    }
}

/// Build the JSON body for the helper pay cmd (caller must zeroize the returned string).
fn build_pay_ipc_payload(
    request: &LdkPayRequest,
) -> std::result::Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        v: u32,
        cmd: &'static str,
        invoice: &'a str,
        mnemonic: &'a str,
        passphrase: &'a str,
        network: &'a str,
        storage_dir: String,
        esplora_url: &'a str,
        timeout_secs: u64,
    }
    let body = Body {
        v: LDK_IPC_PROTOCOL_V,
        cmd: "pay_bolt11",
        invoice: &request.invoice,
        mnemonic: &request.mnemonic_phrase,
        passphrase: &request.passphrase,
        network: &request.network_label,
        storage_dir: request.storage_dir.display().to_string(),
        esplora_url: &request.esplora_url,
        timeout_secs: request.timeout_secs,
    };
    serde_json::to_string(&body)
}

/// Build JSON for helper `create_bolt11_invoice` (caller must zeroize).
fn build_create_invoice_ipc_payload(
    request: &LdkCreateInvoiceRequest,
) -> std::result::Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        v: u32,
        cmd: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        amount_sats: Option<u64>,
        description: &'a str,
        expiry_secs: u32,
        mnemonic: &'a str,
        passphrase: &'a str,
        network: &'a str,
        storage_dir: String,
        esplora_url: &'a str,
        timeout_secs: u64,
    }
    let body = Body {
        v: LDK_IPC_PROTOCOL_V,
        cmd: "create_bolt11_invoice",
        amount_sats: request.amount_sats,
        description: &request.description,
        expiry_secs: request.expiry_secs,
        mnemonic: &request.mnemonic_phrase,
        passphrase: &request.passphrase,
        network: &request.network_label,
        storage_dir: request.storage_dir.display().to_string(),
        esplora_url: &request.esplora_url,
        timeout_secs: request.timeout_secs,
    };
    serde_json::to_string(&body)
}

/// Build JSON for residual helper `open_channel` (caller must zeroize).
///
/// Product residual path: helper returns `ok:false` residual — never channel_id.
pub fn build_open_channel_ipc_payload(
    request: &LdkOpenChannelRequest,
) -> std::result::Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        v: u32,
        cmd: &'static str,
        peer_node_id: &'a str,
        capacity_sats: u64,
        mnemonic: &'a str,
        passphrase: &'a str,
        network: &'a str,
        storage_dir: String,
        esplora_url: &'a str,
        timeout_secs: u64,
    }
    let body = Body {
        v: LDK_IPC_PROTOCOL_V,
        cmd: "open_channel",
        peer_node_id: &request.peer_node_id,
        capacity_sats: request.capacity_sats,
        mnemonic: &request.mnemonic_phrase,
        passphrase: &request.passphrase,
        network: &request.network_label,
        storage_dir: request.storage_dir.display().to_string(),
        esplora_url: &request.esplora_url,
        timeout_secs: request.timeout_secs,
    };
    serde_json::to_string(&body)
}

/// Build JSON for residual helper `connect_peer` (caller must zeroize).
pub fn build_connect_peer_ipc_payload(
    request: &LdkConnectPeerRequest,
) -> std::result::Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        v: u32,
        cmd: &'static str,
        peer_uri: &'a str,
        mnemonic: &'a str,
        passphrase: &'a str,
        network: &'a str,
        storage_dir: String,
        esplora_url: &'a str,
        timeout_secs: u64,
    }
    let body = Body {
        v: LDK_IPC_PROTOCOL_V,
        cmd: "connect_peer",
        peer_uri: &request.peer_uri,
        mnemonic: &request.mnemonic_phrase,
        passphrase: &request.passphrase,
        network: &request.network_label,
        storage_dir: request.storage_dir.display().to_string(),
        esplora_url: &request.esplora_url,
        timeout_secs: request.timeout_secs,
    };
    serde_json::to_string(&body)
}

/// Parse residual open/connect helper stdout — **never** maps to Success.
///
/// Recognizes distinct `residual: open_channel|connect_peer …` vs `unknown cmd`.
pub fn parse_helper_residual_channel_stdout(
    stdout: &[u8],
    exit_ok: bool,
) -> LdkResidualChannelTransportResult {
    let resp = match parse_helper_json_line(stdout, exit_ok) {
        Ok(r) => r,
        Err(reason) => return LdkResidualChannelTransportResult::Failed { reason },
    };

    // Honesty: residual channel cmds must never claim ok:true / channel_id.
    if resp.ok {
        return LdkResidualChannelTransportResult::Failed {
            reason: "helper claimed ok on residual open_channel/connect_peer \
                     (cannot claim Success; no live channel contract)"
                .into(),
        };
    }

    let detail = resp
        .error
        .unwrap_or_else(|| "helper residual failure without error".into());

    if is_helper_residual_channel_cmd_error(&detail) {
        LdkResidualChannelTransportResult::Residual { reason: detail }
    } else {
        LdkResidualChannelTransportResult::Failed {
            reason: if exit_ok {
                detail
            } else {
                format!("helper exit non-zero: {detail}")
            },
        }
    }
}

#[derive(Debug, Deserialize)]
struct HelperResponse {
    #[serde(default)]
    v: Option<u32>,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    preimage_hex: Option<String>,
    #[serde(default)]
    payment_id_hex: Option<String>,
    #[serde(default)]
    bolt11: Option<String>,
}

fn parse_helper_json_line(
    stdout: &[u8],
    exit_ok: bool,
) -> std::result::Result<HelperResponse, String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if line.is_empty() {
        return Err(if exit_ok {
            "helper produced empty stdout".into()
        } else {
            "helper exited non-zero with empty stdout".into()
        });
    }
    let resp: HelperResponse =
        serde_json::from_str(line).map_err(|e| format!("helper JSON parse: {e}"))?;

    match resp.v {
        Some(v) if v == LDK_IPC_PROTOCOL_V => {}
        Some(v) => {
            return Err(format!("helper protocol v={v} (want {LDK_IPC_PROTOCOL_V})"));
        }
        None => {
            return Err(format!(
                "helper response missing protocol v (want {LDK_IPC_PROTOCOL_V})"
            ));
        }
    }
    Ok(resp)
}

fn parse_helper_pay_stdout(stdout: &[u8], exit_ok: bool) -> LdkPayTransportResult {
    let resp = match parse_helper_json_line(stdout, exit_ok) {
        Ok(r) => r,
        Err(reason) => return LdkPayTransportResult::Failed { reason },
    };

    if !exit_ok {
        let detail = resp
            .error
            .unwrap_or_else(|| "helper exited non-zero".into());
        return LdkPayTransportResult::Failed {
            reason: format!("helper exit non-zero: {detail}"),
        };
    }

    if !resp.ok {
        return LdkPayTransportResult::Failed {
            reason: resp
                .error
                .unwrap_or_else(|| "helper reported failure without error".into()),
        };
    }

    // Honesty: Success requires a non-empty preimage hex (payment receipt).
    let preimage_hex = resp
        .preimage_hex
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    match preimage_hex {
        Some(preimage_hex) => LdkPayTransportResult::Success {
            preimage_hex,
            payment_id_hex: resp.payment_id_hex,
        },
        None => LdkPayTransportResult::Failed {
            reason: "helper claimed ok without preimage_hex (cannot claim Success)".into(),
        },
    }
}

fn parse_helper_invoice_stdout(stdout: &[u8], exit_ok: bool) -> LdkCreateInvoiceTransportResult {
    let resp = match parse_helper_json_line(stdout, exit_ok) {
        Ok(r) => r,
        Err(reason) => return LdkCreateInvoiceTransportResult::Failed { reason },
    };

    if !exit_ok {
        let detail = resp
            .error
            .unwrap_or_else(|| "helper exited non-zero".into());
        return LdkCreateInvoiceTransportResult::Failed {
            reason: format!("helper exit non-zero: {detail}"),
        };
    }

    if !resp.ok {
        return LdkCreateInvoiceTransportResult::Failed {
            reason: resp
                .error
                .unwrap_or_else(|| "helper reported failure without error".into()),
        };
    }

    let bolt11 = resp
        .bolt11
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    match bolt11 {
        Some(bolt11) if crate::routstr_invoice::looks_like_bolt11(&bolt11) => {
            LdkCreateInvoiceTransportResult::Created { bolt11 }
        }
        Some(_) => LdkCreateInvoiceTransportResult::Failed {
            reason: "helper claimed ok with non-bolt11 string (cannot claim Created)".into(),
        },
        None => LdkCreateInvoiceTransportResult::Failed {
            reason: "helper claimed ok without bolt11 (cannot claim Created)".into(),
        },
    }
}

/// Back-compat alias used by unit tests (not part of lib surface under clippy --lib).
#[cfg(test)]
#[inline]
fn parse_helper_stdout(stdout: &[u8], exit_ok: bool) -> LdkPayTransportResult {
    parse_helper_pay_stdout(stdout, exit_ok)
}

fn wait_child_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> std::result::Result<std::process::Output, String> {
    // Poll `try_wait` so we can `child.kill()` cross-platform and never block
    // forever on a stuck reaper. Drain stdout on a side thread so a filled
    // pipe cannot deadlock the helper (stderr is already Stdio::null()).
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "helper stdout not piped".to_string())?;
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = match stdout_handle.join() {
                    Ok(b) => b,
                    Err(_) => return Err("helper stdout reader panicked".into()),
                };
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr: Vec::new(),
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    // Soft TERM then hard kill (unix); Child::kill is SIGKILL on
                    // unix and TerminateProcess on Windows.
                    #[cfg(unix)]
                    {
                        let pid = child.id();
                        let _ = Command::new("kill")
                            .arg("-TERM")
                            .arg(pid.to_string())
                            .status();
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    let _ = child.kill();

                    // Best-effort reap within a short grace — never unbounded join.
                    let grace = Duration::from_secs(3);
                    let grace_start = Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) if grace_start.elapsed() < grace => {
                                std::thread::sleep(Duration::from_millis(50));
                            }
                            Ok(None) => break, // unreaped; do not block forever
                            Err(_) => break,
                        }
                    }
                    // Join stdout drain only if finished; else detach (drop handle).
                    if stdout_handle.is_finished() {
                        let _ = stdout_handle.join();
                    }
                    return Err(format!("helper timed out after {timeout:?}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                if stdout_handle.is_finished() {
                    let _ = stdout_handle.join();
                }
                return Err(format!("helper try_wait: {e}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Storage path helpers (absolute + per-seed isolation)
// ---------------------------------------------------------------------------

/// Stable public path id from BIP-39 seed (isolation only — not a secret).
///
/// FNV-1a over the 64-byte seed → 32 hex chars. Different seeds get different
/// channel DBs under the product storage base.
pub fn ldk_storage_id_from_seed(seed: &[u8; 64]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in seed {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut hash2: u64 = 0x84222325cbf29ce4;
    for &b in seed.iter().rev() {
        hash2 ^= u64::from(b);
        hash2 = hash2.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}{hash2:016x}")
}

/// Default absolute storage **base** (env → `$GROK_HOME/bitcoin/ldk` → `~/.grok/...`).
pub fn default_ldk_storage_base() -> PathBuf {
    if let Ok(p) = std::env::var(LDK_STORAGE_ENV) {
        let pb = PathBuf::from(p);
        if !pb.as_os_str().is_empty() {
            return absolutize_path(pb);
        }
    }
    if let Ok(h) = std::env::var("GROK_HOME") {
        let home = PathBuf::from(h);
        if !home.as_os_str().is_empty() {
            return absolutize_path(home.join("bitcoin").join("ldk"));
        }
    }
    if let Some(home) = std::env::home_dir() {
        return home.join(".grok").join("bitcoin").join("ldk");
    }
    // Last resort: absolute temp (still not relative CWD scatter).
    std::env::temp_dir().join("grok-bitcoin-ldk")
}

/// Make `path` absolute (join CWD if relative). Prefer callers that already
/// have absolute paths.
pub fn absolutize_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => std::env::temp_dir().join(path),
    }
}

/// `<base>/<seed_id>` — never share channel monitors across BIP-39 seeds.
pub fn scoped_ldk_storage_dir(base: &Path, seed_id: &str) -> PathBuf {
    absolutize_path(base.to_path_buf()).join(seed_id)
}

/// Ensure dir exists and marker matches `seed_id` (fail closed on mismatch).
pub fn ensure_ldk_storage_seed_binding(
    dir: &Path,
    seed_id: &str,
) -> std::result::Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create LDK storage: {e}"))?;
    let marker = dir.join(LDK_SEED_ID_MARKER);
    if marker.exists() {
        let existing = std::fs::read_to_string(&marker)
            .map_err(|e| format!("read {LDK_SEED_ID_MARKER}: {e}"))?;
        if existing.trim() != seed_id {
            return Err(format!(
                "LDK storage seed id mismatch under {} (store is bound to another wallet; \
                 do not share storage across BIP-39 seeds)",
                dir.display()
            ));
        }
    } else {
        std::fs::write(&marker, seed_id).map_err(|e| format!("write {LDK_SEED_ID_MARKER}: {e}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Product backend
// ---------------------------------------------------------------------------

/// Product LDK backend: SeedVault pay via isolated `ldk-node` helper.
///
/// Does **not** hold mnemonic/seed after construction — only storage base /
/// network config + transport. Seed is supplied at pay time and zeroized.
/// Pay scopes storage to `<storage_base>/<seed_id>/`.
#[derive(Clone)]
pub struct LdkLightning {
    /// Absolute base directory; per-seed subdir is appended at pay time.
    storage_base: PathBuf,
    network_label: String,
    esplora_url: String,
    timeout_secs: u64,
    transport: Arc<dyn LdkPayTransport>,
}

impl std::fmt::Debug for LdkLightning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdkLightning")
            .field("storage_base", &self.storage_base)
            .field("network_label", &self.network_label)
            .field("esplora_url", &self.esplora_url)
            .field("timeout_secs", &self.timeout_secs)
            .field("node_linked", &self.transport.node_linked())
            // Never log seed/mnemonic — this type does not hold them.
            .finish()
    }
}

impl LdkLightning {
    /// Explicit configuration with product process transport.
    pub fn new(
        storage_base: impl Into<PathBuf>,
        network_label: impl Into<String>,
        esplora_url: impl Into<String>,
    ) -> Self {
        Self::with_transport(
            storage_base,
            network_label,
            esplora_url,
            120,
            Arc::new(ProcessLdkPayTransport::new()),
        )
    }

    /// Full constructor (tests / custom timeout / mock transport).
    pub fn with_transport(
        storage_base: impl Into<PathBuf>,
        network_label: impl Into<String>,
        esplora_url: impl Into<String>,
        timeout_secs: u64,
        transport: Arc<dyn LdkPayTransport>,
    ) -> Self {
        Self {
            storage_base: absolutize_path(storage_base.into()),
            network_label: network_label.into(),
            esplora_url: esplora_url.into(),
            timeout_secs: timeout_secs.max(1),
            transport,
        }
    }

    /// Product defaults from env (mainnet + Blockstream Esplora when unset).
    ///
    /// | Env | Role |
    /// |-----|------|
    /// | [`LDK_STORAGE_ENV`] | Absolute storage **base** (per-seed subdir at pay) |
    /// | `GROK_BITCOIN_NETWORK` | `mainnet` / `signet` / `testnet` / `testnet4` / `regtest` |
    /// | [`LDK_ESPLORA_URL_ENV`] or `GROK_BITCOIN_ESPLORA_URL` | Chain source |
    /// | [`LDK_NODE_BIN_ENV`] | Helper binary path |
    pub fn product_default() -> Self {
        let storage_base = default_ldk_storage_base();
        // Preserve testnet4 as its own label (shared acceptance with helper).
        let network_label = match std::env::var("GROK_BITCOIN_NETWORK")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "signet" => "signet",
            "testnet" | "testnet3" => "testnet",
            "testnet4" => "testnet4",
            "regtest" => "regtest",
            _ => "mainnet",
        }
        .to_owned();
        let esplora_url = std::env::var(LDK_ESPLORA_URL_ENV)
            .or_else(|_| std::env::var("GROK_BITCOIN_ESPLORA_URL"))
            .unwrap_or_else(|_| default_esplora_for_label(&network_label));
        Self::new(storage_base, network_label, esplora_url)
    }

    /// Absolute storage **base** (per-seed subdirs live underneath).
    pub fn storage_dir(&self) -> &Path {
        &self.storage_base
    }

    /// Network label (`mainnet` / `signet` / `testnet` / `testnet4` / …).
    pub fn network_label(&self) -> &str {
        &self.network_label
    }

    /// Configured Esplora base URL.
    pub fn esplora_url(&self) -> &str {
        &self.esplora_url
    }

    /// Whether a real `ldk-node` send path is linked (via isolated helper).
    ///
    /// Always `true` for process transport — live flag tracks the adapter, not
    /// whether the helper binary is currently on `PATH` (missing helper →
    /// honest [`PayOutcome::Failed`] at pay time).
    pub fn node_linked(&self) -> bool {
        self.transport.node_linked()
    }
}

impl LightningCapability for LdkLightning {
    fn capabilities(&self) -> LightningCapabilities {
        LightningCapabilities {
            // Real send path: isolated helper → ldk-node bolt11_payment().send.
            bolt11_pay_live: self.transport.node_linked(),
            // Real receive-invoice path: helper → ldk-node bolt11_payment().receive.
            bolt11_invoice_live: self.transport.node_linked(),
            bolt12_supported: BOLT12_SUPPORTED,
            // Live channel open / peer connect remain residual even when BOLT11
            // pay/invoice are live (helper refuses open_channel / connect_peer).
            channel_open_live: false,
            connect_peer_live: false,
        }
    }

    fn open_channel(&self, _peer_node_id: &str, _capacity_sats: u64) -> Result<ChannelOpenOutcome> {
        // Residual product surface — never Success / fabricated channel_id.
        Ok(ChannelOpenOutcome::Unsupported(CHANNEL_OPEN_RESIDUAL))
    }

    fn open_channel_with_seed(
        &self,
        peer_node_id: &str,
        capacity_sats: u64,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<ChannelOpenOutcome> {
        // Residual: build IPC shape (zeroize secrets) for offline honesty tests;
        // do not invent Success. Product refuses without claiming helper Success.
        let mut seed = mnemonic.to_seed(passphrase);
        let seed_id = ldk_storage_id_from_seed(&seed);
        seed.zeroize();
        let storage_dir = scoped_ldk_storage_dir(&self.storage_base, &seed_id);

        let mut phrase = mnemonic.expose().to_owned();
        let mut pass = passphrase.to_owned();
        let request = LdkOpenChannelRequest {
            peer_node_id: peer_node_id.to_owned(),
            capacity_sats,
            mnemonic_phrase: std::mem::take(&mut phrase),
            passphrase: std::mem::take(&mut pass),
            network_label: self.network_label.clone(),
            storage_dir,
            esplora_url: self.esplora_url.clone(),
            timeout_secs: self.timeout_secs,
        };
        phrase.zeroize();
        pass.zeroize();

        // Encode residual IPC payload then drop (zeroizes mnemonic on Drop).
        let mut payload = match build_open_channel_ipc_payload(&request) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ChannelOpenOutcome::Failed(format!("ipc encode: {e}")));
            }
        };
        // Prove residual cmd + never claim Success from payload alone.
        debug_assert!(payload.contains("open_channel"));
        payload.zeroize();
        // request Drop zeroizes mnemonic/passphrase

        Ok(ChannelOpenOutcome::Unsupported(CHANNEL_OPEN_RESIDUAL))
    }

    fn connect_peer(&self, _peer_uri: &str) -> Result<ConnectPeerOutcome> {
        Ok(ConnectPeerOutcome::Unsupported(CONNECT_PEER_RESIDUAL))
    }

    fn connect_peer_with_seed(
        &self,
        peer_uri: &str,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<ConnectPeerOutcome> {
        let mut seed = mnemonic.to_seed(passphrase);
        let seed_id = ldk_storage_id_from_seed(&seed);
        seed.zeroize();
        let storage_dir = scoped_ldk_storage_dir(&self.storage_base, &seed_id);

        let mut phrase = mnemonic.expose().to_owned();
        let mut pass = passphrase.to_owned();
        let request = LdkConnectPeerRequest {
            peer_uri: peer_uri.to_owned(),
            mnemonic_phrase: std::mem::take(&mut phrase),
            passphrase: std::mem::take(&mut pass),
            network_label: self.network_label.clone(),
            storage_dir,
            esplora_url: self.esplora_url.clone(),
            timeout_secs: self.timeout_secs,
        };
        phrase.zeroize();
        pass.zeroize();

        let mut payload = match build_connect_peer_ipc_payload(&request) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ConnectPeerOutcome::Failed(format!("ipc encode: {e}")));
            }
        };
        debug_assert!(payload.contains("connect_peer"));
        payload.zeroize();

        Ok(ConnectPeerOutcome::Unsupported(CONNECT_PEER_RESIDUAL))
    }

    fn pay_bolt11(&self, invoice: &Bolt11Invoice) -> Result<PayOutcome> {
        if invoice.0.trim().is_empty() {
            return Ok(PayOutcome::Failed("empty invoice".into()));
        }
        // Seed-holding path only — never claim Success without BIP-39.
        Ok(PayOutcome::Failed(
            "LDK BOLT11 pay requires SeedVault BIP-39 (pay_bolt11_with_seed); \
             bare pay_bolt11 is not used for live local pay"
                .into(),
        ))
    }

    fn pay_bolt11_with_seed(
        &self,
        invoice: &Bolt11Invoice,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<PayOutcome> {
        if invoice.0.trim().is_empty() {
            return Ok(PayOutcome::Failed("empty invoice".into()));
        }

        // Derive seed for (1) path isolation id (2) zeroize discipline.
        // Helper re-derives from mnemonic; parent must not retain seed.
        let mut seed = mnemonic.to_seed(passphrase);
        let seed_id = ldk_storage_id_from_seed(&seed);
        seed.zeroize();

        let storage_dir = scoped_ldk_storage_dir(&self.storage_base, &seed_id);
        if let Err(e) = ensure_ldk_storage_seed_binding(&storage_dir, &seed_id) {
            return Ok(PayOutcome::Failed(e));
        }

        // Copy phrase into request; LdkPayRequest::drop zeroizes it.
        let mut phrase = mnemonic.expose().to_owned();
        let mut pass = passphrase.to_owned();
        let request = LdkPayRequest {
            invoice: invoice.0.clone(),
            mnemonic_phrase: std::mem::take(&mut phrase),
            passphrase: std::mem::take(&mut pass),
            network_label: self.network_label.clone(),
            storage_dir,
            esplora_url: self.esplora_url.clone(),
            timeout_secs: self.timeout_secs,
        };
        phrase.zeroize();
        pass.zeroize();

        let result = self.transport.pay_bolt11(&request);
        // request dropped here → zeroizes mnemonic_phrase + passphrase

        Ok(match result {
            LdkPayTransportResult::Success {
                preimage_hex,
                payment_id_hex: _,
            } => {
                if preimage_hex.trim().is_empty() {
                    PayOutcome::Failed("transport returned Success with empty preimage_hex".into())
                } else {
                    PayOutcome::Success { preimage_hex }
                }
            }
            LdkPayTransportResult::Failed { reason } => PayOutcome::Failed(reason),
        })
    }

    fn create_bolt11_invoice(&self, _amount_sats: Option<u64>) -> Result<InvoiceOutcome> {
        // Seed-holding path only — never fabricate a bolt11 without BIP-39.
        Ok(InvoiceOutcome::Failed(
            "LDK BOLT11 invoice create requires SeedVault BIP-39 \
             (create_bolt11_invoice_with_seed); bare create is not used for live local invoice"
                .into(),
        ))
    }

    fn create_bolt11_invoice_with_seed(
        &self,
        amount_sats: Option<u64>,
        mnemonic: &MnemonicSecret,
        passphrase: &str,
    ) -> Result<InvoiceOutcome> {
        if let Some(0) = amount_sats {
            return Ok(InvoiceOutcome::Failed(
                "amount_sats must be > 0 when set (pass None for zero-amount invoice)".into(),
            ));
        }

        let mut seed = mnemonic.to_seed(passphrase);
        let seed_id = ldk_storage_id_from_seed(&seed);
        seed.zeroize();

        let storage_dir = scoped_ldk_storage_dir(&self.storage_base, &seed_id);
        if let Err(e) = ensure_ldk_storage_seed_binding(&storage_dir, &seed_id) {
            return Ok(InvoiceOutcome::Failed(e));
        }

        let mut phrase = mnemonic.expose().to_owned();
        let mut pass = passphrase.to_owned();
        let request = LdkCreateInvoiceRequest {
            amount_sats,
            description: "grok-bitcoin-wallet receive".into(),
            expiry_secs: 3600,
            mnemonic_phrase: std::mem::take(&mut phrase),
            passphrase: std::mem::take(&mut pass),
            network_label: self.network_label.clone(),
            storage_dir,
            esplora_url: self.esplora_url.clone(),
            timeout_secs: self.timeout_secs,
        };
        phrase.zeroize();
        pass.zeroize();

        let result = self.transport.create_bolt11_invoice(&request);

        Ok(match result {
            LdkCreateInvoiceTransportResult::Created { bolt11 } => {
                let b = bolt11.trim();
                if b.is_empty() || !crate::routstr_invoice::looks_like_bolt11(b) {
                    InvoiceOutcome::Failed(
                        "transport returned Created without a valid bolt11".into(),
                    )
                } else {
                    InvoiceOutcome::Created {
                        bolt11: b.to_owned(),
                    }
                }
            }
            LdkCreateInvoiceTransportResult::Failed { reason } => InvoiceOutcome::Failed(reason),
        })
    }
}

fn default_esplora_for_label(network_label: &str) -> String {
    match network_label {
        "testnet" | "testnet3" => "https://blockstream.info/testnet/api".into(),
        // Same public host until a dedicated testnet4 Esplora is configured.
        "testnet4" => "https://blockstream.info/testnet/api".into(),
        "signet" => "https://mempool.space/signet/api".into(),
        "regtest" => "http://127.0.0.1:3002".into(),
        _ => "https://blockstream.info/api".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::generate_mnemonic;
    use std::sync::Mutex;

    /// Mock transport: records calls; returns configured result.
    struct MockTransport {
        linked: bool,
        result: Mutex<LdkPayTransportResult>,
        create_result: Mutex<LdkCreateInvoiceTransportResult>,
        last_invoice: Mutex<Option<String>>,
        last_storage: Mutex<Option<PathBuf>>,
        last_create_amount: Mutex<Option<Option<u64>>>,
    }

    impl MockTransport {
        fn ok(preimage_hex: impl Into<String>) -> Self {
            Self {
                linked: true,
                result: Mutex::new(LdkPayTransportResult::Success {
                    preimage_hex: preimage_hex.into(),
                    payment_id_hex: Some("aa".repeat(32)),
                }),
                create_result: Mutex::new(LdkCreateInvoiceTransportResult::Created {
                    bolt11: "lnbc1mockcreatedinvoice".into(),
                }),
                last_invoice: Mutex::new(None),
                last_storage: Mutex::new(None),
                last_create_amount: Mutex::new(None),
            }
        }

        fn fail(reason: &str) -> Self {
            Self {
                linked: true,
                result: Mutex::new(LdkPayTransportResult::Failed {
                    reason: reason.into(),
                }),
                create_result: Mutex::new(LdkCreateInvoiceTransportResult::Failed {
                    reason: reason.into(),
                }),
                last_invoice: Mutex::new(None),
                last_storage: Mutex::new(None),
                last_create_amount: Mutex::new(None),
            }
        }

        fn unlinked() -> Self {
            Self {
                linked: false,
                result: Mutex::new(LdkPayTransportResult::Failed {
                    reason: "unlinked".into(),
                }),
                create_result: Mutex::new(LdkCreateInvoiceTransportResult::Failed {
                    reason: "unlinked".into(),
                }),
                last_invoice: Mutex::new(None),
                last_storage: Mutex::new(None),
                last_create_amount: Mutex::new(None),
            }
        }
    }

    impl LdkPayTransport for MockTransport {
        fn node_linked(&self) -> bool {
            self.linked
        }

        fn pay_bolt11(&self, request: &LdkPayRequest) -> LdkPayTransportResult {
            *self.last_invoice.lock().unwrap() = Some(request.invoice.clone());
            *self.last_storage.lock().unwrap() = Some(request.storage_dir.clone());
            assert!(
                !request.mnemonic_phrase.is_empty(),
                "transport must receive BIP-39 phrase"
            );
            assert!(
                request.storage_dir.is_absolute(),
                "storage_dir must be absolute: {}",
                request.storage_dir.display()
            );
            self.result.lock().unwrap().clone()
        }

        fn create_bolt11_invoice(
            &self,
            request: &LdkCreateInvoiceRequest,
        ) -> LdkCreateInvoiceTransportResult {
            *self.last_create_amount.lock().unwrap() = Some(request.amount_sats);
            *self.last_storage.lock().unwrap() = Some(request.storage_dir.clone());
            assert!(
                !request.mnemonic_phrase.is_empty(),
                "create transport must receive BIP-39 phrase"
            );
            assert!(
                request.storage_dir.is_absolute(),
                "storage_dir must be absolute: {}",
                request.storage_dir.display()
            );
            self.create_result.lock().unwrap().clone()
        }
    }

    #[test]
    fn ldk_live_caps_when_transport_linked() {
        let ln = LdkLightning::with_transport(
            "/tmp/x",
            "mainnet",
            "https://example.invalid",
            30,
            Arc::new(MockTransport::ok("ab".repeat(32))),
        );
        let caps = ln.capabilities();
        assert!(caps.bolt11_pay_live, "linked transport must claim live pay");
        assert!(
            caps.bolt11_invoice_live,
            "linked transport must claim live invoice create"
        );
        assert!(!caps.bolt12_supported);
        // Channel open / connect stay residual even when pay/invoice live.
        assert!(
            !caps.channel_open_live,
            "channel_open_live must stay false with live BOLT11"
        );
        assert!(
            !caps.connect_peer_live,
            "connect_peer_live must stay false with live BOLT11"
        );
        assert!(ln.node_linked());
    }

    #[test]
    fn ldk_unlinked_transport_live_false() {
        let ln = LdkLightning::with_transport(
            "/tmp/x",
            "mainnet",
            "https://example.invalid",
            30,
            Arc::new(MockTransport::unlinked()),
        );
        assert!(!ln.capabilities().bolt11_pay_live);
        assert!(!ln.capabilities().bolt11_invoice_live);
        assert!(!ln.capabilities().channel_open_live);
        assert!(!ln.capabilities().connect_peer_live);
        assert!(!ln.node_linked());
    }

    #[test]
    fn ldk_open_channel_connect_peer_residual_never_success() {
        let ln = LdkLightning::with_transport(
            std::env::temp_dir().join("grok-ldk-mock-channel-residual"),
            "signet",
            "https://mempool.space/signet/api",
            30,
            Arc::new(MockTransport::ok("ab".repeat(32))),
        );
        assert!(ln.capabilities().bolt11_pay_live);
        assert!(!ln.capabilities().channel_open_live);
        assert!(!ln.capabilities().connect_peer_live);

        let open = ln.open_channel("02abc", 100_000).unwrap();
        assert!(
            matches!(open, ChannelOpenOutcome::Unsupported(_)),
            "open_channel must be residual Unsupported: {open:?}"
        );
        assert!(!matches!(open, ChannelOpenOutcome::Success { .. }));

        let connect = ln.connect_peer("02abc@host:9735").unwrap();
        assert!(
            matches!(connect, ConnectPeerOutcome::Unsupported(_)),
            "connect_peer must be residual Unsupported: {connect:?}"
        );
        assert!(!matches!(connect, ConnectPeerOutcome::Success { .. }));

        let m = generate_mnemonic().unwrap();
        let open_seed = ln
            .open_channel_with_seed("02abc", 50_000, &m, "pass")
            .unwrap();
        assert!(
            matches!(open_seed, ChannelOpenOutcome::Unsupported(s) if s.contains("residual")),
            "{open_seed:?}"
        );
        let connect_seed = ln
            .connect_peer_with_seed("02abc@host:9735", &m, "pass")
            .unwrap();
        assert!(
            matches!(connect_seed, ConnectPeerOutcome::Unsupported(s) if s.contains("residual")),
            "{connect_seed:?}"
        );
    }

    #[test]
    fn ldk_create_invoice_success_only_from_transport() {
        let mock = Arc::new(MockTransport::ok("cd".repeat(32)));
        let ln = LdkLightning::with_transport(
            std::env::temp_dir().join("grok-ldk-mock-inv-ok"),
            "signet",
            "https://mempool.space/signet/api",
            30,
            mock.clone(),
        );
        let m = generate_mnemonic().unwrap();
        let out = ln
            .create_bolt11_invoice_with_seed(Some(1000), &m, "")
            .unwrap();
        match out {
            InvoiceOutcome::Created { bolt11 } => {
                assert!(bolt11.starts_with("ln"));
                assert_eq!(bolt11, "lnbc1mockcreatedinvoice");
            }
            other => panic!("expected Created from mock transport: {other:?}"),
        }
        assert_eq!(
            mock.last_create_amount.lock().unwrap().clone(),
            Some(Some(1000))
        );
        let bare = ln.create_bolt11_invoice(Some(1000)).unwrap();
        assert!(
            matches!(bare, InvoiceOutcome::Failed(ref s) if s.contains("SeedVault")),
            "bare create must not invent invoice: {bare:?}"
        );
    }

    #[test]
    fn ldk_create_invoice_failure_never_claims_created() {
        let ln = LdkLightning::with_transport(
            std::env::temp_dir().join("grok-ldk-mock-inv-fail"),
            "signet",
            "https://mempool.space/signet/api",
            30,
            Arc::new(MockTransport::fail("no inbound liquidity / channels")),
        );
        let m = generate_mnemonic().unwrap();
        let out = ln
            .create_bolt11_invoice_with_seed(Some(500), &m, "")
            .unwrap();
        assert!(
            matches!(out, InvoiceOutcome::Failed(ref s) if s.contains("liquidity") || s.contains("channel")),
            "{out:?}"
        );
    }

    #[test]
    fn ldk_create_invoice_rejects_zero_amount_sats() {
        let ln = LdkLightning::with_transport(
            "/tmp/x",
            "mainnet",
            "https://example.invalid",
            30,
            Arc::new(MockTransport::ok("ab".repeat(32))),
        );
        let m = generate_mnemonic().unwrap();
        let out = ln.create_bolt11_invoice_with_seed(Some(0), &m, "").unwrap();
        assert!(matches!(out, InvoiceOutcome::Failed(ref s) if s.contains("amount_sats")));
    }

    #[test]
    fn ldk_pay_success_only_from_transport() {
        let mock = Arc::new(MockTransport::ok("cd".repeat(32)));
        let ln = LdkLightning::with_transport(
            std::env::temp_dir().join("grok-ldk-mock-ok"),
            "signet",
            "https://mempool.space/signet/api",
            30,
            mock.clone(),
        );
        let m = generate_mnemonic().unwrap();
        let out = ln
            .pay_bolt11_with_seed(&Bolt11Invoice("lnbc1test".into()), &m, "")
            .unwrap();
        match out {
            PayOutcome::Success { preimage_hex } => {
                assert_eq!(preimage_hex, "cd".repeat(32));
            }
            other => panic!("expected Success from mock transport: {other:?}"),
        }
        assert_eq!(
            mock.last_invoice.lock().unwrap().as_deref(),
            Some("lnbc1test")
        );
        // Storage must be scoped under seed id (not bare base).
        let storage = mock.last_storage.lock().unwrap().clone().unwrap();
        assert!(storage.is_absolute());
        let seed = m.to_seed("");
        let id = ldk_storage_id_from_seed(&seed);
        assert!(
            storage.ends_with(&id),
            "storage {} should end with seed id {id}",
            storage.display()
        );
    }

    #[test]
    fn ldk_pay_failure_never_claims_success() {
        let ln = LdkLightning::with_transport(
            std::env::temp_dir().join("grok-ldk-mock-fail"),
            "signet",
            "https://mempool.space/signet/api",
            30,
            Arc::new(MockTransport::fail("no outbound liquidity")),
        );
        let m = generate_mnemonic().unwrap();
        let out = ln
            .pay_bolt11_with_seed(&Bolt11Invoice("lnbc1test".into()), &m, "")
            .unwrap();
        assert!(
            matches!(out, PayOutcome::Failed(ref s) if s.contains("outbound")),
            "{out:?}"
        );
    }

    #[test]
    fn ldk_process_transport_missing_bin_fails_honestly() {
        let ln = LdkLightning::with_transport(
            std::env::temp_dir().join("grok-ldk-missing-bin"),
            "signet",
            "https://mempool.space/signet/api",
            5,
            Arc::new(ProcessLdkPayTransport::with_bin(
                "/nonexistent/grok-bitcoin-ldk-node-test-missing",
            )),
        );
        assert!(ln.capabilities().bolt11_pay_live);
        let m = generate_mnemonic().unwrap();
        let out = ln
            .pay_bolt11_with_seed(&Bolt11Invoice("lnbc1test".into()), &m, "")
            .unwrap();
        match out {
            PayOutcome::Failed(s) => {
                assert!(
                    s.contains("helper") || s.contains("spawn") || s.contains("not available"),
                    "{s}"
                );
            }
            other => panic!("missing helper must not Success: {other:?}"),
        }
        let bare = ln.pay_bolt11(&Bolt11Invoice("lnbc1test".into())).unwrap();
        assert!(matches!(bare, PayOutcome::Failed(_)));
    }

    #[test]
    fn ldk_empty_invoice_fails() {
        let ln = LdkLightning::with_transport(
            "/tmp/x",
            "mainnet",
            "https://example.invalid",
            30,
            Arc::new(MockTransport::ok("ab".repeat(32))),
        );
        let m = generate_mnemonic().unwrap();
        let out = ln
            .pay_bolt11_with_seed(&Bolt11Invoice("".into()), &m, "")
            .unwrap();
        assert!(matches!(out, PayOutcome::Failed(ref s) if s.contains("empty")));
    }

    #[test]
    fn ldk_debug_has_no_seed_fields() {
        let ln = LdkLightning::new("/tmp/x", "mainnet", "https://example.invalid");
        let s = format!("{ln:?}");
        assert!(s.contains("LdkLightning"));
        assert!(!s.contains("mnemonic"));
        assert!(!s.to_ascii_lowercase().contains("seed_bytes"));
        assert!(!s.contains("passphrase"));
    }

    #[test]
    fn product_default_env_contract_names() {
        assert_eq!(LDK_STORAGE_ENV, "GROK_BITCOIN_LDK_STORAGE");
        assert_eq!(LDK_ESPLORA_URL_ENV, "GROK_BITCOIN_LDK_ESPLORA_URL");
        assert_eq!(LDK_NODE_BIN_ENV, "GROK_BITCOIN_LDK_NODE_BIN");
        assert_eq!(LDK_NODE_BIN_NAME, "grok-bitcoin-ldk-node");
    }

    #[test]
    fn default_storage_base_is_absolute() {
        let base = default_ldk_storage_base();
        assert!(
            base.is_absolute(),
            "default storage base must be absolute: {}",
            base.display()
        );
    }

    #[test]
    fn seed_ids_differ_for_different_mnemonics() {
        let a = generate_mnemonic().unwrap();
        let b = generate_mnemonic().unwrap();
        let id_a = ldk_storage_id_from_seed(&a.to_seed(""));
        let id_b = ldk_storage_id_from_seed(&b.to_seed(""));
        // Extremely unlikely collision for random mnemonics.
        if a.expose() != b.expose() {
            assert_ne!(id_a, id_b);
        }
        assert_eq!(id_a.len(), 32);
    }

    #[test]
    fn seed_binding_mismatch_fails() {
        let dir = std::env::temp_dir().join(format!("grok-ldk-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_ldk_storage_seed_binding(&dir, "aaa").unwrap();
        let err = ensure_ldk_storage_seed_binding(&dir, "bbb").unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ipc_payload_includes_protocol_fields() {
        let req = LdkPayRequest {
            invoice: "lnbc1x".into(),
            mnemonic_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: String::new(),
            network_label: "signet".into(),
            storage_dir: PathBuf::from("/tmp/ldk"),
            esplora_url: "https://example.invalid".into(),
            timeout_secs: 60,
        };
        let mut payload = build_pay_ipc_payload(&req).unwrap();
        assert!(payload.contains("\"v\":1"));
        assert!(payload.contains("pay_bolt11"));
        assert!(payload.contains("lnbc1x"));
        payload.zeroize();
    }

    #[test]
    fn ipc_create_invoice_payload_includes_protocol_fields() {
        let req = LdkCreateInvoiceRequest {
            amount_sats: Some(2100),
            description: "test receive".into(),
            expiry_secs: 600,
            mnemonic_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: String::new(),
            network_label: "signet".into(),
            storage_dir: PathBuf::from("/tmp/ldk"),
            esplora_url: "https://example.invalid".into(),
            timeout_secs: 60,
        };
        let mut payload = build_create_invoice_ipc_payload(&req).unwrap();
        assert!(payload.contains("\"v\":1"));
        assert!(payload.contains("create_bolt11_invoice"));
        assert!(payload.contains("2100"));
        assert!(payload.contains("test receive"));
        payload.zeroize();
    }

    #[test]
    fn ipc_open_channel_payload_residual_shape_and_zeroize() {
        let req = LdkOpenChannelRequest {
            peer_node_id: "02abc".into(),
            capacity_sats: 100_000,
            mnemonic_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: "secret-pass".into(),
            network_label: "signet".into(),
            storage_dir: PathBuf::from("/tmp/ldk"),
            esplora_url: "https://example.invalid".into(),
            timeout_secs: 60,
        };
        let mut payload = build_open_channel_ipc_payload(&req).unwrap();
        assert!(payload.contains("\"v\":1"));
        assert!(payload.contains("open_channel"));
        assert!(payload.contains("02abc"));
        assert!(payload.contains("100000"));
        assert!(!payload.contains("pay_bolt11"));
        // Secrets present in payload until caller zeroizes (same as pay/create).
        assert!(payload.contains("abandon"));
        payload.zeroize();
        assert!(!payload.contains("abandon"));
        assert!(!payload.contains("secret-pass"));
    }

    #[test]
    fn ipc_connect_peer_payload_residual_shape_and_zeroize() {
        let req = LdkConnectPeerRequest {
            peer_uri: "02abc@lsp.example:9735".into(),
            mnemonic_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: "secret-pass".into(),
            network_label: "signet".into(),
            storage_dir: PathBuf::from("/tmp/ldk"),
            esplora_url: "https://example.invalid".into(),
            timeout_secs: 60,
        };
        let mut payload = build_connect_peer_ipc_payload(&req).unwrap();
        assert!(payload.contains("\"v\":1"));
        assert!(payload.contains("connect_peer"));
        assert!(payload.contains("02abc@lsp.example:9735"));
        payload.zeroize();
        assert!(!payload.contains("abandon"));
        assert!(!payload.contains("secret-pass"));
    }

    #[test]
    fn parse_helper_residual_channel_stdout_classifies_residual_vs_typo() {
        let residual_open = parse_helper_residual_channel_stdout(
            br#"{"v":1,"ok":false,"error":"residual: open_channel not implemented in this helper (product residual; no live channel-open contract; never invents channel_id Success)"}"#,
            false,
        );
        match residual_open {
            LdkResidualChannelTransportResult::Residual { reason } => {
                assert!(is_helper_residual_channel_cmd_error(&reason));
                assert!(reason.contains("open_channel"));
            }
            other => panic!("expected Residual: {other:?}"),
        }

        let residual_connect = parse_helper_residual_channel_stdout(
            br#"{"v":1,"ok":false,"error":"residual: connect_peer not implemented in this helper (product residual; no live peer-connect contract; never invents peer Success)"}"#,
            false,
        );
        assert!(matches!(
            residual_connect,
            LdkResidualChannelTransportResult::Residual { .. }
        ));

        let unknown = parse_helper_residual_channel_stdout(
            br#"{"v":1,"ok":false,"error":"unknown cmd: open_chanel"}"#,
            false,
        );
        match unknown {
            LdkResidualChannelTransportResult::Failed { reason } => {
                assert!(!is_helper_residual_channel_cmd_error(&reason));
                assert!(reason.contains("unknown cmd") || reason.contains("open_chanel"));
            }
            other => panic!("typo must not classify as Residual: {other:?}"),
        }

        // ok:true on residual path must never be treated as Success.
        let lied = parse_helper_residual_channel_stdout(
            br#"{"v":1,"ok":true,"channel_id":"deadbeef"}"#,
            true,
        );
        assert!(
            matches!(
                lied,
                LdkResidualChannelTransportResult::Failed { ref reason }
                    if reason.contains("cannot claim Success")
            ),
            "{lied:?}"
        );
    }

    #[test]
    fn parse_helper_invoice_success_and_failure() {
        let ok =
            parse_helper_invoice_stdout(br#"{"v":1,"ok":true,"bolt11":"lnbc1reallooking"}"#, true);
        assert!(matches!(
            ok,
            LdkCreateInvoiceTransportResult::Created { ref bolt11 } if bolt11 == "lnbc1reallooking"
        ));
        let bad =
            parse_helper_invoice_stdout(br#"{"v":1,"ok":false,"error":"no channels"}"#, false);
        assert!(matches!(
            bad,
            LdkCreateInvoiceTransportResult::Failed { ref reason } if reason.contains("no channels")
        ));
        let no_bolt = parse_helper_invoice_stdout(br#"{"v":1,"ok":true}"#, true);
        assert!(matches!(
            no_bolt,
            LdkCreateInvoiceTransportResult::Failed { ref reason } if reason.contains("bolt11")
        ));
        let not_ln =
            parse_helper_invoice_stdout(br#"{"v":1,"ok":true,"bolt11":"not-an-invoice"}"#, true);
        assert!(matches!(
            not_ln,
            LdkCreateInvoiceTransportResult::Failed { ref reason } if reason.contains("non-bolt11")
        ));
    }

    #[test]
    fn parse_helper_success_and_failure() {
        let ok = parse_helper_stdout(
            br#"{"v":1,"ok":true,"preimage_hex":"aa","payment_id_hex":"bb"}"#,
            true,
        );
        assert!(matches!(
            ok,
            LdkPayTransportResult::Success {
                ref preimage_hex,
                ..
            } if preimage_hex == "aa"
        ));
        let bad = parse_helper_stdout(br#"{"v":1,"ok":false,"error":"no route"}"#, false);
        assert!(matches!(
            bad,
            LdkPayTransportResult::Failed { ref reason } if reason.contains("no route")
        ));
    }

    #[test]
    fn parse_helper_rejects_ok_with_nonzero_exit() {
        let r = parse_helper_stdout(br#"{"v":1,"ok":true,"preimage_hex":"aa"}"#, false);
        assert!(matches!(
            r,
            LdkPayTransportResult::Failed { ref reason } if reason.contains("non-zero")
        ));
    }

    #[test]
    fn parse_helper_rejects_ok_without_preimage() {
        let r = parse_helper_stdout(br#"{"v":1,"ok":true,"payment_id_hex":"bb"}"#, true);
        assert!(matches!(
            r,
            LdkPayTransportResult::Failed { ref reason } if reason.contains("preimage")
        ));
    }

    #[test]
    fn parse_helper_rejects_missing_or_wrong_protocol_v() {
        let missing = parse_helper_stdout(br#"{"ok":true,"preimage_hex":"aa"}"#, true);
        assert!(matches!(
            missing,
            LdkPayTransportResult::Failed { ref reason } if reason.contains("protocol")
        ));
        let wrong = parse_helper_stdout(br#"{"v":99,"ok":true,"preimage_hex":"aa"}"#, true);
        assert!(matches!(
            wrong,
            LdkPayTransportResult::Failed { ref reason } if reason.contains("v=99")
        ));
    }

    #[test]
    fn process_transport_reports_node_linked() {
        assert!(ProcessLdkPayTransport::new().node_linked());
    }

    #[test]
    fn network_label_table_includes_testnet4() {
        // product_default mapping is env-dependent; pin the acceptance table used.
        assert_eq!(
            default_esplora_for_label("testnet4"),
            default_esplora_for_label("testnet")
        );
        assert!(default_esplora_for_label("signet").contains("signet"));
    }
}
