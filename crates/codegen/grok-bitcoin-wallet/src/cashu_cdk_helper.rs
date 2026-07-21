//! Out-of-process Cashu CDK mint helper adapter (feature `cashu-cdk` only).
//!
//! ## Architecture (rusqlite isolation)
//!
//! Full CDK wallet (`cdk` + `cdk-sqlite`) depends on `rusqlite 0.31`, which
//! **cannot** share a Cargo graph with shell `rusqlite 0.37` (`links=sqlite3`).
//! Live proofs mint therefore runs in the **excluded** helper binary
//! `grok-bitcoin-cdk-mint` (see `crates/codegen/grok-bitcoin-cdk-mint/`).
//!
//! This module is the in-process adapter: SeedVault BIP-39 → stdin/stdout JSON
//! IPC → map to mint quote / proofs outcomes. Seed material never uses
//! CredentialsStore; intermediate phrase buffers are zeroized after the child
//! is fed.
//!
//! ## Capability honesty
//!
//! - Token (`cashuA…`) is returned **only** when the transport reports a
//!   validated token string (never fabricated).
//! - Token ≠ Routstr float until `grok routstr redeem` / balance create|topup
//!   succeeds.
//! - `spend_live` / `refund_live` true when mint URL + helper resolvable
//!   (same gate as `proofs_mint_live`); melt Success only from IPC `melt_token`
//!   with verified PAID shape — never fabricated. Bare `refund()` needs
//!   token+bolt11 via `melt_token_to_bolt11_with_seed`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Env: absolute path to the out-of-process CDK mint helper binary.
pub const CDK_MINT_BIN_ENV: &str = "GROK_BITCOIN_CDK_MINT_BIN";

/// Env: storage **base** directory for CDK wallet sqlite (per-seed subdir appended).
pub const CDK_STORAGE_ENV: &str = "GROK_BITCOIN_CDK_STORAGE";

/// Default helper binary file name (PATH / sibling lookup).
pub const CDK_MINT_BIN_NAME: &str = "grok-bitcoin-cdk-mint";

/// IPC protocol version (must match helper).
pub const CDK_IPC_PROTOCOL_V: u32 = 1;

/// Honest detail when the helper cannot be spawned / is missing.
pub const CDK_HELPER_MISSING: &str = "\
grok-bitcoin-cdk-mint helper not available (build with \
`cargo build --manifest-path crates/codegen/grok-bitcoin-cdk-mint/Cargo.toml` \
and set GROK_BITCOIN_CDK_MINT_BIN or PATH); NUT-04 HTTP mint quote still works; \
proofs→cashuA requires the helper";

// ---------------------------------------------------------------------------
// Transport (injectable for unit tests; product = process IPC)
// ---------------------------------------------------------------------------

/// Inputs for one out-of-process (or mock) mint quote.
///
/// Contains BIP-39 material — **never** log or `Debug` this struct.
pub struct CdkMintQuoteRequest {
    pub mint_url: String,
    pub amount_sats: u64,
    pub mnemonic_phrase: String,
    pub passphrase: String,
    pub storage_dir: PathBuf,
    pub timeout_secs: u64,
}

impl Drop for CdkMintQuoteRequest {
    fn drop(&mut self) {
        self.mnemonic_phrase.zeroize();
        self.passphrase.zeroize();
    }
}

/// Inputs for one out-of-process (or mock) mint-after-paid → token.
///
/// Contains BIP-39 material — **never** log or `Debug` this struct.
pub struct CdkMintAfterPaidRequest {
    pub mint_url: String,
    pub quote_id: String,
    pub mnemonic_phrase: String,
    pub passphrase: String,
    pub storage_dir: PathBuf,
    pub timeout_secs: u64,
}

impl Drop for CdkMintAfterPaidRequest {
    fn drop(&mut self) {
        self.mnemonic_phrase.zeroize();
        self.passphrase.zeroize();
    }
}

/// Outcome from a mint-quote transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdkMintQuoteTransportResult {
    Quote {
        quote_id: String,
        bolt11: String,
        amount_sats: u64,
    },
    Failed {
        reason: String,
    },
}

/// Outcome from a mint-after-paid transport.
///
/// **Debug redacts** the bearer `token` (never dump full `cashuA…` via `{:?}`).
#[derive(Clone, PartialEq, Eq)]
pub enum CdkMintAfterPaidTransportResult {
    /// Linked path returned a real `cashuA…` / `cashuB…` token.
    Token {
        token: String,
        amount_sats: u64,
        quote_id: String,
    },
    Failed {
        reason: String,
    },
}

impl std::fmt::Debug for CdkMintAfterPaidTransportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token {
                token,
                amount_sats,
                quote_id,
            } => {
                let redacted = crate::cashu::CashuToken::parse(token)
                    .map(|t| t.redacted())
                    .unwrap_or_else(|_| "cashuA…[REDACTED]".to_owned());
                f.debug_struct("Token")
                    .field("token", &redacted)
                    .field("amount_sats", amount_sats)
                    .field("quote_id", quote_id)
                    .finish()
            }
            Self::Failed { reason } => f.debug_struct("Failed").field("reason", reason).finish(),
        }
    }
}

/// Inputs for one out-of-process (or mock) melt token → destination BOLT11.
///
/// Contains BIP-39 + bearer token — **never** log or `Debug` this struct.
pub struct CdkMeltTokenRequest {
    pub mint_url: String,
    pub token: String,
    pub bolt11: String,
    pub mnemonic_phrase: String,
    pub passphrase: String,
    pub storage_dir: PathBuf,
    pub timeout_secs: u64,
}

impl Drop for CdkMeltTokenRequest {
    fn drop(&mut self) {
        self.token.zeroize();
        self.mnemonic_phrase.zeroize();
        self.passphrase.zeroize();
    }
}

/// Outcome from a melt-token transport.
///
/// [`CdkMeltTokenTransportResult::Paid`] only when helper reports state=PAID
/// with a non-empty quote_id (never invented).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdkMeltTokenTransportResult {
    /// CDK melt confirmed Paid (Lightning payment from proofs).
    Paid {
        quote_id: String,
        amount_sats: u64,
        fee_sats: u64,
        /// Optional Lightning payment preimage.
        payment_preimage: Option<String>,
    },
    Failed {
        reason: String,
    },
}

/// Abstraction over the isolated CDK mint/melt path (process or mock).
pub trait CdkMintTransport: Send + Sync {
    /// Whether this transport is the real linked helper path (vs residual).
    ///
    /// For [`ProcessCdkMintTransport`]: true only when the helper **binary is
    /// resolvable** on disk (override / env / sibling / PATH). Does not prove a
    /// successful spawn; call-time failures still return Failed.
    fn helper_linked(&self) -> bool;

    /// Create one NUT-04 mint quote via CDK. Must not invent bolt11.
    fn mint_quote(&self, request: &CdkMintQuoteRequest) -> CdkMintQuoteTransportResult;

    /// After pay: mint proofs + export cashuA. Must not invent token.
    fn mint_after_paid(&self, request: &CdkMintAfterPaidRequest)
    -> CdkMintAfterPaidTransportResult;

    /// Melt a bearer `cashuA…` token to a destination BOLT11. Must not invent Paid.
    fn melt_token(&self, request: &CdkMeltTokenRequest) -> CdkMeltTokenTransportResult;
}

/// Product transport: spawn `grok-bitcoin-cdk-mint`, JSON on stdin/stdout.
#[derive(Debug, Clone, Default)]
pub struct ProcessCdkMintTransport {
    /// Override binary path (tests / injectors). `None` → env / PATH resolve.
    pub bin_override: Option<PathBuf>,
}

impl ProcessCdkMintTransport {
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
        if let Ok(p) = std::env::var(CDK_MINT_BIN_ENV) {
            let pb = PathBuf::from(p);
            if !pb.as_os_str().is_empty() {
                return pb;
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let sibling = dir.join(CDK_MINT_BIN_NAME);
                if sibling.is_file() {
                    return sibling;
                }
            }
        }
        PathBuf::from(CDK_MINT_BIN_NAME)
    }

    /// True when the helper binary path is a regular file (or found on PATH).
    pub fn binary_resolvable(&self) -> bool {
        let bin = self.resolve_bin();
        if bin.is_file() {
            return true;
        }
        // Bare name: search PATH entries.
        let is_bare = bin.components().count() == 1;
        if is_bare {
            if let Ok(path) = std::env::var("PATH") {
                for dir in std::env::split_paths(&path) {
                    let candidate = dir.join(&bin);
                    if candidate.is_file() {
                        return true;
                    }
                }
            }
        }
        false
    }

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
                return Err(format!("{CDK_HELPER_MISSING} (spawn {bin:?}: {e})"));
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            let write_res = stdin
                .write_all(payload.as_bytes())
                .and_then(|_| stdin.flush());
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

impl CdkMintTransport for ProcessCdkMintTransport {
    fn helper_linked(&self) -> bool {
        self.binary_resolvable()
    }

    fn mint_quote(&self, request: &CdkMintQuoteRequest) -> CdkMintQuoteTransportResult {
        if !request.storage_dir.is_absolute() {
            return CdkMintQuoteTransportResult::Failed {
                reason: format!(
                    "storage_dir must be absolute (got {})",
                    request.storage_dir.display()
                ),
            };
        }
        if request.amount_sats == 0 {
            return CdkMintQuoteTransportResult::Failed {
                reason: "amount_sats must be > 0".into(),
            };
        }

        let mut payload = match build_mint_quote_ipc_payload(request) {
            Ok(p) => p,
            Err(e) => {
                return CdkMintQuoteTransportResult::Failed {
                    reason: format!("ipc encode: {e}"),
                };
            }
        };

        match self.run_helper_ipc(&mut payload, request.timeout_secs) {
            Ok((stdout, exit_ok)) => parse_helper_quote_stdout(&stdout, exit_ok),
            Err(reason) => {
                payload.zeroize();
                CdkMintQuoteTransportResult::Failed { reason }
            }
        }
    }

    fn mint_after_paid(
        &self,
        request: &CdkMintAfterPaidRequest,
    ) -> CdkMintAfterPaidTransportResult {
        if !request.storage_dir.is_absolute() {
            return CdkMintAfterPaidTransportResult::Failed {
                reason: format!(
                    "storage_dir must be absolute (got {})",
                    request.storage_dir.display()
                ),
            };
        }
        if request.quote_id.trim().is_empty() {
            return CdkMintAfterPaidTransportResult::Failed {
                reason: "quote_id must not be empty".into(),
            };
        }

        let mut payload = match build_mint_after_paid_ipc_payload(request) {
            Ok(p) => p,
            Err(e) => {
                return CdkMintAfterPaidTransportResult::Failed {
                    reason: format!("ipc encode: {e}"),
                };
            }
        };

        match self.run_helper_ipc(&mut payload, request.timeout_secs) {
            Ok((stdout, exit_ok)) => parse_helper_token_stdout(&stdout, exit_ok),
            Err(reason) => {
                payload.zeroize();
                CdkMintAfterPaidTransportResult::Failed { reason }
            }
        }
    }

    fn melt_token(&self, request: &CdkMeltTokenRequest) -> CdkMeltTokenTransportResult {
        if !request.storage_dir.is_absolute() {
            return CdkMeltTokenTransportResult::Failed {
                reason: format!(
                    "storage_dir must be absolute (got {})",
                    request.storage_dir.display()
                ),
            };
        }
        if request.token.trim().is_empty() {
            return CdkMeltTokenTransportResult::Failed {
                reason: "token must not be empty".into(),
            };
        }
        if crate::cashu::CashuToken::parse(&request.token).is_err() {
            return CdkMeltTokenTransportResult::Failed {
                reason: "token failed CashuToken::parse (need cashuA…/cashuB…)".into(),
            };
        }
        if !crate::routstr_invoice::looks_like_bolt11(&request.bolt11) {
            return CdkMeltTokenTransportResult::Failed {
                reason: "bolt11 failed looks_like_bolt11 (lnurl rejected)".into(),
            };
        }

        let mut payload = match build_melt_token_ipc_payload(request) {
            Ok(p) => p,
            Err(e) => {
                return CdkMeltTokenTransportResult::Failed {
                    reason: format!("ipc encode: {e}"),
                };
            }
        };

        match self.run_helper_ipc(&mut payload, request.timeout_secs) {
            Ok((stdout, exit_ok)) => parse_helper_melt_stdout(&stdout, exit_ok),
            Err(reason) => {
                payload.zeroize();
                CdkMeltTokenTransportResult::Failed { reason }
            }
        }
    }
}

fn build_mint_quote_ipc_payload(
    request: &CdkMintQuoteRequest,
) -> std::result::Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        v: u32,
        cmd: &'static str,
        mint_url: &'a str,
        amount_sats: u64,
        mnemonic: &'a str,
        passphrase: &'a str,
        storage_dir: String,
        timeout_secs: u64,
    }
    serde_json::to_string(&Body {
        v: CDK_IPC_PROTOCOL_V,
        cmd: "mint_quote",
        mint_url: &request.mint_url,
        amount_sats: request.amount_sats,
        mnemonic: &request.mnemonic_phrase,
        passphrase: &request.passphrase,
        storage_dir: request.storage_dir.display().to_string(),
        timeout_secs: request.timeout_secs,
    })
}

fn build_mint_after_paid_ipc_payload(
    request: &CdkMintAfterPaidRequest,
) -> std::result::Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        v: u32,
        cmd: &'static str,
        mint_url: &'a str,
        quote_id: &'a str,
        mnemonic: &'a str,
        passphrase: &'a str,
        storage_dir: String,
        timeout_secs: u64,
    }
    serde_json::to_string(&Body {
        v: CDK_IPC_PROTOCOL_V,
        cmd: "mint_after_paid",
        mint_url: &request.mint_url,
        quote_id: &request.quote_id,
        mnemonic: &request.mnemonic_phrase,
        passphrase: &request.passphrase,
        storage_dir: request.storage_dir.display().to_string(),
        timeout_secs: request.timeout_secs,
    })
}

fn build_melt_token_ipc_payload(
    request: &CdkMeltTokenRequest,
) -> std::result::Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Body<'a> {
        v: u32,
        cmd: &'static str,
        mint_url: &'a str,
        token: &'a str,
        bolt11: &'a str,
        mnemonic: &'a str,
        passphrase: &'a str,
        storage_dir: String,
        timeout_secs: u64,
    }
    serde_json::to_string(&Body {
        v: CDK_IPC_PROTOCOL_V,
        cmd: "melt_token",
        mint_url: &request.mint_url,
        token: &request.token,
        bolt11: &request.bolt11,
        mnemonic: &request.mnemonic_phrase,
        passphrase: &request.passphrase,
        storage_dir: request.storage_dir.display().to_string(),
        timeout_secs: request.timeout_secs,
    })
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
    quote_id: Option<String>,
    #[serde(default)]
    bolt11: Option<String>,
    #[serde(default)]
    amount_sats: Option<u64>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    fee_sats: Option<u64>,
    #[serde(default)]
    payment_preimage: Option<String>,
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
        Some(v) if v == CDK_IPC_PROTOCOL_V => {}
        Some(v) => {
            return Err(format!("helper protocol v={v} (want {CDK_IPC_PROTOCOL_V})"));
        }
        None => {
            return Err(format!(
                "helper response missing protocol v (want {CDK_IPC_PROTOCOL_V})"
            ));
        }
    }
    Ok(resp)
}

fn parse_helper_quote_stdout(stdout: &[u8], exit_ok: bool) -> CdkMintQuoteTransportResult {
    let resp = match parse_helper_json_line(stdout, exit_ok) {
        Ok(r) => r,
        Err(e) => return CdkMintQuoteTransportResult::Failed { reason: e },
    };
    if !resp.ok {
        return CdkMintQuoteTransportResult::Failed {
            reason: resp
                .error
                .unwrap_or_else(|| "helper ok=false without error".into()),
        };
    }
    let quote_id = resp
        .quote_id
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let bolt11 = resp
        .bolt11
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    match (quote_id, bolt11) {
        (Some(quote_id), Some(bolt11)) => {
            if !crate::routstr_invoice::looks_like_bolt11(&bolt11) {
                return CdkMintQuoteTransportResult::Failed {
                    reason: "helper quote bolt11 failed looks_like_bolt11 (lnurl rejected)".into(),
                };
            }
            CdkMintQuoteTransportResult::Quote {
                quote_id,
                bolt11,
                amount_sats: resp.amount_sats.unwrap_or(0),
            }
        }
        _ => CdkMintQuoteTransportResult::Failed {
            reason: "helper ok but missing quote_id/bolt11".into(),
        },
    }
}

fn parse_helper_token_stdout(stdout: &[u8], exit_ok: bool) -> CdkMintAfterPaidTransportResult {
    let resp = match parse_helper_json_line(stdout, exit_ok) {
        Ok(r) => r,
        Err(e) => return CdkMintAfterPaidTransportResult::Failed { reason: e },
    };
    if !resp.ok {
        return CdkMintAfterPaidTransportResult::Failed {
            reason: resp
                .error
                .unwrap_or_else(|| "helper ok=false without error".into()),
        };
    }
    let token = resp
        .token
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let Some(token) = token else {
        return CdkMintAfterPaidTransportResult::Failed {
            reason: "helper ok but missing token".into(),
        };
    };
    // Validate cashuA/B via CashuToken parse (never invent).
    if crate::cashu::CashuToken::parse(&token).is_err() {
        return CdkMintAfterPaidTransportResult::Failed {
            reason: "helper token failed CashuToken::parse (need cashuA…/cashuB…)".into(),
        };
    }
    let quote_id = resp.quote_id.unwrap_or_default().trim().to_owned();
    CdkMintAfterPaidTransportResult::Token {
        token,
        amount_sats: resp.amount_sats.unwrap_or(0),
        quote_id,
    }
}

/// Parse melt helper stdout. Paid **only** when ok + state=PAID + quote_id present.
fn parse_helper_melt_stdout(stdout: &[u8], exit_ok: bool) -> CdkMeltTokenTransportResult {
    let resp = match parse_helper_json_line(stdout, exit_ok) {
        Ok(r) => r,
        Err(e) => return CdkMeltTokenTransportResult::Failed { reason: e },
    };
    if !resp.ok {
        return CdkMeltTokenTransportResult::Failed {
            reason: resp
                .error
                .unwrap_or_else(|| "helper ok=false without error".into()),
        };
    }
    let state = resp
        .state
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_uppercase();
    if state != "PAID" {
        return CdkMeltTokenTransportResult::Failed {
            reason: format!(
                "helper ok but melt state is not PAID (got {}); refusing invented Success",
                resp.state.as_deref().unwrap_or("<missing>")
            ),
        };
    }
    let quote_id = resp
        .quote_id
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let Some(quote_id) = quote_id else {
        return CdkMeltTokenTransportResult::Failed {
            reason: "helper melt ok but missing quote_id".into(),
        };
    };
    CdkMeltTokenTransportResult::Paid {
        quote_id,
        amount_sats: resp.amount_sats.unwrap_or(0),
        fee_sats: resp.fee_sats.unwrap_or(0),
        payment_preimage: resp
            .payment_preimage
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()),
    }
}

fn wait_child_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> std::result::Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let mut stdout = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_end(&mut stdout);
                }
                let mut stderr = Vec::new();
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_end(&mut stderr);
                }
                return Ok(std::process::Output {
                    status: _status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("helper timed out after {timeout:?}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("helper try_wait: {e}")),
        }
    }
}

/// Product default storage base for CDK state (`$GROK_HOME/bitcoin/cdk` or `~/.grok/bitcoin/cdk`).
pub fn default_cdk_storage_base() -> PathBuf {
    if let Ok(p) = std::env::var(CDK_STORAGE_ENV) {
        let pb = PathBuf::from(p.trim());
        if pb.is_absolute() {
            return pb;
        }
    }
    if let Ok(home) = std::env::var("GROK_HOME") {
        let pb = PathBuf::from(home.trim());
        if pb.is_absolute() {
            return pb.join("bitcoin").join("cdk");
        }
    }
    dirs_home()
        .map(|h| h.join(".grok").join("bitcoin").join("cdk"))
        .unwrap_or_else(|| PathBuf::from("/tmp/grok-bitcoin-cdk"))
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Scope storage under base with a short seed fingerprint.
///
/// Callers should pass hex of the first 8 bytes of the BIP-39 **seed**
/// (phrase + passphrase), not phrase-only. Empty passphrase is the BIP-39
/// default. Parent passes absolute path; helper requires absolute.
pub fn scoped_cdk_storage_dir(base: &Path, seed_fingerprint_hex: &str) -> PathBuf {
    let fp = seed_fingerprint_hex.trim();
    let safe: String = fp
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(16)
        .collect();
    let label = if safe.is_empty() {
        "unknown".to_owned()
    } else {
        safe
    };
    base.join(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockCdk {
        quote_ok: bool,
        token_ok: bool,
        melt_ok: bool,
    }

    impl CdkMintTransport for MockCdk {
        fn helper_linked(&self) -> bool {
            true
        }

        fn mint_quote(&self, request: &CdkMintQuoteRequest) -> CdkMintQuoteTransportResult {
            assert!(request.amount_sats > 0);
            if self.quote_ok {
                CdkMintQuoteTransportResult::Quote {
                    quote_id: "q-mock".into(),
                    bolt11: "lnbc1mockcdkquote".into(),
                    amount_sats: request.amount_sats,
                }
            } else {
                CdkMintQuoteTransportResult::Failed {
                    reason: "mint down".into(),
                }
            }
        }

        fn mint_after_paid(
            &self,
            request: &CdkMintAfterPaidRequest,
        ) -> CdkMintAfterPaidTransportResult {
            assert!(!request.quote_id.is_empty());
            if self.token_ok {
                CdkMintAfterPaidTransportResult::Token {
                    token: "cashuAabcdefghijklmnopqrstuvwxyz".into(),
                    amount_sats: 21,
                    quote_id: request.quote_id.clone(),
                }
            } else {
                CdkMintAfterPaidTransportResult::Failed {
                    reason: "quote unpaid".into(),
                }
            }
        }

        fn melt_token(&self, request: &CdkMeltTokenRequest) -> CdkMeltTokenTransportResult {
            assert!(crate::cashu::CashuToken::parse(&request.token).is_ok());
            assert!(crate::routstr_invoice::looks_like_bolt11(&request.bolt11));
            if self.melt_ok {
                CdkMeltTokenTransportResult::Paid {
                    quote_id: "mq-mock".into(),
                    amount_sats: 21,
                    fee_sats: 1,
                    payment_preimage: Some("preimage-mock".into()),
                }
            } else {
                CdkMeltTokenTransportResult::Failed {
                    reason: "melt unpaid".into(),
                }
            }
        }
    }

    #[test]
    fn mock_transport_quote_and_token() {
        let t = Arc::new(MockCdk {
            quote_ok: true,
            token_ok: true,
            melt_ok: true,
        });
        let mut q = CdkMintQuoteRequest {
            mint_url: "https://mint.example/".into(),
            amount_sats: 100,
            mnemonic_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: String::new(),
            storage_dir: PathBuf::from("/tmp/cdk-test"),
            timeout_secs: 30,
        };
        match t.mint_quote(&q) {
            CdkMintQuoteTransportResult::Quote {
                quote_id, bolt11, ..
            } => {
                assert_eq!(quote_id, "q-mock");
                assert!(bolt11.starts_with("lnbc"));
            }
            other => panic!("expected Quote: {other:?}"),
        }
        q.mnemonic_phrase.zeroize();

        let mut p = CdkMintAfterPaidRequest {
            mint_url: "https://mint.example/".into(),
            quote_id: "q-mock".into(),
            mnemonic_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: String::new(),
            storage_dir: PathBuf::from("/tmp/cdk-test"),
            timeout_secs: 30,
        };
        match t.mint_after_paid(&p) {
            CdkMintAfterPaidTransportResult::Token { token, .. } => {
                assert!(token.starts_with("cashuA"));
                assert!(crate::cashu::CashuToken::parse(&token).is_ok());
            }
            other => panic!("expected Token: {other:?}"),
        }
        p.mnemonic_phrase.zeroize();
    }

    #[test]
    fn parse_token_stdout_rejects_non_cashu() {
        let line = br#"{"v":1,"ok":true,"token":"sk-not-cashu","quote_id":"q","amount_sats":1}"#;
        match parse_helper_token_stdout(line, true) {
            CdkMintAfterPaidTransportResult::Failed { reason } => {
                assert!(
                    reason.contains("CashuToken"),
                    "must reject non-cashu: {reason}"
                );
            }
            other => panic!("expected Failed: {other:?}"),
        }
    }

    #[test]
    fn parse_quote_stdout_rejects_lnurl() {
        let line =
            br#"{"v":1,"ok":true,"quote_id":"q","bolt11":"lnurl1dp68gurn8ghj7","amount_sats":1}"#;
        match parse_helper_quote_stdout(line, true) {
            CdkMintQuoteTransportResult::Failed { reason } => {
                assert!(
                    reason.contains("looks_like_bolt11") || reason.contains("lnurl"),
                    "{reason}"
                );
            }
            other => panic!("expected Failed: {other:?}"),
        }
    }

    #[test]
    fn parse_quote_stdout_ok() {
        let line =
            br#"{"v":1,"ok":true,"quote_id":"q-1","bolt11":"lnbc1realquote","amount_sats":50}"#;
        match parse_helper_quote_stdout(line, true) {
            CdkMintQuoteTransportResult::Quote {
                quote_id,
                bolt11,
                amount_sats,
            } => {
                assert_eq!(quote_id, "q-1");
                assert_eq!(bolt11, "lnbc1realquote");
                assert_eq!(amount_sats, 50);
            }
            other => panic!("expected Quote: {other:?}"),
        }
    }

    #[test]
    fn request_structs_have_no_debug() {
        trait AssertNotDebug {}
        impl AssertNotDebug for CdkMintQuoteRequest {}
        impl AssertNotDebug for CdkMintAfterPaidRequest {}
        impl AssertNotDebug for CdkMeltTokenRequest {}
        impl<T: std::fmt::Debug + ?Sized> AssertNotDebug for T {}
        fn _check<T: AssertNotDebug>() {}
        _check::<CdkMintQuoteRequest>();
        _check::<CdkMintAfterPaidRequest>();
        _check::<CdkMeltTokenRequest>();
    }

    #[test]
    fn scoped_storage_uses_hex_fingerprint() {
        // Non-hex stripped; up to 16 hex digits (8 seed bytes) kept.
        let p = scoped_cdk_storage_dir(Path::new("/tmp/cdk"), "deadbeef!!extra");
        assert_eq!(p, PathBuf::from("/tmp/cdk/deadbeefea"));
        let p16 = scoped_cdk_storage_dir(Path::new("/tmp/cdk"), "0123456789abcdefZZ");
        assert_eq!(p16, PathBuf::from("/tmp/cdk/0123456789abcdef"));
    }

    #[test]
    fn token_transport_result_debug_redacts_bearer() {
        let full = "cashuAabcdefghijklmnopqrstuvwxyz0123456789";
        let r = CdkMintAfterPaidTransportResult::Token {
            token: full.to_owned(),
            amount_sats: 21,
            quote_id: "q-1".into(),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains(full), "Debug must not dump full token: {dbg}");
        assert!(dbg.contains("cashuA") || dbg.contains("REDACTED"), "{dbg}");
        assert!(dbg.contains("21"), "{dbg}");
    }

    #[test]
    fn process_helper_linked_false_for_missing_bin_override() {
        let t = ProcessCdkMintTransport::with_bin("/nonexistent/grok-bitcoin-cdk-mint-xyz");
        assert!(
            !t.helper_linked(),
            "missing override path must not claim helper_linked"
        );
    }

    #[test]
    fn mock_transport_melt_paid() {
        let t = Arc::new(MockCdk {
            quote_ok: true,
            token_ok: true,
            melt_ok: true,
        });
        let mut r = CdkMeltTokenRequest {
            mint_url: "https://mint.example/".into(),
            token: "cashuAabcdefghijklmnopqrstuvwxyz".into(),
            bolt11: "lnbc1meltdest".into(),
            mnemonic_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: String::new(),
            storage_dir: PathBuf::from("/tmp/cdk-melt"),
            timeout_secs: 30,
        };
        match t.melt_token(&r) {
            CdkMeltTokenTransportResult::Paid {
                quote_id,
                amount_sats,
                fee_sats,
                payment_preimage,
            } => {
                assert_eq!(quote_id, "mq-mock");
                assert_eq!(amount_sats, 21);
                assert_eq!(fee_sats, 1);
                assert_eq!(payment_preimage.as_deref(), Some("preimage-mock"));
            }
            other => panic!("expected Paid: {other:?}"),
        }
        r.token.zeroize();
        r.mnemonic_phrase.zeroize();
    }

    #[test]
    fn parse_melt_stdout_requires_paid_state() {
        let unpaid =
            br#"{"v":1,"ok":true,"quote_id":"mq","amount_sats":10,"fee_sats":1,"state":"PENDING"}"#;
        match parse_helper_melt_stdout(unpaid, true) {
            CdkMeltTokenTransportResult::Failed { reason } => {
                assert!(
                    reason.contains("PAID") || reason.contains("invented"),
                    "must reject non-PAID: {reason}"
                );
            }
            other => panic!("expected Failed: {other:?}"),
        }
        let paid = br#"{"v":1,"ok":true,"quote_id":"mq-1","amount_sats":100,"fee_sats":2,"state":"PAID","payment_preimage":"ab"}"#;
        match parse_helper_melt_stdout(paid, true) {
            CdkMeltTokenTransportResult::Paid {
                quote_id,
                amount_sats,
                fee_sats,
                payment_preimage,
            } => {
                assert_eq!(quote_id, "mq-1");
                assert_eq!(amount_sats, 100);
                assert_eq!(fee_sats, 2);
                assert_eq!(payment_preimage.as_deref(), Some("ab"));
            }
            other => panic!("expected Paid: {other:?}"),
        }
        let missing_qid = br#"{"v":1,"ok":true,"amount_sats":1,"state":"PAID"}"#;
        match parse_helper_melt_stdout(missing_qid, true) {
            CdkMeltTokenTransportResult::Failed { reason } => {
                assert!(reason.contains("quote_id"), "{reason}");
            }
            other => panic!("expected Failed: {other:?}"),
        }
        let err = br#"{"v":1,"ok":false,"error":"melt quote expired"}"#;
        match parse_helper_melt_stdout(err, false) {
            CdkMeltTokenTransportResult::Failed { reason } => {
                assert!(reason.contains("expired"), "{reason}");
            }
            other => panic!("expected Failed: {other:?}"),
        }
    }

    #[test]
    fn process_melt_rejects_bad_inputs_offline() {
        let t = ProcessCdkMintTransport::with_bin("/nonexistent/grok-bitcoin-cdk-mint-missing");
        let mut r = CdkMeltTokenRequest {
            mint_url: "https://mint.example/".into(),
            token: "not-cashu".into(),
            bolt11: "lnbc1x".into(),
            mnemonic_phrase: "x".into(),
            passphrase: String::new(),
            storage_dir: PathBuf::from("/tmp/cdk"),
            timeout_secs: 5,
        };
        match t.melt_token(&r) {
            CdkMeltTokenTransportResult::Failed { reason } => {
                assert!(
                    reason.contains("CashuToken") || reason.contains("cashu"),
                    "{reason}"
                );
            }
            other => panic!("expected Failed: {other:?}"),
        }
        r.token = "cashuAabcdefghijklmnopqrstuvwxyz".into();
        r.bolt11 = "lnurl1dp68gurn8ghj7".into();
        match t.melt_token(&r) {
            CdkMeltTokenTransportResult::Failed { reason } => {
                assert!(
                    reason.contains("looks_like_bolt11") || reason.contains("lnurl"),
                    "{reason}"
                );
            }
            other => panic!("expected Failed: {other:?}"),
        }
        r.token.zeroize();
        r.mnemonic_phrase.zeroize();
    }
}
