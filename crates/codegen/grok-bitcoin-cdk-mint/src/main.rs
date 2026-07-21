//! Out-of-process Cashu CDK mint helper (NUT-04 quote + proofs → cashuA token).
//!
//! ## Why a separate binary
//!
//! `cdk-sqlite` pulls `rusqlite 0.31` / `libsqlite3-sys` (`links = "sqlite3"`).
//! The monorepo shell uses `rusqlite 0.37` for FTS5 / sqlite-vec / CVE pins.
//! Cargo forbids both in one dependency graph (even across workspace members).
//! This crate is **excluded** from the monorepo workspace so it resolves and
//! links its own sqlite independently — same isolation pattern as
//! `grok-bitcoin-ldk-node`.
//!
//! ## Protocol (stdin → stdout JSON, v1)
//!
//! Health: `{ "v": 1, "cmd": "ping" }`
//!
//! Create mint quote (returns BOLT11 to pay the mint — **not** Routstr float):
//! ```json
//! {
//!   "v": 1,
//!   "cmd": "mint_quote",
//!   "mint_url": "https://mint.example/Bitcoin",
//!   "amount_sats": 1000,
//!   "mnemonic": "twelve or twenty four words …",
//!   "passphrase": "",
//!   "storage_dir": "/absolute/path/for/cdk/state"
//! }
//! ```
//! Success: `{ "v":1, "ok":true, "quote_id":"…", "bolt11":"ln…", "amount_sats":1000 }`
//!
//! After the mint quote BOLT11 is paid, mint proofs and export a redeemable token:
//! ```json
//! {
//!   "v": 1,
//!   "cmd": "mint_after_paid",
//!   "mint_url": "https://mint.example/Bitcoin",
//!   "quote_id": "…",
//!   "mnemonic": "…",
//!   "passphrase": "",
//!   "storage_dir": "/absolute/path",
//!   "timeout_secs": 120
//! }
//! ```
//! Success: `{ "v":1, "ok":true, "token":"cashuA…", "amount_sats":1000, "quote_id":"…" }`
//!
//! Melt a bearer `cashuA…` token to a destination BOLT11 (NUT-05 via CDK):
//! ```json
//! {
//!   "v": 1,
//!   "cmd": "melt_token",
//!   "mint_url": "https://mint.example/Bitcoin",
//!   "token": "cashuA…",
//!   "bolt11": "lnbc…",
//!   "mnemonic": "…",
//!   "passphrase": "",
//!   "storage_dir": "/absolute/path",
//!   "timeout_secs": 120
//! }
//! ```
//! Success (only when CDK reports melt state Paid):
//! `{ "v":1, "ok":true, "quote_id":"…", "amount_sats":1000, "fee_sats":1, "state":"PAID", "payment_preimage":"…" }`
//! Never invents Paid — Pending/Failed/Unpaid → ok=false.
//!
//! Failure: `{ "v":1, "ok":false, "error":"…" }`
//!
//! ## Security
//! - Mnemonic/passphrase arrive only on stdin (never argv/env/disk plaintext).
//! - Buffers holding phrase material are zeroized after use.
//! - Do not log request bodies (contain seed material). `Request` has no `Debug`.
//! - `storage_dir` **must be absolute**.
//! - Emitted `token` is a bearer secret — parent must not log/Debug dump it;
//!   product redeems via Routstr `balance/create|topup` / `grok routstr redeem`.
//! - Melt **input** `token` is also a bearer secret (zeroized after use).
//! - Mint success ≠ Routstr float credit until redeem succeeds.
//! - Melt Paid = Lightning payment from Cashu proofs; not Routstr float credit.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bip39::Mnemonic;
use cdk::amount::SplitTarget;
use cdk::nuts::{CurrencyUnit, MeltQuoteState, MintQuoteState, PaymentMethod};
use cdk::wallet::{SendOptions, Wallet};
use cdk::Amount;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const PROTOCOL_V: u32 = 1;
const DEFAULT_TIMEOUT_SECS: u64 = 120;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;

/// Request body — **no Debug** (mnemonic/passphrase/token material must never print).
///
/// [`Drop`] zeroizes `mnemonic` / `passphrase` / melt `token` so early exits
/// (ping with accidental secrets, unknown cmd, protocol mismatch) still scrub.
#[derive(Deserialize)]
struct Request {
    #[serde(default = "default_v")]
    v: u32,
    cmd: String,
    #[serde(default)]
    mint_url: Option<String>,
    #[serde(default)]
    amount_sats: Option<u64>,
    #[serde(default)]
    quote_id: Option<String>,
    #[serde(default)]
    mnemonic: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    storage_dir: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    poll_interval_secs: Option<u64>,
    /// Bearer Cashu token for melt (`cashuA…` / `cashuB…`). Zeroized on drop.
    #[serde(default)]
    token: Option<String>,
    /// Destination BOLT11 for melt (NUT-05).
    #[serde(default)]
    bolt11: Option<String>,
}

impl Drop for Request {
    fn drop(&mut self) {
        zeroize_request_secrets(self);
    }
}

fn default_v() -> u32 {
    PROTOCOL_V
}

/// BOLT11 HRP allowlist (parity with wallet `looks_like_bolt11` — rejects lnurl).
fn looks_like_bolt11(s: &str) -> bool {
    let b = s.trim().to_ascii_lowercase();
    if b.is_empty() || b.len() > 4096 {
        return false;
    }
    if b.starts_with("lnurl") {
        return false;
    }
    b.starts_with("lnbc")
        || b.starts_with("lntb")
        || b.starts_with("lnbcrt")
        || b.starts_with("lntbs")
        || b.starts_with("lnsb")
        || b.starts_with("lnbs")
}

#[derive(Debug, Serialize)]
struct Response {
    v: u32,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bolt11: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_sats: Option<u64>,
    /// Bearer Cashu token (`cashuA…`). Parent treats as secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cdk_linked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pong: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    /// Melt fee paid (sats), when ok melt.
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_sats: Option<u64>,
    /// Lightning payment preimage when melt Paid (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_preimage: Option<String>,
}

impl Response {
    fn ok_ping() -> Self {
        Self {
            v: PROTOCOL_V,
            ok: true,
            error: None,
            quote_id: None,
            bolt11: None,
            amount_sats: None,
            token: None,
            cdk_linked: Some(true),
            pong: Some(true),
            state: None,
            fee_sats: None,
            payment_preimage: None,
        }
    }

    fn ok_quote(quote_id: String, bolt11: String, amount_sats: u64) -> Self {
        Self {
            v: PROTOCOL_V,
            ok: true,
            error: None,
            quote_id: Some(quote_id),
            bolt11: Some(bolt11),
            amount_sats: Some(amount_sats),
            token: None,
            cdk_linked: None,
            pong: None,
            state: None,
            fee_sats: None,
            payment_preimage: None,
        }
    }

    fn ok_token(quote_id: String, token: String, amount_sats: u64) -> Self {
        Self {
            v: PROTOCOL_V,
            ok: true,
            error: None,
            quote_id: Some(quote_id),
            bolt11: None,
            amount_sats: Some(amount_sats),
            token: Some(token),
            cdk_linked: None,
            pong: None,
            state: None,
            fee_sats: None,
            payment_preimage: None,
        }
    }

    fn ok_melt(
        quote_id: String,
        amount_sats: u64,
        fee_sats: u64,
        state: String,
        payment_preimage: Option<String>,
    ) -> Self {
        Self {
            v: PROTOCOL_V,
            ok: true,
            error: None,
            quote_id: Some(quote_id),
            bolt11: None,
            amount_sats: Some(amount_sats),
            token: None,
            cdk_linked: None,
            pong: None,
            state: Some(state),
            fee_sats: Some(fee_sats),
            payment_preimage,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_V,
            ok: false,
            error: Some(msg.into()),
            quote_id: None,
            bolt11: None,
            amount_sats: None,
            token: None,
            cdk_linked: None,
            pong: None,
            state: None,
            fee_sats: None,
            payment_preimage: None,
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
    raw.zeroize();

    if req.v != PROTOCOL_V {
        emit(&Response::err(format!(
            "unsupported protocol v={} (want {PROTOCOL_V})",
            req.v
        )));
        return Err(());
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            emit(&Response::err(format!("tokio runtime: {e}")));
            return Err(());
        }
    };

    match req.cmd.as_str() {
        "ping" => {
            emit(&Response::ok_ping());
            Ok(())
        }
        "mint_quote" => rt.block_on(handle_mint_quote(req)),
        "mint_after_paid" => rt.block_on(handle_mint_after_paid(req)),
        "melt_token" => rt.block_on(handle_melt_token(req)),
        other => {
            emit(&Response::err(format!("unknown cmd: {other}")));
            Err(())
        }
    }
}

async fn handle_mint_quote(mut req: Request) -> Result<(), ()> {
    let amount_sats = match req.amount_sats {
        Some(0) | None => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err("amount_sats must be > 0"));
            return Err(());
        }
        Some(a) => a,
    };

    let wallet = match bootstrap_wallet(&mut req).await {
        Ok(w) => w,
        Err(()) => return Err(()),
    };

    let amount = Amount::from(amount_sats);
    let quote = match wallet
        .mint_quote(PaymentMethod::BOLT11, Some(amount), None, None)
        .await
    {
        Ok(q) => q,
        Err(e) => {
            emit(&Response::err(format!("cdk mint_quote failed: {e}")));
            return Err(());
        }
    };

    let bolt11 = quote.request.trim().to_owned();
    if !looks_like_bolt11(&bolt11) {
        emit(&Response::err(
            "cdk mint_quote returned empty/non-bolt11 request (cannot claim invoice; \
             need lnbc…/lntb… HRP, not lnurl)",
        ));
        return Err(());
    }

    emit(&Response::ok_quote(quote.id.clone(), bolt11, amount_sats));
    Ok(())
}

async fn handle_mint_after_paid(mut req: Request) -> Result<(), ()> {
    let quote_id = match req.quote_id.take() {
        Some(s) if !s.trim().is_empty() => s.trim().to_owned(),
        _ => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err("quote_id required for mint_after_paid"));
            return Err(());
        }
    };
    let timeout_secs = req.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS).max(1);
    let poll_secs = req
        .poll_interval_secs
        .unwrap_or(DEFAULT_POLL_INTERVAL_SECS)
        .max(1);

    let wallet = match bootstrap_wallet(&mut req).await {
        Ok(w) => w,
        Err(()) => return Err(()),
    };

    // Recover incomplete sagas (CDK recommendation after re-open).
    if let Err(e) = wallet.recover_incomplete_sagas().await {
        // Non-fatal: continue; mint path will surface real errors.
        let _ = e;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let status = match wallet.check_mint_quote_status(&quote_id).await {
            Ok(q) => q,
            Err(e) => {
                // Quote may not be in localstore if a different helper instance
                // created it without shared storage — try fetch from mint.
                match wallet
                    .fetch_mint_quote(&quote_id, Some(PaymentMethod::BOLT11))
                    .await
                {
                    Ok(q) => q,
                    Err(e2) => {
                        emit(&Response::err(format!(
                            "check/fetch mint quote failed: {e}; fetch: {e2}"
                        )));
                        return Err(());
                    }
                }
            }
        };

        match status.state {
            MintQuoteState::Paid | MintQuoteState::Issued => break,
            MintQuoteState::Unpaid => {
                if tokio::time::Instant::now() >= deadline {
                    emit(&Response::err(format!(
                        "mint quote still unpaid after {timeout_secs}s (quote_id={quote_id})"
                    )));
                    return Err(());
                }
                tokio::time::sleep(Duration::from_secs(poll_secs)).await;
            }
        }
    }

    // Mint proofs for the paid quote (no-op-ish if already issued and stored).
    if let Err(e) = wallet.mint(&quote_id, SplitTarget::default(), None).await {
        // If already issued, proofs may already be in wallet — try send path.
        let msg = format!("{e}");
        if !msg.to_ascii_lowercase().contains("issued")
            && !msg.to_ascii_lowercase().contains("already")
        {
            // Still attempt balance export if mint partial-failed after proofs.
            let balance = wallet.total_balance().await.unwrap_or(Amount::ZERO);
            if balance == Amount::ZERO {
                emit(&Response::err(format!("cdk mint failed: {e}")));
                return Err(());
            }
        }
    }

    let balance = match wallet.total_balance().await {
        Ok(b) => b,
        Err(e) => {
            emit(&Response::err(format!("cdk total_balance: {e}")));
            return Err(());
        }
    };
    if balance == Amount::ZERO {
        emit(&Response::err(
            "cdk mint produced zero balance (quote unpaid or proofs not stored)",
        ));
        return Err(());
    }

    let prepared = match wallet.prepare_send(balance, SendOptions::default()).await {
        Ok(p) => p,
        Err(e) => {
            emit(&Response::err(format!("cdk prepare_send: {e}")));
            return Err(());
        }
    };
    let token = match prepared.confirm(None).await {
        Ok(t) => t,
        Err(e) => {
            emit(&Response::err(format!("cdk send confirm: {e}")));
            return Err(());
        }
    };

    let token_s = token.to_string();
    let trimmed = token_s.trim();
    if !(trimmed.starts_with("cashuA") || trimmed.starts_with("cashuB")) {
        emit(&Response::err(format!(
            "cdk token encode did not produce cashuA/cashuB prefix (got {}…)",
            trimmed.chars().take(12).collect::<String>()
        )));
        return Err(());
    }
    if trimmed.len() < 16 {
        emit(&Response::err("cdk token too short to be redeemable"));
        return Err(());
    }

    let amount_sats = u64::from(balance);
    emit(&Response::ok_token(
        quote_id,
        trimmed.to_owned(),
        amount_sats,
    ));
    Ok(())
}

/// Melt a bearer Cashu token to a destination BOLT11 (NUT-05).
///
/// Success **only** when CDK reports [`MeltQuoteState::Paid`]. Pending / Failed /
/// Unpaid never emit ok=true (no invented Success).
async fn handle_melt_token(mut req: Request) -> Result<(), ()> {
    let mut token = match req.token.take() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            zeroize_request_secrets(&mut req);
            emit(&Response::err(
                "token required for melt_token (cashuA…/cashuB…)",
            ));
            return Err(());
        }
    };
    let bolt11 = match req.bolt11.take() {
        Some(s) if !s.trim().is_empty() => s.trim().to_owned(),
        _ => {
            token.zeroize();
            zeroize_request_secrets(&mut req);
            emit(&Response::err(
                "bolt11 required for melt_token (destination invoice)",
            ));
            return Err(());
        }
    };
    if !looks_like_bolt11(&bolt11) {
        token.zeroize();
        zeroize_request_secrets(&mut req);
        emit(&Response::err(
            "bolt11 failed looks_like_bolt11 (need lnbc…/lntb… HRP, not lnurl)",
        ));
        return Err(());
    }
    let token_trim = token.trim().to_owned();
    token.zeroize();
    if !(token_trim.starts_with("cashuA") || token_trim.starts_with("cashuB")) {
        let mut t = token_trim;
        t.zeroize();
        zeroize_request_secrets(&mut req);
        emit(&Response::err("token must start with cashuA or cashuB"));
        return Err(());
    }
    if token_trim.len() < 16 {
        let mut t = token_trim;
        t.zeroize();
        zeroize_request_secrets(&mut req);
        emit(&Response::err("token too short to be melt-able"));
        return Err(());
    }

    let wallet = match bootstrap_wallet(&mut req).await {
        Ok(w) => w,
        Err(()) => {
            let mut t = token_trim;
            t.zeroize();
            return Err(());
        }
    };

    // Recover incomplete melt sagas if any (non-fatal).
    if let Err(e) = wallet.recover_incomplete_sagas().await {
        let _ = e;
    }

    let quote = match wallet
        .melt_quote(PaymentMethod::BOLT11, bolt11.as_str(), None, None)
        .await
    {
        Ok(q) => q,
        Err(e) => {
            let mut t = token_trim;
            t.zeroize();
            emit(&Response::err(format!("cdk melt_quote failed: {e}")));
            return Err(());
        }
    };

    let prepared = match wallet
        .prepare_melt_token(&quote.id, &token_trim, HashMap::new())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            let mut t = token_trim;
            t.zeroize();
            emit(&Response::err(format!(
                "cdk prepare_melt_token failed: {e}"
            )));
            return Err(());
        }
    };
    // Token material no longer needed after prepare (proofs reserved in wallet).
    let mut t = token_trim;
    t.zeroize();

    let finalized = match prepared.confirm().await {
        Ok(f) => f,
        Err(e) => {
            emit(&Response::err(format!("cdk melt confirm failed: {e}")));
            return Err(());
        }
    };

    match finalized.state() {
        MeltQuoteState::Paid => {
            let amount_sats = u64::from(finalized.amount());
            let fee_sats = u64::from(finalized.fee_paid());
            let preimage = finalized.payment_proof().map(|s| s.to_owned());
            emit(&Response::ok_melt(
                finalized.quote_id().to_owned(),
                amount_sats,
                fee_sats,
                "PAID".into(),
                preimage,
            ));
            Ok(())
        }
        other => {
            emit(&Response::err(format!(
                "cdk melt not Paid (state={other}; quote_id={})",
                finalized.quote_id()
            )));
            Err(())
        }
    }
}

/// Build CDK wallet from BIP-39 + absolute storage_dir. Zeroizes secrets.
async fn bootstrap_wallet(req: &mut Request) -> Result<Wallet, ()> {
    let mut mnemonic_s = match req.mnemonic.take() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            zeroize_request_secrets(req);
            emit(&Response::err("missing mnemonic"));
            return Err(());
        }
    };
    let mut passphrase_s = req.passphrase.take().unwrap_or_default();

    let mint_url = match req
        .mint_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(u) => u.to_owned(),
        None => {
            mnemonic_s.zeroize();
            passphrase_s.zeroize();
            zeroize_request_secrets(req);
            emit(&Response::err("mint_url required"));
            return Err(());
        }
    };
    let lower = mint_url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        mnemonic_s.zeroize();
        passphrase_s.zeroize();
        zeroize_request_secrets(req);
        emit(&Response::err(
            "mint_url must start with https:// or http://",
        ));
        return Err(());
    }

    let storage_dir = match req.storage_dir.take() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            mnemonic_s.zeroize();
            passphrase_s.zeroize();
            zeroize_request_secrets(req);
            emit(&Response::err(
                "storage_dir required (absolute path; parent scopes under grok home)",
            ));
            return Err(());
        }
    };
    let storage_path = PathBuf::from(&storage_dir);
    if !storage_path.is_absolute() {
        mnemonic_s.zeroize();
        passphrase_s.zeroize();
        zeroize_request_secrets(req);
        emit(&Response::err(format!(
            "storage_dir must be absolute (got relative: {storage_dir})"
        )));
        return Err(());
    }
    if let Err(e) = std::fs::create_dir_all(Path::new(&storage_path)) {
        mnemonic_s.zeroize();
        passphrase_s.zeroize();
        zeroize_request_secrets(req);
        emit(&Response::err(format!("create storage_dir: {e}")));
        return Err(());
    }

    let mnemonic = match Mnemonic::parse_normalized(mnemonic_s.trim()) {
        Ok(m) => m,
        Err(e) => {
            mnemonic_s.zeroize();
            passphrase_s.zeroize();
            zeroize_request_secrets(req);
            emit(&Response::err(format!("invalid mnemonic: {e}")));
            return Err(());
        }
    };
    mnemonic_s.zeroize();

    // BIP-39 seed (64 bytes). Zeroize intermediate passphrase after use.
    let seed_arr = mnemonic.to_seed(passphrase_s.as_str());
    passphrase_s.zeroize();
    zeroize_request_secrets(req);

    let db_path = storage_path.join("cdk-wallet.sqlite");
    let localstore = match cdk_sqlite::WalletSqliteDatabase::new(db_path).await {
        Ok(db) => Arc::new(db),
        Err(e) => {
            let mut seed_arr = seed_arr;
            seed_arr.zeroize();
            emit(&Response::err(format!("cdk-sqlite open: {e}")));
            return Err(());
        }
    };

    let wallet = match Wallet::new(
        mint_url.trim_end_matches('/'),
        CurrencyUnit::Sat,
        localstore,
        seed_arr,
        None,
    ) {
        Ok(w) => w,
        Err(e) => {
            // seed consumed by Wallet::new on success; on Err seed may still be live
            // inside builder drop path (cdk zeroizes builder seed on Drop).
            emit(&Response::err(format!("cdk Wallet::new: {e}")));
            return Err(());
        }
    };

    Ok(wallet)
}

fn zeroize_request_secrets(req: &mut Request) {
    if let Some(ref mut s) = req.mnemonic {
        s.zeroize();
    }
    if let Some(ref mut s) = req.passphrase {
        s.zeroize();
    }
    if let Some(ref mut s) = req.token {
        s.zeroize();
    }
}

fn emit(resp: &Response) {
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
        assert!(s.contains("cdk_linked"));
        assert!(!s.contains("mnemonic"));
        assert!(!s.contains("token"));
    }

    #[test]
    fn protocol_quote_shape() {
        let s = serde_json::to_string(&Response::ok_quote("q-1".into(), "lnbc1test".into(), 1000))
            .unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("q-1"));
        assert!(s.contains("lnbc1test"));
        assert!(s.contains("\"amount_sats\":1000"));
        assert!(!s.contains("token"));
        assert!(!s.contains("mnemonic"));
    }

    #[test]
    fn protocol_token_shape() {
        let s = serde_json::to_string(&Response::ok_token(
            "q-1".into(),
            "cashuAabcdefghijklmnopqrstuvwxyz".into(),
            21,
        ))
        .unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("cashuA"));
        assert!(s.contains("\"amount_sats\":21"));
        assert!(!s.contains("mnemonic"));
    }

    #[test]
    fn mint_quote_request_deserializes() {
        let r: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"mint_quote","mint_url":"https://mint.example/","amount_sats":50,"mnemonic":"x","storage_dir":"/tmp/x"}"#,
        )
        .unwrap();
        assert_eq!(r.cmd, "mint_quote");
        assert_eq!(r.amount_sats, Some(50));
        assert_eq!(r.mint_url.as_deref(), Some("https://mint.example/"));
    }

    #[test]
    fn mint_after_paid_request_deserializes() {
        let r: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"mint_after_paid","mint_url":"https://m/","quote_id":"abc","mnemonic":"x","storage_dir":"/tmp/x","timeout_secs":30}"#,
        )
        .unwrap();
        assert_eq!(r.cmd, "mint_after_paid");
        assert_eq!(r.quote_id.as_deref(), Some("abc"));
        assert_eq!(r.timeout_secs, Some(30));
    }

    #[test]
    fn request_has_no_debug_impl() {
        trait AssertNotDebug {}
        impl AssertNotDebug for Request {}
        impl<T: std::fmt::Debug + ?Sized> AssertNotDebug for T {}

        fn _needs_assert_not_debug<T: AssertNotDebug>() {}
        _needs_assert_not_debug::<Request>();
        let _ = std::mem::size_of::<Request>();
    }

    #[test]
    fn absolute_storage_required_docs() {
        assert!(!PathBuf::from("cdk-wallet").is_absolute());
        assert!(PathBuf::from("/tmp/cdk-wallet").is_absolute());
    }

    #[test]
    fn looks_like_bolt11_matches_wallet_hrp_allowlist() {
        assert!(looks_like_bolt11("lnbc10u1abc"));
        assert!(looks_like_bolt11("lntb1u1abc"));
        assert!(looks_like_bolt11("LNBC1XYZ"));
        assert!(!looks_like_bolt11("lnurl1dp68gurn8ghj7"));
        assert!(!looks_like_bolt11("lnxyz1fake"));
        assert!(!looks_like_bolt11(""));
        assert!(!looks_like_bolt11("http://not-an-invoice"));
    }

    #[test]
    fn request_drop_zeroizes_secrets() {
        let r: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"ping","mnemonic":"secret phrase here","passphrase":"pp"}"#,
        )
        .unwrap();
        assert_eq!(r.mnemonic.as_deref(), Some("secret phrase here"));
        drop(r);
        // Explicit zeroize: contents must no longer expose the secret phrase.
        let mut r2: Request =
            serde_json::from_str(r#"{"v":1,"cmd":"ping","mnemonic":"abc","passphrase":"x"}"#)
                .unwrap();
        zeroize_request_secrets(&mut r2);
        let m = r2.mnemonic.as_deref().unwrap_or("");
        let p = r2.passphrase.as_deref().unwrap_or("");
        assert!(!m.contains("abc"), "mnemonic still visible: {m:?}");
        assert!(!p.contains('x'), "passphrase still visible: {p:?}");
    }

    #[test]
    fn melt_token_request_deserializes() {
        let r: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"melt_token","mint_url":"https://m/","token":"cashuAabcdefghijklmnopqrst","bolt11":"lnbc1x","mnemonic":"x","storage_dir":"/tmp/x"}"#,
        )
        .unwrap();
        assert_eq!(r.cmd, "melt_token");
        assert_eq!(r.token.as_deref(), Some("cashuAabcdefghijklmnopqrst"));
        assert_eq!(r.bolt11.as_deref(), Some("lnbc1x"));
    }

    #[test]
    fn protocol_melt_paid_shape() {
        let s = serde_json::to_string(&Response::ok_melt(
            "mq-1".into(),
            1000,
            2,
            "PAID".into(),
            Some("preimage-hex".into()),
        ))
        .unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"state\":\"PAID\""));
        assert!(s.contains("\"amount_sats\":1000"));
        assert!(s.contains("\"fee_sats\":2"));
        assert!(s.contains("mq-1"));
        assert!(s.contains("preimage-hex"));
        assert!(!s.contains("mnemonic"));
        // Melt success must not echo bearer token material.
        assert!(!s.contains("cashuA"));
    }

    #[test]
    fn request_zeroizes_melt_token_secret() {
        let mut r: Request = serde_json::from_str(
            r#"{"v":1,"cmd":"melt_token","token":"cashuAsecretmaterialxyz","bolt11":"lnbc1x"}"#,
        )
        .unwrap();
        assert!(r.token.as_deref().unwrap_or("").contains("secretmaterial"));
        zeroize_request_secrets(&mut r);
        let t = r.token.as_deref().unwrap_or("");
        assert!(
            !t.contains("secretmaterial"),
            "token still visible after zeroize: {t:?}"
        );
    }
}
