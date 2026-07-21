//! Cashu (Chaumian eCash) token newtype + funding wizard state machine.
//!
//! NUT-04 mint **quote** is live under feature `cashu-cdk` when a mint URL is
//! set. Full proofs→`cashuA` mint uses the isolated `grok-bitcoin-cdk-mint`
//! helper (approach B; cdk-sqlite rusqlite 0.31 isolation). Melt/spend live under
//! helper melt IPC when URL + helper resolvable. Redeem `cashuA…` via live
//! Routstr `balance/create|topup`.
//!
//! This module provides safe types, pure NUT-04 parsers, the funding wizard,
//! and honest [`CashuBackend`] capability seams so stubs never claim a live
//! mint invoice, token, or completed refund.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};

use crate::error::{Result, WalletError};

/// Capability flags for a Cashu backend (CDK mint/wallet when live).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CashuCapabilities {
    /// Can request a mint quote / BOLT11 to acquire Cashu tokens.
    pub mint_live: bool,
    /// Can complete a **paid** mint quote → proofs → `cashuA…` token
    /// (isolated CDK helper under feature `cashu-cdk`). Token ≠ Routstr float
    /// until redeem succeeds.
    pub proofs_mint_live: bool,
    /// Can spend Cashu tokens against a Routstr (or other) mint / melt path.
    pub spend_live: bool,
    /// Can return / melt Cashu back to Lightning or on-chain.
    pub refund_live: bool,
}

/// Pre-CDK stub: nothing live.
pub const STUB_CASHU_CAPABILITIES: CashuCapabilities = CashuCapabilities {
    mint_live: false,
    proofs_mint_live: false,
    spend_live: false,
    refund_live: false,
};

/// Product path for Cashu mint → proofs → redeem (not Routstr float until redeem).
///
/// Pure decision from [`CashuCapabilities`] — no network, no seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CashuMintProductPath {
    /// `proofs_mint_live`: SeedVault quote → pay mint BOLT11 → proofs → redeem.
    LiveProofs,
    /// `mint_live` only (quote HTTP/helper possible; proofs helper not linked).
    QuoteOnly,
    /// Stub / no mint URL — fall through to P0 Routstr invoice-first topup.
    Residual,
}

/// Decide product Cashu mint path from capability flags (offline-pure).
pub fn decide_cashu_mint_product_path(caps: CashuCapabilities) -> CashuMintProductPath {
    if caps.proofs_mint_live {
        CashuMintProductPath::LiveProofs
    } else if caps.mint_live {
        CashuMintProductPath::QuoteOnly
    } else {
        CashuMintProductPath::Residual
    }
}

/// Honest residual lines when Cashu mint product path is not fully live.
///
/// Always points at P0 `grok routstr topup` for Routstr float. Never fabricates
/// a mint invoice or claims float credit.
pub fn cashu_mint_residual_lines(sats: Option<u64>, path: CashuMintProductPath) -> Vec<String> {
    let mut lines = match path {
        CashuMintProductPath::Residual => vec![
            "Cashu mint path is not live on this build \
             (need feature `cashu-cdk` + GROK_BITCOIN_CASHU_MINT_URL + \
             resolvable grok-bitcoin-cdk-mint helper)."
                .to_owned(),
        ],
        CashuMintProductPath::QuoteOnly => vec![
            "Cashu mint quote is available, but proofs mint is not live \
             (build/install grok-bitcoin-cdk-mint and set GROK_BITCOIN_CDK_MINT_BIN)."
                .to_owned(),
            "Without the helper, a paid mint quote does not yield a cashuA… token here.".to_owned(),
        ],
        CashuMintProductPath::LiveProofs => vec![
            // Caller should not use residual lines when live; keep honest fallback.
            "Cashu proofs mint reported live but product fell through (see detail above)."
                .to_owned(),
        ],
    };
    if let Some(s) = sats {
        lines.push(format!("Requested amount: {s} sats."));
    }
    lines.push("Falling through to P0 Routstr invoice-first funding for prepaid float.".to_owned());
    lines
        .push("Use `grok routstr topup` (or /routstr topup) for a Routstr node BOLT11.".to_owned());
    lines.push(
        "When you already have a cashuA… token, redeem with `grok routstr redeem` \
         (float only after redeem succeeds)."
            .to_owned(),
    );
    lines
}

/// User-facing lines after a live mint quote (NUT-04). Never claims Routstr float.
pub fn cashu_mint_quote_display_lines(
    bolt11: &str,
    quote_id: &str,
    amount_sats: Option<u64>,
) -> Vec<String> {
    let mut lines = vec![
        "Cashu mint quote invoice (NUT-04) — pays the mint only, not Routstr float.".to_owned(),
        format!("Quote id: {quote_id}"),
        format!("BOLT11: {bolt11}"),
    ];
    if let Some(s) = amount_sats {
        lines.insert(1, format!("Amount: {s} sats."));
    }
    lines
        .push("Pay this BOLT11 with any Lightning wallet (or local LDK pay when live).".to_owned());
    lines.push(
        "After pay: complete proofs mint (CLI: `grok routstr mint --complete <quote_id>`; \
         TUI: re-run /routstr unlock) to obtain a cashuA… token."
            .to_owned(),
    );
    lines.push(
        "Token ≠ Routstr float until `grok routstr redeem` (or auto-redeem) succeeds.".to_owned(),
    );
    lines
}

/// User-facing lines after proofs mint success — still not float until redeem.
pub fn cashu_mint_token_obtained_lines(
    amount_sats: u64,
    quote_id: &str,
    redacted: &str,
) -> Vec<String> {
    vec![
        "Cashu proofs mint produced a redeemable token (not Routstr float yet).".to_owned(),
        format!("Quote id: {quote_id}"),
        format!("Amount: {amount_sats} sats."),
        format!("Token (redacted): {redacted}"),
        "Redeem via Routstr balance/create|topup to credit prepaid float.".to_owned(),
    ]
}

/// User-facing lines after redeem succeeds — only then claim float.
pub fn cashu_mint_float_credited_lines(amount_sats: Option<u64>) -> Vec<String> {
    let mut lines = vec![
        "Routstr prepaid float credited after Cashu redeem succeeded.".to_owned(),
        "Select Routstr Grok 4.5 in the model picker when ready (model is never auto-switched)."
            .to_owned(),
        "Run `grok routstr balance` (or /routstr balance) to confirm float.".to_owned(),
    ];
    if let Some(s) = amount_sats {
        lines.insert(1, format!("Minted amount (mint side): {s} sats."));
    }
    lines
}

/// Product path for local Cashu melt (token → destination BOLT11).
///
/// Pure decision from [`CashuCapabilities`] — no network, no seed.
/// Melt spends Cashu proofs to Lightning; it does **not** credit Routstr float.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CashuMeltProductPath {
    /// `spend_live` / `refund_live`: SeedVault + helper IPC melt (Paid only).
    LiveMelt,
    /// Stub / helper missing — fall through to node `grok routstr refund` (sk- float).
    Residual,
}

/// Decide product Cashu melt path from capability flags (offline-pure).
///
/// Live when either `spend_live` or `refund_live` (same helper gate today).
pub fn decide_cashu_melt_product_path(caps: CashuCapabilities) -> CashuMeltProductPath {
    if caps.spend_live || caps.refund_live {
        CashuMeltProductPath::LiveMelt
    } else {
        CashuMeltProductPath::Residual
    }
}

/// Honest residual lines when local CDK melt is not live.
///
/// Points at node float refund (`grok routstr refund` without token). Never
/// claims melt PAID or Routstr float credit.
///
/// Product guidance: when the user already holds `cashuA…`, prefer melt/spend
/// Cashu over parking large balances as hot `sk-` float; node refund remains
/// the path for existing prepaid float.
pub fn cashu_melt_residual_lines() -> Vec<String> {
    vec![
        "Local Cashu melt (token → BOLT11) is not live on this build \
         (need feature `cashu-cdk` + GROK_BITCOIN_CASHU_MINT_URL + \
         resolvable grok-bitcoin-cdk-mint helper)."
            .to_owned(),
        "Falling through to residual / node refund path.".to_owned(),
        "Prefer spending / melting cashuA… you already hold over leaving large \
         hot sk- float on the node."
            .to_owned(),
        "For Routstr prepaid float (sk-): `grok routstr refund` (POST /v1/balance/refund) \
         returns a Cashu token once when the node succeeds."
            .to_owned(),
        "When melt is live: `grok routstr refund --token <cashuA…> --invoice <BOLT11>` \
         (or TUI `/routstr refund token=… invoice=…`) melts via SeedVault — \
         never credits sk- float."
            .to_owned(),
        "Run `grok routstr balance` (or /routstr balance) to check remaining float.".to_owned(),
    ]
}

/// User-facing lines after melt IPC reports Paid. Never claims Routstr float.
pub fn cashu_melt_paid_lines(detail: &str) -> Vec<String> {
    let mut lines = vec![
        "Cashu melt completed (token spent to destination BOLT11; state=PAID).".to_owned(),
        "This is not Routstr prepaid float credit (melt spends Cashu; no sk- float claim)."
            .to_owned(),
        "Prefer melting/spending cashuA… you hold over parking large hot sk- float.".to_owned(),
    ];
    let d = detail.trim();
    if !d.is_empty() {
        lines.push(format!("Detail: {d}"));
    }
    lines.push(
        "Node hot float is unchanged by local melt. Use `grok routstr balance` for sk- float."
            .to_owned(),
    );
    lines
}

/// User-facing lines when melt was **offered/live** but failed / cancelled.
///
/// Does **not** claim "not live" — capability was available; the attempt failed.
/// Never claims Routstr float. For true not-live residual, use
/// [`cashu_melt_residual_lines`] instead.
pub fn cashu_melt_failed_lines(detail: &str) -> Vec<String> {
    let mut lines = vec![
        "Cashu melt did not complete.".to_owned(),
        "No Routstr float was credited or claimed.".to_owned(),
    ];
    let d = detail.trim();
    if !d.is_empty() {
        lines.push(format!("Detail: {d}"));
    }
    lines.push(
        "Retry: `grok routstr refund --token <cashuA…> --invoice <BOLT11>` \
         (or TUI `/routstr refund token=… invoice=…`) after fixing the detail above."
            .to_owned(),
    );
    lines.push(
        "For Routstr prepaid float (sk-): bare `grok routstr refund` \
         (POST /v1/balance/refund) — separate from local melt."
            .to_owned(),
    );
    lines.push(
        "Run `grok routstr balance` (or /routstr balance) to check remaining float.".to_owned(),
    );
    lines
}

/// Outcome of requesting a Cashu mint (top-up) invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintQuoteOutcome {
    /// Live mint quote with a real BOLT11 (only when `mint_live`).
    Invoice {
        bolt11: String,
        quote_id: String,
    },
    /// Backend cannot mint in this build.
    Unsupported(&'static str),
    Failed(String),
}

/// Outcome of a Cashu refund / melt attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CashuRefundOutcome {
    /// Live refund completed (only when `refund_live`).
    Completed {
        detail: String,
    },
    Unsupported(&'static str),
    Failed(String),
}

/// Outcome of completing a paid NUT-04 quote → proofs → redeemable token.
///
/// [`MintProofsOutcome::Token`] is **not** Routstr float credit — redeem via
/// `grok routstr redeem` / live `balance/create|topup`.
///
/// **Debug redacts** the bearer `token` (never dump full `cashuA…` via `{:?}`).
#[derive(Clone, PartialEq, Eq)]
pub enum MintProofsOutcome {
    /// Real `cashuA…` / `cashuB…` suitable for Routstr redeem (only when
    /// `proofs_mint_live` and transport succeeds).
    Token {
        token: String,
        amount_sats: u64,
        quote_id: String,
    },
    Unsupported(&'static str),
    Failed(String),
}

impl fmt::Debug for MintProofsOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token {
                token,
                amount_sats,
                quote_id,
            } => {
                let redacted = CashuToken::parse(token)
                    .map(|t| t.redacted())
                    .unwrap_or_else(|_| "cashuA…[REDACTED]".to_owned());
                f.debug_struct("Token")
                    .field("token", &redacted)
                    .field("amount_sats", amount_sats)
                    .field("quote_id", quote_id)
                    .finish()
            }
            Self::Unsupported(s) => f.debug_tuple("Unsupported").field(s).finish(),
            Self::Failed(s) => f.debug_tuple("Failed").field(s).finish(),
        }
    }
}

/// Cashu mint/spend/refund surface for Routstr top up / refund product paths.
///
/// Stubs **must** report false capability flags and return
/// [`MintQuoteOutcome::Unsupported`] / [`CashuRefundOutcome::Unsupported`] /
/// [`MintProofsOutcome::Unsupported`].
pub trait CashuBackend {
    fn capabilities(&self) -> CashuCapabilities {
        STUB_CASHU_CAPABILITIES
    }

    /// Request a mint invoice for approximately `amount_sats`.
    ///
    /// Must not return a fabricated `lnbc…` string when `mint_live` is false.
    fn request_mint_invoice(&self, amount_sats: Option<u64>) -> Result<MintQuoteOutcome>;

    /// After the mint quote BOLT11 is paid: mint proofs → `cashuA…` token.
    ///
    /// Default: unsupported. Live only when `proofs_mint_live` (CDK helper).
    /// Must not fabricate a token string.
    fn complete_mint_after_pay(&self, _quote_id: &str) -> Result<MintProofsOutcome> {
        Ok(MintProofsOutcome::Unsupported(
            "CDK proofs mint not wired (stub or no seed; use complete_mint_after_pay_with_seed)",
        ))
    }

    /// Seed-aware proofs mint (BIP-39 → isolated `grok-bitcoin-cdk-mint` helper).
    ///
    /// Default: unsupported. Same seed + passphrase + storage must have created
    /// the quote when using the CDK helper (NUT-20 signing continuity). Prefer
    /// [`Self::request_mint_invoice_with_seed`] for the quote step so helper
    /// localstore stays continuous.
    fn complete_mint_after_pay_with_seed(
        &self,
        _quote_id: &str,
        _mnemonic: &crate::mnemonic::MnemonicSecret,
        _passphrase: &str,
    ) -> Result<MintProofsOutcome> {
        Ok(MintProofsOutcome::Unsupported(
            "CDK proofs mint with seed not wired on this backend",
        ))
    }

    /// Seed-aware mint **quote** (prefer CDK helper when `proofs_mint_live` so
    /// quote + mint share localstore / NUT-20 keys).
    ///
    /// Default: falls through to [`Self::request_mint_invoice`] (HTTP-only path;
    /// open-mint best-effort if proofs mint later uses a different store).
    fn request_mint_invoice_with_seed(
        &self,
        amount_sats: Option<u64>,
        _mnemonic: &crate::mnemonic::MnemonicSecret,
        _passphrase: &str,
    ) -> Result<MintQuoteOutcome> {
        self.request_mint_invoice(amount_sats)
    }

    /// Attempt to refund / melt held Cashu balance.
    ///
    /// When `refund_live`, bare call without token context should return
    /// [`CashuRefundOutcome::Failed`] explaining how to call
    /// [`Self::melt_token_to_bolt11_with_seed`] — never invent Completed.
    fn refund(&self) -> Result<CashuRefundOutcome>;

    /// Melt a bearer `cashuA…` token to a destination BOLT11 (NUT-05 via CDK helper).
    ///
    /// Default: unsupported. Live when `spend_live`/`refund_live` (helper linked).
    /// Must not invent Completed — only from helper IPC Paid.
    fn melt_token_to_bolt11_with_seed(
        &self,
        _token: &str,
        _bolt11: &str,
        _mnemonic: &crate::mnemonic::MnemonicSecret,
        _passphrase: &str,
    ) -> Result<CashuRefundOutcome> {
        Ok(CashuRefundOutcome::Unsupported(
            "CDK melt with seed not wired on this backend",
        ))
    }
}

/// Pre-CDK Cashu backend: honest unsupported outcomes only.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubCashu;

impl CashuBackend for StubCashu {
    fn capabilities(&self) -> CashuCapabilities {
        STUB_CASHU_CAPABILITIES
    }

    fn request_mint_invoice(&self, _amount_sats: Option<u64>) -> Result<MintQuoteOutcome> {
        Ok(MintQuoteOutcome::Unsupported(
            "CDK mint path not wired (stub CashuBackend)",
        ))
    }

    fn refund(&self) -> Result<CashuRefundOutcome> {
        Ok(CashuRefundOutcome::Unsupported(
            "CDK refund / melt path not wired (stub CashuBackend)",
        ))
    }
}

/// Product default Cashu backend for top up / refund CLI+TUI paths.
///
/// - **Default features / CI:** [`StubCashu`] (all live flags false).
/// - **Feature `cashu-cdk`:** [`Nut04MintCashu`] product default with
///   **`mint_live=true`** when env `GROK_BITCOIN_CASHU_MINT_URL` is set
///   (env-only; does **not** auto-fetch Routstr `/v1/info` mints — inject via
///   [`Nut04MintCashu::new`] if desired). **`proofs_mint_live=true`** when mint
///   URL is set **and** the CDK helper transport is linked (process IPC to
///   `grok-bitcoin-cdk-mint`). **`spend_live` / `refund_live`** true under the
///   same helper gate (melt IPC `melt_token`); bare `refund()` needs
///   token+bolt11+seed via [`CashuBackend::melt_token_to_bolt11_with_seed`].
///   Missing URL / HTTP / expired / amount-mismatch → honest
///   [`MintQuoteOutcome::Failed`] (never fabricated bolt11). Token only from
///   helper IPC after paid quote (never fabricated).
///
/// Product copy routes through [`crate::funding_cli::topup_next_steps_for_backends`].
/// NUT-04 quote pay alone does **not** credit Routstr float. A real `cashuA…`
/// from proofs mint is redeemable via Routstr `balance/create|topup` / `grok
/// routstr redeem` — float only after redeem succeeds.
pub fn default_cashu_backend() -> impl CashuBackend {
    #[cfg(feature = "cashu-cdk")]
    {
        Nut04MintCashu::product_default()
    }
    #[cfg(not(feature = "cashu-cdk"))]
    {
        StubCashu
    }
}

// ---------------------------------------------------------------------------
// NUT-04 mint quote (pure parse + optional live HTTP under feature cashu-cdk)
// ---------------------------------------------------------------------------

/// Env: Cashu mint base URL for NUT-04 mint quotes (feature `cashu-cdk`).
pub const CASHU_MINT_URL_ENV: &str = "GROK_BITCOIN_CASHU_MINT_URL";

/// Validate a mint base URL (https preferred; http allowed for onion/local).
pub fn validate_mint_url(url: &str) -> std::result::Result<&str, String> {
    let u = url.trim().trim_end_matches('/');
    if u.is_empty() {
        return Err("mint URL must not be empty".into());
    }
    let lower = u.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err("mint URL must start with https:// or http://".into());
    }
    if u.len() > 512 {
        return Err("mint URL too long".into());
    }
    Ok(u)
}

/// Build NUT-04 `POST {mint}/v1/mint/quote/bolt11` request JSON.
pub fn mint_quote_bolt11_request_json(
    amount_sats: u64,
    unit: &str,
) -> std::result::Result<String, String> {
    if amount_sats == 0 {
        return Err("mint quote amount_sats must be > 0".into());
    }
    let unit = unit.trim();
    if unit.is_empty() {
        return Err("mint quote unit must not be empty".into());
    }
    // NUT-04 body: { "amount": <sats>, "unit": "sat" }
    #[derive(serde::Serialize)]
    struct Body<'a> {
        amount: u64,
        unit: &'a str,
    }
    serde_json::to_string(&Body {
        amount: amount_sats,
        unit,
    })
    .map_err(|e| format!("serialize mint quote request: {e}"))
}

/// Path suffix for NUT-04 BOLT11 mint quote (append to mint base URL).
pub const CASHU_MINT_QUOTE_BOLT11_PATH: &str = "/v1/mint/quote/bolt11";

/// Join mint base + NUT-04 path (no double slash).
pub fn mint_quote_bolt11_url(mint_base: &str) -> std::result::Result<String, String> {
    let base = validate_mint_url(mint_base)?;
    Ok(format!("{base}{CASHU_MINT_QUOTE_BOLT11_PATH}"))
}

/// Parsed NUT-04 mint quote response (flexible field names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintQuoteBolt11Response {
    pub quote_id: String,
    pub bolt11: String,
    pub amount_sats: Option<u64>,
    pub unit: Option<String>,
    pub expiry: Option<i64>,
    pub state: Option<String>,
}

/// Parse NUT-04 mint quote JSON. Requires non-empty quote id + BOLT11 request.
///
/// Does **not** check expiry/state/amount match — use
/// [`validate_mint_quote_for_invoice`] before claiming
/// [`MintQuoteOutcome::Invoice`].
pub fn parse_mint_quote_bolt11_response(
    body: &str,
) -> std::result::Result<MintQuoteBolt11Response, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("mint quote JSON: {e}"))?;
    let quote_id = v
        .get("quote")
        .or_else(|| v.get("quote_id"))
        .or_else(|| v.get("quoteId"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "mint quote: missing quote id".to_string())?
        .to_owned();
    let bolt11 = v
        .get("request")
        .or_else(|| v.get("bolt11"))
        .or_else(|| v.get("invoice"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "mint quote: missing bolt11/request".to_string())?
        .to_owned();
    if !crate::routstr_invoice::looks_like_bolt11(&bolt11) {
        return Err("mint quote: request is not a bolt11 (lnbc…/lntb…; not lnurl)".into());
    }
    let amount_sats = v
        .get("amount")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("amount_sats").and_then(|x| x.as_u64()));
    let unit = v
        .get("unit")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let expiry = v.get("expiry").and_then(|x| {
        x.as_i64()
            .or_else(|| x.as_u64().and_then(|u| i64::try_from(u).ok()))
    });
    let state = v
        .get("state")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    Ok(MintQuoteBolt11Response {
        quote_id,
        bolt11,
        amount_sats,
        unit,
        expiry,
        state,
    })
}

/// Validate a parsed NUT-04 quote before claiming a pay-ready invoice.
///
/// - BOLT11 HRP honesty ([`crate::routstr_invoice::looks_like_bolt11`])
/// - non-empty quote id
/// - if `expiry` present and `now_unix >= expiry` → expired
/// - if `state` is terminal (`EXPIRED` / `PAID` / `ISSUED`) → reject
/// - if mint returns `amount_sats` and it ≠ `requested_amount_sats` → reject
///
/// Mints that omit amount/expiry/state remain allowed (amount-optional).
pub fn validate_mint_quote_for_invoice(
    q: &MintQuoteBolt11Response,
    requested_amount_sats: u64,
    now_unix: i64,
) -> std::result::Result<(), String> {
    let bolt11 = q.bolt11.trim();
    if bolt11.is_empty() || !crate::routstr_invoice::looks_like_bolt11(bolt11) {
        return Err("mint quote: invalid bolt11 (cannot claim Invoice)".into());
    }
    if q.quote_id.trim().is_empty() {
        return Err("mint quote: empty quote id".into());
    }
    if let Some(exp) = q.expiry {
        if now_unix >= exp {
            return Err(format!("mint quote expired (expiry={exp}, now={now_unix})"));
        }
    }
    if let Some(ref st) = q.state {
        let upper = st.trim().to_ascii_uppercase();
        match upper.as_str() {
            "EXPIRED" | "PAID" | "ISSUED" => {
                return Err(format!("mint quote not payable (state={st})"));
            }
            // UNPAID / PENDING / unknown — allow if expiry ok
            _ => {}
        }
    }
    if let Some(a) = q.amount_sats {
        if a != requested_amount_sats {
            return Err(format!(
                "mint quote amount mismatch: requested {requested_amount_sats} sats, \
                 mint returned {a}"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NUT-04 mint quote **state** check + mint proofs response (pure parsers)
// ---------------------------------------------------------------------------

/// Path for NUT-04 GET mint quote state: `/v1/mint/quote/bolt11/{quote_id}`.
pub fn mint_quote_bolt11_status_url(
    mint_base: &str,
    quote_id: &str,
) -> std::result::Result<String, String> {
    let base = validate_mint_url(mint_base)?;
    let q = quote_id.trim();
    if q.is_empty() {
        return Err("quote_id must not be empty".into());
    }
    // Reject path traversal in quote ids.
    if q.contains('/') || q.contains("..") || q.contains('\\') {
        return Err("quote_id contains invalid path characters".into());
    }
    Ok(format!("{base}/v1/mint/quote/bolt11/{q}"))
}

/// NUT-04 mint quote state after check (GET status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintQuoteStateResponse {
    pub quote_id: String,
    pub state: String,
    pub amount_sats: Option<u64>,
    pub expiry: Option<i64>,
    /// Optional bolt11 still present on some mint responses.
    pub bolt11: Option<String>,
}

/// Parse NUT-04 mint quote **status** JSON (paid/unpaid/issued/expired).
pub fn parse_mint_quote_state_response(
    body: &str,
) -> std::result::Result<MintQuoteStateResponse, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("mint quote state JSON: {e}"))?;
    let quote_id = v
        .get("quote")
        .or_else(|| v.get("quote_id"))
        .or_else(|| v.get("quoteId"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "mint quote state: missing quote id".to_string())?
        .to_owned();
    let state = v
        .get("state")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "mint quote state: missing state".to_string())?
        .to_owned();
    let amount_sats = v
        .get("amount")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("amount_sats").and_then(|x| x.as_u64()));
    let expiry = v.get("expiry").and_then(|x| {
        x.as_i64()
            .or_else(|| x.as_u64().and_then(|u| i64::try_from(u).ok()))
    });
    let bolt11 = v
        .get("request")
        .or_else(|| v.get("bolt11"))
        .or_else(|| v.get("invoice"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned());
    Ok(MintQuoteStateResponse {
        quote_id,
        state,
        amount_sats,
        expiry,
        bolt11,
    })
}

/// Whether a parsed quote state is mintable (paid and not yet issued).
pub fn mint_quote_state_is_mintable(state: &str) -> bool {
    matches!(state.trim().to_ascii_uppercase().as_str(), "PAID")
}

/// Whether quote state means already issued (proofs previously minted).
pub fn mint_quote_state_is_issued(state: &str) -> bool {
    matches!(state.trim().to_ascii_uppercase().as_str(), "ISSUED")
}

/// Path for NUT-04 POST mint proofs: `/v1/mint/bolt11`.
pub const CASHU_MINT_BOLT11_PATH: &str = "/v1/mint/bolt11";

/// Join mint base + NUT-04 mint proofs path.
pub fn mint_bolt11_url(mint_base: &str) -> std::result::Result<String, String> {
    let base = validate_mint_url(mint_base)?;
    Ok(format!("{base}{CASHU_MINT_BOLT11_PATH}"))
}

/// One signature entry from NUT-04 mint response (flexible field names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintBlindSignature {
    pub amount_sats: Option<u64>,
    pub id: Option<String>,
    /// Blinded signature payload (hex / compressed point string) — not secret alone.
    pub c: Option<String>,
}

/// Parsed NUT-04 `POST /v1/mint/bolt11` response (signatures only; unblinding is CDK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintBolt11Response {
    pub signatures: Vec<MintBlindSignature>,
}

/// Parse NUT-04 mint proofs response. Requires non-empty `signatures` array.
///
/// This does **not** unblind or assemble a `cashuA` token — that needs the CDK
/// helper / full wallet. Pure parse for transport tests + residual honesty.
pub fn parse_mint_bolt11_response(body: &str) -> std::result::Result<MintBolt11Response, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("mint bolt11 JSON: {e}"))?;
    let arr = v
        .get("signatures")
        .or_else(|| v.get("promises"))
        .and_then(|x| x.as_array())
        .ok_or_else(|| "mint bolt11: missing signatures array".to_string())?;
    if arr.is_empty() {
        return Err("mint bolt11: empty signatures".into());
    }
    let mut signatures = Vec::with_capacity(arr.len());
    for item in arr {
        let amount_sats = item
            .get("amount")
            .and_then(|x| x.as_u64())
            .or_else(|| item.get("amount_sats").and_then(|x| x.as_u64()));
        let id = item
            .get("id")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned());
        let c = item
            .get("C_")
            .or_else(|| item.get("C"))
            .or_else(|| item.get("c"))
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned());
        signatures.push(MintBlindSignature { amount_sats, id, c });
    }
    Ok(MintBolt11Response { signatures })
}

/// Product copy after a real `cashuA…` token is produced (not Routstr float yet).
pub fn cashu_token_redeem_next_steps(
    token_redacted: &str,
    amount_sats: Option<u64>,
) -> Vec<String> {
    let mut lines = vec![
        "Cashu proofs mint completed — redeemable token ready.".to_owned(),
        format!("Token (redacted): {token_redacted}"),
        "This is **not** Routstr prepaid float yet.".to_owned(),
        "Redeem to fund float: `grok routstr redeem <cashuA…>` (or login paste).".to_owned(),
        "Live path: Routstr `balance/create` / `balance/topup` with Bearer token.".to_owned(),
    ];
    if let Some(a) = amount_sats {
        lines.insert(1, format!("Minted amount: {a} sats."));
    }
    lines
}

/// Wall-clock unix seconds for mint-quote expiry checks (tests inject via
/// [`validate_mint_quote_for_invoice`]).
#[cfg(feature = "cashu-cdk")]
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Injectable mint-quote transport (mock in tests; HTTP under feature `cashu-cdk`).
pub trait MintQuoteTransport: Send + Sync {
    fn request_mint_quote(
        &self,
        mint_url: &str,
        amount_sats: u64,
    ) -> std::result::Result<MintQuoteBolt11Response, String>;
}

/// Product HTTP transport: blocking reqwest POST (feature `cashu-cdk` only).
#[cfg(feature = "cashu-cdk")]
#[derive(Debug, Clone, Default)]
pub struct HttpMintQuoteTransport {
    /// Override timeout seconds (default 30).
    pub timeout_secs: u64,
}

#[cfg(feature = "cashu-cdk")]
impl HttpMintQuoteTransport {
    pub fn new() -> Self {
        Self { timeout_secs: 30 }
    }
}

#[cfg(feature = "cashu-cdk")]
impl MintQuoteTransport for HttpMintQuoteTransport {
    fn request_mint_quote(
        &self,
        mint_url: &str,
        amount_sats: u64,
    ) -> std::result::Result<MintQuoteBolt11Response, String> {
        let url = mint_quote_bolt11_url(mint_url)?;
        let body = mint_quote_bolt11_request_json(amount_sats, "sat")?;
        let timeout = std::time::Duration::from_secs(self.timeout_secs.max(1));
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|e| format!("mint quote HTTP: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| format!("mint quote read body: {e}"))?;
        // Bound response size for defensive parse.
        if text.len() > 64 * 1024 {
            return Err("mint quote response too large".into());
        }
        if !status.is_success() {
            let preview: String = text.chars().take(200).collect();
            return Err(format!("mint quote HTTP {status}: {preview}"));
        }
        parse_mint_quote_bolt11_response(&text)
    }
}

/// NUT-04 mint-quote Cashu backend (feature `cashu-cdk`).
///
/// `mint_live` is true when a mint URL is configured (HTTP quote and/or helper).
/// `proofs_mint_live` is true when mint URL is set **and** a CDK helper
/// transport reports linked (process transport: helper binary resolvable on
/// disk/PATH — spawn still required at call time). `spend_live` / `refund_live`
/// true under the same helper gate; melt Success only from IPC Paid.
///
/// **Continuity:** Prefer [`CashuBackend::request_mint_invoice_with_seed`] then
/// [`CashuBackend::complete_mint_after_pay_with_seed`] with the **same** BIP-39
/// phrase + passphrase (shared scoped storage). Bare HTTP
/// [`CashuBackend::request_mint_invoice`] + later helper mint is best-effort for
/// open mints via `fetch_mint_quote` only; NUT-20 / saga recovery may fail.
#[cfg(feature = "cashu-cdk")]
pub struct Nut04MintCashu {
    mint_url: Option<String>,
    transport: std::sync::Arc<dyn MintQuoteTransport>,
    /// Optional isolated CDK helper for proofs→token (and preferred quote path
    /// when seed is supplied).
    cdk_helper: Option<std::sync::Arc<dyn crate::cashu_cdk_helper::CdkMintTransport>>,
    /// Absolute base dir for CDK helper state (per seed+passphrase scoped at call).
    cdk_storage_base: std::path::PathBuf,
}

#[cfg(feature = "cashu-cdk")]
impl std::fmt::Debug for Nut04MintCashu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nut04MintCashu")
            .field("mint_url", &self.mint_url)
            .field("mint_live", &self.mint_url.is_some())
            .field(
                "proofs_mint_live",
                &(self.mint_url.is_some()
                    && self.cdk_helper.as_ref().is_some_and(|t| t.helper_linked())),
            )
            .finish()
    }
}

#[cfg(feature = "cashu-cdk")]
impl Nut04MintCashu {
    pub fn new(
        mint_url: Option<String>,
        transport: std::sync::Arc<dyn MintQuoteTransport>,
    ) -> Self {
        Self::with_cdk_helper(mint_url, transport, None)
    }

    pub fn with_cdk_helper(
        mint_url: Option<String>,
        transport: std::sync::Arc<dyn MintQuoteTransport>,
        cdk_helper: Option<std::sync::Arc<dyn crate::cashu_cdk_helper::CdkMintTransport>>,
    ) -> Self {
        let mint_url = mint_url.and_then(|u| validate_mint_url(&u).ok().map(|s| s.to_owned()));
        Self {
            mint_url,
            transport,
            cdk_helper,
            cdk_storage_base: crate::cashu_cdk_helper::default_cdk_storage_base(),
        }
    }

    /// Product defaults: env [`CASHU_MINT_URL_ENV`] + HTTP quote transport +
    /// process CDK helper transport.
    ///
    /// `proofs_mint_live` is true only when mint URL is set **and** the helper
    /// binary is resolvable (`GROK_BITCOIN_CDK_MINT_BIN` / sibling / PATH).
    /// Does **not** fetch Routstr `/v1/info` mints — residual product wire.
    pub fn product_default() -> Self {
        let mint_url = std::env::var(CASHU_MINT_URL_ENV)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        Self::with_cdk_helper(
            mint_url,
            std::sync::Arc::new(HttpMintQuoteTransport::new()),
            Some(std::sync::Arc::new(
                crate::cashu_cdk_helper::ProcessCdkMintTransport::new(),
            )),
        )
    }

    pub fn mint_url(&self) -> Option<&str> {
        self.mint_url.as_deref()
    }

    pub fn proofs_mint_live(&self) -> bool {
        self.mint_url.is_some() && self.cdk_helper.as_ref().is_some_and(|t| t.helper_linked())
    }

    /// Non-secret storage label from first 8 bytes of BIP-39 seed
    /// (phrase **and** passphrase). Empty passphrase = BIP-39 default path.
    ///
    /// Quote + mint must use the same phrase+passphrase so they share
    /// `scoped_cdk_storage_dir` / `cdk-wallet.sqlite`.
    fn seed_fingerprint_hex(
        mnemonic: &crate::mnemonic::MnemonicSecret,
        passphrase: &str,
    ) -> String {
        use zeroize::Zeroize;
        let mut seed = mnemonic.to_seed(passphrase);
        let mut out = String::with_capacity(16);
        for b in seed.iter().take(8) {
            out.push_str(&format!("{b:02x}"));
        }
        seed.zeroize();
        out
    }

    fn scoped_storage_for_seed(
        &self,
        mnemonic: &crate::mnemonic::MnemonicSecret,
        passphrase: &str,
    ) -> std::path::PathBuf {
        let fp = Self::seed_fingerprint_hex(mnemonic, passphrase);
        crate::cashu_cdk_helper::scoped_cdk_storage_dir(&self.cdk_storage_base, &fp)
    }
}

#[cfg(feature = "cashu-cdk")]
impl CashuBackend for Nut04MintCashu {
    fn capabilities(&self) -> CashuCapabilities {
        let helper_live = self.proofs_mint_live();
        CashuCapabilities {
            // Live mint-quote path when URL is set; missing URL → Failed at call.
            mint_live: self.mint_url.is_some(),
            proofs_mint_live: helper_live,
            // Melt uses the same helper gate as proofs mint (URL + resolvable binary).
            spend_live: helper_live,
            refund_live: helper_live,
        }
    }

    fn request_mint_invoice(&self, amount_sats: Option<u64>) -> Result<MintQuoteOutcome> {
        let Some(ref mint_url) = self.mint_url else {
            return Ok(MintQuoteOutcome::Failed(
                "Cashu mint URL not configured (set GROK_BITCOIN_CASHU_MINT_URL)".into(),
            ));
        };
        let amount = match amount_sats {
            Some(0) => {
                return Ok(MintQuoteOutcome::Failed(
                    "amount_sats must be > 0 for mint quote".into(),
                ));
            }
            Some(a) => a,
            None => 1_000, // product smoke default (align with Routstr default)
        };
        // Bare path: HTTP NUT-04 quote (no seed). For proofs continuity prefer
        // request_mint_invoice_with_seed (helper localstore). HTTP quote + later
        // helper mint is open-mint best-effort only.
        match self.transport.request_mint_quote(mint_url, amount) {
            Ok(q) => {
                if let Err(e) = validate_mint_quote_for_invoice(&q, amount, now_unix_secs()) {
                    return Ok(MintQuoteOutcome::Failed(e));
                }
                Ok(MintQuoteOutcome::Invoice {
                    bolt11: q.bolt11.trim().to_owned(),
                    quote_id: q.quote_id,
                })
            }
            Err(e) => Ok(MintQuoteOutcome::Failed(e)),
        }
    }

    fn request_mint_invoice_with_seed(
        &self,
        amount_sats: Option<u64>,
        mnemonic: &crate::mnemonic::MnemonicSecret,
        passphrase: &str,
    ) -> Result<MintQuoteOutcome> {
        let Some(ref mint_url) = self.mint_url else {
            return Ok(MintQuoteOutcome::Failed(
                "Cashu mint URL not configured (set GROK_BITCOIN_CASHU_MINT_URL)".into(),
            ));
        };
        let amount = match amount_sats {
            Some(0) => {
                return Ok(MintQuoteOutcome::Failed(
                    "amount_sats must be > 0 for mint quote".into(),
                ));
            }
            Some(a) => a,
            None => 1_000,
        };

        // Prefer CDK helper quote when linked so mint_after_paid shares localstore.
        if let Some(ref helper) = self.cdk_helper {
            if helper.helper_linked() {
                let storage_dir = self.scoped_storage_for_seed(mnemonic, passphrase);
                if let Err(e) = std::fs::create_dir_all(&storage_dir) {
                    return Ok(MintQuoteOutcome::Failed(format!(
                        "create cdk storage_dir: {e}"
                    )));
                }
                let req = crate::cashu_cdk_helper::CdkMintQuoteRequest {
                    mint_url: mint_url.clone(),
                    amount_sats: amount,
                    mnemonic_phrase: mnemonic.expose().to_owned(),
                    passphrase: passphrase.to_owned(),
                    storage_dir,
                    timeout_secs: 120,
                };
                return match helper.mint_quote(&req) {
                    crate::cashu_cdk_helper::CdkMintQuoteTransportResult::Quote {
                        quote_id,
                        bolt11,
                        amount_sats: _,
                    } => {
                        if bolt11.trim().is_empty()
                            || !crate::routstr_invoice::looks_like_bolt11(&bolt11)
                        {
                            return Ok(MintQuoteOutcome::Failed(
                                "helper mint quote bolt11 failed looks_like_bolt11".into(),
                            ));
                        }
                        if quote_id.trim().is_empty() {
                            return Ok(MintQuoteOutcome::Failed(
                                "helper mint quote empty quote_id".into(),
                            ));
                        }
                        Ok(MintQuoteOutcome::Invoice {
                            bolt11: bolt11.trim().to_owned(),
                            quote_id,
                        })
                    }
                    crate::cashu_cdk_helper::CdkMintQuoteTransportResult::Failed { reason } => {
                        Ok(MintQuoteOutcome::Failed(reason))
                    }
                };
            }
        }

        // Helper not linked: HTTP NUT-04 only (proofs later may be best-effort).
        self.request_mint_invoice(Some(amount))
    }

    fn complete_mint_after_pay(&self, _quote_id: &str) -> Result<MintProofsOutcome> {
        if !self.proofs_mint_live() {
            return Ok(MintProofsOutcome::Unsupported(
                "CDK proofs mint requires mint URL + resolvable grok-bitcoin-cdk-mint helper \
                 (set GROK_BITCOIN_CASHU_MINT_URL + GROK_BITCOIN_CDK_MINT_BIN / PATH)",
            ));
        }
        Ok(MintProofsOutcome::Failed(
            "CDK proofs mint requires SeedVault BIP-39 \
             (use complete_mint_after_pay_with_seed); bare call cannot invent token"
                .into(),
        ))
    }

    fn complete_mint_after_pay_with_seed(
        &self,
        quote_id: &str,
        mnemonic: &crate::mnemonic::MnemonicSecret,
        passphrase: &str,
    ) -> Result<MintProofsOutcome> {
        let Some(ref mint_url) = self.mint_url else {
            return Ok(MintProofsOutcome::Failed(
                "Cashu mint URL not configured (set GROK_BITCOIN_CASHU_MINT_URL)".into(),
            ));
        };
        let Some(ref helper) = self.cdk_helper else {
            return Ok(MintProofsOutcome::Unsupported(
                "CDK helper transport not linked",
            ));
        };
        if !helper.helper_linked() {
            return Ok(MintProofsOutcome::Unsupported(
                "CDK helper binary not resolvable (set GROK_BITCOIN_CDK_MINT_BIN or PATH)",
            ));
        }
        let q = quote_id.trim();
        if q.is_empty() {
            return Ok(MintProofsOutcome::Failed(
                "quote_id must not be empty".into(),
            ));
        }

        // Same scoped path as request_mint_invoice_with_seed (phrase+passphrase).
        let storage_dir = self.scoped_storage_for_seed(mnemonic, passphrase);
        if let Err(e) = std::fs::create_dir_all(&storage_dir) {
            return Ok(MintProofsOutcome::Failed(format!(
                "create cdk storage_dir: {e}"
            )));
        }

        let req = crate::cashu_cdk_helper::CdkMintAfterPaidRequest {
            mint_url: mint_url.clone(),
            quote_id: q.to_owned(),
            mnemonic_phrase: mnemonic.expose().to_owned(),
            passphrase: passphrase.to_owned(),
            storage_dir,
            timeout_secs: 120,
        };
        match helper.mint_after_paid(&req) {
            crate::cashu_cdk_helper::CdkMintAfterPaidTransportResult::Token {
                token,
                amount_sats,
                quote_id,
            } => {
                // Defense in depth: re-parse before claiming Token.
                if CashuToken::parse(&token).is_err() {
                    return Ok(MintProofsOutcome::Failed(
                        "helper token failed CashuToken::parse".into(),
                    ));
                }
                Ok(MintProofsOutcome::Token {
                    token,
                    amount_sats,
                    quote_id,
                })
            }
            crate::cashu_cdk_helper::CdkMintAfterPaidTransportResult::Failed { reason } => {
                Ok(MintProofsOutcome::Failed(reason))
            }
        }
    }

    fn refund(&self) -> Result<CashuRefundOutcome> {
        if self.proofs_mint_live() {
            Ok(CashuRefundOutcome::Failed(
                "CDK melt requires cashuA token + destination BOLT11 + SeedVault \
                 (use melt_token_to_bolt11_with_seed); bare refund has no token context. \
                 For Routstr node float use `grok routstr refund` (POST /v1/balance/refund)."
                    .into(),
            ))
        } else {
            Ok(CashuRefundOutcome::Unsupported(
                "Cashu melt / refund not live (need mint URL + resolvable grok-bitcoin-cdk-mint \
                 helper; use `grok routstr refund` for node float)",
            ))
        }
    }

    fn melt_token_to_bolt11_with_seed(
        &self,
        token: &str,
        bolt11: &str,
        mnemonic: &crate::mnemonic::MnemonicSecret,
        passphrase: &str,
    ) -> Result<CashuRefundOutcome> {
        let Some(ref mint_url) = self.mint_url else {
            return Ok(CashuRefundOutcome::Failed(
                "Cashu mint URL not configured (set GROK_BITCOIN_CASHU_MINT_URL)".into(),
            ));
        };
        let Some(ref helper) = self.cdk_helper else {
            return Ok(CashuRefundOutcome::Unsupported(
                "CDK helper transport not linked",
            ));
        };
        if !helper.helper_linked() {
            return Ok(CashuRefundOutcome::Unsupported(
                "CDK helper binary not resolvable (set GROK_BITCOIN_CDK_MINT_BIN or PATH)",
            ));
        }
        if CashuToken::parse(token).is_err() {
            return Ok(CashuRefundOutcome::Failed(
                "token failed CashuToken::parse (need cashuA…/cashuB…)".into(),
            ));
        }
        if !crate::routstr_invoice::looks_like_bolt11(bolt11) {
            return Ok(CashuRefundOutcome::Failed(
                "bolt11 failed looks_like_bolt11 (lnurl rejected)".into(),
            ));
        }

        let storage_dir = self.scoped_storage_for_seed(mnemonic, passphrase);
        if let Err(e) = std::fs::create_dir_all(&storage_dir) {
            return Ok(CashuRefundOutcome::Failed(format!(
                "create cdk storage_dir: {e}"
            )));
        }

        let req = crate::cashu_cdk_helper::CdkMeltTokenRequest {
            mint_url: mint_url.clone(),
            token: token.trim().to_owned(),
            bolt11: bolt11.trim().to_owned(),
            mnemonic_phrase: mnemonic.expose().to_owned(),
            passphrase: passphrase.to_owned(),
            storage_dir,
            timeout_secs: 120,
        };
        match helper.melt_token(&req) {
            crate::cashu_cdk_helper::CdkMeltTokenTransportResult::Paid {
                quote_id,
                amount_sats,
                fee_sats,
                payment_preimage,
            } => {
                let mut detail = format!(
                    "melted {amount_sats} sats (fee {fee_sats}) quote_id={quote_id} state=PAID"
                );
                if let Some(ref pre) = payment_preimage {
                    // Preimage is not a seed secret; short redacted tail only.
                    let tail: String = pre
                        .chars()
                        .rev()
                        .take(4)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    detail.push_str(&format!(" preimage…{tail}"));
                }
                Ok(CashuRefundOutcome::Completed { detail })
            }
            crate::cashu_cdk_helper::CdkMeltTokenTransportResult::Failed { reason } => {
                Ok(CashuRefundOutcome::Failed(reason))
            }
        }
    }
}

/// Bearer Cashu token (`cashuA…`). Never `Debug`-prints the full token.
pub struct CashuToken(SecretString);

impl CashuToken {
    /// Parse a Cashu token string. Requires `cashuA` prefix (v4/v3 common form).
    pub fn parse(token: &str) -> Result<Self> {
        let t = token.trim();
        if t.is_empty() {
            return Err(WalletError::Cashu("empty token".into()));
        }
        if !t.starts_with("cashuA") && !t.starts_with("cashuB") {
            return Err(WalletError::Cashu(
                "token must start with cashuA (or cashuB)".into(),
            ));
        }
        if t.len() < 16 {
            return Err(WalletError::Cashu("token too short".into()));
        }
        Ok(Self(SecretString::from(t.to_owned())))
    }

    /// Controlled expose for Authorization header construction.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Redacted preview (actual prefix + ellipsis + last 4).
    pub fn redacted(&self) -> String {
        let s = self.expose();
        let prefix = if s.starts_with("cashuB") {
            "cashuB"
        } else {
            "cashuA"
        };
        let tail = s
            .char_indices()
            .rev()
            .nth(3)
            .map(|(i, _)| &s[i..])
            .unwrap_or("");
        format!("{prefix}…{tail}")
    }
}

impl fmt::Debug for CashuToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CashuToken").field(&self.redacted()).finish()
    }
}

/// Funding wizard steps (deposit → channel → Cashu → inference).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FundingStep {
    NeedWallet,
    ShowAddress,
    WatchingTx,
    OpenChannel,
    AcquireCashu,
    ReadyForInference,
    RefundOptional,
}

impl FundingStep {
    /// Stable user-facing label (not Rust Debug).
    pub fn user_label(self) -> &'static str {
        match self {
            Self::NeedWallet => "need wallet",
            Self::ShowAddress => "showing receive address",
            Self::WatchingTx => "watching transaction",
            Self::OpenChannel => "open channel",
            Self::AcquireCashu => "acquire Cashu",
            Self::ReadyForInference => "ready for inference",
            Self::RefundOptional => "refund optional",
        }
    }

    /// Stable wire name for persistence (snake_case; not user copy).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::NeedWallet => "need_wallet",
            Self::ShowAddress => "show_address",
            Self::WatchingTx => "watching_tx",
            Self::OpenChannel => "open_channel",
            Self::AcquireCashu => "acquire_cashu",
            Self::ReadyForInference => "ready_for_inference",
            Self::RefundOptional => "refund_optional",
        }
    }

    /// Parse [`Self::as_wire_str`] (and a few aliases). Unknown → `None`.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "need_wallet" => Some(Self::NeedWallet),
            "show_address" => Some(Self::ShowAddress),
            "watching_tx" => Some(Self::WatchingTx),
            "open_channel" => Some(Self::OpenChannel),
            "acquire_cashu" => Some(Self::AcquireCashu),
            "ready_for_inference" => Some(Self::ReadyForInference),
            "refund_optional" => Some(Self::RefundOptional),
            _ => None,
        }
    }
}

/// Funding wizard state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingWizard {
    pub step: FundingStep,
    pub receive_address: Option<String>,
    pub watched_txid: Option<String>,
    pub confirmations: u32,
    pub required_confirmations: u32,
    /// BIP-39 show-once + full re-entry completed (required before ShowAddress).
    backup_confirmed: bool,
}

impl Default for FundingWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl FundingWizard {
    pub fn new() -> Self {
        Self {
            step: FundingStep::NeedWallet,
            receive_address: None,
            watched_txid: None,
            confirmations: 0,
            required_confirmations: 3,
            backup_confirmed: false,
        }
    }

    /// Whether backup show-once + re-entry has been marked complete.
    pub fn backup_confirmed(&self) -> bool {
        self.backup_confirmed
    }

    /// Test-only: mark backup complete without a [`crate::seed_vault::MnemonicBackupGate`].
    ///
    /// Product code must use [`Self::show_address_with_backup_gate`] so show-once
    /// + full re-entry cannot be skipped.
    #[cfg(test)]
    pub(crate) fn mark_backup_confirmed_for_test(&mut self) {
        self.backup_confirmed = true;
    }

    /// Resume at ShowAddress after the gated fund path already finished.
    ///
    /// **Invariant:** call only once `grok routstr fund` (or TUI equivalent)
    /// completed backup confirm + durable SeedVault store + address reveal.
    /// This constructor does **not** display BIP-39 and must never be used to
    /// skip the fund path for a new wallet.
    pub fn for_watch_after_fund(address: impl Into<String>, required_confirmations: u32) -> Self {
        Self {
            step: FundingStep::ShowAddress,
            receive_address: Some(address.into()),
            watched_txid: None,
            confirmations: 0,
            required_confirmations: required_confirmations.max(1),
            backup_confirmed: true,
        }
    }

    /// Resume funding-wizard watch progress after a process restart.
    ///
    /// **No BIP-39 / seed material.** Address + txid + confirmation counts only.
    /// Call only when the original fund path already confirmed backup (watch
    /// sessions never re-display recovery words).
    ///
    /// Invalid for `NeedWallet` (would skip backup gates).
    pub fn resume_watch(
        address: impl Into<String>,
        required_confirmations: u32,
        step: FundingStep,
        watched_txid: Option<String>,
        confirmations: u32,
    ) -> Result<Self> {
        if matches!(step, FundingStep::NeedWallet) {
            return Err(WalletError::Onchain(
                "cannot resume watch at need_wallet (backup gate not skippable)".into(),
            ));
        }
        Ok(Self {
            step,
            receive_address: Some(address.into()),
            watched_txid,
            confirmations,
            required_confirmations: required_confirmations.max(1),
            backup_confirmed: true,
        })
    }

    /// After BIP-39 backup confirmed and address derived.
    ///
    /// Requires a prior successful [`Self::show_address_with_backup_gate`] (or
    /// the test-only mark helper). Without backup confirmation returns
    /// [`WalletError::BackupNotConfirmed`].
    pub fn show_address(&mut self, address: impl Into<String>) -> Result<()> {
        if !self.backup_confirmed {
            return Err(WalletError::BackupNotConfirmed);
        }
        self.transition(FundingStep::NeedWallet, FundingStep::ShowAddress)?;
        self.receive_address = Some(address.into());
        Ok(())
    }

    /// Advance to ShowAddress only when `gate` has completed show-once + re-entry.
    ///
    /// Supported product path for funding UX wire-up.
    pub fn show_address_with_backup_gate(
        &mut self,
        address: impl Into<String>,
        gate: &crate::seed_vault::MnemonicBackupGate,
    ) -> Result<()> {
        if !gate.is_confirmed() {
            return Err(WalletError::BackupNotConfirmed);
        }
        self.backup_confirmed = true;
        self.show_address(address)
    }

    /// User broadcast / watcher saw a tx paying the address.
    pub fn watch_tx(&mut self, txid: impl Into<String>) -> Result<()> {
        self.transition(FundingStep::ShowAddress, FundingStep::WatchingTx)?;
        self.watched_txid = Some(txid.into());
        self.confirmations = 0;
        Ok(())
    }

    /// Update confirmation count; auto-advance when threshold met.
    pub fn set_confirmations(&mut self, n: u32) -> Result<()> {
        if self.step != FundingStep::WatchingTx {
            return Err(WalletError::InvalidTransition {
                from: self.step,
                to: FundingStep::WatchingTx,
            });
        }
        self.confirmations = n;
        if n >= self.required_confirmations {
            self.step = FundingStep::OpenChannel;
        }
        Ok(())
    }

    pub fn channel_opened(&mut self) -> Result<()> {
        self.transition(FundingStep::OpenChannel, FundingStep::AcquireCashu)
    }

    pub fn cashu_acquired(&mut self) -> Result<()> {
        self.transition(FundingStep::AcquireCashu, FundingStep::ReadyForInference)
    }

    pub fn begin_refund(&mut self) -> Result<()> {
        self.transition(FundingStep::ReadyForInference, FundingStep::RefundOptional)
    }

    /// Escape hatch: skip channel and go acquire Cashu externally funded.
    pub fn skip_channel_for_external_cashu(&mut self) -> Result<()> {
        match self.step {
            FundingStep::OpenChannel | FundingStep::WatchingTx | FundingStep::ShowAddress => {
                self.step = FundingStep::AcquireCashu;
                Ok(())
            }
            other => Err(WalletError::InvalidTransition {
                from: other,
                to: FundingStep::AcquireCashu,
            }),
        }
    }

    fn transition(&mut self, from: FundingStep, to: FundingStep) -> Result<()> {
        if self.step != from {
            return Err(WalletError::InvalidTransition {
                from: self.step,
                to,
            });
        }
        self.step = to;
        Ok(())
    }
}

/// HTTP-shaped helper: Routstr balance info body to msats.
///
/// Accepts explicit unit fields only: `msats`, `balance_msats`, `sats`,
/// `balance_sats`, and the same under nested `data`. Bare `balance` is ignored
/// (unit is ambiguous).
pub fn parse_balance_msats_from_json(body: &str) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    read_msats(&v)
}

fn read_msats(v: &serde_json::Value) -> Option<u64> {
    // Prefer explicit unit fields only (avoid guessing bare `balance` units).
    if let Some(n) = v.get("msats").and_then(as_u64) {
        return Some(n);
    }
    if let Some(n) = v.get("balance_msats").and_then(as_u64) {
        return Some(n);
    }
    if let Some(n) = v.get("sats").and_then(as_u64) {
        return Some(n.saturating_mul(1000));
    }
    if let Some(n) = v.get("balance_sats").and_then(as_u64) {
        return Some(n.saturating_mul(1000));
    }
    if let Some(data) = v.get("data") {
        return read_msats(data);
    }
    None
}

fn as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
        .or_else(|| {
            v.as_f64()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        })
        .or_else(|| v.as_str()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_cashu_melt_product_path_and_residual_never_float() {
        assert_eq!(
            decide_cashu_melt_product_path(STUB_CASHU_CAPABILITIES),
            CashuMeltProductPath::Residual
        );
        assert_eq!(
            decide_cashu_melt_product_path(CashuCapabilities {
                mint_live: true,
                proofs_mint_live: true,
                spend_live: true,
                refund_live: true,
            }),
            CashuMeltProductPath::LiveMelt
        );
        assert_eq!(
            decide_cashu_melt_product_path(CashuCapabilities {
                mint_live: false,
                proofs_mint_live: false,
                spend_live: false,
                refund_live: true,
            }),
            CashuMeltProductPath::LiveMelt
        );
        let residual = cashu_melt_residual_lines().join("\n").to_ascii_lowercase();
        assert!(residual.contains("not live") || residual.contains("refund"));
        assert!(residual.contains("balance") || residual.contains("token"));
        assert!(
            residual.contains("cashua") && residual.contains("sk-"),
            "must guide prefer cashuA over large hot sk- float: {residual}"
        );
        assert!(!residual.contains("float credited"));
        assert!(!residual.contains("state=paid") || residual.contains("never"));
        let paid = cashu_melt_paid_lines("melted 21 sats state=PAID")
            .join("\n")
            .to_ascii_lowercase();
        assert!(paid.contains("melt") && paid.contains("paid"));
        assert!(paid.contains("not") && paid.contains("float"));
        assert!(
            paid.contains("cashua") && paid.contains("sk-"),
            "must guide prefer cashuA melt over large hot sk- float: {paid}"
        );
        assert!(!paid.contains("float credited"));
        let failed = cashu_melt_failed_lines("helper rejected")
            .join("\n")
            .to_ascii_lowercase();
        assert!(failed.contains("did not complete") || failed.contains("not complete"));
        assert!(!failed.contains("float credited"));
        // Live-attempt failure must not invert capability honesty ("not live").
        assert!(
            !failed.contains("not live"),
            "live-fail lines must not claim melt not live: {failed}"
        );
        assert!(failed.contains("retry") || failed.contains("refund"));
    }

    #[test]
    fn decide_cashu_mint_product_path_and_residual_honesty() {
        assert_eq!(
            decide_cashu_mint_product_path(STUB_CASHU_CAPABILITIES),
            CashuMintProductPath::Residual
        );
        assert_eq!(
            decide_cashu_mint_product_path(CashuCapabilities {
                mint_live: true,
                proofs_mint_live: false,
                spend_live: false,
                refund_live: false,
            }),
            CashuMintProductPath::QuoteOnly
        );
        assert_eq!(
            decide_cashu_mint_product_path(CashuCapabilities {
                mint_live: true,
                proofs_mint_live: true,
                spend_live: false,
                refund_live: false,
            }),
            CashuMintProductPath::LiveProofs
        );
        // Residual copy never claims float / fabricates bolt11.
        let residual = cashu_mint_residual_lines(Some(500), CashuMintProductPath::Residual)
            .join("\n")
            .to_ascii_lowercase();
        assert!(residual.contains("not live") || residual.contains("p0"));
        assert!(residual.contains("topup"));
        assert!(!residual.contains("lnbc"));
        assert!(!residual.contains("float credited"));
        let quote_lines = cashu_mint_quote_display_lines("lnbc1x", "q-1", Some(21))
            .join("\n")
            .to_ascii_lowercase();
        assert!(quote_lines.contains("mint quote"));
        assert!(quote_lines.contains("not") && quote_lines.contains("float"));
        assert!(quote_lines.contains("lnbc1x"));
        let token_lines = cashu_mint_token_obtained_lines(21, "q-1", "cashuA…[REDACTED]")
            .join("\n")
            .to_ascii_lowercase();
        assert!(token_lines.contains("not routstr float"));
        let float_lines = cashu_mint_float_credited_lines(Some(21))
            .join("\n")
            .to_ascii_lowercase();
        assert!(float_lines.contains("float credited") || float_lines.contains("redeem succeeded"));
    }

    #[test]
    fn stub_cashu_never_claims_live_mint_or_refund() {
        let c = StubCashu;
        let caps = c.capabilities();
        assert!(!caps.mint_live);
        assert!(!caps.proofs_mint_live);
        assert!(!caps.spend_live);
        assert!(!caps.refund_live);

        let mint = c.request_mint_invoice(Some(21_000)).unwrap();
        assert!(
            matches!(mint, MintQuoteOutcome::Unsupported(_)),
            "stub must not invent mint invoice: {mint:?}"
        );
        if let MintQuoteOutcome::Invoice { bolt11, .. } = mint {
            panic!("stub fabricated bolt11: {bolt11}");
        }

        let proofs = c.complete_mint_after_pay("q-1").unwrap();
        assert!(
            matches!(proofs, MintProofsOutcome::Unsupported(_)),
            "stub must not invent token: {proofs:?}"
        );
        if let MintProofsOutcome::Token { token, .. } = proofs {
            panic!("stub fabricated token: {token}");
        }

        let refnd = c.refund().unwrap();
        assert!(
            matches!(refnd, CashuRefundOutcome::Unsupported(_)),
            "stub must not claim refund completed: {refnd:?}"
        );
        assert!(!matches!(refnd, CashuRefundOutcome::Completed { .. }));
    }

    #[test]
    fn default_cashu_backend_honest_live_flags() {
        let c = default_cashu_backend();
        let caps = c.capabilities();
        // Without GROK_BITCOIN_CASHU_MINT_URL, even feature cashu-cdk keeps mint_live false.
        assert!(
            !caps.mint_live,
            "default backend without mint URL must not claim mint_live"
        );
        // proofs_mint_live requires mint URL + helper; without URL stays false.
        assert!(!caps.proofs_mint_live);
        assert!(!caps.spend_live);
        assert!(!caps.refund_live);
        let mint = c.request_mint_invoice(Some(1)).unwrap();
        #[cfg(feature = "cashu-cdk")]
        assert!(
            matches!(mint, MintQuoteOutcome::Failed(_)),
            "cashu-cdk without URL → Failed not fabricated Invoice: {mint:?}"
        );
        #[cfg(not(feature = "cashu-cdk"))]
        assert!(
            matches!(mint, MintQuoteOutcome::Unsupported(_)),
            "stub → Unsupported: {mint:?}"
        );
        assert!(
            !matches!(mint, MintQuoteOutcome::Invoice { .. }),
            "must not invent mint invoice: {mint:?}"
        );
        assert!(matches!(
            c.refund().unwrap(),
            CashuRefundOutcome::Unsupported(_)
        ));
    }

    #[test]
    fn mint_quote_request_and_parse_nut04_shape() {
        let j = mint_quote_bolt11_request_json(1000, "sat").unwrap();
        assert!(j.contains("\"amount\":1000"));
        assert!(j.contains("\"unit\":\"sat\""));
        assert!(mint_quote_bolt11_request_json(0, "sat").is_err());
        assert!(validate_mint_url("https://mint.example/Bitcoin").is_ok());
        assert!(validate_mint_url("not-a-url").is_err());
        let url = mint_quote_bolt11_url("https://mint.example/Bitcoin/").unwrap();
        assert_eq!(url, "https://mint.example/Bitcoin/v1/mint/quote/bolt11");

        // Live-shaped NUT-04 response (minibits-style).
        let body = r#"{
            "quote":"019f7f1d-52f0-70ae-9ee2-b8dffe7609b8",
            "request":"lnbc10n1p49m7ecpp5test",
            "amount":1,
            "unit":"sat",
            "state":"UNPAID",
            "expiry":1784630456
        }"#;
        let q = parse_mint_quote_bolt11_response(body).unwrap();
        assert_eq!(q.quote_id, "019f7f1d-52f0-70ae-9ee2-b8dffe7609b8");
        assert!(q.bolt11.starts_with("lnbc"));
        assert_eq!(q.amount_sats, Some(1));
        assert_eq!(q.state.as_deref(), Some("UNPAID"));

        assert!(parse_mint_quote_bolt11_response(r#"{"quote":"q"}"#).is_err());
        assert!(parse_mint_quote_bolt11_response(r#"{"quote":"q","request":"not-ln"}"#).is_err());
        assert!(
            parse_mint_quote_bolt11_response(r#"{"quote":"q","request":"lnurl1dp68gurn8ghj7"}"#)
                .is_err(),
            "LNURL must not parse as mint quote bolt11"
        );

        // validate_mint_quote_for_invoice: expiry / state / amount
        let mut q = parse_mint_quote_bolt11_response(body).unwrap();
        assert!(validate_mint_quote_for_invoice(&q, 1, 1_000).is_ok());
        assert!(
            validate_mint_quote_for_invoice(&q, 1, 9_999_999_999).is_err(),
            "now past expiry must fail"
        );
        q.state = Some("EXPIRED".into());
        assert!(
            validate_mint_quote_for_invoice(&q, 1, 1_000).is_err(),
            "EXPIRED state must fail"
        );
        q.state = Some("UNPAID".into());
        q.expiry = Some(9_999_999_999);
        assert!(
            validate_mint_quote_for_invoice(&q, 99, 1_000).is_err(),
            "amount mismatch must fail"
        );
        assert!(validate_mint_quote_for_invoice(&q, 1, 1_000).is_ok());
        // amount optional from mint
        q.amount_sats = None;
        assert!(validate_mint_quote_for_invoice(&q, 500, 1_000).is_ok());
    }

    #[cfg(feature = "cashu-cdk")]
    #[test]
    fn nut04_mint_cashu_success_only_from_transport() {
        use std::sync::Arc;

        struct MockMint {
            ok: bool,
        }
        impl MintQuoteTransport for MockMint {
            fn request_mint_quote(
                &self,
                mint_url: &str,
                amount_sats: u64,
            ) -> std::result::Result<MintQuoteBolt11Response, String> {
                assert!(mint_url.starts_with("https://"));
                assert!(amount_sats > 0);
                if self.ok {
                    Ok(MintQuoteBolt11Response {
                        quote_id: "q-1".into(),
                        bolt11: "lnbc1mockmintquote".into(),
                        amount_sats: Some(amount_sats),
                        unit: Some("sat".into()),
                        expiry: None,
                        state: Some("UNPAID".into()),
                    })
                } else {
                    Err("mint down".into())
                }
            }
        }

        let live = Nut04MintCashu::new(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockMint { ok: true }),
        );
        assert!(live.capabilities().mint_live);
        // No CDK helper → proofs_mint_live false (HTTP quote only).
        assert!(!live.capabilities().proofs_mint_live);
        assert!(!live.capabilities().spend_live);
        assert!(!live.capabilities().refund_live);
        match live.request_mint_invoice(Some(500)).unwrap() {
            MintQuoteOutcome::Invoice { bolt11, quote_id } => {
                assert_eq!(bolt11, "lnbc1mockmintquote");
                assert_eq!(quote_id, "q-1");
            }
            other => panic!("expected Invoice: {other:?}"),
        }

        let fail = Nut04MintCashu::new(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockMint { ok: false }),
        );
        assert!(matches!(
            fail.request_mint_invoice(Some(1)).unwrap(),
            MintQuoteOutcome::Failed(ref s) if s.contains("mint down")
        ));

        let no_url = Nut04MintCashu::new(None, Arc::new(MockMint { ok: true }));
        assert!(!no_url.capabilities().mint_live);
        assert!(!no_url.capabilities().proofs_mint_live);
        assert!(matches!(
            no_url.request_mint_invoice(Some(1)).unwrap(),
            MintQuoteOutcome::Failed(_)
        ));
    }

    #[cfg(feature = "cashu-cdk")]
    #[test]
    fn nut04_proofs_mint_only_from_helper_transport() {
        use std::sync::Arc;

        use crate::cashu_cdk_helper::{
            CdkMintAfterPaidRequest, CdkMintAfterPaidTransportResult, CdkMintQuoteRequest,
            CdkMintQuoteTransportResult, CdkMintTransport,
        };
        use crate::mnemonic::import_mnemonic;

        struct MockMintQuoteAlways;
        impl MintQuoteTransport for MockMintQuoteAlways {
            fn request_mint_quote(
                &self,
                _mint_url: &str,
                amount_sats: u64,
            ) -> std::result::Result<MintQuoteBolt11Response, String> {
                Ok(MintQuoteBolt11Response {
                    quote_id: "q-http".into(),
                    bolt11: "lnbc1httpquote".into(),
                    amount_sats: Some(amount_sats),
                    unit: Some("sat".into()),
                    expiry: None,
                    state: Some("UNPAID".into()),
                })
            }
        }

        struct MockCdkHelper {
            token_ok: bool,
        }
        impl CdkMintTransport for MockCdkHelper {
            fn helper_linked(&self) -> bool {
                true
            }
            fn mint_quote(&self, _r: &CdkMintQuoteRequest) -> CdkMintQuoteTransportResult {
                CdkMintQuoteTransportResult::Failed {
                    reason: "not used in this test".into(),
                }
            }
            fn mint_after_paid(
                &self,
                r: &CdkMintAfterPaidRequest,
            ) -> CdkMintAfterPaidTransportResult {
                if self.token_ok {
                    CdkMintAfterPaidTransportResult::Token {
                        token: "cashuAabcdefghijklmnopqrstuvwxyz".into(),
                        amount_sats: 21,
                        quote_id: r.quote_id.clone(),
                    }
                } else {
                    CdkMintAfterPaidTransportResult::Failed {
                        reason: "unpaid".into(),
                    }
                }
            }
            fn melt_token(
                &self,
                _r: &crate::cashu_cdk_helper::CdkMeltTokenRequest,
            ) -> crate::cashu_cdk_helper::CdkMeltTokenTransportResult {
                crate::cashu_cdk_helper::CdkMeltTokenTransportResult::Failed {
                    reason: "melt not used in this test".into(),
                }
            }
        }

        let backend = Nut04MintCashu::with_cdk_helper(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockMintQuoteAlways),
            Some(Arc::new(MockCdkHelper { token_ok: true })),
        );
        assert!(backend.capabilities().mint_live);
        assert!(backend.capabilities().proofs_mint_live);
        assert!(backend.capabilities().spend_live);
        assert!(backend.capabilities().refund_live);

        // Bare complete without seed → Failed (not Token).
        assert!(matches!(
            backend.complete_mint_after_pay("q-1").unwrap(),
            MintProofsOutcome::Failed(_)
        ));

        let mn = import_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        match backend
            .complete_mint_after_pay_with_seed("q-1", &mn, "")
            .unwrap()
        {
            MintProofsOutcome::Token {
                token,
                amount_sats,
                quote_id,
            } => {
                assert!(token.starts_with("cashuA"));
                assert_eq!(amount_sats, 21);
                assert_eq!(quote_id, "q-1");
                let redacted = CashuToken::parse(&token).unwrap().redacted();
                let steps = cashu_token_redeem_next_steps(&redacted, Some(amount_sats));
                let joined = steps.join("\n");
                assert!(joined.contains("redeem"), "{joined}");
                assert!(
                    joined.contains("not") && joined.to_ascii_lowercase().contains("float"),
                    "must not claim float: {joined}"
                );
            }
            other => panic!("expected Token: {other:?}"),
        }

        let fail = Nut04MintCashu::with_cdk_helper(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockMintQuoteAlways),
            Some(Arc::new(MockCdkHelper { token_ok: false })),
        );
        assert!(matches!(
            fail.complete_mint_after_pay_with_seed("q-1", &mn, "")
                .unwrap(),
            MintProofsOutcome::Failed(ref s) if s.contains("unpaid")
        ));
    }

    #[cfg(feature = "cashu-cdk")]
    #[test]
    fn nut04_melt_only_from_helper_paid() {
        use std::sync::Arc;

        use crate::cashu_cdk_helper::{
            CdkMeltTokenRequest, CdkMeltTokenTransportResult, CdkMintAfterPaidRequest,
            CdkMintAfterPaidTransportResult, CdkMintQuoteRequest, CdkMintQuoteTransportResult,
            CdkMintTransport,
        };
        use crate::mnemonic::import_mnemonic;

        struct MockHttpNever;
        impl MintQuoteTransport for MockHttpNever {
            fn request_mint_quote(
                &self,
                _mint_url: &str,
                _amount_sats: u64,
            ) -> std::result::Result<MintQuoteBolt11Response, String> {
                Err("http not used".into())
            }
        }

        struct MockMeltHelper {
            paid: bool,
        }
        impl CdkMintTransport for MockMeltHelper {
            fn helper_linked(&self) -> bool {
                true
            }
            fn mint_quote(&self, _r: &CdkMintQuoteRequest) -> CdkMintQuoteTransportResult {
                CdkMintQuoteTransportResult::Failed {
                    reason: "n/a".into(),
                }
            }
            fn mint_after_paid(
                &self,
                _r: &CdkMintAfterPaidRequest,
            ) -> CdkMintAfterPaidTransportResult {
                CdkMintAfterPaidTransportResult::Failed {
                    reason: "n/a".into(),
                }
            }
            fn melt_token(&self, r: &CdkMeltTokenRequest) -> CdkMeltTokenTransportResult {
                assert!(CashuToken::parse(&r.token).is_ok());
                assert!(crate::routstr_invoice::looks_like_bolt11(&r.bolt11));
                if self.paid {
                    CdkMeltTokenTransportResult::Paid {
                        quote_id: "mq-1".into(),
                        amount_sats: 1000,
                        fee_sats: 2,
                        payment_preimage: Some("deadbeef".into()),
                    }
                } else {
                    CdkMeltTokenTransportResult::Failed {
                        reason: "mint rejected melt".into(),
                    }
                }
            }
        }

        let backend = Nut04MintCashu::with_cdk_helper(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockHttpNever),
            Some(Arc::new(MockMeltHelper { paid: true })),
        );
        assert!(backend.capabilities().spend_live);
        assert!(backend.capabilities().refund_live);

        // Bare refund never invents Completed.
        match backend.refund().unwrap() {
            CashuRefundOutcome::Failed(ref s) => {
                assert!(
                    s.contains("melt_token") || s.contains("token context"),
                    "{s}"
                );
            }
            other => panic!("bare refund must be Failed not Completed: {other:?}"),
        }

        let mn = import_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        match backend
            .melt_token_to_bolt11_with_seed(
                "cashuAabcdefghijklmnopqrstuvwxyz",
                "lnbc1meltdest",
                &mn,
                "",
            )
            .unwrap()
        {
            CashuRefundOutcome::Completed { detail } => {
                assert!(detail.contains("1000"));
                assert!(detail.contains("PAID") || detail.contains("melted"));
                assert!(detail.contains("mq-1"));
            }
            other => panic!("expected Completed: {other:?}"),
        }

        let fail = Nut04MintCashu::with_cdk_helper(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockHttpNever),
            Some(Arc::new(MockMeltHelper { paid: false })),
        );
        assert!(matches!(
            fail.melt_token_to_bolt11_with_seed(
                "cashuAabcdefghijklmnopqrstuvwxyz",
                "lnbc1meltdest",
                &mn,
                "",
            )
            .unwrap(),
            CashuRefundOutcome::Failed(ref s) if s.contains("rejected")
        ));

        // Bad token / lnurl offline rejections.
        assert!(matches!(
            backend
                .melt_token_to_bolt11_with_seed("sk-not-cashu", "lnbc1x", &mn, "")
                .unwrap(),
            CashuRefundOutcome::Failed(ref s) if s.contains("CashuToken") || s.contains("cashu")
        ));
        assert!(matches!(
            backend
                .melt_token_to_bolt11_with_seed(
                    "cashuAabcdefghijklmnopqrstuvwxyz",
                    "lnurl1dp68gurn8ghj7",
                    &mn,
                    "",
                )
                .unwrap(),
            CashuRefundOutcome::Failed(ref s) if s.contains("looks_like_bolt11") || s.contains("lnurl")
        ));

        // Helper not linked → spend/refund live false.
        struct Unlinked;
        impl CdkMintTransport for Unlinked {
            fn helper_linked(&self) -> bool {
                false
            }
            fn mint_quote(&self, _: &CdkMintQuoteRequest) -> CdkMintQuoteTransportResult {
                CdkMintQuoteTransportResult::Failed {
                    reason: "n/a".into(),
                }
            }
            fn mint_after_paid(
                &self,
                _: &CdkMintAfterPaidRequest,
            ) -> CdkMintAfterPaidTransportResult {
                CdkMintAfterPaidTransportResult::Failed {
                    reason: "n/a".into(),
                }
            }
            fn melt_token(&self, _: &CdkMeltTokenRequest) -> CdkMeltTokenTransportResult {
                CdkMeltTokenTransportResult::Failed {
                    reason: "n/a".into(),
                }
            }
        }
        let no_helper = Nut04MintCashu::with_cdk_helper(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockHttpNever),
            Some(Arc::new(Unlinked)),
        );
        assert!(!no_helper.capabilities().spend_live);
        assert!(!no_helper.capabilities().refund_live);
        assert!(!no_helper.capabilities().proofs_mint_live);
    }

    #[test]
    fn mint_proofs_outcome_debug_redacts_token() {
        let full = "cashuAabcdefghijklmnopqrstuvwxyz0123456789";
        let out = MintProofsOutcome::Token {
            token: full.to_owned(),
            amount_sats: 21,
            quote_id: "q-redact".into(),
        };
        let dbg = format!("{out:?}");
        assert!(
            !dbg.contains(full),
            "Debug must not dump full bearer token: {dbg}"
        );
        assert!(dbg.contains("cashuA") || dbg.contains("REDACTED"), "{dbg}");
        assert!(dbg.contains("21"), "{dbg}");
        assert!(dbg.contains("q-redact"), "{dbg}");
    }

    #[cfg(feature = "cashu-cdk")]
    #[test]
    fn seed_fingerprint_includes_passphrase() {
        use crate::mnemonic::import_mnemonic;

        let mn = import_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let empty = Nut04MintCashu::seed_fingerprint_hex(&mn, "");
        let with_pp = Nut04MintCashu::seed_fingerprint_hex(&mn, "correct horse");
        assert_eq!(empty.len(), 16);
        assert_eq!(with_pp.len(), 16);
        assert_ne!(empty, with_pp, "passphrase must change storage fingerprint");
        // Same inputs → stable label.
        assert_eq!(empty, Nut04MintCashu::seed_fingerprint_hex(&mn, ""));
        let base = std::path::Path::new("/tmp/cdk-fp");
        let d1 = crate::cashu_cdk_helper::scoped_cdk_storage_dir(base, &empty);
        let d2 = crate::cashu_cdk_helper::scoped_cdk_storage_dir(base, &with_pp);
        assert_ne!(d1, d2);
    }

    #[cfg(feature = "cashu-cdk")]
    #[test]
    fn request_mint_invoice_with_seed_prefers_helper_quote() {
        use std::sync::{Arc, Mutex};

        use crate::cashu_cdk_helper::{
            CdkMintAfterPaidRequest, CdkMintAfterPaidTransportResult, CdkMintQuoteRequest,
            CdkMintQuoteTransportResult, CdkMintTransport,
        };
        use crate::mnemonic::import_mnemonic;

        struct MockHttpNever;
        impl MintQuoteTransport for MockHttpNever {
            fn request_mint_quote(
                &self,
                _mint_url: &str,
                _amount_sats: u64,
            ) -> std::result::Result<MintQuoteBolt11Response, String> {
                panic!("HTTP transport must not be used when helper quote is linked");
            }
        }

        struct MockCdkQuote {
            saw_storage: Mutex<Option<std::path::PathBuf>>,
        }
        impl CdkMintTransport for MockCdkQuote {
            fn helper_linked(&self) -> bool {
                true
            }
            fn mint_quote(&self, r: &CdkMintQuoteRequest) -> CdkMintQuoteTransportResult {
                *self.saw_storage.lock().unwrap() = Some(r.storage_dir.clone());
                CdkMintQuoteTransportResult::Quote {
                    quote_id: "q-helper".into(),
                    bolt11: "lnbc1helperscope".into(),
                    amount_sats: r.amount_sats,
                }
            }
            fn mint_after_paid(
                &self,
                _r: &CdkMintAfterPaidRequest,
            ) -> CdkMintAfterPaidTransportResult {
                CdkMintAfterPaidTransportResult::Failed {
                    reason: "not used".into(),
                }
            }
            fn melt_token(
                &self,
                _r: &crate::cashu_cdk_helper::CdkMeltTokenRequest,
            ) -> crate::cashu_cdk_helper::CdkMeltTokenTransportResult {
                crate::cashu_cdk_helper::CdkMeltTokenTransportResult::Failed {
                    reason: "melt not used in this test".into(),
                }
            }
        }

        let mock = Arc::new(MockCdkQuote {
            saw_storage: Mutex::new(None),
        });
        let backend = Nut04MintCashu::with_cdk_helper(
            Some("https://mint.example/Bitcoin".into()),
            Arc::new(MockHttpNever),
            Some(mock.clone()),
        );
        let mn = import_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        match backend
            .request_mint_invoice_with_seed(Some(50), &mn, "pp")
            .unwrap()
        {
            MintQuoteOutcome::Invoice { bolt11, quote_id } => {
                assert_eq!(quote_id, "q-helper");
                assert_eq!(bolt11, "lnbc1helperscope");
            }
            other => panic!("expected helper Invoice: {other:?}"),
        }
        let storage = mock.saw_storage.lock().unwrap().clone().unwrap();
        assert!(storage.is_absolute(), "{storage:?}");
        // complete_mint uses same scoped dir for same phrase+passphrase.
        let expected = backend.scoped_storage_for_seed(&mn, "pp");
        assert_eq!(storage, expected);
    }

    #[test]
    fn parse_mint_quote_state_and_mint_response() {
        let status_url =
            mint_quote_bolt11_status_url("https://mint.example/Bitcoin/", "q-abc").unwrap();
        assert_eq!(
            status_url,
            "https://mint.example/Bitcoin/v1/mint/quote/bolt11/q-abc"
        );
        assert!(mint_quote_bolt11_status_url("https://m/", "../x").is_err());
        assert!(mint_quote_bolt11_status_url("https://m/", "").is_err());

        let body = r#"{
            "quote":"q-abc",
            "state":"PAID",
            "amount":21,
            "expiry":9999999999
        }"#;
        let st = parse_mint_quote_state_response(body).unwrap();
        assert_eq!(st.quote_id, "q-abc");
        assert!(mint_quote_state_is_mintable(&st.state));
        assert!(!mint_quote_state_is_issued(&st.state));

        let unpaid = r#"{"quote":"q","state":"UNPAID"}"#;
        let u = parse_mint_quote_state_response(unpaid).unwrap();
        assert!(!mint_quote_state_is_mintable(&u.state));

        let issued = r#"{"quote":"q","state":"ISSUED"}"#;
        assert!(mint_quote_state_is_issued(
            &parse_mint_quote_state_response(issued).unwrap().state
        ));

        assert!(parse_mint_quote_state_response(r#"{"quote":"q"}"#).is_err());

        let mint_url = mint_bolt11_url("https://mint.example/Bitcoin").unwrap();
        assert_eq!(mint_url, "https://mint.example/Bitcoin/v1/mint/bolt11");

        let sigs = r#"{
            "signatures":[
                {"amount":1,"id":"00ab","C_":"02abc"},
                {"amount":2,"id":"00ab","C":"03def"}
            ]
        }"#;
        let m = parse_mint_bolt11_response(sigs).unwrap();
        assert_eq!(m.signatures.len(), 2);
        assert_eq!(m.signatures[0].amount_sats, Some(1));
        assert_eq!(m.signatures[0].c.as_deref(), Some("02abc"));
        assert!(parse_mint_bolt11_response(r#"{"signatures":[]}"#).is_err());
        assert!(parse_mint_bolt11_response(r#"{}"#).is_err());
    }

    #[test]
    fn parse_cashu_token() {
        let t = CashuToken::parse("cashuAabcdefghijklmnopqrstuvwxyz").unwrap();
        assert!(t.expose().starts_with("cashuA"));
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(dbg.contains("cashuA"));
    }

    #[test]
    fn reject_non_cashu() {
        assert!(CashuToken::parse("sk-not-a-token").is_err());
        assert!(CashuToken::parse("cashuAshort").is_err());
    }

    #[test]
    fn funding_step_user_labels_are_stable() {
        assert_eq!(
            FundingStep::ShowAddress.user_label(),
            "showing receive address"
        );
        assert_eq!(FundingStep::WatchingTx.user_label(), "watching transaction");
        // Must not look like Debug.
        assert!(
            !FundingStep::ShowAddress
                .user_label()
                .contains("ShowAddress")
        );
    }

    #[test]
    fn funding_wizard_happy_path() {
        let mut w = FundingWizard::new();
        assert_eq!(w.step, FundingStep::NeedWallet);
        w.mark_backup_confirmed_for_test();
        w.show_address("bc1q…").unwrap();
        w.watch_tx("txid").unwrap();
        w.set_confirmations(1).unwrap();
        assert_eq!(w.step, FundingStep::WatchingTx);
        w.set_confirmations(3).unwrap();
        assert_eq!(w.step, FundingStep::OpenChannel);
        w.channel_opened().unwrap();
        w.cashu_acquired().unwrap();
        assert_eq!(w.step, FundingStep::ReadyForInference);
        w.begin_refund().unwrap();
        assert_eq!(w.step, FundingStep::RefundOptional);
    }

    #[test]
    fn funding_wizard_invalid_skip() {
        let mut w = FundingWizard::new();
        assert!(w.watch_tx("x").is_err());
    }

    #[test]
    fn funding_wizard_show_address_requires_backup() {
        let mut w = FundingWizard::new();
        let err = w.show_address("bc1qtest").unwrap_err();
        assert!(matches!(err, WalletError::BackupNotConfirmed));
        assert_eq!(w.step, FundingStep::NeedWallet);
        assert!(w.receive_address.is_none());
    }

    #[test]
    fn funding_wizard_backup_gate_accept_and_reject() {
        use crate::mnemonic::generate_mnemonic;
        use crate::seed_vault::MnemonicBackupGate;

        let m = generate_mnemonic().unwrap();
        let mut gate = MnemonicBackupGate::new();
        let mut w = FundingWizard::new();

        // Unconfirmed gate rejected.
        assert!(matches!(
            w.show_address_with_backup_gate("bc1qtest", &gate)
                .unwrap_err(),
            WalletError::BackupNotConfirmed
        ));

        let _words = gate.show_once(&m).unwrap();
        // Shown but not re-entered yet.
        assert!(matches!(
            w.show_address_with_backup_gate("bc1qtest", &gate)
                .unwrap_err(),
            WalletError::BackupNotConfirmed
        ));

        // Wrong re-entry still blocked.
        assert!(gate.confirm_reentry("wrong words only").is_err());
        assert!(matches!(
            w.show_address_with_backup_gate("bc1qtest", &gate)
                .unwrap_err(),
            WalletError::BackupNotConfirmed
        ));

        gate.confirm_reentry(m.expose()).unwrap();
        w.show_address_with_backup_gate("bc1qaccepted", &gate)
            .unwrap();
        assert_eq!(w.step, FundingStep::ShowAddress);
        assert_eq!(w.receive_address.as_deref(), Some("bc1qaccepted"));
        assert!(w.backup_confirmed());
    }

    #[test]
    fn parse_balance_msats() {
        assert_eq!(
            parse_balance_msats_from_json(r#"{"msats": 1500000}"#),
            Some(1_500_000)
        );
        assert_eq!(
            parse_balance_msats_from_json(r#"{"data":{"sats":1000}}"#),
            Some(1_000_000)
        );
        // Bare `balance` is ambiguous; do not guess.
        assert_eq!(
            parse_balance_msats_from_json(r#"{"data":{"balance":1000}}"#),
            None
        );
        assert_eq!(parse_balance_msats_from_json("nope"), None);
    }
}
