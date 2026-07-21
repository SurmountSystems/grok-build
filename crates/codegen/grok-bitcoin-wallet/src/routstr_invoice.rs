//! Routstr node Lightning invoice create/status (pure parse + display).
//!
//! Live HTTP lives in the shell (`xai-grok-shell` auth/routstr). This module
//! holds OpenAPI-aligned types, amount bounds, and honest display helpers so
//! stubs never invent a BOLT11.
//!
//! Confirmed against live `https://api.routstr.com/openapi.json` (2026-07-19):
//! - `POST /lightning/invoice` body: `amount_sats` (1..=1_000_000), `purpose`
//!   `create` | `topup`
//! - Response: `invoice_id`, `bolt11`, `amount_sats`, `expires_at`, `payment_hash`
//! - `GET /lightning/invoice/{id}/status` → `status`, optional `api_key` when paid

use serde::{Deserialize, Serialize};

use crate::address_ux::{PaymentDisplay, bolt11_payment_display};

/// OpenAPI exclusive minimum is 0 → valid amounts start at **1 sat**.
pub const ROUTSTR_INVOICE_MIN_SATS: u64 = 1;

/// OpenAPI maximum for `amount_sats`.
pub const ROUTSTR_INVOICE_MAX_SATS: u64 = 1_000_000;

/// Product default when the user omits an amount (OpenAPI / smoke example).
///
/// API allows 1 sat; many Lightning wallets route small amounts poorly. Prefer
/// this for mainnet smoke unless the user overrides.
pub const ROUTSTR_INVOICE_DEFAULT_SATS: u64 = 1_000;

/// Suggested mainnet smoke top-up (same as default; documented for UX copy).
pub const ROUTSTR_MAINNET_SMOKE_SATS: u64 = ROUTSTR_INVOICE_DEFAULT_SATS;

/// Relative path on the Routstr node origin (not under `/v1`).
pub const ROUTSTR_LIGHTNING_INVOICE_PATH: &str = "/lightning/invoice";

/// Relative path for `POST /lightning/recover` (BOLT11 → status).
pub const ROUTSTR_LIGHTNING_RECOVER_PATH: &str = "/lightning/recover";

/// Max accepted invoice id length for path interpolation (defensive).
pub const ROUTSTR_INVOICE_ID_MAX_LEN: usize = 128;

/// Validate amount against live OpenAPI bounds.
pub fn validate_invoice_amount_sats(amount_sats: u64) -> Result<u64, String> {
    if amount_sats < ROUTSTR_INVOICE_MIN_SATS {
        return Err(format!(
            "amount_sats must be >= {ROUTSTR_INVOICE_MIN_SATS} (OpenAPI exclusiveMinimum 0; live API rejects 0)"
        ));
    }
    if amount_sats > ROUTSTR_INVOICE_MAX_SATS {
        return Err(format!(
            "amount_sats must be <= {ROUTSTR_INVOICE_MAX_SATS} (OpenAPI maximum)"
        ));
    }
    Ok(amount_sats)
}

/// Resolve CLI/TUI optional amount: default smoke size when `None`.
pub fn resolve_topup_amount_sats(requested: Option<u64>) -> Result<u64, String> {
    validate_invoice_amount_sats(requested.unwrap_or(ROUTSTR_INVOICE_DEFAULT_SATS))
}

/// Validate invoice id for URL path segments (charset + non-empty + max len).
///
/// Rejects empty, oversized, or characters outside `[A-Za-z0-9._-]`.
pub fn validate_invoice_id(invoice_id: &str) -> Result<&str, String> {
    let id = invoice_id.trim();
    if id.is_empty() {
        return Err("invoice id must not be empty".into());
    }
    if id.len() > ROUTSTR_INVOICE_ID_MAX_LEN {
        return Err(format!(
            "invoice id too long (max {ROUTSTR_INVOICE_ID_MAX_LEN} chars)"
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err("invoice id must contain only ASCII alphanumeric, '-', '_', or '.'".into());
    }
    Ok(id)
}

/// True if `s` looks like a BOLT11 invoice (not LNURL / bare `ln…`).
///
/// Accepts common BOLT11 HRP prefixes (`lnbc`, `lntb`, `lnbcrt`, `lntbs`,
/// `lnsb`, `lnbs`). Explicitly rejects `lnurl…` (also starts with `ln`).
pub fn looks_like_bolt11(s: &str) -> bool {
    let b = s.trim().to_ascii_lowercase();
    if b.is_empty() || b.len() > 4096 {
        return false;
    }
    if b.starts_with("lnurl") {
        return false;
    }
    // BOLT11 HRP: `ln` + currency (bc / tb / bcrt / tbs / sb / bs …).
    b.starts_with("lnbc")
        || b.starts_with("lntb")
        || b.starts_with("lnbcrt")
        || b.starts_with("lntbs")
        || b.starts_with("lnsb")
        || b.starts_with("lnbs")
}

/// Validate a BOLT11 string for recover / display (non-empty, real BOLT11 HRP).
pub fn validate_bolt11(bolt11: &str) -> Result<&str, String> {
    let b = bolt11.trim();
    if b.is_empty() {
        return Err("bolt11 must not be empty".into());
    }
    if !looks_like_bolt11(b) {
        return Err(
            "bolt11 must be a Lightning invoice (lnbc…/lntb…/…), not lnurl or other ln…".into(),
        );
    }
    // Defensive size cap (BOLT11 is typically < 2k chars).
    if b.len() > 4096 {
        return Err("bolt11 too long".into());
    }
    Ok(b)
}

/// Request body for `POST /lightning/recover`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvoiceRecoverRequest {
    pub bolt11: String,
}

/// Build recover request JSON after bolt11 validation.
pub fn invoice_recover_request_json(bolt11: &str) -> Result<String, String> {
    let bolt11 = validate_bolt11(bolt11)?.to_owned();
    let req = InvoiceRecoverRequest { bolt11 };
    serde_json::to_string(&req).map_err(|e| format!("serialize recover request: {e}"))
}

/// Build status URL path segment after id validation (no origin).
pub fn invoice_status_path(invoice_id: &str) -> Result<String, String> {
    let id = validate_invoice_id(invoice_id)?;
    Ok(format!("{ROUTSTR_LIGHTNING_INVOICE_PATH}/{id}/status"))
}

/// Invoice purpose for create vs top-up of an existing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvoicePurpose {
    Create,
    Topup,
}

impl InvoicePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Topup => "topup",
        }
    }
}

/// Request body for `POST /lightning/invoice`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvoiceCreateRequest {
    pub amount_sats: u64,
    pub purpose: InvoicePurpose,
}

/// Success body for `POST /lightning/invoice`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InvoiceCreateResponse {
    pub invoice_id: String,
    pub bolt11: String,
    pub amount_sats: u64,
    pub expires_at: i64,
    pub payment_hash: String,
}

/// Status body for `GET /lightning/invoice/{id}/status`.
///
/// Custom [`Debug`]: `api_key` is redacted so `{:?}` never dumps a paid `sk-`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct InvoiceStatusResponse {
    pub status: String,
    #[serde(default)]
    pub api_key: Option<String>,
    pub amount_sats: u64,
    #[serde(default)]
    pub paid_at: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
}

impl std::fmt::Debug for InvoiceStatusResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvoiceStatusResponse")
            .field("status", &self.status)
            .field("api_key", &self.api_key.as_ref().map(|_| "***"))
            .field("amount_sats", &self.amount_sats)
            .field("paid_at", &self.paid_at)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Whether a status string is a terminal unpaid outcome (stop polling).
pub fn is_terminal_unpaid_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "expired" | "cancelled" | "canceled" | "failed" | "fail" | "rejected"
    )
}

impl InvoiceStatusResponse {
    /// Whether the invoice is paid (case-insensitive `paid` / `complete` / `settled`).
    pub fn is_paid(&self) -> bool {
        matches!(
            self.status.trim().to_ascii_lowercase().as_str(),
            "paid" | "complete" | "completed" | "settled" | "success"
        )
    }

    /// Terminal unpaid statuses that should stop background poll.
    pub fn is_terminal_unpaid(&self) -> bool {
        !self.is_paid() && is_terminal_unpaid_status(&self.status)
    }

    /// Whether `expires_at` is in the past (unix seconds) and still unpaid.
    ///
    /// `expires_at <= 0` is treated as unknown (not expired by wall clock).
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        !self.is_paid() && self.expires_at > 0 && now_unix >= self.expires_at
    }

    /// Non-empty API key from a paid invoice (`sk-…` expected).
    pub fn api_key_if_paid(&self) -> Option<&str> {
        if !self.is_paid() {
            return None;
        }
        self.api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
    }
}

/// Parse create response JSON. Rejects empty / malformed id and bolt11.
pub fn parse_invoice_create_response(body: &str) -> Result<InvoiceCreateResponse, String> {
    let v: InvoiceCreateResponse =
        serde_json::from_str(body).map_err(|e| format!("invoice create JSON: {e}"))?;
    let invoice_id = validate_invoice_id(&v.invoice_id)
        .map_err(|e| format!("invoice create: {e}"))?
        .to_owned();
    let bolt11 = validate_bolt11(&v.bolt11)
        .map_err(|e| format!("invoice create: {e}"))?
        .to_owned();
    Ok(InvoiceCreateResponse {
        invoice_id,
        bolt11,
        amount_sats: v.amount_sats,
        expires_at: v.expires_at,
        payment_hash: v.payment_hash,
    })
}

/// Parse status response JSON.
pub fn parse_invoice_status_response(body: &str) -> Result<InvoiceStatusResponse, String> {
    serde_json::from_str(body).map_err(|e| format!("invoice status JSON: {e}"))
}

/// Build create request JSON bytes after amount validation.
pub fn invoice_create_request_json(
    amount_sats: u64,
    purpose: InvoicePurpose,
) -> Result<String, String> {
    let amount_sats = validate_invoice_amount_sats(amount_sats)?;
    let req = InvoiceCreateRequest {
        amount_sats,
        purpose,
    };
    serde_json::to_string(&req).map_err(|e| format!("serialize invoice request: {e}"))
}

/// Payment display for a live BOLT11 (QR payload = invoice string).
pub fn bolt11_invoice_payment_display(bolt11: &str) -> PaymentDisplay {
    bolt11_payment_display(bolt11.trim())
}

/// Optional BIP21-style `lightning:` URI (some wallets). QR defaults to raw bolt11.
pub fn lightning_uri(bolt11: &str) -> String {
    let b = bolt11.trim();
    if b.to_ascii_lowercase().starts_with("lightning:") {
        b.to_owned()
    } else {
        format!("lightning:{b}")
    }
}

/// CLI/TUI lines after a successful live invoice create.
///
/// Does **not** claim payment or store a key. Never fabricates bolt11.
pub fn live_invoice_display_lines(
    created: &InvoiceCreateResponse,
    include_qr: bool,
) -> Vec<String> {
    let display = bolt11_invoice_payment_display(&created.bolt11);
    let mut lines = vec![
        "Routstr top up: Lightning invoice ready (mainnet Routstr node).".to_owned(),
        format!("Amount: {} sats.", created.amount_sats),
        format!("Invoice id: {}", created.invoice_id),
        format!("BOLT11: {}", display.text),
        format!("lightning: URI: {}", lightning_uri(&created.bolt11)),
        "Scan the QR with a Lightning wallet (Phoenix, Zeus, Wallet of Satoshi, …), \
         or paste the BOLT11."
            .to_owned(),
        "After payment, re-run `grok routstr topup --status <invoice_id>` (or wait if \
         this command is polling) then `grok routstr balance`."
            .to_owned(),
        format!(
            "API bounds: {ROUTSTR_INVOICE_MIN_SATS}..={ROUTSTR_INVOICE_MAX_SATS} sats \
             (default smoke {ROUTSTR_INVOICE_DEFAULT_SATS})."
        ),
        "Note: this is a Lightning invoice, not an on-chain BIP21 URI. For on-chain \
         deposit use `grok routstr fund` (BIP21 + QR)."
            .to_owned(),
    ];
    if include_qr {
        #[cfg(feature = "qr")]
        {
            match crate::address_ux::qr_matrix_lines(&display.qr_payload) {
                Ok(matrix) => {
                    lines.push(String::new());
                    lines.push("QR (scan with a Lightning wallet):".to_owned());
                    lines.extend(matrix);
                }
                Err(e) => lines.push(format!("QR unavailable: {e}")),
            }
        }
        #[cfg(not(feature = "qr"))]
        {
            lines.push("QR feature not enabled in this build; copy the BOLT11 string.".to_owned());
        }
    }
    lines
}

// ---------------------------------------------------------------------------
// GET /v1/info (node metadata + Cashu mints; optional peer/LSP hints)
// ---------------------------------------------------------------------------

/// Relative path for Routstr node info (under API origin that already includes `/v1`
/// when using the product base, or full `/v1/info` from host root).
pub const ROUTSTR_V1_INFO_PATH: &str = "/v1/info";

/// Parsed `GET /v1/info` body (flexible; live node returns additionalProperties).
///
/// Live shape (api.routstr.com, 2026-07-20): `name`, `description`, `version`,
/// `npub`, `mints` (Cashu mint URLs), `http_url`, `onion_url`,
/// `child_key_cost_msats`. **No** Lightning peer/LSP node id is published today;
/// optional peer fields are parsed when present for forward-compat channel wizard
/// residual — never invent peer connectivity success.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoutstrNodeInfo {
    pub name: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
    pub npub: Option<String>,
    /// Cashu mint base URLs recommended / accepted by this node.
    pub mints: Vec<String>,
    pub http_url: Option<String>,
    pub onion_url: Option<String>,
    pub child_key_cost_msats: Option<u64>,
    /// Optional LN peer pubkey / URI when a future node advertises one.
    pub peer_id: Option<String>,
    /// Optional LSP / peer connection URI (`nodeid@host:port` or similar).
    pub peer_uri: Option<String>,
    /// Optional LSP node id when distinct from [`Self::peer_id`].
    pub lsp_node_id: Option<String>,
}

impl RoutstrNodeInfo {
    /// First non-empty mint URL (product default when selecting a Cashu mint).
    pub fn primary_mint_url(&self) -> Option<&str> {
        self.mints.iter().map(|s| s.trim()).find(|s| !s.is_empty())
    }

    /// Best-effort channel wizard peer hint (uri preferred, then peer_id / lsp).
    ///
    /// Returns `None` when the live node does not advertise a peer (current
    /// api.routstr.com behavior). Callers must not claim a channel was opened.
    pub fn channel_peer_hint(&self) -> Option<&str> {
        self.peer_uri
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                self.peer_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| {
                self.lsp_node_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
    }
}

/// Parse `GET /v1/info` JSON into [`RoutstrNodeInfo`].
///
/// Accepts flexible field names for peer/LSP residual (`peer`, `peer_id`,
/// `node_id`, `ln_node_id`, `lsp`, `lsp_node_id`, `peer_uri`, `connection_uri`).
/// Invalid JSON → `Err`. Missing optional fields → empty / `None` (not invented).
pub fn parse_routstr_node_info(body: &str) -> Result<RoutstrNodeInfo, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("routstr /v1/info JSON: {e}"))?;
    if !v.is_object() {
        return Err("routstr /v1/info: expected JSON object".into());
    }

    let name = string_field(&v, &["name"]);
    let description = string_field(&v, &["description"]);
    let version = string_field(&v, &["version"]);
    let npub = string_field(&v, &["npub"]);
    let http_url = string_field(&v, &["http_url", "httpUrl", "url"]);
    let onion_url = string_field(&v, &["onion_url", "onionUrl"]);
    let child_key_cost_msats = u64_field(&v, &["child_key_cost_msats", "childKeyCostMsats"]);

    let mut mints = Vec::new();
    if let Some(arr) = v.get("mints").and_then(|x| x.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                mints.push(s.to_owned());
            } else if let Some(url) = item
                .get("url")
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                mints.push(url.to_owned());
            }
        }
    }

    let peer_id = string_field(
        &v,
        &[
            "peer_id",
            "peerId",
            "node_id",
            "nodeId",
            "ln_node_id",
            "lnNodeId",
            "pubkey",
            "node_pubkey",
        ],
    );
    let peer_uri = string_field(
        &v,
        &[
            "peer_uri",
            "peerUri",
            "connection_uri",
            "connectionUri",
            "ln_address",
            "lightning_address",
        ],
    );
    let lsp_node_id = string_field(&v, &["lsp_node_id", "lspNodeId", "lsp"]);
    // Nested `peer` / `lsp` objects (forward-compat).
    let peer_id = peer_id.or_else(|| {
        v.get("peer")
            .and_then(|p| string_field(p, &["id", "node_id", "pubkey", "nodeId"]))
    });
    let peer_uri = peer_uri.or_else(|| {
        v.get("peer")
            .and_then(|p| string_field(p, &["uri", "connection_uri", "address"]))
    });
    let lsp_node_id = lsp_node_id.or_else(|| {
        v.get("lsp")
            .and_then(|p| string_field(p, &["id", "node_id", "pubkey", "nodeId"]))
    });

    Ok(RoutstrNodeInfo {
        name,
        description,
        version,
        npub,
        mints,
        http_url,
        onion_url,
        child_key_cost_msats,
        peer_id,
        peer_uri,
        lsp_node_id,
    })
}

fn string_field(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v
            .get(*k)
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(s.to_owned());
        }
    }
    None
}

fn u64_field(v: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(n) = v.get(*k).and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_i64().and_then(|i| u64::try_from(i).ok()))
                .or_else(|| x.as_str()?.parse().ok())
        }) {
            return Some(n);
        }
    }
    None
}

/// On-chain BIP21 receive lines with optional amount (mainnet fund path).
///
/// BIP21 is **on-chain only** (`bitcoin:<addr>?amount=…`). Lightning top-up uses
/// [`live_invoice_display_lines`].
pub fn bip21_receive_display_lines(
    address: &str,
    amount_sats: Option<u64>,
    include_qr: bool,
) -> Vec<String> {
    let display =
        crate::address_ux::onchain_payment_display(address, amount_sats, Some("Grok OSS Routstr"));
    let mut lines = vec![
        "Receive address (Bitcoin, on-chain):".to_owned(),
        display.text.clone(),
        format!("BIP21: {}", display.qr_payload),
    ];
    if let Some(s) = amount_sats {
        lines.push(format!("Amount locked in BIP21: {s} sats."));
    } else {
        lines.push(
            "No amount in BIP21 (open amount). Pass an amount to encode sats in the QR.".to_owned(),
        );
    }
    lines.push(
        "QR encodes the BIP21 URI. Scan with a Bitcoin (on-chain) wallet — not Lightning."
            .to_owned(),
    );
    if include_qr {
        #[cfg(feature = "qr")]
        {
            match crate::address_ux::qr_matrix_lines(&display.qr_payload) {
                Ok(matrix) => {
                    lines.push(String::new());
                    lines.push("QR (scan with a Bitcoin wallet):".to_owned());
                    lines.extend(matrix);
                }
                Err(e) => lines.push(format!("QR unavailable: {e}")),
            }
        }
        #[cfg(not(feature = "qr"))]
        {
            lines.push("QR feature not enabled in this build; copy the BIP21 URI.".to_owned());
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_bounds() {
        assert!(validate_invoice_amount_sats(0).is_err());
        assert_eq!(validate_invoice_amount_sats(1).unwrap(), 1);
        assert_eq!(validate_invoice_amount_sats(1_000).unwrap(), 1_000);
        assert!(validate_invoice_amount_sats(1_000_001).is_err());
        assert_eq!(resolve_topup_amount_sats(None).unwrap(), 1_000);
    }

    #[test]
    fn parse_create_live_shape() {
        let body = r#"{
            "invoice_id": "abc",
            "bolt11": "lnbc10u1ptest",
            "amount_sats": 1000,
            "expires_at": 1784523933,
            "payment_hash": "ph"
        }"#;
        let c = parse_invoice_create_response(body).unwrap();
        assert_eq!(c.amount_sats, 1000);
        assert!(c.bolt11.starts_with("lnbc"));
        let lines = live_invoice_display_lines(&c, false);
        let j = lines.join("\n").to_ascii_lowercase();
        assert!(j.contains("lnbc10u1ptest"));
        assert!(j.contains("1000"));
        assert!(j.contains("lightning"));
        assert!(!j.contains("payment sent"));
    }

    #[test]
    fn parse_create_rejects_empty_bolt11() {
        let body = r#"{
            "invoice_id": "abc",
            "bolt11": "  ",
            "amount_sats": 1,
            "expires_at": 1,
            "payment_hash": "ph"
        }"#;
        assert!(parse_invoice_create_response(body).is_err());
    }

    #[test]
    fn parse_create_rejects_malformed_invoice_id() {
        for bad_id in ["id/with/slash", "id?q=1", "id#frag", &"a".repeat(129)] {
            let body = format!(
                r#"{{
                    "invoice_id": "{bad_id}",
                    "bolt11": "lnbc10u1p",
                    "amount_sats": 1,
                    "expires_at": 1,
                    "payment_hash": "ph"
                }}"#
            );
            assert!(
                parse_invoice_create_response(&body).is_err(),
                "expected reject for id={bad_id}"
            );
        }
    }

    #[test]
    fn parse_status_paid_key() {
        let body = r#"{
            "status": "paid",
            "api_key": "sk-testkey",
            "amount_sats": 1000,
            "paid_at": 1,
            "created_at": 0,
            "expires_at": 2
        }"#;
        let s = parse_invoice_status_response(body).unwrap();
        assert!(s.is_paid());
        assert_eq!(s.api_key_if_paid(), Some("sk-testkey"));
        // Debug must not dump the raw key.
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("sk-testkey"), "Debug leaked api_key: {dbg}");
        assert!(dbg.contains("***") || dbg.contains("api_key"), "{dbg}");
    }

    #[test]
    fn parse_status_pending_no_key() {
        let body = r#"{
            "status": "pending",
            "api_key": null,
            "amount_sats": 1,
            "paid_at": null,
            "created_at": 0,
            "expires_at": 2
        }"#;
        let s = parse_invoice_status_response(body).unwrap();
        assert!(!s.is_paid());
        assert!(s.api_key_if_paid().is_none());
        assert!(!s.is_terminal_unpaid());
    }

    #[test]
    fn terminal_unpaid_and_expires_at() {
        assert!(is_terminal_unpaid_status("expired"));
        assert!(is_terminal_unpaid_status("Cancelled"));
        assert!(!is_terminal_unpaid_status("pending"));
        let body = r#"{
            "status": "expired",
            "api_key": null,
            "amount_sats": 1,
            "paid_at": null,
            "created_at": 0,
            "expires_at": 100
        }"#;
        let s = parse_invoice_status_response(body).unwrap();
        assert!(s.is_terminal_unpaid());
        assert!(s.is_expired_at(100));
        assert!(s.is_expired_at(101));
        assert!(!s.is_expired_at(99));
    }

    #[test]
    fn request_json_purpose() {
        let j = invoice_create_request_json(100, InvoicePurpose::Create).unwrap();
        assert!(j.contains("\"amount_sats\":100"));
        assert!(j.contains("\"purpose\":\"create\""));
        let j2 = invoice_create_request_json(50, InvoicePurpose::Topup).unwrap();
        assert!(j2.contains("\"purpose\":\"topup\""));
    }

    #[test]
    fn validate_invoice_id_charset() {
        assert_eq!(validate_invoice_id("abc-123_XYZ.").unwrap(), "abc-123_XYZ.");
        assert!(validate_invoice_id("").is_err());
        assert!(validate_invoice_id("  ").is_err());
        assert!(validate_invoice_id("id/with/slash").is_err());
        assert!(validate_invoice_id("id?q=1").is_err());
        assert!(validate_invoice_id(&"a".repeat(129)).is_err());
        let path = invoice_status_path("inv-1").unwrap();
        assert_eq!(path, "/lightning/invoice/inv-1/status");
    }

    #[test]
    fn validate_bolt11_and_recover_json() {
        assert!(validate_bolt11("").is_err());
        assert!(validate_bolt11("not-an-invoice").is_err());
        assert!(
            validate_bolt11("lnurl1dp68gurn8ghj7").is_err(),
            "LNURL must not pass as BOLT11"
        );
        assert!(looks_like_bolt11("lnbc10u1ptest"));
        assert!(looks_like_bolt11("lntb1u1ptest"));
        assert!(!looks_like_bolt11("lnurl1dp68gurn8ghj7"));
        assert!(!looks_like_bolt11("lnxyz1fake"));
        assert_eq!(
            validate_bolt11("  lnbc10u1ptest  ").unwrap(),
            "lnbc10u1ptest"
        );
        let j = invoice_recover_request_json("lnbc10u1ptest").unwrap();
        assert!(j.contains("\"bolt11\":\"lnbc10u1ptest\""));
    }

    #[test]
    fn bip21_lines_with_amount() {
        let lines = bip21_receive_display_lines("bc1qexample", Some(1000), false);
        let j = lines.join("\n");
        assert!(j.contains("bitcoin:bc1qexample"));
        assert!(j.contains("amount="));
        assert!(j.contains("1000 sats"));
    }

    #[test]
    fn parse_routstr_v1_info_live_shape_mints_no_peer() {
        // Shape confirmed against live api.routstr.com/v1/info (2026-07-20).
        let body = r#"{
            "name":"A Routstr Node",
            "description":"First routstr node",
            "version":"0.4.4",
            "npub":"npub1jad47jpa96yafxf0vy3pfpuxvt3e2f996vrv2f4px7dwpjdseyrq2ezjnj",
            "mints":[
                "https://mint.minibits.cash/Bitcoin",
                "https://mint.cubabitcoin.org"
            ],
            "http_url":"https://api.routstr.com/",
            "onion_url":"http://example.onion",
            "child_key_cost_msats":1000
        }"#;
        let info = parse_routstr_node_info(body).unwrap();
        assert_eq!(info.name.as_deref(), Some("A Routstr Node"));
        assert_eq!(info.version.as_deref(), Some("0.4.4"));
        assert_eq!(info.mints.len(), 2);
        assert_eq!(
            info.primary_mint_url(),
            Some("https://mint.minibits.cash/Bitcoin")
        );
        assert_eq!(info.child_key_cost_msats, Some(1000));
        // Live node does not advertise LN peer/LSP — residual honesty.
        assert!(info.channel_peer_hint().is_none());
        assert!(info.peer_id.is_none());
        assert!(info.peer_uri.is_none());
        assert!(info.lsp_node_id.is_none());
    }

    #[test]
    fn parse_routstr_v1_info_optional_peer_lsp_fields() {
        let body = r#"{
            "name":"x",
            "mints":["https://mint.example/"],
            "peer_id":"02abc",
            "peer_uri":"02abc@lsp.example:9735",
            "lsp_node_id":"03def"
        }"#;
        let info = parse_routstr_node_info(body).unwrap();
        assert_eq!(info.channel_peer_hint(), Some("02abc@lsp.example:9735"));
        assert_eq!(info.peer_id.as_deref(), Some("02abc"));
        assert_eq!(info.lsp_node_id.as_deref(), Some("03def"));

        let nested = r#"{
            "mints":[],
            "peer":{"id":"02nested","uri":"02nested@h:1"},
            "lsp":{"node_id":"03lsp"}
        }"#;
        let n = parse_routstr_node_info(nested).unwrap();
        assert_eq!(n.channel_peer_hint(), Some("02nested@h:1"));
        assert_eq!(n.lsp_node_id.as_deref(), Some("03lsp"));
    }

    #[test]
    fn parse_routstr_v1_info_rejects_non_object() {
        assert!(parse_routstr_node_info("[]").is_err());
        assert!(parse_routstr_node_info("not-json").is_err());
    }
}
