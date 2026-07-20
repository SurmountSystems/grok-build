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

/// Product default when the user omits an amount (`docs.routstr.com` example).
///
/// API allows 1 sat; many Lightning wallets route small amounts poorly. Prefer
/// this for mainnet smoke unless the user overrides.
pub const ROUTSTR_INVOICE_DEFAULT_SATS: u64 = 1_000;

/// Suggested mainnet smoke top-up (same as default; documented for UX copy).
pub const ROUTSTR_MAINNET_SMOKE_SATS: u64 = ROUTSTR_INVOICE_DEFAULT_SATS;

/// Relative path on the Routstr node origin (not under `/v1`).
pub const ROUTSTR_LIGHTNING_INVOICE_PATH: &str = "/lightning/invoice";

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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

impl InvoiceStatusResponse {
    /// Whether the invoice is paid (case-insensitive `paid` / `complete` / `settled`).
    pub fn is_paid(&self) -> bool {
        matches!(
            self.status.trim().to_ascii_lowercase().as_str(),
            "paid" | "complete" | "completed" | "settled" | "success"
        )
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

/// Parse create response JSON. Rejects empty bolt11 (never invents).
pub fn parse_invoice_create_response(body: &str) -> Result<InvoiceCreateResponse, String> {
    let v: InvoiceCreateResponse =
        serde_json::from_str(body).map_err(|e| format!("invoice create JSON: {e}"))?;
    if v.invoice_id.trim().is_empty() {
        return Err("invoice create: empty invoice_id".into());
    }
    let bolt = v.bolt11.trim();
    if bolt.is_empty() {
        return Err("invoice create: empty bolt11".into());
    }
    if !bolt.to_ascii_lowercase().starts_with("ln") {
        return Err("invoice create: bolt11 must start with ln…".into());
    }
    Ok(InvoiceCreateResponse {
        invoice_id: v.invoice_id.trim().to_owned(),
        bolt11: bolt.to_owned(),
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
            lines.push(
                "QR feature not enabled in this build; copy the BOLT11 string.".to_owned(),
            );
        }
    }
    lines
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
    let display = crate::address_ux::onchain_payment_display(
        address,
        amount_sats,
        Some("Grok OSS Routstr"),
    );
    let mut lines = vec![
        "Receive address (Bitcoin, on-chain):".to_owned(),
        display.text.clone(),
        format!("BIP21: {}", display.qr_payload),
    ];
    if let Some(s) = amount_sats {
        lines.push(format!("Amount locked in BIP21: {s} sats."));
    } else {
        lines.push(
            "No amount in BIP21 (open amount). Pass an amount to encode sats in the QR."
                .to_owned(),
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
            lines.push(
                "QR feature not enabled in this build; copy the BIP21 URI.".to_owned(),
            );
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
    fn bip21_lines_with_amount() {
        let lines = bip21_receive_display_lines("bc1qexample", Some(1000), false);
        let j = lines.join("\n");
        assert!(j.contains("bitcoin:bc1qexample"));
        assert!(j.contains("amount="));
        assert!(j.contains("1000 sats"));
    }
}
