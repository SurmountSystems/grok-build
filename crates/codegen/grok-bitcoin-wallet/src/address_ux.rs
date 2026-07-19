//! Payment display helpers: QR payload, clipboard text, BIP21, mempool.space URLs.
//!
//! See `docs/bitcoin-routstr/ADDRESS_UX.md`.

use std::fmt;

/// Bitcoin network for explorer URL selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BitcoinNetwork {
    #[default]
    Mainnet,
    Signet,
    Testnet,
    /// Testnet4 explorer path when used with mempool.space.
    Testnet4,
}

impl BitcoinNetwork {
    /// Parse from `GROK_BITCOIN_NETWORK` style strings.
    pub fn from_env_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "bitcoin" | "main" => Some(Self::Mainnet),
            "signet" => Some(Self::Signet),
            "testnet" | "testnet3" => Some(Self::Testnet),
            "testnet4" => Some(Self::Testnet4),
            _ => None,
        }
    }

    /// Canonical wire / env string for this network (for persistence).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Signet => "signet",
            Self::Testnet => "testnet",
            Self::Testnet4 => "testnet4",
        }
    }
}

/// Everything the UI needs to show a payment endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct PaymentDisplay {
    /// Human-visible primary string (address, bolt11, bip21, …).
    pub text: String,
    /// Payload encoded into the QR (often same as text; BIP21 URI when amount set).
    pub qr_payload: String,
    /// Preferred clipboard contents.
    pub clipboard: String,
}

impl fmt::Debug for PaymentDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentDisplay")
            .field("text_len", &self.text.len())
            .field("qr_payload_len", &self.qr_payload.len())
            .field("clipboard_len", &self.clipboard.len())
            .finish()
    }
}

impl PaymentDisplay {
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            qr_payload: text.clone(),
            clipboard: text.clone(),
            text,
        }
    }

    pub fn with_qr(mut self, qr: impl Into<String>) -> Self {
        self.qr_payload = qr.into();
        self
    }

    pub fn with_clipboard(mut self, clipboard: impl Into<String>) -> Self {
        self.clipboard = clipboard.into();
        self
    }
}

/// BIP21 URI: `bitcoin:<address>?amount=<btc>&label=…`
///
/// `amount_sats` is integer satoshis (formatted as BTC with fixed-scale math).
/// Omit amount when `None`.
pub fn bip21_uri(address: &str, amount_sats: Option<u64>, label: Option<&str>) -> String {
    let mut uri = format!("bitcoin:{address}");
    let mut params = Vec::new();
    if let Some(sats) = amount_sats {
        params.push(format!("amount={}", format_btc_from_sats(sats)));
    }
    if let Some(l) = label.filter(|l| !l.is_empty()) {
        params.push(format!("label={}", urlencoding_minimal(l)));
    }
    if !params.is_empty() {
        uri.push('?');
        uri.push_str(&params.join("&"));
    }
    uri
}

/// Format satoshis as a BIP21 BTC decimal without floating point.
fn format_btc_from_sats(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_s = format!("{frac:08}");
    while frac_s.ends_with('0') {
        frac_s.pop();
    }
    format!("{whole}.{frac_s}")
}

/// On-chain payment display (address +/- BIP21 amount).
pub fn onchain_payment_display(
    address: &str,
    amount_sats: Option<u64>,
    label: Option<&str>,
) -> PaymentDisplay {
    let uri = bip21_uri(address, amount_sats, label);
    if amount_sats.is_some() {
        PaymentDisplay::new(uri.clone())
            .with_qr(uri.clone())
            .with_clipboard(uri)
    } else {
        PaymentDisplay::new(address.to_owned())
            .with_qr(uri)
            .with_clipboard(address.to_owned())
    }
}

/// BOLT11 invoice display.
pub fn bolt11_payment_display(bolt11: &str) -> PaymentDisplay {
    PaymentDisplay::new(bolt11.to_owned())
}

/// Minimal percent-encoding for BIP21 labels (space → %20, reserve URI chars).
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// mempool.space base for a network.
pub fn mempool_base_url(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Mainnet => "https://mempool.space",
        BitcoinNetwork::Signet => "https://mempool.space/signet",
        BitcoinNetwork::Testnet => "https://mempool.space/testnet",
        BitcoinNetwork::Testnet4 => "https://mempool.space/testnet4",
    }
}

/// Explorer URL for an address.
pub fn mempool_address_url(network: BitcoinNetwork, address: &str) -> String {
    format!("{}/address/{address}", mempool_base_url(network))
}

/// Explorer URL for a transaction id.
pub fn mempool_txid_url(network: BitcoinNetwork, txid: &str) -> String {
    format!("{}/tx/{txid}", mempool_base_url(network))
}

/// ASCII/Unicode QR matrix as lines (for tests / narrow TUI). Feature `qr`.
#[cfg(feature = "qr")]
pub fn qr_matrix_lines(payload: &str) -> Result<Vec<String>, String> {
    use qrcode::render::unicode;
    use qrcode::{EcLevel, QrCode};

    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| e.to_string())?;
    let rendered = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build();
    Ok(rendered.lines().map(str::to_owned).collect())
}

/// Compact string QR (module grid with `#` / space). Stable for unit tests.
#[cfg(feature = "qr")]
pub fn qr_ascii(payload: &str) -> Result<String, String> {
    use qrcode::{EcLevel, QrCode};

    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .map_err(|e| e.to_string())?;
    let width = code.width();
    let mut out = String::new();
    for y in 0..width {
        for x in 0..width {
            out.push(if code[(x, y)] == qrcode::Color::Dark {
                '#'
            } else {
                ' '
            });
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip21_address_only() {
        let u = bip21_uri("bc1qexample", None, None);
        assert_eq!(u, "bitcoin:bc1qexample");
    }

    #[test]
    fn bip21_with_amount_and_label() {
        // 100_000 sats = 0.001 BTC
        let u = bip21_uri("bc1qabc", Some(100_000), Some("Grok OSS Routstr"));
        assert!(u.starts_with("bitcoin:bc1qabc?"));
        assert!(u.contains("amount=0.001"));
        assert!(u.contains("label=Grok%20OSS%20Routstr"));
    }

    #[test]
    fn format_btc_from_sats_no_float() {
        assert_eq!(format_btc_from_sats(0), "0");
        assert_eq!(format_btc_from_sats(100_000_000), "1");
        assert_eq!(format_btc_from_sats(100_000), "0.001");
        assert_eq!(format_btc_from_sats(1), "0.00000001");
    }

    #[test]
    fn onchain_display_uses_bip21_qr_when_amount() {
        let d = onchain_payment_display("bc1qabc", Some(1_000_000), Some("x"));
        assert!(d.qr_payload.contains("amount="));
        assert_eq!(d.clipboard, d.qr_payload);
    }

    #[test]
    fn onchain_display_address_clipboard_without_amount() {
        let d = onchain_payment_display("bc1qabc", None, None);
        assert_eq!(d.text, "bc1qabc");
        assert_eq!(d.clipboard, "bc1qabc");
        assert_eq!(d.qr_payload, "bitcoin:bc1qabc");
    }

    #[test]
    fn mempool_urls_mainnet() {
        assert_eq!(
            mempool_address_url(BitcoinNetwork::Mainnet, "bc1qxyz"),
            "https://mempool.space/address/bc1qxyz"
        );
        assert_eq!(
            mempool_txid_url(BitcoinNetwork::Mainnet, "abcd"),
            "https://mempool.space/tx/abcd"
        );
    }

    #[test]
    fn mempool_urls_signet_testnet() {
        assert!(
            mempool_address_url(BitcoinNetwork::Signet, "tb1q")
                .starts_with("https://mempool.space/signet/address/")
        );
        assert!(mempool_txid_url(BitcoinNetwork::Testnet, "ff").contains("/testnet/tx/"));
    }

    #[test]
    fn network_from_env_str() {
        assert_eq!(
            BitcoinNetwork::from_env_str("signet"),
            Some(BitcoinNetwork::Signet)
        );
        assert_eq!(BitcoinNetwork::from_env_str("nope"), None);
    }

    #[cfg(feature = "qr")]
    #[test]
    fn qr_ascii_nonempty_for_address() {
        let q = qr_ascii("bc1qexamplepaymentaddress000000000000000").expect("qr");
        assert!(q.contains('#'));
        assert!(q.lines().count() > 10);
    }

    #[test]
    fn payment_display_debug_omits_full_text() {
        let d = PaymentDisplay::new("lnbc1secretinvoicepayload");
        let s = format!("{d:?}");
        assert!(!s.contains("lnbc1secret"));
        assert!(s.contains("text_len"));
    }
}
