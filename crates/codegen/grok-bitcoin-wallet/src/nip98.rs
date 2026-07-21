//! NIP-98 HTTP Auth pure helpers (offline-proveable against the NIP).
//!
//! Builds and parses `Authorization: Nostr <base64(event-json)>` values using a
//! signed kind-27235 event (`u` absolute URL, `method`, optional `payload`
//! SHA-256 of the request body).
//!
//! # Product residual (Routstr)
//!
//! Live Routstr node auth (re-verified 2026-07-20: `Routstr/routstr-core`
//! `routstr/auth.py` `validate_bearer_key` + docs.routstr.com) remains
//! **Bearer `sk-` / `cashu…` only** (plus `x-cashu`). Provider discovery uses
//! Nostr (NIP-91); client HTTP is not NIP-98 today. These helpers prove the
//! **NIP-98 wire format** offline — they do **not** claim Routstr accepts Nostr
//! Authorization, and must not be wired into product login/inference until a
//! known offline-proveable Routstr contract exists.
//!
//! # Secrets
//!
//! Sign only from SeedVault-derived material held ephemerally (mnemonic →
//! [`crate::nip06::derive_nostr_identity`] or controlled secret expose). **Never**
//! store nsec/seed in CredentialsStore / `provider_credentials` / watch_session.
//! Temporary secret-hex copies are zeroized after `Keys` construction; `Keys`
//! itself is scoped to the signing call (nostr `SecretKey` Drop).

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use nostr::hashes::Hash;
use nostr::hashes::sha256::Hash as Sha256Hash;
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, TagStandard, Url};
use zeroize::Zeroize;

use crate::error::{Result, WalletError};
use crate::mnemonic::MnemonicSecret;
use crate::nip06::NostrIdentity;

/// NIP-98 HTTP methods accepted by the standard (and `nostr` crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nip98HttpMethod {
    Get,
    Post,
    Put,
    Patch,
}

impl Nip98HttpMethod {
    /// Canonical uppercase method string for the `method` tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
        }
    }
}

impl fmt::Display for Nip98HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Nip98HttpMethod {
    type Err = WalletError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "GET" | "get" | "Get" => Ok(Self::Get),
            "POST" | "post" | "Post" => Ok(Self::Post),
            "PUT" | "put" | "Put" => Ok(Self::Put),
            "PATCH" | "patch" | "Patch" => Ok(Self::Patch),
            other => Err(WalletError::Nip98(format!(
                "unknown HTTP method for NIP-98: {other}"
            ))),
        }
    }
}

impl From<Nip98HttpMethod> for HttpMethod {
    fn from(m: Nip98HttpMethod) -> Self {
        match m {
            Nip98HttpMethod::Get => HttpMethod::GET,
            Nip98HttpMethod::Post => HttpMethod::POST,
            Nip98HttpMethod::Put => HttpMethod::PUT,
            Nip98HttpMethod::Patch => HttpMethod::PATCH,
        }
    }
}

impl TryFrom<HttpMethod> for Nip98HttpMethod {
    type Error = WalletError;

    fn try_from(m: HttpMethod) -> Result<Self> {
        match m {
            HttpMethod::GET => Ok(Self::Get),
            HttpMethod::POST => Ok(Self::Post),
            HttpMethod::PUT => Ok(Self::Put),
            HttpMethod::PATCH => Ok(Self::Patch),
        }
    }
}

/// Parsed fields from a NIP-98 `Authorization` header **value** (`Nostr <base64>`).
///
/// Only returned from [`parse_nip98_authorization_header`] when the event fully
/// verifies (NIP-01 id + schnorr). Does not retain raw secret material. `Debug`
/// is safe to log (public event fields).
///
/// Callers that need freshness must also apply [`nip98_auth_is_fresh`] (or an
/// equivalent window) — parse does **not** invent a default TTL.
#[derive(Clone, PartialEq, Eq)]
pub struct Nip98AuthEvent {
    /// Event id hex.
    pub event_id: String,
    /// Author pubkey hex (x-only / Nostr hex).
    pub pubkey_hex: String,
    /// Event `created_at` unix seconds.
    pub created_at: u64,
    /// Must be 27235 ([`Kind::HttpAuth`]) for a valid NIP-98 event.
    pub kind: u16,
    /// Absolute request URL from the `u` tag.
    pub absolute_url: String,
    /// HTTP method from the `method` tag.
    pub method: Nip98HttpMethod,
    /// Optional hex SHA-256 of the request body (`payload` tag).
    pub payload_sha256_hex: Option<String>,
    /// Always `true` on the `Ok` path: full NIP-01 id + schnorr verified.
    /// Present so callers can assert the invariant without re-checking; parse
    /// **fail-closes** on invalid id/sig (returns `Err`, never soft-Ok).
    pub signature_valid: bool,
}

impl fmt::Debug for Nip98AuthEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nip98AuthEvent")
            .field("event_id", &self.event_id)
            .field("pubkey_hex", &self.pubkey_hex)
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("absolute_url", &self.absolute_url)
            .field("method", &self.method)
            .field("payload_sha256_hex", &self.payload_sha256_hex)
            .field("signature_valid", &self.signature_valid)
            .finish()
    }
}

/// Kind number for NIP-98 HTTP Auth events.
pub const NIP98_HTTP_AUTH_KIND: u16 = 27235;

/// Canonical scheme token for the Authorization header value (`Nostr <base64>`).
pub const NIP98_AUTHORIZATION_SCHEME: &str = "Nostr";

/// Lowercase scheme token accepted for interop (still requires following whitespace).
const NIP98_AUTHORIZATION_SCHEME_LOWER: &str = "nostr";

/// Construct ephemeral [`Keys`] from identity secret hex.
///
/// Copies secret hex into a temporary buffer, parses, then **zeroizes** the copy.
/// `Keys` is returned for immediate signing only; caller should drop it when done
/// (nostr `SecretKey` implements `Drop`). Never persists nsec.
fn keys_from_identity(identity: &NostrIdentity) -> Result<Keys> {
    let mut hex = identity.secret_key_hex().to_string();
    let parsed = Keys::parse(&hex).map_err(|e| {
        hex.zeroize();
        WalletError::Nip98(format!("keys from identity: {e}"))
    });
    hex.zeroize();
    parsed
}

fn http_data(absolute_url: &str, method: Nip98HttpMethod, body: Option<&[u8]>) -> Result<HttpData> {
    let url = Url::parse(absolute_url)
        .map_err(|e| WalletError::Nip98(format!("invalid absolute URL: {e}")))?;
    let mut data = HttpData::new(url, method.into());
    if let Some(bytes) = body {
        let hash = Sha256Hash::hash(bytes);
        data = data.payload(hash);
    }
    Ok(data)
}

/// Build the NIP-98 Authorization header **value**: `Nostr <base64(event-json)>`.
///
/// Sync / offline. Signs a kind-27235 event with tags `u`, `method`, and optional
/// `payload` (SHA-256 of `body`). Does not perform HTTP and does not claim any
/// remote server accepts the result.
///
/// # Secrets
///
/// Uses [`NostrIdentity::secret_key_hex`] only ephemerally (temp hex zeroized);
/// never persists nsec.
pub fn build_nip98_authorization_header(
    identity: &NostrIdentity,
    absolute_url: &str,
    method: Nip98HttpMethod,
    body: Option<&[u8]>,
) -> Result<String> {
    let keys = keys_from_identity(identity)?;
    let data = http_data(absolute_url, method, body)?;
    let event = EventBuilder::http_auth(data)
        .sign_with_keys(&keys)
        .map_err(|e| WalletError::Nip98(format!("sign http_auth event: {e}")))?;
    // `keys` drops here (end of scope after last use below would also work;
    // keep lifetime explicit by dropping after sign).
    drop(keys);
    let json = event
        .try_as_json()
        .map_err(|e| WalletError::Nip98(format!("event json: {e}")))?;
    let encoded = B64.encode(json.as_bytes());
    Ok(format!("{NIP98_AUTHORIZATION_SCHEME} {encoded}"))
}

/// Sign-on-unlock style: derive NIP-06 identity from mnemonic, then build header.
///
/// Ephemeral only — does not store identity, nsec, or seed.
pub fn build_nip98_authorization_from_mnemonic(
    mnemonic: &MnemonicSecret,
    passphrase: Option<&str>,
    absolute_url: &str,
    method: Nip98HttpMethod,
    body: Option<&[u8]>,
) -> Result<String> {
    let identity = crate::nip06::derive_nostr_identity(mnemonic, passphrase)?;
    build_nip98_authorization_header(&identity, absolute_url, method, body)
}

/// Convenience: phrase string → BIP-39 validate → NIP-98 header (ephemeral).
pub fn build_nip98_authorization_from_phrase(
    phrase: &str,
    passphrase: Option<&str>,
    absolute_url: &str,
    method: Nip98HttpMethod,
    body: Option<&[u8]>,
) -> Result<String> {
    let m = crate::mnemonic::import_mnemonic(phrase)?;
    build_nip98_authorization_from_mnemonic(&m, passphrase, absolute_url, method, body)
}

/// Hex SHA-256 of `body` (same digest as the optional NIP-98 `payload` tag).
pub fn nip98_payload_sha256_hex(body: &[u8]) -> String {
    Sha256Hash::hash(body).to_string()
}

/// True when the optional NIP-98 `payload` tag is consistent with `body`.
///
/// - **No `payload` tag** (`payload_sha256_hex` is `None`): **no body constraint**
///   — returns `true` for any `body` (including empty). The helper does **not**
///   require an empty body when the tag is absent.
/// - **Present `payload` tag**: hex must equal [`nip98_payload_sha256_hex`] of
///   `body` (case-insensitive).
///
/// Callers who need “request had no body” (and therefore must reject events that
/// *do* carry a `payload` tag) should use
/// [`nip98_auth_matches_request`]`(…, body: None)` — that path requires
/// `payload_sha256_hex.is_none()`.
///
/// Pure offline helper; not a product Routstr Success.
pub fn nip98_payload_matches(body: &[u8], payload_sha256_hex: Option<&str>) -> bool {
    match payload_sha256_hex {
        None => true, // no payload tag — no body constraint
        Some(hex) => hex.eq_ignore_ascii_case(&nip98_payload_sha256_hex(body)),
    }
}

/// Pure offline: whether a verified NIP-98 auth event matches an intended HTTP request.
///
/// Checks:
/// - [`Nip98AuthEvent::signature_valid`] is `true` (Ok-path invariant)
/// - kind is [`NIP98_HTTP_AUTH_KIND`]
/// - `method` equals the intended method
/// - absolute URL equals `absolute_url` (trailing `/` ignored on both sides)
/// - optional body digest via [`nip98_payload_matches`] when `body` is `Some`
/// - when `body` is `None`, requires **no** `payload` tag (request had no body)
///
/// Does **not** check event freshness — combine with [`nip98_auth_is_fresh`].
/// Does **not** claim any remote (including Routstr) accepts the header; product
/// live Routstr remains Bearer `sk-` / `cashu…` only (see module docs).
pub fn nip98_auth_matches_request(
    auth: &Nip98AuthEvent,
    absolute_url: &str,
    method: Nip98HttpMethod,
    body: Option<&[u8]>,
) -> bool {
    if !auth.signature_valid || auth.kind != NIP98_HTTP_AUTH_KIND {
        return false;
    }
    if auth.method != method {
        return false;
    }
    let left = auth.absolute_url.trim_end_matches('/');
    let right = absolute_url.trim_end_matches('/');
    if left != right {
        return false;
    }
    match body {
        None => auth.payload_sha256_hex.is_none(),
        Some(bytes) => nip98_payload_matches(bytes, auth.payload_sha256_hex.as_deref()),
    }
}

/// Convenience: [`nip98_auth_matches_request`] **and** [`nip98_auth_is_fresh`].
///
/// Pure offline request binding + TTL window. Still not a product Routstr Success.
pub fn nip98_auth_matches_request_fresh(
    auth: &Nip98AuthEvent,
    absolute_url: &str,
    method: Nip98HttpMethod,
    body: Option<&[u8]>,
    now_unix: u64,
    max_age_secs: u64,
) -> bool {
    nip98_auth_matches_request(auth, absolute_url, method, body)
        && nip98_auth_is_fresh(auth.created_at, now_unix, max_age_secs)
}

/// True when `created_at` is within `max_age_secs` of `now_unix` (either direction
/// skew is allowed via saturating abs diff).
///
/// Pure offline. NIP-98 recommends a short validity window; product callers **must**
/// enforce freshness — parse does not invent a default TTL.
///
/// Boundary: `diff == max_age_secs` is fresh; `diff > max_age_secs` is stale.
/// `max_age_secs == 0` accepts only exact `created_at == now_unix`.
pub fn nip98_auth_is_fresh(created_at: u64, now_unix: u64, max_age_secs: u64) -> bool {
    created_at.abs_diff(now_unix) <= max_age_secs
}

/// Shared scheme splitter for NIP-98 Authorization values.
///
/// Requires exact scheme token `Nostr` or `nostr` followed by **at least one**
/// ASCII whitespace character, then a non-empty base64 token (first
/// whitespace-delimited field). Rejects glued forms (`Nostrbase64…`), bare
/// scheme-only values, Bearer/sk-/cashu, and other schemes.
///
/// Single acceptance set used by both [`is_nip98_authorization_scheme`] and
/// [`parse_nip98_authorization_header`] (no dual independent parsers).
fn split_nostr_authorization_scheme(header_value: &str) -> Result<&str> {
    let trimmed = header_value.trim();
    let rest = if let Some(r) = trimmed.strip_prefix(NIP98_AUTHORIZATION_SCHEME) {
        r
    } else if let Some(r) = trimmed.strip_prefix(NIP98_AUTHORIZATION_SCHEME_LOWER) {
        r
    } else {
        return Err(WalletError::Nip98(format!(
            "Authorization value must start with '{NIP98_AUTHORIZATION_SCHEME} ' (scheme + whitespace), got prefix {:?}",
            trimmed.chars().take(16).collect::<String>()
        )));
    };

    // Require ASCII whitespace immediately after the scheme token (not glue).
    let first = rest.chars().next();
    match first {
        Some(c) if c.is_ascii_whitespace() => {}
        Some(_) => {
            return Err(WalletError::Nip98(
                "Nostr scheme must be followed by whitespace (glued scheme rejected)".into(),
            ));
        }
        None => {
            return Err(WalletError::Nip98(
                "missing base64 payload after Nostr scheme".into(),
            ));
        }
    }

    let rest = rest.trim_start();
    if rest.is_empty() {
        return Err(WalletError::Nip98(
            "missing base64 payload after Nostr scheme".into(),
        ));
    }
    // First whitespace-delimited token is the base64 blob.
    let token = rest.split_whitespace().next().unwrap_or(rest);
    if token.is_empty() {
        return Err(WalletError::Nip98("empty base64 payload".into()));
    }
    Ok(token)
}

fn event_to_parsed(event: &Event) -> Result<Nip98AuthEvent> {
    let kind_u16 = event.kind.as_u16();
    if event.kind != Kind::HttpAuth && kind_u16 != NIP98_HTTP_AUTH_KIND {
        return Err(WalletError::Nip98(format!(
            "expected kind {NIP98_HTTP_AUTH_KIND} (HTTP Auth), got {kind_u16}"
        )));
    }

    let data = parse_http_data_from_event(event)?;
    let method = Nip98HttpMethod::try_from(data.method)?;
    let payload_sha256_hex = data.payload.map(|h| h.to_string());

    // Fail closed: invalid id/sig → Err (never soft-Ok with signature_valid=false).
    event
        .verify()
        .map_err(|e| WalletError::Nip98(format!("NIP-01 event verification failed: {e}")))?;

    Ok(Nip98AuthEvent {
        event_id: event.id.to_hex(),
        pubkey_hex: event.pubkey.to_hex(),
        created_at: event.created_at.as_u64(),
        kind: kind_u16,
        absolute_url: data.url.to_string(),
        method,
        payload_sha256_hex,
        signature_valid: true,
    })
}

fn parse_http_data_from_event(event: &Event) -> Result<HttpData> {
    let mut url: Option<Url> = None;
    let mut method: Option<HttpMethod> = None;
    let mut payload: Option<Sha256Hash> = None;

    for tag in event.tags.iter() {
        match tag.as_standardized() {
            Some(TagStandard::AbsoluteURL(u)) => url = Some(u.clone()),
            Some(TagStandard::Method(m)) => method = Some(m.clone()),
            Some(TagStandard::Payload(p)) => payload = Some(*p),
            _ => {}
        }
    }

    let url = url.ok_or_else(|| WalletError::Nip98("missing u (url) tag".into()))?;
    let method = method.ok_or_else(|| WalletError::Nip98("missing method tag".into()))?;
    Ok(HttpData {
        url,
        method,
        payload,
    })
}

/// Parse a NIP-98 Authorization header **value** (`Nostr <base64>`).
///
/// Offline. Fail-closed:
/// - wrong scheme / glued scheme / empty payload → `Err`
/// - malformed base64 / non-event JSON → `Err`
/// - wrong kind / missing `u` or `method` tags → `Err`
/// - NIP-01 id or schnorr verification failure → `Err` (never soft-Ok)
///
/// On `Ok`, [`Nip98AuthEvent::signature_valid`] is always `true`. Does **not**
/// check event freshness — use [`nip98_auth_is_fresh`]. Does **not** compare body
/// digest — use [`nip98_payload_matches`].
pub fn parse_nip98_authorization_header(header_value: &str) -> Result<Nip98AuthEvent> {
    let b64 = split_nostr_authorization_scheme(header_value)?;
    let bytes = B64
        .decode(b64.as_bytes())
        .map_err(|e| WalletError::Nip98(format!("base64 decode: {e}")))?;
    let json = std::str::from_utf8(&bytes)
        .map_err(|e| WalletError::Nip98(format!("event json utf-8: {e}")))?;
    let event =
        Event::from_json(json).map_err(|e| WalletError::Nip98(format!("event json parse: {e}")))?;
    event_to_parsed(&event)
}

/// True when `header_value` uses the NIP-98 scheme (`Nostr`/`nostr` + whitespace).
///
/// Shares the exact acceptance set with [`parse_nip98_authorization_header`] via
/// [`split_nostr_authorization_scheme`]. Does not validate the event body — use
/// parse for full offline validation.
pub fn is_nip98_authorization_scheme(header_value: &str) -> bool {
    split_nostr_authorization_scheme(header_value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic::import_mnemonic;
    use crate::nip06::{NIP06_TEST_MNEMONIC, NIP06_TEST_SECRET_KEY_HEX, derive_nostr_identity};

    const SAMPLE_URL: &str = "https://api.example.com/v1/chat/completions";

    #[test]
    fn build_parse_roundtrip_vector_identity_get() {
        let m = import_mnemonic(NIP06_TEST_MNEMONIC).unwrap();
        let id = derive_nostr_identity(&m, None).unwrap();
        let header =
            build_nip98_authorization_header(&id, SAMPLE_URL, Nip98HttpMethod::Get, None).unwrap();

        assert!(header.starts_with("Nostr "));
        assert!(is_nip98_authorization_scheme(&header));
        assert!(!header.contains(NIP06_TEST_SECRET_KEY_HEX));
        assert!(!header.contains("nsec1"));

        let parsed = parse_nip98_authorization_header(&header).unwrap();
        assert_eq!(parsed.kind, NIP98_HTTP_AUTH_KIND);
        assert_eq!(parsed.absolute_url, SAMPLE_URL);
        assert_eq!(parsed.method, Nip98HttpMethod::Get);
        assert!(parsed.payload_sha256_hex.is_none());
        assert!(parsed.signature_valid, "Ok path always has signature_valid");
        // pubkey hex must match derived keys (temp hex for assert only)
        let mut hex = id.secret_key_hex().to_string();
        let keys = Keys::parse(&hex).unwrap();
        hex.zeroize();
        assert_eq!(parsed.pubkey_hex, keys.public_key().to_hex());
    }

    #[test]
    fn build_with_body_sets_payload_sha256() {
        let body = br#"{"model":"grok-4.5","messages":[]}"#;
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Post,
            Some(body),
        )
        .unwrap();
        let parsed = parse_nip98_authorization_header(&header).unwrap();
        assert_eq!(parsed.method, Nip98HttpMethod::Post);
        let expected = nip98_payload_sha256_hex(body);
        assert_eq!(
            parsed.payload_sha256_hex.as_deref(),
            Some(expected.as_str())
        );
        assert!(parsed.signature_valid);
        assert!(nip98_payload_matches(
            body,
            parsed.payload_sha256_hex.as_deref()
        ));
        assert!(!nip98_payload_matches(
            b"other-body",
            parsed.payload_sha256_hex.as_deref()
        ));
    }

    #[test]
    fn from_mnemonic_matches_from_identity() {
        let m = import_mnemonic(NIP06_TEST_MNEMONIC).unwrap();
        let id = derive_nostr_identity(&m, None).unwrap();
        // Two independent builds share same pubkey + tags shape (created_at may differ).
        let h1 =
            build_nip98_authorization_header(&id, SAMPLE_URL, Nip98HttpMethod::Put, Some(b"x"))
                .unwrap();
        let h2 = build_nip98_authorization_from_mnemonic(
            &m,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Put,
            Some(b"x"),
        )
        .unwrap();
        let p1 = parse_nip98_authorization_header(&h1).unwrap();
        let p2 = parse_nip98_authorization_header(&h2).unwrap();
        assert_eq!(p1.pubkey_hex, p2.pubkey_hex);
        assert_eq!(p1.absolute_url, p2.absolute_url);
        assert_eq!(p1.method, p2.method);
        assert_eq!(p1.payload_sha256_hex, p2.payload_sha256_hex);
        assert!(p1.signature_valid && p2.signature_valid);
    }

    #[test]
    fn reject_bearer_sk_and_cashu_schemes() {
        for bad in [
            "Bearer sk-abc",
            "bearer cashuAfoo",
            "sk-not-nostr",
            "cashuAeyJ",
            "",
            "Nostr",
            "Nostr ",
            "Basic abc",
        ] {
            let err = parse_nip98_authorization_header(bad).unwrap_err();
            match err {
                WalletError::Nip98(_) => {}
                other => panic!("expected Nip98 error for {bad:?}, got {other:?}"),
            }
            assert!(
                !is_nip98_authorization_scheme(bad),
                "predicate must agree with parse for {bad:?}"
            );
        }
    }

    #[test]
    fn scheme_requires_whitespace_shared_acceptance() {
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
        )
        .unwrap();
        let b64 = split_nostr_authorization_scheme(&header).unwrap();

        // Space (canonical)
        let space = format!("Nostr {b64}");
        assert!(is_nip98_authorization_scheme(&space));
        assert!(parse_nip98_authorization_header(&space).is_ok());

        // Tab after scheme
        let tab = format!("Nostr\t{b64}");
        assert!(is_nip98_authorization_scheme(&tab));
        assert!(parse_nip98_authorization_header(&tab).is_ok());

        // Lowercase scheme + space
        let lower = format!("nostr {b64}");
        assert!(is_nip98_authorization_scheme(&lower));
        assert!(parse_nip98_authorization_header(&lower).is_ok());

        // Lowercase scheme + tab
        let lower_tab = format!("nostr\t{b64}");
        assert!(is_nip98_authorization_scheme(&lower_tab));
        assert!(parse_nip98_authorization_header(&lower_tab).is_ok());

        // Glued scheme (no whitespace) — reject; predicate must agree with parse
        let glued = format!("Nostr{b64}");
        assert!(!is_nip98_authorization_scheme(&glued));
        assert!(matches!(
            parse_nip98_authorization_header(&glued),
            Err(WalletError::Nip98(_))
        ));
        let glued_lower = format!("nostr{b64}");
        assert!(!is_nip98_authorization_scheme(&glued_lower));
        assert!(matches!(
            parse_nip98_authorization_header(&glued_lower),
            Err(WalletError::Nip98(_))
        ));

        // Bare scheme
        assert!(!is_nip98_authorization_scheme("Nostr"));
        assert!(!is_nip98_authorization_scheme("nostr"));
        assert!(matches!(
            parse_nip98_authorization_header("Nostr"),
            Err(WalletError::Nip98(_))
        ));
    }

    #[test]
    fn reject_malformed_base64_and_non_event_json() {
        let bad_b64 = format!("{NIP98_AUTHORIZATION_SCHEME} !!!not-base64!!!");
        assert!(matches!(
            parse_nip98_authorization_header(&bad_b64),
            Err(WalletError::Nip98(_))
        ));

        let not_event = format!("{NIP98_AUTHORIZATION_SCHEME} {}", B64.encode(b"{\"hi\":1}"));
        assert!(matches!(
            parse_nip98_authorization_header(&not_event),
            Err(WalletError::Nip98(_))
        ));
    }

    #[test]
    fn reject_invalid_url_on_build() {
        let m = import_mnemonic(NIP06_TEST_MNEMONIC).unwrap();
        let id = derive_nostr_identity(&m, None).unwrap();
        let err = build_nip98_authorization_header(&id, "not a url", Nip98HttpMethod::Get, None)
            .unwrap_err();
        assert!(matches!(err, WalletError::Nip98(_)));
    }

    #[test]
    fn method_from_str_accepts_canonical() {
        assert_eq!(
            Nip98HttpMethod::from_str("POST").unwrap(),
            Nip98HttpMethod::Post
        );
        assert!(Nip98HttpMethod::from_str("DELETE").is_err());
    }

    #[test]
    fn debug_parsed_has_no_secret_hex() {
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
        )
        .unwrap();
        let parsed = parse_nip98_authorization_header(&header).unwrap();
        let dbg = format!("{parsed:?}");
        assert!(!dbg.contains(NIP06_TEST_SECRET_KEY_HEX));
        assert!(dbg.contains("Nip98AuthEvent"));
        assert!(dbg.contains("signature_valid"));
    }

    #[test]
    fn tampered_url_tag_fail_closed_err() {
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
        )
        .unwrap();
        // Decode event JSON and rewrite the absolute URL tag so the signed
        // id/tags no longer match — must be Err (fail closed), not soft Ok.
        let b64 = split_nostr_authorization_scheme(&header).unwrap();
        let bytes = B64.decode(b64.as_bytes()).unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        assert!(
            json.contains(SAMPLE_URL),
            "fixture header must embed sample URL"
        );
        let tampered_json = json.replace(SAMPLE_URL, "https://evil.example/v1/steal");
        assert_ne!(tampered_json, json);
        let corrupted = format!(
            "{NIP98_AUTHORIZATION_SCHEME} {}",
            B64.encode(tampered_json.as_bytes())
        );
        match parse_nip98_authorization_header(&corrupted) {
            Err(WalletError::Nip98(msg)) => {
                assert!(
                    msg.contains("verification") || msg.contains("NIP-01") || msg.contains("id"),
                    "tamper Err should name verification failure, got: {msg}"
                );
            }
            Ok(parsed) => panic!(
                "tampered URL must fail closed, got Ok(signature_valid={})",
                parsed.signature_valid
            ),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn truncated_base64_payload_is_error() {
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
        )
        .unwrap();
        let b64 = split_nostr_authorization_scheme(&header).unwrap();
        // Drop most of the payload so decode/parse fails.
        let short = &b64[..b64.len().min(8)];
        let bad = format!("{NIP98_AUTHORIZATION_SCHEME} {short}");
        assert!(matches!(
            parse_nip98_authorization_header(&bad),
            Err(WalletError::Nip98(_))
        ));
    }

    #[test]
    fn wrong_kind_event_is_error() {
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
        )
        .unwrap();
        let b64 = split_nostr_authorization_scheme(&header).unwrap();
        let bytes = B64.decode(b64.as_bytes()).unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        // Force kind away from 27235 while keeping other fields.
        let wrong_kind = json.replacen("\"kind\":27235", "\"kind\":1", 1);
        assert_ne!(wrong_kind, json, "fixture must contain kind 27235");
        let bad = format!(
            "{NIP98_AUTHORIZATION_SCHEME} {}",
            B64.encode(wrong_kind.as_bytes())
        );
        match parse_nip98_authorization_header(&bad) {
            Err(WalletError::Nip98(msg)) => {
                assert!(
                    msg.contains("27235") || msg.contains("kind") || msg.contains("verification"),
                    "wrong kind should fail, got: {msg}"
                );
            }
            Ok(_) => panic!("wrong kind must not parse as NIP-98 Success"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn missing_url_or_method_tags_is_error() {
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
        )
        .unwrap();
        let b64 = split_nostr_authorization_scheme(&header).unwrap();
        let bytes = B64.decode(b64.as_bytes()).unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();

        // Drop the u tag array entry (tags include ["u", url]).
        // Safer: empty tags array → missing u and method.
        // Parse as JSON, clear tags, re-serialize.
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        v["tags"] = serde_json::json!([]);
        let no_tags = v.to_string();
        let bad = format!(
            "{NIP98_AUTHORIZATION_SCHEME} {}",
            B64.encode(no_tags.as_bytes())
        );
        match parse_nip98_authorization_header(&bad) {
            Err(WalletError::Nip98(msg)) => {
                assert!(
                    msg.contains("missing")
                        || msg.contains("u")
                        || msg.contains("method")
                        || msg.contains("verification"),
                    "empty tags should fail, got: {msg}"
                );
            }
            Ok(_) => panic!("missing tags must not succeed"),
            Err(other) => panic!("unexpected: {other:?}"),
        }

        // Method only, no u
        let mut v2: serde_json::Value = serde_json::from_str(json).unwrap();
        v2["tags"] = serde_json::json!([["method", "GET"]]);
        let no_u = format!(
            "{NIP98_AUTHORIZATION_SCHEME} {}",
            B64.encode(v2.to_string().as_bytes())
        );
        assert!(matches!(
            parse_nip98_authorization_header(&no_u),
            Err(WalletError::Nip98(_))
        ));
    }

    #[test]
    fn freshness_boundaries() {
        let now = 1_700_000_000_u64;
        assert!(nip98_auth_is_fresh(now, now, 0));
        assert!(!nip98_auth_is_fresh(now.saturating_sub(1), now, 0));
        assert!(nip98_auth_is_fresh(now.saturating_sub(60), now, 60));
        assert!(!nip98_auth_is_fresh(now.saturating_sub(61), now, 60));
        // Future skew within window
        assert!(nip98_auth_is_fresh(now.saturating_add(30), now, 60));
        assert!(!nip98_auth_is_fresh(now.saturating_add(61), now, 60));
    }

    #[test]
    fn payload_matches_none_tag() {
        assert!(nip98_payload_matches(b"anything", None));
        assert!(nip98_payload_matches(b"", None));
        let hex = nip98_payload_sha256_hex(b"abc");
        assert!(nip98_payload_matches(b"abc", Some(&hex)));
        assert!(!nip98_payload_matches(b"abd", Some(&hex)));
    }

    #[test]
    fn auth_matches_request_url_method_body() {
        let body = br#"{"model":"grok-4.5"}"#;
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Post,
            Some(body),
        )
        .unwrap();
        let auth = parse_nip98_authorization_header(&header).unwrap();

        assert!(nip98_auth_matches_request(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Post,
            Some(body)
        ));
        // Trailing slash ignored on both sides
        assert!(nip98_auth_matches_request(
            &auth,
            &format!("{SAMPLE_URL}/"),
            Nip98HttpMethod::Post,
            Some(body)
        ));
        // Wrong method
        assert!(!nip98_auth_matches_request(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            Some(body)
        ));
        // Wrong URL
        assert!(!nip98_auth_matches_request(
            &auth,
            "https://evil.example/v1/chat/completions",
            Nip98HttpMethod::Post,
            Some(body)
        ));
        // Wrong body
        assert!(!nip98_auth_matches_request(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Post,
            Some(b"other")
        ));
        // body=None requires no payload tag — this event has payload
        assert!(!nip98_auth_matches_request(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Post,
            None
        ));
    }

    #[test]
    fn auth_matches_request_get_no_body_and_freshness() {
        let header = build_nip98_authorization_from_phrase(
            NIP06_TEST_MNEMONIC,
            None,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
        )
        .unwrap();
        let auth = parse_nip98_authorization_header(&header).unwrap();
        assert!(nip98_auth_matches_request(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None
        ));
        // Present body expectation with no payload tag still matches (optional tag)
        assert!(nip98_auth_matches_request(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            Some(b"ignored-when-no-payload-tag")
        ));

        let now = auth.created_at;
        assert!(nip98_auth_matches_request_fresh(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
            now,
            60
        ));
        assert!(!nip98_auth_matches_request_fresh(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
            now.saturating_add(120),
            60
        ));
        // Stale even when request fields match
        assert!(!nip98_auth_matches_request_fresh(
            &auth,
            SAMPLE_URL,
            Nip98HttpMethod::Get,
            None,
            now.saturating_add(61),
            60
        ));
    }
}
