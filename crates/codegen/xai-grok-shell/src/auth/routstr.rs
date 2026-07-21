//! Routstr provider helpers: constants, key load/store, login CLI, balance.
//!
//! Mirrors [`super::openrouter`] for the Bitcoin-native inference path.
//! Hot `sk-` / short-lived Cashu bearer strings may use [`CredentialsStore`];
//! BIP-39 seed material must **never** land here (see `grok-bitcoin-wallet`).
//!
//! # Auth residual (NIP-06 / NIP-98)
//!
//! Library NIP-06 derive is green (`grok_bitcoin_wallet::nip06` —
//! `derive_nostr_identity` from SeedVault mnemonic; official vectors; redacted
//! Debug; nsec only via controlled API). Pure NIP-98 Authorization header
//! build/parse + request-match helpers are green offline
//! (`grok_bitcoin_wallet::nip98`) against the NIP wire — **not** a product
//! Routstr success.
//!
//! **Re-verified 2026-07-20** against upstream `Routstr/routstr-core`
//! `routstr/auth.py` `validate_bearer_key` (+ docs.routstr.com): live client
//! HTTP accepts **Bearer `sk-…` / `cashu…` only** (also `x-cashu` for tokens).
//! Invalid-format errors name those two shapes only — no Nostr/NIP-98 path.
//! Nostr is used for provider discovery (NIP-91 / kind announcements), not
//! OpenAI-compatible API Authorization. Product login/store uses
//! [`classify_routstr_product_auth_material`] +
//! [`validate_routstr_product_bearer_key`] to accept only live Bearer shapes and
//! to **refuse** NIP-98 / nsec / BIP-39 into CredentialsStore (honest residual,
//! never invented signed-auth Success).

use std::io::{self, Write};
use std::path::Path;

use super::credentials_store::{BEARER_USERNAME, CredentialsStore, CredentialsStoreError};

/// Default Routstr OpenAI-compatible API base URL.
pub const ROUTSTR_API_URL: &str = "https://api.routstr.com/v1";

/// Routstr node origin (Lightning invoice paths are **not** under `/v1`).
pub const ROUTSTR_NODE_ORIGIN: &str = "https://api.routstr.com";

/// Environment variable for the Routstr API key (env wins over secret store).
///
/// May hold a single key or a comma-/newline-separated list; additional keys
/// are used as credit-exhaustion failover (see also [`ROUTSTR_API_KEYS_ENV`]).
pub const ROUTSTR_API_KEY_ENV: &str = "ROUTSTR_API_KEY";

/// Optional extra Routstr keys for multi-account credit failover.
/// Comma- or newline-separated. Merged after [`ROUTSTR_API_KEY_ENV`].
pub const ROUTSTR_API_KEYS_ENV: &str = "ROUTSTR_API_KEYS";

/// Catalog key shown in the model picker (separate from native xAI / OpenRouter).
pub const ROUTSTR_GROK_45_CATALOG_ID: &str = "routstr-grok-4.5";

/// Model slug sent to the Routstr API (OpenAI-compatible).
///
/// Confirmed against live `GET https://api.routstr.com/v1/models` (2026-07-18):
/// catalog entry `id: "grok-4.5"`, name `xAI: Grok 4.5`,
/// `canonical_slug: "x-ai/grok-4.5-20260708"`. The OpenAI-compatible request
/// model field uses the short `id` (`grok-4.5`), not the canonical slug.
/// Re-check with the `#[ignore]` live test when the catalog drifts.
pub const ROUTSTR_GROK_45_MODEL: &str = "grok-4.5";

/// Context window for Grok 4.5 on Routstr (aligned with other Grok 4.5 entries).
pub const ROUTSTR_GROK_45_CONTEXT_WINDOW: u64 = 500_000;

/// HTTP-Referer for Routstr logs / app attribution.
pub const ROUTSTR_HTTP_REFERER: &str = "https://github.com/SurmountSystems/grok-oss";

/// Display title for Routstr request attribution.
pub const ROUTSTR_X_TITLE: &str = "Grok OSS";

#[cfg(test)]
mod attribution_tests {
    use super::*;

    #[test]
    fn referer_is_surmount() {
        assert!(ROUTSTR_HTTP_REFERER.contains("SurmountSystems/grok-oss"));
    }

    #[test]
    fn model_slug_and_catalog() {
        assert_eq!(ROUTSTR_GROK_45_MODEL, "grok-4.5");
        assert_eq!(ROUTSTR_GROK_45_CATALOG_ID, "routstr-grok-4.5");
        assert_eq!(ROUTSTR_API_URL, "https://api.routstr.com/v1");
    }

    /// Live catalog check. Default CI stays offline-safe (`#[ignore]`).
    /// Run: `cargo test -p xai-grok-shell --lib live_routstr_grok_45_model_in_catalog -- --ignored`
    #[test]
    #[ignore = "network: live GET https://api.routstr.com/v1/models"]
    fn live_routstr_grok_45_model_in_catalog() {
        let url = format!("{ROUTSTR_API_URL}/models");
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("http client");
        let resp = client
            .get(&url)
            .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
            .header("X-Title", ROUTSTR_X_TITLE)
            .send()
            .expect("routstr /v1/models reachable");
        assert!(
            resp.status().is_success(),
            "models status {}",
            resp.status()
        );
        let body: serde_json::Value = resp.json().expect("models json");
        let items = body
            .get("data")
            .and_then(|d| d.as_array())
            .expect("data array");
        let found = items.iter().any(|m| {
            m.get("id")
                .and_then(|id| id.as_str())
                .is_some_and(|id| id == ROUTSTR_GROK_45_MODEL)
        });
        assert!(
            found,
            "ROUTSTR_GROK_45_MODEL={ROUTSTR_GROK_45_MODEL} missing from live catalog; update constant"
        );
    }
}

/// Whether `base_url` targets Routstr (host is `routstr.com` or a subdomain).
pub fn is_routstr_base_url(base_url: &str) -> bool {
    url::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .is_some_and(|host| host == "routstr.com" || host.ends_with(".routstr.com"))
}

/// Normalize the credential URL used as the store key.
pub fn routstr_credential_url(base_url: Option<&str>) -> String {
    let url = base_url.unwrap_or(ROUTSTR_API_URL).trim_end_matches('/');
    if url.is_empty() {
        ROUTSTR_API_URL.to_owned()
    } else {
        url.to_owned()
    }
}

/// Non-empty entries from `ROUTSTR_API_KEY` (comma/newline multi-key list).
///
/// Same splitter as inference failover. Callers that discard residual entries
/// must zeroize owned strings (seed-like material).
fn routstr_api_keys_from_env() -> Vec<String> {
    let Ok(raw) = std::env::var(ROUTSTR_API_KEY_ENV) else {
        return Vec::new();
    };
    crate::agent::config::split_api_key_list(&raw)
}

/// First non-empty `ROUTSTR_API_KEY` entry from the process environment.
///
/// Multi-key lists (comma / newline separated, same as inference failover): this
/// returns the **first** token only (may be residual). The **remainder** of the
/// list is always drained and [`zeroize_phrase`](grok_bitcoin_wallet::mnemonic::zeroize_phrase)d
/// so seed-like tails are not left to ordinary `String` Drop. Product Bearer
/// paths use [`live_routstr_api_key_from_env`], which prefers the **first live**
/// `sk-…` / `cashu…` entry so residual-first lists do not split-brain against
/// inference.
///
/// May be residual (NIP-98 / seed / Other). Product load/store paths use
/// [`live_routstr_api_key_from_env`] so residual env does not win over store
/// or block writing a live key. Callers that only need presence (no secret)
/// should prefer [`routstr_api_key_env_has_token`].
pub fn routstr_api_key_from_env() -> Option<String> {
    let mut keys = routstr_api_keys_from_env();
    if keys.is_empty() {
        return None;
    }
    let first = keys.remove(0);
    // Scrub unreturned multi-list tail (may be nsec / BIP-39 / residual).
    for rest in &mut keys {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(rest);
    }
    Some(first)
}

/// Whether `ROUTSTR_API_KEY` has any non-empty multi-list token.
///
/// Presence-only: splits, checks non-empty, then zeroizes every owned token.
/// Prefer this over [`routstr_api_key_from_env`].is_some() when the secret is
/// not needed (load residual fall-through, logout messaging, paid-store debug).
fn routstr_api_key_env_has_token() -> bool {
    let mut keys = routstr_api_keys_from_env();
    let any = !keys.is_empty();
    for k in &mut keys {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(k);
    }
    any
}

/// First **live** product Bearer shape (`sk-…` / `cashu…`) from `ROUTSTR_API_KEY`.
///
/// Scans the multi-key list in order; residual leading entries are skipped
/// (and zeroized) so a residual-first list with a later live key still loads
/// for balance/invoice/Authorization — aligned with inference filtering.
/// After a live hit, the **remainder** of the list is still drained and
/// zeroized (no early return leaves seed-like tails for ordinary Drop).
/// Pure residual lists return `None` (same fall-through policy as
/// [`load_routstr_api_key`]). Use this to decide env-over-store precedence and
/// whether store writes should be blocked.
pub fn live_routstr_api_key_from_env() -> Option<String> {
    let mut keys = routstr_api_keys_from_env();
    let mut found: Option<String> = None;
    for key in &mut keys {
        if found.is_none() {
            if let Ok(live) = validate_routstr_product_bearer_key(key) {
                found = Some(live.to_owned());
            }
        }
        // Always scrub every owned env token (accepted copy already taken when
        // live; residual never returned). Covers multi-list tails after early live.
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(key);
    }
    found
}

/// Load Routstr API key: env → Grok store (no Zed harness for Routstr).
///
/// Returns **only** live product Bearer material (`sk-…` / `cashu…`). Residual
/// shapes (NIP-98 / nsec / BIP-39 / other) from env or a legacy store entry are
/// treated as missing so product HTTP never transmits them as
/// `Authorization: Bearer`. Env-over-store precedence applies only when the env
/// list contains a live Bearer shape ([`live_routstr_api_key_from_env`]); pure
/// residual env falls through to a live store key.
pub fn load_routstr_api_key(
    store: &CredentialsStore,
) -> Result<Option<String>, CredentialsStoreError> {
    if let Some(live) = live_routstr_api_key_from_env() {
        return Ok(Some(live));
    }
    if routstr_api_key_env_has_token() {
        // Residual-only env list: do not send as Bearer; try store for a live key.
        // Presence-only helper zeroizes split tokens (no residual secret retained).
        tracing::debug!(
            "routstr key: {ROUTSTR_API_KEY_ENV} is set but has no live sk-/cashu shape; \
             not using it for product Authorization"
        );
    }
    let url = routstr_credential_url(None);
    if let Some((_, mut secret)) = store.read(&url)? {
        match validate_routstr_product_bearer_key(&secret) {
            Ok(live) => {
                let out = live.to_owned();
                // Scrub owned store secret after copy (live or residual path).
                grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut secret);
                return Ok(Some(out));
            }
            Err(_) => {
                // Legacy residual store entry — never re-transmit as Bearer.
                tracing::debug!(
                    "routstr key: store entry is not live sk-/cashu shape; treating as missing"
                );
                grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut secret);
                return Ok(None);
            }
        }
    }
    Ok(None)
}

/// Load Routstr API key using the default store under `$GROK_HOME`.
pub fn load_routstr_api_key_default() -> Result<Option<String>, CredentialsStoreError> {
    load_routstr_api_key(&CredentialsStore::default_store())
}

/// Whether any Routstr credential is available (env or Grok store).
pub fn has_routstr_api_key() -> bool {
    load_routstr_api_key_default().ok().flatten().is_some()
}

/// Store a Routstr API key.
///
/// Refuses with [`RoutstrAuthError::EnvVarSet`] only when `ROUTSTR_API_KEY` holds
/// a **live** Bearer shape ([`live_routstr_api_key_from_env`]) — residual env
/// (NIP-98 / seed / Other) does **not** block store, matching load fall-through
/// so a paid live `sk-` is not orphaned behind a residual env var.
///
/// Accepts only live product Bearer material ([`validate_routstr_product_bearer_key`]):
/// `sk-…` or `cashu…`. Refuses NIP-98 / nsec / BIP-39 / other (never CredentialsStore).
pub fn store_routstr_api_key(
    store: &CredentialsStore,
    api_key: &str,
) -> Result<(), RoutstrAuthError> {
    if let Some(mut live) = live_routstr_api_key_from_env() {
        // Presence check only — scrub the owned live copy after EnvVarSet decision.
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut live);
        return Err(RoutstrAuthError::EnvVarSet);
    }
    let key = validate_routstr_product_bearer_key(api_key)?;
    let url = routstr_credential_url(None);
    store
        .write(&url, BEARER_USERNAME, key)
        .map_err(RoutstrAuthError::Store)
}

/// Live product Routstr client HTTP does **not** accept NIP-98 Authorization.
///
/// Re-verified 2026-07-20 against upstream `Routstr/routstr-core`
/// `routstr/auth.py` `validate_bearer_key` (and docs.routstr.com authentication):
/// only accepts `sk-…` prepaid keys and `cashu…` tokens (plus `x-cashu` header
/// path). Invalid-format error text names those two shapes only — no Nostr /
/// NIP-98 branch. Pure library NIP-98 helpers remain offline-green but must not
/// be claimed as product Success until a known offline-proveable live contract
/// lands.
pub const ROUTSTR_PRODUCT_NIP98_AUTH_LIVE: bool = false;

/// Classification of material offered as a Routstr product credential / header.
///
/// Pure offline. Mirrors live routstr-core acceptance for Bearer shapes and
/// names residual classes (NIP-98, seed-like) that must **never** enter
/// CredentialsStore or product `Authorization: Bearer`. Does not perform HTTP
/// and does not invent auth Success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutstrProductAuthMaterial {
    /// Prepaid API key (`sk-…`) accepted by live `validate_bearer_key`.
    SkPrepaid,
    /// Cashu token (`cashu…` / `cashuA…` / `cashuB…`) accepted by live contract.
    CashuToken,
    /// NIP-98 `Nostr <base64>` Authorization — library green, **product residual**.
    Nip98Nostr,
    /// `nsec1…`, BIP-39 mnemonic, or 64-hex secret key material — never
    /// CredentialsStore / provider_credentials / product Bearer.
    SecretSeedLike,
    /// Empty / whitespace-only.
    Empty,
    /// Other non-empty string (not live Bearer shape; not named residual secrets).
    Other,
}

impl RoutstrProductAuthMaterial {
    /// True when live Routstr Bearer path accepts this kind (`sk-` or `cashu…`).
    pub fn accepted_by_live_bearer(self) -> bool {
        matches!(self, Self::SkPrepaid | Self::CashuToken)
    }
}

/// Classify a Routstr product credential or Authorization **value** (offline).
///
/// Detection order (fail closed toward residual / refuse) — matches runtime:
/// 1. empty → [`Empty`](RoutstrProductAuthMaterial::Empty)
/// 2. optional `Bearer `/`bearer ` wrapper stripped (so `Bearer Nostr …` is NIP-98)
/// 3. NIP-98 scheme (`Nostr`/`nostr` + payload, bare scheme, or glued scheme)
///    via [`grok_bitcoin_wallet::nip98::is_nip98_authorization_scheme`] + prefix
///    → [`Nip98Nostr`](RoutstrProductAuthMaterial::Nip98Nostr)
/// 4. `nsec1…` (bech32), valid BIP-39 word list, or 64-char hex secret →
///    [`SecretSeedLike`](RoutstrProductAuthMaterial::SecretSeedLike)
/// 5. `sk-…` → [`SkPrepaid`](RoutstrProductAuthMaterial::SkPrepaid)
/// 6. `cashu…` (case-sensitive prefix, matching routstr-core) →
///    [`CashuToken`](RoutstrProductAuthMaterial::CashuToken)
/// 7. else → [`Other`](RoutstrProductAuthMaterial::Other)
///
/// Never stores material. Never claims live NIP-98 Success
/// ([`ROUTSTR_PRODUCT_NIP98_AUTH_LIVE`] is `false`).
pub fn classify_routstr_product_auth_material(value: &str) -> RoutstrProductAuthMaterial {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return RoutstrProductAuthMaterial::Empty;
    }

    // Optional "Bearer " wrapper (OpenAI SDK style) — classify inner token.
    // Apply before scheme checks so `Bearer Nostr …` is residual NIP-98, not Other.
    let inner = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(trimmed);

    // NIP-98 Authorization value or residual scheme attempt (not live Bearer).
    if looks_like_nip98_authorization_attempt(inner) {
        return RoutstrProductAuthMaterial::Nip98Nostr;
    }

    // Seed-like: nsec (bech32), BIP-39 mnemonic, or raw 32-byte hex — never store/send.
    if inner.len() >= 5 && inner[..5].eq_ignore_ascii_case("nsec1") {
        return RoutstrProductAuthMaterial::SecretSeedLike;
    }
    if looks_like_bip39_mnemonic(inner) {
        return RoutstrProductAuthMaterial::SecretSeedLike;
    }
    if looks_like_hex_secret_key(inner) {
        return RoutstrProductAuthMaterial::SecretSeedLike;
    }

    // Live Bearer acceptance set (routstr-core validate_bearer_key).
    if inner.starts_with("sk-") && inner.len() > 3 {
        return RoutstrProductAuthMaterial::SkPrepaid;
    }
    if inner.starts_with("cashu") && inner.len() > 5 {
        return RoutstrProductAuthMaterial::CashuToken;
    }

    RoutstrProductAuthMaterial::Other
}

/// True for NIP-98 scheme values (valid or residual attempt): full
/// `Nostr <base64>`, bare `Nostr`, or glued `Nostr…` without requiring a
/// successful event parse (product residual refuse path).
fn looks_like_nip98_authorization_attempt(value: &str) -> bool {
    if grok_bitcoin_wallet::nip98::is_nip98_authorization_scheme(value) {
        return true;
    }
    // Bare scheme
    if value.eq_ignore_ascii_case("nostr") {
        return true;
    }
    // "Nostr " / "nostr\t" with empty or junk payload still residual
    if value.len() >= 5 && value[..5].eq_ignore_ascii_case("nostr") {
        let rest = &value[5..];
        // Scheme + whitespace (possibly empty payload) or glued non-empty body
        return rest.starts_with(|c: char| c.is_ascii_whitespace()) || !rest.is_empty();
    }
    false
}

/// True when `value` is a plausible English BIP-39 mnemonic (12/15/18/21/24 words)
/// that passes BIP-39 checksum validation. Pure offline; used only to refuse
/// seed material in product credential stores (not a wallet import path).
fn looks_like_bip39_mnemonic(value: &str) -> bool {
    let words: Vec<&str> = value.split_whitespace().collect();
    match words.len() {
        12 | 15 | 18 | 21 | 24 => grok_bitcoin_wallet::mnemonic::validate_mnemonic(value).is_ok(),
        _ => false,
    }
}

/// True when `value` is a 64-character hex string (32-byte secret key material,
/// e.g. raw Nostr/secp256k1 secret). Pure offline refuse path — never store or
/// send as product Bearer. Case-insensitive hex digits only.
fn looks_like_hex_secret_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate material for product Routstr login/store (live Bearer only).
///
/// Returns the trimmed key (`sk-…` or `cashu…`; strips a leading `Bearer `
/// wrapper). Errors are residual-honest — never store NIP-98 / nsec / seed.
pub fn validate_routstr_product_bearer_key(value: &str) -> Result<&str, RoutstrAuthError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RoutstrAuthError::EmptyKey);
    }
    match classify_routstr_product_auth_material(trimmed) {
        RoutstrProductAuthMaterial::SkPrepaid | RoutstrProductAuthMaterial::CashuToken => {
            let inner = trimmed
                .strip_prefix("Bearer ")
                .or_else(|| trimmed.strip_prefix("bearer "))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(trimmed);
            Ok(inner)
        }
        RoutstrProductAuthMaterial::Nip98Nostr => Err(RoutstrAuthError::Nip98NotLive),
        RoutstrProductAuthMaterial::SecretSeedLike => Err(RoutstrAuthError::SeedMaterialRefused),
        RoutstrProductAuthMaterial::Empty => Err(RoutstrAuthError::EmptyKey),
        RoutstrProductAuthMaterial::Other => Err(RoutstrAuthError::NotLiveBearerShape),
    }
}

/// Residual honesty lines when product NIP-98 / Nostr-signed Routstr auth is
/// requested or refused. Pure offline copy — not a Success path.
pub fn routstr_nip98_product_residual_lines() -> Vec<&'static str> {
    vec![
        "Routstr product API auth remains Bearer sk-… / cashu… only (live routstr-core).",
        "NIP-06 derive + pure NIP-98 Authorization helpers are library/offline green.",
        "Nostr-signed HTTP auth is not wired for login/inference (ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false).",
        "Never store nsec or BIP-39 seed in CredentialsStore / provider_credentials / watch_session.",
        "Fund with `grok routstr topup` (invoice-first) or redeem cashuA…; do not invent signed-auth Success.",
    ]
}

/// Residual honesty lines when nsec / BIP-39 / hex-seed is offered as a product
/// Routstr credential. Pure offline copy — never a Success path; seed stays in
/// SeedVault only.
pub fn routstr_seed_material_product_residual_lines() -> Vec<&'static str> {
    vec![
        "Refusing nsec / BIP-39 mnemonic / hex secret as a Routstr product credential.",
        "Seed material belongs in SeedVault only — never CredentialsStore / provider_credentials / watch_session.",
        "Live Routstr API auth is Bearer sk-… / cashu… only (ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false).",
        "Fund with `grok routstr topup` (invoice-first) or redeem cashuA…; do not invent signed-auth Success.",
    ]
}

/// True when `err` is a product residual auth refuse (NIP-98 / seed / non-live
/// shape) — offline-proveable residual classifier, mirroring channel residual
/// cmd honesty. Not `EmptyKey` / `EnvVarSet` / store I/O.
pub fn is_routstr_product_auth_residual_error(err: &RoutstrAuthError) -> bool {
    matches!(
        err,
        RoutstrAuthError::Nip98NotLive
            | RoutstrAuthError::SeedMaterialRefused
            | RoutstrAuthError::NotLiveBearerShape
    )
}

/// Emit residual honesty lines for a product auth residual refuse (stderr).
/// No-op for non-residual errors. Never claims Success.
fn eprint_routstr_product_auth_residual(err: &RoutstrAuthError) {
    match err {
        RoutstrAuthError::Nip98NotLive => {
            for line in routstr_nip98_product_residual_lines() {
                eprintln!("{line}");
            }
        }
        RoutstrAuthError::SeedMaterialRefused => {
            for line in routstr_seed_material_product_residual_lines() {
                eprintln!("{line}");
            }
        }
        RoutstrAuthError::NotLiveBearerShape => {
            eprintln!(
                "Routstr product credentials must be sk-… or cashu… \
                 (live validate_bearer_key; residual schemes refused)."
            );
            eprintln!(
                "ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false — Nostr-signed auth is not product Success."
            );
        }
        _ => {}
    }
}

/// Clear the stored Routstr API key (does not unset env).
pub fn clear_routstr_api_key(store: &CredentialsStore) -> Result<(), CredentialsStoreError> {
    store.delete(&routstr_credential_url(None))
}

/// Whether a catalog / model id is the Routstr-backed Grok entry (or a
/// future `routstr-*` catalog id).
pub fn is_routstr_catalog_id(model_id: &str) -> bool {
    let id = model_id.trim();
    id == ROUTSTR_GROK_45_CATALOG_ID || id.starts_with("routstr-")
}

/// Account balance payload from `GET /v1/balance/info` (flexible fields).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RoutstrBalanceInfo {
    #[serde(default)]
    pub msats: Option<u64>,
    #[serde(default)]
    pub balance_msats: Option<u64>,
    #[serde(default)]
    pub balance: Option<u64>,
    #[serde(default)]
    pub sats: Option<u64>,
    #[serde(default)]
    pub balance_sats: Option<u64>,
}

/// Remaining balance in millisatoshis from a balance-info body.
///
/// Uses explicit unit fields only (`msats`, `balance_msats`, `sats`,
/// `balance_sats`). Bare `balance` is ignored (unit ambiguous). Aligned with
/// `grok_bitcoin_wallet::cashu::parse_balance_msats_from_json`.
pub fn routstr_balance_msats_from_info(info: &RoutstrBalanceInfo) -> Option<u64> {
    if let Some(m) = info.msats.or(info.balance_msats) {
        return Some(m);
    }
    if let Some(s) = info.sats.or(info.balance_sats) {
        return Some(s.saturating_mul(1000));
    }
    let _ = info.balance; // ignored until API documents unit
    None
}

/// Parse msats from a raw JSON body (unit-testable without HTTP).
pub fn parse_routstr_balance_msats(body: &str) -> Option<u64> {
    // Try direct struct, then nested `data`.
    if let Ok(info) = serde_json::from_str::<RoutstrBalanceInfo>(body)
        && let Some(m) = routstr_balance_msats_from_info(&info)
    {
        return Some(m);
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if let Some(data) = v.get("data") {
        let info: RoutstrBalanceInfo = serde_json::from_value(data.clone()).ok()?;
        return routstr_balance_msats_from_info(&info);
    }
    None
}

/// Whether product code should attempt a Routstr balance network fetch.
///
/// When `[features] routstr_enabled = false`, the catalog entry is omitted and
/// balance chrome must not hit the Routstr API either. Pure helper for tests
/// and call sites that already know the feature flag.
pub fn should_fetch_routstr_balance(routstr_enabled: bool) -> bool {
    routstr_enabled
}

/// Read `[features].routstr_enabled` from a raw TOML config root (default true).
///
/// Mirrors [`crate::agent::config::routstr_catalog_enabled`] without needing a
/// fully parsed [`crate::agent::config::Config`].
pub fn routstr_enabled_from_raw_config(root: &toml::Value) -> bool {
    root.get("features")
        .and_then(|f| f.get("routstr_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// Load disk config and return whether Routstr balance fetches are allowed.
///
/// Defaults to **enabled** when config is unreadable so a missing/broken file
/// never silently disables a configured key path.
pub fn routstr_balance_fetch_enabled_from_disk() -> bool {
    match crate::config::load_effective_config_disk_only() {
        Ok(root) => should_fetch_routstr_balance(routstr_enabled_from_raw_config(&root)),
        Err(_) => true,
    }
}

/// Fetch remaining Routstr balance (msats) for the configured key.
///
/// Returns `None` when Routstr is disabled in config, no key is available, the
/// request fails, or the body cannot be parsed.
pub async fn fetch_routstr_balance_msats() -> Option<u64> {
    if !routstr_balance_fetch_enabled_from_disk() {
        tracing::debug!("routstr balance: skipped (features.routstr_enabled=false)");
        return None;
    }
    let key = load_routstr_api_key_default().ok().flatten()?;
    fetch_routstr_balance_msats_with_key(&key).await
}

/// Fetch Routstr balance with an explicit API key.
///
/// **Ungated on config:** does **not** consult `[features] routstr_enabled`.
/// Use only from tests or callers that already decided a network hit is allowed.
/// Product paths must use [`fetch_routstr_balance_msats`], which applies the
/// feature gate (and key load) before calling this helper.
///
/// **Auth-gated:** refuses residual material (`Nip98Nostr` / `SecretSeedLike` /
/// `Other` / empty) — never sends seed-like or NIP-98 values as
/// `Authorization: Bearer`. Accepts only live `sk-…` / `cashu…`.
pub async fn fetch_routstr_balance_msats_with_key(api_key: &str) -> Option<u64> {
    let key = match validate_routstr_product_bearer_key(api_key) {
        Ok(k) => k,
        Err(_) => {
            tracing::debug!(
                "routstr balance: refusing non-live product auth material (not sending Bearer)"
            );
            return None;
        }
    };
    let url = format!("{ROUTSTR_API_URL}/balance/info");
    let client = crate::http::shared_client();
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        tracing::debug!(
            status = response.status().as_u16(),
            "routstr balance: non-success status"
        );
        return None;
    }
    let body = response.text().await.ok()?;
    parse_routstr_balance_msats(&body)
}

#[derive(Debug, thiserror::Error)]
pub enum RoutstrAuthError {
    #[error(
        "{ROUTSTR_API_KEY_ENV} holds a live sk-…/cashu… key; unset it before storing \
         a key in the secret store (residual env shapes do not block store)"
    )]
    EnvVarSet,
    #[error("Routstr API key must not be empty")]
    EmptyKey,
    /// NIP-98 / Nostr Authorization offered for product store — residual, not live.
    #[error(
        "NIP-98 / Nostr Authorization is not accepted for product Routstr login \
         (live node is Bearer sk-… / cashu… only; pure helpers are library/offline). \
         Never store nsec/seed in CredentialsStore. Use `grok routstr topup` or a cashuA… token."
    )]
    Nip98NotLive,
    /// nsec, BIP-39, or 64-hex secret offered as product credential — hard refuse.
    #[error(
        "Refusing to store nsec / BIP-39 / hex secret seed as a Routstr API key \
         (SeedVault only for seed material; CredentialsStore is Bearer sk-/cashu float only)"
    )]
    SeedMaterialRefused,
    /// Non-empty material that is not a live Bearer shape.
    #[error(
        "Routstr product credentials must be sk-… or cashu… \
         (live validate_bearer_key; not NIP-98 / other schemes)"
    )]
    NotLiveBearerShape,
    #[error(transparent)]
    Store(#[from] CredentialsStoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// `grok login --routstr`: store a Routstr API key (`sk-` or `cashuA…`).
///
/// When `api_key` is `Some`, use it; otherwise prompt on stdin (TTY).
///
/// **Residual:** permissionless NIP-06 / Nostr-signed Routstr auth is not
/// wired here — library NIP-06 + pure NIP-98 only (`grok_bitcoin_wallet`).
/// This path stores Bearer float material only via
/// [`validate_routstr_product_bearer_key`]; never nsec or BIP-39.
/// Residual refuse paths print honest residual lines and zeroize temporary
/// key buffers (never invent signed-auth Success).
pub fn run_routstr_login(grok_home: &Path, api_key: Option<&str>) -> Result<(), RoutstrAuthError> {
    let store = CredentialsStore::at_grok_home(grok_home);
    let mut key = if let Some(k) = api_key {
        k.to_owned()
    } else if let Some(mut live) = live_routstr_api_key_from_env() {
        // Live env wins — do not write store (env-over-store for live shapes only).
        // Presence check only; multi-list already drained/zeroized inside live_*.
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut live);
        eprintln!(
            "{ROUTSTR_API_KEY_ENV} is set to a live sk-…/cashu… key; Routstr will use it \
             (not writing to the secret store)."
        );
        eprintln!("Routstr authentication ready via {ROUTSTR_API_KEY_ENV}.");
        return Ok(());
    } else if let Some(mut env_key) = routstr_api_key_from_env() {
        // Residual-only env (no live sk-/cashu in multi-list): fail closed.
        // Do not invent Success (exit 0 with no credential ready).
        let class = classify_routstr_product_auth_material(&env_key);
        let result = match class {
            RoutstrProductAuthMaterial::Nip98Nostr => {
                let err = RoutstrAuthError::Nip98NotLive;
                eprint_routstr_product_auth_residual(&err);
                Err(err)
            }
            RoutstrProductAuthMaterial::SecretSeedLike => {
                let err = RoutstrAuthError::SeedMaterialRefused;
                eprint_routstr_product_auth_residual(&err);
                Err(err)
            }
            RoutstrProductAuthMaterial::Empty
            | RoutstrProductAuthMaterial::Other
            | RoutstrProductAuthMaterial::SkPrepaid
            | RoutstrProductAuthMaterial::CashuToken => {
                // Sk/Cashu already handled via live_* above when present in the
                // multi-key list. Empty/Other (and unreachable Sk/Cashu here)
                // are residual refuse — same as explicit --api-key path.
                let err = RoutstrAuthError::NotLiveBearerShape;
                eprint_routstr_product_auth_residual(&err);
                eprintln!(
                    "warning: {ROUTSTR_API_KEY_ENV} is set but has no live sk-…/cashu… shape; \
                     it is not used for Authorization. Unset it or pass a live key to store \
                     (e.g. `grok login --routstr --api-key sk-…` / paid topup store)."
                );
                Err(err)
            }
        };
        // Zeroize residual/seed-like env material after classify (Issue 3 hygiene).
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut env_key);
        return result;
    } else {
        eprint!(
            "Enter your Routstr API key (sk-… or cashuA…), or run `grok routstr topup` to fund via Lightning: "
        );
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim().to_owned()
    };

    let store_result = store_routstr_api_key(&store, &key);
    match &store_result {
        Ok(()) => {
            eprintln!("Routstr API key saved to the secret store.");
            eprintln!(
                "Select the model with `/model {ROUTSTR_GROK_45_CATALOG_ID}` or \
                 `grok -m {ROUTSTR_GROK_45_CATALOG_ID}`."
            );
        }
        Err(err) => {
            // Explicit / stdin residual: honest residual lines (not silent refuse).
            eprint_routstr_product_auth_residual(err);
        }
    }
    // Always zeroize owned key buffer (live or residual) after store attempt.
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut key);
    store_result
}

/// `grok logout --routstr`: remove stored Routstr key.
pub fn run_routstr_logout(grok_home: &Path) -> Result<(), RoutstrAuthError> {
    let store = CredentialsStore::at_grok_home(grok_home);
    clear_routstr_api_key(&store)?;
    if let Some(mut live) = live_routstr_api_key_from_env() {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut live);
        eprintln!(
            "Cleared stored Routstr key. {ROUTSTR_API_KEY_ENV} is still set to a live \
             sk-…/cashu… key and will be used for Authorization."
        );
    } else if routstr_api_key_env_has_token() {
        eprintln!(
            "Cleared stored Routstr key. {ROUTSTR_API_KEY_ENV} is still set but is not a \
             live sk-…/cashu… shape — it is not used for Authorization. Unset it or store \
             a live key."
        );
    } else {
        eprintln!("Cleared stored Routstr API key.");
    }
    Ok(())
}

/// Format msats as a short human balance line (sats + msats remainder).
pub fn format_routstr_balance_line(msats: u64) -> String {
    let sats = msats / 1000;
    let rem = msats % 1000;
    if rem == 0 {
        format!("{sats} sats ({msats} msats)")
    } else {
        format!("{sats} sats + {rem} msats ({msats} msats total)")
    }
}

/// `grok routstr balance`: fetch remaining prepaid float when a key is present.
pub async fn run_routstr_balance() -> Result<(), RoutstrCliError> {
    // Config-disabled is not a network/key failure — surface that before fetch.
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    if !has_routstr_api_key() {
        return Err(RoutstrCliError::NoApiKey);
    }
    match fetch_routstr_balance_msats().await {
        Some(msats) => {
            println!("Routstr balance: {}", format_routstr_balance_line(msats));
            println!(
                "This is hot prepaid float on the Routstr node, not your local Bitcoin wallet."
            );
            Ok(())
        }
        None => Err(RoutstrCliError::BalanceUnavailable),
    }
}

/// Default minimum float (msats) considered "ready" for [`ensure_routstr_ready`].
///
/// 1000 sats = 1_000_000 msats (matches credit-bar low threshold).
pub const ROUTSTR_READY_MIN_MSATS: u64 = 1_000_000;

/// Outcome of the invoice-first readiness / setup orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutstrReadyOutcome {
    /// Key present and float meets threshold (or threshold is zero and key works).
    Ready { msats: u64 },
    /// Invoice created; user must pay BOLT11 (poll may still be in progress).
    ///
    /// `invoice_id` / `bolt11` are always non-empty validated values.
    NeedsPayment {
        invoice_id: String,
        bolt11: String,
        amount_sats: u64,
    },
    /// Payment observed and key stored (or env already set); balance after store.
    PaidAndStored { msats: Option<u64> },
    /// Live invoice create failed; residual next-steps were printed (no invoice).
    CreateFailed,
    /// Feature disabled in config.
    FeatureDisabled,
}

/// Structured outcome of [`run_routstr_topup_with_options`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutstrTopupOutcome {
    /// Live create succeeded; optional poll may have stored a key.
    InvoiceReady {
        invoice_id: String,
        bolt11: String,
        amount_sats: u64,
        /// True when poll observed payment and stored (or env already set).
        paid_and_stored: bool,
    },
    /// Live create failed; residual next-steps printed (no fabricated invoice).
    CreateFailedResidual,
}

/// Truncate HTTP error bodies for user-facing messages (CLI stderr / TUI).
///
/// Caps length and avoids dumping multi-KB HTML or accidental secret fields.
pub fn format_routstr_http_error(
    context: &str,
    status: impl std::fmt::Display,
    body: &str,
) -> String {
    const MAX_CHARS: usize = 280;
    let trimmed = body.trim();
    let mut preview: String = trimmed.chars().take(MAX_CHARS).collect();
    if trimmed.chars().count() > MAX_CHARS {
        preview.push('…');
    }
    // Collapse whitespace so multi-line HTML is one short line.
    let preview = preview.split_whitespace().collect::<Vec<_>>().join(" ");
    if preview.is_empty() {
        format!("{context} HTTP {status}")
    } else {
        format!("{context} HTTP {status}: {preview}")
    }
}

/// Pure readiness decision after loading key + optional balance (unit-testable).
///
/// - No key → need invoice (`create` purpose).
/// - Key + balance ≥ `min_msats` → ready.
/// - Key + balance known but low → need topup invoice.
/// - Key + balance unknown → treat as need topup (caller may still try create).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutstrReadyDecision {
    Ready { msats: u64 },
    NeedInvoice { has_existing_key: bool },
}

/// Decide whether float is ready without HTTP (inject balance snapshot).
pub fn decide_routstr_ready(
    has_key: bool,
    balance_msats: Option<u64>,
    min_msats: u64,
) -> RoutstrReadyDecision {
    if !has_key {
        return RoutstrReadyDecision::NeedInvoice {
            has_existing_key: false,
        };
    }
    match balance_msats {
        Some(msats) if msats >= min_msats => RoutstrReadyDecision::Ready { msats },
        Some(_) | None => RoutstrReadyDecision::NeedInvoice {
            has_existing_key: true,
        },
    }
}

/// Redact an API key / Cashu token for stderr (never full secret).
pub fn redact_secret_preview(secret: &str) -> String {
    let s = secret.trim();
    if s.len() > 12 {
        format!("{}…{}", &s[..4], &s[s.len().saturating_sub(4)..])
    } else if s.is_empty() {
        "(empty)".to_owned()
    } else {
        "(secret)".to_owned()
    }
}

/// Parse flexible balance-create / key-bearing JSON (`additionalProperties`).
///
/// Looks for non-empty `api_key`, `key`, `token`, or nested `data.*`.
pub fn parse_routstr_api_key_from_body(body: &str) -> Option<String> {
    fn from_value(v: &serde_json::Value) -> Option<String> {
        for field in ["api_key", "key", "token", "sk"] {
            if let Some(s) = v
                .get(field)
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return Some(s.to_owned());
            }
        }
        if let Some(data) = v.get("data") {
            return from_value(data);
        }
        None
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    from_value(&v)
}

/// Parse Cashu token from a refund response (flexible field names).
///
/// Looks for `token`, `cashu_token`, `cashu`, or nested `data.*`.
/// Returns owned string; caller must show once and not log full value.
pub fn parse_routstr_refund_cashu_token(body: &str) -> Option<String> {
    fn from_value(v: &serde_json::Value) -> Option<String> {
        for field in ["token", "cashu_token", "cashu", "refund_token"] {
            if let Some(s) = v
                .get(field)
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return Some(s.to_owned());
            }
        }
        if let Some(data) = v.get("data") {
            return from_value(data);
        }
        None
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    from_value(&v)
}

/// Parse msats-like fields from topup/create balance bodies (optional).
pub fn parse_routstr_msats_flexible(body: &str) -> Option<u64> {
    if let Some(m) = parse_routstr_balance_msats(body) {
        return Some(m);
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    // Topup OpenAPI: additionalProperties integer map.
    if let Some(obj) = v.as_object() {
        for key in ["msats", "balance_msats", "amount_msats"] {
            if let Some(n) = obj.get(key).and_then(|x| x.as_u64()) {
                return Some(n);
            }
        }
        for key in ["sats", "balance_sats", "amount_sats"] {
            if let Some(n) = obj.get(key).and_then(|x| x.as_u64()) {
                return Some(n.saturating_mul(1000));
            }
        }
    }
    None
}

/// `grok routstr setup` / readiness: ensure key + float or create invoice + poll.
///
/// Does **not** auto-select a model. Uses [`ROUTSTR_READY_MIN_MSATS`] threshold.
pub fn ensure_routstr_ready(sats: Option<u64>) -> Result<RoutstrReadyOutcome, RoutstrCliError> {
    ensure_routstr_ready_with_options(sats, true, ROUTSTR_READY_MIN_MSATS)
}

/// Like [`ensure_routstr_ready`] with poll + min balance controls.
pub fn ensure_routstr_ready_with_options(
    sats: Option<u64>,
    poll_after_create: bool,
    min_msats: u64,
) -> Result<RoutstrReadyOutcome, RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Ok(RoutstrReadyOutcome::FeatureDisabled);
    }
    let has_key = has_routstr_api_key();
    let balance = if has_key {
        // Blocking balance for CLI: use short async runtime or skip when none.
        fetch_routstr_balance_msats_blocking()
    } else {
        None
    };
    match decide_routstr_ready(has_key, balance, min_msats) {
        RoutstrReadyDecision::Ready { msats } => {
            eprintln!("Routstr ready: {}", format_routstr_balance_line(msats));
            eprintln!("Select model `/model {ROUTSTR_GROK_45_CATALOG_ID}` (not auto-switched).");
            Ok(RoutstrReadyOutcome::Ready { msats })
        }
        RoutstrReadyDecision::NeedInvoice { .. } => {
            match run_routstr_topup_with_options(sats, poll_after_create)? {
                RoutstrTopupOutcome::CreateFailedResidual => Ok(RoutstrReadyOutcome::CreateFailed),
                RoutstrTopupOutcome::InvoiceReady {
                    invoice_id,
                    bolt11,
                    amount_sats,
                    paid_and_stored,
                } => {
                    if paid_and_stored || has_routstr_api_key() {
                        if let Some(msats) = fetch_routstr_balance_msats_blocking() {
                            if msats >= min_msats {
                                return Ok(RoutstrReadyOutcome::Ready { msats });
                            }
                            return Ok(RoutstrReadyOutcome::PaidAndStored { msats: Some(msats) });
                        }
                        return Ok(RoutstrReadyOutcome::PaidAndStored { msats: None });
                    }
                    Ok(RoutstrReadyOutcome::NeedsPayment {
                        invoice_id,
                        bolt11,
                        amount_sats,
                    })
                }
            }
        }
    }
}

/// Blocking balance fetch for CLI orchestrator (small temporary runtime).
fn fetch_routstr_balance_msats_blocking() -> Option<u64> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(fetch_routstr_balance_msats())
}

/// `grok routstr topup`: create a live Routstr Lightning invoice (mainnet node)
/// and print BOLT11 + QR. Falls back to residual copy if the network create fails.
///
/// - No existing key → `purpose=create` (status returns `sk-…` after pay).
/// - Existing key → `purpose=topup` with `Authorization: Bearer`.
/// - When local Lightning reports `bolt11_pay_live` is true (feature `ldk` →
///   out-of-process `grok-bitcoin-ldk-node`): unlock SeedVault → pay the node
///   BOLT11 → poll. On failure / missing helper, keep QR + external pay (P0).
///   Seed never uses CredentialsStore.
/// - Otherwise: user pays the invoice from any LN wallet (invoice-first).
/// - Optional short poll after create; use [`run_routstr_topup_status`] to re-check.
pub fn run_routstr_topup(sats: Option<u64>) -> Result<(), RoutstrCliError> {
    run_routstr_topup_with_options(sats, true).map(|_| ())
}

/// Like [`run_routstr_topup`] with optional post-create poll (TTY-friendly).
///
/// Returns a structured outcome so callers (e.g. [`ensure_routstr_ready`]) never
/// invent empty invoice ids when create failed or poll timed out.
pub fn run_routstr_topup_with_options(
    sats: Option<u64>,
    poll_after_create: bool,
) -> Result<RoutstrTopupOutcome, RoutstrCliError> {
    let ln = grok_bitcoin_wallet::lightning::default_lightning_backend();
    run_routstr_topup_with_lightning(sats, poll_after_create, &ln)
}

/// Injectable Lightning backend for topup (unit tests without network LDK).
///
/// Product path: [`run_routstr_topup_with_options`] uses
/// [`grok_bitcoin_wallet::lightning::default_lightning_backend`].
pub fn run_routstr_topup_with_lightning(
    sats: Option<u64>,
    poll_after_create: bool,
    ln: &dyn grok_bitcoin_wallet::lightning::LightningCapability,
) -> Result<RoutstrTopupOutcome, RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let amount = grok_bitcoin_wallet::routstr_invoice::resolve_topup_amount_sats(sats)
        .map_err(RoutstrCliError::Message)?;

    match create_routstr_lightning_invoice(amount) {
        Ok(created) => {
            for line in
                grok_bitcoin_wallet::routstr_invoice::live_invoice_display_lines(&created, true)
            {
                eprintln!("{line}");
            }

            // Phase C: when bolt11_pay_live, try SeedVault → local pay before
            // (or in addition to) external QR. Never regress P0: failures fall
            // through to QR + poll.
            let local_paid = maybe_auto_pay_routstr_bolt11(ln, &created.bolt11);

            let mut paid_and_stored = false;
            if poll_after_create {
                eprintln!();
                if local_paid {
                    eprintln!(
                        "Local pay reported success; polling Routstr for api_key (up to ~90s)…"
                    );
                } else {
                    eprintln!(
                        "Polling payment status for up to ~90s (Ctrl-C to stop; re-check later with \
                         `grok routstr topup --status {}`)…",
                        created.invoice_id
                    );
                }
                match poll_routstr_invoice_until_paid(&created.invoice_id, 18, 5) {
                    Ok(Some(key)) => {
                        store_paid_routstr_key(&key)?;
                        paid_and_stored = true;
                    }
                    Ok(None) => {
                        eprintln!(
                            "Still unpaid or no api_key yet. Pay the BOLT11, then:\n  \
                             grok routstr topup --status {}",
                            created.invoice_id
                        );
                    }
                    Err(e) => {
                        eprintln!("Status poll error: {e}");
                        eprintln!(
                            "Re-check with: grok routstr topup --status {}",
                            created.invoice_id
                        );
                    }
                }
            }
            Ok(RoutstrTopupOutcome::InvoiceReady {
                invoice_id: created.invoice_id,
                bolt11: created.bolt11,
                amount_sats: created.amount_sats,
                paid_and_stored,
            })
        }
        Err(e) => {
            eprintln!("Routstr live invoice create failed: {e}");
            eprintln!("Falling back to residual next-steps (no fabricated invoice).");
            for line in grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(sats) {
                eprintln!("{line}");
            }
            Ok(RoutstrTopupOutcome::CreateFailedResidual)
        }
    }
}

/// Attempt local BOLT11 pay when `bolt11_pay_live` (SeedVault unlock).
///
/// Returns `true` only when local pay reported [`PayOutcome::Success`]. On any
/// other path (stub, no wallet, unlock cancel, pay fail) prints honest lines and
/// returns `false` so the QR + external path remains available.
///
/// Pure decision is [`grok_bitcoin_wallet::lightning::decide_local_bolt11_pay_path`];
/// seed material never touches CredentialsStore / provider_credentials.json.
///
/// Unlock failures use [`unlock_failed_fallback_lines`] (no liquidity copy —
/// pay never started). Liquidity honesty is reserved for
/// [`apply_local_bolt11_pay`] → FailedFallback after a real pay attempt.
fn maybe_auto_pay_routstr_bolt11(
    ln: &dyn grok_bitcoin_wallet::lightning::LightningCapability,
    bolt11: &str,
) -> bool {
    use grok_bitcoin_wallet::lightning::{
        Bolt11Invoice, LocalBolt11PayPath, LocalPayApplyResult, apply_local_bolt11_pay,
        decide_local_bolt11_pay_path, local_pay_result_lines,
    };

    if decide_local_bolt11_pay_path(ln.capabilities()) != LocalBolt11PayPath::AutoPayFromSeedVault {
        return false;
    }

    eprintln!();
    eprintln!(
        "Local Lightning pay is live — attempting to pay this Routstr invoice from SeedVault…"
    );
    // Liquidity honesty is printed only via local_pay_result_lines after a real
    // pay attempt (FailedFallback), not before unlock — unlock failures never
    // imply outbound liquidity problems.

    match unlock_seed_session_for_local_bolt11_pay() {
        Ok(mut session) => {
            use std::time::Instant;
            let bip39_pass = product_bip39_passphrase_from_env();
            let result = match session.mnemonic(Instant::now()) {
                Ok(m) => apply_local_bolt11_pay(
                    ln,
                    &Bolt11Invoice(bolt11.to_owned()),
                    m,
                    bip39_pass.expose(),
                ),
                Err(e) => {
                    session.lock();
                    LocalPayApplyResult::FailedFallback {
                        reason: e.to_string(),
                    }
                }
            };
            // Always lock after pay attempt (success or fail) so seed does not linger.
            session.lock();
            for line in local_pay_result_lines(&result) {
                eprintln!("{line}");
            }
            matches!(result, LocalPayApplyResult::Paid { .. })
        }
        Err(reason) => {
            // Unlock never reached pay — do not imply outbound liquidity failure.
            for line in unlock_failed_fallback_lines(&reason) {
                eprintln!("{line}");
            }
            false
        }
    }
}

/// User-facing lines when SeedVault unlock failed before any local pay attempt.
///
/// Deliberately omits [`outbound_liquidity_honesty_lines`]: no pay was tried.
fn unlock_failed_fallback_lines(reason: &str) -> Vec<String> {
    vec![
        "Could not unlock SeedVault for local Lightning pay; falling back to external wallet."
            .to_owned(),
        format!("Detail: {reason}"),
        "Pay the BOLT11 QR / string with any Lightning wallet, then wait for poll \
         or `grok routstr topup --status <invoice_id>`."
            .to_owned(),
    ]
}

/// Outcome of TUI local BOLT11 pay after unlock re-entry (no BIP-39 in payload).
///
/// `lines` are safe for scrollback. `local_paid` is true only when local
/// Lightning reported [`PayOutcome::Success`]. On every other path, invoice
/// poll + external QR remain the funding path (P0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrTopupLocalPaySuccess {
    pub lines: Vec<String>,
    pub local_paid: bool,
}

/// TUI Routstr topup local pay after unlock re-entry (product Lightning backend).
///
/// Same SeedVault gates as spend/utxos: AEAD password + recovery-phrase re-entry.
/// Seed never uses CredentialsStore / provider_credentials.json / watch_session.
/// Always locks the unlock session. Zeroizes the typed re-entry phrase buffer.
///
/// Unlock failures return **Ok** with [`unlock_failed_fallback_lines`] (no
/// liquidity honesty — pay never started). Pay failures return Ok with
/// [`local_pay_result_lines`] (liquidity honesty only after a real attempt).
/// Not-live backends skip unlock and return external-wallet guidance.
pub fn complete_routstr_topup_local_pay_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    bolt11: &str,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrTopupLocalPaySuccess, RoutstrCliError> {
    let ln = grok_bitcoin_wallet::lightning::default_lightning_backend();
    complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
        grok_home,
        reentry_phrase,
        password,
        bolt11,
        bip39_passphrase,
        &ln,
    )
}

/// Injectable Lightning backend for TUI topup local pay (unit tests without LDK).
///
/// Product path: [`complete_routstr_topup_local_pay_reentry_for_tui`] uses
/// [`grok_bitcoin_wallet::lightning::default_lightning_backend`].
pub fn complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    bolt11: &str,
    bip39_passphrase: Option<&str>,
    ln: &dyn grok_bitcoin_wallet::lightning::LightningCapability,
) -> Result<RoutstrTopupLocalPaySuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::lightning::{
        Bolt11Invoice, LocalBolt11PayPath, LocalPayApplyResult, apply_local_bolt11_pay,
        decide_local_bolt11_pay_path, local_pay_result_lines,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Not live → never touch SeedVault; P0 external QR only.
    if decide_local_bolt11_pay_path(ln.capabilities()) != LocalBolt11PayPath::AutoPayFromSeedVault {
        return Ok(RoutstrTopupLocalPaySuccess {
            lines: vec![
                "Local Lightning pay is not live on this build; pay the BOLT11 with any \
                 Lightning wallet (background poll continues)."
                    .to_owned(),
            ],
            local_paid: false,
        });
    }

    let bolt11 = bolt11.trim();
    if bolt11.is_empty() {
        return Err(RoutstrCliError::Message(
            "internal topup local pay: empty bolt11".into(),
        ));
    }

    // Owned copy so we can zeroize after gate confirm (or on any early return).
    let mut reentry = reentry_phrase.to_owned();
    let unlock_fail = |reason: &str| RoutstrTopupLocalPaySuccess {
        lines: unlock_failed_fallback_lines(reason),
        local_paid: false,
    };
    let finish_unlock_fail = |reentry: &mut String,
                              reason: &str|
     -> Result<RoutstrTopupLocalPaySuccess, RoutstrCliError> {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(reentry);
        Ok(unlock_fail(reason))
    };

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = match SeedVault::with_aead_path(&aead_path) {
        Ok(v) => v,
        Err(e) => return finish_unlock_fail(&mut reentry, &e.to_string()),
    };

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return finish_unlock_fail(&mut reentry, password_required_message());
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return finish_unlock_fail(&mut reentry, &keyring_blocked_message(&reason));
            }
            FundPathDecision::NewWallet => {
                return finish_unlock_fail(
                    &mut reentry,
                    "no local wallet found for auto-pay. Run `grok routstr fund` first, \
                     or pay the BOLT11 QR with an external Lightning wallet.",
                );
            }
            FundPathDecision::LoadError { message } => {
                return finish_unlock_fail(&mut reentry, &message);
            }
            FundPathDecision::ReturningUnlock => {
                return finish_unlock_fail(
                    &mut reentry,
                    "internal auto-pay: unexpected ReturningUnlock on load error",
                );
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return finish_unlock_fail(&mut reentry, &e.to_string());
        }
    };
    let mut gate = MnemonicBackupGate::new();
    if let Err(e) = gate.begin_reentry_without_display(unlocked) {
        session.lock();
        return finish_unlock_fail(&mut reentry, &e.to_string());
    }
    if reentry.trim().is_empty() {
        session.lock();
        return finish_unlock_fail(
            &mut reentry,
            "recovery phrase re-entry cancelled; use external wallet to pay the BOLT11",
        );
    }
    if let Err(e) = gate.confirm_reentry(&reentry) {
        session.lock();
        return finish_unlock_fail(&mut reentry, &e.to_string());
    }
    // Scrub typed recovery phrase as soon as the gate accepts it.
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut reentry);

    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Ok(unlock_fail(&e.to_string()));
        }
    };
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Real pay attempt only after unlock succeeded — liquidity honesty is
    // reserved for apply_local_bolt11_pay FailedFallback (not unlock fail).
    let apply = apply_local_bolt11_pay(
        ln,
        &Bolt11Invoice(bolt11.to_owned()),
        unlocked,
        bip39_pass.expose(),
    );
    // Always lock after pay attempt (success or fail).
    session.lock();

    let local_paid = matches!(apply, LocalPayApplyResult::Paid { .. });
    Ok(RoutstrTopupLocalPaySuccess {
        lines: local_pay_result_lines(&apply),
        local_paid,
    })
}

/// Load SeedVault for auto-pay (password if AEAD; recovery-phrase re-entry).
///
/// Same gates as spend/fund authorize paths. Caller **must** [`UnlockSession::lock`]
/// on every path after use. Never stores seed in CredentialsStore.
fn unlock_seed_session_for_local_bolt11_pay()
-> Result<grok_bitcoin_wallet::seed_vault::UnlockSession, String> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    let grok_home = crate::util::grok_home::grok_home();
    let aead_path = routstr_seed_aead_path(&grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(|e| e.to_string())?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw =
                    read_secret_prompt("Unlock seed file password: ").map_err(|e| e.to_string())?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(password_required_message().into());
                }
                vault.load(Some(&pw)).map_err(|e| e.to_string())?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(keyring_blocked_message(&reason));
            }
            FundPathDecision::NewWallet => {
                return Err(
                    "no local wallet found for auto-pay. Run `grok routstr fund` first, \
                     or pay the BOLT11 QR with an external Lightning wallet."
                        .into(),
                );
            }
            FundPathDecision::LoadError { message } => return Err(message),
            FundPathDecision::ReturningUnlock => {
                return Err("internal auto-pay: unexpected ReturningUnlock on load error".into());
            }
        },
    };

    eprintln!(
        "Authorize local Lightning pay: re-enter your recovery phrase (words are not re-displayed)."
    );
    eprint!("Recovery phrase: ");
    let _ = io::stderr().flush();
    let mut reentry = String::new();
    if let Err(e) = io::stdin().read_line(&mut reentry) {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut reentry);
        return Err(format!("read recovery phrase: {e}"));
    }

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut reentry);
            return Err(e.to_string());
        }
    };
    let gate_result = {
        let mut gate = MnemonicBackupGate::new();
        if let Err(e) = gate.begin_reentry_without_display(unlocked) {
            session.lock();
            Err(e.to_string())
        } else if reentry.trim().is_empty() {
            session.lock();
            Err("recovery phrase re-entry cancelled; use external wallet to pay the BOLT11".into())
        } else if let Err(e) = gate.confirm_reentry(&reentry) {
            session.lock();
            Err(e.to_string())
        } else {
            Ok(())
        }
    };
    // Always scrub the typed recovery phrase buffer (success or fail).
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut reentry);
    gate_result?;

    // Session still holds mnemonic; caller pays then locks.
    if let Err(e) = session.mnemonic(Instant::now()) {
        session.lock();
        return Err(e.to_string());
    }
    Ok(session)
}

/// Poll a previously created invoice; store `api_key` when paid.
pub fn run_routstr_topup_status(invoice_id: &str) -> Result<(), RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let id = grok_bitcoin_wallet::routstr_invoice::validate_invoice_id(invoice_id)
        .map_err(RoutstrCliError::Message)?;
    let status = fetch_routstr_invoice_status(id).map_err(RoutstrCliError::Message)?;
    eprintln!(
        "Invoice {id}: status={} amount_sats={}",
        status.status, status.amount_sats
    );
    if let Some(key) = status.api_key_if_paid() {
        store_paid_routstr_key(key)?;
        return Ok(());
    }
    if status.is_paid() {
        eprintln!(
            "Paid, but no api_key in status body — try `grok routstr topup --recover <bolt11>` \
             if you still have the invoice string."
        );
    } else {
        eprintln!(
            "Not paid yet (status={}). Pay the BOLT11, then re-run this command.",
            status.status
        );
    }
    Ok(())
}

/// `POST /lightning/recover`: recover invoice status from a BOLT11 string.
///
/// Stores `api_key` when the recovered status is paid.
pub fn run_routstr_topup_recover(bolt11: &str) -> Result<(), RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let status = recover_routstr_invoice_status(bolt11).map_err(RoutstrCliError::Message)?;
    eprintln!(
        "Recover: status={} amount_sats={}",
        status.status, status.amount_sats
    );
    if let Some(key) = status.api_key_if_paid() {
        store_paid_routstr_key(key)?;
        return Ok(());
    }
    if status.is_paid() {
        eprintln!("Paid according to recover, but no api_key in body.");
    } else {
        eprintln!(
            "Not paid yet (status={}). Pay the BOLT11, then re-run recover or --status.",
            status.status
        );
    }
    Ok(())
}

/// Store a key returned by a paid invoice / create / redeem path.
///
/// Public for TUI poll completion. Never logs the full secret.
///
/// Skips writing only when env holds a **live** Bearer key (env-over-store).
/// Residual env (NIP-98 / seed / Other) does not block — paid live `sk-` is
/// stored so load can fall through and use it.
pub fn store_paid_routstr_key(key: &str) -> Result<(), RoutstrCliError> {
    let redacted = redact_secret_preview(key);
    if let Some(mut live) = live_routstr_api_key_from_env() {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut live);
        eprintln!(
            "Payment credited. {ROUTSTR_API_KEY_ENV} holds a live sk-…/cashu… key — not \
             writing to the secret store (env wins). Key from node (redacted): {redacted}"
        );
        return Ok(());
    }
    if routstr_api_key_env_has_token() {
        // Residual env: still store the paid live key (load falls through to store).
        // Presence-only — no residual secret retained for this branch.
        tracing::debug!(
            "routstr paid store: residual {ROUTSTR_API_KEY_ENV} present; writing live key to store"
        );
    }
    let store = CredentialsStore::default_store();
    store_routstr_api_key(&store, key).map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    eprintln!("Payment confirmed. Routstr API key saved to the secret store ({redacted}).");
    eprintln!(
        "Run `grok routstr balance` and select `/model {ROUTSTR_GROK_45_CATALOG_ID}` \
         (model is never auto-switched)."
    );
    Ok(())
}

/// Redeem a Cashu token into a new balance (`GET /v1/balance/create`) or top up
/// an existing key (`POST /v1/balance/topup`).
pub fn run_routstr_redeem(cashu_token: &str) -> Result<(), RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let token = grok_bitcoin_wallet::cashu::CashuToken::parse(cashu_token)
        .map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    redeem_parsed_cashu_token(&token)
}

/// Redeem an already-parsed Cashu token (internal / product mint path).
fn redeem_parsed_cashu_token(
    token: &grok_bitcoin_wallet::cashu::CashuToken,
) -> Result<(), RoutstrCliError> {
    let existing = load_routstr_api_key_default()
        .map_err(|e| RoutstrCliError::Message(e.to_string()))?
        .filter(|k| !k.trim().is_empty());
    if let Some(key) = existing {
        match topup_routstr_balance_with_cashu(&key, token.expose()) {
            Ok(msats) => {
                eprintln!(
                    "Cashu topup applied to existing key ({}).",
                    redact_secret_preview(&key)
                );
                if let Some(m) = msats {
                    eprintln!("Balance after topup: {}", format_routstr_balance_line(m));
                } else {
                    eprintln!("Topup succeeded; run `grok routstr balance` to confirm.");
                }
                Ok(())
            }
            Err(e) => Err(RoutstrCliError::Message(format!("Cashu topup failed: {e}"))),
        }
    } else {
        match create_routstr_balance_with_cashu(token.expose()) {
            Ok(api_key) => {
                store_paid_routstr_key(&api_key)?;
                Ok(())
            }
            Err(e) => Err(RoutstrCliError::Message(format!(
                "Cashu balance create failed: {e}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Cashu mint product path (NUT-04 quote → pay → proofs → redeem)
// ---------------------------------------------------------------------------

/// Structured outcome of [`run_routstr_mint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutstrMintOutcome {
    /// Full path succeeded: token obtained **and** Routstr redeem credited float.
    FloatCredited { quote_id: String, amount_sats: u64 },
    /// Proofs mint produced a token but redeem failed / skipped — not float.
    TokenObtainedNotRedeemed {
        quote_id: String,
        amount_sats: u64,
        redeem_error: String,
    },
    /// Live quote shown; user must pay then `--complete` (or TUI second unlock).
    QuoteReady {
        quote_id: String,
        bolt11: String,
        amount_sats: u64,
    },
    /// Not live / unlock cancel / quote fail — residual lines printed; P0 fall-through.
    ResidualFallback,
}

/// Outcome of TUI mint **quote** stage after unlock re-entry (no BIP-39 in payload).
///
/// `quote_id` / `bolt11` are set only on a real live quote. Never claims float.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrMintQuoteSuccess {
    pub lines: Vec<String>,
    pub quote_id: Option<String>,
    pub bolt11: Option<String>,
    pub amount_sats: Option<u64>,
}

/// Outcome of TUI mint **after-pay** stage after unlock re-entry (no BIP-39 / no full token).
///
/// `float_credited` is true **only** when redeem succeeded. Token (if any) is
/// redacted in `lines`; optional `token_for_clipboard` is for one-shot clipboard
/// only (never scrollback). Callers must zeroize / drop it after copy.
#[derive(Clone, PartialEq, Eq)]
pub struct RoutstrMintAfterPaySuccess {
    pub lines: Vec<String>,
    pub float_credited: bool,
    pub token_obtained: bool,
    /// Bearer token for clipboard only — **not** Debug-printed fully.
    pub token_for_clipboard: Option<String>,
    pub amount_sats: Option<u64>,
    pub quote_id: Option<String>,
}

impl std::fmt::Debug for RoutstrMintAfterPaySuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutstrMintAfterPaySuccess")
            .field("lines", &self.lines)
            .field("float_credited", &self.float_credited)
            .field("token_obtained", &self.token_obtained)
            .field(
                "token_for_clipboard",
                &self
                    .token_for_clipboard
                    .as_ref()
                    .map(|_| "cashuA…[REDACTED]"),
            )
            .field("amount_sats", &self.amount_sats)
            .field("quote_id", &self.quote_id)
            .finish()
    }
}

/// `grok routstr mint`: Cashu NUT-04 quote → pay → proofs → redeem when live.
///
/// When `proofs_mint_live` (feature `cashu-cdk` + mint URL + helper binary):
/// 1. SeedVault unlock (same gates as topup local-pay / spend / utxos)
/// 2. `request_mint_invoice_with_seed` → show mint BOLT11 (not Routstr float)
/// 3. Optional local LDK pay when `bolt11_pay_live`
/// 4. After pay: `complete_mint_after_pay_with_seed` → cashuA…
/// 5. Redeem via balance/create|topup — **float only after redeem succeeds**
///
/// `--complete <quote_id>` resumes after an earlier quote (same seed+passphrase).
///
/// When not live / unlock cancel / failure: residual lines + P0 topup fall-through.
/// Seed never uses CredentialsStore.
pub fn run_routstr_mint(
    sats: Option<u64>,
    complete_quote_id: Option<&str>,
) -> Result<RoutstrMintOutcome, RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let cashu = grok_bitcoin_wallet::cashu::default_cashu_backend();
    run_routstr_mint_with_cashu(sats, complete_quote_id, &cashu)
}

/// Print residual mint honesty + P0 Routstr topup next-steps (live-fail fall-through).
///
/// Call after live-path entry fails (unlock cancel, quote/proofs transport error, etc.).
/// Uses LiveProofs residual wording so we never imply the mint path was never offered.
fn print_mint_p0_fallback(sats: Option<u64>, detail: &str) {
    use grok_bitcoin_wallet::cashu::{CashuMintProductPath, cashu_mint_residual_lines};
    if !detail.is_empty() {
        eprintln!("{detail}");
    }
    for line in cashu_mint_residual_lines(sats, CashuMintProductPath::LiveProofs) {
        eprintln!("{line}");
    }
    eprintln!();
    eprintln!("P0 fall-through next steps:");
    for line in grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(sats) {
        eprintln!("{line}");
    }
}

/// Injectable Cashu backend for mint product path (unit tests without CDK helper).
pub fn run_routstr_mint_with_cashu(
    sats: Option<u64>,
    complete_quote_id: Option<&str>,
    cashu: &dyn grok_bitcoin_wallet::cashu::CashuBackend,
) -> Result<RoutstrMintOutcome, RoutstrCliError> {
    use grok_bitcoin_wallet::cashu::{
        CashuMintProductPath, cashu_mint_quote_display_lines, cashu_mint_residual_lines,
        decide_cashu_mint_product_path,
    };

    let path = decide_cashu_mint_product_path(cashu.capabilities());
    if path != CashuMintProductPath::LiveProofs {
        for line in cashu_mint_residual_lines(sats, path) {
            eprintln!("{line}");
        }
        eprintln!();
        eprintln!("P0 fall-through next steps:");
        for line in grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(sats) {
            eprintln!("{line}");
        }
        return Ok(RoutstrMintOutcome::ResidualFallback);
    }

    let amount = grok_bitcoin_wallet::routstr_invoice::resolve_topup_amount_sats(sats)
        .map_err(RoutstrCliError::Message)?;

    // Complete-only path: unlock → proofs → redeem (quote already paid).
    if let Some(qid) = complete_quote_id.map(str::trim).filter(|s| !s.is_empty()) {
        return run_routstr_mint_complete_after_pay_cli(qid, amount, cashu);
    }

    eprintln!("Cashu mint path is live — unlocking SeedVault for mint quote (not Routstr float)…");
    let mut session = match unlock_seed_session_for_local_bolt11_pay() {
        Ok(s) => s,
        Err(reason) => {
            print_mint_p0_fallback(
                Some(amount),
                &format!("Could not unlock SeedVault for Cashu mint: {reason}"),
            );
            return Ok(RoutstrMintOutcome::ResidualFallback);
        }
    };

    use std::time::Instant;
    let bip39_pass = product_bip39_passphrase_from_env();
    let mnemonic = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            print_mint_p0_fallback(Some(amount), &format!("SeedVault session error: {e}"));
            return Ok(RoutstrMintOutcome::ResidualFallback);
        }
    };

    let quote =
        match cashu.request_mint_invoice_with_seed(Some(amount), mnemonic, bip39_pass.expose()) {
            Ok(o) => o,
            Err(e) => {
                session.lock();
                print_mint_p0_fallback(Some(amount), &format!("Mint quote error: {e}"));
                return Ok(RoutstrMintOutcome::ResidualFallback);
            }
        };

    match quote {
        grok_bitcoin_wallet::cashu::MintQuoteOutcome::Invoice { bolt11, quote_id } => {
            for line in cashu_mint_quote_display_lines(&bolt11, &quote_id, Some(amount)) {
                eprintln!("{line}");
            }
            // Optional local pay of mint quote when LDK live (same as topup).
            let ln = grok_bitcoin_wallet::lightning::default_lightning_backend();
            let _local = maybe_auto_pay_routstr_bolt11(&ln, &bolt11);

            eprintln!();
            eprintln!(
                "After the mint marks the quote paid, press Enter to complete proofs mint \
                 (or Ctrl-C and later: grok routstr mint --complete {quote_id})…"
            );
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
            // Re-borrow mnemonic after pay attempt (session still unlocked).
            let mnemonic = match session.mnemonic(Instant::now()) {
                Ok(m) => m,
                Err(e) => {
                    session.lock();
                    eprintln!("SeedVault session error after pay: {e}");
                    eprintln!("Resume with: grok routstr mint --complete {quote_id}");
                    return Ok(RoutstrMintOutcome::QuoteReady {
                        quote_id,
                        bolt11,
                        amount_sats: amount,
                    });
                }
            };
            let outcome = complete_and_redeem_mint_after_pay_cli(
                &quote_id,
                amount,
                cashu,
                mnemonic,
                bip39_pass.expose(),
            );
            session.lock();
            // If complete failed before token, leave quote-ready for resume.
            match &outcome {
                Ok(RoutstrMintOutcome::FloatCredited { .. })
                | Ok(RoutstrMintOutcome::TokenObtainedNotRedeemed { .. }) => outcome,
                Ok(RoutstrMintOutcome::ResidualFallback) | Err(_) => {
                    for line in cashu_mint_quote_display_lines(&bolt11, &quote_id, Some(amount)) {
                        // already shown; skip re-print
                        let _ = line;
                    }
                    eprintln!("Resume after pay: grok routstr mint --complete {quote_id}");
                    Ok(RoutstrMintOutcome::QuoteReady {
                        quote_id,
                        bolt11,
                        amount_sats: amount,
                    })
                }
                Ok(RoutstrMintOutcome::QuoteReady { .. }) => outcome,
            }
        }
        grok_bitcoin_wallet::cashu::MintQuoteOutcome::Unsupported(reason) => {
            session.lock();
            print_mint_p0_fallback(Some(amount), &format!("Mint quote unsupported: {reason}"));
            Ok(RoutstrMintOutcome::ResidualFallback)
        }
        grok_bitcoin_wallet::cashu::MintQuoteOutcome::Failed(e) => {
            session.lock();
            print_mint_p0_fallback(Some(amount), &format!("Mint quote failed: {e}"));
            Ok(RoutstrMintOutcome::ResidualFallback)
        }
    }
}

fn run_routstr_mint_complete_after_pay_cli(
    quote_id: &str,
    amount_hint: u64,
    cashu: &dyn grok_bitcoin_wallet::cashu::CashuBackend,
) -> Result<RoutstrMintOutcome, RoutstrCliError> {
    eprintln!("Completing Cashu proofs mint for quote {quote_id} (SeedVault unlock)…");
    let mut session = match unlock_seed_session_for_local_bolt11_pay() {
        Ok(s) => s,
        Err(reason) => {
            print_mint_p0_fallback(
                Some(amount_hint),
                &format!("Could not unlock SeedVault: {reason}"),
            );
            return Ok(RoutstrMintOutcome::ResidualFallback);
        }
    };
    use std::time::Instant;
    let bip39_pass = product_bip39_passphrase_from_env();
    let mnemonic = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            print_mint_p0_fallback(Some(amount_hint), &format!("SeedVault session error: {e}"));
            return Ok(RoutstrMintOutcome::ResidualFallback);
        }
    };
    let out = complete_and_redeem_mint_after_pay_cli(
        quote_id,
        amount_hint,
        cashu,
        mnemonic,
        bip39_pass.expose(),
    );
    session.lock();
    out
}

fn complete_and_redeem_mint_after_pay_cli(
    quote_id: &str,
    amount_hint: u64,
    cashu: &dyn grok_bitcoin_wallet::cashu::CashuBackend,
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    passphrase: &str,
) -> Result<RoutstrMintOutcome, RoutstrCliError> {
    use grok_bitcoin_wallet::cashu::{
        CashuToken, cashu_mint_float_credited_lines, cashu_mint_token_obtained_lines,
    };

    // Transport / helper errors → residual + P0 (not hard CLI Err).
    let proofs = match cashu.complete_mint_after_pay_with_seed(quote_id, mnemonic, passphrase) {
        Ok(o) => o,
        Err(e) => {
            print_mint_p0_fallback(
                Some(amount_hint),
                &format!(
                    "Proofs mint transport error: {e}\n\
                     If unpaid, pay the mint BOLT11 then: grok routstr mint --complete {quote_id}"
                ),
            );
            return Ok(RoutstrMintOutcome::ResidualFallback);
        }
    };

    match proofs {
        grok_bitcoin_wallet::cashu::MintProofsOutcome::Token {
            mut token,
            amount_sats,
            quote_id: qid,
        } => {
            let amount_sats = if amount_sats > 0 {
                amount_sats
            } else {
                amount_hint
            };
            let redacted = CashuToken::parse(&token)
                .map(|t| t.redacted())
                .unwrap_or_else(|_| "cashuA…[REDACTED]".to_owned());
            for line in cashu_mint_token_obtained_lines(amount_sats, &qid, &redacted) {
                eprintln!("{line}");
            }
            // Redeem — only claim float on success. On redeem fail, surface the
            // full token once (stdout) so the user can retry redeem — same
            // one-shot pattern as live refund token return. Never Debug-dump.
            let outcome = match run_routstr_redeem(&token) {
                Ok(()) => {
                    for line in cashu_mint_float_credited_lines(Some(amount_sats)) {
                        eprintln!("{line}");
                    }
                    RoutstrMintOutcome::FloatCredited {
                        quote_id: qid,
                        amount_sats,
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    eprintln!("Redeem failed (token is NOT Routstr float yet): {msg}");
                    eprintln!("Cashu token (copy now; not re-shown or logged in full):");
                    // One-time surface of the bearer to the user TTY (funds recovery).
                    println!("{token}");
                    eprintln!(
                        "Retry: grok routstr redeem <paste-token-above>. \
                         Store offline if needed; this is not prepaid Routstr float until redeem succeeds."
                    );
                    RoutstrMintOutcome::TokenObtainedNotRedeemed {
                        quote_id: qid,
                        amount_sats,
                        redeem_error: msg,
                    }
                }
            };
            // Zeroize bearer buffer after redeem Ok/Err (parity with helper Drop hygiene).
            grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut token);
            Ok(outcome)
        }
        grok_bitcoin_wallet::cashu::MintProofsOutcome::Unsupported(reason) => {
            print_mint_p0_fallback(
                Some(amount_hint),
                &format!("Proofs mint unsupported: {reason}"),
            );
            Ok(RoutstrMintOutcome::ResidualFallback)
        }
        grok_bitcoin_wallet::cashu::MintProofsOutcome::Failed(e) => {
            print_mint_p0_fallback(
                Some(amount_hint),
                &format!(
                    "Proofs mint failed: {e}\n\
                     If the quote is unpaid, pay the mint BOLT11 first, then: \
                     grok routstr mint --complete {quote_id}"
                ),
            );
            Ok(RoutstrMintOutcome::ResidualFallback)
        }
    }
}

/// TUI mint **quote** after unlock re-entry (product Cashu backend).
///
/// Same SeedVault gates as spend/utxos/topup-local-pay. Zeroizes re-entry phrase.
/// When not `proofs_mint_live`, returns residual lines without touching SeedVault.
pub fn complete_routstr_mint_quote_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    amount_sats: Option<u64>,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrMintQuoteSuccess, RoutstrCliError> {
    let cashu = grok_bitcoin_wallet::cashu::default_cashu_backend();
    complete_routstr_mint_quote_reentry_for_tui_with_cashu(
        grok_home,
        reentry_phrase,
        password,
        amount_sats,
        bip39_passphrase,
        &cashu,
    )
}

/// Injectable Cashu backend for TUI mint quote (unit tests).
pub fn complete_routstr_mint_quote_reentry_for_tui_with_cashu(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    amount_sats: Option<u64>,
    bip39_passphrase: Option<&str>,
    cashu: &dyn grok_bitcoin_wallet::cashu::CashuBackend,
) -> Result<RoutstrMintQuoteSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::cashu::{
        CashuMintProductPath, cashu_mint_quote_display_lines, cashu_mint_residual_lines,
        decide_cashu_mint_product_path,
    };
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    let path = decide_cashu_mint_product_path(cashu.capabilities());
    if path != CashuMintProductPath::LiveProofs {
        let mut lines = cashu_mint_residual_lines(amount_sats, path);
        lines.extend(grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(
            amount_sats,
        ));
        return Ok(RoutstrMintQuoteSuccess {
            lines,
            quote_id: None,
            bolt11: None,
            amount_sats: None,
        });
    }

    let amount = grok_bitcoin_wallet::routstr_invoice::resolve_topup_amount_sats(amount_sats)
        .map_err(RoutstrCliError::Message)?;

    let mut reentry = reentry_phrase.to_owned();
    let unlock_fail = |reason: &str| {
        let mut lines = vec![
            "Could not unlock SeedVault for Cashu mint quote; falling through to P0 topup."
                .to_owned(),
            format!("Detail: {reason}"),
        ];
        lines.extend(grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(
            Some(amount),
        ));
        RoutstrMintQuoteSuccess {
            lines,
            quote_id: None,
            bolt11: None,
            amount_sats: None,
        }
    };
    let finish_unlock_fail =
        |reentry: &mut String, reason: &str| -> Result<RoutstrMintQuoteSuccess, RoutstrCliError> {
            grok_bitcoin_wallet::mnemonic::zeroize_phrase(reentry);
            Ok(unlock_fail(reason))
        };

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = match SeedVault::with_aead_path(&aead_path) {
        Ok(v) => v,
        Err(e) => return finish_unlock_fail(&mut reentry, &e.to_string()),
    };

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return finish_unlock_fail(&mut reentry, password_required_message());
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return finish_unlock_fail(&mut reentry, &keyring_blocked_message(&reason));
            }
            FundPathDecision::NewWallet => {
                return finish_unlock_fail(
                    &mut reentry,
                    "no local wallet found for Cashu mint. Run `grok routstr fund` first, \
                     or use `grok routstr topup` (P0) for Routstr float.",
                );
            }
            FundPathDecision::LoadError { message } => {
                return finish_unlock_fail(&mut reentry, &message);
            }
            FundPathDecision::ReturningUnlock => {
                return finish_unlock_fail(
                    &mut reentry,
                    "internal mint quote: unexpected ReturningUnlock on load error",
                );
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return finish_unlock_fail(&mut reentry, &e.to_string());
        }
    };
    let mut gate = MnemonicBackupGate::new();
    if let Err(e) = gate.begin_reentry_without_display(unlocked) {
        session.lock();
        return finish_unlock_fail(&mut reentry, &e.to_string());
    }
    if reentry.trim().is_empty() {
        session.lock();
        return finish_unlock_fail(
            &mut reentry,
            "recovery phrase re-entry cancelled; use `grok routstr topup` for P0 float",
        );
    }
    if let Err(e) = gate.confirm_reentry(&reentry) {
        session.lock();
        return finish_unlock_fail(&mut reentry, &e.to_string());
    }
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut reentry);

    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Ok(unlock_fail(&e.to_string()));
        }
    };
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    let quote = cashu.request_mint_invoice_with_seed(Some(amount), unlocked, bip39_pass.expose());
    session.lock();

    match quote {
        Ok(grok_bitcoin_wallet::cashu::MintQuoteOutcome::Invoice { bolt11, quote_id }) => {
            if bolt11.trim().is_empty()
                || !grok_bitcoin_wallet::routstr_invoice::looks_like_bolt11(&bolt11)
            {
                return Ok(RoutstrMintQuoteSuccess {
                    lines: vec![
                        "Mint quote returned empty/non-bolt11 request (no fabricated invoice)."
                            .to_owned(),
                    ]
                    .into_iter()
                    .chain(cashu_mint_residual_lines(
                        Some(amount),
                        CashuMintProductPath::LiveProofs,
                    ))
                    .collect(),
                    quote_id: None,
                    bolt11: None,
                    amount_sats: None,
                });
            }
            let mut lines = cashu_mint_quote_display_lines(&bolt11, &quote_id, Some(amount));
            lines.push(
                "Authorize proofs mint after pay with: /routstr unlock <recovery phrase…> \
                 (staged after-pay). Token is still not float until redeem succeeds."
                    .to_owned(),
            );
            Ok(RoutstrMintQuoteSuccess {
                lines,
                quote_id: Some(quote_id),
                bolt11: Some(bolt11),
                amount_sats: Some(amount),
            })
        }
        Ok(grok_bitcoin_wallet::cashu::MintQuoteOutcome::Unsupported(reason)) => {
            Ok(RoutstrMintQuoteSuccess {
                lines: {
                    let mut l = vec![format!("Mint quote unsupported: {reason}")];
                    l.extend(cashu_mint_residual_lines(
                        Some(amount),
                        CashuMintProductPath::LiveProofs,
                    ));
                    l
                },
                quote_id: None,
                bolt11: None,
                amount_sats: None,
            })
        }
        Ok(grok_bitcoin_wallet::cashu::MintQuoteOutcome::Failed(e)) => {
            Ok(RoutstrMintQuoteSuccess {
                lines: {
                    let mut l = vec![format!("Mint quote failed: {e}")];
                    l.extend(cashu_mint_residual_lines(
                        Some(amount),
                        CashuMintProductPath::LiveProofs,
                    ));
                    l.extend(grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(
                        Some(amount),
                    ));
                    l
                },
                quote_id: None,
                bolt11: None,
                amount_sats: None,
            })
        }
        Err(e) => Ok(unlock_fail(&e.to_string())),
    }
}

/// TUI mint **after-pay** (proofs → redeem) after unlock re-entry.
///
/// Product Cashu backend + real redeem. Never puts full token in `lines`.
/// `amount_sats_hint` is a display/float-lines fallback when the helper reports
/// zero amount (staged from the mint quote).
pub fn complete_routstr_mint_after_pay_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    quote_id: &str,
    bip39_passphrase: Option<&str>,
    amount_sats_hint: Option<u64>,
) -> Result<RoutstrMintAfterPaySuccess, RoutstrCliError> {
    let cashu = grok_bitcoin_wallet::cashu::default_cashu_backend();
    complete_routstr_mint_after_pay_reentry_for_tui_with_cashu(
        grok_home,
        reentry_phrase,
        password,
        quote_id,
        bip39_passphrase,
        amount_sats_hint,
        &cashu,
        None,
    )
}

/// Test-only redeem hook: token string → Ok/Err (skips live HTTP redeem).
type MintRedeemHook = dyn Fn(&str) -> Result<(), String>;

/// Injectable Cashu + optional redeem hook for unit tests (skip live HTTP redeem).
///
/// When `redeem` is `Some`, it is called with the token instead of
/// [`run_routstr_redeem`]. When `None`, product uses live redeem.
/// `amount_sats_hint` falls back when helper `amount_sats` is 0.
pub fn complete_routstr_mint_after_pay_reentry_for_tui_with_cashu(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    quote_id: &str,
    bip39_passphrase: Option<&str>,
    amount_sats_hint: Option<u64>,
    cashu: &dyn grok_bitcoin_wallet::cashu::CashuBackend,
    redeem: Option<&MintRedeemHook>,
) -> Result<RoutstrMintAfterPaySuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::cashu::{
        CashuMintProductPath, CashuToken, cashu_mint_float_credited_lines,
        cashu_mint_residual_lines, cashu_mint_token_obtained_lines, decide_cashu_mint_product_path,
    };
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    let path = decide_cashu_mint_product_path(cashu.capabilities());
    if path != CashuMintProductPath::LiveProofs {
        return Ok(RoutstrMintAfterPaySuccess {
            lines: cashu_mint_residual_lines(None, path),
            float_credited: false,
            token_obtained: false,
            token_for_clipboard: None,
            amount_sats: None,
            quote_id: None,
        });
    }

    let q = quote_id.trim();
    if q.is_empty() {
        return Err(RoutstrCliError::Message(
            "internal mint after-pay: empty quote_id".into(),
        ));
    }

    let mut reentry = reentry_phrase.to_owned();
    let unlock_fail = |reason: &str| RoutstrMintAfterPaySuccess {
        lines: vec![
            "Could not unlock SeedVault for Cashu proofs mint.".to_owned(),
            format!("Detail: {reason}"),
            format!("Resume with: grok routstr mint --complete {q}"),
        ],
        float_credited: false,
        token_obtained: false,
        token_for_clipboard: None,
        amount_sats: None,
        quote_id: None,
    };
    let finish_unlock_fail = |reentry: &mut String,
                              reason: &str|
     -> Result<RoutstrMintAfterPaySuccess, RoutstrCliError> {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(reentry);
        Ok(unlock_fail(reason))
    };

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = match SeedVault::with_aead_path(&aead_path) {
        Ok(v) => v,
        Err(e) => return finish_unlock_fail(&mut reentry, &e.to_string()),
    };

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return finish_unlock_fail(&mut reentry, password_required_message());
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return finish_unlock_fail(&mut reentry, &keyring_blocked_message(&reason));
            }
            FundPathDecision::NewWallet => {
                return finish_unlock_fail(
                    &mut reentry,
                    "no local wallet found for Cashu proofs mint",
                );
            }
            FundPathDecision::LoadError { message } => {
                return finish_unlock_fail(&mut reentry, &message);
            }
            FundPathDecision::ReturningUnlock => {
                return finish_unlock_fail(
                    &mut reentry,
                    "internal mint after-pay: unexpected ReturningUnlock",
                );
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return finish_unlock_fail(&mut reentry, &e.to_string());
        }
    };
    let mut gate = MnemonicBackupGate::new();
    if let Err(e) = gate.begin_reentry_without_display(unlocked) {
        session.lock();
        return finish_unlock_fail(&mut reentry, &e.to_string());
    }
    if reentry.trim().is_empty() {
        session.lock();
        return finish_unlock_fail(&mut reentry, "recovery phrase re-entry cancelled");
    }
    if let Err(e) = gate.confirm_reentry(&reentry) {
        session.lock();
        return finish_unlock_fail(&mut reentry, &e.to_string());
    }
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut reentry);

    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Ok(unlock_fail(&e.to_string()));
        }
    };
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    let proofs = cashu.complete_mint_after_pay_with_seed(q, unlocked, bip39_pass.expose());
    session.lock();

    match proofs {
        Ok(grok_bitcoin_wallet::cashu::MintProofsOutcome::Token {
            mut token,
            amount_sats,
            quote_id: qid,
        }) => {
            let amount_sats = if amount_sats > 0 {
                amount_sats
            } else {
                amount_sats_hint.unwrap_or(0)
            };
            let redacted = CashuToken::parse(&token)
                .map(|t| t.redacted())
                .unwrap_or_else(|_| "cashuA…[REDACTED]".to_owned());
            let mut lines = cashu_mint_token_obtained_lines(amount_sats, &qid, &redacted);

            let redeem_result = match redeem {
                Some(f) => f(&token),
                None => run_routstr_redeem(&token).map_err(|e| e.to_string()),
            };

            match redeem_result {
                Ok(()) => {
                    lines.extend(cashu_mint_float_credited_lines(Some(amount_sats)));
                    // Redeemed — wipe local bearer buffer (float is on the node).
                    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut token);
                    Ok(RoutstrMintAfterPaySuccess {
                        lines,
                        float_credited: true,
                        token_obtained: true,
                        // Float already credited — no need to clipboard token.
                        token_for_clipboard: None,
                        amount_sats: Some(amount_sats),
                        quote_id: Some(qid),
                    })
                }
                Err(e) => {
                    lines.push(format!("Redeem failed (still not Routstr float): {e}"));
                    lines.push(
                        "Full token copied to clipboard when available (not stored in scrollback). \
                         Retry: grok routstr redeem <token>."
                            .to_owned(),
                    );
                    Ok(RoutstrMintAfterPaySuccess {
                        lines,
                        float_credited: false,
                        token_obtained: true,
                        // Move token to clipboard field (caller zeroizes after copy).
                        token_for_clipboard: Some(token),
                        amount_sats: Some(amount_sats),
                        quote_id: Some(qid),
                    })
                }
            }
        }
        Ok(grok_bitcoin_wallet::cashu::MintProofsOutcome::Unsupported(reason)) => {
            Ok(RoutstrMintAfterPaySuccess {
                lines: vec![format!("Proofs mint unsupported: {reason}")]
                    .into_iter()
                    .chain(cashu_mint_residual_lines(None, path))
                    .collect(),
                float_credited: false,
                token_obtained: false,
                token_for_clipboard: None,
                amount_sats: None,
                quote_id: None,
            })
        }
        Ok(grok_bitcoin_wallet::cashu::MintProofsOutcome::Failed(e)) => {
            Ok(RoutstrMintAfterPaySuccess {
                lines: vec![
                    format!("Proofs mint failed: {e}"),
                    format!(
                        "If unpaid, pay the mint BOLT11 then: grok routstr mint --complete {q}"
                    ),
                ],
                float_credited: false,
                token_obtained: false,
                token_for_clipboard: None,
                amount_sats: None,
                quote_id: Some(q.to_owned()),
            })
        }
        Err(e) => Ok(unlock_fail(&e.to_string())),
    }
}

/// Origin used for `/lightning/*` (strip trailing `/v1` from API URL).
pub fn routstr_node_origin() -> String {
    let base = ROUTSTR_API_URL.trim_end_matches('/');
    if let Some(stripped) = base.strip_suffix("/v1") {
        if stripped.is_empty() {
            ROUTSTR_NODE_ORIGIN.to_owned()
        } else {
            stripped.to_owned()
        }
    } else {
        ROUTSTR_NODE_ORIGIN.to_owned()
    }
}

/// Create a Lightning invoice on the Routstr node (blocking HTTP).
pub fn create_routstr_lightning_invoice(
    amount_sats: u64,
) -> Result<grok_bitcoin_wallet::routstr_invoice::InvoiceCreateResponse, String> {
    use grok_bitcoin_wallet::routstr_invoice::{
        InvoicePurpose, ROUTSTR_LIGHTNING_INVOICE_PATH, invoice_create_request_json,
        parse_invoice_create_response, validate_invoice_amount_sats,
    };

    let amount_sats = validate_invoice_amount_sats(amount_sats)?;
    let existing = load_routstr_api_key_default().ok().flatten();
    let purpose = if existing.is_some() {
        InvoicePurpose::Topup
    } else {
        InvoicePurpose::Create
    };
    let body = invoice_create_request_json(amount_sats, purpose)?;
    let url = format!("{}{ROUTSTR_LIGHTNING_INVOICE_PATH}", routstr_node_origin());

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .body(body);

    if let Some(key) = existing.as_deref() {
        req = req.header("Authorization", format!("Bearer {key}"));
    }

    let resp = req
        .send()
        .map_err(|e| format!("invoice create request: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("invoice create body: {e}"))?;
    if !status.is_success() {
        return Err(format_routstr_http_error("invoice create", status, &text));
    }
    parse_invoice_create_response(&text)
}

/// Fetch invoice status (blocking HTTP).
pub fn fetch_routstr_invoice_status(
    invoice_id: &str,
) -> Result<grok_bitcoin_wallet::routstr_invoice::InvoiceStatusResponse, String> {
    use grok_bitcoin_wallet::routstr_invoice::{
        invoice_status_path, parse_invoice_status_response,
    };

    let path = invoice_status_path(invoice_id)?;
    let url = format!("{}{path}", routstr_node_origin());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(&url)
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .send()
        .map_err(|e| format!("invoice status request: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("invoice status body: {e}"))?;
    if !status.is_success() {
        return Err(format_routstr_http_error("invoice status", status, &text));
    }
    parse_invoice_status_response(&text)
}

/// Recover invoice status from BOLT11 (`POST /lightning/recover`).
pub fn recover_routstr_invoice_status(
    bolt11: &str,
) -> Result<grok_bitcoin_wallet::routstr_invoice::InvoiceStatusResponse, String> {
    use grok_bitcoin_wallet::routstr_invoice::{
        ROUTSTR_LIGHTNING_RECOVER_PATH, invoice_recover_request_json, parse_invoice_status_response,
    };

    let body = invoice_recover_request_json(bolt11)?;
    let url = format!("{}{ROUTSTR_LIGHTNING_RECOVER_PATH}", routstr_node_origin());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .body(body)
        .send()
        .map_err(|e| format!("invoice recover request: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("invoice recover body: {e}"))?;
    if !status.is_success() {
        return Err(format_routstr_http_error("invoice recover", status, &text));
    }
    parse_invoice_status_response(&text)
}

/// `GET /v1/balance/create?initial_balance_token=` — Cashu → new balance/key.
pub fn create_routstr_balance_with_cashu(cashu_token: &str) -> Result<String, String> {
    let token = cashu_token.trim();
    if token.is_empty() {
        return Err("cashu token must not be empty".into());
    }
    // Reject obvious path injection; full Cashu parse is done by callers when available.
    if token.contains('\n') || token.contains('\r') {
        return Err("cashu token must not contain newlines".into());
    }
    let url = reqwest::Url::parse_with_params(
        &format!("{ROUTSTR_API_URL}/balance/create"),
        &[("initial_balance_token", token)],
    )
    .map_err(|e| format!("balance create url: {e}"))?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(url)
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .send()
        .map_err(|e| format!("balance create request: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("balance create body: {e}"))?;
    if !status.is_success() {
        return Err(format_routstr_http_error("balance create", status, &text));
    }
    parse_routstr_api_key_from_body(&text)
        .ok_or_else(|| "balance create: no api_key in response".into())
}

/// `POST /v1/balance/topup` with Cashu token into an existing key.
///
/// Returns optional balance msats when the body includes unit fields.
/// Refuses residual auth material (never Bearer-sends seed / NIP-98 / Other).
pub fn topup_routstr_balance_with_cashu(
    api_key: &str,
    cashu_token: &str,
) -> Result<Option<u64>, String> {
    let key = validate_routstr_product_bearer_key(api_key).map_err(|e| e.to_string())?;
    let token = cashu_token.trim();
    if token.is_empty() {
        return Err("cashu token must not be empty".into());
    }
    if token.contains('\n') || token.contains('\r') {
        return Err("cashu token must not contain newlines".into());
    }
    let url = format!("{ROUTSTR_API_URL}/balance/topup");
    let body = serde_json::json!({ "cashu_token": token }).to_string();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {key}"))
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .body(body)
        .send()
        .map_err(|e| format!("balance topup request: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("balance topup body: {e}"))?;
    if !status.is_success() {
        return Err(format_routstr_http_error("balance topup", status, &text));
    }
    Ok(parse_routstr_msats_flexible(&text))
}

/// Live `POST /v1/balance/refund` — returns Cashu token string once when present.
///
/// Caller must not log the full token (use [`redact_secret_preview`]).
/// Refuses residual auth material (never Bearer-sends seed / NIP-98 / Other).
pub fn refund_routstr_balance_live(api_key: &str) -> Result<Option<String>, String> {
    let key = validate_routstr_product_bearer_key(api_key).map_err(|e| e.to_string())?;
    let url = format!("{ROUTSTR_API_URL}/balance/refund");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("HTTP-Referer", ROUTSTR_HTTP_REFERER)
        .header("X-Title", ROUTSTR_X_TITLE)
        .send()
        .map_err(|e| format!("balance refund request: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| format!("balance refund body: {e}"))?;
    if !status.is_success() {
        return Err(format_routstr_http_error("balance refund", status, &text));
    }
    Ok(parse_routstr_refund_cashu_token(&text))
}

/// Poll status until paid (returns api_key), terminal unpaid, attempts exhausted, or error.
fn poll_routstr_invoice_until_paid(
    invoice_id: &str,
    attempts: u32,
    sleep_secs: u64,
) -> Result<Option<String>, String> {
    for i in 0..attempts {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
        }
        let st = fetch_routstr_invoice_status(invoice_id)?;
        if let Some(key) = st.api_key_if_paid() {
            return Ok(Some(key.to_owned()));
        }
        if st.is_paid() {
            return Ok(None);
        }
        if st.is_terminal_unpaid() {
            eprintln!();
            return Err(format!(
                "invoice {invoice_id} ended unpaid (status={})",
                st.status
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if st.is_expired_at(now) {
            eprintln!();
            return Err(format!(
                "invoice {invoice_id} expired (expires_at={})",
                st.expires_at
            ));
        }
        eprint!(".");
        let _ = io::stderr().flush();
    }
    eprintln!();
    Ok(None)
}

/// Structured outcome of product refund / local melt CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutstrRefundOutcome {
    /// Node `POST /v1/balance/refund` returned a Cashu token (printed once).
    NodeTokenReturned,
    /// Node refund HTTP ok but no token field.
    NodeNoToken,
    /// Local CDK melt Completed (Paid) — **not** Routstr float credit.
    MeltPaid { detail: String },
    /// Not live / unlock cancel / melt fail / node fail — residual printed.
    ResidualFallback,
}

/// Outcome of TUI local melt after unlock re-entry (no BIP-39 / no full token in payload).
///
/// `melted` is true **only** when helper IPC reported Paid. Never claims float.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrMeltSuccess {
    pub lines: Vec<String>,
    /// True only when melt Completed (state=PAID). Never means sk- float credit.
    pub melted: bool,
}

/// `grok routstr refund`: node float refund and/or local Cashu melt.
///
/// - **No `--token` / `--invoice`:** live `POST /v1/balance/refund` when a key
///   exists; otherwise residual (no fabricated Cashu token). Surfaces returned
///   Cashu **once** on stdout; never logs the full token at Debug.
/// - **Both `--token` + `--invoice`:** when `spend_live`/`refund_live`, SeedVault
///   unlock → [`CashuBackend::melt_token_to_bolt11_with_seed`]. Success only when
///   helper IPC returns Paid. **Never claims Routstr sk- float** (melt spends
///   Cashu to LN). Token + phrase buffers zeroized on all paths.
/// - Exactly one of token/invoice → usage error.
///
/// When melt not live / unlock cancel / fail → residual + node refund next-steps.
pub fn run_routstr_refund(
    token: Option<&str>,
    invoice: Option<&str>,
) -> Result<RoutstrRefundOutcome, RoutstrCliError> {
    if !routstr_balance_fetch_enabled_from_disk() {
        return Err(RoutstrCliError::FeatureDisabled);
    }
    let token_opt = token.map(str::trim).filter(|s| !s.is_empty());
    let invoice_opt = invoice.map(str::trim).filter(|s| !s.is_empty());
    match (token_opt, invoice_opt) {
        (Some(t), Some(inv)) => {
            let cashu = grok_bitcoin_wallet::cashu::default_cashu_backend();
            run_routstr_melt_with_cashu(t, inv, &cashu)
        }
        (None, None) => run_routstr_node_refund(),
        (Some(_), None) => Err(RoutstrCliError::Message(
            "melt requires both --token <cashuA…> and --invoice <BOLT11> \
             (or omit both for node float refund)"
                .into(),
        )),
        (None, Some(_)) => Err(RoutstrCliError::Message(
            "melt requires both --token <cashuA…> and --invoice <BOLT11> \
             (or omit both for node float refund)"
                .into(),
        )),
    }
}

/// Node-only refund path (POST /v1/balance/refund).
fn run_routstr_node_refund() -> Result<RoutstrRefundOutcome, RoutstrCliError> {
    let Some(key) = load_routstr_api_key_default()
        .map_err(|e| RoutstrCliError::Message(e.to_string()))?
        .filter(|k| !k.trim().is_empty())
    else {
        eprintln!("No Routstr API key — cannot call live refund.");
        for line in grok_bitcoin_wallet::funding_cli::refund_next_steps_lines() {
            eprintln!("{line}");
        }
        return Ok(RoutstrRefundOutcome::ResidualFallback);
    };
    match refund_routstr_balance_live(&key) {
        Ok(Some(token)) => {
            let redacted = redact_secret_preview(&token);
            eprintln!("Routstr refund succeeded (Cashu token returned once).");
            eprintln!("Redacted: {redacted}");
            eprintln!("Cashu token (copy now; not re-shown or logged in full):");
            // One-time surface of the secret to the user TTY.
            println!("{token}");
            eprintln!(
                "Store this token offline if you need it. Hot float on the node may now be zero."
            );
            Ok(RoutstrRefundOutcome::NodeTokenReturned)
        }
        Ok(None) => {
            eprintln!(
                "Routstr refund HTTP succeeded but no Cashu token field was found in the body."
            );
            eprintln!("Run `grok routstr balance` to check remaining float.");
            Ok(RoutstrRefundOutcome::NodeNoToken)
        }
        Err(e) => {
            eprintln!("Routstr live refund failed: {e}");
            eprintln!("Falling back to residual next-steps (no fabricated token).");
            for line in grok_bitcoin_wallet::funding_cli::refund_next_steps_lines() {
                eprintln!("{line}");
            }
            Ok(RoutstrRefundOutcome::ResidualFallback)
        }
    }
}

/// Print **true not-live** residual melt honesty + node refund next-steps.
///
/// Only for paths that never offered live melt (stub / helper missing / invalid
/// args before LiveMelt gate). Do **not** use after LiveMelt was selected —
/// that inverts capability honesty (see [`print_melt_live_fail_fallback`]).
fn print_melt_residual_fallback(detail: &str) {
    use grok_bitcoin_wallet::cashu::cashu_melt_residual_lines;
    if !detail.is_empty() {
        eprintln!("{detail}");
    }
    for line in cashu_melt_residual_lines() {
        eprintln!("{line}");
    }
    eprintln!();
    eprintln!("Node float refund next steps:");
    for line in grok_bitcoin_wallet::funding_cli::refund_next_steps_lines() {
        eprintln!("{line}");
    }
}

/// Print live-attempt melt failure honesty (unlock cancel / helper Failed / transport).
///
/// Capability was live — never claims "not live". Never claims sk- float.
fn print_melt_live_fail_fallback(detail: &str) {
    use grok_bitcoin_wallet::cashu::cashu_melt_failed_lines;
    for line in cashu_melt_failed_lines(detail) {
        eprintln!("{line}");
    }
}

/// Local CDK melt product path (token + bolt11 + SeedVault). Injectable backend.
///
/// Owned `token` is zeroized on every return path. Never claims sk- float.
pub fn run_routstr_melt_with_cashu(
    token: &str,
    bolt11: &str,
    cashu: &dyn grok_bitcoin_wallet::cashu::CashuBackend,
) -> Result<RoutstrRefundOutcome, RoutstrCliError> {
    use grok_bitcoin_wallet::cashu::{
        CashuMeltProductPath, CashuRefundOutcome, cashu_melt_paid_lines,
        decide_cashu_melt_product_path,
    };

    let mut token_buf = token.trim().to_owned();
    let bolt11 = bolt11.trim();

    let finish = |token_buf: &mut String, out: RoutstrRefundOutcome| {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(token_buf);
        out
    };

    // Match TUI order: product path first. Shape failures after LiveMelt use
    // live-fail lines (never "not live"); residual printer only when not offered.
    let path = decide_cashu_melt_product_path(cashu.capabilities());
    if path != CashuMeltProductPath::LiveMelt {
        print_melt_residual_fallback("");
        return Ok(finish(
            &mut token_buf,
            RoutstrRefundOutcome::ResidualFallback,
        ));
    }

    if token_buf.is_empty() || bolt11.is_empty() {
        print_melt_live_fail_fallback("melt requires non-empty token and BOLT11");
        return Ok(finish(
            &mut token_buf,
            RoutstrRefundOutcome::ResidualFallback,
        ));
    }

    if grok_bitcoin_wallet::cashu::CashuToken::parse(&token_buf).is_err() {
        print_melt_live_fail_fallback(
            "token failed CashuToken::parse (need cashuA…/cashuB…); no melt attempted",
        );
        return Ok(finish(
            &mut token_buf,
            RoutstrRefundOutcome::ResidualFallback,
        ));
    }
    if !grok_bitcoin_wallet::routstr_invoice::looks_like_bolt11(bolt11) {
        print_melt_live_fail_fallback(
            "invoice failed looks_like_bolt11 (lnurl rejected); no melt attempted",
        );
        return Ok(finish(
            &mut token_buf,
            RoutstrRefundOutcome::ResidualFallback,
        ));
    }

    eprintln!(
        "Cashu melt path is live — unlocking SeedVault (token → destination BOLT11; \
         not Routstr float)…"
    );
    let mut session = match unlock_seed_session_for_local_bolt11_pay() {
        Ok(s) => s,
        Err(reason) => {
            print_melt_live_fail_fallback(&format!(
                "Could not unlock SeedVault for Cashu melt: {reason}"
            ));
            return Ok(finish(
                &mut token_buf,
                RoutstrRefundOutcome::ResidualFallback,
            ));
        }
    };

    use std::time::Instant;
    let bip39_pass = product_bip39_passphrase_from_env();
    let mnemonic = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            print_melt_live_fail_fallback(&format!("SeedVault session error: {e}"));
            return Ok(finish(
                &mut token_buf,
                RoutstrRefundOutcome::ResidualFallback,
            ));
        }
    };

    let outcome =
        cashu.melt_token_to_bolt11_with_seed(&token_buf, bolt11, mnemonic, bip39_pass.expose());
    session.lock();
    // Token buffer no longer needed after melt call (helper may have copied).
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut token_buf);

    match outcome {
        Ok(CashuRefundOutcome::Completed { detail }) => {
            for line in cashu_melt_paid_lines(&detail) {
                eprintln!("{line}");
            }
            Ok(RoutstrRefundOutcome::MeltPaid { detail })
        }
        Ok(CashuRefundOutcome::Unsupported(reason)) => {
            // Live gate passed but backend returned Unsupported (helper race /
            // mid-run unlink) — still live-fail honesty, not "not live" residual.
            print_melt_live_fail_fallback(&format!("Melt unsupported: {reason}"));
            Ok(RoutstrRefundOutcome::ResidualFallback)
        }
        Ok(CashuRefundOutcome::Failed(e)) => {
            print_melt_live_fail_fallback(&format!("Melt failed: {e}"));
            Ok(RoutstrRefundOutcome::ResidualFallback)
        }
        Err(e) => {
            print_melt_live_fail_fallback(&format!("Melt transport error: {e}"));
            Ok(RoutstrRefundOutcome::ResidualFallback)
        }
    }
}

/// TUI local melt after unlock re-entry (product Cashu backend).
///
/// Same SeedVault gates as mint/spend/topup-local-pay. Zeroizes re-entry phrase
/// **and** token buffer. When not melt-live, residual without SeedVault.
/// Never claims Routstr sk- float.
pub fn complete_routstr_melt_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    token: &str,
    bolt11: &str,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrMeltSuccess, RoutstrCliError> {
    let cashu = grok_bitcoin_wallet::cashu::default_cashu_backend();
    complete_routstr_melt_reentry_for_tui_with_cashu(
        grok_home,
        reentry_phrase,
        password,
        token,
        bolt11,
        bip39_passphrase,
        &cashu,
    )
}

/// Injectable Cashu backend for TUI melt (unit tests without CDK helper).
pub fn complete_routstr_melt_reentry_for_tui_with_cashu(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    token: &str,
    bolt11: &str,
    bip39_passphrase: Option<&str>,
    cashu: &dyn grok_bitcoin_wallet::cashu::CashuBackend,
) -> Result<RoutstrMeltSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::cashu::{
        CashuMeltProductPath, CashuRefundOutcome, cashu_melt_failed_lines, cashu_melt_paid_lines,
        cashu_melt_residual_lines, decide_cashu_melt_product_path,
    };
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    let mut token_buf = token.trim().to_owned();
    let mut reentry = reentry_phrase.to_owned();
    let bolt11 = bolt11.trim();

    let finish = |token_buf: &mut String,
                  reentry: &mut String,
                  success: RoutstrMeltSuccess|
     -> Result<RoutstrMeltSuccess, RoutstrCliError> {
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(token_buf);
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(reentry);
        Ok(success)
    };

    let path = decide_cashu_melt_product_path(cashu.capabilities());
    if path != CashuMeltProductPath::LiveMelt {
        let mut lines = cashu_melt_residual_lines();
        lines.extend(grok_bitcoin_wallet::funding_cli::refund_next_steps_lines());
        return finish(
            &mut token_buf,
            &mut reentry,
            RoutstrMeltSuccess {
                lines,
                melted: false,
            },
        );
    }

    if token_buf.is_empty() || grok_bitcoin_wallet::cashu::CashuToken::parse(&token_buf).is_err() {
        return finish(
            &mut token_buf,
            &mut reentry,
            RoutstrMeltSuccess {
                lines: cashu_melt_failed_lines(
                    "token failed CashuToken::parse (need cashuA…/cashuB…)",
                ),
                melted: false,
            },
        );
    }
    if bolt11.is_empty() || !grok_bitcoin_wallet::routstr_invoice::looks_like_bolt11(bolt11) {
        return finish(
            &mut token_buf,
            &mut reentry,
            RoutstrMeltSuccess {
                lines: cashu_melt_failed_lines("invoice failed looks_like_bolt11 (lnurl rejected)"),
                melted: false,
            },
        );
    }

    let unlock_fail = |reason: &str| RoutstrMeltSuccess {
        lines: cashu_melt_failed_lines(&format!(
            "Could not unlock SeedVault for Cashu melt: {reason}"
        )),
        melted: false,
    };

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = match SeedVault::with_aead_path(&aead_path) {
        Ok(v) => v,
        Err(e) => {
            return finish(&mut token_buf, &mut reentry, unlock_fail(&e.to_string()));
        }
    };

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return finish(
                    &mut token_buf,
                    &mut reentry,
                    unlock_fail(password_required_message()),
                );
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return finish(
                    &mut token_buf,
                    &mut reentry,
                    unlock_fail(&keyring_blocked_message(&reason)),
                );
            }
            FundPathDecision::NewWallet => {
                return finish(
                    &mut token_buf,
                    &mut reentry,
                    unlock_fail(
                        "no local wallet found for Cashu melt. Run `grok routstr fund` first, \
                         or use bare `grok routstr refund` for node float.",
                    ),
                );
            }
            FundPathDecision::LoadError { message } => {
                return finish(&mut token_buf, &mut reentry, unlock_fail(&message));
            }
            FundPathDecision::ReturningUnlock => {
                return finish(
                    &mut token_buf,
                    &mut reentry,
                    unlock_fail("internal melt: unexpected ReturningUnlock on load error"),
                );
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return finish(&mut token_buf, &mut reentry, unlock_fail(&e.to_string()));
        }
    };
    let mut gate = MnemonicBackupGate::new();
    if let Err(e) = gate.begin_reentry_without_display(unlocked) {
        session.lock();
        return finish(&mut token_buf, &mut reentry, unlock_fail(&e.to_string()));
    }
    if reentry.trim().is_empty() {
        session.lock();
        return finish(
            &mut token_buf,
            &mut reentry,
            unlock_fail("recovery phrase re-entry cancelled"),
        );
    }
    if let Err(e) = gate.confirm_reentry(&reentry) {
        session.lock();
        return finish(&mut token_buf, &mut reentry, unlock_fail(&e.to_string()));
    }
    // Phrase confirmed — zeroize re-entry buffer before melt (token still needed).
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut reentry);

    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return finish(&mut token_buf, &mut reentry, unlock_fail(&e.to_string()));
        }
    };
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    let outcome =
        cashu.melt_token_to_bolt11_with_seed(&token_buf, bolt11, unlocked, bip39_pass.expose());
    session.lock();
    grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut token_buf);

    match outcome {
        Ok(CashuRefundOutcome::Completed { detail }) => Ok(RoutstrMeltSuccess {
            lines: cashu_melt_paid_lines(&detail),
            melted: true,
        }),
        Ok(CashuRefundOutcome::Unsupported(reason)) => Ok(RoutstrMeltSuccess {
            lines: cashu_melt_failed_lines(&format!("Melt unsupported: {reason}")),
            melted: false,
        }),
        Ok(CashuRefundOutcome::Failed(e)) => Ok(RoutstrMeltSuccess {
            lines: cashu_melt_failed_lines(&format!("Melt failed: {e}")),
            melted: false,
        }),
        Err(e) => Ok(RoutstrMeltSuccess {
            lines: cashu_melt_failed_lines(&format!("Melt transport error: {e}")),
            melted: false,
        }),
    }
}

/// Successful local prepare (+ optional broadcast) for on-chain spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrSpendSuccess {
    pub payment_address: String,
    pub payment_sats: u64,
    pub fee_sats: u64,
    pub change_sats: u64,
    pub txid: String,
    pub raw_hex: String,
    /// Set only when a broadcaster accepted the tx (never invented).
    pub broadcast_txid: Option<String>,
    pub network_label: String,
    pub lines: Vec<String>,
}

/// Successful TUI UTXO list (observational; never includes BIP-39 / passphrase).
///
/// `lines` are the same product format as CLI `grok routstr utxos` (balance,
/// outpoints, gap notices). Not a spend/broadcast path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrUtxosSuccess {
    pub network_label: String,
    pub lines: Vec<String>,
}

/// Successful local RBF replacement prepare (+ optional broadcast).
///
/// `broadcast_txid` is set **only** when a broadcaster returned Accepted with a
/// parseable txid — never invented from the local replacement txid alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrRbfSuccess {
    pub payment_address: String,
    pub payment_sats: u64,
    pub original_fee_sats: u64,
    pub fee_sats: u64,
    pub change_sats: u64,
    pub txid: String,
    pub raw_hex: String,
    /// Set only when a broadcaster accepted the replacement (never invented).
    pub broadcast_txid: Option<String>,
    pub network_label: String,
    pub fee_rate_sat_vb: u64,
    pub lines: Vec<String>,
}

/// Successful local CPFP **child** prepare (+ optional broadcast).
///
/// Does **not** replace the parent. `broadcast_txid` is set **only** when a
/// broadcaster returned Accepted with a parseable txid — never invented from
/// the local child txid alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrCpfpSuccess {
    pub payment_address: String,
    pub payment_sats: u64,
    pub parent_fee_sats: u64,
    /// Child absolute fee (not package).
    pub fee_sats: u64,
    pub change_sats: u64,
    pub txid: String,
    pub raw_hex: String,
    /// Set only when a broadcaster accepted the child (never invented).
    pub broadcast_txid: Option<String>,
    pub network_label: String,
    pub fee_rate_sat_vb: u64,
    pub lines: Vec<String>,
}

/// Resolve product spend fee rate (sat/vB) with an injected estimate ladder.
///
/// Pure / offline-testable: no network. Order: explicit override (>0) →
/// estimates halfHour (>0) →
/// [`grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB`].
/// Never returns 0. Callers that treat explicit `0` as invalid must reject
/// before calling (see [`run_routstr_spend`] / `parse_spend_request`).
pub fn resolve_spend_fee_rate_with_estimates(
    user_override: Option<u64>,
    estimates: Option<&grok_bitcoin_wallet::explorer::FeeEstimates>,
) -> u64 {
    use grok_bitcoin_wallet::explorer::{FeePriority, resolve_spend_fee_rate_sat_vb};
    use grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB;

    resolve_spend_fee_rate_sat_vb(
        user_override,
        estimates,
        FeePriority::HalfHour,
        DEFAULT_SPEND_FEE_RATE_SAT_VB,
    )
}

/// Try live mempool.space fee ladder for `network` (`explorer-http`).
///
/// Returns `None` on any failure — never invents rates. Blocking; call from
/// CLI / effect worker, not slash-command parse.
pub fn try_fetch_live_fee_estimates_for_network(
    network: grok_bitcoin_wallet::address_ux::BitcoinNetwork,
) -> Option<grok_bitcoin_wallet::explorer::FeeEstimates> {
    grok_bitcoin_wallet::explorer::MempoolHttpClient::with_defaults(network)
        .ok()
        .and_then(|mut c| c.fetch_fee_estimates())
}

/// Try live mempool.space halfHour ladder (`explorer-http`). Returns `None`
/// on any failure — never invents rates. Blocking; call from CLI / effect
/// worker, not slash-command parse.
///
/// Network from `GROK_BITCOIN_NETWORK` (default mainnet).
pub fn try_fetch_live_fee_estimates() -> Option<grok_bitcoin_wallet::explorer::FeeEstimates> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let btc_net =
        BitcoinNetwork::from_env_str(network_str.trim()).unwrap_or(BitcoinNetwork::Mainnet);
    try_fetch_live_fee_estimates_for_network(btc_net)
}

/// Resolve Bitcoin network for `grok routstr fees`.
///
/// Order: explicit CLI `--network` → `GROK_BITCOIN_NETWORK` → mainnet.
/// Rejects unknown network strings (does not silently fall back when the
/// user passed an explicit invalid value).
pub fn resolve_fees_network(
    cli_network: Option<&str>,
) -> Result<grok_bitcoin_wallet::address_ux::BitcoinNetwork, RoutstrCliError> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    if let Some(raw) = cli_network {
        let t = raw.trim();
        if t.is_empty() {
            return Err(RoutstrCliError::Message(
                "invalid --network: empty (use mainnet|signet|testnet|testnet4)".into(),
            ));
        }
        return BitcoinNetwork::from_env_str(t).ok_or_else(|| {
            RoutstrCliError::Message(format!(
                "unknown --network '{t}' (use mainnet|signet|testnet|testnet4)"
            ))
        });
    }
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    let t = network_str.trim();
    if t.is_empty() {
        return Ok(BitcoinNetwork::Mainnet);
    }
    // Env path keeps prior soft-default for unknown labels; product complete
    // fund/spend/rbf/cpfp/utxos use [`resolve_product_complete_network`] /
    // [`resolve_product_entry_network`] (hard error).
    Ok(BitcoinNetwork::from_env_str(t).unwrap_or(BitcoinNetwork::Mainnet))
}

/// Single product-network resolve for complete fund/spend/rbf/cpfp/utxos paths.
///
/// - Empty / whitespace → [`BitcoinNetwork::Mainnet`] (env default).
/// - Known labels (`mainnet|signet|testnet|testnet4` and aliases) → enum.
/// - Unknown (incl. `regtest`) → hard error — **never** silent Mainnet.
///
/// Wallet construction / receive derive must use
/// [`grok_bitcoin_wallet::onchain::bitcoin_network_to_network`] on the result
/// (not a second string parse with a different acceptance set — e.g. do not
/// call env-string derive helpers that still accept `regtest`).
pub fn resolve_product_complete_network(
    network_str: &str,
) -> Result<grok_bitcoin_wallet::address_ux::BitcoinNetwork, RoutstrCliError> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    let t = network_str.trim();
    if t.is_empty() {
        return Ok(BitcoinNetwork::Mainnet);
    }
    BitcoinNetwork::from_env_str(t).ok_or_else(|| {
        RoutstrCliError::Message(format!(
            "unknown network '{t}' (use mainnet|signet|testnet|testnet4)"
        ))
    })
}

/// Product entry network for fund/utxos/spend/rbf/cpfp CLI + TUI (fail-closed).
///
/// Order: explicit CLI/slash `--network` → `GROK_BITCOIN_NETWORK` → mainnet.
/// - Explicit empty → hard error (invalid flag).
/// - Explicit or env unknown (incl. `regtest`) → hard error — **never** silent
///   Mainnet (unlike [`resolve_fees_network`] env soft-default, which is fees-only).
/// - Empty env → Mainnet.
///
/// Call **before** vault unlock so poisoned network fails without touching seed.
/// Fund uses env-only (`cli_network = None`); same acceptance as spend entry.
pub fn resolve_product_entry_network(
    cli_network: Option<&str>,
) -> Result<grok_bitcoin_wallet::address_ux::BitcoinNetwork, RoutstrCliError> {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

    if let Some(raw) = cli_network {
        let t = raw.trim();
        if t.is_empty() {
            return Err(RoutstrCliError::Message(
                "invalid --network: empty (use mainnet|signet|testnet|testnet4)".into(),
            ));
        }
        return BitcoinNetwork::from_env_str(t).ok_or_else(|| {
            RoutstrCliError::Message(format!(
                "unknown --network '{t}' (use mainnet|signet|testnet|testnet4)"
            ))
        });
    }
    let network_str = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    resolve_product_complete_network(&network_str)
}

/// Pure product lines for `grok routstr fees` (inject estimates; offline tests).
pub fn fees_command_lines(
    estimates: Option<&grok_bitcoin_wallet::explorer::FeeEstimates>,
    network_label: &str,
) -> Vec<String> {
    grok_bitcoin_wallet::funding_cli::fees_cli_result_lines(estimates, network_label)
}

/// `grok routstr fees [--network …]`: print mempool fee estimate ladder only.
///
/// Live fetch via rate-limited mempool.space (`explorer-http`). Never invents
/// rates when fetch fails — prints honest unavailable copy. Not RBF/CPFP.
pub fn run_routstr_fees(cli_network: Option<&str>) -> Result<(), RoutstrCliError> {
    let btc_net = resolve_fees_network(cli_network)?;
    let network_label = btc_net.as_str();
    let estimates = try_fetch_live_fee_estimates_for_network(btc_net);
    let lines = fees_command_lines(estimates.as_ref(), network_label);
    for line in &lines {
        println!("{line}");
    }
    // Exit 0 with unavailable copy is intentional (honest offline): CLI still
    // succeeds so scripts can print guidance; rates were not fabricated.
    Ok(())
}

/// Pure product lines for `grok routstr utxos` from a gap-sync snapshot
/// (offline-testable; inject mock snapshot — no network).
///
/// Gap-limit residual copy. For BDK path results use
/// [`utxos_command_lines_bdk`] (feature `bdk`) so notices are not mislabeled.
pub fn utxos_command_lines(
    snap: &grok_bitcoin_wallet::descriptor_wallet::WalletSyncSnapshot,
    network_label: &str,
) -> Vec<String> {
    grok_bitcoin_wallet::funding_cli::format_gap_sync_utxos_cli_lines(snap, network_label)
}

/// Pure product lines for `grok routstr utxos` after BDK full_scan (feature `bdk`).
///
/// Uses BDK notice copy — never gap-limit "not full bdk" residual when BDK ran.
#[cfg(feature = "bdk")]
pub fn utxos_command_lines_bdk(
    snap: &grok_bitcoin_wallet::descriptor_wallet::WalletSyncSnapshot,
    network_label: &str,
) -> Vec<String> {
    grok_bitcoin_wallet::funding_cli::format_bdk_sync_utxos_cli_lines(snap, network_label)
}

/// Core UTXO list after vault unlock + re-entry (shared CLI path).
///
/// Default: gap-limit ChainSource sync via
/// [`grok_bitcoin_wallet::descriptor_wallet::list_bip84_utxos_with_gap_sync`]
/// (default [`GapExtendOptions`]). Opt-in prefer-BDK when
/// `GROK_BITCOIN_UTXO_SYNC=bdk` **and** feature `bdk` is compiled (Esplora/
/// Electrum full_scan; mempool fails closed). Prefer-BDK without feature →
/// structured residual (not hang / invent Success). Snapshot UTXOs are
/// authoritative — no post-sync re-list. Product chain selector (default
/// mempool; env selectable). Wrong passphrase fail-closed.
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Never
/// log / format the secret.
pub fn complete_routstr_utxos_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<Vec<String>, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        UtxoSyncMode, open_product_chain_source, product_chain_source_config_from_env,
        product_utxo_sync_mode_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, GapExtendOptions, list_bip84_utxos_with_gap_sync,
    };
    use grok_bitcoin_wallet::funding_cli::bip39_passphrase_active_notice_lines;
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (no dual string parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str();
    // Shared Testnet4 → Testnet mapping for descriptors (matches chain_select / Electrum).
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    let sync_mode = product_utxo_sync_mode_from_env().map_err(RoutstrCliError::Wallet)?;
    let mut lines = match sync_mode {
        UtxoSyncMode::Gap => {
            let mut wallet = DescriptorWallet::from_mnemonic_with_passphrase(
                mnemonic,
                pass,
                rust_net,
                DEFAULT_RECEIVE_GAP,
            )
            .map_err(RoutstrCliError::Wallet)?;

            let chain_cfg =
                product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
            let chain =
                open_product_chain_source(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;

            let snap = list_bip84_utxos_with_gap_sync(
                &mut wallet,
                chain.as_ref(),
                mnemonic,
                pass,
                GapExtendOptions::default(),
            )
            .map_err(RoutstrCliError::Wallet)?;
            utxos_command_lines(&snap, network_label)
        }
        UtxoSyncMode::Bdk => {
            #[cfg(not(feature = "bdk"))]
            {
                let _ = rust_net;
                return Err(RoutstrCliError::Wallet(
                    grok_bitcoin_wallet::chain_select::bdk_utxo_sync_feature_missing_error(),
                ));
            }
            #[cfg(feature = "bdk")]
            {
                use grok_bitcoin_wallet::bdk_sync::{
                    BdkBip84Wallet, list_bip84_utxos_with_bdk_sync, open_product_bdk_update_source,
                };

                let mut bdk = BdkBip84Wallet::from_mnemonic_with_passphrase(
                    mnemonic,
                    pass,
                    rust_net,
                    DEFAULT_RECEIVE_GAP,
                )
                .map_err(RoutstrCliError::Wallet)?;
                let chain_cfg =
                    product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
                let source =
                    open_product_bdk_update_source(&chain_cfg).map_err(RoutstrCliError::Wallet)?;
                let snap = list_bip84_utxos_with_bdk_sync(&mut bdk, source.as_ref())
                    .map_err(RoutstrCliError::Wallet)?;
                utxos_command_lines_bdk(&snap, network_label)
            }
        }
    };
    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }
    Ok(lines)
}

/// `grok routstr utxos [--network …]`: list local wallet UTXOs + on-chain balance.
///
/// Requires SeedVault unlock + recovery-phrase re-entry (same gate as spend/fund).
/// Default UTXO discovery: gap-limit ChainSource (product chain selector; default
/// mempool). Optional prefer-BDK when `GROK_BITCOIN_UTXO_SYNC=bdk` and feature
/// `bdk` is compiled (esplora|electrum full_scan; mempool fails closed; without
/// feature → structured residual). Never invents UTXOs. Not a spend/broadcast path.
pub fn run_routstr_utxos(
    grok_home: &Path,
    cli_network: Option<&str>,
) -> Result<(), RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Fail-closed product network before unlock (not fees soft-default).
    let btc_net = resolve_product_entry_network(cli_network)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal utxos path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    eprintln!("Authorize UTXO list: re-enter your recovery phrase (words are not re-displayed).");
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        if let Err(e) = gate.begin_reentry_without_display(unlocked) {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not listing UTXOs".into(),
            ));
        }
        if let Err(e) = gate.confirm_reentry(&reentry) {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    }

    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };

    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or chain/sync failure) so seed material
    // does not linger until the stack frame ends.
    let result = complete_routstr_utxos_with_mnemonic(unlocked, &network_str, &bip39_pass);
    session.lock();
    let lines = result?;

    for line in &lines {
        println!("{line}");
    }
    Ok(())
}

/// TUI UTXO list after unlock re-entry (no BIP-39 in returned payload).
///
/// Same SeedVault + recovery-phrase gates as [`run_routstr_utxos`] / spend.
/// Observational only — never broadcasts. Product chain selector (default
/// mempool; env selectable). Gap notices still shown on success lines.
///
/// `cli_network`: explicit slash `--network` / `None` →
/// [`resolve_product_entry_network`] (env `GROK_BITCOIN_NETWORK` or mainnet;
/// unknown labels fail closed — never silent Mainnet).
///
/// `bip39_passphrase`: `Some` from private TUI modal (empty = default path for
/// this unlock); `None` loads env. Never persisted.
///
/// **Locks session on all paths** (Ok and Err after unlock) so seed material
/// does not linger on post-unlock failure.
pub fn complete_routstr_utxos_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    cli_network: Option<&str>,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrUtxosSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before unlock (not fees soft-default).
    let btc_net = resolve_product_entry_network(cli_network)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal utxos path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let mut gate = MnemonicBackupGate::new();
    if let Err(e) = gate.begin_reentry_without_display(unlocked) {
        session.lock();
        return Err(RoutstrCliError::Wallet(e));
    }
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not listing UTXOs".into(),
        ));
    }
    if let Err(e) = gate.confirm_reentry(reentry_phrase) {
        session.lock();
        return Err(RoutstrCliError::Wallet(e));
    }
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or chain/sync failure).
    let result = complete_routstr_utxos_with_mnemonic(unlocked, &network_str, &bip39_pass);
    session.lock();
    let lines = result?;
    Ok(RoutstrUtxosSuccess {
        network_label: network_str,
        lines,
    })
}

/// Resolve product spend fee rate (sat/vB).
///
/// Order: explicit user override (>0) → live mempool.space halfHour estimates
/// (`explorer-http`) → [`grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB`].
/// Never invents a rate from a failed fetch; never returns 0.
///
/// **Product paths must reject explicit `0` before calling** (CLI uses
/// `parse_spend_request` first). A `Some(0)` here is treated as unset by the
/// pure ladder helper — not a product validation substitute.
///
/// Blocking network when override is absent; prefer
/// [`resolve_spend_fee_rate_with_estimates`] in unit tests.
pub fn resolve_spend_fee_rate_for_product(user_override: Option<u64>) -> u64 {
    if let Some(n) = user_override
        && n > 0
    {
        return n;
    }
    resolve_spend_fee_rate_with_estimates(None, try_fetch_live_fee_estimates().as_ref())
}

/// `grok routstr spend <address> <sats> [--broadcast] [--fee-rate N]`.
///
/// **Dry-run by default** (build/sign/extract only). Explicit `--broadcast`
/// submits via the product chain selector
/// ([`grok_bitcoin_wallet::chain_select`]; default **mempool** `POST /api/tx`
/// when `GROK_BITCOIN_CHAIN_SOURCE` is unset; Esplora `POST /tx` or Electrum
/// `blockchain.transaction.broadcast` when env + optional features match).
/// Requires SeedVault unlock + full recovery-phrase re-entry (same gate as fund).
/// Never mints a new wallet; keyring errors never mint.
///
/// When `fee_rate_sat_vb` is `None`, uses explorer halfHour estimates when the
/// HTTP client can fetch them; otherwise the wallet default (5 sat/vB).
/// Explicit `--fee-rate 0` is rejected (same as TUI `fee=0`).
pub fn run_routstr_spend(
    grok_home: &Path,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        parse_spend_request, password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Parse with the *user* option first so:
    // - explicit `Some(0)` is rejected (parity with TUI `fee=0`)
    // - `fee_rate_explicit` reflects whether the user passed --fee-rate
    let mut req = parse_spend_request(payment_address, amount_sats, broadcast, fee_rate_sat_vb)
        .map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    if !req.fee_rate_explicit {
        // Blocking fetch only when user omitted fee; not on slash parse.
        req.fee_rate_sat_vb = resolve_spend_fee_rate_for_product(None);
    }

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal spend path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    // Re-entry gate (same as fund): authorize spend without re-displaying words.
    eprintln!(
        "Authorize on-chain spend: re-enter your recovery phrase (words are not re-displayed)."
    );
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    // Confirm re-entry matches vault material (begin_reentry + confirm).
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(unlocked)
            .map_err(RoutstrCliError::Wallet)?;
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not spending".into(),
            ));
        }
        gate.confirm_reentry(&reentry).map_err(|e| {
            session.lock();
            RoutstrCliError::Wallet(e)
        })?;
    }

    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;

    // Optional BIP-39 passphrase from env at unlock time only (never persisted).
    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_spend_with_mnemonic(
        unlocked,
        &network_str,
        &req.payment_address,
        req.amount_sats,
        req.broadcast,
        req.fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    let success = result?;

    for line in &success.lines {
        // Prepared summary on stderr; keep the full raw-hex block off stderr so
        // dry-run can put hex alone on stdout for pipes (filter label + body +
        // copy note, not just the "Raw tx hex" prefix).
        if grok_bitcoin_wallet::funding_cli::is_spend_raw_hex_output_line(line, &success.raw_hex) {
            continue;
        }
        eprintln!("{line}");
    }
    if success.broadcast_txid.is_none() && !req.broadcast {
        println!("{}", success.raw_hex);
        eprintln!("(Full raw tx hex written to stdout above for inspection / external broadcast.)");
    } else if let Some(ref txid) = success.broadcast_txid {
        println!("{txid}");
    }

    Ok(success)
}

/// Load optional BIP-39 passphrase for product unlock/sign paths.
///
/// Always via [`Bip39Passphrase::from_env`] — never hardcoded empty at the
/// entrypoint (empty env → default path). Wrapper keeps Debug redacted.
fn product_bip39_passphrase_from_env() -> grok_bitcoin_wallet::mnemonic::Bip39Passphrase {
    grok_bitcoin_wallet::mnemonic::Bip39Passphrase::from_env()
}

/// Resolve product BIP-39 passphrase: explicit TUI modal value wins over env.
///
/// - `Some(s)` → use `s` for this unlock only (empty string = default path).
///   Never falls back to env when explicit is provided (modal owns the secret).
/// - `None` → [`product_bip39_passphrase_from_env`] (CLI / unlock without
///   private passphrase prompt).
///
/// Never persists. Never log / format the secret.
fn product_bip39_passphrase(
    explicit: Option<&str>,
) -> grok_bitcoin_wallet::mnemonic::Bip39Passphrase {
    match explicit {
        Some(s) => grok_bitcoin_wallet::mnemonic::Bip39Passphrase::new(s.to_owned()),
        None => product_bip39_passphrase_from_env(),
    }
}

/// Core spend after vault unlock + re-entry (shared by CLI and TUI complete path).
///
/// Does **not** print or return BIP-39. Uses the product chain selector
/// ([`grok_bitcoin_wallet::chain_select`]; default **mempool** when
/// `GROK_BITCOIN_CHAIN_SOURCE` is unset) for both UTXO list and `--broadcast`
/// (mempool `POST /api/tx`, Esplora `POST /tx`, Electrum
/// `blockchain.transaction.broadcast`). Optional shell features `esplora` /
/// `electrum` / `bdk` forward to the wallet crate (not default CI).
///
/// UTXO discovery **default**: gap-limit ChainSource sync
/// (`select_and_prepare_bip84_spend_with_gap_sync` + default
/// `GapExtendOptions` — BIP44-style look-ahead 20, hard `MAX_ADDRESS_GAP`)
/// **before** coin select/sign. Opt-in prefer-BDK when
/// `GROK_BITCOIN_UTXO_SYNC=bdk` and feature `bdk` (Esplora/Electrum full_scan;
/// mempool fails closed; without feature → structured residual). RBF/CPFP
/// sibling paths take explicit prevouts and do **not** re-fetch or re-extend;
/// their broadcast path uses the same product broadcaster selector.
///
/// On select/prepare failure **after** successful sync, surfaces the cause
/// plus honest notices (`gap_sync_spend_notice_lines` or BDK notices — never
/// the wrong backend's residual copy). Sync-stage failures map to
/// `RoutstrCliError::Wallet` without fabricated notices.
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Product
/// callers load it via [`product_bip39_passphrase_from_env`] at unlock time —
/// never CredentialsStore / watch_session / chat. Never log / format the secret.
pub fn complete_routstr_spend_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: u64,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        UtxoSyncMode, open_product_tx_broadcaster, product_chain_source_config_from_env,
        product_utxo_sync_mode_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::broadcast_raw_tx;
    use grok_bitcoin_wallet::funding_cli::{
        bip39_passphrase_active_notice_lines, format_spend_broadcast_failed_lines,
        format_spend_broadcast_success_lines, format_spend_fee_meta_lines,
        format_spend_prepared_lines, format_spend_rbf_input_lines, spend_broadcast_claimed_txid,
    };
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (same as utxos; no dual parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    let chain_cfg = product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
    let sync_mode = product_utxo_sync_mode_from_env().map_err(RoutstrCliError::Wallet)?;

    // Shared (payment_sats, fee_sats, change_sats, txid, raw_hex, lines) for both engines.
    let (payment_sats, fee_sats, change_sats, txid, raw_hex, mut lines) = match sync_mode {
        UtxoSyncMode::Gap => {
            use grok_bitcoin_wallet::chain_select::open_product_chain_source;
            use grok_bitcoin_wallet::descriptor_wallet::{
                DEFAULT_RECEIVE_GAP, DescriptorWallet, GapExtendOptions,
                gap_sync_spend_notice_lines, select_and_prepare_bip84_spend_with_gap_sync,
            };

            let mut wallet = DescriptorWallet::from_mnemonic_with_passphrase(
                mnemonic,
                pass,
                rust_net,
                DEFAULT_RECEIVE_GAP,
            )
            .map_err(RoutstrCliError::Wallet)?;
            let chain =
                open_product_chain_source(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;
            let synced = select_and_prepare_bip84_spend_with_gap_sync(
                &mut wallet,
                chain.as_ref(),
                mnemonic,
                payment_address,
                amount_sats,
                fee_rate_sat_vb,
                pass,
                GapExtendOptions::default(),
            )
            .map_err(map_gap_sync_spend_failure)?;
            let prepared = &synced.prepared;
            let raw_hex = prepared.raw_hex();
            let txid = prepared.txid_hex();
            let mut lines = format_spend_prepared_lines(
                payment_address,
                prepared.payment_sats,
                prepared.fee_sats,
                prepared.change_sats,
                &txid,
                &raw_hex,
                broadcast,
            );
            lines.extend(format_spend_fee_meta_lines(
                prepared.fee_sats,
                prepared.weight_vbytes(),
                fee_rate_sat_vb,
            ));
            lines.extend(format_spend_rbf_input_lines(&prepared.selected_inputs));
            lines.extend(gap_sync_spend_notice_lines(&synced.sync));
            (
                prepared.payment_sats,
                prepared.fee_sats,
                prepared.change_sats,
                txid,
                raw_hex,
                lines,
            )
        }
        UtxoSyncMode::Bdk => {
            #[cfg(not(feature = "bdk"))]
            {
                let _ = rust_net;
                return Err(RoutstrCliError::Wallet(
                    grok_bitcoin_wallet::chain_select::bdk_utxo_sync_feature_missing_error(),
                ));
            }
            #[cfg(feature = "bdk")]
            {
                use grok_bitcoin_wallet::bdk_sync::{
                    BdkBip84Wallet, bdk_sync_notice_lines, open_product_bdk_update_source,
                    select_and_prepare_bip84_spend_with_bdk_sync,
                };
                use grok_bitcoin_wallet::descriptor_wallet::DEFAULT_RECEIVE_GAP;

                let mut bdk = BdkBip84Wallet::from_mnemonic_with_passphrase(
                    mnemonic,
                    pass,
                    rust_net,
                    DEFAULT_RECEIVE_GAP,
                )
                .map_err(RoutstrCliError::Wallet)?;
                let source =
                    open_product_bdk_update_source(&chain_cfg).map_err(RoutstrCliError::Wallet)?;
                let synced = select_and_prepare_bip84_spend_with_bdk_sync(
                    &mut bdk,
                    source.as_ref(),
                    mnemonic,
                    payment_address,
                    amount_sats,
                    fee_rate_sat_vb,
                    pass,
                )
                .map_err(map_bdk_sync_spend_failure)?;
                let prepared = &synced.prepared;
                let raw_hex = prepared.raw_hex();
                let txid = prepared.txid_hex();
                let mut lines = format_spend_prepared_lines(
                    payment_address,
                    prepared.payment_sats,
                    prepared.fee_sats,
                    prepared.change_sats,
                    &txid,
                    &raw_hex,
                    broadcast,
                );
                lines.extend(format_spend_fee_meta_lines(
                    prepared.fee_sats,
                    prepared.weight_vbytes(),
                    fee_rate_sat_vb,
                ));
                lines.extend(format_spend_rbf_input_lines(&prepared.selected_inputs));
                // BDK notice copy — never gap-limit residual when BDK path ran.
                lines.extend(bdk_sync_notice_lines(&synced.sync));
                (
                    prepared.payment_sats,
                    prepared.fee_sats,
                    prepared.change_sats,
                    txid,
                    raw_hex,
                    lines,
                )
            }
        }
    };

    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }

    let broadcast_txid = if broadcast {
        // Same ProductChainSourceConfig as UTXO list (aligned push backend).
        let mut broadcaster =
            open_product_tx_broadcaster(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;
        match broadcast_raw_tx(broadcaster.as_mut(), &raw_hex) {
            Ok(res) => {
                lines.extend(format_spend_broadcast_success_lines(
                    &res.txid,
                    &network_label,
                ));
                spend_broadcast_claimed_txid(true, Some(&res.txid))
            }
            Err(e) => {
                // Failure after local prepare: append full hex so CLI/TUI can
                // external-broadcast without re-running unlock (never claims accept).
                lines.extend(format_spend_broadcast_failed_lines(
                    &e.to_string(),
                    &raw_hex,
                ));
                return Err(RoutstrCliError::Message(lines.join("\n")));
            }
        }
    } else {
        None
    };

    Ok(RoutstrSpendSuccess {
        payment_address: payment_address.to_owned(),
        payment_sats,
        fee_sats,
        change_sats,
        txid,
        raw_hex,
        broadcast_txid,
        network_label,
        lines,
    })
}

/// `grok routstr rbf <address> <sats> --original-fee N --original-vbytes V --input ... [--broadcast] [--fee-rate N]`.
///
/// Rebuilds a **same-input** BIP-125 RBF replacement at a higher absolute fee.
/// Requires original prevouts (`--input txid:vout:amount:address` from spend
/// dry-run meta) — does **not** re-select confirmed UTXOs (those disappear once
/// the stuck tx is in the mempool).
/// **Dry-run by default.** Explicit `--broadcast` submits via the product chain
/// selector (default mempool; Esplora/Electrum when env + optional features match —
/// same as spend). Same SeedVault unlock + recovery-phrase re-entry as spend.
/// Never claims broadcast without Accepted + parseable txid.
///
/// When `fee_rate_sat_vb` is `None`, uses explorer halfHour estimates when
/// available; otherwise the wallet default. Explicit `Some(0)` is rejected.
/// Product uses plan_rbf_fee_bump recommended absolute fee (not floor rate).
pub fn run_routstr_rbf(
    grok_home: &Path,
    payment_address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    input_specs: &[String],
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Result<RoutstrRbfSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        parse_rbf_replace_request, password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    let mut req = parse_rbf_replace_request(
        payment_address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        input_specs,
        broadcast,
        fee_rate_sat_vb,
    )
    .map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    if !req.fee_rate_explicit {
        req.fee_rate_sat_vb = resolve_spend_fee_rate_for_product(None);
    }

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal rbf path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    eprintln!(
        "Authorize RBF replacement spend: re-enter your recovery phrase (words are not re-displayed)."
    );
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(unlocked)
            .map_err(RoutstrCliError::Wallet)?;
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not building RBF replacement".into(),
            ));
        }
        gate.confirm_reentry(&reentry).map_err(|e| {
            session.lock();
            RoutstrCliError::Wallet(e)
        })?;
    }

    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;

    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_rbf_with_mnemonic(
        unlocked,
        &network_str,
        &req.payment_address,
        req.amount_sats,
        req.original_fee_sats,
        req.original_vbytes,
        &req.inputs,
        req.broadcast,
        req.fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    let success = result?;

    for line in &success.lines {
        if grok_bitcoin_wallet::funding_cli::is_spend_raw_hex_output_line(line, &success.raw_hex) {
            continue;
        }
        eprintln!("{line}");
    }
    if success.broadcast_txid.is_none() && !req.broadcast {
        println!("{}", success.raw_hex);
        eprintln!(
            "(Full raw replacement hex written to stdout above for inspection / external broadcast.)"
        );
    } else if let Some(ref txid) = success.broadcast_txid {
        println!("{txid}");
    }

    Ok(success)
}

/// Core same-input RBF replacement after vault unlock + re-entry (CLI path).
///
/// Does **not** print or return BIP-39. Does **not** re-select from chain or
/// gap-extend — uses `original_inputs` only. BIP84 **signing** scan is
/// `PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP` (`MAX_ADDRESS_GAP`) so deep indices
/// recovered by product gap-sync spend still match keys (not
/// `DEFAULT_RECEIVE_GAP`). Optional broadcast via product chain selector
/// (mempool / Esplora / Electrum, same env as spend UTXO).
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Load via
/// [`product_bip39_passphrase_from_env`] at unlock — never persist. Never log it.
pub fn complete_routstr_rbf_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    payment_address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    original_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<RoutstrRbfSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        open_product_tx_broadcaster, product_chain_source_config_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP, broadcast_raw_tx,
        prepare_rbf_replacement,
    };
    use grok_bitcoin_wallet::funding_cli::{
        bip39_passphrase_active_notice_lines, format_rbf_replacement_prepared_lines,
        format_spend_broadcast_failed_lines, format_spend_broadcast_success_lines,
        format_spend_fee_meta_lines, spend_broadcast_claimed_txid,
    };
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (same as utxos/spend; no dual parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    // Wallet construction gap is for change address only; explicit prevouts
    // carry spend UTXOs. Signing uses PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP so
    // deep indices recovered by product gap-sync spend still match keys.
    let wallet = DescriptorWallet::from_mnemonic_with_passphrase(
        mnemonic,
        pass,
        rust_net,
        DEFAULT_RECEIVE_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    if original_inputs.is_empty() {
        return Err(RoutstrCliError::Message(
            "RBF requires at least one --input txid:vout:amount:address (same prevouts as stuck tx)"
                .into(),
        ));
    }
    let utxos: Vec<_> = original_inputs.iter().map(|s| s.to_wallet_utxo()).collect();

    // Same-input absolute-fee path: no chain re-select / no gap re-extend
    // (confirmed UTXOs vanish in mempool). Signing scan covers hard max so
    // deep gap-sync recovered prevouts still sign (not DEFAULT_RECEIVE_GAP).
    let rbf = prepare_rbf_replacement(
        &wallet,
        mnemonic,
        &utxos,
        payment_address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        fee_rate_sat_vb,
        pass,
        PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    let prepared = &rbf.prepared;
    let raw_hex = prepared.raw_hex();
    let txid = prepared.txid_hex();
    let mut lines = format_rbf_replacement_prepared_lines(
        payment_address,
        prepared.payment_sats,
        rbf.original_fee_sats,
        prepared.fee_sats,
        prepared.change_sats,
        &txid,
        &raw_hex,
        broadcast,
        &rbf.plan,
    );
    lines.extend(format_spend_fee_meta_lines(
        prepared.fee_sats,
        prepared.weight_vbytes(),
        rbf.fee_rate_sat_vb,
    ));
    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }

    let broadcast_txid = if broadcast {
        let chain_cfg = product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
        let mut broadcaster =
            open_product_tx_broadcaster(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;
        match broadcast_raw_tx(broadcaster.as_mut(), &raw_hex) {
            Ok(res) => {
                lines.extend(format_spend_broadcast_success_lines(
                    &res.txid,
                    &network_label,
                ));
                spend_broadcast_claimed_txid(true, Some(&res.txid))
            }
            Err(e) => {
                lines.extend(format_spend_broadcast_failed_lines(
                    &e.to_string(),
                    &raw_hex,
                ));
                return Err(RoutstrCliError::Message(lines.join("\n")));
            }
        }
    } else {
        spend_broadcast_claimed_txid(false, None)
    };

    Ok(RoutstrRbfSuccess {
        payment_address: payment_address.to_owned(),
        payment_sats: prepared.payment_sats,
        original_fee_sats: rbf.original_fee_sats,
        fee_sats: prepared.fee_sats,
        change_sats: prepared.change_sats,
        txid,
        raw_hex,
        broadcast_txid,
        network_label,
        fee_rate_sat_vb: rbf.fee_rate_sat_vb,
        lines,
    })
}

/// `grok routstr cpfp <address> <sats> --parent-fee N --parent-vbytes V --parent ... [--extra-input ...] [--broadcast] [--fee-rate N]`.
///
/// Builds a CPFP **child** spending wallet-owned parent output(s) so the
/// parent+child package meets the target fee rate. Optional `--extra-input`
/// confirmed UTXOs fund the child fee when the parent alone is short.
/// **Dry-run by default.** Explicit `--broadcast` submits via the product chain
/// selector (default mempool; Esplora/Electrum when env + optional features match —
/// same as spend). Same SeedVault unlock + recovery-phrase re-entry as spend.
/// Never claims the parent was replaced. Never claims broadcast without
/// Accepted + parseable txid.
///
/// When `fee_rate_sat_vb` is `None`, uses explorer halfHour estimates when
/// available; otherwise the wallet default. Explicit `Some(0)` is rejected.
pub fn run_routstr_cpfp(
    grok_home: &Path,
    payment_address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parent_specs: &[String],
    extra_specs: &[String],
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Result<RoutstrCpfpSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        parse_cpfp_child_request, password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    let mut req = parse_cpfp_child_request(
        payment_address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        parent_specs,
        extra_specs,
        broadcast,
        fee_rate_sat_vb,
    )
    .map_err(|e| RoutstrCliError::Message(e.to_string()))?;
    if !req.fee_rate_explicit {
        req.fee_rate_sat_vb = resolve_spend_fee_rate_for_product(None);
    }

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let mnemonic = match vault.load(None) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                let pw = VaultPassword::new(pw_raw);
                if pw.expose().is_empty() {
                    return Err(RoutstrCliError::Message(password_required_message().into()));
                }
                vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` first (new-wallet path)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal cpfp path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    eprintln!(
        "Authorize CPFP child spend: re-enter your recovery phrase (words are not re-displayed)."
    );
    eprint!("Recovery phrase: ");
    io::stderr().flush()?;
    let mut reentry = String::new();
    io::stdin().read_line(&mut reentry)?;

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    {
        use grok_bitcoin_wallet::seed_vault::MnemonicBackupGate;
        let mut gate = MnemonicBackupGate::new();
        gate.begin_reentry_without_display(unlocked)
            .map_err(RoutstrCliError::Wallet)?;
        if reentry.trim().is_empty() {
            session.lock();
            return Err(RoutstrCliError::Message(
                "recovery phrase re-entry cancelled; not building CPFP child".into(),
            ));
        }
        gate.confirm_reentry(&reentry).map_err(|e| {
            session.lock();
            RoutstrCliError::Wallet(e)
        })?;
    }

    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;

    let bip39_pass = product_bip39_passphrase_from_env();
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_cpfp_with_mnemonic(
        unlocked,
        &network_str,
        &req.payment_address,
        req.amount_sats,
        req.parent_fee_sats,
        req.parent_vbytes,
        &req.parents,
        &req.extra_inputs,
        req.broadcast,
        req.fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    let success = result?;

    for line in &success.lines {
        if grok_bitcoin_wallet::funding_cli::is_spend_raw_hex_output_line(line, &success.raw_hex) {
            continue;
        }
        eprintln!("{line}");
    }
    if success.broadcast_txid.is_none() && !req.broadcast {
        println!("{}", success.raw_hex);
        eprintln!(
            "(Full raw child hex written to stdout above for inspection / external broadcast.)"
        );
    } else if let Some(ref txid) = success.broadcast_txid {
        println!("{txid}");
    }

    Ok(success)
}

/// Core CPFP child prepare after vault unlock + re-entry (CLI path).
///
/// Does **not** print or return BIP-39. Uses parent + optional extra inputs only
/// (no chain re-select / no gap re-extend). BIP84 **signing** scan is
/// `PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP` so deep gap-sync recovered addresses
/// still sign. Optional broadcast via product chain selector (same env as
/// spend). Never claims the parent was replaced.
///
/// `passphrase` is the BIP-39 passphrase wrapper (empty = default path). Load via
/// [`product_bip39_passphrase_from_env`] at unlock — never persist. Never log it.
pub fn complete_routstr_cpfp_with_mnemonic(
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    network_str: &str,
    payment_address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parents: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    extra_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    passphrase: &grok_bitcoin_wallet::mnemonic::Bip39Passphrase,
) -> Result<RoutstrCpfpSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::chain_select::{
        open_product_tx_broadcaster, product_chain_source_config_from_env,
    };
    use grok_bitcoin_wallet::descriptor_wallet::{
        DEFAULT_RECEIVE_GAP, DescriptorWallet, PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP, broadcast_raw_tx,
        prepare_cpfp_child,
    };
    use grok_bitcoin_wallet::funding_cli::{
        bip39_passphrase_active_notice_lines, format_cpfp_child_fee_meta_lines,
        format_cpfp_child_prepared_lines, format_spend_broadcast_failed_lines,
        format_spend_broadcast_success_lines, spend_broadcast_claimed_txid,
    };
    use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

    // Single product-network resolve (same as utxos/spend/rbf; no dual parse / silent Mainnet).
    let btc_net = resolve_product_complete_network(network_str)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);
    let pass = passphrase.expose();

    // Construction gap for change only; parents/extras are explicit prevouts.
    // Sign with PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP (deep gap-sync recovery).
    let wallet = DescriptorWallet::from_mnemonic_with_passphrase(
        mnemonic,
        pass,
        rust_net,
        DEFAULT_RECEIVE_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    if parents.is_empty() {
        return Err(RoutstrCliError::Message(
            "CPFP requires at least one --parent txid:vout:amount:address (wallet-owned parent output)"
                .into(),
        ));
    }
    let parent_utxos: Vec<_> = parents.iter().map(|s| s.to_wallet_utxo()).collect();
    let extra_utxos: Vec<_> = extra_inputs.iter().map(|s| s.to_wallet_utxo()).collect();

    // Explicit prevouts only — no chain re-select / no gap re-extend. Signing
    // scan = hard max so deep recovered parent/extra addresses still match.
    let cpfp = prepare_cpfp_child(
        &wallet,
        mnemonic,
        &parent_utxos,
        &extra_utxos,
        payment_address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        fee_rate_sat_vb,
        pass,
        PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP,
    )
    .map_err(RoutstrCliError::Wallet)?;

    let prepared = &cpfp.prepared;
    let raw_hex = prepared.raw_hex();
    let txid = prepared.txid_hex();
    let mut lines = format_cpfp_child_prepared_lines(
        payment_address,
        prepared.payment_sats,
        cpfp.parent_fee_sats,
        prepared.fee_sats,
        prepared.change_sats,
        &txid,
        &raw_hex,
        broadcast,
        &cpfp.plan,
    );
    // Package target vs child/package effective — not spend "requested vs effective"
    // on the child alone (which misreads min-relay children under overpaying parents).
    lines.extend(format_cpfp_child_fee_meta_lines(
        cpfp.parent_fee_sats,
        cpfp.parent_vbytes,
        prepared.fee_sats,
        prepared.weight_vbytes(),
        cpfp.fee_rate_sat_vb,
    ));
    if !passphrase.is_empty() {
        lines.extend(bip39_passphrase_active_notice_lines());
    }

    let broadcast_txid = if broadcast {
        let chain_cfg = product_chain_source_config_from_env().map_err(RoutstrCliError::Wallet)?;
        let mut broadcaster =
            open_product_tx_broadcaster(&chain_cfg, btc_net).map_err(RoutstrCliError::Wallet)?;
        match broadcast_raw_tx(broadcaster.as_mut(), &raw_hex) {
            Ok(res) => {
                lines.extend(format_spend_broadcast_success_lines(
                    &res.txid,
                    &network_label,
                ));
                spend_broadcast_claimed_txid(true, Some(&res.txid))
            }
            Err(e) => {
                lines.extend(format_spend_broadcast_failed_lines(
                    &e.to_string(),
                    &raw_hex,
                ));
                return Err(RoutstrCliError::Message(lines.join("\n")));
            }
        }
    } else {
        spend_broadcast_claimed_txid(false, None)
    };

    Ok(RoutstrCpfpSuccess {
        payment_address: payment_address.to_owned(),
        payment_sats: prepared.payment_sats,
        parent_fee_sats: cpfp.parent_fee_sats,
        fee_sats: prepared.fee_sats,
        change_sats: prepared.change_sats,
        txid,
        raw_hex,
        broadcast_txid,
        network_label,
        fee_rate_sat_vb: cpfp.fee_rate_sat_vb,
        lines,
    })
}

/// TUI spend after unlock re-entry (no BIP-39 in returned payload).
///
/// `bip39_passphrase`: `Some` from private TUI modal (empty = default path for
/// this unlock); `None` loads [`GROK_BITCOIN_BIP39_PASSPHRASE`](grok_bitcoin_wallet::mnemonic::BIP39_PASSPHRASE_ENV)
/// when set. Never persisted.
pub fn complete_routstr_spend_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    payment_address: &str,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: u64,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrSpendSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal spend path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let mut gate = MnemonicBackupGate::new();
    gate.begin_reentry_without_display(unlocked)
        .map_err(RoutstrCliError::Wallet)?;
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not spending".into(),
        ));
    }
    gate.confirm_reentry(reentry_phrase).map_err(|e| {
        session.lock();
        RoutstrCliError::Wallet(e)
    })?;
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_spend_with_mnemonic(
        unlocked,
        &network_str,
        payment_address,
        amount_sats,
        broadcast,
        fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    result
}

/// TUI same-input RBF after unlock re-entry (no BIP-39 in returned payload).
///
/// Uses original prevouts only — never re-selects confirmed UTXOs. Fee rate
/// must already be resolved by the caller (effect worker); this path does not
/// fetch estimates.
///
/// `bip39_passphrase`: `Some` from private TUI modal; `None` → env. Never persisted.
pub fn complete_routstr_rbf_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    payment_address: &str,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    original_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrRbfSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal rbf path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let mut gate = MnemonicBackupGate::new();
    gate.begin_reentry_without_display(unlocked)
        .map_err(RoutstrCliError::Wallet)?;
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not building RBF replacement".into(),
        ));
    }
    gate.confirm_reentry(reentry_phrase).map_err(|e| {
        session.lock();
        RoutstrCliError::Wallet(e)
    })?;
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_rbf_with_mnemonic(
        unlocked,
        &network_str,
        payment_address,
        amount_sats,
        original_fee_sats,
        original_vbytes,
        original_inputs,
        broadcast,
        fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    result
}

/// TUI CPFP child after unlock re-entry (no BIP-39 in returned payload).
///
/// Uses parent + optional extra inputs only — never re-selects as RBF.
/// Fee rate must already be resolved by the caller (effect worker); this path
/// does not fetch estimates. Never claims the parent was replaced.
///
/// `bip39_passphrase`: `Some` from private TUI modal; `None` → env. Never persisted.
pub fn complete_routstr_cpfp_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    payment_address: &str,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parents: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    extra_inputs: &[grok_bitcoin_wallet::funding_cli::RbfInputSpec],
    broadcast: bool,
    fee_rate_sat_vb: u64,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrCpfpSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message,
    };
    use grok_bitcoin_wallet::seed_vault::{
        MnemonicBackupGate, SeedVault, UnlockSession, VaultPassword,
    };
    use std::time::Instant;

    // Fail-closed product network before vault unlock (poisoned env never unlocks).
    let btc_net = resolve_product_entry_network(None)?;
    let network_str = btc_net.as_str().to_owned();

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal first."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal cpfp path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let mut gate = MnemonicBackupGate::new();
    gate.begin_reentry_without_display(unlocked)
        .map_err(RoutstrCliError::Wallet)?;
    if reentry_phrase.trim().is_empty() {
        session.lock();
        return Err(RoutstrCliError::Message(
            "recovery phrase re-entry cancelled; not building CPFP child".into(),
        ));
    }
    gate.confirm_reentry(reentry_phrase).map_err(|e| {
        session.lock();
        RoutstrCliError::Wallet(e)
    })?;
    let unlocked = session
        .mnemonic(Instant::now())
        .map_err(RoutstrCliError::Wallet)?;
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    // Always lock after complete (success or post-unlock failure).
    let result = complete_routstr_cpfp_with_mnemonic(
        unlocked,
        &network_str,
        payment_address,
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        parents,
        extra_inputs,
        broadcast,
        fee_rate_sat_vb,
        &bip39_pass,
    );
    session.lock();
    result
}

/// AEAD seed blob path under grok home (never `provider_credentials.json`).
pub fn routstr_seed_aead_path(grok_home: &Path) -> std::path::PathBuf {
    grok_home.join("bitcoin").join("seed.aead")
}

/// Read a password from the TTY with echo disabled when possible.
///
/// Falls back to line-read (echo on) for non-TTY stdin (tests / pipes).
fn read_secret_prompt(prompt: &str) -> Result<String, RoutstrCliError> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    #[cfg(unix)]
    {
        use std::io::BufRead;
        use std::os::fd::AsRawFd;
        let stdin = io::stdin();
        let fd = stdin.as_raw_fd();
        // isatty: 1 = TTY
        let is_tty = unsafe { libc::isatty(fd) == 1 };
        if is_tty {
            let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
            let rc = unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) };
            if rc == 0 {
                let old = unsafe { term.assume_init() };
                let mut neo = old;
                neo.c_lflag &= !libc::ECHO;
                if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &neo) } == 0 {
                    let mut line = String::new();
                    let read_res = stdin.lock().read_line(&mut line);
                    // Always restore terminal echo.
                    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
                    eprintln!(); // newline after hidden input
                    read_res?;
                    return Ok(line.trim_end_matches(['\r', '\n']).to_owned());
                }
            }
        }
    }
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Store mnemonic in SeedVault (keyring, else password-wrapped AEAD).
fn store_seed_in_vault(
    vault: &grok_bitcoin_wallet::seed_vault::SeedVault,
    mnemonic: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
    aead_path: &Path,
) -> Result<(), RoutstrCliError> {
    use grok_bitcoin_wallet::seed_vault::VaultPassword;

    match vault.store(mnemonic, None) {
        Ok(backend) => {
            eprintln!("Seed stored via {backend:?}.");
            Ok(())
        }
        Err(_) => {
            eprintln!(
                "Keyring unavailable. Seed will be password-wrapped at:\n  {}",
                aead_path.display()
            );
            let pw_raw = read_secret_prompt("Set a password to wrap the seed file: ")?;
            let pw = VaultPassword::new(pw_raw);
            if pw.expose().is_empty() {
                return Err(RoutstrCliError::Message(
                    "password required when keyring is unavailable; seed was NOT saved".into(),
                ));
            }
            vault.store(mnemonic, Some(&pw)).map_err(|e| {
                RoutstrCliError::Message(format!(
                    "failed to save seed ({e}); seed was NOT saved. \
                         Do not send funds until `grok routstr fund` completes successfully. \
                         Re-run fund and complete backup again if needed."
                ))
            })?;
            eprintln!("Seed stored as password-wrapped AEAD file.");
            Ok(())
        }
    }
}

fn print_fund_success(
    address: &str,
    step_label: &str,
    network_label: &str,
    saved: bool,
    bip39_passphrase_active: bool,
) {
    println!();
    for line in grok_bitcoin_wallet::funding_cli::format_fund_success_lines_with_passphrase_flag(
        address,
        step_label,
        network_label,
        saved,
        bip39_passphrase_active,
    ) {
        println!("{line}");
    }
}

/// `grok routstr fund`: backup gate + unlock, then print BIP84 receive address.
///
/// Creates a wallet when none exists:
/// generate → show-once + re-entry → **durable store** → print address.
///
/// Existing wallets unlock and print the receive address without re-displaying
/// the recovery phrase.
///
/// Network via [`resolve_product_entry_network`] **before** vault unlock /
/// seed touch (env `GROK_BITCOIN_NETWORK` or mainnet; unknown/`regtest` fail
/// closed — same acceptance as spend/utxos). Derive uses
/// [`bitcoin_network_to_network`] +
/// [`derive_bip84_receive_address_with_passphrase`] (not env-string helpers
/// that still accept regtest).
///
/// BIP-39 is stored only in SeedVault (keyring and/or AEAD file under
/// `$GROK_HOME/bitcoin/seed.aead`). Hard keyring errors never mint a new wallet.
pub fn run_routstr_fund(grok_home: &Path) -> Result<(), RoutstrCliError> {
    use grok_bitcoin_wallet::BOLT12_SUPPORTED;
    use grok_bitcoin_wallet::funding_cli::{
        generate_new_wallet_mnemonic, run_backup_gate_to_show_address_stdio,
    };
    use grok_bitcoin_wallet::onchain::{
        bitcoin_network_to_network, derive_bip84_receive_address_with_passphrase,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Compile-time honesty: BOLT12 must stay false until offer routing lands.
    const _: () = assert!(!BOLT12_SUPPORTED);

    // Fail-closed product network before vault unlock / seed touch (not fees
    // soft-default; not env-string derive that accepts regtest).
    let btc_net = resolve_product_entry_network(None)?;
    let network_label = btc_net.as_str();
    let rust_net = bitcoin_network_to_network(btc_net);

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    // Prefer keyring; AEAD may need a password. Never treat Keyring errors as empty.
    // Shared classify with TUI fund path (`funding_cli::fund_path_decision_from_load`).
    let existing = match vault.load(None) {
        Ok(m) => Some(m),
        Err(e) => {
            use grok_bitcoin_wallet::funding_cli::{
                FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
                password_required_message,
            };
            match fund_path_decision_from_load::<()>(Err(e)) {
                FundPathDecision::NewWallet => None,
                FundPathDecision::NeedPassword => {
                    let pw_raw = read_secret_prompt("Unlock seed file password: ")?;
                    let pw = VaultPassword::new(pw_raw);
                    if pw.expose().is_empty() {
                        return Err(RoutstrCliError::Message(password_required_message().into()));
                    }
                    Some(vault.load(Some(&pw)).map_err(RoutstrCliError::Wallet)?)
                }
                FundPathDecision::KeyringBlocked { reason } => {
                    return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
                }
                FundPathDecision::LoadError { message } => {
                    return Err(RoutstrCliError::Message(message));
                }
                FundPathDecision::ReturningUnlock => {
                    // Unreachable: we only classify Err here.
                    return Err(RoutstrCliError::Message(
                        "internal fund path: unexpected ReturningUnlock on load error".into(),
                    ));
                }
            }
        }
    };

    if let Some(mnemonic) = existing {
        // Returning user: re-entry without re-displaying words (shared with TUI).
        eprintln!(
            "Local wallet found. Re-enter your recovery phrase to unlock the receive address."
        );
        eprintln!("(Words are not re-displayed.)");
        eprint!("Recovery phrase: ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;

        let mut session = UnlockSession::unlock_default(mnemonic);
        let now = Instant::now();
        let unlocked = match session.mnemonic(now) {
            Ok(m) => m,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        // Optional BIP-39 passphrase from env at unlock (never stored in SeedVault).
        let bip39_pass = product_bip39_passphrase_from_env();
        let address = match derive_bip84_receive_address_with_passphrase(
            unlocked,
            bip39_pass.expose(),
            rust_net,
            0,
        ) {
            Ok(a) => a,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        // Re-borrow for re-entry gate (same material; no clone of phrase).
        let unlocked = match session.mnemonic(Instant::now()) {
            Ok(m) => m,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        let reveal = match grok_bitcoin_wallet::funding_cli::returning_user_reveal_after_reentry(
            unlocked, &line, address,
        ) {
            Ok(r) => r,
            Err(e) => {
                session.lock();
                return Err(RoutstrCliError::Wallet(e));
            }
        };
        session.lock();

        // Returning unlock: vault already held the seed; do not claim "Wallet saved."
        // When env passphrase is non-empty, success lines warn (value never printed).
        print_fund_success(
            &reveal.address,
            reveal.wizard.step.user_label(),
            network_label,
            false,
            !bip39_pass.is_empty(),
        );
        return Ok(());
    }

    // New wallet: generate → backup confirm → store → only then print address.
    // Network already resolved fail-closed above (no seed touch on poisoned env).
    eprintln!("No local Bitcoin wallet found. Generating a new recovery phrase.");
    eprintln!("The phrase is stored in the OS keyring when available, otherwise in:");
    eprintln!("  {}", aead_path.display());
    eprintln!("Never in provider_credentials.json.");

    let mnemonic = generate_new_wallet_mnemonic().map_err(RoutstrCliError::Wallet)?;
    // Optional passphrase for new wallets: set GROK_BITCOIN_BIP39_PASSPHRASE before fund
    // if using a non-empty BIP-39 passphrase (advanced; never stored).
    let bip39_pass = product_bip39_passphrase_from_env();
    let address =
        derive_bip84_receive_address_with_passphrase(&mnemonic, bip39_pass.expose(), rust_net, 0)
            .map_err(RoutstrCliError::Wallet)?;

    // Backup confirm without printing address yet.
    let reveal = run_backup_gate_to_show_address_stdio(&mnemonic, address.clone(), false)
        .map_err(RoutstrCliError::Wallet)?;

    // Durable store before any address print so a failed store cannot leave the
    // user believing a fundable wallet exists.
    if let Err(e) = store_seed_in_vault(&vault, &mnemonic, &aead_path) {
        eprintln!();
        eprintln!("ERROR: wallet was NOT saved. Do not send funds to any address from this run.");
        eprintln!("{e}");
        eprintln!(
            "Your recovery phrase was shown above during backup. Keep those words offline \
             and re-run `grok routstr fund` after fixing storage (keyring or disk)."
        );
        return Err(e);
    }

    // New wallet: durable store succeeded above.
    print_fund_success(
        &reveal.address,
        reveal.wizard.step.user_label(),
        network_label,
        true,
        !bip39_pass.is_empty(),
    );
    Ok(())
}

/// TUI probe after vault load (no secrets). Drives pager fund UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutstrFundProbe {
    /// No seed: recovery phrase must be shown once. Prefer private terminal CLI.
    NeedCliNewWallet { aead_hint: String },
    /// AEAD present; need password before re-entry.
    NeedPassword,
    /// Keyring hard error: do not mint.
    KeyringBlocked { message: String },
    /// Seed available (keyring): collect re-entry phrase in TUI (not re-displayed).
    NeedReentry,
    /// Other load failure.
    Error { message: String },
}

/// Successful TUI fund reveal (address only; never includes BIP-39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutstrFundSuccess {
    pub address: String,
    pub network_label: String,
    pub step_label: String,
    pub lines: Vec<String>,
}

/// Probe seed vault for TUI `/routstr fund` without minting or printing seeds.
pub fn probe_routstr_fund_for_tui(grok_home: &Path) -> RoutstrFundProbe {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
    };
    use grok_bitcoin_wallet::seed_vault::SeedVault;

    let aead_path = routstr_seed_aead_path(grok_home);
    let aead_hint = aead_path.display().to_string();
    let vault = match SeedVault::with_aead_path(&aead_path) {
        Ok(v) => v,
        Err(e) => {
            return RoutstrFundProbe::Error {
                message: e.to_string(),
            };
        }
    };
    match fund_path_decision_from_load(vault.load(None)) {
        FundPathDecision::NewWallet => RoutstrFundProbe::NeedCliNewWallet { aead_hint },
        FundPathDecision::ReturningUnlock => RoutstrFundProbe::NeedReentry,
        FundPathDecision::NeedPassword => RoutstrFundProbe::NeedPassword,
        FundPathDecision::KeyringBlocked { reason } => RoutstrFundProbe::KeyringBlocked {
            message: keyring_blocked_message(&reason),
        },
        FundPathDecision::LoadError { message } => RoutstrFundProbe::Error { message },
    }
}

/// Complete TUI fund for returning wallet: password (optional) + re-entry + address.
///
/// Never mints a new wallet. Never puts BIP-39 in the returned success payload.
///
/// Network via [`resolve_product_entry_network`] **before** vault unlock
/// (env `GROK_BITCOIN_NETWORK` or mainnet; unknown/`regtest` fail closed —
/// same acceptance as spend/utxos). Derive uses
/// [`bitcoin_network_to_network`] +
/// [`derive_bip84_receive_address_with_passphrase`].
///
/// `bip39_passphrase`: `Some` from private TUI modal; `None` → env. Never persisted.
///
/// **Locks session on all paths** (Ok and Err after unlock) so seed material
/// does not linger on post-unlock failure.
pub fn complete_routstr_fund_reentry_for_tui(
    grok_home: &Path,
    reentry_phrase: &str,
    password: Option<&str>,
    bip39_passphrase: Option<&str>,
) -> Result<RoutstrFundSuccess, RoutstrCliError> {
    use grok_bitcoin_wallet::funding_cli::{
        FundPathDecision, fund_path_decision_from_load, keyring_blocked_message,
        password_required_message, returning_user_reveal_after_reentry,
    };
    use grok_bitcoin_wallet::onchain::{
        bitcoin_network_to_network, derive_bip84_receive_address_with_passphrase,
    };
    use grok_bitcoin_wallet::seed_vault::{SeedVault, UnlockSession, VaultPassword};
    use std::time::Instant;

    // Fail-closed product network before unlock (not fees soft-default; not
    // env-string derive that accepts regtest).
    let btc_net = resolve_product_entry_network(None)?;
    let network_label = btc_net.as_str().to_owned();
    let rust_net = bitcoin_network_to_network(btc_net);

    let aead_path = routstr_seed_aead_path(grok_home);
    let vault = SeedVault::with_aead_path(&aead_path).map_err(RoutstrCliError::Wallet)?;

    let pw;
    let password_ref = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            pw = VaultPassword::new(raw.to_owned());
            Some(&pw)
        }
        None => None,
    };

    let mnemonic = match vault.load(password_ref) {
        Ok(m) => m,
        Err(e) => match fund_path_decision_from_load::<()>(Err(e)) {
            FundPathDecision::NeedPassword => {
                return Err(RoutstrCliError::Message(password_required_message().into()));
            }
            FundPathDecision::KeyringBlocked { reason } => {
                return Err(RoutstrCliError::Message(keyring_blocked_message(&reason)));
            }
            FundPathDecision::NewWallet => {
                return Err(RoutstrCliError::Message(
                    "no local wallet found. Run `grok routstr fund` in a private terminal \
                     to create one (recovery phrase is shown only once)."
                        .into(),
                ));
            }
            FundPathDecision::LoadError { message } => {
                return Err(RoutstrCliError::Message(message));
            }
            FundPathDecision::ReturningUnlock => {
                return Err(RoutstrCliError::Message(
                    "internal fund path: unexpected ReturningUnlock on load error".into(),
                ));
            }
        },
    };

    let mut session = UnlockSession::unlock_default(mnemonic);
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    // Optional BIP-39 passphrase: TUI modal override or env; never persisted.
    let bip39_pass = product_bip39_passphrase(bip39_passphrase);
    let address = match derive_bip84_receive_address_with_passphrase(
        unlocked,
        bip39_pass.expose(),
        rust_net,
        0,
    ) {
        Ok(a) => a,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let unlocked = match session.mnemonic(Instant::now()) {
        Ok(m) => m,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    let reveal = match returning_user_reveal_after_reentry(unlocked, reentry_phrase, address) {
        Ok(r) => r,
        Err(e) => {
            session.lock();
            return Err(RoutstrCliError::Wallet(e));
        }
    };
    session.lock();

    let step_label = reveal.wizard.step.user_label().to_owned();
    // TUI re-entry never stores again; avoid "Wallet saved." copy.
    // Non-empty resolved passphrase → non-secret notice on success lines.
    let lines = grok_bitcoin_wallet::funding_cli::format_fund_success_lines_with_passphrase_flag(
        &reveal.address,
        &step_label,
        &network_label,
        false,
        !bip39_pass.is_empty(),
    );
    Ok(RoutstrFundSuccess {
        address: reveal.address,
        network_label,
        step_label,
        lines,
    })
}

/// Errors from `grok routstr` product subcommands.
#[derive(Debug, thiserror::Error)]
pub enum RoutstrCliError {
    #[error("No Routstr API key. Set {ROUTSTR_API_KEY_ENV} or run `grok login --routstr`.")]
    NoApiKey,
    #[error("Could not fetch Routstr balance. Check network access and that the key is valid.")]
    BalanceUnavailable,
    /// `[features] routstr_enabled = false` — network fetch intentionally skipped.
    #[error("Routstr is disabled (`[features] routstr_enabled = false`). Balance fetch skipped.")]
    FeatureDisabled,
    #[error(transparent)]
    Wallet(#[from] grok_bitcoin_wallet::error::WalletError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Message(String),
}

/// Map product gap-sync spend failure to CLI error (pure; offline-testable).
///
/// - [`GapSyncSpendFailure::Sync`] → [`RoutstrCliError::Wallet`] (no notices).
/// - Quiet AfterSync (empty notices) → [`RoutstrCliError::Wallet`](cause).
/// - AfterSync with hit-max / extend notices → multi-line
///   [`RoutstrCliError::Message`] via `display_lines` (not success-path only).
///
/// Callers must not convert via bare `WalletError` / `?` that drops the snapshot.
fn map_gap_sync_spend_failure(
    fail: grok_bitcoin_wallet::descriptor_wallet::GapSyncSpendFailure,
) -> RoutstrCliError {
    use grok_bitcoin_wallet::descriptor_wallet::GapSyncSpendFailure;
    match fail {
        GapSyncSpendFailure::Sync(e) => RoutstrCliError::Wallet(e),
        fail @ GapSyncSpendFailure::AfterSync { .. } => {
            if fail.notice_lines().is_empty() {
                RoutstrCliError::Wallet(fail.into_cause())
            } else {
                RoutstrCliError::Message(fail.display_lines().join("\n"))
            }
        }
    }
}

/// Map product BDK-sync spend failure to CLI error (pure; offline-testable).
///
/// Mirrors [`map_gap_sync_spend_failure`] but uses BDK notice lines — never
/// gap-limit residual copy when the BDK path ran.
#[cfg(feature = "bdk")]
fn map_bdk_sync_spend_failure(
    fail: grok_bitcoin_wallet::bdk_sync::BdkSyncSpendFailure,
) -> RoutstrCliError {
    use grok_bitcoin_wallet::bdk_sync::BdkSyncSpendFailure;
    match fail {
        BdkSyncSpendFailure::Sync(e) => RoutstrCliError::Wallet(e),
        fail @ BdkSyncSpendFailure::AfterSync { .. } => {
            if fail.notice_lines().is_empty() {
                RoutstrCliError::Wallet(fail.into_cause())
            } else {
                RoutstrCliError::Message(fail.display_lines().join("\n"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::Path;
    use tempfile::TempDir;
    use xai_grok_test_support::EnvGuard;

    #[test]
    fn detects_routstr_urls() {
        assert!(is_routstr_base_url(ROUTSTR_API_URL));
        assert!(is_routstr_base_url("https://api.routstr.com/v1/"));
        assert!(is_routstr_base_url("https://my.routstr.com/v1"));
        assert!(!is_routstr_base_url("https://api.x.ai/v1"));
        assert!(!is_routstr_base_url("https://openrouter.ai/api/v1"));
        assert!(!is_routstr_base_url("https://evil.example/routstr.com"));
        assert!(!is_routstr_base_url("https://notroutstr.com.attacker"));
    }

    /// Prefer-BDK without feature `bdk`: structured residual (not hang / Success).
    #[test]
    #[serial(GROK_BITCOIN_UTXO_SYNC)]
    fn prefer_bdk_utxos_without_feature_is_structured_residual() {
        use grok_bitcoin_wallet::mnemonic::{Bip39Passphrase, generate_mnemonic};

        let _env = EnvGuard::set("GROK_BITCOIN_UTXO_SYNC", "bdk");
        let m = generate_mnemonic().unwrap();
        let pass = Bip39Passphrase::new(String::new());
        let err = complete_routstr_utxos_with_mnemonic(&m, "mainnet", &pass).unwrap_err();
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        #[cfg(not(feature = "bdk"))]
        {
            assert!(
                lower.contains("feature") && lower.contains("bdk"),
                "expected feature-missing residual, got: {msg}"
            );
            assert!(
                lower.contains("gap") || lower.contains("utxo_sync"),
                "expected gap residual guidance, got: {msg}"
            );
            assert!(!lower.contains("crypto"));
        }
        #[cfg(feature = "bdk")]
        {
            // With feature on, path proceeds past feature gate; mempool (default
            // chain) still fails closed with honest residual (no invent Success).
            assert!(
                lower.contains("mempool")
                    || lower.contains("esplora")
                    || lower.contains("electrum")
                    || lower.contains("bdk"),
                "expected chain/bdk residual when feature on + default mempool, got: {msg}"
            );
            assert!(!lower.contains("crypto"));
        }
    }

    /// Prefer-BDK spend residual twin of utxos (same env/cfg contract; no network).
    #[test]
    #[serial(GROK_BITCOIN_UTXO_SYNC)]
    fn prefer_bdk_spend_without_feature_is_structured_residual() {
        use grok_bitcoin_wallet::mnemonic::{Bip39Passphrase, generate_mnemonic};

        let _env = EnvGuard::set("GROK_BITCOIN_UTXO_SYNC", "bdk");
        let m = generate_mnemonic().unwrap();
        let pass = Bip39Passphrase::new(String::new());
        // Dummy mainnet address + amount; residual fires before live full_scan.
        let err = complete_routstr_spend_with_mnemonic(
            &m,
            "mainnet",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            1000,
            false,
            10,
            &pass,
        )
        .unwrap_err();
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        #[cfg(not(feature = "bdk"))]
        {
            assert!(
                lower.contains("feature") && lower.contains("bdk"),
                "expected feature-missing residual, got: {msg}"
            );
            assert!(
                lower.contains("gap") || lower.contains("utxo_sync"),
                "expected gap residual guidance, got: {msg}"
            );
            assert!(!lower.contains("crypto"));
        }
        #[cfg(feature = "bdk")]
        {
            assert!(
                lower.contains("mempool")
                    || lower.contains("esplora")
                    || lower.contains("electrum")
                    || lower.contains("bdk"),
                "expected chain/bdk residual when feature on + default mempool, got: {msg}"
            );
            assert!(!lower.contains("crypto"));
        }
    }

    /// Invalid UTXO_SYNC env fails closed (single parser; no dual acceptance).
    #[test]
    #[serial(GROK_BITCOIN_UTXO_SYNC)]
    fn utxo_sync_env_unknown_fail_closed() {
        use grok_bitcoin_wallet::mnemonic::{Bip39Passphrase, generate_mnemonic};

        let _env = EnvGuard::set("GROK_BITCOIN_UTXO_SYNC", "full-scan");
        let m = generate_mnemonic().unwrap();
        let pass = Bip39Passphrase::new(String::new());
        let err = complete_routstr_utxos_with_mnemonic(&m, "mainnet", &pass).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("GROK_BITCOIN_UTXO_SYNC") || msg.to_ascii_lowercase().contains("unknown"),
            "got: {msg}"
        );
        assert!(!msg.to_ascii_lowercase().contains("crypto"));
    }

    /// Empty / unset UTXO_SYNC remains gap path (default product).
    #[test]
    #[serial(GROK_BITCOIN_UTXO_SYNC)]
    fn utxo_sync_env_default_is_gap_parser() {
        use grok_bitcoin_wallet::chain_select::{
            UtxoSyncMode, parse_utxo_sync_mode, product_utxo_sync_mode_from_env_reader,
        };

        assert_eq!(parse_utxo_sync_mode("").unwrap(), UtxoSyncMode::Gap);
        assert_eq!(parse_utxo_sync_mode("gap").unwrap(), UtxoSyncMode::Gap);
        assert_eq!(parse_utxo_sync_mode("BDK").unwrap(), UtxoSyncMode::Bdk);
        let _unset = EnvGuard::unset("GROK_BITCOIN_UTXO_SYNC");
        let mode = product_utxo_sync_mode_from_env_reader(|_| None).unwrap();
        assert_eq!(mode, UtxoSyncMode::Gap);
    }

    /// Shell UX mapping for gap-sync spend dual-error (no chain/mnemonic).
    #[test]
    fn map_gap_sync_spend_failure_three_arms() {
        use grok_bitcoin_wallet::descriptor_wallet::{
            GapSyncSpendFailure, WalletBalance, WalletSyncSnapshot,
        };
        use grok_bitcoin_wallet::error::WalletError;

        // Sync-stage → structured Wallet; no fabricated notices.
        let sync_err = map_gap_sync_spend_failure(GapSyncSpendFailure::Sync(WalletError::Onchain(
            "passphrase mismatch during gap extend".into(),
        )));
        match sync_err {
            RoutstrCliError::Wallet(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                assert!(msg.contains("passphrase"), "{e}");
            }
            other => panic!("Sync must map to Wallet, got: {other}"),
        }

        // Quiet AfterSync (no grow / no max) → Wallet(cause).
        let quiet = map_gap_sync_spend_failure(GapSyncSpendFailure::AfterSync {
            sync: WalletSyncSnapshot {
                utxos: vec![],
                balance: WalletBalance::default(),
                receive_gap: 5,
                change_gap: 5,
                highest_used_receive: None,
                highest_used_change: None,
                extended_receive_by: 0,
                extended_change_by: 0,
                hit_max_gap: false,
            },
            cause: WalletError::Onchain(
                "insufficient funds: need 100000 sats, have 1000 sats in 1 UTXOs".into(),
            ),
        });
        match quiet {
            RoutstrCliError::Wallet(e) => {
                assert!(
                    e.to_string().to_ascii_lowercase().contains("insufficient"),
                    "{e}"
                );
            }
            other => panic!("quiet AfterSync must map to Wallet, got: {other}"),
        }

        // AfterSync with hit_max notices → multi-line Message (not bare Wallet).
        let hit_max = map_gap_sync_spend_failure(GapSyncSpendFailure::AfterSync {
            sync: WalletSyncSnapshot {
                utxos: vec![],
                balance: WalletBalance::default(),
                receive_gap: 20,
                change_gap: 20,
                highest_used_receive: Some(19),
                highest_used_change: None,
                extended_receive_by: 5,
                extended_change_by: 0,
                hit_max_gap: true,
            },
            cause: WalletError::Onchain(
                "insufficient funds: need 50000 sats, have 1000 sats in 1 UTXOs".into(),
            ),
        });
        match hit_max {
            RoutstrCliError::Message(payload) => {
                let lower = payload.to_ascii_lowercase();
                assert!(
                    lower.contains("insufficient"),
                    "Message must include cause: {payload}"
                );
                assert!(
                    lower.contains("max") || lower.contains("gap"),
                    "Message must include hit-max / gap notice: {payload}"
                );
                assert!(
                    payload.contains('\n'),
                    "multi-line Message expected, got single line: {payload}"
                );
            }
            other => panic!("hit_max AfterSync must map to Message, got: {other}"),
        }
    }

    /// Product entrypoints must load passphrase via `from_env` wrapper (not hardcode `""`).
    #[test]
    #[serial]
    fn product_bip39_passphrase_from_env_is_non_empty_aware() {
        use grok_bitcoin_wallet::mnemonic::{BIP39_PASSPHRASE_ENV, Bip39Passphrase};

        let secret = "unit-test-passphrase-not-for-prod";
        let _env = EnvGuard::set(BIP39_PASSPHRASE_ENV, secret);
        let from_product = product_bip39_passphrase_from_env();
        let from_direct = Bip39Passphrase::from_env();
        assert!(!from_product.is_empty());
        assert_eq!(from_product.expose(), secret);
        assert_eq!(from_direct.expose(), secret);
        // Debug must not dump the secret (shell boundary keeps the wrapper).
        let dbg = format!("{from_product:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(secret));
        // Complete APIs accept &Bip39Passphrase (compile-time boundary); empty is default path.
        let empty = Bip39Passphrase::default();
        assert!(empty.is_empty());
        assert_eq!(format!("{empty:?}"), "Bip39Passphrase([REDACTED])");
    }

    #[test]
    #[serial]
    fn product_bip39_passphrase_from_env_empty_when_unset() {
        use grok_bitcoin_wallet::mnemonic::BIP39_PASSPHRASE_ENV;

        let _env = EnvGuard::unset(BIP39_PASSPHRASE_ENV);
        let p = product_bip39_passphrase_from_env();
        assert!(p.is_empty());
        assert_eq!(p.expose(), "");
    }

    /// Explicit TUI modal override must not fall back to env (empty explicit = default path).
    #[test]
    #[serial]
    fn product_bip39_passphrase_explicit_overrides_env() {
        use grok_bitcoin_wallet::mnemonic::BIP39_PASSPHRASE_ENV;

        let env_secret = "env-passphrase-should-not-win";
        let _env = EnvGuard::set(BIP39_PASSPHRASE_ENV, env_secret);
        let modal = product_bip39_passphrase(Some("modal-only-pass"));
        assert_eq!(modal.expose(), "modal-only-pass");
        let dbg = format!("{modal:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("modal-only-pass"));
        assert!(!dbg.contains(env_secret));
        // Explicit empty does not read env.
        let empty_explicit = product_bip39_passphrase(Some(""));
        assert!(empty_explicit.is_empty());
        assert_eq!(empty_explicit.expose(), "");
        // None still uses env.
        let from_env = product_bip39_passphrase(None);
        assert_eq!(from_env.expose(), env_secret);
    }

    #[test]
    fn catalog_id_detection() {
        assert!(is_routstr_catalog_id(ROUTSTR_GROK_45_CATALOG_ID));
        assert!(is_routstr_catalog_id("routstr-other"));
        assert!(!is_routstr_catalog_id("grok-4.5"));
        assert!(!is_routstr_catalog_id("openrouter-grok-4.5"));
    }

    #[test]
    fn should_fetch_routstr_balance_respects_feature_flag() {
        assert!(should_fetch_routstr_balance(true));
        assert!(!should_fetch_routstr_balance(false));
    }

    #[test]
    fn feature_disabled_cli_error_is_not_network_or_key_wording() {
        let msg = RoutstrCliError::FeatureDisabled.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("disabled") && lower.contains("routstr_enabled"),
            "expected feature-disabled wording: {msg}"
        );
        assert!(
            !lower.contains("network") && !lower.contains("key is valid"),
            "must not look like BalanceUnavailable: {msg}"
        );
        // BalanceUnavailable remains the transport/key failure path.
        let unavail = RoutstrCliError::BalanceUnavailable
            .to_string()
            .to_ascii_lowercase();
        assert!(unavail.contains("network") || unavail.contains("key"));
    }

    #[test]
    fn routstr_enabled_from_raw_config_defaults_true() {
        let empty: toml::Value = toml::from_str("").unwrap();
        assert!(routstr_enabled_from_raw_config(&empty));

        let on: toml::Value = toml::from_str(
            r#"
[features]
routstr_enabled = true
"#,
        )
        .unwrap();
        assert!(routstr_enabled_from_raw_config(&on));

        let off: toml::Value = toml::from_str(
            r#"
[features]
routstr_enabled = false
"#,
        )
        .unwrap();
        assert!(!routstr_enabled_from_raw_config(&off));
        assert!(!should_fetch_routstr_balance(
            routstr_enabled_from_raw_config(&off)
        ));
    }

    #[test]
    fn format_balance_line_sats_and_remainder() {
        assert_eq!(
            format_routstr_balance_line(2_100_000),
            "2100 sats (2100000 msats)"
        );
        assert_eq!(
            format_routstr_balance_line(2_100_001),
            "2100 sats + 1 msats (2100001 msats total)"
        );
    }

    #[test]
    fn seed_aead_path_not_credentials_store() {
        let p = routstr_seed_aead_path(std::path::Path::new("/tmp/grok-home"));
        assert!(p.ends_with("bitcoin/seed.aead"));
        assert!(!p.ends_with("provider_credentials.json"));
    }

    #[test]
    fn topup_and_refund_residual_has_no_website() {
        // Shared copy with TUI (`funding_cli`); residual never points at a website.
        let top = grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(Some(1000))
            .join(" ")
            .to_ascii_lowercase();
        assert!(top.contains("grok routstr topup") || top.contains("routstr topup"));
        assert!(!top.contains("docs.routstr.com"));
        assert!(!top.contains("invoice created"));
        let refnd = grok_bitcoin_wallet::funding_cli::refund_next_steps_lines()
            .join(" ")
            .to_ascii_lowercase();
        assert!(refnd.contains("grok routstr refund") || refnd.contains("balance/refund"));
        assert!(!refnd.contains("docs.routstr.com"));
        assert!(!refnd.contains("refund completed"));
    }

    #[test]
    fn format_http_error_truncates_body() {
        let long = "x".repeat(500);
        let msg = format_routstr_http_error("invoice create", 500, &long);
        assert!(msg.contains("invoice create HTTP 500"));
        assert!(msg.ends_with('…') || msg.contains('…'));
        assert!(msg.len() < 400, "expected truncated: len={}", msg.len());
    }

    #[test]
    #[serial]
    fn routstr_api_key_from_env_uses_primary_of_list() {
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, " sk-primary , sk-secondary\nsk-third ");
        let key = routstr_api_key_from_env().expect("primary");
        assert_eq!(key, "sk-primary");
    }

    #[test]
    fn decide_routstr_ready_state_machine() {
        assert_eq!(
            decide_routstr_ready(false, None, ROUTSTR_READY_MIN_MSATS),
            RoutstrReadyDecision::NeedInvoice {
                has_existing_key: false
            }
        );
        assert_eq!(
            decide_routstr_ready(true, Some(2_000_000), ROUTSTR_READY_MIN_MSATS),
            RoutstrReadyDecision::Ready { msats: 2_000_000 }
        );
        assert_eq!(
            decide_routstr_ready(true, Some(500), ROUTSTR_READY_MIN_MSATS),
            RoutstrReadyDecision::NeedInvoice {
                has_existing_key: true
            }
        );
        assert_eq!(
            decide_routstr_ready(true, None, ROUTSTR_READY_MIN_MSATS),
            RoutstrReadyDecision::NeedInvoice {
                has_existing_key: true
            }
        );
    }

    #[test]
    fn default_lightning_backend_auto_pay_matches_ldk_feature() {
        use grok_bitcoin_wallet::lightning::{
            LightningCapability, LocalBolt11PayPath, decide_local_bolt11_pay_path,
        };
        let ln = grok_bitcoin_wallet::lightning::default_lightning_backend();
        let caps = LightningCapability::capabilities(&ln);
        // Feature `ldk` → LdkLightning claims live pay (IPC helper).
        // Default CI (no feature) → stub, external QR only (P0).
        #[cfg(feature = "ldk")]
        {
            assert!(
                caps.bolt11_pay_live,
                "feature ldk default backend must claim live BOLT11 pay"
            );
            assert_eq!(
                decide_local_bolt11_pay_path(caps),
                LocalBolt11PayPath::AutoPayFromSeedVault
            );
        }
        #[cfg(not(feature = "ldk"))]
        {
            assert!(!caps.bolt11_pay_live);
            assert_eq!(
                decide_local_bolt11_pay_path(caps),
                LocalBolt11PayPath::ExternalWalletQr
            );
        }
        assert!(!caps.bolt12_supported);
        assert!(!caps.bolt11_invoice_live);
    }

    #[test]
    fn local_pay_apply_mock_live_success_and_fallback() {
        use grok_bitcoin_wallet::lightning::{
            Bolt11Invoice, LightningCapabilities, LightningCapability, LocalPayApplyResult,
            PayOutcome, apply_local_bolt11_pay, local_pay_result_lines,
        };
        use grok_bitcoin_wallet::mnemonic::generate_mnemonic;

        struct MockOk;
        impl LightningCapability for MockOk {
            fn capabilities(&self) -> LightningCapabilities {
                LightningCapabilities {
                    bolt11_pay_live: true,
                    bolt11_invoice_live: false,
                    bolt12_supported: false,
                    channel_open_live: false,
                    connect_peer_live: false,
                }
            }
            fn pay_bolt11(
                &self,
                _: &Bolt11Invoice,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Failed("use seed".into()))
            }
            fn pay_bolt11_with_seed(
                &self,
                _: &Bolt11Invoice,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Success {
                    preimage_hex: "aa".repeat(32),
                })
            }
        }

        struct MockFail;
        impl LightningCapability for MockFail {
            fn capabilities(&self) -> LightningCapabilities {
                LightningCapabilities {
                    bolt11_pay_live: true,
                    bolt11_invoice_live: false,
                    bolt12_supported: false,
                    channel_open_live: false,
                    connect_peer_live: false,
                }
            }
            fn pay_bolt11(
                &self,
                _: &Bolt11Invoice,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Failed("n/a".into()))
            }
            fn pay_bolt11_with_seed(
                &self,
                _: &Bolt11Invoice,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Failed("no outbound liquidity".into()))
            }
        }

        let m = generate_mnemonic().unwrap();
        let ok = apply_local_bolt11_pay(&MockOk, &Bolt11Invoice("lnbc1x".into()), &m, "");
        assert!(matches!(ok, LocalPayApplyResult::Paid { .. }));
        let fail = apply_local_bolt11_pay(&MockFail, &Bolt11Invoice("lnbc1x".into()), &m, "");
        assert!(matches!(fail, LocalPayApplyResult::FailedFallback { .. }));
        let lines = local_pay_result_lines(&fail)
            .join("\n")
            .to_ascii_lowercase();
        assert!(lines.contains("external") || lines.contains("falling back"));
        assert!(!lines.contains("not wired yet"));
        // Stub path skips local pay (P0 QR).
        let skipped = apply_local_bolt11_pay(
            &grok_bitcoin_wallet::lightning::StubLightning,
            &Bolt11Invoice("lnbc1x".into()),
            &m,
            "",
        );
        assert_eq!(skipped, LocalPayApplyResult::SkippedExternal);
    }

    #[test]
    fn unlock_failed_lines_omit_liquidity_honesty() {
        let lines = unlock_failed_fallback_lines("no local wallet found for auto-pay")
            .join("\n")
            .to_ascii_lowercase();
        assert!(lines.contains("unlock") || lines.contains("seedvault"));
        assert!(lines.contains("external") || lines.contains("bolt11"));
        // Must not imply a failed local pay / route / liquidity problem.
        assert!(!lines.contains("outbound"));
        assert!(!lines.contains("liquidity"));
        assert!(!lines.contains("channel"));
        let pay_fail = grok_bitcoin_wallet::lightning::local_pay_result_lines(
            &grok_bitcoin_wallet::lightning::LocalPayApplyResult::FailedFallback {
                reason: "no route".into(),
            },
        )
        .join("\n")
        .to_ascii_lowercase();
        assert!(pay_fail.contains("outbound") || pay_fail.contains("liquidity"));
    }

    /// Cashu mint product path: stub residual never claims float; mock live quote
    /// + after-pay redeem inject (offline, no network).
    #[test]
    fn mint_product_path_residual_and_tui_stages_offline() {
        use grok_bitcoin_wallet::cashu::{
            CashuBackend, CashuCapabilities, CashuRefundOutcome, MintProofsOutcome,
            MintQuoteOutcome, StubCashu,
        };
        use grok_bitcoin_wallet::mnemonic::generate_mnemonic;
        use grok_bitcoin_wallet::seed_vault::{SeedVault, VaultPassword};
        use tempfile::TempDir;

        // Residual: stub never unlocks, never fabricates quote/token/float.
        let residual =
            run_routstr_mint_with_cashu(Some(500), None, &StubCashu).expect("residual is Ok");
        assert_eq!(residual, RoutstrMintOutcome::ResidualFallback);

        struct MockLiveCashu;
        impl CashuBackend for MockLiveCashu {
            fn capabilities(&self) -> CashuCapabilities {
                CashuCapabilities {
                    mint_live: true,
                    proofs_mint_live: true,
                    spend_live: false,
                    refund_live: false,
                }
            }
            fn request_mint_invoice(
                &self,
                _: Option<u64>,
            ) -> grok_bitcoin_wallet::error::Result<MintQuoteOutcome> {
                Ok(MintQuoteOutcome::Failed("use seed".into()))
            }
            fn request_mint_invoice_with_seed(
                &self,
                amount_sats: Option<u64>,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<MintQuoteOutcome> {
                Ok(MintQuoteOutcome::Invoice {
                    bolt11: "lnbc1mockmintquote000000000000000000000000000000000".into(),
                    quote_id: "q-mock-1".into(),
                })
            }
            fn complete_mint_after_pay_with_seed(
                &self,
                quote_id: &str,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<MintProofsOutcome> {
                Ok(MintProofsOutcome::Token {
                    token: "cashuAabcdefghijklmnopqrstuvwxyz012345".into(),
                    amount_sats: 500,
                    quote_id: quote_id.to_owned(),
                })
            }
            fn refund(&self) -> grok_bitcoin_wallet::error::Result<CashuRefundOutcome> {
                Ok(CashuRefundOutcome::Unsupported("melt residual"))
            }
        }

        let tmp = TempDir::new().expect("tempdir");
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        // No vault → unlock fail Ok with residual lines (no float claim).
        let no_wallet = complete_routstr_mint_quote_reentry_for_tui_with_cashu(
            tmp.path(),
            phrase,
            None,
            Some(500),
            None,
            &MockLiveCashu,
        )
        .expect("unlock fail is Ok");
        assert!(no_wallet.quote_id.is_none());
        assert!(no_wallet.bolt11.is_none());
        let lower = no_wallet.lines.join("\n").to_ascii_lowercase();
        assert!(
            lower.contains("unlock") || lower.contains("wallet") || lower.contains("seedvault"),
            "expected unlock residual: {lower}"
        );
        assert!(!lower.contains("float credited"));
        assert!(!lower.contains("abandon abandon"));

        // Not-live skips SeedVault entirely.
        let skipped = complete_routstr_mint_quote_reentry_for_tui_with_cashu(
            tmp.path(),
            "should-not-matter",
            None,
            Some(100),
            None,
            &StubCashu,
        )
        .expect("not-live Ok");
        assert!(skipped.quote_id.is_none());
        let skip_l = skipped.lines.join("\n").to_ascii_lowercase();
        assert!(
            skip_l.contains("not live") || skip_l.contains("topup") || skip_l.contains("p0"),
            "expected residual: {skip_l}"
        );

        // AEAD vault + correct re-entry → live quote staged (mock).
        let aead = routstr_seed_aead_path(tmp.path());
        let vault = SeedVault::with_aead_path(&aead).unwrap();
        let mn = generate_mnemonic().unwrap();
        let words = mn.expose().to_owned();
        vault
            .store_aead(&mn, &VaultPassword::new("mint-pw"))
            .unwrap();

        let quoted = complete_routstr_mint_quote_reentry_for_tui_with_cashu(
            tmp.path(),
            &words,
            Some("mint-pw"),
            Some(500),
            None,
            &MockLiveCashu,
        )
        .expect("quote Ok");
        assert_eq!(quoted.quote_id.as_deref(), Some("q-mock-1"));
        assert!(
            quoted
                .bolt11
                .as_deref()
                .is_some_and(|b| b.starts_with("lnbc")),
            "expected bolt11: {:?}",
            quoted.bolt11
        );
        let q_lower = quoted.lines.join("\n").to_ascii_lowercase();
        assert!(
            q_lower.contains("mint quote")
                || (q_lower.contains("not") && q_lower.contains("float")),
            "expected mint quote honesty: {q_lower}"
        );
        assert!(!q_lower.contains("float credited"));
        assert!(!q_lower.contains(&words.to_ascii_lowercase()));

        // After-pay with redeem inject success → float_credited only then.
        let redeem_ok = complete_routstr_mint_after_pay_reentry_for_tui_with_cashu(
            tmp.path(),
            &words,
            Some("mint-pw"),
            "q-mock-1",
            None,
            Some(500),
            &MockLiveCashu,
            Some(&|_| Ok(())),
        )
        .expect("after-pay Ok");
        assert!(redeem_ok.float_credited);
        assert!(redeem_ok.token_obtained);
        assert!(redeem_ok.token_for_clipboard.is_none());
        let r_lower = redeem_ok.lines.join("\n").to_ascii_lowercase();
        assert!(
            r_lower.contains("float credited") || r_lower.contains("redeem succeeded"),
            "expected float claim after redeem: {r_lower}"
        );
        // Full bearer token must not appear in scrollback lines.
        assert!(
            redeem_ok
                .lines
                .iter()
                .all(|l| !l.contains("cashuAabcdefghijklmnopqrstuvwxyz012345")),
            "full token must not be in lines: {:?}",
            redeem_ok.lines
        );

        // Redeem inject fail → token obtained, float NOT credited.
        let redeem_fail = complete_routstr_mint_after_pay_reentry_for_tui_with_cashu(
            tmp.path(),
            &words,
            Some("mint-pw"),
            "q-mock-1",
            None,
            Some(500),
            &MockLiveCashu,
            Some(&|_| Err("mock redeem down".into())),
        )
        .expect("after-pay Ok");
        assert!(!redeem_fail.float_credited);
        assert!(redeem_fail.token_obtained);
        assert!(redeem_fail.token_for_clipboard.is_some());
        let f_lower = redeem_fail.lines.join("\n").to_ascii_lowercase();
        assert!(
            (f_lower.contains("not") && f_lower.contains("float"))
                || f_lower.contains("redeem failed"),
            "expected redeem-fail honesty: {f_lower}"
        );
        assert!(!f_lower.contains("float credited"));

        // Cancel re-entry (empty phrase) → no float.
        let cancel = complete_routstr_mint_after_pay_reentry_for_tui_with_cashu(
            tmp.path(),
            "   ",
            Some("mint-pw"),
            "q-mock-1",
            None,
            Some(500),
            &MockLiveCashu,
            Some(&|_| Ok(())),
        )
        .expect("cancel Ok");
        assert!(!cancel.float_credited);
        assert!(!cancel.token_obtained);

        // Empty quote_id hard-fails.
        let empty_q = complete_routstr_mint_after_pay_reentry_for_tui_with_cashu(
            tmp.path(),
            &words,
            Some("mint-pw"),
            "  ",
            None,
            Some(500),
            &MockLiveCashu,
            Some(&|_| Ok(())),
        );
        assert!(
            empty_q.is_err(),
            "empty quote_id must hard-fail: {empty_q:?}"
        );
    }

    /// Cashu melt product path: stub residual never claims float; mock live Paid;
    /// never float credit; bad token / unlock fail honest.
    #[test]
    fn melt_product_path_residual_and_tui_never_float() {
        use grok_bitcoin_wallet::cashu::{
            CashuBackend, CashuCapabilities, CashuRefundOutcome, MintProofsOutcome,
            MintQuoteOutcome, StubCashu,
        };
        use grok_bitcoin_wallet::mnemonic::generate_mnemonic;
        use grok_bitcoin_wallet::seed_vault::{SeedVault, VaultPassword};
        use tempfile::TempDir;

        let token = "cashuAabcdefghijklmnopqrstuvwxyz012345";
        let bolt11 = "lnbc1mockmeltdest00000000000000000000000000000000";

        // Residual CLI: stub never unlocks, never fabricates Paid / float.
        let residual = run_routstr_melt_with_cashu(token, bolt11, &StubCashu).expect("Ok");
        assert_eq!(residual, RoutstrRefundOutcome::ResidualFallback);

        // Partial args: CLI usage error (not silent residual).
        let only_token = run_routstr_refund(Some(token), None);
        assert!(only_token.is_err(), "token without invoice must err");
        let only_inv = run_routstr_refund(None, Some(bolt11));
        assert!(only_inv.is_err(), "invoice without token must err");

        // Live + bad shape: fail lines must not claim "not live" (capability honesty).
        // Pure helper assertion mirrors CLI post-gate shape path / TUI order.
        {
            use grok_bitcoin_wallet::cashu::{
                CashuCapabilities, CashuMeltProductPath, cashu_melt_failed_lines,
                decide_cashu_melt_product_path,
            };
            let live_caps = CashuCapabilities {
                mint_live: false,
                proofs_mint_live: false,
                spend_live: true,
                refund_live: true,
            };
            assert_eq!(
                decide_cashu_melt_product_path(live_caps),
                CashuMeltProductPath::LiveMelt
            );
            let bad_shape = cashu_melt_failed_lines(
                "token failed CashuToken::parse (need cashuA…/cashuB…); no melt attempted",
            )
            .join("\n")
            .to_ascii_lowercase();
            assert!(
                !bad_shape.contains("not live"),
                "live+bad-token lines must not claim melt not live: {bad_shape}"
            );
            assert!(
                bad_shape.contains("did not complete") || bad_shape.contains("no melt"),
                "expected live-fail detail: {bad_shape}"
            );
        }

        struct MockMeltCashu {
            paid: bool,
        }
        impl CashuBackend for MockMeltCashu {
            fn capabilities(&self) -> CashuCapabilities {
                CashuCapabilities {
                    mint_live: false,
                    proofs_mint_live: false,
                    spend_live: true,
                    refund_live: true,
                }
            }
            fn request_mint_invoice(
                &self,
                _: Option<u64>,
            ) -> grok_bitcoin_wallet::error::Result<MintQuoteOutcome> {
                Ok(MintQuoteOutcome::Unsupported("n/a"))
            }
            fn complete_mint_after_pay_with_seed(
                &self,
                _: &str,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<MintProofsOutcome> {
                Ok(MintProofsOutcome::Unsupported("n/a"))
            }
            fn refund(&self) -> grok_bitcoin_wallet::error::Result<CashuRefundOutcome> {
                Ok(CashuRefundOutcome::Failed(
                    "bare refund has no token context (use melt_token_to_bolt11_with_seed)".into(),
                ))
            }
            fn melt_token_to_bolt11_with_seed(
                &self,
                token: &str,
                bolt11: &str,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<CashuRefundOutcome> {
                if !token.starts_with("cashuA") {
                    return Ok(CashuRefundOutcome::Failed("bad token".into()));
                }
                if !bolt11.starts_with("lnbc") {
                    return Ok(CashuRefundOutcome::Failed("bad bolt11".into()));
                }
                if self.paid {
                    Ok(CashuRefundOutcome::Completed {
                        detail: "melted 21 sats (fee 1) quote_id=mq-1 state=PAID".into(),
                    })
                } else {
                    Ok(CashuRefundOutcome::Failed("mint rejected melt".into()))
                }
            }
        }

        let tmp = TempDir::new().expect("tempdir");
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Not-live skips SeedVault entirely.
        let skipped = complete_routstr_melt_reentry_for_tui_with_cashu(
            tmp.path(),
            "should-not-matter",
            None,
            token,
            bolt11,
            None,
            &StubCashu,
        )
        .expect("not-live Ok");
        assert!(!skipped.melted);
        let skip_l = skipped.lines.join("\n").to_ascii_lowercase();
        assert!(
            skip_l.contains("not live") || skip_l.contains("refund"),
            "expected residual: {skip_l}"
        );
        assert!(!skip_l.contains("float credited"));
        assert!(!skip_l.contains(token));

        // Live + bad token shape: fail lines, never "not live" (TUI order; CLI matches).
        let bad_token_tui = complete_routstr_melt_reentry_for_tui_with_cashu(
            tmp.path(),
            phrase,
            None,
            "not-a-cashu-token",
            bolt11,
            None,
            &MockMeltCashu { paid: true },
        )
        .expect("bad token is Ok");
        assert!(!bad_token_tui.melted);
        let bad_l = bad_token_tui.lines.join("\n").to_ascii_lowercase();
        assert!(
            !bad_l.contains("not live"),
            "live+bad-token must not claim melt not live: {bad_l}"
        );
        assert!(
            bad_l.contains("token") || bad_l.contains("did not complete"),
            "expected shape fail: {bad_l}"
        );
        assert!(!bad_l.contains("float credited"));

        // No vault → unlock fail Ok with residual (no float claim).
        let no_wallet = complete_routstr_melt_reentry_for_tui_with_cashu(
            tmp.path(),
            phrase,
            None,
            token,
            bolt11,
            None,
            &MockMeltCashu { paid: true },
        )
        .expect("unlock fail is Ok");
        assert!(!no_wallet.melted);
        let lower = no_wallet.lines.join("\n").to_ascii_lowercase();
        assert!(
            lower.contains("unlock") || lower.contains("wallet") || lower.contains("seedvault"),
            "expected unlock residual: {lower}"
        );
        assert!(!lower.contains("float credited"));
        // Live unlock fail must not invert capability honesty either.
        assert!(
            !lower.contains("not live"),
            "live unlock fail must not claim melt not live: {lower}"
        );
        assert!(!lower.contains("abandon abandon"));

        // Bad token shape → residual without claiming Paid.
        let bad_tok = complete_routstr_melt_reentry_for_tui_with_cashu(
            tmp.path(),
            phrase,
            None,
            "sk-not-cashu-token",
            bolt11,
            None,
            &MockMeltCashu { paid: true },
        )
        .expect("bad token Ok residual");
        assert!(!bad_tok.melted);
        assert!(
            !bad_tok
                .lines
                .join("\n")
                .to_ascii_lowercase()
                .contains("float credited")
        );

        // AEAD vault + correct re-entry → melt Paid (mock); never float.
        let aead = routstr_seed_aead_path(tmp.path());
        let vault = SeedVault::with_aead_path(&aead).unwrap();
        let mn = generate_mnemonic().unwrap();
        let words = mn.expose().to_owned();
        vault
            .store_aead(&mn, &VaultPassword::new("melt-pw"))
            .unwrap();

        let paid = complete_routstr_melt_reentry_for_tui_with_cashu(
            tmp.path(),
            &words,
            Some("melt-pw"),
            token,
            bolt11,
            None,
            &MockMeltCashu { paid: true },
        )
        .expect("melt Ok");
        assert!(paid.melted, "expected melted=true on Paid");
        let p_lower = paid.lines.join("\n").to_ascii_lowercase();
        assert!(
            p_lower.contains("melt") && (p_lower.contains("paid") || p_lower.contains("completed")),
            "expected melt paid honesty: {p_lower}"
        );
        assert!(
            p_lower.contains("not") && p_lower.contains("float"),
            "must deny float claim: {p_lower}"
        );
        assert!(!p_lower.contains("float credited"));
        assert!(!p_lower.contains(&words.to_ascii_lowercase()));
        assert!(
            paid.lines.iter().all(|l| !l.contains(token)),
            "full token must not be in lines: {:?}",
            paid.lines
        );

        // Melt Failed from helper → not melted, no float.
        let failed = complete_routstr_melt_reentry_for_tui_with_cashu(
            tmp.path(),
            &words,
            Some("melt-pw"),
            token,
            bolt11,
            None,
            &MockMeltCashu { paid: false },
        )
        .expect("melt fail Ok");
        assert!(!failed.melted);
        let f_lower = failed.lines.join("\n").to_ascii_lowercase();
        assert!(!f_lower.contains("float credited"));
        assert!(
            f_lower.contains("did not complete")
                || f_lower.contains("failed")
                || f_lower.contains("rejected"),
            "expected fail honesty: {f_lower}"
        );
    }

    /// TUI topup local-pay complete: not-live backend skips SeedVault; live mock
    /// unlock-fail (no wallet) omits liquidity; empty bolt11 hard-fails.
    #[test]
    fn tui_topup_local_pay_complete_not_live_and_no_wallet_paths() {
        use grok_bitcoin_wallet::lightning::{
            Bolt11Invoice, LightningCapabilities, LightningCapability, PayOutcome,
        };
        use tempfile::TempDir;

        struct MockLiveOk;
        impl LightningCapability for MockLiveOk {
            fn capabilities(&self) -> LightningCapabilities {
                LightningCapabilities {
                    bolt11_pay_live: true,
                    bolt11_invoice_live: false,
                    bolt12_supported: false,
                    channel_open_live: false,
                    connect_peer_live: false,
                }
            }
            fn pay_bolt11(
                &self,
                _: &Bolt11Invoice,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Failed("use seed".into()))
            }
            fn pay_bolt11_with_seed(
                &self,
                _: &Bolt11Invoice,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Success {
                    preimage_hex: "bb".repeat(32),
                })
            }
        }

        let tmp = TempDir::new().expect("tempdir");
        // Empty home → no SeedVault; live backend still unlock-fails without liquidity copy.
        let no_wallet = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            tmp.path(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            None,
            "lnbc1testinvoice",
            None,
            &MockLiveOk,
        )
        .expect("unlock fail is Ok with fallback lines");
        assert!(!no_wallet.local_paid);
        let lower = no_wallet.lines.join("\n").to_ascii_lowercase();
        assert!(
            lower.contains("unlock") || lower.contains("seedvault") || lower.contains("wallet"),
            "expected unlock/wallet fallback: {lower}"
        );
        assert!(
            lower.contains("external") || lower.contains("bolt11"),
            "expected external fallback: {lower}"
        );
        assert!(!lower.contains("outbound"));
        assert!(!lower.contains("liquidity"));
        // Success payload holds lines + local_paid only — never re-entry phrase.
        // (Effect/SensitiveString Debug redaction is covered in pager unlock tests.)
        assert_eq!(
            format!("{:?}", no_wallet.local_paid),
            "false",
            "local_paid must stay plain bool"
        );
        assert!(
            no_wallet
                .lines
                .iter()
                .all(|l| !l.to_ascii_lowercase().contains("abandon abandon")),
            "lines must not echo recovery phrase: {:?}",
            no_wallet.lines
        );

        // Stub / not-live: no SeedVault touch; external guidance only.
        let skipped = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            tmp.path(),
            "should-not-matter",
            None,
            "lnbc1x",
            None,
            &grok_bitcoin_wallet::lightning::StubLightning,
        )
        .expect("not-live is Ok");
        assert!(!skipped.local_paid);
        let skip_l = skipped.lines.join("\n").to_ascii_lowercase();
        assert!(
            skip_l.contains("not live") || skip_l.contains("external") || skip_l.contains("bolt11"),
            "expected not-live guidance: {skip_l}"
        );
        assert!(!skip_l.contains("outbound"));

        // Empty bolt11 is a hard error (no fabricated pay).
        let empty = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            tmp.path(),
            "phrase",
            None,
            "   ",
            None,
            &MockLiveOk,
        );
        assert!(empty.is_err(), "empty bolt11 must hard-fail: {empty:?}");
    }

    /// Offline AEAD vault gates for TUI topup local-pay (mirror utxos re-entry suite).
    ///
    /// Unlock-fail paths return **Ok** with `unlock_failed_fallback_lines` (no
    /// liquidity honesty). Correct phrase + mock pay fail returns pay lines **with**
    /// liquidity honesty. Session is locked on every path inside the complete helper.
    #[test]
    fn tui_topup_local_pay_reentry_aead_gates_offline() {
        use grok_bitcoin_wallet::lightning::{
            Bolt11Invoice, LightningCapabilities, LightningCapability, PayOutcome,
        };
        use grok_bitcoin_wallet::mnemonic::generate_mnemonic;
        use grok_bitcoin_wallet::seed_vault::{SeedVault, VaultPassword};
        use tempfile::TempDir;

        struct MockLiveFail;
        impl LightningCapability for MockLiveFail {
            fn capabilities(&self) -> LightningCapabilities {
                LightningCapabilities {
                    bolt11_pay_live: true,
                    bolt11_invoice_live: false,
                    bolt12_supported: false,
                    channel_open_live: false,
                    connect_peer_live: false,
                }
            }
            fn pay_bolt11(
                &self,
                _: &Bolt11Invoice,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Failed("use seed".into()))
            }
            fn pay_bolt11_with_seed(
                &self,
                _: &Bolt11Invoice,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Failed(
                    "no outbound liquidity for unit test".into(),
                ))
            }
        }

        struct MockLiveOk;
        impl LightningCapability for MockLiveOk {
            fn capabilities(&self) -> LightningCapabilities {
                LightningCapabilities {
                    bolt11_pay_live: true,
                    bolt11_invoice_live: false,
                    bolt12_supported: false,
                    channel_open_live: false,
                    connect_peer_live: false,
                }
            }
            fn pay_bolt11(
                &self,
                _: &Bolt11Invoice,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Failed("use seed".into()))
            }
            fn pay_bolt11_with_seed(
                &self,
                _: &Bolt11Invoice,
                _: &grok_bitcoin_wallet::mnemonic::MnemonicSecret,
                _: &str,
            ) -> grok_bitcoin_wallet::error::Result<PayOutcome> {
                Ok(PayOutcome::Success {
                    preimage_hex: "cc".repeat(32),
                })
            }
        }

        let home = TempDir::new().expect("tempdir");
        let aead = routstr_seed_aead_path(home.path());
        let vault = SeedVault::with_aead_path(&aead).unwrap();
        let mnemonic = generate_mnemonic().unwrap();
        let phrase = mnemonic.expose().to_owned();
        vault
            .store_aead(&mnemonic, &VaultPassword::new("test-pw"))
            .unwrap();

        // Empty re-entry → cancel wording; unlock-fail lines (no liquidity).
        let cancel = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            home.path(),
            "   ",
            Some("test-pw"),
            "lnbc1testinvoice",
            None,
            &MockLiveFail,
        )
        .expect("cancel is Ok with unlock-fail lines");
        assert!(!cancel.local_paid);
        let cancel_l = cancel.lines.join("\n").to_ascii_lowercase();
        assert!(
            cancel_l.contains("cancelled")
                || cancel_l.contains("unlock")
                || cancel_l.contains("external"),
            "expected cancel/unlock fallback: {cancel_l}"
        );
        assert!(!cancel_l.contains("outbound"));
        assert!(!cancel_l.contains("liquidity"));

        // Wrong recovery phrase → unlock-fail (not cancel); no liquidity honesty.
        let wrong = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            home.path(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Some("test-pw"),
            "lnbc1testinvoice",
            None,
            &MockLiveFail,
        )
        .expect("wrong phrase is Ok with unlock-fail lines");
        assert!(!wrong.local_paid);
        let wrong_l = wrong.lines.join("\n").to_ascii_lowercase();
        assert!(
            !wrong_l.contains("cancelled"),
            "wrong phrase is not cancel: {wrong_l}"
        );
        assert!(
            wrong_l.contains("unlock")
                || wrong_l.contains("seedvault")
                || wrong_l.contains("external"),
            "expected unlock-fail fallback: {wrong_l}"
        );
        assert!(!wrong_l.contains("outbound"));
        assert!(!wrong_l.contains("liquidity"));

        // Wrong AEAD password → unlock-fail without liquidity.
        let bad_pw = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            home.path(),
            &phrase,
            Some("wrong-password"),
            "lnbc1testinvoice",
            None,
            &MockLiveFail,
        )
        .expect("wrong password is Ok with unlock-fail lines");
        assert!(!bad_pw.local_paid);
        let bad_pw_l = bad_pw.lines.join("\n").to_ascii_lowercase();
        assert!(
            bad_pw_l.contains("password")
                || bad_pw_l.contains("decrypt")
                || bad_pw_l.contains("aead")
                || bad_pw_l.contains("seed")
                || bad_pw_l.contains("vault")
                || bad_pw_l.contains("unlock")
                || bad_pw_l.contains("external"),
            "expected password/decrypt unlock-fail: {bad_pw_l}"
        );
        assert!(!bad_pw_l.contains("outbound"));
        assert!(!bad_pw_l.contains("liquidity"));

        // AEAD present + password: None → NeedPassword unlock-fail (no pay attempt).
        let need_pw = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            home.path(),
            &phrase,
            None,
            "lnbc1testinvoice",
            None,
            &MockLiveFail,
        )
        .expect("NeedPassword is Ok with unlock-fail lines");
        assert!(!need_pw.local_paid);
        let need_pw_l = need_pw.lines.join("\n").to_ascii_lowercase();
        assert!(
            need_pw_l.contains("password") || need_pw_l.contains("unlock"),
            "expected password-required unlock-fail: {need_pw_l}"
        );
        assert!(!need_pw_l.contains("outbound"));
        assert!(!need_pw_l.contains("liquidity"));

        // Correct phrase + mock pay fail → real pay attempt → liquidity honesty.
        let pay_fail = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            home.path(),
            &phrase,
            Some("test-pw"),
            "lnbc1testinvoice",
            None,
            &MockLiveFail,
        )
        .expect("pay fail is Ok with local_pay_result_lines");
        assert!(!pay_fail.local_paid);
        let pay_fail_l = pay_fail.lines.join("\n").to_ascii_lowercase();
        assert!(
            pay_fail_l.contains("external") || pay_fail_l.contains("falling back"),
            "expected external fallback after pay fail: {pay_fail_l}"
        );
        assert!(
            pay_fail_l.contains("outbound") || pay_fail_l.contains("liquidity"),
            "pay-fail must include liquidity honesty: {pay_fail_l}"
        );
        // Must not fall through to residual "not wired" copy.
        assert!(!pay_fail_l.contains("not wired"));

        // Correct phrase + mock pay success → local_paid true; no fallback liquidity copy.
        let paid = complete_routstr_topup_local_pay_reentry_for_tui_with_lightning(
            home.path(),
            &phrase,
            Some("test-pw"),
            "lnbc1testinvoice",
            None,
            &MockLiveOk,
        )
        .expect("pay success is Ok");
        assert!(paid.local_paid, "expected local_paid: {:?}", paid.lines);
        let paid_l = paid.lines.join("\n").to_ascii_lowercase();
        assert!(
            paid_l.contains("success") || paid_l.contains("submitted") || paid_l.contains("poll"),
            "expected success lines: {paid_l}"
        );
        assert!(!paid_l.contains("falling back"));
        // Phrase never appears in returned lines.
        assert!(
            paid.lines.iter().all(|l| !l.contains(&phrase)),
            "success lines must not echo recovery phrase"
        );
        // Scrub owned phrase buffer (test hygiene; complete already zeroizes its copy).
        let mut phrase = phrase;
        grok_bitcoin_wallet::mnemonic::zeroize_phrase(&mut phrase);
    }

    /// Pin that unlock-fail lines omit liquidity honesty while pay-fail lines include it.
    #[test]
    fn tui_topup_local_pay_liquidity_honesty_only_after_pay_attempt() {
        let unlock = unlock_failed_fallback_lines("phrase mismatch")
            .join("\n")
            .to_ascii_lowercase();
        assert!(!unlock.contains("outbound"));
        assert!(!unlock.contains("liquidity"));
        let pay = grok_bitcoin_wallet::lightning::local_pay_result_lines(
            &grok_bitcoin_wallet::lightning::LocalPayApplyResult::FailedFallback {
                reason: "no outbound path".into(),
            },
        )
        .join("\n")
        .to_ascii_lowercase();
        assert!(pay.contains("outbound") || pay.contains("liquidity"));
        let paid = grok_bitcoin_wallet::lightning::local_pay_result_lines(
            &grok_bitcoin_wallet::lightning::LocalPayApplyResult::Paid {
                preimage_hex: "aa".repeat(32),
            },
        )
        .join("\n")
        .to_ascii_lowercase();
        assert!(paid.contains("success") || paid.contains("submitted") || paid.contains("poll"));
        assert!(!paid.contains("falling back"));
    }

    #[test]
    fn parse_api_key_and_refund_token_flexible() {
        assert_eq!(
            parse_routstr_api_key_from_body(r#"{"api_key":"sk-abc"}"#).as_deref(),
            Some("sk-abc")
        );
        assert_eq!(
            parse_routstr_api_key_from_body(r#"{"data":{"key":"sk-nested"}}"#).as_deref(),
            Some("sk-nested")
        );
        assert!(parse_routstr_api_key_from_body(r#"{"api_key":""}"#).is_none());
        assert_eq!(
            parse_routstr_refund_cashu_token(r#"{"token":"cashuAlongtokenhere"}"#).as_deref(),
            Some("cashuAlongtokenhere")
        );
        assert_eq!(
            parse_routstr_refund_cashu_token(r#"{"data":{"cashu_token":"cashuBxyz"}}"#).as_deref(),
            Some("cashuBxyz")
        );
        assert!(parse_routstr_refund_cashu_token("{}").is_none());
        assert_eq!(parse_routstr_msats_flexible(r#"{"msats":42}"#), Some(42));
        assert_eq!(parse_routstr_msats_flexible(r#"{"sats":10}"#), Some(10_000));
    }

    #[test]
    fn redact_secret_never_dumps_full_key() {
        let r = redact_secret_preview("sk-supersecrettokenvalue");
        assert!(r.contains('…'));
        assert!(!r.contains("supersecret"));
    }

    #[test]
    fn balance_msats_from_info() {
        let info = RoutstrBalanceInfo {
            msats: Some(2_500_000),
            balance_msats: None,
            balance: None,
            sats: None,
            balance_sats: None,
        };
        assert_eq!(routstr_balance_msats_from_info(&info), Some(2_500_000));
        let info = RoutstrBalanceInfo {
            msats: None,
            balance_msats: None,
            balance: None,
            sats: Some(100),
            balance_sats: None,
        };
        assert_eq!(routstr_balance_msats_from_info(&info), Some(100_000));
        let info = RoutstrBalanceInfo {
            msats: None,
            balance_msats: None,
            balance: None,
            sats: None,
            balance_sats: Some(250),
        };
        assert_eq!(routstr_balance_msats_from_info(&info), Some(250_000));
    }

    #[test]
    fn parse_balance_json_variants() {
        assert_eq!(parse_routstr_balance_msats(r#"{"msats":42}"#), Some(42));
        assert_eq!(
            parse_routstr_balance_msats(r#"{"data":{"balance_msats":99}}"#),
            Some(99)
        );
        assert_eq!(
            parse_routstr_balance_msats(r#"{"balance_sats":10}"#),
            Some(10_000)
        );
        assert_eq!(
            parse_routstr_balance_msats(r#"{"data":{"balance_sats":3}}"#),
            Some(3_000)
        );
        // Bare balance is ambiguous.
        assert_eq!(parse_routstr_balance_msats(r#"{"balance":1000}"#), None);
        assert_eq!(parse_routstr_balance_msats("not-json"), None);
    }

    #[test]
    #[serial]
    fn load_prefers_env_over_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store
            .write_bearer(ROUTSTR_API_URL, "sk-from-store")
            .unwrap();

        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "sk-from-env");
        let key = load_routstr_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "sk-from-env");
    }

    #[test]
    #[serial]
    fn load_falls_back_to_store() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store
            .write_bearer(ROUTSTR_API_URL, "sk-from-store")
            .unwrap();

        let _env = EnvGuard::unset(ROUTSTR_API_KEY_ENV);
        let key = load_routstr_api_key(&store).unwrap().unwrap();
        assert_eq!(key, "sk-from-store");
    }

    #[test]
    #[serial]
    fn load_refuses_residual_env_and_store_shapes() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        store
            .write_bearer(ROUTSTR_API_URL, "sk-from-store")
            .unwrap();

        // Residual env is not transmitted; live store key still wins (env-over-store
        // only for live shapes).
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "Nostr e30=");
        assert_eq!(
            load_routstr_api_key(&store).unwrap().as_deref(),
            Some("sk-from-store")
        );

        let _env = EnvGuard::set(
            ROUTSTR_API_KEY_ENV,
            grok_bitcoin_wallet::nip06::NIP06_TEST_MNEMONIC,
        );
        assert_eq!(
            load_routstr_api_key(&store).unwrap().as_deref(),
            Some("sk-from-store")
        );

        // Residual env + residual-only store → missing (no Bearer transmit).
        let dir2 = TempDir::new().unwrap();
        let store2 = CredentialsStore::at_path(dir2.path().join("creds.json"));
        // Direct store write bypasses product validate (legacy / test fixture).
        store2
            .write_bearer(ROUTSTR_API_URL, "not-a-live-key")
            .unwrap();
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "Nostr e30=");
        assert!(load_routstr_api_key(&store2).unwrap().is_none());

        let _env = EnvGuard::unset(ROUTSTR_API_KEY_ENV);
        assert!(load_routstr_api_key(&store2).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn store_refuses_when_live_env_set() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        // Live env wins / blocks store (env-over-store for live shapes only).
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "sk-env-key");
        let err = store_routstr_api_key(&store, "sk-store-key").unwrap_err();
        assert!(matches!(err, RoutstrAuthError::EnvVarSet));
    }

    #[test]
    #[serial]
    fn store_allows_live_key_when_residual_env_set() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        // Residual env must not orphan a paid/live key (Issue 7).
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "Nostr e30=");
        store_routstr_api_key(&store, "sk-paid-from-invoice").unwrap();
        assert_eq!(
            load_routstr_api_key(&store).unwrap().as_deref(),
            Some("sk-paid-from-invoice"),
            "load falls through residual env to live store key"
        );

        // Other residual shape likewise does not block store.
        let dir2 = TempDir::new().unwrap();
        let store2 = CredentialsStore::at_path(dir2.path().join("creds.json"));
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "not-sk-or-cashu");
        store_routstr_api_key(&store2, "cashuApaidtoken").unwrap();
        assert_eq!(
            load_routstr_api_key(&store2).unwrap().as_deref(),
            Some("cashuApaidtoken")
        );
    }

    #[test]
    #[serial]
    fn store_and_clear() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        let _env = EnvGuard::unset(ROUTSTR_API_KEY_ENV);
        store_routstr_api_key(&store, "sk-routstr-test").unwrap();
        assert_eq!(
            load_routstr_api_key(&store).unwrap().as_deref(),
            Some("sk-routstr-test")
        );
        clear_routstr_api_key(&store).unwrap();
        assert!(load_routstr_api_key(&store).unwrap().is_none());
    }

    #[test]
    fn classify_routstr_product_auth_material_live_and_residual() {
        assert_eq!(
            classify_routstr_product_auth_material(""),
            RoutstrProductAuthMaterial::Empty
        );
        assert_eq!(
            classify_routstr_product_auth_material("   "),
            RoutstrProductAuthMaterial::Empty
        );
        assert_eq!(
            classify_routstr_product_auth_material("sk-abc"),
            RoutstrProductAuthMaterial::SkPrepaid
        );
        assert_eq!(
            classify_routstr_product_auth_material("Bearer sk-abc"),
            RoutstrProductAuthMaterial::SkPrepaid
        );
        assert_eq!(
            classify_routstr_product_auth_material("cashuAeyJ0ZXN0"),
            RoutstrProductAuthMaterial::CashuToken
        );
        assert_eq!(
            classify_routstr_product_auth_material("cashuBxyz"),
            RoutstrProductAuthMaterial::CashuToken
        );
        assert!(classify_routstr_product_auth_material("sk-abc").accepted_by_live_bearer());
        assert!(classify_routstr_product_auth_material("cashuAeyJ").accepted_by_live_bearer());

        // NIP-98 residual (scheme attempt — not live Success)
        assert_eq!(
            classify_routstr_product_auth_material("Nostr"),
            RoutstrProductAuthMaterial::Nip98Nostr
        );
        assert_eq!(
            classify_routstr_product_auth_material("Nostr e30="),
            RoutstrProductAuthMaterial::Nip98Nostr
        );
        assert_eq!(
            classify_routstr_product_auth_material("Bearer Nostr e30="),
            RoutstrProductAuthMaterial::Nip98Nostr
        );
        assert_eq!(
            classify_routstr_product_auth_material("nostr e30="),
            RoutstrProductAuthMaterial::Nip98Nostr
        );
        // Glued scheme (no whitespace) still residual refuse
        assert_eq!(
            classify_routstr_product_auth_material("NostrBASE64payload"),
            RoutstrProductAuthMaterial::Nip98Nostr
        );
        assert!(!RoutstrProductAuthMaterial::Nip98Nostr.accepted_by_live_bearer());
        assert!(!ROUTSTR_PRODUCT_NIP98_AUTH_LIVE);

        // Seed material refuse
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        assert_eq!(
            classify_routstr_product_auth_material(nsec),
            RoutstrProductAuthMaterial::SecretSeedLike
        );
        // Bearer-wrapped seed still residual (wrapper stripped before nsec check)
        assert_eq!(
            classify_routstr_product_auth_material(&format!("Bearer {nsec}")),
            RoutstrProductAuthMaterial::SecretSeedLike
        );
        let mnemonic = grok_bitcoin_wallet::nip06::NIP06_TEST_MNEMONIC;
        assert_eq!(
            classify_routstr_product_auth_material(mnemonic),
            RoutstrProductAuthMaterial::SecretSeedLike
        );
        assert_eq!(
            classify_routstr_product_auth_material(&format!("Bearer {mnemonic}")),
            RoutstrProductAuthMaterial::SecretSeedLike
        );

        // 64-char hex secret key material → SecretSeedLike (clearer refuse than Other)
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(hex64.len(), 64);
        assert_eq!(
            classify_routstr_product_auth_material(hex64),
            RoutstrProductAuthMaterial::SecretSeedLike
        );
        assert_eq!(
            classify_routstr_product_auth_material(&hex64.to_ascii_uppercase()),
            RoutstrProductAuthMaterial::SecretSeedLike
        );
        assert_eq!(
            classify_routstr_product_auth_material(&format!("Bearer {hex64}")),
            RoutstrProductAuthMaterial::SecretSeedLike
        );
        // Not 64 hex → Other
        assert_eq!(
            classify_routstr_product_auth_material(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
            ),
            RoutstrProductAuthMaterial::Other
        );

        assert_eq!(
            classify_routstr_product_auth_material("not-a-key"),
            RoutstrProductAuthMaterial::Other
        );
        assert_eq!(
            classify_routstr_product_auth_material("sk-"),
            RoutstrProductAuthMaterial::Other
        );
        // Public npub is not seed material (not live Bearer either)
        assert_eq!(
            classify_routstr_product_auth_material(
                "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q4hcstx"
            ),
            RoutstrProductAuthMaterial::Other
        );
    }

    #[test]
    fn validate_routstr_product_bearer_key_accepts_live_refuses_residual() {
        assert_eq!(
            validate_routstr_product_bearer_key("sk-ok").unwrap(),
            "sk-ok"
        );
        assert_eq!(
            validate_routstr_product_bearer_key("Bearer sk-ok").unwrap(),
            "sk-ok"
        );
        assert_eq!(
            validate_routstr_product_bearer_key("cashuAtoken").unwrap(),
            "cashuAtoken"
        );
        assert_eq!(
            validate_routstr_product_bearer_key("Bearer cashuAtoken").unwrap(),
            "cashuAtoken"
        );
        assert!(matches!(
            validate_routstr_product_bearer_key(""),
            Err(RoutstrAuthError::EmptyKey)
        ));
        assert!(matches!(
            validate_routstr_product_bearer_key("Nostr e30="),
            Err(RoutstrAuthError::Nip98NotLive)
        ));
        assert!(matches!(
            validate_routstr_product_bearer_key("Bearer Nostr e30="),
            Err(RoutstrAuthError::Nip98NotLive)
        ));
        assert!(matches!(
            validate_routstr_product_bearer_key(grok_bitcoin_wallet::nip06::NIP06_TEST_MNEMONIC),
            Err(RoutstrAuthError::SeedMaterialRefused)
        ));
        assert!(matches!(
            validate_routstr_product_bearer_key(
                "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
            ),
            Err(RoutstrAuthError::SeedMaterialRefused)
        ));
        assert!(matches!(
            validate_routstr_product_bearer_key("random-token"),
            Err(RoutstrAuthError::NotLiveBearerShape)
        ));
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(matches!(
            validate_routstr_product_bearer_key(hex64),
            Err(RoutstrAuthError::SeedMaterialRefused)
        ));
        // Product Success shapes only: live flag stays false; accepted_by_live_bearer
        // is the sole Success gate for store/inference Authorization.
        assert!(!ROUTSTR_PRODUCT_NIP98_AUTH_LIVE);
        for live in ["sk-paid", "cashuAabc", "cashuBxyz"] {
            let class = classify_routstr_product_auth_material(live);
            assert!(
                class.accepted_by_live_bearer(),
                "live shape {live:?} must be accepted_by_live_bearer"
            );
            assert!(validate_routstr_product_bearer_key(live).is_ok());
        }
        for residual in [
            "Nostr e30=",
            grok_bitcoin_wallet::nip06::NIP06_TEST_MNEMONIC,
            "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
            hex64,
            "not-sk-or-cashu",
        ] {
            let class = classify_routstr_product_auth_material(residual);
            assert!(
                !class.accepted_by_live_bearer(),
                "residual {residual:?} must not be accepted_by_live_bearer"
            );
            assert!(validate_routstr_product_bearer_key(residual).is_err());
        }
    }

    #[test]
    fn routstr_auth_error_variants_are_distinct_residual() {
        let nip98 = RoutstrAuthError::Nip98NotLive;
        let seed = RoutstrAuthError::SeedMaterialRefused;
        let other = RoutstrAuthError::NotLiveBearerShape;
        let empty = RoutstrAuthError::EmptyKey;
        let env = RoutstrAuthError::EnvVarSet;

        assert!(is_routstr_product_auth_residual_error(&nip98));
        assert!(is_routstr_product_auth_residual_error(&seed));
        assert!(is_routstr_product_auth_residual_error(&other));
        assert!(!is_routstr_product_auth_residual_error(&empty));
        assert!(!is_routstr_product_auth_residual_error(&env));

        let m_nip98 = nip98.to_string();
        let m_seed = seed.to_string();
        let m_other = other.to_string();
        assert_ne!(m_nip98, m_seed);
        assert_ne!(m_nip98, m_other);
        assert_ne!(m_seed, m_other);
        assert!(
            m_nip98.contains("NIP-98") || m_nip98.contains("Nostr"),
            "Nip98NotLive message must name residual: {m_nip98}"
        );
        assert!(
            m_seed.to_ascii_lowercase().contains("nsec")
                || m_seed.to_ascii_lowercase().contains("bip-39")
                || m_seed.to_ascii_lowercase().contains("seed"),
            "SeedMaterialRefused must name seed residual: {m_seed}"
        );
        assert!(
            m_other.contains("sk-") && m_other.contains("cashu"),
            "NotLiveBearerShape must name live shapes: {m_other}"
        );
        // Never invent Success wording
        for m in [&m_nip98, &m_seed, &m_other] {
            let lower = m.to_ascii_lowercase();
            assert!(!lower.contains("signed-auth success"));
            assert!(!lower.contains("nip-98 live"));
        }
    }

    #[test]
    #[serial]
    fn store_refuses_nip98_seed_and_other_shapes() {
        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        let _env = EnvGuard::unset(ROUTSTR_API_KEY_ENV);

        let err = store_routstr_api_key(&store, "Nostr e30=").unwrap_err();
        assert!(matches!(err, RoutstrAuthError::Nip98NotLive));
        assert!(is_routstr_product_auth_residual_error(&err));
        assert!(store.read(&routstr_credential_url(None)).unwrap().is_none());

        let err = store_routstr_api_key(&store, grok_bitcoin_wallet::nip06::NIP06_TEST_MNEMONIC)
            .unwrap_err();
        assert!(matches!(err, RoutstrAuthError::SeedMaterialRefused));
        assert!(is_routstr_product_auth_residual_error(&err));
        assert!(store.read(&routstr_credential_url(None)).unwrap().is_none());

        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = store_routstr_api_key(&store, hex64).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::SeedMaterialRefused));
        assert!(store.read(&routstr_credential_url(None)).unwrap().is_none());

        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let err = store_routstr_api_key(&store, nsec).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::SeedMaterialRefused));
        assert!(store.read(&routstr_credential_url(None)).unwrap().is_none());

        let err = store_routstr_api_key(&store, "not-sk-or-cashu").unwrap_err();
        assert!(matches!(err, RoutstrAuthError::NotLiveBearerShape));
        assert!(is_routstr_product_auth_residual_error(&err));
        assert!(store.read(&routstr_credential_url(None)).unwrap().is_none());

        // Live cashu still stores
        store_routstr_api_key(&store, "cashuAstoretest").unwrap();
        assert_eq!(
            load_routstr_api_key(&store).unwrap().as_deref(),
            Some("cashuAstoretest")
        );
    }

    #[test]
    fn nip98_product_residual_lines_are_honest() {
        let lines = routstr_nip98_product_residual_lines();
        assert!(!lines.is_empty());
        let joined = lines.join(" ");
        assert!(joined.contains("Bearer"));
        assert!(joined.contains("NIP-98") || joined.contains("NIP-06"));
        assert!(
            joined.to_ascii_lowercase().contains("credentialsstore")
                || joined.contains("CredentialsStore")
        );
        assert!(
            !joined
                .to_ascii_lowercase()
                .contains("signed-auth success wired")
        );
        // Constant + residual copy must both stay honest (no vacuous OR).
        assert!(
            !ROUTSTR_PRODUCT_NIP98_AUTH_LIVE,
            "ROUTSTR_PRODUCT_NIP98_AUTH_LIVE must stay false until live contract proven"
        );
        assert!(
            joined.contains("ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false"),
            "residual lines must name ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false; got: {joined}"
        );

        let seed_lines = routstr_seed_material_product_residual_lines();
        assert!(!seed_lines.is_empty());
        let seed_joined = seed_lines.join(" ");
        assert!(
            seed_joined.to_ascii_lowercase().contains("seedvault")
                || seed_joined.contains("SeedVault"),
            "seed residual lines must name SeedVault; got: {seed_joined}"
        );
        assert!(
            seed_joined.contains("CredentialsStore")
                || seed_joined
                    .to_ascii_lowercase()
                    .contains("credentialsstore"),
            "seed residual lines must refuse CredentialsStore; got: {seed_joined}"
        );
        assert!(
            seed_joined.contains("ROUTSTR_PRODUCT_NIP98_AUTH_LIVE=false"),
            "seed residual lines must name flag false; got: {seed_joined}"
        );
        assert!(
            !seed_joined
                .to_ascii_lowercase()
                .contains("signed-auth success wired")
        );
    }

    /// Assert residual login did not write under the test grok_home file store
    /// (file path is always written on store Success; residual must not create it).
    /// Avoids ambient OS keyring false positives on `read()`.
    fn assert_no_routstr_file_store(grok_home: &Path) {
        let creds = grok_home.join("provider_credentials.json");
        assert!(!creds.exists(), "residual auth must not create {creds:?}");
        let store = CredentialsStore::at_path(creds);
        assert!(
            store.read(&routstr_credential_url(None)).unwrap().is_none(),
            "file CredentialsStore must not hold Routstr key after residual refuse"
        );
    }

    #[test]
    #[serial]
    fn run_routstr_login_env_residual_nip98_refuses_without_store_write() {
        let dir = TempDir::new().unwrap();
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "Nostr e30=");
        let err = run_routstr_login(dir.path(), None).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::Nip98NotLive));
        assert!(is_routstr_product_auth_residual_error(&err));
        assert_no_routstr_file_store(dir.path());
    }

    #[test]
    #[serial]
    fn run_routstr_login_env_residual_seed_refuses_without_store_write() {
        let dir = TempDir::new().unwrap();
        let _env = EnvGuard::set(
            ROUTSTR_API_KEY_ENV,
            grok_bitcoin_wallet::nip06::NIP06_TEST_MNEMONIC,
        );
        let err = run_routstr_login(dir.path(), None).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::SeedMaterialRefused));
        assert!(is_routstr_product_auth_residual_error(&err));
        assert_no_routstr_file_store(dir.path());
    }

    #[test]
    #[serial]
    fn run_routstr_login_env_other_shape_refuses_without_store_write() {
        let dir = TempDir::new().unwrap();
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "not-sk-or-cashu");
        // Other residual: fail closed (Err), same as explicit --api-key; no store write.
        let err = run_routstr_login(dir.path(), None).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::NotLiveBearerShape));
        assert!(is_routstr_product_auth_residual_error(&err));
        assert_no_routstr_file_store(dir.path());
    }

    #[test]
    #[serial]
    fn live_routstr_api_key_from_env_prefers_first_live_in_multi_list() {
        // Residual-first multi-key must not split-brain vs inference: first live wins.
        // Also drains residual *tail* after live (zeroize hygiene; Issue re-review 1).
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "Nostr e30=,sk-live-second,cashuAthird");
        assert_eq!(
            live_routstr_api_key_from_env().as_deref(),
            Some("sk-live-second")
        );
        // First raw token is still residual (for residual messaging paths);
        // first-token helper zeroizes unreturned multi-list tail.
        assert_eq!(routstr_api_key_from_env().as_deref(), Some("Nostr e30="));

        // Live-first with residual seed-like tail: still returns first live (and
        // drains/zeroizes nsec + mnemonic tokens before return).
        let _env = EnvGuard::set(
            ROUTSTR_API_KEY_ENV,
            "sk-live-first,nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5,abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        assert_eq!(
            live_routstr_api_key_from_env().as_deref(),
            Some("sk-live-first"),
            "live-first must not early-return without draining residual tail"
        );
        // first-token helper: primary only; tail still zeroized.
        assert_eq!(routstr_api_key_from_env().as_deref(), Some("sk-live-first"));

        let _env = EnvGuard::set(
            ROUTSTR_API_KEY_ENV,
            "not-sk-or-cashu\nnsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
        );
        assert!(
            live_routstr_api_key_from_env().is_none(),
            "pure residual multi-list must yield None"
        );
        // Presence-only residual check must not retain secrets for callers.
        assert!(
            routstr_api_key_env_has_token(),
            "pure residual multi-list still has tokens"
        );

        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "cashuAfirst,sk-second");
        assert_eq!(
            live_routstr_api_key_from_env().as_deref(),
            Some("cashuAfirst"),
            "first live cashu wins over later sk-"
        );

        let dir = TempDir::new().unwrap();
        let store = CredentialsStore::at_path(dir.path().join("creds.json"));
        // Residual-first + live second: load uses live env (not store fall-through only).
        let _env = EnvGuard::set(ROUTSTR_API_KEY_ENV, "Nostr e30=,sk-from-multi");
        store
            .write_bearer(ROUTSTR_API_URL, "sk-from-store")
            .unwrap();
        assert_eq!(
            load_routstr_api_key(&store).unwrap().as_deref(),
            Some("sk-from-multi")
        );
    }

    #[test]
    #[serial]
    fn run_routstr_login_explicit_residual_refuses_without_store_write() {
        let dir = TempDir::new().unwrap();
        let _env = EnvGuard::unset(ROUTSTR_API_KEY_ENV);

        let err = run_routstr_login(dir.path(), Some("Nostr e30=")).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::Nip98NotLive));
        assert!(is_routstr_product_auth_residual_error(&err));
        assert_no_routstr_file_store(dir.path());

        let err = run_routstr_login(
            dir.path(),
            Some(grok_bitcoin_wallet::nip06::NIP06_TEST_MNEMONIC),
        )
        .unwrap_err();
        assert!(matches!(err, RoutstrAuthError::SeedMaterialRefused));
        assert_no_routstr_file_store(dir.path());

        let err = run_routstr_login(
            dir.path(),
            Some("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"),
        )
        .unwrap_err();
        assert!(matches!(err, RoutstrAuthError::SeedMaterialRefused));
        assert_no_routstr_file_store(dir.path());

        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = run_routstr_login(dir.path(), Some(hex64)).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::SeedMaterialRefused));
        assert_no_routstr_file_store(dir.path());

        let err = run_routstr_login(dir.path(), Some("not-sk-or-cashu")).unwrap_err();
        assert!(matches!(err, RoutstrAuthError::NotLiveBearerShape));
        assert_no_routstr_file_store(dir.path());

        // Live Success for login is covered by store_and_clear / store_refuses_*
        // (file-only store). Do **not** call run_routstr_login with a live key here:
        // at_grok_home may write the OS keyring for the fixed Routstr URL and
        // pollute ambient suite state.
    }

    #[test]
    fn resolve_spend_fee_rate_override_skips_network() {
        // Explicit override never needs explorer; must not return 0.
        assert_eq!(resolve_spend_fee_rate_for_product(Some(12)), 12);
        assert_eq!(resolve_spend_fee_rate_for_product(Some(1)), 1);
    }

    #[test]
    fn resolve_fees_network_explicit_and_rejects_unknown() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

        assert_eq!(
            resolve_fees_network(Some("signet")).unwrap(),
            BitcoinNetwork::Signet
        );
        assert_eq!(
            resolve_fees_network(Some("testnet4")).unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_fees_network(Some("main")).unwrap(),
            BitcoinNetwork::Mainnet
        );
        let err = resolve_fees_network(Some("regtest")).unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(msg.contains("unknown") || msg.contains("network"), "{msg}");
        let err = resolve_fees_network(Some("   ")).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("empty"));
    }

    /// Product complete paths share one network resolve (empty → Mainnet;
    /// testnet4 accepted; unknown/regtest fail closed — never silent Mainnet).
    #[test]
    fn resolve_product_complete_network_parity_and_fail_closed() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
        use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

        assert_eq!(
            resolve_product_complete_network("").unwrap(),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            resolve_product_complete_network("   ").unwrap(),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            resolve_product_complete_network("testnet4").unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_product_complete_network("Testnet4").unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_product_complete_network("testnet").unwrap(),
            BitcoinNetwork::Testnet
        );
        // testnet4 → same rust Network as testnet (utxos / Electrum parity).
        assert_eq!(
            bitcoin_network_to_network(resolve_product_complete_network("testnet4").unwrap()),
            bitcoin_network_to_network(resolve_product_complete_network("testnet").unwrap())
        );
        assert_ne!(
            bitcoin_network_to_network(resolve_product_complete_network("signet").unwrap()),
            bitcoin_network_to_network(resolve_product_complete_network("mainnet").unwrap())
        );

        for bad in ["regtest", "mainet", "not-a-network", "testnet5"] {
            let err = resolve_product_complete_network(bad).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "expected fail-closed for {bad:?}: {err}"
            );
            // Must not claim mainnet success path.
            assert!(!matches!(err, RoutstrCliError::Wallet(_)));
        }
    }

    /// complete_routstr_{utxos,spend,rbf,cpfp}_with_mnemonic reject unknown
    /// network before wallet/chain work (no silent Mainnet).
    #[test]
    fn complete_utxos_spend_rbf_cpfp_unknown_network_fail_closed() {
        use grok_bitcoin_wallet::mnemonic::{Bip39Passphrase, import_mnemonic};

        const VECTOR: &str =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = Bip39Passphrase::default();

        for bad in ["regtest", "mainet", "bogus"] {
            let err = complete_routstr_utxos_with_mnemonic(&m, bad, &pass).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "utxos must fail-closed on {bad:?}: {err}"
            );

            let err =
                complete_routstr_spend_with_mnemonic(&m, bad, "bc1qtest", 1000, false, 10, &pass)
                    .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "spend must fail-closed on {bad:?}: {err}"
            );

            let err = complete_routstr_rbf_with_mnemonic(
                &m,
                bad,
                "bc1qtest",
                1000,
                500,
                141,
                &[],
                false,
                10,
                &pass,
            )
            .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "rbf must fail-closed on {bad:?}: {err}"
            );

            let err = complete_routstr_cpfp_with_mnemonic(
                &m,
                bad,
                "bc1qtest",
                1000,
                500,
                141,
                &[],
                &[],
                false,
                10,
                &pass,
            )
            .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "cpfp must fail-closed on {bad:?}: {err}"
            );
        }
    }

    /// Product entry (CLI/TUI) fail-closed on poisoned env — never soft-Mainnet
    /// like fees. Empty env → Mainnet; explicit empty `--network` still rejected.
    #[test]
    #[serial]
    fn resolve_product_entry_network_fail_closed_env() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;

        // Unset → Mainnet.
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        assert_eq!(
            resolve_product_entry_network(None).unwrap(),
            BitcoinNetwork::Mainnet
        );

        // Empty env value → Mainnet.
        let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", "   ");
        assert_eq!(
            resolve_product_entry_network(None).unwrap(),
            BitcoinNetwork::Mainnet
        );

        // Poisoned env must hard-error (utxos/spend entry contract).
        for bad in ["regtest", "mainet", "bogus"] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", bad);
            let err = resolve_product_entry_network(None).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "env-only entry must fail-closed on {bad:?}: {err}"
            );
            // Contrast: fees soft-defaults unknown env (intentionally different).
            assert_eq!(
                resolve_fees_network(None).unwrap(),
                BitcoinNetwork::Mainnet,
                "fees soft-default still Mainnet for env {bad:?}"
            );
        }

        // Explicit CLI still rejects empty / unknown (parity with fees CLI).
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        let err = resolve_product_entry_network(Some("   ")).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("empty"));
        let err = resolve_product_entry_network(Some("regtest")).unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("unknown"));
        assert_eq!(
            resolve_product_entry_network(Some("testnet4")).unwrap(),
            BitcoinNetwork::Testnet4
        );
        assert_eq!(
            resolve_product_entry_network(Some("signet")).unwrap(),
            BitcoinNetwork::Signet
        );
    }

    /// Fund CLI/TUI use the same product entry resolve + enum→Network map as
    /// spend/utxos (canonical labels; regtest/unknown fail closed). Pure pin
    /// for derive path: resolve → `as_str` label → `bitcoin_network_to_network`
    /// → `derive_bip84_receive_address_with_passphrase` (not env-string helper).
    #[test]
    #[serial]
    fn fund_product_network_resolve_and_derive_parity() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
        use grok_bitcoin_wallet::mnemonic::import_mnemonic;
        use grok_bitcoin_wallet::onchain::{
            bitcoin_network_to_network, derive_bip84_receive_address_with_passphrase,
        };

        const VECTOR: &str =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let m = import_mnemonic(VECTOR).unwrap();

        // Empty / unset → Mainnet (fund calls resolve_product_entry_network(None)).
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        let btc_net = resolve_product_entry_network(None).unwrap();
        assert_eq!(btc_net, BitcoinNetwork::Mainnet);
        assert_eq!(btc_net.as_str(), "mainnet");
        let addr = derive_bip84_receive_address_with_passphrase(
            &m,
            "",
            bitcoin_network_to_network(btc_net),
            0,
        )
        .unwrap();
        assert!(addr.starts_with("bc1q"), "mainnet receive: {addr}");

        for (label, expected, prefix) in [
            ("signet", BitcoinNetwork::Signet, "tb1"),
            ("testnet", BitcoinNetwork::Testnet, "tb1"),
            ("testnet4", BitcoinNetwork::Testnet4, "tb1"),
            ("mainnet", BitcoinNetwork::Mainnet, "bc1q"),
        ] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", label);
            let btc_net = resolve_product_entry_network(None).unwrap();
            assert_eq!(btc_net, expected, "fund entry for {label}");
            // Canonical label for success lines (not raw env string / regtest).
            assert_eq!(btc_net.as_str(), expected.as_str());
            let addr = derive_bip84_receive_address_with_passphrase(
                &m,
                "",
                bitcoin_network_to_network(btc_net),
                0,
            )
            .unwrap();
            assert!(
                addr.starts_with(prefix),
                "fund derive {label}: expected prefix {prefix}, got {addr}"
            );
        }

        // testnet4 and testnet share rust Network / same BIP84 receive.
        let a = derive_bip84_receive_address_with_passphrase(
            &m,
            "",
            bitcoin_network_to_network(BitcoinNetwork::Testnet4),
            0,
        )
        .unwrap();
        let b = derive_bip84_receive_address_with_passphrase(
            &m,
            "",
            bitcoin_network_to_network(BitcoinNetwork::Testnet),
            0,
        )
        .unwrap();
        assert_eq!(a, b);

        // Poisoned env: fund must fail closed before unlock (same helper as spend).
        for bad in ["regtest", "mainet", "bogus"] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", bad);
            let err = resolve_product_entry_network(None).unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "fund entry must fail-closed on {bad:?}: {err}"
            );
            // Must not be a Wallet error from low-level env-string derive
            // (that path still accepts regtest for tests/dev).
            assert!(
                matches!(err, RoutstrCliError::Message(_)),
                "fund network reject should be Message, got {err:?}"
            );
        }
    }

    /// Full TUI fund re-entry hits product entry resolve first: poisoned env
    /// fails closed as Message network reject **before** no-wallet / password /
    /// re-entry gates (empty temp home proves resolve order — not pure-helper only).
    #[test]
    #[serial]
    fn fund_reentry_for_tui_rejects_poisoned_network_before_wallet() {
        // Empty home: if resolve were after vault load, we'd get "no local wallet".
        let empty_home = TempDir::new().unwrap();

        for bad in ["regtest", "bogus"] {
            let _g = EnvGuard::set("GROK_BITCOIN_NETWORK", bad);
            let err =
                complete_routstr_fund_reentry_for_tui(empty_home.path(), "any phrase", None, None)
                    .unwrap_err();
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unknown") && msg.contains(bad),
                "fund TUI re-entry must network-reject {bad:?} before no-wallet: {err}"
            );
            assert!(
                !msg.contains("no local wallet")
                    && !msg.contains("password")
                    && !msg.contains("re-enter")
                    && !msg.contains("recovery phrase"),
                "must not be vault/re-entry gate: {err}"
            );
            assert!(
                matches!(err, RoutstrCliError::Message(_)),
                "expected Message network reject, got {err:?}"
            );
        }

        // Sanitized env: empty home then reaches no-wallet (proves only network
        // gate was the early fail for poisoned labels).
        let _g = EnvGuard::unset("GROK_BITCOIN_NETWORK");
        let err =
            complete_routstr_fund_reentry_for_tui(empty_home.path(), "any phrase", None, None)
                .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("no local wallet") || msg.contains("fund"),
            "empty home + mainnet should hit no-wallet, not network: {err}"
        );
        assert!(!msg.contains("unknown network"));
    }

    /// testnet4 constructs a descriptor wallet (same rust Network as testnet)
    /// on RBF/CPFP complete paths; empty inputs then fail with product copy
    /// (proves resolve + from_mnemonic_with_passphrase accepted testnet4).
    #[test]
    fn complete_rbf_cpfp_testnet4_wallet_constructs_like_utxos() {
        use grok_bitcoin_wallet::descriptor_wallet::{DEFAULT_RECEIVE_GAP, DescriptorWallet};
        use grok_bitcoin_wallet::mnemonic::{Bip39Passphrase, import_mnemonic};
        use grok_bitcoin_wallet::onchain::bitcoin_network_to_network;

        const VECTOR: &str =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let m = import_mnemonic(VECTOR).unwrap();
        let pass = Bip39Passphrase::default();

        // Parity with utxos: single resolve → bitcoin_network_to_network → wallet.
        let btc_net = resolve_product_complete_network("testnet4").unwrap();
        let rust_net = bitcoin_network_to_network(btc_net);
        let w = DescriptorWallet::from_mnemonic_with_passphrase(
            &m,
            pass.expose(),
            rust_net,
            DEFAULT_RECEIVE_GAP,
        )
        .expect("testnet4 wallet construction");
        // testnet label maps to the same rust Network (descriptor parity).
        let w_tn = DescriptorWallet::from_mnemonic_with_passphrase(
            &m,
            pass.expose(),
            bitcoin_network_to_network(resolve_product_complete_network("testnet").unwrap()),
            DEFAULT_RECEIVE_GAP,
        )
        .unwrap();
        assert_eq!(w.network(), w_tn.network());
        assert_eq!(w.receive_addresses()[0], w_tn.receive_addresses()[0]);
        assert!(
            w.receive_addresses()[0].starts_with("tb1")
                || w.receive_addresses()[0].starts_with("bcrt"),
            "testnet4 BIP84 receive should be testnet-class: {}",
            w.receive_addresses()[0]
        );

        // complete RBF/CPFP: testnet4 accepted past network resolve; empty inputs
        // is the next gate (wallet already built).
        let err = complete_routstr_rbf_with_mnemonic(
            &m,
            "testnet4",
            "tb1qtest",
            1000,
            500,
            141,
            &[],
            false,
            10,
            &pass,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("input") || msg.contains("rbf"),
            "testnet4 rbf should reach empty-input gate, not network reject: {err}"
        );
        assert!(!msg.contains("unknown network"));

        let err = complete_routstr_cpfp_with_mnemonic(
            &m,
            "testnet4",
            "tb1qtest",
            1000,
            500,
            141,
            &[],
            &[],
            false,
            10,
            &pass,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("parent") || msg.contains("cpfp"),
            "testnet4 cpfp should reach empty-parent gate, not network reject: {err}"
        );
        assert!(!msg.contains("unknown network"));
    }

    /// BDK spend failure mapping uses BDK notices (feature `bdk` only).
    #[cfg(feature = "bdk")]
    #[test]
    fn map_bdk_sync_spend_failure_three_arms() {
        use grok_bitcoin_wallet::bdk_sync::BdkSyncSpendFailure;
        use grok_bitcoin_wallet::descriptor_wallet::{WalletBalance, WalletSyncSnapshot};
        use grok_bitcoin_wallet::error::WalletError;

        let sync_err = map_bdk_sync_spend_failure(BdkSyncSpendFailure::Sync(WalletError::Onchain(
            "bdk full_scan transport refused".into(),
        )));
        match sync_err {
            RoutstrCliError::Wallet(e) => {
                assert!(e.to_string().to_ascii_lowercase().contains("bdk"), "{e}");
            }
            other => panic!("Sync must map to Wallet, got: {other}"),
        }

        let quiet = map_bdk_sync_spend_failure(BdkSyncSpendFailure::AfterSync {
            sync: WalletSyncSnapshot {
                utxos: vec![],
                balance: WalletBalance::default(),
                receive_gap: 1,
                change_gap: 1,
                highest_used_receive: None,
                highest_used_change: None,
                extended_receive_by: 0,
                extended_change_by: 0,
                hit_max_gap: false,
            },
            cause: WalletError::Onchain("insufficient funds: need 100 sats".into()),
        });
        // Quiet AfterSync still carries bdk_sync_notice_lines (always ≥1 line).
        match quiet {
            RoutstrCliError::Message(payload) => {
                let lower = payload.to_ascii_lowercase();
                assert!(lower.contains("insufficient"), "{payload}");
                assert!(lower.contains("bdk"), "must use BDK notice copy: {payload}");
                // BDK notice contrasts "not gap-limit"; reject gap-only residual phrasing.
                assert!(
                    !lower.contains("gap-limit chainsource sync only")
                        && !lower.contains("not full bdk_wallet"),
                    "must not use gap residual: {payload}"
                );
            }
            RoutstrCliError::Wallet(e) => {
                // If notices empty (shouldn't for BDK), cause still honest.
                assert!(
                    e.to_string().to_ascii_lowercase().contains("insufficient"),
                    "{e}"
                );
            }
            other => panic!("unexpected: {other}"),
        }
    }

    /// Pure utxos CLI formatter via shell wrapper (mock snapshot; no network).
    #[test]
    fn utxos_command_lines_from_mock_snapshot() {
        use grok_bitcoin_wallet::descriptor_wallet::{
            OutPointRef, WalletBalance, WalletSyncSnapshot, WalletUtxo,
        };

        let utxo = WalletUtxo {
            outpoint: OutPointRef::new("cd".repeat(32), 0),
            amount_sats: 50_000,
            address: "bc1qtest".into(),
            confirmations: 3,
            is_change: false,
        };
        let snap = WalletSyncSnapshot {
            utxos: vec![utxo],
            balance: WalletBalance {
                confirmed_sats: 50_000,
                unconfirmed_sats: 1_000,
            },
            receive_gap: 25,
            change_gap: 20,
            highest_used_receive: Some(0),
            highest_used_change: None,
            extended_receive_by: 5,
            extended_change_by: 0,
            hit_max_gap: false,
        };
        let lines = utxos_command_lines(&snap, "mainnet");
        let j = lines.join("\n");
        let lower = j.to_ascii_lowercase();
        assert!(j.contains("50000") || j.contains("confirmed"));
        assert!(j.contains("unconfirmed"));
        assert!(j.contains("--input"));
        assert!(j.contains(&"cd".repeat(32)));
        assert!(lower.contains("extended") || lower.contains("gap"));
        assert!(lower.contains("gap-limit") || lower.contains("not full"));
        assert!(!lower.contains("crypto"));

        // Empty: honest zero, no invented UTXOs.
        let empty = WalletSyncSnapshot {
            utxos: vec![],
            balance: WalletBalance::default(),
            receive_gap: 20,
            change_gap: 20,
            highest_used_receive: None,
            highest_used_change: None,
            extended_receive_by: 0,
            extended_change_by: 0,
            hit_max_gap: false,
        };
        let empty_j = utxos_command_lines(&empty, "signet").join("\n");
        let empty_l = empty_j.to_ascii_lowercase();
        assert!(empty_l.contains("signet"));
        assert!(empty_l.contains("0 sats") || empty_l.contains("confirmed"));
        assert!(empty_l.contains("none") || !empty_l.contains("--input"));
        assert!(!empty_l.contains("crypto"));
    }

    /// TUI utxos re-entry: cancel / wrong phrase / no wallet / bad network
    /// (offline; never reaches chain). Session is locked on every Err path.
    #[test]
    fn utxos_reentry_for_tui_gates_offline() {
        use grok_bitcoin_wallet::mnemonic::generate_mnemonic;
        use grok_bitcoin_wallet::seed_vault::{SeedVault, VaultPassword};

        // No wallet at empty grok home.
        let empty_home = TempDir::new().unwrap();
        let err = complete_routstr_utxos_reentry_for_tui(
            empty_home.path(),
            "leader monkey parrot ring guide accident before fence cannon height naive bean",
            None,
            None,
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("no local wallet") || msg.contains("fund"),
            "expected no-wallet guidance: {err}"
        );

        // Unknown network fails before unlock (bad flag never touches seed).
        let err = complete_routstr_utxos_reentry_for_tui(
            empty_home.path(),
            "any phrase",
            None,
            Some("regtest"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("unknown") || msg.contains("network"),
            "expected network reject: {err}"
        );

        // AEAD vault: empty re-entry → cancel (session locked).
        let home = TempDir::new().unwrap();
        let aead = routstr_seed_aead_path(home.path());
        let vault = SeedVault::with_aead_path(&aead).unwrap();
        let mnemonic = generate_mnemonic().unwrap();
        let phrase = mnemonic.expose().to_owned();
        vault
            .store_aead(&mnemonic, &VaultPassword::new("test-pw"))
            .unwrap();

        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            "   ",
            Some("test-pw"),
            Some("signet"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("cancelled") || msg.contains("not listing"),
            "expected re-entry cancel: {err}"
        );

        // Wrong phrase → gate error (session locked; no chain).
        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Some("test-pw"),
            Some("mainnet"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            !msg.contains("cancelled"),
            "wrong phrase is not cancel: {err}"
        );
        // Confirm correct phrase would pass the gate — but stop before live chain
        // by using an invalid network after re-entry would run. Network is checked
        // first, so re-use wrong-password to prove password gate.
        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            &phrase,
            Some("wrong-password"),
            None,
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("password")
                || msg.contains("decrypt")
                || msg.contains("aead")
                || msg.contains("seed")
                || msg.contains("vault")
                || msg.contains("incorrect")
                || msg.contains("invalid"),
            "expected password/decrypt failure: {err}"
        );

        // AEAD present + password: None → NeedPassword (no unlock, no chain).
        let err = complete_routstr_utxos_reentry_for_tui(
            home.path(),
            &phrase,
            None,
            Some("signet"),
            None,
        )
        .unwrap_err();
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("password required") || msg.contains("password"),
            "expected NeedPassword guidance: {err}"
        );
        // Phrase kept only for gate correctness; never returned in success payload.
        let _ = phrase;
    }

    fn fees_command_lines_offline_ladder_and_unavailable() {
        let est = grok_bitcoin_wallet::explorer::FeeEstimates {
            fastest_sat_vb: 30,
            half_hour_sat_vb: 12,
            hour_sat_vb: 8,
            economy_sat_vb: 3,
            minimum_sat_vb: 1,
        };
        let ok = fees_command_lines(Some(&est), "mainnet").join("\n");
        let ok_l = ok.to_ascii_lowercase();
        assert!(ok.contains("fastest: 30"));
        assert!(ok.contains("halfHour: 12"));
        assert!(ok_l.contains("product default when live"));
        assert!(ok_l.contains("mainnet"));
        assert!(ok_l.contains("rbf") && ok_l.contains("cpfp"));
        assert!(!ok_l.contains("crypto"));
        // Ladder only — no broadcast claim.
        assert!(!ok_l.contains("broadcast accepted"));

        // Zero halfHour: product ignores 0 estimates — do not label as live default.
        let zero_hh = grok_bitcoin_wallet::explorer::FeeEstimates {
            fastest_sat_vb: 30,
            half_hour_sat_vb: 0,
            hour_sat_vb: 8,
            economy_sat_vb: 3,
            minimum_sat_vb: 1,
        };
        let zero_lines = fees_command_lines(Some(&zero_hh), "mainnet").join("\n");
        let zero_l = zero_lines.to_ascii_lowercase();
        assert!(zero_lines.contains("halfHour: 0"));
        assert!(!zero_l.contains("product default when live"));
        assert!(zero_l.contains("ignored") || zero_l.contains("fall"));

        let miss = fees_command_lines(None, "signet").join("\n");
        let miss_l = miss.to_ascii_lowercase();
        assert!(miss_l.contains("unavailable") || miss_l.contains("not inventing"));
        assert!(miss_l.contains("signet"));
        assert!(
            miss_l.contains("rate-limit") || miss_l.contains("rate limit"),
            "unavailable must cover rate-limit, not only reachability: {miss}"
        );
        assert!(!miss_l.contains("fastest:"));
        assert!(!miss_l.contains("crypto"));
    }

    #[test]
    fn resolve_spend_fee_rate_offline_fallback_is_default() {
        use grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB;
        // No estimates → product default; no network.
        assert_eq!(
            resolve_spend_fee_rate_with_estimates(None, None),
            DEFAULT_SPEND_FEE_RATE_SAT_VB
        );
        assert_eq!(
            resolve_spend_fee_rate_with_estimates(Some(0), None),
            DEFAULT_SPEND_FEE_RATE_SAT_VB
        );
        let est = grok_bitcoin_wallet::explorer::FeeEstimates {
            fastest_sat_vb: 20,
            half_hour_sat_vb: 15,
            hour_sat_vb: 10,
            economy_sat_vb: 5,
            minimum_sat_vb: 1,
        };
        assert_eq!(resolve_spend_fee_rate_with_estimates(None, Some(&est)), 15);
        assert_eq!(
            resolve_spend_fee_rate_with_estimates(Some(9), Some(&est)),
            9
        );
    }

    #[test]
    fn run_routstr_spend_parse_rejects_explicit_zero_fee_like_tui() {
        use grok_bitcoin_wallet::funding_cli::{SpendParseError, parse_spend_request};
        // CLI path now parse_spend_request's first: same rejection as TUI fee=0.
        assert!(matches!(
            parse_spend_request("bc1qtest", 100, false, Some(0)),
            Err(SpendParseError::InvalidFeeRate(_))
        ));
        // None is allowed (resolved later to estimate/default).
        let req = parse_spend_request("bc1qtest", 100, false, None).unwrap();
        assert!(!req.fee_rate_explicit);
        assert_eq!(
            req.fee_rate_sat_vb,
            grok_bitcoin_wallet::funding_cli::DEFAULT_SPEND_FEE_RATE_SAT_VB
        );
        let req = parse_spend_request("bc1qtest", 100, false, Some(8)).unwrap();
        assert!(req.fee_rate_explicit);
        assert_eq!(req.fee_rate_sat_vb, 8);
    }

    #[test]
    fn run_routstr_rbf_parse_rejects_zero_fee_and_zero_vbytes() {
        use grok_bitcoin_wallet::funding_cli::{RbfReplaceParseError, parse_rbf_replace_request};
        let input = format!("{}:0:100000:bc1qrecv", "ab".repeat(32));
        let inputs = vec![input];
        assert!(matches!(
            parse_rbf_replace_request("bc1qtest", 100, 500, 141, &inputs, false, Some(0)),
            Err(RbfReplaceParseError::InvalidFeeRate(_))
        ));
        assert_eq!(
            parse_rbf_replace_request("bc1qtest", 100, 500, 0, &inputs, false, Some(10)),
            Err(RbfReplaceParseError::ZeroOriginalVbytes)
        );
        assert_eq!(
            parse_rbf_replace_request("bc1qtest", 0, 500, 141, &inputs, false, None),
            Err(RbfReplaceParseError::ZeroAmount)
        );
        assert_eq!(
            parse_rbf_replace_request("bc1qtest", 100, 500, 141, &[], false, None),
            Err(RbfReplaceParseError::MissingInputs)
        );
        let req =
            parse_rbf_replace_request("bc1qtest", 100, 705, 141, &inputs, false, None).unwrap();
        assert!(!req.fee_rate_explicit);
        assert!(!req.broadcast);
        assert_eq!(req.inputs.len(), 1);
        let req =
            parse_rbf_replace_request("bc1qtest", 100, 705, 141, &inputs, true, Some(12)).unwrap();
        assert!(req.fee_rate_explicit);
        assert!(req.broadcast);
        assert_eq!(req.fee_rate_sat_vb, 12);
        assert_eq!(req.original_fee_sats, 705);
        assert_eq!(req.original_vbytes, 141);
    }

    #[test]
    fn rbf_broadcast_claim_helper_matches_product_gate() {
        use grok_bitcoin_wallet::funding_cli::spend_broadcast_claimed_txid;
        let txid = "cd".repeat(32);
        assert!(spend_broadcast_claimed_txid(true, Some(&txid)).is_some());
        assert!(spend_broadcast_claimed_txid(false, Some(&txid)).is_none());
        assert!(spend_broadcast_claimed_txid(true, Some("bad")).is_none());
    }

    #[test]
    fn run_routstr_cpfp_parse_rejects_zero_fee_and_zero_vbytes() {
        use grok_bitcoin_wallet::funding_cli::{CpfpChildParseError, parse_cpfp_child_request};
        let parent = format!("{}:1:80000:bc1qchange", "ab".repeat(32));
        let parents = vec![parent];
        assert!(matches!(
            parse_cpfp_child_request("bc1qtest", 100, 200, 200, &parents, &[], false, Some(0)),
            Err(CpfpChildParseError::InvalidFeeRate(_))
        ));
        assert_eq!(
            parse_cpfp_child_request("bc1qtest", 100, 200, 0, &parents, &[], false, Some(10)),
            Err(CpfpChildParseError::ZeroParentVbytes)
        );
        assert_eq!(
            parse_cpfp_child_request("bc1qtest", 0, 200, 200, &parents, &[], false, None),
            Err(CpfpChildParseError::ZeroAmount)
        );
        assert_eq!(
            parse_cpfp_child_request("bc1qtest", 100, 200, 200, &[], &[], false, None),
            Err(CpfpChildParseError::MissingParents)
        );
        let req = parse_cpfp_child_request("bc1qtest", 100, 200, 200, &parents, &[], false, None)
            .unwrap();
        assert!(!req.fee_rate_explicit);
        assert!(!req.broadcast);
        assert_eq!(req.parents.len(), 1);
        let req =
            parse_cpfp_child_request("bc1qtest", 100, 200, 200, &parents, &[], true, Some(12))
                .unwrap();
        assert!(req.fee_rate_explicit);
        assert!(req.broadcast);
        assert_eq!(req.fee_rate_sat_vb, 12);
        assert_eq!(req.parent_fee_sats, 200);
        assert_eq!(req.parent_vbytes, 200);
    }
}
