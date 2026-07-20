//! Product selection of live [`ChainSource`](crate::descriptor_wallet::ChainSource)
//! and [`TxBroadcaster`](crate::explorer::TxBroadcaster) backends.
//!
//! Pure parse/config helpers are always available with `onchain-address`. Opening a live
//! backend requires the matching feature (`explorer-http` / `esplora` / `electrum`) and
//! returns a **structured error** when the feature is not compiled in (never hangs on
//! network for a missing feature).
//!
//! ## Environment
//!
//! | Env | Role |
//! |-----|------|
//! | [`CHAIN_SOURCE_ENV`] (`GROK_BITCOIN_CHAIN_SOURCE`) | `mempool` \| `esplora` \| `electrum` (case-insensitive; empty/unset → mempool) |
//! | [`ESPLORA_URL_ENV`] (`GROK_BITCOIN_ESPLORA_URL`) | Esplora REST base URL when kind is esplora (required) |
//! | [`ELECTRUM_ADDR_ENV`] (`GROK_BITCOIN_ELECTRUM_ADDR`) | `host:port` or `ssl://host:port` when kind is electrum (required) |
//! | [`ELECTRUM_TLS_ENV`] (`GROK_BITCOIN_ELECTRUM_TLS`) | `1`/`true`/`yes` enables TLS for bare `host:port` (default off = plaintext) |
//!
//! Default product behavior is **mempool** (unchanged when env is unset). UTXO list and
//! `--broadcast` share this config so spend uses a matching push path when features
//! are compiled in (mempool `POST /api/tx`, Esplora `POST /tx`, Electrum
//! `blockchain.transaction.broadcast`). Electrum default transport is **plaintext TCP**
//! (local/regtest); TLS is opt-in via env or `ssl://` scheme.

use crate::address_ux::BitcoinNetwork;
use crate::descriptor_wallet::ChainSource;
use crate::error::{Result, WalletError};
use crate::explorer::TxBroadcaster;

/// `GROK_BITCOIN_CHAIN_SOURCE` — product UTXO list backend name.
pub const CHAIN_SOURCE_ENV: &str = "GROK_BITCOIN_CHAIN_SOURCE";

/// `GROK_BITCOIN_ESPLORA_URL` — Esplora REST API base (e.g. `https://blockstream.info/api`).
pub const ESPLORA_URL_ENV: &str = "GROK_BITCOIN_ESPLORA_URL";

/// `GROK_BITCOIN_ELECTRUM_ADDR` — Electrum `host:port` or `ssl://host:port`.
pub const ELECTRUM_ADDR_ENV: &str = "GROK_BITCOIN_ELECTRUM_ADDR";

/// `GROK_BITCOIN_ELECTRUM_TLS` — enable TLS for bare Electrum `host:port`
/// (`1` / `true` / `yes`, case-insensitive). Default unset/false = plaintext TCP.
/// `ssl://` in [`ELECTRUM_ADDR_ENV`] always forces TLS regardless of this flag.
pub const ELECTRUM_TLS_ENV: &str = "GROK_BITCOIN_ELECTRUM_TLS";

/// Named product chain backends for UTXO discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSourceKind {
    /// mempool.space address UTXO REST (feature `explorer-http`).
    Mempool,
    /// Esplora-compatible REST (feature `esplora`).
    Esplora,
    /// Electrum JSON-RPC (feature `electrum`; plaintext TCP or TLS).
    Electrum,
}

impl ChainSourceKind {
    /// Canonical lowercase wire / env name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mempool => "mempool",
            Self::Esplora => "esplora",
            Self::Electrum => "electrum",
        }
    }
}

/// Pure product chain config (no I/O). Open via [`open_product_chain_source`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductChainSourceConfig {
    pub kind: ChainSourceKind,
    /// Set when [`ChainSourceKind::Esplora`]; ignored for other kinds.
    pub esplora_url: Option<String>,
    /// Set when [`ChainSourceKind::Electrum`]; stripped `host:port` / `[ipv6]:port`
    /// (no scheme). Ignored for other kinds.
    pub electrum_addr: Option<String>,
    /// When kind is Electrum: use TLS (rustls) instead of plaintext TCP.
    /// Set by [`ELECTRUM_TLS_ENV`] and/or `ssl://` scheme on the addr.
    pub electrum_tls: bool,
}

impl ProductChainSourceConfig {
    /// Mempool default (no extra env required).
    pub fn mempool() -> Self {
        Self {
            kind: ChainSourceKind::Mempool,
            esplora_url: None,
            electrum_addr: None,
            electrum_tls: false,
        }
    }
}

/// Parse a chain-source name. Empty / whitespace → [`ChainSourceKind::Mempool`].
///
/// Case-insensitive: `mempool`, `esplora`, `electrum`. Unknown values error
/// (no silent fallback).
pub fn parse_chain_source_kind(s: &str) -> Result<ChainSourceKind> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(ChainSourceKind::Mempool);
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "mempool" => Ok(ChainSourceKind::Mempool),
        "esplora" => Ok(ChainSourceKind::Esplora),
        "electrum" => Ok(ChainSourceKind::Electrum),
        other => Err(WalletError::Explorer(format!(
            "unknown {CHAIN_SOURCE_ENV} value {other:?}; use mempool, esplora, or electrum \
             (empty/unset defaults to mempool)"
        ))),
    }
}

/// Build pure config from explicit parts (no process env read).
///
/// - `kind_raw`: `None` or empty → mempool; otherwise [`parse_chain_source_kind`]
/// - When kind is esplora, `esplora_url` must be non-empty after trim and use
///   `http://` or `https://` (no DNS; offline shape check only)
/// - When kind is electrum, `electrum_addr` must be non-empty after trim:
///   bare `host:port` / `[ipv6]:port` (plaintext unless `electrum_tls_flag`), or
///   `ssl://host:port` (forces TLS; scheme stripped in stored addr)
///
/// Does **not** check compile-time features (see [`open_product_chain_source`]).
/// Prefer [`product_chain_source_config_with_electrum_tls`] when the TLS env flag
/// is available; this 3-arg form defaults the TLS flag to **false** (plaintext)
/// unless the addr uses `ssl://`.
pub fn product_chain_source_config(
    kind_raw: Option<&str>,
    esplora_url: Option<&str>,
    electrum_addr: Option<&str>,
) -> Result<ProductChainSourceConfig> {
    product_chain_source_config_with_electrum_tls(kind_raw, esplora_url, electrum_addr, false)
}

/// Like [`product_chain_source_config`] with an explicit Electrum TLS env flag.
///
/// `electrum_tls_flag` is the parsed [`ELECTRUM_TLS_ENV`] truthy value. Combined
/// with `ssl://` on the addr (`ssl://` **or** flag → TLS).
pub fn product_chain_source_config_with_electrum_tls(
    kind_raw: Option<&str>,
    esplora_url: Option<&str>,
    electrum_addr: Option<&str>,
    electrum_tls_flag: bool,
) -> Result<ProductChainSourceConfig> {
    let kind = match kind_raw {
        None => ChainSourceKind::Mempool,
        Some(s) => parse_chain_source_kind(s)?,
    };
    match kind {
        ChainSourceKind::Mempool => Ok(ProductChainSourceConfig::mempool()),
        ChainSourceKind::Esplora => {
            let url = esplora_url
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    WalletError::Explorer(format!(
                        "chain source 'esplora' requires {ESPLORA_URL_ENV} \
                         (Esplora REST base URL, e.g. https://blockstream.info/api or \
                         https://mempool.space/api)"
                    ))
                })?;
            validate_esplora_base_url(url)?;
            Ok(ProductChainSourceConfig {
                kind: ChainSourceKind::Esplora,
                esplora_url: Some(url.to_owned()),
                electrum_addr: None,
                electrum_tls: false,
            })
        }
        ChainSourceKind::Electrum => {
            let raw = electrum_addr
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    WalletError::Explorer(format!(
                        "chain source 'electrum' requires {ELECTRUM_ADDR_ENV} \
                         (host:port for Electrum JSON-RPC, or ssl://host:port for TLS; \
                         optional {ELECTRUM_TLS_ENV}=1 for TLS with bare host:port; \
                         default is plaintext TCP for local/regtest)"
                    ))
                })?;
            let (host_port, scheme_tls) = normalize_electrum_addr(raw)?;
            Ok(ProductChainSourceConfig {
                kind: ChainSourceKind::Electrum,
                esplora_url: None,
                electrum_addr: Some(host_port),
                electrum_tls: scheme_tls || electrum_tls_flag,
            })
        }
    }
}

/// Parse a truthy env flag: `1`, `true`, `yes` (case-insensitive, trimmed).
///
/// Empty / unset / anything else → `false` (no silent TLS enable).
pub fn parse_electrum_tls_flag(raw: Option<&str>) -> bool {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

/// Offline shape check: require `http://` or `https://` prefix (no DNS).
fn validate_esplora_base_url(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        // Reject bare scheme-only / empty host after scheme.
        let rest = if let Some(r) = lower.strip_prefix("https://") {
            r
        } else {
            lower.strip_prefix("http://").unwrap_or("")
        };
        if rest.is_empty() || rest.starts_with('/') {
            return Err(WalletError::Explorer(format!(
                "invalid {ESPLORA_URL_ENV} {url:?}; expected http(s) URL with a host \
                 (e.g. https://blockstream.info/api)"
            )));
        }
        return Ok(());
    }
    Err(WalletError::Explorer(format!(
        "invalid {ESPLORA_URL_ENV} {url:?}; expected http:// or https:// base URL \
         (e.g. https://blockstream.info/api)"
    )))
}

/// Normalize Electrum endpoint: strip optional `ssl://`, validate `host:port`.
///
/// Returns `(host:port, tls_forced_by_ssl_scheme)`.
///
/// - `ssl://host:port` / `SSL://…` → stripped host:port, `tls = true`
/// - bare `host:port` / `[ipv6]:port` → as-is, `tls = false` (caller ORs env flag)
/// - other schemes (`tcp://`, `https://`, …) → hard error (do not silently
///   treat as plaintext while accepting a scheme that implies another transport)
pub fn normalize_electrum_addr(addr: &str) -> Result<(String, bool)> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Explorer(format!(
            "invalid {ELECTRUM_ADDR_ENV} {addr:?}; expected host:port or ssl://host:port"
        )));
    }

    let (without_scheme, scheme_tls) = if let Some(rest) = strip_prefix_ci(trimmed, "ssl://") {
        if rest.is_empty() {
            return Err(WalletError::Explorer(format!(
                "invalid {ELECTRUM_ADDR_ENV} {addr:?}; ssl:// requires host:port \
                 (e.g. ssl://electrum.example:50002)"
            )));
        }
        (rest, true)
    } else if trimmed.contains("://") {
        return Err(WalletError::Explorer(format!(
            "invalid {ELECTRUM_ADDR_ENV} {addr:?}; unsupported URI scheme — use host:port \
             (plaintext TCP) or ssl://host:port (TLS). Other schemes (tcp://, https://, …) \
             are rejected"
        )));
    } else {
        (trimmed, false)
    };

    validate_electrum_host_port(without_scheme)?;
    Ok((without_scheme.to_owned(), scheme_tls))
}

/// Case-insensitive prefix strip. Returns the remainder with original casing.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    if s.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Offline shape check for Electrum `host:port` or `[ipv6]:port` (**no** URI scheme).
///
/// Callers that accept `ssl://` must strip via [`normalize_electrum_addr`] first.
fn validate_electrum_host_port(addr: &str) -> Result<()> {
    if addr.contains("://") {
        return Err(WalletError::Explorer(format!(
            "invalid {ELECTRUM_ADDR_ENV} {addr:?}; URI schemes must be handled by \
             normalize_electrum_addr (ssl:// only); use host:port or [ipv6]:port"
        )));
    }

    let (host, port_s) = if let Some(rest) = addr.strip_prefix('[') {
        // Bracketed IPv6: [::1]:50001
        let Some((host, port_s)) = rest.split_once("]:") else {
            return Err(WalletError::Explorer(format!(
                "invalid {ELECTRUM_ADDR_ENV} {addr:?}; expected [ipv6]:port \
                 (e.g. [::1]:50001)"
            )));
        };
        if host.is_empty() {
            return Err(WalletError::Explorer(format!(
                "invalid {ELECTRUM_ADDR_ENV} {addr:?}; empty IPv6 host in [ipv6]:port"
            )));
        }
        (host, port_s)
    } else {
        // host:port — exactly one colon separating host and numeric port.
        let Some((host, port_s)) = addr.split_once(':') else {
            return Err(WalletError::Explorer(format!(
                "invalid {ELECTRUM_ADDR_ENV} {addr:?}; expected host:port \
                 (e.g. 127.0.0.1:50001) or ssl://host:port for TLS"
            )));
        };
        if host.is_empty() || host.contains(':') || port_s.contains(':') {
            return Err(WalletError::Explorer(format!(
                "invalid {ELECTRUM_ADDR_ENV} {addr:?}; expected a single host:port \
                 (use [ipv6]:port for IPv6)"
            )));
        }
        (host, port_s)
    };

    if port_s.is_empty() || !port_s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WalletError::Explorer(format!(
            "invalid {ELECTRUM_ADDR_ENV} {addr:?}; port must be a positive integer \
             (e.g. 50001)"
        )));
    }
    let port: u16 = port_s.parse().map_err(|_| {
        WalletError::Explorer(format!(
            "invalid {ELECTRUM_ADDR_ENV} {addr:?}; port out of range 1–65535"
        ))
    })?;
    if port == 0 {
        return Err(WalletError::Explorer(format!(
            "invalid {ELECTRUM_ADDR_ENV} {addr:?}; port must be 1–65535"
        )));
    }
    let _ = host; // host non-empty checked above for both branches
    Ok(())
}

/// Honest product notice when UTXO list and broadcast backends diverge.
///
/// Empty when both kinds match (the product default: same
/// [`ProductChainSourceConfig`] for UTXO + push). When they diverge (tests or a
/// forced fallback), surfaces a clear note — never claims the wrong push was used.
pub fn broadcast_backend_notice_lines(
    utxo_kind: ChainSourceKind,
    broadcast_kind: ChainSourceKind,
) -> Vec<String> {
    if utxo_kind == broadcast_kind {
        return Vec::new();
    }
    vec![format!(
        "Note: UTXO list uses {} but --broadcast submits via {} \
         (backends diverge; never treat prepare-only as network accept).",
        utxo_kind.as_str(),
        broadcast_kind.as_str()
    )]
}

/// Deprecated: product UTXO + push are aligned (no automatic mempool-fallback gap).
///
/// Always empty. Prefer [`broadcast_backend_notice_lines`] when a caller actually
/// opens diverging backends and needs an honesty note.
#[deprecated(
    note = "product UTXO+push are aligned; use broadcast_backend_notice_lines(utxo, push) when kinds can diverge"
)]
pub fn non_mempool_broadcast_notice_lines(_kind: ChainSourceKind) -> Vec<String> {
    // Historical helper assumed "non-mempool UTXO ⇒ mempool push". That gap is
    // closed: open_product_tx_broadcaster uses the same config as UTXO. Keep the
    // symbol so older call sites compile, but never emit a false divergence note.
    Vec::new()
}

/// Read product chain config via an injectable env lookup (no network).
///
/// `get(key)` returns `None` when the variable is **unset**; `Some("")` for an
/// empty string. Unset/empty [`CHAIN_SOURCE_ENV`] → mempool. Reads
/// [`ELECTRUM_TLS_ENV`] when present. Does not read BIP-39 or passphrase env.
/// Prefer this in unit tests; production uses
/// [`product_chain_source_config_from_env`].
pub fn product_chain_source_config_from_env_reader(
    mut get: impl FnMut(&str) -> Option<String>,
) -> Result<ProductChainSourceConfig> {
    let kind = get(CHAIN_SOURCE_ENV);
    let esplora = get(ESPLORA_URL_ENV);
    let electrum = get(ELECTRUM_ADDR_ENV);
    let tls_flag = parse_electrum_tls_flag(get(ELECTRUM_TLS_ENV).as_deref());
    product_chain_source_config_with_electrum_tls(
        kind.as_deref(),
        esplora.as_deref(),
        electrum.as_deref(),
        tls_flag,
    )
}

/// Read product chain config from process env (pure parse; no network).
///
/// Unset [`CHAIN_SOURCE_ENV`] → mempool. Does not read BIP-39 or passphrase env.
pub fn product_chain_source_config_from_env() -> Result<ProductChainSourceConfig> {
    product_chain_source_config_from_env_reader(|k| std::env::var(k).ok())
}

/// Map product [`BitcoinNetwork`] to `bitcoin::Network` for Electrum address checks.
///
/// Delegates to [`crate::onchain::bitcoin_network_to_network`] so product CLI,
/// descriptors, and Electrum share one Testnet4 → Testnet mapping.
#[cfg(any(feature = "electrum", test))]
fn bitcoin_network_for_electrum(network: BitcoinNetwork) -> bitcoin::Network {
    crate::onchain::bitcoin_network_to_network(network)
}

/// Open a live [`ChainSource`] for the product spend path.
///
/// Feature honesty:
/// - `mempool` without `explorer-http` → structured error (not a network hang)
/// - `esplora` without `esplora` → structured error
/// - `electrum` without `electrum` → structured error
///
/// Re-applies offline URL / Electrum endpoint shape validation (including
/// `ssl://` normalize) so hand-built [`ProductChainSourceConfig`] values cannot
/// bypass the gates in [`product_chain_source_config`].
///
/// Does **not** invent UTXOs. Callers that need offline fixtures should inject
/// [`crate::descriptor_wallet::MockChainSource`] directly.
pub fn open_product_chain_source(
    config: &ProductChainSourceConfig,
    network: BitcoinNetwork,
) -> Result<Box<dyn ChainSource>> {
    match config.kind {
        ChainSourceKind::Mempool => open_mempool_chain_source(network),
        ChainSourceKind::Esplora => {
            let url = validated_esplora_url_from_config(config)?;
            open_esplora_chain_source(url)
        }
        ChainSourceKind::Electrum => {
            let (addr, tls) = validated_electrum_endpoint_from_config(config)?;
            open_electrum_chain_source(&addr, network, tls)
        }
    }
}

/// Convenience: [`product_chain_source_config_from_env`] + [`open_product_chain_source`].
pub fn open_product_chain_source_from_env(network: BitcoinNetwork) -> Result<Box<dyn ChainSource>> {
    let config = product_chain_source_config_from_env()?;
    open_product_chain_source(&config, network)
}

/// Same as [`open_product_chain_source_from_env`] with an injectable env reader
/// (unit tests; no process-env mutation; crate forbids `unsafe_code`).
pub fn open_product_chain_source_from_env_reader(
    network: BitcoinNetwork,
    get: impl FnMut(&str) -> Option<String>,
) -> Result<Box<dyn ChainSource>> {
    let config = product_chain_source_config_from_env_reader(get)?;
    open_product_chain_source(&config, network)
}

/// Open a live [`TxBroadcaster`] aligned with the product chain config.
///
/// Same env / feature honesty as [`open_product_chain_source`]:
/// - `mempool` without `explorer-http` → structured error
/// - `esplora` without `esplora` → structured error (not a network hang)
/// - `electrum` without `electrum` → structured error
///
/// Re-applies offline URL / `host:port` shape validation (same as chain open)
/// so hand-built configs cannot skip [`product_chain_source_config`] gates.
/// Uses the same base URL / Electrum addr as UTXO discovery. Never claims
/// broadcast success without a successful [`crate::explorer::BroadcastResult`].
pub fn open_product_tx_broadcaster(
    config: &ProductChainSourceConfig,
    network: BitcoinNetwork,
) -> Result<Box<dyn TxBroadcaster>> {
    match config.kind {
        ChainSourceKind::Mempool => open_mempool_tx_broadcaster(network),
        ChainSourceKind::Esplora => {
            let url = validated_esplora_url_from_config(config)?;
            open_esplora_tx_broadcaster(url)
        }
        ChainSourceKind::Electrum => {
            let (addr, tls) = validated_electrum_endpoint_from_config(config)?;
            open_electrum_tx_broadcaster(&addr, tls)
        }
    }
}

/// Extract + offline-shape-validate Esplora base URL from a product config.
///
/// Shared by chain open and broadcaster open so hand-built configs cannot
/// bypass [`validate_esplora_base_url`].
fn validated_esplora_url_from_config(config: &ProductChainSourceConfig) -> Result<&str> {
    let url = config
        .esplora_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WalletError::Explorer(format!(
                "chain/broadcast backend 'esplora' requires {ESPLORA_URL_ENV} \
                 (Esplora REST base URL)"
            ))
        })?;
    validate_esplora_base_url(url)?;
    Ok(url)
}

/// Extract + offline-shape-validate Electrum endpoint from a product config.
///
/// Returns `(host:port, use_tls)`. Accepts bare `host:port` or `ssl://host:port`
/// still left in hand-built configs; ORs scheme TLS with [`ProductChainSourceConfig::electrum_tls`].
/// Shared by chain open and broadcaster open.
fn validated_electrum_endpoint_from_config(
    config: &ProductChainSourceConfig,
) -> Result<(String, bool)> {
    let raw = config
        .electrum_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WalletError::Explorer(format!(
                "chain/broadcast backend 'electrum' requires {ELECTRUM_ADDR_ENV} \
                 (host:port or ssl://host:port)"
            ))
        })?;
    let (host_port, scheme_tls) = normalize_electrum_addr(raw)?;
    Ok((host_port, scheme_tls || config.electrum_tls))
}

/// Convenience: config from env + [`open_product_tx_broadcaster`].
pub fn open_product_tx_broadcaster_from_env(
    network: BitcoinNetwork,
) -> Result<Box<dyn TxBroadcaster>> {
    let config = product_chain_source_config_from_env()?;
    open_product_tx_broadcaster(&config, network)
}

/// Same as [`open_product_tx_broadcaster_from_env`] with an injectable env reader.
pub fn open_product_tx_broadcaster_from_env_reader(
    network: BitcoinNetwork,
    get: impl FnMut(&str) -> Option<String>,
) -> Result<Box<dyn TxBroadcaster>> {
    let config = product_chain_source_config_from_env_reader(get)?;
    open_product_tx_broadcaster(&config, network)
}

fn open_mempool_chain_source(network: BitcoinNetwork) -> Result<Box<dyn ChainSource>> {
    #[cfg(feature = "explorer-http")]
    {
        use crate::descriptor_wallet::MempoolChainSource;
        Ok(Box::new(MempoolChainSource::with_defaults(network)?))
    }
    #[cfg(not(feature = "explorer-http"))]
    {
        let _ = network;
        Err(WalletError::Explorer(
            "chain source 'mempool' requires feature `explorer-http` \
             (not compiled into this build; rebuild with explorer-http or select another backend)"
                .into(),
        ))
    }
}

fn open_esplora_chain_source(base_url: &str) -> Result<Box<dyn ChainSource>> {
    #[cfg(feature = "esplora")]
    {
        use crate::esplora::EsploraChainSource;
        Ok(Box::new(EsploraChainSource::with_http_base_url(base_url)?))
    }
    #[cfg(not(feature = "esplora"))]
    {
        let _ = base_url;
        Err(WalletError::Explorer(
            "chain source 'esplora' requires feature `esplora` \
             (not compiled into this build; rebuild with --features esplora, set \
             GROK_BITCOIN_ESPLORA_URL, or use GROK_BITCOIN_CHAIN_SOURCE=mempool)"
                .into(),
        ))
    }
}

fn open_electrum_chain_source(
    addr: &str,
    network: BitcoinNetwork,
    tls: bool,
) -> Result<Box<dyn ChainSource>> {
    #[cfg(feature = "electrum")]
    {
        use crate::electrum::ElectrumChainSource;
        let btc_net = bitcoin_network_for_electrum(network);
        if tls {
            Ok(Box::new(ElectrumChainSource::with_tls(addr, btc_net)))
        } else {
            Ok(Box::new(ElectrumChainSource::with_tcp(addr, btc_net)))
        }
    }
    #[cfg(not(feature = "electrum"))]
    {
        let _ = (addr, network, tls);
        Err(WalletError::Explorer(
            "chain source 'electrum' requires feature `electrum` \
             (not compiled into this build; rebuild with --features electrum, set \
             GROK_BITCOIN_ELECTRUM_ADDR [and optional GROK_BITCOIN_ELECTRUM_TLS=1 or \
             ssl://host:port for TLS], or use GROK_BITCOIN_CHAIN_SOURCE=mempool)"
                .into(),
        ))
    }
}

fn open_mempool_tx_broadcaster(network: BitcoinNetwork) -> Result<Box<dyn TxBroadcaster>> {
    #[cfg(feature = "explorer-http")]
    {
        use crate::explorer::MempoolHttpClient;
        Ok(Box::new(MempoolHttpClient::with_defaults(network)?))
    }
    #[cfg(not(feature = "explorer-http"))]
    {
        let _ = network;
        Err(WalletError::Explorer(
            "broadcast backend 'mempool' requires feature `explorer-http` \
             (not compiled into this build; rebuild with explorer-http or select another backend)"
                .into(),
        ))
    }
}

fn open_esplora_tx_broadcaster(base_url: &str) -> Result<Box<dyn TxBroadcaster>> {
    #[cfg(feature = "esplora")]
    {
        use crate::esplora::EsploraTxBroadcaster;
        Ok(Box::new(EsploraTxBroadcaster::with_http_base_url(
            base_url,
        )?))
    }
    #[cfg(not(feature = "esplora"))]
    {
        let _ = base_url;
        Err(WalletError::Explorer(
            "broadcast backend 'esplora' requires feature `esplora` \
             (not compiled into this build; rebuild with --features esplora, set \
             GROK_BITCOIN_ESPLORA_URL, or use GROK_BITCOIN_CHAIN_SOURCE=mempool)"
                .into(),
        ))
    }
}

fn open_electrum_tx_broadcaster(addr: &str, tls: bool) -> Result<Box<dyn TxBroadcaster>> {
    #[cfg(feature = "electrum")]
    {
        use crate::electrum::ElectrumTxBroadcaster;
        if tls {
            Ok(Box::new(ElectrumTxBroadcaster::with_tls(addr)))
        } else {
            Ok(Box::new(ElectrumTxBroadcaster::with_tcp(addr)))
        }
    }
    #[cfg(not(feature = "electrum"))]
    {
        let _ = (addr, tls);
        Err(WalletError::Explorer(
            "broadcast backend 'electrum' requires feature `electrum` \
             (not compiled into this build; rebuild with --features electrum, set \
             GROK_BITCOIN_ELECTRUM_ADDR [and optional GROK_BITCOIN_ELECTRUM_TLS=1 or \
             ssl://host:port for TLS], or use GROK_BITCOIN_CHAIN_SOURCE=mempool)"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kind_empty_and_default_mempool() {
        assert_eq!(
            parse_chain_source_kind("").unwrap(),
            ChainSourceKind::Mempool
        );
        assert_eq!(
            parse_chain_source_kind("   ").unwrap(),
            ChainSourceKind::Mempool
        );
        assert_eq!(
            parse_chain_source_kind("mempool").unwrap(),
            ChainSourceKind::Mempool
        );
        assert_eq!(
            parse_chain_source_kind("MEMPOOL").unwrap(),
            ChainSourceKind::Mempool
        );
    }

    #[test]
    fn parse_kind_esplora_electrum_case_insensitive() {
        assert_eq!(
            parse_chain_source_kind("Esplora").unwrap(),
            ChainSourceKind::Esplora
        );
        assert_eq!(
            parse_chain_source_kind("ELECTRUM").unwrap(),
            ChainSourceKind::Electrum
        );
        assert_eq!(ChainSourceKind::Esplora.as_str(), "esplora");
        assert_eq!(ChainSourceKind::Electrum.as_str(), "electrum");
    }

    #[test]
    fn parse_kind_unknown_errors() {
        let err = parse_chain_source_kind("blockstream")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown") && err.contains(CHAIN_SOURCE_ENV),
            "err={err}"
        );
        assert!(err.contains("mempool") && err.contains("esplora") && err.contains("electrum"));
    }

    #[test]
    fn config_default_none_is_mempool() {
        let cfg = product_chain_source_config(None, None, None).unwrap();
        assert_eq!(cfg, ProductChainSourceConfig::mempool());
        assert_eq!(cfg.kind, ChainSourceKind::Mempool);
        assert!(cfg.esplora_url.is_none());
        assert!(cfg.electrum_addr.is_none());
    }

    #[test]
    fn config_empty_kind_string_is_mempool() {
        let cfg =
            product_chain_source_config(Some(""), Some("https://ignored"), Some("x:1")).unwrap();
        assert_eq!(cfg.kind, ChainSourceKind::Mempool);
        // Extra env for other backends is ignored when kind is mempool.
        assert!(cfg.esplora_url.is_none());
        assert!(cfg.electrum_addr.is_none());
    }

    #[test]
    fn config_esplora_requires_url() {
        let err = product_chain_source_config(Some("esplora"), None, None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("esplora") && err.contains(ESPLORA_URL_ENV),
            "err={err}"
        );

        let err_empty = product_chain_source_config(Some("esplora"), Some("  "), None)
            .unwrap_err()
            .to_string();
        assert!(err_empty.contains(ESPLORA_URL_ENV), "err={err_empty}");
    }

    #[test]
    fn config_esplora_accepts_url() {
        let cfg = product_chain_source_config(
            Some("esplora"),
            Some(" https://blockstream.info/api "),
            None,
        )
        .unwrap();
        assert_eq!(cfg.kind, ChainSourceKind::Esplora);
        assert_eq!(
            cfg.esplora_url.as_deref(),
            Some("https://blockstream.info/api")
        );
        assert!(cfg.electrum_addr.is_none());

        let http =
            product_chain_source_config(Some("esplora"), Some("http://127.0.0.1:3000"), None)
                .unwrap();
        assert_eq!(http.esplora_url.as_deref(), Some("http://127.0.0.1:3000"));
    }

    #[test]
    fn config_esplora_rejects_non_http_scheme() {
        for bad in [
            "htps://blockstream.info/api",
            "blockstream.info/api",
            "ftp://example.com/api",
            "https://",
            "http://",
        ] {
            let err = product_chain_source_config(Some("esplora"), Some(bad), None)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(ESPLORA_URL_ENV) && err.contains("http"),
                "bad={bad:?} err={err}"
            );
        }
    }

    #[test]
    fn config_electrum_requires_addr() {
        let err = product_chain_source_config(Some("electrum"), None, None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("electrum") && err.contains(ELECTRUM_ADDR_ENV),
            "err={err}"
        );

        let err_empty = product_chain_source_config(Some("electrum"), None, Some(""))
            .unwrap_err()
            .to_string();
        assert!(err_empty.contains(ELECTRUM_ADDR_ENV), "err={err_empty}");
    }

    #[test]
    fn config_electrum_rejects_bad_host_port_shape() {
        for bad in [
            "nosuchport",
            ":50001",
            "127.0.0.1:",
            "  ",
            "tcp://host:50001",
            "https://host:50001",
            "ssl://",
            "host:port:extra",
            "127.0.0.1:0",
            "127.0.0.1:abc",
            "[]:50001",
            "[::1]",
            "[::1]:",
        ] {
            let err = product_chain_source_config(Some("electrum"), None, Some(bad))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(ELECTRUM_ADDR_ENV) || err.contains("electrum"),
                "bad={bad:?} err={err}"
            );
        }
        // Non-ssl schemes must stay rejected (no silent plaintext for tcp://).
        let tcp_err =
            product_chain_source_config(Some("electrum"), None, Some("tcp://127.0.0.1:50001"))
                .unwrap_err()
                .to_string();
        assert!(
            tcp_err.contains("unsupported") || tcp_err.contains("scheme"),
            "tcp_err={tcp_err}"
        );
    }

    #[test]
    fn config_electrum_accepts_host_port() {
        let cfg =
            product_chain_source_config(Some("electrum"), None, Some(" 127.0.0.1:50001 ")).unwrap();
        assert_eq!(cfg.kind, ChainSourceKind::Electrum);
        assert_eq!(cfg.electrum_addr.as_deref(), Some("127.0.0.1:50001"));
        assert!(!cfg.electrum_tls, "bare host:port defaults to plaintext");
        assert!(cfg.esplora_url.is_none());

        let v6 = product_chain_source_config(Some("electrum"), None, Some("[::1]:50001")).unwrap();
        assert_eq!(v6.electrum_addr.as_deref(), Some("[::1]:50001"));
        assert!(!v6.electrum_tls);
    }

    #[test]
    fn config_electrum_ssl_scheme_forces_tls_and_strips() {
        let cfg = product_chain_source_config(
            Some("electrum"),
            None,
            Some("ssl://electrum.example:50002"),
        )
        .unwrap();
        assert_eq!(cfg.electrum_addr.as_deref(), Some("electrum.example:50002"));
        assert!(cfg.electrum_tls, "ssl:// must force TLS");

        let upper =
            product_chain_source_config(Some("electrum"), None, Some("SSL://127.0.0.1:50002"))
                .unwrap();
        assert_eq!(upper.electrum_addr.as_deref(), Some("127.0.0.1:50002"));
        assert!(upper.electrum_tls);

        // Flag alone enables TLS for bare host:port.
        let flagged = product_chain_source_config_with_electrum_tls(
            Some("electrum"),
            None,
            Some("fulcrum.example:50002"),
            true,
        )
        .unwrap();
        assert_eq!(
            flagged.electrum_addr.as_deref(),
            Some("fulcrum.example:50002")
        );
        assert!(flagged.electrum_tls);

        // Flag false + bare host → plaintext.
        let plain = product_chain_source_config_with_electrum_tls(
            Some("electrum"),
            None,
            Some("127.0.0.1:50001"),
            false,
        )
        .unwrap();
        assert!(!plain.electrum_tls);
    }

    #[test]
    fn parse_electrum_tls_flag_truthy_and_falsey() {
        assert!(!parse_electrum_tls_flag(None));
        assert!(!parse_electrum_tls_flag(Some("")));
        assert!(!parse_electrum_tls_flag(Some("  ")));
        assert!(!parse_electrum_tls_flag(Some("0")));
        assert!(!parse_electrum_tls_flag(Some("false")));
        assert!(!parse_electrum_tls_flag(Some("no")));
        assert!(!parse_electrum_tls_flag(Some("maybe")));
        assert!(parse_electrum_tls_flag(Some("1")));
        assert!(parse_electrum_tls_flag(Some("true")));
        assert!(parse_electrum_tls_flag(Some("YES")));
        assert!(parse_electrum_tls_flag(Some(" True ")));
    }

    #[test]
    fn env_reader_electrum_tls_flag_and_ssl_scheme() {
        let cfg = product_chain_source_config_from_env_reader(|k| match k {
            CHAIN_SOURCE_ENV => Some("electrum".into()),
            ELECTRUM_ADDR_ENV => Some("electrum.example:50002".into()),
            ELECTRUM_TLS_ENV => Some("yes".into()),
            _ => None,
        })
        .unwrap();
        assert!(cfg.electrum_tls);
        assert_eq!(cfg.electrum_addr.as_deref(), Some("electrum.example:50002"));

        let ssl_cfg = product_chain_source_config_from_env_reader(|k| match k {
            CHAIN_SOURCE_ENV => Some("electrum".into()),
            ELECTRUM_ADDR_ENV => Some("ssl://electrum.example:50002".into()),
            // Flag off must not cancel ssl://.
            ELECTRUM_TLS_ENV => Some("0".into()),
            _ => None,
        })
        .unwrap();
        assert!(ssl_cfg.electrum_tls);
        assert_eq!(
            ssl_cfg.electrum_addr.as_deref(),
            Some("electrum.example:50002")
        );

        let plain = product_chain_source_config_from_env_reader(|k| match k {
            CHAIN_SOURCE_ENV => Some("electrum".into()),
            ELECTRUM_ADDR_ENV => Some("127.0.0.1:50001".into()),
            _ => None,
        })
        .unwrap();
        assert!(!plain.electrum_tls);
    }

    #[test]
    fn normalize_electrum_addr_ssl_and_bare() {
        let (hp, tls) = normalize_electrum_addr("ssl://h.example:50002").unwrap();
        assert_eq!(hp, "h.example:50002");
        assert!(tls);
        let (hp2, tls2) = normalize_electrum_addr("127.0.0.1:50001").unwrap();
        assert_eq!(hp2, "127.0.0.1:50001");
        assert!(!tls2);
        assert!(normalize_electrum_addr("tcp://x:1").is_err());
        assert!(normalize_electrum_addr("ssl://").is_err());
    }

    #[test]
    fn normalize_electrum_addr_ssl_bracketed_ipv6() {
        // Product IPv6 + TLS shape: ssl://[::1]:port → stripped host:port + tls.
        let (hp, tls) = normalize_electrum_addr("ssl://[::1]:50002").unwrap();
        assert_eq!(hp, "[::1]:50002");
        assert!(tls);
        let cfg =
            product_chain_source_config(Some("electrum"), None, Some("ssl://[2001:db8::1]:50002"))
                .unwrap();
        assert_eq!(cfg.electrum_addr.as_deref(), Some("[2001:db8::1]:50002"));
        assert!(cfg.electrum_tls);
        let bare_v6 =
            product_chain_source_config(Some("electrum"), None, Some("[::1]:50001")).unwrap();
        assert_eq!(bare_v6.electrum_addr.as_deref(), Some("[::1]:50001"));
        assert!(!bare_v6.electrum_tls);
    }

    #[test]
    fn broadcast_backend_notice_empty_when_kinds_match() {
        assert!(
            broadcast_backend_notice_lines(ChainSourceKind::Mempool, ChainSourceKind::Mempool)
                .is_empty()
        );
        assert!(
            broadcast_backend_notice_lines(ChainSourceKind::Esplora, ChainSourceKind::Esplora)
                .is_empty()
        );
        assert!(
            broadcast_backend_notice_lines(ChainSourceKind::Electrum, ChainSourceKind::Electrum)
                .is_empty()
        );
    }

    #[test]
    fn broadcast_backend_notice_when_kinds_diverge() {
        let e = broadcast_backend_notice_lines(ChainSourceKind::Esplora, ChainSourceKind::Mempool);
        assert_eq!(e.len(), 1);
        assert!(e[0].contains("esplora") && e[0].contains("mempool"));
        assert!(!e[0].to_ascii_lowercase().contains("broadcast accepted"));
        let el =
            broadcast_backend_notice_lines(ChainSourceKind::Electrum, ChainSourceKind::Mempool);
        assert!(el[0].contains("electrum") && el[0].contains("mempool"));
    }

    #[test]
    #[allow(deprecated)]
    fn non_mempool_broadcast_notice_always_empty_after_aligned_push() {
        // Deprecated helper must not emit a false "mempool push gap" notice:
        // product UTXO + push are aligned.
        assert!(non_mempool_broadcast_notice_lines(ChainSourceKind::Mempool).is_empty());
        assert!(non_mempool_broadcast_notice_lines(ChainSourceKind::Esplora).is_empty());
        assert!(non_mempool_broadcast_notice_lines(ChainSourceKind::Electrum).is_empty());
        // Real divergence still documented via the two-arg helper.
        let diverge =
            broadcast_backend_notice_lines(ChainSourceKind::Esplora, ChainSourceKind::Mempool);
        assert_eq!(diverge.len(), 1);
        assert!(diverge[0].contains("esplora") && diverge[0].contains("mempool"));
    }

    #[test]
    fn open_rejects_hand_built_bad_esplora_url_before_feature_or_network() {
        // Public fields allow hand-built configs; open must re-validate shape.
        let bad = ProductChainSourceConfig {
            kind: ChainSourceKind::Esplora,
            esplora_url: Some("ssl://not-http.example/api".into()),
            electrum_addr: None,
            electrum_tls: false,
        };
        let chain_err =
            open_as_err_string(open_product_chain_source(&bad, BitcoinNetwork::Mainnet))
                .expect_err("hand-built bad esplora URL must fail at open");
        assert!(
            chain_err.contains(ESPLORA_URL_ENV) || chain_err.contains("http"),
            "chain_err={chain_err}"
        );
        assert!(
            !chain_err.to_ascii_lowercase().contains("timeout"),
            "{chain_err}"
        );

        let bc_err =
            open_bc_as_err_string(open_product_tx_broadcaster(&bad, BitcoinNetwork::Mainnet))
                .expect_err("hand-built bad esplora URL must fail at broadcaster open");
        assert!(
            bc_err.contains(ESPLORA_URL_ENV) || bc_err.contains("http"),
            "bc_err={bc_err}"
        );
    }

    #[test]
    fn open_rejects_hand_built_tcp_scheme_electrum_addr() {
        // tcp:// is not a real transport selector — must fail (not silent plaintext).
        let bad = ProductChainSourceConfig {
            kind: ChainSourceKind::Electrum,
            esplora_url: None,
            electrum_addr: Some("tcp://127.0.0.1:50001".into()),
            electrum_tls: false,
        };
        let chain_err =
            open_as_err_string(open_product_chain_source(&bad, BitcoinNetwork::Mainnet))
                .expect_err("tcp:// must fail shape gate at open");
        assert!(
            chain_err.contains("scheme")
                || chain_err.contains("unsupported")
                || chain_err.contains(ELECTRUM_ADDR_ENV),
            "chain_err={chain_err}"
        );
        assert!(
            !chain_err.to_ascii_lowercase().contains("timeout"),
            "{chain_err}"
        );

        let bc_err =
            open_bc_as_err_string(open_product_tx_broadcaster(&bad, BitcoinNetwork::Mainnet))
                .expect_err("tcp:// must fail shape gate at broadcaster open");
        assert!(
            bc_err.contains("scheme")
                || bc_err.contains("unsupported")
                || bc_err.contains(ELECTRUM_ADDR_ENV),
            "bc_err={bc_err}"
        );
    }

    #[test]
    fn open_hand_built_ssl_electrum_normalizes_to_tls_path() {
        // Hand-built ssl:// must normalize (not reject) and open as TLS when feature on.
        let cfg = ProductChainSourceConfig {
            kind: ChainSourceKind::Electrum,
            esplora_url: None,
            electrum_addr: Some("ssl://electrum.example:50002".into()),
            electrum_tls: false, // scheme alone forces TLS
        };
        let result = open_as_err_string(open_product_chain_source(&cfg, BitcoinNetwork::Mainnet));
        let bc = open_bc_as_err_string(open_product_tx_broadcaster(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "electrum"))]
        {
            let err = result.expect_err("feature-missing");
            assert!(err.contains("feature `electrum`"), "err={err}");
            assert!(!err.to_ascii_lowercase().contains("timeout"), "{err}");
            let bc_err = bc.expect_err("feature-missing broadcaster");
            assert!(bc_err.contains("feature `electrum`"), "bc_err={bc_err}");
        }
        #[cfg(feature = "electrum")]
        {
            // Construction does not connect — Ok with electrum feature (TLS transport).
            assert!(
                result.is_ok(),
                "expected Ok with electrum+ssl://; {result:?}"
            );
            assert!(
                bc.is_ok(),
                "expected Ok broadcaster with electrum+ssl://; {bc:?}"
            );
        }
    }

    #[test]
    fn open_electrum_tls_flag_construction_when_feature_on() {
        let cfg = product_chain_source_config_with_electrum_tls(
            Some("electrum"),
            None,
            Some("electrum.example:50002"),
            true,
        )
        .unwrap();
        assert!(cfg.electrum_tls);
        let result = open_as_err_string(open_product_chain_source(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "electrum"))]
        {
            let err = result.expect_err("feature-missing");
            assert!(err.contains("feature `electrum`"), "err={err}");
            // Honest feature-missing — not a network/key failure.
            assert!(!err.to_ascii_lowercase().contains("timeout"), "{err}");
            assert!(!err.to_ascii_lowercase().contains("certificate"), "{err}");
        }
        #[cfg(feature = "electrum")]
        {
            assert!(result.is_ok(), "TLS flag path constructs without network");
        }
    }

    #[test]
    fn env_const_names_match_product_contract() {
        assert_eq!(CHAIN_SOURCE_ENV, "GROK_BITCOIN_CHAIN_SOURCE");
        assert_eq!(ESPLORA_URL_ENV, "GROK_BITCOIN_ESPLORA_URL");
        assert_eq!(ELECTRUM_ADDR_ENV, "GROK_BITCOIN_ELECTRUM_ADDR");
        assert_eq!(ELECTRUM_TLS_ENV, "GROK_BITCOIN_ELECTRUM_TLS");
    }

    /// `Box<dyn ChainSource>` is not Debug — extract errors without `unwrap_err`.
    fn open_as_err_string(result: Result<Box<dyn ChainSource>>) -> std::result::Result<(), String> {
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn open_esplora_without_feature_is_structured_error() {
        let cfg = product_chain_source_config(
            Some("esplora"),
            Some("https://blockstream.info/api"),
            None,
        )
        .unwrap();
        let result = open_as_err_string(open_product_chain_source(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "esplora"))]
        {
            let err = result.expect_err("expected feature-missing error");
            assert!(err.contains("feature `esplora`"), "err={err}");
            assert!(err.contains("not compiled"), "err={err}");
            // Must not look like a network failure.
            assert!(!err.to_ascii_lowercase().contains("timeout"), "err={err}");
            assert!(
                !err.to_ascii_lowercase().contains("connection refused"),
                "err={err}"
            );
        }
        #[cfg(feature = "esplora")]
        {
            // With feature on, construction succeeds without connecting (HTTP client only).
            assert!(result.is_ok(), "expected Ok with esplora feature");
        }
    }

    #[test]
    fn open_electrum_without_feature_is_structured_error() {
        let cfg =
            product_chain_source_config(Some("electrum"), None, Some("127.0.0.1:50001")).unwrap();
        let result = open_as_err_string(open_product_chain_source(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "electrum"))]
        {
            let err = result.expect_err("expected feature-missing error");
            assert!(err.contains("feature `electrum`"), "err={err}");
            assert!(err.contains("not compiled"), "err={err}");
            assert!(!err.to_ascii_lowercase().contains("timeout"), "err={err}");
        }
        #[cfg(feature = "electrum")]
        {
            // with_tcp does not connect until list_unspent — construction is Ok.
            assert!(result.is_ok(), "expected Ok with electrum feature");
        }
    }

    #[test]
    fn open_mempool_feature_honesty() {
        let cfg = ProductChainSourceConfig::mempool();
        let result = open_as_err_string(open_product_chain_source(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "explorer-http"))]
        {
            let err = result.expect_err("expected feature-missing error");
            assert!(err.contains("feature `explorer-http`"), "err={err}");
            assert!(err.contains("not compiled"), "err={err}");
        }
        #[cfg(feature = "explorer-http")]
        {
            // with_defaults builds HTTP client only (no UTXO fetch yet).
            assert!(result.is_ok(), "expected Ok with explorer-http");
        }
    }

    /// `Box<dyn TxBroadcaster>` is not Debug — extract errors without `unwrap_err`.
    fn open_bc_as_err_string(
        result: Result<Box<dyn TxBroadcaster>>,
    ) -> std::result::Result<(), String> {
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn open_broadcaster_esplora_without_feature_is_structured_error() {
        let cfg = product_chain_source_config(
            Some("esplora"),
            Some("https://blockstream.info/api"),
            None,
        )
        .unwrap();
        let result =
            open_bc_as_err_string(open_product_tx_broadcaster(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "esplora"))]
        {
            let err = result.expect_err("expected feature-missing error");
            assert!(
                err.contains("feature `esplora`") || err.contains("broadcast backend 'esplora'"),
                "err={err}"
            );
            assert!(err.contains("not compiled"), "err={err}");
            assert!(!err.to_ascii_lowercase().contains("timeout"), "err={err}");
            assert!(
                !err.to_ascii_lowercase().contains("connection refused"),
                "err={err}"
            );
        }
        #[cfg(feature = "esplora")]
        {
            assert!(result.is_ok(), "expected Ok with esplora feature");
        }
    }

    #[test]
    fn open_broadcaster_electrum_without_feature_is_structured_error() {
        let cfg =
            product_chain_source_config(Some("electrum"), None, Some("127.0.0.1:50001")).unwrap();
        let result =
            open_bc_as_err_string(open_product_tx_broadcaster(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "electrum"))]
        {
            let err = result.expect_err("expected feature-missing error");
            assert!(
                err.contains("feature `electrum`") || err.contains("broadcast backend 'electrum'"),
                "err={err}"
            );
            assert!(err.contains("not compiled"), "err={err}");
            assert!(!err.to_ascii_lowercase().contains("timeout"), "err={err}");
        }
        #[cfg(feature = "electrum")]
        {
            // with_tcp does not connect until broadcast — construction is Ok.
            assert!(result.is_ok(), "expected Ok with electrum feature");
        }
    }

    #[test]
    fn open_broadcaster_mempool_feature_honesty() {
        let cfg = ProductChainSourceConfig::mempool();
        let result =
            open_bc_as_err_string(open_product_tx_broadcaster(&cfg, BitcoinNetwork::Mainnet));
        #[cfg(not(feature = "explorer-http"))]
        {
            let err = result.expect_err("expected feature-missing error");
            assert!(err.contains("feature `explorer-http`"), "err={err}");
            assert!(err.contains("not compiled"), "err={err}");
        }
        #[cfg(feature = "explorer-http")]
        {
            assert!(result.is_ok(), "expected Ok with explorer-http");
        }
    }

    #[test]
    fn bitcoin_network_for_electrum_maps_known_variants() {
        assert_eq!(
            bitcoin_network_for_electrum(BitcoinNetwork::Mainnet),
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            bitcoin_network_for_electrum(BitcoinNetwork::Signet),
            bitcoin::Network::Signet
        );
        assert_eq!(
            bitcoin_network_for_electrum(BitcoinNetwork::Testnet),
            bitcoin::Network::Testnet
        );
        assert_eq!(
            bitcoin_network_for_electrum(BitcoinNetwork::Testnet4),
            bitcoin::Network::Testnet
        );
    }

    /// Env-wrapper tests via injectable reader (no process env; crate
    /// `#![forbid(unsafe_code)]` forbids set_var/remove_var).
    mod from_env_reader {
        use super::*;
        use std::collections::HashMap;

        fn map_get<'a>(
            map: &'a HashMap<&'static str, String>,
        ) -> impl FnMut(&str) -> Option<String> + 'a {
            move |k| map.get(k).cloned()
        }

        #[test]
        fn unset_defaults_to_mempool() {
            let map = HashMap::new();
            let cfg = product_chain_source_config_from_env_reader(map_get(&map)).unwrap();
            assert_eq!(cfg, ProductChainSourceConfig::mempool());
        }

        #[test]
        fn empty_string_kind_defaults_to_mempool() {
            let mut map = HashMap::new();
            map.insert(CHAIN_SOURCE_ENV, String::new());
            let cfg = product_chain_source_config_from_env_reader(map_get(&map)).unwrap();
            assert_eq!(cfg.kind, ChainSourceKind::Mempool);
        }

        #[test]
        fn whitespace_kind_defaults_to_mempool() {
            let mut map = HashMap::new();
            map.insert(CHAIN_SOURCE_ENV, "   ".into());
            let cfg = product_chain_source_config_from_env_reader(map_get(&map)).unwrap();
            assert_eq!(cfg.kind, ChainSourceKind::Mempool);
        }

        #[test]
        fn esplora_requires_url_when_kind_set() {
            let mut map = HashMap::new();
            map.insert(CHAIN_SOURCE_ENV, "esplora".into());
            let err = product_chain_source_config_from_env_reader(map_get(&map))
                .unwrap_err()
                .to_string();
            assert!(err.contains(ESPLORA_URL_ENV), "err={err}");
        }

        #[test]
        fn esplora_accepts_url_case_insensitive_kind() {
            let mut map = HashMap::new();
            map.insert(CHAIN_SOURCE_ENV, "ESPLORA".into());
            map.insert(ESPLORA_URL_ENV, "https://mempool.space/api".into());
            let cfg = product_chain_source_config_from_env_reader(map_get(&map)).unwrap();
            assert_eq!(cfg.kind, ChainSourceKind::Esplora);
            assert_eq!(
                cfg.esplora_url.as_deref(),
                Some("https://mempool.space/api")
            );
        }

        #[test]
        fn electrum_requires_addr_when_kind_set() {
            let mut map = HashMap::new();
            map.insert(CHAIN_SOURCE_ENV, "electrum".into());
            let err = product_chain_source_config_from_env_reader(map_get(&map))
                .unwrap_err()
                .to_string();
            assert!(err.contains(ELECTRUM_ADDR_ENV), "err={err}");
        }

        #[test]
        fn electrum_accepts_host_port() {
            let mut map = HashMap::new();
            map.insert(CHAIN_SOURCE_ENV, "electrum".into());
            map.insert(ELECTRUM_ADDR_ENV, "127.0.0.1:50001".into());
            let cfg = product_chain_source_config_from_env_reader(map_get(&map)).unwrap();
            assert_eq!(cfg.kind, ChainSourceKind::Electrum);
            assert_eq!(cfg.electrum_addr.as_deref(), Some("127.0.0.1:50001"));
        }

        #[test]
        fn open_from_reader_mempool_feature_honesty() {
            let map = HashMap::new();
            let result = open_as_err_string(open_product_chain_source_from_env_reader(
                BitcoinNetwork::Mainnet,
                map_get(&map),
            ));
            #[cfg(not(feature = "explorer-http"))]
            {
                let err = result.expect_err("expected feature-missing error");
                assert!(err.contains("feature `explorer-http`"), "err={err}");
            }
            #[cfg(feature = "explorer-http")]
            {
                assert!(result.is_ok(), "default mempool open with explorer-http");
            }
        }

        #[test]
        fn open_from_reader_esplora_missing_feature_or_ok() {
            let mut map = HashMap::new();
            map.insert(CHAIN_SOURCE_ENV, "esplora".into());
            map.insert(ESPLORA_URL_ENV, "https://blockstream.info/api".into());
            let result = open_as_err_string(open_product_chain_source_from_env_reader(
                BitcoinNetwork::Mainnet,
                map_get(&map),
            ));
            #[cfg(not(feature = "esplora"))]
            {
                let err = result.expect_err("expected feature-missing error");
                assert!(err.contains("feature `esplora`"), "err={err}");
                assert!(err.contains("not compiled"), "err={err}");
            }
            #[cfg(feature = "esplora")]
            {
                assert!(result.is_ok());
            }
        }
    }
}
