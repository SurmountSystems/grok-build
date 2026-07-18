//! Flock-backed shared cooldown map under `$GROK_HOME/rate_limits/`.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

/// Env kill-switch: when set (any value), shared coordination is disabled.
pub const DISABLE_ENV: &str = "GROK_DISABLE_SHARED_RATE_LIMIT";

/// Whether shared rate limits are disabled for this process.
pub fn shared_rate_limits_disabled() -> bool {
    std::env::var_os(DISABLE_ENV).is_some()
}

/// Provider identity for the cooldown map (host or logical name; no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderKey(String);

impl ProviderKey {
    pub fn new(s: impl Into<String>) -> Self {
        let raw = s.into();
        let safe: String = raw
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        Self(if safe.is_empty() {
            "unknown".into()
        } else {
            safe
        })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive a key from an HTTP base URL host (lowercase).
    pub fn from_base_url(base_url: &str) -> Self {
        let host = url_host(base_url).unwrap_or_else(|| "unknown".into());
        Self::new(host)
    }

    /// Host + short fingerprint of a credential (not the secret itself).
    pub fn from_base_url_and_key_fingerprint(base_url: &str, key_fingerprint: &str) -> Self {
        let host = url_host(base_url).unwrap_or_else(|| "unknown".into());
        if key_fingerprint.is_empty() {
            return Self::new(host);
        }
        let fp: String = key_fingerprint.chars().take(16).collect();
        Self::new(format!("{host}+{fp}"))
    }
}

fn url_host(base_url: &str) -> Option<String> {
    // Avoid pulling `url` crate: light parse.
    let s = base_url.trim();
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let host = rest.split('/').next()?.split('@').next_back()?;
    let host = host.split(':').next()?.to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

/// Metadata stored with a cooldown for TUI / logs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimitMeta {
    pub status: Option<u16>,
    pub reason: Option<String>,
}

/// Snapshot of shared cooldown state for one provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSnapshot {
    pub not_before_unix_ms: u64,
    pub last_status: Option<u16>,
    pub last_reason: Option<String>,
    pub updated_at_unix_ms: u64,
}

impl RateLimitSnapshot {
    pub fn remaining(&self, now_ms: u64) -> Duration {
        if self.not_before_unix_ms <= now_ms {
            Duration::ZERO
        } else {
            Duration::from_millis(self.not_before_unix_ms - now_ms)
        }
    }

    pub fn is_active(&self, now_ms: u64) -> bool {
        self.not_before_unix_ms > now_ms
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRecord {
    not_before_unix_ms: u64,
    #[serde(default)]
    last_status: Option<u16>,
    #[serde(default)]
    last_reason: Option<String>,
    updated_at_unix_ms: u64,
}

/// Cross-process shared rate-limit store.
#[derive(Debug, Clone)]
pub struct SharedRateLimitStore {
    root: PathBuf,
    /// Process-local cache: key → not_before_unix_ms (fast path without flock).
    cache: Arc<Mutex<HashMap<String, AtomicU64>>>,
}

impl SharedRateLimitStore {
    /// Store under `$GROK_HOME/rate_limits` or `home/rate_limits` when provided.
    pub fn open(grok_home: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = grok_home.as_ref().join("rate_limits");
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Global store for this process using `GROK_HOME` / `~/.grok`.
    pub fn process_default() -> Self {
        static STORE: OnceLock<SharedRateLimitStore> = OnceLock::new();
        STORE
            .get_or_init(|| {
                let home = grok_home_path();
                Self::open(&home).unwrap_or_else(|_| Self {
                    root: home.join("rate_limits"),
                    cache: Arc::new(Mutex::new(HashMap::new())),
                })
            })
            .clone()
    }

    fn path_for(&self, key: &ProviderKey) -> PathBuf {
        self.root.join(format!("{}.json", key.as_str()))
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn cache_get(&self, key: &str) -> Option<u64> {
        let guard = self.cache.lock().ok()?;
        guard.get(key).map(|a| a.load(Ordering::Acquire))
    }

    fn cache_set(&self, key: &str, not_before: u64) {
        if let Ok(mut guard) = self.cache.lock() {
            guard
                .entry(key.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_max(not_before, Ordering::AcqRel);
        }
    }

    /// Current snapshot (None if no record or disabled).
    ///
    /// Always reads the flock file for full metadata (status/reason). The
    /// in-process cache is only a fast path for [`Self::remaining`].
    pub fn snapshot(&self, key: &ProviderKey) -> Option<RateLimitSnapshot> {
        if shared_rate_limits_disabled() {
            return None;
        }
        let snap = self
            .with_locked(key, |rec| {
                rec.map(|r| {
                    self.cache_set(key.as_str(), r.not_before_unix_ms);
                    RateLimitSnapshot {
                        not_before_unix_ms: r.not_before_unix_ms,
                        last_status: r.last_status,
                        last_reason: r.last_reason,
                        updated_at_unix_ms: r.updated_at_unix_ms,
                    }
                })
            })
            .ok()
            .flatten()?;
        Some(snap)
    }

    /// Remaining wait before a call is allowed (ZERO if open).
    pub fn remaining(&self, key: &ProviderKey) -> Duration {
        if shared_rate_limits_disabled() {
            return Duration::ZERO;
        }
        let now = Self::now_ms();
        if let Some(nb) = self.cache_get(key.as_str())
            && nb > now
        {
            return Duration::from_millis(nb - now);
        }
        self.snapshot(key)
            .map(|s| s.remaining(now))
            .unwrap_or(Duration::ZERO)
    }

    /// Record a rate limit / throttle. Strictest `not_before` wins.
    pub fn observe(
        &self,
        key: &ProviderKey,
        wait: Duration,
        meta: RateLimitMeta,
    ) -> std::io::Result<()> {
        if shared_rate_limits_disabled() {
            return Ok(());
        }
        let now = Self::now_ms();
        let until = now.saturating_add(wait.as_millis() as u64);
        self.with_locked_mut(key, |rec| {
            let existing = rec.as_ref().map(|r| r.not_before_unix_ms).unwrap_or(0);
            let not_before = existing.max(until);
            *rec = Some(StoredRecord {
                not_before_unix_ms: not_before,
                last_status: meta
                    .status
                    .or_else(|| rec.as_ref().and_then(|r| r.last_status)),
                last_reason: meta
                    .reason
                    .or_else(|| rec.as_ref().and_then(|r| r.last_reason.clone())),
                updated_at_unix_ms: now,
            });
            self.cache_set(key.as_str(), not_before);
        })
    }

    /// Async sleep until the shared cooldown expires (if any).
    pub async fn wait_if_limited(&self, key: &ProviderKey) {
        if shared_rate_limits_disabled() {
            return;
        }
        loop {
            let rem = self.remaining(key);
            if rem.is_zero() {
                return;
            }
            // Cap single sleep slice so disable-env / clock jumps are noticed.
            let slice = rem.min(Duration::from_secs(30));
            tracing::debug!(
                provider = key.as_str(),
                wait_ms = rem.as_millis() as u64,
                "shared rate limit: waiting"
            );
            tokio::time::sleep(slice).await;
        }
    }

    fn with_locked<R>(
        &self,
        key: &ProviderKey,
        f: impl FnOnce(Option<StoredRecord>) -> R,
    ) -> std::io::Result<R> {
        let path = self.path_for(key);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        file.lock_exclusive()?;
        let rec = read_record(&mut file)?;
        let out = f(rec);
        let _ = file.unlock();
        Ok(out)
    }

    fn with_locked_mut(
        &self,
        key: &ProviderKey,
        f: impl FnOnce(&mut Option<StoredRecord>),
    ) -> std::io::Result<()> {
        let path = self.path_for(key);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        file.lock_exclusive()?;
        let mut rec = read_record(&mut file)?;
        f(&mut rec);
        write_record(&mut file, rec.as_ref())?;
        let _ = file.unlock();
        Ok(())
    }
}

fn read_record(file: &mut File) -> std::io::Result<Option<StoredRecord>> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        return Ok(None);
    }
    Ok(serde_json::from_str(&buf).ok())
}

fn write_record(file: &mut File, rec: Option<&StoredRecord>) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    if let Some(rec) = rec {
        let data = serde_json::to_vec_pretty(rec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    Ok(())
}

fn grok_home_path() -> PathBuf {
    if let Ok(v) = std::env::var("GROK_HOME") {
        return PathBuf::from(v);
    }
    #[allow(deprecated)]
    let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".grok")
}

/// Fingerprint an API key for provider keys (truncated hex of a simple hash).
pub fn fingerprint_secret(secret: &str) -> String {
    // FNV-1a 64-bit — no extra dep; not cryptographic, just de-collision for local map keys.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in secret.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    /// Serialize tests that read/write `GROK_DISABLE_SHARED_RATE_LIMIT` or assume
    /// shared limits are enabled. Cargo runs tests multi-threaded by default.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    /// Hold the env lock for the duration of a store test (limits must stay enabled).
    fn with_shared_limits_enabled<R>(f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Another test may have left the kill-switch set; clear while we hold the lock.
        let prev = std::env::var_os(DISABLE_ENV);
        if prev.is_some() {
            // SAFETY: exclusive via ENV_LOCK; restored before unlock.
            unsafe { std::env::remove_var(DISABLE_ENV) };
        }
        let out = f();
        match prev {
            Some(v) => unsafe { std::env::set_var(DISABLE_ENV, v) },
            None => {}
        }
        out
    }

    #[test]
    fn provider_key_sanitizes() {
        let k = ProviderKey::from_base_url("https://openrouter.ai/api/v1");
        assert_eq!(k.as_str(), "openrouter.ai");
    }

    #[test]
    fn provider_key_from_base_url_and_fingerprint_differs_by_key() {
        let a = ProviderKey::from_base_url_and_key_fingerprint(
            "https://openrouter.ai/api/v1",
            "aaaaaaaaaaaaaaaa",
        );
        let b = ProviderKey::from_base_url_and_key_fingerprint(
            "https://openrouter.ai/api/v1",
            "bbbbbbbbbbbbbbbb",
        );
        assert_ne!(a.as_str(), b.as_str());
        // '+' is sanitized to '_' in ProviderKey::new
        assert!(
            a.as_str().starts_with("openrouter.ai_"),
            "got {}",
            a.as_str()
        );
    }

    #[test]
    fn max_merge_keeps_strictest() {
        with_shared_limits_enabled(|| {
            let dir = TempDir::new().unwrap();
            let store = SharedRateLimitStore::open(dir.path()).unwrap();
            let key = ProviderKey::new("test-prov");
            store
                .observe(
                    &key,
                    Duration::from_secs(5),
                    RateLimitMeta {
                        status: Some(429),
                        reason: Some("first".into()),
                    },
                )
                .unwrap();
            store
                .observe(
                    &key,
                    Duration::from_secs(1),
                    RateLimitMeta {
                        status: Some(429),
                        reason: Some("weaker".into()),
                    },
                )
                .unwrap();
            let snap = store.snapshot(&key).unwrap();
            let now = SharedRateLimitStore::now_ms();
            // Should still be ~5s from first observe (not shortened to 1s).
            assert!(
                snap.not_before_unix_ms >= now + 3000,
                "not_before too soon: {:?}",
                snap.remaining(now)
            );
            assert_eq!(snap.last_status, Some(429));
        });
    }

    #[test]
    fn two_store_handles_share_file_state() {
        with_shared_limits_enabled(|| {
            // Simulates two processes: separate store instances, same on-disk dir.
            let dir = TempDir::new().unwrap();
            let a = SharedRateLimitStore::open(dir.path()).unwrap();
            let b = SharedRateLimitStore::open(dir.path()).unwrap();
            let key = ProviderKey::new("shared-peer");
            a.observe(
                &key,
                Duration::from_secs(10),
                RateLimitMeta {
                    status: Some(429),
                    reason: Some("from-a".into()),
                },
            )
            .unwrap();
            let rem_b = b.remaining(&key);
            assert!(
                rem_b >= Duration::from_secs(8),
                "peer B should see A's cooldown, got {rem_b:?}"
            );
            // B observes a longer wait → A must see the stricter value after re-read.
            b.observe(
                &key,
                Duration::from_secs(30),
                RateLimitMeta {
                    status: Some(429),
                    reason: Some("from-b".into()),
                },
            )
            .unwrap();
            // Clear A's process cache by opening a third handle (same files).
            let c = SharedRateLimitStore::open(dir.path()).unwrap();
            let rem_c = c.remaining(&key);
            assert!(
                rem_c >= Duration::from_secs(25),
                "strictest wait should win, got {rem_c:?}"
            );
        });
    }

    #[test]
    fn remaining_zero_when_open() {
        with_shared_limits_enabled(|| {
            let dir = TempDir::new().unwrap();
            let store = SharedRateLimitStore::open(dir.path()).unwrap();
            let key = ProviderKey::new("open");
            assert_eq!(store.remaining(&key), Duration::ZERO);
            assert!(
                store.snapshot(&key).is_none()
                    || !store
                        .snapshot(&key)
                        .unwrap()
                        .is_active(SharedRateLimitStore::now_ms())
            );
        });
    }

    #[tokio::test]
    async fn wait_if_limited_sleeps() {
        // Lock must outlive the async body; take it for the whole test.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os(DISABLE_ENV);
        if prev.is_some() {
            unsafe { std::env::remove_var(DISABLE_ENV) };
        }
        let dir = TempDir::new().unwrap();
        let store = SharedRateLimitStore::open(dir.path()).unwrap();
        let key = ProviderKey::new("wait-me");
        store
            .observe(&key, Duration::from_millis(40), RateLimitMeta::default())
            .unwrap();
        assert!(store.remaining(&key) > Duration::ZERO);
        store.wait_if_limited(&key).await;
        assert_eq!(store.remaining(&key), Duration::ZERO);
        match prev {
            Some(v) => unsafe { std::env::set_var(DISABLE_ENV, v) },
            None => {}
        }
    }

    #[test]
    fn fingerprint_stable() {
        assert_eq!(fingerprint_secret("sk-a"), fingerprint_secret("sk-a"));
        assert_ne!(fingerprint_secret("sk-a"), fingerprint_secret("sk-b"));
    }

    #[test]
    fn disable_env_makes_ops_noop() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: exclusive via ENV_LOCK; we restore after.
        let prev = std::env::var_os(DISABLE_ENV);
        unsafe {
            std::env::set_var(DISABLE_ENV, "1");
        }
        let dir = TempDir::new().unwrap();
        let store = SharedRateLimitStore::open(dir.path()).unwrap();
        let key = ProviderKey::new("disabled");
        store
            .observe(&key, Duration::from_secs(60), RateLimitMeta::default())
            .unwrap();
        assert_eq!(store.remaining(&key), Duration::ZERO);
        assert!(store.snapshot(&key).is_none());
        match prev {
            Some(v) => unsafe { std::env::set_var(DISABLE_ENV, v) },
            None => unsafe { std::env::remove_var(DISABLE_ENV) },
        }
    }

    #[test]
    fn longer_second_observe_extends_not_before() {
        with_shared_limits_enabled(|| {
            let dir = TempDir::new().unwrap();
            let store = SharedRateLimitStore::open(dir.path()).unwrap();
            let key = ProviderKey::new("extend");
            store
                .observe(&key, Duration::from_secs(2), RateLimitMeta::default())
                .unwrap();
            let first = store.snapshot(&key).unwrap().not_before_unix_ms;
            store
                .observe(&key, Duration::from_secs(20), RateLimitMeta::default())
                .unwrap();
            let second = store.snapshot(&key).unwrap().not_before_unix_ms;
            assert!(second >= first + 10_000, "second={second} first={first}");
        });
    }
}
