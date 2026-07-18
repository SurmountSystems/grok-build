//! Grok OSS update status: compare this binary’s embedded git SHA to
//! Surmount `main` on GitHub.
//!
//! There is no formal Surmount release channel. Version identity is
//! **upstream package version + short commit**. Users rebuild or reinstall
//! from git / Nix / AUR when behind `main`.

use anyhow::{Context, Result};
use serde::Deserialize;

/// Public clone / packaging repo.
pub const OSS_GITHUB_REPO: &str = "SurmountSystems/grok-oss";

/// How to get a fresher build (no binary auto-install).
pub fn how_to_update_message() -> String {
    format!(
        "Rebuild from source or reinstall a package that tracks main:\n\
         \n\
         git clone https://github.com/{OSS_GITHUB_REPO}.git\n\
         cd grok-oss && git pull\n\
         just install          # or: just install-nix / AUR package\n\
         \n\
         See FORK.md — Grok OSS has no separate release train."
    )
}

/// User-facing build id: `0.1.220-alpha.4 (cfe4602)`.
pub fn format_build_id(upstream_version: &str, git_sha: &str) -> String {
    format!("{upstream_version} ({git_sha})")
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OssUpdateStatus {
    /// e.g. `0.1.220-alpha.4 (cfe4602)`
    pub build_id: String,
    pub upstream_version: String,
    pub git_sha: String,
    /// Tip of `main` on GitHub (short sha when known).
    pub main_sha: Option<String>,
    /// Commits on `main` not in this build (0 = current).
    pub behind: Option<u64>,
    /// Commits in this build not on `main` (local / PR builds).
    pub ahead: Option<u64>,
    pub update_available: bool,
    pub status: String,
    pub error: Option<String>,
    pub how_to_update: String,
}

#[derive(Debug, Deserialize)]
struct GhCommitRef {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GhCompare {
    status: String,
    ahead_by: u64,
    behind_by: u64,
}

/// Query GitHub for how `git_sha` relates to Surmount `main`.
///
/// `upstream_version` is the lockstep package version (e.g. from
/// `CARGO_PKG_VERSION` of the pager-bin crate), not a Surmount release number.
pub async fn check_against_main(upstream_version: &str, git_sha: &str) -> OssUpdateStatus {
    let build_id = format_build_id(upstream_version, git_sha);
    let how = how_to_update_message();

    if git_sha == "unknown" || git_sha.is_empty() {
        return OssUpdateStatus {
            build_id,
            upstream_version: upstream_version.to_string(),
            git_sha: git_sha.to_string(),
            main_sha: None,
            behind: None,
            ahead: None,
            update_available: false,
            status: "unknown".into(),
            error: Some(format!(
                "This binary was built without a git SHA (e.g. pure Nix without .git). \
                 Set GROK_GIT_SHA at build time or compare against \
                 https://github.com/{OSS_GITHUB_REPO} manually."
            )),
            how_to_update: how,
        };
    }

    match fetch_compare(git_sha).await {
        Ok((main_sha, compare)) => {
            // GitHub compare base...head with base=this build, head=main:
            //   ahead_by  = commits on main not in this build → we are *behind* main
            //   behind_by = commits in this build not on main → we are *ahead* of main
            let behind = compare.ahead_by;
            let ahead = compare.behind_by;
            OssUpdateStatus {
                build_id,
                upstream_version: upstream_version.to_string(),
                git_sha: git_sha.to_string(),
                main_sha: Some(shorten_sha(&main_sha)),
                behind: Some(behind),
                ahead: Some(ahead),
                update_available: behind > 0,
                status: compare.status,
                error: None,
                how_to_update: how,
            }
        }
        Err(e) => OssUpdateStatus {
            build_id,
            upstream_version: upstream_version.to_string(),
            git_sha: git_sha.to_string(),
            main_sha: None,
            behind: None,
            ahead: None,
            update_available: false,
            status: "error".into(),
            error: Some(e.to_string()),
            how_to_update: how,
        },
    }
}

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn apply_github_headers(mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    req = req.header(reqwest::header::ACCEPT, "application/vnd.github+json");
    if let Some(token) = github_token() {
        req = req.bearer_auth(token);
    }
    req
}

async fn fetch_compare(base_sha: &str) -> Result<(String, GhCompare)> {
    use grok_rate_limit::{ProviderKey, RateLimitMeta, SharedRateLimitStore, keys};
    use std::time::Duration;

    let rate = SharedRateLimitStore::process_default();
    let rate_key = ProviderKey::new(keys::GITHUB);
    rate.wait_if_limited(&rate_key).await;

    let client = reqwest::Client::builder()
        .user_agent(format!("grok-oss/{base_sha}"))
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("http client")?;

    let main_url = format!("https://api.github.com/repos/{OSS_GITHUB_REPO}/commits/main");
    let main_resp = apply_github_headers(client.get(&main_url))
        .send()
        .await
        .context("fetch main tip")?;
    let main_status = main_resp.status();
    if !main_status.is_success() {
        let headers = main_resp.headers().clone();
        let body = main_resp.text().await.unwrap_or_default();
        if main_status.as_u16() == 403 || main_status.as_u16() == 429 {
            let wait = github_rate_limit_wait(&headers).unwrap_or(Duration::from_secs(60));
            let _ = rate.observe(
                &rate_key,
                wait,
                RateLimitMeta {
                    status: Some(main_status.as_u16()),
                    reason: Some("GitHub API rate limit".into()),
                },
            );
        }
        let hint = if main_status.as_u16() == 403 {
            " (set GITHUB_TOKEN or GH_TOKEN for a higher API rate limit)"
        } else {
            ""
        };
        anyhow::bail!(
            "could not read github.com/{OSS_GITHUB_REPO} main ({main_status}){hint}: {}",
            body.chars().take(160).collect::<String>()
        );
    }
    let main: GhCommitRef = main_resp.json().await.context("parse main tip")?;

    // base...head with head = main: ahead_by = commits on main not in this build
    let compare_url = format!(
        "https://api.github.com/repos/{OSS_GITHUB_REPO}/compare/{base_sha}...{head}",
        head = main.sha
    );
    let cmp_resp = apply_github_headers(client.get(&compare_url))
        .send()
        .await
        .context("compare with main")?;
    let cmp_status = cmp_resp.status();
    if !cmp_status.is_success() {
        let headers = cmp_resp.headers().clone();
        let body = cmp_resp.text().await.unwrap_or_default();
        if cmp_status.as_u16() == 403 || cmp_status.as_u16() == 429 {
            let wait = github_rate_limit_wait(&headers).unwrap_or(Duration::from_secs(60));
            let _ = rate.observe(
                &rate_key,
                wait,
                RateLimitMeta {
                    status: Some(cmp_status.as_u16()),
                    reason: Some("GitHub API rate limit".into()),
                },
            );
        }
        // 404 usually means this SHA is not on the remote (local-only commits).
        if cmp_status.as_u16() == 404 {
            anyhow::bail!(
                "commit {base_sha} is not on github.com/{OSS_GITHUB_REPO} \
                 (local/unpushed build?). Main tip is {}.",
                shorten_sha(&main.sha)
            );
        }
        anyhow::bail!(
            "compare failed ({cmp_status}): {}",
            body.chars().take(200).collect::<String>()
        );
    }
    let compare: GhCompare = cmp_resp.json().await.context("parse compare")?;

    Ok((main.sha, compare))
}

/// Prefer `Retry-After` seconds; else `x-ratelimit-reset` unix epoch.
fn github_rate_limit_wait(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    if let Some(secs) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Some(Duration::from_secs(secs));
    }
    let reset = headers
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(reset.saturating_sub(now).max(1)))
}

fn shorten_sha(sha: &str) -> String {
    sha.chars().take(12).collect()
}

/// Print [`OssUpdateStatus`] for humans or JSON.
pub fn print_oss_update_status(status: &OssUpdateStatus, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(status)?);
        return Ok(());
    }

    println!("Grok OSS  {}", status.build_id);

    if let Some(err) = status.error.as_deref() {
        println!("Update check failed: {err}");
        return Ok(());
    }

    let main = status.main_sha.as_deref().unwrap_or("?");
    let behind = status.behind.unwrap_or(0);
    let ahead = status.ahead.unwrap_or(0);

    match (behind, ahead) {
        (0, 0) => {
            println!("Up to date with github.com/{OSS_GITHUB_REPO} main ({main}).");
        }
        (b, 0) if b > 0 => {
            println!(
                "Behind main by {b} commit(s) (main is {main}). Rebuild or reinstall to update."
            );
            println!();
            println!("{}", status.how_to_update);
        }
        (0, a) if a > 0 => {
            println!("Ahead of main by {a} commit(s) (local or unreleased build; main is {main}).");
        }
        (b, a) => {
            println!(
                "Diverged from main: behind {b}, ahead {a} (main is {main}). \
                 Merge or rebase when ready."
            );
            if b > 0 {
                println!();
                println!("{}", status.how_to_update);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn format_build_id_shape() {
        assert_eq!(
            format_build_id("0.1.220-alpha.4", "cfe4602"),
            "0.1.220-alpha.4 (cfe4602)"
        );
    }

    #[test]
    fn shorten_sha_truncates() {
        assert_eq!(shorten_sha("abcdef0123456789"), "abcdef012345");
        assert_eq!(shorten_sha("abc"), "abc");
    }

    #[test]
    fn github_rate_limit_wait_prefers_retry_after() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "42".parse().unwrap());
        headers.insert("x-ratelimit-reset", "9999999999".parse().unwrap());
        assert_eq!(
            github_rate_limit_wait(&headers),
            Some(Duration::from_secs(42))
        );
    }

    #[test]
    fn github_rate_limit_wait_uses_reset_epoch() {
        let mut headers = reqwest::header::HeaderMap::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        headers.insert("x-ratelimit-reset", (now + 90).to_string().parse().unwrap());
        let wait = github_rate_limit_wait(&headers).expect("reset wait");
        assert!(
            wait >= Duration::from_secs(80) && wait <= Duration::from_secs(100),
            "got {wait:?}"
        );
    }

    #[test]
    fn github_rate_limit_wait_none_without_headers() {
        let headers = reqwest::header::HeaderMap::new();
        assert_eq!(github_rate_limit_wait(&headers), None);
    }

    #[test]
    fn how_to_update_mentions_rebuild_not_xai_installer() {
        let msg = how_to_update_message();
        assert!(msg.contains("just install") || msg.contains("git pull"));
        assert!(msg.contains(OSS_GITHUB_REPO));
        assert!(!msg.contains("x.ai/cli/install"));
    }

    #[test]
    fn print_oss_status_up_to_date_is_ok() {
        let status = OssUpdateStatus {
            build_id: "0.1.0 (abc)".into(),
            upstream_version: "0.1.0".into(),
            git_sha: "abc".into(),
            main_sha: Some("abc".into()),
            behind: Some(0),
            ahead: Some(0),
            update_available: false,
            status: "identical".into(),
            error: None,
            how_to_update: how_to_update_message(),
        };
        print_oss_update_status(&status, false).unwrap();
        print_oss_update_status(&status, true).unwrap();
    }
}
