//! OpenRouter app-attribution headers for Grok OSS (Surmount).
//!
//! Integration test so we don't depend on broken unit-test harness modules
//! in `xai-grok-shell` (e.g. WorkspaceOps::for_test).

use indexmap::IndexMap;
use xai_grok_shell::agent::config::inject_url_derived_headers;
use xai_grok_shell::auth::openrouter::{
    OPENROUTER_API_URL, OPENROUTER_CATEGORIES, OPENROUTER_GROK_45_CATALOG_ID,
    OPENROUTER_GROK_45_MODEL, OPENROUTER_HTTP_REFERER, OPENROUTER_X_OPENROUTER_TITLE_HEADER,
    OPENROUTER_X_TITLE, OPENROUTER_X_TITLE_HEADER,
};

#[test]
fn referer_is_surmount_grok_oss_not_xai() {
    assert!(OPENROUTER_HTTP_REFERER.contains("SurmountSystems/grok-oss"));
    assert_ne!(OPENROUTER_HTTP_REFERER, "https://x.ai");
    assert!(!OPENROUTER_HTTP_REFERER.contains("x.ai/cli"));
    assert_eq!(OPENROUTER_X_TITLE, "Grok OSS");
    assert_eq!(OPENROUTER_X_OPENROUTER_TITLE_HEADER, "X-OpenRouter-Title");
    assert_eq!(OPENROUTER_X_TITLE_HEADER, "X-Title");
    assert_eq!(OPENROUTER_CATEGORIES, "cli-agent");
    assert_eq!(OPENROUTER_GROK_45_MODEL, "x-ai/grok-4.5");
    assert_eq!(OPENROUTER_GROK_45_CATALOG_ID, "openrouter-grok-4.5");
}

#[test]
fn inject_url_derived_headers_sets_openrouter_attribution() {
    let mut headers = IndexMap::new();
    inject_url_derived_headers(&mut headers, None, OPENROUTER_API_URL);

    assert_eq!(
        headers.get("HTTP-Referer").map(String::as_str),
        Some(OPENROUTER_HTTP_REFERER)
    );
    assert_eq!(
        headers
            .get(OPENROUTER_X_OPENROUTER_TITLE_HEADER)
            .map(String::as_str),
        Some(OPENROUTER_X_TITLE)
    );
    assert_eq!(
        headers.get(OPENROUTER_X_TITLE_HEADER).map(String::as_str),
        Some(OPENROUTER_X_TITLE)
    );
    assert_eq!(
        headers.get("X-OpenRouter-Categories").map(String::as_str),
        Some(OPENROUTER_CATEGORIES)
    );
    assert!(!headers.contains_key("X-XAI-Token-Auth"));
}
