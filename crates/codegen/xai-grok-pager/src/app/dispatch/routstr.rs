//! `/routstr` product surface: balance, fund gates, top up / refund honesty,
//! and background address watch.

use std::cell::RefCell;
use std::path::PathBuf;

use super::status::dispatch_show_usage;
use crate::app::actions::Effect;
use crate::app::agent::AgentId;
use crate::app::app_view::{ActiveView, AppView};
use crate::scrollback::block::RenderBlock;

/// Max consecutive watch error system messages before status-only updates.
/// Semantics: exactly this many error lines may enter scrollback; further
/// errors still update `routstr_watch_status` (footer) only.
const WATCH_ERROR_SCROLLBACK_CAP: u32 = 2;

// Test-only override for the durable watch path. When set under `cfg!(test)`,
// pager unit tests may exercise resume/persist glue against a `tempfile`
// without touching developer `~/.grok`. Product builds never set this.
thread_local! {
    static WATCH_SESSION_PATH_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Resolve grok home for wallet paths (same layout as CLI).
fn grok_home() -> std::path::PathBuf {
    xai_grok_shell::util::grok_home::grok_home()
}

/// Durable watch progress path (`{GROK_HOME}/bitcoin/watch_session.json`).
///
/// Under unit tests, returns the injected override when set; otherwise the
/// default path (persistence is still gated by [`watch_persistence_enabled`]).
pub(crate) fn watch_session_path() -> PathBuf {
    if let Some(p) = WATCH_SESSION_PATH_OVERRIDE.with(|c| c.borrow().clone()) {
        return p;
    }
    grok_bitcoin_wallet::watcher::default_watch_session_path(grok_home())
}

/// Whether durable watch FS I/O is active.
///
/// Product binaries: always on. Unit-test builds: only when a path override is
/// injected so lib tests never pollute developer `~/.grok` by default, but
/// resume/persist glue can still be covered with a `tempfile`.
pub(crate) fn watch_persistence_enabled() -> bool {
    if cfg!(test) {
        WATCH_SESSION_PATH_OVERRIDE.with(|c| c.borrow().is_some())
    } else {
        true
    }
}

/// Install (or clear) the test-only durable watch path override.
///
/// Prefer [`with_watch_session_path_for_test`] so panics still clear the TLS.
#[cfg(test)]
pub(crate) fn set_watch_session_path_override(path: Option<PathBuf>) {
    WATCH_SESSION_PATH_OVERRIDE.with(|c| {
        *c.borrow_mut() = path;
    });
}

/// Run `f` with durable watch FS pointed at `path`, then clear the override.
#[cfg(test)]
pub(crate) fn with_watch_session_path_for_test<T>(path: PathBuf, f: impl FnOnce() -> T) -> T {
    set_watch_session_path_override(Some(path));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    set_watch_session_path_override(None);
    match result {
        Ok(v) => v,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Canonical network wire string for a brand-new watch (`GROK_BITCOIN_NETWORK`).
fn network_from_env() -> String {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
    let raw = std::env::var("GROK_BITCOIN_NETWORK").unwrap_or_else(|_| "mainnet".into());
    BitcoinNetwork::from_env_str(&raw)
        .map(|n| n.as_str().to_owned())
        .unwrap_or_else(|| raw.trim().to_ascii_lowercase())
}

/// Canonicalize a network string; fall back to env/mainnet when unknown.
fn canonicalize_network(network: &str) -> String {
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
    BitcoinNetwork::from_env_str(network)
        .map(|n| n.as_str().to_owned())
        .unwrap_or_else(network_from_env)
}

/// Persist a running watch (address + network only seed-free fields).
///
/// Merges prior txid/confirmations when the address matches so a restart mid-
/// confirmation does not forget progress. Best-effort: disk errors are logged
/// and never abort the in-process watch loop.
///
/// `network` must already be the watch's intended network (durable state on
/// resume, env only for brand-new watches). Matching-address merges **keep**
/// the caller's network rather than re-reading env.
fn persist_routstr_watch_running(address: &str, network: &str, generation: u64) {
    if !watch_persistence_enabled() {
        return;
    }
    use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
    use grok_bitcoin_wallet::watcher::{
        WatchSession, load_watch_session_state, save_watch_session_state,
    };
    let path = watch_session_path();
    let address = address.trim();
    if address.is_empty() {
        return;
    }
    let net = BitcoinNetwork::from_env_str(network).unwrap_or(BitcoinNetwork::Mainnet);
    let net_wire = net.as_str().to_owned();
    let state = match load_watch_session_state(&path) {
        Ok(Some(prior)) if prior.address.trim() == address => {
            let mut s = prior;
            s.running = true;
            s.generation = generation;
            // Honor the network the watch was (re)armed with — durable on
            // resume, not a fresh env default that would rewrite signet→mainnet.
            s.network = net_wire;
            s.address = address.to_owned();
            s
        }
        _ => {
            let session = WatchSession::start(address, net, 3);
            let mut s = session.to_state(true);
            s.generation = generation;
            s
        }
    };
    if let Err(e) = save_watch_session_state(&path, &state) {
        tracing::warn!(error = %e, path = %path.display(), "persist routstr watch session failed");
    }
}

/// Stop durable watch (stop / deposit confirmed). Best-effort.
///
/// Unlink first; if remove fails, write `running: false` so the next pager
/// start cannot re-arm a user-stopped or already-confirmed watch.
fn clear_persisted_routstr_watch() {
    if !watch_persistence_enabled() {
        return;
    }
    let path = watch_session_path();
    if let Err(e) = grok_bitcoin_wallet::watcher::stop_watch_session_state(&path) {
        tracing::warn!(error = %e, path = %path.display(), "stop routstr watch session failed");
    }
}

/// Re-arm a deposit watch after pager process restart if a durable session exists.
///
/// Call when an agent view is available (session load / startup). No BIP-39.
/// Returns empty when nothing to resume or a watch is already running.
///
/// **Network:** durable `state.network` is passed through to the effect and
/// re-persist path — never discarded in favor of `GROK_BITCOIN_NETWORK`.
pub(crate) fn try_resume_persisted_routstr_watch(app: &mut AppView) -> Vec<Effect> {
    let ActiveView::Agent(agent_id) = app.active_view else {
        return vec![];
    };
    try_resume_persisted_routstr_watch_for_agent(app, agent_id)
}

/// Same as [`try_resume_persisted_routstr_watch`] but bound to an explicit agent
/// (session create/load completions).
pub(crate) fn try_resume_persisted_routstr_watch_for_agent(
    app: &mut AppView,
    agent_id: AgentId,
) -> Vec<Effect> {
    if !watch_persistence_enabled() {
        return vec![];
    }
    if app.routstr_watch_address.is_some() {
        return vec![];
    }
    if !app.agents.contains_key(&agent_id) {
        return vec![];
    }
    let path = watch_session_path();
    let state = match grok_bitcoin_wallet::watcher::load_watch_session_state(&path) {
        Ok(Some(s)) if s.should_resume() => s,
        Ok(_) => return vec![],
        Err(e) => {
            tracing::warn!(error = %e, "load routstr watch session failed");
            return vec![];
        }
    };
    let address = state.address.trim().to_owned();
    if address.is_empty() {
        return vec![];
    }
    let network = canonicalize_network(&state.network);
    push_system_to_agent(
        app,
        agent_id,
        format!(
            "Resuming deposit watch for {address} on {network} after restart \
             (no recovery phrase involved)."
        ),
    );
    // Re-arm with durable network (not env); re-persists with a fresh generation.
    start_routstr_watch_for_agent_on_network(
        app,
        agent_id,
        address,
        Some(network),
        /*immediate*/ true,
    )
}

fn push_system_to_agent(app: &mut AppView, agent_id: AgentId, text: impl Into<String>) {
    if let Some(agent) = app.agents.get_mut(&agent_id) {
        agent.scrollback.push_block(RenderBlock::system(text));
    }
}

fn push_system_active(app: &mut AppView, text: impl Into<String>) {
    let ActiveView::Agent(id) = app.active_view else {
        return;
    };
    push_system_to_agent(app, id, text);
}

fn push_system_lines_active(app: &mut AppView, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    push_system_active(app, lines.join("\n"));
}

/// `/routstr balance` — refresh billing so Routstr float shows in usage.
pub(super) fn dispatch_routstr_balance(app: &mut AppView) -> Vec<Effect> {
    let mut effects = dispatch_show_usage(app);
    if effects.is_empty() {
        effects.push(Effect::FetchAppBilling);
    }
    effects
}

/// Cancel a staged spend if present; notify the staging agent.
///
/// Returns `true` when a pending spend was cleared.
fn clear_pending_routstr_spend(app: &mut AppView, reason: &str) -> bool {
    let Some(pending) = app.pending_routstr_spend.take() else {
        return false;
    };
    push_system_to_agent(
        app,
        pending.agent_id,
        format!(
            "Cancelled staged spend ({reason}): {} sats → {}.",
            pending.amount_sats, pending.address
        ),
    );
    true
}

/// `/routstr fund` — probe vault (async); never mint on keyring errors.
///
/// Also cancels any staged `/routstr spend` so unlock cannot authorize a
/// stale (possibly broadcast) spend after the user switched to fund.
pub(super) fn dispatch_routstr_fund(app: &mut AppView) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        // No agent view: cannot show system block either.
        return vec![];
    };
    let _ = clear_pending_routstr_spend(app, "running /routstr fund");
    push_system_to_agent(
        app,
        id,
        "Checking local Bitcoin wallet (SeedVault). Recovery phrases are never stored in chat history.",
    );
    vec![Effect::RoutstrFundProbe {
        agent_id: id,
        grok_home: grok_home(),
    }]
}

/// Complete re-entry after `/routstr unlock <phrase>`.
///
/// If a pending spend was staged via `/routstr spend`, unlock authorizes that
/// spend (not fund). BIP-39 never enters chat history — only the unlock path
/// carries [`SensitiveString`] into a blocking task.
///
/// Spend completion is bound to the **staging** agent (`pending.agent_id`),
/// not merely the current active view, so switching agents cannot mis-route
/// a money path.
pub(super) fn dispatch_routstr_fund_reentry(
    app: &mut AppView,
    phrase: crate::app::actions::SensitiveString,
    password: Option<crate::app::actions::SensitiveString>,
) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    if phrase.is_empty() {
        push_system_to_agent(app, id, "Recovery phrase re-entry cancelled.");
        return vec![];
    }
    if let Some(pending) = app.pending_routstr_spend.take() {
        // Bind money path to staging agent; reject if active agent differs so
        // the user cannot authorize agent-A's spend from agent-B by accident.
        if pending.agent_id != id {
            // Restore pending so the correct agent can still unlock.
            let staging = pending.agent_id;
            app.pending_routstr_spend = Some(pending);
            push_system_to_agent(
                app,
                id,
                format!(
                    "Staged spend belongs to another agent session (agent {staging:?}). \
                     Switch back to that agent and run /routstr unlock there, or cancel \
                     with /routstr fund on the staging agent."
                ),
            );
            return vec![];
        }
        let mode = if pending.broadcast {
            "broadcast"
        } else {
            "dry-run"
        };
        push_system_to_agent(
            app,
            pending.agent_id,
            format!(
                "Authorizing on-chain spend ({mode}): {} sats → {}. Recovery phrase is not stored in chat.",
                pending.amount_sats, pending.address
            ),
        );
        return vec![Effect::RoutstrSpendComplete {
            agent_id: pending.agent_id,
            grok_home: grok_home(),
            phrase,
            password,
            address: pending.address,
            amount_sats: pending.amount_sats,
            broadcast: pending.broadcast,
            fee_rate_sat_vb: pending.fee_rate_sat_vb,
        }];
    }
    push_system_to_agent(
        app,
        id,
        "Unlocking receive address (backup gate re-entry). Do not fund until the address is shown.",
    );
    vec![Effect::RoutstrFundComplete {
        agent_id: id,
        grok_home: grok_home(),
        phrase,
        password,
    }]
}

/// Stage `/routstr spend` then require unlock re-entry (no BIP-39 on this action).
pub(super) fn dispatch_routstr_spend(
    app: &mut AppView,
    address: String,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: u64,
) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    if app.pending_routstr_spend.is_some() {
        let _ = clear_pending_routstr_spend(app, "superseded by a new /routstr spend");
    }
    app.pending_routstr_spend = Some(crate::app::app_view::PendingRoutstrSpend {
        agent_id: id,
        address: address.clone(),
        amount_sats,
        broadcast,
        fee_rate_sat_vb,
    });
    let mode = if broadcast {
        "with network broadcast"
    } else {
        "dry-run only (not broadcast)"
    };
    push_system_to_agent(
        app,
        id,
        format!(
            "Staged on-chain spend ({mode}): {amount_sats} sats → {address} (fee rate {fee_rate_sat_vb} sat/vB).\n\
             Authorize with: /routstr unlock <recovery phrase words…>\n\
             Optional AEAD password: /routstr unlock pw:<password> <phrase…>\n\
             Recovery words are never stored in chat history. Cancel by staging a different spend or running /routstr fund \
             (fund cancels any staged spend so unlock cannot broadcast a stale one)."
        ),
    );
    vec![]
}

/// Handle spend task result (system block only; no secrets).
///
/// Does **not** clear `pending_routstr_spend`. Unlock already `take()`s the
/// staged params into the in-flight effect. Clearing here would silently drop
/// a **newer** stage created while the prior spend task was still running
/// (no cancel notice). Leave any re-staged pending intact for the next unlock.
pub(super) fn handle_routstr_spend_completed(
    app: &mut AppView,
    agent_id: AgentId,
    result: Result<xai_grok_shell::auth::RoutstrSpendSuccess, String>,
) -> Vec<Effect> {
    match result {
        Ok(success) => {
            push_system_to_agent(app, agent_id, success.lines.join("\n"));
        }
        Err(message) => {
            push_system_to_agent(
                app,
                agent_id,
                format!("Spend failed (not broadcast unless explorer accepted):\n{message}"),
            );
        }
    }
    vec![]
}

/// Honest top-up stub (shared copy with CLI).
pub(super) fn dispatch_routstr_topup(app: &mut AppView, sats: Option<u64>) -> Vec<Effect> {
    let lines = grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(sats);
    push_system_lines_active(app, &lines);
    vec![]
}

/// Honest refund stub (shared copy with CLI).
pub(super) fn dispatch_routstr_refund(app: &mut AppView) -> Vec<Effect> {
    let lines = grok_bitcoin_wallet::funding_cli::refund_next_steps_lines();
    push_system_lines_active(app, &lines);
    vec![]
}

/// Start background watch for `address` on the **active** agent (slash path).
pub(super) fn dispatch_routstr_watch(app: &mut AppView, address: String) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    start_routstr_watch_for_agent(app, id, address, /*immediate*/ true)
}

/// Start watch bound to an explicit `agent_id` (async completions must use this).
///
/// Does **not** consult `app.active_view`. First poll is immediate when
/// `immediate` is true; subsequent re-arms sleep between polls.
///
/// Network comes from `GROK_BITCOIN_NETWORK` (brand-new watch). Resume paths
/// must call [`start_routstr_watch_for_agent_on_network`] with durable network.
///
/// **Singleton watch (intentional):** process-wide generation/address on
/// `AppView`, not per-agent concurrent watches. Tick *messages* still target
/// the owning `agent_id`. Semantics match
/// [`grok_bitcoin_wallet::watcher::WatchTaskLifecycle`] (`start` bumps
/// generation; stale ticks must be dropped via [`watch_tick_accepts`]).
pub(super) fn start_routstr_watch_for_agent(
    app: &mut AppView,
    agent_id: AgentId,
    address: String,
    immediate: bool,
) -> Vec<Effect> {
    start_routstr_watch_for_agent_on_network(app, agent_id, address, None, immediate)
}

/// Like [`start_routstr_watch_for_agent`] with an optional network override.
///
/// `network_override: Some` is used when resuming durable state so signet /
/// testnet watches are not rewritten to the env default. `None` reads env for
/// a brand-new watch (slash `/routstr watch`, fund complete).
pub(super) fn start_routstr_watch_for_agent_on_network(
    app: &mut AppView,
    agent_id: AgentId,
    address: String,
    network_override: Option<String>,
    immediate: bool,
) -> Vec<Effect> {
    let address = address.trim().to_owned();
    if address.is_empty() {
        push_system_to_agent(app, agent_id, "Watch requires a receive address.");
        return vec![];
    }
    if !app.agents.contains_key(&agent_id) {
        return vec![];
    }
    // Supersede note when another agent held the singleton watch.
    if let Some(prev_agent) = app.routstr_watch_agent_id
        && prev_agent != agent_id
        && app.routstr_watch_address.is_some()
    {
        push_system_to_agent(
            app,
            agent_id,
            "Note: superseding the process-wide address watch previously owned by another agent session.",
        );
        push_system_to_agent(
            app,
            prev_agent,
            "Address watch superseded by another agent session (singleton watch).",
        );
    }
    // Mirror WatchTaskLifecycle::start (bump generation, set address).
    app.routstr_watch_generation = app.routstr_watch_generation.saturating_add(1);
    let generation = app.routstr_watch_generation;
    app.routstr_watch_address = Some(address.clone());
    let network = match network_override {
        Some(n) if !n.trim().is_empty() => canonicalize_network(&n),
        _ => network_from_env(),
    };
    app.routstr_watch_network = Some(network.clone());
    app.routstr_watch_agent_id = Some(agent_id);
    app.routstr_watch_status = Some(format!("Watching {address}: starting"));
    app.routstr_watch_last_scrollback = None;
    app.routstr_watch_error_streak = 0;
    push_system_to_agent(
        app,
        agent_id,
        format!(
            "Watching receive address for deposits (mempool.space, ~{}s between polls). \
             Use /routstr stop to cancel. (One process-wide watch at a time.)",
            grok_bitcoin_wallet::watcher::DEFAULT_WATCH_POLL_INTERVAL.as_secs()
        ),
    );
    // Durable progress so a pager restart can re-arm (no BIP-39 in the file).
    persist_routstr_watch_running(&address, &network, generation);
    vec![Effect::RoutstrWatchLoop {
        agent_id,
        address,
        generation,
        network,
        skip_sleep: immediate,
    }]
}

pub(super) fn dispatch_routstr_watch_stop(app: &mut AppView) -> Vec<Effect> {
    if app.routstr_watch_address.is_none() && app.routstr_watch_generation == 0 {
        push_system_active(app, "No address watch is running.");
        return vec![];
    }
    // Mirror WatchTaskLifecycle::stop (bump generation while running, clear address).
    app.routstr_watch_generation = app.routstr_watch_generation.saturating_add(1);
    app.routstr_watch_address = None;
    app.routstr_watch_network = None;
    app.routstr_watch_agent_id = None;
    app.routstr_watch_status = None;
    app.routstr_watch_last_scrollback = None;
    app.routstr_watch_error_streak = 0;
    clear_persisted_routstr_watch();
    push_system_active(app, "Address watch stopped.");
    vec![]
}

/// Whether a watch tick should apply — same rule as
/// [`grok_bitcoin_wallet::watcher::WatchTaskLifecycle::accepts`].
fn watch_tick_accepts(app: &AppView, tick_generation: u64, address: &str) -> bool {
    app.routstr_watch_address.is_some()
        && app.routstr_watch_generation > 0
        && tick_generation == app.routstr_watch_generation
        && app.routstr_watch_address.as_deref() == Some(address)
}

/// Handle probe TaskResult: guide unlock or CLI for new wallet.
pub(super) fn handle_routstr_fund_probed(
    app: &mut AppView,
    agent_id: AgentId,
    probe: xai_grok_shell::auth::RoutstrFundProbe,
) -> Vec<Effect> {
    use xai_grok_shell::auth::RoutstrFundProbe;
    let Some(agent) = app.agents.get_mut(&agent_id) else {
        return vec![];
    };
    match probe {
        RoutstrFundProbe::NeedCliNewWallet { aead_hint } => {
            agent.scrollback.push_block(RenderBlock::system(format!(
                "No local Bitcoin wallet found.\n\
                 Creating a recovery phrase must happen in a private terminal so words \
                 are not written to chat history.\n\
                 Run: grok routstr fund\n\
                 Seed storage: OS keyring when available, otherwise {aead_hint}\n\
                 Never provider_credentials.json.\n\
                 After fund completes, run /routstr fund then /routstr unlock <phrase> here."
            )));
            vec![]
        }
        RoutstrFundProbe::KeyringBlocked { message } => {
            agent
                .scrollback
                .push_block(RenderBlock::system(format!("Fund blocked: {message}")));
            vec![]
        }
        RoutstrFundProbe::Error { message } => {
            agent
                .scrollback
                .push_block(RenderBlock::system(format!("Fund error: {message}")));
            vec![]
        }
        RoutstrFundProbe::NeedPassword => {
            agent.scrollback.push_block(RenderBlock::system(
                "Local wallet is password-wrapped. Unlock with:\n\
                 /routstr unlock pw:<password> <recovery phrase words…>\n\
                 Password must be a single token (no spaces). Words are not re-displayed.",
            ));
            vec![]
        }
        RoutstrFundProbe::NeedReentry => {
            agent.scrollback.push_block(RenderBlock::system(
                "Local wallet found. Re-enter your recovery phrase (not re-displayed):\n\
                 /routstr unlock <word1 word2 … word12>\n\
                 Then the receive address is shown and deposit watching can start.",
            ));
            vec![]
        }
    }
}

/// Handle fund complete TaskResult.
pub(super) fn handle_routstr_fund_completed(
    app: &mut AppView,
    agent_id: AgentId,
    result: Result<xai_grok_shell::auth::RoutstrFundSuccess, String>,
) -> Vec<Effect> {
    match result {
        Ok(success) => {
            present_receive_address(app, agent_id, &success.address, Some(&success.lines));
            // Bind watch to the task's agent, not active_view (multi-session safe).
            start_routstr_watch_for_agent(app, agent_id, success.address, /*immediate*/ true)
        }
        Err(e) => {
            push_system_to_agent(app, agent_id, format!("Fund failed: {e}"));
            vec![]
        }
    }
}

/// Show receive address + BIP21 QR and copy address to clipboard with toast.
///
/// `preamble_lines` are optional fund-success lines (status / network). Never
/// invents BOLT11; on-chain / BIP21 only.
pub(super) fn present_receive_address(
    app: &mut AppView,
    agent_id: AgentId,
    address: &str,
    preamble_lines: Option<&[String]>,
) {
    let address = address.trim();
    if address.is_empty() {
        push_system_to_agent(app, agent_id, "No receive address to display.");
        return;
    }
    let mut block_lines: Vec<String> = preamble_lines.map(|p| p.to_vec()).unwrap_or_default();
    let display_lines = grok_bitcoin_wallet::funding_cli::receive_address_display_lines(
        address, /*include_qr*/ true,
    );
    // Avoid duplicating the bare address line when preamble already printed it.
    for line in display_lines {
        if block_lines.iter().any(|existing| existing == &line) {
            continue;
        }
        block_lines.push(line);
    }
    let clipboard = grok_bitcoin_wallet::funding_cli::receive_address_clipboard(address);
    if let Some(agent) = app.agents.get_mut(&agent_id) {
        if !block_lines.is_empty() {
            agent
                .scrollback
                .push_block(RenderBlock::system(block_lines.join("\n")));
        }
        // Copy + toast (route-aware delivery message via clipboard helper).
        let _ = agent.copy_to_clipboard(&clipboard);
    }
}

/// `/routstr qr [address]` — re-show QR + copy for an address (or last watch).
pub(super) fn dispatch_routstr_qr(app: &mut AppView, address: Option<String>) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    let resolved = address
        .map(|a| a.trim().to_owned())
        .filter(|a| !a.is_empty())
        .or_else(|| app.routstr_watch_address.clone());
    match resolved {
        Some(addr) => {
            present_receive_address(app, id, &addr, None);
        }
        None => {
            push_system_to_agent(
                app,
                id,
                "Usage: /routstr qr <receive-address>\n\
                 Or start a watch first so /routstr qr can reuse that address.",
            );
        }
    }
    vec![]
}

/// Whether this tick status should also land in scrollback (transitions only).
///
/// For errors, call **before** incrementing `routstr_watch_error_streak` so
/// `WATCH_ERROR_SCROLLBACK_CAP` is the actual number of error lines allowed
/// (`streak < CAP` with streak still counting already-shown errors).
fn watch_tick_should_scrollback(
    app: &AppView,
    status_line: &str,
    confirmed: bool,
    is_error: bool,
) -> bool {
    if confirmed {
        return true;
    }
    if is_error {
        return app.routstr_watch_error_streak < WATCH_ERROR_SCROLLBACK_CAP;
    }
    app.routstr_watch_last_scrollback.as_deref() != Some(status_line)
}

/// Apply one watch tick if generation is still current.
pub(super) fn handle_routstr_watch_tick(
    app: &mut AppView,
    agent_id: AgentId,
    generation: u64,
    status_line: String,
    confirmed: bool,
    address: String,
) -> Vec<Effect> {
    // Keep in sync with WatchTaskLifecycle::accepts (singleton AppView fields).
    if !watch_tick_accepts(app, generation, &address) {
        return vec![];
    }
    app.routstr_watch_status = Some(status_line.clone());
    let is_error = status_line.starts_with("Watch error:");
    // Decide scrollback using the pre-increment streak so CAP means "this many
    // error lines", then bump (or reset) the streak for the next tick.
    if watch_tick_should_scrollback(app, &status_line, confirmed, is_error) {
        push_system_to_agent(app, agent_id, status_line.clone());
        if !is_error {
            app.routstr_watch_last_scrollback = Some(status_line.clone());
        }
    }
    if is_error {
        app.routstr_watch_error_streak = app.routstr_watch_error_streak.saturating_add(1);
    } else {
        app.routstr_watch_error_streak = 0;
    }
    if confirmed {
        app.routstr_watch_address = None;
        app.routstr_watch_network = None;
        app.routstr_watch_agent_id = None;
        app.routstr_watch_status = Some("Deposit confirmed enough for next funding steps.".into());
        app.routstr_watch_last_scrollback = None;
        app.routstr_watch_error_streak = 0;
        clear_persisted_routstr_watch();
        push_system_to_agent(
            app,
            agent_id,
            "Deposit has enough confirmations. Channel open / Cashu acquire remain residual. \
             Use /routstr topup for node float next steps.",
        );
        return vec![];
    }
    // Re-arm poll loop while generation is current (stop bumps generation).
    // Subsequent polls sleep first for rate-limit honesty.
    // Reuse in-memory / durable network — never re-read env (would rewrite
    // signet watches to mainnet when GROK_BITCOIN_NETWORK is unset).
    let network = app
        .routstr_watch_network
        .clone()
        .unwrap_or_else(network_from_env);
    vec![Effect::RoutstrWatchLoop {
        agent_id,
        address,
        generation,
        network,
        skip_sleep: false,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::actions::Action;
    use crate::app::dispatch::dispatch;
    use crate::app::dispatch::tests::test_app_with_agent;

    #[test]
    fn topup_and_refund_push_honest_copy() {
        let mut app = test_app_with_agent();
        let _ = dispatch(Action::RoutstrTopup { sats: Some(1000) }, &mut app);
        let _ = dispatch(Action::RoutstrRefund, &mut app);
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("not wired") || lower.contains("not available"),
            "expected honest stub wording: {text}"
        );
        assert!(!lower.contains("invoice created"));
    }

    #[test]
    fn fund_probe_effect_emitted() {
        let mut app = test_app_with_agent();
        let effects = dispatch(Action::RoutstrFund, &mut app);
        assert!(
            matches!(effects.first(), Some(Effect::RoutstrFundProbe { .. })),
            "expected probe effect: {effects:?}"
        );
    }

    #[test]
    fn spend_stages_pending_without_bip39_and_unlock_routes_to_spend() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let effects = dispatch(
            Action::RoutstrSpend {
                address: "bc1qdest".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: 5,
            },
            &mut app,
        );
        assert!(effects.is_empty());
        let pending = app.pending_routstr_spend.as_ref().expect("pending spend");
        assert_eq!(pending.address, "bc1qdest");
        assert_eq!(pending.amount_sats, 1000);
        assert!(!pending.broadcast);
        assert_eq!(pending.agent_id, AgentId(0));

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrSpendComplete {
                    amount_sats: 1000,
                    broadcast: false,
                    agent_id: AgentId(0),
                    ..
                })
            ),
            "unlock with pending spend must complete spend, not fund: {effects:?}"
        );
        assert!(
            app.pending_routstr_spend.is_none(),
            "pending consumed into effect"
        );
        let dbg = format!("{:?}", effects.first());
        assert!(!dbg.contains("abandon"), "Debug leaked phrase: {dbg}");
    }

    #[test]
    fn fund_clears_pending_spend_so_unlock_routes_to_fund() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qstale".into(),
                amount_sats: 99_000,
                broadcast: true,
                fee_rate_sat_vb: 5,
            },
            &mut app,
        );
        assert!(app.pending_routstr_spend.is_some());

        let effects = dispatch(Action::RoutstrFund, &mut app);
        assert!(
            matches!(effects.first(), Some(Effect::RoutstrFundProbe { .. })),
            "expected fund probe: {effects:?}"
        );
        assert!(
            app.pending_routstr_spend.is_none(),
            "fund must cancel staged spend so unlock cannot broadcast it"
        );
        // System copy should note cancellation.
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            text.to_ascii_lowercase().contains("cancelled staged spend"),
            "expected cancel notice: {text}"
        );

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
            },
            &mut app,
        );
        assert!(
            matches!(effects.first(), Some(Effect::RoutstrFundComplete { .. })),
            "after fund cancel, unlock must fund not spend: {effects:?}"
        );
        assert!(
            !matches!(effects.first(), Some(Effect::RoutstrSpendComplete { .. })),
            "must not complete stale spend: {effects:?}"
        );
    }

    #[test]
    fn unlock_rejects_spend_when_active_agent_differs_from_staging() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        crate::app::dispatch::tests::insert_placeholder_agent(&mut app, AgentId(1));
        // Stage on agent 0.
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qagent0".into(),
                amount_sats: 500,
                broadcast: true,
                fee_rate_sat_vb: 5,
            },
            &mut app,
        );
        assert_eq!(
            app.pending_routstr_spend.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
        // Switch to agent 1 and try unlock.
        app.active_view = ActiveView::Agent(AgentId(1));
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
            },
            &mut app,
        );
        assert!(
            effects.is_empty(),
            "cross-agent unlock must not authorize spend: {effects:?}"
        );
        assert!(
            app.pending_routstr_spend.is_some(),
            "pending must remain for the staging agent"
        );
        assert_eq!(
            app.pending_routstr_spend.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
    }

    #[test]
    fn spend_task_complete_does_not_drop_newer_staged_spend() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        // Stage A then unlock (consumes A into in-flight effect).
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qstage-a".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: 5,
            },
            &mut app,
        );
        let unlock_effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
            },
            &mut app,
        );
        assert!(
            matches!(
                unlock_effects.first(),
                Some(Effect::RoutstrSpendComplete {
                    amount_sats: 1000,
                    ..
                })
            ),
            "stage A unlock: {unlock_effects:?}"
        );
        assert!(app.pending_routstr_spend.is_none());

        // Re-stage B while A is still "in flight".
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qstage-b".into(),
                amount_sats: 2500,
                broadcast: true,
                fee_rate_sat_vb: 8,
            },
            &mut app,
        );
        let pending_b = app
            .pending_routstr_spend
            .as_ref()
            .expect("stage B must be pending");
        assert_eq!(pending_b.address, "bc1qstage-b");
        assert_eq!(pending_b.amount_sats, 2500);
        assert!(pending_b.broadcast);

        // Completion of A must not wipe B (no silent drop).
        let _ = handle_routstr_spend_completed(
            &mut app,
            AgentId(0),
            Ok(xai_grok_shell::auth::RoutstrSpendSuccess {
                payment_address: "bc1qstage-a".into(),
                payment_sats: 1000,
                fee_sats: 50,
                change_sats: 0,
                txid: "a".repeat(64),
                raw_hex: "ab".repeat(20),
                broadcast_txid: None,
                network_label: "mainnet".into(),
                lines: vec!["prepared stage A (simulated)".into()],
            }),
        );
        let still = app
            .pending_routstr_spend
            .as_ref()
            .expect("stage B must survive completion of A");
        assert_eq!(still.address, "bc1qstage-b");
        assert_eq!(still.amount_sats, 2500);
        assert!(still.broadcast);
        assert_eq!(still.fee_rate_sat_vb, 8);

        // Unlock still authorizes B, not a wiped/missing pending fund path.
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrSpendComplete {
                    amount_sats: 2500,
                    broadcast: true,
                    ..
                })
            ),
            "unlock after A complete must still spend B: {effects:?}"
        );
    }

    #[test]
    fn watch_start_and_stop_bump_generation() {
        let mut app = test_app_with_agent();
        let effects = dispatch(
            Action::RoutstrWatch {
                address: "bc1qtest0000000000000000000000000000".into(),
            },
            &mut app,
        );
        assert!(matches!(
            effects.first(),
            Some(Effect::RoutstrWatchLoop {
                generation: 1,
                skip_sleep: true,
                ..
            })
        ));
        assert_eq!(app.routstr_watch_generation, 1);
        assert_eq!(app.routstr_watch_agent_id, Some(AgentId(0)));
        let _ = dispatch(Action::RoutstrWatchStop, &mut app);
        assert_eq!(app.routstr_watch_generation, 2);
        assert!(app.routstr_watch_address.is_none());
        assert!(app.routstr_watch_agent_id.is_none());
    }

    #[test]
    fn watch_start_notes_when_superseding_other_agent() {
        let mut app = test_app_with_agent();
        // Second agent placeholder (same helper as multi-agent dispatch tests).
        crate::app::dispatch::tests::insert_placeholder_agent(&mut app, AgentId(1));
        let id0 = AgentId(0);
        let id1 = AgentId(1);
        let _ = start_routstr_watch_for_agent(
            &mut app,
            id0,
            "bc1qfirst0000000000000000000000000".into(),
            true,
        );
        let _ = start_routstr_watch_for_agent(
            &mut app,
            id1,
            "bc1qsecond000000000000000000000000".into(),
            true,
        );
        assert_eq!(app.routstr_watch_agent_id, Some(id1));
        let a1 = app.agents.get(&id1).unwrap();
        let t1: String = (0..a1.scrollback.len())
            .filter_map(|i| a1.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            t1.to_ascii_lowercase().contains("superseding"),
            "new owner should see supersede note: {t1}"
        );
        let a0 = app.agents.get(&id0).unwrap();
        let t0: String = (0..a0.scrollback.len())
            .filter_map(|i| a0.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            t0.to_ascii_lowercase().contains("superseded"),
            "previous owner should be notified: {t0}"
        );
    }

    #[test]
    fn stale_watch_tick_dropped() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        app.routstr_watch_generation = 2;
        app.routstr_watch_address = Some("bc1q".into());
        let effects = handle_routstr_watch_tick(
            &mut app,
            id,
            1, // stale
            "old".into(),
            false,
            "bc1q".into(),
        );
        assert!(effects.is_empty());
        assert_ne!(app.routstr_watch_status.as_deref(), Some("old"));
    }

    #[test]
    fn keyring_blocked_probe_does_not_mint() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        let _ = handle_routstr_fund_probed(
            &mut app,
            id,
            xai_grok_shell::auth::RoutstrFundProbe::KeyringBlocked {
                message: "could not read seed vault (down); not creating a new wallet.".into(),
            },
        );
        let agent = app.agents.get(&id).unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(text.contains("not creating a new wallet"));
        assert!(!text.to_ascii_lowercase().contains("generating a new"));
    }

    #[test]
    fn fund_complete_auto_watch_uses_task_agent_not_active_view() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        // Simulate user left agent view while unlock was in flight.
        app.active_view = ActiveView::Welcome;
        let effects = handle_routstr_fund_completed(
            &mut app,
            id,
            Ok(xai_grok_shell::auth::RoutstrFundSuccess {
                address: "bc1qfundcomplete000000000000000000".into(),
                network_label: "mainnet".into(),
                step_label: "showing receive address".into(),
                lines: vec!["ok".into()],
            }),
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrWatchLoop {
                    agent_id: AgentId(0),
                    skip_sleep: true,
                    ..
                })
            ),
            "auto-watch must target fund agent even when active_view is Welcome: {effects:?}"
        );
        assert_eq!(
            app.routstr_watch_address.as_deref(),
            Some("bc1qfundcomplete000000000000000000")
        );
    }

    #[test]
    fn fund_complete_shows_qr_and_sets_clipboard_toast_on_task_agent() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        let addr = "bc1q8zxz5kl6q30y2mzhx86gcwcz0t0hgzl2f2jpm5";
        let _ = handle_routstr_fund_completed(
            &mut app,
            id,
            Ok(xai_grok_shell::auth::RoutstrFundSuccess {
                address: addr.into(),
                network_label: "mainnet".into(),
                step_label: "showing receive address".into(),
                lines: vec![
                    "Backup confirmed. Receive address (mainnet):".into(),
                    addr.into(),
                ],
            }),
        );
        let agent = app.agents.get(&id).unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(text.contains(addr), "address must appear: {text}");
        assert!(
            text.contains("bitcoin:") || text.contains("BIP21"),
            "BIP21 / QR section expected: {text}"
        );
        // No fabricated BOLT11 in on-chain fund path.
        assert!(
            !text.to_ascii_lowercase().contains("lnbc"),
            "must not invent BOLT11: {text}"
        );
        // Clipboard toast on the fund agent (copy_to_clipboard path).
        assert!(
            agent.toast.is_some(),
            "expected clipboard toast after fund complete"
        );
        let toast = agent.toast.as_ref().map(|(m, _)| m.as_str()).unwrap_or("");
        assert!(
            toast.starts_with("Copied")
                || toast.starts_with("Copy sent")
                || toast.starts_with("Copy failed")
                || toast.to_ascii_lowercase().contains("clipboard"),
            "unexpected clipboard toast: {toast}"
        );
    }

    #[test]
    fn routstr_qr_uses_watch_address_when_none_given() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        app.routstr_watch_address = Some("bc1qwatchqr00000000000000000000000".into());
        let _ = dispatch(Action::RoutstrQr { address: None }, &mut app);
        let agent = app.agents.get(&id).unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            text.contains("bc1qwatchqr00000000000000000000000"),
            "qr must reuse watch address: {text}"
        );
        assert!(agent.toast.is_some(), "qr path should toast clipboard copy");
    }

    #[test]
    fn watch_tick_dedupes_identical_status_scrollback() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        app.routstr_watch_generation = 1;
        app.routstr_watch_address = Some("bc1q".into());
        let status = "Watching bc1q: waiting for payment".to_string();
        let e1 = handle_routstr_watch_tick(&mut app, id, 1, status.clone(), false, "bc1q".into());
        assert!(matches!(
            e1.first(),
            Some(Effect::RoutstrWatchLoop {
                skip_sleep: false,
                ..
            })
        ));
        let len_after_first = app.agents.get(&id).unwrap().scrollback.len();
        let _ = handle_routstr_watch_tick(&mut app, id, 1, status, false, "bc1q".into());
        let len_after_second = app.agents.get(&id).unwrap().scrollback.len();
        assert_eq!(
            len_after_first, len_after_second,
            "identical status must not spam scrollback"
        );
    }

    #[test]
    fn watch_error_scrollback_allows_exactly_cap_lines() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        app.routstr_watch_generation = 1;
        app.routstr_watch_address = Some("bc1q".into());
        let len0 = app.agents.get(&id).unwrap().scrollback.len();

        for i in 0..(WATCH_ERROR_SCROLLBACK_CAP + 2) {
            let status = format!("Watch error: transient {i}");
            let _ = handle_routstr_watch_tick(&mut app, id, 1, status, false, "bc1q".into());
            // Footer/status always updates even past the cap.
            assert!(
                app.routstr_watch_status
                    .as_deref()
                    .is_some_and(|s| s.starts_with("Watch error:")),
                "status must update on every error tick"
            );
        }

        let agent = app.agents.get(&id).unwrap();
        let error_blocks: usize = (len0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .filter(|t| t.contains("Watch error:"))
            .count();
        assert_eq!(
            error_blocks, WATCH_ERROR_SCROLLBACK_CAP as usize,
            "exactly CAP error lines should reach scrollback; got {error_blocks}"
        );
        assert_eq!(
            app.routstr_watch_error_streak,
            WATCH_ERROR_SCROLLBACK_CAP + 2,
            "streak counts every consecutive error, including past CAP"
        );
    }

    /// Durable signet watch must survive resume when env defaults to mainnet.
    #[test]
    fn resume_honors_durable_signet_network_not_env() {
        use grok_bitcoin_wallet::address_ux::BitcoinNetwork;
        use grok_bitcoin_wallet::cashu::FundingStep;
        use grok_bitcoin_wallet::watcher::{
            WatchSession, load_watch_session_state, save_watch_session_state,
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch_session.json");
        let addr = "tb1qtestsignet000000000000000000000";
        let txid = "a".repeat(64);

        let mut state = WatchSession::start(addr, BitcoinNetwork::Signet, 3).to_state(true);
        state.watched_txid = Some(txid.clone());
        state.confirmations = 1;
        state.step = FundingStep::WatchingTx.as_wire_str().into();
        state.generation = 7;
        save_watch_session_state(&path, &state).unwrap();

        with_watch_session_path_for_test(path.clone(), || {
            let mut app = test_app_with_agent();
            // Brand-new watch without override would use env/mainnet; resume must
            // ignore that and keep durable signet (regression for Issue 1).
            let effects = try_resume_persisted_routstr_watch_for_agent(&mut app, AgentId(0));
            assert!(
                matches!(
                    effects.first(),
                    Some(Effect::RoutstrWatchLoop {
                        network,
                        skip_sleep: true,
                        ..
                    }) if network == "signet"
                ),
                "resume effect must keep durable signet, got {effects:?}"
            );
            assert_eq!(app.routstr_watch_network.as_deref(), Some("signet"));
            assert_eq!(app.routstr_watch_address.as_deref(), Some(addr));

            // Re-persist must not rewrite network to env default.
            let reloaded = load_watch_session_state(&path).unwrap().expect("file");
            assert_eq!(reloaded.network, "signet");
            assert!(reloaded.should_resume());
            assert_eq!(reloaded.watched_txid.as_deref(), Some(txid.as_str()));
            assert_eq!(reloaded.confirmations, 1);

            // Re-arm tick must also keep signet (not re-read env).
            let generation = app.routstr_watch_generation;
            let rearm = handle_routstr_watch_tick(
                &mut app,
                AgentId(0),
                generation,
                "Watching: waiting".into(),
                false,
                addr.into(),
            );
            assert!(
                matches!(
                    rearm.first(),
                    Some(Effect::RoutstrWatchLoop { network, .. }) if network == "signet"
                ),
                "re-arm must keep signet: {rearm:?}"
            );
        });
    }

    #[test]
    fn watch_persist_start_stop_and_no_resume_after_stop() {
        use grok_bitcoin_wallet::watcher::load_watch_session_state;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch_session.json");
        let addr = "bc1qpersisttest0000000000000000000";

        with_watch_session_path_for_test(path.clone(), || {
            let mut app = test_app_with_agent();
            let effects = start_routstr_watch_for_agent_on_network(
                &mut app,
                AgentId(0),
                addr.into(),
                Some("testnet".into()),
                true,
            );
            assert!(
                matches!(
                    effects.first(),
                    Some(Effect::RoutstrWatchLoop {
                        network,
                        ..
                    }) if network == "testnet"
                ),
                "{effects:?}"
            );
            let loaded = load_watch_session_state(&path).unwrap().expect("persisted");
            assert_eq!(loaded.network, "testnet");
            assert_eq!(loaded.address, addr);
            assert!(loaded.should_resume());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "pager persist must write 0600");
            }

            let _ = dispatch(Action::RoutstrWatchStop, &mut app);
            assert!(app.routstr_watch_address.is_none());
            assert!(app.routstr_watch_network.is_none());
            // File unlinked (or non-resumable).
            let after = load_watch_session_state(&path).unwrap();
            assert!(
                after.as_ref().is_none_or(|s| !s.should_resume()),
                "stop must not leave resumable state: {after:?}"
            );

            // Fresh app must not re-arm.
            let mut app2 = test_app_with_agent();
            let resume = try_resume_persisted_routstr_watch_for_agent(&mut app2, AgentId(0));
            assert!(resume.is_empty(), "must not resume after stop: {resume:?}");
        });
    }

    #[test]
    fn watch_confirm_clears_durable_and_does_not_resume() {
        use grok_bitcoin_wallet::watcher::load_watch_session_state;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch_session.json");
        let addr = "bc1qconfirmtest000000000000000000";

        with_watch_session_path_for_test(path.clone(), || {
            let mut app = test_app_with_agent();
            let _ = start_routstr_watch_for_agent(&mut app, AgentId(0), addr.into(), true);
            assert!(path.exists());
            let generation = app.routstr_watch_generation;
            let effects = handle_routstr_watch_tick(
                &mut app,
                AgentId(0),
                generation,
                "confirmed enough".into(),
                true,
                addr.into(),
            );
            assert!(effects.is_empty());
            assert!(app.routstr_watch_address.is_none());
            assert!(app.routstr_watch_network.is_none());
            let after = load_watch_session_state(&path).unwrap();
            assert!(
                after.as_ref().is_none_or(|s| !s.should_resume()),
                "confirm must clear/stop durable: {after:?}"
            );
            let mut app2 = test_app_with_agent();
            assert!(try_resume_persisted_routstr_watch_for_agent(&mut app2, AgentId(0)).is_empty());
        });
    }

    #[test]
    fn without_path_override_unit_tests_skip_durable_fs() {
        // Default cfg!(test) without override must not touch real GROK_HOME.
        assert!(!watch_persistence_enabled());
        let mut app = test_app_with_agent();
        assert!(try_resume_persisted_routstr_watch_for_agent(&mut app, AgentId(0)).is_empty());
    }
}
