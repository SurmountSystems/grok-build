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

/// Product-network wire for a brand-new watch (`GROK_BITCOIN_NETWORK`).
///
/// Same acceptance as fund/spend/utxos: `mainnet|signet|testnet|testnet4`
/// (empty/unset → mainnet). Unknown labels (incl. `regtest`) **fail closed** —
/// never raw env garbage and never silent Mainnet (unlike fees soft-default).
fn network_from_env() -> Result<String, String> {
    xai_grok_shell::auth::routstr::resolve_product_entry_network(None)
        .map(|n| n.as_str().to_owned())
        .map_err(|e| e.to_string())
}

/// Canonical product-network wire label (fail-closed).
///
/// Empty → mainnet. Known labels → `BitcoinNetwork::as_str()`. Unknown /
/// `regtest` → error (same text shape as shell product complete resolve).
/// Does **not** fall back to env (resume must honor durable network only).
fn canonicalize_network(network: &str) -> Result<String, String> {
    xai_grok_shell::auth::routstr::resolve_product_complete_network(network)
        .map(|n| n.as_str().to_owned())
        .map_err(|e| e.to_string())
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
    // Fail closed: never silent-Mainnet rewrite of regtest/unknown wire.
    let Some(net) = BitcoinNetwork::from_env_str(network) else {
        tracing::warn!(
            network,
            "persist routstr watch session skipped: unknown network (not soft-defaulting to mainnet)"
        );
        return;
    };
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
    // Durable network must be a product label; regtest/unknown fail closed
    // (do not invent Mainnet — matches fund/spend acceptance).
    let network = match canonicalize_network(&state.network) {
        Ok(n) => n,
        Err(msg) => {
            tracing::warn!(
                network = %state.network,
                error = %msg,
                "resume routstr watch failed: durable network not product-accepted"
            );
            push_system_to_agent(
                app,
                agent_id,
                format!(
                    "Cannot resume deposit watch for {address}: {msg}. \
                     Fix watch_session network or GROK_BITCOIN_NETWORK \
                     (mainnet|signet|testnet|testnet4) and re-run /routstr watch."
                ),
            );
            return vec![];
        }
    };
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

/// Drop private BIP-39 passphrase modal secrets if open (no durable write).
///
/// Returns `true` when a modal was cleared. Does not touch staged money paths.
fn clear_routstr_passphrase_modal(app: &mut AppView, reason: &str) -> bool {
    let Some(mut modal) = app.routstr_passphrase_modal.take() else {
        return false;
    };
    let agent_id = modal.agent_id;
    modal.clear_secrets();
    push_system_to_agent(
        app,
        agent_id,
        format!(
            "Cancelled private BIP-39 passphrase entry ({reason}). \
             Staged spend/rbf/cpfp/utxos (if any) is unchanged — re-run /routstr unlock to authorize."
        ),
    );
    true
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

/// Cancel a staged RBF if present; notify the staging agent.
///
/// Returns `true` when a pending rbf was cleared.
fn clear_pending_routstr_rbf(app: &mut AppView, reason: &str) -> bool {
    let Some(pending) = app.pending_routstr_rbf.take() else {
        return false;
    };
    push_system_to_agent(
        app,
        pending.agent_id,
        format!(
            "Cancelled staged RBF ({reason}): {} sats → {} (original fee {} sats, {} input(s)).",
            pending.amount_sats,
            pending.address,
            pending.original_fee_sats,
            pending.input_specs.len()
        ),
    );
    true
}

/// Cancel a staged CPFP if present; notify the staging agent.
///
/// Returns `true` when a pending cpfp was cleared.
fn clear_pending_routstr_cpfp(app: &mut AppView, reason: &str) -> bool {
    let Some(pending) = app.pending_routstr_cpfp.take() else {
        return false;
    };
    push_system_to_agent(
        app,
        pending.agent_id,
        format!(
            "Cancelled staged CPFP ({reason}): {} sats → {} (parent fee {} sats, {} parent(s)).",
            pending.amount_sats,
            pending.address,
            pending.parent_fee_sats,
            pending.parent_specs.len()
        ),
    );
    true
}

/// Cancel a staged UTXO list if present; notify the staging agent.
///
/// Returns `true` when a pending utxos was cleared.
fn clear_pending_routstr_utxos(app: &mut AppView, reason: &str) -> bool {
    let Some(pending) = app.pending_routstr_utxos.take() else {
        return false;
    };
    let net = pending
        .network
        .as_deref()
        .map(|n| format!(" network={n}"))
        .unwrap_or_default();
    push_system_to_agent(
        app,
        pending.agent_id,
        format!("Cancelled staged UTXO list ({reason}){net}."),
    );
    true
}

/// `/routstr fund` — probe vault (async); never mint on keyring errors.
///
/// Also cancels any staged `/routstr spend`, `/routstr rbf`, `/routstr cpfp`,
/// or `/routstr utxos` so unlock cannot authorize a stale (possibly broadcast)
/// money path or a leftover observational stage after the user switched to fund.
pub(super) fn dispatch_routstr_fund(app: &mut AppView) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        // No agent view: cannot show system block either.
        return vec![];
    };
    let _ = clear_routstr_passphrase_modal(app, "running /routstr fund");
    let _ = clear_pending_routstr_spend(app, "running /routstr fund");
    let _ = clear_pending_routstr_rbf(app, "running /routstr fund");
    let _ = clear_pending_routstr_cpfp(app, "running /routstr fund");
    let _ = clear_pending_routstr_utxos(app, "running /routstr fund");
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

/// Complete re-entry after `/routstr unlock <phrase>` (optional `pass` modal).
///
/// If a pending spend, rbf, cpfp, or utxos was staged, unlock authorizes that
/// path (not fund). BIP-39 never enters chat history — only the unlock path
/// carries [`SensitiveString`] into a blocking task.
///
/// When `request_passphrase_prompt` is true, opens the private masked modal
/// and leaves staged spend/rbf/cpfp/utxos paths intact until submit/cancel. Env
/// passphrase is used only when the flag is false (`bip39_passphrase: None` on
/// effects).
///
/// Completion is bound to the **staging** agent (`pending.agent_id`), not merely
/// the current active view, so switching agents cannot mis-route a staged path.
/// Spend, rbf, cpfp, and utxos are mutually exclusive pending states.
pub(super) fn dispatch_routstr_fund_reentry(
    app: &mut AppView,
    phrase: crate::app::actions::SensitiveString,
    password: Option<crate::app::actions::SensitiveString>,
    request_passphrase_prompt: bool,
) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    if phrase.is_empty() {
        push_system_to_agent(app, id, "Recovery phrase re-entry cancelled.");
        return vec![];
    }
    // Supersede any prior open passphrase modal (new unlock owns secrets).
    if app.routstr_passphrase_modal.is_some() {
        let _ = clear_routstr_passphrase_modal(app, "superseded by a new /routstr unlock");
    }
    if request_passphrase_prompt {
        app.routstr_passphrase_modal = Some(
            crate::app::app_view::RoutstrPassphraseModalState::new(id, phrase, password),
        );
        push_system_to_agent(
            app,
            id,
            "Private BIP-39 passphrase entry open (masked; not stored in chat). \
             Enter empty for default path, or type your passphrase then Enter. \
             Esc cancels unlock and keeps any staged spend/rbf/cpfp/utxos. \
             Env GROK_BITCOIN_BIP39_PASSPHRASE is ignored for this unlock while the modal is used.",
        );
        return vec![];
    }
    complete_routstr_unlock_with_secrets(app, id, phrase, password, None)
}

/// Submit typed passphrase from the private modal → complete unlock.
///
/// Input layer already took the modal and moved secrets + **originating**
/// `agent_id` into this action. Unlock completes for that agent only — never
/// silently follow a different `active_view` if the user (or lifecycle) switched
/// mid-entry. Residual modal slot is cleared (supersede race).
pub(super) fn dispatch_routstr_bip39_passphrase_submit(
    app: &mut AppView,
    agent_id: AgentId,
    phrase: crate::app::actions::SensitiveString,
    password: Option<crate::app::actions::SensitiveString>,
    passphrase: crate::app::actions::SensitiveString,
) -> Vec<Effect> {
    // Drop any leftover modal (should already be None after input take).
    if let Some(mut leftover) = app.routstr_passphrase_modal.take() {
        leftover.clear_secrets();
    }
    // Hard-fail if active view is not the modal-bound agent: secrets are already
    // off the modal; drop them without completing against the wrong agent/fund path.
    match app.active_view {
        ActiveView::Agent(active) if active == agent_id => {}
        ActiveView::Agent(active) => {
            push_system_to_agent(
                app,
                active,
                format!(
                    "Private BIP-39 passphrase submit discarded: unlock was started for \
                     agent {agent_id:?}, but agent {active:?} is active. Switch back to \
                     agent {agent_id:?} and re-run /routstr unlock pass."
                ),
            );
            push_system_to_agent(
                app,
                agent_id,
                "Private BIP-39 passphrase submit discarded: active view changed mid-entry. \
                 Re-run /routstr unlock pass on this agent (staged money path unchanged if still set)."
                    .to_owned(),
            );
            return vec![];
        }
        _ => {
            // No agent view — cannot complete money/fund path safely.
            return vec![];
        }
    }
    complete_routstr_unlock_with_secrets(app, agent_id, phrase, password, Some(passphrase))
}

/// Cancel private passphrase modal; leave staged money path for re-unlock.
pub(super) fn dispatch_routstr_bip39_passphrase_cancel(app: &mut AppView) -> Vec<Effect> {
    let _ = clear_routstr_passphrase_modal(app, "user cancelled");
    vec![]
}

/// Shared unlock completion after phrase is known and optional modal passphrase
/// resolved. `bip39_passphrase: None` → shell uses env; `Some` (incl. empty) →
/// explicit modal value for this unlock only.
fn complete_routstr_unlock_with_secrets(
    app: &mut AppView,
    id: AgentId,
    phrase: crate::app::actions::SensitiveString,
    password: Option<crate::app::actions::SensitiveString>,
    bip39_passphrase: Option<crate::app::actions::SensitiveString>,
) -> Vec<Effect> {
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
            bip39_passphrase,
            address: pending.address,
            amount_sats: pending.amount_sats,
            broadcast: pending.broadcast,
            fee_rate_sat_vb: pending.fee_rate_sat_vb,
        }];
    }
    if let Some(pending) = app.pending_routstr_rbf.take() {
        if pending.agent_id != id {
            let staging = pending.agent_id;
            app.pending_routstr_rbf = Some(pending);
            push_system_to_agent(
                app,
                id,
                format!(
                    "Staged RBF belongs to another agent session (agent {staging:?}). \
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
                "Authorizing RBF replacement ({mode}): {} sats → {} (original fee {} sats, {} input(s)). \
                 Recovery phrase is not stored in chat.",
                pending.amount_sats,
                pending.address,
                pending.original_fee_sats,
                pending.input_specs.len()
            ),
        );
        return vec![Effect::RoutstrRbfComplete {
            agent_id: pending.agent_id,
            grok_home: grok_home(),
            phrase,
            password,
            bip39_passphrase,
            address: pending.address,
            amount_sats: pending.amount_sats,
            original_fee_sats: pending.original_fee_sats,
            original_vbytes: pending.original_vbytes,
            input_specs: pending.input_specs,
            broadcast: pending.broadcast,
            fee_rate_sat_vb: pending.fee_rate_sat_vb,
        }];
    }
    if let Some(pending) = app.pending_routstr_cpfp.take() {
        if pending.agent_id != id {
            let staging = pending.agent_id;
            app.pending_routstr_cpfp = Some(pending);
            push_system_to_agent(
                app,
                id,
                format!(
                    "Staged CPFP belongs to another agent session (agent {staging:?}). \
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
                "Authorizing CPFP child ({mode}): {} sats → {} (parent fee {} sats, {} parent(s)). \
                 Child only — does not replace the parent. Recovery phrase is not stored in chat.",
                pending.amount_sats,
                pending.address,
                pending.parent_fee_sats,
                pending.parent_specs.len()
            ),
        );
        return vec![Effect::RoutstrCpfpComplete {
            agent_id: pending.agent_id,
            grok_home: grok_home(),
            phrase,
            password,
            bip39_passphrase,
            address: pending.address,
            amount_sats: pending.amount_sats,
            parent_fee_sats: pending.parent_fee_sats,
            parent_vbytes: pending.parent_vbytes,
            parent_specs: pending.parent_specs,
            extra_input_specs: pending.extra_input_specs,
            broadcast: pending.broadcast,
            fee_rate_sat_vb: pending.fee_rate_sat_vb,
        }];
    }
    if let Some(pending) = app.pending_routstr_utxos.take() {
        if pending.agent_id != id {
            let staging = pending.agent_id;
            app.pending_routstr_utxos = Some(pending);
            push_system_to_agent(
                app,
                id,
                format!(
                    "Staged UTXO list belongs to another agent session (agent {staging:?}). \
                     Switch back to that agent and run /routstr unlock there, or cancel \
                     with /routstr fund on the staging agent."
                ),
            );
            return vec![];
        }
        let net = pending.network.as_deref().unwrap_or("env/default mainnet");
        push_system_to_agent(
            app,
            pending.agent_id,
            format!(
                "Authorizing UTXO list (observational, network={net}). \
                 Recovery phrase is not stored in chat. No broadcast."
            ),
        );
        return vec![Effect::RoutstrUtxosComplete {
            agent_id: pending.agent_id,
            grok_home: grok_home(),
            phrase,
            password,
            bip39_passphrase,
            network: pending.network,
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
        bip39_passphrase,
    }]
}

/// Stage `/routstr spend` then require unlock re-entry (no BIP-39 on this action).
///
/// `fee_rate_sat_vb`: `Some(n)` is an explicit user rate; `None` is resolved
/// later in the spend effect (explorer halfHour or default 5) — not here.
///
/// Staging spend cancels any pending rbf/cpfp/utxos (and supersedes a prior spend).
pub(super) fn dispatch_routstr_spend(
    app: &mut AppView,
    address: String,
    amount_sats: u64,
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    if app.routstr_passphrase_modal.is_some() {
        let _ = clear_routstr_passphrase_modal(app, "superseded by /routstr spend");
    }
    if app.pending_routstr_spend.is_some() {
        let _ = clear_pending_routstr_spend(app, "superseded by a new /routstr spend");
    }
    if app.pending_routstr_rbf.is_some() {
        let _ = clear_pending_routstr_rbf(app, "superseded by /routstr spend");
    }
    if app.pending_routstr_cpfp.is_some() {
        let _ = clear_pending_routstr_cpfp(app, "superseded by /routstr spend");
    }
    if app.pending_routstr_utxos.is_some() {
        let _ = clear_pending_routstr_utxos(app, "superseded by /routstr spend");
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
    let fee_line = match fee_rate_sat_vb {
        Some(n) => format!("{n} sat/vB"),
        None => {
            "explorer halfHour when available, else 5 sat/vB (resolved at authorize)".to_owned()
        }
    };
    push_system_to_agent(
        app,
        id,
        format!(
            "Staged on-chain spend ({mode}): {amount_sats} sats → {address} (fee rate {fee_line}).\n\
             Authorize with: /routstr unlock <recovery phrase words…>\n\
             Optional private BIP-39 passphrase: /routstr unlock pass <phrase…>\n\
             Optional AEAD password: /routstr unlock [pass] pw:<password> <phrase…>\n\
             Env GROK_BITCOIN_BIP39_PASSPHRASE still applies without the pass flag.\n\
             Recovery words are never stored in chat history. Cancel by staging a different spend/rbf/cpfp/utxos or running /routstr fund \
             (fund cancels any staged money path so unlock cannot broadcast a stale one)."
        ),
    );
    vec![]
}

/// Stage `/routstr rbf` then require unlock re-entry (no BIP-39 on this action).
///
/// Same-input BIP-125 only: `input_specs` are `txid:vout:amount:address` from
/// prior spend dry-run meta. Fee resolve only at authorize when not explicit.
/// Staging rbf cancels any pending spend/cpfp/utxos (and supersedes a prior rbf).
///
/// Argument count mirrors [`crate::app::actions::Action::RoutstrRbf`] fields
/// plus `app` (same pattern as spend dispatch; keep flat for router matching).
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_routstr_rbf(
    app: &mut AppView,
    address: String,
    amount_sats: u64,
    original_fee_sats: u64,
    original_vbytes: u64,
    input_specs: Vec<String>,
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    if app.routstr_passphrase_modal.is_some() {
        let _ = clear_routstr_passphrase_modal(app, "superseded by /routstr rbf");
    }
    if app.pending_routstr_rbf.is_some() {
        let _ = clear_pending_routstr_rbf(app, "superseded by a new /routstr rbf");
    }
    if app.pending_routstr_spend.is_some() {
        let _ = clear_pending_routstr_spend(app, "superseded by /routstr rbf");
    }
    if app.pending_routstr_cpfp.is_some() {
        let _ = clear_pending_routstr_cpfp(app, "superseded by /routstr rbf");
    }
    if app.pending_routstr_utxos.is_some() {
        let _ = clear_pending_routstr_utxos(app, "superseded by /routstr rbf");
    }
    let n_inputs = input_specs.len();
    app.pending_routstr_rbf = Some(crate::app::app_view::PendingRoutstrRbf {
        agent_id: id,
        address: address.clone(),
        amount_sats,
        original_fee_sats,
        original_vbytes,
        input_specs,
        broadcast,
        fee_rate_sat_vb,
    });
    let mode = if broadcast {
        "with network broadcast"
    } else {
        "dry-run only (not broadcast)"
    };
    let fee_line = match fee_rate_sat_vb {
        Some(n) => format!("{n} sat/vB target"),
        None => {
            "explorer halfHour when available, else 5 sat/vB (resolved at authorize)".to_owned()
        }
    };
    push_system_to_agent(
        app,
        id,
        format!(
            "Staged same-input RBF ({mode}): {amount_sats} sats → {address}\n\
             Original fee {original_fee_sats} sats / {original_vbytes} vB; {n_inputs} input(s); \
             target fee rate {fee_line}.\n\
             Authorize with: /routstr unlock <recovery phrase words…>\n\
             Optional private BIP-39 passphrase: /routstr unlock pass <phrase…>\n\
             Optional AEAD password: /routstr unlock [pass] pw:<password> <phrase…>\n\
             Env GROK_BITCOIN_BIP39_PASSPHRASE still applies without the pass flag.\n\
             Recovery words are never stored in chat history. Cancel by staging a different rbf/spend/cpfp/utxos or running /routstr fund \
             (fund cancels any staged money path so unlock cannot broadcast a stale one)."
        ),
    );
    vec![]
}

/// Stage `/routstr cpfp` then require unlock re-entry (no BIP-39 on this action).
///
/// CPFP **child** only: `parent_specs` (and optional `extra_input_specs`) are
/// `txid:vout:amount:address`. Fee resolve only at authorize when not explicit.
/// Staging cpfp cancels any pending spend/rbf/utxos (and supersedes a prior cpfp).
/// Never claims the parent was replaced.
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_routstr_cpfp(
    app: &mut AppView,
    address: String,
    amount_sats: u64,
    parent_fee_sats: u64,
    parent_vbytes: u64,
    parent_specs: Vec<String>,
    extra_input_specs: Vec<String>,
    broadcast: bool,
    fee_rate_sat_vb: Option<u64>,
) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    if app.routstr_passphrase_modal.is_some() {
        let _ = clear_routstr_passphrase_modal(app, "superseded by /routstr cpfp");
    }
    if app.pending_routstr_cpfp.is_some() {
        let _ = clear_pending_routstr_cpfp(app, "superseded by a new /routstr cpfp");
    }
    if app.pending_routstr_spend.is_some() {
        let _ = clear_pending_routstr_spend(app, "superseded by /routstr cpfp");
    }
    if app.pending_routstr_rbf.is_some() {
        let _ = clear_pending_routstr_rbf(app, "superseded by /routstr cpfp");
    }
    if app.pending_routstr_utxos.is_some() {
        let _ = clear_pending_routstr_utxos(app, "superseded by /routstr cpfp");
    }
    let n_parents = parent_specs.len();
    let n_extras = extra_input_specs.len();
    app.pending_routstr_cpfp = Some(crate::app::app_view::PendingRoutstrCpfp {
        agent_id: id,
        address: address.clone(),
        amount_sats,
        parent_fee_sats,
        parent_vbytes,
        parent_specs,
        extra_input_specs,
        broadcast,
        fee_rate_sat_vb,
    });
    let mode = if broadcast {
        "with network broadcast"
    } else {
        "dry-run only (not broadcast)"
    };
    let fee_line = match fee_rate_sat_vb {
        Some(n) => format!("{n} sat/vB package target"),
        None => {
            "explorer halfHour when available, else 5 sat/vB (resolved at authorize)".to_owned()
        }
    };
    push_system_to_agent(
        app,
        id,
        format!(
            "Staged CPFP child ({mode}): {amount_sats} sats → {address}\n\
             Parent fee {parent_fee_sats} sats / {parent_vbytes} vB; {n_parents} parent outpoint(s)\
             {}; package target fee rate {fee_line}.\n\
             Child only — does **not** replace the parent.\n\
             Authorize with: /routstr unlock <recovery phrase words…>\n\
             Optional private BIP-39 passphrase: /routstr unlock pass <phrase…>\n\
             Optional AEAD password: /routstr unlock [pass] pw:<password> <phrase…>\n\
             Env GROK_BITCOIN_BIP39_PASSPHRASE still applies without the pass flag.\n\
             Recovery words are never stored in chat history. Cancel by staging a different cpfp/spend/rbf/utxos or running /routstr fund \
             (fund cancels any staged money path so unlock cannot broadcast a stale one).",
            if n_extras > 0 {
                format!(", {n_extras} extra input(s)")
            } else {
                String::new()
            }
        ),
    );
    vec![]
}

/// Stage `/routstr utxos` then require unlock re-entry (no BIP-39 on this action).
///
/// Observational only — gap-limit ChainSource UTXO list / on-chain balance.
/// Optional `network` mirrors CLI `--network` (already validated at slash parse
/// via the product resolver). Staging utxos cancels any pending spend/rbf/cpfp
/// (and supersedes a prior utxos). Never broadcasts.
pub(super) fn dispatch_routstr_utxos(app: &mut AppView, network: Option<String>) -> Vec<Effect> {
    let ActiveView::Agent(id) = app.active_view else {
        return vec![];
    };
    if app.routstr_passphrase_modal.is_some() {
        let _ = clear_routstr_passphrase_modal(app, "superseded by /routstr utxos");
    }
    if app.pending_routstr_utxos.is_some() {
        let _ = clear_pending_routstr_utxos(app, "superseded by a new /routstr utxos");
    }
    if app.pending_routstr_spend.is_some() {
        let _ = clear_pending_routstr_spend(app, "superseded by /routstr utxos");
    }
    if app.pending_routstr_rbf.is_some() {
        let _ = clear_pending_routstr_rbf(app, "superseded by /routstr utxos");
    }
    if app.pending_routstr_cpfp.is_some() {
        let _ = clear_pending_routstr_cpfp(app, "superseded by /routstr utxos");
    }
    app.pending_routstr_utxos = Some(crate::app::app_view::PendingRoutstrUtxos {
        agent_id: id,
        network: network.clone(),
    });
    let net_line = match network.as_deref() {
        Some(n) => n.to_owned(),
        None => "GROK_BITCOIN_NETWORK or mainnet (resolved at authorize)".to_owned(),
    };
    push_system_to_agent(
        app,
        id,
        format!(
            "Staged UTXO list (observational, gap-limit ChainSource sync; network={net_line}).\n\
             Authorize with: /routstr unlock <recovery phrase words…>\n\
             Optional private BIP-39 passphrase: /routstr unlock pass <phrase…>\n\
             Optional AEAD password: /routstr unlock [pass] pw:<password> <phrase…>\n\
             Env GROK_BITCOIN_BIP39_PASSPHRASE still applies without the pass flag.\n\
             Recovery words are never stored in chat history. No broadcast. Cancel by staging \
             spend/rbf/cpfp/utxos or running /routstr fund."
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

/// Handle RBF task result (system block only; no secrets).
///
/// Same non-clear rule as spend: do not drop a newer staged rbf/spend/cpfp that
/// may have been created while this task was in flight.
pub(super) fn handle_routstr_rbf_completed(
    app: &mut AppView,
    agent_id: AgentId,
    result: Result<xai_grok_shell::auth::RoutstrRbfSuccess, String>,
) -> Vec<Effect> {
    match result {
        Ok(success) => {
            push_system_to_agent(app, agent_id, success.lines.join("\n"));
        }
        Err(message) => {
            push_system_to_agent(
                app,
                agent_id,
                format!(
                    "RBF replacement failed (not broadcast unless explorer accepted):\n{message}"
                ),
            );
        }
    }
    vec![]
}

/// Handle CPFP task result (system block only; no secrets).
///
/// Same non-clear rule as spend/rbf: do not drop a newer staged money path that
/// may have been created while this task was in flight.
pub(super) fn handle_routstr_cpfp_completed(
    app: &mut AppView,
    agent_id: AgentId,
    result: Result<xai_grok_shell::auth::RoutstrCpfpSuccess, String>,
) -> Vec<Effect> {
    match result {
        Ok(success) => {
            push_system_to_agent(app, agent_id, success.lines.join("\n"));
        }
        Err(message) => {
            push_system_to_agent(
                app,
                agent_id,
                format!(
                    "CPFP child failed (not broadcast unless explorer accepted; parent not replaced):\n{message}"
                ),
            );
        }
    }
    vec![]
}

/// Handle UTXO list task result (system block only; no secrets).
///
/// Same non-clear rule as spend: do not drop a newer staged utxos/spend path
/// that may have been created while this task was in flight.
pub(super) fn handle_routstr_utxos_completed(
    app: &mut AppView,
    agent_id: AgentId,
    result: Result<xai_grok_shell::auth::RoutstrUtxosSuccess, String>,
) -> Vec<Effect> {
    match result {
        Ok(success) => {
            push_system_to_agent(app, agent_id, success.lines.join("\n"));
        }
        Err(message) => {
            push_system_to_agent(
                app,
                agent_id,
                format!("UTXO list failed (observational; nothing broadcast):\n{message}"),
            );
        }
    }
    vec![]
}

/// Honest top-up stub (shared copy with CLI).
pub(super) fn dispatch_routstr_topup(app: &mut AppView, sats: Option<u64>) -> Vec<Effect> {
    // TUI: try live create without long poll (user can `/routstr topup` again or CLI --status).
    let lines = match xai_grok_shell::auth::create_routstr_lightning_invoice(
        grok_bitcoin_wallet::routstr_invoice::resolve_topup_amount_sats(sats).unwrap_or(
            grok_bitcoin_wallet::routstr_invoice::ROUTSTR_INVOICE_DEFAULT_SATS,
        ),
    ) {
        Ok(created) => {
            let mut lines =
                grok_bitcoin_wallet::routstr_invoice::live_invoice_display_lines(&created, true);
            lines.push(format!(
                "After paying, run CLI: grok routstr topup --status {}",
                created.invoice_id
            ));
            lines
        }
        Err(e) => {
            let mut lines = vec![
                format!("Routstr live invoice create failed: {e}"),
                "Falling back to residual next-steps (no fabricated invoice).".to_owned(),
            ];
            lines.extend(grok_bitcoin_wallet::funding_cli::topup_next_steps_lines(sats));
            lines
        }
    };
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
/// Network comes from product resolve of `GROK_BITCOIN_NETWORK` (brand-new
/// watch; fail-closed). Resume paths must call
/// [`start_routstr_watch_for_agent_on_network`] with durable network.
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
/// a brand-new watch (slash `/routstr watch`). Fund complete passes the
/// already-resolved product network label.
///
/// Unknown / `regtest` (env or override) **fail closed**: no generation bump,
/// no in-memory watch fields, no persist, no [`Effect::RoutstrWatchLoop`].
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
    // Resolve product network **before** arming (fail closed: no start / persist).
    let network = match network_override {
        Some(n) if !n.trim().is_empty() => canonicalize_network(&n),
        _ => network_from_env(),
    };
    let network = match network {
        Ok(n) => n,
        Err(msg) => {
            push_system_to_agent(
                app,
                agent_id,
                format!(
                    "Cannot start address watch: {msg}. \
                     Set GROK_BITCOIN_NETWORK to mainnet|signet|testnet|testnet4 \
                     (or leave unset for mainnet)."
                ),
            );
            app.routstr_watch_status = Some(format!("Watch not started: {msg}"));
            return vec![];
        }
    };
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
            // Reuse fund's product-resolved network label (canonical as_str).
            start_routstr_watch_for_agent_on_network(
                app,
                agent_id,
                success.address,
                Some(success.network_label),
                /*immediate*/ true,
            )
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
    // Reuse in-memory network — never re-read env (would rewrite signet
    // watches when GROK_BITCOIN_NETWORK is unset). Missing in-memory network
    // falls back to product entry resolve (fail-closed; no silent Mainnet).
    let network = match app.routstr_watch_network.clone() {
        Some(n) => n,
        None => match network_from_env() {
            Ok(n) => n,
            Err(msg) => {
                push_system_to_agent(app, agent_id, format!("Watch re-arm aborted: {msg}"));
                app.routstr_watch_status = Some(format!("Watch re-arm aborted: {msg}"));
                return vec![];
            }
        },
    };
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
        // Live create may succeed (invoice ready) or fail to residual (not wired).
        // Never claim a completed payment without status poll + api_key store.
        assert!(
            lower.contains("not wired")
                || lower.contains("not available")
                || lower.contains("invoice ready")
                || lower.contains("bolt11")
                || lower.contains("live invoice create failed"),
            "expected topup residual or live invoice wording: {text}"
        );
        assert!(!lower.contains("payment sent"));
        assert!(!lower.contains("refund completed"));
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
    fn utxos_stages_pending_and_unlock_routes_to_utxos() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let effects = dispatch(
            Action::RoutstrUtxos {
                network: Some("signet".into()),
            },
            &mut app,
        );
        assert!(effects.is_empty());
        let pending = app.pending_routstr_utxos.as_ref().expect("pending utxos");
        assert_eq!(pending.network.as_deref(), Some("signet"));
        assert_eq!(pending.agent_id, AgentId(0));
        assert!(app.pending_routstr_spend.is_none());

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrUtxosComplete {
                    agent_id: AgentId(0),
                    network: Some(n),
                    ..
                }) if n == "signet"
            ),
            "unlock with pending utxos must complete utxos, not fund: {effects:?}"
        );
        assert!(
            app.pending_routstr_utxos.is_none(),
            "pending consumed into effect"
        );
        let dbg = format!("{:?}", effects.first());
        assert!(!dbg.contains("abandon"), "Debug leaked phrase: {dbg}");
    }

    #[test]
    fn utxos_clears_pending_spend_and_fund_clears_utxos() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qstale".into(),
                amount_sats: 99_000,
                broadcast: true,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert!(app.pending_routstr_spend.is_some());

        let _ = dispatch(Action::RoutstrUtxos { network: None }, &mut app);
        assert!(
            app.pending_routstr_spend.is_none(),
            "staging utxos must cancel spend"
        );
        assert!(app.pending_routstr_utxos.is_some());

        let effects = dispatch(Action::RoutstrFund, &mut app);
        assert!(
            matches!(effects.first(), Some(Effect::RoutstrFundProbe { .. })),
            "expected fund probe: {effects:?}"
        );
        assert!(
            app.pending_routstr_utxos.is_none(),
            "fund must cancel staged utxos"
        );

        // Unlock without pending → fund complete, not utxos.
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("word word word"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(effects.first(), Some(Effect::RoutstrFundComplete { .. })),
            "no pending money/utxos → fund: {effects:?}"
        );
        assert!(!matches!(
            effects.first(),
            Some(Effect::RoutstrUtxosComplete { .. })
        ));
    }

    #[test]
    fn handle_utxos_completed_prints_lines_or_error() {
        let mut app = test_app_with_agent();
        let id = AgentId(0);
        let _ = handle_routstr_utxos_completed(
            &mut app,
            id,
            Ok(xai_grok_shell::auth::RoutstrUtxosSuccess {
                network_label: "signet".into(),
                lines: vec!["confirmed: 0 sats".into(), "UTXOs: none".into()],
            }),
        );
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            text.contains("confirmed") || text.contains("0 sats"),
            "expected success lines: {text}"
        );

        let _ = handle_routstr_utxos_completed(
            &mut app,
            id,
            Err("recovery phrase re-entry cancelled; not listing UTXOs".into()),
        );
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("utxo list failed") || lower.contains("cancelled"),
            "expected failure notice: {text}"
        );
        assert!(
            lower.contains("observational") || lower.contains("nothing broadcast"),
            "failure must stay observational: {text}"
        );
    }

    #[test]
    fn unlock_rejects_utxos_when_active_agent_differs_from_staging() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        crate::app::dispatch::tests::insert_placeholder_agent(&mut app, AgentId(1));
        let _ = dispatch(
            Action::RoutstrUtxos {
                network: Some("signet".into()),
            },
            &mut app,
        );
        assert_eq!(
            app.pending_routstr_utxos.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
        app.active_view = ActiveView::Agent(AgentId(1));
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            effects.is_empty(),
            "cross-agent unlock must not authorize utxos: {effects:?}"
        );
        assert!(
            app.pending_routstr_utxos.is_some(),
            "pending must remain for the staging agent"
        );
        assert_eq!(
            app.pending_routstr_utxos.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
        assert_eq!(
            app.pending_routstr_utxos
                .as_ref()
                .and_then(|p| p.network.as_deref()),
            Some("signet")
        );
        // Staging agent still sees the mismatch notice on the active agent.
        let agent1 = app.agents.get(&AgentId(1)).expect("agent 1");
        let text: String = (0..agent1.scrollback.len())
            .filter_map(|i| agent1.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("another agent") || lower.contains("staged utxo"),
            "expected cross-agent notice: {text}"
        );
    }

    #[test]
    fn utxos_task_complete_does_not_drop_newer_staged_utxos() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrUtxos {
                network: Some("mainnet".into()),
            },
            &mut app,
        );
        let unlock_effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                unlock_effects.first(),
                Some(Effect::RoutstrUtxosComplete {
                    network: Some(n),
                    ..
                }) if n == "mainnet"
            ),
            "stage A unlock: {unlock_effects:?}"
        );
        assert!(app.pending_routstr_utxos.is_none());

        // Re-stage B while A is still "in flight".
        let _ = dispatch(
            Action::RoutstrUtxos {
                network: Some("signet".into()),
            },
            &mut app,
        );
        let pending_b = app
            .pending_routstr_utxos
            .as_ref()
            .expect("stage B must be pending");
        assert_eq!(pending_b.network.as_deref(), Some("signet"));
        assert_eq!(pending_b.agent_id, AgentId(0));

        // Completion of A must not wipe B.
        let _ = handle_routstr_utxos_completed(
            &mut app,
            AgentId(0),
            Ok(xai_grok_shell::auth::RoutstrUtxosSuccess {
                network_label: "mainnet".into(),
                lines: vec!["confirmed: 0 sats (stage A complete)".into()],
            }),
        );
        let pending_after = app
            .pending_routstr_utxos
            .as_ref()
            .expect("newer staged utxos must survive task complete");
        assert_eq!(pending_after.network.as_deref(), Some("signet"));
        assert_eq!(pending_after.agent_id, AgentId(0));
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
                fee_rate_sat_vb: Some(5),
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
                request_passphrase_prompt: false,
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
                fee_rate_sat_vb: Some(5),
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
                request_passphrase_prompt: false,
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

    fn sample_rbf_input_spec() -> String {
        format!("{}:0:100000:bc1qrecv", "ab".repeat(32))
    }

    #[test]
    fn rbf_stages_pending_without_bip39_and_unlock_routes_to_rbf() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let input = sample_rbf_input_spec();
        let effects = dispatch(
            Action::RoutstrRbf {
                address: "bc1qdest".into(),
                amount_sats: 21_000,
                original_fee_sats: 705,
                original_vbytes: 141,
                input_specs: vec![input.clone()],
                broadcast: false,
                fee_rate_sat_vb: Some(10),
            },
            &mut app,
        );
        assert!(effects.is_empty());
        let pending = app.pending_routstr_rbf.as_ref().expect("pending rbf");
        assert_eq!(pending.address, "bc1qdest");
        assert_eq!(pending.amount_sats, 21_000);
        assert_eq!(pending.original_fee_sats, 705);
        assert_eq!(pending.original_vbytes, 141);
        assert_eq!(pending.input_specs, vec![input.clone()]);
        assert!(!pending.broadcast);
        assert_eq!(pending.fee_rate_sat_vb, Some(10));
        assert_eq!(pending.agent_id, AgentId(0));
        assert!(app.pending_routstr_spend.is_none());

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrRbfComplete {
                    amount_sats: 21_000,
                    original_fee_sats: 705,
                    original_vbytes: 141,
                    broadcast: false,
                    agent_id: AgentId(0),
                    ..
                })
            ),
            "unlock with pending rbf must complete rbf, not fund: {effects:?}"
        );
        // Inputs preserved into effect.
        match effects.first() {
            Some(Effect::RoutstrRbfComplete { input_specs, .. }) => {
                assert_eq!(input_specs, &vec![input]);
            }
            other => panic!("expected rbf complete: {other:?}"),
        }
        assert!(
            app.pending_routstr_rbf.is_none(),
            "pending consumed into effect"
        );
        let dbg = format!("{:?}", effects.first());
        assert!(!dbg.contains("abandon"), "Debug leaked phrase: {dbg}");
    }

    #[test]
    fn fund_clears_pending_rbf_so_unlock_routes_to_fund() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qstale".into(),
                amount_sats: 99_000,
                original_fee_sats: 500,
                original_vbytes: 141,
                input_specs: vec![sample_rbf_input_spec()],
                broadcast: true,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert!(app.pending_routstr_rbf.is_some());

        let effects = dispatch(Action::RoutstrFund, &mut app);
        assert!(matches!(
            effects.first(),
            Some(Effect::RoutstrFundProbe { .. })
        ));
        assert!(
            app.pending_routstr_rbf.is_none(),
            "fund must cancel staged rbf"
        );
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            text.to_ascii_lowercase().contains("cancelled staged rbf"),
            "expected rbf cancel notice: {text}"
        );

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(effects.first(), Some(Effect::RoutstrFundComplete { .. })),
            "after fund cancel, unlock must fund not rbf: {effects:?}"
        );
        assert!(
            !matches!(effects.first(), Some(Effect::RoutstrRbfComplete { .. })),
            "must not complete stale rbf: {effects:?}"
        );
    }

    #[test]
    fn spend_and_rbf_supersede_each_other() {
        let mut app = test_app_with_agent();
        // Stage spend.
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qspend".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert!(app.pending_routstr_spend.is_some());
        // Stage rbf → cancels spend.
        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qrbf".into(),
                amount_sats: 2000,
                original_fee_sats: 100,
                original_vbytes: 141,
                input_specs: vec![sample_rbf_input_spec()],
                broadcast: false,
                fee_rate_sat_vb: None,
            },
            &mut app,
        );
        assert!(app.pending_routstr_spend.is_none());
        assert_eq!(
            app.pending_routstr_rbf.as_ref().map(|p| p.address.as_str()),
            Some("bc1qrbf")
        );
        // Stage spend again → cancels rbf.
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qspend2".into(),
                amount_sats: 3000,
                broadcast: true,
                fee_rate_sat_vb: Some(8),
            },
            &mut app,
        );
        assert!(app.pending_routstr_rbf.is_none());
        assert_eq!(
            app.pending_routstr_spend
                .as_ref()
                .map(|p| p.address.as_str()),
            Some("bc1qspend2")
        );
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("cancelled staged spend") && lower.contains("cancelled staged rbf"),
            "expected both cancel notices: {text}"
        );
    }

    fn sample_cpfp_parent_spec() -> String {
        format!("{}:1:80000:bc1qchange", "cd".repeat(32))
    }

    #[test]
    fn cpfp_stages_pending_without_bip39_and_unlock_routes_to_cpfp() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let parent = sample_cpfp_parent_spec();
        let effects = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qdest".into(),
                amount_sats: 40_000,
                parent_fee_sats: 200,
                parent_vbytes: 200,
                parent_specs: vec![parent.clone()],
                extra_input_specs: vec![],
                broadcast: false,
                fee_rate_sat_vb: Some(10),
            },
            &mut app,
        );
        assert!(effects.is_empty());
        let pending = app.pending_routstr_cpfp.as_ref().expect("pending cpfp");
        assert_eq!(pending.address, "bc1qdest");
        assert_eq!(pending.amount_sats, 40_000);
        assert_eq!(pending.parent_fee_sats, 200);
        assert_eq!(pending.parent_vbytes, 200);
        assert_eq!(pending.parent_specs, vec![parent.clone()]);
        assert!(pending.extra_input_specs.is_empty());
        assert!(!pending.broadcast);
        assert_eq!(pending.fee_rate_sat_vb, Some(10));
        assert_eq!(pending.agent_id, AgentId(0));
        assert!(app.pending_routstr_spend.is_none());
        assert!(app.pending_routstr_rbf.is_none());

        // Staging copy must stress child-only / not replace parent.
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("child")
                && (lower.contains("does not replace")
                    || lower.contains("not replace")
                    || lower.contains("does **not** replace")
                    || (lower.contains("replace") && lower.contains("not"))),
            "expected child-only product copy: {text}"
        );

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrCpfpComplete {
                    amount_sats: 40_000,
                    parent_fee_sats: 200,
                    parent_vbytes: 200,
                    broadcast: false,
                    agent_id: AgentId(0),
                    ..
                })
            ),
            "unlock with pending cpfp must complete cpfp, not fund: {effects:?}"
        );
        match effects.first() {
            Some(Effect::RoutstrCpfpComplete {
                parent_specs,
                extra_input_specs,
                ..
            }) => {
                assert_eq!(parent_specs, &vec![parent]);
                assert!(extra_input_specs.is_empty());
            }
            other => panic!("expected cpfp complete: {other:?}"),
        }
        assert!(
            app.pending_routstr_cpfp.is_none(),
            "pending consumed into effect"
        );
        let dbg = format!("{:?}", effects.first());
        assert!(!dbg.contains("abandon"), "Debug leaked phrase: {dbg}");
    }

    #[test]
    fn fund_clears_pending_cpfp_so_unlock_routes_to_fund() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qstale".into(),
                amount_sats: 99_000,
                parent_fee_sats: 500,
                parent_vbytes: 141,
                parent_specs: vec![sample_cpfp_parent_spec()],
                extra_input_specs: vec![],
                broadcast: true,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert!(app.pending_routstr_cpfp.is_some());

        let effects = dispatch(Action::RoutstrFund, &mut app);
        assert!(matches!(
            effects.first(),
            Some(Effect::RoutstrFundProbe { .. })
        ));
        assert!(
            app.pending_routstr_cpfp.is_none(),
            "fund must cancel staged cpfp"
        );
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            text.to_ascii_lowercase().contains("cancelled staged cpfp"),
            "expected cpfp cancel notice: {text}"
        );

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(effects.first(), Some(Effect::RoutstrFundComplete { .. })),
            "after fund cancel, unlock must fund not cpfp: {effects:?}"
        );
        assert!(
            !matches!(effects.first(), Some(Effect::RoutstrCpfpComplete { .. })),
            "must not complete stale cpfp: {effects:?}"
        );
    }

    #[test]
    fn spend_rbf_cpfp_supersede_each_other() {
        let mut app = test_app_with_agent();
        // Stage spend.
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qspend".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert!(app.pending_routstr_spend.is_some());
        // Stage cpfp → cancels spend.
        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qcpfp".into(),
                amount_sats: 2000,
                parent_fee_sats: 100,
                parent_vbytes: 141,
                parent_specs: vec![sample_cpfp_parent_spec()],
                extra_input_specs: vec![],
                broadcast: false,
                fee_rate_sat_vb: None,
            },
            &mut app,
        );
        assert!(app.pending_routstr_spend.is_none());
        assert_eq!(
            app.pending_routstr_cpfp
                .as_ref()
                .map(|p| p.address.as_str()),
            Some("bc1qcpfp")
        );
        // Stage rbf → cancels cpfp.
        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qrbf".into(),
                amount_sats: 3000,
                original_fee_sats: 200,
                original_vbytes: 150,
                input_specs: vec![sample_rbf_input_spec()],
                broadcast: false,
                fee_rate_sat_vb: Some(8),
            },
            &mut app,
        );
        assert!(app.pending_routstr_cpfp.is_none());
        assert_eq!(
            app.pending_routstr_rbf.as_ref().map(|p| p.address.as_str()),
            Some("bc1qrbf")
        );
        // Stage cpfp again → cancels rbf.
        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qcpfp2".into(),
                amount_sats: 4000,
                parent_fee_sats: 50,
                parent_vbytes: 100,
                parent_specs: vec![sample_cpfp_parent_spec()],
                extra_input_specs: vec![],
                broadcast: true,
                fee_rate_sat_vb: Some(12),
            },
            &mut app,
        );
        assert!(app.pending_routstr_rbf.is_none());
        assert_eq!(
            app.pending_routstr_cpfp
                .as_ref()
                .map(|p| p.address.as_str()),
            Some("bc1qcpfp2")
        );
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("cancelled staged spend")
                && lower.contains("cancelled staged cpfp")
                && lower.contains("cancelled staged rbf"),
            "expected spend/rbf/cpfp cancel notices: {text}"
        );
    }

    #[test]
    fn unlock_rejects_cpfp_when_active_agent_differs_from_staging() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        crate::app::dispatch::tests::insert_placeholder_agent(&mut app, AgentId(1));
        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qagent0".into(),
                amount_sats: 500,
                parent_fee_sats: 50,
                parent_vbytes: 100,
                parent_specs: vec![sample_cpfp_parent_spec()],
                extra_input_specs: vec![],
                broadcast: true,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert_eq!(
            app.pending_routstr_cpfp.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
        app.active_view = ActiveView::Agent(AgentId(1));
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            effects.is_empty(),
            "cross-agent unlock must not authorize cpfp: {effects:?}"
        );
        assert!(
            app.pending_routstr_cpfp.is_some(),
            "pending must remain for the staging agent"
        );
        assert_eq!(
            app.pending_routstr_cpfp.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
    }

    #[test]
    fn cpfp_task_complete_does_not_drop_newer_staged_cpfp() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let parent = sample_cpfp_parent_spec();
        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qstage-a".into(),
                amount_sats: 1000,
                parent_fee_sats: 100,
                parent_vbytes: 141,
                parent_specs: vec![parent.clone()],
                extra_input_specs: vec![],
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        let unlock_effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                unlock_effects.first(),
                Some(Effect::RoutstrCpfpComplete {
                    amount_sats: 1000,
                    ..
                })
            ),
            "stage A unlock: {unlock_effects:?}"
        );
        assert!(app.pending_routstr_cpfp.is_none());

        // Re-stage B while A is still "in flight".
        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qstage-b".into(),
                amount_sats: 2500,
                parent_fee_sats: 200,
                parent_vbytes: 150,
                parent_specs: vec![parent],
                extra_input_specs: vec![],
                broadcast: true,
                fee_rate_sat_vb: Some(8),
            },
            &mut app,
        );
        let pending_b = app
            .pending_routstr_cpfp
            .as_ref()
            .expect("stage B must be pending");
        assert_eq!(pending_b.address, "bc1qstage-b");
        assert_eq!(pending_b.amount_sats, 2500);
        assert!(pending_b.broadcast);

        // Completion of A must not wipe B.
        let _ = handle_routstr_cpfp_completed(
            &mut app,
            AgentId(0),
            Ok(xai_grok_shell::auth::RoutstrCpfpSuccess {
                payment_address: "bc1qstage-a".into(),
                payment_sats: 1000,
                parent_fee_sats: 100,
                fee_sats: 250,
                change_sats: 0,
                txid: "a".repeat(64),
                raw_hex: "ab".repeat(20),
                broadcast_txid: None,
                network_label: "mainnet".into(),
                fee_rate_sat_vb: 5,
                lines: vec!["prepared stage A cpfp child (simulated)".into()],
            }),
        );
        let still = app
            .pending_routstr_cpfp
            .as_ref()
            .expect("stage B must survive completion of A");
        assert_eq!(still.address, "bc1qstage-b");
        assert_eq!(still.amount_sats, 2500);
        assert!(still.broadcast);
        assert_eq!(still.fee_rate_sat_vb, Some(8));

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrCpfpComplete {
                    amount_sats: 2500,
                    broadcast: true,
                    ..
                })
            ),
            "unlock after A complete must still cpfp B: {effects:?}"
        );
    }

    #[test]
    fn unlock_rejects_rbf_when_active_agent_differs_from_staging() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        crate::app::dispatch::tests::insert_placeholder_agent(&mut app, AgentId(1));
        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qagent0".into(),
                amount_sats: 500,
                original_fee_sats: 50,
                original_vbytes: 100,
                input_specs: vec![sample_rbf_input_spec()],
                broadcast: true,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert_eq!(
            app.pending_routstr_rbf.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
        app.active_view = ActiveView::Agent(AgentId(1));
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            effects.is_empty(),
            "cross-agent unlock must not authorize rbf: {effects:?}"
        );
        assert!(
            app.pending_routstr_rbf.is_some(),
            "pending must remain for the staging agent"
        );
        assert_eq!(
            app.pending_routstr_rbf.as_ref().map(|p| p.agent_id),
            Some(AgentId(0))
        );
    }

    #[test]
    fn rbf_task_complete_does_not_drop_newer_staged_rbf() {
        use crate::app::actions::SensitiveString;
        let mut app = test_app_with_agent();
        let input = sample_rbf_input_spec();
        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qstage-a".into(),
                amount_sats: 1000,
                original_fee_sats: 100,
                original_vbytes: 141,
                input_specs: vec![input.clone()],
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        let unlock_effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                unlock_effects.first(),
                Some(Effect::RoutstrRbfComplete {
                    amount_sats: 1000,
                    ..
                })
            ),
            "stage A unlock: {unlock_effects:?}"
        );
        assert!(app.pending_routstr_rbf.is_none());

        // Re-stage B while A is still "in flight".
        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qstage-b".into(),
                amount_sats: 2500,
                original_fee_sats: 200,
                original_vbytes: 150,
                input_specs: vec![input],
                broadcast: true,
                fee_rate_sat_vb: Some(8),
            },
            &mut app,
        );
        let pending_b = app
            .pending_routstr_rbf
            .as_ref()
            .expect("stage B must be pending");
        assert_eq!(pending_b.address, "bc1qstage-b");
        assert_eq!(pending_b.amount_sats, 2500);
        assert!(pending_b.broadcast);

        // Completion of A must not wipe B.
        let _ = handle_routstr_rbf_completed(
            &mut app,
            AgentId(0),
            Ok(xai_grok_shell::auth::RoutstrRbfSuccess {
                payment_address: "bc1qstage-a".into(),
                payment_sats: 1000,
                original_fee_sats: 100,
                fee_sats: 250,
                change_sats: 0,
                txid: "a".repeat(64),
                raw_hex: "ab".repeat(20),
                broadcast_txid: None,
                network_label: "mainnet".into(),
                fee_rate_sat_vb: 5,
                lines: vec!["prepared stage A rbf (simulated)".into()],
            }),
        );
        let still = app
            .pending_routstr_rbf
            .as_ref()
            .expect("stage B must survive completion of A");
        assert_eq!(still.address, "bc1qstage-b");
        assert_eq!(still.amount_sats, 2500);
        assert!(still.broadcast);
        assert_eq!(still.fee_rate_sat_vb, Some(8));

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrRbfComplete {
                    amount_sats: 2500,
                    broadcast: true,
                    ..
                })
            ),
            "unlock after A complete must still rbf B: {effects:?}"
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
                fee_rate_sat_vb: Some(5),
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
                request_passphrase_prompt: false,
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
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        let unlock_effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
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
                fee_rate_sat_vb: Some(8),
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
        assert_eq!(still.fee_rate_sat_vb, Some(8));

        // Unlock still authorizes B, not a wiped/missing pending fund path.
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
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
    fn unlock_pass_opens_modal_without_effect_and_debug_redacts_secrets() {
        use crate::app::actions::SensitiveString;
        use crate::app::app_view::RoutstrPassphraseModalOutcome;
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qdest".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        assert!(app.pending_routstr_spend.is_some());

        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(
            effects.is_empty(),
            "pass flag must open modal, not complete yet: {effects:?}"
        );
        assert!(
            app.pending_routstr_spend.is_some(),
            "pending spend must stay until passphrase submit"
        );
        let modal = app
            .routstr_passphrase_modal
            .as_ref()
            .expect("passphrase modal open");
        let dbg = format!("{modal:?}");
        assert!(
            !dbg.contains("abandon"),
            "AppView modal Debug leaked phrase: {dbg}"
        );
        assert!(
            dbg.contains("***") || dbg.contains("REDACTED") || dbg.contains("SensitiveString"),
            "expected redacted phrase field: {dbg}"
        );
        // Type a secret into the draft; Debug must never show it.
        let modal = app.routstr_passphrase_modal.as_mut().unwrap();
        for c in "my-secret-bip39-pass".chars() {
            assert_eq!(
                modal.handle_key(&KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)),
                RoutstrPassphraseModalOutcome::Changed
            );
        }
        // Bracketed paste also lands in the draft (not chat); control chars skipped.
        assert!(modal.push_paste(" +pasted\n\t"));
        assert_eq!(
            modal.draft_char_len(),
            "my-secret-bip39-pass +pasted".chars().count()
        );
        let dbg = format!("{:?}", app.routstr_passphrase_modal);
        assert!(
            !dbg.contains("my-secret-bip39-pass"),
            "Debug leaked typed passphrase: {dbg}"
        );
        assert!(
            !dbg.contains("+pasted"),
            "Debug leaked pasted passphrase: {dbg}"
        );
        assert!(
            !dbg.contains("abandon"),
            "Debug leaked phrase after type: {dbg}"
        );
        // Pending spend params still contain no secrets.
        let pend_dbg = format!("{:?}", app.pending_routstr_spend);
        assert!(!pend_dbg.contains("my-secret"));
        assert!(!pend_dbg.contains("abandon"));
    }

    #[test]
    fn passphrase_modal_cancel_clears_secrets_keeps_pending_spend() {
        use crate::app::actions::SensitiveString;

        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qkeep".into(),
                amount_sats: 42,
                broadcast: true,
                fee_rate_sat_vb: Some(3),
            },
            &mut app,
        );
        let _ = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: Some(SensitiveString::new("aead-pw")),
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(app.routstr_passphrase_modal.is_some());
        let effects = dispatch(Action::RoutstrBip39PassphraseCancel, &mut app);
        assert!(effects.is_empty());
        assert!(
            app.routstr_passphrase_modal.is_none(),
            "cancel must drop modal"
        );
        let pending = app
            .pending_routstr_spend
            .as_ref()
            .expect("cancel must leave staged spend");
        assert_eq!(pending.address, "bc1qkeep");
        assert_eq!(pending.amount_sats, 42);
        assert!(pending.broadcast);
        // System notice mentions cancel (non-secret).
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(
            text.to_ascii_lowercase().contains("cancelled private")
                || text.to_ascii_lowercase().contains("passphrase entry"),
            "expected cancel notice: {text}"
        );
        assert!(!text.contains("aead-pw"));
        assert!(!text.contains("abandon"));
    }

    #[test]
    fn passphrase_modal_submit_completes_spend_with_explicit_passphrase() {
        use crate::app::actions::SensitiveString;

        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qdest".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        let _ = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(app.routstr_passphrase_modal.is_some());
        let modal_agent = app.routstr_passphrase_modal.as_ref().unwrap().agent_id;
        // Input layer would take modal into the submit action; dispatch accepts
        // secrets + agent_id directly (modal already cleared by input).
        app.routstr_passphrase_modal = None;
        let effects = dispatch(
            Action::RoutstrBip39PassphraseSubmit {
                agent_id: modal_agent,
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                passphrase: SensitiveString::new("modal-pass-not-for-prod"),
            },
            &mut app,
        );
        match effects.first() {
            Some(Effect::RoutstrSpendComplete {
                amount_sats: 1000,
                bip39_passphrase: Some(pp),
                ..
            }) => {
                assert_eq!(pp.as_str(), "modal-pass-not-for-prod");
                let dbg = format!("{:?}", effects.first());
                assert!(
                    !dbg.contains("modal-pass-not-for-prod"),
                    "effect Debug leaked passphrase: {dbg}"
                );
                assert!(
                    !dbg.contains("abandon"),
                    "effect Debug leaked phrase: {dbg}"
                );
            }
            other => panic!("expected spend complete with explicit passphrase: {other:?}"),
        }
        assert!(app.pending_routstr_spend.is_none());
        assert!(app.routstr_passphrase_modal.is_none());
    }

    #[test]
    fn passphrase_modal_submit_empty_is_explicit_default_path() {
        use crate::app::actions::SensitiveString;

        let mut app = test_app_with_agent();
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(effects.is_empty());
        let modal_agent = app.routstr_passphrase_modal.as_ref().unwrap().agent_id;
        app.routstr_passphrase_modal = None;
        let effects = dispatch(
            Action::RoutstrBip39PassphraseSubmit {
                agent_id: modal_agent,
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                passphrase: SensitiveString::new(""),
            },
            &mut app,
        );
        match effects.first() {
            Some(Effect::RoutstrFundComplete {
                bip39_passphrase: Some(pp),
                ..
            }) => {
                assert!(pp.is_empty(), "empty modal submit is explicit default path");
            }
            other => panic!("expected fund complete with Some(\"\"): {other:?}"),
        }
    }

    #[test]
    fn passphrase_modal_submit_wrong_agent_drops_secrets_no_effect() {
        use crate::app::actions::SensitiveString;

        let mut app = test_app_with_agent();
        crate::app::dispatch::tests::insert_placeholder_agent(&mut app, AgentId(1));
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qdest".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        let _ = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        let modal_agent = app.routstr_passphrase_modal.as_ref().unwrap().agent_id;
        assert_eq!(modal_agent, AgentId(0));
        app.routstr_passphrase_modal = None;
        // Simulate active view switched after modal open (non-input path).
        app.active_view = crate::app::app_view::ActiveView::Agent(AgentId(1));
        let effects = dispatch(
            Action::RoutstrBip39PassphraseSubmit {
                agent_id: modal_agent,
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                passphrase: SensitiveString::new("must-not-complete"),
            },
            &mut app,
        );
        assert!(
            effects.is_empty(),
            "must not complete unlock for wrong active agent: {effects:?}"
        );
        assert!(
            app.pending_routstr_spend.is_some(),
            "staged spend must remain for correct agent re-unlock"
        );
        // System text must not leak secrets.
        for agent in app.agents.values() {
            let text: String = (0..agent.scrollback.len())
                .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
                .collect();
            assert!(!text.contains("must-not-complete"));
            assert!(!text.contains("abandon"));
        }
    }

    #[test]
    fn fund_and_restage_supersede_passphrase_modal() {
        use crate::app::actions::SensitiveString;

        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qold".into(),
                amount_sats: 1,
                broadcast: false,
                fee_rate_sat_vb: Some(1),
            },
            &mut app,
        );
        let _ = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(app.routstr_passphrase_modal.is_some());

        // Re-staging spend cancels modal (secrets dropped) and supersedes pending.
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qnew".into(),
                amount_sats: 2,
                broadcast: false,
                fee_rate_sat_vb: Some(2),
            },
            &mut app,
        );
        assert!(
            app.routstr_passphrase_modal.is_none(),
            "restage must clear passphrase modal"
        );
        assert_eq!(
            app.pending_routstr_spend.as_ref().unwrap().address,
            "bc1qnew"
        );

        // Open modal again, then fund cancels both.
        let _ = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(app.routstr_passphrase_modal.is_some());
        let _ = dispatch(Action::RoutstrFund, &mut app);
        assert!(app.routstr_passphrase_modal.is_none());
        assert!(app.pending_routstr_spend.is_none());
    }

    #[test]
    fn rbf_restage_supersedes_passphrase_modal() {
        use crate::app::actions::SensitiveString;

        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qoldrbf".into(),
                amount_sats: 1000,
                original_fee_sats: 200,
                original_vbytes: 140,
                input_specs: vec![
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0:2000:bc1qin"
                        .into(),
                ],
                broadcast: false,
                fee_rate_sat_vb: Some(10),
            },
            &mut app,
        );
        let _ = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(app.routstr_passphrase_modal.is_some());
        // Type a secret into the draft so supersede must drop process-memory secret.
        if let Some(modal) = app.routstr_passphrase_modal.as_mut() {
            for c in "rbf-modal-secret".chars() {
                modal.push_char(c);
            }
        }

        let _ = dispatch(
            Action::RoutstrRbf {
                address: "bc1qnewrbf".into(),
                amount_sats: 1100,
                original_fee_sats: 250,
                original_vbytes: 150,
                input_specs: vec![
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1:3000:bc1qin2"
                        .into(),
                ],
                broadcast: false,
                fee_rate_sat_vb: Some(12),
            },
            &mut app,
        );
        assert!(
            app.routstr_passphrase_modal.is_none(),
            "rbf restage must clear passphrase modal"
        );
        let pending = app.pending_routstr_rbf.as_ref().expect("new rbf pending");
        assert_eq!(pending.address, "bc1qnewrbf");
        assert_eq!(pending.amount_sats, 1100);
        assert_eq!(pending.original_fee_sats, 250);
        // System / pending debug must not leak the typed secret or phrase.
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(!text.contains("rbf-modal-secret"));
        assert!(!text.contains("abandon"));
        let pend_dbg = format!("{:?}", app.pending_routstr_rbf);
        assert!(!pend_dbg.contains("rbf-modal-secret"));
        assert!(!pend_dbg.contains("abandon"));
    }

    #[test]
    fn cpfp_restage_supersedes_passphrase_modal() {
        use crate::app::actions::SensitiveString;

        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qoldcpfp".into(),
                amount_sats: 500,
                parent_fee_sats: 100,
                parent_vbytes: 140,
                parent_specs: vec![
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:0:1500:bc1qpar"
                        .into(),
                ],
                extra_input_specs: vec![],
                broadcast: false,
                fee_rate_sat_vb: Some(8),
            },
            &mut app,
        );
        let _ = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: true,
            },
            &mut app,
        );
        assert!(app.routstr_passphrase_modal.is_some());
        if let Some(modal) = app.routstr_passphrase_modal.as_mut() {
            for c in "cpfp-modal-secret".chars() {
                modal.push_char(c);
            }
        }

        let _ = dispatch(
            Action::RoutstrCpfp {
                address: "bc1qnewcpfp".into(),
                amount_sats: 600,
                parent_fee_sats: 120,
                parent_vbytes: 160,
                parent_specs: vec![
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd:2:2000:bc1qpar2"
                        .into(),
                ],
                extra_input_specs: vec![],
                broadcast: false,
                fee_rate_sat_vb: Some(9),
            },
            &mut app,
        );
        assert!(
            app.routstr_passphrase_modal.is_none(),
            "cpfp restage must clear passphrase modal"
        );
        let pending = app.pending_routstr_cpfp.as_ref().expect("new cpfp pending");
        assert_eq!(pending.address, "bc1qnewcpfp");
        assert_eq!(pending.amount_sats, 600);
        assert_eq!(pending.parent_fee_sats, 120);
        let agent = app.agents.values().next().unwrap();
        let text: String = (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect();
        assert!(!text.contains("cpfp-modal-secret"));
        assert!(!text.contains("abandon"));
        let pend_dbg = format!("{:?}", app.pending_routstr_cpfp);
        assert!(!pend_dbg.contains("cpfp-modal-secret"));
        assert!(!pend_dbg.contains("abandon"));
    }

    #[test]
    fn unlock_without_pass_still_completes_immediately_env_path() {
        use crate::app::actions::SensitiveString;

        // Regression: default unlock (no pass flag) must not require the modal.
        let mut app = test_app_with_agent();
        let _ = dispatch(
            Action::RoutstrSpend {
                address: "bc1qdest".into(),
                amount_sats: 1000,
                broadcast: false,
                fee_rate_sat_vb: Some(5),
            },
            &mut app,
        );
        let effects = dispatch(
            Action::RoutstrFundReentry {
                phrase: SensitiveString::new("abandon abandon abandon"),
                password: None,
                request_passphrase_prompt: false,
            },
            &mut app,
        );
        assert!(
            matches!(
                effects.first(),
                Some(Effect::RoutstrSpendComplete {
                    bip39_passphrase: None,
                    ..
                })
            ),
            "no-pass unlock uses env path (None): {effects:?}"
        );
        assert!(app.routstr_passphrase_modal.is_none());
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

    /// Scrollback dump helper for fail-closed watch messaging.
    fn agent_scrollback_text(app: &AppView, id: AgentId) -> String {
        let agent = app.agents.get(&id).unwrap();
        (0..agent.scrollback.len())
            .filter_map(|i| agent.scrollback.entry(i).map(|e| format!("{:?}", e.block)))
            .collect()
    }

    /// Brand-new watch with `GROK_BITCOIN_NETWORK=regtest` must not emit the
    /// watch loop and must surface a product unknown-network error (parity
    /// with fund/spend; no silent Mainnet / raw "regtest" wire).
    #[test]
    #[serial_test::serial(GROK_BITCOIN_NETWORK)]
    fn watch_start_regtest_env_fail_closed_no_loop() {
        let _env = xai_grok_test_support::EnvGuard::set("GROK_BITCOIN_NETWORK", "regtest");
        let mut app = test_app_with_agent();
        let gen_before = app.routstr_watch_generation;
        let effects = start_routstr_watch_for_agent(
            &mut app,
            AgentId(0),
            "bc1qregtestfailclosed0000000000000".into(),
            true,
        );
        assert!(
            effects.is_empty(),
            "regtest must not emit RoutstrWatchLoop: {effects:?}"
        );
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::RoutstrWatchLoop { .. })),
            "{effects:?}"
        );
        assert!(app.routstr_watch_address.is_none());
        assert!(app.routstr_watch_network.is_none());
        assert_eq!(
            app.routstr_watch_generation, gen_before,
            "fail-closed must not bump generation"
        );
        let text = agent_scrollback_text(&app, AgentId(0)).to_ascii_lowercase();
        assert!(
            text.contains("unknown") && text.contains("regtest"),
            "user-visible product network error expected: {text}"
        );
        assert!(
            app.routstr_watch_status
                .as_deref()
                .is_some_and(|s| s.to_ascii_lowercase().contains("unknown")),
            "status should note failure: {:?}",
            app.routstr_watch_status
        );
    }

    /// Unknown env typo fails closed like regtest (no loop / no soft-Mainnet).
    #[test]
    #[serial_test::serial(GROK_BITCOIN_NETWORK)]
    fn watch_start_typo_env_fail_closed_no_loop() {
        let _env = xai_grok_test_support::EnvGuard::set("GROK_BITCOIN_NETWORK", "mainet");
        let mut app = test_app_with_agent();
        let effects = start_routstr_watch_for_agent(
            &mut app,
            AgentId(0),
            "bc1qtypofailclosed000000000000000".into(),
            true,
        );
        assert!(effects.is_empty(), "{effects:?}");
        assert!(app.routstr_watch_address.is_none());
        let text = agent_scrollback_text(&app, AgentId(0)).to_ascii_lowercase();
        assert!(
            text.contains("unknown") && text.contains("mainet"),
            "typo must surface in error: {text}"
        );
    }

    /// Valid product labels start with canonical wire (not raw env aliases).
    #[test]
    #[serial_test::serial(GROK_BITCOIN_NETWORK)]
    fn watch_start_signet_and_testnet4_canonical_wire() {
        for (env, wire) in [
            ("signet", "signet"),
            ("testnet4", "testnet4"),
            ("Testnet4", "testnet4"),
        ] {
            let _env = xai_grok_test_support::EnvGuard::set("GROK_BITCOIN_NETWORK", env);
            let mut app = test_app_with_agent();
            let effects = start_routstr_watch_for_agent(
                &mut app,
                AgentId(0),
                format!("tb1q{wire}canonical000000000000000"),
                true,
            );
            assert!(
                matches!(
                    effects.first(),
                    Some(Effect::RoutstrWatchLoop { network, .. }) if network == wire
                ),
                "env {env:?} must wire as {wire:?}: {effects:?}"
            );
            assert_eq!(app.routstr_watch_network.as_deref(), Some(wire));
        }
    }

    /// Empty / unset env → mainnet start (product default).
    #[test]
    #[serial_test::serial(GROK_BITCOIN_NETWORK)]
    fn watch_start_empty_or_unset_env_mainnet() {
        {
            let _env = xai_grok_test_support::EnvGuard::unset("GROK_BITCOIN_NETWORK");
            let mut app = test_app_with_agent();
            let effects = start_routstr_watch_for_agent(
                &mut app,
                AgentId(0),
                "bc1qunsetmainnet00000000000000000".into(),
                true,
            );
            assert!(
                matches!(
                    effects.first(),
                    Some(Effect::RoutstrWatchLoop { network, .. }) if network == "mainnet"
                ),
                "unset → mainnet: {effects:?}"
            );
        }
        {
            let _env = xai_grok_test_support::EnvGuard::set("GROK_BITCOIN_NETWORK", "   ");
            let mut app = test_app_with_agent();
            let effects = start_routstr_watch_for_agent(
                &mut app,
                AgentId(0),
                "bc1qemptymainnet00000000000000000".into(),
                true,
            );
            assert!(
                matches!(
                    effects.first(),
                    Some(Effect::RoutstrWatchLoop { network, .. }) if network == "mainnet"
                ),
                "empty env → mainnet: {effects:?}"
            );
        }
    }

    /// Explicit override regtest/unknown fails closed (resume-shaped path).
    #[test]
    fn watch_start_override_regtest_fail_closed() {
        let mut app = test_app_with_agent();
        let effects = start_routstr_watch_for_agent_on_network(
            &mut app,
            AgentId(0),
            "bc1qoverrideregtest00000000000000".into(),
            Some("regtest".into()),
            true,
        );
        assert!(effects.is_empty(), "{effects:?}");
        assert!(app.routstr_watch_address.is_none());
        let text = agent_scrollback_text(&app, AgentId(0)).to_ascii_lowercase();
        assert!(
            text.contains("unknown") && text.contains("regtest"),
            "{text}"
        );
    }

    /// Persist must skip (not soft-Mainnet) when wire network is unknown.
    #[test]
    fn persist_skips_unknown_network_no_soft_mainnet() {
        use grok_bitcoin_wallet::watcher::load_watch_session_state;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watch_session.json");
        with_watch_session_path_for_test(path.clone(), || {
            persist_routstr_watch_running("bc1qunknownnetpersist00000000000", "regtest", 1);
            assert!(
                !path.exists(),
                "unknown network must not write durable session"
            );
            assert!(load_watch_session_state(&path).unwrap().is_none());

            // Canonical product label still persists.
            persist_routstr_watch_running("bc1qsignetpersist000000000000000", "signet", 2);
            let loaded = load_watch_session_state(&path).unwrap().expect("persisted");
            assert_eq!(loaded.network, "signet");
            assert_eq!(loaded.address, "bc1qsignetpersist000000000000000");
        });
    }

    /// Pure helpers: product acceptance parity with shell resolve.
    #[test]
    #[serial_test::serial(GROK_BITCOIN_NETWORK)]
    fn watch_network_helpers_fail_closed_parity() {
        let _env = xai_grok_test_support::EnvGuard::unset("GROK_BITCOIN_NETWORK");
        assert_eq!(network_from_env().unwrap(), "mainnet");
        assert_eq!(canonicalize_network("signet").unwrap(), "signet");
        assert_eq!(canonicalize_network("testnet4").unwrap(), "testnet4");
        assert_eq!(canonicalize_network("").unwrap(), "mainnet");
        assert_eq!(canonicalize_network("bitcoin").unwrap(), "mainnet"); // alias → canonical
        for bad in ["regtest", "mainet", "bogus"] {
            let err = canonicalize_network(bad).unwrap_err().to_ascii_lowercase();
            assert!(
                err.contains("unknown") && err.contains(bad),
                "canonicalize must fail-closed on {bad:?}: {err}"
            );
        }
        let _env = xai_grok_test_support::EnvGuard::set("GROK_BITCOIN_NETWORK", "regtest");
        let err = network_from_env().unwrap_err().to_ascii_lowercase();
        assert!(err.contains("unknown") && err.contains("regtest"), "{err}");
    }
}
