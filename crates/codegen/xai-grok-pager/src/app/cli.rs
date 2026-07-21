//! CLI argument parsing for the pager.
pub use crate::headless::OutputFormat;
use clap::{ArgAction, Parser, Subcommand, ValueHint};
use clap_complete::Shell;
use std::net::SocketAddr;
use std::path::PathBuf;
/// Top-level commands for the pager binary.
#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Run Grok without the interactive UI
    Agent(Box<AgentArgs>),
    /// Show the configuration Grok discovers for this directory
    Inspect {
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Manage running leader processes
    Leader(LeaderMgmtArgs),
    /// Sign out and clear cached credentials
    Logout {
        /// Clear only the stored OpenRouter API key (not xAI session auth).
        #[arg(long = "openrouter", conflicts_with = "routstr")]
        openrouter: bool,
        /// Clear only the stored Routstr API key (not xAI session auth).
        #[arg(long = "routstr", conflicts_with = "openrouter")]
        routstr: bool,
    },
    /// Sign in to Grok
    Login {
        /// Ignored (kept for backwards compatibility). OAuth2 is now the only auth method.
        #[arg(long, hide = true)]
        legacy: bool,
        /// Use Grok OAuth via auth.x.ai.
        #[arg(long = "oauth", alias = "oidc", conflicts_with_all = ["device_auth", "openrouter", "routstr"])]
        oauth: bool,
        /// Use device-code authentication for headless/remote environments.
        #[arg(
            long = "device-auth",
            visible_alias = "device-code",
            conflicts_with_all = ["oauth", "openrouter", "routstr"]
        )]
        device_auth: bool,
        /// Store an OpenRouter API key (for Grok 4.5 via OpenRouter).
        ///
        /// Keys go to the OS secret store (or `$GROK_HOME/provider_credentials.json`
        /// when the keyring is unavailable). Prefer `OPENROUTER_API_KEY` env over
        /// storing a key. Does not replace xAI login.
        #[arg(long = "openrouter", conflicts_with_all = ["oauth", "device_auth", "routstr"])]
        openrouter: bool,
        /// Store a Routstr API key (for Grok 4.5 via Bitcoin/Lightning/Cashu).
        ///
        /// Hot `sk-` / Cashu bearer only; never BIP-39. Prefer `ROUTSTR_API_KEY`
        /// env over storing a key. Does not replace xAI login.
        #[arg(long = "routstr", conflicts_with_all = ["oauth", "device_auth", "openrouter"])]
        routstr: bool,
        /// API key with `--openrouter` or `--routstr`. If omitted, prompts on stdin.
        #[arg(long = "api-key")]
        api_key: Option<String>,
        /// Authenticate for remote development environments (hidden).
        ///
        /// Field is always present so match arms stay feature-unification-safe
        /// across Bazel/cargo graphs; clap only registers `--devbox` when
        /// `devbox-login` is enabled (`arg(skip)` otherwise → always false).
        #[arg(skip)]
        devbox: bool,
    },
    /// Manage MCP server configurations
    Mcp(crate::mcp_cmd::McpArgs),
    /// Manage plugins and marketplace sources
    Plugin(crate::plugin_cmd::PluginArgs),
    /// Manage cross-session memory
    Memory(crate::memory_cmd::MemoryArgs),
    /// List available models and exit
    Models,
    /// List, search, or restore sessions
    Sessions(crate::sessions_cmd::SessionsArgs),
    /// Fetch and install managed configuration
    Setup {
        /// Print the fetched configuration as JSON instead of installing it;
        /// writes nothing to ~/.grok.
        #[arg(long)]
        json: bool,
    },
    /// Share a session and print the share URL
    #[command(hide = true)]
    Share(crate::share_cmd::ShareArgs),
    /// Run any command with local clipboard support (OSC 52 → system clipboard).
    #[cfg_attr(not(any(unix, windows)), command(hide = true))]
    #[command(long_about = "\
Run any command inside a local PTY that forwards its clipboard to yours.

Wraps an arbitrary command (for example `docker exec`, `kubectl exec`, or a
remote shell) in a local pseudo-terminal, intercepts OSC 52 clipboard escape
sequences from its output, and writes them to your local system clipboard. This
makes copy work when the program runs somewhere that cannot reach your
clipboard (containers, SSH) and your terminal does not handle OSC 52 itself
(for example Apple Terminal). The wrapped command's terminal is also kept in
sync with your window size.

Examples:
  grok wrap docker exec -it my-container bash
  grok wrap kubectl exec -it my-pod -- bash

See ~/.grok/README.md for more information.
")]
    Wrap(WrapArgs),
    /// Export a session transcript as Markdown
    Export(crate::export_cmd::ExportArgs),
    /// Export or upload session trace data
    Trace(crate::trace_cmd::TraceArgs),
    /// Check for updates or install a specific version
    /// Check freshness vs Surmount main (git SHA), or print how to rebuild.
    ///
    /// Grok OSS has no binary release train. `update --check` compares this
    /// build’s commit to github.com/SurmountSystems/grok-oss `main`.
    Update {
        /// Compare embedded git SHA to Surmount `main` (no install).
        #[arg(long)]
        check: bool,
        /// Emit machine-readable JSON output (for --check).
        #[arg(long)]
        json: bool,
        /// Force re-download via xAI updater (requires GROK_OSS_ENABLE_XAI_UPDATER=1).
        #[arg(long, hide = true)]
        force_reinstall: bool,
        /// Install a specific version via xAI updater (requires GROK_OSS_ENABLE_XAI_UPDATER=1).
        #[arg(long, hide = true)]
        version: Option<String>,
        /// xAI channel switch (hidden; requires GROK_OSS_ENABLE_XAI_UPDATER=1).
        #[arg(long, conflicts_with_all = ["stable", "enterprise"], hide = true)]
        alpha: bool,
        #[arg(long, conflicts_with_all = ["alpha", "enterprise"], hide = true)]
        stable: bool,
        #[arg(long, conflicts_with_all = ["alpha", "stable"], hide = true)]
        enterprise: bool,
    },
    /// Print version information
    #[command(visible_alias = "v")]
    Version {
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completion scripts (bash, zsh, fish, powershell, ...)
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Manage git worktrees
    Worktree(crate::worktree_cmd::WorktreeArgs),
    /// Expose this workspace to the Computer Hub (via the leader).
    ///
    /// Disabled by default and enabled server-side per account; set
    /// `GROK_WORKSPACE_COMMAND=1` to enable it locally for testing.
    #[command(hide = true)]
    Workspace(WorkspaceMgmtArgs),
    /// Open the Agent Dashboard view at startup.
    ///
    /// Centralised, agent-native overview of every session (top-level and
    /// subagents). Disabled when `[dashboard].enabled = false` in
    /// `~/.grok/config.toml` or when the `GROK_AGENT_DASHBOARD=0` env
    /// var is set.
    Dashboard,
    /// Routstr balance, top up, refund, fee ladder, and local funding helpers
    Routstr(RoutstrArgs),
}

/// Arguments for `grok routstr …`.
#[derive(Debug, clap::Args, Clone)]
pub struct RoutstrArgs {
    #[command(subcommand)]
    pub command: RoutstrCommand,
}

/// Subcommands under `grok routstr`.
#[derive(Debug, Subcommand, Clone)]
pub enum RoutstrCommand {
    /// Show remaining Routstr prepaid balance (requires API key)
    Balance,
    /// Create a live Routstr Lightning invoice (mainnet) or check payment status.
    ///
    /// Default amount: 1000 sats (API allows 1..=1_000_000). Pay BOLT11 with any
    /// Lightning wallet; on pay, status returns `sk-…` and we store it (unless
    /// `ROUTSTR_API_KEY` is set). Residual copy only if create fails.
    Topup {
        /// Amount in sats (default 1000; min 1, max 1_000_000)
        #[arg(long)]
        sats: Option<u64>,
        /// Poll a previously created invoice id (store api_key when paid)
        #[arg(long, conflicts_with = "recover")]
        status: Option<String>,
        /// Recover invoice status from a BOLT11 string (`POST /lightning/recover`)
        #[arg(long, conflicts_with = "status")]
        recover: Option<String>,
        /// Create invoice and print QR without polling for payment
        #[arg(long)]
        no_poll: bool,
    },
    /// Ensure Routstr key + prepaid float (alias for readiness / topup orchestrator).
    ///
    /// When already funded, prints balance. Otherwise creates a Lightning invoice
    /// like `topup`. Does **not** auto-select a model.
    Setup {
        /// Amount in sats when an invoice is needed (default 1000)
        #[arg(long)]
        sats: Option<u64>,
        /// Skip post-create payment poll
        #[arg(long)]
        no_poll: bool,
    },
    /// Redeem a Cashu token (`cashuA…`) into a new balance or top up an existing key.
    Redeem {
        /// Cashu token string (cashuA… / cashuB…)
        cashu_token: String,
    },
    /// Cashu mint path: NUT-04 quote → pay mint BOLT11 → proofs → redeem (when live).
    ///
    /// Requires feature `cashu-cdk` + `GROK_BITCOIN_CASHU_MINT_URL` + resolvable
    /// `grok-bitcoin-cdk-mint` helper (`proofs_mint_live`). SeedVault unlock (same
    /// gates as topup local-pay / spend). Token ≠ Routstr float until redeem
    /// succeeds. When not live / unlock cancel / failure: residual + P0
    /// `grok routstr topup` fall-through (never fabricates invoice or float).
    Mint {
        /// Amount in sats (default 1000; min 1, max 1_000_000)
        #[arg(long)]
        sats: Option<u64>,
        /// Resume after mint quote BOLT11 is paid: proofs mint + redeem
        #[arg(long = "complete", value_name = "QUOTE_ID")]
        complete: Option<String>,
    },
    /// Refund unused Routstr float via live node API, or melt a Cashu token to BOLT11.
    ///
    /// Default (no flags): `POST /v1/balance/refund` when a key exists — returns a
    /// Cashu token once (stdout); residual next-steps otherwise.
    ///
    /// With **both** `--token` and `--invoice`: local CDK melt when feature
    /// `cashu-cdk` + mint URL + resolvable `grok-bitcoin-cdk-mint` helper
    /// (`spend_live` / `refund_live`). SeedVault unlock (same gates as mint /
    /// spend). Success only when helper IPC returns state=PAID. **Never** claims
    /// Routstr sk- float (melt spends Cashu to LN). When not live / unlock
    /// cancel / fail: residual + node refund next-steps.
    Refund {
        /// Bearer Cashu token (`cashuA…` / `cashuB…`) to melt (requires `--invoice`)
        #[arg(long, requires = "invoice")]
        token: Option<String>,
        /// Destination BOLT11 for local melt (requires `--token`)
        #[arg(long, requires = "token")]
        invoice: Option<String>,
    },
    /// Create or unlock local wallet, confirm BIP-39 backup, show receive address
    Fund,
    /// Build (and optionally broadcast) a BIP84 P2WPKH payment from the local wallet.
    ///
    /// Dry-run by default: fee-aware select + sign + extract only. Pass
    /// `--broadcast` to submit via rate-limited mempool.space. Requires SeedVault
    /// unlock + recovery-phrase re-entry.
    Spend {
        /// Destination Bitcoin address
        address: String,
        /// Amount to send in satoshis
        sats: u64,
        /// Submit the signed transaction to the network (default: dry-run only)
        #[arg(long)]
        broadcast: bool,
        /// Fee rate in sat/vB (omit for explorer halfHour estimates when available, else default 5; must be > 0 if set)
        #[arg(long)]
        fee_rate: Option<u64>,
    },
    /// Rebuild a same-input BIP-125 RBF replacement (higher fee) for a stuck spend.
    ///
    /// Dry-run by default. Pass `--original-fee`, `--original-vbytes`, and each
    /// `--input txid:vout:amount:address` from a prior `spend` dry-run meta
    /// (same prevouts as the stuck tx). `--broadcast` submits via rate-limited
    /// mempool.space after SeedVault unlock + recovery-phrase re-entry.
    Rbf {
        /// Destination Bitcoin address (same payment intent as the original)
        address: String,
        /// Amount to send in satoshis (same payment intent as the original)
        sats: u64,
        /// Absolute fee of the original (stuck) transaction in sats
        #[arg(long)]
        original_fee: u64,
        /// Virtual size of the original transaction (from prior prepare meta)
        #[arg(long)]
        original_vbytes: u64,
        /// Original prevout for same-input replace: `txid:vout:amount_sats:address`
        /// (repeatable; at least one required — copy from spend dry-run meta)
        #[arg(long = "input", required = true, value_name = "TXID:VOUT:AMOUNT:ADDR")]
        inputs: Vec<String>,
        /// Submit the replacement to the network (default: dry-run only)
        #[arg(long)]
        broadcast: bool,
        /// Target fee rate in sat/vB for the replacement (omit for explorer halfHour /
        /// default 5; product uses BIP-125 recommended absolute fee, not floor rate)
        #[arg(long)]
        fee_rate: Option<u64>,
    },
    /// Build a CPFP child that spends a wallet-owned parent output (package fee bump).
    ///
    /// Dry-run by default. Pass `--parent-fee`, `--parent-vbytes`, and each
    /// `--parent txid:vout:amount:address` (output of the stuck parent you control).
    /// Optional `--extra-input` confirmed UTXOs fund the child fee when the parent
    /// alone is short. Does **not** replace the parent. `--broadcast` submits the
    /// child via rate-limited mempool.space after SeedVault unlock + re-entry.
    Cpfp {
        /// Destination Bitcoin address for the child payment
        address: String,
        /// Amount to send in satoshis on the child
        sats: u64,
        /// Absolute fee of the underpaying parent transaction in sats
        #[arg(long)]
        parent_fee: u64,
        /// Virtual size of the parent transaction
        #[arg(long)]
        parent_vbytes: u64,
        /// Parent output the child must spend: `txid:vout:amount_sats:address`
        /// (repeatable; at least one required)
        #[arg(long = "parent", required = true, value_name = "TXID:VOUT:AMOUNT:ADDR")]
        parents: Vec<String>,
        /// Optional confirmed UTXO to fund child fee: `txid:vout:amount_sats:address`
        #[arg(long = "extra-input", value_name = "TXID:VOUT:AMOUNT:ADDR")]
        extra_inputs: Vec<String>,
        /// Submit the child to the network (default: dry-run only)
        #[arg(long)]
        broadcast: bool,
        /// Target **package** fee rate in sat/vB (omit for explorer halfHour /
        /// default 5; product uses plan_cpfp_child_fee minimum absolute child fee)
        #[arg(long)]
        fee_rate: Option<u64>,
    },
    /// Print mempool.space recommended fee estimate ladder (sat/vB only)
    ///
    /// Ladder only — does not rebuild transactions. Not RBF (`grok routstr rbf`)
    /// or CPFP (`grok routstr cpfp`). Live fetch via rate-limited explorer; never
    /// invents rates when the explorer is unavailable (network error, rate-limit,
    /// or parse failure).
    #[command(
        about = grok_bitcoin_wallet::funding_cli::FEES_CLI_ABOUT,
        long_about = grok_bitcoin_wallet::funding_cli::FEES_CLI_LONG_ABOUT
    )]
    Fees {
        /// Bitcoin network (default: `GROK_BITCOIN_NETWORK` or mainnet)
        #[arg(long)]
        network: Option<String>,
    },
    /// List local wallet UTXOs and on-chain balance (gap-limit ChainSource sync).
    ///
    /// Requires SeedVault unlock + recovery-phrase re-entry (same gate as spend).
    /// Never invents UTXOs; empty wallet prints zero balance. Not a spend path.
    #[command(
        about = grok_bitcoin_wallet::funding_cli::UTXOS_CLI_ABOUT,
        long_about = grok_bitcoin_wallet::funding_cli::UTXOS_CLI_LONG_ABOUT
    )]
    Utxos {
        /// Bitcoin network (default: `GROK_BITCOIN_NETWORK` or mainnet)
        #[arg(long)]
        network: Option<String>,
    },
}
/// Arguments for the `wrap` subcommand: the command to run, then its args.
#[derive(Debug, clap::Args, Clone)]
pub struct WrapArgs {
    /// Command to run, followed by its arguments
    /// (e.g. `docker exec -it my-container bash`).
    /// On Unix a single quoted string or an aliased command runs via `$SHELL -i -c`.
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "CMD"
    )]
    pub command: Vec<String>,
}
/// Targets a running leader process by PID (used by `grok leader` / `grok workspace`).
#[derive(Debug, clap::Args, Clone, Default)]
pub struct LeaderTargetArgs {
    /// Leader process ID from `grok leader list`.
    #[arg(long)]
    pub pid: Option<u32>,
}
#[derive(Debug, clap::Args, Clone)]
pub struct LeaderMgmtArgs {
    #[command(subcommand)]
    pub command: LeaderMgmtCommand,
}
#[derive(Debug, Subcommand, Clone)]
pub enum LeaderMgmtCommand {
    /// List running leader processes
    List {
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Show details for a leader process
    Info {
        #[command(flatten)]
        target: LeaderTargetArgs,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Stop all running leader processes
    Kill,
}
#[derive(Debug, clap::Args, Clone)]
pub struct WorkspaceMgmtArgs {
    #[command(subcommand)]
    pub command: WorkspaceMgmtCommand,
}
#[derive(Debug, Subcommand, Clone)]
pub enum WorkspaceMgmtCommand {
    /// Start (or update) the workspace→hub exposure.
    Start(WorkspaceStartArgs),
    /// Drain and disconnect from the hub, keeping the exposure warm.
    Pause {
        #[command(flatten)]
        target: LeaderTargetArgs,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Reconnect a paused exposure to the hub.
    Resume {
        #[command(flatten)]
        target: LeaderTargetArgs,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Stop exposing the workspace (the leader keeps running).
    Stop {
        #[command(flatten)]
        target: LeaderTargetArgs,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Restart the exposure (stop, then start with the given options).
    Restart(WorkspaceStartArgs),
    /// Show the current workspace-exposure status.
    #[command(visible_alias = "list")]
    Status {
        #[command(flatten)]
        target: LeaderTargetArgs,
        /// Emit machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
}
#[derive(Debug, clap::Args, Clone)]
pub struct WorkspaceStartArgs {
    /// Computer Hub WebSocket URL (default: `[hub].url`, then the prod hub).
    #[arg(long, value_name = "URL")]
    pub hub_url: Option<String>,
    /// Workspace root directory to expose. Defaults to the current directory.
    #[arg(long, value_name = "DIR", value_hint = ValueHint::DirPath)]
    pub cwd: Option<PathBuf>,
    /// Force leader mode for this command, overriding config.
    #[arg(long, conflicts_with = "no_leader")]
    pub leader: bool,
    /// Refuse to start even when config enables leader mode.
    #[arg(long, conflicts_with = "leader")]
    pub no_leader: bool,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
}
/// Arguments for the `agent` subcommand.
#[derive(Debug, clap::Args, Clone)]
pub struct AgentArgs {
    /// Run authentication before starting the agent
    #[arg(
        long = "reauth",
        visible_alias = "--reauthenticate",
        default_value = "false"
    )]
    pub reauthenticate: bool,
    /// Model ID to use
    #[arg(short = 'm', long = "model", value_name = "MODEL")]
    pub model: Option<String>,
    /// Reasoning effort for reasoning models
    #[clap(
        long = "reasoning-effort",
        visible_alias = "effort",
        value_name = "EFFORT",
        overrides_with = "reasoning_effort"
    )]
    pub reasoning_effort: Option<String>,
    /// Auto-approve all tool executions
    #[arg(long = "always-approve", alias = "yolo")]
    pub yolo: bool,
    /// Path to an agent profile file.
    #[arg(long = "agent-profile", value_name = "PATH")]
    pub agent_profile: Option<PathBuf>,
    /// Load a plugin from this directory for this process only (repeatable).
    /// Highest-priority plugin scope; always trusted — hooks and MCP servers
    /// activate without a prompt. Used by the Agent SDKs to inject
    /// per-connection plugins.
    #[arg(long = "plugin-dir", value_name = "DIR", value_hint = ValueHint::DirPath)]
    pub plugin_dirs: Vec<PathBuf>,
    /// Connect to a shared leader process instead of starting a new agent.
    /// Allows multiple clients to share one backend.
    /// Defaults to [cli] use_leader in config.toml.
    #[arg(long, conflicts_with = "no_leader")]
    pub leader: bool,
    /// Start a new agent even when config enables leader mode.
    #[arg(long, conflicts_with = "leader")]
    pub no_leader: bool,
    #[command(flatten)]
    pub headless: HeadlessArgs,
    /// Override the CLI chat proxy base URL.
    #[arg(long = "cli-chat-proxy-base-url")]
    pub cli_chat_proxy_base_url: Option<String>,
    /// Override the public xAI API base URL.
    #[arg(long = "xai-api-base-url")]
    pub xai_api_base_url: Option<String>,
    /// Agent runtime mode
    #[command(subcommand)]
    pub mode: Option<AgentCmd>,
}
impl AgentArgs {
    /// Canonicalized `--plugin-dir` paths, warning to stderr and skipping
    /// anything that isn't an existing directory (stderr is safe: JSON-RPC
    /// rides stdout).
    pub fn canonical_plugin_dirs(&self) -> Vec<PathBuf> {
        self.plugin_dirs
            .iter()
            .filter_map(|p| match dunce::canonicalize(p) {
                Ok(canonical) if canonical.is_dir() => Some(canonical),
                Ok(_) => {
                    eprintln!(
                        "grok: --plugin-dir {}: not a directory; skipping",
                        p.display()
                    );
                    None
                }
                Err(e) => {
                    eprintln!("grok: --plugin-dir {}: {e}; skipping", p.display());
                    None
                }
            })
            .collect()
    }
}
/// Agent sub-subcommands.
#[derive(Debug, Subcommand, Clone)]
pub enum AgentCmd {
    /// Run the agent over stdio
    Stdio,
    /// Run the agent headlessly over the Grok WebSocket relay
    Headless(HeadlessArgs),
    /// Run the agent as a WebSocket server
    Serve(ServeArgs),
    /// Run as the shared leader process for other clients
    Leader(LeaderArgs),
}
/// WebSocket URL override arguments, used by headless / leader / serve modes.
#[derive(Debug, clap::Args, Clone, Default)]
pub struct HeadlessArgs {
    #[arg(long = "grok-ws-origin")]
    pub grok_ws_origin: Option<String>,
    #[arg(long = "grok-ws-url")]
    pub grok_ws_url: Option<String>,
}
/// Arguments for the `agent serve` subcommand.
#[derive(Debug, clap::Args, Clone)]
pub struct ServeArgs {
    /// Address for the server to listen on
    #[arg(long, default_value = "127.0.0.1:2419")]
    pub bind: SocketAddr,
    /// Secret token for client authentication (auto-generated if not provided)
    #[arg(long, env = "GROK_AGENT_SECRET")]
    pub secret: Option<String>,
    /// Remote agent URL for proxy mode
    #[arg(long)]
    pub remote: Option<String>,
    /// Authentication and WebSocket URL overrides
    #[command(flatten)]
    pub headless: HeadlessArgs,
}
impl ServeArgs {
    /// Get the secret, generating a random one if not provided.
    pub fn get_secret(&self) -> String {
        self.secret
            .clone()
            .unwrap_or_else(|| generate_random_key(12))
    }
}
/// Generate a random alphanumeric key of the given length.
fn generate_random_key(len: usize) -> String {
    let raw = uuid::Uuid::new_v4().to_string().replace('-', "");
    raw.chars().cycle().take(len).collect()
}
/// Arguments for the `agent leader` subcommand.
#[derive(Debug, clap::Args, Clone)]
pub struct LeaderArgs {
    /// Keep the leader running after the last client disconnects.
    #[arg(long)]
    pub no_exit_on_disconnect: bool,
    /// Defer the grok.com relay WebSocket until the first headless IPC client
    /// registers. Without this flag the leader connects the relay eagerly at
    /// startup — required for bare leaders (headless remote env / systemd) that
    /// receive remote prompts *through* the relay. Passed by leaders auto-spawned
    /// from interactive clients (TUI/IDE), which only need the relay if a
    /// headless client appears.
    #[arg(long)]
    pub relay_on_demand: bool,
    /// Disable periodic auto-update checks for the leader.
    #[arg(long)]
    pub no_auto_update: bool,
    /// All environment URL overrides (passed from follower process)
    #[command(flatten)]
    pub headless: HeadlessArgs,
}
/// Return the version string for `--version` / `-v` (clap `ArgAction::Version`).
///
/// Grok OSS: upstream package version + short git SHA (no release channel).
/// Uses a `OnceLock` so the result is `'static` for clap.
fn version_with_channel() -> &'static str {
    use std::sync::OnceLock;
    static V: OnceLock<String> = OnceLock::new();
    // env!("VERSION_WITH_COMMIT") is set by this crate's build.rs.
    V.get_or_init(|| env!("VERSION_WITH_COMMIT").to_string())
}
#[derive(Debug, Clone, Parser)]
#[command(
    name = "grok-oss",
    version = version_with_channel(),
    about = "Grok OSS TUI (unofficial Surmount fork of Grok Build)",
    disable_version_flag = true,
    next_display_order = None,
    help_template = "\
{before-help}{about-with-newline}
{usage-heading} {usage}

Arguments:
{positionals}

Options:
{options}

Commands:
{subcommands}{after-help}\
"
)]
pub struct PagerArgs {
    /// Print version
    #[arg(short = 'v', short_alias = 'V', long = "version", action = ArgAction::Version)]
    pub version: (),
    /// Working directory.
    #[arg(long)]
    pub cwd: Option<PathBuf>,
    /// Use a custom leader socket path instead of the default `~/.grok/leader.sock`.
    #[arg(
        long = "leader-socket",
        value_name = "PATH",
        global = true,
        value_hint = ValueHint::FilePath
    )]
    pub leader_socket: Option<PathBuf>,
    /// Enable debug logging.
    #[arg(long = "debug", global = true)]
    pub debug: bool,
    /// Write debug logs to FILE.
    #[arg(
        long = "debug-file",
        value_name = "FILE",
        global = true,
        value_hint = ValueHint::FilePath
    )]
    pub debug_file: Option<PathBuf>,
    /// Auto-approve all tool executions.
    #[clap(
        long = "always-approve",
        alias = "yolo",
        alias = "dangerously-skip-permissions"
    )]
    pub yolo: bool,
    /// Trust this folder and persist the decision to the trust store.
    #[arg(long = "trust", alias = "trust-folder", hide = true)]
    pub trust: bool,
    /// Permission allow rule (compat alias: --allowedTools).
    #[arg(
        long = "allow",
        alias = "allowedTools",
        value_name = "RULE",
        value_delimiter = ','
    )]
    pub allow_rules: Vec<String>,
    /// Permission deny rule (compat alias: --disallowedTools).
    #[arg(
        long = "deny",
        alias = "disallowedTools",
        value_name = "RULE",
        value_delimiter = ','
    )]
    pub deny_rules: Vec<String>,
    /// Single-turn prompt. Prints the response to stdout and exits.
    #[clap(
        short = 'p',
        long = "single",
        alias = "print",
        value_name = "PROMPT",
        conflicts_with_all = &["prompt_json",
        "prompt_file"]
    )]
    pub single: Option<String>,
    /// Single-turn prompt as JSON content blocks.
    #[clap(
        long = "prompt-json",
        value_name = "JSON",
        conflicts_with_all = &["single",
        "prompt_file"]
    )]
    pub prompt_json: Option<String>,
    /// Single-turn prompt from a file.
    #[clap(
        long = "prompt-file",
        value_name = "PATH",
        conflicts_with_all = &["single",
        "prompt_json"],
        value_hint = ValueHint::FilePath
    )]
    pub prompt_file: Option<PathBuf>,
    /// Send the prompt exactly as given.
    #[clap(long)]
    pub verbatim: bool,
    /// Output format for headless mode.
    #[clap(long = "output-format", value_enum, default_value = "plain")]
    pub output_format: OutputFormat,
    /// JSON Schema for structured output. When set, the model is constrained to
    /// produce JSON matching this schema. Implies --output-format json.
    /// Example: --json-schema '{"type":"object","properties":{"name":{"type":"string"}}}'
    #[clap(long = "json-schema", value_name = "SCHEMA")]
    pub json_schema: Option<String>,
    /// Model ID to use.
    #[clap(short = 'm', long = "model", value_name = "MODEL")]
    pub model: Option<String>,
    /// Reasoning effort for reasoning models
    #[clap(
        long = "reasoning-effort",
        visible_alias = "effort",
        value_name = "EFFORT",
        overrides_with = "reasoning_effort"
    )]
    pub reasoning_effort: Option<String>,
    /// Extra rules to append to the system prompt.
    #[clap(long = "rules", alias = "append-system-prompt")]
    pub rules: Option<String>,
    /// Compaction mode [summary|transcript|segments]: `summary` (default) adds
    /// no pointer; `transcript` points at the raw transcript; `segments`
    /// persists per-segment markdown to grep. Sets `GROK_COMPACTION_MODE`.
    #[clap(long = "compaction-mode", value_name = "MODE", hide = true)]
    pub compaction_mode: Option<String>,
    /// Segments verbatim detail [none|minimal|balanced|verbose] (default
    /// `verbose`). Only affects `--compaction-mode segments`. Sets
    /// `GROK_COMPACTION_DETAIL`.
    #[clap(long = "compaction-detail", value_name = "DETAIL", hide = true)]
    pub compaction_detail: Option<String>,
    /// Override the agent's system prompt (compat alias: --system-prompt).
    #[clap(
        long = "system-prompt-override",
        alias = "system-prompt",
        value_name = "PROMPT"
    )]
    pub system_prompt_override: Option<String>,
    /// Resume a session by ID, or the most recent if omitted.
    #[arg(
        long = "resume",
        short = 'r',
        value_name = "SESSION_ID",
        num_args = 0..= 1,
        default_missing_value = "",
        conflicts_with_all = ["continue_last_session"]
    )]
    pub resume_session: Option<String>,
    /// Resume a previous session by session ID (alias for --resume).
    #[arg(
        long = "load",
        value_name = "SESSION_ID",
        hide = true,
        conflicts_with_all = ["continue_last_session"]
    )]
    pub load_session: Option<String>,
    /// Continue the most recent session for the current working directory.
    #[arg(
        short = 'c',
        long = "continue",
        conflicts_with_all = ["resume_session",
        "load_session"]
    )]
    pub continue_last_session: bool,
    /// Use a specific session UUID for a **new** conversation (must be a valid
    /// UUID and must not already exist under the target session directory).
    /// With `--resume`/`--continue`, only valid together with `--fork-session`
    /// (names the forked session). Does not resume existing sessions — use
    /// `--resume` / `--continue` instead.
    #[arg(short = 's', long = "session-id", value_name = "SESSION_ID")]
    pub session_id: Option<String>,
    /// When resuming (`--resume` / `--continue`), create a new session ID
    /// instead of reusing the original (optionally set via `--session-id`).
    #[arg(long = "fork-session")]
    pub fork_session: bool,
    /// Start the session in a new git worktree, optionally named.
    #[arg(short = 'w', long = "worktree", num_args = 0..= 1, default_missing_value = "")]
    pub worktree: Option<String>,
    /// Branch, tag, or commit to base the worktree on (with `--worktree`).
    /// Defaults to the current HEAD of the source checkout when omitted.
    #[arg(long = "worktree-ref", visible_alias = "ref", requires = "worktree")]
    pub worktree_ref: Option<String>,
    /// Check out the original session's commit when resuming.
    #[arg(long = "restore-code", requires = "resume_session")]
    pub restore_code: bool,
    /// Disable plan mode.
    #[arg(long = "no-plan")]
    pub no_plan: bool,
    /// Disable subagent spawning.
    #[arg(long = "no-subagents")]
    pub no_subagents: bool,
    /// Disable structured question prompts from the agent.
    #[arg(long = "no-ask-user", hide = true)]
    pub no_ask_user: bool,
    /// Enable cross-session memory.
    #[arg(long = "experimental-memory", conflicts_with = "no_memory")]
    pub experimental_memory: bool,
    /// Disable cross-session memory for this session.
    #[arg(long = "no-memory", conflicts_with = "experimental_memory")]
    pub no_memory: bool,
    /// Agent name or definition file path.
    #[arg(long = "agent", value_name = "NAME")]
    pub agent: Option<String>,
    /// Inline subagent definitions as JSON.
    #[arg(long = "agents", value_name = "JSON")]
    pub agents_json: Option<String>,
    /// Built-in tools to allow (comma-separated).
    #[arg(long = "tools", value_name = "TOOLS")]
    pub cli_tools: Option<String>,
    /// Built-in tools to remove (comma-separated).
    #[arg(long = "disallowed-tools", value_name = "TOOLS")]
    pub cli_disallowed_tools: Option<String>,
    /// Maximum number of agent turns.
    #[arg(
        long = "max-turns",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub max_turns: Option<u32>,
    /// Permission mode.
    #[arg(
        long = "permission-mode",
        value_name = "MODE",
        value_parser = clap::builder::PossibleValuesParser::new(
            xai_grok_shell::agent::config::PermissionMode::VALID_VALUES
        )
    )]
    pub permission_mode_flag: Option<String>,
    /// Disable web search and web fetch tools.
    #[arg(long = "disable-web-search")]
    pub disable_web_search: bool,
    /// Append a self-verification loop to the prompt (headless only).
    #[arg(long = "check", alias = "self-verify", conflicts_with = "no_subagents")]
    pub self_verify: bool,
    /// Exit as soon as the first agent turn ends, without waiting for pending
    /// background bash/monitor tasks or background subagents (headless only).
    /// Default for all `grok -p` runs is to wait (up to `--background-wait-timeout`)
    /// so eval harnesses see full task completion. Use this for fast scripts that
    /// only need the first turn's text. Does not wait for server-side auto-wake
    /// output or persistent monitors (those hit the timeout).
    #[arg(long = "no-wait-for-background", hide = true)]
    pub no_wait_for_background: bool,
    /// Max seconds to wait for background work after the first turn ends
    /// (headless only). Applies to bash/monitor `task_completed`, background
    /// subagents (`SubagentFinished`), and any still-running non-persistent
    /// work. Persistent `monitor(persistent:true)` never completes and always
    /// waits the full timeout — use `--no-wait-for-background` or a lower
    /// timeout for throughput. Conflicts with `--no-wait-for-background`.
    #[arg(
        long = "background-wait-timeout",
        value_name = "SECS",
        default_value = "600",
        conflicts_with = "no_wait_for_background",
        hide = true,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub background_wait_timeout_secs: u64,
    /// Run the task N ways in parallel and pick the best (headless only).
    #[arg(long = "best-of-n", value_name = "N", conflicts_with = "no_subagents")]
    pub best_of_n: Option<u32>,
    /// Sandbox profile for filesystem and network access.
    #[arg(long, env = "GROK_SANDBOX", value_name = "PROFILE")]
    pub sandbox: Option<String>,
    /// Session storage mode: local or writeback.
    #[arg(long = "storage-mode", value_name = "MODE", hide = true)]
    pub storage_mode: Option<String>,
    /// Override the client identifier sent to the agent.
    #[arg(long = "client-identifier", value_name = "ID", hide = true)]
    pub client_identifier: Option<String>,
    /// Hunk tracker mode: agent_only, all_dirty, or off ("disabled" is an
    /// alias for off, which turns the hunk tracker off entirely).
    #[arg(long = "hunk-tracker-mode", value_name = "MODE", hide = true)]
    pub hunk_tracker_mode: Option<String>,
    /// Enable terminal support for the agent.
    #[arg(long = "terminal", hide = true)]
    pub terminal: bool,
    /// Enable client-side file reads.
    #[arg(long = "fs-read", hide = true)]
    pub fs_read: bool,
    /// Enable client-side file writes.
    #[arg(long = "fs-write", hide = true)]
    pub fs_write: bool,
    /// Disable automatic updates for this session.
    #[arg(long = "no-auto-update", hide = true)]
    pub no_auto_update: bool,
    /// Enable the runtime turn-end TodoGate for this session.
    ///
    /// Session-scoped (not persisted). Highest precedence —
    /// overrides remote `todo_gate_enabled` and the built-in
    /// default (which is `false`).
    #[arg(long = "todo-gate", hide = true)]
    pub todo_gate: bool,
    /// Set the installer field in config.toml.
    #[arg(long = "installer", value_name = "VALUE", hide = true)]
    pub installer: Option<String>,
    /// Run inline instead of using the terminal alternate screen.
    #[arg(long = "no-alt-screen")]
    pub no_alt_screen: bool,
    /// Experimental: scrollback-native rendering. Finalized blocks are printed
    /// into the terminal's native scrollback (use the terminal's own scroll /
    /// selection); a small pinned region holds the prompt + running turn.
    /// Session-scoped only — does not write config. To default plain `grok` to
    /// minimal, set `[ui] screen_mode = "minimal"` in ~/.grok/config.toml.
    #[arg(long = "minimal")]
    pub minimal: bool,
    /// Open in the standard fullscreen TUI for this session, overriding a
    /// config `[ui] screen_mode = "minimal"` preference. Session-scoped only —
    /// does not write config. Fullscreen-vs-inline still follows the alt-screen
    /// policy (--no-alt-screen, [terminal] alt_screen, terminal auto-detection).
    #[arg(long = "fullscreen", conflicts_with = "minimal")]
    pub fullscreen: bool,
    /// Write sampling events to ~/.grok/logs/sampling.jsonl.
    #[arg(long = "log-sampling", env = "GROK_LOG_SAMPLING", hide = true)]
    pub log_sampling: bool,
    /// Show the login screen even when credentials are already available.
    #[arg(long = "force-login", hide = true)]
    pub force_login: bool,
    /// Use OAuth when the welcome screen starts authentication.
    #[arg(long = "oauth")]
    pub oauth: bool,
    /// Connect to a shared leader process.
    #[arg(long, conflicts_with = "no_leader", hide = true)]
    pub leader: bool,
    /// Run standalone even when leader mode is configured.
    #[arg(long, conflicts_with = "leader", hide = true)]
    pub no_leader: bool,
    /// Initial prompt for the interactive session, e.g. `grok "fix the bug"` or `grok --worktree=feat "create this feature"`.
    #[arg(
        value_name = "PROMPT",
        conflicts_with_all = &["single",
        "prompt_json",
        "prompt_file"]
    )]
    pub prompt: Option<String>,
    /// Subcommand (e.g., `agent`).
    #[command(subcommand, next_display_order = 0)]
    pub command: Option<Command>,
}
/// Outcome of resolving the startup sandbox profile for a (possibly resumed)
/// session. See [`PagerArgs::startup_sandbox_profile`].
#[derive(Debug, PartialEq, Eq)]
pub enum SandboxStartup {
    /// Apply this profile. `None` means fall through to config/`off`.
    Apply(Option<String>),
    /// Resume requested a profile that differs from the one the session was
    /// created with. Refused so resuming can't silently change the sandbox.
    Conflict { requested: String, saved: String },
}
/// How resume-selection flags resolve for sandbox profile lookup.
/// Derived from [`PagerArgs::session_startup_intent`]; new-with-id is not a resume.
#[derive(Debug, PartialEq, Eq)]
pub enum ResumeTarget {
    /// Resume (or fork-from) a specific session id.
    SessionId(String),
    /// Resume (or fork-from) the most recent session for the current directory.
    MostRecentForCwd,
    /// Not resuming an existing session (new auto or new-with-id).
    None,
}
impl PagerArgs {
    /// Parse CLI arguments and apply `--cwd` if provided.
    pub fn parse_and_apply_cwd() -> anyhow::Result<Self> {
        let bin_name = std::env::args()
            .next()
            .as_deref()
            .map(std::path::Path::new)
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .filter(|n| *n == "grok" || *n == "agent")
            .unwrap_or("grok")
            .to_owned();
        let mut args = Self::parse_from(std::iter::once(bin_name).chain(std::env::args().skip(1)));
        if let Some(socket) = args.leader_socket.take() {
            args.leader_socket = Some(std::path::absolute(&socket).unwrap_or(socket));
        }
        if let Some(file) = args.debug_file.take() {
            args.debug_file = Some(std::path::absolute(&file).unwrap_or(file));
        }
        if let Some(ref cwd) = args.cwd {
            std::env::set_current_dir(cwd).map_err(|e| {
                anyhow::anyhow!("Failed to set working directory to {:?}: {}", cwd, e)
            })?;
        }
        Ok(args)
    }
    /// Optional-flag accessor; always `false` in builds without the optional
    /// feature, so call sites need no `cfg` of their own.
    pub fn chat(&self) -> bool {
        false
    }
    /// Get the session ID to resume, from either --resume or --load (hidden alias).
    ///
    /// Returns `None` when `--resume` was used without a value (the empty-string
    /// sentinel). Use [`resume_most_recent`] to detect that case.
    pub fn session_to_resume(&self) -> Option<&str> {
        self.resume_session
            .as_deref()
            .or(self.load_session.as_deref())
            .filter(|s| !s.is_empty())
    }
    /// Whether `--resume` was used without a session ID (meaning "resume most recent").
    pub fn resume_most_recent(&self) -> bool {
        self.resume_session.as_deref() == Some("")
    }
    /// Classify flags for sandbox profile lookup on an existing session.
    ///
    /// Uses [`Self::session_startup_intent`]; invalid combos fall through to
    /// `None` (caller should have rejected intent errors earlier at startup).
    pub fn resume_target(&self) -> ResumeTarget {
        use crate::app::session_startup::SessionStartupIntent;
        match self.session_startup_intent() {
            Ok(SessionStartupIntent::Resume {
                session_id: Some(id),
                ..
            })
            | Ok(SessionStartupIntent::ForkFrom {
                source_session_id: Some(id),
                ..
            }) => ResumeTarget::SessionId(id),
            Ok(SessionStartupIntent::Resume {
                most_recent_for_cwd: true,
                ..
            })
            | Ok(SessionStartupIntent::ForkFrom {
                most_recent_for_cwd: true,
                ..
            }) => ResumeTarget::MostRecentForCwd,
            _ => ResumeTarget::None,
        }
    }
    /// Resolve the sandbox profile to apply at startup, accounting for the
    /// profile the resumed session was created with. `saved` is the resumed
    /// session's persisted profile (read once via [`Self::saved_resume_profile`]).
    ///
    /// A session's profile is fixed at creation. Resuming restores it; passing an
    /// explicit `--sandbox`/`GROK_SANDBOX` that differs from the saved profile is
    /// refused (changing a session's sandbox on resume is a safety footgun). A
    /// matching flag, or no flag, resumes with the saved profile.
    pub fn startup_sandbox_profile(&self, saved: Option<&str>) -> SandboxStartup {
        let explicit = self.sandbox.as_deref().filter(|s| !s.is_empty());
        Self::resolve_startup_sandbox(explicit, saved.map(String::from))
    }
    /// The sandbox profile persisted with the session being resumed, if any.
    /// Local, best-effort; `None` when not resuming or nothing is found. Read once
    /// for the profile resume resolution.
    pub fn saved_resume_profile(&self) -> Option<String> {
        let cwd_buf = std::env::current_dir().ok();
        let cwd_str = cwd_buf.as_deref().map(|p| p.to_string_lossy());
        let cwd = cwd_str.as_deref();
        match self.resume_target() {
            ResumeTarget::SessionId(id) => {
                xai_grok_shell::session::persistence::resumed_session_sandbox_profile(
                    Some(&id),
                    cwd,
                )
            }
            ResumeTarget::MostRecentForCwd => {
                xai_grok_shell::session::persistence::resumed_session_sandbox_profile(None, cwd)
            }
            ResumeTarget::None => None,
        }
    }
    /// Pure resolution of the explicit flag against the resumed session's saved
    /// profile. Separated from disk access so it can be unit-tested.
    fn resolve_startup_sandbox(explicit: Option<&str>, saved: Option<String>) -> SandboxStartup {
        match (explicit, saved) {
            (Some(x), Some(s))
                if x.parse::<xai_grok_sandbox::ProfileName>().ok()
                    != s.parse::<xai_grok_sandbox::ProfileName>().ok() =>
            {
                SandboxStartup::Conflict {
                    requested: x.to_owned(),
                    saved: s,
                }
            }
            (Some(x), _) => SandboxStartup::Apply(Some(x.to_owned())),
            (None, saved) => SandboxStartup::Apply(saved),
        }
    }
    /// The initial interactive prompt from the positional argument, trimmed.
    ///
    /// Returns `None` when no positional prompt was given or it is only
    /// whitespace. This is the `grok "<prompt>"` launch form; the headless
    /// `-p`/`--single` path is handled separately.
    pub fn initial_prompt(&self) -> Option<&str> {
        self.prompt
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_flag_exits_zero() {
        let err = PagerArgs::try_parse_from(["grok", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(
            err.exit_code() == 0,
            "--version must exit 0; got {}",
            err.exit_code()
        );
    }
    #[test]
    fn version_short_flag_exits_zero() {
        let err = PagerArgs::try_parse_from(["grok", "-v"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(
            err.exit_code() == 0,
            "-v must exit 0; got {}",
            err.exit_code()
        );
    }
    #[test]
    fn resume_target_classifies_flags() {
        assert_eq!(
            PagerArgs::try_parse_from(["grok"]).unwrap().resume_target(),
            ResumeTarget::None
        );
        assert_eq!(
            PagerArgs::try_parse_from(["grok", "-c"])
                .unwrap()
                .resume_target(),
            ResumeTarget::MostRecentForCwd
        );
        assert_eq!(
            PagerArgs::try_parse_from(["grok", "--resume"])
                .unwrap()
                .resume_target(),
            ResumeTarget::MostRecentForCwd
        );
        assert_eq!(
            PagerArgs::try_parse_from(["grok", "--resume", "sess-1"])
                .unwrap()
                .resume_target(),
            ResumeTarget::SessionId("sess-1".to_string())
        );
        assert_eq!(
            PagerArgs::try_parse_from(["grok", "-s", "sess-2"])
                .unwrap()
                .resume_target(),
            ResumeTarget::None
        );
        assert_eq!(
            PagerArgs::try_parse_from(["grok", "-r", "old", "--fork-session"])
                .unwrap()
                .resume_target(),
            ResumeTarget::SessionId("old".to_string())
        );
    }
    /// The screen-mode flags are mutually exclusive: the pair exists so one
    /// can override the other's sticky config value, so accepting both in one
    /// invocation would be ambiguous.
    #[test]
    fn minimal_and_fullscreen_flags_conflict() {
        let args = PagerArgs::try_parse_from(["grok", "--minimal"]).unwrap();
        assert!(args.minimal && !args.fullscreen);
        let args = PagerArgs::try_parse_from(["grok", "--fullscreen"]).unwrap();
        assert!(args.fullscreen && !args.minimal);
        let err = PagerArgs::try_parse_from(["grok", "--minimal", "--fullscreen"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    #[test]
    fn agent_plugin_dir_repeatable_and_canonicalized() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("plugin");
        std::fs::create_dir(&dir).unwrap();
        let file = tmp.path().join("file.txt");
        std::fs::write(&file, "x").unwrap();
        let missing = tmp.path().join("missing");
        let args = PagerArgs::try_parse_from([
            "grok".as_ref(),
            "agent".as_ref(),
            "--no-leader".as_ref(),
            "--plugin-dir".as_ref(),
            dir.as_os_str(),
            "--plugin-dir".as_ref(),
            file.as_os_str(),
            "--plugin-dir".as_ref(),
            missing.as_os_str(),
            "stdio".as_ref(),
        ])
        .unwrap();
        let Some(Command::Agent(agent)) = args.command else {
            panic!("expected agent subcommand");
        };
        assert_eq!(agent.plugin_dirs, vec![dir.clone(), file, missing]);
        assert!(matches!(agent.mode, Some(AgentCmd::Stdio)));
        assert!(agent.no_leader);
        assert_eq!(
            agent.canonical_plugin_dirs(),
            vec![dunce::canonicalize(&dir).unwrap()]
        );
    }
    #[test]
    fn resolve_startup_sandbox_cases() {
        use SandboxStartup::{Apply, Conflict};
        assert_eq!(
            PagerArgs::resolve_startup_sandbox(Some("strict"), None),
            Apply(Some("strict".to_string()))
        );
        assert_eq!(
            PagerArgs::resolve_startup_sandbox(Some("workspace"), Some("workspace".to_string())),
            Apply(Some("workspace".to_string()))
        );
        assert_eq!(
            PagerArgs::resolve_startup_sandbox(Some("read-only"), Some("workspace".to_string())),
            Conflict {
                requested: "read-only".to_string(),
                saved: "workspace".to_string(),
            }
        );
        assert_eq!(
            PagerArgs::resolve_startup_sandbox(None, Some("workspace".to_string())),
            Apply(Some("workspace".to_string()))
        );
        assert_eq!(PagerArgs::resolve_startup_sandbox(None, None), Apply(None));
        assert_eq!(
            PagerArgs::resolve_startup_sandbox(Some("readonly"), Some("read-only".to_string())),
            Apply(Some("readonly".to_string()))
        );
        assert_eq!(
            PagerArgs::resolve_startup_sandbox(Some("none"), Some("off".to_string())),
            Apply(Some("none".to_string()))
        );
    }
    #[test]
    fn startup_sandbox_profile_no_resume() {
        assert_eq!(
            PagerArgs::try_parse_from(["grok", "--sandbox", "strict"])
                .unwrap()
                .startup_sandbox_profile(None),
            SandboxStartup::Apply(Some("strict".to_string()))
        );
        assert_eq!(
            PagerArgs::try_parse_from(["grok", "--sandbox", ""])
                .unwrap()
                .startup_sandbox_profile(None),
            SandboxStartup::Apply(None)
        );
        assert_eq!(
            PagerArgs::try_parse_from(["grok"])
                .unwrap()
                .startup_sandbox_profile(None),
            SandboxStartup::Apply(None)
        );
    }
    #[test]
    fn leader_socket_flag_parses_at_root() {
        let args = PagerArgs::try_parse_from(["grok", "--leader-socket", "/tmp/leader-x.sock"])
            .expect("--leader-socket parses at the root");
        assert_eq!(
            args.leader_socket.as_deref(),
            Some(std::path::Path::new("/tmp/leader-x.sock"))
        );
    }
    #[test]
    fn leader_socket_flag_is_global_for_subcommands() {
        let args = PagerArgs::try_parse_from([
            "grok",
            "agent",
            "leader",
            "--leader-socket",
            "/tmp/leader-y.sock",
        ])
        .expect("--leader-socket parses after a subcommand (global)");
        assert_eq!(
            args.leader_socket.as_deref(),
            Some(std::path::Path::new("/tmp/leader-y.sock"))
        );
    }
    #[test]
    fn leader_socket_flag_defaults_to_none() {
        let args = PagerArgs::try_parse_from(["grok"]).expect("bare grok parses");
        assert!(args.leader_socket.is_none());
    }
    #[test]
    fn leader_mgmt_list_info_kill_parse() {
        let list = PagerArgs::try_parse_from(["grok", "leader", "list", "--json"])
            .expect("grok leader list --json");
        assert!(matches!(
            list.command,
            Some(Command::Leader(LeaderMgmtArgs {
                command: LeaderMgmtCommand::List { json: true },
            }))
        ));
        let info = PagerArgs::try_parse_from(["grok", "leader", "info", "--pid", "42"])
            .expect("grok leader info --pid");
        assert!(matches!(
            info.command,
            Some(Command::Leader(LeaderMgmtArgs {
                command: LeaderMgmtCommand::Info {
                    target: LeaderTargetArgs { pid: Some(42) },
                    json: false,
                },
            }))
        ));
        let kill = PagerArgs::try_parse_from(["grok", "leader", "kill"]).expect("grok leader kill");
        assert!(matches!(
            kill.command,
            Some(Command::Leader(LeaderMgmtArgs {
                command: LeaderMgmtCommand::Kill,
            }))
        ));
        assert!(PagerArgs::try_parse_from(["grok", "leader", "profile"]).is_err());
    }
    #[test]
    fn debug_file_flag_parses_and_is_global() {
        let root = PagerArgs::try_parse_from(["grok", "--debug-file", "/tmp/fire.txt"])
            .expect("--debug-file parses at the root");
        assert_eq!(
            root.debug_file.as_deref(),
            Some(std::path::Path::new("/tmp/fire.txt"))
        );
        let sub =
            PagerArgs::try_parse_from(["grok", "agent", "stdio", "--debug-file", "/tmp/f.txt"])
                .expect("--debug-file parses after a subcommand (global)");
        assert_eq!(
            sub.debug_file.as_deref(),
            Some(std::path::Path::new("/tmp/f.txt"))
        );
    }
    #[test]
    fn debug_file_flag_defaults_to_none() {
        let args = PagerArgs::try_parse_from(["grok"]).expect("bare grok parses");
        assert!(args.debug_file.is_none());
    }
    #[test]
    fn positional_prompt_seeds_interactive_session() {
        let args =
            PagerArgs::try_parse_from(["grok", "fix the bug"]).expect("positional prompt parses");
        assert_eq!(args.initial_prompt(), Some("fix the bug"));
        assert!(args.command.is_none());
        assert!(args.single.is_none());
    }
    #[test]
    fn bare_grok_has_no_initial_prompt() {
        let args = PagerArgs::try_parse_from(["grok"]).expect("bare grok parses");
        assert_eq!(args.initial_prompt(), None);
    }
    #[test]
    fn initial_prompt_trims_and_ignores_whitespace_only() {
        let args = PagerArgs::try_parse_from(["grok", "  spaced  "]).expect("padded prompt parses");
        assert_eq!(args.initial_prompt(), Some("spaced"));
        let blank = PagerArgs::try_parse_from(["grok", "   "]).expect("blank prompt parses");
        assert_eq!(blank.initial_prompt(), None);
    }
    #[test]
    fn subcommand_takes_precedence_over_positional_prompt() {
        let args = PagerArgs::try_parse_from(["grok", "logout"]).expect("subcommand parses");
        assert!(matches!(
            args.command,
            Some(Command::Logout {
                openrouter: false,
                routstr: false
            })
        ));
        assert!(args.prompt.is_none());
    }

    #[test]
    fn login_openrouter_parses_api_key() {
        let args =
            PagerArgs::try_parse_from(["grok", "login", "--openrouter", "--api-key", "sk-or-test"])
                .expect("login --openrouter parses");
        match args.command {
            Some(Command::Login {
                openrouter: true,
                routstr: false,
                api_key: Some(key),
                ..
            }) => assert_eq!(key, "sk-or-test"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn login_routstr_parses_api_key() {
        let args = PagerArgs::try_parse_from([
            "grok",
            "login",
            "--routstr",
            "--api-key",
            "sk-routstr-test",
        ])
        .expect("login --routstr parses");
        match args.command {
            Some(Command::Login {
                openrouter: false,
                routstr: true,
                api_key: Some(key),
                ..
            }) => assert_eq!(key, "sk-routstr-test"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn logout_openrouter_parses() {
        let args = PagerArgs::try_parse_from(["grok", "logout", "--openrouter"])
            .expect("logout --openrouter parses");
        assert!(matches!(
            args.command,
            Some(Command::Logout {
                openrouter: true,
                routstr: false
            })
        ));
    }

    #[test]
    fn logout_routstr_parses() {
        let args = PagerArgs::try_parse_from(["grok", "logout", "--routstr"])
            .expect("logout --routstr parses");
        assert!(matches!(
            args.command,
            Some(Command::Logout {
                openrouter: false,
                routstr: true
            })
        ));
    }

    #[test]
    fn routstr_balance_parses() {
        let args = PagerArgs::try_parse_from(["grok", "routstr", "balance"])
            .expect("routstr balance parses");
        assert!(matches!(
            args.command,
            Some(Command::Routstr(RoutstrArgs {
                command: RoutstrCommand::Balance
            }))
        ));
    }

    #[test]
    fn routstr_topup_parses_sats() {
        let args = PagerArgs::try_parse_from(["grok", "routstr", "topup", "--sats", "21000"])
            .expect("routstr topup parses");
        match args.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Topup {
                        sats: Some(21_000),
                        status: None,
                        recover: None,
                        no_poll: false,
                    },
            })) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_topup_parses_status() {
        let args = PagerArgs::try_parse_from(["grok", "routstr", "topup", "--status", "inv123"])
            .expect("routstr topup status parses");
        match args.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Topup {
                        sats: None,
                        status: Some(id),
                        recover: None,
                        no_poll: false,
                    },
            })) if id == "inv123" => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_topup_parses_recover() {
        let args =
            PagerArgs::try_parse_from(["grok", "routstr", "topup", "--recover", "lnbc10u1ptest"])
                .expect("routstr topup recover parses");
        match args.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Topup {
                        recover: Some(b),
                        status: None,
                        ..
                    },
            })) if b == "lnbc10u1ptest" => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_setup_and_redeem_parse() {
        let setup = PagerArgs::try_parse_from(["grok", "routstr", "setup", "--sats", "500"])
            .expect("routstr setup parses");
        match setup.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Setup {
                        sats: Some(500),
                        no_poll: false,
                    },
            })) => {}
            other => panic!("unexpected: {other:?}"),
        }
        let redeem = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "redeem",
            "cashuAabcdefghijklmnopqrstuvwxyz",
        ])
        .expect("routstr redeem parses");
        match redeem.command {
            Some(Command::Routstr(RoutstrArgs {
                command: RoutstrCommand::Redeem { cashu_token },
            })) => {
                assert!(cashu_token.starts_with("cashuA"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        let mint = PagerArgs::try_parse_from(["grok", "routstr", "mint", "--sats", "210"])
            .expect("routstr mint parses");
        match mint.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Mint {
                        sats: Some(210),
                        complete: None,
                    },
            })) => {}
            other => panic!("unexpected mint: {other:?}"),
        }
        let mint_c =
            PagerArgs::try_parse_from(["grok", "routstr", "mint", "--complete", "quote-abc"])
                .expect("routstr mint --complete parses");
        match mint_c.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Mint {
                        sats: None,
                        complete: Some(q),
                    },
            })) => assert_eq!(q, "quote-abc"),
            other => panic!("unexpected mint complete: {other:?}"),
        }
    }

    #[test]
    fn routstr_refund_and_fund_parse() {
        let refund = PagerArgs::try_parse_from(["grok", "routstr", "refund"])
            .expect("routstr refund parses");
        assert!(matches!(
            refund.command,
            Some(Command::Routstr(RoutstrArgs {
                command: RoutstrCommand::Refund {
                    token: None,
                    invoice: None
                }
            }))
        ));
        let melt = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "refund",
            "--token",
            "cashuAabcdefghijklmnopqrstuvwxyz012345",
            "--invoice",
            "lnbc1x",
        ])
        .expect("routstr refund melt parses");
        match melt.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Refund {
                        token: Some(t),
                        invoice: Some(inv),
                    },
            })) => {
                assert!(t.starts_with("cashuA"));
                assert!(inv.starts_with("lnbc"));
            }
            other => panic!("unexpected melt refund: {other:?}"),
        }
        // Token without invoice / invoice without token rejected by clap requires.
        assert!(
            PagerArgs::try_parse_from(["grok", "routstr", "refund", "--token", "cashuAabc",])
                .is_err()
        );
        assert!(
            PagerArgs::try_parse_from(["grok", "routstr", "refund", "--invoice", "lnbc1x",])
                .is_err()
        );
        let fund =
            PagerArgs::try_parse_from(["grok", "routstr", "fund"]).expect("routstr fund parses");
        assert!(matches!(
            fund.command,
            Some(Command::Routstr(RoutstrArgs {
                command: RoutstrCommand::Fund
            }))
        ));
    }

    #[test]
    fn routstr_spend_parses_dry_run_and_broadcast() {
        let dry = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "spend",
            "bc1qtestaddress000000000000000000000",
            "21000",
        ])
        .expect("routstr spend dry-run parses");
        match dry.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Spend {
                        address,
                        sats: 21_000,
                        broadcast: false,
                        fee_rate: None,
                    },
            })) => {
                assert!(address.starts_with("bc1q"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        let live = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "spend",
            "bc1qtestaddress000000000000000000000",
            "1000",
            "--broadcast",
            "--fee-rate",
            "8",
        ])
        .expect("routstr spend --broadcast parses");
        match live.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Spend {
                        sats: 1000,
                        broadcast: true,
                        fee_rate: Some(8),
                        ..
                    },
            })) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_rbf_parses_dry_run_and_broadcast() {
        let sample_input = format!(
            "{}:0:100000:bc1qtestaddress000000000000000000000",
            "ab".repeat(32)
        );
        let dry = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "rbf",
            "bc1qtestaddress000000000000000000000",
            "21000",
            "--original-fee",
            "705",
            "--original-vbytes",
            "141",
            "--input",
            &sample_input,
        ])
        .expect("routstr rbf dry-run parses");
        match dry.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Rbf {
                        address,
                        sats: 21_000,
                        original_fee: 705,
                        original_vbytes: 141,
                        ref inputs,
                        broadcast: false,
                        fee_rate: None,
                    },
            })) => {
                assert!(address.starts_with("bc1q"));
                assert_eq!(inputs.len(), 1);
                assert_eq!(inputs[0], sample_input);
            }
            other => panic!("unexpected: {other:?}"),
        }
        let live = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "rbf",
            "bc1qtestaddress000000000000000000000",
            "1000",
            "--original-fee",
            "500",
            "--original-vbytes",
            "100",
            "--input",
            &sample_input,
            "--broadcast",
            "--fee-rate",
            "20",
        ])
        .expect("routstr rbf --broadcast parses");
        match live.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Rbf {
                        sats: 1000,
                        original_fee: 500,
                        original_vbytes: 100,
                        broadcast: true,
                        fee_rate: Some(20),
                        ref inputs,
                        ..
                    },
            })) => {
                assert_eq!(inputs.len(), 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_rbf_requires_original_flags_and_input() {
        // Missing --original-fee / --original-vbytes / --input
        let err = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "rbf",
            "bc1qtestaddress000000000000000000000",
            "21000",
        ])
        .expect_err("rbf without required flags must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        let err = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "rbf",
            "bc1qtestaddress000000000000000000000",
            "21000",
            "--original-fee",
            "705",
            "--original-vbytes",
            "141",
            // no --input
        ])
        .expect_err("rbf without --input must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn routstr_rbf_fee_rate_zero_rejected_by_product_parse() {
        // Clap accepts u64 0; product parse_rbf_replace_request rejects it.
        let sample_input = format!("{}:0:100000:bc1qrecv", "ab".repeat(32));
        let parsed = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "rbf",
            "bc1qtestaddress000000000000000000000",
            "1000",
            "--original-fee",
            "500",
            "--original-vbytes",
            "100",
            "--input",
            &sample_input,
            "--fee-rate",
            "0",
        ])
        .expect("clap allows fee_rate 0; product rejects later");
        match parsed.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Rbf {
                        fee_rate: Some(0),
                        ref inputs,
                        original_fee: 500,
                        original_vbytes: 100,
                        ..
                    },
            })) => {
                assert_eq!(inputs.len(), 1);
                let err = grok_bitcoin_wallet::funding_cli::parse_rbf_replace_request(
                    "bc1qtestaddress000000000000000000000",
                    1000,
                    500,
                    100,
                    inputs,
                    false,
                    Some(0),
                )
                .unwrap_err();
                assert!(
                    err.to_string().to_ascii_lowercase().contains("fee"),
                    "{err}"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_cpfp_parses_dry_run_and_broadcast() {
        let sample_parent = format!(
            "{}:1:80000:bc1qtestaddress000000000000000000000",
            "cd".repeat(32)
        );
        let sample_extra = format!(
            "{}:0:50000:bc1qtestaddress000000000000000000000",
            "ef".repeat(32)
        );
        let dry = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "cpfp",
            "bc1qtestaddress000000000000000000000",
            "40000",
            "--parent-fee",
            "200",
            "--parent-vbytes",
            "200",
            "--parent",
            &sample_parent,
        ])
        .expect("routstr cpfp dry-run parses");
        match dry.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Cpfp {
                        address,
                        sats: 40_000,
                        parent_fee: 200,
                        parent_vbytes: 200,
                        ref parents,
                        ref extra_inputs,
                        broadcast: false,
                        fee_rate: None,
                    },
            })) => {
                assert!(address.starts_with("bc1q"));
                assert_eq!(parents.len(), 1);
                assert_eq!(parents[0], sample_parent);
                assert!(extra_inputs.is_empty());
            }
            other => panic!("unexpected: {other:?}"),
        }
        let live = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "cpfp",
            "bc1qtestaddress000000000000000000000",
            "30000",
            "--parent-fee",
            "100",
            "--parent-vbytes",
            "141",
            "--parent",
            &sample_parent,
            "--extra-input",
            &sample_extra,
            "--broadcast",
            "--fee-rate",
            "20",
        ])
        .expect("routstr cpfp --broadcast parses");
        match live.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Cpfp {
                        sats: 30_000,
                        parent_fee: 100,
                        parent_vbytes: 141,
                        broadcast: true,
                        fee_rate: Some(20),
                        ref parents,
                        ref extra_inputs,
                        ..
                    },
            })) => {
                assert_eq!(parents.len(), 1);
                assert_eq!(extra_inputs.len(), 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_cpfp_requires_parent_flags() {
        let err = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "cpfp",
            "bc1qtestaddress000000000000000000000",
            "40000",
        ])
        .expect_err("cpfp without required flags must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);

        let err = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "cpfp",
            "bc1qtestaddress000000000000000000000",
            "40000",
            "--parent-fee",
            "200",
            "--parent-vbytes",
            "200",
            // no --parent
        ])
        .expect_err("cpfp without --parent must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn routstr_cpfp_fee_rate_zero_rejected_by_product_parse() {
        let sample_parent = format!("{}:1:80000:bc1qrecv", "cd".repeat(32));
        let parsed = PagerArgs::try_parse_from([
            "grok",
            "routstr",
            "cpfp",
            "bc1qtestaddress000000000000000000000",
            "1000",
            "--parent-fee",
            "200",
            "--parent-vbytes",
            "200",
            "--parent",
            &sample_parent,
            "--fee-rate",
            "0",
        ])
        .expect("clap allows fee_rate 0; product rejects later");
        match parsed.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Cpfp {
                        fee_rate: Some(0),
                        ref parents,
                        parent_fee: 200,
                        parent_vbytes: 200,
                        ref extra_inputs,
                        ..
                    },
            })) => {
                assert_eq!(parents.len(), 1);
                let err = grok_bitcoin_wallet::funding_cli::parse_cpfp_child_request(
                    "bc1qtestaddress000000000000000000000",
                    1000,
                    200,
                    200,
                    parents,
                    extra_inputs,
                    false,
                    Some(0),
                )
                .unwrap_err();
                assert!(
                    err.to_string().to_ascii_lowercase().contains("fee"),
                    "{err}"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn routstr_fees_parses_default_and_network() {
        let bare =
            PagerArgs::try_parse_from(["grok", "routstr", "fees"]).expect("routstr fees parses");
        match bare.command {
            Some(Command::Routstr(RoutstrArgs {
                command: RoutstrCommand::Fees { network: None },
            })) => {}
            other => panic!("unexpected: {other:?}"),
        }
        let with_net =
            PagerArgs::try_parse_from(["grok", "routstr", "fees", "--network", "signet"])
                .expect("routstr fees --network parses");
        match with_net.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Fees {
                        network: Some(ref n),
                    },
            })) => {
                assert_eq!(n, "signet");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // fees has no --fee-rate (ladder only; RBF/CPFP keep their own rates).
        let err = PagerArgs::try_parse_from(["grok", "routstr", "fees", "--fee-rate", "5"])
            .expect_err("fees must not accept --fee-rate");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn routstr_utxos_parses_default_and_network() {
        let bare =
            PagerArgs::try_parse_from(["grok", "routstr", "utxos"]).expect("routstr utxos parses");
        match bare.command {
            Some(Command::Routstr(RoutstrArgs {
                command: RoutstrCommand::Utxos { network: None },
            })) => {}
            other => panic!("unexpected: {other:?}"),
        }
        let with_net =
            PagerArgs::try_parse_from(["grok", "routstr", "utxos", "--network", "signet"])
                .expect("routstr utxos --network parses");
        match with_net.command {
            Some(Command::Routstr(RoutstrArgs {
                command:
                    RoutstrCommand::Utxos {
                        network: Some(ref n),
                    },
            })) => {
                assert_eq!(n, "signet");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // utxos is observational — not a spend/broadcast path.
        let err = PagerArgs::try_parse_from(["grok", "routstr", "utxos", "--broadcast"])
            .expect_err("utxos must not accept --broadcast");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn routstr_fees_clap_help_is_ladder_only_not_rebuild() {
        use clap::CommandFactory;
        let mut root = PagerArgs::command();
        let routstr = root
            .find_subcommand_mut("routstr")
            .expect("routstr subcommand");
        let fees = routstr
            .find_subcommand_mut("fees")
            .expect("fees subcommand");
        let about = fees.get_about().map(|s| s.to_string()).unwrap_or_default();
        let long = fees
            .get_long_about()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let help = fees.render_long_help().to_string();
        let joined = format!("{about}\n{long}\n{help}").to_ascii_lowercase();

        // Shared wallet constants (about/long_about) — must not drift from honesty.
        assert_eq!(about, grok_bitcoin_wallet::funding_cli::FEES_CLI_ABOUT);
        assert_eq!(long, grok_bitcoin_wallet::funding_cli::FEES_CLI_LONG_ABOUT);

        assert!(
            joined.contains("ladder"),
            "fees help must say ladder: {joined}"
        );
        assert!(
            joined.contains("never invents") || joined.contains("unavailable"),
            "fees help must be honest about unavailable estimates: {joined}"
        );
        assert!(
            joined.contains("rbf") && joined.contains("cpfp"),
            "fees help should point at rbf/cpfp as separate: {joined}"
        );
        // Not a rebuild/broadcast path (negative phrasing like "does not rebuild" is OK).
        assert!(
            !joined.contains("broadcast") && !joined.contains("--broadcast"),
            "fees help must not claim broadcast: {joined}"
        );
        if joined.contains("rebuild") {
            assert!(
                joined.contains("does not rebuild") || joined.contains("not rebuild"),
                "fees help may only mention rebuild to deny it: {joined}"
            );
        }
    }

    #[test]
    fn positional_prompt_conflicts_with_headless_single() {
        let err = PagerArgs::try_parse_from(["grok", "-p", "headless", "interactive"])
            .expect_err("positional prompt + --single must conflict");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    #[test]
    fn worktree_flag_and_initial_prompt_combine() {
        let a = PagerArgs::try_parse_from(["grok", "do the thing", "-w"])
            .expect("prompt then bare -w parses");
        assert_eq!(a.initial_prompt(), Some("do the thing"));
        assert_eq!(a.worktree.as_deref(), Some(""));
        let b = PagerArgs::try_parse_from(["grok", "--worktree=feat", "do the thing"])
            .expect("--worktree=name + positional parses");
        assert_eq!(b.initial_prompt(), Some("do the thing"));
        assert_eq!(b.worktree.as_deref(), Some("feat"));
        let c = PagerArgs::try_parse_from(["grok", "-w", "x"]).expect("-w x parses");
        assert_eq!(c.worktree.as_deref(), Some("x"));
        assert_eq!(c.initial_prompt(), None);
    }
    #[test]
    fn trust_flag_parses_on_pager_and_alias() {
        let bare = PagerArgs::try_parse_from(["grok"]).expect("bare grok parses");
        assert!(!bare.trust);
        let long = PagerArgs::try_parse_from(["grok", "--trust"]).expect("--trust parses");
        assert!(long.trust);
        let alias =
            PagerArgs::try_parse_from(["grok", "--trust-folder"]).expect("--trust-folder parses");
        assert!(alias.trust);
    }
    #[test]
    fn reasoning_effort_and_effort_alias_parse_same_field() {
        let long = PagerArgs::try_parse_from(["grok", "--reasoning-effort", "high"])
            .expect("--reasoning-effort parses");
        assert_eq!(long.reasoning_effort.as_deref(), Some("high"));
        let alias =
            PagerArgs::try_parse_from(["grok", "--effort", "high"]).expect("--effort alias parses");
        assert_eq!(alias.reasoning_effort.as_deref(), Some("high"));
    }
    #[test]
    fn reasoning_effort_accepts_max_and_remapped_ids() {
        let max = PagerArgs::try_parse_from(["grok", "--effort", "max"]).expect("max parses");
        assert_eq!(max.reasoning_effort.as_deref(), Some("max"));
        let deep =
            PagerArgs::try_parse_from(["grok", "--reasoning-effort", "deep"]).expect("deep parses");
        assert_eq!(deep.reasoning_effort.as_deref(), Some("deep"));
    }
    #[test]
    fn reasoning_effort_last_flag_wins_when_both_names_set() {
        let args =
            PagerArgs::try_parse_from(["grok", "--reasoning-effort", "low", "--effort", "high"])
                .expect("both effort flag names parse");
        assert_eq!(args.reasoning_effort.as_deref(), Some("high"));
        let reverse =
            PagerArgs::try_parse_from(["grok", "--effort", "high", "--reasoning-effort", "low"])
                .expect("both effort flag names parse (reverse order)");
        assert_eq!(reverse.reasoning_effort.as_deref(), Some("low"));
    }
    #[test]
    fn agent_args_effort_alias_parses() {
        let args = PagerArgs::try_parse_from(["grok", "agent", "--effort", "max", "stdio"])
            .expect("agent --effort parses");
        let Command::Agent(agent) = args.command.expect("agent subcommand") else {
            panic!("expected agent subcommand");
        };
        assert_eq!(agent.reasoning_effort.as_deref(), Some("max"));
    }
}
