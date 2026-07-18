//! Memory-aware wrapper around cargo (or any command).
//!
//! Polls host memory while a child process runs. When free memory falls below
//! a high-water mark, terminates the child process group and restarts with
//! fewer cargo jobs so incremental compilation can continue from `target/`.
//!
//! Designed for free CI runners (~16GB) where uncapped monorepo builds OOM.
//! Not a system daemon -- one process per build invocation.

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Restart when available memory is below this fraction of total (default 15% free).
const DEFAULT_HIGH_WATER: f64 = 0.15;
const DEFAULT_JOBS_START: u32 = 2;
const DEFAULT_JOBS_MIN: u32 = 1;
const DEFAULT_MAX_RESTARTS: u32 = 3;
const DEFAULT_POLL_MS: u64 = 1500;

#[derive(Debug, Clone)]
struct Config {
    high_water: f64,
    jobs_start: u32,
    jobs_min: u32,
    max_restarts: u32,
    poll: Duration,
    use_mold: bool,
    cargo: PathBuf,
    child_env: Vec<(OsString, OsString)>,
    /// Env keys to remove from the child (e.g. CARGO_ENCODED_RUSTFLAGS).
    child_env_remove: Vec<OsString>,
}

impl Config {
    fn from_env() -> Self {
        let high_water = env_f64("CARGO_MEM_HIGH_WATER", DEFAULT_HIGH_WATER).clamp(0.05, 0.5);
        let jobs_start = env_u32("CARGO_MEM_JOBS_START", DEFAULT_JOBS_START).max(1);
        let jobs_min = env_u32("CARGO_MEM_JOBS_MIN", DEFAULT_JOBS_MIN)
            .max(1)
            .min(jobs_start);
        let max_restarts = env_u32("CARGO_MEM_MAX_RESTARTS", DEFAULT_MAX_RESTARTS);
        let poll =
            Duration::from_millis(u64::from(env_u32("CARGO_MEM_POLL_MS", DEFAULT_POLL_MS as u32)));
        let use_mold = env_truthy("CARGO_MEM_USE_MOLD") || env_truthy("USE_MOLD");
        let cargo = env::var_os("CARGO")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("cargo"));
        Self {
            high_water,
            jobs_start,
            jobs_min,
            max_restarts,
            poll,
            use_mold,
            cargo,
            child_env: Vec::new(),
            child_env_remove: Vec::new(),
        }
    }
}

fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_truthy(key: &str) -> bool {
    matches!(
        env::var(key).as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

#[derive(Debug, Clone, Copy)]
struct MemInfo {
    total_kb: u64,
    available_kb: u64,
}

impl MemInfo {
    fn available_ratio(self) -> f64 {
        if self.total_kb == 0 {
            return 1.0;
        }
        self.available_kb as f64 / self.total_kb as f64
    }
}

fn read_meminfo() -> io::Result<MemInfo> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/meminfo")?;
        let mut total = None;
        let mut available = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                total = parse_kb(rest);
            } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                available = parse_kb(rest);
            }
        }
        match (total, available) {
            (Some(total_kb), Some(available_kb)) => Ok(MemInfo {
                total_kb,
                available_kb,
            }),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MemTotal/MemAvailable missing from /proc/meminfo",
            )),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(MemInfo {
            total_kb: 1,
            available_kb: 1,
        })
    }
}

#[cfg(target_os = "linux")]
fn parse_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse().ok()
}

fn eprint_log(msg: impl AsRef<str>) {
    let _ = writeln!(io::stderr(), "cargo-mem-guard: {}", msg.as_ref());
}

fn usage() -> ! {
    let _ = writeln!(
        io::stderr(),
        "\
cargo-mem-guard -- memory-aware cargo runner

Usage:
  cargo-mem-guard [--mold] [--jobs-start N] -- cargo <args...>
  cargo-mem-guard [--mold] cargo <args...>

Environment:
  CARGO_MEM_HIGH_WATER   restart when MemAvailable/MemTotal is below this (default {DEFAULT_HIGH_WATER})
  CARGO_MEM_JOBS_START   initial -j / CARGO_BUILD_JOBS (default {DEFAULT_JOBS_START})
  CARGO_MEM_JOBS_MIN     floor after restarts (default {DEFAULT_JOBS_MIN})
  CARGO_MEM_MAX_RESTARTS max pressure restarts (default {DEFAULT_MAX_RESTARTS})
  CARGO_MEM_POLL_MS      poll interval ms (default {DEFAULT_POLL_MS})
  CARGO_MEM_USE_MOLD=1   append mold link-arg to RUSTFLAGS when mold is on PATH
  USE_MOLD=1             same as CARGO_MEM_USE_MOLD
  CARGO                  cargo binary (default: cargo)

On memory pressure the child process group is terminated and the same command
is restarted with fewer jobs so target/ incremental state can be reused.
"
    );
    std::process::exit(2);
}

fn parse_args(args: Vec<String>) -> (Config, Vec<String>) {
    let mut config = Config::from_env();
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => usage(),
            "--mold" => {
                config.use_mold = true;
                i += 1;
            }
            "--jobs-start" => {
                config.jobs_start = args
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage());
                config.jobs_min = config.jobs_min.min(config.jobs_start);
                i += 2;
            }
            "--" => {
                i += 1;
                break;
            }
            other if other.starts_with('-') => {
                eprint_log(format!("unknown option {other}"));
                usage();
            }
            _ => break,
        }
    }
    let cmd: Vec<String> = args[i..].to_vec();
    if cmd.is_empty() {
        eprint_log("missing command (expected cargo ...)");
        usage();
    }
    (config, cmd)
}

fn mold_on_path() -> bool {
    env::var_os("PATH")
        .map(|p| env::split_paths(&p).any(|dir| dir.join("mold").is_file()))
        .unwrap_or(false)
}

/// Unit separator cargo uses in CARGO_ENCODED_RUSTFLAGS.
const RUSTFLAGS_UNIT_SEP: char = '\x1f';

/// Linux host triples we force mold on via target-specific env.
const LINUX_TARGET_RUSTFLAGS_KEYS: [&str; 2] = [
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
];

/// Pure plan for mold-related child env edits (unit-tested).
///
/// Cargo joins rustflags from several sources onto the rustc link line
/// (host `~/.cargo/config.toml` `build.rustflags` + workspace target flags +
/// env). Free-GHA / developer hosts often inject `-fuse-ld=wild` via host
/// config; if we only set `CARGO_TARGET_*`, wild still appears next to mold
/// and gcc dies on the unrecognized option.
///
/// Env vs config (practical):
/// - `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` replace `build.rustflags`
/// - `CARGO_TARGET_<triple>_RUSTFLAGS` replaces `target.<triple>.rustflags`
/// - rustc may still emit its own `-fuse-ld=lld` for self-contained linking
///
/// Strategy when mold is on PATH:
/// 1. Always set plain `RUSTFLAGS` to force_mold(parent global or empty) so
///    host `build.rustflags` wild cannot survive.
/// 2. Always set linux `CARGO_TARGET_*` (seed workspace defaults when unset)
///    so force-unwind-tables / aarch64 cpu flags are not lost when target
///    config is replaced.
/// 3. Remove `CARGO_ENCODED_RUSTFLAGS` for the child when it was set so cargo
///    cannot prefer a stale encoded form over our plain RUSTFLAGS.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MoldEnvPlan {
    /// When Some, set child RUSTFLAGS to this value.
    rustflags: Option<String>,
    /// Remove CARGO_ENCODED_RUSTFLAGS from the child env.
    remove_encoded: bool,
    /// (key, value) pairs to set on the child.
    target_flags: Vec<(String, String)>,
}

/// Workspace defaults matching `.cargo/config.toml` for linux gnu triples.
/// Used when we must set CARGO_TARGET_* (which replaces config) and the parent
/// had no prior value for that key -- keeps force-unwind-tables (and aarch64
/// target-cpu) from being dropped.
fn default_linux_target_rustflags(key: &str) -> &'static str {
    match key {
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS" => "-C force-unwind-tables=yes",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS" => {
            "-C target-cpu=neoverse-v2 -C force-unwind-tables=yes"
        }
        _ => "",
    }
}

/// Build a mold env plan from parent env snapshots (no process I/O).
///
/// - `encoded`: `Some` if CARGO_ENCODED_RUSTFLAGS is present (even empty).
/// - `plain`: `Some` if RUSTFLAGS is present (even empty).
/// - `target_priors`: prior values for LINUX_TARGET_RUSTFLAGS_KEYS (None = unset).
fn plan_mold_rustflags(
    mold_ok: bool,
    encoded: Option<&str>,
    plain: Option<&str>,
    target_priors: &[Option<&str>; 2],
) -> MoldEnvPlan {
    let remove_encoded = encoded.is_some();
    // Empty encoded is still "present" for cargo precedence; fall through to
    // plain content when encoded is empty.
    let raw_global = match encoded {
        Some(enc) if !enc.is_empty() => decode_encoded_rustflags(enc),
        Some(_) | None => plain.unwrap_or("").to_string(),
    };
    let parent_global = encoded.is_some() || plain.is_some();

    // mold_ok: always set RUSTFLAGS so host ~/.cargo build.rustflags (wild)
    // cannot coexist with mold on the rustc link line.
    // mold missing: only rewrite when parent already had global flags.
    let rustflags = if mold_ok {
        Some(force_mold_rustflags(&raw_global))
    } else if parent_global {
        Some(strip_fuse_ld_rustflags(&raw_global))
    } else {
        None
    };

    let mut target_flags = Vec::new();
    for (i, key) in LINUX_TARGET_RUSTFLAGS_KEYS.iter().enumerate() {
        let prior = target_priors[i];
        if mold_ok {
            // CARGO_TARGET_* env replaces config for this triple -- seed
            // workspace defaults when prior unset so force-unwind-tables live.
            let base = prior.unwrap_or_else(|| default_linux_target_rustflags(key));
            target_flags.push(((*key).to_string(), force_mold_rustflags(base)));
        } else if let Some(p) = prior {
            // Mold missing: only rewrite keys already present (strip fuse-ld).
            target_flags.push(((*key).to_string(), strip_fuse_ld_rustflags(p)));
        }
    }

    MoldEnvPlan {
        rustflags,
        remove_encoded,
        target_flags,
    }
}

fn apply_mold_rustflags(config: &mut Config) {
    if !config.use_mold {
        return;
    }
    let mold_ok = mold_on_path();
    if !mold_ok {
        eprint_log("USE_MOLD set but mold not on PATH; stripping competing fuse-ld only");
    }

    let encoded = env::var("CARGO_ENCODED_RUSTFLAGS").ok();
    let plain = env::var("RUSTFLAGS").ok();
    let target_priors = [
        env::var(LINUX_TARGET_RUSTFLAGS_KEYS[0]).ok(),
        env::var(LINUX_TARGET_RUSTFLAGS_KEYS[1]).ok(),
    ];
    let plan = plan_mold_rustflags(
        mold_ok,
        encoded.as_deref(),
        plain.as_deref(),
        &[
            target_priors[0].as_deref(),
            target_priors[1].as_deref(),
        ],
    );

    if plan.remove_encoded {
        config
            .child_env_remove
            .push(OsString::from("CARGO_ENCODED_RUSTFLAGS"));
    }
    if let Some(flags) = plan.rustflags {
        config
            .child_env
            .push((OsString::from("RUSTFLAGS"), OsString::from(flags)));
    }
    for (key, val) in plan.target_flags {
        config
            .child_env
            .push((OsString::from(key), OsString::from(val)));
    }

    if mold_ok {
        eprint_log(
            "using mold linker (RUSTFLAGS + CARGO_TARGET_* force -C link-arg=-fuse-ld=mold)",
        );
    }
}

/// Decode cargo's CARGO_ENCODED_RUSTFLAGS (0x1f-separated tokens) to a
/// space-joined string suitable for force_mold / strip helpers.
fn decode_encoded_rustflags(encoded: &str) -> String {
    encoded
        .split(RUSTFLAGS_UNIT_SEP)
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// True if this token (or -C + next) is a fuse-ld link-arg form we strip.
fn is_fuse_ld_pair(flag: &str, next: Option<&str>) -> Option<usize> {
    if flag == "-C" {
        if let Some(n) = next {
            if n.starts_with("link-arg=-fuse-ld=") || n == "link-arg=-fuse-ld" {
                return Some(2);
            }
        }
        return None;
    }
    if flag.starts_with("-Clink-arg=-fuse-ld=")
        || flag.starts_with("-fuse-ld=")
        || flag.starts_with("link-arg=-fuse-ld=")
    {
        return Some(1);
    }
    None
}

/// Drop any -C link-arg=-fuse-ld=* / -fuse-ld=* tokens (no mold append).
fn strip_fuse_ld_rustflags(raw: &str) -> String {
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    let mut i = 0;
    while i < tokens.len() {
        if let Some(skip) = is_fuse_ld_pair(tokens[i], tokens.get(i + 1).copied()) {
            i += skip;
            continue;
        }
        out.push(tokens[i].to_string());
        i += 1;
    }
    out.join(" ")
}

/// Drop any -C link-arg=-fuse-ld=* / -fuse-ld=* tokens, then append mold.
fn force_mold_rustflags(raw: &str) -> String {
    let mut stripped = strip_fuse_ld_rustflags(raw);
    if !stripped.is_empty() {
        stripped.push(' ');
    }
    stripped.push_str("-C link-arg=-fuse-ld=mold");
    stripped
}

/// Cargo subcommands that accept `-j` / `--jobs` (compile-heavy work).
/// Others (notably `fmt`) reject `-j` and must only get `CARGO_BUILD_JOBS` via
/// env if anything — injecting argv `-j` breaks GHA `just test` under
/// `CI_LOW_MEM` (`cargo fmt -j 2 --all -- --check`).
fn cargo_subcommand_accepts_jobs(sub: &str) -> bool {
    matches!(
        sub,
        "build"
            | "check"
            | "test"
            | "bench"
            | "run"
            | "clippy"
            | "rustc"
            | "doc"
            | "install"
            | "rustdoc"
    )
}

/// Insert or replace cargo -j N so restarts actually reduce parallelism.
/// Only injects for job-aware cargo subcommands (build/check/test/clippy/...).
/// Meta invocations (`cargo --version`) and non-job subcommands (`fmt`) only
/// get `CARGO_BUILD_JOBS` via env in [`run_once`].
fn with_jobs_args(cmd: &[String], jobs: u32) -> Vec<String> {
    let mut out = Vec::with_capacity(cmd.len() + 2);
    let mut i = 0;
    if let Some(bin) = cmd.first() {
        out.push(bin.clone());
        i = 1;
    }
    // Skip global cargo flags until a subcommand (token not starting with '-').
    while i < cmd.len() && cmd[i].starts_with('-') {
        // cargo +toolchain is not a flag with '-', leave as-is later
        out.push(cmd[i].clone());
        // flags that take a value
        if matches!(
            cmd[i].as_str(),
            "-Z" | "--config" | "-C" | "--color" | "--explain"
        ) {
            i += 1;
            if i < cmd.len() {
                out.push(cmd[i].clone());
            }
        }
        i += 1;
    }
    if i >= cmd.len() || cmd[i].starts_with('-') {
        // No subcommand (e.g. cargo --version) -- do not inject -j.
        out.extend(cmd[i..].iter().cloned());
        return out;
    }
    // Subcommand
    let sub = cmd[i].as_str();
    out.push(cmd[i].clone());
    i += 1;
    if !cargo_subcommand_accepts_jobs(sub) {
        // e.g. `cargo fmt` — pass through without -j.
        out.extend(cmd[i..].iter().cloned());
        return out;
    }
    // Drop existing -j / --jobs on the remainder
    let rest = &cmd[i..];
    let mut j = 0;
    let mut cleaned = Vec::new();
    while j < rest.len() {
        let a = &rest[j];
        if a == "-j" || a == "--jobs" {
            j += 2;
            continue;
        }
        if let Some(restn) = a.strip_prefix("-j") {
            if !restn.is_empty() && restn.chars().all(|c| c.is_ascii_digit()) {
                j += 1;
                continue;
            }
        }
        if a.starts_with("--jobs=") {
            j += 1;
            continue;
        }
        cleaned.push(rest[j].clone());
        j += 1;
    }
    out.push("-j".into());
    out.push(jobs.to_string());
    out.extend(cleaned);
    out
}

fn resolve_command(cmd: &[String], cargo: &Path) -> (PathBuf, Vec<String>) {
    if cmd.first().map(|s| s.as_str()) == Some("cargo") {
        (cargo.to_path_buf(), cmd[1..].to_vec())
    } else {
        (
            PathBuf::from(&cmd[0]),
            cmd.get(1..).unwrap_or(&[]).to_vec(),
        )
    }
}

enum RunOutcome {
    Success(i32),
    Failed(i32),
    PressureRestart,
}

fn run_once(
    config: &Config,
    program: &Path,
    args: &[String],
    jobs: u32,
) -> io::Result<RunOutcome> {
    let mut command = Command::new(program);
    command.args(args);
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());
    command.stdin(Stdio::inherit());
    command.env("CARGO_BUILD_JOBS", jobs.to_string());
    for k in &config.child_env_remove {
        command.env_remove(k);
    }
    for (k, v) in &config.child_env {
        command.env(k, v);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc_setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = command.spawn()?;
    let pid = child.id();
    eprint_log(format!(
        "spawn pid={pid} jobs={jobs} high_water={:.0}% free",
        config.high_water * 100.0
    ));

    let (tx, rx) = mpsc::channel::<()>();
    let stop_monitor = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop_monitor);
    let high_water = config.high_water;
    let poll = config.poll;
    let monitor = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            if let Ok(mem) = read_meminfo() {
                if mem.available_ratio() < high_water {
                    eprint_log(format!(
                        "memory pressure: available {:.1}% of {} MiB (threshold {:.0}% free)",
                        mem.available_ratio() * 100.0,
                        mem.total_kb / 1024,
                        high_water * 100.0
                    ));
                    let _ = tx.send(());
                    return;
                }
            }
            thread::sleep(poll);
        }
    });

    let outcome = loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(()) => {
                eprint_log("terminating build due to memory pressure");
                terminate_tree(pid);
                let _ = child.wait()?;
                break RunOutcome::PressureRestart;
            }
            Err(RecvTimeoutError::Timeout) => match child.try_wait()? {
                Some(status) => {
                    let code = status.code().unwrap_or(1);
                    if status.success() {
                        break RunOutcome::Success(code);
                    }
                    break RunOutcome::Failed(code);
                }
                None => continue,
            },
            Err(RecvTimeoutError::Disconnected) => match child.wait()? {
                status if status.success() => {
                    break RunOutcome::Success(status.code().unwrap_or(0));
                }
                status => break RunOutcome::Failed(status.code().unwrap_or(1)),
            },
        }
    };

    stop_monitor.store(true, Ordering::Relaxed);
    let _ = monitor.join();
    Ok(outcome)
}

#[cfg(unix)]
fn libc_setsid() -> i32 {
    unsafe extern "C" {
        fn setsid() -> i32;
    }
    unsafe { setsid() }
}

fn terminate_tree(pid: u32) {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        const SIGTERM: i32 = 15;
        const SIGKILL: i32 = 9;
        let pgid = pid as i32;
        unsafe {
            let _ = kill(-pgid, SIGTERM);
        }
        thread::sleep(Duration::from_millis(800));
        unsafe {
            let _ = kill(-pgid, SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (mut config, cmd) = parse_args(args);
    apply_mold_rustflags(&mut config);

    let mut jobs = config.jobs_start;
    let mut restarts = 0u32;
    let start = Instant::now();

    loop {
        let with_j = with_jobs_args(&cmd, jobs);
        let (program, prog_args) = resolve_command(&with_j, &config.cargo);
        eprint_log(format!(
            "run attempt restarts={restarts} jobs={jobs} cmd={} {}",
            program.display(),
            prog_args.join(" ")
        ));

        match run_once(&config, &program, &prog_args, jobs) {
            Ok(RunOutcome::Success(code)) => {
                eprint_log(format!(
                    "ok in {:.1}s (restarts={restarts})",
                    start.elapsed().as_secs_f64()
                ));
                return ExitCode::from(code as u8);
            }
            Ok(RunOutcome::Failed(code)) => {
                eprint_log(format!("command failed exit={code}"));
                return ExitCode::from(code as u8);
            }
            Ok(RunOutcome::PressureRestart) => {
                if restarts >= config.max_restarts {
                    eprint_log(format!(
                        "giving up after {restarts} pressure restarts (max {})",
                        config.max_restarts
                    ));
                    return ExitCode::from(1);
                }
                restarts += 1;
                let next = (jobs / 2).max(config.jobs_min);
                jobs = next;
                eprint_log(format!(
                    "restarting with jobs={jobs} (restart {restarts}/{})",
                    config.max_restarts
                ));
                thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                eprint_log(format!("spawn/wait error: {e}"));
                return ExitCode::from(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_jobs_inserts_after_subcommand() {
        let cmd = vec![
            "cargo".into(),
            "build".into(),
            "-p".into(),
            "xai-grok-pager-bin".into(),
        ];
        let out = with_jobs_args(&cmd, 2);
        assert_eq!(
            out,
            vec!["cargo", "build", "-j", "2", "-p", "xai-grok-pager-bin"]
        );
    }

    #[test]
    fn with_jobs_replaces_existing_j() {
        let cmd = vec![
            "cargo".into(),
            "check".into(),
            "-j".into(),
            "8".into(),
            "--locked".into(),
        ];
        let out = with_jobs_args(&cmd, 1);
        assert_eq!(out, vec!["cargo", "check", "-j", "1", "--locked"]);
    }

    #[test]
    fn with_jobs_replaces_compact_j8() {
        let cmd = vec![
            "cargo".into(),
            "build".into(),
            "-j8".into(),
            "-p".into(),
            "foo".into(),
        ];
        let out = with_jobs_args(&cmd, 2);
        assert_eq!(out, vec!["cargo", "build", "-j", "2", "-p", "foo"]);
        assert!(!out.iter().any(|a| a == "-j8"));
    }

    #[test]
    fn with_jobs_replaces_jobs_eq_form() {
        let cmd = vec![
            "cargo".into(),
            "test".into(),
            "--jobs=16".into(),
            "--locked".into(),
        ];
        let out = with_jobs_args(&cmd, 1);
        assert_eq!(out, vec!["cargo", "test", "-j", "1", "--locked"]);
        assert!(!out.iter().any(|a| a.starts_with("--jobs")));
    }

    #[test]
    fn with_jobs_meta_version_no_j() {
        let cmd = vec!["cargo".into(), "--version".into()];
        let out = with_jobs_args(&cmd, 2);
        assert_eq!(out, vec!["cargo", "--version"]);
        assert!(!out.iter().any(|a| a == "-j" || a.starts_with("-j")));
    }

    #[test]
    fn with_jobs_fmt_does_not_inject_j() {
        // GHA CI_LOW_MEM: cargo-mem-guard wraps `cargo fmt --all -- --check`.
        // cargo-fmt rejects argv -j (exit 2); only job-aware subcommands get it.
        let cmd = vec![
            "cargo".into(),
            "fmt".into(),
            "--all".into(),
            "--".into(),
            "--check".into(),
        ];
        let out = with_jobs_args(&cmd, 2);
        assert_eq!(
            out,
            vec!["cargo", "fmt", "--all", "--", "--check"]
        );
        assert!(!out.iter().any(|a| a == "-j" || a.starts_with("-j") || a.starts_with("--jobs")));
    }

    #[test]
    fn resolve_cargo_prefix() {
        let cmd = vec!["cargo".into(), "test".into(), "-p".into(), "foo".into()];
        let (prog, args) = resolve_command(&cmd, Path::new("/nix/store/cargo"));
        assert_eq!(prog, Path::new("/nix/store/cargo"));
        assert_eq!(args, vec!["test", "-p", "foo"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn meminfo_parses() {
        let m = read_meminfo().expect("meminfo");
        assert!(m.total_kb > 0);
        assert!(m.available_kb > 0);
    }

    #[test]
    fn force_mold_table_driven() {
        let cases = [
            (
                "",
                "-C link-arg=-fuse-ld=mold",
            ),
            (
                "-C link-arg=-fuse-ld=wild -C force-unwind-tables=yes",
                "-C force-unwind-tables=yes -C link-arg=-fuse-ld=mold",
            ),
            (
                "-Clink-arg=-fuse-ld=lld",
                "-C link-arg=-fuse-ld=mold",
            ),
            (
                "link-arg=-fuse-ld=wild -C force-unwind-tables=yes",
                "-C force-unwind-tables=yes -C link-arg=-fuse-ld=mold",
            ),
            (
                "-fuse-ld=lld -C opt-level=0",
                "-C opt-level=0 -C link-arg=-fuse-ld=mold",
            ),
            (
                "-C force-unwind-tables=yes",
                "-C force-unwind-tables=yes -C link-arg=-fuse-ld=mold",
            ),
        ];
        for (input, expect) in cases {
            let out = force_mold_rustflags(input);
            assert_eq!(out, expect, "input={input:?}");
            assert!(!out.contains("wild"), "wild leaked: {out}");
            assert!(!out.contains("fuse-ld=lld"), "lld leaked: {out}");
            assert!(out.contains("fuse-ld=mold"), "mold missing: {out}");
        }
    }

    #[test]
    fn strip_fuse_ld_keeps_other_flags() {
        let out = strip_fuse_ld_rustflags("-C link-arg=-fuse-ld=wild -C force-unwind-tables=yes");
        assert_eq!(out, "-C force-unwind-tables=yes");
        assert!(!out.contains("mold"));
    }

    #[test]
    fn decode_encoded_rustflags_unit_sep() {
        let enc = format!(
            "-C{sep}link-arg=-fuse-ld=wild{sep}-C{sep}force-unwind-tables=yes",
            sep = RUSTFLAGS_UNIT_SEP
        );
        let decoded = decode_encoded_rustflags(&enc);
        assert_eq!(
            decoded,
            "-C link-arg=-fuse-ld=wild -C force-unwind-tables=yes"
        );
        let molded = force_mold_rustflags(&decoded);
        assert!(!molded.contains("wild"));
        assert!(molded.contains("force-unwind-tables=yes"));
        assert!(molded.contains("fuse-ld=mold"));
    }

    #[test]
    fn force_mold_does_not_strip_clinker_path() {
        // Documented gap (issue 16): -Clinker= / ld-path forms are left alone.
        let out = force_mold_rustflags("-Clinker=/usr/bin/ld");
        assert!(out.contains("-Clinker=/usr/bin/ld"));
        assert!(out.contains("fuse-ld=mold"));
    }

    #[test]
    fn plan_mold_ok_no_parent_global_still_sets_rustflags() {
        // Host ~/.cargo build.rustflags often injects -fuse-ld=wild. Only
        // setting CARGO_TARGET_* leaves wild on the link line next to mold;
        // always set RUSTFLAGS when mold is on to replace build.rustflags.
        let plan = plan_mold_rustflags(true, None, None, &[None, None]);
        assert_eq!(
            plan.rustflags.as_deref(),
            Some("-C link-arg=-fuse-ld=mold")
        );
        assert!(!plan.remove_encoded);
        assert_eq!(plan.target_flags.len(), 2);
        assert_eq!(
            plan.target_flags[0].1,
            "-C force-unwind-tables=yes -C link-arg=-fuse-ld=mold"
        );
        assert_eq!(
            plan.target_flags[1].1,
            "-C target-cpu=neoverse-v2 -C force-unwind-tables=yes -C link-arg=-fuse-ld=mold"
        );
    }

    #[test]
    fn plan_mold_ok_with_plain_rustflags_rewrites_global() {
        let plan = plan_mold_rustflags(
            true,
            None,
            Some("-C link-arg=-fuse-ld=wild -C force-unwind-tables=yes"),
            &[None, None],
        );
        assert_eq!(
            plan.rustflags.as_deref(),
            Some("-C force-unwind-tables=yes -C link-arg=-fuse-ld=mold")
        );
        assert!(!plan.remove_encoded);
        assert_eq!(plan.target_flags.len(), 2);
        assert!(!plan.rustflags.as_deref().unwrap_or("").contains("wild"));
    }

    #[test]
    fn plan_mold_ok_encoded_removes_and_decodes() {
        let enc = format!(
            "-C{sep}link-arg=-fuse-ld=wild{sep}-C{sep}opt-level=0",
            sep = RUSTFLAGS_UNIT_SEP
        );
        let plan = plan_mold_rustflags(true, Some(&enc), None, &[None, None]);
        assert!(plan.remove_encoded);
        let rf = plan.rustflags.expect("encoded parent => set RUSTFLAGS");
        assert!(!rf.contains("wild"));
        assert!(rf.contains("opt-level=0"));
        assert!(rf.contains("fuse-ld=mold"));
    }

    #[test]
    fn plan_mold_ok_empty_encoded_falls_through_to_plain() {
        // Empty CARGO_ENCODED_RUSTFLAGS is still "set" (remove it for child)
        // but decode is empty -- fall through to plain RUSTFLAGS content.
        let plan = plan_mold_rustflags(
            true,
            Some(""),
            Some("-C force-unwind-tables=yes"),
            &[None, None],
        );
        assert!(plan.remove_encoded);
        assert_eq!(
            plan.rustflags.as_deref(),
            Some("-C force-unwind-tables=yes -C link-arg=-fuse-ld=mold")
        );
    }

    #[test]
    fn plan_mold_ok_uses_prior_target_env_over_defaults() {
        let plan = plan_mold_rustflags(
            true,
            None,
            None,
            &[Some("-C opt-level=1"), None],
        );
        // mold_ok always sets global RUSTFLAGS (host build.rustflags override).
        assert_eq!(
            plan.rustflags.as_deref(),
            Some("-C link-arg=-fuse-ld=mold")
        );
        // Prior wins over workspace default for x86_64.
        assert_eq!(
            plan.target_flags[0].1,
            "-C opt-level=1 -C link-arg=-fuse-ld=mold"
        );
        // Unset aarch64 still gets workspace default + mold.
        assert_eq!(
            plan.target_flags[1].1,
            "-C target-cpu=neoverse-v2 -C force-unwind-tables=yes -C link-arg=-fuse-ld=mold"
        );
    }

    #[test]
    fn plan_mold_missing_only_rewrites_present_keys() {
        let plan = plan_mold_rustflags(
            false,
            None,
            Some("-C link-arg=-fuse-ld=wild -C opt-level=0"),
            &[Some("-C link-arg=-fuse-ld=lld"), None],
        );
        assert_eq!(plan.rustflags.as_deref(), Some("-C opt-level=0"));
        assert_eq!(plan.target_flags.len(), 1);
        assert_eq!(plan.target_flags[0].0, LINUX_TARGET_RUSTFLAGS_KEYS[0]);
        assert_eq!(plan.target_flags[0].1, "");
    }
}
