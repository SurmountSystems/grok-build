//! Environment helpers for benchmarking and testing.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(|p| p.to_path_buf())
        .context("failed to resolve workspace root from CARGO_MANIFEST_DIR")
}

fn target_dir() -> Result<PathBuf> {
    Ok(std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            workspace_root()
                .expect("workspace root for target_dir fallback")
                .join("target")
        }))
}

/// Installed/composition-root binary name (Surmount fork: package
/// `xai-grok-pager-bin`, artifact `grok-oss`).
const PAGER_BIN_NAME: &str = "grok-oss";

fn local_pager_binary_path() -> Result<PathBuf> {
    Ok(target_dir()?
        .join("debug")
        .join(format!("{PAGER_BIN_NAME}{}", std::env::consts::EXE_SUFFIX)))
}

fn ensure_local_pager_binary(binary: &std::path::Path) -> Result<()> {
    if binary.exists() {
        return Ok(());
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(workspace_root()?)
        .args(["build", "-p", "xai-grok-pager-bin", "--bin", PAGER_BIN_NAME])
        .stdin(Stdio::null())
        .envs(xai_tty_utils::pager_env());
    xai_tty_utils::detach_std_command(&mut cmd);
    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn {cargo} to build {PAGER_BIN_NAME}"))?;

    if !output.status.success() {
        bail!(
            "failed to build {PAGER_BIN_NAME} (exit {:?})\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    if !binary.exists() {
        bail!(
            "{PAGER_BIN_NAME} build completed but binary missing at {}",
            binary.display()
        );
    }
    Ok(())
}

/// Resolve the pager binary path.
///
/// Resolution order:
/// 1. `PAGER_BINARY` env var (for CI / explicit override)
/// 2. `CARGO_BIN_EXE_grok-oss` (set by `cargo test` when the bin is a dep)
/// 3. Legacy `CARGO_BIN_EXE_xai-grok-pager` (upstream name)
/// 4. Build locally via `cargo build -p xai-grok-pager-bin --bin grok-oss`
pub fn pager_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("PAGER_BINARY") {
        let p = PathBuf::from(path);
        if !p.exists() {
            bail!("PAGER_BINARY does not exist: {}", p.display());
        }
        // Bazel sets PAGER_BINARY to a runfiles-relative path; portable_pty
        // resolves non-absolute paths via PATH lookup instead of the cwd.
        return std::path::absolute(&p)
            .with_context(|| format!("failed to absolutize PAGER_BINARY: {}", p.display()));
    }

    for key in ["CARGO_BIN_EXE_grok-oss", "CARGO_BIN_EXE_xai-grok-pager"] {
        if let Ok(path) = std::env::var(key) {
            let p = PathBuf::from(path);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    let binary = local_pager_binary_path()?;
    ensure_local_pager_binary(&binary)?;
    Ok(binary)
}
