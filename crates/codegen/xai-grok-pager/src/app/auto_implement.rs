//! Auto-run `/implement` follow-ups after a successful turn ends.
//!
//! When enabled (default on), turn end looks for a **sentence/line-leading**
//! `/implement` command and enqueues the **full multi-line block** from the
//! implement token through EOF (body may include later slash lines that are
//! part of residual notes — models often paste a whole next-prompt blob).
//!
//! Sources (in order):
//! 1. **User prompt follow-up** — prior user message has non-implement content
//!    first, then a later `/implement` block (same-message design→implement).
//! 2. **Assistant residual** — last turn’s agent messages contain a trailing
//!    `/implement` block (models should leave “Next implement prompt” near the
//!    end). Skipped when the block is an exact echo of the user prompt just
//!    run (avoids re-queueing the same primary implement).
//!
//! When **economic mode** is on (soft-cap context ≈ 200K), auto-queued blocks
//! clamp explicit `--effort N` / `effort N` above 1 down to 1 so implement
//! loops stay on the cheap tier (no multi-reviewer fan-out).

use crate::app::agent_view::AgentView;
use crate::scrollback::block::RenderBlock;

/// Toast shown when a follow-up `/implement` is auto-queued after turn end.
pub const AUTO_IMPLEMENT_TOAST: &str = "next task /implement detected, automatically running";

/// Max explicit `/implement` effort when economic mode is enabled.
pub const ECONOMIC_MODE_MAX_IMPLEMENT_EFFORT: u8 = 1;

/// Whether `text` is an `/implement` command at the start of the string
/// (optional args after whitespace). Case-insensitive command token.
pub fn is_implement_command_sentence(text: &str) -> bool {
    let t = text.trim_start();
    let lower = t.to_ascii_lowercase();
    if !lower.starts_with("/implement") {
        return false;
    }
    match t.as_bytes().get("/implement".len()) {
        None => true,
        Some(b) => b.is_ascii_whitespace(),
    }
}

/// Split text into sentence-like units (used only to find mid-line implement
/// starts such as `Review the PR. /implement …`).
fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            push_unit(&mut out, &text[start..i]);
            start = i + 1;
            i += 1;
            continue;
        }
        if matches!(b, b'.' | b'!' | b'?') {
            let next = i + 1;
            if next >= bytes.len() || bytes[next].is_ascii_whitespace() {
                push_unit(&mut out, &text[start..next]);
                start = next;
                while start < bytes.len()
                    && bytes[start].is_ascii_whitespace()
                    && bytes[start] != b'\n'
                {
                    start += 1;
                }
                i = start;
                continue;
            }
        }
        i += 1;
    }
    push_unit(&mut out, &text[start..]);
    out
}

fn push_unit(out: &mut Vec<String>, s: &str) {
    let t = s.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
}

/// From byte offset `start` (must point at `/implement…`), take the full block
/// through EOF (trimmed). Body is not cut at a later slash command — residual
/// prompts often include notes or nested paths after the implement line.
pub fn extract_implement_block_at(text: &str, start: usize) -> Option<String> {
    if start >= text.len() || !is_implement_command_sentence(&text[start..]) {
        return None;
    }
    let trimmed = text[start..].trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Clamp explicit implement effort flags when economic mode is on.
///
/// Rewrites leading `/implement --effort N` / `/implement effort N` so any
/// `N > `[`ECONOMIC_MODE_MAX_IMPLEMENT_EFFORT`] becomes that max. Leaves the
/// text unchanged when economic mode is off, when no effort flag is present,
/// or when effort is already ≤ max. Only the first effort flag on the first
/// line is rewritten (matches skill arg parsing).
pub fn clamp_implement_effort_for_economic_mode(cmd: &str, economic_mode: bool) -> String {
    if !economic_mode {
        return cmd.to_string();
    }
    clamp_implement_effort(cmd, ECONOMIC_MODE_MAX_IMPLEMENT_EFFORT)
}

/// Rewrite the first `--effort N` / `effort N` after `/implement` if `N > max`.
fn clamp_implement_effort(cmd: &str, max_effort: u8) -> String {
    let trimmed = cmd.trim_start();
    if !is_implement_command_sentence(trimmed) {
        return cmd.to_string();
    }
    // Work on the first line only for the flag; keep the rest of the block.
    let (first_line, rest) = match trimmed.find('\n') {
        Some(i) => (&trimmed[..i], Some(&trimmed[i..])),
        None => (trimmed, None),
    };
    let Some((prefix, n, suffix)) = split_first_effort_flag(first_line) else {
        return cmd.to_string();
    };
    if n <= max_effort as u32 {
        return cmd.to_string();
    }
    let mut out = String::with_capacity(cmd.len());
    // Preserve any leading whitespace from the original `cmd`.
    let lead = cmd.len() - cmd.trim_start().len();
    out.push_str(&cmd[..lead]);
    out.push_str(prefix);
    out.push_str(&max_effort.to_string());
    out.push_str(suffix);
    if let Some(r) = rest {
        out.push_str(r);
    }
    out
}

/// Find the first `--effort N` or `effort N` on an implement first line.
/// Returns `(text_before_N, N, text_after_N)`.
fn split_first_effort_flag(first_line: &str) -> Option<(&str, u32, &str)> {
    let lower = first_line.to_ascii_lowercase();
    // Prefer `--effort` over bare `effort` when both could match.
    for needle in ["--effort", "effort"] {
        let mut search_from = 0usize;
        while let Some(rel) = lower[search_from..].find(needle) {
            let abs = search_from + rel;
            // Token boundary before: start or whitespace.
            if abs > 0 && !first_line.as_bytes()[abs - 1].is_ascii_whitespace() {
                search_from = abs + 1;
                continue;
            }
            let after_flag = abs + needle.len();
            let rest = &first_line[after_flag..];
            // Require whitespace (or `=`) then digits.
            let rest_trim_start =
                rest.trim_start_matches(|c: char| c == '=' || c.is_ascii_whitespace());
            if rest_trim_start.len() == rest.len() {
                // No separator between flag and value.
                search_from = abs + 1;
                continue;
            }
            let digits_end = rest_trim_start
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest_trim_start.len());
            if digits_end == 0 {
                search_from = abs + 1;
                continue;
            }
            let num_str = &rest_trim_start[..digits_end];
            let Ok(n) = num_str.parse::<u32>() else {
                search_from = abs + 1;
                continue;
            };
            let value_start_in_line = after_flag + (rest.len() - rest_trim_start.len());
            let value_end_in_line = value_start_in_line + digits_end;
            return Some((
                &first_line[..value_start_in_line],
                n,
                &first_line[value_end_in_line..],
            ));
        }
    }
    None
}

/// Byte offset of a follow-up implement start in `text`, or `None` when the
/// prompt’s primary content already is implement / no implement exists.
fn find_followup_implement_offset(text: &str) -> Option<usize> {
    let mut saw_non_implement = false;
    let mut pos = 0usize;
    while pos <= text.len() {
        let nl = text[pos..].find('\n').map(|i| pos + i);
        let end = nl.unwrap_or(text.len());
        let line = &text[pos..end];

        if !line.trim().is_empty() {
            let trim_off = line.len() - line.trim_start().len();
            let body = &line[trim_off..];
            if is_implement_command_sentence(body) {
                if saw_non_implement {
                    return Some(pos + trim_off);
                }
                // Primary turn is implement — do not auto from user prompt.
                return None;
            }
            // Mid-line: "Review the PR. /implement …"
            for unit in split_sentences(line) {
                if is_implement_command_sentence(&unit)
                    && let Some(rel) = find_implement_token_offset(line)
                {
                    let before = line[..rel].trim();
                    if !before.is_empty() || saw_non_implement {
                        return Some(pos + rel);
                    }
                }
            }
            saw_non_implement = true;
        }

        if nl.is_none() {
            break;
        }
        pos = end + 1;
    }
    None
}

/// Case-insensitive index of `/implement` as a command token on `line`.
fn find_implement_token_offset(line: &str) -> Option<usize> {
    let lower = line.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find("/implement") {
        let abs = search_from + rel;
        let after = abs + "/implement".len();
        let boundary_ok = match line.as_bytes().get(after) {
            None => true,
            Some(b) => b.is_ascii_whitespace(),
        };
        if boundary_ok {
            // Sentence-leading: start of line or after `.!?` + whitespace.
            let prefix = line[..abs].trim_end();
            if prefix.is_empty()
                || prefix.ends_with('.')
                || prefix.ends_with('!')
                || prefix.ends_with('?')
            {
                return Some(abs);
            }
        }
        search_from = abs + 1;
    }
    None
}

/// Extract a follow-up multi-line `/implement` block from the prior user prompt.
///
/// Returns `None` when no follow-up exists or the primary turn is already
/// implement (first non-empty line starts with `/implement`).
pub fn extract_auto_implement_followup(prior_prompt: &str) -> Option<String> {
    let start = find_followup_implement_offset(prior_prompt)?;
    extract_implement_block_at(prior_prompt, start)
}

/// Extract the **last** full multi-line `/implement` block from `text`
/// (prefer residual “next implement” near the end of a report).
pub fn extract_last_implement_block(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let mut last: Option<usize> = None;
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find("/implement") {
        let abs = search_from + rel;
        let after = abs + "/implement".len();
        let boundary_ok = match text.as_bytes().get(after) {
            None => true,
            Some(b) => b.is_ascii_whitespace(),
        };
        if boundary_ok {
            // Line-leading only for residual assistant blocks (avoid mid-prose).
            let line_start = text[..abs].rfind('\n').map(|i| i + 1).unwrap_or(0);
            if text[line_start..abs].trim().is_empty() {
                last = Some(abs);
            }
        }
        search_from = abs + 1;
    }
    last.and_then(|s| extract_implement_block_at(text, s))
}

/// Collect agent-message source markdown from the most recent turn
/// (everything after the last user prompt in scrollback).
pub fn last_turn_assistant_text(agent: &AgentView) -> Option<String> {
    let len = agent.scrollback.len();
    if len == 0 {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for i in (0..len).rev() {
        let Some(entry) = agent.scrollback.entry(i) else {
            continue;
        };
        match &entry.block {
            RenderBlock::UserPrompt(_) => break,
            RenderBlock::AgentMessage(m) => {
                let t = m.text();
                if !t.trim().is_empty() {
                    parts.push(t);
                }
            }
            _ => {}
        }
    }
    if parts.is_empty() {
        return None;
    }
    parts.reverse();
    Some(parts.join("\n"))
}

/// After a successful non-cancel agent turn, maybe queue a multi-line
/// `/implement` block. Returns `Some(toast)` when enqueued (caller should
/// show toast + drain), or `None` when nothing was queued.
pub fn maybe_enqueue_auto_implement(agent: &mut AgentView, enabled: bool) -> Option<String> {
    if !enabled {
        return None;
    }
    if agent.attached_as_viewer {
        return None;
    }
    if agent.bash_turn {
        return None;
    }
    // Don't stack on top of an already-busy local/server queue.
    if !agent.session.pending_prompts.is_empty() || !agent.shared_queue.is_empty() {
        return None;
    }

    let prior = agent.session.prompt_history.first().cloned();

    // 1) Follow-up implement in the same user message (design then /implement …).
    let from_user = prior.as_deref().and_then(extract_auto_implement_followup);

    // 2) Trailing residual block in the assistant’s just-finished turn.
    let from_assistant = last_turn_assistant_text(agent)
        .as_deref()
        .and_then(extract_last_implement_block)
        .filter(|cmd| {
            // Don't re-queue an exact echo of the prompt that just ran.
            prior
                .as_deref()
                .map(|p| p.trim() != cmd.trim())
                .unwrap_or(true)
        });

    let raw = from_user.or(from_assistant)?;

    let economic = crate::appearance::cache::load_economic_mode();
    let cmd = clamp_implement_effort_for_economic_mode(&raw, economic);
    let toast = auto_implement_toast_for(&raw, &cmd, economic);

    let ranges = agent
        .prompt
        .slash_controller
        .recognized_token_ranges(&cmd, &agent.session.models);
    agent.session.enqueue_prompt_with_skill_tokens(cmd, ranges);
    Some(toast)
}

/// Toast when a follow-up was auto-queued. Mentions economic effort clamp when
/// the enqueued text differs from the raw extract (effort was rewritten).
pub fn auto_implement_toast_for(raw_cmd: &str, enqueued_cmd: &str, economic_mode: bool) -> String {
    if economic_mode && raw_cmd.trim() != enqueued_cmd.trim() {
        format!(
            "{AUTO_IMPLEMENT_TOAST} (economic mode: --effort capped at {ECONOMIC_MODE_MAX_IMPLEMENT_EFFORT})"
        )
    } else {
        AUTO_IMPLEMENT_TOAST.to_string()
    }
}

/// After a clean agent turn ends (before queue drain): enqueue a follow-up
/// `/implement` when the setting is on, and toast.
///
/// Call only on successful, non-cancel, non-bash turn ends.
pub fn on_successful_turn_end(agent: &mut AgentView) {
    let enabled = crate::appearance::cache::load_auto_run_implement();
    if let Some(toast) = maybe_enqueue_auto_implement(agent, enabled) {
        agent.show_toast(&toast);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_implement_accepts_bare_and_args() {
        assert!(is_implement_command_sentence("/implement"));
        assert!(is_implement_command_sentence("  /implement fix tests"));
        assert!(is_implement_command_sentence("/IMPLEMENT the plan"));
        assert!(!is_implement_command_sentence("/implements"));
        assert!(!is_implement_command_sentence("please /implement later"));
        assert!(!is_implement_command_sentence("/goal do stuff"));
    }

    #[test]
    fn extract_skips_when_primary_is_implement() {
        assert_eq!(
            extract_auto_implement_followup("/implement fix the gate"),
            None
        );
        assert_eq!(
            extract_auto_implement_followup("/implement\n/implement again"),
            None
        );
        assert_eq!(
            extract_auto_implement_followup(
                "/implement --effort 5 residual work:\n1) wire Systems.Proc\n2) keep SCORE fail=0"
            ),
            None
        );
    }

    #[test]
    fn extract_finds_followup_after_plain_sentence() {
        assert_eq!(
            extract_auto_implement_followup(
                "Design a hermetic test plan.\n/implement the plan carefully"
            )
            .as_deref(),
            Some("/implement the plan carefully")
        );
        assert_eq!(
            extract_auto_implement_followup(
                "Review the PR. /implement any remaining test failures"
            )
            .as_deref(),
            Some("/implement any remaining test failures")
        );
    }

    #[test]
    fn extract_grabs_full_multiline_implement_block() {
        let prior = "\
Highest-value residual next (bottleneck order)
1. Slake_Proc_dogfood — wire freestanding Systems.Proc

---

Next implement prompt

/implement --effort 5 all remaining planned residual in priority order:
1) Slake_Proc_dogfood — freestanding Systems.Proc (or Extract C ABI)
2) TomlConfig_more — expand TomlConfigLite toward more lakefile.toml keys
3) Track L residual-green product trio if parallelizable
4) Do NOT claim H5 residual_free elaborator unless measured GC_FREE_ELABORATOR=1
Update RESIDUAL.md PRODUCT_FS_NEXT. Stay in cwd; subagent hierarchy; SCORE fail=0.";

        let got = extract_auto_implement_followup(prior).expect("follow-up block");
        assert!(
            got.starts_with("/implement --effort 5 all remaining planned residual"),
            "must start with implement line: {got}"
        );
        assert!(
            got.contains("1) Slake_Proc_dogfood"),
            "must include body line 1: {got}"
        );
        assert!(
            got.contains("4) Do NOT claim H5"),
            "must include body line 4: {got}"
        );
        assert!(
            got.contains("Update RESIDUAL.md PRODUCT_FS_NEXT"),
            "must include trailing body: {got}"
        );
        assert!(
            got.lines().count() >= 5,
            "expected multi-line block, got {} lines: {got}",
            got.lines().count()
        );
    }

    #[test]
    fn extract_grabs_through_eof_including_later_slash_lines() {
        // Residual blobs sometimes include other slash notes after the body;
        // take everything through EOF so we do not truncate mid-prompt.
        let prior = "\
Plan first.

/implement do the wiring
1) keep dual residual honest
/review check security after
more review notes";
        let got = extract_auto_implement_followup(prior).expect("block");
        assert!(got.contains("1) keep dual residual honest"));
        assert!(
            got.contains("/review check security after"),
            "must keep later slash lines through EOF: {got}"
        );
        assert!(got.contains("more review notes"));
    }

    #[test]
    fn clamp_effort_when_economic_rewrites_above_max() {
        let raw = "/implement --effort 5 residual work:\n1) wire Systems.Proc";
        let got = clamp_implement_effort_for_economic_mode(raw, true);
        assert!(
            got.starts_with("/implement --effort 1 "),
            "expected effort clamped to 1: {got}"
        );
        assert!(got.contains("1) wire Systems.Proc"));
        // Off: unchanged.
        assert_eq!(clamp_implement_effort_for_economic_mode(raw, false), raw);
        // Already ≤ max: unchanged.
        let low = "/implement --effort 1 fix tests";
        assert_eq!(clamp_implement_effort_for_economic_mode(low, true), low);
        // Bare `effort N` form.
        let bare = "/implement effort 3 do the thing";
        let got_bare = clamp_implement_effort_for_economic_mode(bare, true);
        assert!(
            got_bare.starts_with("/implement effort 1 "),
            "bare effort form: {got_bare}"
        );
        // No flag: unchanged.
        let none = "/implement fix the gate";
        assert_eq!(clamp_implement_effort_for_economic_mode(none, true), none);
    }

    #[test]
    fn last_implement_block_prefers_trailing_residual() {
        let assistant = "\
## Summary
Done with score green.

Early note:
/implement never_use_this
1) old body

## Next implement prompt
/implement --effort 5 remaining residual:
1) Slake_Proc_dogfood
2) TomlConfig_more
Stay in cwd.";
        let got = extract_last_implement_block(assistant).expect("last block");
        assert!(got.contains("Slake_Proc_dogfood"));
        assert!(
            !got.contains("never_use_this"),
            "must prefer last block: {got}"
        );
        assert!(got.lines().count() >= 3);
    }

    #[test]
    fn path_like_slash_does_not_end_block() {
        let prior = "\
Do the work.

/implement fix crates/codegen/xai-foo/src/lib.rs
1) edit the file
2) run tests";
        let got = extract_auto_implement_followup(prior).expect("block");
        assert!(got.contains("1) edit the file"));
        assert!(got.contains("2) run tests"));
    }

    #[test]
    fn extract_none_without_implement() {
        assert_eq!(
            extract_auto_implement_followup("just review the code please"),
            None
        );
    }

    #[test]
    fn toast_copy_matches_product() {
        assert_eq!(
            AUTO_IMPLEMENT_TOAST,
            "next task /implement detected, automatically running"
        );
        let raw = "/implement --effort 5 residual";
        let clamped = clamp_implement_effort_for_economic_mode(raw, true);
        assert!(
            auto_implement_toast_for(raw, &clamped, true).contains("economic mode"),
            "clamped enqueue should mention economic mode in toast"
        );
        assert_eq!(
            auto_implement_toast_for(raw, raw, true),
            AUTO_IMPLEMENT_TOAST
        );
        assert_eq!(
            auto_implement_toast_for(raw, &clamped, false),
            AUTO_IMPLEMENT_TOAST
        );
    }
}
