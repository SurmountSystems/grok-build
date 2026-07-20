//! `/economic-mode` -- toggle 200K context soft-cap (pricing).
//!
//! Session-scoped: queues to the shell builtin so the live sampling config is
//! updated. Global default is also editable in Settings → Economic mode.
//!
//! Usage:
//! - `/economic-mode` — toggle this conversation
//! - `/economic-mode on|off` — set this conversation
//! - `/economic-mode status` — show current session state
//! - `/economic-mode global on|off` — set session + persist `[ui].economic_mode`

use crate::slash::command::{CommandExecCtx, CommandResult, SlashCommand};

/// Soft-cap effective context at 200K for cheaper Grok 4.5 pricing.
pub struct EconomicModeCommand;

impl SlashCommand for EconomicModeCommand {
    fn name(&self) -> &str {
        "economic-mode"
    }

    fn aliases(&self) -> &[&str] {
        &["economic", "econ"]
    }

    fn description(&self) -> &str {
        "Cap context at 200K for cheaper Grok 4.5 pricing; clamps auto /implement --effort to 1 (on by default)"
    }

    fn session_scoped(&self) -> bool {
        true
    }

    fn usage(&self) -> &str {
        "/economic-mode [on|off|status|global on|global off]"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn args_required(&self) -> bool {
        false
    }

    fn arg_placeholder(&self) -> Option<&str> {
        Some("on|off|status|global on|global off")
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        let text = if args.trim().is_empty() {
            "/economic-mode".to_string()
        } else {
            format!("/economic-mode {}", args.trim())
        };
        CommandResult::QueueCommand(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acp::model_state::ModelState;
    use crate::app::bundle::BundleState;
    use crate::settings::PagerLocalSnapshot;

    fn make_ctx<'a>(models: &'a ModelState, bundle: &'a BundleState) -> CommandExecCtx<'a> {
        CommandExecCtx {
            models,
            session_id: None,
            bundle_state: bundle,
            screen_mode: crate::app::ScreenMode::Inline,
            pager_state: PagerLocalSnapshot::default(),
        }
    }

    #[test]
    fn bare_command_queues_toggle() {
        let models = ModelState::default();
        let bundle = BundleState::default();
        let mut ctx = make_ctx(&models, &bundle);
        match EconomicModeCommand.run(&mut ctx, "") {
            CommandResult::QueueCommand(text) => assert_eq!(text, "/economic-mode"),
            other => panic!("expected QueueCommand, got {other:?}"),
        }
    }

    #[test]
    fn args_are_forwarded() {
        let models = ModelState::default();
        let bundle = BundleState::default();
        let mut ctx = make_ctx(&models, &bundle);
        match EconomicModeCommand.run(&mut ctx, "global off") {
            CommandResult::QueueCommand(text) => assert_eq!(text, "/economic-mode global off"),
            other => panic!("expected QueueCommand, got {other:?}"),
        }
    }

    #[test]
    fn aliases_resolve() {
        use std::sync::Arc;
        let reg = crate::slash::registry::CommandRegistry::new(vec![Arc::new(EconomicModeCommand)]);
        assert_eq!(reg.get("econ").unwrap().name(), "economic-mode");
        assert_eq!(reg.get("economic").unwrap().name(), "economic-mode");
    }
}
