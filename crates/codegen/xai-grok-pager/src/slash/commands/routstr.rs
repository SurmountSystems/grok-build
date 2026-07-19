//! `/routstr` -- balance, fund, top up, refund, and address watch.
//!
//! Password-wrapped unlock uses a single-token password after `pw:`
//! (`/routstr unlock pw:<password> <phrase words…>`). Passwords containing
//! spaces are not supported on this path; use a private terminal or change
//! the AEAD password to a single token.

use crate::app::actions::{Action, SensitiveString};
use crate::slash::command::{AppCtx, ArgItem, CommandExecCtx, CommandResult, SlashCommand};

/// Routstr product surface inside the pager (mirrors `grok routstr …` CLI).
///
/// Bare `/fund` is a **separate** command ([`FundCommand`]) so it always runs
/// the fund/probe path. It is intentionally **not** an alias of `/routstr`
/// (empty args on `/routstr` mean balance).
pub struct RoutstrCommand;

impl SlashCommand for RoutstrCommand {
    fn name(&self) -> &str {
        "routstr"
    }

    fn aliases(&self) -> &[&str] {
        &[]
    }

    fn description(&self) -> &str {
        "Routstr balance, local Bitcoin fund, spend, rbf, top up, refund, watch"
    }

    fn usage(&self) -> &str {
        "/routstr [balance|fund|unlock|spend|rbf|topup|refund|watch|stop|qr] [args]"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn arg_placeholder(&self) -> Option<&str> {
        Some(
            "balance | fund | unlock <phrase> | spend <addr> <sats> [broadcast] | rbf <addr> <sats> original-fee=… | topup [sats] | refund | watch <addr> | stop | qr [addr]",
        )
    }

    fn suggest_args(&self, _ctx: &AppCtx, _args_query: &str) -> Option<Vec<ArgItem>> {
        Some(vec![
            ArgItem {
                display: "balance".to_string(),
                match_text: "balance".to_string(),
                insert_text: "balance".to_string(),
                description: "Show Routstr prepaid float".to_string(),
            },
            ArgItem {
                display: "fund".to_string(),
                match_text: "fund".to_string(),
                insert_text: "fund".to_string(),
                description: "Local wallet fund path (backup gates)".to_string(),
            },
            ArgItem {
                display: "unlock".to_string(),
                match_text: "unlock".to_string(),
                insert_text: "unlock ".to_string(),
                description: "Re-enter recovery phrase after /routstr fund, spend, or rbf"
                    .to_string(),
            },
            ArgItem {
                display: "spend".to_string(),
                match_text: "spend".to_string(),
                insert_text: "spend ".to_string(),
                description: "On-chain spend dry-run (add broadcast to submit)".to_string(),
            },
            ArgItem {
                display: "rbf".to_string(),
                match_text: "rbf".to_string(),
                insert_text: "rbf ".to_string(),
                description: "Same-input RBF dry-run (add broadcast to submit)".to_string(),
            },
            ArgItem {
                display: "topup".to_string(),
                match_text: "topup".to_string(),
                insert_text: "topup".to_string(),
                description: "Top up next steps (no live mint yet)".to_string(),
            },
            ArgItem {
                display: "refund".to_string(),
                match_text: "refund".to_string(),
                insert_text: "refund".to_string(),
                description: "Refund next steps (no live CDK yet)".to_string(),
            },
            ArgItem {
                display: "watch".to_string(),
                match_text: "watch".to_string(),
                insert_text: "watch ".to_string(),
                description: "Watch a receive address for deposits".to_string(),
            },
            ArgItem {
                display: "stop".to_string(),
                match_text: "stop".to_string(),
                insert_text: "stop".to_string(),
                description: "Stop address watch".to_string(),
            },
            ArgItem {
                display: "qr".to_string(),
                match_text: "qr".to_string(),
                insert_text: "qr ".to_string(),
                description: "Show BIP21 QR and copy receive address".to_string(),
            },
        ])
    }

    fn run(&self, _ctx: &mut CommandExecCtx, args: &str) -> CommandResult {
        parse_routstr_args(args)
    }
}

/// Dedicated `/fund` command — always the local wallet fund / probe path.
///
/// Kept separate from [`RoutstrCommand`] so bare `/fund` never falls through to
/// `/routstr`'s empty-args → balance default.
pub struct FundCommand;

impl SlashCommand for FundCommand {
    fn name(&self) -> &str {
        "fund"
    }

    fn description(&self) -> &str {
        "Local Bitcoin wallet fund path (SeedVault backup gates)"
    }

    fn usage(&self) -> &str {
        "/fund"
    }

    fn takes_args(&self) -> bool {
        false
    }

    fn run(&self, _ctx: &mut CommandExecCtx, _args: &str) -> CommandResult {
        CommandResult::Action(Action::RoutstrFund)
    }
}

/// Parse `/routstr` args into an action (pure; unit-tested).
pub(crate) fn parse_routstr_args(args: &str) -> CommandResult {
    let trimmed = args.trim();
    // unlock consumes the rest of the line as the recovery phrase.
    // Match the first token case-insensitively so `Unlock` / `UNLOCK` work.
    let unlock_rest = {
        let mut sp = trimmed.splitn(2, char::is_whitespace);
        let first = sp.next().unwrap_or("");
        if first.eq_ignore_ascii_case("unlock") {
            Some(sp.next().unwrap_or("").trim())
        } else {
            None
        }
    };
    if let Some(phrase) = unlock_rest {
        if phrase.is_empty() {
            return CommandResult::Error(
                "Usage: /routstr unlock <recovery phrase words…>\n\
                 Optional password-wrapped seed: first token `pw:<password>` then the phrase.\n\
                 Password must be a single token (no spaces)."
                    .into(),
            );
        }
        let (password, phrase) = if let Some(after) = phrase.strip_prefix("pw:") {
            // Single-token password only: split once on whitespace so the rest
            // is the recovery phrase. Passwords with spaces are not supported.
            let mut sp = after.splitn(2, char::is_whitespace);
            let pw = sp.next().unwrap_or("").to_owned();
            let ph = sp.next().unwrap_or("").trim().to_owned();
            if ph.is_empty() {
                return CommandResult::Error(
                    "Usage: /routstr unlock pw:<password> <recovery phrase…>\n\
                     Password must be a single token (no spaces)."
                        .into(),
                );
            }
            (Some(SensitiveString::new(pw)), ph)
        } else {
            (None, phrase.to_owned())
        };
        return CommandResult::Action(Action::RoutstrFundReentry {
            phrase: SensitiveString::new(phrase),
            password,
        });
    }

    let mut parts = trimmed.split_whitespace();
    let sub = parts.next().unwrap_or("balance");
    match sub {
        "balance" | "bal" | "" => CommandResult::Action(Action::RoutstrBalance),
        "fund" => CommandResult::Action(Action::RoutstrFund),
        "spend" => {
            let rest: Vec<&str> = parts.collect();
            match grok_bitcoin_wallet::funding_cli::parse_spend_tokens(&rest) {
                Ok(req) => {
                    // Parse only here — no blocking fee HTTP on the slash path.
                    // Explicit fee=N → Some(n); omit → None (resolve at authorize
                    // in the spend effect worker via halfHour estimates / default 5).
                    let fee_rate_sat_vb = if req.fee_rate_explicit {
                        Some(req.fee_rate_sat_vb)
                    } else {
                        None
                    };
                    CommandResult::Action(Action::RoutstrSpend {
                        address: req.payment_address,
                        amount_sats: req.amount_sats,
                        broadcast: req.broadcast,
                        fee_rate_sat_vb,
                    })
                }
                Err(e) => CommandResult::Error(format!(
                    "{e}\nUsage: /routstr spend <address> <sats> [broadcast] [fee=<n>]\n\
                     Dry-run by default. BIP-39 is never part of this command — \
                     authorize with /routstr unlock after spend is staged."
                )),
            }
        }
        "rbf" => {
            let rest: Vec<&str> = parts.collect();
            match grok_bitcoin_wallet::funding_cli::parse_rbf_tokens(&rest) {
                Ok(req) => {
                    // Parse only — no fee HTTP. Explicit fee → Some; omit → None
                    // (resolve halfHour/default in the rbf effect worker).
                    let fee_rate_sat_vb = if req.fee_rate_explicit {
                        Some(req.fee_rate_sat_vb)
                    } else {
                        None
                    };
                    let input_specs: Vec<String> = req
                        .inputs
                        .iter()
                        .map(grok_bitcoin_wallet::funding_cli::format_rbf_input_spec_value)
                        .collect();
                    CommandResult::Action(Action::RoutstrRbf {
                        address: req.payment_address,
                        amount_sats: req.amount_sats,
                        original_fee_sats: req.original_fee_sats,
                        original_vbytes: req.original_vbytes,
                        input_specs,
                        broadcast: req.broadcast,
                        fee_rate_sat_vb,
                    })
                }
                Err(e) => CommandResult::Error(format!(
                    "{e}\nUsage: /routstr rbf <address> <sats> original-fee=<n> \
                     original-vbytes=<n> input=<txid:vout:amount:address> [...] \
                     [broadcast] [fee=<n>]\n\
                     Same-input BIP-125 only (from prior spend dry-run meta). Dry-run \
                     by default. BIP-39 is never part of this command — authorize with \
                     /routstr unlock after rbf is staged."
                )),
            }
        }
        "topup" | "top-up" | "top_up" => {
            let sats = parts.next().and_then(|s| s.parse::<u64>().ok());
            CommandResult::Action(Action::RoutstrTopup { sats })
        }
        "refund" => CommandResult::Action(Action::RoutstrRefund),
        "watch" => {
            let Some(address) = parts.next() else {
                return CommandResult::Error("Usage: /routstr watch <receive-address>".into());
            };
            if address.trim().is_empty() {
                return CommandResult::Error("Usage: /routstr watch <receive-address>".into());
            }
            CommandResult::Action(Action::RoutstrWatch {
                address: address.trim().to_owned(),
            })
        }
        "stop" => CommandResult::Action(Action::RoutstrWatchStop),
        "qr" | "show" => {
            let address = parts.next().map(|s| s.trim().to_owned());
            CommandResult::Action(Action::RoutstrQr { address })
        }
        other => CommandResult::Error(format!(
            "Unknown /routstr argument: {other}. Use balance, fund, unlock, spend, rbf, topup, refund, watch, stop, or qr"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subcommands() {
        assert!(matches!(
            parse_routstr_args("balance"),
            CommandResult::Action(Action::RoutstrBalance)
        ));
        assert!(matches!(
            parse_routstr_args("fund"),
            CommandResult::Action(Action::RoutstrFund)
        ));
        assert!(matches!(
            parse_routstr_args("topup 21000"),
            CommandResult::Action(Action::RoutstrTopup { sats: Some(21000) })
        ));
        assert!(matches!(
            parse_routstr_args("refund"),
            CommandResult::Action(Action::RoutstrRefund)
        ));
        assert!(matches!(
            parse_routstr_args("watch bc1qtestaddress000000000000000000000"),
            CommandResult::Action(Action::RoutstrWatch { .. })
        ));
        assert!(matches!(
            parse_routstr_args("stop"),
            CommandResult::Action(Action::RoutstrWatchStop)
        ));
        assert!(matches!(
            parse_routstr_args("qr bc1qtestaddress000000000000000000000"),
            CommandResult::Action(Action::RoutstrQr { address: Some(_) })
        ));
        assert!(matches!(
            parse_routstr_args("qr"),
            CommandResult::Action(Action::RoutstrQr { address: None })
        ));
        assert!(matches!(
            parse_routstr_args("nope"),
            CommandResult::Error(_)
        ));
        // bare /routstr → balance
        assert!(matches!(
            parse_routstr_args(""),
            CommandResult::Action(Action::RoutstrBalance)
        ));
        match parse_routstr_args("spend bc1qdest 21000") {
            CommandResult::Action(Action::RoutstrSpend {
                address,
                amount_sats: 21_000,
                broadcast: false,
                fee_rate_sat_vb: None,
            }) => assert_eq!(address, "bc1qdest"),
            other => panic!("expected spend dry-run with deferred fee: {other:?}"),
        }
        match parse_routstr_args("spend bc1qdest 100 broadcast fee=7") {
            CommandResult::Action(Action::RoutstrSpend {
                amount_sats: 100,
                broadcast: true,
                fee_rate_sat_vb: Some(7),
                ..
            }) => {}
            other => panic!("expected spend broadcast: {other:?}"),
        }
        // Explicit zero is rejected offline (no network).
        assert!(matches!(
            parse_routstr_args("spend bc1qdest 100 fee=0"),
            CommandResult::Error(_)
        ));
        assert!(matches!(
            parse_routstr_args("spend"),
            CommandResult::Error(_)
        ));
        // RBF slash: offline parse, deferred fee, required original-fee/vbytes/inputs.
        let txid = "ab".repeat(32);
        let input = format!("{txid}:0:100000:bc1qrecv");
        match parse_routstr_args(&format!(
            "rbf bc1qdest 21000 original-fee=705 original-vbytes=141 input={input}"
        )) {
            CommandResult::Action(Action::RoutstrRbf {
                address,
                amount_sats: 21_000,
                original_fee_sats: 705,
                original_vbytes: 141,
                input_specs,
                broadcast: false,
                fee_rate_sat_vb: None,
            }) => {
                assert_eq!(address, "bc1qdest");
                assert_eq!(input_specs.len(), 1);
                assert_eq!(input_specs[0], input);
            }
            other => panic!("expected rbf dry-run deferred fee: {other:?}"),
        }
        match parse_routstr_args(&format!(
            "rbf bc1qdest 100 original-fee=500 original-vbytes=100 input={input} broadcast fee=12"
        )) {
            CommandResult::Action(Action::RoutstrRbf {
                amount_sats: 100,
                broadcast: true,
                fee_rate_sat_vb: Some(12),
                ..
            }) => {}
            other => panic!("expected rbf broadcast: {other:?}"),
        }
        // fee=0 rejected offline.
        assert!(matches!(
            parse_routstr_args(&format!(
                "rbf bc1qdest 100 original-fee=50 original-vbytes=100 input={input} fee=0"
            )),
            CommandResult::Error(_)
        ));
        // Missing inputs / zero vbytes / bare rbf.
        assert!(matches!(
            parse_routstr_args("rbf bc1qdest 100 original-fee=50 original-vbytes=100"),
            CommandResult::Error(_)
        ));
        assert!(matches!(
            parse_routstr_args(&format!(
                "rbf bc1qdest 100 original-fee=50 original-vbytes=0 input={input}"
            )),
            CommandResult::Error(_)
        ));
        assert!(matches!(parse_routstr_args("rbf"), CommandResult::Error(_)));
    }

    #[test]
    fn bare_fund_command_dispatches_fund_not_balance() {
        // Regression: `/fund` must not share RoutstrCommand's empty-args → balance.
        let cmd = FundCommand;
        assert_eq!(cmd.name(), "fund");
        assert!(cmd.aliases().is_empty());
        let models = crate::acp::model_state::ModelState::default();
        let mut ctx = crate::slash::commands::tests::make_ctx(&models);
        assert!(matches!(
            cmd.run(&mut ctx, ""),
            CommandResult::Action(Action::RoutstrFund)
        ));
        // Extra args on `/fund` are ignored; still fund (not balance).
        assert!(matches!(
            cmd.run(&mut ctx, "balance"),
            CommandResult::Action(Action::RoutstrFund)
        ));
        // /routstr with empty args remains balance.
        assert!(matches!(
            parse_routstr_args(""),
            CommandResult::Action(Action::RoutstrBalance)
        ));
        // RoutstrCommand no longer aliases "fund".
        assert!(!RoutstrCommand.aliases().contains(&"fund"));
    }

    #[test]
    fn parses_unlock_phrase_and_password() {
        match parse_routstr_args("unlock abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                phrase,
                password: None,
            }) => {
                assert_eq!(phrase.as_str(), "abandon abandon abandon");
            }
            other => panic!("expected unlock action: {other:?}"),
        }
        match parse_routstr_args("unlock pw:secret abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                phrase,
                password: Some(pw),
            }) => {
                assert_eq!(pw.as_str(), "secret");
                assert_eq!(phrase.as_str(), "abandon abandon abandon");
                // Debug must not leak secrets.
                let dbg = format!("{phrase:?} {pw:?}");
                assert!(!dbg.contains("abandon"), "Debug leaked phrase: {dbg}");
                assert!(!dbg.contains("secret"), "Debug leaked password: {dbg}");
                assert!(dbg.contains("***"));
            }
            other => panic!("expected unlock with password: {other:?}"),
        }
        assert!(matches!(
            parse_routstr_args("unlock"),
            CommandResult::Error(_)
        ));
        assert!(matches!(
            parse_routstr_args("unlock pw:onlypass"),
            CommandResult::Error(_)
        ));
        // Document single-token password: spaces truncate password and attach remainder to phrase.
        match parse_routstr_args("unlock pw:has spaces abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                phrase,
                password: Some(pw),
            }) => {
                assert_eq!(pw.as_str(), "has");
                assert_eq!(phrase.as_str(), "spaces abandon abandon");
            }
            other => panic!("expected single-token split: {other:?}"),
        }
        // Mixed case first token must work (eq_ignore_ascii_case).
        match parse_routstr_args("Unlock abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                phrase,
                password: None,
            }) => assert_eq!(phrase.as_str(), "abandon abandon abandon"),
            other => panic!("expected Unlock mixed-case: {other:?}"),
        }
        match parse_routstr_args("UNLOCK abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry { password: None, .. }) => {}
            other => panic!("expected UNLOCK: {other:?}"),
        }
    }
}
