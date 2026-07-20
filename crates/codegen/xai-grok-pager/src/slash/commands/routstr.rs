//! `/routstr` -- balance, fund, top up, refund, and address watch.
//!
//! Password-wrapped unlock uses a single-token password after `pw:`
//! (`/routstr unlock pw:<password> <phrase words…>`). Passwords containing
//! spaces are not supported on this path; use a private terminal or change
//! the AEAD password to a single token.
//!
//! Optional private BIP-39 passphrase: `/routstr unlock pass [pw:…] <phrase>`
//! opens a masked modal (never chat history / CredentialsStore / watch_session).
//! Env `GROK_BITCOIN_BIP39_PASSPHRASE` still works without the `pass` flag.

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
        "Routstr balance, local Bitcoin fund, spend, rbf, cpfp, utxos, top up, refund, watch"
    }

    fn usage(&self) -> &str {
        "/routstr [balance|fund|unlock|spend|rbf|cpfp|utxos|topup|refund|watch|stop|qr] [args]"
    }

    fn takes_args(&self) -> bool {
        true
    }

    fn arg_placeholder(&self) -> Option<&str> {
        Some(
            "balance | fund | unlock <phrase> | spend <addr> <sats> [broadcast] | rbf <addr> <sats> original-fee=… | cpfp <addr> <sats> parent-fee=… | utxos [--network …] | topup [sats] | refund | watch <addr> | stop | qr [addr]",
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
                description:
                    "Re-enter recovery phrase; add 'pass' for private BIP-39 passphrase modal"
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
                display: "cpfp".to_string(),
                match_text: "cpfp".to_string(),
                insert_text: "cpfp ".to_string(),
                description:
                    "CPFP child dry-run (add broadcast to submit; does not replace parent)"
                        .to_string(),
            },
            ArgItem {
                display: "utxos".to_string(),
                match_text: "utxos".to_string(),
                insert_text: "utxos".to_string(),
                description: "List UTXOs / on-chain balance (stage + unlock; optional --network)"
                    .to_string(),
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
    // Optional leading `pass` requests the private BIP-39 passphrase modal.
    // Optional `pw:<aead>` (single token) for SeedVault AEAD password.
    let unlock_rest = {
        let mut sp = trimmed.splitn(2, char::is_whitespace);
        let first = sp.next().unwrap_or("");
        if first.eq_ignore_ascii_case("unlock") {
            Some(sp.next().unwrap_or("").trim())
        } else {
            None
        }
    };
    if let Some(rest) = unlock_rest {
        if rest.is_empty() {
            return CommandResult::Error(
                "Usage: /routstr unlock [pass] [pw:<password>] <recovery phrase words…>\n\
                 `pass` opens a private masked BIP-39 passphrase prompt (not chat history).\n\
                 Optional AEAD password: `pw:<password>` (single token, no spaces).\n\
                 Env GROK_BITCOIN_BIP39_PASSPHRASE still applies when `pass` is omitted."
                    .into(),
            );
        }
        let mut rest = rest;
        let mut request_passphrase_prompt = false;
        // Leading `pass` flag (case-insensitive). Must be a whole token so a
        // recovery word that happens to be "pass" still works when not first.
        {
            let mut sp = rest.splitn(2, char::is_whitespace);
            let tok = sp.next().unwrap_or("");
            if tok.eq_ignore_ascii_case("pass") {
                request_passphrase_prompt = true;
                rest = sp.next().unwrap_or("").trim();
            }
        }
        if rest.is_empty() {
            return CommandResult::Error(
                "Usage: /routstr unlock pass [pw:<password>] <recovery phrase words…>\n\
                 Recovery phrase is required after the pass flag."
                    .into(),
            );
        }
        let (password, phrase) = if let Some(after) = rest.strip_prefix("pw:") {
            // Single-token password only: split once on whitespace so the rest
            // is the recovery phrase. Passwords with spaces are not supported.
            let mut sp = after.splitn(2, char::is_whitespace);
            let pw = sp.next().unwrap_or("").to_owned();
            let ph = sp.next().unwrap_or("").trim().to_owned();
            if ph.is_empty() {
                return CommandResult::Error(
                    "Usage: /routstr unlock [pass] pw:<password> <recovery phrase…>\n\
                     Password must be a single token (no spaces)."
                        .into(),
                );
            }
            (Some(SensitiveString::new(pw)), ph)
        } else {
            (None, rest.to_owned())
        };
        return CommandResult::Action(Action::RoutstrFundReentry {
            phrase: SensitiveString::new(phrase),
            password,
            request_passphrase_prompt,
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
        "cpfp" => {
            let rest: Vec<&str> = parts.collect();
            match grok_bitcoin_wallet::funding_cli::parse_cpfp_tokens(&rest) {
                Ok(req) => {
                    // Parse only — no fee HTTP. Explicit fee → Some; omit → None
                    // (resolve halfHour/default in the cpfp effect worker).
                    let fee_rate_sat_vb = if req.fee_rate_explicit {
                        Some(req.fee_rate_sat_vb)
                    } else {
                        None
                    };
                    let parent_specs: Vec<String> = req
                        .parents
                        .iter()
                        .map(grok_bitcoin_wallet::funding_cli::format_rbf_input_spec_value)
                        .collect();
                    let extra_input_specs: Vec<String> = req
                        .extra_inputs
                        .iter()
                        .map(grok_bitcoin_wallet::funding_cli::format_rbf_input_spec_value)
                        .collect();
                    CommandResult::Action(Action::RoutstrCpfp {
                        address: req.payment_address,
                        amount_sats: req.amount_sats,
                        parent_fee_sats: req.parent_fee_sats,
                        parent_vbytes: req.parent_vbytes,
                        parent_specs,
                        extra_input_specs,
                        broadcast: req.broadcast,
                        fee_rate_sat_vb,
                    })
                }
                Err(e) => CommandResult::Error(format!(
                    "{e}\nUsage: /routstr cpfp <address> <sats> parent-fee=<n> \
                     parent-vbytes=<n> parent=<txid:vout:amount:address> [...] \
                     [extra-input=<txid:vout:amount:address>] [broadcast] [fee=<n>]\n\
                     CPFP child only (spends wallet-owned parent output; does not replace \
                     the parent). Dry-run by default. BIP-39 is never part of this command — \
                     authorize with /routstr unlock after cpfp is staged."
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
        "utxos" | "coins" => {
            let rest: Vec<&str> = parts.collect();
            match parse_utxos_slash_tokens(&rest) {
                Ok(network) => CommandResult::Action(Action::RoutstrUtxos { network }),
                Err(e) => CommandResult::Error(format!(
                    "{e}\nUsage: /routstr utxos [--network mainnet|signet|testnet|testnet4]\n\
                     Stage only — authorize with /routstr unlock after utxos is staged.\n\
                     Observational gap-limit ChainSource sync (no broadcast). \
                     Omit --network to use GROK_BITCOIN_NETWORK (default mainnet)."
                )),
            }
        }
        other => CommandResult::Error(format!(
            "Unknown /routstr argument: {other}. Use balance, fund, unlock, spend, rbf, cpfp, utxos, topup, refund, watch, stop, or qr"
        )),
    }
}

/// Parse `/routstr utxos` optional network tokens (pure; offline-testable).
///
/// Accepts `--network <label>`, `--network=<label>`, or `network=<label>`.
/// Validates via product [`xai_grok_shell::auth::resolve_fees_network`] (same
/// acceptance set as CLI `--network`).
fn parse_utxos_slash_tokens(tokens: &[&str]) -> Result<Option<String>, String> {
    let mut network: Option<String> = None;
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        if let Some(v) = t.strip_prefix("--network=") {
            if network.is_some() {
                return Err("duplicate --network".into());
            }
            if v.trim().is_empty() {
                return Err("empty --network value".into());
            }
            network = Some(v.trim().to_owned());
        } else if t == "--network" {
            i += 1;
            let Some(v) = tokens.get(i) else {
                return Err("missing value after --network".into());
            };
            if v.trim().is_empty() {
                return Err("empty --network value".into());
            }
            if network.is_some() {
                return Err("duplicate --network".into());
            }
            network = Some(v.trim().to_owned());
        } else if let Some(v) = t.strip_prefix("network=") {
            if network.is_some() {
                return Err("duplicate network=".into());
            }
            if v.trim().is_empty() {
                return Err("empty network= value".into());
            }
            network = Some(v.trim().to_owned());
        } else {
            return Err(format!("unknown utxos argument: {t}"));
        }
        i += 1;
    }
    if let Some(ref n) = network {
        // Single product resolver — same labels as CLI (no dual accept sets).
        xai_grok_shell::auth::resolve_fees_network(Some(n)).map_err(|e| e.to_string())?;
    }
    Ok(network)
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
        // utxos: stages unlock re-entry (TUI path; not CLI Error).
        match parse_routstr_args("utxos") {
            CommandResult::Action(Action::RoutstrUtxos { network: None }) => {}
            other => panic!("expected RoutstrUtxos default: {other:?}"),
        }
        match parse_routstr_args("utxos --network signet") {
            CommandResult::Action(Action::RoutstrUtxos { network: Some(n) }) => {
                assert_eq!(n, "signet")
            }
            other => panic!("expected utxos --network signet: {other:?}"),
        }
        match parse_routstr_args("utxos --network=testnet4") {
            CommandResult::Action(Action::RoutstrUtxos { network: Some(n) }) => {
                assert_eq!(n, "testnet4")
            }
            other => panic!("expected utxos --network=testnet4: {other:?}"),
        }
        match parse_routstr_args("utxos network=mainnet") {
            CommandResult::Action(Action::RoutstrUtxos { network: Some(n) }) => {
                assert_eq!(n, "mainnet")
            }
            other => panic!("expected utxos network=mainnet: {other:?}"),
        }
        match parse_routstr_args("coins") {
            CommandResult::Action(Action::RoutstrUtxos { network: None }) => {}
            other => panic!("coins alias should stage utxos: {other:?}"),
        }
        match parse_routstr_args("utxos --network regtest") {
            CommandResult::Error(msg) => {
                let lower = msg.to_ascii_lowercase();
                assert!(
                    lower.contains("unknown") || lower.contains("network"),
                    "regtest must be rejected: {msg}"
                );
            }
            other => panic!("expected Error for regtest: {other:?}"),
        }
        match parse_routstr_args("utxos broadcast") {
            CommandResult::Error(msg) => {
                assert!(
                    msg.to_ascii_lowercase().contains("unknown")
                        || msg.to_ascii_lowercase().contains("usage"),
                    "utxos must not accept broadcast: {msg}"
                );
            }
            other => panic!("expected Error for broadcast: {other:?}"),
        }
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

        // CPFP slash: offline parse, deferred fee, required parent-fee/vbytes/parents.
        let parent = format!("{txid}:1:80000:bc1qchange");
        match parse_routstr_args(&format!(
            "cpfp bc1qdest 40000 parent-fee=200 parent-vbytes=200 parent={parent}"
        )) {
            CommandResult::Action(Action::RoutstrCpfp {
                address,
                amount_sats: 40_000,
                parent_fee_sats: 200,
                parent_vbytes: 200,
                parent_specs,
                extra_input_specs,
                broadcast: false,
                fee_rate_sat_vb: None,
            }) => {
                assert_eq!(address, "bc1qdest");
                assert_eq!(parent_specs.len(), 1);
                assert_eq!(parent_specs[0], parent);
                assert!(extra_input_specs.is_empty());
            }
            other => panic!("expected cpfp dry-run deferred fee: {other:?}"),
        }
        let extra = format!("{}:0:50000:bc1qextra", "ef".repeat(32));
        match parse_routstr_args(&format!(
            "cpfp bc1qdest 100 parent-fee=500 parent-vbytes=100 parent={parent} \
             extra-input={extra} broadcast fee=12"
        )) {
            CommandResult::Action(Action::RoutstrCpfp {
                amount_sats: 100,
                broadcast: true,
                fee_rate_sat_vb: Some(12),
                extra_input_specs,
                ..
            }) => {
                assert_eq!(extra_input_specs.len(), 1);
                assert_eq!(extra_input_specs[0], extra);
            }
            other => panic!("expected cpfp broadcast: {other:?}"),
        }
        // fee=0 rejected offline.
        assert!(matches!(
            parse_routstr_args(&format!(
                "cpfp bc1qdest 100 parent-fee=50 parent-vbytes=100 parent={parent} fee=0"
            )),
            CommandResult::Error(_)
        ));
        // Missing parents / zero vbytes / bare cpfp / parent-fee=0 still allowed via tokens.
        assert!(matches!(
            parse_routstr_args("cpfp bc1qdest 100 parent-fee=50 parent-vbytes=100"),
            CommandResult::Error(_)
        ));
        assert!(matches!(
            parse_routstr_args(&format!(
                "cpfp bc1qdest 100 parent-fee=50 parent-vbytes=0 parent={parent}"
            )),
            CommandResult::Error(_)
        ));
        assert!(matches!(
            parse_routstr_args("cpfp"),
            CommandResult::Error(_)
        ));
        match parse_routstr_args(&format!(
            "cpfp bc1qdest 100 parent-fee=0 parent-vbytes=100 parent={parent} fee=5"
        )) {
            CommandResult::Action(Action::RoutstrCpfp {
                parent_fee_sats: 0,
                fee_rate_sat_vb: Some(5),
                ..
            }) => {}
            other => panic!("parent-fee=0 with explicit fee should parse: {other:?}"),
        }
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
                request_passphrase_prompt: false,
            }) => {
                assert_eq!(phrase.as_str(), "abandon abandon abandon");
            }
            other => panic!("expected unlock action: {other:?}"),
        }
        match parse_routstr_args("unlock pw:secret abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                phrase,
                password: Some(pw),
                request_passphrase_prompt: false,
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
                request_passphrase_prompt: false,
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
                request_passphrase_prompt: false,
            }) => assert_eq!(phrase.as_str(), "abandon abandon abandon"),
            other => panic!("expected Unlock mixed-case: {other:?}"),
        }
        match parse_routstr_args("UNLOCK abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry { password: None, .. }) => {}
            other => panic!("expected UNLOCK: {other:?}"),
        }
    }

    #[test]
    fn parses_unlock_pass_flag_for_private_passphrase_modal() {
        match parse_routstr_args("unlock pass abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                phrase,
                password: None,
                request_passphrase_prompt: true,
            }) => {
                assert_eq!(phrase.as_str(), "abandon abandon abandon");
                let dbg = format!("{phrase:?}");
                assert!(!dbg.contains("abandon"), "Debug leaked phrase: {dbg}");
            }
            other => panic!("expected unlock pass: {other:?}"),
        }
        match parse_routstr_args("unlock pass pw:aeadsecret word1 word2 word3") {
            CommandResult::Action(Action::RoutstrFundReentry {
                phrase,
                password: Some(pw),
                request_passphrase_prompt: true,
            }) => {
                assert_eq!(pw.as_str(), "aeadsecret");
                assert_eq!(phrase.as_str(), "word1 word2 word3");
                let dbg = format!("{phrase:?} {pw:?}");
                assert!(
                    !dbg.contains("aeadsecret") && !dbg.contains("word1"),
                    "{dbg}"
                );
            }
            other => panic!("expected unlock pass + pw: {other:?}"),
        }
        // Case-insensitive pass flag.
        match parse_routstr_args("unlock PASS abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                request_passphrase_prompt: true,
                ..
            }) => {}
            other => panic!("expected PASS flag: {other:?}"),
        }
        // pass without phrase is an error.
        assert!(matches!(
            parse_routstr_args("unlock pass"),
            CommandResult::Error(_)
        ));
        // Without pass flag, request is false (env path).
        match parse_routstr_args("unlock abandon abandon abandon") {
            CommandResult::Action(Action::RoutstrFundReentry {
                request_passphrase_prompt: false,
                ..
            }) => {}
            other => panic!("expected no pass flag: {other:?}"),
        }
    }
}
