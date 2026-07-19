# Residual work: Bitcoin-native Routstr + wallet (2026-07-19)

## Done this pass (RBF replacement PSBT rebuild/broadcast CLI)

| Item | Status |
|------|--------|
| `selection_with_rbf_fee` (same inputs, higher absolute fee, dust fold) | **Done** |
| `prepare_rbf_replacement_from_selection` (same-size sign/finalize/extract) | **Done** |
| `prepare_rbf_replacement` + `RbfReplacementSpend` (same-input plan → absolute fee → prepare) | **Done** |
| BIP-125 absolute + bandwidth fee enforced; never claim broadcast without broadcaster | **Done** |
| `parse_rbf_replace_request` / `--input` / `RbfReplaceRequest` + product formatters + usage | **Done** |
| CLI `grok routstr rbf … --original-fee N --original-vbytes V --input … [--fee-rate] [--broadcast]` | **Done** |
| Shell `run_routstr_rbf` / `complete_routstr_rbf_with_mnemonic` (same-input; unlock + re-entry) | **Done** |
| Dry-run default; `--broadcast` only after unlock; Accepted + parseable txid only | **Done** |
| Offline unit tests (wallet mocks + parse/format + clap + BIP-125 underpay guard) | **Done** |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Multi-sig finalize *support* (beyond honest Partial) | **Still residual** |
| TUI `/routstr rbf` slash path | **Still residual** (CLI first) |
| CPFP child construction (plan helpers only) | **Still residual** |

## Done prior pass (RBF / CPFP fee estimation + mempool fee ladder)

| Item | Status |
|------|--------|
| Pure `plan_rbf_fee_bump` / `RbfFeePlan` (BIP-125 same-size guidance) | Done |
| Pure `plan_cpfp_child_fee` / `CpfpFeePlan` + `estimate_cpfp_child_vbytes` | Done |
| `effective_fee_rate_sat_vb`, `rbf_min_fee_increase_sats`, `transaction_vbytes` | Done |
| `PreparedSpend::weight_vbytes` / `effective_fee_rate_sat_vb` / `estimated_vbytes` | Done |
| mempool `GET /api/v1/fees/recommended` URL + pure parse + `FeeEstimates` / `FeePriority` | Done |
| `resolve_spend_fee_rate_sat_vb` (override → estimates → fallback) | Done |
| `MempoolHttpClient::fetch_fee_estimates` (`explorer-http`, rate-limited) | Done |
| Product copy: RBF/CPFP plan lines, fee meta on prepare, fee estimates lines | Done |
| CLI/TUI: non-explicit fee uses live halfHour estimates else default 5 sat/vB | Done |
| `SpendRequest.fee_rate_explicit`; spend usage notes RBF + estimates | Done |
| Unit tests: RBF/CPFP edges, fee parse rejects, product formatters, override | Done |

## Done prior pass (multi-sig/non-P2WPKH finalize honesty + WatchSession persistence)

| Item | Status |
|------|--------|
| `FinalizeOutcome` Complete/Partial (honest multi-sig / non-P2WPKH residual) | Done |
| Empty `final_script_witness` never counted complete; extract rejects empty | Done |
| Multi-sig (`partial_sigs.len() != 1`) → Partial, no invented witness | Done |
| Non-P2WPKH (P2WSH) residual → Partial, no extract success | Done |
| `psbt_is_broadcast_ready` + product prepare refuses partial finalize | Done |
| Partial sign → no extract / prepare / broadcast success claim | Done |
| `WatchSessionState` serialize/deserialize (no BIP-39) | Done |
| Durable file `{GROK_HOME}/bitcoin/watch_session.json` + atomic write | Done |
| Resume after pager restart (session create/load + startup hook) | Done |
| Unit tests: empty witness, multi-sig, P2WSH, partial sign, persist lifecycle | Done |
| Live CDK mint/refund / LDK BOLT11 | Still residual (flags remain false; no fake success) |

## Done prior pass (OR balance fetch gate + TUI dry-run full hex)

| Item | Status |
|------|--------|
| Pure `should_fetch_openrouter_balance` / `_for_model_id` (shell) | Done |
| `Effect::FetchBilling { fetch_openrouter }` + product helpers | Done |
| App-level `FetchAppBilling` skips OR network (no active model) | Done |
| Model switch re-fetches billing so dual-footer appears without waiting for turn end | Done |
| Dual-footer still correct when both OR + Grok balances known | Unchanged |
| TUI dry-run spend: full raw hex in shared prepared lines | Done |
| Live CDK mint/refund / LDK BOLT11 | Still residual |

## Done prior pass (pager settings Bool `routstr_enabled`)

| Item | Status |
|------|--------|
| Settings Bool `routstr_enabled` (Models, SHELL-owned, restart_required) | Done |
| `ALL_SETTINGS_EXERCISED` + keyboard Space + mouse value-column tests | Done |
| Persist `[features].routstr_enabled` via specialized merge (no Features splat) | Done |
| `set_routstr_enabled` + `Effect::PersistSetting` + rollback to default/`None` | Done |
| AppView / PagerLocalSnapshot mirrors; event_loop load; settings modal snapshot | Done |

## Done prior pass (CDK/LN product seams + honest gates)

| Item | Status |
|------|--------|
| `default_cashu_backend()` / `default_lightning_backend()` product factories | Done (return stubs today) |
| CLI/TUI topup/refund via factories → capability-aware copy | Done |
| TDD capability gates: stub never invents invoice/refund; live fail ≠ not-wired | Done |
| Optional empty features `cashu-cdk` / `ldk` (flags still false) | Done |
| Gate Routstr balance fetch on `[features] routstr_enabled` | Done |

## Done prior pass (broadcast + PSBT spend CLI/TUI)

| Item | Status |
|------|--------|
| `TxBroadcaster` + mempool `POST /api/tx` + `PreparedSpend` + CLI/TUI spend | Done |
| SeedVault unlock + re-entry gates; dry-run default | Done |

## Done prior pass (PSBT build/sign + descriptor UTXO + fee select)

| Item | Status |
|------|--------|
| Unsigned PSBT, BIP84 P2WPKH sign, finalize/extract, honest `SignOutcome::Partial` | Done |
| Mempool ChainSource + fee-aware select + dust fold | Done |

## Done prior (TUI fund + watch + honesty + clamp + foundations)

| Item | Status |
|------|--------|
| TUI `/routstr` fund/watch/topup/refund; WatchTaskLifecycle; OR clamp+failover | Done |
| MnemonicBackupGate + UnlockSession + funding CLI; pager credit footer | Done |

### Settings note

- Pager settings Bool **Routstr** (`routstr_enabled`) is in Models (SHELL-owned, default on, restart_required).
- Writes `[features] routstr_enabled` via specialized merge (never wholesale Features).
- When false: catalog omit **and** Routstr balance network fetch skipped.

### OpenRouter balance fetch note

- Product gate: `should_fetch_openrouter_balance` / `_for_model_id`.
- Pager: `Effect::FetchBilling { fetch_openrouter }` from active catalog id.
- Dual-footer still requires both balances known.

### Finalize honesty note

- Only single-key **P2WPKH** is finalized into `final_script_witness`.
- Multi-sig / multi-key and non-P2WPKH scripts yield `FinalizeOutcome::Partial`
  with explicit "not broadcast-ready" detail — never invent witnesses.
- Empty witnesses are cleared/not counted; extract rejects empty or missing.
- `prepare_bip84_p2wpkh_spend` requires both complete sign and complete finalize.
- Pubkey HASH160 mismatch vs P2WPKH UTXO remains a hard error (tamper/corrupt).

### WatchSession persistence note

- File: `{GROK_HOME}/bitcoin/watch_session.json` (mode 0600, atomic rename).
- Fields: address, network, required_confirmations, watched_txid, confirmations,
  step wire name, generation, running — **never** BIP-39 / seed material.
- Load rejects BIP-39-shaped address/txid strings.
- Pager: persist on start + after each poll; clear on stop / deposit confirmed.
- Resume on session create/load and event_loop startup when agent is active.
- Unit-test builds of the pager skip durable FS (do not pollute developer home).
- Wallet crate tests cover serialize/deserialize + full resume lifecycle.

### RBF replacement note (this pass)

- Built PSBT inputs still set `Sequence::ENABLE_RBF_NO_LOCKTIME`.
- Pure planners size same-size RBF replacements and CPFP child fees offline.
- **Shipped:** `grok routstr rbf` rebuilds a **same-input** BIP-125 replacement
  from `--original-fee`, `--original-vbytes`, and each `--input
  txid:vout:amount:address` (from prior spend dry-run meta). Plans via
  `plan_rbf_fee_bump`, applies **recommended absolute fee** (not floor-rate
  re-select), signs/finalizes with original prevouts only; dry-run by default;
  `--broadcast` only after unlock + re-entry and only claims success on
  broadcaster Accepted + parseable txid.
- Library: `selection_with_rbf_fee` / `prepare_rbf_replacement` /
  `prepare_rbf_replacement_from_selection` + post-prepare
  `validate_rbf_replacement_fee` (bandwidth on actual replacement vB).
- Spend dry-run prints `--input` lines for copy into rbf CLI.
- **Not** shipped: TUI `/routstr rbf` slash; CPFP child PSBT construction;
  multi-sig finalize beyond Partial honesty; live CDK/LN.

## Residual (next implement)

### P0 / polish
1. Live keyring integration test behind `#[ignore]` + CI secret-service fixture (optional).
2. Optional: emergency mnemonic re-print only if store fails after backup (today: hard error + "do not fund" + keep paper backup).
3. New-wallet TUI still routes to private CLI (`grok routstr fund`) so recovery words never hit chat history. Optional private modal later.
4. Spend path: live UTXO/broadcast require network; dry-run still needs funded wallet UTXOs. Optional offline mock product mode not shipped.

### P1 / product surfaces
1. Wire `topup` / `refund` to **real** CDK/LN when those stacks land: flip `mint_live` / `refund_live` / `bolt11_*_live` only with tested impls; swap `default_*_backend()` factories.
2. Optional: dedicated QR pane widget (today: Unicode QR matrix in system block + clipboard toast).
3. Optional: `grok routstr fees` CLI that prints estimate ladder only (RBF rebuild is now `grok routstr rbf`).
4. Optional: TUI `/routstr rbf` slash + staged unlock path (CLI complete).

### P2 / spend path + explorers
1. ~~Multi-sig / non-P2WPKH finalize residual~~ **Done** (honest Partial; still only single-key P2WPKH finalized).
2. Optional full `bdk_wallet` electrum/esplora sync if still needed beyond mempool UTXO ChainSource.
3. ~~Persist WatchSession across pager process restarts~~ **Done**.
4. ~~RBF / CPFP-aware fee estimation~~ **Done** (pure planners + fee ladder + product meta).
5. ~~End-to-end RBF replace-by-fee rebuild~~ **Done this pass** (`grok routstr rbf` + library rebuild).
6. Electrum push broadcaster alternative (mempool.space POST wired).
7. Optional: multi-sig / script-path **finalize support** (today: residual Partial only).
8. Optional: CPFP child PSBT construction (plan helpers only today).

### P3 / LDK
1. `ldk-node` (or LDK) from BIP-39 seed; BOLT11 pay + invoice create with live capability flags.
2. Enable optional `ldk` feature with real deps; keep factory returning live impl only when tested.
3. Channel open to Routstr-recommended peer (API discovery).
4. BOLT12 only when peer+stack support; keep `BOLT12_SUPPORTED` honest (`false`).

### P4 / CDK Cashu
1. CDK mint/wallet for `cashuA` acquire/spend against Routstr (`CashuBackend` live impl).
2. Enable optional `cashu-cdk` feature with real deps; flip `mint_live`/`spend_live`/`refund_live` only when green.
3. Prefer spend Cashu over large hot `sk-` float; refund path (`refund_live`).

### P5 / docs & packaging
1. Shell README Routstr section — **done**.
2. Nix/CI: ensure `grok-bitcoin-wallet` stays in workspace checks; optional `explorer-http` job not required for default CI; do **not** enable `cashu-cdk`/`ldk` in default CI until deps land.
3. Language grep gate already in `scripts/bitcoin-routstr-validate.sh`.

## Next `/implement` prompt (copy)

```text
Continue Bitcoin-native Routstr from RESIDUAL.md (CDK/LN live backends).

RBF replacement rebuild CLI (`grok routstr rbf`) + fee planners landed.
Do not regress:
  cargo test -p grok-bitcoin-wallet --lib
  cargo test -p xai-grok-shell --lib openrouter
  cargo test -p xai-grok-shell --lib routstr
  cargo test -p xai-grok-pager --lib credit_bar
  cargo test -p xai-grok-pager --lib routstr
  ./scripts/bitcoin-routstr-validate.sh

1. Wire topup/refund to real CDK/LN when stacks land; flip capability flags only when live; keep stubs honest.
2. Optional: multi-sig/script-path finalize support (today Partial residual only); CPFP child PSBT; TUI rbf slash; bdk electrum/esplora.
3. Do not claim BOLT12; do not store BIP-39 in CredentialsStore or watch_session.json.
4. cargo test -p grok-bitcoin-wallet --lib
   cargo test -p xai-grok-shell --lib routstr
   cargo test -p xai-grok-pager --lib routstr
   ./scripts/bitcoin-routstr-validate.sh
```

## Test commands (this pass)

```bash
cargo fmt --all
cargo test -p grok-bitcoin-wallet --lib
cargo test -p xai-grok-shell --lib routstr
cargo test -p xai-grok-shell --lib openrouter
cargo test -p xai-grok-pager --lib credit_bar
cargo test -p xai-grok-pager --lib routstr
cargo clippy -p grok-bitcoin-wallet --lib -- -D warnings
cargo clippy -p xai-grok-pager --lib -- -D warnings
./scripts/bitcoin-routstr-validate.sh
```

## Validation ran (2026-07-19 residual implement — RBF replacement CLI)

| Check | Result |
|-------|--------|
| `cargo fmt` (touched packages) | pass |
| `cargo test -p grok-bitcoin-wallet --lib` | pass (214) |
| `cargo test -p xai-grok-shell --lib routstr` | pass (30 + 1 ignored) |
| `cargo test -p xai-grok-shell --lib openrouter` | pass (19) |
| `cargo test -p xai-grok-pager --lib credit_bar` | pass (41) |
| `cargo test -p xai-grok-pager --lib routstr` | pass (33) |
| `cargo clippy -p grok-bitcoin-wallet --lib -- -D warnings` | pass |
| `cargo clippy -p xai-grok-shell --lib -- -D warnings` | pass |
| `cargo clippy -p xai-grok-pager --lib -- -D warnings` | pass |
| `./scripts/bitcoin-routstr-validate.sh` | pass |
| Cashu/LN live flags | still false (honest) |
| RBF sequence on built inputs | unchanged (`ENABLE_RBF_NO_LOCKTIME`) |
| Multi-sig / non-P2WPKH finalize | honest Partial (unchanged) |
| WatchSession durable resume | unchanged |
| No BIP-39 in watch persistence | unchanged |
| Fee estimates default CI | offline parse/Mock; live fetch feature-gated |
| RBF broadcast claim | only on Accepted + parseable txid |
