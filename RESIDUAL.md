# Residual work: Bitcoin-native Routstr + wallet (2026-07-19)

## Done this pass (multi-sig/non-P2WPKH finalize honesty + WatchSession persistence)

| Item | Status |
|------|--------|
| `FinalizeOutcome` Complete/Partial (honest multi-sig / non-P2WPKH residual) | **Done** |
| Empty `final_script_witness` never counted complete; extract rejects empty | **Done** |
| Multi-sig (`partial_sigs.len() != 1`) → Partial, no invented witness | **Done** |
| Non-P2WPKH (P2WSH) residual → Partial, no extract success | **Done** |
| `psbt_is_broadcast_ready` + product prepare refuses partial finalize | **Done** |
| Partial sign → no extract / prepare / broadcast success claim | **Done** |
| `WatchSessionState` serialize/deserialize (no BIP-39) | **Done** |
| Durable file `{GROK_HOME}/bitcoin/watch_session.json` + atomic write | **Done** |
| Resume after pager restart (session create/load + startup hook) | **Done** |
| Unit tests: empty witness, multi-sig, P2WSH, partial sign, persist lifecycle | **Done** |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |

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

### Finalize honesty note (this pass)

- Only single-key **P2WPKH** is finalized into `final_script_witness`.
- Multi-sig / multi-key and non-P2WPKH scripts yield `FinalizeOutcome::Partial`
  with explicit "not broadcast-ready" detail — never invent witnesses.
- Empty witnesses are cleared/not counted; extract rejects empty or missing.
- `prepare_bip84_p2wpkh_spend` requires both complete sign and complete finalize.
- Pubkey HASH160 mismatch vs P2WPKH UTXO remains a hard error (tamper/corrupt).

### WatchSession persistence note (this pass)

- File: `{GROK_HOME}/bitcoin/watch_session.json` (mode 0600, atomic rename).
- Fields: address, network, required_confirmations, watched_txid, confirmations,
  step wire name, generation, running — **never** BIP-39 / seed material.
- Load rejects BIP-39-shaped address/txid strings.
- Pager: persist on start + after each poll; clear on stop / deposit confirmed.
- Resume on session create/load and event_loop startup when agent is active.
- Unit-test builds of the pager skip durable FS (do not pollute developer home).
- Wallet crate tests cover serialize/deserialize + full resume lifecycle.

## Residual (next implement)

### P0 / polish
1. Live keyring integration test behind `#[ignore]` + CI secret-service fixture (optional).
2. Optional: emergency mnemonic re-print only if store fails after backup (today: hard error + "do not fund" + keep paper backup).
3. New-wallet TUI still routes to private CLI (`grok routstr fund`) so recovery words never hit chat history. Optional private modal later.
4. Spend path: live UTXO/broadcast require network; dry-run still needs funded wallet UTXOs. Optional offline mock product mode not shipped.

### P1 / product surfaces
1. Wire `topup` / `refund` to **real** CDK/LN when those stacks land: flip `mint_live` / `refund_live` / `bolt11_*_live` only with tested impls; swap `default_*_backend()` factories.
2. Optional: dedicated QR pane widget (today: Unicode QR matrix in system block + clipboard toast).

### P2 / spend path + explorers
1. ~~Multi-sig / non-P2WPKH finalize residual~~ **Done this pass** (honest Partial; still only single-key P2WPKH finalized).
2. Optional full `bdk_wallet` electrum/esplora sync if still needed beyond mempool UTXO ChainSource.
3. ~~Persist WatchSession across pager process restarts~~ **Done this pass**.
4. Optional: RBF / CPFP-aware fee estimation (today: flat sat/vB + P2WPKH vb heuristics; RBF sequence set on built inputs).
5. Electrum push broadcaster alternative (mempool.space POST wired).
6. Optional: multi-sig / script-path **finalize support** (today: residual Partial only).

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

Multi-sig/non-P2WPKH finalize honesty + WatchSession persistence landed.
Do not regress:
  cargo test -p grok-bitcoin-wallet --lib
  cargo test -p xai-grok-shell --lib openrouter
  cargo test -p xai-grok-shell --lib routstr
  cargo test -p xai-grok-pager --lib credit_bar
  cargo test -p xai-grok-pager --lib routstr
  ./scripts/bitcoin-routstr-validate.sh

1. Wire topup/refund to real CDK/LN when stacks land; flip capability flags only when live; keep stubs honest.
2. Optional: multi-sig/script-path finalize support (today Partial residual only); RBF/CPFP fee; bdk electrum/esplora.
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

## Validation ran (2026-07-19 residual implement — finalize honesty + WatchSession persistence)

| Check | Result |
|-------|--------|
| `cargo fmt --all` | pass |
| `cargo test -p grok-bitcoin-wallet --lib` | pass (184) |
| `cargo test -p xai-grok-shell --lib routstr` | pass (26 + 1 ignored) |
| `cargo test -p xai-grok-shell --lib openrouter` | pass (19) |
| `cargo test -p xai-grok-pager --lib credit_bar` | pass (41) |
| `cargo test -p xai-grok-pager --lib routstr` | pass (28) |
| `cargo clippy -p grok-bitcoin-wallet --lib -- -D warnings` | pass |
| `cargo clippy -p xai-grok-pager --lib -- -D warnings` | pass |
| `./scripts/bitcoin-routstr-validate.sh` | pass |
| Cashu/LN live flags | still false (honest) |
| Multi-sig / non-P2WPKH finalize | honest Partial (not broadcast-ready) |
| WatchSession durable resume | `{GROK_HOME}/bitcoin/watch_session.json` |
| No BIP-39 in watch persistence | enforced + tests |
| Network broadcast of signed tx | wired prior (dry-run default) |
