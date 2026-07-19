# Residual work: Bitcoin-native Routstr + wallet (2026-07-19)

## Done this pass (credit failover + dual balance)

| Item | Status |
|------|--------|
| OR → Grok API **provider** failover (`FailoverProvider` on sampler) | Done (after same-host multi-key) |
| Attach first-party session / `XAI_API_KEY` when resolving OpenRouter / Routstr | Done |
| Subagent inherits parent `failover_api_keys` + providers (was hard-zeroed) | Done |
| Footer: on OpenRouter model, show OR credits **and** `Grok used: N%` when both known | Done |
| OpenRouter credit failure UI (not SuperGrok "weekly limit") | Done |
| TDD: rotate provider, resolve attaches xAI, dual footer, OR error wording | Done |

## Still residual: Bitcoin-native Routstr + wallet

### Done earlier (Routstr foundations)

| Item | Status |
|------|--------|
| Wire `MnemonicBackupGate` + `UnlockSession` into funding CLI before ShowAddress | Done (`funding_cli` + `grok routstr fund`) |
| `grok routstr balance` / `topup` / `refund` / `fund` clap + binary wire-up | Done (`balance` live; `topup`/`refund` honest stubs) |
| Address watcher: poll → FundingWizard confirmations (injected producer) | Done (`watcher`; multi-URL clock advance under default min_interval) |
| `MempoolHttpClient` path for watcher (`explorer-http` helper) | Done (single-gate `poll_with_http_client`) |
| Fund: keyring error ≠ mint new wallet; store before address print | Done (review fix) |
| Fund: AEAD password unlock when keyring miss + file present | Done (`PasswordRequired` + no-echo prompt) |
| `begin_reentry_without_display` for returning unlock | Done |
| Skip pager settings row for `routstr_enabled` (avoid settings_e2e cost) | Done (config `[features] routstr_enabled` remains) |
| SeedVault `UnlockSession` idle TTL + zeroize on expire/lock | Done (prior) |
| `MnemonicBackupGate` show-once + full re-entry | Done (prior) |
| `FundingWizard::show_address` gated on backup confirm | Done (prior) |
| `ROUTSTR_GROK_45_MODEL` confirmed live as `grok-4.5` | Done (prior) |
| Pager credit footer + `/usage` Routstr paths | Done (prior) |
| `MempoolHttpClient` GET behind `RateLimitedExplorer` | Done (prior) |
| Prior foundations (BIP-39, AEAD vault, NIP-06, Routstr auth, wizards, …) | Still done |

### Settings note

- **No** new pager settings Bool row for `routstr_enabled` this pass.
- Toggle remains config-only: `[features] routstr_enabled` (default true).
- Adding a settings row later **must** update `settings_e2e` `ALL_SETTINGS_EXERCISED` + keyboard/mouse tests.

### Live catalog note (ROUTSTR_GROK_45_MODEL)

- Fetched `GET https://api.routstr.com/v1/models` (2026-07-18).
- Match: `id: "grok-4.5"`, name `xAI: Grok 4.5`,
  `canonical_slug: "x-ai/grok-4.5-20260708"`.
- Constant kept as short OpenAI-compatible `id` (`grok-4.5`), not the slug.
- Offline CI: `#[ignore]` test
  `auth::routstr::attribution_tests::live_routstr_grok_45_model_in_catalog`.

## Residual (next implement)

### P0 / product polish
1. Live keyring integration test behind `#[ignore]` + CI secret-service fixture (optional).
2. TUI funding path (pager wizard) reusing `funding_cli` / same gate invariants (CLI is wired; TUI still residual).
3. Optional: emergency mnemonic re-print only if store fails after backup (today: hard error + "do not fund" + keep paper backup).

### P1 / product surfaces
1. Pager settings row for `routstr_enabled` (optional); if added, update `settings_e2e`.
2. Smoke real Routstr 402 body through provider failover (same path as OpenRouter → xAI).
3. Welcome-screen Routstr balance line (app-level fetch lands; welcome UI still xAI-oriented).
4. Optionally gate OpenRouter/Routstr balance fetches on active model / `routstr_enabled`.
5. Wire `topup` / `refund` to real CDK/LN when those stacks land (stubs print next steps today).
6. Optional: parse OpenRouter "can only afford N max_tokens" and clamp+retry same key before provider failover.
7. Optional: surface mid-turn toast when sampler fails over OpenRouter → Grok API (footer model label may lag until next model switch).

### P2 / BDK + explorers
1. Full `bdk_wallet` sync + UTXO selection (currently BIP84 address-only).
2. Background watcher task in pager (library `AddressWatcher` multi-URL poll ready; no long-running UI task yet).
3. TUI QR pane + clipboard toast for receive / BOLT11.

### P3 / LDK
1. `ldk-node` (or LDK) from BIP-39 seed; BOLT11 pay real path.
2. Channel open to Routstr-recommended peer (API discovery).
3. BOLT12 only when peer+stack support; keep `BOLT12_SUPPORTED` honest (`false`).

### P4 / CDK Cashu
1. CDK mint/wallet for `cashuA` acquire/spend against Routstr.
2. Prefer spend Cashu over large hot `sk-` float; refund path.

### P5 / docs & packaging
1. Shell README short Routstr section (if not already).
2. Nix/CI: ensure `grok-bitcoin-wallet` stays in workspace checks; optional `explorer-http` job not required for default CI.
3. Language grep gate already in `scripts/bitcoin-routstr-validate.sh`.

## Next `/implement` prompt (copy)

```text
Continue Bitcoin-native Routstr from RESIDUAL.md (TUI + real topup/refund + BDK).

Credit failover OR→Grok API + dual footer landed; do not regress those tests.
1. Optional TUI funding path reusing funding_cli gate invariants (CLI already wired).
2. Optional: settings Bool routstr_enabled + settings_e2e ALL_SETTINGS_EXERCISED.
3. Replace routstr topup/refund stubs when CDK/LN ready; keep balance path.
4. Background address watcher task in pager (AddressWatcher + FundingWizard exist).
5. Do not claim BOLT12; do not store BIP-39 in CredentialsStore.
6. cargo test -p grok-bitcoin-wallet --lib
   cargo test -p xai-grok-shell --lib openrouter_resolve
   cargo test -p xai-grok-shell --lib routstr
   cargo test -p xai-grok-sampler --lib rotate_failover
   cargo test -p xai-grok-pager --lib credit_bar
   cargo test -p xai-grok-pager --lib routstr
   ./scripts/bitcoin-routstr-validate.sh
```

## Test commands (this pass)

```bash
cargo test -p grok-bitcoin-wallet --lib
cargo test -p xai-grok-shell --lib routstr
cargo test -p xai-grok-pager --lib credit_bar
cargo test -p xai-grok-pager --lib routstr
cargo clippy -p grok-bitcoin-wallet --lib -- -D warnings
./scripts/bitcoin-routstr-validate.sh
# optional network:
cargo test -p xai-grok-shell --lib live_routstr_grok_45_model_in_catalog -- --ignored
cargo test -p grok-bitcoin-wallet --lib --features explorer-http live_mempool -- --ignored
```
