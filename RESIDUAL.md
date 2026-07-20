# Residual work: Bitcoin-native Routstr + wallet (2026-07-19)

## Done this pass (watch path product-network fail-closed)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Watch brand-new start network | **Done** (`network_from_env` / `start_routstr_watch_for_agent*`: `resolve_product_entry_network` acceptance only — empty → Mainnet; unknown/`regtest` **fail closed** with scrollback+status; **no** `Effect::RoutstrWatchLoop`, **no** generation bump, **no** persist; wire always `BitcoinNetwork::as_str()`) |
| Watch resume / re-arm network | **Done** (durable `state.network` via `resolve_product_complete_network`; unknown durable → fail closed, no silent Mainnet; tick re-arm reuses in-memory network) |
| Watch persist + poll | **Done** (`persist_routstr_watch_running` skips unknown wire; `routstr_watch_poll_once` returns Err on unknown — **no** `unwrap_or(Mainnet)`) |
| Fund auto-watch | **Done** (passes fund `network_label` into watch override — product-resolved canonical label) |
| Fees soft-default | **Unchanged** (env unknown still soft-Mainnet; fees-only intentional) |
| Offline unit tests | **Done** (pager serial env: regtest/typo fail-closed no loop; signet/testnet4 canonical wire; empty/unset → mainnet; override regtest; persist skip unknown; helper parity) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (nested CLEANSTACK-valid or_c / non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention; bare or_c named residual only) |
| BIP-39 / passphrase persistence | **Still residual** (never CredentialsStore / watch_session.json) |

## Done prior pass (fund path product-network single-resolve)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Fund CLI + TUI re-entry network | **Done** (`run_routstr_fund` + `complete_routstr_fund_reentry_for_tui`: `resolve_product_entry_network(None)` **before** vault unlock / seed touch; `btc_net.as_str()` label; derive via `bitcoin_network_to_network` + `derive_bip84_receive_address_with_passphrase` — **not** env-string helper that accepts regtest) |
| Fund/spend split-brain removed | **Done** (fund no longer mints regtest addresses while spend rejects regtest; same acceptance = `mainnet\|signet\|testnet\|testnet4`; empty → Mainnet) |
| Low-level `network_from_str` / env-network derive | **Unchanged** (regtest still valid for tests/dev; product fund does not call them) |
| Fees soft-default | **Unchanged** (env unknown still soft-Mainnet; fees-only intentional) |
| Offline unit tests | **Done** (fund entry resolve + pure derive parity pin; full `complete_routstr_fund_reentry_for_tui` poisoned-env-before-no-wallet serial gate; existing entry/complete fail-closed coverage reused) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (nested CLEANSTACK-valid or_c / non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention; bare or_c named residual only) |
| BIP-39 / passphrase persistence | **Still residual** (never CredentialsStore / watch_session.json) |

## Done prior pass (product spend/RBF/CPFP single-resolve network mapping)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Shared product network resolve | **Done** (`resolve_product_complete_network`: empty → Mainnet; unknown/regtest hard error — **no** silent Mainnet; acceptance = `mainnet\|signet\|testnet\|testnet4`) |
| Spend/RBF/CPFP complete paths | **Done** (`complete_routstr_{spend,rbf,cpfp}_with_mnemonic` single-resolve → `bitcoin_network_to_network` → `from_mnemonic_with_passphrase`; chain/broadcaster use same `btc_net`; utxos path refactored onto shared helper) |
| Dual-parse split-brain removed | **Done** (no more `from_env_str(...).unwrap_or(Mainnet)` + independent `from_mnemonic_env_network_*` string re-parse on product complete paths) |
| Offline unit tests | **Done** (resolve parity + fail-closed; complete spend/rbf/cpfp unknown/regtest reject; testnet4 wallet construct parity with testnet; existing pure spend/rbf/cpfp parse tests unchanged) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (nested CLEANSTACK-valid or_c / non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention; bare or_c named residual only) |
| BIP-39 / passphrase persistence | **Still residual** (never CredentialsStore / watch_session.json) |

## Done prior pass (TUI `/routstr utxos` full unlock path)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Shell TUI re-entry | **Done** (`complete_routstr_utxos_reentry_for_tui` + `RoutstrUtxosSuccess`; SeedVault + phrase re-entry; optional network via `resolve_product_entry_network` (fail-closed; not fees soft-default); bip39 passphrase modal/env; **session locked on all Ok/Err paths** after unlock; observational — no broadcast) |
| Pager slash + dispatch | **Done** (`/routstr utxos [--network …]` stages `PendingRoutstrUtxos`; unlock → `Effect::RoutstrUtxosComplete`; mutually exclusive with spend/rbf/cpfp; fund clears pending; help/autocomplete no longer CLI-only) |
| Honesty | **Done** (same gates as CLI `run_routstr_utxos`; product chain select env default mempool; no BIP-39/passphrase in CredentialsStore / watch_session; gap-sync notices still on success lines) |
| Offline unit tests | **Done** (shell reentry cancel/wrong-phrase/no-wallet/bad-network/wrong-password; slash parse network + reject regtest/broadcast; dispatch stage/unlock/fund-clear + result handler) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (nested CLEANSTACK-valid or_c / non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention; bare or_c named residual only) |
| BIP-39 / passphrase persistence | **Still residual** (never CredentialsStore / watch_session.json) |

## Done prior pass (product gap-sync UTXO list / on-chain balance surface)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Product gap-sync UTXO list helper | **Done** (`list_bip84_utxos_with_gap_sync` → `sync_with_gap_extend`; returns `WalletSyncSnapshot`; **no** extra full-window `list_unspent`; snapshot.utxos authoritative; wrong passphrase fail-closed; empty chain → empty snapshot success, not invented coins) |
| Pure CLI format helpers | **Done** (`format_utxos_balance_lines` / `format_utxos_list_lines` / `format_gap_sync_utxos_cli_lines`; RBF-friendly `--input` via `format_rbf_input_cli_flag`; gap notices via shared `gap_sync_spend_notice_lines`) |
| Shell product wire | **Done** (`complete_routstr_utxos_with_mnemonic` + `run_routstr_utxos`; SeedVault unlock + recovery-phrase re-entry; `open_product_chain_source` from env; default mempool) |
| CLI + pager wire | **Done** (`grok routstr utxos [--network …]`; clap `RoutstrCommand::Utxos`; pager-bin dispatch; slash table — **TUI unlock path shipped next pass**) |
| Bare or_c residual honesty polish | **Done** (detect bare top-level `or_c` leaf; distinct Partial reason contains `or_c` + `CLEANSTACK`; **never assemble** final witness) |
| Offline unit tests | **Done** (list-count vs sync-only; deep tip after extend; empty chain; wrong passphrase; format helpers mock snapshot; bare or_c keywords; shell pure mapper; clap parse) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (nested CLEANSTACK-valid or_c / non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention; bare or_c named residual only) |
| BIP-39 / passphrase persistence | **Still residual** (never CredentialsStore / watch_session.json) |
| TUI `/routstr utxos` full unlock path | **Prior residual** — shipped this pass |

## Done prior pass (product gap-sync select-from-snapshot — drop extra list)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Select-from-snapshot on product gap-sync spend | **Done** (`select_and_prepare_bip84_spend_from_utxos` + product path uses `sync.utxos` after `sync_with_gap_extend`; **no** extra full-window `list_unspent`; fixed-window helper lists once then delegates; snapshot authoritative as of final sync list) |
| Chain-call honesty | **Done** (product spend = N+1 sync lists only; list-counter tests pin quiet + extend paths vs sync-only baseline) |
| Offline unit tests | **Done** (list-count matches sync-only; from_utxos no chain call / empty / zero fee; fixed-window lists once; existing gap_sync_spend_* + RBF/CPFP + wrong-passphrase Sync-only unchanged) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Bare or_c as top-level leaf | **Prior residual** — named residual polish shipped this pass (still not assembled) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |
| BIP-39 / passphrase persistence | **Still residual** (never CredentialsStore / watch_session.json) |

## Done prior pass (hit-max notice on select/prepare Err — structured error-with-sync)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Structured gap-sync spend failure | **Done** (`GapSyncSpendFailure::{Sync, AfterSync}` dual-error; AfterSync carries real `WalletSyncSnapshot` + cause; `notice_lines` / `display_lines`; kept out of generic `WalletError`) |
| Product helper return type | **Done** (`select_and_prepare_bip84_spend_with_gap_sync` → `Result<GapSyncedPreparedSpend, GapSyncSpendFailure>`; sync-stage fail = `Sync` without fabricated snapshot; select/prepare fail after successful extend = `AfterSync` with hit-max / extend meta) |
| Shell UX on AfterSync | **Done** (`complete_routstr_spend_with_mnemonic` surfaces cause + `gap_sync_spend_notice_lines` via `RoutstrCliError::Message` when notices present; quiet AfterSync / Sync-only → plain `Wallet`) |
| Offline unit tests | **Done** (hit-max then insufficient funds carries notices; quiet insufficient empty notices; empty chain AfterSync; wrong-passphrase Sync-only fail-closed; extend-then-insufficient notices; success path + RBF/CPFP explicit-prevout + `PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP` unchanged) |
| Hit-max notice on select/prepare Err | **Done** (no longer success-path only; wallet windows still grown on AfterSync) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |
| BIP-39 / passphrase persistence | **Still residual** (never CredentialsStore / watch_session.json) |

## Done prior pass (product gap-sync wire into shell spend)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Product gap-sync spend wire | **Done** (`select_and_prepare_bip84_spend_with_gap_sync` → `sync_with_gap_extend` then select/prepare with grown `max(receive,change)` gap; `GapSyncedPreparedSpend` + `gap_sync_spend_notice_lines`; shell `complete_routstr_spend_with_mnemonic` uses default `GapExtendOptions`; RBF/CPFP keep explicit prevouts — no re-extend; product RBF/CPFP sign with `PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP` = `MAX_ADDRESS_GAP` so deep recovered indices still sign) |
| Fixed-window helper retained | **Done** (`select_and_prepare_bip84_spend` still fixed window for callers that already extended or want no re-list/extend) |
| Offline unit tests | **Done** (deep tip-activity UTXO found after extend vs fixed miss; wrong-passphrase fail-closed; empty chain not invented success; RBF explicit-prevout sibling + deep gap-sync→RBF with product sign gap) |
| Hit-max notice on select/prepare Err | **Prior residual** — shipped this pass (structured `GapSyncSpendFailure::AfterSync`) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |

## Done prior pass (gap-limit ChainSource UTXO sync)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Gap-limit ChainSource sync | **Done** (`DescriptorWallet::sync_utxos` + `sync_with_gap_extend` / `extend_gap_if_needed`; pure helpers; `WalletSyncSnapshot` / `GapExtendOptions`; hard `MAX_ADDRESS_GAP` on construction + extend; default look-ahead = BIP44-style stop-gap 20; receive/change independent; wrong-passphrase fail-closed on extend) |
| Honesty | **Done** (only UTXOs from injectable `ChainSource`; no invent; BIP-39 not stored on wallet; MockChainSource offline tests only; not full bdk / no spent-tx history) |
| Full `bdk_wallet` auto-sync | **Still residual** (no bdk_wallet engine; UTXO-list gap + bounded extend only) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |

## Done prior pass (Electrum TLS transport)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Electrum TLS transport | **Done** (`TlsElectrumTransport` + rustls + WebPKI roots; no skip-verify; shared JSON-RPC line framing with TCP) |
| Feature gate | **Done** (`electrum` enables plaintext TCP **and** TLS; rustls/webpki-roots optional deps; not default CI) |
| Product wire | **Done** (`GROK_BITCOIN_ELECTRUM_TLS=1\|true\|yes` and/or `ssl://host:port`; default plaintext; `open_product_chain_source` / broadcaster use TLS when selected) |
| Offline unit tests | **Done** (TLS flag/scheme parse, SNI host extract, feature-disabled honesty, local closed-port Explorer error) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |
| Full `bdk_wallet` auto-sync | **Still residual** (injectable ChainSources cover UTXO list; gap-limit list/extend shipped this pass; no full wallet sync engine) |

## Done prior pass (Esplora / Electrum push broadcasters + product alignment)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Esplora `TxBroadcaster` (`POST /tx`) | **Done** (`EsploraTxBroadcaster` + `EsploraTransport::post_text`; pure txid parse; `MockEsploraTransport` POST fixtures; live behind `esplora`) |
| Electrum `TxBroadcaster` (`blockchain.transaction.broadcast`) | **Done** (`ElectrumTxBroadcaster` + pure `parse_electrum_broadcast_result`; mock scripted results; live behind `electrum`; TLS shipped this pass) |
| Product broadcaster select | **Done** (`open_product_tx_broadcaster` / `_from_env`; same env as UTXO; feature-missing → structured error) |
| Shell spend/RBF/CPFP broadcast wire | **Done** (aligned with `GROK_BITCOIN_CHAIN_SOURCE`; default mempool unchanged) |
| Honesty notice | **Done** (`broadcast_backend_notice_lines` empty when UTXO+push match; residual only on kind divergence) |
| Offline unit tests | **Done** (success parse, non-hex/RPC error, empty hex, feature-disabled open, mock method/path counts) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |
| Full `bdk_wallet` auto-sync | **Still residual** (injectable ChainSources cover UTXO list; no full wallet sync engine) |
| Electrum TLS / SSL | **Prior residual** — shipped this pass |

## Done prior pass (product ChainSource wire into shell spend)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Pure `chain_select` config helper | **Done** (`parse_chain_source_kind` / `product_chain_source_config` / `product_chain_source_config_from_env`; default mempool) |
| Env contract | **Done** (`GROK_BITCOIN_CHAIN_SOURCE` = mempool\|esplora\|electrum; `GROK_BITCOIN_ESPLORA_URL`; `GROK_BITCOIN_ELECTRUM_ADDR`; no BIP-39 env stores invented) |
| Feature honesty on open | **Done** (selecting esplora/electrum/mempool without matching feature → structured `WalletError::Explorer`, not network hang) |
| Shell spend wire | **Done** (`complete_routstr_spend_with_mnemonic` → `open_product_chain_source_from_env`; RBF/CPFP keep explicit prevouts, no chain re-fetch) |
| Shell optional features | **Done** (`esplora` / `electrum` feature passthrough; **not** default; pager stays mempool-only) |
| Offline unit tests | **Done** (parse/default/missing URL·addr/feature-disabled paths) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |
| Full `bdk_wallet` auto-sync | **Still residual** (injectable ChainSources cover UTXO list; no full wallet sync engine) |
| Electrum TLS / SSL | **Prior residual** — shipped this pass |
| Electrum/Esplora push broadcasters | **Prior residual** — shipped this pass |

## Done prior pass (Esplora + Electrum ChainSource)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Esplora REST [`ChainSource`] | **Done** (`EsploraChainSource` + `EsploraTransport`; pure path/join + `parse_esplora_address_utxos` = mempool schema; `MockEsploraTransport` offline fixtures; tip-miss conf=1 honesty) |
| Electrum JSON-RPC [`ChainSource`] | **Done** (`ElectrumChainSource` + `ElectrumTransport`; scripthash + listunspent/headers pure parse; `MockElectrumTransport` offline fixtures; network-checked addresses; tip-miss conf=1 honesty) |
| Feature `esplora` live HTTP | **Done** (`HttpEsploraTransport` via reqwest + `RateLimitedExplorer`; not default CI) |
| Feature `electrum` live TCP | **Done** (plaintext `TcpElectrumTransport`; TLS shipped this pass; not default CI) |
| Default unit tests | **Done** (mock/offline fixtures only; no forced network) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |
| Full `bdk_wallet` auto-sync | **Still residual** (injectable ChainSources cover UTXO list; no full wallet sync engine) |
| Electrum TLS / SSL | **Prior residual** — shipped this pass |
| Product wire of Esplora/Electrum into shell spend | **Prior residual** — shipped this pass (`chain_select` + shell spend) |

## Done prior pass (Taproot after / CLTV script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** `and_v(v:pk, after(n))` offline finalize | **Done** (`<A> CHECKSIGVERIFY <n> CLTV`; matching `tap_script_sig` + **already-present** nLockTime satisfying BIP-65 + non-final nSequence; never invents sig/nLockTime/nSequence) |
| Taproot **script-path** `and_v(v:after(n), pk)` offline finalize | **Done** (`<n> CLTV VERIFY <A> CHECKSIG`; same honesty gates) |
| Taproot **script-path** bare `after(n)` offline finalize | **Done** (`<n> CLTV`; empty script-input witness; nLockTime must already satisfy BIP-65 with non-final nSequence) |
| nLockTime plumbing into finalize | **Done** (from `unsigned_tx`; never mutates locktime/sequence; below / type-mismatch / final sequence → Partial) |
| Missing sig / bad locktime / sibling false positives | **Done** (honest Partial residual; bad control block → hard error) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Bare CHECKSIG + multi_a + thresh + and_v + or_i + or_d + and_n + andor + hash + older + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh /…) finalize | **Still residual** (honest Partial; no invention) |
| bdk electrum/esplora ChainSource | **Prior residual** — shipped this pass (injectable + feature-gated live) |

## Done prior pass (Taproot older / CSV script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** `and_v(v:pk, older(n))` offline finalize | **Done** (`<A> CHECKSIGVERIFY <n> CSV`; matching `tap_script_sig` + **already-present** nSequence satisfying BIP-112; never invents sig/nSequence) |
| Taproot **script-path** `and_v(v:older(n), pk)` offline finalize | **Done** (`<n> CSV VERIFY <A> CHECKSIG`; same honesty gates) |
| Taproot **script-path** bare `older(n)` offline finalize | **Done** (`<n> CSV`; empty script-input witness; nSequence must already satisfy BIP-112) |
| nSequence / tx version plumbing into finalize | **Done** (from `unsigned_tx`; never mutates sequence/version; disabled / below / type-mismatch / v1 → Partial) |
| Missing sig / bad sequence / sibling false positives | **Done** (honest Partial residual; bad control block → hard error) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Bare CHECKSIG + multi_a + thresh + and_v + or_i + or_d + and_n + andor + hash + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (or_c/ non-s:pk thresh / after /…) finalize | **Prior residual** — after/CLTV done this pass; other still residual |
| bdk electrum/esplora ChainSource | **Prior residual** — shipped after after/CLTV pass |

## Done prior pass (Taproot hash / preimage script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** bare miniscript hash offline finalize | **Done** (`SIZE 32 EQUALVERIFY <HASHOP> <digest> EQUAL` for sha256/hash256/ripemd160/hash160; matching 32-byte PSBT preimage map only; never invents preimages; corrupt map / wrong length → hard error) |
| Taproot **script-path** and_v(v:pk, hash) offline finalize | **Done** (`<A> CHECKSIGVERIFY` + hash fragment; both matching `tap_script_sig` + preimage required; witness `<preimage> <sigA>`; never invents either) |
| Missing preimage / missing pk sig / wrong map stay Partial | **Done** (honest residual; extract refuses; sibling templates not mis-parsed) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Bare CHECKSIG + multi_a + thresh + and_v + or_i + or_d + and_n + andor + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (older/or_c/ non-s:pk thresh /…) finalize | **Prior residual** — older/CSV done this pass; other still residual |
| bdk electrum/esplora ChainSource | **Still residual** (mempool + mock only) |

## Done prior pass (Taproot thresh script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** bare thresh offline finalize | **Done** (miniscript `thresh(k, pk(A), s:pk(B), …)` = `<A> CHECKSIG (SWAP <B> CHECKSIG ADD)+ <k> EQUAL`; ≥ k matching `tap_script_sigs` in script order; reverse-key witness + empty BIP-342 placeholders for unused keys; **distinct from multi_a** CHECKSIGADD/NUMEQUAL; never invents control block / leaf / sigs) |
| Insufficient thresh threshold / non-template stay Partial | **Done** (honest residual; extract refuses; multi_a sibling not mis-parsed as thresh) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Bare CHECKSIG + multi_a + and_v + or_i + or_d + and_n + andor + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (older/hash/or_c/ non-s:pk thresh /…) finalize | **Prior residual** — hash/preimage done this pass; other still residual |
| bdk electrum/esplora ChainSource | **Still residual** (mempool + mock only) |

## Done prior pass (Taproot andor script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** bare andor offline finalize | **Done** (`andor(pk(A), pk(B), pk(C))` = `<A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF`; AB preferred when both A+B; else C with empty BIP-342 dissatisfaction of A; never invents control block / leaf / sigs / B when only A) |
| Incomplete andor (neither AB nor C completeable) stay Partial | **Done** (honest residual; distinct missing-A / missing-B reasons; extract refuses) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP/ELSE, CLEANSTACK-invalid; not assembled; honest Partial) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Bare CHECKSIG + multi_a + and_v + or_i + or_d + and_n + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (thresh/older/hash/or_c/…) finalize | **Prior residual** — thresh done this pass; other still residual |
| bdk electrum/esplora ChainSource | **Still residual** (mempool + mock only) |

## Done prior pass (Taproot or_d + and_n script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** bare or_d offline finalize | **Done** (`<A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF`; A preferred when both; only-B uses empty BIP-342 dissatisfaction of A; never invents control block / leaf / sigs) |
| Taproot **script-path** bare and_n offline finalize | **Done** (`<A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF`; both sigs required; witness `<sigB> <sigA>`; never invents B-only / empty-A partial path) |
| Bare or_c as top-level leaf | **Still residual** (without IFDUP, A path leaves empty stack → CLEANSTACK fail; not assembled; honest Partial) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Missing both or_d branches / incomplete and_n / non-template stay Partial | **Done** (honest residual; extract refuses) |
| Bare CHECKSIG + multi_a + and_v + or_i + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (thresh/older/hash/or_c/…) finalize | **Prior residual** — andor done this pass; other still residual |

## Done prior pass (Taproot and_v + or_i script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** bare and_v offline finalize | **Done** (`(<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG`, n ≥ 2; all n matching `tap_script_sigs` required; reverse-key witness; never invents control block / leaf / sigs or empty CSV placeholders) |
| Taproot **script-path** bare or_i offline finalize | **Done** (`IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF`; IF/A preferred when both sigs present; ELSE/B when only B; standard OP_IF branch encoding; never invents branch selector without a present sig) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Insufficient and_v / missing both or_i branches / non-template stay Partial | **Done** (honest residual; extract refuses) |
| Bare CHECKSIG + multi_a + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex miniscript (thresh/older/hash/or_c/…) finalize | **Prior residual** — or_d + and_n done this pass; other still residual |

## Done prior pass (Taproot multi_a CHECKSIGADD script-path finalize)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** bare multi_a offline finalize | **Done** (present `tap_scripts` control block + bare `<pk1> CHECKSIG <pk2..n> CHECKSIGADD <k> NUMEQUAL` leaf + ≥ k matching `tap_script_sigs` → witness reverse-key stack + empty BIP-342 placeholders for unused keys; never invents control block / leaf / sigs) |
| Control-block commitment verify against P2TR output | **Unchanged** (fail → hard error / tamper; no silent finalize) |
| Insufficient multi_a threshold / non-template leaves stay Partial | **Done** (honest residual; extract refuses) |
| Bare single-key CHECKSIG + key-path still preferred when material present | **Unchanged** (prior passes) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot other complex / non-multi_a miniscript finalize | **Prior residual** — and_v + or_i done this pass; other still residual |

## Done prior pass (Taproot bare script-path finalize honesty)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **script-path** bare x-only CHECKSIG offline finalize | **Done** (present `tap_scripts` control block + bare leaf + matching `tap_script_sigs` → witness `<sig><script><control block>`; never invents control block / leaf / sig) |
| Control-block commitment verify against P2TR output | **Done** (fail → hard error / tamper; no silent finalize) |
| Non-bare / complex leaves / missing sig or `tap_scripts` stay Partial | **Done** (honest residual; extract refuses) |
| Key-path still preferred when `tap_key_sig` present | **Unchanged** (prior pass) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot complex script-path / miniscript finalize | **Prior residual** — multi_a CHECKSIGADD done this pass; other miniscript still residual |

## Done prior pass (Taproot key-path finalize honesty)

| Item | Status |
|------|--------|
| Stack readiness: CDK mint/spend/refund | **Not ready** (optional `cashu-cdk` empty; no CDK deps; stubs + `mint_live`/`spend_live`/`refund_live` remain false) |
| Stack readiness: LDK BOLT11 pay/invoice | **Not ready** (optional `ldk` empty; no LDK deps; `bolt11_*_live` false; `BOLT12_SUPPORTED=false`) |
| Taproot **key-path** offline finalize | **Done** (P2TR + present `tap_key_sig` → `Witness::p2tr_key_spend`; never invents Schnorr) |
| Missing `tap_key_sig` / ECDSA-only / script-path maps stay Partial | **Done** (honest residual; extract refuses) |
| `tap_internal_key` (+ merkle) mismatch vs P2TR spk | **Done** (hard error / tamper; no silent finalize) |
| Live CDK mint/refund / LDK BOLT11 | **Still residual** (flags remain false; no fake success) |
| Taproot **script-path** / complex miniscript finalize | **Prior residual** — bare CHECKSIG + multi_a done; other still residual |

## Done prior pass (CHECKMULTISIG finalize assembler)

| Item | Status |
|------|--------|
| Bare m-of-n CHECKMULTISIG offline finalize | **Done** (native P2WSH + nested P2SH-P2WSH; BIP147 NULLDUMMY + script-order sigs; never invents missing sigs) |
| Insufficient threshold / wrong keys stay Partial | **Done** (extract rejects; product prepare still refuses Partial) |
| Pre-existing non-empty finals still preserved | **Done** (unchanged) |
| Heavy unit tests (1-of-2, 2-of-3 enough/insufficient, wrong key, nested, non-standard) | **Done** |

## Done prior pass (offline finalize expansion + honesty gates)

| Item | Status |
|------|--------|
| Shared finalize helpers + Complete vs Partial gates | **Done** (`finalize_psbt` / `try_finalize_input` / `input_is_finalized`) |
| Preserve already-present non-empty `final_script_witness` / `final_script_sig` | **Done** |
| Single-key offline finalize: P2WPKH, P2SH-P2WPKH, P2PKH, bare CHECKSIG P2WSH | **Done** (no invented multi-sig stacks) |
| Incomplete multi-sig / CHECKMULTISIG P2WSH stays Partial | **Done** (insufficient threshold; extract rejects; product prepare refuses Partial) |
| Empty witness / empty script_sig never Complete | **Done** |
| Full multi-sig finalize (threshold CHECKMULTISIG assembly) | **Done** (bare template only) |

## Done prior pass (TUI BIP-39 passphrase private re-entry)

| Item | Status |
|------|--------|
| TUI private BIP-39 passphrase modal (`/routstr unlock pass …`) | **Done** (masked input; redacted Debug; never CredentialsStore / watch_session / SeedVault / chat) |
| Env `GROK_BITCOIN_BIP39_PASSPHRASE` path kept additive | **Done** (no `pass` flag → shell loads env; modal explicit overrides for that unlock) |
| Cancel clears secrets; fund/restage supersede modal | **Done** (staged money path kept on cancel; fund cancels modal + pending) |
| Shell TUI reentry accepts optional passphrase override | **Done** (`Some` = modal; `None` = env) |
| Unit tests: parse `pass` flag, Debug redaction, cancel/submit/supersede | **Done** |

## Done prior pass (product BIP-39 passphrase plumb)

| Item | Status |
|------|--------|
| Product BIP-39 passphrase on spend/rbf/cpfp prepares | **Done** (`passphrase: &str` on product prepares; wallet + sign use same value) |
| `Bip39Passphrase` + `GROK_BITCOIN_BIP39_PASSPHRASE` (env at unlock; redacted Debug) | **Done** (never CredentialsStore / watch_session / SeedVault) |
| Shell/CLI/TUI complete paths + fund address derive | **Done** (read env at unlock/sign; not on CLI/TUI arg lines) |
| Offline tests: empty vs non-empty affects addresses + sign | **Done** |
| Full TUI passphrase modal / secret re-entry prompt | **Done** (this pass: `/routstr unlock pass`) |

## Done prior pass (`grok routstr fees` CLI — fee ladder only)

| Item | Status |
|------|--------|
| `grok routstr fees [--network …]` CLI | Done (ladder only; not RBF/CPFP rebuild) |
| Pure `fees_usage_lines` / `format_fees_command_lines` / `fees_unavailable_lines` / `fees_cli_result_lines` | Done |
| Shell `run_routstr_fees` + `resolve_fees_network` + inject-able `fees_command_lines` | Done |
| Live fetch via existing rate-limited mempool `GET /api/v1/fees/recommended` | Done (honest unavailable when offline; never invents rates) |
| Clap `RoutstrCommand::Fees` + pager-bin dispatch | Done |
| Offline unit tests (format/unavailable/usage + clap parse + network reject) | Done |

## Done prior pass (TUI `/routstr cpfp` slash path)

| Item | Status |
|------|--------|
| TUI `/routstr cpfp` slash parse (offline; no fee HTTP) | Done |
| `parse_cpfp_tokens` (address, sats, parent-fee=, parent-vbytes=, parent=, extra-input=, broadcast, fee=) | Done |
| Stage `PendingRoutstrCpfp` + `/routstr unlock` authorize (no BIP-39 on cpfp line) | Done |
| Supersede spend ↔ rbf ↔ cpfp; fund cancels all; agent-bound pending | Done |
| Fee resolve (halfHour) only in effect/spawn_blocking when fee not explicit | Done |
| `complete_routstr_cpfp_reentry_for_tui` + effect/task result wiring | Done |
| Never claim broadcast without Accepted + parseable txid (shared shell path) | Done |
| Child-only product copy (never claims parent replaced) | Done |
| Usage/help lists TUI path (not CLI-only) | Done |
| Unit tests: parse edges (fee=0, missing parents, zero vbytes) + dispatch/unlock supersede | Done |

## Done prior pass (CPFP child PSBT construction + CLI)

| Item | Status |
|------|--------|
| `coin_selection_for_cpfp` (parent + optional extra; dust fold; fee>0) | Done |
| `validate_cpfp_child_fee` (package floor + min-relay; zero sizes rejected) | Done |
| `prepare_cpfp_child` / `prepare_cpfp_child_from_selection` + `CpfpChildSpend` | Done |
| Absolute child fee via `plan_cpfp_child_fee` (package rate ≥ target; re-check actual weight) | Done |
| Parent outputs required; optional confirmed `--extra-input`; never re-selects as RBF | Done |
| Sign/finalize/extract single-key P2WPKH only; Partial honesty unchanged | Done |
| Never claims parent replaced (child-only product copy) | Done |
| `parse_cpfp_child_request` / formatters / `cpfp_usage_lines` | Done |
| CLI `grok routstr cpfp … --parent-fee N --parent-vbytes V --parent … [--extra-input] [--fee-rate] [--broadcast]` | Done |
| Shell `run_routstr_cpfp` / `complete_routstr_cpfp_with_mnemonic` (unlock + re-entry) | Done |
| Dry-run default; full raw hex; broadcast only Accepted + parseable txid | Done |
| Offline unit tests (wallet mocks + parse/format + clap + fee=0 / zero vbytes) | Done |

## Done prior pass (TUI `/routstr rbf` slash path)

| Item | Status |
|------|--------|
| TUI `/routstr rbf` slash parse (offline; no fee HTTP) | Done |
| `parse_rbf_tokens` (address, sats, original-fee=, original-vbytes=, input=, broadcast, fee=) | Done |
| Stage `PendingRoutstrRbf` + `/routstr unlock` authorize (no BIP-39 on rbf line) | Done |
| Supersede spend ↔ rbf; fund cancels both; agent-bound pending | Done |
| Fee resolve (halfHour) only in effect/spawn_blocking when fee not explicit | Done |
| `complete_routstr_rbf_reentry_for_tui` + effect/task result wiring | Done |
| Never claim broadcast without Accepted + parseable txid (shared shell path) | Done |
| Unit tests: parse edges (fee=0, missing inputs, zero vbytes) + dispatch/unlock | Done |

## Done prior pass (RBF replacement PSBT rebuild/broadcast CLI)

| Item | Status |
|------|--------|
| `selection_with_rbf_fee` (same inputs, higher absolute fee, dust fold) | Done |
| `prepare_rbf_replacement_from_selection` (same-size sign/finalize/extract) | Done |
| `prepare_rbf_replacement` + `RbfReplacementSpend` (same-input plan → absolute fee → prepare) | Done |
| BIP-125 absolute + bandwidth fee enforced; never claim broadcast without broadcaster | Done |
| `parse_rbf_replace_request` / `--input` / `RbfReplaceRequest` + product formatters + usage | Done |
| CLI `grok routstr rbf … --original-fee N --original-vbytes V --input … [--fee-rate] [--broadcast]` | Done |
| Shell `run_routstr_rbf` / `complete_routstr_rbf_with_mnemonic` (same-input; unlock + re-entry) | Done |
| Dry-run default; `--broadcast` only after unlock; Accepted + parseable txid only | Done |
| Offline unit tests (wallet mocks + parse/format + clap + BIP-125 underpay guard) | Done |

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

- Shared offline finalizer (`finalize_psbt` / alias `finalize_p2wpkh_psbt`) with
  clear Complete vs Partial gates via `input_is_finalized` /
  `psbt_is_broadcast_ready` (non-empty `final_script_witness` **and/or**
  non-empty `final_script_sig`).
- **Completeable offline (no invention):** already-present non-empty finals
  (preserved); single-key **P2WPKH**; single-key **P2SH-P2WPKH** (redeem_script);
  single-key **P2PKH** → `final_script_sig`; bare single-key **CHECKSIG P2WSH**
  (`witness_script` template only); bare m-of-n **CHECKMULTISIG** P2WSH /
  nested P2SH-P2WSH when ≥ m matching `partial_sigs` exist for script
  pubkeys (assembler builds BIP147 NULLDUMMY + sigs in witness_script
  pubkey order; never invents; foreign partial_sigs ignored); **Taproot
  key-path** P2TR when `tap_key_sig` is already present
  (`Witness::p2tr_key_spend`; never invents Schnorr); **Taproot
  script-path** bare `<x-only pk> OP_CHECKSIG` when present `tap_scripts`
  (control block + leaf) + matching `tap_script_sigs` and control block
  verifies against prevout (never invents control block / leaf / sig);
  **Taproot script-path multi_a** bare
  `<pk1> CHECKSIG <pk2..n> CHECKSIGADD <k> NUMEQUAL` when ≥ k matching
  `tap_script_sigs` exist (first k keys **that already have**
  `tap_script_sigs`, walking script order; earlier unsigned keys and any
  beyond the threshold get empty BIP-342 placeholders only — not invented
  signatures; witness stack reverse key order; control block verified);
  **Taproot script-path thresh** bare
  `<pk1> CHECKSIG (SWAP <pki> CHECKSIG ADD)+ <k> EQUAL` (miniscript
  `thresh(k, pk, s:pk, …)`; distinct from multi_a) when ≥ k matching
  `tap_script_sigs` exist (same reverse-key + empty-placeholder policy);
  **Taproot script-path and_v** bare
  `(<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG` (n ≥ 2) when **all** n matching
  `tap_script_sigs` exist (no empty placeholders — CHECKSIGVERIFY rejects
  empty; reverse-key witness); **Taproot script-path or_i** bare
  `IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF` when a matching sig for A
  and/or B is present (IF/A preferred when both; standard OP_IF branch
  encoding; never invents a branch without a present sig); **Taproot
  script-path or_d** bare
  `<A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF` when a matching sig for A
  and/or B is present (A preferred when both; only-B uses empty BIP-342
  dissatisfaction of A — not an invented Schnorr); **Taproot script-path
  and_n** bare
  `<A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF` when **both** matching
  sigs exist (witness `<sigB> <sigA>`; never invents B-only path — and_n
  short-circuits to 0 when A is false); **Taproot script-path andor** bare
  `<A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF` when A+B are
  present (AB preferred; witness `<sigB> <sigA>`) or C alone (witness
  `<sigC> <empty>` BIP-342 dissatisfaction of A; never invents B when
  only A); **Taproot script-path bare hash** miniscript
  `SIZE 32 EQUALVERIFY HASHOP digest EQUAL` (sha256/hash256/ripemd160/
  hash160) when a matching **32-byte** PSBT preimage is already present
  (never invents preimages; corrupt map / wrong length → hard error);
  **Taproot script-path and_v(v:pk, hash)**
  (`<A> CHECKSIGVERIFY` + hash fragment) when both matching
  `tap_script_sig` and preimage are present (witness `<preimage> <sigA>`);
  **Taproot script-path older/CSV** forms
  (`and_v(v:pk, older(n))` = `<A> CHECKSIGVERIFY <n> CSV`;
  `and_v(v:older(n), pk)` = `<n> CSV VERIFY <A> CHECKSIG`; bare `older(n)` =
  `<n> CSV`) when matching sig (if required) is present **and** the
  unsigned-tx input nSequence already satisfies BIP-112 for `n` (tx version
  ≥ 2; never invents or mutates nSequence/version);
  **Taproot script-path after/CLTV** forms
  (`and_v(v:pk, after(n))` = `<A> CHECKSIGVERIFY <n> CLTV`;
  `and_v(v:after(n), pk)` = `<n> CLTV VERIFY <A> CHECKSIG`; bare `after(n)` =
  `<n> CLTV`) when matching sig (if required) is present **and** the
  unsigned-tx nLockTime already satisfies BIP-65 for `n` with a non-final
  nSequence (never invents or mutates nLockTime/nSequence).
  Optional `tap_internal_key` (+ `tap_merkle_root`) verified against prevout
  P2TR (mismatch → hard error).
- **Still Partial:** *incomplete* CHECKMULTISIG / multi_a / thresh / and_v /
  and_n thresholds / or_i or or_d with neither branch sig / andor with neither
  AB nor C completeable / bare hash missing preimage / and_v(v:pk, hash)
  missing sig or preimage / older/CSV missing sig or nSequence that does not
  satisfy BIP-112 / after/CLTV missing sig or nLockTime/nSequence that does not
  satisfy BIP-65 / wrong keys only (not bare templates when threshold
  is met); Taproot **other complex script-path** / miniscript
  (or_c/ non-s:pk thresh / non-template leaves; bare or_c is not a
  valid top-level CLEANSTACK leaf); non-standard P2WSH script-path; bare legacy
  P2SH multi-sig; missing UTXO/scripts / `tap_key_sig` / incomplete
  script-path maps; unsigned inputs. Never invent missing multi-sig or
  Taproot material.
- Empty witnesses / empty script_sigs are cleared/not counted; extract rejects
  empty or missing finals.
- `prepare_bip84_p2wpkh_spend` requires both complete sign and complete finalize
  (product still refuses Partial before any broadcast claim).
- Pubkey / script template mismatch remains a hard error (tamper/corrupt).

### WatchSession persistence note

- File: `{GROK_HOME}/bitcoin/watch_session.json` (mode 0600, atomic rename).
- Fields: address, network, required_confirmations, watched_txid, confirmations,
  step wire name, generation, running — **never** BIP-39 / seed material.
- Load rejects BIP-39-shaped address/txid strings.
- Pager: persist on start + after each poll; clear on stop / deposit confirmed.
- Resume on session create/load and event_loop startup when agent is active.
- Unit-test builds of the pager skip durable FS (do not pollute developer home).
- Wallet crate tests cover serialize/deserialize + full resume lifecycle.

### RBF + CPFP note (this pass)

- Built PSBT inputs still set `Sequence::ENABLE_RBF_NO_LOCKTIME`.
- Pure planners size same-size RBF replacements and CPFP child fees offline.
- **Shipped RBF:** `grok routstr rbf` **and** TUI `/routstr rbf` rebuild a **same-input**
  BIP-125 replacement from original-fee, original-vbytes, and each
  `input=txid:vout:amount:address` (from prior spend dry-run meta). Plans via
  `plan_rbf_fee_bump`, applies **recommended absolute fee** (not floor-rate
  re-select), signs/finalizes with original prevouts only; dry-run by default;
  `broadcast` only after unlock + re-entry and only claims success on
  broadcaster Accepted + parseable txid.
- **Shipped CPFP:** `grok routstr cpfp` **and** TUI `/routstr cpfp` build a **child**
  that spends wallet-owned parent output(s) (`--parent` / `parent=`) so package
  rate ≥ target via `plan_cpfp_child_fee` absolute child fee. Optional
  `--extra-input` / `extra-input=` confirmed UTXOs when the parent alone cannot
  fund the child fee. Does **not** replace the parent. Dry-run by default; full
  signed hex; broadcast only after unlock + re-entry; success only on Accepted +
  parseable txid. TUI stages `PendingRoutstrCpfp` then `/routstr unlock` (same
  supersede rules as spend/rbf; agent-bound; fee halfHour only in effect worker).
- Library: `coin_selection_for_cpfp` / `prepare_cpfp_child` /
  `prepare_cpfp_child_from_selection` + `validate_cpfp_child_fee` (package floor
  on actual child weight); `parse_cpfp_tokens` for offline TUI parse.
- Spend dry-run meta mentions both RBF and CPFP product paths (CLI + TUI).
- **Shipped fees ladder:** `grok routstr fees [--network …]` prints mempool
  recommended rates only (pure format + live fetch when explorer reachable).
  Never invents a ladder when offline. Not a rebuild path (RBF/CPFP separate).
- **Shipped product BIP-39 passphrase:** product `select_and_prepare_bip84_spend` /
  `prepare_rbf_replacement` / `prepare_cpfp_child` take `passphrase: &str` (same
  contract as `*_from_selection`). Shell/CLI/TUI complete paths + fund address
  derive load `GROK_BITCOIN_BIP39_PASSPHRASE` at unlock/sign via
  `Bip39Passphrase::from_env` (redacted Debug; never CredentialsStore /
  watch_session / SeedVault). Empty/unset = default path.
- **Shipped TUI private passphrase re-entry:** `/routstr unlock pass [pw:…] <phrase>`
  opens a masked modal (process memory only). Empty Enter = explicit default path
  for that unlock; Esc cancels and keeps staged spend/rbf/cpfp. Fund / re-stage
  money paths supersede and drop modal secrets. Modal override does not persist
  and does not write env. Without `pass`, env path unchanged.
- **Shipped CHECKMULTISIG finalize assembler:** bare `OP_m <pks> OP_n
  OP_CHECKMULTISIG` on native P2WSH and nested P2SH-P2WSH assembles
  `final_script_witness` (BIP147 NULLDUMMY + m sigs in witness_script
  pubkey order + script) when ≥ m matching `partial_sigs` for script
  pubkeys are already present (never invents; PSBT fields need not be
  pre-ordered). Insufficient threshold / wrong keys / non-standard scripts
  stay Partial; product prepare still refuses Partial.
- **Shipped Taproot key-path finalize:** P2TR with present `tap_key_sig`
  assembles key-path witness via `Witness::p2tr_key_spend` (never invents
  Schnorr; ECDSA `partial_sigs` alone do not complete P2TR). Optional
  `tap_internal_key` mismatch is a hard error. Key-path preferred when both
  key-path and script-path material exist.
- **Shipped Taproot bare script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare `<x-only pk> OP_CHECKSIG` plus a
  matching `tap_script_sigs` entry assembles
  `final_script_witness = <sig> <script> <control block>` (control block is
  the already-present map key; never invented). Control-block commitment
  must verify against prevout output key (fail → hard error).
- **Shipped Taproot multi_a script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare multi_a
  (`<pk1> CHECKSIG <pk2..n> CHECKSIGADD <k> NUMEQUAL`, k via OP_1..=OP_16,
  n ≥ 2) plus ≥ k matching `tap_script_sigs` assembles reverse-key-order
  witness stack with empty BIP-342 placeholders for unused keys (first k
  keys **that already have** `tap_script_sigs` in script order; never invents
  signatures or control blocks). Insufficient threshold / non-template leaves
  stay Partial.
- **Shipped Taproot and_v script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare and_v
  (`(<pk> CHECKSIGVERIFY)+ <pk> CHECKSIG`, n ≥ 2) plus **all** n matching
  `tap_script_sigs` assembles reverse-key-order witness (no empty
  placeholders — CHECKSIGVERIFY rejects empty; never invents). Missing any
  key stays Partial.
- **Shipped Taproot or_i script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare or_i
  (`IF <A> CHECKSIG ELSE <B> CHECKSIG ENDIF`) plus a matching sig for A
  and/or B assembles `<sig> <0x01|empty> <script> <control block>` (IF/A
  preferred when both; never invents branch selector without a present sig).
- **Shipped Taproot or_d script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare or_d
  (`<A> CHECKSIG IFDUP NOTIF <B> CHECKSIG ENDIF`) plus a matching sig for
  A and/or B assembles `<sigA> <script> <cb>` or
  `<sigB> <empty> <script> <cb>` (A preferred when both; empty = BIP-342
  dissatisfaction of A only — never invents sigs/control blocks). Bare
  or_c (no IFDUP) is **not** assembled (CLEANSTACK-invalid as top-level).
- **Shipped Taproot and_n script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare and_n
  (`<A> CHECKSIG NOTIF 0 ELSE <B> CHECKSIG ENDIF`) plus **both** matching
  `tap_script_sigs` assembles `<sigB> <sigA> <script> <cb>` (never invents
  a B-only path — and_n short-circuits when A is false).
- **Shipped Taproot andor script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare andor
  (`<A> CHECKSIG NOTIF <C> CHECKSIG ELSE <B> CHECKSIG ENDIF` =
  `andor(pk(A), pk(B), pk(C))`) plus A+B (AB preferred) or C alone
  assembles `<sigB> <sigA> <script> <cb>` or
  `<sigC> <empty> <script> <cb>` (empty = BIP-342 dissatisfaction of A;
  never invents B when only A present; A+C without B takes C path).
- **Shipped Taproot thresh script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare thresh-of-pks
  (`<A> CHECKSIG (SWAP <B> CHECKSIG ADD)+ <k> EQUAL` =
  miniscript `thresh(k, pk(A), s:pk(B), …)`) plus ≥ k matching
  `tap_script_sigs` assembles reverse-key-order witness with empty BIP-342
  placeholders for unused keys (first k keys **that already have**
  `tap_script_sigs` in script order; never invents). Distinct from multi_a
  (`CHECKSIGADD`/`NUMEQUAL`). Insufficient threshold / non-template stay Partial.
- **Shipped Taproot hash / preimage script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is bare miniscript hash
  (`SIZE 32 EQUALVERIFY HASHOP digest EQUAL` for sha256/hash256/ripemd160/
  hash160) plus a matching **32-byte** preimage in the corresponding PSBT
  preimage map assembles `<preimage> <script> <control block>` (never
  invents preimages; BIP-174 key consistency + SIZE length enforced;
  corrupt map → hard error). Also **and_v(v:pk, hash)**
  (`<A> CHECKSIGVERIFY` + hash fragment) when both matching `tap_script_sig`
  and preimage are present (`<preimage> <sigA> <script> <cb>`).
- **Shipped Taproot older / CSV script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is
  `and_v(v:pk, older(n))` / `and_v(v:older(n), pk)` / bare `older(n)` plus
  matching `tap_script_sig` (when a key is in the template) **and** an
  already-present unsigned-tx nSequence that satisfies BIP-112 for `n`
  (tx version ≥ 2; height/time type must match; never invents or mutates
  nSequence/version). Witness is `<sig>` or empty script inputs for bare
  older. Disabled / below-required / type-mismatch / v1 → Partial residual.
- **Shipped Taproot after / CLTV script-path finalize:** P2TR with present
  `tap_scripts` entry whose leaf is
  `and_v(v:pk, after(n))` / `and_v(v:after(n), pk)` / bare `after(n)` plus
  matching `tap_script_sig` (when a key is in the template) **and** an
  already-present unsigned-tx nLockTime that satisfies BIP-65 for `n` with
  non-final nSequence (height/time type must match; never invents or mutates
  nLockTime/nSequence). Witness is `<sig>` or empty script inputs for bare
  after. Below-required / type-mismatch / final sequence → Partial residual.
- **Shipped Esplora + Electrum ChainSource:** injectable
  `EsploraChainSource` / `ElectrumChainSource` implementing the shared
  `ChainSource` trait (alongside mock + mempool). Offline pure parsers +
  `MockEsploraTransport` / `MockElectrumTransport` always available with
  `onchain-address`. Live HTTP behind feature `esplora`
  (`HttpEsploraTransport` + rate limiter); live plaintext TCP behind
  feature `electrum` (`TcpElectrumTransport` + `TlsElectrumTransport`
  rustls/WebPKI). Default CI does **not** enable either feature (no forced
  network). Tip-miss policy matches mempool (confirmed → conf=1 depth untrusted).
- **Shipped product ChainSource wire:** `chain_select` pure config +
  feature-honest `open_product_chain_source`; shell
  `complete_routstr_spend_with_mnemonic` uses env selector (default
  mempool). Optional shell features `esplora`/`electrum` not default.
  RBF/CPFP still use explicit prevouts (no chain re-list).
- **Shipped Electrum TLS:** `TlsElectrumTransport` (rustls + WebPKI roots;
  no skip-verify); product `GROK_BITCOIN_ELECTRUM_TLS` + `ssl://host:port`;
  default remains plaintext TCP.
- **Not** shipped: other complex Taproot miniscript (or_c/
  non-s:pk thresh /…); live CDK/LN; full `bdk_wallet` auto-sync engine.

## Residual (next implement)

### P0 / polish
1. Live keyring integration test behind `#[ignore]` + CI secret-service fixture (optional).
2. Optional: emergency mnemonic re-print only if store fails after backup (today: hard error + "do not fund" + keep paper backup).
3. New-wallet TUI still routes to private CLI (`grok routstr fund`) so recovery words never hit chat history. Optional private modal later.
4. Spend path: live UTXO/broadcast require network; dry-run still needs funded wallet UTXOs. Optional offline mock product mode not shipped.

### P1 / product surfaces
1. Wire `topup` / `refund` to **real** CDK/LN when those stacks land: flip `mint_live` / `refund_live` / `bolt11_*_live` only with tested impls; swap `default_*_backend()` factories.
2. Optional: dedicated QR pane widget (today: Unicode QR matrix in system block + clipboard toast).
3. ~~Optional: `grok routstr fees` CLI~~ **Done** (ladder only; RBF is `rbf`, CPFP is `cpfp`).
4. ~~Optional: TUI `/routstr cpfp` slash~~ **Done** (mirror rbf stage/unlock; offline parse; fee resolve in effect).
5. ~~Optional: product BIP-39 **passphrase** plumb through spend/rbf/cpfp~~ **Done** (env + TUI `/routstr unlock pass` modal).

### P2 / spend path + explorers
1. ~~Multi-sig / non-P2WPKH finalize residual honesty~~ **Done** (Partial without invention).
2. ~~Offline finalize expansion (preserve finals + single-key non-P2WPKH)~~ **Done**.
3. ~~Full multi-sig **CHECKMULTISIG** finalize assembler~~ **Done** (bare m-of-n only; never invents; product requires Complete).
4. Optional full `bdk_wallet` auto-sync if still needed beyond injectable mempool/Esplora/Electrum UTXO `ChainSource` (list_unspent backends **Done**).
5. Residual finalize: Taproot **other complex script-path** / miniscript (or_c/ non-s:pk thresh /…) / non-standard script paths still Partial (and_v + or_i + or_d + and_n + andor + thresh + hash/preimage + older/CSV + after/CLTV done).
6. ~~Taproot **key-path** finalize~~ **Done** (`tap_key_sig` → key-path witness).
7. ~~Taproot **bare script-path** finalize~~ **Done** (bare x-only CHECKSIG leaf + present control block + matching `tap_script_sigs`).
8. ~~Taproot **multi_a CHECKSIGADD** script-path finalize~~ **Done** (k-of-n with present sigs + empty placeholders for unused keys).
9. ~~Taproot **and_v CHECKSIGVERIFY** + **or_i IF/ELSE** script-path finalize~~ **Done** (present material only; no invention).
10. ~~Taproot **or_d IFDUP NOTIF** + **and_n NOTIF 0 ELSE** script-path finalize~~ **Done** (present material only; bare or_c still residual).
11. ~~Taproot **andor NOTIF/ELSE** triple CHECKSIG script-path finalize~~ **Done** (AB preferred; C with empty A dissat; no invention).
12. ~~Taproot **thresh** SWAP-CHECKSIG-ADD script-path finalize~~ **Done** (k-of-n s:pk form; distinct from multi_a; present material only).
13. ~~Taproot **hash / preimage** + **and_v(v:pk, hash)** script-path finalize~~ **Done** (PSBT preimage maps only; never invents preimages).
14. ~~Taproot **older / CSV** script-path finalize~~ **Done** (nSequence from unsigned_tx only; never invents locktimes).
15. ~~Taproot **after / CLTV** script-path finalize~~ **Done** (nLockTime from unsigned_tx only; never invents locktimes).
16. ~~Persist WatchSession across pager process restarts~~ **Done**.
17. ~~RBF / CPFP-aware fee estimation~~ **Done** (pure planners + fee ladder + product meta).
18. ~~End-to-end RBF replace-by-fee rebuild~~ **Done** (CLI + TUI slash).
19. ~~Electrum / Esplora push broadcaster alternative~~ **Done** (product-aligned with UTXO chain; mempool default unchanged).
20. ~~CPFP child PSBT construction~~ **Done** (CLI + TUI slash).
21. ~~Esplora + Electrum injectable `ChainSource`~~ **Done** (mock always; live `esplora`/`electrum` features not in default CI).
22. ~~Electrum TLS transport~~ **Done** (`TlsElectrumTransport` + rustls/WebPKI; product TLS env + `ssl://`).
23. ~~Product wire of Esplora/Electrum into shell spend~~ **Done** (`chain_select` + env; default mempool unchanged).

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
Continue Bitcoin-native Routstr from RESIDUAL.md (CDK/LN live backends only when stacks ready).

Already landed (do not regress):
RBF + CPFP (CLI+TUI) + fees + passphrase + offline finalize + bare CHECKMULTISIG
+ Taproot key-path + bare script-path CHECKSIG + multi_a CHECKSIGADD
+ thresh SWAP-CHECKSIG-ADD + and_v CHECKSIGVERIFY + or_i IF/ELSE
+ or_d IFDUP-NOTIF + and_n NOTIF-0 + andor NOTIF-ELSE
+ bare hash preimage + and_v(v:pk, hash)
+ older/CSV + after/CLTV finalize
+ Esplora/Electrum injectable ChainSource (mock always; live features gated)
+ product chain_select wire into shell spend (default mempool; env selectable)
+ Esplora/Electrum push broadcasters + Electrum TLS
+ gap-limit ChainSource UTXO sync
+ product gap-sync spend wire + select-from-snapshot (no extra list)
+ PRODUCT_EXPLICIT_PREVOUT_SIGN_GAP for RBF/CPFP sign
+ hit-max notice on select/prepare Err (GapSyncSpendFailure::AfterSync)
+ product gap-sync UTXO list / balance (`list_bip84_utxos_with_gap_sync`
  + CLI `grok routstr utxos` + TUI `/routstr utxos` staged unlock)
+ bare or_c named residual (or_c + CLEANSTACK; never assemble)
+ product complete-path single-resolve network mapping
  (`resolve_product_complete_network` + `bitcoin_network_to_network` on
  spend/rbf/cpfp/utxos; no dual string parse / silent Mainnet)
+ fund path product-network single-resolve
  (`run_routstr_fund` + `complete_routstr_fund_reentry_for_tui` via
  `resolve_product_entry_network` before unlock; derive via enum map —
  no env-string regtest acceptance on product fund)
+ watch path product-network fail-closed
  (pager `start_routstr_watch*` / resume / persist / poll use product
  acceptance; no raw env wire; no silent Mainnet on regtest/unknown)

Prefer next (when stacks ready; else residual honesty only):
1. Wire topup/refund to real CDK/LN when stacks land; flip capability flags only when live;
   keep stubs honest (`mint_live`/`spend_live`/`refund_live`/`bolt11_*_live` false until ready).
2. Optional: nested CLEANSTACK-valid or_c / non-s:pk thresh only if offline-proved
   (prefer skip over invention); full bdk_wallet sync still residual.
3. Do not claim BOLT12; do not store BIP-39 or passphrase in CredentialsStore or watch_session.json.

Hard gates:
  cargo test -p grok-bitcoin-wallet --lib
  cargo test -p xai-grok-shell --lib openrouter
  cargo test -p xai-grok-shell --lib routstr
  cargo test -p xai-grok-pager --lib credit_bar
  cargo test -p xai-grok-pager --lib routstr
  ./scripts/bitcoin-routstr-validate.sh
```

## Test commands (this pass)

```bash
cargo test -p grok-bitcoin-wallet --lib
cargo test -p xai-grok-shell --lib openrouter
cargo test -p xai-grok-shell --lib routstr
cargo test -p xai-grok-pager --lib routstr
cargo test -p xai-grok-pager --lib credit_bar
./scripts/bitcoin-routstr-validate.sh
# fmt/clippy -D warnings on touched packages
# also: cargo clippy -p grok-bitcoin-wallet --lib --features esplora,electrum -- -D warnings
```

## Validation ran (2026-07-19 residual implement — watch path product-network fail-closed)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Pager watch product-network fail-closed (parity with fund/spend) |
| `cargo fmt` / clippy / hard-gate tests | see implement summary (this pass) |
| Cashu/LN live flags | still false (honest) |
| BOLT12 | still false |
| Product default chain | **mempool** (unchanged) |
| full bdk_wallet sync / nested or_c | still residual |

## Validation ran (2026-07-19 residual implement — fund path product-network single-resolve)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Fund CLI + TUI re-entry product-network single-resolve (fail-closed before unlock) |
| `cargo fmt` / clippy / hard-gate tests | see implement summary (this pass) |
| Cashu/LN live flags | still false (honest) |
| BOLT12 | still false |
| Product default chain | **mempool** (unchanged) |
| full bdk_wallet sync / nested or_c | still residual |

## Validation ran (2026-07-19 residual implement — spend/RBF/CPFP single-resolve network)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Product complete spend/rbf/cpfp single-resolve network mapping |
| `cargo fmt` / clippy / hard-gate tests | see implement summary (this pass) |
| Cashu/LN live flags | still false (honest) |
| BOLT12 | still false |
| Product default chain | **mempool** (unchanged) |
| full bdk_wallet sync / nested or_c | still residual |

## Validation ran (2026-07-19 residual implement — TUI `/routstr utxos` unlock)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | TUI `/routstr utxos` full unlock path (stage + re-entry; observational) |
| `cargo fmt` / clippy / hard-gate tests | see implement summary (this pass) |
| Cashu/LN live flags | still false (honest) |
| BOLT12 | still false |
| Product default chain | **mempool** (unchanged) |
| full bdk_wallet sync / nested or_c | still residual |

## Validation ran (2026-07-19 residual implement — Electrum TLS)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Electrum TLS (`TlsElectrumTransport` + product `GROK_BITCOIN_ELECTRUM_TLS` / `ssl://`) |
| `cargo fmt` / clippy / hard-gate tests | see implement summary (this pass) |
| Cashu/LN live flags | still false (honest) |
| BOLT12 | still false |
| Product default chain | **mempool** (unchanged); electrum default **plaintext** |
| Electrum TLS | **Done** this pass |
| full bdk_wallet sync / bare or_c | still residual |

## Validation ran (2026-07-19 residual implement — product ChainSource wire)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Product wire of Esplora/Electrum injectable `ChainSource` into shell spend via `chain_select` (default mempool; env selectable; feature-honest open) |
| Wallet/shell/pager tests + validate | pass (superseded by Electrum TLS table for latest residual) |
| Cashu/LN live flags | still false (honest) |
| BOLT12 | still false |
| Product default chain | **mempool** (unchanged when env unset) |
| Electrum TLS | **Done** this pass; full bdk_wallet sync / bare or_c still residual |

## Validation ran (prior residual — Esplora + Electrum ChainSource)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Esplora + Electrum injectable `ChainSource` (mock transports + pure parsers offline; live HTTP/TCP feature-gated; no default-CI network) |
| Wallet/shell/pager tests + validate script | pass (superseded by product wire table above for latest residual) |
| Cashu/LN live flags | still false (honest) |
| BOLT12 | still false |
| Esplora/Electrum mock fixtures invent nothing on miss | **honest** (hard error) |
| Product wire of Esplora/Electrum into shell spend | **Done** this pass |
| Taproot other complex miniscript (or_c/ non-s:pk thresh) | still residual |
| Electrum TLS | **Done**; full bdk_wallet sync still residual |

## Validation ran (prior residual — Taproot after/CLTV)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Taproot after/CLTV (`and_v(v:pk, after)` / `and_v(v:after, pk)` / bare `after`) offline finalize (present control block + matching sig when required + **already-present** nLockTime satisfying BIP-65 with non-final nSequence; never invents nLockTime/nSequence/sigs; bare or_c not assembled) |
| Wallet/shell/pager tests + validate script | pass (superseded by Esplora/Electrum table above for latest residual) |
| Taproot after/CLTV assembler | **Done** |
| Taproot other complex miniscript (or_c/ non-s:pk thresh) | still residual |
| bdk electrum/esplora ChainSource | **Done** this pass |

## Validation ran (prior residual — Taproot thresh)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Taproot bare thresh (`CHECKSIG` + `SWAP CHECKSIG ADD`… + `k EQUAL`) offline finalize (present control block + ≥ k matching `tap_script_sigs`; reverse-key + empty placeholders; distinct from multi_a; never invents; bare or_c not assembled) |
| Wallet/shell/pager tests + validate script | pass (superseded by after/CLTV table above for latest residual) |
| Taproot thresh SWAP-CHECKSIG-ADD assembler | **Done** |
| Taproot other complex miniscript (older/hash/or_c/after) | prior residual — after/CLTV done this pass |
| bdk electrum/esplora ChainSource | still residual |

## Validation ran (prior residual — Taproot andor)

| Check | Result |
|-------|--------|
| Primary deliverable | Taproot andor NOTIF-ELSE triple CHECKSIG offline finalize |
| Wallet/shell/pager tests + validate script | pass (superseded by thresh table above for latest residual) |
| Taproot andor NOTIF-ELSE assembler | **Done** |

## Validation ran (prior residual — Taproot or_d + and_n)

| Check | Result |
|-------|--------|
| Stack readiness CDK/LDK | **not ready** — stubs + live flags false; empty feature gates |
| Primary deliverable | Taproot or_d IFDUP-NOTIF dual CHECKSIG + and_n NOTIF-0 dual CHECKSIG offline finalize (present control block + matching `tap_script_sigs` only; never invents; bare or_c not assembled) |
| Wallet/shell/pager tests + validate script | pass (superseded by andor table above for latest residual) |
| Taproot or_d IFDUP-NOTIF assembler | **Done** |
| Taproot and_n NOTIF-0 assembler | **Done** |

## Validation ran (prior residual — Taproot and_v + or_i)

| Check | Result |
|-------|--------|
| Primary deliverable | Taproot and_v CHECKSIGVERIFY n-of-n + or_i IF/ELSE dual CHECKSIG offline finalize |
| Wallet/shell/pager tests + validate script | pass (superseded by or_d/and_n table above for latest residual) |

## Validation ran (prior residual — Taproot multi_a CHECKSIGADD)

| Check | Result |
|-------|--------|
| Primary deliverable | Taproot multi_a CHECKSIGADD k-of-n offline finalize |
| Wallet/shell/pager tests + validate script | pass (superseded by and_v/or_i table above for latest residual) |

## Validation ran (prior residual — Taproot bare script-path finalize)

| Check | Result |
|-------|--------|
| Primary deliverable | Taproot bare script-path offline finalize (x-only CHECKSIG leaf + present control block + matching `tap_script_sigs`) |
| Wallet/shell/pager tests + validate script | pass (superseded by multi_a table above for latest residual) |

## Validation ran (prior residual — Taproot key-path finalize)

| Check | Result |
|-------|--------|
| Primary deliverable | Taproot key-path offline finalize (`tap_key_sig` → p2tr_key_spend) |
| Wallet/shell/pager tests + validate script | pass (superseded by bare script-path table above for latest residual) |

## Validation ran (prior residual — CHECKMULTISIG finalize assembler)

| Check | Result |
|-------|--------|
| Primary deliverable | Bare m-of-n CHECKMULTISIG finalize assembler (P2WSH + nested P2SH-P2WSH) |
| Wallet/shell/pager tests + validate script | pass (superseded by Taproot key-path table above for latest residual) |

## Validation ran (prior residual — offline finalize expansion)

| Check | Result |
|-------|--------|
| Primary deliverable | Offline finalize expansion (shared helpers + single-key completeable cases) |
| Wallet/shell/pager tests + validate script | pass |

## Validation ran (prior residual — product BIP-39 passphrase plumb)

| Check | Result |
|-------|--------|
| Primary deliverable | Product BIP-39 passphrase on spend/rbf/cpfp + fund derive via env + TUI pass modal |
| Wallet/shell/pager tests + validate script | pass |

## Validation ran (prior residual — `grok routstr fees`)

| Check | Result |
|-------|--------|
| Primary deliverable | `grok routstr fees` ladder CLI |
| Wallet/shell/pager tests + validate script | pass |
