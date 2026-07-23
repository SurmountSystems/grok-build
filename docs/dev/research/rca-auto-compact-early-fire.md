# RCA: Auto-compact fires ~80% while Settings show 98%

**Session under investigation:** `019f8a78-9d7c-7210-af74-b562f0bb56f0`  
**Workspace:** `/home/hunter/Projects/surmount/grok-build`  
**Date of analysis:** 2026-07-22  
**Mode:** read-only investigation (no code changes)

---

## 1. Summary

- Auto-compact **did fire correctly against the live gate** at ~80% of the *effective* context window. The banner percentage is **usage at fire time**, not the Settings threshold.
- Live threshold was **80** because the grok-4.5 catalog/remote model card sets `auto_compact_threshold_percent: 80`, and at session spawn no user session override was resolved into the live `CompactionConfig` cell (or the cell was never re-resolved after disk became 98).
- Settings UI shows **disk** preference (later set to 98%) with `restart_required: true`. Open sessions **do not** re-apply auto-compact threshold from config.toml.
- First compact used window **500_000** (economic cap off for that stretch); later compacts used **200_000** (economic mode on). Residual **~12K/200K** is post-compact remainder, not the fire point.
- This is **not** a broken threshold arithmetic bug. It is a **product mismatch**: catalog 80% vs documented default 95%, plus **settings/live desync** after mid-session edits. Pattern repeats across many other long sessions (80% of 200k).

---

## 2. Timeline / evidence table

### Session `019f8a78-9d7c-7210-af74-b562f0bb56f0` (`updates.jsonl`)

| # | Event | tokens_used / tokens_before | context_window | percentage / after | Meaning |
|---|--------|----------------------------|----------------|--------------------|---------|
| 1 | `auto_compact_started` | 400_918 | **500_000** | **80** | Gate: ≥80% of full catalog window → ~400k |
| 1 | `auto_compact_completed` | 400_918 → **11_587** | — | — | Residual ~12k matches screenshot bar |
| 2 | `auto_compact_started` | 164_907 | **200_000** | **82** | Gate: ≥80% of economic window (~160k); discrete check overshoot |
| 2 | `auto_compact_completed` | 164_907 → 8_740 | — | — | |
| 3 | `auto_compact_started` | 163_580 | **200_000** | **82** | Same 80% threshold on 200k window |
| 3 | `auto_compact_completed` | 163_580 → 10_778 | — | — | |

Timestamps (unix): compact1 `1784743684` → `1784743721` (~37s); compact2 `1784751572` → `1784751605` (~33s); compact3 `1784760797` → `1784760818` (~21s).

### Other sessions (same workspace, same pattern)

Multiple sessions fire near **80% of 200k** with economic window active, e.g.:

| Session (prefix) | tokens_used | window | % |
|------------------|-------------|--------|---|
| `019f7edc…` / `019f7ec7…` | 160_109 | 200_000 | 80 |
| `019f7fab…` / `019f7f9c…` | 160_268 | 200_000 | 80 |
| `019f7e78…` | 160_005 | 200_000 | 80 |
| `019f7f6b…` | 160_358 | 200_000 | 80 |
| `019f7a51…` | 161_224 | 200_000 | 81 |
| `019f7ac1…` | 165_246 | 200_000 | 83 |
| `019f7b3c…` | 163_705 | 200_000 | 82 |

Conclusion: early fire at catalog 80% is **systemic**, not a one-off corruption of this session.

### Config / catalog evidence (verified)

| Source | Value |
|--------|--------|
| `~/.grok/config.toml` `[session].auto_compact_threshold_percent` | **98** (present now; brief notes set later, may post-date spawn) |
| `~/.grok/config.toml` `[ui].economic_mode` | **absent** → product default **on** |
| `crates/codegen/xai-grok-models/default_models.json` grok-4.5 | `"auto_compact_threshold_percent": 80` |
| `~/.grok/models_cache.json` grok-4.5 (origin cli-chat-proxy) | `"auto_compact_threshold_percent": 80` |
| Code constant `DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT` | **95** (only when no env/user/remote tier wins) |
| Settings registry default canonical | **"95"**; choices include 85/90/95/98 + 200k/475k tokens |
| Settings `auto_compact_threshold_percent` | `restart_required: **true**` |
| Settings `economic_mode` | `restart_required: **false**` (live toggle) |

### Gate math (compact 1)

```
exceeds_threshold(400918, 500000, 80)
  ⇔ 400918 * 100 >= 500000 * 80
  ⇔ 40_091_800 >= 40_000_000  → true
usage_percentage_u8(400918, 500000) → 80
```

Banner string: `Context {percentage}% full. Compacting…` where `percentage` is **usage**, not configured threshold.

---

## 3. Causal chain (numbered)

1. **Catalog ships grok-4.5 with `auto_compact_threshold_percent: 80`.**  
   Present in baked `default_models.json` and in remote `models_cache.json` from `cli-chat-proxy.grok.com`.

2. **Resolver precedence (percent path):**  
   `env` → user `[model.<id>]` → user `[session]` → **remote/GB per-model** → remote global → hardcoded **95**.  
   With no user session percent at resolve time, **GB per-model 80 wins**.

3. **Session spawn resolves once** (`resolve_auto_compact_threshold` in `agent_ops` → `CompactionConfig.threshold_percent: Cell::new(...)` in `spawn.rs`).  
   Live gate forever reads that Cell (unless model switch re-resolves).

4. **Pre-sampling check** (`check_auto_compact_needed` → `should_auto_compact` → `exceeds_threshold_resolved`) fires when usage ≥ live threshold % of **effective** sampling `context_window`.

5. **Effective window** depends on economic mode:
   - Off (or uncapped): catalog 500k → fire ~400k at 80%.
   - On (default when `[ui].economic_mode` unset): soft-cap **200k** → fire ~160k at 80%.

6. **This session’s first compact used 500k** → economic soft-cap was **not** applied to the sampling window for that stretch (session Cell off and/or spawn-time economic false; later path shows 200k). Economic can be toggled live (`/economic-mode`, settings `restart_required: false`).

7. **User later set Settings to 98%** → disk + pager snapshot updated; **open session Cell stayed 80** (`restart_required: true`; setter only persists, does not push a session command to update threshold).

8. **UI mismatch:** Settings modal mirrors **disk** (98%). Banner shows **usage** (80–82%). Screenshot bar **12K/200K** is **after** compact. Operator reasonably concludes “98% is broken”; gate actually still runs catalog **80**.

9. Compacts 2–3 continue at ~80% of **200k** (82% reported due to discrete pre-turn checks overshooting 160k).

---

## 4. Root causes ranked

### R1 — Catalog/remote per-model threshold is 80, and it silently beats the “default 95” product story  
**Severity: High (primary product root)**

- Grok 4.5 model card (default_models + remote cache) pins **80%**.
- Hardcoded and Settings defaults advertise **95%**.
- Operators with no user override believe they are on 95; live sessions use **80**.
- **Intentional upstream/catalog product value**, not a fork-only arithmetic regression. Fork ships the same catalog field; Surmount economic mode then makes “80% of 200k” fire even earlier in absolute tokens than “80% of 500k”.

### R2 — Auto-compact threshold is spawn-frozen; Settings mid-session writes do not re-arm the live gate  
**Severity: High (primary UX/root of “I set 98 and it still fired at 80”)**

- Explicit product comment: *“Restart-required: sessions resolve the threshold once at build time.”*
- Persist path updates `config.toml` + pager local mirror only.
- Live `CompactionConfig.threshold_percent` is a `Cell` (can update on model switch) but **settings commit does not update it**.
- Result: disk 98 + live 80 is a designed lag, poorly surfaced as “the product ignored me.”

### R3 — Banner and Settings answer different questions  
**Severity: Medium (contributing UX root)**

- Banner: usage % at fire (`usage_percentage_u8`).
- Settings: disk preference.
- `/context` can show live threshold via `ContextInfo.auto_compact_threshold_percent`; Settings does not.
- When usage ≈ threshold, banner “80% full” looks like “threshold is 80,” which confuses diagnosis.

### R4 — Economic mode window switch (500k ↔ 200k) without linking threshold UX  
**Severity: Medium (contributing)**

- Economic default **on** soft-caps effective window at 200k for bar, gate, and pricing.
- This session still hit 500k once → economic was off for a long stretch, then on (live toggle works).
- Operators see “12K/200K after compact” and “80% full” together and mis-attribute residual bar size as fire point.
- Absolute work lost: 80% of 200k (~160k) is much earlier than 95–98% of 500k (~475–490k).

### R5 — No single “what will fire next” surface in the modal  
**Severity: Low–Medium (contributing)**

- Modal shows preferred threshold, restart pill when expanded, but not **live session threshold** vs **disk**, nor effective window under economic mode on the same row.
- Description text mentions restart and economic 200k, but the row value alone still reads as “current behavior.”

---

## 5. Non-causes (ruled out)

| Hypothesis | Why ruled out |
|------------|----------------|
| Integer gate off-by-one / broken `exceeds_threshold` | Events match exact 80% boundary math; unit tests pin boundary semantics. |
| Banner percentage = configured threshold | Code uses usage %; coincidence when fire is on-threshold. |
| Compact at 12k tokens | 12k is **tokens_after**; before was 400k / 164k / 163k. |
| User 98% applied live then ignored by gate | `restart_required: true`; no live session update path from settings setter. |
| Fork-only invent of 80% | Remote models_cache from xAI proxy also has 80; baked default_models matches. |
| Economic mode alone forcing 80% | Economic only changes **window** (200k vs 500k); percent comes from threshold tiers. |
| Random session corruption | Many sessions show 80% of 200k. |
| Hardcoded 85 intra-compaction policies | Different subsystem (intra step compaction); full-replace auto-compact uses shell `CompactionConfig`. |

---

## 6. Prevention hypotheses (design only — no implementation)

1. **Align catalog with product default**  
   Set grok-4.5 catalog `auto_compact_threshold_percent` to **95** (or remove the field so hardcoded 95 applies), **or** change Settings/docs default copy to “80 for Grok 4.5” so UI matches remote.

2. **Live-apply auto-compact threshold**  
   On Settings commit / config reload, send a session command to update `threshold_percent` / `threshold_tokens` Cells (mirror model-switch path). Drop or narrow `restart_required` if safe.

3. **Settings dual display**  
   Row shows: `Disk: 98% · Live this session: 80% · Effective window: 200k (economic)`. Block the lie that the enum value alone is live behavior.

4. **Banner clarity**  
   e.g. `Context 82% full (auto-compact at 80%). Compacting…` so usage and threshold are distinct.

5. **Spawn-time log / session info**  
   Structured log + `/context` always expose resolved threshold, source tier (catalog vs user), and effective window.

6. **Economic + threshold joint defaults**  
   When economic is on, prefer absolute **200k tokens** threshold option or warn that “98% of 200k” is still only ~196k — price cliff awareness without surprising early summarization relative to full 500k.

7. **Regression tests**  
   - Resolver: grok-4.5 catalog 80 + no user override → 80; + session 98 → 98.  
   - Spawn freeze + settings persist does not change live Cell (document current); after fix, live Cell updates.  
   - Transcript fixture: auto_compact_started percentage ≈ usage, not necessarily settings disk value.

8. **Catalog honesty review**  
   Treat remote 80 as an explicit product decision (earlier compact for long-context cost/quality) and document it in user guide / FORK, not as an invisible override of “default 95.”

---

## 7. Acceptance criteria for “fixed for good”

1. **Predictability:** With only defaults (no user session percent), the Settings default row and the live gate for grok-4.5 **agree** (both 95, or both 80 with copy that says 80).
2. **User override:** Setting 98% (or 200k tokens) either applies to the **open session within one turn**, or the UI **blocks** claiming it applied until restart—and shows live vs disk.
3. **Banner:** Compaction banner does not imply Settings is wrong; usage and threshold are distinguishable.
4. **Economic:** With economic on, bar denominator, gate window, and modal description all show **200k** consistently; toggling economic live updates the gate window without requiring restart.
5. **Evidence tests:** Unit/integration tests cover resolver tier order, spawn seed, settings apply (or restart contract), and a transcript-shaped assertion that 80% catalog fires only when resolved threshold is 80.
6. **Multi-session:** New long sessions under economic + default config either do not fire at 80% (if default becomes 95), or fire at 80% with Settings also showing 80.
7. **No silent dual truth:** `config.toml` 98 + live 80 cannot present as a single “98” in the only user-facing control without a restart/live badge.

---

## 8. File / path index of key code

| Path | Role |
|------|------|
| `crates/codegen/xai-grok-models/default_models.json` | Baked grok-4.5 card: `auto_compact_threshold_percent: 80` |
| `~/.grok/models_cache.json` | Remote mirror of same 80 for grok-4.5 |
| `~/.grok/config.toml` | User disk: session percent 98; no economic key → default on |
| `crates/codegen/xai-grok-shell/src/util/config/resolve/compaction.rs` | `resolve_auto_compact_threshold` / `_percent` / `_from_tiers` precedence |
| `crates/codegen/xai-grok-shell/src/agent/mvp_agent/agent_ops.rs` (~3170) | Spawn-time resolve into percent/tokens for session build |
| `crates/codegen/xai-grok-shell/src/session/acp_session_impl/spawn.rs` (~401–431, ~1441) | Economic cap on sampling window; seed `CompactionConfig` |
| `crates/codegen/xai-grok-shell/src/session/compaction_config.rs` | `threshold_percent` Cell; `economic_mode` Cell; model window tracking |
| `crates/codegen/xai-grok-shell/src/session/compaction.rs` | `should_auto_compact`, `check_auto_compact_needed`, event payload |
| `crates/codegen/xai-token-estimation/src/lib.rs` | `exceeds_threshold`, `exceeds_threshold_resolved`, `usage_percentage_u8` |
| `crates/common/xai-grok-compaction/src/code_compaction/config.rs` | `DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT = 95`; Grok 4.5 token constants |
| `crates/codegen/xai-grok-shell/src/util/config/economic_mode.rs` | Default on; `ECONOMIC_CONTEXT_CAP = 200_000`; apply cap |
| `crates/codegen/xai-grok-shell/src/session/acp_session_impl/slash_exec.rs` | Live economic toggle updates sampling window |
| `crates/codegen/xai-grok-shell/src/session/acp_session_impl/model_switch.rs` | Re-resolve threshold + re-apply economic on model switch |
| `crates/codegen/xai-grok-shell/src/agent/handlers/model_switch.rs` | Computes new threshold for `SetSessionModel` |
| `crates/codegen/xai-grok-shell/src/util/config/settings_writes.rs` | Persist session auto-compact percent/tokens (disk only) |
| `crates/codegen/xai-grok-pager/src/settings/defs.rs` | Setting meta: default 95, **restart_required true**, economic live |
| `crates/codegen/xai-grok-pager/src/settings/registry.rs` | Modal current value from disk/pager snapshot |
| `crates/codegen/xai-grok-pager/src/scrollback/blocks/session_event.rs` | Banner: `Context {percentage}% full. Compacting…` |
| `crates/codegen/xai-grok-shell/src/session/acp_types.rs` | `ContextInfo.auto_compact_threshold_percent` (live resolved) |
| Session transcript | `~/.grok/sessions/%2Fhome%2Fhunter%2FProjects%2Fsurmount%2Fgrok-build/019f8a78-9d7c-7210-af74-b562f0bb56f0/updates.jsonl` |

---

## Proximate vs root vs contributing (explicit)

| Kind | Items |
|------|--------|
| **Proximate** (what fired) | Live `threshold_percent = 80`; `exceeds_threshold` true at ~400k/500k then ~164k/200k; banner shows usage 80–82%. |
| **Root** (why product allowed mismatch) | R1 catalog 80 overrides advertised 95; R2 settings/disk not live for open sessions. |
| **Contributing** | R3 banner vs settings semantics; R4 economic window flip + residual bar; R5 weak dual-state UI; mid-session set of 98 after spawn. |

---

*End of RCA.*
