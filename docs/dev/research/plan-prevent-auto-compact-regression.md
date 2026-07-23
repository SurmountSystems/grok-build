# Plan: prevent auto-compact early-fire regression

**Status:** design only (read-only).  
**RCA file:** `docs/dev/research/rca-auto-compact-early-fire.md` was **missing** at plan time — treat as **RCA incomplete**. Findings below come from confirmed product direction plus code paths listed at the end.

## What goes wrong (short)

Three separate holes stack:

1. **Catalog undercuts the product default.**  
   `DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT` is **95** (compaction crate + resolver + settings UI default).  
   But `crates/codegen/xai-grok-models/default_models.json` ships Grok 4.5 with  
   `"auto_compact_threshold_percent": 80`. That field becomes **GB per-model** on `ModelInfo` and wins over the bare 95 default whenever the user has not set `[session]` / env.

2. **Settings UI can show a value that is not live.**  
   The modal default is **95**; users can pick **98**. Committing only updates AppView + disk and toasts *“restart to apply”* (`restart_required: true`). Open sessions keep the threshold frozen at session build (or last model-switch re-resolve). Model switch already re-resolves and writes `CompactionConfig.threshold_percent` / `threshold_tokens` Cells; settings does not.

3. **Banner % is usage at fire, not the configured threshold.**  
   `should_auto_compact` reports `usage_percentage_u8(used, cw)`. UI shows e.g. `Context 81% full. Compacting…`. Users who believe the threshold is 98% read “81%” as “it fired too early,” even when the live gate was 80%.

**Economic mode multiplies the pain:** default on soft-caps effective context at **200k**, so live **80% ≈ 160k** tokens. Docs/UI that talk about 95% of 200k (≈190k) or 98% never match that gate.

`/context` already shows the **live** session threshold (`ContextInfo.auto_compact_threshold_percent` from `compaction.threshold_percent`). That is honest once the session value is correct; the modal and banner are the confusing surfaces.

---

## Goals

- Default path (no user TOML, stock Grok 4.5 catalog) auto-compacts at **95% of the effective window**, matching product narrative, settings default, and `DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT`.
- User-chosen percent/tokens either **apply to open sessions** or are **clearly labeled as disk-only** with a visible live value.
- Compaction banner and `/context` never imply the wrong threshold.
- **Regression tests fail** if the embedded catalog silently reintroduces a per-model percent below the product default without an intentional, documented tier.
- Changes stay surgical; reuse model-switch re-resolve and economic-mode live-toggle patterns.

## Non-goals

- Changing the 6-tier resolver order (env > user per-model > user session > GB per-model > GB global > default).
- Removing remote/fleet ability to set a real GB per-model threshold (e.g. grok-build at 65%) once intentional.
- Redesigning economic mode pricing policy.
- Full settings-system redesign or bulk renames of `auto_compact_threshold_percent` config keys.
- Implementing in this pass (plan only).

---

## Root-cause map (code)

| Hole | Mechanism | Key sites |
|------|-----------|-----------|
| Silent 80% | `default_models.json` → `default_models()` → `ModelInfo.auto_compact_threshold_percent` → resolver tier “GB per-model” | `xai-grok-models/default_models.json`, `agent/config.rs` `default_models` / `ModelInfo::from_config`, `resolve/compaction.rs` |
| Live freeze | Threshold resolved at session spawn; only model-switch re-applies | `mvp_agent/agent_ops.rs` spawn, `handlers/model_switch.rs`, `session/acp_session_impl/model_switch.rs` Cells |
| Settings disk ≠ live | `set_auto_compact_threshold` mutates AppView + `PersistSetting`; toast restart; `restart_required: true` | `pager/.../setters.rs`, `settings/defs.rs` |
| Banner honesty | `AutoCompactTriggerInfo.percentage` = usage, not threshold | `session/compaction.rs` `should_auto_compact`, pager `session_event.rs` / headless |
| Economic amp | `economic_mode` Cell + `apply_economic_context_cap` → 200k effective window | `compaction_config.rs`, slash `/economic-mode` |

Gate math (already correct once threshold/window are right):

- `xai_token_estimation::exceeds_threshold_resolved(used, cw, threshold_percent, threshold_tokens)`
- Percent: `used * 100 >= cw * threshold_percent`

---

## Ranked fix options

### Option A — Catalog honesty (minimum fix)

**Change:** Remove `auto_compact_threshold_percent: 80` from Grok 4.5 in `default_models.json` (prefer **omit field** so it is `None` and falls through to default 95). Do **not** leave a deliberate undercut.

| Pros | Cons |
|------|------|
| One-line product fix; matches all narrative defaults | Alone: users who already changed settings mid-session still need restart |
| Smallest blast radius | Remote GB can still set per-model % intentionally |
| Unlocks green regression tests immediately | |

**Verdict:** **Required.** Without this, any “default is 95%” story is false for stock Grok 4.5.

### Option B — Live apply threshold (settings → open session)

**Change:** When settings commit auto-compact, push into open sessions the same way model-switch updates Cells:

- Add `SessionCommand::SetAutoCompactThreshold { percent: u8, tokens: Option<u64> }` (or factor shared helper used by model-switch).
- Wire pager → shell: either ACP ext method, or session-scoped slash (mirror `/economic-mode` → `BuiltinAction`) queued from the setter.
- Set `restart_required: false`; toast without “restart to apply”.
- Re-resolve from full config when possible so env/per-model still win; if commit is user session value, apply that preference for the active model.

| Pros | Cons |
|------|------|
| Closes disk/live split that confuses users | More plumbing than A |
| Reuses existing `Cell` pattern | Pager has no direct `cmd_tx`; need slash/ACP bridge |
| Aligns with economic-mode *session* live toggle | Multi-agent / leader sessions need care |

**Verdict:** **Strongly recommended** as second slice (or same PR if kept thin).  
Note: settings **economic_mode** today only updates disk/cache for *new* sessions; live toggle is `/economic-mode`. Prefer **better** than that for auto-compact: settings commit should hit the open session.

### Option C — UX honesty without live apply

**Change (can ship with A even if B waits):**

- Banner: include configured threshold, e.g.  
  `Context 81% full (auto-compact at 80%). Compacting…`
- Settings description: state that modal shows **saved preference**; open sessions use value resolved at start / model switch until restart (if B not done).
- Optional modal subline: “Live for this session: N%” from last `/context` or session info (only if cheap).
- Fix stale comments that still say default **85** (`ContextInfo` docs, serde default comment).

| Pros | Cons |
|------|------|
| Low risk; clarifies the 81% vs 98% confusion | Does not stop early fire if catalog stays 80 |
| Complements A/B | Extra string churn in tests |

**Verdict:** **Recommended** with A; keep if B ships (still useful when remote sets a non-default threshold).

### Option D — Demote catalog/GB per-model below product default

**Change:** Resolver treats “absent user intent” as always 95 even when catalog sets 80 (ignore GB per-model unless remote feature flag / explicit opt-in).

| Pros | Cons |
|------|------|
| Harder to re-break via JSON | Breaks intentional fleet per-model thresholds |
| | Larger semantic change; more tests |

**Verdict:** **Not recommended.** Fix the catalog value; keep the tier for real remote control.

### Option E — Raise approaching-tip band / special-case economic

**Change:** Heuristics only (e.g. tip band starts at threshold−15 instead of hard 80).

| Pros | Cons |
|------|------|
| Small | Does not fix wrong gate |

**Verdict:** Optional polish only after A.

---

## Recommended package (ordered slices)

Prefer **one PR** if review stays tight; else two sequential PRs.

### Slice 1 — Correctness + regression lock (must ship)

1. **Catalog:** omit `auto_compact_threshold_percent` on Grok 4.5 in `default_models.json` (or set explicitly to **95** if omit is awkward for codegen/docs).  
   Prefer omit so “no special model policy” is obvious.
2. **Guard tests** (see below) so a future re-import of upstream catalog with 80 fails CI.
3. **Banner honesty** (Option C): show configured threshold next to usage %.
4. **Docs:** `FORK.md` short note; user-guide `05-configuration.md` already documents 95 / economic 200k — add one sentence that the **catalog must not undercut** the session default, and that mid-session changes need restart **or** live apply (update after Slice 2).
5. Stale comment cleanup: ContextInfo “default 85” → 95.

**Acceptance:** fresh session, no user `[session].auto_compact_*`, economic on → gate at **95% of 200k ≈ 190k**. Banner mentions threshold 95 when it fires near that.

### Slice 2 — Live apply (recommended follow-through)

1. Shell: `SessionCommand` (or slash builtin) that sets `threshold_percent` / `threshold_tokens` Cells only (no model rebuild).
2. Pager: settings setter after successful persist also notifies open session(s) (slash queue is the smallest mirror of `/economic-mode`).
3. `restart_required: false` + toast/description updates; settings_e2e asserts flip.
4. Optional: when live value ≠ disk (leader race, failure), show warning toast.

**Acceptance:** set 98% in settings mid-session → next `should_auto_compact` uses 98% (or tokens mode); `/context` line matches; no restart.

### Slice 3 — Optional polish

- Approaching tip band relative to live threshold (not hard-coded 80).
- Settings row subtitle “Effective now: …” from session snapshot if already available without new RPC.

---

## Tests (red → green)

Concrete names and asserts. Prefer unit/integration near existing modules.

### Catalog / product contract

| Test | Location (suggested) | Assert |
|------|----------------------|--------|
| `default_models_grok_45_does_not_undercut_auto_compact_default` | `xai-grok-shell` config tests near `default_models` | Parse embedded `DEFAULT_MODELS_JSON`; for `id == "grok-4.5"`, `auto_compact_threshold_percent` is `None` **or** `Some(p)` with `p >= DEFAULT_AUTO_COMPACT_THRESHOLD_PERCENT` (95). **Fails red today** on 80. |
| `default_is_95_percent` (existing) | `resolve/compaction.rs` | Keep; still 95 when all tiers unset. |
| `stock_grok_45_model_info_resolves_to_default_95` | shell resolve tests | `Config::default()` + `ModelInfo` built from real default_models entry for grok-4.5 → `resolve_auto_compact_threshold_percent(...) == 95`. **Red today** (returns 80). |
| `user_session_98_beats_catalog_even_if_catalog_80` | keep / extend persist matrix | user_session 98 + gb_per_model 80 → 98 (already true; pin against reorder). |

### Gate math (economic window)

| Test | Location | Assert |
|------|----------|--------|
| `economic_200k_at_95_percent_fires_at_190k` | `xai-token-estimation` or shell compaction tests | `!exceeds_threshold(189_999, 200_000, 95)` and `exceeds_threshold(190_000, 200_000, 95)`. |
| `economic_200k_at_80_percent_fires_at_160k` | same | Documents *old* bug behavior; can live as historical comment or negative regression only if catalog still had 80. After Slice 1, stock path must not use 80. |
| `exceeds_threshold_resolved_tokens_mode_uncapped` | existing patterns | tokens 200_000 wins over percent when set. |

### Session apply

| Test | Location | Assert |
|------|----------|--------|
| `handle_set_session_model_updates_threshold_cells` | shell model_switch tests | After command, `threshold_percent.get()` / `threshold_tokens.get()` match payload (partially covered; tighten). |
| `set_auto_compact_threshold_command_updates_gate` (Slice 2) | shell session tests | New command/slash changes Cells; `should_auto_compact` flips at new boundary without model switch. |
| `auto_compact_threshold_restart_required_false` (Slice 2) | `settings_e2e.rs` | Flip current assert that requires `restart_required: true` (lines ~7683–7686). |
| `set_auto_compact_threshold_toast_no_restart` (Slice 2) | dispatch settings tests | Toast does not say “restart to apply”. |

### Banner / context honesty

| Test | Location | Assert |
|------|----------|--------|
| `compaction_started_banner_includes_threshold` | pager `session_event` tests | Format includes both usage % and threshold % (or absolute tokens). |
| `context_info_auto_compact_line_uses_snapshot_threshold` | existing `context_info` tests (~95%) | Keep; add case with threshold **80** still displays “Auto-compact at 80%” (live honesty). |
| settings default remains `"95"` | `settings_e2e` `auto_compact_threshold_renders_under_session...` | Keep. |

### Import / merge guard

| Test | Location | Assert |
|------|----------|--------|
| Same catalog test as above runs in `just check` quality suite | no separate CI job | Prevents silent reintroduction of 80 on upstream merge of `default_models.json`. |

**Red today (Slice 1):** catalog undercut tests.  
**Green after Slice 1:** stock resolve 95; banner optionally still needs string update tests.  
**Red until Slice 2:** live-apply and `restart_required: false` tests.

---

## Implementation notes (for implementer)

### Catalog

```json
// default_models.json — remove this line on grok-4.5:
// "auto_compact_threshold_percent": 80,
```

If product ever wants a **model-specific** earlier compact, document it in FORK and set an **explicit** value with a test that allows that id only — never a silent lower default.

### Live apply (Slice 2 sketch)

Reuse:

```text
model_switch: resolve_auto_compact_threshold(cfg, model_id, model)
  → SessionCommand::SetSessionModel { auto_compact_threshold_percent, auto_compact_threshold_tokens }
  → handle_set_session_model sets Cells

economic-mode: BuiltinAction flips economic_mode Cell + sampling context_window
```

Minimal path:

1. Factor `apply_auto_compact_threshold(actor, percent, tokens)` from model_switch handler.
2. `SessionCommand::SetAutoCompactThreshold { percent, tokens }` → that helper.
3. Slash e.g. `/auto-compact 98` | `200k` | `status` → same helper (+ optional persist).
4. Settings setter: after AppView update, `CommandResult::QueueCommand` or ACP notify so the **active** session updates; still `PersistSetting` for disk.

Precedence on live push: prefer **re-resolve from Config** after disk write so env still wins; if re-resolve races disk, apply the committed enum value for user session scope (document choice in code comment).

### Banner

Today:

```text
Context {percentage}% full. Compacting…
```

Proposed:

```text
Context {usage}% full (auto-compact at {threshold}%). Compacting…
```

or for tokens mode:

```text
Context {used}/{threshold_tokens} tokens. Compacting…
```

Requires plumbing threshold into `AutoCompactTriggerInfo` / `XaiUpdate::AutoCompactStarted` if not already present — check notification payload before inventing fields; may only need to pass `compaction.threshold_percent.get()` at emit site.

### Docs

- `FORK.md` — one hierarchical bullet under Product: auto-compact default 95%; catalog must not undercut; economic window + optional live apply.
- `crates/codegen/xai-grok-pager/docs/user-guide/05-configuration.md` — adjust “restart required” when Slice 2 lands; mention banner shows usage and threshold.
- Do **not** invent new residual noise; if something stays open, one line in `RESIDUAL.md`.

---

## Rollout / user-facing notes

**Before fix (user-visible):**  
“I set 98% / UI says 95%, but it compacted around 80% / ~160k with economic mode.”

**After Slice 1:**  
New sessions compact near **95% of effective window** (~190k with economic on). Users with **explicit** lower remote/GB per-model still get that value. Users who only changed settings mid-session still need restart until Slice 2.

**After Slice 2:**  
Settings change applies to the open conversation; no restart toast.

**Migration:**  
No config migration. Users who wrote `auto_compact_threshold_percent = 98` already win over catalog once a session is (re)built. Omitting catalog 80 only affects users with **no** user-tier override.

**Upstream merge risk:**  
xAI catalog may reintroduce 80. Guard test is the hard stop; on merge conflict prefer Surmount omit/95 + keep test.

**Telemetry:**  
Optional log field `auto_compact_threshold_percent` on fire events (if not already) for field confirmation; not required for prevention.

---

## Risks and open questions

| Risk | Mitigation |
|------|------------|
| RCA incomplete (file missing) | Reconcile this plan with RCA when written; do not block Slice 1 catalog fix |
| Intentional 80 for model-card product reason | If found in RCA, document in FORK and change tests to allow 80 **only** with matching UI default — do not leave UI at 95 |
| Leader multi-session apply | Apply to session that owns the settings change; document others still restart |
| Tokens mode display | Banner and settings already dual-mode; keep both in honesty strings |
| Hard-coded tip band 80 in context_info | Harmless when threshold is 95; empty gap if threshold were 80 — Slice 3 |

---

## Suggested sequencing for implementer

1. Land catalog omit + failing-then-green guard tests.  
2. Banner threshold in same PR if small.  
3. Live apply + settings `restart_required` flip.  
4. FORK + user-guide.  
5. `just check` / focused crate tests.

---

## Critical code pointers

- `crates/codegen/xai-grok-models/default_models.json` — catalog 80 undercut  
- `crates/codegen/xai-grok-shell/src/util/config/resolve/compaction.rs` — 6-tier resolve + default 95  
- `crates/codegen/xai-grok-shell/src/session/compaction.rs` — `should_auto_compact`  
- `crates/codegen/xai-grok-shell/src/session/compaction_config.rs` — threshold Cells, economic_mode  
- `crates/codegen/xai-grok-shell/src/agent/handlers/model_switch.rs` — re-resolve pattern  
- `crates/codegen/xai-grok-shell/src/session/acp_session_impl/model_switch.rs` — Cell apply  
- `crates/codegen/xai-grok-pager/src/settings/defs.rs` — setting meta / restart_required  
- `crates/codegen/xai-grok-pager/src/app/dispatch/settings/setters.rs` — disk-only commit  
- `crates/codegen/xai-grok-pager/src/scrollback/blocks/session_event.rs` — banner text  
- `crates/codegen/xai-token-estimation/src/lib.rs` — `exceeds_threshold_resolved`  
- `crates/common/xai-grok-compaction/src/code_compaction/config.rs` — DEFAULT 95, Grok 4.5 card constants  
- `crates/codegen/xai-grok-pager/docs/user-guide/05-configuration.md` — user docs  
- `FORK.md` — fork product checklist  
