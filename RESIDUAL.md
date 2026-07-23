# Open residual (human intent and unfinished honesty)

Only **open** items. Finished work lives in [`FORK.md`](FORK.md), process docs,
or code — not only here.

## Open

1. **Formal content import of current xAI tip into Surmount `main`**  
   Tip `3af4d5d…` / tree `e595174…` is logged as *pending* in the import ledger.
   The `onto-xai/3af4d5d39897` stack + **join-main** (`-s ours`) is the landable
   product path (PR onto → `main`). That is **not** the same as a reviewed
   import-ledger absorption under Surmount-first parents. Decide when import
   still needs its own PR/log row.

2. **xAI history stability**  
   Unknown whether force-exports continue. Prefer stacking product on their tip
   when they rewrite; do not promise they will stop.

3. **Finish join + PR for current onto tip**  
   Merge of `main` into onto is staged or about to be signed; docs/script for
   the workflow land in a follow-up commit; then push and open PR to `main`.

4. **Confidence notes**  
   If a process detail is still fuzzy after reading FORK + upstream-history,
   ask a human rather than inventing policy. Write the answer here only while
   it stays open; then migrate the lasting rule into FORK or AGENTS.

5. **Live-apply auto-compact threshold (settings → open session)**  
   Settings still mark `auto_compact_threshold_percent` as restart-required:
   open sessions keep the threshold resolved at spawn / last model switch.
   Slice 1 fixed catalog undercut + banner honesty; live Cell update on
   settings commit (mirror model-switch / economic-mode patterns,
   `restart_required: false`) is still open.

## Not residual (resolved elsewhere)

- CI checks-only (no release package in GHA) — FORK + justfile + AGENTS  
- `just check` ≡ `just ci` — justfile  
- put-history is cherry-pick — upstream-history + onto log  
- Auto-implement **appends** after existing local queue — `auto_implement.rs` + FORK  
- GPG / no bulk replace / no agent commit defaults — AGENTS.md  

## Local quality before push

```bash
just check    # or just ci
```
