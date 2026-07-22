# Open residual (human intent and unfinished honesty)

Only **open** items. Finished work lives in [`FORK.md`](FORK.md), process docs,
or code — not only here.

## Open

1. **Formal content import of current xAI tip into Surmount `main`**  
   Tip `3af4d5d…` / tree `e595174…` is logged as *pending* in the import ledger.
   The `onto-xai/3af4d5d39897` stack puts product commits on that tip; that is
   **not** the same as a reviewed import PR into `main`. Decide when to run
   import + PR.

2. **xAI history stability**  
   Unknown whether force-exports continue. Prefer stacking product on their tip
   when they rewrite; do not promise they will stop.

3. **Onto branch vs `main` for the honesty-pass commit**  
   Doc/rules work may sit on the current feature/`onto-xai` branch until a normal
   PR to `main`. No second permanent mainline.

4. **Confidence notes**  
   If a process detail is still fuzzy after reading FORK + upstream-history,
   ask a human rather than inventing policy. Write the answer here only while
   it stays open; then migrate the lasting rule into FORK or AGENTS.

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
