# Upstream export import log

Append-only record of monorepo exports absorbed into **SurmountSystems/grok-oss**.
Each row is a **reviewed** content import, not a git merge of histories.

| Date (UTC) | xAI commit | xAI tree | Surmount import commit | Notes |
|------------|------------|----------|------------------------|-------|
| 2026-07-15 | `b189869b7755d2b482969acf6c92da3ecfeffd36` | `3dd054cb911a6975e4b414c3d9f72108ed0eeeca` | seed (`b189869` as initial Surmount base) | First public export used as Surmount root; OpenRouter + branding built on top |
| *(pending)* | `c68e39f60462f28d9be5e683d9cbe2c57b1a5027` | `cf33971a730b9c9f29ca743b3c4d76f9e5e7d8c8` | — | Detected 2026-07-16 force-export; **not yet reviewed/imported** — ~158 files under `crates/codegen` |

## How to append

After a successful import PR merges to `main`:

```bash
# values printed by scripts/import-upstream-export.sh
echo "| $(date -u +%Y-%m-%d) | \`<xai-sha>\` | \`<xai-tree>\` | \`<surmount-sha>\` | <notes> |" \
  >> docs/upstream-import-log.md
```
