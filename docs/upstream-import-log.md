# Upstream export import log

Append-only record of monorepo exports absorbed into **SurmountSystems/grok-oss**
as **reviewed content** on Surmount history (not a git merge of xAI parents).

| Date (UTC) | xAI commit | xAI tree | Surmount import commit | Notes |
|------------|------------|----------|------------------------|-------|
| 2026-07-15 | `b189869b7755d2b482969acf6c92da3ecfeffd36` | `3dd054cb911a6975e4b414c3d9f72108ed0eeeca` | seed (`b189869` as initial Surmount base) | First public export used as Surmount root; OpenRouter + branding built on top |
| *(pending)* | `c68e39f60462f28d9be5e683d9cbe2c57b1a5027` | `cf33971a730b9c9f29ca743b3c4d76f9e5e7d8c8` | — | Older force-export; **superseded** by tip below for absorb purposes |
| *(pending)* | `3af4d5d39897855bdcc74f23e690024a5dc05573` | `e595174931be9bfb490aacf149e2c9cc0ca0ebba` | — | Tip as of 2026-07-22 (`Synced from monorepo` chain). **Not** a completed Surmount `import/*` PR yet. Product-on-tip work may live on `onto-xai/3af4d5d39897` (see onto log) — that is **not** the same as a content import into Surmount `main`. |

## How to append

After a successful import PR merges to `main`:

```bash
echo "| $(date -u +%Y-%m-%d) | \`<xai-sha>\` | \`<xai-tree>\` | \`<surmount-sha>\` | <notes> |" \
  >> docs/upstream-import-log.md
```

Mark older *(pending)* rows resolved or superseded in the Notes column when you land a newer tip.

## Detect / import

```bash
./scripts/detect-upstream-export.sh    # exit 2 = new export vs last completed row
./scripts/import-upstream-export.sh
```

Process: [`upstream-history.md`](upstream-history.md). Signed commits only.
