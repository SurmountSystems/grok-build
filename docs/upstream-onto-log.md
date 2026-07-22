# Onto-xAI stack log

Record of **Surmount product history stacked on** an xAI export tip so
`git log xai-org/main..<onto tip>` lists our work when GitHub’s compare page
refuses unrelated histories.

Surmount `main` remains the product archive. `onto-xai/*` branches are for
surviving force-exports and contribution-shaped review; they still land on
`main` through normal PRs when appropriate.

| Date (UTC) | xAI tip | xAI tree | Surmount tip stacked | Onto tip | Notes |
|------------|---------|----------|----------------------|----------|-------|
| 2026-07-18 | `98c3b2438aa922fbbe6178a5c0a4c48f85edc8ce` | `b40a1962cb8061b85c2354850ab4d5707f48414b` | (older) | (local) | Prior tip; historical only |
| 2026-07-22 | `3af4d5d39897855bdcc74f23e690024a5dc05573` | `e595174931be9bfb490aacf149e2c9cc0ca0ebba` | product commits via cherry-pick | `0bba0743431c84c23e01dd0369307f8d12ab208a` (branch `onto-xai/3af4d5d39897` before later honesty-pass edits) | Real cherry-pick stack: OpenRouter, branding, rate-limit/import, merge-2 tooling, economic mode / impl. Local uncommitted honesty fixes may sit on top. |

## How the script works (current)

**Real `git cherry-pick -x`.** Not commit-tree reparenting. Not `MODE=overlay`
(removed / never use that flag with the current script).

```bash
git fetch xai-org main --force
./scripts/put-history-on-xai.sh
FORCE=1 SURMOUNT_REF=origin/main ./scripts/put-history-on-xai.sh
```

Default: leave an existing good `onto-xai/<tip>` alone unless `FORCE=1`.

## How to append

```bash
echo "| $(date -u +%Y-%m-%d) | \`<xai-sha>\` | \`<xai-tree>\` | \`<surmount-sha>\` | \`<onto-sha>\` | <notes> |" \
  >> docs/upstream-onto-log.md
```

Full process: [`upstream-history.md`](upstream-history.md).
