# Onto-xAI replay log

Append-only record of **Surmount history replayed onto** an xAI export tip.
Each row is a local (or Surmount-remote) `onto-xai/*` branch whose **parent is
the xAI tip** — so `git log xai-org/main..<onto tip>` shows our work even when
GitHub’s compare page refuses unrelated histories.

Surmount `main` remains the product archive. These branches are for
archaeology, contribution-shaped review, and surviving the next force-export.

| Date (UTC) | xAI tip | xAI tree | Surmount tip | Onto tip | Mode | Notes |
|------------|---------|----------|--------------|----------|------|-------|
| 2026-07-18 | `98c3b2438aa922fbbe6178a5c0a4c48f85edc8ce` | `b40a1962cb8061b85c2354850ab4d5707f48414b` | `744c2dd9929135bb1ec47b0017f40a2860ac7692` | `1fa4faa7169da96379f0f1f202a22139ebc01749` | history | 3 first-parent commits via commit-tree; tip tree == Surmount main |
| 2026-07-18 | `98c3b2438aa922fbbe6178a5c0a4c48f85edc8ce` | `b40a1962cb8061b85c2354850ab4d5707f48414b` | `744c2dd9929135bb1ec47b0017f40a2860ac7692` | `68a053f1ae4325bdf9cc4be9bb8ef4ab97edea95` | overlay | single PR-shaped commit: xAI tree + Surmount seams |

## How to append

```bash
# values printed by scripts/put-history-on-xai.sh
echo "| $(date -u +%Y-%m-%d) | \`<xai-sha>\` | \`<xai-tree>\` | \`<surmount-sha>\` | \`<onto-sha>\` | <mode> | <notes> |" \
  >> docs/upstream-onto-log.md
```

## Rebuild after the next force-export

```bash
git fetch xai-org main --force
./scripts/put-history-on-xai.sh          # history (default); replaces onto-xai/*
MODE=overlay ./scripts/put-history-on-xai.sh
```
