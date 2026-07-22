# Canonical history and xAI monorepo exports

## Principle

**Surmount `main` is the continuous product history** (Grok Build tree plus
fork features). [xai-org/grok-build](https://github.com/xai-org/grok-build) is a
**series of published snapshots** — a content feed, not a history we must share
commit hashes with.

GitHub may say the histories are “entirely different.” **Expected.** There is
often **no merge-base**. Do not “Sync fork” or reset Surmount `main` to theirs.

## How xAI publishes (observed)

| Behavior | Notes |
|----------|--------|
| Bot author | `grokkybara[bot]` |
| Messages | e.g. `Publish harness…`, `Synced from monorepo` |
| Shape | Often an **orphan** force-push root; sometimes a **short bot chain** |
| Updates | Force-push replaces the tip; package versions may not bump |

We absorb **trees** (`git rev-parse <export>^{tree}`), not their parent graph.
Whether they stop rewriting history is **unknown** — do not promise stability.

## Two directions

| Job | Script | Branch | When |
|-----|--------|--------|------|
| **Their tree → Surmount** | `scripts/import-upstream-export.sh` | `import/*` | Product archive on Surmount `main` after review |
| **Our commits → their tip** | `scripts/put-history-on-xai.sh` | `onto-xai/<short>` | Preferred when histories break: one branch that is a **descendant of their tip** and carries Grok OSS |

```
xai-org/main  (force-pushed snapshots)
      │
      ├── import/*     ← their tree into Surmount base + fork paths
      │
      └── onto-xai/*   ← real cherry-pick of Surmount product commits onto their tip
```

**Preferred HITL when they rewrite history:** put **our product work on their
current tip** (put-history). Import remains the way to record a reviewed
content absorption into Surmount’s archive.

Tool branches still land on **`main` through normal PRs** (feature-branch git flow).

Detect: `./scripts/detect-upstream-export.sh` or `just upstream-detect`.

## Put history on their tip (cherry-pick)

`scripts/put-history-on-xai.sh` runs **real `git cherry-pick -x`** of Surmount
product commits (after the seed) onto the current `xai-org/main` tip.

There is **no** `MODE=overlay` / commit-tree mode in the current script. Older
docs that mentioned those modes are obsolete.

```bash
git fetch xai-org main --force
# clean worktree preferred
./scripts/put-history-on-xai.sh
# FORCE=1 SURMOUNT_REF=origin/main ./scripts/put-history-on-xai.sh   # rebuild

# on conflict:
git add -u
git cherry-pick --continue    # signed on a real TTY when commit.gpgsign=true
CONTINUE=1 ./scripts/put-history-on-xai.sh
```

Does not push. Does not rewrite Surmount `main`. Does not touch xAI (pull-only).

## Import their tree into Surmount

```bash
./scripts/import-upstream-export.sh           # stages import/* from origin/main
./scripts/import-upstream-export.sh --stay
```

Uses `git read-tree` of the xAI tree, restores fork-only paths, then a **signed**
content-import commit (or leaves staged for a human TTY). Re-apply OpenRouter,
branding, rate-limit seams; run `just check`; append the import log; PR to `main`.

## Never do

| Don’t | Do |
|-------|-----|
| `git merge xai-org/main` with no merge-base | Content import or put-history |
| GitHub Sync fork that drops Surmount | Branch from Surmount `main` |
| Blind `reset --hard` to export | Review + re-apply seams |
| Disable GPG for import/onto commits | Human signs on a real TTY |
| Reset Surmount `main` to an onto-xai tip “to match” them | Keep archive history |

## Signed commits

Agents do not bypass GPG. Prefer multi `-m` flags (not heredocs) for commands
handed to humans. See project `AGENTS.md` and global GPG rules.

## Logs

| File | Meaning |
|------|---------|
| [`upstream-import-log.md`](upstream-import-log.md) | Reviewed trees absorbed into Surmount |
| [`upstream-onto-log.md`](upstream-onto-log.md) | Stacks parented at an xAI tip |

## Related

- Product divergences: [`FORK.md`](../FORK.md)
- Open PR workflow: [`git-workflow.md`](git-workflow.md)
