# Git workflow for open PRs (Surmount Grok OSS)

## Rule (non-negotiable)

**On a branch that already exists on `origin` with an open PR or running CI:
merge the base in. Do not rebase. Do not force-push.**

Rebase rewrites commit SHAs. Updating the remote then requires a force-push,
which:

- Confuses CI mid-run (old SHAs vanish; checks look “stuck” or orphaned)
- Makes PR conversation and review diffs harder to follow
- Is unnecessary for catching up with `main`

## Correct: catch up with `main`

```bash
git fetch origin
git checkout feat/your-branch
# If local rebased or diverged by mistake, restore the published tip first:
#   git reset --hard origin/feat/your-branch
git merge origin/main
# resolve conflicts → stage → signed merge commit
git commit -S -m "Merge origin/main into feat/your-branch"
git push origin feat/your-branch   # normal push only
```

During merge conflicts: **HEAD = feature branch**, bottom = `main` (theirs).
Prefer feature for fork-only work (branding, OpenRouter, `grok-rate-limit`,
packaging); combine when both sides change the same logic.

## Wrong: rebase a published PR branch

```bash
# DO NOT do this on an open PR
git rebase origin/main
git push --force-with-lease   # required after rebase; still not okay here
```

## When rebase *is* allowed

Only when the user **explicitly** asks to rewrite history (e.g. private
branch never pushed, or they accept force-push and CI restarts). Agents must
not choose rebase by default.

## Agent rules

| Do | Don’t |
|----|--------|
| `git merge origin/main` into the PR branch | `git rebase origin/main` on a published PR |
| Normal `git push` | `git push --force` / `--force-with-lease` for conflict catch-up |
| Match remote tip if you diverged locally (`reset --hard origin/<branch>`) then merge | Keep a rebased local tip and force-push “to match” |
| Honor `commit.gpgsign` / signed commits | `git -c commit.gpgsign=false commit` |

See also: [upstream-history.md](upstream-history.md) (xAI content import is
separate from PR-vs-`main` integration).
