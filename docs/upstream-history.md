# Canonical history & xAI monorepo exports

## Principle

**SurmountSystems/grok-oss is the complete, continuous git history** of the
open-source Grok Build tree **plus** fork features.

[xai-org/grok-build](https://github.com/xai-org/grok-build) is treated as a
**series of published snapshots**, not as a linear history we must share
commit hashes with.

## How xAI publishes (observed)

| Behavior | Evidence |
|----------|----------|
| Bot author | `grokkybara[bot]` |
| Message | `Publish harness and TUI open-source` / `initial sync from the monorepo` |
| Shape | **`main` is a single orphan commit** (no parents) |
| Updates | **Force-push a new root** with a new tree; previous export is replaced |
| Tags / GH Releases | Often none on that repo |
| Package versions | May stay at the same `CARGO_PKG_VERSION` while the tree still changes |

GitHub’s “entirely different commit histories” compare is **expected** after
each force-export. It is **not** a Surmount mistake.

## What we never do

| Anti-pattern | Why |
|--------------|-----|
| `git merge xai-org/main` when there is no merge-base | Creates nonsense history or fails |
| GitHub **Sync fork** that resets to upstream | Drops Surmount history and review trail |
| Blind `git reset --hard` to the new export | Loses OpenRouter, branding, rate-limit, etc. |
| “Lazy” bulk accept without reading the delta | Violates **review every contribution** |
| Rewriting Surmount `main` to match xAI SHAs | We are the archive; they are the feed |

## What we always do

1. **Preserve** Surmount history (tags, notes, PR commits).
2. **Detect** a new export (new tip SHA / tree on `xai-org/main`).
3. **Diff** against the **last imported tree**, not against git ancestry.
4. **Review** the delta (human and/or agent skill) file-by-file / area-by-area.
5. **Import** as a **normal commit on Surmount `main`** whose **tree** matches
   the export’s upstream-owned paths, while **keeping** fork-only paths.
6. **Record** the import in `docs/upstream-import-log.md` (SHA, tree, date).
7. **Re-apply / verify** fork seams (branding, OpenRouter, `grok-rate-limit`, …).

Result: `git log` on Surmount stays linear and meaningful. Each upstream
snapshot appears as one or more **reviewed** commits (“Import xAI export
`<shortsha>` …”), not as a disconnected root.

## Mental model

```
xai-org/main (force-push snapshots)
    │  export tree T0     export tree T1     export tree T2
    │       │                  │                  │
    │       ▼                  ▼                  ▼
    │   [orphan]            [orphan]           [orphan]
    │
    │   content-only diffs (git diff T0 T1) — no shared parents
    │
Surmount main (canonical continuous history)
    A──B──C──D──E──F──G──…
              ▲     ▲
              │     └── Import export T1 (reviewed)
              └── Import export T0 (or initial seed)
    + fork commits (OpenRouter, branding, rate-limit, …) interleaved / on top
```

Git may never see a merge-base with `xai-org/main`. **That is fine.** We use
**tree identity** (`git rev-parse <export>^{tree}`) as the upstream pin.

## Put Surmount history on their tip (`put-history-on-xai`)

**This is the script for “our history on theirs”.** Import (below) is the
*opposite* direction (their tree into Surmount).

After each export, rebuild a branch **parented at their tip** that carries
Surmount’s product narrative. When they force-break history again, re-run —
nothing depends on a stable xAI parent chain.

```
xai-org/main @ T2  (orphan / re-rooted tip)
        │
        ├── onto-xai/<short>  (MODE=history)     ← put-history-on-xai.sh
        │     Surmount first-parent commits stacked via commit-tree
        │     final tree == Surmount main; parents start at T2
        │
        └── onto-xai/<short>  (MODE=overlay)
              single commit: T2 tree + Surmount fork/product seams
```

| Goal | Command |
|------|---------|
| Stack **current branch** on their tip | `./scripts/put-history-on-xai.sh` |
| Stack published main only | `SURMOUNT_REF=origin/main ./scripts/put-history-on-xai.sh` |
| One contribution-shaped commit on their tip | `MODE=overlay ./scripts/put-history-on-xai.sh` |
| Rebuild after next force-export | `./scripts/put-history-on-xai.sh` (replaces `onto-xai/*`) |
| Log | [`docs/upstream-onto-log.md`](upstream-onto-log.md) |

Default Surmount tip is **HEAD of the branch you are on** (e.g. `merge-2`), so
in-flight commits are included. Only when you are on `onto-xai/*` / `import/*`
(or detached) does it fall back to `origin/main`.

`scripts/replay-onto-upstream.sh` is a thin alias of the same script.

**How history mode works:** cherry-pick/format-patch usually fails (export
trees diverge). We **stack trees** with `git commit-tree`: each Surmount
first-parent commit after the seed becomes a new commit with the same tree
and message, parented on the previous stack commit (first parent = xAI tip).
Result: `git merge-base --is-ancestor xai-org/main onto-xai/…` is true, and
`git log xai-org/main..onto-xai/…` lists our work.

**Limits (honest):**

- We **cannot** force-push or rewrite `xai-org/main` (pull-only remote).
- GitHub’s fork compare may still say “different histories” until a PR head
  is pushed that is a **descendant** of their current tip (onto-xai branches are).
- History mode tip tree is **pure Surmount**, not “xAI plus delta” — use
  overlay when you want their latest export files under our seams.
- Overlay is not a full three-way merge of every file; it overlays known fork
  paths, product seams, and paths added on Surmount since seed. Re-review
  before opening a PR to xAI.

**Never** reset Surmount `main` to an onto-xai tip to “match” them.

## Tools

| Tool | Role |
|------|------|
| [`scripts/put-history-on-xai.sh`](../scripts/put-history-on-xai.sh) | **Our history on their tip** → `onto-xai/<short>` (re-run replaces branch) |
| [`scripts/import-upstream-export.sh`](../scripts/import-upstream-export.sh) | **Their tree into Surmount** → `import/*` content-import review branch |
| [`scripts/detect-upstream-export.sh`](../scripts/detect-upstream-export.sh) | Fetch xAI tip; compare to last imported tree; exit codes for CI |
| [`scripts/sync-upstream.sh`](../scripts/sync-upstream.sh) | Detect → print both directions (or `PUT_ON_XAI=1` / `IMPORT_NOW=1`) |
| [`scripts/replay-onto-upstream.sh`](../scripts/replay-onto-upstream.sh) | Alias of `put-history-on-xai.sh` |
| [`.github/workflows/upstream-export.yml`](../.github/workflows/upstream-export.yml) | Scheduled detection; opens issue when a new export appears |
| Agent skill `upstream-export-import` | Checklist for both directions |

### Import safety (in-flight feature work)

| Rule | Behavior |
|------|----------|
| Dirty worktree | **Abort** unless `ALLOW_DIRTY=1` |
| Default base | **`origin/main`**, never the currently checked-out feature tip |
| Feature commits | **Not** included unless you set `BASE_REF=feat/your-branch` |
| After import | Returns to your previous branch (pass `--stay` to remain on `import/…`) |
| Tree apply | `git read-tree -u --reset <xai-tree>` — **not** `git add -A` (that bug once imported only a `result` symlink) |

**Recommended order when you have unmerged features:** finish the feature (merge
`main` *into* the feature with a normal push if the PR is open — **never rebase**
a published PR branch; see [git-workflow.md](git-workflow.md)), land it on
`main`, **or** decide the import should sit on the feature — then run import
with a clean tree.

## Review checklist (every import)

- [ ] Last import tree recorded; new export tip/tree captured
- [ ] `git diff --stat <old-tree> <new-tree>` reviewed (not empty “noise only”)
- [ ] Permission / workspace / shell / pager high-churn areas skimmed for behavior changes
- [ ] Fork-only files still present: branding, OpenRouter, `grok-rate-limit`, AUR, FORK.md, justfile, flake
- [ ] `just ci` or at least `cargo check -p xai-grok-pager-bin` + focused tests
- [ ] `docs/upstream-import-log.md` updated
- [ ] Signed commit on Surmount (no signing bypass)

## Pins

| Pin | Meaning |
|-----|---------|
| `upstream/export/<fullsha>` tag (optional) | Points at a fetched xAI commit for archaeology |
| Log line in `docs/upstream-import-log.md` | Authoritative “we absorbed this tree” record |
| Surmount `main` tip | What users and `grok-oss update --check` care about |

## Related

- Product versioning: [FORK.md](../FORK.md) (upstream package version + Surmount SHA)
- Superset policy: fork features on top; never hollow out upstream behavior
