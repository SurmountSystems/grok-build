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

## Tools

| Tool | Role |
|------|------|
| [`scripts/detect-upstream-export.sh`](../scripts/detect-upstream-export.sh) | Fetch xAI tip; compare to last imported tree; exit codes for CI |
| [`scripts/import-upstream-export.sh`](../scripts/import-upstream-export.sh) | Build a review branch with a clean content import commit (refuses dirty trees; base defaults to `origin/main`, not your feature branch) |
| [`scripts/sync-upstream.sh`](../scripts/sync-upstream.sh) | Wrapper: detect → print next steps (no lazy merge) |
| [`.github/workflows/upstream-export.yml`](../.github/workflows/upstream-export.yml) | Scheduled detection; opens issue when a new export appears |
| Agent skill `upstream-export-import` | Review checklist for humans/agents |

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
