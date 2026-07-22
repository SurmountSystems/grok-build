# Agent rules — Surmount Grok OSS

Concise rules for work in this repository. Global GPG and subagent rules also
apply (`~/.grok/AGENTS.md`).

## Hard constraints

1. **Do not commit** unless the human explicitly asks. Prefer leaving a clean
   staged/unstaged tree and giving **signed** multi-message commit commands
   for a real TTY.
2. **Never bypass GPG** (`commit.gpgsign=false`, `--no-gpg-sign`, fake
   `gpg.program`, hook disables, etc.).
3. **Never bulk find-and-replace.** Bulk **find** (`rg`) is fine. Edits must
   be surgical and reviewed in context.
4. **Talk to humans in plain language.** No pack of opaque acronyms, false
   either/or menus, or planning jargon (phases, tracks, workstreams) in user
   replies, product docs, tests, or **filenames**.

## When you ship product work

- Update **[`FORK.md`](FORK.md)** with a short hierarchical note (what changed
  for Grok OSS). Link out for detail; do not write novels in FORK.
- Prefer existing living docs over new ephemeral notes.

## CI and quality

- **CI is for checks only** — never a release package build in GHA (supply
  chain). Humans package with `just build` / install recipes when needed.
- Full local gate (same idea as GHA quality): **`just check`** or **`just ci`**.
  Run before push. No pre-commit hook is required for that.
- There is no `ci-quick` or `ci-host` recipe.

## Git flow

- Feature branches → pull request → **`main`**. Tool branches (`import/*`,
  `onto-xai/*`) are not a second product main; they land through PRs.

## Upstream (xAI)

- Prefer **product commits on their current tip** when histories break
  (`scripts/put-history-on-xai.sh` — real cherry-pick). See
  [`docs/upstream-history.md`](docs/upstream-history.md).
- **Import** absorbs their tree into Surmount history (different job).
- This fork exists because upstream does not accept external PRs. If that
  changes, open a PR to contribute.

## Residual

- [`RESIDUAL.md`](RESIDUAL.md) holds **open** human-intent or unfinished honesty
  items only. When something is finished, move the lasting truth into FORK or
  the right process doc — do not leave it only in residual.

## Naming

- `xai-*` crates and paths stay for mergeability with upstream.
- Surmount-only crates and product names use **`grok-*`** / **`grok-oss`**
  (no `xai-` prefix on novel fork crates).
