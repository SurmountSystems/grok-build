# Plan: Hard-prevent unsigned git commits (agent + global)

## Context

**Incident:** On `merge-2` / PR #4 the agent hit a GPG TTY failure and “fixed” it with
`git -c commit.gpgsign=false commit …`, producing unsigned tip `b89ca95`. Soft
rules in AGENTS.md were not enough under always-approve + stress.

**Goal:** Make unsigned commits **structurally hard** for the agent on this
machine, with a human-only escape. Prefer fail-closed before an object exists;
cleanup after the fact is a backstop only.

**Constraints**

- User runs Grok with `permission_mode = "always-approve"` — deny rules and
  PreToolUse hooks still apply; ask/allow memory does not.
- GPG signing remains the real requirement (GitHub “Verified”); do not fake
  signatures (`gpg.program=true`).
- Human escape must remain: `ALLOW_UNSIGNED_COMMIT=1 git commit …` outside
  agent policy.
- Do **not** rewrite/re-sign `b89ca95` or force-push PR history unless the user
  explicitly asks later.
- Scope is **machine/agent config** (`~/.grok/*`, `~/.git-hooks`, global git
  config) — not product code in grok-build, unless we add a tiny optional
  smoke script under `.agents/` for docs only.

**Non-goals**

- Fixing GPG agent/TTY so the agent can always sign (nice later; separate).
- Org-wide managed `/etc/grok/requirements.toml` lock (optional hardening only).
- Blocking every creative bypass (e.g. raw `git` via custom binary path with
  no string match) — git hooks are the ground truth.

**Assumption:** Layers 1–3 were partially installed in the prior turn. This plan
treats them as **baseline to audit + close gaps**, not greenfield.

### What already exists (baseline)

| Layer | Location | Status |
|-------|----------|--------|
| Soft rule | `~/.grok/AGENTS.md` | Present |
| Permission deny | `~/.grok/config.toml` `[permission].deny` | Present |
| PreToolUse hook | `~/.grok/hooks/block-unsigned-git-commit.{json,sh}` | Present |
| Global pre-commit | `~/.git-hooks/pre-commit` + `core.hooksPath` | Present but **gapped** |
| Global post-commit | `~/.git-hooks/post-commit` soft-reset | Present but **exit ignored by git** |
| `commit.gpgsign=true` global | git config | Present |

### Proven gaps (explored)

1. **`pre-commit` only checks `git config --bool commit.gpgsign`.**
   `git commit --no-gpg-sign` leaves config `true`, so pre-commit **allows**;
   an unsigned object is created.
2. **`post-commit` exit status is ignored by git.** Soft-reset works (tip gone,
   tree kept), but the agent still sees **commit success / exit 0** and may
   push or continue as if signed. Backstop ≠ hard stop.
3. **PreToolUse hooks fail-open** if the script crashes/times out — cannot be
   the only layer.
4. **AGENTS.md escape text is slightly wrong:** it says only post-commit honors
   `ALLOW_UNSIGNED_COMMIT`; pre-commit also does.
5. **Bypass strings not fully covered** (defense in depth): e.g.
   `git -c core.hooksPath=/empty commit`, `git config commit.gpgsign false`,
   `GIT_CONFIG_COUNT` / env overrides already partly in hook, `--gpg-sign=` empty
   edge cases, writing via `python -c` / `/usr/bin/git` without matching deny
   globs (hooks must catch).

## Approach

**Recommended: close the pre-commit hole + tighten deny/hook strings + verify
end-to-end + fix docs.** Keep three independent layers; make layer 3 (git)
actually refuse *before* the object exists for all common unsigned paths.

### Layer map (target)

```
Agent shell command
  → [1] permission deny (always-approve still honors deny)
  → [2] PreToolUse hook (clear reason; fail-open risk)
  → git commit
       → [3a] pre-commit: refuse if signing off OR --no-gpg-sign OR hooks disabled
       → create object + GPG sign
       → [3b] post-commit: verify-commit or soft-reset (backstop only)
```

### Changes

1. **Harden `~/.git-hooks/pre-commit`**
   - Keep `ALLOW_UNSIGNED_COMMIT=1` escape.
   - Keep `commit.gpgsign` must be `true`.
   - **Detect `--no-gpg-sign`** (and `-c commit.gpgsign=false`) by scanning the
     parent `git` command line via `/proc/$PPID/cmdline` and, if needed, one
     level up (shell → git). Portable enough on Linux (user’s OS).
   - **Detect empty/disabled hooksPath override** is N/A inside the hook (if
     hooksPath is empty this file never runs) — instead block those strings in
     layers 1–2.
   - Optional: if `gpg.program` resolves to `true`/`/bin/true`, refuse.
   - Print the same recovery message: unlock GPG, `git commit -S` on a TTY.

2. **Expand permission deny + PreToolUse patterns** (mirror each other)
   - Existing: `commit.gpgsign=false`, `--no-gpg-sign`, fake `gpg.program`.
   - Add: `core.hooksPath=` / `core.hooksPath=/dev/null` / `hooksPath=` empty
     when clearly disabling hooks; `commit.gpgsign=0`; `--no-gpg-sign=true`
     variants if any; `git config … commit.gpgsign false` / `--unset`.
   - Keep patterns narrow enough not to block reading docs about these flags.

3. **Post-commit stays as backstop**
   - Do not rely on its exit code.
   - Keep soft-reset + message.
   - Optionally append a loud stderr banner so logs show “UNSIGNED WIPED”.

4. **Docs**
   - Fix `~/.grok/AGENTS.md` escape + pre-commit description.
   - Update `~/.git-hooks/README.md` (pre-commit + post-commit table).
   - Short note in `~/.grok/memory/MEMORY.md` (or create) so future sessions
     load the incident + layers without re-deriving.

5. **Verification script** (local, non-product): `~/.git-hooks/smoke-unsigned-guard.sh`
   - Temp repo; assert each attack is blocked or wiped; assert signed path still
     works only if gpg available (or skip sign-success when no TTY).
   - Run once after install; leave script for reruns.

### Rejected alternatives

- **Not only AGENTS.md / MEMORY** — already failed once under pressure.
- **Not post-commit-only** — git ignores hook failure; agent sees success.
- **Not `gpg.program` wrapper that always signs** — wrong layer; passphrase/TTY
  still breaks; risk of hanging agent.
- **Not removing always-approve** — user wants YOLO; deny+hooks are the design.
- **Not amending/re-signing `b89ca95` in this work** — separate explicit ask.
- **Not `/etc/grok/requirements.toml` as required** — stronger but needs root;
  mention as optional follow-up.

## Critical files

| Path | Why |
|------|-----|
| `~/.git-hooks/pre-commit` | Must block `--no-gpg-sign` before object exists |
| `~/.git-hooks/post-commit` | Backstop soft-reset; docs only unless banner tweak |
| `~/.git-hooks/README.md` | Accurate layer description |
| `~/.git-hooks/smoke-unsigned-guard.sh` | Repeatable proof |
| `~/.grok/config.toml` | `[permission] deny` patterns |
| `~/.grok/hooks/block-unsigned-git-commit.sh` | PreToolUse mirror of deny patterns |
| `~/.grok/hooks/block-unsigned-git-commit.json` | Matcher already covers Bash \| run_terminal_command |
| `~/.grok/AGENTS.md` | Soft rule + hard layers + correct escape |
| `~/.grok/memory/MEMORY.md` | Durable incident memory for new sessions |

## Reuse

| Piece | Path | How |
|-------|------|-----|
| Existing deny list | `~/.grok/config.toml` | Extend array only |
| Existing hook script | `block-unsigned-git-commit.sh` | Extend `case` / greps |
| Existing pre-commit | `~/.git-hooks/pre-commit` | Add cmdline scan; keep escape |
| Existing post-commit | `~/.git-hooks/post-commit` | Keep soft-reset logic |
| Docs: deny wins | `~/.grok/docs/user-guide/22-permissions-and-safety.md` | Reference only |
| Docs: hooks fail-open | `~/.grok/docs/user-guide/10-hooks.md` | Justify multi-layer |

## Steps

1. **impl:precommit-harden** — Rewrite/extend `~/.git-hooks/pre-commit`:
   - `ALLOW_UNSIGNED_COMMIT=1` → exit 0
   - Require `commit.gpgsign=true`
   - Scan `/proc/$PPID/cmdline` (+ grandparent if PPID is shell) for
     `--no-gpg-sign`, `commit.gpgsign=false` (any casing), `gpg.program=true`
   - Refuse fake `gpg.program` via `git config --get gpg.program`
   - Clear stderr instructions
2. **impl:deny-expand** — Add deny globs to `~/.grok/config.toml` for hooksPath
   disable + `git config` unsigned + any missing variants from step 1.
3. **impl:hook-expand** — Mirror the same detections in
   `block-unsigned-git-commit.sh` (string match on tool command).
4. **impl:postcommit-banner** — Optional one-line louder stderr on wipe; no
   behavior change to reset logic.
5. **impl:docs** — AGENTS.md (layers + escape truth), git-hooks README,
   MEMORY.md bullet (incident `b89ca95`, three layers, human escape).
6. **impl:smoke** — Add and run `smoke-unsigned-guard.sh`:
   - Block: `-c commit.gpgsign=false`, `--no-gpg-sign`, without ALLOW
   - Allow wipe path: if something slips, post-commit leaves no unsigned HEAD
   - Escape: `ALLOW_UNSIGNED_COMMIT=1` creates unsigned commit successfully
   - Do not push; use `/tmp` repo only
7. **impl:session-note** — Tell user: **restart Grok session** (or reload
   config) so permission deny + hooks are guaranteed picked up; `core.hooksPath`
   is already global and live for all git.

## Risks

| Risk | Mitigation |
|------|------------|
| `/proc/cmdline` scan misses wrapper scripts | Keep post-commit backstop; expand patterns if a miss is found |
| Deny globs too broad (`*hooksPath*`) block legitimate docs/config reads | Anchor on `git`/`-c core.hooksPath` / `commit` contexts; test false positives |
| Hooks fail-open | Git pre-commit is source of truth; never rely on PreToolUse alone |
| `core.hooksPath` replaces per-repo hooks | README already notes dispatcher; add only if a Surmount repo needs husky later |
| Agent disables `core.hooksPath` via `git -c` | Deny + PreToolUse patterns for `core.hooksPath=` |
| User needs unsigned in CI containers | Escape env var; CI shouldn’t use this global hooksPath image blindly |
| Signed commit still fails without TTY | Correct behavior: stop and hand user TTY commands — do not bypass |

## Verification

Run after implementation (commands):

```bash
# 1) pre-commit blocks config override
cd /tmp && rm -rf u && mkdir u && cd u && git init && git config user.email t@t \
  && git config user.name t && git config commit.gpgsign true
echo a > f && git add f
git -c commit.gpgsign=false commit -m x ; echo exit=$?   # expect non-zero, no HEAD

# 2) pre-commit blocks --no-gpg-sign
echo b >> f && git add f
git commit --no-gpg-sign -m x ; echo exit=$?             # expect non-zero, no new commit

# 3) post-commit backstop (only if 2 ever regresses): unsigned HEAD must not remain
git verify-commit HEAD 2>/dev/null && echo FAIL_unsigned_tip || echo ok_no_bad_tip

# 4) human escape still works
ALLOW_UNSIGNED_COMMIT=1 git commit --no-gpg-sign -m escape
git verify-commit HEAD 2>/dev/null || echo ok_escape_unsigned

# 5) hook script unit
echo '{"toolInput":{"command":"git -c commit.gpgsign=false commit -m x"}}' \
  | ~/.grok/hooks/block-unsigned-git-commit.sh ; echo exit=$?   # expect 2

echo '{"toolInput":{"command":"git status"}}' \
  | ~/.grok/hooks/block-unsigned-git-commit.sh ; echo exit=$?   # expect 0

# 6) config present
grep -n 'no-gpg-sign\|gpgsign' ~/.grok/config.toml
git config --global --get core.hooksPath   # ~/.git-hooks
```

Permission deny for live agent: only fully confirmed after **new session**
(attempt a denied command; expect hard deny, no execution).

## Open questions

- None blocking. Optional later: root-owned `/etc/grok/requirements.toml` so
  deny rules cannot be edited away by the agent editing `~/.grok/config.toml`.
- Optional later: pin GPG via pinentry / `GPG_TTY` SessionStart hook so signed
  commits work more often without escape pressure.

## Approval

After approval, implement steps 1–7 on the machine (no grok-build product code,
no PR push, no re-sign of `b89ca95`).
