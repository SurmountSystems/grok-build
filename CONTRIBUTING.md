# Contributing to Grok OSS

**Pull requests are welcome on this repository**
([SurmountSystems/grok-oss](https://github.com/SurmountSystems/grok-oss) or the
current Surmount fork URL if the rename is pending).

This project is a **faithful open-source fork** of
[xai-org/grok-build](https://github.com/xai-org/grok-build). Upstream does **not**
accept external PRs; improvements intended for Grok OSS should target **this**
repo. See [`FORK.md`](FORK.md) for remotes, sync policy, and branding rules.

## How to contribute

1. Fork or branch from current `main`.
2. Prefer small, reviewable commits.
3. Keep **upstream mergeability**: avoid renaming `xai-grok-*` crates or
   rewriting large unrelated areas.
4. Run targeted checks when possible:
   ```bash
   cargo check -p xai-grok-pager-bin
   cargo test -p xai-grok-shell --test openrouter_credentials
   ```
5. Open a PR against Surmount `main` with a short summary and test plan.

## Security reports

Do **not** open public issues for vulnerabilities. Prefer the process in
[`SECURITY.md`](SECURITY.md). For Surmount-specific packaging or fork-only
code, contact maintainers privately (see SECURITY.md).

## Licensing

By submitting a contribution, you agree it is provided under the
**Apache License, Version 2.0** (see [`LICENSE`](LICENSE)), consistent with
this tree.
