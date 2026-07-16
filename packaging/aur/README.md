# AUR packaging for Grok OSS

In-tree **source of truth** for Arch User Repository packages. The AUR itself
is a separate git repo on `aur.archlinux.org`; copy PKGBUILD + `.SRCINFO` there
when publishing.

## Packages

| Directory | AUR name | Tracks |
|-----------|----------|--------|
| [`grok-oss-git/`](grok-oss-git/) | `grok-oss-git` | Git `main` (faithful to latest fork + upstream merges) |

Installs **`/usr/bin/grok-oss`**. Unofficial Surmount fork of xai-org/grok-build.

## Local build test

```bash
cd packaging/aur/grok-oss-git
makepkg -s
# inspect package:
pacman -Qlp grok-oss-git-*.pkg.tar.zst
```

Generate `.SRCINFO` after PKGBUILD edits:

```bash
makepkg --printsrcinfo > .SRCINFO
```

## Publish to AUR

1. Create an [AUR account](https://aur.archlinux.org/) and add an SSH key.
2. Once (creates empty AUR package if you have rights):
   ```bash
   git clone ssh://aur@aur.archlinux.org/grok-oss-git.git
   ```
3. Copy `PKGBUILD` and `.SRCINFO` from this tree into the AUR clone.
4. Commit and push:
   ```bash
   git add PKGBUILD .SRCINFO
   git commit -m "grok-oss-git: initial package"
   git push
   ```
5. Bump `pkgver` (git rev) / `pkgrel` on each update; always regenerate `.SRCINFO`.

## Notes

- Prefer [Arch Rust package guidelines](https://wiki.archlinux.org/title/Rust_package_guidelines).
- Build uses `cargo build --release --locked -p xai-grok-pager-bin`.
- Binary name is `grok-oss` (see `xai-grok-pager-bin` crate).
- Do not conflict with a hypothetical official `grok` package unless paths collide.
