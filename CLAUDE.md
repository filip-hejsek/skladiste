# skladiště

Design principles (also for humans, so kept outside this file):

@planning/PRINCIPLES.md

Decisions already made, with rejected alternatives, are in
planning/DECISIONS.md; plans and open questions are in planning/TODO.md,
and known bugs in planning/BUGS.md. Designs that outlive their TODO
item have their own file (planning/WORKERS.md: workers that handle a
queue of items; planning/PACKAGES.md: the native package format). Larger designs that were rejected are kept in
planning/rejected/, with the reason. Check them before proposing design
changes, and keep them up to date: when something is done or fixed,
remove it from TODO.md or BUGS.md and record the decisions it involved
in DECISIONS.md. When you find a bug you aren't fixing now, add it to
BUGS.md; when tests fail or something behaves oddly, check BUGS.md first.

Self-contained subprojects have their own directory in planning/ (e.g.
planning/<subproject>/), with their own DECISIONS.md and TODO.md.

Update the planning files in the same commit as the code change they
describe. Keep entries short and current: they describe the code as it
is, not its history.

## Testing

Most of skl needs btrfs: the store and images must be on the same btrfs
filesystem. Check with `stat -f -c %T DIR` (prints `btrfs`).

The integration tests in `tests/` run in the cargo target directory and
pass without testing anything when it isn't on btrfs (they print
`skipping: … is not on btrfs`; see it with `cargo test -- --nocapture`).
If no btrfs is available, say that these tests didn't really run.
`CARGO_TARGET_DIR` can point to a directory on btrfs.

Changes to importing or installing also need a check with real Arch
packages. They come from a local repo: a pinned snapshot of the Arch
Linux Archive in `tmp/test-cache` of the main checkout (shared by all
worktrees), served by nginx over HTTP and HTTPS. Use a directory on
btrfs for the store; `tmp/` in the repo is gitignored for this if the
repo is on btrfs:

```sh
dir=tmp  # any directory on btrfs
scripts/test-mirror.sh fetch  # once; does nothing if it is there
# Starts nginx (or reloads it) and sets TEST_MIRROR (http),
# TEST_MIRROR_TLS (https), SKL_CA_CERTS and SKL_KEYRING (the snapshot's
# keyring, which `skl arch keyring init` reads).
eval "$(scripts/test-mirror.sh serve)"
export SKL_STORE=$dir/store
skl() { cargo run -q --release -- "$@"; }
mirror=$TEST_MIRROR_TLS  # or $TEST_MIRROR
skl init && skl arch keyring init  # once
skl arch repo add core "$mirror" && skl arch repo add extra "$mirror"  # once
# 42 packages with dependencies, downloaded into the store's downloads/.
skl arch build --sync --fetch --repo core --repo extra -o $dir/img filesystem bash coreutils
unshare -r chroot $dir/img /usr/bin/bash -c 'ls /'  # needs user namespaces
rm -rf $dir/img
```

`scripts/test-mirror.sh stop` stops nginx. Its access log is
`tmp/test-cache/nginx/access.log` in the main checkout. For importing
package files (`skl arch import FILE...`, then `skl arch build --repo
@local`), take them from `tmp/test-cache/arch/*/{core,extra}/os/x86_64/`.

Changes to downloading or syncing also need an occasional check against
a live mirror (`https://geo.mirror.pkgbuild.com/$repo/os/$arch`, in
a store whose keyring is current: `skl arch keyring init
/usr/share/pacman/keyrings/archlinux`, then `skl arch keyring update
--sync --fetch --repo core`). The `SKL_CA_CERTS` that
`serve` sets has the test CA added to the roots in use before (the
`SKL_CA_CERTS` it found, e.g. a proxy's CA, or else the system's
bundle), so it works for live mirrors too. For package files of other
packages, `scripts/fetch-arch-packages.sh $dir/pkgs PKGNAME...`
downloads their current versions and their dependencies (ignoring
versions) from a live mirror and prints their paths; with `--urls` it
prints their URLs instead.

Without root, chown to other users fails; `skl arch build` reports how many
entries kept the wrong owner. This is expected. If you have subordinate
uids and gids (`/etc/subuid`, `/etc/subgid`), run `skl arch build` under
`unshare --map-auto --map-root-user` so owners are applied; the image then
contains files owned by those ids, so remove it the same way
(`unshare --map-auto --map-root-user rm -rf $dir/img`).

## Checks

Before committing, all of these must pass:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps
```

## Style

- Commits: short imperative subject line; add a body only when the why
  isn't obvious.
- Commit finished work without asking, once the checks pass; a commit can
  be amended if more changes are needed.
