# skladiště

An experimental OS package manager (`skl`) built around a content-addressed
file store on btrfs. Files are installed from the store into images with
reflinks, so every copy shares data with the store but stays an independent,
freely modifiable file.

The first use case is building container images from Arch Linux packages. The
core works with a format-independent package description, so other package
formats can be added as frontends.

## Status

- Imports Arch `.pkg.tar.zst` packages into the store, after checking
  each package's signature (`.sig` next to it) against the Arch keyring:
  the signing key must be certified by at least 3 of the master keys
- Builds a new image subvolume from a list of package names, looked up
  in repos and among package files imported before (`skl arch import`)
- Keeps Arch repo databases (`skl arch repo add`, `skl arch sync`), every
  version
- Downloads over one connection per server, kept open between files, and
  continues a file after a broken connection where the server allows
- Resolves dependencies pacman-style (versioned dependencies, provides,
  conflicts)
- Runs the packages' install scripts and the alpm hooks they trigger in
  the new image, sandboxed with bubblewrap, and keeps what they changed
  in the store, so that building the same packages again gives the same
  image without running them again (`--rerun-scripts` runs them anyway)
- `skl run` runs a program in an image, sandboxed the same way, and
  lists what it changed
- Owners are applied only where permitted; unprivileged builds report how
  many entries could not be chowned
- Archives and repo databases are parsed and images filled by worker
  processes started in new namespaces with bubblewrap (`bwrap` must be in
  `PATH`) and confined with Landlock and seccomp; `skl` refuses to run
  where these aren't available (builds with the `insecure` feature can
  turn them off)

## Usage

The store and images must be on the same btrfs filesystem.

```sh
export SKL_STORE=/path/on/btrfs/store
skl init
export SKL_KEYRING=/usr/share/pacman/keyrings/archlinux  # from archlinux-keyring
mirror='https://geo.mirror.pkgbuild.com/$repo/os/$arch'
skl arch repo add core "$mirror"
skl arch repo add extra "$mirror"
skl arch sync
skl arch build --fetch --repo core --repo extra -o image filesystem bash coreutils
skl run image bash
```

`skl run` runs the program as root in the image, without network or a
view of the host. When skl isn't root, changing owners to other ids fails
there. Afterwards it lists what the program added, modified and removed,
found by comparing the image with a snapshot taken before.

Commands for Arch packages are under `skl arch`; `skl run` and the
store work for images of any format.

`skl arch build` takes package names (`NAME`, or `REPO/NAME` for a package from
one repo) and uses the repos given with `--repo`, in priority order. It
uses the network only when asked: `--sync` downloads the repos'
databases first (as `skl arch sync`), and `--fetch` downloads packages
that aren't in the store yet.

Package files and URLs (with their signatures as `.sig` next to them)
are imported in a step of their own, and are then available to builds as
the repo `@local`:

```sh
skl arch import ./mypkg-1.0-1-x86_64.pkg.tar.zst
skl arch build --fetch --repo @local --repo core --repo extra -o image mypkg
```

HTTPS servers are checked against the Mozilla root certificates built
into skl; `--ca-certs FILE` (`SKL_CA_CERTS`) uses the certificates in a
PEM file instead, e.g. behind a TLS-intercepting proxy.

An image is a btrfs subvolume. Unprivileged users can remove it with
`rm -rf`, or with `btrfs subvolume delete`, which is much faster, if the
filesystem is mounted with `user_subvol_rm_allowed`. skl uses the same
for the snapshots `skl run` takes, and suggests the option when it's
missing; note that it lets any user remove a subvolume whose root
directory they can write to, with all its contents.

## Store layout

- `skl-store.json` — marks the directory as a store and records the
  version of its format: a number for a stable format, a random string
  for a development one (until the first stable format, all are
  development formats). A store of an older stable version is migrated
  with `skl migrate`; one of another development version can't be.
- `blobs/ab/cdef…` — file contents named by BLAKE3 hash (read-only)
- `objects/ab/cdef…` — skl's own records, such as package manifests,
  named by their hash (read-only): a header listing the blobs and
  objects they refer to, and a JSON body. A package's id is the hash of
  its manifest.
- `packages/<repo>/<hash>` — each repo's index: the id of the package
  imported from the archive with that hash; packages imported from
  files or URLs are in the repo `@arch/@local`
- `synthetic/<spec>` — the id of the package that holds what install
  scripts and hooks changed in a build of the packages of a build spec
- `downloads/<repo>/` — downloaded packages and their signatures
- `repos/<repo>/` — a repo's configuration and a record of each version of
  its database that was synced (the database itself is a blob)
- `tmp/` — staging area for new files

`<repo>` is the repo's id, `@FORMAT/NAME`: each package format has its
own namespace, so the Arch repo `core` is `@arch/core`. `skl repo list`
lists the repos of all formats by id; `skl arch` takes names or ids.

## License

Copyright 2026 Filip Hejsek

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
