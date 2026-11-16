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
- Builds a new image subvolume from a list of package files or URLs
- Keeps Arch repo databases (`skl repo add`, `skl sync`), every version
- No dependency resolution, install scripts or hooks yet
- Owners are applied only where permitted; unprivileged builds report how
  many entries could not be chowned
- Archives are parsed and images filled by worker processes started in
  new namespaces with bubblewrap (`bwrap` must be in `PATH`) and confined
  with Landlock and seccomp; `skl` refuses to run where these aren't
  available (builds with the `insecure` feature can turn them off)

## Usage

The store and images must be on the same btrfs filesystem.

```sh
export SKL_STORE=/path/on/btrfs/store
export SKL_KEYRING=/usr/share/pacman/keyrings/archlinux  # from archlinux-keyring
# Downloads the packages and their dependencies; prints their paths.
pkgs=$(scripts/fetch-arch-packages.sh pkgs filesystem bash coreutils)
skl build -o image $pkgs
unshare -r chroot image /usr/bin/bash
```

HTTPS servers are checked against the Mozilla root certificates built
into skl; `--ca-certs FILE` (`SKL_CA_CERTS`) uses the certificates in a
PEM file instead, e.g. behind a TLS-intercepting proxy.

An image is a btrfs subvolume. Unprivileged users can remove it with `rm -rf`.

## Store layout

- `objects/ab/cdef…` — file contents named by BLAKE3 hash (read-only)
- `packages/<id>.json` — imported package manifests, keyed by the archive's hash
- `downloads/` — downloaded packages and their signatures
- `repos/<repo>/` — a repo's configuration and a record of each version of
  its database that was synced (the database itself is an object)
- `tmp/` — staging area for new objects

## License

Copyright 2026 Filip Hejsek

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
