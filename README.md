# skladiště

An experimental OS package manager (`skl`) built around a content-addressed
file store on btrfs. Files are installed from the store into images with
reflinks, so every copy shares data with the store but stays an independent,
freely modifiable file.

The first use case is building container images from Arch Linux packages. The
core works with a format-independent package description, so other package
formats can be added as frontends.

## Status

- Imports Arch `.pkg.tar.zst` packages into the store
- Builds a new image subvolume from a list of package files
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
scripts/fetch-arch-packages.sh pkgs filesystem glibc bash ncurses readline
skl build -o image pkgs/*.pkg.tar.zst
unshare -r chroot image /usr/bin/bash
```

An image is a btrfs subvolume. Unprivileged users can remove it with `rm -rf`.

## Store layout

- `objects/ab/cdef…` — file contents named by BLAKE3 hash (read-only)
- `packages/<id>.json` — imported package manifests, keyed by the archive's hash
- `tmp/` — staging area for new objects

## License

Copyright 2026 Filip Hejsek

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
