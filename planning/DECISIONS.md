# Decisions

Decisions already made, with their reasons, and rejected alternatives
worth remembering. Plans and open questions are in TODO.md; known bugs
are in BUGS.md.

## Overall

- skladiště (`skl`) is an OS package manager that requires btrfs and keeps
  a content-addressed file store, installing files into systems with
  reflinks. It shares goals with ostree but doesn't focus on immutable
  systems or prebuilt images.
- First use is building container images: a relatively safe way to
  dogfood an experimental package manager.
- Focus is system/image maintenance, not package building. Arch Linux
  packages are reused for now.
- The core is independent of the source package format so that images
  from other distros can be built later. Format-specific code lives in
  frontends (`src/arch.rs`) that produce a `manifest::Package`.
- Written in Rust.

## Store

- Objects are addressed by the BLAKE3 hash of their content: a modern
  hash function considered secure. There was no strong preference over
  SHA-256.
- Rejected for now: the fs-verity digest as the content address. fs-verity
  is left for later, so there's no need to tie the store to it now.
- Layout: `objects/ab/cdef…` (read-only, mode 0444), `packages/<id>.json`
  for imported manifests, `tmp/` for objects being written. Objects are
  written to `tmp/` while hashing, then renamed into place unless an
  identical object already exists.
- An imported package is identified by the BLAKE3 hash of its archive
  file, so re-importing the same file is skipped.
- Manifests are JSON; hashes and xattr values are hex strings.

## Arch frontend

- Only zstd-compressed packages are supported, as current Arch packages
  use zstd.
- Package name and version come from `.PKGINFO`; other metadata files
  (`.MTREE`, `.BUILDINFO`, `.INSTALL`, `.CHANGELOG`) are ignored for now.
- Owner, mode and mtime come from the tar headers; xattrs come from
  `SCHILY.xattr.*` PAX records, as written by bsdtar.

## Installation

- Files are reflinked (`FICLONE`) from the store, not hardlinked as in
  ostree. Each installed file is a separate inode with its own owner,
  mode and xattrs, and can be modified without affecting the store.
- The store and images must be on the same btrfs filesystem; reflinks
  across subvolumes work.
- Files small enough to be stored inline by btrfs (up to about 2 KiB by
  default) are copied by `FICLONE` rather than shared. This is accepted.
- Paths are resolved with `openat2(RESOLVE_IN_ROOT)`, so symlinks in the
  image (including absolute ones like `/bin -> /usr/bin`) resolve inside
  the image and can never reach the host.
- Two packages providing the same path is an error, except for
  directories, where the first package wins.
- Entries are created in path order. Entries whose parent is missing
  (reached through a symlink to a path that sorts later) are retried
  until no more progress is made. Hard links are created after
  everything else because their targets may sort after them.
- Metadata order on each entry: chown, chmod, xattrs, mtime, because
  chown clears setuid bits and file capabilities.
- Directory metadata is applied after all entries exist, deepest first,
  so restrictive permissions and mtimes aren't disturbed.
- Failures to chown or set xattrs for lack of permission are counted and
  reported, not fatal, so builds work unprivileged (the dev container can
  map only one uid in a user namespace).

## Images

- An image is a new btrfs subvolume, created with the
  `BTRFS_IOC_SUBVOL_CREATE` ioctl.
- Unprivileged users can delete an image with `rm -rf` (an empty
  subvolume can be removed with `rmdir`); `btrfs subvolume delete`
  needs privileges.

## Tests

- Integration tests build synthetic packages and skip themselves when
  the cargo target directory isn't on btrfs.

## Build

- Dev builds keep only line tables as debug info: backtraces still have
  files and lines, and `target/` stays smaller.
