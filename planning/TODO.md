# TODO

Plans and open questions. Decisions already made are in DECISIONS.md;
known bugs are in BUGS.md.

Next priorities: dependency resolution, then install scripts and hooks.

## Arch frontend

- Dependency resolution from repo databases (`core.db`, `extra.db`),
  with Arch version comparison (`vercmp`) supplied by the frontend
  rather than the core.
- Manage the keyring in skl (from the `archlinux-keyring` package,
  updated like other packages and verified by the current keyring)
  instead of a path on the command line.
- Signatures of downloaded packages: the repo database has them too
  (`%PGPSIG%`); repo databases themselves are usually unsigned in Arch.
- Download packages from a mirror in `skl` itself
  (`scripts/fetch-arch-packages.sh` does this for testing now, with
  dependencies resolved by name and provides, ignoring versions).
  Import each archive as soon as it arrives. Download order matters
  more than import order: this is a two-stage flow shop, where Johnson's
  rule is optimal for one downloader and one importer. Downloading is
  usually slower, which gives largest import first. Sizes are known
  beforehand from the repo database (`%CSIZE%`, `%ISIZE%`). To measure
  once it exists.
- Run `.INSTALL` scriptlets and alpm hooks inside the image, in a
  sandbox (see Sandboxing).
- Device nodes and FIFOs in packages are rejected; support them if a
  package needs them.

## Images

- Open question: where to record what an image contains (needed for
  upgrade and verify). Inside the image (e.g. `/var/lib/skl`), or
  alongside it outside the image. Once package code has run in an image,
  its contents are untrusted, so state kept inside it can't be trusted
  either.
- Open question: ownership in unprivileged builds. Alternatives: map a
  full uid range in a user namespace (needs uids and capabilities
  granted to the container), or record ownership in the manifest only
  and apply it on export.
- Export to OCI images, or use podman's btrfs storage driver directly.
- Upgrades and generations using subvolume snapshots, with rollback.

## Store

- Garbage collection of objects no package references.
- Detect modified files cheaply by comparing extents (FIEMAP) with the
  store object; on a mismatch, rehash instead of reporting a
  modification, since defrag also breaks sharing.
- Later: fs-verity on store objects to make them immutable and
  tamper-evident. Needs a check that `FICLONE` from an fs-verity file
  is allowed. The fs-verity digest is a Merkle tree root, not a hash of
  the plain content, so it would be stored next to the BLAKE3 address.

## Sandboxing

Decisions already made are under Sandboxing in DECISIONS.md.

- Supervisor: confine `skl` itself after opening its paths (Landlock with
  the store, the package files and the image's parent directory).
- Script runner: bubblewrap with user, mount, pid, net, ipc and uts
  namespaces, root is the image, no access to the store (can build on
  `src/bwrap.rs`).
- Low priority: signature verification in a worker (one per import
  run, not per package). It runs in the supervisor now, so a parser
  exploit gets `skl`'s privileges, which may exceed the image's.
- Downloader (once skl downloads): network plus a download directory.
  Repo databases are untrusted archives and get parsed like packages.
