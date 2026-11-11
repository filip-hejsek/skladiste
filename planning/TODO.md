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
- Download from a mirror list with packages named rather than given as
  URLs (`scripts/fetch-arch-packages.sh --urls` prints the URLs for
  testing now, with dependencies resolved by name and provides,
  ignoring versions). Then:
  - Download order: this is a two-stage flow shop, where Johnson's rule
    is optimal for one downloader and one importer. Downloading is
    usually slower, which gives largest import first. Sizes are known
    beforehand from the repo database (`%CSIZE%`, `%ISIZE%`).
  - Limit each download to its `%CSIZE%` and check `%SHA256SUM%`; there
    is no size limit on package downloads now.
  - Fall back to the next mirror when a download fails.
- Mirror trust: packages are signed, but Arch's repo databases aren't,
  so a malicious mirror (or anyone impersonating one; TLS stops only
  that) can't be fully defended against. It can:
  - serve an older signed package, or an older database;
  - serve a version newer than the client's but not the latest, e.g.
    one with a vulnerability the latest fixes;
  - serve an inconsistent set of versions, so a package is installed
    with incompatible dependencies;
  - serve wrong metadata: claim false dependencies to get a package
    installed, omit packages that provide a needed dependency, or
    withhold a dependency so a package isn't installed;
  - serve some packages and not others.

  Partial checks worth doing:
  - Name and version in `.PKGINFO` must match the database entry the
    package was chosen from (or at least the file name).
  - Refuse versions older than one skl has already seen for a package.
  - Dependency metadata is also in the signed `.PKGINFO` (`depend`,
    `provides`, including soname provides like `libfoo.so=1-64`):
    resolve again from those after download and fail on a mismatch with
    the database. This catches false dependencies and many
    incompatible version sets, not omitted or withheld packages.
  - Warn when the mirror's `lastupdate` is old; optionally compare
    databases from a second mirror.
- Downloads: follow redirects (the worker would report the target and
  the supervisor connect again), use the system's CA certificates
  instead of the compiled-in Mozilla roots, support HTTP proxies.
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
- Repo databases are untrusted archives and get parsed in a worker like
  packages.
