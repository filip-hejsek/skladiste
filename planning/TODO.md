# TODO

Plans and open questions. Decisions already made are in DECISIONS.md;
known bugs are in BUGS.md.

Native packages and package code are in place (planning/PACKAGES.md);
left of that design: image records (see Images).

## Arch frontend

- A build can't choose an older version of a name in `@local` except
  through a versioned dependency (or by removing the newer one with
  `skl arch local remove NAME=VERSION`).
- `skl arch import` doesn't check a package's architecture (`arch` in
  `.PKGINFO`).
- A command to download a build's packages without building.
- The resolver doesn't search: like pacman, it takes the first package
  that fits each dependency and reports a conflict rather than trying
  another choice.
- `REPLACES` is read but not used; it matters for upgrades.
- Builds don't update the keyring (`skl arch keyring update` is a step
  of its own), so a package signed by a new packager key fails until it
  is run. `build --sync` could update it first from the same repos.
  Keys aren't refreshed from WKD as `archlinux-keyring-wkd-sync` does.
- Downloads from mirrors (see Mirrors under Downloads in DECISIONS.md):
  - Download order: this is a two-stage flow shop, where Johnson's rule
    is optimal for one downloader and one importer. Downloading is
    usually slower, which gives largest import first. Sizes are known
    beforehand from the repo database (`%CSIZE%`, `%ISIZE%`). Now the
    order is largest `%CSIZE%` first, across all mirrors.
  - Fall back when a download is slow: sketched in WORKERS.md
    (Fallback). Now only failures move a file to another mirror.
  - Measure how many mirrors should share a repo's files (now 2) on a
    fast link.
  - A sync's database can go to the other of the two mirrors than the
    one its latest record is from, which then sends all of it instead
    of a `304`. The record's mirror should get it first.
  - Fetch a file again when it fails validation, from another mirror if
    there is one; now that fails the run. Needs `done` to hand back
    the sink, or a way to get a new one.
  - A mirror that isn't in sync answers `404` for each newer file, and
    each costs a reconnect (the worker exits after a status other than
    `200`/`206`). Reading the body of short error responses would keep
    the connection.
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
- Downloads: follow redirects (the worker would report the target as
  the result, and the supervisor pass it to that origin's worker), use
  the system's CA certificates by default (now only with `--ca-certs`),
  support HTTP proxies.
- Package code (PACKAGES.md): masking hooks with a symlink to
  `/dev/null`, and hooks' `Depends`, aren't supported. `skl run` passes
  the terminal through to the program; builds escape its output.
- Device nodes and FIFOs in packages are rejected; support them if a
  package needs them.

## Images

- Open question: where to record what an image contains (an image
  record in PACKAGES.md: its build spec and synthetic package; neither
  is recorded per image yet), (needed for
  upgrade and verify), including the snapshot used per repo (for
  upgrades, and to refuse versions older than those already used).
  Inside the image (e.g. `/var/lib/skl`), or alongside it outside the
  image. Once package code has run in an image,
  its contents are untrusted, so state kept inside it can't be trusted
  either.
- Open question: ownership in unprivileged builds. Alternatives: map a
  full uid range in a user namespace (needs uids and capabilities
  granted to the container), or record ownership in the manifest only
  and apply it on export.
- `build` may become a core verb now that the core builds from a list
  of package ids (see Building in PACKAGES.md and CLI in DECISIONS.md).
- Export to OCI images, or use podman's btrfs storage driver directly.
- Upgrades and generations using subvolume snapshots, with rollback.

## Store

- GC (DECISIONS.md, Garbage collection): `downloads/` isn't collected,
  so archives of packages no longer in any snapshot stay; neither are
  index entries of packages no build can choose any more. Images
  aren't roots until image records exist, so what `skl run` adds is
  removed.
- Commands wait without a message while `skl gc` or `skl migrate`
  holds the store's lock.
- Detect modified files cheaply by comparing extents (FIEMAP) with the
  store blob; on a mismatch, rehash instead of reporting a
  modification, since defrag also breaks sharing.
- Later: fs-verity on store blobs to make them immutable and
  tamper-evident. Needs a check that `FICLONE` from an fs-verity file
  is allowed. The fs-verity digest is a Merkle tree root, not a hash of
  the plain content, so it would be stored next to the BLAKE3 address.

## Sandboxing

Decisions already made are under Sandboxing in DECISIONS.md.

- Supervisor: confine `skl` itself after opening its paths (Landlock with
  the store, the package files and the image's parent directory).
  `Workers` opens the `skl` binary and looks up `bwrap` in `PATH` at
  each spawn (as does `run::run`); they would have to be opened once
  beforehand, or be given as fds.
- Package code has no limits on memory, processes or disk use in the
  image (it can fill the filesystem). Cgroups or btrfs qgroups would do.

## Library API

- Not worth doing yet: return proper error types from the library
  instead of `anyhow` messages, and move all messages that mention CLI
  commands or flags (e.g. ``run `skl arch sync` ``, `use --fetch`) to
  the CLI, which would match on the errors to add them, as it does for
  `store::NotAStore` (found with `downcast_ref`).
