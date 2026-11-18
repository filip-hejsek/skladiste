# TODO

Plans and open questions. Decisions already made are in DECISIONS.md;
known bugs are in BUGS.md.

Next priorities: install scripts and hooks.

## Arch frontend

- `@local` can't be managed: no command lists or removes imported
  packages, and a build can't choose an older version of a name except
  through a versioned dependency.
- `skl arch import` doesn't check a package's architecture (`arch` in
  `.PKGINFO`).
- A command to download a build's packages without building.
- The resolver doesn't search: like pacman, it takes the first package
  that fits each dependency and reports a conflict rather than trying
  another choice.
- `REPLACES` is read but not used; it matters for upgrades.
- Conditional requests in `skl arch sync` (`If-None-Match` with the recorded
  `ETag`, else `If-Modified-Since`; 304): each sync downloads the whole
  database now (`extra.db` is 8.7 MiB).
- Manage the keyring in skl (from the `archlinux-keyring` package,
  updated like other packages and verified by the current keyring)
  instead of a path on the command line.
- Downloads from a mirror list. Now a repo has one server, and each
  origin one worker with one connection (see Downloads in
  DECISIONS.md), so the packages of repos on one host are downloaded
  one after another.
  - Download order: this is a two-stage flow shop, where Johnson's rule
    is optimal for one downloader and one importer. Downloading is
    usually slower, which gives largest import first. Sizes are known
    beforehand from the repo database (`%CSIZE%`, `%ISIZE%`). Now the
    order is largest `%CSIZE%` first.
  - Fall back to the next mirror when a download fails or is slow, and
    download from several mirrors at once: sketched in WORKERS.md,
    where the scheduling across mirrors and most limits are still open.
  - Fetch a file again when it fails validation, from another mirror if
    there is one; now that fails the run.
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
- Run `.INSTALL` scriptlets and alpm hooks inside the image, with
  `run::run_captured`, which also finds what they changed (see Changes by
  package code in DECISIONS.md). Next: run them in `skl arch build` and record
  their changes with the image (see Images). Output of package code should go to the
  user escaped, as workers' stderr does; `skl run` passes the terminal
  through.
- Device nodes and FIFOs in packages are rejected; support them if a
  package needs them.

## Images

- Open question: where to record what an image contains, including the
  changes install scripts and hooks made, (needed for
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
- Split building into a frontend step that works out what an image
  contains (a spec: the packages' manifests, later what install scripts
  need) and a format-independent step that builds an image from a spec.
  `build` may then become a core verb (see CLI in DECISIONS.md).
- Export to OCI images, or use podman's btrfs storage driver directly.
- Upgrades and generations using subvolume snapshots, with rollback.

## Store

- Lock the store during `skl migrate` (and against it in other
  commands); for now nothing else may use the store meanwhile.
- Garbage collection of objects no package or sync record references,
  and of old repo database snapshots. Must not race with `add_object`
  finding an object already present (see DECISIONS.md, store layout).
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
