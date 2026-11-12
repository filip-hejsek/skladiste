# TODO

Plans and open questions. Decisions already made are in DECISIONS.md;
known bugs are in BUGS.md.

Next priorities: dependency resolution, then install scripts and hooks.

## Arch frontend

- Repo databases (sync dbs) and building by package name. Design
  agreed; to be done in this order, one commit each:
  1. Repos and `skl sync`. A repo is a local name, the trust unit, with
     its configuration in the store (`skl repo add NAME URL`, kept in
     `repos/<name>/config.json`): a URL template in pacman's format
     (`…/$repo/os/$arch`, arch fixed to `x86_64`) and the remote
     database name (`core` for `core.db`), later its keyring.
     Frontend-specific configuration may move out of the store later.
     `skl sync` downloads each repo's database (gzip tar, unsigned) with
     `Workers::download` and a size limit, and keeps every version: the
     database as a store object, plus a record
     `repos/<repo>/syncs/<time>.json` with its hash and size, the URL,
     the fetch time (supervisor's clock) and the server's
     `Last-Modified` (sent by the worker, so untrusted and only for
     information). Records of repos synced together are written only
     after all of them downloaded and parsed. A build uses each repo's
     latest snapshot; it fails if a repo was never synced. Conditional
     requests (304) if cheap, else later.
  2. Reading databases in a `read-arch-db` worker (`src/arch/repo.rs`;
     fd 0 the database, one `DONE` with JSON; import worker's sandbox,
     a size cap per `desc`). Fields: `FILENAME`, `NAME`, `BASE`,
     `VERSION`, `CSIZE`, `ISIZE`, `SHA256SUM`, `PGPSIG` (base64-decoded),
     `ARCH`, `DEPENDS`, `PROVIDES`, `CONFLICTS`, `REPLACES`, the latter
     as strings. The supervisor validates: name and version character
     sets, the entry's directory matches `NAME-VERSION`, no duplicate
     names, `FILENAME` a plain file name, the hash 64 hex digits, the
     signature at most `MAX_SIGNATURE_SIZE`. Parse on every use and
     measure (`gzip -dc extra.db`, 15,245 entries, takes 75 ms); cache by
     database hash only if needed.
  3. Package ids include the repo: `<repo>/<archive hash>`, manifests in
     `packages/<repo>/<hash>.json` (objects are shared, so a package in
     two repos costs only its manifest twice). Packages given as paths
     or URLs belong to the pseudo-repo `@local`. Downloads move to
     `downloads/<repo>/<file name>`, as the same file name can have
     different content in different repos.
  4. Build by name. A build lists the repos it may use in priority order
     (`--repo`); a name can be qualified (`repo/name`). Restrictions are
     per repo only: a single package can install any file, so limiting
     which names a repo may provide would protect nothing. Arguments
     containing `/` or ending in `.pkg.tar.zst` are paths, URLs stay
     URLs, anything else is a name. The snapshot's entry gives the URL,
     the signature (`%PGPSIG%`, still saved as `.sig`), the size limit
     (`%CSIZE%`) and `%SHA256SUM%` (checked while downloading), and
     `.PKGINFO`'s name and version must match it. Download order by
     `%CSIZE%`.
  5. Dependency resolution against the snapshots, with Arch version
     comparison (`vercmp`) supplied by the frontend rather than the
     core: versioned dependencies and soname provides are checked across
     everything going into the image, so incompatible versions (also
     from snapshots of different times) are reported. This trusts the
     unsigned databases more, for usability; checking again against
     `.PKGINFO` (see Mirror trust) limits that. Image metadata records
     the snapshot used per repo, for upgrades and the check against
     older versions.

  Testing until 5: `scripts/fetch-arch-packages.sh --urls` prints the
  URLs, with dependencies resolved by name and provides, ignoring
  versions.
- Manage the keyring in skl (from the `archlinux-keyring` package,
  updated like other packages and verified by the current keyring)
  instead of a path on the command line.
- Downloads from a mirror list:
  - Download order: this is a two-stage flow shop, where Johnson's rule
    is optimal for one downloader and one importer. Downloading is
    usually slower, which gives largest import first. Sizes are known
    beforehand from the repo database (`%CSIZE%`, `%ISIZE%`).
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

- Garbage collection of objects no package or sync record references,
  and of old repo database snapshots.
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
