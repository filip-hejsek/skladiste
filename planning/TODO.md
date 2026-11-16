# TODO

Plans and open questions. Decisions already made are in DECISIONS.md;
known bugs are in BUGS.md.

Next priorities: dependency resolution, then install scripts and hooks.

## Arch frontend

- Repo databases (sync dbs) and building by package name: done up to
  building by name (see Repos in DECISIONS.md); still to do:
  - Dependency resolution against the snapshots, with Arch version
    comparison (`vercmp`) supplied by the frontend rather than the
    core: versioned dependencies and soname provides are checked across
    everything going into the image, so incompatible versions (also
    from snapshots of different times) are reported. This trusts the
    unsigned databases more, for usability; checking again against
    `.PKGINFO` (see Mirror trust) limits that. Image metadata records
    the snapshot used per repo, for upgrades and the check against
    older versions.

  Testing until then: `scripts/fetch-arch-packages.sh --urls` prints the
  URLs, with dependencies resolved by name and provides, ignoring
  versions.
- Conditional requests in `skl sync` (`If-Modified-Since`, 304): each
  sync downloads the whole database now (`extra.db` is 8.7 MiB).
- Manage the keyring in skl (from the `archlinux-keyring` package,
  updated like other packages and verified by the current keyring)
  instead of a path on the command line.
- Downloads from a mirror list:
  - Download order: this is a two-stage flow shop, where Johnson's rule
    is optimal for one downloader and one importer. Downloading is
    usually slower, which gives largest import first. Sizes are known
    beforehand from the repo database (`%CSIZE%`, `%ISIZE%`).
  - Fall back to the next mirror when a download fails.
  - One download worker per mirror (origin: scheme, host, port), with
    one keep-alive connection, replacing one worker per file.
    Parallelism comes from downloading from several mirrors at once,
    not from several connections to one host.
  - Isolation per origin is enough: the worker parses only TLS and
    response heads, never bodies, so only the server (or a network
    attacker before the certificate is checked) can attack it, and a
    compromised worker can do only what that server could already do.
    Repos sharing a host (e.g. a CDN) control only bodies, so they can
    share its worker. Different origins don't share a worker, which
    matters because databases are unsigned.
  - Protocol: the worker gets a list of paths and streams each body as
    start, chunks, end, in the order of the list. It waits
    for each response before the next request; this round trip is with
    the server, not between processes. No pipelining: some servers and
    CDNs handle it badly.
  - Reconnecting: when the server closes the connection (keep-alive
    request limits, timeouts), the worker exits and the supervisor
    starts a new one with a new connection, resuming the file in
    progress. The design is in WORKERS.md; limits, retries and
    scheduling across mirrors are still open there.
  - `skl` gets a download stage that hands each verified file to the
    import jobs, instead of each job downloading its own package; this
    is where download order matters. `skl sync` can use the same
    workers for databases.
  - Saves a TLS handshake and a worker start per file and is gentler
    on mirrors. The measured run was bandwidth-bound at `-j8`, so the
    gain shows mainly on high-latency links or with many small
    packages.
  - Quick win before this: fetch the `.sig` and the archive over one
    connection, halving the handshakes.
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
  the supervisor connect again), use the system's CA certificates by
  default (now only with `--ca-certs`), support HTTP proxies.
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
- Script runner: bubblewrap with user, mount, pid, net, ipc and uts
  namespaces, root is the image, no access to the store (can build on
  `src/bwrap.rs`).
- Workers that handle a queue of items (first user: the download
  worker per mirror): the design is in WORKERS.md. Measure the time of
  a worker start first.
- Low priority: signature verification in a worker (one per import
  run, not per package). It runs in the supervisor now, so a parser
  exploit gets `skl`'s privileges, which may exceed the image's.
