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
  frontends (`src/arch.rs`) that produce a `manifest::Package` (see
  PACKAGES.md for the native format).
- Written in Rust.

## CLI

- Commands of a package format are under a subcommand named for its
  frontend (`skl arch import|build|repo|sync`); format-independent ones
  (`skl run`, `skl repo list`) are at the top level. Options only a frontend uses
  (`--keyring`) are its subcommand's. Rejected: flat commands (`skl
  build`), which give the generic verbs to Arch; core verbs that
  dispatch to a frontend by the repo's format, premature with one
  frontend (and a build can't mix formats).
- Code: `src/main.rs` only starts a worker or the CLI, `src/cli.rs` has
  the global options, core commands and helpers shared by commands,
  `src/cli/<frontend>.rs` a frontend's commands (under `cli/`, since
  `mod arch` in `main.rs` would be the library's `src/arch.rs`). The CLI parses arguments, opens paths
  and prints; what the commands do is in the library (e.g.
  `arch::packages`, `arch::repo`), which reports progress through a
  callback (`arch::packages::Event`) rather than printing. Package files
  given by path reach the library as a function that opens them, so that
  only those being imported are open (one fd each would exceed the
  usual limit of 1024 for large imports).

## Store

- Blobs are addressed by the BLAKE3 hash of their content: a modern
  hash function considered secure. There was no strong preference over
  SHA-256.
- Rejected for now: the fs-verity digest as the content address. fs-verity
  is left for later, so there's no need to tie the store to it now.
- Layout: `blobs/ab/cdef…` (read-only, mode 0444) for file contents,
  `objects/ab/cdef…` (also read-only) for skl's own records (see
  PACKAGES.md: a header of references and a canonical JSON body),
  `packages/<repo>/<key>` for each repo's index of imported packages,
  `downloads/<repo>/` for downloaded packages, `repos/<repo>/` for repos
  (see Repos), `tmp/` for blobs and manifests being written.
- A store is set up explicitly (`skl init`, `Store::init`); other
  commands only open an existing one and fail if it has no store
  manifest or a directory of the layout is missing, so a mistyped
  `--store` doesn't silently start an empty store. Setting up an
  existing store again creates what's missing; setting up a store in a
  non-empty directory that isn't one is refused. The CLI suggests
  `skl init` only where it would succeed (`NotAStore::can_init`).
- The store manifest `skl-store.json` (`{"version": 1}` or
  `{"version": "dev-…"}`) tells a store apart from a directory that
  happens to have the layout's directories, and records the store
  format version (`src/store/format.rs`). Only the current version is
  opened; older versions are never read directly.
  - Stable versions are numbers from 1. Every one after the first has a
    migration from the one before; `Formats::check` enforces it at
    compile time (the current version is `latest_stable`).
  - While the format changes between stable versions, builds use a
    development version: a random string in `src/store/dev-version`
    (made by `scripts/new-store-dev-version.sh`), so iterating doesn't
    use up numbers. Development versions have no order and are never
    migrated from; two branches that both change the format conflict on
    the file. A release gives the development version the next number
    and its migration joins the stable ones. Rejected: numbering every
    format change, which needs migrations (or skipped numbers) for
    formats only test stores ever had.
  - A store of an older stable version is opened only after an explicit
    `skl migrate`. A development build can migrate the latest stable
    version to its development version with `skl migrate --dev`; the
    store then opens only with builds of that version (snapshot it to
    keep a copy). This development migration is kept apart from the
    stable ones until the release.
  - Each migration is followed by writing the manifest with the version
    it reached, so an interrupted migration is run again: migrations
    must be safe to repeat. Nothing else may use the store during a
    migration; nothing enforces this yet.
  - There is no stable version yet; the old `{"version": 0}` is rejected
    like an unknown development version.
  - Init writes the manifest first (an unnamed file linked into place),
    so an interrupted init can be repeated. Init and open check whether
    the directory is empty before reading the manifest, so a concurrent
    init can't make a directory look non-empty without one.

  Blobs are written to an unnamed `O_TMPFILE` in `tmp/` while hashing,
  then linked into place unless an identical blob already exists;
  linking fails if the name exists, so of concurrent adds of the same
  blob (threads or processes) exactly one counts it as new. The
  existing blob must be the one kept, with the new copy dropped:
  replacing it would leave images reflinked to the old extents, so the
  same content would be stored twice. A future GC must not delete a
  blob between an add finding it present and the caller recording a
  reference to it (e.g. by locking, or by sparing blobs added during
  the GC). An unnamed file leaves nothing behind if skl is killed, and nobody can open it by
  name while it's written. Linking goes through `/proc/self/fd/N`
  (`AT_SYMLINK_FOLLOW`), since `AT_EMPTY_PATH` needs
  `CAP_DAC_READ_SEARCH`; so writing to the store needs `/proc` (only the
  supervisor writes). Objects are written the same way. Index entries
  are written to a named file in `tmp/` and renamed over any earlier
  one, which linking can't do.
- A package's id is the address of its manifest, an object (see
  PACKAGES.md). Each repo has an index of the packages imported from it,
  `packages/<repo>/<archive-hash>` holding the package's id, so
  re-importing the same file is skipped. Equal manifests are one object,
  so a package in two repos costs two index entries. Packages imported
  from paths or URLs belong to their format's pseudo-repo `@local`
  (`@arch/@local`).
- Manifests are canonical JSON (PACKAGES.md); hashes are in the
  object's header, xattr values are hex strings.

## Arch frontend

- Only zstd-compressed packages are supported, as current Arch packages
  use zstd.
- Package name and version come from `.PKGINFO`; dependencies,
  provides and conflicts too, kept in the manifest's Arch section
  (`arch::ArchSection`, as strings in Arch's syntax; the supervisor
  checks them when importing, as for database entries), with `.INSTALL`
  as a blob of the section. Other metadata files (`.MTREE`,
  `.BUILDINFO`, `.CHANGELOG`) are ignored.
- Owner, mode and mtime come from the tar headers; xattrs come from
  `SCHILY.xattr.*` PAX records, as written by bsdtar.

## Repos

- A repo is a local name and the unit of trust: a build will list the
  repos it may use, and restrictions are per repo. Names are ASCII
  letters, digits and `._+-`; names starting with `@` are kept for
  pseudo-repos.
- Repos are partitioned by package format: the store knows a repo by its
  id `@FORMAT/NAME` (`@arch/core`, `@arch/@local`; `src/repo.rs`), which
  is also its path under `repos/`, `packages/` and `downloads/`. So
  formats don't compete for names: Arch can't take `core` from another
  distro's repo. Frontend commands take names in their own namespace or
  ids (`skl arch build --repo core`, or `--repo @arch/core`, and
  `@arch/core/bash`); `skl repo list` lists all repos by id. Rejected:
  one shared namespace with the format recorded in each repo's config.
  Format names are lowercase ASCII letters and digits. Stores from
  before the namespaces need their repos moved under `@arch/` by hand
  (repos, packages and downloads directories).
- Configuration is in the store, `repos/<repo>/config.json`, written by
  `skl arch repo add NAME SERVER [--db DB]`. For Arch: a URL template in the
  format of pacman's `Server` (`…/$repo/os/$arch`, `$arch` is always
  `x86_64`) and the remote database name (`core` for `core.db`; default
  the repo's name). The store doesn't interpret it; frontend-specific
  configuration may move out of the store later.
- `skl arch sync` downloads each repo's database with the download stage
  (see Downloads; at most 64 MiB, held in memory) and keeps every
  version: the database
  as a store blob, and a record `repos/<repo>/syncs/<time>.json` with
  its hash, size, URL, the fetch time (supervisor's clock, UTC with
  microseconds; fixed width, so the names sort by time) and the server's
  `Last-Modified` and `ETag` (sent by the worker, so untrusted: at most
  100 and 256 bytes, control characters escaped, for information only
  until requests are conditional). Records are linked
  into place from an unnamed file, so one is never replaced or seen
  half-written. Records of repos synced together are written only after
  all of them were downloaded. A repo's latest record is its current
  snapshot.
- Databases are read in a `read-arch-db` worker (`src/arch/repo.rs`):
  fd 0 the database, one `DONE` with the entries as JSON, the import
  worker's sandbox and memory limit. gzip (as Arch serves them) and
  zstd are accepted; each entry must be a `NAME-VERSION/desc` of at most
  1 MiB (no other files, so the old format with separate `depends`
  files is rejected rather than read without dependencies). Fields:
  `FILENAME`, `NAME`, `BASE`, `VERSION`, `CSIZE`, `ISIZE`, `SHA256SUM`,
  `PGPSIG` (base64-decoded in the worker, hex in JSON), `ARCH`, and
  `DEPENDS`, `PROVIDES`, `CONFLICTS`, `REPLACES` as strings; `BASE`,
  `ISIZE` and `PGPSIG` are optional. The supervisor validates: name and
  version character sets, the entry's directory is `NAME-VERSION`, no
  duplicate names, `FILENAME` a plain file name, the hash 64 hex digits,
  the signature at most `MAX_SIGNATURE_SIZE`, dependencies printable
  ASCII. `skl arch sync` reads each database before recording it.
- gzip with `flate2` and its default pure-Rust backend (`miniz_oxide`);
  5 crates added to `Cargo.lock`.
- Databases are parsed on every use, not cached. `extra.db` (15,279
  entries, 8.7 MiB) takes about 360 ms through the worker: gunzip 85 ms,
  tar and `desc` parsing 60 ms, 17 MB of JSON written in 25 ms and
  parsed by the supervisor in 55-85 ms, validation 13 ms, and the
  worker's start (`gzip -dc` alone takes 150 ms on the same machine).
  Encoding the signatures as hex with `write!` took 100 ms before it
  was replaced. Cache by database hash only if this matters.
- No conditional requests yet: syncing core and extra (8.8 MiB) took
  0.9 s, 1.35 s with reading them.
- The keyring is needed to import packages: by `import`, and by `build`
  when it uses packages from synced repos (their archives are verified
  again each time).
- `build` takes only package names. It lists the repos it may use in
  priority order (`--repo`, at least one) and uses each one's latest
  snapshot, failing if a repo was never synced; the first repo with the
  name wins, and `REPO/NAME` takes it from that repo, which must be
  among `--repo`. Restrictions are per repo only: a single package can
  install any file, so limiting which names a repo may provide would
  protect nothing. A package named twice is taken once.
- `build` uses the network only when asked: `--sync` syncs the `--repo`
  repos first (as `skl arch sync` with those repos), `--fetch` downloads
  packages that aren't in the store's downloads; without it, a missing
  package is an error.
- Package files and URLs are imported in a step of their own (`skl arch
  import FILE|URL...`) into the pseudo-repo `@local`, which a build uses
  like any other repo (`--repo @local`, `@local/NAME`). So `build`'s
  arguments are never paths, and local packages take part in dependency
  resolution, by the metadata in their manifests. Rejected: files and
  URLs as `build` arguments (a name could be read as a path and the
  reverse, which needed rules like `./REPO/NAME`; their dependencies
  were known only after importing, so they weren't resolved).
- `@local` offers every package imported into it. Of several versions
  of a name, the newest comes first, so it is taken unless a versioned
  dependency excludes it. Signatures of local packages are checked when
  importing, not again by builds: the archive of a file isn't kept.
  All `@local` manifests are read for each build that uses it (not
  measured); keep their Arch sections apart if this gets slow.
- The snapshot's entry gives the URL (`<server>/<FILENAME>`), the
  signature (`%PGPSIG%`, still saved as `.sig` next to the download;
  an entry without one is an error), the size limit and exact size
  (`%CSIZE%`) and `%SHA256SUM%`, checked while downloading, before the
  file is kept, and again for earlier downloads while hashing the
  archive for its id. `.PKGINFO`'s name and version must match the
  entry's, also for packages imported before. The architecture must be
  `x86_64` or `any`.
- Downloads go largest first by `%CSIZE%`. The import jobs take
  finished downloads first, then the archives already there (largest
  first).

## Dependency resolution

- Packages are resolved with their dependencies against the `--repo`
  repos: latest snapshots and `@local` (`src/resolve.rs`). The
  resolver is format-independent: the frontend turns database entries
  and imported manifests into candidates (name, version, depends, provides, conflicts; Arch's
  `NAME`, `NAME<=V` etc. parsed in `src/arch/repo.rs`) and supplies the
  version comparison (`src/arch/version.rs`, pacman's `vercmp`: epoch,
  then version with rpm's segment rules, then the release only if both
  have one). It gives the results of pacman's `alpm_pkg_vercmp`
  (compiled from `lib/libalpm/version.c`) on 300,000 random pairs of
  versions; the unit test has all cases of pacman's own test.
- As in pacman, there's no search: each dependency not yet satisfied by
  a chosen package takes the first package with that name whose version
  fits, in repo priority order, else the first package (in priority and
  database order) that provides it. Names given on the command line can
  also be provided. A provide satisfies a versioned dependency only if
  it has a version. A qualified name (`REPO/NAME`) is resolved in that
  repo only; its dependencies in all of them.
- Everything going into the image is checked as a whole, so incompatible
  versions (also from snapshots of different times) are reported rather
  than installed: every versioned dependency, including soname provides
  (`libcrypto.so=4-64`), is satisfied; two packages with the same name
  are an error (e.g. a dependency needs a newer version than another
  repo's package already chosen); no package conflicts with another
  (a package's conflicts with itself, as with a package that provides
  and conflicts with the same name, don't count).
- This trusts the unsigned databases more, for usability: their
  dependencies decide what is installed. Checking again against
  `.PKGINFO` is planned (see Mirror trust in TODO.md).
- Measured: `filesystem bash coreutils` resolve to 42 packages (the
  version-blind script picked 43, with `openssl-3` for a dependency on
  `libcrypto.so=4-64`); `plasma-meta kde-applications-meta texlive-meta
  gnome-shell` resolve to 1,265 packages in 14 ms (67 ms when checking
  satisfied dependencies by scanning the chosen packages, before they
  were indexed by name and provides). Reading the databases dominates
  (about 400 ms for core and extra).

## Downloads

- `skl arch import` takes `http` or `https` URLs as well as files; the
  signature is the same URL with `.sig` appended.
- The supervisor resolves the host (`getaddrinfo`, not sandboxed, like
  any program's name lookup) and opens the TCP connection; the download
  worker gets the connected socket and speaks TLS and HTTP over it. The
  worker therefore has the import worker's sandbox: no network
  namespace of the host, no files, no DNS, and it can reach no other
  host, including services on localhost. It streams only the response
  bodies; the supervisor writes the files, so no other process holds an
  fd to them. Rejected: a worker in the host's network namespace doing
  its own DNS (needs `/etc/resolv.conf` and more system calls, and can
  connect anywhere; Landlock can restrict only TCP ports); an HTTP
  client library such as ureq (it opens its own connections; its
  transport API is unstable).
- One worker per origin (scheme, host, port), with one connection that
  is kept open between requests: the files of an origin are downloaded
  one after another, in the order given. Parallelism comes from
  downloading from several origins at once (at most `-j`), not from
  several connections to one host, which is gentler on mirrors.
  Requests aren't pipelined: the worker waits for each response before
  the next request (a round trip with the server, not between
  processes), as some servers and CDNs handle pipelining badly.
- Isolation per origin is enough: the worker parses only TLS and
  response heads, never bodies, so only the server (or a network
  attacker before the certificate is checked) can attack it, and a
  compromised worker can do only what that server could already do.
  Repos sharing a host (e.g. a CDN) control only bodies, so they share
  its worker. Different origins don't share a worker, which matters
  because databases are unsigned.
- The worker handles a queue of files (`src/download.rs`; the
  design is in WORKERS.md). The supervisor sends items (a path, and
  what continues a file), keeping at most two unanswered, so the worker
  has the next file at hand without a round trip and sending never
  blocks. The worker answers each in order with a start (the length,
  a validator, `Last-Modified` and `ETag`), the body in chunks and an
  end. One supervisor thread per worker reads this, writes the file
  and counts the bytes itself; a length the worker reports only serves
  to fail early when it is over the limit.
- A worker lives as long as its connection. When the server closes it,
  or after a response that ends it (`Connection: close`, HTTP/1.0, a
  body that runs until the close, or a status other than `200` and
  `206`, whose body the worker doesn't read), the worker exits and the
  supervisor connects again and starts a new one for the files left. A
  worker start takes about 4 ms (bwrap, exec, Landlock and seccomp:
  4.0-4.6 ms for a 2-byte download from localhost, 3.7-3.9 ms for a
  `read-arch-db` worker that fails at once), little next to the TCP
  and TLS handshakes of the new connection. Rejected: passing a new
  socket to the running worker (`SCM_RIGHTS`), which would save only
  that.
- A file whose connection broke is continued where it stopped, if its
  response had a strong validator: an `ETag` that isn't weak, or, only
  if there is no `ETag`, a `Last-Modified` at least a second older than
  `Date`. The request has `Range` and `If-Range`; a `206` must start at
  the offset and end the file at the length the first response gave.
  Otherwise the file is fetched again from the beginning. The offset is
  the supervisor's count of what it received, and the validator is
  opaque to it (at most 256 printable ASCII characters). If the server
  has another version by then (it answers `200`), packages from a
  repo's snapshot fail, as the database says by SHA-256 what the file
  is; databases and URLs given to `skl arch import` are downloaded again
  from the beginning. Details and reasons are in WORKERS.md.
- Limits: a connection that neither completes a file nor gets the file
  under way further than any connection before is a strike. The next
  connection to that origin then waits 1 s, doubled with each strike,
  and at 3 strikes (per origin and run, not reset by progress in
  between) the download fails. A read or write that times out counts
  as a connection that ended. A connection that can't be opened fails
  the download at once, as before. Other limits are open (WORKERS.md).
- The download stage runs next to the import jobs
  (`download::fetch_and_run`) instead of within them. The thread of an origin checks
  each finished file (size and SHA-256 from the database, then the
  signature), keeps it in the store's downloads and hands the open file
  to the jobs, which take finished downloads before archives that were
  there already. At most 64 files wait for a job (each is an open fd);
  then the thread blocks and its worker stalls, which is the wanted
  back-pressure. A download's file is created when its body starts, so
  queued downloads hold no fd. `skl arch sync` uses the same stage: the
  jobs read the databases.
- After a failure anywhere, no new download or import starts. A
  download whose body has started is finished and kept; then its worker
  is killed.
- Rejected: one connection and one worker per file (`Connection:
  close`), started within the import jobs, as it was before. Measured
  with 42 packages (39.5 MiB) from `geo.mirror.pkgbuild.com` into an
  empty store (`build --fetch`, 4 CPUs), on a fast link where a new
  connection takes about 0.2 s to the first response byte: 21-25 s with
  `-j1`, 5.8-7.1 s `-j4`, 3.8-4.2 s `-j8`; with a worker per origin
  4.6-5.3 s whatever `-j`. `curl` took 4.1 s for the same files over
  one connection and 19.1 s with a connection per file; verifying,
  importing and installing them without downloading takes 1.35 s. So
  on such a link several connections to the host would still gain a
  little (the `-j8` above); that is left to downloading from several
  mirrors. On a link of about 2.4 MB/s a worker per file was
  bandwidth-bound (43 packages, 43 MiB: 32.7 s with `-j1`, 19.8 s
  `-j4`, 18.0 s `-j8` and `-j16`; sequential `curl` 28.6 s), where one
  connection isn't measured. Syncing core and extra took 1.3-1.4 s
  either way.
- HTTP/1.1 is written by hand on `httparse` for the response head:
  `Content-Length`, chunked or until close; `Accept-Encoding: identity`,
  other encodings are rejected. Only `200` is accepted, and `206` for
  a continuation; redirects are reported with their target and not
  followed. A `408` counts as a connection that ended (some servers
  send it when they close an idle connection). Reads and writes time
  out after 30 s (`SO_RCVTIMEO`/`SO_SNDTIMEO` set by the supervisor,
  also in effect in the worker). The worker's memory limit is 256 MiB.
- TLS: rustls with the `ring` provider (C and assembly from BoringSSL)
  and the Mozilla roots compiled in (`webpki-roots`), so the worker
  needs no files. A memory-safe crypto backend matters less here than
  for signatures: TLS runs sandboxed and package integrity comes from
  signatures; TLS keeps a network attacker from serving an older signed
  package under a newer URL. Added 17 crates to `Cargo.lock` (most are
  Windows-only).
- Root certificates given by the user (`--ca-certs FILE`,
  `SKL_CA_CERTS`): a PEM file whose certificates replace the built-in
  roots, not add to them, as with a CA bundle such as
  `/etc/ssl/certs/ca-certificates.crt` (or a TLS-intercepting proxy's).
  The supervisor reads and checks them at startup (each must be a usable
  trust anchor; non-certificate PEM sections are ignored) and sends them
  in DER to each `https` download worker on its socket, before the
  first item, so the worker still needs no files. Rejected: an
  argument (a bundle of 122 roots is 180 KB of PEM, over Linux's
  128 KiB limit per argument); an extra fd (needs new plumbing through
  bubblewrap for one input sent once).
- The worker sends the response's `Last-Modified` and `ETag` headers
  with the start of each file.
- Downloads are kept in the store's `downloads/<repo>/` by file name
  (the URL's last path segment; Arch file names include the version; the
  same name can have different content in different repos), written to
  an unnamed file in `tmp/` and linked into place only after the
  signature verified (removing any file there first), so a file there
  is complete; the signature is saved after the
  archive. Present files are used without downloading, and verified
  again. A file that fails verification there is an error, not
  downloaded again.
- Worker error messages are shown with control characters escaped, as
  they can contain text from servers or archives.

## Package signatures

- Every package's detached signature (`<package>.sig`) is checked
  against the Arch keyring before the archive is hashed or parsed. For
  packages from synced repos this is repeated by every build, from the
  kept download (the keyring may have changed since); `@local` packages
  are checked only when imported.
  There's no option to skip it. The keyring is given as a path prefix
  (`--keyring`, `SKL_KEYRING`): `PREFIX.gpg`, `PREFIX-trusted`,
  `PREFIX-revoked`, as in `/usr/share/pacman/keyrings/`. skl is meant
  to manage the keyring itself later.
- OpenPGP library: Sequoia (`sequoia-openpgp`) with its pure-Rust
  crypto backend (`crypto-rust`, which needs `allow-experimental-crypto`
  and `allow-variable-time-crypto`; timing doesn't matter, only public
  data is handled), not the default Nettle (C), so that verification is
  memory-safe. It grew `Cargo.lock` from 63 to 273 crates, the release
  binary from 2.7 to 6.5 MB and a clean release build from about 23 s
  to 65 s. Rejected: GnuPG/gpgme as pacman uses (C, and the web of trust
  below); rPGP (also pure Rust, but lower level, leaving more of
  certificate validity to us).
- Verification runs in `verify-arch` workers (`src/arch/verify.rs`),
  so an exploit of the OpenPGP parser doesn't get `skl`'s privileges,
  which may exceed the image's. The supervisor can't check a verdict, so
  a compromised verifier is as bad as a forged signature: the worker
  protects the host, not the result.
  - A pool (`arch::verify::with_verifier`): up to `--jobs` workers, started
    as callers need them, so verification stays parallel. Each loads the
    keyring once and keeps its certification cache for the run. Rejected:
    a worker per package (a start and a keyring load each); a single
    worker for the run (verifying on one core while imports use all).
  - A worker has one item at a time: each caller waits for its verdict
    before going on, so there is nothing to pipeline per caller, and
    concurrent callers get different workers.
  - Input is a `SOCK_SEQPACKET` socket with fds attached (`SCM_RIGHTS`):
    first the three keyring files, then a signature with the archive's fd
    per item. Verdicts come back on a pipe. The supervisor sends a new
    read-only open file of each (through `/proc/self/fd`, regular files
    only), so the worker can't write a download in the store, and its
    reads don't move the supervisor's offset. Rejected: streaming the
    archive through the socket (a copy, and an item wouldn't fit in the
    socket buffer, so sending could block).
  - Cost, measured on a build of the 42-package set from kept downloads
    (40 MB, all verified again, 8 CPUs): 995 ms instead of 936 ms. With
    `-j1`: verifying took 143 ms in the worker instead of 126 ms in the
    supervisor, round trips 4 ms in all, and the first worker's start and
    keyring load 36-65 ms instead of 30 ms. Ending 8 workers one after
    another took 18 ms, so their inputs are closed together.
- Trust is an explicit rule, not GnuPG's web of trust: a packager key is
  a certificate with a user ID certified by at least 3 master keys
  (`archlinux-trusted`, which must list them at marginal trust `4`;
  other levels are rejected rather than interpreted). This is what
  pacman's setup amounts to (marginal owner trust, `marginals-needed`
  3). Master keys don't count as packager keys themselves. Keys in
  `archlinux-revoked` are dropped entirely. A certification counts if it
  is the issuer's active one and not revoked by a later or hard
  revocation from the same issuer. A file with several signatures is
  accepted if one is good (at most 8, as the data is hashed for each).
- Validity is evaluated at the current time, as GnuPG does, not as of
  the signature's creation time: the Arch keyring keeps only each key's
  latest self-signatures, so with Sequoia's stream verifier (which
  checks the key as of the signature time) `filesystem` failed as
  "subkey not bound". skl therefore parses and checks signatures itself
  with Sequoia's primitives and standard policy.
- Certifications are checked when a key first signs something and
  cached, not for the whole keyring when it's loaded: with the real
  keyring (144 certificates) that took 210 ms of a 240 ms load; lazily,
  loading takes about 30 ms. Importing 7 packages (43 MB) into an empty
  store took 290 ms instead of 233 ms without verification.

## Installation

- Files are reflinked (`FICLONE`) from the store, not hardlinked as in
  ostree. Each installed file is a separate inode with its own owner,
  mode and xattrs, and can be modified without affecting the store.
  This also means code running in an image (install scripts, the
  container itself) can't modify the store.
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

## Changes by package code

- `run::run_captured` (used by `skl run`) finds what a program changed in
  an image: it takes a writable btrfs snapshot of the image in the
  store's `tmp/` (12 ms), runs the program, compares the image with the
  snapshot in a worker, and removes the snapshot. A snapshot keeps inode
  numbers and ctimes, and a sandboxed program can't set a ctime, so an
  entry is unchanged if inode number, type and ctime (with ns) equal the
  snapshot's at the same path. Only directories whose ctime changed are
  listed in the snapshot to find removed entries. No file is read unless
  it changed. Rejected: overlayfs (bwrap `--overlay`), whose upper
  directory holds the changes, but with whiteouts and opaque directories,
  xattrs and inode numbers to handle and a merge back; `btrfs send` or
  generation searches (`BTRFS_IOC_TREE_SEARCH`), which need
  `CAP_SYS_ADMIN`; hashing every file.
- Before the program starts, skl waits until `CLOCK_REALTIME_COARSE`
  (which sets ctimes) is past the fine-grained time after the snapshot,
  at most one tick. Otherwise an inode created and changed within the
  same tick would keep its ctime. Accepted: setting the clock back during
  a run could, very unlikely, give a changed inode its old ctime.
- Changes are `diff::Change`: `Added` or `Modified` with the new entry,
  which replaces what was at its path (a directory's contents are entries
  of their own), or `Removed` with everything beneath; in path order, the
  removals in a directory after its other changes. A file with several
  links is a file entry at its first path and hard links at the others
  (adding a link changes the inode's ctime, so all its paths are
  reported). The image root itself isn't reported: manifest paths aren't
  empty. Devices, FIFOs, sockets, non-UTF-8 names and mount points or
  nested subvolumes make the comparison fail.
- The diff worker gets both trees bound read-only, Landlock read access
  and `CAP_DAC_READ_SEARCH`, to read files of any mode: as root in the
  supervisor's user namespace (as the install worker), otherwise in its
  new user namespace, where it covers only files whose owner and group
  are skl's. It streams contents as the import worker does; the
  supervisor validates the changes (normal paths, each once, hard links
  only to a file changed earlier). New contents become store blobs,
  not yet referenced by any manifest.
- The snapshot is removed with `BTRFS_IOC_SNAP_DESTROY` (2 ms), which
  needs `CAP_SYS_ADMIN` or, for a user who can write to the subvolume's
  root, the mount option `user_subvol_rm_allowed`. Otherwise (`EPERM`) its
  entries are removed one by one (0.84 s with `rm -rf` for 20,000
  entries), and `skl run` suggests the mount option, saying that it lets
  any user remove a subvolume they can write to with all its contents.
  The `EPERM` tells, so mount options aren't read. `skl run` of a small
  script on an image of 20,000 entries took 0.23 s in all as root, and as
  an unprivileged user 0.42 s without the option and 0.15 s with it.

## Sandboxing

- Goal: every part of skl runs with only the access it needs, using
  namespaces, Landlock and seccomp. Work that needs different access
  (parsing untrusted archives, writing the store, writing an image,
  running package code, network) goes in separate processes. See the
  Sandboxing section of TODO.md for what isn't done yet.
- Library code works on file descriptors, not paths: `Store` holds a
  directory fd, frontends read from a `Read` and write file contents to
  an `BlobSink`, and the installer uses only the store fd and the
  image root fd. Only the CLI opens paths. Exceptions:
  `Store::init_path` and `Store::open_path`, conveniences for the CLI
  and tests that open the directory and call `Store::init` or
  `Store::open`, and the programs `Workers` executes (see Sandboxing in
  TODO.md).
- Workers (`src/worker.rs`) are started by re-executing the `skl` binary
  (`/proc/self/exe`; tests pass `CARGO_BIN_EXE_skl`) with the hidden
  `__worker` subcommand, which `main` checks before parsing arguments.
  A fresh exec is single-threaded and inherits no memory; fork without
  exec is unsafe in a multithreaded process. Both ends are the same
  binary, so the protocol needs no stability. The environment is cleared
  and the working directory is `/`.
- Each kind of worker is a `worker::Kind` (name, directories,
  capabilities, entry point) defined with the code it runs: the Arch
  ones in `arch`, the others in `download`, `diff` and `install`. Their
  supervisor sides are functions there that take `&Workers`, which only
  starts workers and holds settings. `worker::KINDS` lists every kind
  (the only place the generic module names them);
  `__worker` runs only those, with the directories the kind declares.
  Rejected: a method on `Workers` per kind (the generic module grows
  with every frontend, against keeping the core format-agnostic); a
  trait per kind (the supervisor sides differ too much: one result, a
  stream, a pool, a queue).
- Fds for a worker (and for bwrap to bind) are inherited at their own
  numbers (CLOEXEC cleared in the child before exec), and the numbers
  passed as arguments. Rejected:
  `dup2` to fixed numbers in `pre_exec`, which can clobber the pipe std
  uses to report exec errors. The worker closes every other fd except
  stdio before confining itself, since Landlock and seccomp don't affect
  fds already open.
- A worker's stderr (panic messages) is a pipe, non-blocking on the
  worker's side, that the supervisor reads after the worker exits. It
  prints the output with control characters escaped and each line
  prefixed with the worker's name, so a worker can't control the
  terminal or pass for the supervisor. Each worker's output is printed
  as one block with stderr locked, so output from parallel workers won't
  interleave. Output beyond the pipe's capacity
  (64 KiB) is lost; workers only write there when something is wrong.
  Rejected: inheriting stderr (a worker could write escape sequences to
  the terminal); a thread or `poll` to drain the pipe while the worker
  runs (a blocking worker could deadlock with a supervisor that waits on
  another fd; more code for output that's rarely there).
- Workers start in new namespaces under bubblewrap (`src/bwrap.rs`), then
  confine themselves with Landlock and seccomp. bwrap is found in the
  supervisor's `PATH`. The root is an empty read-only tmpfs with the
  host's `/usr` and `/lib*` (for the dynamic loader, `/etc/ld.so.cache` if
  present), the `skl` binary bound from an `O_PATH` fd at `/skl`, and the
  worker's directories bound from their fds at fixed paths, which the
  worker opens before confining itself. New pid, net, ipc, uts and cgroup
  namespaces; `--die-with-parent` and `--new-session`. That kills a
  worker when the *thread* that started it ends (`PR_SET_PDEATHSIG`), so
  a `Worker` from `Workers::spawn` is `!Send`. Workers shared between
  threads (see Package signatures) come from `Workers::with_spawner`: a
  scoped thread of its own starts them, and a lifetime brand keeps them
  from outliving it. Rejected: one thread that starts every worker (all
  starts would go through it, while only the verifier's workers are
  shared; not measured). bwrap exits with
  128 + the signal that killed the worker, which is reported like the
  signal itself. Namespaces add what Landlock lacks: a read-only store
  (Landlock doesn't restrict metadata changes), no view of host processes
  or network, and a hidden host filesystem during exec, before Landlock
  applies.
- User namespaces in workers: the install worker stays in the
  supervisor's user namespace when skl runs as root, keeping only
  `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID` and
  `CAP_SETFCAP`, so owners apply in a user namespace with a range of ids
  mapped. bwrap can map only one id in a new user namespace without
  setuid. Otherwise (import worker, or skl not root) a worker gets a new
  user namespace mapping only skl's uid and gid, with
  `--disable-userns` and no capabilities, except those a worker asks to
  keep there (only the diff worker does), which apply to files of skl's
  uid and gid. Xattrs that need `CAP_SYS_ADMIN` (`trusted.*`,
  `security.*` other than `security.capability`) are counted as failures.
- Workers confine themselves (`src/sandbox.rs`): `no_new_privs`, then
  Landlock (all filesystem access handled, plus TCP and the abstract
  socket and signal scopes; only the given directory fds are allowed),
  then a seccomp allowlist that kills the process on any other system
  call. Allowlisting also rejects x32 system calls. `fcntl` is allowed
  only with `F_GETFD`, which debug builds use when closing fds; `ioctl`
  only with listed request numbers. Before confining, a worker calls
  `tzset()`: glibc's `strftime` (Sequoia's error messages) otherwise
  opens `/etc/localtime` on first use, and seccomp kills the worker.
- Workers have a fixed address space limit (`RLIMIT_AS`, soft and hard,
  set before confining): 1 GiB for import (real packages need tens of
  MiB; zstd's decoding window is at most 128 MiB by default), 4 GiB for
  install, whose memory grows with the plan. Death by `SIGABRT` is
  reported as a possible out-of-memory. Not limited: CPU time (a stuck
  worker only hangs skl, which can be interrupted, and any limit risks
  failing large legitimate jobs), processes (seccomp blocks `clone`),
  open files and file sizes (the import worker can't open files; the
  install worker writes only what the plan says). Rejected for now:
  cgroups, which would also limit the total of parallel workers but need
  a delegated cgroup (e.g. from systemd).
- Landlock is best effort with ABI 9 requested: an older kernel that
  enforces only part of it is accepted (TCP is blocked by seccomp
  anyway), a kernel without Landlock is refused.
- The import worker gets the archive as stdin and a socket as stdout, no
  filesystem access and no ioctls. It streams file contents to the
  supervisor without waiting for anything: data flows only from the
  worker (the supervisor shuts down its sending side), so neither side
  can block the other. Each blob is `BEGIN` with its size, then
  `CHUNK`s of exactly that many bytes; an `ERROR` can come between
  chunks, e.g. when the archive is corrupt in the middle of a file.
  The supervisor writes and hashes the blobs as they arrive.
- Frontends get no hashes: `BlobSink::add_blob` returns a
  `BlobId`, the blob's position in the stream, and the manifest
  (`Package<BlobId>`) refers to files by id. The supervisor resolves
  ids to hash and size (`Package::resolve`), validates the result
  (`Package::validate`) and counts the import statistics itself. Ids are
  explicit rather than implied by the order of file entries, so formats
  whose metadata doesn't come in content order need no change.
  Rejected: a reply with the hash for each file (the worker waits
  for every file; 1.07 s instead of 0.77 s below); the worker naming
  hashes the supervisor checks (the worker would hash everything again).
- Both ends of a worker's output buffer it (64 KiB), so the many small
  files of a package cost few system calls; chunks of 64 KiB bypass the
  buffer. The final `DONE` or `ERROR` goes through the same buffer, so
  it can't overtake earlier messages. Not done: a 64 KiB copy buffer in
  `Store::add_blob` instead of `io::copy`'s 8 KiB (0.75 s instead of
  0.77 s, close to noise).
- File contents stay in the import socket; avoiding the copy isn't worth
  it. Importing 17 Arch packages (8,300 files, 185 MiB; 140 MiB in files
  of 64 KiB or more) takes 0.77 s through the socket and took 0.92 s in
  process, where parsing and storing don't overlap. With a reply per
  file it took 1.07 s, and sending everything through the socket a
  second time added only 0.09 s: the round trip was the cost, not the
  copy. Rejected (prototypes measured with files of 64 KiB or more
  written by the worker to a staging `O_TMPFILE` that the supervisor
  created): reflinking it into
  the store and hashing the clone (1.69 s: `FICLONE` waits for the
  source to be written to disk, and the clone isn't in the page cache,
  so hashing reads from disk); hashing and linking the staging file
  itself after a read lease (`F_SETLEASE`) shows that nothing has it
  open for writing (1.19 s: the worker waits while the supervisor reads
  and hashes the whole file, where the socket lets both run during a
  file); a writable directory for the worker (more Landlock rights,
  names and fds from the worker to check); pipes with `splice` (the
  kernel copies from a pipe into a file, and hashing needs a read back).
- The supervisor (the `skl` process) is the only writer of the store and
  creates the image subvolume. It merges packages (conflict checks) and
  sends the plan to the install worker, which gets the store fd
  (Landlock: read files) and the image root fd (read dirs, write files,
  create dirs, files and symlinks, link across dirs), and only `FICLONE`
  as an ioctl, since Landlock doesn't restrict btrfs ioctls such as
  subvolume creation. The store is bound read-only and the image
  read-write in its mount namespace.
- Workers end with one result or error message; an error the worker
  sent is reported in preference to its exit status, and death by
  `SIGSYS` is reported as a blocked system call. The download worker
  is the exception: it handles a queue of files (see Downloads).
- Packages are imported in parallel, `-j` at once (default: the number
  of CPUs), each by its own worker (a compromised worker could otherwise
  change another package's manifest) and one supervisor thread per
  worker (`jobs::par_map_iter`). The largest archives start first, since
  the largest package bounds the total time. After a failure no new
  imports start; running ones finish and are saved. The same archive
  given twice is imported twice; not worth coordinating between
  threads. Importing
  the 17 packages below (now 109 MiB of archives): 0.81 s with `-j1`,
  0.51 s with `-j2`, 0.50 s with `-j4`, 0.50 s with `-j8` on 8 CPUs,
  where perl alone takes 0.27 s. Sys time grows with more threads
  (0.50 s at `-j1`, 0.75 s at `-j8`), presumably contention in btrfs.
  Starting in command-line order instead took 0.56 s with `-j2` and
  0.49 s with `-j8`.
- A package archive is opened once, verified (through a read-only open
  file of it), hashed for its id, and the same open file is parsed, so
  the manifest matches the id unless the file is written to meanwhile
  (see BUGS.md).
- Package code (install scripts, hooks) runs under an existing sandbox
  tool, bubblewrap for now (minijail or nsjail would also do). Rejected:
  setting up namespaces ourselves; no clear benefit for more code. Workers
  running skl's own code also start under bubblewrap and add Landlock and
  seccomp themselves.
- Package code runs with `skl::run` (`skl run IMAGE PROGRAM...`): bwrap
  with the image fd bound read-write as `/`, new pid, net, ipc, uts and
  cgroup namespaces, a read-only `/proc`, bwrap's minimal `/dev`, tmpfs on
  `/tmp` and `/run` (not kept in the image), no `/sys`, the environment
  only `PATH` (and `PWD`, set by bwrap). It runs as root with the install
  worker's capabilities: when skl is root, in the supervisor's user
  namespace (owners mean the same as outside); otherwise in a new user
  namespace mapping skl's ids to 0. `/proc` is read-only because uid 0
  of the host's user namespace can write sysctls without capabilities,
  and bwrap doesn't cover `/proc/sys` (it checks `access(W_OK)`, which
  fails on the 0555 directory without `CAP_DAC_OVERRIDE`). bwrap's
  `--disable-userns` needs a new user namespace, so a seccomp filter
  given to bwrap (`--add-seccomp-fd`) makes `unshare` and `clone` with
  `CLONE_NEWUSER` fail with `EPERM`, and `clone3` with `ENOSYS` (its
  flags are behind a pointer; libc falls back to `clone`); x32 numbers
  are listed too. Otherwise package code has no seccomp filter.
- In that `/proc`, paths showing host-wide information are hidden
  (`bwrap::MASKED_PROC`): runc's default masked paths, plus files of mode
  0400 that root reads without capabilities (`kpage*`, `slabinfo`,
  `vmallocinfo`, `pagetypeinfo`), since the program may be uid 0 of the
  host. Files get the host's `/dev/null` bound `nodev` (opening fails
  with `EACCES`; the source is resolved on the host, so the image can't
  redirect it), directories a read-only tmpfs (bwrap's `--remount-ro
  /proc` doesn't reach it). Which exist is read from skl's own `/proc`.
  Rejected: making only some paths read-only as runc does (`/proc/sys`,
  `/proc/sysrq-trigger`, …), a list that misses what it doesn't name;
  package code has no need to write `/proc`. Workers get no `/proc`.
- If a sandboxing layer is unavailable, skl refuses to run. The escape
  hatch is the `insecure` cargo feature (off by default), which adds
  `--insecure-no-namespaces` (workers run without bwrap and get their
  directories as fds), `--insecure-no-landlock` and
  `--insecure-no-seccomp`; workers reject the last two in builds without
  it.
- Checked on Linux 7.2: `FICLONE` works across bind mounts of the same
  filesystem, including from a read-only bind mount, so a mount namespace
  can bind the store read-only and the image separately. Landlock doesn't restrict btrfs ioctls (subvolume creation
  succeeds where it blocks `mkdir`) or `FICLONE`.
- Tests of the layers themselves re-run the unit test binary as a child
  that confines itself (or under bwrap), since confinement can't be
  undone.

## Tests

- Integration tests build synthetic packages and skip themselves when
  the cargo target directory isn't on btrfs.
- Checks with real packages use a local repo by default
  (`scripts/test-mirror.sh`): a pinned day of the Arch Linux Archive
  (`archive.archlinux.org/repos/YYYY/MM/DD/`), 42 packages and their
  signatures plus that day's keyring, so results don't drift with the
  live repos and runs don't download from public mirrors again. It is
  fetched once into `tmp/test-cache` of the main checkout, shared by
  all worktrees (cloud sessions fetch it in the setup script), and
  served by one nginx over HTTP and HTTPS. Its test CA is added to the
  roots in use before (`SKL_CA_CERTS`, which cloud sessions need for
  their proxy, or the system's bundle), so one shell reaches both the
  test repo and live mirrors. nginx is
  what real mirrors run, with keep-alive, ranges and `ETag`/`If-Range`.
  Rejected: `python -m http.server` (none of those), a test server of
  our own (it would share skl's reading of HTTP, so it tests no
  interop; fault injection stays in `tests/download.rs`), caddy (less
  like real mirrors). The live mirror is still for occasional checks.

## Build

- Dev builds keep only line tables as debug info: backtraces still have
  files and lines, and `target/` stays smaller.
