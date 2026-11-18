# Native packages

Design for skl's own package format: a manifest that refers to blobs
in the store, without an archive for now. Frontends convert their
packages to it, and the core builds images from a list of such
packages. Nothing of this is implemented yet; the code still has
`manifest::Package` with Arch's dependency fields, identified by the
hash of its archive (see Store and Arch frontend in DECISIONS.md).

Decided: objects with a reference header, manifests as objects
with untyped sections per format, the build split, one
synthetic package per build for package code, reused by default. Open
questions are at the end.

## Blobs and objects

- The store has two kinds of content. Blobs are file contents
  (`Store::add_blob`, `BlobSink`, `BlobId`). Objects are skl's own
  records (manifests, image records, sync records), which refer to
  blobs and other objects. Both are read-only and addressed by hash, in
  directories of their own (`blobs/ab/cdef…`, `objects/ab/cdef…`).
- An object is a header followed by a body. The header lists
  everything the object refers to, one per line, after a first line
  with the format, the hash algorithm and the count:

  ```
  skl-object 1 blake3 3
  b 4f2a…
  b 9c01…
  o e7d3…
  ```

  `b` is a blob, `o` an object, so following references needs no
  knowledge of the body. The body is canonical JSON (below) and refers
  to blobs and objects only by their index in the header, counting
  from 0; it contains no hashes.
- So the GC reads only headers: it starts from the roots (below) and
  follows `o` references, never parsing a body. Any part of a body,
  including a frontend's section, can refer to blobs and objects
  without the core knowing its schema. Rejected: hashes in the JSON,
  found by the core through fields it knows (each format's sections
  would need a schema the core understands, or couldn't refer to
  anything).
- An object's address is the hash of all its bytes, header included,
  in a different BLAKE3 mode from blobs (`derive_key("skl object")`),
  so a file whose bytes are a valid object never has the address of
  one.
- The header is canonical: each reference once, in the order of its
  first use in the body. Workers keep referring to blobs by their
  position in the stream they send (now `ObjectId`); the supervisor
  maps those positions to header indices when it writes the object, so
  the same content always gets the same address, also when a package
  has two identical files. The supervisor alone writes objects, so the
  trusted side still names things.
- Sizes of files are in the body, as the supervisor counted them when
  storing the blobs; the GC doesn't need them and a change of hash
  function doesn't change them.
- Reading an object checks that its bytes hash to its address and that
  every index in the body is within the header.
- Changing the hash function rewrites headers only: blobs are rehashed,
  then objects are rewritten in dependency order with the new algorithm
  in their headers and their bodies unchanged, then the roots. The
  objects' addresses change too (they hash their headers), but the core
  needs no knowledge of any body to do it, so a migration works for
  every frontend's sections. Keys from outside the store (e.g. the hash
  of an Arch archive, below) aren't covered; indexes keyed by them are
  recomputed or dropped.
- Text with hex hashes costs 65 bytes per reference, about 1 MB for a
  package of 17,000 files, no more than today's JSON with hashes inline.
  Binary would halve it but not be readable. Paths in the store and the
  ids skl prints are hex as before.
- Bodies aren't readable on their own (`"blob": 17`); `skl show ID`
  would print an object with its references resolved.

## Canonical JSON

- Equal values must give equal bytes, or equal packages get different
  ids. The body is written in one canonical form:
  - no whitespace outside strings;
  - keys sorted by their UTF-8 bytes, each once;
  - strings escape only `"`, `\` and control characters: `\b`, `\f`,
    `\n`, `\r`, `\t` where they exist, otherwise `\u00XX` with lowercase
    hex; everything else, including `/` and non-ASCII, is written as
    UTF-8;
  - numbers are integers (no fractions or exponents), without leading
    zeros or `+`, `-0` as `0`;
  - no floats anywhere in the format.
- This is `serde_json`'s compact output of a `serde_json::Value`
  (without `preserve_order`, its maps are sorted): serializing through
  `Value` sorts keys whatever the field order of the Rust types. Close
  to RFC 8785 (JCS), which differs only in sorting keys by UTF-16 code
  units (the same for ASCII keys) and in its rules for floats, which
  aren't allowed here.
- Objects are written only through one function that canonicalizes
  the body. Reading checks the hash, not the form: only the supervisor
  writes, so a check on every read would cost a second serialization of
  large manifests to protect against nothing. A `skl fsck` would check
  it.
- Open: paths that aren't UTF-8 (BUGS.md) can't be JSON strings; they
  would need an encoding of their own (e.g. bytes as an array, or
  escapes for invalid bytes).

## Manifests

- A package manifest is an object; its address is the package's id.
  Body:

  ```json
  {"entries":[{"mode":493,"path":"usr/bin/bash","type":"file","blob":0,"size":1234,…}],
   "name":"bash","sections":{"arch":{"depends":["glibc","readline>=8.3"],…}},
   "version":"5.3.3-1"}
  ```

  - `name` and `version`: opaque strings, for messages; the core
    doesn't compare versions.
  - `entries`: as `manifest::Entry` now, with file contents as a header
    index and size instead of a hash.
  - `sections`: one per format, by its name (`arch`), untyped JSON that
    the core keeps and doesn't read. Rejected: a generic type parameter
    for sections (it would leak into `install` and `store`, and the
    stored form is JSON anyway).
  - Overlay packages (below) also have `"overlay": true` and `removed`.
- Arch's section: `depends`, `provides`, `conflicts` (in Arch's syntax,
  checked when importing as now), later `replaces`, and `install`, the
  header index of `.INSTALL` if the package has one. `.MTREE`,
  `.BUILDINFO` and `.CHANGELOG` stay ignored.
- `skl arch import` and builds keep identifying archives by their hash,
  so importing the same file again is skipped: an Arch index
  `packages/@arch/<repo>/<archive-hash>` holds the id of the manifest
  made from it. It also lists `@local`. It is a GC root and a cache:
  a hash migration may drop it.
- The store format changes, so the implementation gets a new
  development version (`scripts/new-store-dev-version.sh`); there is no
  stable version to migrate from yet.

## Building

- The frontend works out what goes into an image: Arch resolves
  dependencies as now, from database entries and the Arch sections of
  imported packages (`resolve.rs` stays a format-independent library
  that Arch calls), imports what it chose, and hands the core an
  ordered list of package ids. The core installs them (`install::build`)
  without knowing their format. This is the build split in TODO.md;
  `build` may then become a core verb.
- Ordinary packages are merged as now: a path in two packages is an
  error, except directories, where the first wins.

## Package code: synthetic packages

- After the packages are installed, Arch runs package code in the
  image in one `run::run_captured`: each package's `post_install`
  (from `.INSTALL`) in dependency order (dependencies first, as pacman
  installs them; the resolver's order needs a topological sort), then
  the `PostTransaction` hooks whose triggers match the installed paths.
  `PreTransaction` hooks don't run in a new image: pacman reads hooks
  from the system before installing, and there are none yet.
- This differs from pacman, which runs each package's scripts right
  after extracting it, before later packages are there. Running them
  with every file present is simpler and needs one snapshot. Accepted:
  `pre_install` can't run before its own package's files (few Arch
  packages have one), so it runs in the same order, just before that
  package's `post_install`. One synthetic package per build for now;
  one per package (a snapshot and diff each) may be revisited if
  upgrades need finer granularity.
- What the code changed (`diff::Change`) becomes one synthetic package,
  an overlay: `"overlay": true`, `entries` with every added or modified
  entry, and `removed` with the paths it removed. An overlay's entries
  replace those of the packages before it, and `removed` takes away a
  path with everything beneath it; ordinary packages can't do either.
  Its hard links point only within itself, since the diff reports every
  path of a changed inode. Its blobs are the contents `run_captured`
  already adds to the store, which now no manifest refers to.
- Its Arch section records what ran: the packages whose scripts ran
  and the hooks, in order. Its name is fixed (e.g. `@arch/scripts`) and
  its version empty.
- Reuse: the inputs of package code are a build spec, an object
  with the ordered package ids and the version of the way skl runs the
  code (bumped when the environment or order changes). A cache entry
  `synthetic/<spec id>` holds the id of the synthetic package made from
  it. A build whose spec has an entry installs that package instead of
  running the code again, so building the same list twice gives the
  same image. An option (e.g. `--rerun-scripts`) runs the code anyway
  and replaces the entry. Package code isn't deterministic (timestamps,
  generated keys), so reuse is what makes rebuilds reproducible, and
  also means keys generated by scripts are shared between images built
  from the same spec.

## Image records

- An image is its spec plus its synthetic package: an object
  referring to both. Installing the spec's packages and then the
  synthetic package gives the image again, without running package
  code.
- Where image records are kept is still open (TODO.md, Images); not
  inside the image, since package code has run there.

## Roots

- What the GC starts from: the Arch index, the synthetic cache, image
  records, and repo snapshots. Sync records become objects
  referring to the database (a blob), with a named ref per
  repo snapshot. Roots are small files holding an id, outside `objects/`.
- GC itself is still in TODO.md, with the race against `add_object`
  (`add_blob` then).

## Open

- Whether `removed` entries and overlays need an order among several
  overlays (only one per build now).
- How an upgrade reuses parts of an image: with one synthetic package
  per build, any change of the package list runs all package code
  again.
- The encoding of non-UTF-8 paths (above).
- A native archive (the manifest with its blobs and objects) for moving packages
  between stores; the ids stay those of the manifests.
