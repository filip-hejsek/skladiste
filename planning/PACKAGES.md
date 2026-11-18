# Native packages

Design for skl's own package format: a manifest that refers to blobs
in the store, without an archive for now. Frontends convert their
packages to it, and the core builds images from a list of such
packages. Implemented: blobs and objects, canonical JSON,
manifests with sections, the Arch index, the build split,
overlays, package code as synthetic packages with reuse, and sync
records as objects, and the GC; image records are not.

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
  from 0; it contains no hashes. A reference in the body is a JSON
  object with the single key `#`, `{"#":0}`, and `#` is reserved for
  that: any other object with that key is an error. This is what lets
  the core find references in a body without its schema, to renumber
  them when writing and check them when reading (`src/object.rs`).
  Rejected: plain numbers for indices, which only code that knows the
  schema can tell from other numbers (a frontend's section couldn't be
  written canonically by the core).
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
  position in the stream they send (`BlobId`); the supervisor
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
- Bodies aren't readable on their own (`"blob":{"#":17}`); `skl show ID`
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
  the body (`object::encode`, through `Store::add_object`, which takes
  the body with references as indices into a list the caller collected
  in any order). Reading checks the hash, not the form: only the supervisor
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
  {"entries":[{"mode":493,"path":"usr/bin/bash","type":"file","blob":{"#":0},"size":1234,…}],
   "name":"bash","sections":{"arch":{"depends":["glibc","readline>=8.3"],…}},
   "version":"5.3.3-1"}
  ```

  - `name` and `version`: opaque strings, for messages; the core
    doesn't compare versions.
  - `entries`: `manifest::Entry`, with file contents as a reference
    and the size.
  - `sections`: one per format, by its name (`arch`), untyped JSON that
    the core keeps and doesn't read. Rejected: a generic type parameter
    for sections (it would leak into `install` and `store`, and the
    stored form is JSON anyway). In memory a section
    (`manifest::Section`) is its JSON with references as indices into
    its own list of blobs, so that it stands alone; the core renumbers
    them when writing the manifest and back when reading it. Sections
    refer only to blobs for now, without their sizes.
  - Overlay packages (below) also have `"overlay": true` and `removed`
    (`manifest::Overlay`; `diff::overlay` makes one from changes).
- Arch's section (`arch::ArchSection`): `depends`, `provides`,
  `conflicts` (in Arch's syntax, checked when importing as now), later
  `replaces`, and `install`, the reference to `.INSTALL` if the package
  has one. `.MTREE`, `.BUILDINFO` and `.CHANGELOG` stay ignored.
- `skl arch import` and builds keep identifying archives by their hash,
  so importing the same file again is skipped: an Arch index
  `packages/@arch/<repo>/<archive-hash>` holds the id of the manifest
  made from it (`Store::index_package`). It also lists `@local`. It is
  a GC root and a cache: a hash migration may drop it.

## Building

- The frontend works out what goes into an image: Arch resolves
  dependencies as now, from database entries and the Arch sections of
  imported packages (`resolve.rs` stays a format-independent library
  that Arch calls), imports what it chose, and hands the core an
  ordered list of package ids. The core installs them (`install::build`)
  without knowing their format. `build` may become a core verb.
- Ordinary packages are merged as now: a path in two packages is an
  error, except directories, where the first wins.

## Package code: synthetic packages

- After the packages are installed, Arch runs package code in the
  image in one `run::run_captured` (`arch::scripts`): each package's
  `post_install` (from `.INSTALL`) in dependency order (dependencies
  first, as pacman installs them: `resolve::install_order`, depth first
  from each package in the resolver's order, so a cycle is broken where
  it is first entered), then the `PostTransaction` hooks whose triggers
  match, by name. The packages are installed in the same order.
  `PreTransaction` hooks don't run in a new image: pacman reads hooks
  from the system before installing, and there are none yet.
- Hook files (`usr/share/libalpm/hooks/*.hook`, and
  `etc/pacman.d/hooks/*.hook`, which replace those of the same name)
  are package content, so the import worker parses them
  (`arch::hooks`, at most 64 KiB each; a hook that doesn't parse fails
  the import) into the Arch section, and the supervisor checks them.
  Triggers match as in alpm: `Install` operations only (the image is
  new), `Path` targets against the paths of all packages' entries
  (directories with a trailing `/`), `Package` targets against their
  names, with `fnmatch` without flags and the last matching pattern
  deciding (`!` excludes). Not supported: masking a hook with a symlink
  to `/dev/null`, and `Depends` (all packages are there).
- The code runs as one shell script that skl writes (`Plan::driver`),
  with `/bin/sh` from the image, as pacman's `SCRIPTLET_SHELL`. The
  script and the scriptlets (their blobs) are read-only files in the
  sandbox's `/run/skl` (bwrap `--ro-bind-data`), so nothing of them is
  left in the image. Each scriptlet is sourced in a subshell (they
  define functions of the same names) and its `pre_install` and
  `post_install` are called with the version if it defines them
  (`command -v`); hooks run their `Exec` words, quoted for the shell,
  with the targets on stdin if `NeedsTargets`. Failures are reported and
  the rest goes on, as in pacman. Output goes to skl's stderr with
  control characters escaped (`run::Options::escape_output`); stdin is
  `/dev/null`.
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
  adds to the store. Mount points that bwrap creates in the image
  (`dev`, `proc`, `run`, `tmp`, where no package has them) are changes
  like any other, so installing the synthetic package gives them too.
- Its Arch section (`ScriptsSection`) records what ran: the packages
  whose scripts ran and the hooks, in order. Its name is
  `@arch/scripts` and its version empty.
- Reuse: the inputs of package code are a build spec, an object
  with the ordered package ids and the version of the way skl runs the
  code (bumped when the environment or order changes). A cache entry
  `synthetic/<spec id>` holds the id of the synthetic package made from
  it. A build whose spec has an entry installs that package instead of
  running the code again, so building the same list twice gives the
  same image. `--rerun-scripts` runs the code anyway and replaces the
  entry. A run in which any code failed isn't recorded, so the next
  build runs it again. Packages without code get no spec and no
  synthetic package. Package code isn't deterministic (timestamps,
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
  records (not kept yet), and repo snapshots. Sync records are objects
  referring to the database (a blob), each with a named ref
  (`repos/<repo>/syncs/<time>`). Roots are small files holding an id,
  outside `objects/`. Build specs aren't roots: a synthetic cache entry
  is named by one and keeps it (and so its packages) alive.
- The GC (`Store::gc`, `skl gc`) is under Garbage collection in
  DECISIONS.md.

## Open

- Whether `removed` entries and overlays need an order among several
  overlays (only one per build now).
- How an upgrade reuses parts of an image: with one synthetic package
  per build, any change of the package list runs all package code
  again.
- The encoding of non-UTF-8 paths (above).
- A native archive (the manifest with its blobs and objects) for moving packages
  between stores; the ids stay those of the manifests.
