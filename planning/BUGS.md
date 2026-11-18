# Bugs

Known defects in the current code. Decisions are in DECISIONS.md; plans
are in TODO.md.

## Store

- Blobs aren't fsynced before being linked into place, so a crash can
  leave a blob whose content doesn't match its name. A fix needs
  fsync (or syncfs once per import) before publishing blobs and
  manifests.
- A manifest being saved is left in `tmp/` if the process is killed
  before it's renamed into place; nothing cleans it up. The same goes for
  the snapshot `skl run` takes (`tmp/snapshot-*`).

## Arch frontend

- The archive is read three times from the same file (signature
  check, hash, import). Someone who can write the file meanwhile can get
  unverified content imported. This affects package files given as
  paths; downloads are written only by the supervisor (in the store).
  Hashing while downloading would also save a read. A fix: verify, hash and import a private copy (a
  reflink clone or a sealed memfd), or hash and verify in one pass while
  copying.
- Paths and symlink targets that aren't valid UTF-8 are rejected.
- Sub-second mtimes from PAX headers are dropped.

## Installation

- `skl run` doesn't report changes to the image's root directory itself
  (its mode, owner or xattrs).
- Without root, finding changes fails on a changed file that skl can't
  read and whose owner or group isn't skl's (e.g. in an image built as
  root).

- A failed build leaves a partial image subvolume behind; the user has
  to remove it.
- When packages share a directory with different owner or mode, the
  first package's metadata is used silently; pacman warns in this case.
