# Bugs

Known defects in the current code. Decisions are in DECISIONS.md; plans
are in TODO.md.

## Store

- Objects aren't fsynced before being renamed into place, so a crash can
  leave an object whose content doesn't match its name. A fix needs
  fsync (or syncfs once per import) before publishing objects and
  manifests.
- Files in `tmp/` are left behind if the process is killed during an
  import or download; nothing cleans them up.

## Arch frontend

- The archive is read three times from the same open file (signature
  check, hash, import). Someone who can write the file meanwhile can get
  unverified content imported. This affects package files given as
  paths; downloads are written only by the supervisor (in the store).
  Hashing while downloading would also save a read. A fix: verify, hash and import a private copy (a
  reflink clone or a sealed memfd), or hash and verify in one pass while
  copying.
- Paths and symlink targets that aren't valid UTF-8 are rejected.
- Sub-second mtimes from PAX headers are dropped.

## Installation

- A failed build leaves a partial image subvolume behind; the user has
  to remove it.
- When packages share a directory with different owner or mode, the
  first package's metadata is used silently; pacman warns in this case.
