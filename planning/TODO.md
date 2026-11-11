# TODO

Plans and open questions. Decisions already made are in DECISIONS.md;
known bugs are in BUGS.md.

Next priorities: dependency resolution, then install scripts and hooks.

## Arch frontend

- Dependency resolution from repo databases (`core.db`, `extra.db`),
  with Arch version comparison (`vercmp`) supplied by the frontend
  rather than the core.
- Download packages from a mirror in `skl` itself
  (`scripts/fetch-arch-packages.sh` does this for testing now).
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

- Worker processes: re-exec `/proc/self/exe` with a hidden subcommand,
  passing only the needed fds. A fresh exec is single-threaded (needed
  for `unshare(CLONE_NEWUSER)`) and inherits no memory; fork without
  exec is unsafe in a multithreaded process. Both ends are the same
  binary, so the protocol needs no stability.
- Unpacker worker (frontends): gets the archive fd and a socket, no
  filesystem or network access, tight seccomp allowlist. Sends entries
  and file contents over the socket; the supervisor writes and hashes
  them through `ObjectSink`. Later, to avoid the copy: the worker writes
  files and passes their fds, and the supervisor reflinks them into the
  store before hashing (the worker can't change a clone).
- When frontends run out of process, check that every file hash in the
  returned manifest was returned by the store during that import.
- Installer worker: Landlock with the store read-only and the image
  writable; possibly in a user namespace with a uid range mapped, for
  chown (see the ownership question under Images).
- Script runner: bubblewrap with user, mount, pid, net, ipc and uts
  namespaces, root is the image, no access to the store.
- Downloader (once skl downloads): network plus a download directory.
  Repo databases are untrusted archives and get parsed like packages.
  Sandboxing a signature verifier protects the host, not the verdict,
  so verification should use a memory-safe implementation.
- The escape hatch for missing sandboxing layers: a cargo feature (off
  by default) that adds runtime options to run without them.
