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
  frontends (`src/arch.rs`) that produce a `manifest::Package`.
- Written in Rust.

## Store

- Objects are addressed by the BLAKE3 hash of their content: a modern
  hash function considered secure. There was no strong preference over
  SHA-256.
- Rejected for now: the fs-verity digest as the content address. fs-verity
  is left for later, so there's no need to tie the store to it now.
- Layout: `objects/ab/cdef…` (read-only, mode 0444), `packages/<id>.json`
  for imported manifests, `tmp/` for objects being written. Objects are
  written to `tmp/` while hashing, then renamed into place unless an
  identical object already exists.
- An imported package is identified by the BLAKE3 hash of its archive
  file, so re-importing the same file is skipped.
- Manifests are JSON; hashes and xattr values are hex strings.

## Arch frontend

- Only zstd-compressed packages are supported, as current Arch packages
  use zstd.
- Package name and version come from `.PKGINFO`; other metadata files
  (`.MTREE`, `.BUILDINFO`, `.INSTALL`, `.CHANGELOG`) are ignored for now.
- Owner, mode and mtime come from the tar headers; xattrs come from
  `SCHILY.xattr.*` PAX records, as written by bsdtar.

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

## Sandboxing

- Goal: every part of skl runs with only the access it needs, using
  namespaces, Landlock and seccomp. Work that needs different access
  (parsing untrusted archives, writing the store, writing an image,
  running package code, network) goes in separate processes. See the
  Sandboxing section of TODO.md for what isn't done yet.
- Library code works on file descriptors, not paths: `Store` holds a
  directory fd, frontends read from a `Read` and write file contents to
  an `ObjectSink`, and the installer uses only the store fd and the
  image root fd. Only the CLI opens paths.
- Workers (`src/worker.rs`) are started by re-executing the `skl` binary
  (`/proc/self/exe`; tests pass `CARGO_BIN_EXE_skl`) with the hidden
  `__worker` subcommand, which `main` checks before parsing arguments.
  A fresh exec is single-threaded and inherits no memory; fork without
  exec is unsafe in a multithreaded process. Both ends are the same
  binary, so the protocol needs no stability. The environment is cleared
  and the working directory is `/`.
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
  namespaces; `--die-with-parent` and `--new-session`. bwrap exits with
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
  user namespace mapping only skl's uid and gid, with no capabilities and
  `--disable-userns`. Xattrs that need `CAP_SYS_ADMIN` (`trusted.*`,
  `security.*` other than `security.capability`) are counted as failures.
- Workers confine themselves (`src/sandbox.rs`): `no_new_privs`, then
  Landlock (all filesystem access handled, plus TCP and the abstract
  socket and signal scopes; only the given directory fds are allowed),
  then a seccomp allowlist that kills the process on any other system
  call. Allowlisting also rejects x32 system calls. `fcntl` is allowed
  only with `F_GETFD`, which debug builds use when closing fds; `ioctl`
  only with listed request numbers.
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
  can block the other. Each object is `BEGIN` with its size, then
  `CHUNK`s of exactly that many bytes; an `ERROR` can come between
  chunks, e.g. when the archive is corrupt in the middle of a file.
  The supervisor writes and hashes the objects as they arrive.
- Frontends get no hashes: `ObjectSink::add_object` returns an
  `ObjectId`, the object's position in the stream, and the manifest
  (`Package<ObjectId>`) refers to files by id. The supervisor resolves
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
  `Store::add_object` instead of `io::copy`'s 8 KiB (0.75 s instead of
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
  `SIGSYS` is reported as a blocked system call.
- A package archive is opened once, hashed for its id, and the same open
  file is parsed, so the manifest always matches the id.
- Package code (install scripts, hooks) runs under an existing sandbox
  tool, bubblewrap for now (minijail or nsjail would also do). Rejected:
  setting up namespaces ourselves; no clear benefit for more code. Workers
  running skl's own code also start under bubblewrap and add Landlock and
  seccomp themselves.
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

## Build

- Dev builds keep only line tables as debug info: backtraces still have
  files and lines, and `target/` stays smaller.
