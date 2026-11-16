# Principles

What guides design decisions in skl, for people and agents alike. Keep
this file short enough to read in full every time. Concrete decisions
are in DECISIONS.md.

- **Least privilege.** Each part of skl runs with only the access it
  needs. Untrusted input (archives, repo databases, package code) is
  handled in sandboxed processes, and what they return is checked. If a
  sandboxing layer is missing, skl refuses to run rather than run with
  less protection.
- **The trusted side names things.** A worker sends data; the supervisor
  hashes it and decides where it goes. Nothing a worker claims about
  content (a hash, a size) is taken on trust.
- **Pipeline across processes.** Data between processes flows one way,
  without a round trip per item, and is buffered at both ends. A worker
  refers to what it sent by its position in the stream, and the receiver
  resolves that. One-way flow also keeps blocking I/O free of deadlocks:
  no cycles, also not through the supervisor's threads.
- **File descriptors, not paths.** Library code works on fds it is given;
  only the CLI opens paths. This is what lets parts of skl run sandboxed.
- **The core doesn't know package formats.** Format-specific code lives
  in frontends that produce the core's manifest.
- **Measure before choosing for performance.** Record the numbers with
  the decision, including for rejected alternatives.
- **Internal protocols are free to change.** Workers are the same binary
  as the supervisor, so wire formats need no stability. What deserves
  care is the shape of APIs and who trusts whom, which are hard to
  change later.
