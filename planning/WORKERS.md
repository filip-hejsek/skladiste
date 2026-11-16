# Workers that handle many items

Design for workers that process a queue of items instead of one input.
Nothing here is implemented yet; the first user is the download worker
per mirror (see Downloads in TODO.md).

Settled: the queues and the window, a worker's lifetime, and how a
download resumes. Open: limits and retries, and scheduling across
mirrors, which is where the remaining design work is.

## Queues

- A one-shot worker gets its whole input when it starts (an archive, a
  plan) and ends with one result, as now. A queue worker has one input
  queue and one output queue, both one-way and buffered at both ends.
- Results come in input order, so a result's position says which item
  it belongs to. More results than items submitted get the worker
  killed.
- There is no channel besides the queues: a worker never asks the
  supervisor for anything. When it can't go on with what it has, it
  reports where it stopped and exits, and the supervisor starts a new
  worker. Items that got no result go back to the scheduler.
- The supervisor never blocks writing input. It keeps at most a small
  window of items outstanding per worker (two: the worker has the next
  item at hand while the supervisor reacts to a result, so there is no
  round trip per item), and a window always fits in the socket buffer.
  A short window also leaves the assignment of items to workers open
  until the last moment (fallback, download order, whichever mirror is
  free).
- So one supervisor thread per worker is enough: it reads output and
  submits the next item when one finishes. It may block handing
  results downstream (e.g. to busy import jobs); the worker then stalls
  on its output, which is the wanted back-pressure. Nothing downstream
  waits on that thread except for its results, so there is no cycle.
- Cancelling: the supervisor kills the worker. (For the download
  worker, shutting down the network socket would be gentler, if the
  supervisor kept a copy of it; not decided.) With a window of two,
  queued items aren't worth cancelling one by one.

## Download worker

- A worker lives as long as its connection. The supervisor opens the
  connection and starts the worker with it, as now; when the server
  closes it (keep-alive request limits, timeouts), the worker reports
  that as the result of the item in progress and exits. The supervisor
  connects again and starts a new worker.
- An item is a path, and for a continuation also an offset and a
  validator. The output for an item is start, chunks, end. The start
  message carries the length, if the response gives one, and a
  validator to resume with, if there is a usable one.
- Resuming: when the connection ends in the middle of a body, the
  supervisor submits the item again with the offset, which is its own
  count of the bytes it received, and the validator from the start
  message. The validator is opaque to the supervisor, which only bounds
  its length and requires printable ASCII, so it can't break a request
  head.
  - The worker offers a validator only if it is strong: an `ETag` that
    isn't weak (`W/`), or, only if there is no `ETag` at all, a
    `Last-Modified` at least a second older than the response's `Date`.
    It is sent in `If-Range`. This keeps an honest mirror that updated
    the file between the requests (e.g. a repo database, which is
    unsigned) from producing a file joined from two versions.
  - The worker accepts a `206` whose `Content-Range` starts at the
    offset. If the first response gave a length (the supervisor passes
    it along), the range must end at its last byte and the total must
    match.
  - A `200` means the file changed. The item carries a flag from the
    supervisor that says what to do then: fail the item, or download
    the new file from the beginning. In that case the start message
    says that this isn't a continuation, and the supervisor discards
    the bytes it had. This probably counts as a strike (see Limits).
  - Without a validator, or when resuming fails, the file is fetched
    again from the beginning.
- A request that fails before any response byte arrives, typically on
  a connection the server closed while the worker was idle, is safe to
  submit again on a new connection.
- Redirects are a result too: the worker reports the target and the
  supervisor decides whether to submit it to that origin's worker.
- Progress needs nothing from the worker: the supervisor writes the
  file and sees every byte.
- Cost compared with handing a new socket to a running worker: a
  worker start per reconnect and a lost TLS session cache. Reconnects
  are expected to be rare and each already costs a TCP and TLS
  handshake. To measure before implementing: the time of a worker
  start on its own. If it matters, an input item can carry a socket
  (`SCM_RIGHTS` on the input queue), which still needs no other
  channel.

## Status mailbox

An option kept open for workers whose progress the supervisor can't
see in their output (not the download worker).

- The supervisor creates a small memfd of fixed size, sealed against
  shrinking and growing, and passes it to the worker, which maps it
  before confining itself. The worker updates it with plain memory
  writes: no system calls, nothing that can fill up or block, and no
  flow control, since only the latest state exists.
- The supervisor reads it with `pread` whenever it wants to display
  progress, at its own rate. It doesn't map it, so the worker can't
  change values between a check and a use.
- The content is untrusted and may be torn (the worker can write
  during the read): a fixed layout of numbers, each bounded when read.
  It is for display only and never feeds into limits or decisions. A
  sequence counter could make reads consistent, but a wrong number on
  a progress line isn't worth it.

## Limits and retries

Not settled. The supervisor opens every connection itself and counts
everything on its side, so no claim by a worker is involved. A sketch:

- A connection should make progress: a file that passes validation, or
  more bytes of the item in progress than the supervisor had before.
  One that makes none is a strike, and the next connection to that
  mirror waits, with a growing delay.
- A file that fails validation is a strike as well. It can be a
  corrupted transfer, a corrupt copy on the mirror or a compromised
  worker, so one failure only means the file is fetched again, from
  another mirror if there is one.
- Strikes are capped per mirror and aren't reset by results that
  passed in between; at the cap the mirror isn't used further. This
  keeps a worker from making `skl` hammer a mirror, and from feeding
  it bad files again and again.
- Bytes of a file that isn't validated yet count as progress only up
  to its size where that is known beforehand, and for an unsigned file
  (a repo database) there is no validation at all. What bounds those
  is open.

Scheduling across mirrors (which mirror gets which file, when to fall
back, how this meets largest-import-first) is open too; see Downloads
in TODO.md.

## Rejected

- A control socket next to the queues, for blocking requests from the
  worker (a new connection), advisory messages and cancel
  notifications. Its only concrete user was reconnecting, which a new
  worker does without a round trip, and the mailbox covers status. The
  design and what it cost are in rejected/control-socket.md.
- Any number of input and output queues per worker: an idle worker
  wouldn't know what to block on, and outputs could stall each other.
- A long input queue filled in advance: writing it can block, which
  with a thread that also reads the output is a deadlock, and it fixes
  the assignment of items too early.
- Resuming without a validator, or accepting a `200` and skipping its
  first bytes: signatures catch a joined package, but nothing catches
  a joined database.
