# Workers that handle many items

Design for workers that process a queue of items instead of one input.
The download worker, one per origin, is the only one so far
(`src/worker/download.rs`; what was decided for it is under Downloads
in DECISIONS.md).

Implemented: the queues and the window, a worker's lifetime, how a
download resumes, and a first limit on connections that get nowhere.
Open: the other limits, fallback to another mirror and scheduling
across mirrors, which is where the remaining design work is. Not
needed so far: the status mailbox.

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
  worker. Items that got no result go back to the scheduler (now: to
  the front of their origin's queue, in their order).
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
  queued items aren't worth cancelling one by one. The item queued
  behind the cancelled one wasn't started and goes back to the
  scheduler, so a cancel costs a worker start and whatever state the
  worker held (for the download worker, see Fallback).
- When something fails elsewhere in the run, the supervisor sends no
  more items. A file whose body has started is finished and kept; then
  the worker is killed, with the item behind it.

## Download worker

- A worker lives as long as its connection. The supervisor opens the
  connection and starts the worker with it; when the server closes it
  (keep-alive request limits, timeouts), the worker reports that as
  the result of the item in progress and exits. So it does after a
  response that ends the connection: one that says so, or one that
  isn't a `200` or `206`, whose body the worker doesn't read. The
  supervisor connects again and starts a new worker.
- An item is a path, and for a continuation also an offset, a
  validator and the file's length, if known. The output for an item is
  start, chunks, end. The start message carries the length, if the
  response gives one, and a validator to resume with, if there is a
  usable one. The end says how the request ended: done, the connection
  ended, the rest of the file wasn't served, or failed for good.
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
    the bytes it had. The flag comes with the download: a file whose
    content is known beforehand (a package, by the hash in its repo's
    database) fails, as another version can't be the one wanted;
    databases and URLs given to `skl import` start again. A server
    that can't continue downloads looks the same and gets the same.
  - Without a validator, or when resuming fails (a `416`, or a `206`
    that doesn't fit), the file is fetched again from the beginning,
    over a new connection.
  - Starting again isn't a strike by itself, but it is no progress
    until the file gets further than it was (see Limits).
- A request that fails before any response byte arrives, typically on
  a connection the server closed while the worker was idle, is safe to
  submit again on a new connection.
- Redirects are a result too: the worker reports the target and the
  supervisor decides whether to submit it to that origin's worker.
  Not implemented: a redirect fails the item, with the target in the
  message.
- Progress needs nothing from the worker: the supervisor writes the
  file and sees every byte.
- Cost compared with handing a new socket to a running worker: a
  worker start per reconnect and a lost TLS session cache. Reconnects
  are expected to be rare and each already costs a TCP and TLS
  handshake; a worker start takes about 4 ms (see Downloads in
  DECISIONS.md). If that ever matters, an input item can carry a
  socket (`SCM_RIGHTS` on the input queue), which still needs no other
  channel.

## Fallback to another mirror

A sketch; the thresholds are open. This was a large part of the
motivation for the rejected control socket (cancel notifications), so
it is worked out here as far as it bears on that choice.

- A slow download isn't cancelled when it turns slow: the file is
  started on a second mirror as well, and the slow one is cancelled
  only once the second is confirmed to make progress. If every mirror
  is slow (a slow network), nothing is confirmed and nothing is
  cancelled, so there is no loop of cancels.
- Both can then be healthy at once: the first recovers while the
  second gets going, and each has more items queued. One copy of the
  file has to go. The supervisor compares what the loser has left
  with the price of a reconnect:
  - little left: nothing is cancelled. Both finish, the second result
    is discarded, and both workers keep their connections.
  - otherwise: the one expected to finish later is killed. Its mirror
    isn't given up: a new worker with a new connection takes the next
    item.
- So a healthy mirror loses at most one connection per file that was
  started twice. No design avoids that: HTTP/1.1 can end a response
  early only by closing the connection, so a worker told to cancel
  would have to close and reconnect too. What a surviving worker
  would save is the worker start and the TLS session cache, the same
  cost as for a reconnect, with the same measurement to make and the
  same way out: the supervisor shuts down the network socket, the
  worker reports the item as ended and stays, and the next item
  carries a new socket. That is still no channel besides the queues.
- A cancel by the supervisor is no strike against the mirror and has
  no delay before the next connection (see Limits).

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

The supervisor opens every connection itself and counts everything on
its side, so no claim by a worker is involved.

Implemented:

- A connection should make progress: a file that passes validation, or
  more bytes of the item in progress than the supervisor ever had of
  it (so a file that starts again has to get past where it was). One
  that makes none is a strike, and the next connection to that origin
  waits: 1 s, doubled with each strike.
- Strikes are capped per origin (3 in a run) and aren't reset by
  results that passed in between; at the cap the origin isn't used
  further, which fails the run while a repo has one server. This keeps
  a worker from making `skl` hammer a mirror.
- A connection that can't be opened fails the run at once, as does a
  file that fails validation.

Not settled; a sketch:

- A file that fails validation should be a strike as well. It can be a
  corrupted transfer, a corrupt copy on the mirror or a compromised
  worker, so one failure should only mean that the file is fetched
  again, from another mirror if there is one, with the cap keeping the
  worker from feeding `skl` bad files again and again.
- Bytes of a file that isn't validated yet should count as progress
  only up to its size where that is known beforehand, and for an
  unsigned file (a repo database) there is no validation at all. What
  bounds those is open: now any new byte is progress, so a worker can
  still have `skl` connect once for each.
- Whether a connection that can't be opened should be a strike, and
  tried again.

Scheduling across mirrors (which mirror gets which file, when to fall
back, how this meets largest-import-first) is open too; see Downloads
in TODO.md.

## Rejected

- A control socket next to the queues, for blocking requests from the
  worker (a new connection), advisory messages and cancel
  notifications. Reconnecting is done by a new worker without a round
  trip, the mailbox covers status, and cancelling one of two downloads
  of a file costs the connection with or without a notification (see
  Fallback). The design and what it cost are in
  rejected/control-socket.md.
- Any number of input and output queues per worker: an idle worker
  wouldn't know what to block on, and outputs could stall each other.
- A long input queue filled in advance: writing it can block, which
  with a thread that also reads the output is a deadlock, and it fixes
  the assignment of items too early.
- Resuming without a validator, or accepting a `200` and skipping its
  first bytes: signatures catch a joined package, but nothing catches
  a joined database.
