# Rejected: a control socket for long-lived workers

A design for workers that handle many items, with a control socket
next to their queues: blocking requests from the worker (e.g. for a
new connection), advisory messages and cancel notifications. It was
never implemented. The design in use is in ../WORKERS.md.

Why it was rejected: its only concrete user was the download worker
asking for a new connection, and that needs no round trip if a worker
lives only as long as its connection and resuming moves into the item.
Status updates fit a memfd mailbox better than advisory messages.
Without those users, what remains is the cost: a service thread per
worker, rules for who may block on what, a list of protocol
violations, and a wait for output before a limit can be replenished.

What it would be for: a worker with state too expensive to lose in a
restart that needs something from the supervisor in the middle of an
item. No such worker is planned.

The rest of this file is the design as it stood.

## Queues

- A one-shot worker gets its whole input when it starts (an archive, a
  plan) and ends with one result, as now. A persistent worker has
  exactly one input queue, so when idle it knows what to block on, and
  one output queue: with several outputs, the consumer of one could
  wait on a worker that is stalled until another is consumed.
- Queues carry work items and results one way and are buffered at both
  ends, as now. Every input item gets exactly one result, in input
  order, so a result's position says which item it belongs to. More
  results than items submitted get the worker killed.
- The queues don't know about control messages. A cancelled item is
  reported like a failed one. Everything needed to start work on an
  item comes over the input queue, never only over the control socket.
- No cycles in data flow. Take every worker and every supervisor thread
  as a node and every queue or blocking hand-off between them as an
  edge: the graph has no cycle. So the thread that receives a worker's
  output never blocks on writing that worker's input, directly or
  through other threads; a worker that is blocked writing output
  doesn't read input, and both would wait forever. The only round
  trip is a blocking request on the control socket (below).

## Control socket

- Only workers that need one have a control socket (`SOCK_SEQPACKET`).
  The seccomp allowlist needs `recvmsg` and `sendmsg` for it (workers
  have only `read` and `write` now).
- The supervisor never assumes that a control message arrives before a
  work item, or after one: they travel on different sockets, from
  different threads. A control message can only change work the worker
  could already do without it.
- Control messages overtake queued work, not running work. A worker
  reads all pending control messages (`MSG_DONTWAIT`):
  - after taking an item from the input queue (from its own buffer,
    not just the fd) and before starting work on it;
  - before each write to the output queue;
  - before sending a blocking request;
  - at other times when it has the opportunity.

  A worker blocked on an empty input queue has no work, so it doesn't
  read control then. A worker blocked on something else, e.g. a
  download stalled in the middle of a body, notices a cancel only at
  its next check. For a stalled download the supervisor can shut down
  the network socket (it keeps a copy of the fd) or kill the worker; a
  mirror that stalls is likely unusable anyway.
- Possible later: the worker `poll`s the control socket together with
  what it blocks on, to notice cancels while blocked on the network
  and to discard cancels that arrive after it went idle. Needs a
  seccomp rule.

### Messages from the worker

- Blocking requests (e.g. a new connection): for when the worker can't
  proceed without the response. Only one is in flight, and the worker
  sends nothing else until the response arrives. This is the only time
  a worker waits on the control socket; while it waits it keeps reading
  other control messages, so a response never waits behind unread
  notifications.
  - Before sending one, the worker flushes its output buffer (this may
    block on a slow consumer, which is fine: it isn't waiting on
    control yet) and states its output position in the request. See
    Limits for what the position is for.
  - A response either grants the request or refuses it (the connection
    failed, a limit is used up, the item was cancelled). After a
    refusal the item in progress fails. A granted connection comes as
    an fd attached to the response (`SCM_RIGHTS`).
- Advisory messages (e.g. progress): fire-and-forget. The supervisor
  may drop them and never relies on receiving them. The worker sends
  them with `MSG_DONTWAIT` and, when the socket is full, keeps only
  what is worth sending later (e.g. the latest progress).
  - They are throttled by an allowance from the supervisor, a
    cumulative count ("up to N in total"), so an update is idempotent.
    The supervisor counts advisory messages as they arrive and sends a
    new total only once the old one is used up, so at most one
    allowance update is outstanding; it throttles by delaying the
    update. Without allowance the worker holds off.
  - Content is untrusted like error messages: values are bounded and
    text is shown with control characters escaped. It is for display
    only and never feeds into limits.
  - The download worker doesn't need them: the supervisor writes the
    file and sees every byte.

### Messages from the supervisor

- Responses to blocking requests, sent with a blocking send: the
  worker is reading control while it waits, so a full buffer drains.
  At most one is in flight.
- Allowance updates, sent without blocking. If the buffer is full, the
  supervisor keeps the latest total and sends it once the socket is
  writable; dropping it would silence the worker for good.
- Notifications (e.g. cancels), sent without blocking. They are
  advisory too: every item gets a result anyway, so a dropped cancel
  only means the item runs to the end. If the buffer is full, the
  supervisor drops the notification, or queues it and sends it once
  the socket is writable. A full buffer isn't necessarily the worker's
  fault (an honest worker can't read control while blocked writing
  output to a slow consumer), so the worker isn't killed for it.

### Violations

These get the worker killed:

- a message while a request is outstanding (the supervisor checks the
  socket once more, without blocking, just before it sends the
  response; later it couldn't tell such a message from a legitimate
  one);
- advisory messages beyond the allowance;
- a message too large for the fixed-size receive buffer (`MSG_TRUNC`);
- attached fds;
- an output position beyond what the worker can have written (more
  results than items submitted, more bytes than the known sizes).

## Supervisor threads

- Each worker has a service thread that handles its blocking requests,
  so slow name resolution doesn't hold up other workers. Receiving
  control messages can be on that thread or on a shared polling
  thread.
- A request is answered independently of the queues: the supervisor
  needn't drain the output queue first and the worker needn't drain
  the input queue.
- Only the service thread does blocking sends on the control socket,
  and it never writes the worker's input queue: the worker may be
  blocked reading input and not reading control.
- The service thread never blocks on a queue. Its only wait on other
  threads is the one for validated output under Limits, and the
  threads that receive and validate output never wait on the service
  thread or the control socket, so this adds no cycle.

## Limits

Not worked out yet. Limits on requests keep a compromised worker from
making `skl` hammer a mirror, e.g. with reconnects. What is settled:

- The supervisor trusts no count from the worker. The number of items
  a worker really processed is somewhere between the results that
  passed validation and the inputs submitted, and a limit must hold
  for any value in between.
- A limit that is used up can be replenished by progress. This is what
  the output position in a request is for, and how it is used depends
  on whether the output is validated:
  - Validated output (e.g. files checked against signatures): the
    handler waits until the output up to the stated position has been
    received and validated, and counts only that. Otherwise an honest
    worker far ahead of the receiving side would be refused. A worker
    that states a position it hasn't written only stalls its own
    request. The wait happens only once a limit is used up, and
    depends on the receiving side making progress (e.g. import jobs
    being busy slows it down).
  - Output that isn't validated (e.g. repo databases): receiving it
    proves nothing, since a compromised worker can make up results. The
    supervisor takes the stated position as it is, without waiting,
    bounded by what it knows itself: the items submitted and their
    sizes where known beforehand.
- Submitting an item again doesn't raise a limit; limits count distinct
  items.
- A file that fails validation can be a corrupted transfer, a corrupt
  copy on the mirror or a compromised worker. One failure doesn't get
  the worker killed: the file is fetched again, from another mirror if
  there is one. Failures are capped per worker, and counted without
  regard to results in between that passed; at the cap the worker is
  killed and the mirror not used further, as a mirror that keeps
  serving bad files makes its worker useless anyway.
- Ideas for the reconnect limit: a growing delay between reconnects, a
  cap that depends on the distinct items submitted (keep-alive request
  limits), and a term per item bounded by its size, since one large
  file on a server with short timeouts can resume many times.

## Cancelling

Later; nothing needs it yet.

- The supervisor sends a notification naming an input position. A
  worker that hasn't started that item reports it as cancelled, also
  when the cancel arrives before the item itself. One that has started
  can stop at its next check; if it was about to send a blocking
  request, it reports the item as cancelled instead.
- The worker keeps the cancelled positions it hasn't reached yet. Only
  the trusted supervisor adds to that set, so it needs no bound.
- Whole workers are cancelled by killing them.

## Reconnecting the download worker

- When the server closes the connection, the worker asks for a new
  socket with a blocking request, stalling its output meanwhile, and
  closes the old one. A request that failed before any response byte
  is sent again; an item in progress resumes with a range request. The
  output stays continuous, so the queue needn't mention reconnects.
- The conditions for resuming (a strong validator in `If-Range`, the
  checks on the `206`) are the ones in ../WORKERS.md, applied inside
  the worker. If resuming fails, the item fails and can be submitted
  again from the beginning.

## Rejected within this design

- Any number of input and output queues per worker: an idle worker
  wouldn't know what to block on, and outputs could stall each other.
- Waiting for the output that is in the socket when the handler looks
  (`FIONREAD` plus a count of bytes received) instead of a position
  stated by the worker: the two values must be read in the right order
  or an honest worker hangs, and receiving output that isn't validated
  proves nothing anyway.
