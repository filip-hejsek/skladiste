# Download benchmarks

How parallel downloads are measured, to choose their settings (TODO.md,
Downloads from mirrors). Most runs use simulated mirrors: reproducible,
independent of the internet connection, and they cost the mirrors no
bandwidth. Real mirrors calibrate the simulation and validate its
results.

## What is decided by it

The proposal: `N` parallel downloads, with a default that doesn't depend
on the number of CPUs (`-j` stays for CPU-bound jobs). The files are
spread over the first `N` usable mirrors with one connection each; with
fewer mirrors than `N`, the rest go to the mirrors in use as further
connections, up to a cap per origin. Mirrors at once and the cap per
origin can be set on their own. To be measured: the default `N`, and
whether more mirrors or more connections to the nearest ones do better.

Why it matters: requests aren't pipelined, so each file costs a round
trip to the server, and one connection per origin moves at most one file
per round trip. With many small files, that bounds throughput long
before bandwidth does.

## Simulated network

`scripts/netsim.sh`, run under `unshare -r` (no root needed; veth,
netem and ifb work in a user namespace here). Network namespaces:

- client: runs skl;
- router: the access link, shared by all mirrors (netem on both
  directions: rate, base RTT, jitter, loss; the queue size is set
  explicitly, as it shapes TCP at the bottleneck);
- one per mirror: nginx on its own IP, with the mirror's extra RTT and
  bandwidth (netem), and optionally a rate limit per connection, a
  connection limit, `keepalive_requests`, or `404` for some files (a
  mirror that isn't in sync).

Static neighbour entries, so the first connection doesn't pay an ARP
round trip. The test CA's certificate for the mirrors has their IPs as
SANs. Runs over HTTPS, as the handshake is part of what a new
connection costs.

Network profiles, calibrated from real measurements (below): fiber over
ethernet (about 500 Mbit/s), WiFi on 5 GHz and on 2.4 GHz (lower rate,
jitter, loss), a server (1 Gbit/s or more, low RTT), a slow link
(10-20 Mbit/s, 40-50 ms).

Mirror sets: one origin; 2-5 equal mirrors; one near mirror and farther
ones; one slow or rate-limited mirror among good ones; one that isn't
in sync.

## Workloads

- Small files: the sizes of 997 packages under 1 MB from a pacman cache
  after several upgrades (185 MiB, median 100 KB, 10th percentile
  23 KB, 90th 540 KB; most are Haskell rebuilds). Sizes only are kept
  in the repo; the names aren't needed. At 25 ms RTT the round trips
  alone are about 25 s over one connection, against 3 s of transfer at
  500 Mbit/s and 31 s at 50 Mbit/s.
- Mixed: the `%CSIZE%` distribution of core and extra in the snapshot,
  for upgrades that include large packages.
- End to end: the 42 packages of `build --fetch filesystem bash
  coreutils` from the snapshot, which includes the overlap of
  downloading and importing.

The synthetic workloads are random files of those sizes, downloaded by
a download-only example (`examples/`): `download_all` with sinks that
discard, so a sweep measures the network and not importing. It
dispatches to `worker::main` as `main.rs` does.

## Instrumentation

An environment variable makes the download stage trace each file
(start, end, origin, bytes) and each origin (connections opened,
strikes, `404`s), to see idle gaps and stragglers, not only the total.
Baseline: `curl --parallel --parallel-max N` on the same URLs.

## Sweeps

`N` = 1, 2, 3, 5, 8; for a given `N`, its split into mirrors and
connections per origin (for 4: 4×1, 2×2, 1×4); the current behaviour
as baseline. Each configuration about 5 times, interleaved with the
others; median and range are recorded, with the decision, in
DECISIONS.md.

## Real mirrors

- Calibration (little traffic): from each place, handshake times
  (`curl -w`: TCP connect, TLS, first byte) and one transfer of about
  10 MB over one connection, to `geo.mirror.pkgbuild.com` and a few of
  the nearest mirrors on the mirror status page.
- pasta: the container reaches the internet through pasta. TCP connect
  takes a real round trip (about 23-26 ms to geo over WiFi), so pasta
  doesn't complete handshakes locally; its effect on throughput is
  unknown. On ethernet, the same curl measurements on the host and in
  the container; if they differ beyond noise, validation runs on the
  host or the server instead.
- Validation: only a few configurations chosen from the sweeps (the
  current behaviour, the chosen default, its closest alternative), from
  WiFi (place in the room and band recorded), ethernet (fiber, about
  500 Mbit/s) and a server. About 1-2 GB of traffic per place. The
  question is whether they rank as the simulation predicts.
