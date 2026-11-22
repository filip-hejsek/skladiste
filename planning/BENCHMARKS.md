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

`scripts/netsim.sh` (usage in its header) runs a command in a client
network namespace behind simulated mirrors, all under `unshare -rn`
(no root needed: veth, bridges and netem work in a user namespace):

- the namespace of the script is the router: a bridge, whose port to
  the client is the access link shared by all mirrors (netem on both
  directions: rate, base RTT, jitter, loss, queue size);
- one namespace per mirror: nginx on its own IP (10.77.0.11 on), with
  the mirror's extra RTT and bandwidth (netem), and optionally
  `limit_rate` (per request, and only after the first write, so it
  slows large files only), a connection limit (`503` beyond it),
  `keepalive_requests`, or `404` for every Kth file (a mirror that
  isn't in sync).

Static neighbour entries, so the first connection pays no ARP round
trip. HTTPS by default, as the handshake is part of what a new
connection costs; the script's own CA (in `tmp/netsim/tls`) has the
mirrors' IPs as SANs. Checked: TCP connect and TLS each take one round
trip of the configured RTT, and two mirrors share a 20 Mbit/s downlink
at 18.7 Mbit/s in all.

Network profiles, to be calibrated from real measurements (below):
fiber over ethernet (about 500 Mbit/s), WiFi on 5 GHz and on 2.4 GHz
(lower rate, jitter, loss), a server (1 Gbit/s or more, low RTT), a
slow link (10-20 Mbit/s, 40-50 ms).

Mirror sets: one origin; 2-5 equal mirrors; one near mirror and farther
ones; one slow or rate-limited mirror among good ones; one that isn't
in sync.

## Workloads

Lists of sizes, which `netsim.sh files SIZES DIR` turns into sparse
files and the list the example reads. No list of anyone's packages is
kept in the repo.

- Upgrades: `scripts/upgrade-sizes.sh OLD_DAY NEW_DAY [NAMES]`, the
  packages of core and extra whose version changed between two days of
  the archive, optionally only those in NAMES (e.g. `pacman -Qq` of a
  real system, kept locally). Unfiltered, a week (2026/11/08 to
  2026/11/15) is 3190 packages and 29.7 GiB (median 300 KB, 2276 under
  1 MB), far more than one system downloads.
- Small files: a pacman cache's packages under 1 MB from 30 days
  (`find /var/cache/pacman/pkg -mtime -30 -size -1000k`): 997 files,
  185 MiB, median 100 KB, 10th percentile 23 KB, 90th 540 KB, most of
  them Haskell rebuilds. Not a whole upgrade (no large files), but the
  case where round trips dominate: at 25 ms RTT about 25 s over one
  connection, against 3 s of transfer at 500 Mbit/s.
- End to end: the 42 packages of `build --fetch filesystem bash
  coreutils` from the snapshot, which includes the overlap of
  downloading and importing.

`examples/download.rs` downloads a list from the mirrors given through
`download_all`, largest first as skl does, into sinks that only count,
so a sweep measures the network and not importing. It prints the time,
and files, bytes and the last finish per origin; `--trace FILE` writes
each file's finish time, size and origin.

## Instrumentation

Still to do: the download stage itself tracing each file's start and
each origin's connections, strikes and `404`s (the example only sees
finishes). Baseline: `curl --parallel --parallel-max N` on the same
URLs.

## Sweeps

`N` = 1, 2, 3, 5, 8; for a given `N`, its split into mirrors and
connections per origin (for 4: 4×1, 2×2, 1×4); the current behaviour
as baseline. Each configuration about 5 times, interleaved with the
others; median and range are recorded, with the decision, in
DECISIONS.md.

First check of the setup (one run each, current scheduling): the small
files at 20 ms RTT and 500 Mbit/s take 24.0 s from one mirror with
`-j1` and 12.05 s from two equal mirrors with `-j2`, as the round trips
predict.

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
