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

`--logs DIR` keeps each mirror's access log, with nginx's connection
number and the request's number on it, to see how a client uses its
connections.

Static neighbour entries, so the first connection pays no ARP round
trip. HTTPS by default, as the handshake is part of what a new
connection costs; the script's own CA (in `tmp/netsim/tls`) has the
mirrors' IPs as SANs. Checked: TCP connect and TLS each take one round
trip of the configured RTT, and two mirrors share a 20 Mbit/s downlink
at 18.7 Mbit/s in all.

Network profiles (`--profile`), from the calibration below: `fiber`
(730/720 Mbit/s, 19 ms), `router` (90 Mbit/s, 19 ms), `wifi-5ghz`
(60 Mbit/s, 20 ms), `wifi-24ghz` (45 Mbit/s, 20 ms), `wifi-weak`
(12 Mbit/s, 20 ms); the RTT is the whole round trip to geo, and
uplinks other than fiber's are guesses. One connection gets 638 Mbit/s
of `fiber` over HTTPS for a 200 MB file (653 over HTTP; netem's rate
includes headers), 528 for 50 MB (slow start). Still to add: a server,
and the jitter and retransmissions of weak WiFi.

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
each file's finish time, size and origin. `-n`, `--mirrors-at-once` and
`--connections-per-server` are skl's options of the same names.

## Instrumentation

Still to do: the download stage itself tracing each file's start and
each origin's connections, strikes and `404`s (the example only sees
finishes). Baseline: `curl --parallel --parallel-max N` on the same
URLs.

pacman as a comparison: `netsim.sh files` also writes a pacman repo of
the files (`f/netsim.db`, with their SHA-256), and
`scripts/pacman-bench.sh DIR N`, run in `netsim.sh`, times `pacman -Sw`
of all of them with `ParallelDownloads = N`, a database and cache of
its own, root of the user namespace without download user and sandbox,
and the netsim CA bind-mounted over the system's bundle. Its time
includes checking the SHA-256 after the downloads. pacman takes each
file from the first server that has it, so its parallel downloads are
connections to one origin.

## Sweeps

`N` = 1, 2, 3, 5, 8; for a given `N`, its split into mirrors and
connections per origin (for 4: 4×1, 2×2, 1×4); one connection per
origin (the scheduling before `--parallel-downloads`) as baseline. Each configuration about 5 times, interleaved with the
others; median and range are recorded, with the decision, in
DECISIONS.md.

First check of the setup (one run each, one connection per origin): the small
files at 20 ms RTT and 500 Mbit/s take 24.0 s from one mirror with
`-j1` and 12.05 s from two equal mirrors with `-j2`, as the round trips
predict.

Against pacman 7.1 (3 rounds, interleaved; the small files, 20 ms
RTT; skl with one connection per origin, as before
`--parallel-downloads`):

| link     | mirrors | skl              | pacman `ParallelDownloads`               |
|----------|---------|------------------|------------------------------------------|
| 500 Mbit | 1       | `-j1` 23.9-24.0 s | 1: 24.4-24.5 s, 2: 21.7-22.0 s, 5: 6.3-6.5 s, 8: 4.74-4.75 s |
| 500 Mbit | 2       | `-j2` 12.1 s      | 5: 6.3-6.4 s                              |
| 50 Mbit  | 1       | `-j1` 53.4 s      | 5: 33.3 s (46.6 Mbit/s)                   |

Over one connection both pay a round trip per file. pacman takes all
files from the first server, so a second mirror doesn't change its
time. At 50 Mbit/s its 5 connections almost fill the link, while skl
loses about 20 s to round trips. pacman with 2 is barely faster than with
1: its access log shows each of the two connections making a request
per two round trips for the first 12 s (about 23 a second each), and
then one going on alone; from 3 on (10.5 s with 3, 7.7 s with 4) it
uses all its connections evenly.

With `--parallel-downloads N` (3 rounds; same files and network):

| link     | mirrors | skl `-n N`                                       | pacman, same N |
|----------|---------|--------------------------------------------------|----------------|
| 500 Mbit | 1       | 1: 24.0 s, 2: 12.1 s, 5: 5.61-5.63 s, 8: 4.42-4.44 s | 24.4, 21.9, 6.3-6.5, 4.75 s |
| 500 Mbit | 2       | 2: 12.1 s (1+1), 5: 5.62-5.63 s (3+2)            | 5: 6.3-6.4 s   |
| 50 Mbit  | 1       | 5: 32.95-32.96 s (47.1 Mbit/s)                   | 33.3 s         |

Equal mirrors at the same RTT make no difference to the time, as
expected; the split (3 and 2 connections, about 200 requests each) is
from the access logs. Up to 5, time falls with N about as round trips
predict; from 5 to 8 it gains less, as transfer (3 s at 500 Mbit/s)
starts to dominate.

On the calibrated profiles (2 rounds, within 0.2 s; the small files,
one mirror):

| profile     | skl `-n`: 1 | 2      | 3     | 5      | 8      | 12     | 16     | pacman 5, 8, 16       |
|-------------|-------------|--------|-------|--------|--------|--------|--------|-----------------------|
| `fiber`     | 22.0 s      | 11.1 s | 7.5 s | 4.8 s  | 3.55 s | 2.97 s | 2.71 s | 5.5-5.7, 3.9, 3.0 s   |
| `wifi-5ghz` | 47.9 s      | 31.1 s |       | 27.6 s |        |        |        | 28.0 s                |
| `wifi-weak` | 156.9 s     |        |       | 136.1 s |       |        |        |                       |

The transfer alone takes about 2.3 s on `fiber`, 26 s on `wifi-5ghz`
and 130 s on `wifi-weak`. On fiber, more connections keep paying off
up to about 8 (5 to 8 saves 27 %, 8 to 16 another 24 %); over WiFi 2
already come within 20 % of the link, and 5 within 6 %.

## Real mirrors

- Calibration: `scripts/calibrate.sh LABEL [SERVER...]` (only bash,
  curl, tar and awk, so it runs on a host, in a container and on a
  server alike) measures per server new connections (TCP, TLS, first
  byte), requests over a kept connection, one package of about 10 MB
  over one connection and 4 at once, about 50 MB in all, and records
  the local link (WiFi band and signal where `iw` sees them; a
  container's virtual device is marked as such). Results with median
  and range go to `tmp/calibrate/LABEL-DATE.txt`. To run from each
  place, against `geo.mirror.pkgbuild.com` (the default) and a few of
  the nearest mirrors (`--mirrorlist FILE --top N` takes them from a
  mirror list).
- pasta: the container reaches the internet through pasta. TCP connect
  takes a real round trip (about 23-26 ms to geo over WiFi), so pasta
  doesn't complete handshakes locally; its effect on throughput is
  unknown. On ethernet, `calibrate.sh` on the host and in the
  container; if they differ beyond noise, validation runs on the
  host or the server instead.
- Calibration done so far (2026-11-22, the host, geo only, 10 samples
  each; medians):

  | place                        | request on a kept connection | TCP, TLS | 10 MB alone, 4 at once |
  |------------------------------|------------|----------|-----------------|
  | ethernet without the router  | 19.2 ms    | 16, 28 ms | 347, 387 Mbit/s |
  | ethernet through the router  | 18.9 ms    | 18, 28 ms | 88, 92 Mbit/s   |
  | WiFi 5 GHz, -67 dBm          | 20.0 ms    | 19, 31 ms | 63, 54 Mbit/s   |
  | WiFi 2.4 GHz, -21 dBm        | 19.0 ms    | 18, 34 ms | 50, 44 Mbit/s   |
  | WiFi 2.4 GHz, -58 dBm        | 20.5 ms    | 22, 94 ms | 44, 42 Mbit/s   |
  | WiFi 2.4 GHz, -73 dBm        | 21.4 ms    | 20, 32 ms | 24, 23 Mbit/s   |
  | WiFi 5 GHz, -86 dBm          | 19.2 ms    | 21, 33 ms | 14, 11 Mbit/s   |

  A web speed test without the router: 730 Mbit/s down, 721 up, 14 ms
  to a server in Prague, 3.7 ms jitter. The round trip to geo is the
  same everywhere (WiFi adds a millisecond or two); bandwidth varies
  50-fold. The router's port negotiates 100 Mbit/s. 4 at once gain
  nothing except on the direct link, so the link is the limit, not a
  limit per connection; there 10 MB is too short for slow start
  (`--size 50` instead). WiFi at -58 dBm on 2.4 GHz had handshakes up to
  240 ms (retransmissions, probably). Still to do: other mirrors than
  geo, a server, and the container on the direct link (pasta).
- Validation: only a few configurations chosen from the sweeps (the
  current behaviour, the chosen default, its closest alternative), from
  WiFi (place in the room and band recorded), ethernet (fiber, about
  500 Mbit/s) and a server. About 1-2 GB of traffic per place. The
  question is whether they rank as the simulation predicts.
