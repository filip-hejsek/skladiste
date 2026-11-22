#!/bin/bash
# Measurements of real mirrors to calibrate the simulated network of
# netsim.sh (planning/BENCHMARKS.md). Needs only bash, curl, tar and awk,
# so it runs the same on a host, in a container and on a server; run it
# in each place, and on the host and in the container to see what pasta
# changes.
#
# Usage: calibrate.sh [OPTION...] LABEL [SERVER...]
#
# LABEL names the place and conditions (e.g. wifi-5ghz-desk, ethernet,
# server); it goes into the name of the results file. SERVERs are mirror
# URLs as in pacman's mirrorlist (https://host/$repo/os/$arch; a URL
# without $repo is taken as that already). Default:
# https://geo.mirror.pkgbuild.com/$repo/os/$arch.
#
# For each server:
#   connect  SAMPLES new connections, each a HEAD request of core.db: TCP
#            connect, TLS handshake, then the first byte of the response
#   reuse    SAMPLES HEAD requests over one kept connection: what each
#            file costs over a connection that stays open (one round trip
#            and the server's time)
#   single   a package of about SIZE MB over one connection; the rate
#            is from its first byte to its end
#   parallel PARALLEL other packages of that size at once, each over its
#            own connection: whether one connection or the link is the
#            limit; the rate is from the first byte of any to the end of
#            the last
# The packages are taken from core.db, which is downloaded once from the
# first server (about 130 KB).
#
# Options:
#   --samples N     handshakes and requests per server (default 10)
#   --size MB       size of the packages for throughput (default 10)
#   --parallel K    packages at once (default 4; 0 skips it)
#   --no-transfer   only connect and reuse (a few KB per server)
#   --mirrorlist F  also the first --top servers of a pacman mirrorlist
#   --top N         (default 5)
#
# Traffic per server with the defaults: about (1 + K) × SIZE MB, 50 MB.
#
# Results go to tmp/calibrate/LABEL-DATE.txt, one line per measurement
# (times in seconds), followed by a summary, which is also printed.
set -euo pipefail

scripts=$(dirname "$(realpath "$0")")
out_dir=$(dirname "$scripts")/tmp/calibrate

usage() {
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2
	exit 1
}

samples=10 size=10 parallel=4 transfer=1 mirrorlist='' top=5
servers=()
while (($#)); do
	case $1 in
	--samples | --size | --parallel | --mirrorlist | --top)
		(($# >= 2)) || usage
		case $1 in
		--samples) samples=$2 ;;
		--size) size=$2 ;;
		--parallel) parallel=$2 ;;
		--mirrorlist) mirrorlist=$2 ;;
		--top) top=$2 ;;
		esac
		shift 2
		;;
	--no-transfer)
		transfer=0
		shift
		;;
	-h | --help) usage ;;
	-*) usage ;;
	*)
		servers+=("$1")
		shift
		;;
	esac
done
((${#servers[@]})) || usage
label=${servers[0]}
servers=("${servers[@]:1}")
if [[ ! $label =~ ^[A-Za-z0-9._-]+$ ]]; then
	echo "LABEL may have only letters, digits and ._-: $label" >&2
	exit 1
fi
if [[ -n $mirrorlist ]]; then
	mapfile -t listed < <(sed -n 's/^[[:space:]]*Server[[:space:]]*=[[:space:]]*//p' "$mirrorlist" | head -n "$top")
	servers+=("${listed[@]}")
fi
if ((! ${#servers[@]})); then
	# shellcheck disable=SC2016 # pacman's variables, not the shell's
	servers=('https://geo.mirror.pkgbuild.com/$repo/os/$arch')
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out_dir"
results=$out_dir/$label-$(date +%Y%m%d-%H%M%S).txt

# The URL of core's directory on a server.
core() {
	local s=${1%/}
	s=${s//\$repo/core}
	echo "${s//\$arch/x86_64}"
}

record() {
	echo "$*" >>"$results"
}

# Where this machine is connected, as far as it can see.
{
	echo "# label $label"
	echo "# date $(date -Iseconds)"
	echo "# curl $(curl -V | head -1)"
	route=$(ip route get 1.1.1.1 2>/dev/null | head -1 || true)
	echo "# route $route"
	dev=$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<<"$route")
	if [[ -n $dev && -d /sys/class/net/$dev/wireless ]]; then
		echo "# link wireless $dev"
		if command -v iw >/dev/null; then
			iw dev "$dev" link 2>/dev/null | sed -n 's/^[[:space:]]*\(freq\|signal\|rx bitrate\|tx bitrate\):/# wifi \1:/p'
		fi
	elif [[ -n $dev && -e /sys/class/net/$dev && ! -e /sys/class/net/$dev/device ]]; then
		# Such as the one pasta gives a container: its speed means nothing.
		echo "# link $dev (virtual: no hardware device; the real link is on the host)"
	elif [[ -n $dev && -e /sys/class/net/$dev ]]; then
		echo "# link $dev (speed $(cat "/sys/class/net/$dev/speed" 2>/dev/null || echo '?') Mbit/s)"
	fi
	if [[ -n ${container:-} || -f /run/.containerenv || -f /.dockerenv ]]; then
		echo "# in a container"
	fi
} >"$results"

# Packages for throughput from the first server's core.db: those nearest
# SIZE MB, one for the single transfer and PARALLEL for the parallel one.
files=()
if ((transfer)); then
	curl -fsS --max-time 60 -o "$work/core.db" "$(core "${servers[0]}")/core.db"
	mkdir "$work/db"
	tar -xf "$work/core.db" -C "$work/db"
	mapfile -t files < <(
		awk -v want=$((size * 1000000)) '
			/^%.*%$/ { section = $0; next }
			$0 == "" { section = ""; next }
			section == "%FILENAME%" { file = $0 }
			section == "%CSIZE%" { d = $0 - want; if (d < 0) d = -d; print d, $0, file }
		' "$work"/db/*/desc | sort -n | head -n $((1 + parallel)) | awk '{ print $2, $3 }'
	)
fi

fmt='%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{num_connects} %{http_code}\n'

for server in "${servers[@]}"; do
	base=$(core "$server")
	host=${base#*://}
	host=${host%%/*}
	echo "measuring $host" >&2

	# New connections: TCP, TLS and the first byte, each from the step
	# before (name lookup is left out).
	for ((i = 0; i < samples; i++)); do
		curl -sS -I -o /dev/null --max-time 30 -w "$fmt" "$base/core.db" |
			awk -v h="$host" '$6 < 400 { printf "%s connect tcp=%.4f tls=%.4f first=%.4f\n", h, $2 - $1, $3 - $2, $4 - $3 }' >>"$results" ||
			record "$host connect failed"
	done

	# Requests over one kept connection; the first opens it.
	args=()
	for ((i = 0; i <= samples; i++)); do
		args+=(-o /dev/null "$base/core.db")
	done
	curl -sS -I --max-time 60 -w "$fmt" "${args[@]}" |
		awk -v h="$host" 'NR > 1 && $5 == 0 && $6 < 400 { printf "%s reuse request=%.4f\n", h, $4 }' >>"$results" ||
		record "$host reuse failed"

	((transfer)) || continue
	if ((${#files[@]} == 0)); then
		record "$host single failed (no packages in core.db)"
		continue
	fi
	read -r _ file <<<"${files[0]}"
	curl -sS -o /dev/null --max-time 300 \
		-w '%{size_download} %{time_starttransfer} %{time_total}\n' "$base/$file" |
		awk -v h="$host" '{ t = $3 - $2; printf "%s single bytes=%d time=%.3f mbit=%.1f\n", h, $1, $3, (t > 0 ? $1 * 8 / 1e6 / t : 0) }' >>"$results" ||
		record "$host single failed"

	((parallel > 0 && ${#files[@]} > 1)) || continue
	args=()
	for entry in "${files[@]:1}"; do
		read -r _ file <<<"$entry"
		args+=(-o /dev/null "$base/$file")
	done
	# All start at once; the rate is over the span from the first byte of
	# any to the end of the last, without the handshakes.
	curl -sS -Z --parallel-immediate --parallel-max "$parallel" --max-time 300 \
		-w '%{size_download} %{time_starttransfer} %{time_total}\n' "${args[@]}" |
		awk -v h="$host" '
			{ b += $1; k++; if (!first || $2 < first) first = $2; if ($3 > last) last = $3 }
			END { t = last - first; printf "%s parallel k=%d bytes=%d time=%.3f mbit=%.1f\n", h, k, b, last, (t > 0 ? b * 8 / 1e6 / t : 0) }
		' >>"$results" || record "$host parallel failed"
done

# Median and range of each measurement per server.
{
	echo "# summary: median (min-max), seconds; throughput in Mbit/s"
	awk '!/^#/ && NF > 2 && $3 ~ /=/ {
		for (i = 3; i <= NF; i++) {
			split($i, kv, "=")
			if (kv[1] == "bytes" || kv[1] == "k") continue
			print $1, $2 "." kv[1], kv[2]
		}
	}' "$results" | sort -k1,1 -k2,2 -k3,3g |
		awk '
			function flush() {
				if (n) printf "# %-36s %-16s %8.4f (%.4f-%.4f) n=%d\n", key1, key2, n % 2 ? v[(n + 1) / 2] : (v[n / 2] + v[n / 2 + 1]) / 2, v[1], v[n], n
				n = 0
			}
			$1 != key1 || $2 != key2 { flush(); key1 = $1; key2 = $2 }
			{ v[++n] = $3 }
			END { flush() }
		'
} | tee -a "$results"
echo "results in $results" >&2
