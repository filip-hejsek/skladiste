#!/bin/bash
# pacman's downloads of a synthetic workload, to compare with
# examples/download.rs (planning/BENCHMARKS.md). Runs in netsim.sh:
#
#   scripts/netsim.sh --mirror ... -- scripts/pacman-bench.sh DIR N
#
# DIR is what `netsim.sh files` made, N pacman's ParallelDownloads. The
# mirrors are NETSIM_MIRRORS, in order (pacman takes each file from the
# first one that has it), and their CA is SKL_CA_CERTS, bind-mounted over
# the system's bundle in a mount namespace of its own. pacman runs as root
# of the user namespace, without its download user and sandbox, with a
# database and cache of its own. Prints the time of `pacman -Sw`, which
# includes checking each file's SHA-256 after the downloads; the database
# is synced before.
set -euo pipefail

if (($# != 2)); then
	sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2
	exit 1
fi
dir=$(realpath "$1")
parallel=$2
: "${NETSIM_MIRRORS:?not run in netsim.sh}"

if [[ ${PACMAN_BENCH_NS:-} != 1 ]]; then
	PACMAN_BENCH_NS=1 exec unshare -m -- "$0" "$@"
fi
bundle=$(realpath /etc/ssl/certs/ca-certificates.crt)
mount --bind "$SKL_CA_CERTS" "$bundle"

work=$(mktemp -d "$(dirname "$dir")/pacman.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/db" "$work/cache"
{
	cat <<EOF
[options]
Architecture = auto
ParallelDownloads = $parallel
SigLevel = Never
DisableSandboxFilesystem
DisableSandboxSyscalls
[netsim]
EOF
	for m in $NETSIM_MIRRORS; do
		echo "Server = $m/f"
	done
} >"$work/pacman.conf"
pacman=(pacman --config "$work/pacman.conf" --dbpath "$work/db"
	--cachedir "$work/cache" --logfile /dev/null --noconfirm --noprogressbar)
"${pacman[@]}" -Sy >/dev/null

mapfile -t names < <(awk '{ n = $2; sub(/^f\//, "", n); sub(/-1-1-any\.pkg\.tar\.zst$/, "", n); print n }' "$dir/list")
start=$(date +%s.%N)
"${pacman[@]}" -Sw "${names[@]}" >"$work/out" 2>&1 || {
	tail -20 "$work/out" >&2
	exit 1
}
end=$(date +%s.%N)
files=$(find "$work/cache" -name '*.pkg.tar.zst' | wc -l)
bytes=$(du -sb --apparent-size "$work/cache" | cut -f1)
awk -v s="$start" -v e="$end" -v n="$files" -v b="$bytes" -v p="$parallel" 'BEGIN {
	t = e - s
	printf "pacman: %d files, %.1f MiB in %.2f s (%.1f Mbit/s), ParallelDownloads=%d\n",
		n, b / 1048576, t, b * 8 / 1e6 / t, p
}'
