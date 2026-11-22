#!/bin/bash
# The packages an upgrade from one day to another downloads, for download
# benchmarks (planning/BENCHMARKS.md): those of core and extra whose
# version changed between the two days in the Arch Linux Archive.
#
# Usage: upgrade-sizes.sh OLD_DAY NEW_DAY [NAMES]
#
# Days are YYYY/MM/DD. With NAMES, a file of package names one per line
# (such as `pacman -Qq` prints), only those are counted, as for a system
# with those installed. Prints "SIZE FILE" lines (the compressed size and
# file name from NEW_DAY's database), smallest first, which
# `netsim.sh files` reads. The databases are kept in tmp/netsim/dbs.
#
# Environment:
#   ARCH_ARCHIVE  the Arch Linux Archive or a mirror of it (default
#                 https://archive.archlinux.org)
set -euo pipefail

scripts=$(dirname "$(realpath "$0")")
dbs=$(dirname "$scripts")/tmp/netsim/dbs
archive=${ARCH_ARCHIVE:-https://archive.archlinux.org}
archive=${archive%/}
repos=(core extra)

if (($# < 2 || $# > 3)); then
	sed -n '5,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2
	exit 1
fi

# "NAME VERSION CSIZE FILENAME" for each package of DAY's databases.
packages() {
	local day=$1 repo db
	if [[ ! $day =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}$ ]]; then
		echo "not a day (YYYY/MM/DD): $day" >&2
		exit 1
	fi
	for repo in "${repos[@]}"; do
		db=$dbs/${day//\//-}/$repo.db
		if [[ ! -f $db ]]; then
			mkdir -p "${db%/*}"
			curl -fsSL --connect-timeout 20 "$archive/repos/$day/$repo/os/x86_64/$repo.db" -o "$db.part"
			mv "$db.part" "$db"
		fi
		tar -xOf "$db" --wildcards '*/desc' | awk '
			function flush() {
				if (name != "") print name, version, size, file
				name = ""
			}
			/^%.*%$/ { section = $0; next }
			$0 == "" { section = ""; next }
			section == "%FILENAME%" { flush(); file = $0 }
			section == "%NAME%" { name = $0 }
			section == "%VERSION%" { version = $0 }
			section == "%CSIZE%" { size = $0 }
			END { flush() }
		'
	done
}

old=$(packages "$1")
new=$(packages "$2")
names=${3:-/dev/null}
awk -v filter="${3:+1}" '
	FILENAME == ARGV[1] { wanted[$1] = 1; next }
	FILENAME == ARGV[2] { before[$1] = $2; next }
	(!filter || $1 in wanted) && ($1 in before) && before[$1] != $2 { print $3, $4 }
' "$names" <(echo "$old") <(echo "$new") | sort -n
