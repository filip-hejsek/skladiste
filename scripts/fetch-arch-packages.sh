#!/bin/bash
# Download the current versions of the named Arch Linux packages (no
# dependency resolution) and their signatures (.sig) into DEST.
#
# Usage: fetch-arch-packages.sh DEST PKGNAME...
# Environment: ARCH_MIRROR (default https://geo.mirror.pkgbuild.com)
set -euo pipefail

if (($# < 2)); then
	echo "usage: $0 DEST PKGNAME..." >&2
	exit 1
fi

mirror=${ARCH_MIRROR:-https://geo.mirror.pkgbuild.com}
repos=(core extra)
dest=$1
shift
mkdir -p "$dest/db"

# Repo databases are cached in DEST/db; delete them to refresh.
for repo in "${repos[@]}"; do
	db="$dest/db/$repo"
	if [[ ! -d $db ]]; then
		curl -fsSL "$mirror/$repo/os/x86_64/$repo.db" -o "$db.db"
		mkdir -p "$db"
		tar -xf "$db.db" -C "$db"
		rm "$db.db"
	fi
done

# Print "name repo filename" for every package in the cached databases.
index() {
	for repo in "${repos[@]}"; do
		for desc in "$dest/db/$repo"/*/desc; do
			awk -v repo="$repo" '
				prev == "%NAME%" { name = $0 }
				prev == "%FILENAME%" { file = $0 }
				{ prev = $0 }
				END { print name, repo, file }
			' "$desc"
		done
	done
}

declare -A available
while read -r name repo file; do
	available[$name]="$repo/os/x86_64/$file"
done < <(index)

for name in "$@"; do
	path=${available[$name]:-}
	if [[ -z $path ]]; then
		echo "package not found: $name" >&2
		exit 1
	fi
	file="$dest/${path##*/}"
	if [[ ! -f $file ]]; then
		echo "fetching ${path##*/}" >&2
		curl -fsSL "$mirror/$path" -o "$file.part"
		mv "$file.part" "$file"
	fi
	if [[ ! -f $file.sig ]]; then
		curl -fsSL "$mirror/$path.sig" -o "$file.sig.part"
		mv "$file.sig.part" "$file.sig"
	fi
	echo "$file"
done
