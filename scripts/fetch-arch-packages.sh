#!/bin/bash
# Download the current versions of the named Arch Linux packages and
# their dependencies (transitively, ignoring versions), with signatures
# (.sig), into DEST. Prints the paths of the package files. With --urls,
# prints their URLs instead and downloads only the repo databases.
#
# Usage: fetch-arch-packages.sh [--urls] DEST PKGNAME...
# Environment: ARCH_MIRROR (default https://geo.mirror.pkgbuild.com)
set -euo pipefail

urls=
if [[ ${1:-} == --urls ]]; then
	urls=1
	shift
fi
if (($# < 2)); then
	echo "usage: $0 [--urls] DEST PKGNAME..." >&2
	exit 1
fi

mirror=${ARCH_MIRROR:-https://geo.mirror.pkgbuild.com}
repos=(core extra)
dest=$1
shift
mkdir -p "$dest/db"

# Repo databases are cached in DEST/db (as downloaded and extracted);
# delete it to refresh.
for repo in "${repos[@]}"; do
	db="$dest/db/$repo"
	if [[ ! -d $db ]]; then
		curl -fsSL "$mirror/$repo/os/x86_64/$repo.db" -o "$db.db"
		mkdir -p "$db"
		tar -xf "$db.db" -C "$db"
	fi
done

# Print a line for every package in the cached databases ("P name
# repo/filename"), each of its dependencies ("D name dependency", without
# version constraints) and each name it provides ("V provided name").
index() {
	# Relative paths, so that a long DEST doesn't exceed the argument limit.
	for repo in "${repos[@]}"; do
		(cd "$dest/db/$repo" && awk -v repo="$repo" '
			function flush() {
				if (name != "") print "P", name, repo "/os/x86_64/" file
				for (i = 1; i <= nd; i++) print "D", name, deps[i]
				for (i = 1; i <= np; i++) print "V", provs[i], name
				name = ""; nd = 0; np = 0
			}
			FNR == 1 { flush() }
			/^%.*%$/ { section = $0; next }
			$0 == "" { section = ""; next }
			{ v = $0; sub(/[<>=].*/, "", v) }
			section == "%NAME%" { name = $0 }
			section == "%FILENAME%" { file = $0 }
			section == "%DEPENDS%" { deps[++nd] = v }
			section == "%PROVIDES%" { provs[++np] = v }
			END { flush() }
		' ./*/desc)
	done
}

declare -A available depends provider
while read -r kind a b; do
	case $kind in
	P) [[ -n ${available[$a]:-} ]] || available[$a]=$b ;;
	D) depends[$a]+=" $b" ;;
	V) [[ -n ${provider[$a]:-} ]] || provider[$a]=$b ;;
	esac
done < <(index)

# Resolve the named packages and their dependencies, transitively. A
# dependency is a package name or, failing that, something a package
# provides (the first one found).
declare -A wanted
queue=("$@")
order=()
while ((${#queue[@]})); do
	name=${queue[0]}
	queue=("${queue[@]:1}")
	if [[ -z ${available[$name]:-} ]]; then
		if [[ -z ${provider[$name]:-} ]]; then
			echo "package not found: $name" >&2
			exit 1
		fi
		name=${provider[$name]}
	fi
	[[ -z ${wanted[$name]:-} ]] || continue
	wanted[$name]=1
	order+=("$name")
	read -ra deps <<<"${depends[$name]:-}"
	queue+=("${deps[@]}")
done

for name in "${order[@]}"; do
	path=${available[$name]}
	if [[ -n $urls ]]; then
		echo "$mirror/$path"
		continue
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
