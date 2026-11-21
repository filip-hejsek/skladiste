#!/bin/bash
# A local Arch repo for testing: a pinned snapshot of a few packages from
# the Arch Linux Archive, served by nginx over HTTP and HTTPS.
#
# Usage: test-mirror.sh lock DAY PACKAGE...|fetch|serve|stop
#   lock   Pin the snapshot in test-mirror.lock: the repo databases of
#          DAY (YYYY/MM/DD) in the archive, the named packages with their
#          dependencies and archlinux-keyring, with signatures, and the
#          SHA-256 of each file. Downloads only the databases: they have
#          the hashes of the packages and their signatures.
#   fetch  Download the snapshot pinned by test-mirror.lock into the
#          cache, unless it is there, and check the hashes. Files that
#          an earlier snapshot already had are reused.
#   serve  Start nginx (or reload it if it runs) and print export lines
#          for eval: the mirror URLs TEST_MIRROR (http) and
#          TEST_MIRROR_TLS (https), and what skl needs for them:
#          SKL_CA_CERTS and SKL_KEYRING (the snapshot's keyring, for
#          `skl arch keyring init`).
#          SKL_CA_CERTS is a bundle of the test CA and the roots in use
#          before (SKL_CA_CERTS if set, such as a proxy's CA, else the
#          system's bundle), so live mirrors keep working.
#   stop   Stop nginx.
#
# Environment:
#   SKL_TEST_CACHE  cache directory (default: tmp/test-cache in the main
#                   checkout, shared by all git worktrees)
#   SKL_TEST_PORT   HTTP port (default 8480); HTTPS uses the next one.
#                   Each port has its own nginx (in nginx/PORT/ of the
#                   cache), which serve and stop act on.
#   ARCH_ARCHIVE    the Arch Linux Archive or a mirror of it (default
#                   https://archive.archlinux.org)
set -euo pipefail

scripts=$(dirname "$(realpath "$0")")
lockfile=$scripts/test-mirror.lock
archive=${ARCH_ARCHIVE:-https://archive.archlinux.org}
archive=${archive%/}
repos=(core extra)
if [[ -z ${SKL_TEST_CACHE:-} ]]; then
	common=$(git -C "$scripts" rev-parse --path-format=absolute --git-common-dir)
	SKL_TEST_CACHE=$(dirname "$common")/tmp/test-cache
fi
cache=$SKL_TEST_CACHE
port=${SKL_TEST_PORT:-8480}
# Every file fetched, named by its SHA-256 and read-only; snapshots are
# trees of hard links to them.
pool=$cache/arch/files
# One nginx per port, each with its own config, pid file and logs, so
# that serving on another port leaves the others alone.
run=$cache/nginx/$port

# Read the lockfile: the day it pins, and the snapshot's directory, named
# by the day and the lockfile's hash, so that a changed lockfile is
# fetched anew.
load() {
	if [[ ! -f $lockfile ]]; then
		echo "$lockfile missing; run $0 lock DAY PACKAGE..." >&2
		exit 1
	fi
	day=$(sed -n 's/^# snapshot //p' "$lockfile")
	name=${day//\//-}-$(sha256sum <"$lockfile" | head -c 8)
	snap=$cache/arch/$name
}

# The archive's URL of a file of the snapshot. Repo databases are under
# the day; packages and their signatures are taken from the pool
# (packages/b/bash/...), since mirrors of the archive may redirect the
# files under the day elsewhere (umea.archive.pkgbuild.com to archive.org,
# which lacks recent ones).
url() {
	local path=$1
	local file=${path##*/} repo=${path%%/*}
	if [[ $file == "$repo.db" ]]; then
		echo "$archive/repos/$day/$path"
		return
	fi
	# The name precedes the version, release and architecture, none of
	# which contain a dash.
	local name=${file%.sig}
	name=${name%-*-*-*}
	echo "$archive/packages/${name:0:1}/$name/$file"
}

lock() {
	if (($# < 2)); then
		echo "usage: $0 lock DAY PACKAGE..." >&2
		exit 1
	fi
	day=$1
	shift
	if [[ ! $day =~ ^[0-9]{4}/[0-9]{2}/[0-9]{2}$ ]]; then
		echo "not a day (YYYY/MM/DD): $day" >&2
		exit 1
	fi
	mkdir -p "$pool"
	local work
	work=$(mktemp -d "$cache/arch/.lock.XXXXXX")
	# shellcheck disable=SC2064 # expand $work now
	trap "rm -rf '$work'" EXIT
	local repo
	for repo in "${repos[@]}"; do
		curl -fsSL "$(url "$repo/os/x86_64/$repo.db")" -o "$work/$repo.db"
		mkdir "$work/$repo"
		tar -xf "$work/$repo.db" -C "$work/$repo"
	done

	# Every package in the databases ("P name path sha256 pgpsig"), each
	# of its dependencies ("D name dependency", without version
	# constraints) and each name it provides ("V provided name").
	# Relative paths, so that the desc files don't exceed the argument
	# limit.
	local index
	index=$(for repo in "${repos[@]}"; do
		(cd "$work/$repo" && awk -v repo="$repo" '
			function flush() {
				if (pkg != "") print "P", pkg, repo "/os/x86_64/" file, sum, sig
				for (i = 1; i <= nd; i++) print "D", pkg, deps[i]
				for (i = 1; i <= np; i++) print "V", provs[i], pkg
				pkg = ""; sum = ""; sig = ""; nd = 0; np = 0
			}
			FNR == 1 { flush() }
			/^%.*%$/ { section = $0; next }
			$0 == "" { section = ""; next }
			{ v = $0; sub(/[<>=].*/, "", v) }
			section == "%NAME%" { pkg = $0 }
			section == "%FILENAME%" { file = $0 }
			section == "%SHA256SUM%" { sum = $0 }
			section == "%PGPSIG%" { sig = $0 }
			section == "%DEPENDS%" { deps[++nd] = v }
			section == "%PROVIDES%" { provs[++np] = v }
			END { flush() }
		' ./*/desc)
	done)
	local -A path sum sig depends provider
	local kind a b c d
	while read -r kind a b c d; do
		case $kind in
		P)
			if [[ -z ${path[$a]:-} ]]; then
				path[$a]=$b sum[$a]=$c sig[$a]=$d
			fi
			;;
		D) depends[$a]+=" $b" ;;
		V) [[ -n ${provider[$a]:-} ]] || provider[$a]=$b ;;
		esac
	done <<<"$index"

	# The named packages and their dependencies, transitively, ignoring
	# versions. A dependency is a package name or, failing that,
	# something a package provides (the first one found).
	# archlinux-keyring is added without its dependencies.
	local -A wanted
	local queue=("$@") order=() pkg deps
	while ((${#queue[@]})); do
		pkg=${queue[0]}
		queue=("${queue[@]:1}")
		if [[ -z ${path[$pkg]:-} ]]; then
			if [[ -z ${provider[$pkg]:-} ]]; then
				echo "package not found: $pkg" >&2
				exit 1
			fi
			pkg=${provider[$pkg]}
		fi
		[[ -z ${wanted[$pkg]:-} ]] || continue
		wanted[$pkg]=1
		order+=("$pkg")
		read -ra deps <<<"${depends[$pkg]:-}"
		queue+=("${deps[@]}")
	done
	pkg=archlinux-keyring
	[[ -n ${wanted[$pkg]:-} ]] || order+=("$pkg")

	local hash
	{
		cat <<-EOF
			# The test repo of scripts/test-mirror.sh: its files and their SHA-256.
			# Written by \`scripts/test-mirror.sh lock DAY PACKAGE...\` from the
			# day and packages below (with their dependencies, and
			# archlinux-keyring for its keyring); run it again to change them.
		EOF
		printf '# snapshot %s\n' "$day"
		printf '# package %s\n' "$@"
		{
			for repo in "${repos[@]}"; do
				hash=$(sha256sum <"$work/$repo.db" | head -c 64)
				printf '%s  %s\n' "$hash" "$repo/os/x86_64/$repo.db"
				# Downloaded already; keep it for fetch.
				chmod a-w "$work/$repo.db"
				mv "$work/$repo.db" "$pool/$hash"
			done
			for pkg in "${order[@]}"; do
				if [[ ! ${sum[$pkg]} =~ ^[0-9a-f]{64}$ || -z ${sig[$pkg]} ]]; then
					echo "no SHA-256 or signature for $pkg in the database" >&2
					exit 1
				fi
				hash=$(base64 -d <<<"${sig[$pkg]}" | sha256sum | head -c 64)
				printf '%s  %s\n' "${sum[$pkg]}" "${path[$pkg]}"
				printf '%s  %s\n' "$hash" "${path[$pkg]}.sig"
			done
		} | sort -k 2
	} >"$work/lock"
	mv "$work/lock" "$lockfile"
	rm -rf "$work"
	trap - EXIT
}

fetch() {
	load
	if [[ -d $snap ]]; then
		return
	fi
	mkdir -p "$pool"
	local work
	work=$(mktemp -d "$cache/arch/.fetch.XXXXXX")
	# shellcheck disable=SC2064 # expand $work now
	trap "rm -rf '$work'" EXIT
	local files
	files=$(grep -v '^#' "$lockfile")

	# The files not in the pool yet, downloaded by one curl.
	local hash path n=0
	while read -r hash path; do
		if [[ ! -f $pool/$hash ]]; then
			printf 'url = "%s"\noutput = "%s"\n' "$(url "$path")" "$work/$hash"
			n=$((n + 1))
		fi
	done <<<"$files" >"$work/curl.conf"
	if ((n)); then
		echo "fetching $n files of snapshot $day" >&2
		curl -fsSL --parallel --parallel-max 4 -K "$work/curl.conf" || true
	fi
	local failed=0
	while read -r hash path; do
		if [[ -f $pool/$hash ]]; then
			continue
		fi
		if [[ ! -f $work/$hash ]]; then
			echo "failed to download $path from $(url "$path")" >&2
			failed=1
		elif [[ $(sha256sum <"$work/$hash" | head -c 64) != "$hash" ]]; then
			echo "wrong SHA-256 of $path from $(url "$path")" >&2
			failed=1
		else
			chmod a-w "$work/$hash"
			mv "$work/$hash" "$pool/$hash"
		fi
	done <<<"$files"
	if ((failed)); then
		exit 1
	fi

	local tree=$work/tree
	while read -r hash path; do
		mkdir -p "$tree/${path%/*}"
		ln "$pool/$hash" "$tree/$path"
	done <<<"$files"
	# The snapshot's keyring, for SKL_KEYRING=$snap/keyring/archlinux.
	local keyring
	keyring=$(awk '$2 ~ /\/archlinux-keyring-[^\/]*\.pkg\.tar\.[^.\/]*$/ { print $2 }' <<<"$files")
	mkdir "$tree/keyring"
	tar -xf "$tree/$keyring" -C "$tree/keyring" \
		--strip-components=4 usr/share/pacman/keyrings
	# Another fetch may have finished meanwhile; then keep that one.
	mv -T "$tree" "$snap" 2>/dev/null || [[ -d $snap ]]
	rm -rf "$work"
	trap - EXIT
}

# A CA and a certificate for 127.0.0.1 and localhost signed by it.
certs() {
	local tls=$cache/tls
	if [[ -f $tls/server.pem ]]; then
		return
	fi
	mkdir -p "$tls"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$tls/ca.key" -out "$tls/ca.pem.part" -days 3650 \
		-subj "/CN=skl test mirror CA" \
		-addext basicConstraints=critical,CA:TRUE \
		-addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$tls/server.key" -out "$tls/server.csr" \
		-subj "/CN=localhost" 2>/dev/null
	openssl x509 -req -in "$tls/server.csr" -CA "$tls/ca.pem.part" \
		-CAkey "$tls/ca.key" -out "$tls/server.pem.part" -days 3650 \
		-extfile <(printf '%s\n' \
			basicConstraints=critical,CA:FALSE \
			keyUsage=critical,digitalSignature \
			extendedKeyUsage=serverAuth \
			subjectAltName=IP:127.0.0.1,DNS:localhost) 2>/dev/null
	rm "$tls/server.csr"
	mv "$tls/ca.pem.part" "$tls/ca.pem"
	mv "$tls/server.pem.part" "$tls/server.pem"
}

# Print the path of a bundle of the test CA and the roots in use before.
bundle() {
	local tls=$cache/tls base=${SKL_CA_CERTS:-}
	# Already one of these bundles (serve run again in the same shell).
	if [[ $base == "$tls"/roots-*.pem && -f $base ]]; then
		echo "$base"
		return
	fi
	if [[ -z $base ]]; then
		base=/etc/ssl/certs/ca-certificates.crt
	fi
	local roots
	roots=$(cat "$tls/ca.pem" "$base")
	local file
	file=$tls/roots-$(sha256sum <<<"$roots" | head -c 16).pem
	if [[ ! -f $file ]]; then
		echo "$roots" >"$file.part"
		mv "$file.part" "$file"
	fi
	echo "$file"
}

running() {
	[[ -f $run/nginx.pid ]] && kill -0 "$(cat "$run/nginx.pid")" 2>/dev/null
}

nginx_cmd() {
	local nginx
	nginx=$(PATH=$PATH:/usr/sbin command -v nginx) || {
		echo "nginx not found" >&2
		exit 1
	}
	"$nginx" -p "$run" -c "$run/nginx.conf" -e "$run/error.log" "$@"
}

serve() {
	load
	if [[ ! -d $snap ]]; then
		echo "snapshot $day not fetched; run $0 fetch" >&2
		exit 1
	fi
	certs
	mkdir -p "$run/temp"
	# Run as root, nginx's workers would become nobody, who may not be
	# able to read the cache.
	local user=
	if ((EUID == 0)); then
		user='user root;'
	fi
	cat >"$run/nginx.conf" <<EOF
$user
pid $run/nginx.pid;
worker_processes 2;
events {}
http {
	access_log $run/access.log;
	client_body_temp_path $run/temp/body;
	proxy_temp_path $run/temp/proxy;
	fastcgi_temp_path $run/temp/fastcgi;
	uwsgi_temp_path $run/temp/uwsgi;
	scgi_temp_path $run/temp/scgi;
	types {}
	default_type application/octet-stream;
	sendfile on;
	root $cache/arch;
	autoindex on;
	server {
		listen 127.0.0.1:$port;
	}
	server {
		listen 127.0.0.1:$((port + 1)) ssl;
		ssl_certificate $cache/tls/server.pem;
		ssl_certificate_key $cache/tls/server.key;
	}
}
EOF
	if running; then
		nginx_cmd -s reload
	else
		local p
		for p in "$port" $((port + 1)); do
			if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
				echo "port $p is in use, but not by nginx from $run; set SKL_TEST_PORT" >&2
				exit 1
			fi
		done
		nginx_cmd
	fi
	local roots
	roots=$(bundle)
	local path="$name/\$repo/os/\$arch"
	printf 'export %s=%q\n' \
		TEST_MIRROR "http://127.0.0.1:$port/$path" \
		TEST_MIRROR_TLS "https://localhost:$((port + 1))/$path" \
		SKL_CA_CERTS "$roots" \
		SKL_KEYRING "$snap/keyring/archlinux"
}

stop() {
	if running; then
		nginx_cmd -s quit
	fi
}

case ${1:-} in
lock)
	shift
	lock "$@"
	;;
fetch) fetch ;;
serve) serve ;;
stop) stop ;;
*)
	echo "usage: $0 lock DAY PACKAGE...|fetch|serve|stop" >&2
	exit 1
	;;
esac
