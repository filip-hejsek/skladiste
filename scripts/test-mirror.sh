#!/bin/bash
# A local Arch repo for testing: a pinned snapshot of a few packages from
# the Arch Linux Archive, served by nginx over HTTP and HTTPS.
#
# Usage: test-mirror.sh fetch|serve|stop
#   fetch  Download the snapshot into the cache, unless it is there.
#   serve  Start nginx (or reload it if it runs) and print export lines
#          for eval: the mirror URLs TEST_MIRROR (http) and
#          TEST_MIRROR_TLS (https), and what skl needs for them:
#          SKL_CA_CERTS and SKL_KEYRING (the snapshot's keyring).
#          SKL_CA_CERTS is a bundle of the test CA and the roots in use
#          before (SKL_CA_CERTS if set, such as a proxy's CA, else the
#          system's bundle), so live mirrors keep working.
#   stop   Stop nginx.
#
# Environment:
#   SKL_TEST_CACHE  cache directory (default: tmp/test-cache in the main
#                   checkout, shared by all git worktrees)
#   SKL_TEST_PORT   HTTP port (default 8480); HTTPS uses the next one
set -euo pipefail

# The snapshot: a day of the Arch Linux Archive, and the packages taken
# from it with their dependencies, plus archlinux-keyring without them.
# systemd for its hooks (tmpfiles, sysusers) and what they make.
snapshot=2026/11/15
packages=(filesystem bash coreutils systemd)
archive=https://archive.archlinux.org/repos/$snapshot

scripts=$(dirname "$(realpath "$0")")
if [[ -z ${SKL_TEST_CACHE:-} ]]; then
	common=$(git -C "$scripts" rev-parse --path-format=absolute --git-common-dir)
	SKL_TEST_CACHE=$(dirname "$common")/tmp/test-cache
fi
cache=$SKL_TEST_CACHE
port=${SKL_TEST_PORT:-8480}
# The directory is named by the day and the package list, so that a
# changed list is fetched anew.
name=${snapshot//\//-}-$(printf '%s\n' "${packages[@]}" | sha256sum | head -c 8)
snap=$cache/arch/$name
run=$cache/nginx

fetch() {
	if [[ -d $snap ]]; then
		return
	fi
	mkdir -p "$cache/arch"
	local work
	work=$(mktemp -d "$cache/arch/.$name.XXXXXX")
	# shellcheck disable=SC2064 # expand $work now
	trap "rm -rf '$work'" EXIT
	echo "fetching snapshot $snapshot" >&2
	local urls keyring
	urls=$(ARCH_MIRROR=$archive "$scripts/fetch-arch-packages.sh" --urls "$work/resolve" "${packages[@]}")
	keyring=$(ARCH_MIRROR=$archive "$scripts/fetch-arch-packages.sh" --urls "$work/resolve" archlinux-keyring |
		grep /archlinux-keyring-)
	urls+=$'\n'$keyring
	local repo
	for repo in core extra; do
		mkdir -p "$work/$repo/os/x86_64"
		mv "$work/resolve/db/$repo.db" "$work/$repo/os/x86_64/$repo.db"
	done
	local url path
	while read -r url; do
		path=${url#"$archive/"}
		curl -fsSL "$url" -o "$work/$path"
		curl -fsSL "$url.sig" -o "$work/$path.sig"
	done <<<"$urls"
	rm -rf "$work/resolve"
	# The snapshot's keyring, for SKL_KEYRING=$snap/keyring/archlinux.
	mkdir "$work/keyring"
	tar -xf "$work/${keyring#"$archive/"}" -C "$work/keyring" \
		--strip-components=4 usr/share/pacman/keyrings
	# Another fetch may have finished meanwhile; then keep that one.
	mv -T "$work" "$snap" 2>/dev/null || [[ -d $snap ]]
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
	if [[ ! -d $snap ]]; then
		echo "snapshot $snapshot not fetched; run $0 fetch" >&2
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
fetch) fetch ;;
serve) serve ;;
stop) stop ;;
*)
	echo "usage: $0 fetch|serve|stop" >&2
	exit 1
	;;
esac
