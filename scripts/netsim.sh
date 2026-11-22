#!/bin/bash
# Simulated mirrors for download benchmarks (planning/BENCHMARKS.md): nginx
# in network namespaces behind a shaped access link, all in a user
# namespace, so no root is needed.
#
# Usage: netsim.sh [OPTION...] -- COMMAND [ARG...]
#        netsim.sh files SIZES DIR
#
# The first form runs COMMAND in the client's namespace, with these set:
#   NETSIM_MIRRORS  the mirrors' base URLs, separated by spaces, in the
#                   order of the --mirror options
#   SKL_CA_CERTS    the CA that signed the mirrors' certificate
# and removes the namespaces when it exits. Options:
#   --down RATE     downlink of the access link (default 500mbit)
#   --up RATE       uplink (default 50mbit)
#   --rtt MS        round trip of the access link (default 10)
#   --jitter MS     jitter on each direction of it (default 0; netem
#                   reorders packets with jitter)
#   --loss PCT      packet loss on the downlink (default 0)
#   --queue N       queue of the downlink in packets (default 1000)
#   --root DIR      directory every mirror serves (default
#                   tmp/netsim/files)
#   --http          plain HTTP instead of HTTPS
#   --logs DIR      keep each mirror's access log as DIR/mN.log: per
#                   request the time it ended, nginx's connection number,
#                   the request's number on it, status, body bytes, the
#                   request's time and the request line
#   --mirror SPEC   a mirror (repeatable; default one with no options).
#                   SPEC is KEY=VALUE pairs separated by commas:
#                     rtt=MS        round trip added behind the access link
#                     rate=RATE     the mirror's bandwidth
#                     req-rate=R    nginx limit_rate: per request, and only
#                                   after the first write, so it slows
#                                   large files only (bytes/s, e.g. 1m)
#                     max-conns=N   connections per client, more get 503
#                     keepalive=N   requests per connection
#                     missing=K     404 for every Kth file of the list (a
#                                   mirror that isn't in sync)
#                   e.g. --mirror rtt=5 --mirror rtt=30,rate=100mbit
#
# RATE is in tc's units (kbit, mbit, gbit).
#
# The second form makes the files of a synthetic workload: SIZES has a
# size in bytes at the start of each line (the rest is ignored, as are
# empty lines and lines starting with #). DIR gets sparse files of those
# sizes, named as packages (f/pNNNNN-1-1-any.pkg.tar.zst), a pacman repo
# of them (f/netsim.db) and a list of "SIZE PATH" lines (largest first),
# for examples/download.rs. The content doesn't matter: nothing on the way
# compresses it.
set -euo pipefail

scripts=$(dirname "$(realpath "$0")")
top=$(dirname "$scripts")
state=$top/tmp/netsim

usage() {
	sed -n '3,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2
	exit 1
}

files() {
	local sizes=$1 dir
	dir=$(realpath -m "$2")
	rm -rf "$dir/f" "$dir/list"
	mkdir -p "$dir/f"
	local size rest n=0 path
	# n counts in the pipeline's subshell, for the names.
	while read -r size rest; do
		[[ -n $size && $size != \#* ]] || continue
		if [[ ! $size =~ ^[0-9]+$ ]]; then
			echo "not a size: $size" >&2
			exit 1
		fi
		n=$((n + 1))
		path=$(printf 'f/p%05d-1-1-any.pkg.tar.zst' "$n")
		truncate -s "$size" "$dir/$path"
		echo "$size $path"
	done <"$sizes" | sort -rn >"$dir/list.part"

	# A pacman repo of them, f/netsim.db, for scripts/pacman-bench.sh.
	local descs=$dir/descs sum file name
	rm -rf "$descs"
	mkdir "$descs"
	(cd "$dir/f" && find . -name '*.pkg.tar.zst' -print0 | xargs -0 sha256sum) |
		while read -r sum file; do
			file=${file#./}
			name=${file%-1-1-any.pkg.tar.zst}
			mkdir "$descs/$name-1-1"
			printf '%%FILENAME%%\n%s\n\n%%NAME%%\n%s\n\n%%VERSION%%\n1-1\n\n%%CSIZE%%\n%s\n\n%%ARCH%%\nany\n\n%%SHA256SUM%%\n%s\n\n' \
				"$file" "$name" "$(stat -c %s "$dir/f/$file")" "$sum" >"$descs/$name-1-1/desc"
		done
	# Entries named NAME-VERSION/desc, without "./", which pacman rejects.
	(cd "$descs" && find . -mindepth 1 -maxdepth 1 -printf '%P\0' |
		tar -czf "$dir/f/netsim.db" --null -T -)
	rm -rf "$descs"
	mv "$dir/list.part" "$dir/list"
	echo "$(wc -l <"$dir/list") files in $dir" >&2
}

# A CA and a certificate for the mirrors' addresses signed by it.
certs() {
	local tls=$state/tls
	if [[ -f $tls/server.pem ]]; then
		return
	fi
	mkdir -p "$tls"
	local san=IP:10.77.0.2 i
	for i in $(seq 11 99); do
		san+=,IP:10.77.0.$i
	done
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$tls/ca.key" -out "$tls/ca.pem.part" -days 3650 \
		-subj "/CN=skl netsim CA" \
		-addext basicConstraints=critical,CA:TRUE \
		-addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$tls/server.key" -out "$tls/server.csr" \
		-subj "/CN=netsim mirror" 2>/dev/null
	openssl x509 -req -in "$tls/server.csr" -CA "$tls/ca.pem.part" \
		-CAkey "$tls/ca.key" -out "$tls/server.pem.part" -days 3650 \
		-extfile <(printf '%s\n' \
			basicConstraints=critical,CA:FALSE \
			keyUsage=critical,digitalSignature \
			extendedKeyUsage=serverAuth \
			"subjectAltName=$san") 2>/dev/null
	rm "$tls/server.csr"
	mv "$tls/ca.pem.part" "$tls/ca.pem"
	mv "$tls/server.pem.part" "$tls/server.pem"
}

# Holders of the namespaces, and nginx pid files, for cleanup.
holders=()
run=
logs=

cleanup() {
	local pid
	if [[ -n $run ]]; then
		for pid in "$run"/m*/nginx.pid; do
			[[ -f $pid ]] && kill "$(cat "$pid")" 2>/dev/null
		done
	fi
	for pid in "${holders[@]}"; do
		kill "$pid" 2>/dev/null
	done
	wait 2>/dev/null
	if [[ -n $run && -n $logs ]]; then
		mkdir -p "$logs"
		local log
		for log in "$run"/m*/access.log; do
			[[ -f $log ]] && cp "$log" "$logs/$(basename "$(dirname "$log")").log"
		done
	fi
	[[ -z $run ]] || rm -rf "$run"
}

# Start a process in a new network namespace and print its pid once the
# namespace exists.
holder() {
	unshare -n sleep infinity &
	local pid=$! own
	own=$(readlink /proc/self/ns/net)
	while [[ $(readlink "/proc/$pid/ns/net" 2>/dev/null) == "$own" ]]; do
		sleep 0.01
	done
	holders+=("$pid")
	held=$pid
}

in_ns() {
	local pid=$1
	shift
	nsenter --net="/proc/$pid/ns/net" -- "$@"
}

# netem arguments: delay MS [jitter], and the rest as given.
netem() {
	local dev=$1 delay=$2 jitter=$3
	shift 3
	local args=(delay "${delay}ms")
	if [[ $jitter != 0 ]]; then
		args+=("${jitter}ms")
	fi
	tc qdisc add dev "$dev" root netem "${args[@]}" "$@"
}

# Half of MS, as a decimal.
half() {
	awk -v x="$1" 'BEGIN { printf "%g", x / 2 }'
}

# The MAC address of a device in the namespace of pid $1. Not from
# /sys/class/net, which shows the namespace that sysfs was mounted in.
mac() {
	in_ns "$1" ip -o link show dev "$2" | sed -n 's/.* link\/ether \([^ ]*\).*/\1/p'
}

nginx_conf() {
	local dir=$1 addr=$2 req_rate=$3 max_conns=$4 keepalive=$5 missing=$6
	local user=
	if ((EUID == 0)); then
		user='user root;'
	fi
	local listen=80 ssl=
	if ((! http)); then
		listen='443 ssl'
		ssl="ssl_certificate $state/tls/server.pem;
		ssl_certificate_key $state/tls/server.key;"
	fi
	local limits=
	[[ -z $req_rate ]] || limits+="limit_rate $req_rate;"
	[[ -z $max_conns ]] || limits+="limit_conn conns $max_conns;"
	[[ -z $keepalive ]] || limits+="keepalive_requests $keepalive;"
	local gone=
	if [[ -n $missing ]]; then
		# Every Kth file of the list, by its position.
		gone=$(awk -v k="$missing" 'NR % k == 0 { printf "location = /%s { return 404; }\n", $2 }' \
			"$root/list" 2>/dev/null || true)
	fi
	cat >"$dir/nginx.conf" <<EOF
$user
pid $dir/nginx.pid;
worker_processes 2;
events {}
http {
	log_format timing '\$msec \$connection \$connection_requests \$status '
		'\$body_bytes_sent \$request_time "\$request"';
	access_log $dir/access.log timing;
	client_body_temp_path $dir/temp/body;
	proxy_temp_path $dir/temp/proxy;
	fastcgi_temp_path $dir/temp/fastcgi;
	uwsgi_temp_path $dir/temp/uwsgi;
	scgi_temp_path $dir/temp/scgi;
	types {}
	default_type application/octet-stream;
	sendfile on;
	limit_conn_zone \$binary_remote_addr zone=conns:1m;
	server {
		listen $addr:$listen;
		$ssl
		root $root;
		$limits
		$gone
	}
}
EOF
}

simulate() {
	local down=500mbit up=50mbit rtt=10 jitter=0 loss=0 queue=1000
	root=$state/files
	http=0
	logs=
	local mirrors=()
	while (($#)); do
		case $1 in
		--down | --up | --rtt | --jitter | --loss | --queue | --root | --mirror | --logs)
			(($# >= 2)) || usage
			case $1 in
			--down) down=$2 ;;
			--up) up=$2 ;;
			--rtt) rtt=$2 ;;
			--jitter) jitter=$2 ;;
			--loss) loss=$2 ;;
			--queue) queue=$2 ;;
			--root) root=$(realpath "$2") ;;
			--mirror) mirrors+=("$2") ;;
			--logs) logs=$(realpath -m "$2") ;;
			esac
			shift 2
			;;
		--http)
			http=1
			shift
			;;
		--)
			shift
			break
			;;
		*) usage ;;
		esac
	done
	(($#)) || usage
	((${#mirrors[@]})) || mirrors=("")
	if ((${#mirrors[@]} > 89)); then
		echo "at most 89 mirrors" >&2
		exit 1
	fi
	local nginx
	nginx=$(PATH=$PATH:/usr/sbin command -v nginx) || {
		echo "nginx not found" >&2
		exit 1
	}
	((http)) || certs
	mkdir -p "$state/run"
	run=$(mktemp -d "$state/run/XXXXXX")
	trap cleanup EXIT

	# This namespace is the router: a bridge that the client and the
	# mirrors are attached to by veth pairs. Its port to the client is
	# the downlink, shared by all mirrors.
	ip link set lo up
	ip link add name br0 type bridge
	ip link set br0 up
	local held client
	holder
	client=$held
	ip link add name cl0 type veth peer name cl1 netns "$client"
	ip link set cl0 master br0 up
	in_ns "$client" ip link set lo up
	in_ns "$client" ip addr add 10.77.0.2/24 dev cl1
	in_ns "$client" ip link set cl1 up
	local half_rtt
	half_rtt=$(half "$rtt")
	in_ns "$client" bash -c "$(declare -f netem); netem cl1 $half_rtt $jitter rate $up limit $queue"
	netem cl0 "$half_rtt" "$jitter" rate "$down" limit "$queue" loss "$loss%"
	local client_mac
	client_mac=$(mac "$client" cl1)

	local urls=() i=0 spec kv key value
	for spec in "${mirrors[@]}"; do
		i=$((i + 1))
		local m_rtt=0 m_rate='' req_rate='' max_conns='' keepalive='' missing=''
		IFS=, read -ra kv <<<"$spec"
		for kv in "${kv[@]}"; do
			key=${kv%%=*} value=${kv#*=}
			case $key in
			rtt) m_rtt=$value ;;
			rate) m_rate=$value ;;
			req-rate) req_rate=$value ;;
			max-conns) max_conns=$value ;;
			keepalive) keepalive=$value ;;
			missing) missing=$value ;;
			*)
				echo "unknown mirror option: $key" >&2
				exit 1
				;;
			esac
		done
		local addr=10.77.0.$((10 + i)) dir=$run/m$i mirror
		mkdir -p "$dir/temp"
		holder
		mirror=$held
		ip link add name "m${i}a" type veth peer name "m${i}b" netns "$mirror"
		ip link set "m${i}a" master br0 up
		in_ns "$mirror" ip link set lo up
		in_ns "$mirror" ip addr add "$addr/24" dev "m${i}b"
		in_ns "$mirror" ip link set "m${i}b" up
		half_rtt=$(half "$m_rtt")
		local rate=()
		[[ -z $m_rate ]] || rate=(rate "$m_rate")
		in_ns "$mirror" bash -c "$(declare -f netem); netem m${i}b $half_rtt 0 ${rate[*]} limit $queue"
		netem "m${i}a" "$half_rtt" 0 limit "$queue"
		# Static neighbours: no ARP round trip on the first connection.
		in_ns "$mirror" ip neigh replace 10.77.0.2 lladdr "$client_mac" dev "m${i}b" nud permanent
		in_ns "$client" ip neigh replace "$addr" lladdr \
			"$(mac "$mirror" "m${i}b")" dev cl1 nud permanent
		nginx_conf "$dir" "$addr" "$req_rate" "$max_conns" "$keepalive" "$missing"
		in_ns "$mirror" "$nginx" -p "$dir" -c "$dir/nginx.conf" -e "$dir/error.log"
		if ((http)); then
			urls+=("http://$addr")
		else
			urls+=("https://$addr")
		fi
	done

	local status=0
	in_ns "$client" env NETSIM_MIRRORS="${urls[*]}" SKL_CA_CERTS="$state/tls/ca.pem" "$@" ||
		status=$?
	exit "$status"
}

case ${1:-} in
files)
	(($# == 3)) || usage
	files "$2" "$3"
	;;
-h | --help | '') usage ;;
*)
	if [[ ${NETSIM_INSIDE:-} != 1 ]]; then
		NETSIM_INSIDE=1 exec unshare -rn -- "$0" "$@"
	fi
	simulate "$@"
	;;
esac
