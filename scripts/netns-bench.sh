#!/usr/bin/env bash
# Network-namespace bench (ETUDE-IPV6 T22): a real heliosd against a real
# WireGuard client, with the kernel data plane and nftables, and no root.
#
# Three namespaces inside one unprivileged user namespace:
#
#   cl (client) ── veth ── net (WAN router + "Internet" host) ── veth ── gw (heliosd)
#
# `gw` runs heliosd built with `netlink,wireguard`, *without* `--dev`: the
# ruleset is applied by the real nftables backend and `helios0` is a kernel
# WireGuard interface. `cl` is a plain kernel WireGuard peer driven by `wg`,
# admitted through the local administration socket with the production CLI.
#
#   bash scripts/netns-bench.sh     # build, run every scenario, tear down
#
# The namespaces live as long as the unshare process: nothing survives the run.
# On failure the working directory (daemon log, ruleset) is kept and printed.
#
# What this proves, and what it does not (TESTING.md, « Banc netns »): the
# kernel's behaviour on this machine's kernel, through veth. It proves neither
# a physical NIC, nor a real WAN, nor WireGuard-NT, nor a TPM: heliosd runs
# with TPM sealing disabled and the legacy in-file gateway key, exactly like
# scripts/lab.sh.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"

for arg in "$@"; do
    case "$arg" in
        --inner) ;;
        *) echo "argument inconnu : $arg" >&2; exit 2 ;;
    esac
done

# ─── Outer stage: build, then re-enter in a user + network + mount namespace ──

if [ "${1:-}" != "--inner" ]; then
    # shellcheck source=scripts/cargo-budget.sh
    source scripts/cargo-budget.sh
    helios_budget_enter "$PWD"

    for tool in ip wg nft unshare ping python3 curl; do
        command -v "$tool" > /dev/null || { echo "outil absent : $tool" >&2; exit 2; }
    done

    echo "==> Construction (heliosd netlink + wireguard, helios)"
    cargo build --quiet -p heliosd --features netlink,wireguard -p helios
    BIN="${CARGO_TARGET_DIR:-$REPO/target}/debug"

    TMP="$(mktemp -d)"
    export HELIOS_BENCH_BIN="$BIN" HELIOS_BENCH_TMP="$TMP"
    status=0
    unshare --user --map-root-user --net --mount bash "$0" --inner || status=$?
    if [ "$status" -eq 0 ]; then
        rm -rf "$TMP"
    else
        echo "  Répertoire du banc conservé : $TMP" >&2
    fi
    exit "$status"
fi

# ─── Inner stage: we are root of a private user namespace ─────────────────────

BIN="$HELIOS_BENCH_BIN"
TMP="$HELIOS_BENCH_TMP"
SOCK="$TMP/admin.sock"
GW_V4=192.0.2.1
GW_V6=2001:db8:1::1
INET_V4=203.0.113.10
INET_V6=2001:db8:ffff::10
ULA_PREFIX=fd42:6865:6c69
PORT=51820

FAILED=0
pass() { echo "    PASS  $1"; }
fail() { echo "    FAIL  $1" >&2; FAILED=$((FAILED + 1)); }
check() {
    local label="$1"; shift
    if "$@" > /dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}
# Retries for up to five seconds: IPv6 neighbour discovery waits for the
# link-local address to finish duplicate address detection.
eventually() {
    local label="$1"; shift
    for _ in $(seq 1 10); do
        if "$@" > /dev/null 2>&1; then pass "$label"; return; fi
        sleep 0.5
    done
    fail "$label"
}
refuse() {
    local label="$1"; shift
    if "$@" > /dev/null 2>&1; then fail "$label"; else pass "$label"; fi
}
in_gw() { ip netns exec gw "$@"; }
in_cl() { ip netns exec cl "$@"; }
in_net() { ip netns exec net "$@"; }

DAEMON_PID=""
SERVER_PID=""
teardown() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
}
trap teardown EXIT

# `ip netns` keeps its bind mounts under /run/netns: a private tmpfs keeps them
# inside this mount namespace.
mount -t tmpfs none /run
mkdir -p /run/netns

echo "==> Topologie"
for ns in gw net cl; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

ip link add wan0 netns gw type veth peer name to-gw netns net
ip link add eth0 netns cl type veth peer name to-cl netns net

ip -n net addr add 192.0.2.254/24 dev to-gw
ip -n net addr add 2001:db8:1::254/64 dev to-gw nodad
ip -n net addr add 198.51.100.254/24 dev to-cl
ip -n net addr add 2001:db8:2::254/64 dev to-cl nodad
ip -n net addr add "$INET_V4/32" dev lo
ip -n net addr add "$INET_V6/128" dev lo
ip -n net link set to-gw up
ip -n net link set to-cl up
in_net sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
# The "Internet" sees the client's tunnel traffic only once the gateway has
# masqueraded it: no route back to 100.64.0.0/10 exists here on purpose.

ip -n gw addr add "$GW_V4/24" dev wan0
ip -n gw addr add "$GW_V6/64" dev wan0 nodad
ip -n gw link set wan0 up
ip -n gw route add default via 192.0.2.254
ip -n gw -6 route add default via 2001:db8:1::254

ip -n cl addr add 198.51.100.2/24 dev eth0
ip -n cl addr add 2001:db8:2::2/64 dev eth0 nodad
ip -n cl link set eth0 up
ip -n cl route add default via 198.51.100.254
ip -n cl -6 route add default via 2001:db8:2::254

eventually "le client joint l'endpoint IPv4 de la gateway hors tunnel" in_cl ping -c1 -W1 "$GW_V4"
eventually "le client joint l'endpoint IPv6 de la gateway hors tunnel" in_cl ping -6 -c1 -W1 "$GW_V6"

echo "==> Gateway"
"$BIN/helios" campaign --generate-keys 2> /dev/null > "$TMP/gateway.env"
"$BIN/helios" campaign --generate-keys 2> /dev/null > "$TMP/client.env"
GW_PRIV="$(sed -n 's/^WG_PRIVATE_KEY=//p' "$TMP/gateway.env")"
GW_PUB="$(sed -n 's/^WG_PUBLIC_KEY=//p' "$TMP/gateway.env")"
CLIENT_PRIV="$(sed -n 's/^WG_PRIVATE_KEY=//p' "$TMP/client.env")"
CLIENT_PUB="$(sed -n 's/^WG_PUBLIC_KEY=//p' "$TMP/client.env")"
for v in GW_PRIV GW_PUB CLIENT_PRIV CLIENT_PUB; do
    [ -n "${!v}" ] || { echo "extraction de $v impossible" >&2; exit 1; }
done

# Same legacy in-file key as scripts/lab.sh: there is no TPM to seal into.
#
# The client is declared here rather than admitted through the API. Admission
# now requires the TLS and PQ key-negotiation certificates (floor `ml_kem`),
# whose gateway half is sealed into a TPM this bench does not have; a local
# edit of network.toml is the one path the code leaves to a classic peer. The
# bench therefore exercises the data plane, not admission or negotiation.
VIP4=100.64.0.2/32
VIP6=$ULA_PREFIX::2/128
cat > "$TMP/network.toml" <<EOF
wan_iface = "wan0"
wg_iface = "helios0"
wg_private_key = "$GW_PRIV"
wg_address = "100.64.0.1/10"
wg_address_v6 = "$ULA_PREFIX::1/64"
wg_listen_port = $PORT
allow_client_internet = true

[[peers]]
name = "bench"
public_key = "$CLIENT_PUB"
address = "$VIP4"
address_v6 = "$VIP6"
EOF

daemon_env=(
    HELIOS_NETWORK_CONFIG="$TMP/network.toml"
    HELIOS_UPDATE_STAGING="$TMP/updates"
    HELIOS_UPDATE_CHANNEL=testing
    HELIOS_READY_PATH="$TMP/ready"
    HELIOS_ADMIN_SOCKET="$SOCK"
)
# Not through in_gw: a backgrounded shell function is a subshell, and $! would
# be its PID — killing it would leave heliosd running. `ip netns exec` and
# `env` both exec, so $! is heliosd itself.
ip netns exec gw env "${daemon_env[@]}" "$BIN/heliosd" run > "$TMP/daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 60); do
    [ -S "$SOCK" ] && curl -sf --unix-socket "$SOCK" http://localhost/api/status > /dev/null 2>&1 && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "heliosd s'est arrêté :" >&2
        cat "$TMP/daemon.log" >&2
        exit 1
    fi
    sleep 0.5
done

api_state() {
    curl -sf --unix-socket "$SOCK" http://localhost/api/status \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["state"])'
}
wait_state() {
    local wanted="$1"
    for _ in $(seq 1 40); do
        [ "$(api_state 2> /dev/null)" = "$wanted" ] && return 0
        sleep 0.5
    done
    return 1
}

check "heliosd démarre sans --dev (backends réels)" grep -q "table inet helios applied" "$TMP/daemon.log"
check "kill-switch engagé avant le réseau" grep -q "kill-switch engaged" "$TMP/daemon.log"
check "helios0 est une interface WireGuard noyau" in_gw wg show helios0
check "la table inet helios est posée en politique drop" \
    sh -c "ip netns exec gw nft list chain inet helios forward | grep -q 'policy drop'"

echo "==> Pair déclaré (CLI de production, socket d'administration)"
export HELIOS_ADMIN_SOCKET="$SOCK"
check "heliosd pose le pair déclaré sur helios0" \
    sh -c "ip netns exec gw wg show helios0 peers | grep -qxF '$CLIENT_PUB'"
check "AllowedIPs de la gateway = VIP IPv4 /32 et VIP IPv6 /128" \
    sh -c "ip netns exec gw wg show helios0 allowed-ips | grep -F '$CLIENT_PUB' | grep -F '$VIP4' | grep -qF '$VIP6'"
# The emitted profile must carry the persisted addresses, never re-derived
# ones (ADRESSAGE-IPV6 §3 bis.2, rule 4).
emitted_matches_declared() {
    in_gw "$BIN/helios" profile emit --name bench --endpoint "$GW_V4:$PORT" \
        --public-key "$CLIENT_PUB" --output "$TMP/bench.invitation.orion" > /dev/null
    python3 - "$TMP/bench.invitation.orion" "$VIP4" "$VIP6" <<'PY'
import json, sys
profile = json.load(open(sys.argv[1]))["profile"]
assert "private_key" not in profile, "invitation profile carries a private key"
assert profile["address"] == sys.argv[2], profile["address"]
assert profile.get("address_v6") == sys.argv[3], profile.get("address_v6")
PY
}
check "le profil émis porte les VIP persistées, sans clé privée" emitted_matches_declared

echo "==> Client WireGuard"
umask 077
printf '%s\n' "$CLIENT_PRIV" > "$TMP/client.key"
bring_up_client() {
    local endpoint="$1"
    in_cl ip link del wgc0 2> /dev/null || true
    in_cl ip link add wgc0 type wireguard
    in_cl wg set wgc0 private-key "$TMP/client.key" \
        peer "$GW_PUB" endpoint "$endpoint" allowed-ips 0.0.0.0/0,::/0 persistent-keepalive 25
    in_cl ip addr add "$VIP4" dev wgc0
    [ "$VIP6" = "-" ] || in_cl ip addr add "$VIP6" dev wgc0 nodad
    in_cl ip link set wgc0 up
    # Split routes only: the endpoint itself must stay outside the tunnel.
    in_cl ip route add 100.64.0.0/10 dev wgc0
    in_cl ip route add "$INET_V4/32" dev wgc0
    in_cl ip -6 route add "$ULA_PREFIX::/64" dev wgc0
    in_cl ip -6 route add "$INET_V6/128" dev wgc0
}
handshake_seen() {
    for _ in $(seq 1 20); do
        in_cl ping -c1 -W1 100.64.0.1 > /dev/null 2>&1 || true
        [ "$(in_cl wg show wgc0 latest-handshakes | awk '{print $2}')" != "0" ] && return 0
        sleep 0.5
    done
    return 1
}

bring_up_client "$GW_V4:$PORT"
check "handshake WireGuard sur endpoint IPv4" handshake_seen
check "la gateway passe en Up sur preuve de handshake" wait_state up

echo "==> Scénarios (ETUDE-IPV6 §12)"
check "§12.1 IPv4 dans le tunnel : ping de la gateway" in_cl ping -c3 -W2 100.64.0.1
check "§12.3 dual-stack : ping -6 de la gateway (ULA)" in_cl ping -6 -c3 -W2 "$ULA_PREFIX::1"
check "§12.4 forward IPv4 du tunnel vers Internet (NAT44)" in_cl ping -c3 -W2 "$INET_V4"

# A TCP and a UDP echo on the "Internet" host, reached through the tunnel.
ip netns exec net python3 - "$INET_V4" > "$TMP/echo.log" 2>&1 <<'PY' &
import socket, sys, threading
host = sys.argv[1]
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, 7007)); s.listen()
    while True:
        c, _ = s.accept(); c.sendall(c.recv(1024)); c.close()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((host, 7007))
    while True:
        data, peer = s.recvfrom(1024); s.sendto(data, peer)
threading.Thread(target=tcp, daemon=True).start()
udp()
PY
SERVER_PID=$!
sleep 0.5
echo_probe() {
    in_cl python3 - "$INET_V4" "$1" <<'PY'
import socket, sys
host, kind = sys.argv[1], sys.argv[2]
if kind == "tcp":
    s = socket.create_connection((host, 7007), timeout=3)
    s.sendall(b"helios"); assert s.recv(16) == b"helios"
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(b"helios", (host, 7007)); assert s.recvfrom(16)[0] == b"helios"
PY
}
check "§12.5 TCP traversant le tunnel puis le NAT" echo_probe tcp
check "§12.6 UDP traversant le tunnel puis le NAT" echo_probe udp

# T21: IPv6 from the tunnel to a WAN is rejected in every state, no NAT66. A
# reject answers at once, where a silent drop would time out.
v6_rejected_fast() {
    local started ended
    started=$(date +%s%N)
    ! in_cl ping -6 -c1 -W3 "$INET_V6" > "$TMP/ping6-wan.log" 2>&1 || return 1
    ended=$(date +%s%N)
    {
        echo "elapsed_ms=$(((ended - started) / 1000000))"
        in_gw sysctl net.ipv6.conf.all.forwarding net.ipv4.ip_forward
    } >> "$TMP/ping6-wan.log" 2>&1
    [ $(((ended - started) / 1000000)) -lt 2000 ]
}
check "§12.16 / T21 IPv6 tunnel → WAN rejeté sans attente (pas de NAT66)" v6_rejected_fast

# WireGuard's cryptokey routing drops a source outside the peer's AllowedIPs.
spoof() {
    in_cl ip addr add 100.64.250.250/32 dev wgc0
    local status=0
    in_cl ping -c2 -W2 -I 100.64.250.250 100.64.0.1 > /dev/null 2>&1 || status=$?
    in_cl ip addr del 100.64.250.250/32 dev wgc0
    return $((status == 0))
}
check "§12.14 anti-spoofing : source hors AllowedIPs jetée par WireGuard" spoof

check "§12.8 ND : voisin IPv6 du WAN résolu sous politique drop" \
    sh -c "ip netns exec gw ping -6 -c1 -W2 2001:db8:1::254 > /dev/null; ip netns exec gw ip -6 neigh show dev wan0 | grep -q 2001:db8:1::254"

echo "==> Endpoint IPv6 (§12.10)"
bring_up_client "[$GW_V6]:$PORT"
check "§12.10 handshake WireGuard sur endpoint IPv6" handshake_seen
check "§12.10 trafic IPv4 et IPv6 dans un tunnel porté par IPv6" \
    sh -c "ip netns exec cl ping -c2 -W2 100.64.0.1 > /dev/null && ip netns exec cl ping -6 -c2 -W2 $ULA_PREFIX::1 > /dev/null"

echo "==> Arrêt : le kill-switch reste engagé"
in_gw nft list ruleset > "$TMP/ruleset.up.nft"
kill "$DAEMON_PID"
wait "$DAEMON_PID" 2> /dev/null || true
DAEMON_PID=""
check "heliosd journalise l'arrêt fail-closed" grep -q "kill-switch maintained" "$TMP/daemon.log"
check "la table inet helios survit à l'arrêt" in_gw nft list table inet helios
refuse "aucun forward vers Internet après l'arrêt" in_cl ping -c2 -W2 "$INET_V4"

echo "==> Aucun secret dans le journal du daemon"
refuse "clé privée absente du journal" \
    sh -c "grep -qF -e '$CLIENT_PRIV' -e '$GW_PRIV' '$TMP/daemon.log'"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "Banc netns : tous les scénarios passent."
else
    echo "Banc netns : $FAILED scénario(s) en échec — journal : $TMP/daemon.log" >&2
fi
echo "Non couverts ici : §12.9 PMTU, §12.12 DNS AAAA, §12.15 conntrack (outil absent), matériel et WireGuard-NT."
[ "$FAILED" -eq 0 ]
