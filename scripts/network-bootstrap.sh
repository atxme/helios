#!/bin/sh
# Atomically merges deployment-owned settings into a gateway network.toml.
#
# Existing peer tables and operator choices are preserved. Global settings are
# always emitted before the first [[peers]] table; appending them at end of file
# would silently attach them to the last peer in TOML.
set -eu

CONFIG="/var/lib/helios/network.toml"
WAN_IFACE=""
SSH_CIDR=""
WG_PORT="51820"
KEY_NEGOTIATION_PORT="51821"
ESCROW_PUBLIC_KEY=""
DYNAMIC_WAN="0"
MESHNET_PEER_CIDRS=""
MESHNET_ROUTING_PEER_CIDRS=""
MESHNET_LOCAL_NETWORK_PEER_CIDRS=""

usage() {
    cat >&2 <<'EOF'
Usage: network-bootstrap.sh --wan IFACE --ssh-cidr CIDR --escrow-public-key KEY [options]

  --config PATH
  --wg-port PORT
  --key-negotiation-port PORT
  --dynamic-wan
  --meshnet-peer-cidrs CIDR[,CIDR...]
  --meshnet-routing-peer-cidrs CIDR[,CIDR...]
  --meshnet-local-network-peer-cidrs CIDR[,CIDR...]
EOF
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --config) CONFIG="${2:-}"; shift 2 ;;
        --wan) WAN_IFACE="${2:-}"; shift 2 ;;
        --ssh-cidr) SSH_CIDR="${2:-}"; shift 2 ;;
        --wg-port) WG_PORT="${2:-}"; shift 2 ;;
        --key-negotiation-port) KEY_NEGOTIATION_PORT="${2:-}"; shift 2 ;;
        --escrow-public-key) ESCROW_PUBLIC_KEY="${2:-}"; shift 2 ;;
        --dynamic-wan) DYNAMIC_WAN="1"; shift ;;
        --admin-ifaces) ADMIN_IFACES="${2:-}"; shift 2 ;;
        --meshnet-peer-cidrs) MESHNET_PEER_CIDRS="${2:-}"; shift 2 ;;
        --meshnet-routing-peer-cidrs) MESHNET_ROUTING_PEER_CIDRS="${2:-}"; shift 2 ;;
        --meshnet-local-network-peer-cidrs) MESHNET_LOCAL_NETWORK_PEER_CIDRS="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

[ -n "$WAN_IFACE" ] || { echo "WAN interface is required" >&2; exit 2; }
[ -n "$SSH_CIDR" ] || { echo "SSH source CIDR is required" >&2; exit 2; }
[ -n "$ESCROW_PUBLIC_KEY" ] || { echo "escrow public key is required" >&2; exit 2; }

case "$WG_PORT:$KEY_NEGOTIATION_PORT" in
    *[!0-9:]*|:*) echo "ports must be decimal integers" >&2; exit 2 ;;
esac
[ "$WG_PORT" -gt 0 ] && [ "$WG_PORT" -le 65535 ] ||
    { echo "invalid WireGuard port: $WG_PORT" >&2; exit 2; }
[ "$KEY_NEGOTIATION_PORT" -gt 0 ] && [ "$KEY_NEGOTIATION_PORT" -le 65535 ] ||
    { echo "invalid key-negotiation port: $KEY_NEGOTIATION_PORT" >&2; exit 2; }
[ "$WG_PORT" != "$KEY_NEGOTIATION_PORT" ] ||
    { echo "WireGuard and key-negotiation ports must differ" >&2; exit 2; }

cidr_list_to_toml() {
    cidr_list="$1"
    cidr_toml=""
    old_ifs=$IFS
    IFS=,
    for cidr in $cidr_list; do
        case "$cidr" in
            ""|*[!0-9./]*) echo "invalid Meshnet peer CIDR: $cidr" >&2; exit 2 ;;
        esac
        address=${cidr%/*}
        prefix=${cidr##*/}
        [ "$address" != "$cidr" ] && [ "$prefix" -ge 0 ] 2>/dev/null && [ "$prefix" -le 32 ] ||
            { echo "invalid Meshnet peer CIDR: $cidr" >&2; exit 2; }
        if [ -n "$cidr_toml" ]; then
            cidr_toml="$cidr_toml, "
        fi
        cidr_toml="$cidr_toml\"$cidr\""
    done
    IFS=$old_ifs
    printf '[%s]' "$cidr_toml"
}

list_contains() {
    case ",$1," in
        *",$2,"*) return 0 ;;
        *) return 1 ;;
    esac
}

for cidr in $(printf '%s' "$MESHNET_ROUTING_PEER_CIDRS" | tr ',' ' '); do
    list_contains "$MESHNET_PEER_CIDRS" "$cidr" ||
        { echo "Meshnet routing peer is absent from peer inventory: $cidr" >&2; exit 2; }
done
for cidr in $(printf '%s' "$MESHNET_LOCAL_NETWORK_PEER_CIDRS" | tr ',' ' '); do
    list_contains "$MESHNET_ROUTING_PEER_CIDRS" "$cidr" ||
        { echo "Meshnet local-network peer has no routing permission: $cidr" >&2; exit 2; }
done

# Left empty when the caller names none, and an empty value keeps the key
# **unmanaged** below. That is deliberate: a redeploy that forgets
# `--admin-ifaces` must not silently erase the operator's way back in.
ADMIN_IFACES_TOML=""
if [ -n "${ADMIN_IFACES:-}" ]; then
    admin_toml=""
    old_ifs=$IFS
    IFS=,
    for iface in $ADMIN_IFACES; do
        case "$iface" in
            ""|*[!A-Za-z0-9_.:-]*) echo "invalid administration interface: $iface" >&2; exit 2 ;;
        esac
        if [ -n "$admin_toml" ]; then
            admin_toml="$admin_toml, "
        fi
        admin_toml="$admin_toml\"$iface\""
    done
    IFS=$old_ifs
    ADMIN_IFACES_TOML="[$admin_toml]"
fi

MESHNET_TOML=""
MESHNET_ROUTING_TOML="[]"
MESHNET_LOCAL_NETWORK_TOML="[]"
if [ -n "$MESHNET_PEER_CIDRS" ]; then
    MESHNET_TOML="$(cidr_list_to_toml "$MESHNET_PEER_CIDRS")"
    MESHNET_ROUTING_TOML="$(cidr_list_to_toml "$MESHNET_ROUTING_PEER_CIDRS")"
    MESHNET_LOCAL_NETWORK_TOML="$(cidr_list_to_toml "$MESHNET_LOCAL_NETWORK_PEER_CIDRS")"
fi

if [ ! -f "$CONFIG" ]; then
    echo "network configuration does not exist: $CONFIG" >&2
    exit 1
fi

case "$CONFIG" in
    */*) CONFIG_DIR=${CONFIG%/*} ;;
    *) CONFIG_DIR=. ;;
esac
BACKUP="$CONFIG.deploy-backup"
TEMP="$CONFIG_DIR/.network.toml.deploy.$$.tmp"
[ ! -e "$TEMP" ] || { echo "temporary path already exists: $TEMP" >&2; exit 1; }
umask 077
trap 'rm -f "$TEMP"' EXIT HUP INT TERM

cp -a "$CONFIG" "$BACKUP"

awk \
    -v wan_iface="$WAN_IFACE" \
    -v ssh_cidr="$SSH_CIDR" \
    -v wg_port="$WG_PORT" \
    -v key_port="$KEY_NEGOTIATION_PORT" \
    -v escrow_key="$ESCROW_PUBLIC_KEY" \
    -v admin_ifaces="$ADMIN_IFACES_TOML" \
    -v dynamic_wan="$DYNAMIC_WAN" \
    -v meshnet_cidrs="$MESHNET_TOML" \
    -v meshnet_routing_cidrs="$MESHNET_ROUTING_TOML" \
    -v meshnet_local_cidrs="$MESHNET_LOCAL_NETWORK_TOML" '
BEGIN {
    order[1] = "wan_iface"
    order[2] = "lan_ifaces"
    order[3] = "allow_ssh_from"
    order[4] = "allow_dhcp_on_wan"
    order[5] = "allow_client_internet"
    order[6] = "admin_iface"
    order[7] = "split_tunnel_cidrs"
    order[8] = "wg_iface"
    order[9] = "wg_private_key"
    order[10] = "wg_address"
    order[11] = "wg_listen_port"
    order[12] = "key_negotiation_port"
    order[13] = "static_peer_addrs"
    order[14] = "escrow_public_key"
    order[15] = "allow_tunnel_icmp"
    order[16] = "allow_ssh_over_tunnel"
    order[17] = "allow_gateway_egress"
    order_count = 17
    if (admin_ifaces != "") {
        order_count++
        order[order_count] = "admin_ifaces"
    }
    if (meshnet_cidrs != "") {
        order_count++
        order[order_count] = "nordvpn_meshnet"
    }

    managed["wan_iface"] = 1
    managed["lan_ifaces"] = 1
    managed["allow_ssh_from"] = 1
    managed["allow_dhcp_on_wan"] = 1
    managed["allow_client_internet"] = 1
    managed["admin_iface"] = 1
    managed["split_tunnel_cidrs"] = 1
    managed["wg_iface"] = 1
    managed["wg_private_key"] = 1
    managed["wg_address"] = 1
    managed["wg_listen_port"] = 1
    managed["key_negotiation_port"] = 1
    managed["static_peer_addrs"] = 1
    managed["escrow_public_key"] = 1
    managed["allow_tunnel_icmp"] = 1
    managed["allow_ssh_over_tunnel"] = 1
    managed["allow_gateway_egress"] = 1
    # Unmanaged when the caller names none: a redeploy without --admin-ifaces
    # leaves whatever the operator already relies on in place.
    if (admin_ifaces != "") {
        managed["admin_ifaces"] = 1
        desired["admin_ifaces"] = admin_ifaces
    }
    if (meshnet_cidrs != "") {
        managed["nordvpn_meshnet"] = 1
    }

    desired["wan_iface"] = "\"" wan_iface "\""
    desired["lan_ifaces"] = "[]"
    desired["allow_ssh_from"] = "[\"" ssh_cidr "\"]"
    desired["allow_dhcp_on_wan"] = dynamic_wan == "1" ? "true" : "false"
    desired["allow_client_internet"] = "true"
    desired["admin_iface"] = "\"helios0\""
    desired["split_tunnel_cidrs"] = "[]"
    desired["wg_iface"] = "\"helios0\""
    desired["wg_private_key"] = "\"\""
    desired["wg_address"] = "\"100.64.0.1/10\""
    desired["wg_listen_port"] = wg_port
    desired["key_negotiation_port"] = key_port
    desired["static_peer_addrs"] = "[]"
    desired["escrow_public_key"] = "\"" escrow_key "\""
    # Écrites plutôt que laissées au défaut de serde : une valeur visible dans
    # le fichier est une valeur qu on sait pouvoir changer. Ni l une ni l autre
    # n est « forced » — l operateur qui les ferme les garde fermées.
    desired["allow_tunnel_icmp"] = "true"
    desired["allow_ssh_over_tunnel"] = "true"
    desired["allow_gateway_egress"] = meshnet_cidrs != "" ? "true" : "false"
    if (meshnet_cidrs != "") {
        desired["nordvpn_meshnet"] = "{ iface = \"nordlynx\", fwmark = 0xe1f1, peer_cidrs = " meshnet_cidrs ", traffic_routing_peer_cidrs = " meshnet_routing_cidrs ", local_network_peer_cidrs = " meshnet_local_cidrs ", inbound_tcp_ports = [22, 49111], inbound_udp_ports = [], allow_icmp = true }"
    }

    forced["wan_iface"] = 1
    forced["wg_listen_port"] = 1
    forced["key_negotiation_port"] = 1
    forced["escrow_public_key"] = 1
    if (dynamic_wan == "1") {
        forced["allow_dhcp_on_wan"] = 1
    }
    if (meshnet_cidrs != "") {
        forced["allow_gateway_egress"] = 1
        forced["nordvpn_meshnet"] = 1
    }
}

function emit_missing(    i, key) {
    if (emitted) {
        return
    }
    for (i = 1; i <= order_count; i++) {
        key = order[i]
        if (!seen[key]) {
            print key " = " desired[key]
        }
    }
    emitted = 1
}

/^[[:space:]]*\[\[peers\]\][[:space:]]*$/ {
    emit_missing()
    in_peers = 1
    print
    next
}

{
    line = $0
    if (match(line, /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/)) {
        assignment = substr(line, RSTART, RLENGTH)
        sub(/^[[:space:]]*/, "", assignment)
        sub(/[[:space:]]*=.*/, "", assignment)
        key = assignment
        if (managed[key]) {
            if (in_peers) {
                next
            }
            if (seen[key]) {
                next
            }
            seen[key] = 1
            if (forced[key]) {
                print key " = " desired[key]
            } else if (key == "allow_ssh_from" &&
                       line ~ /=[[:space:]]*\[[[:space:]]*\][[:space:]]*$/) {
                print key " = " desired[key]
            } else {
                print line
            }
            next
        }
    }
    print line
}

END {
    emit_missing()
}
' "$CONFIG" > "$TEMP"

chmod --reference="$CONFIG" "$TEMP"
chown --reference="$CONFIG" "$TEMP"
mv -f "$TEMP" "$CONFIG"
trap - EXIT HUP INT TERM

echo "network configuration updated atomically: $CONFIG"
echo "previous version: $BACKUP"
