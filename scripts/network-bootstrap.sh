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

usage() {
    cat >&2 <<'EOF'
Usage: network-bootstrap.sh --wan IFACE --ssh-cidr CIDR --escrow-public-key KEY [options]

  --config PATH
  --wg-port PORT
  --key-negotiation-port PORT
  --dynamic-wan
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
    -v dynamic_wan="$DYNAMIC_WAN" '
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

    forced["wan_iface"] = 1
    forced["wg_listen_port"] = 1
    forced["key_negotiation_port"] = 1
    forced["escrow_public_key"] = 1
    if (dynamic_wan == "1") {
        forced["allow_dhcp_on_wan"] = 1
    }
}

function emit_missing(    i, key) {
    if (emitted) {
        return
    }
    for (i = 1; i <= 16; i++) {
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
