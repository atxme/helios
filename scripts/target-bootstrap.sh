#!/usr/bin/env bash
# Completes the operational bootstrap of one installed Helios gateway.
#
# Operator secrets stay under ~/.helios/certs. Each gateway gets a directory
# named after its SSH host; the internal client CA is shared deliberately so a
# fleet does not create a new trust root on every deployment.
set -euo pipefail

# Absolute, and resolved **before** the `cd`: `dirname "$0"` is relative to the
# working directory, so computing it afterwards makes it point somewhere else.
# Invoked as `./target-bootstrap.sh` from `scripts/`, it resolved to «.», the
# `cd ..` moved to the repository root, and the sourced path was looked up
# there — failing only when called from that one directory.
SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPTS/.."

# Un seul mot de passe sudo pour tout le déploiement, et l'adresse de la
# gateway : voir lib-remote.sh.
# shellcheck source=scripts/lib-remote.sh
. "$SCRIPTS/lib-remote.sh"

TARGET=""
FIREWALL_MODE=preserve
while [ "$#" -gt 0 ]; do
    case "$1" in
        --disable-firewall) FIREWALL_MODE=disabled; shift ;;
        --enable-firewall) FIREWALL_MODE=enabled; shift ;;
        -*) echo "unknown target-bootstrap option: $1" >&2; exit 2 ;;
        *)
            [ -z "$TARGET" ] || { echo "target-bootstrap accepts one SSH target" >&2; exit 2; }
            TARGET="$1"
            shift
            ;;
    esac
done
TARGET="${TARGET:-$HELIOS_CIBLE}"
[ -n "$TARGET" ] || { echo "target-bootstrap.sh requires an SSH target" >&2; exit 2; }

# Une seule invite pour tout le déploiement, prise **ici** : dans un pipeline,
# `helios_ssh_sudo` tourne en sous-shell et le mot de passe y serait perdu.
helios_sudo_init "$TARGET"

CERTS_ROOT="${HELIOS_CERTS_ROOT:-$HOME/.helios/certs}"
TARGET_HOST="${TARGET#*@}"
ADDRESS_ID="$(printf '%s' "$TARGET_HOST" | tr -c 'A-Za-z0-9._-' '_')"

# The deployment state is indexed on the **machine**, not on the address used
# to reach it.
#
# Indexing on the address is what caused the 2026-09-01 lockout: the same
# gateway reached at a second address got an empty state directory, so the
# `client-enrollment.conf` guard below saw no enrolment, re-issued the admin
# certificate, and the client still holding the previous one stopped being
# admitted. A gateway has many addresses — LAN, Tailscale, NordVPN — and which
# one an operator types is not an identity.
#
# `/etc/machine-id` is stable across addresses and reboots, exists on every
# systemd host, and does not depend on Helios being up to be readable.
MACHINE_ID="$(ssh "$TARGET" 'cat /etc/machine-id 2>/dev/null' | tr -cd 'a-f0-9')"
if [ -n "$MACHINE_ID" ]; then
    TARGET_ID="$MACHINE_ID"
else
    echo "    /etc/machine-id illisible : repli sur l'adresse ($ADDRESS_ID)" >&2
    TARGET_ID="$ADDRESS_ID"
fi
TARGET_DIR="$CERTS_ROOT/$TARGET_ID"

# Adopt the state a previous address-indexed run left behind, rather than
# treating this machine as new — re-enrolling is exactly the failure this
# indexing change exists to prevent. Only ever a rename of an existing
# directory: nothing is merged, so no enrolment can be silently overwritten.
if [ ! -d "$TARGET_DIR" ] && [ -d "$CERTS_ROOT/$ADDRESS_ID" ]; then
    echo "==> Reprise de l'état de déploiement $ADDRESS_ID -> $TARGET_ID"
    mv "$CERTS_ROOT/$ADDRESS_ID" "$TARGET_DIR"
fi
CA_DIR="$CERTS_ROOT/internal-ca"
TARGET_CONFIG="$TARGET_DIR/target.conf"
REMOTE_HELIOSD="/opt/helios/current/heliosd"
REMOTE_NETWORK="/var/lib/helios/network.toml"

umask 077
mkdir -p "$CERTS_ROOT" "$TARGET_DIR"
chmod 700 "$CERTS_ROOT" "$TARGET_DIR"

# Every address this machine has been reached at, so an operator can tell which
# directory belongs to which gateway without decoding a machine-id.
if ! grep -qxF "$TARGET_HOST" "$TARGET_DIR/aliases" 2>/dev/null; then
    printf '%s\n' "$TARGET_HOST" >> "$TARGET_DIR/aliases"
    chmod 600 "$TARGET_DIR/aliases"
fi

read_setting() {
    setting="$1"
    sed -n "s/^${setting}=//p" "$TARGET_CONFIG" 2>/dev/null | head -1
}

if [ ! -f "$TARGET_CONFIG" ]; then
    SERVER_NAME="${HELIOS_SERVER_NAME:-$TARGET_HOST}"
    WG_PORT="${HELIOS_WG_PORT:-51820}"
    KEY_PORT="${HELIOS_KEY_NEGOTIATION_PORT:-51821}"
    WG_ENDPOINT="${HELIOS_WG_ENDPOINT:-$SERVER_NAME:$WG_PORT}"
    DEFAULT_CLIENT="${HELIOS_DEPLOY_CLIENT_NAME:-poste-windows}"
    {
        printf 'target=%s\n' "$TARGET"
        printf 'server_name=%s\n' "$SERVER_NAME"
        printf 'wireguard_endpoint=%s\n' "$WG_ENDPOINT"
        printf 'wireguard_port=%s\n' "$WG_PORT"
        printf 'key_negotiation_port=%s\n' "$KEY_PORT"
        printf 'default_client=%s\n' "$DEFAULT_CLIENT"
    } > "$TARGET_CONFIG"
    chmod 600 "$TARGET_CONFIG"
else
    SERVER_NAME="$(read_setting server_name)"
    WG_ENDPOINT="$(read_setting wireguard_endpoint)"
    WG_PORT="$(read_setting wireguard_port)"
    KEY_PORT="$(read_setting key_negotiation_port)"
    DEFAULT_CLIENT="$(read_setting default_client)"
fi

[ -n "$SERVER_NAME" ] || { echo "server_name is missing in $TARGET_CONFIG" >&2; exit 1; }
[ -n "$WG_ENDPOINT" ] || { echo "wireguard_endpoint is missing in $TARGET_CONFIG" >&2; exit 1; }
[ -n "$WG_PORT" ] || { echo "wireguard_port is missing in $TARGET_CONFIG" >&2; exit 1; }
[ -n "$KEY_PORT" ] || { echo "key_negotiation_port is missing in $TARGET_CONFIG" >&2; exit 1; }
[ -n "$DEFAULT_CLIENT" ] || { echo "default_client is missing in $TARGET_CONFIG" >&2; exit 1; }

case "$SERVER_NAME" in
    *[!A-Za-z0-9._:-]*) echo "unsafe server_name in $TARGET_CONFIG" >&2; exit 1 ;;
esac
case "$WG_PORT:$KEY_PORT" in
    *[!0-9:]*) echo "invalid ports in $TARGET_CONFIG" >&2; exit 1 ;;
esac
case "$DEFAULT_CLIENT" in
    *[!A-Za-z0-9._-]*) echo "unsafe default_client in $TARGET_CONFIG" >&2; exit 1 ;;
esac

echo "==> Operational state  $TARGET_DIR"

# Preserve an authority created by an older workflow instead of silently
# replacing it. The source is intentionally left untouched for manual review.
if [ ! -f "$CA_DIR/orion-client-ca.der" ]; then
    for LEGACY_CA in "$PWD/orion-client-ca" "$HOME/.helios/orion-client-ca"; do
        if [ -f "$LEGACY_CA/orion-client-ca.der" ] &&
           [ -f "$LEGACY_CA/orion-client-ca-key.der" ] &&
           [ -f "$LEGACY_CA/orion-client-pq-ca-public.bin" ] &&
           [ -f "$LEGACY_CA/orion-client-pq-ca-private.bin" ]; then
            mkdir -p "$CA_DIR"
            chmod 700 "$CA_DIR"
            install -m 644 "$LEGACY_CA/orion-client-ca.der" "$CA_DIR/"
            install -m 600 "$LEGACY_CA/orion-client-ca-key.der" "$CA_DIR/"
            install -m 644 "$LEGACY_CA/orion-client-pq-ca-public.bin" "$CA_DIR/"
            install -m 600 "$LEGACY_CA/orion-client-pq-ca-private.bin" "$CA_DIR/"
            echo "    existing client CA copied from $LEGACY_CA"
            echo "    source retained; remove it manually after checking the secured copy"
            break
        fi
    done
fi

ESCROW_DIR="$TARGET_DIR/escrow"
if [ ! -f "$ESCROW_DIR/escrow-private.key" ] ||
   [ ! -f "$ESCROW_DIR/escrow-public.key" ]; then
    [ ! -e "$ESCROW_DIR" ] ||
        { echo "incomplete escrow directory: $ESCROW_DIR" >&2; exit 1; }
    echo "==> Generating target-specific escrow identity"
    cargo run --quiet -p helios-ctl -- escrow keygen --output-dir "$ESCROW_DIR" >/dev/null
fi
ESCROW_PUBLIC_KEY="$(tr -d '\r\n' < "$ESCROW_DIR/escrow-public.key")"
case "$ESCROW_PUBLIC_KEY" in
    *[!A-Za-z0-9+/=]*) echo "invalid escrow public key" >&2; exit 1 ;;
esac

echo "==> Detecting gateway network"
# Détecté pour le diagnostic et pour la question du bail DHCP ci-dessous — pas
# pour être écrit dans network.toml. Ce qui y est écrit est « auto », par
# l'argument `--wan` passé à network-bootstrap.sh plus bas : c'est lui qui
# fusionne le fichier de la gateway, et lui seul. Figer le nom détecté ferait
# qu\'un câble branché plus tard ne serait jamais permis, et qu\'une machine
# renommant ses interfaces démarrerait sur une interface disparue.
WAN_IFACE="$(ssh "$TARGET" "ip -4 route show default" |
    awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
[ -n "$WAN_IFACE" ] || { echo "could not detect the gateway default interface" >&2; exit 1; }
echo "    uplink actuel : $WAN_IFACE (écrit « auto » ; heliosd rechoisit au démarrage)"
case "$WAN_IFACE" in
    *[!A-Za-z0-9_.:-]*) echo "unsafe WAN interface returned by gateway" >&2; exit 1 ;;
esac

SSH_SOURCE="$(ssh "$TARGET" 'printf "%s\n" "$SSH_CONNECTION"' | awk '{print $1}')"
[ -n "$SSH_SOURCE" ] || { echo "could not detect the SSH source address" >&2; exit 1; }
case "$SSH_SOURCE" in
    *:*) SSH_CIDR="$SSH_SOURCE/128" ;;
    *) SSH_CIDR="$SSH_SOURCE/32" ;;
esac

# The interface this deployment actually arrives on, asked of the kernel that
# routes it back. This is the pivot of the whole check below: an address tells
# us nothing about which overlay carries it, and the overlay is what decides
# whether the rule we are about to write survives a `heliosd` restart.
SSH_ARRIVAL_IFACE="$(ssh "$TARGET" "ip route get '$SSH_SOURCE' 2>/dev/null" |
    awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"

# Refuse to pin SSH to an address that only exists while Helios is up.
#
# This is the 2026-09-01 lockout, encoded. The deployment was reached at a
# CGNAT address that Helios itself routes, so `$SSH_CONNECTION` reported a peer
# VIP; `allow_ssh_from` was pinned to it, `heliosd` restarted, the tunnel went
# down and took the only permitted SSH source with it. `aether` now refuses
# such a config outright — this catches it before it is ever written, where the
# operator can still act on the advice.
HELIOS_WG_IFACE="${HELIOS_WG_IFACE:-helios0}"
if [ "$SSH_ARRIVAL_IFACE" = "$HELIOS_WG_IFACE" ]; then
    cat >&2 <<EOF
    Ce déploiement passe par le tunnel Helios lui-même ($SSH_ARRIVAL_IFACE,
    source $SSH_SOURCE). Épingler allow_ssh_from sur cette adresse produirait
    une règle qui disparaît au prochain redémarrage de heliosd — c'est
    exactement le verrouillage du 1er septembre 2026.

    Relancez depuis un chemin qui survit à une coupure du tunnel : le LAN, ou
    une interface d'administration hors-bande (Tailscale, NordVPN).
EOF
    exit 1
fi

# Out-of-band administration interfaces: the way back in when the tunnel is
# the thing that broke. Detected here and *proposed*, never opened silently —
# HELIOS_ADMIN_IFACES is what actually decides, so nothing reaches the firewall
# that the operator did not name.
#
# Filtered by interface rather than by address on purpose: Tailscale carries a
# v4 and a v6, NordVPN's address follows the server it picked, and an address
# list stops matching the day either moves — the day the recovery path is
# needed. One `iifname` covers every address the interface will ever hold.
ADMIN_IFACE_CANDIDATES="$(ssh "$TARGET" '
    ip -brief link show 2>/dev/null |
        awk "{print \$1}" |
        sed "s/@.*//" |
        grep -E "^(tailscale[0-9]*|nordlynx|zt[a-z0-9]+|tun[0-9]+)$" |
        sort -u
')"
ADMIN_IFACES="${HELIOS_ADMIN_IFACES-}"
if [ -z "${HELIOS_ADMIN_IFACES+set}" ]; then
    # Unset (not merely empty): adopt the interface this deployment arrives on
    # when it is one of the recognised overlays. That is the one path we have
    # positive evidence works — the operator is using it right now.
    for candidate in $ADMIN_IFACE_CANDIDATES; do
        if [ "$candidate" = "$SSH_ARRIVAL_IFACE" ]; then
            ADMIN_IFACES="$candidate"
        fi
    done
fi
if [ -n "$ADMIN_IFACE_CANDIDATES" ]; then
    echo "    Interfaces d'administration détectées : $(printf '%s' "$ADMIN_IFACE_CANDIDATES" | paste -sd' ' -)"
    echo "    Retenues (HELIOS_ADMIN_IFACES) : ${ADMIN_IFACES:-aucune}"
fi
for iface in $ADMIN_IFACES; do
    case "$iface" in
        *[!A-Za-z0-9_.:-]*) echo "unsafe administration interface name: $iface" >&2; exit 1 ;;
    esac
    if [ "$iface" = "$HELIOS_WG_IFACE" ] || [ "$iface" = "$WAN_IFACE" ]; then
        echo "admin_ifaces must not name the Helios tunnel or the WAN: $iface" >&2
        exit 1
    fi
done

DYNAMIC_ARG=()
if ssh "$TARGET" "ip -4 addr show dev '$WAN_IFACE'" | grep -qw dynamic; then
    DYNAMIC_ARG=(--dynamic-wan)
fi

# NordVPN owns the Meshnet peer inventory. Reading the running interface keeps
# deployment generic: no account-specific Meshnet address is baked into this
# repository, and every actual /32 is projected into Helios' bounded policy.
MESHNET_CIDRS="$(helios_ssh_sudo_capture "$TARGET" '
    if wg show nordlynx >/dev/null 2>&1; then
        wg show nordlynx allowed-ips |
            awk '\''{ for (i = 2; i <= NF; i++) print $i }'\'' |
            grep -E '\''^[0-9]+(\.[0-9]+){3}/32$'\'' |
            sort -u | paste -sd, -
    fi
')"
MESHNET_ARG=()
if [ -n "$MESHNET_CIDRS" ]; then
    case "$MESHNET_CIDRS" in
        *[!0-9.,/]*) echo "unsafe Meshnet CIDR inventory returned by gateway" >&2; exit 1 ;;
    esac
    MESHNET_ARG=(--meshnet-peer-cidrs "$MESHNET_CIDRS")

    # NordVPN keeps routing and LAN permissions in per-peer nftables sets.
    # Mirror those sets into Helios instead of granting forwarding to every
    # peer merely because it may contact a local service.
    MESHNET_ROUTING_CIDRS="$(helios_ssh_sudo_capture "$TARGET" '
        nft list set inet nordvpn allow_peer_traffic_routing 2>/dev/null |
            grep -Eo '\''([0-9]{1,3}\.){3}[0-9]{1,3}'\'' |
            sort -u | sed '\''s|$|/32|'\'' | paste -sd, -
    ')"
    MESHNET_LOCAL_NETWORK_CIDRS="$(helios_ssh_sudo_capture "$TARGET" '
        nft list set inet nordvpn peer_local_network_access 2>/dev/null |
            grep -Eo '\''([0-9]{1,3}\.){3}[0-9]{1,3}'\'' |
            sort -u | sed '\''s|$|/32|'\'' | paste -sd, -
    ')"
    for permission_cidrs in "$MESHNET_ROUTING_CIDRS" "$MESHNET_LOCAL_NETWORK_CIDRS"; do
        case "$permission_cidrs" in
            *[!0-9.,/]*) echo "unsafe Meshnet permission inventory returned by gateway" >&2; exit 1 ;;
        esac
    done
    if [ -n "$MESHNET_ROUTING_CIDRS" ]; then
        MESHNET_ARG+=(--meshnet-routing-peer-cidrs "$MESHNET_ROUTING_CIDRS")
    fi
    if [ -n "$MESHNET_LOCAL_NETWORK_CIDRS" ]; then
        MESHNET_ARG+=(--meshnet-local-network-peer-cidrs "$MESHNET_LOCAL_NETWORK_CIDRS")
    fi
    echo "    Meshnet      : $MESHNET_CIDRS (SSH et Fileshare entrants)"
    echo "    Routage      : ${MESHNET_ROUTING_CIDRS:-aucun}"
    echo "    Réseau local : ${MESHNET_LOCAL_NETWORK_CIDRS:-aucun}"
fi

{
    printf 'wan_iface = "auto"\n'
    printf 'allow_ssh_from = ["%s"]\n' "$SSH_CIDR"
    if [ -n "$ADMIN_IFACES" ]; then
        printf 'admin_ifaces = [%s]\n' \
            "$(printf '%s\n' $ADMIN_IFACES | sed 's/.*/"&"/' | paste -sd, -)"
    fi
    if [ "${#DYNAMIC_ARG[@]}" -gt 0 ]; then
        printf 'allow_dhcp_on_wan = true\n'
    else
        printf 'allow_dhcp_on_wan = false\n'
    fi
    printf 'allow_client_internet = true\n'
    printf 'wg_listen_port = %s\n' "$WG_PORT"
    printf 'key_negotiation_port = %s\n' "$KEY_PORT"
    printf 'escrow_public_key = "%s"\n' "$ESCROW_PUBLIC_KEY"
} > "$TARGET_DIR/network-bootstrap.toml"
chmod 600 "$TARGET_DIR/network-bootstrap.toml"

echo "==> Merging network configuration"
scp -q scripts/network-bootstrap.sh "$TARGET:/tmp/helios-network-bootstrap.sh"
helios_ssh_sudo "$TARGET" "sh /tmp/helios-network-bootstrap.sh \
    --config '$REMOTE_NETWORK' \
    --wan 'auto' \
    --ssh-cidr '$SSH_CIDR' \
    --wg-port '$WG_PORT' \
    --key-negotiation-port '$KEY_PORT' \
    --escrow-public-key '$ESCROW_PUBLIC_KEY' \
    ${ADMIN_IFACES:+--admin-ifaces \"$(printf '%s' $ADMIN_IFACES | tr ' ' ,)\"} \
    ${MESHNET_ARG[*]} \
    ${DYNAMIC_ARG[*]} && \
    '$REMOTE_HELIOSD' status && \
    rm -f /tmp/helios-network-bootstrap.sh"

NEED_TPM=0
NEED_WG_IDENTITY=0
ssh "$TARGET" "test -f /var/lib/helios/sealed.key" || NEED_TPM=1
ssh "$TARGET" "test -f /var/lib/helios/wg-key.sealed" || NEED_WG_IDENTITY=1
if [ "$NEED_TPM" -eq 1 ] || [ "$NEED_WG_IDENTITY" -eq 1 ]; then
    echo "==> Provisioning missing sealed identities"
    helios_ssh_sudo "$TARGET" "
        if [ '$NEED_TPM' -eq 1 ]; then
            '$REMOTE_HELIOSD' provision-tpm
        fi
        if [ '$NEED_WG_IDENTITY' -eq 1 ]; then
            '$REMOTE_HELIOSD' init-identity
        fi
    " | tee "$TARGET_DIR/init-identity.log"
    if [ "$NEED_WG_IDENTITY" -eq 1 ]; then
        GATEWAY_WG_PUBLIC="$(grep -oE '[A-Za-z0-9+/]{43}=' \
            "$TARGET_DIR/init-identity.log" | head -1)"
        [ -n "$GATEWAY_WG_PUBLIC" ] ||
            { echo "could not read the gateway WireGuard public key" >&2; exit 1; }
        printf '%s\n' "$GATEWAY_WG_PUBLIC" > "$TARGET_DIR/gateway-wireguard-public.key"
        chmod 600 "$TARGET_DIR/gateway-wireguard-public.key"
    fi
fi

echo "==> Creating or reusing gateway key-negotiation identity"
HELIOS_CLIENT_CA_DIR="$CA_DIR" \
HELIOS_KEYNEGO_OUT="$TARGET_DIR" \
    ./scripts/key-negotiation-setup.sh "$TARGET" \
        --server-name "$SERVER_NAME" \
        --endpoint "$WG_ENDPOINT" \
        --port-nego "$KEY_PORT" \
        --skip-network \
        --gateway-only

ENROLLMENT_STATE="$TARGET_DIR/client-enrollment.conf"
if [ ! -f "$ENROLLMENT_STATE" ]; then
    echo "==> Selecting the first Orion administrator"
    [ -s "$TARGET_DIR/peer-list.log" ] ||
        { echo "gateway peer inventory is missing" >&2; exit 1; }
    PEER_LIST="$(cat "$TARGET_DIR/peer-list.log")"
    ADMIN_LINE="$(printf '%s\n' "$PEER_LIST" |
        awk -F '\t' '$3 ~ /\[admin\]/ { print; exit }')"

    CLIENT_NAME="$DEFAULT_CLIENT"
    CLIENT_PUBLIC_KEY=""
    REPLACE_ARGS=()
    if [ -n "$ADMIN_LINE" ]; then
        CLIENT_NAME="$(printf '%s\n' "$ADMIN_LINE" | awk -F '\t' '{print $1}')"
        CLIENT_PUBLIC_KEY="$(printf '%s\n' "$ADMIN_LINE" |
            awk -F '\t' '{split($3, fields, " "); print fields[1]}')"
        case "$CLIENT_NAME" in
            *[!A-Za-z0-9._-]*) echo "existing admin peer name is not automation-safe" >&2; exit 1 ;;
        esac
        case "$CLIENT_PUBLIC_KEY" in
            *[!A-Za-z0-9+/=]*) echo "existing admin peer has an invalid public key" >&2; exit 1 ;;
        esac
        REPLACE_ARGS=(--public-key "$CLIENT_PUBLIC_KEY" --remplacer)
        echo "    existing admin selected: $CLIENT_NAME"
    else
        echo "    no admin peer found; a new $CLIENT_NAME identity will be generated"
    fi

    HELIOS_CLIENT_CA_DIR="$CA_DIR" \
    HELIOS_KEYNEGO_OUT="$TARGET_DIR" \
        ./scripts/key-negotiation-setup.sh "$TARGET" \
            --nom "$CLIENT_NAME" \
            --server-name "$SERVER_NAME" \
            --endpoint "$WG_ENDPOINT" \
            --port-nego "$KEY_PORT" \
            --mode ml-kem \
            --admin \
            --skip-network \
            --client-only \
            "${REPLACE_ARGS[@]}"

    {
        printf 'name=%s\n' "$CLIENT_NAME"
        printf 'public_key=%s\n' "$CLIENT_PUBLIC_KEY"
        printf 'profile=%s/%s.orion\n' "$TARGET_DIR" "$CLIENT_NAME"
    } > "$ENROLLMENT_STATE"
    chmod 600 "$ENROLLMENT_STATE"
else
    echo "==> Orion administrator already enrolled"
fi

echo "==> Starting deployed services and staging the encrypted escrow"
REMOTE_ESCROW="/tmp/helios-wg-key.escrow"
FIREWALL_DROPIN_DIR="/etc/systemd/system/heliosd.service.d"
FIREWALL_DROPIN="$FIREWALL_DROPIN_DIR/firewall-maintenance.conf"
case "$FIREWALL_MODE" in
    disabled)
        echo "==> Enabling persistent Helios firewall maintenance mode"
        helios_ssh_sudo "$TARGET" "
            install -d -m 755 '$FIREWALL_DROPIN_DIR'
            printf '%s\n' \
                '[Service]' \
                'ExecStart=' \
                'ExecStart=/opt/helios/current/heliosd run --unsafe-disable-firewall' \
                > '$FIREWALL_DROPIN'
            chmod 644 '$FIREWALL_DROPIN'
            systemctl unmask --runtime heliosd.service
            systemctl daemon-reload
        "
        ;;
    enabled)
        echo "==> Re-enabling fail-closed Helios firewall enforcement"
        helios_ssh_sudo "$TARGET" "
            rm -f '$FIREWALL_DROPIN'
            systemctl unmask --runtime heliosd.service
            systemctl daemon-reload
        "
        ;;
    preserve)
        if ssh "$TARGET" "test -f '$FIREWALL_DROPIN'"; then
            echo "==> Preserving existing Helios firewall maintenance mode"
        fi
        ;;
esac
# `heliosd` reconstruit le pare-feu au démarrage, sur le lien même par lequel
# cette session passe. Le redémarrer **dans** la session, c'est demander à la
# commande de survivre à la coupure de son propre transport : la connexion se
# fige sans jamais se fermer, et il ne reste que Ctrl+C.
#
# `systemd-run` le détache : la commande rend la main tout de suite, le
# redémarrage se fait hors de la session, et l'état se relit ensuite sur une
# connexion neuve.
helios_ssh_sudo "$TARGET" "
    systemctl enable heliosd helios-update.path >/dev/null
    systemctl start helios-update.path
    systemd-run --collect --unit=helios-deploy-restart \
        systemctl restart heliosd >/dev/null
"

echo "    redémarrage détaché ; attente de la remontée du service"
DEMARRE=0
# One deployment may still be stopping the previous binary, whose raw
# speedtest listener waited for systemd's 90-second kill timeout. The new
# binary exits promptly, but the first upgrade must wait long enough to cross
# that old behavior once instead of falsely reporting a failed installation.
for _ in $(seq 1 60); do
    sleep 2
    if ssh "${HELIOS_SSH_OPTS[@]}" "$TARGET" 'systemctl is-active --quiet heliosd' 2>/dev/null; then
        DEMARRE=1
        break
    fi
done
if [ "$DEMARRE" = "0" ]; then
    echo "    heliosd n'est pas remonté en 120 s :" >&2
    ssh "${HELIOS_SSH_OPTS[@]}" "$TARGET" \
        'systemctl --no-pager --full status heliosd' >&2 || true
    exit 1
fi
ssh "${HELIOS_SSH_OPTS[@]}" "$TARGET" 'systemctl --no-pager --full status heliosd' || true

if [ "$FIREWALL_MODE" = "disabled" ]; then
    readiness="$(helios_ssh_sudo_capture "$TARGET" \
        "cat /run/helios/ready 2>/dev/null || true")"
    printf '%s\n' "$readiness" | grep -qx 'firewall_enforced=false' || {
        echo "    heliosd n'annonce pas le mode firewall désactivé" >&2
        exit 1
    }
    if helios_ssh_sudo "$TARGET" "nft list table inet helios >/dev/null 2>&1"; then
        echo "    la table inet helios existe encore malgré le mode maintenance" >&2
        exit 1
    fi
    echo "    firewall Helios désactivé et table inet helios absente"
fi

helios_ssh_sudo "$TARGET" "
    if test -f /var/lib/helios/wg-key.escrow; then
        install -m 600 /var/lib/helios/wg-key.escrow '$REMOTE_ESCROW'
        chown \$SUDO_UID:\$SUDO_GID '$REMOTE_ESCROW'
    fi
"

if ssh "$TARGET" "test -f '$REMOTE_ESCROW'"; then
    scp -q "$TARGET:$REMOTE_ESCROW" "$TARGET_DIR/wg-key.escrow"
    ssh "$TARGET" "rm -f '$REMOTE_ESCROW'"
    chmod 600 "$TARGET_DIR/wg-key.escrow"
fi

cat <<EOF

Operational bootstrap complete.

  Target state:  $TARGET_DIR
  Target config: $TARGET_CONFIG
  Orion profile: $(sed -n 's/^profile=//p' "$ENROLLMENT_STATE")

Import the Orion profile once, then remove that profile file because it carries
the client private identity. Keep $CERTS_ROOT backed up and off the gateway.
EOF
