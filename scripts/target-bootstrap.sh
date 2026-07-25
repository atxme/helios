#!/usr/bin/env bash
# Completes the operational bootstrap of one installed Helios gateway.
#
# Operator secrets stay under ~/.helios/certs. Each gateway gets a directory
# named after its SSH host; the internal client CA is shared deliberately so a
# fleet does not create a new trust root on every deployment.
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${1:-}"
[ -n "$TARGET" ] || { echo "target-bootstrap.sh requires an SSH target" >&2; exit 2; }

CERTS_ROOT="${HELIOS_CERTS_ROOT:-$HOME/.helios/certs}"
TARGET_HOST="${TARGET#*@}"
TARGET_ID="$(printf '%s' "$TARGET_HOST" | tr -c 'A-Za-z0-9._-' '_')"
TARGET_DIR="$CERTS_ROOT/$TARGET_ID"
CA_DIR="$CERTS_ROOT/internal-ca"
TARGET_CONFIG="$TARGET_DIR/target.conf"
REMOTE_HELIOSD="/opt/helios/current/heliosd"
REMOTE_NETWORK="/var/lib/helios/network.toml"

umask 077
mkdir -p "$CERTS_ROOT" "$TARGET_DIR"
chmod 700 "$CERTS_ROOT" "$TARGET_DIR"

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
WAN_IFACE="$(ssh "$TARGET" "ip -4 route show default" |
    awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
[ -n "$WAN_IFACE" ] || { echo "could not detect the gateway default interface" >&2; exit 1; }
case "$WAN_IFACE" in
    *[!A-Za-z0-9_.:-]*) echo "unsafe WAN interface returned by gateway" >&2; exit 1 ;;
esac

SSH_SOURCE="$(ssh "$TARGET" 'printf "%s\n" "$SSH_CONNECTION"' | awk '{print $1}')"
[ -n "$SSH_SOURCE" ] || { echo "could not detect the SSH source address" >&2; exit 1; }
case "$SSH_SOURCE" in
    *:*) SSH_CIDR="$SSH_SOURCE/128" ;;
    *) SSH_CIDR="$SSH_SOURCE/32" ;;
esac

DYNAMIC_ARG=()
if ssh "$TARGET" "ip -4 addr show dev '$WAN_IFACE'" | grep -qw dynamic; then
    DYNAMIC_ARG=(--dynamic-wan)
fi

{
    printf 'wan_iface = "%s"\n' "$WAN_IFACE"
    printf 'allow_ssh_from = ["%s"]\n' "$SSH_CIDR"
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
ssh -t "$TARGET" "sudo sh /tmp/helios-network-bootstrap.sh \
    --config '$REMOTE_NETWORK' \
    --wan '$WAN_IFACE' \
    --ssh-cidr '$SSH_CIDR' \
    --wg-port '$WG_PORT' \
    --key-negotiation-port '$KEY_PORT' \
    --escrow-public-key '$ESCROW_PUBLIC_KEY' \
    ${DYNAMIC_ARG[*]} && \
    sudo '$REMOTE_HELIOSD' status && \
    rm -f /tmp/helios-network-bootstrap.sh"

NEED_TPM=0
NEED_WG_IDENTITY=0
ssh "$TARGET" "test -f /var/lib/helios/sealed.key" || NEED_TPM=1
ssh "$TARGET" "test -f /var/lib/helios/wg-key.sealed" || NEED_WG_IDENTITY=1
if [ "$NEED_TPM" -eq 1 ] || [ "$NEED_WG_IDENTITY" -eq 1 ]; then
    echo "==> Provisioning missing sealed identities"
    ssh -t "$TARGET" "
        if [ '$NEED_TPM' -eq 1 ]; then
            sudo '$REMOTE_HELIOSD' provision-tpm
        fi
        if [ '$NEED_WG_IDENTITY' -eq 1 ]; then
            sudo '$REMOTE_HELIOSD' init-identity
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
        printf 'profile=%s/%s.orionprofile\n' "$TARGET_DIR" "$CLIENT_NAME"
    } > "$ENROLLMENT_STATE"
    chmod 600 "$ENROLLMENT_STATE"
else
    echo "==> Orion administrator already enrolled"
fi

echo "==> Starting deployed services and staging the encrypted escrow"
REMOTE_ESCROW="/tmp/helios-wg-key.escrow"
ssh -t "$TARGET" "
    sudo systemctl enable heliosd helios-update.path >/dev/null
    sudo systemctl restart heliosd
    sudo systemctl start helios-update.path
    sudo systemctl --no-pager --full status heliosd
    if sudo test -f /var/lib/helios/wg-key.escrow; then
        sudo install -m 600 /var/lib/helios/wg-key.escrow '$REMOTE_ESCROW'
        sudo chown \$(id -u):\$(id -g) '$REMOTE_ESCROW'
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
