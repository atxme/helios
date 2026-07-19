#!/usr/bin/env bash
# Campagne de provisioning post-quantique en dry-run, de bout en bout.
#
# Monte un heliosd --dev isolé (config temporaire, jamais /var/lib/helios),
# déclare un pair de campagne, joue la campagne, puis démonte tout.
#
# Sur la cible, ne pas utiliser ce script : la gateway y tourne déjà et son
# `network.toml` est celui de production. Jouer plutôt, depuis le client :
#
#   helios-ctl --url http://100.64.0.1:8080 campaign \
#     --client-key <privée du client> --gateway-key <publique gateway>
#
# puis, depuis la gateway, la catégorie plan de données :
#
#   helios-ctl campaign --only plan-de-donnees --wg-iface helios0 \
#     --client-key <privée du client> --gateway-key <publique gateway>
#
# Voir docs/testing/TESTING.md.
set -euo pipefail

cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
DAEMON_PID=""

nettoyer() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
    [ -n "$DAEMON_PID" ] && wait "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap nettoyer EXIT

echo "==> Construction"
cargo build --quiet -p heliosd -p helios-ctl

# Clés de campagne, jetables : elles ne servent qu'à cette exécution et
# disparaissent avec le répertoire temporaire. `--generate-keys` n'écrit que des
# lignes CLÉ=valeur sur stdout ; l'aide part sur stderr, d'où le 2>/dev/null.
echo "==> Clés de campagne"
cargo run --quiet -p helios-ctl -- campaign --generate-keys 2>/dev/null > "$TMP/client.env"
cargo run --quiet -p helios-ctl -- campaign --generate-keys 2>/dev/null > "$TMP/gateway.env"
CLIENT_PRIV="$(sed -n 's/^WG_PRIVATE_KEY=//p' "$TMP/client.env")"
CLIENT_PUB="$(sed -n 's/^WG_PUBLIC_KEY=//p' "$TMP/client.env")"
GW_PRIV="$(sed -n 's/^WG_PRIVATE_KEY=//p' "$TMP/gateway.env")"
GW_PUB="$(sed -n 's/^WG_PUBLIC_KEY=//p' "$TMP/gateway.env")"

for v in CLIENT_PRIV CLIENT_PUB GW_PRIV GW_PUB; do
    [ -n "${!v}" ] || { echo "extraction de $v impossible" >&2; exit 1; }
done

cat > "$TMP/network.toml" <<EOF
wan_iface = "eth0"
wg_iface = "helios0"
wg_private_key = "$GW_PRIV"
wg_address = "100.64.0.1/10"
wg_listen_port = 51820

[[peers]]
name = "campagne"
public_key = "$CLIENT_PUB"
address = "100.64.1.2/32"
EOF

echo "==> Daemon dry-run isolé"
HELIOS_NETWORK_CONFIG="$TMP/network.toml" \
    cargo run --quiet -p heliosd -- run --dev > "$TMP/daemon.log" 2>&1 &
DAEMON_PID=$!

# Attendre que l'API réponde plutôt que de dormir un délai arbitraire.
for _ in $(seq 1 60); do
    if curl -sf http://127.0.0.1:8080/api/status > /dev/null 2>&1; then break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "le daemon s'est arrêté :" >&2
        cat "$TMP/daemon.log" >&2
        exit 1
    fi
    sleep 0.5
done

echo "==> Campagne"
# `--only` absent : les scénarios de plan de données se signalent d'eux-mêmes
# comme hors de portée, sans --wg-iface. C'est voulu — la sortie rappelle à
# chaque exécution ce que le dry-run ne prouve pas.
cargo run --quiet -p helios-ctl -- campaign \
    --client-key "$CLIENT_PRIV" \
    --gateway-key "$GW_PUB" \
    "$@"

echo "==> Vérification : aucun secret dans le journal du daemon"
if grep -qF "$CLIENT_PRIV" "$TMP/daemon.log"; then
    echo "ÉCHEC : une clé privée a été journalisée" >&2
    exit 1
fi
echo "    ok"
