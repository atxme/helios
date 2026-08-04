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

# Un daemon résiduel — typiquement celui que `lab.sh --keep` laisse vivant —
# tiendrait le port et la campagne interrogerait *sa* configuration au lieu de
# celle qu'elle vient d'écrire. Les scénarios échoueraient alors sur « pair
# inconnu », un message qui n'a aucun rapport avec la cause.
if curl -sf http://127.0.0.1:8080/api/status > /dev/null 2>&1; then
    echo "Refus : un heliosd écoute déjà sur 127.0.0.1:8080." >&2
    echo "La campagne interrogerait ce daemon-là, pas le sien." >&2
    echo "L'arrêter d'abord (banc laissé vivant par 'lab.sh --keep' ?) :" >&2
    echo "  pkill -f 'heliosd run'" >&2
    exit 1
fi

echo "==> Construction"
cargo run --quiet -p helios-publisher -- keygen \
    --key-epoch 4294967294 --output-dir "$TMP/publisher"
export HELIOS_PUBLISHER_KEYRING_PATH="$TMP/publisher/publisher-keyring.json"
cargo build --quiet -p heliosd -p helios-ctl -p helios-publisher -p helios-installer

# Artefacts de campagne : des copies **strippées** des binaires de debug.
#
# Ce n'est pas une optimisation, c'est ce qui rend la campagne représentative.
# Un `heliosd` de debug pèse ~131 Mio dont 83 % d'informations de débogage, et
# dépasse donc `helios_update::MAX_BINARY_SIZE` (128 Mio) — une borne qui existe
# pour le chemin de mise à jour et qu'il serait absurde de relever pour
# accommoder un script. Aucun artefact réellement livré ne contient ces
# symboles : la campagne signait quelque chose six fois plus gros que ce
# qu'elle est censée éprouver.
if ! command -v strip > /dev/null; then
    echo "Refus : « strip » est introuvable (paquet binutils)." >&2
    echo "  La campagne ne peut pas produire d'artefact représentatif sans lui." >&2
    exit 1
fi
ARTIFACTS="$TMP/artifacts"
mkdir -p "$ARTIFACTS"
for binaire in heliosd helios-ctl helios-installer; do
    cp "target/debug/$binaire" "$ARTIFACTS/$binaire"
    strip "$ARTIFACTS/$binaire"
done

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
admin = true
EOF

echo "==> Daemon dry-run isolé"
HELIOS_NETWORK_CONFIG="$TMP/network.toml" \
HELIOS_UPDATE_STAGING="$TMP/updates" \
HELIOS_UPDATE_CHANNEL=testing \
HELIOS_READY_PATH="$TMP/ready" \
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

echo "==> Campagne de mise à jour applicative signée"
TARGET_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
GIT_COMMIT="$(git rev-parse --short=16 HEAD)"
PACKAGE_ID="$(cargo pkgid -p heliosd)"
HELIOS_VERSION="${PACKAGE_ID##*#}"
HELIOS_VERSION="${HELIOS_VERSION##*@}"
cargo run --quiet -p helios-publisher -- binary-release \
    --key-epoch 4294967294 \
    --release-sequence 9001 \
    --channel testing \
    --version "$HELIOS_VERSION" \
    --git-commit "$GIT_COMMIT" \
    --target "$TARGET_TRIPLE" \
    --binary "$ARTIFACTS/heliosd" \
    --ed25519-private-key "$TMP/publisher/ed25519-private.pk8" \
    --ml-dsa-65-private-key "$TMP/publisher/ml-dsa-65-private.bin" \
    --keyring "$TMP/publisher/publisher-keyring.json" \
    --output "$TMP/heliosd.release.json"
python3 scripts/update_campaign.py \
    --url http://127.0.0.1:8080 \
    --manifest "$TMP/heliosd.release.json" \
    --binary "$ARTIFACTS/heliosd" \
    --activate

echo "==> Campagne d'installation par bundle signé"
# Le bundle est vérifié contre le trousseau éditeur réellement compilé dans
# `helios-installer` — c'est ce que les tests unitaires, qui injectent un
# trousseau, ne peuvent pas prouver.
python3 scripts/bundle_campaign.py \
    --tmp "$TMP" \
    --epoch-dir "$TMP/publisher" \
    --version "$HELIOS_VERSION" \
    --git-commit "$GIT_COMMIT" \
    --target "$TARGET_TRIPLE" \
    --artifacts "$ARTIFACTS"

echo "==> Vérification : aucun secret dans le journal du daemon"
if grep -qF "$CLIENT_PRIV" "$TMP/daemon.log"; then
    echo "ÉCHEC : une clé privée a été journalisée" >&2
    exit 1
fi
echo "    ok"
