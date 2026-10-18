#!/usr/bin/env bash
# Banc de développement : une gateway, un client admis, un profil émis.
#
# Monte un heliosd --dev isolé, admet un client par l'API, émet son profil Orion
# et joue la campagne — le tout avec les **mêmes outils qu'en production**
# (ADR-004). C'est délibéré : le banc valide l'outillage d'exploitation en même
# temps qu'il sert au développement. Un chemin de test parallèle ne prouverait
# que lui-même.
#
#   bash scripts/lab.sh              # monte, éprouve, démonte
#   bash scripts/lab.sh --keep       # laisse le banc vivant pour l'exploration
#
# Le client est admis avec ses certificats de négociation TLS et PQ, émis par
# une CA cliente jetable. Le profil produit est une invitation, sans clé
# privée : il ne s'importe pas seul dans un Orion neuf.
#
# Rien n'est écrit hors du répertoire temporaire : ni /var/lib/helios, ni la
# configuration de production.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/cargo-budget.sh
source scripts/cargo-budget.sh
helios_budget_enter "$PWD"

URL="http://127.0.0.1:8080"
ENDPOINT="127.0.0.1:51820"
KEEP=0
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        *) ARGS+=("$arg") ;;
    esac
done

TMP="$(mktemp -d)"
DAEMON_PID=""

nettoyer() {
    if [ "$KEEP" = "1" ] && [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        return
    fi
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
    [ -n "$DAEMON_PID" ] && wait "$DAEMON_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap nettoyer EXIT

# Un banc déjà monté tiendrait le port : le nouveau daemon ne pourrait pas se
# lier et toutes les commandes suivantes s'adresseraient à l'ancien, avec sa
# configuration et ses pairs. Mieux vaut refuser que de piloter le mauvais.
if curl -sf "$URL/api/status" > /dev/null 2>&1; then
    echo "Refus : un heliosd écoute déjà sur ${URL#http://}." >&2
    echo "Un banc précédent est sans doute resté vivant (--keep) :" >&2
    echo "  pkill -f 'heliosd run'" >&2
    exit 1
fi

echo "==> Construction"
cargo build --quiet -p heliosd -p helios

echo "==> Identité de la gateway"
# `heliosd init-identity` n'est PAS utilisable ici : il scelle la clé dans le
# TPM, absent en --dev. Le banc passe donc par `wg_private_key` dans un
# network.toml jetable — le repli hérité que l'ADR-004 §3 conserve précisément
# pour le développement et les campagnes. Ne pas « corriger » cette incohérence
# apparente avec le chemin de production : elle est la conséquence de l'absence
# de TPM, pas un oubli.
cargo run --quiet -p helios -- campaign --generate-keys 2>/dev/null > "$TMP/gateway.env"
GW_PRIV="$(sed -n 's/^WG_PRIVATE_KEY=//p' "$TMP/gateway.env")"
GW_PUB="$(sed -n 's/^WG_PUBLIC_KEY=//p' "$TMP/gateway.env")"

cargo run --quiet -p helios -- campaign --generate-keys 2>/dev/null > "$TMP/client.env"
CLIENT_PRIV="$(sed -n 's/^WG_PRIVATE_KEY=//p' "$TMP/client.env")"
CLIENT_PUB="$(sed -n 's/^WG_PUBLIC_KEY=//p' "$TMP/client.env")"

for v in GW_PRIV GW_PUB CLIENT_PRIV CLIENT_PUB; do
    [ -n "${!v}" ] || { echo "extraction de $v impossible" >&2; exit 1; }
done

# La table de pairs est laissée VIDE : le client sera admis par l'API, comme en
# production. Le déclarer ici court-circuiterait exactement ce qu'on veut
# éprouver.
cat > "$TMP/network.toml" <<EOF
wan_iface = "eth0"
wg_iface = "helios0"
wg_private_key = "$GW_PRIV"
wg_address = "100.64.0.1/10"
wg_listen_port = 51820
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
    if curl -sf "$URL/api/status" > /dev/null 2>&1; then break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "le daemon s'est arrêté :" >&2
        cat "$TMP/daemon.log" >&2
        exit 1
    fi
    sleep 0.5
done

echo "==> Certificats de négociation du client"
# Admission requires the client's TLS and PQ key-negotiation certificates
# (floor `ml_kem`): the classic path is refused. A throwaway client CA lives in
# $TMP and disappears with the bench — it is never the operator's CA.
cargo run --quiet -p helios -- key-nego init-client-ca \
    --name lab-ca --output-dir "$TMP/client-ca" > /dev/null
cargo run --quiet -p helios -- key-nego issue-client --name lab \
    --ca-certificate "$TMP/client-ca/orion-client-ca.der" \
    --ca-private-key "$TMP/client-ca/orion-client-ca-key.der" \
    --ca-pq-private-key "$TMP/client-ca/orion-client-pq-ca-private.bin" \
    --wireguard-public-key "$CLIENT_PUB" \
    --output-dir "$TMP/client-cert" > "$TMP/issue-client.log"
CLIENT_CERT_SHA256="$(sed -n 's/^sha256: //p' "$TMP/issue-client.log")"
CLIENT_PQ_SHA256="$(sed -n 's/^PQ certificate sha256: //p' "$TMP/issue-client.log")"
for v in CLIENT_CERT_SHA256 CLIENT_PQ_SHA256; do
    [ -n "${!v}" ] || { echo "extraction de $v impossible" >&2; exit 1; }
done

echo "==> Admission du client"
# En dry-run, la boucle locale vaut administrateur simulé : `peer add` emprunte
# donc le même chemin API qu'un opérateur dans le tunnel.
cargo run --quiet -p helios -- --url "$URL" peer add \
    --name lab --public-key "$CLIENT_PUB" --admin \
    --key-negotiation-certificate-sha256 "$CLIENT_CERT_SHA256" \
    --key-negotiation-pq-certificate-sha256 "$CLIENT_PQ_SHA256" \
    --certificate "$TMP/client-cert/orion-client-cert.der" \
    --pq-certificate "$TMP/client-cert/orion-client-pq-cert.json"

echo "==> Émission du profil client"
# Invitation (ADR-004 §6) : l'opérateur part de la clé PUBLIQUE et ne fabrique
# aucun secret. Le pair étant déjà admis, l'outil réutilise son adresse au lieu
# d'échouer. Ce profil n'est PAS importable seul : Orion y complète la clé
# privée depuis le profil local de même nom.
#
# Le mode assisté (`--with-private-key`) a été retiré : il admettait un second
# pair sans certificats de négociation, ce que le plancher `ml_kem` refuse
# (ADR-004 §6, amendement du 18 octobre 2026).
cargo run --quiet -p helios -- --url "$URL" profile emit \
    --name lab --endpoint "$ENDPOINT" \
    --public-key "$CLIENT_PUB" \
    --output "$TMP/lab.invitation.orion"

echo "==> Contrôle du profil émis"
# Sans ce contrôle, une régression de l'émission passerait inaperçue jusqu'à un
# import manuel dans Orion.
python3 - "$TMP/lab.invitation.orion" <<'PY'
import json, sys

doc = json.load(open(sys.argv[1]))
if doc.get("format") != "orion-profile" or doc.get("version") != 1:
    raise SystemExit(f"ÉCHEC : en-tête inattendu dans le profil : {doc}")
profil = doc["profile"]
for champ in ("name", "endpoint", "peer_public_key", "address"):
    if not profil.get(champ):
        raise SystemExit(f"ÉCHEC : champ {champ} absent du profil")
if not profil["address"].endswith("/32"):
    raise SystemExit("ÉCHEC : VIP sans /32 dans le profil")
if "private_key" in profil:
    raise SystemExit("ÉCHEC : le profil d'invitation porte une clé privée")
print("    ok — invitation sans secret")
PY

echo "==> Campagne de bout en bout"
cargo run --quiet -p helios -- --url "$URL" campaign \
    --client-key "$CLIENT_PRIV" \
    --gateway-key "$GW_PUB" \
    ${ARGS[@]+"${ARGS[@]}"}

echo "==> Vérification : aucun secret dans le journal du daemon"
for secret in "$CLIENT_PRIV" "$GW_PRIV"; do
    if grep -qF "$secret" "$TMP/daemon.log"; then
        echo "ÉCHEC : une clé privée a été journalisée" >&2
        exit 1
    fi
done
echo "    ok"

echo
echo "──────────────────────────────────────────────────────────────"
echo "  Banc opérationnel."
echo
echo "  API gateway       $URL"
echo "  Clé publique      $GW_PUB"
echo "  Profil invitation $TMP/lab.invitation.orion    (sans secret)"
echo
if [ "$KEEP" = "1" ]; then
    echo "  Le daemon reste en vie (PID $DAEMON_PID)."
    echo
    echo "  Explorer :"
    echo "    cargo run -p helios -- --url $URL status"
    echo "    cargo run -p helios -- --url $URL peer list"
    echo "    cargo run -p helios -- --url $URL watch"
    echo
    echo "  Pour arrêter et tout effacer :"
    echo "    kill $DAEMON_PID && rm -rf $TMP"
else
    echo "  Démontage en cours — relancer avec --keep pour explorer."
fi
echo "──────────────────────────────────────────────────────────────"
