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
# Le profil produit est importable tel quel dans Orion : c'est le moyen le plus
# court d'éprouver l'IHM du client contre une vraie gateway.
#
# Rien n'est écrit hors du répertoire temporaire : ni /var/lib/helios, ni la
# configuration de production.
set -euo pipefail

cd "$(dirname "$0")/.."

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
cargo build --quiet -p heliosd -p helios-ctl

echo "==> Identité de la gateway"
# `heliosd init-identity` n'est PAS utilisable ici : il scelle la clé dans le
# TPM, absent en --dev. Le banc passe donc par `wg_private_key` dans un
# network.toml jetable — le repli hérité que l'ADR-004 §3 conserve précisément
# pour le développement et les campagnes. Ne pas « corriger » cette incohérence
# apparente avec le chemin de production : elle est la conséquence de l'absence
# de TPM, pas un oubli.
cargo run --quiet -p helios-ctl -- campaign --generate-keys 2>/dev/null > "$TMP/gateway.env"
GW_PRIV="$(sed -n 's/^WG_PRIVATE_KEY=//p' "$TMP/gateway.env")"
GW_PUB="$(sed -n 's/^WG_PUBLIC_KEY=//p' "$TMP/gateway.env")"

cargo run --quiet -p helios-ctl -- campaign --generate-keys 2>/dev/null > "$TMP/client.env"
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

echo "==> Admission du client"
# En dry-run, la boucle locale vaut administrateur simulé : `peer add` emprunte
# donc le même chemin API qu'un opérateur dans le tunnel.
cargo run --quiet -p helios-ctl -- --url "$URL" peer add \
    --name lab --public-key "$CLIENT_PUB" --admin

echo "==> Émission des profils client"
# Deux profils, parce que les deux modes de l'ADR-004 §6 ne servent pas à la
# même chose ici.
#
# 1. Invitation — mode recommandé : l'opérateur part de la clé PUBLIQUE et ne
#    fabrique aucun secret. Le pair étant déjà admis, l'outil réutilise son
#    adresse au lieu d'échouer. Ce profil n'est PAS importable seul : Orion y
#    complète la clé privée depuis le profil local de même nom.
cargo run --quiet -p helios-ctl -- --url "$URL" profile emit \
    --name lab --endpoint "$ENDPOINT" \
    --public-key "$CLIENT_PUB" \
    --output "$TMP/lab.invitation.json"

# 2. Assisté — l'opérateur génère la paire et livre un profil complet. C'est
#    celui-là qu'on importe dans un Orion neuf pour éprouver l'IHM : il porte la
#    clé privée, donc il fonctionne sans rien d'autre. Il admet un second pair.
cargo run --quiet -p helios-ctl -- --url "$URL" profile emit \
    --name lab-poste --endpoint "$ENDPOINT" \
    --with-private-key \
    --output "$TMP/lab-poste.json"

echo "==> Contrôle des profils émis"
# Sans ce contrôle, le banc afficherait deux chemins sans jamais vérifier ce
# qu'ils contiennent — et une régression de l'émission passerait inaperçue
# jusqu'à un import manuel dans Orion.
python3 - "$TMP/lab.invitation.json" "$TMP/lab-poste.json" <<'PY'
import json, sys

invitation, complet = (json.load(open(p)) for p in sys.argv[1:3])
for nom, doc in (("invitation", invitation), ("complet", complet)):
    if doc.get("format") != "orion-profile" or doc.get("version") != 1:
        raise SystemExit(f"ÉCHEC : en-tête inattendu dans le profil {nom} : {doc}")
    profil = doc["profile"]
    for champ in ("name", "endpoint", "peer_public_key", "address"):
        if not profil.get(champ):
            raise SystemExit(f"ÉCHEC : champ {champ} absent du profil {nom}")
    if not profil["address"].endswith("/32"):
        raise SystemExit(f"ÉCHEC : VIP sans /32 dans le profil {nom}")

if "private_key" in invitation["profile"]:
    raise SystemExit("ÉCHEC : le profil d'invitation porte une clé privée")
if not complet["profile"].get("private_key"):
    raise SystemExit("ÉCHEC : le profil assisté n'est pas importable tel quel")
if invitation["profile"]["peer_public_key"] != complet["profile"]["peer_public_key"]:
    raise SystemExit("ÉCHEC : les deux profils annoncent des gateways différentes")
print("    ok — invitation sans secret, profil assisté importable")
PY

echo "==> Campagne de bout en bout"
cargo run --quiet -p helios-ctl -- --url "$URL" campaign \
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
echo "  Profil importable $TMP/lab-poste.json"
echo "  Profil invitation $TMP/lab.invitation.json    (sans secret)"
echo
if [ "$KEEP" = "1" ]; then
    echo "  Le daemon reste en vie (PID $DAEMON_PID)."
    echo
    echo "  Importer lab-poste.json dans Orion, ou explorer :"
    echo "    cargo run -p helios-ctl -- --url $URL status"
    echo "    cargo run -p helios-ctl -- --url $URL peer list"
    echo "    cargo run -p helios-ctl -- --url $URL watch"
    echo
    echo "  lab-poste.json porte une clé privée : il disparaît avec le banc."
    echo "  Pour arrêter et tout effacer :"
    echo "    kill $DAEMON_PID && rm -rf $TMP"
else
    echo "  Démontage en cours — relancer avec --keep pour explorer."
fi
echo "──────────────────────────────────────────────────────────────"
