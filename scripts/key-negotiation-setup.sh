#!/usr/bin/env bash
# Met en place la négociation de clé PQC de bout en bout, et produit les deux
# fichiers de configuration à charger : celui de la gateway, celui d'Orion.
#
#   ./scripts/key-negotiation-setup.sh christophe@192.168.1.44 --nom portable
#
# Ce que le script enchaîne, dans l'ordre où chaque étape débloque la suivante :
#
#   1. CA opérateur (TLS + ML-DSA-65)     — poste opérateur, une seule fois
#   2. copie des CA PUBLIQUES             — vers la gateway
#   3. `heliosd init-key-negotiation`     — SUR la gateway, scellé au TPM
#   4. `network.toml` avec le port ouvert — chargé dans la gateway
#   5. `helios-ctl enroll`                — profil Orion + identité cliente
#
# Les clés privées de la CA restent sur le poste opérateur ; celles de la
# gateway naissent sur la gateway et ne sont jamais lues d'ici. Seul le fichier
# produit à l'étape 5 contient des secrets clients : il est en 0600 et doit être
# détruit après import dans Orion.
#
# Ce script ne construit ni ne déploie heliosd. Le binaire installé doit déjà
# porter la feature `key-negotiation` — c'est le cas depuis que
# `cargo xtask bundle` l'inclut. Pour mettre la gateway à jour : ./scripts/deploy.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# La CA opérateur vit HORS du dépôt : c'est une clé privée, elle n'a rien à
# faire dans un arbre versionné où un `git add -A` finirait par l'attraper.
CA_DIR="${HELIOS_CLIENT_CA_DIR:-$HOME/.helios/orion-client-ca}"
SORTIE="${HELIOS_KEYNEGO_OUT:-$PWD/target/key-negotiation}"
ETAT="${HELIOS_DEPLOY_STATE:-$HOME/.helios/deploy.conf}"
NOM="portable"
SERVER_NAME=""
ENDPOINT=""
PORT_WG="51820"
PORT_NEGO="51821"
MODE="ml-kem"
REMPLACER=0
CIBLE=""
PUBLIC_KEY=""

usage() {
    cat >&2 <<'EOF'
Usage : ./scripts/key-negotiation-setup.sh [hôte-ssh] [options]

  --nom N            Nom du client et du pair (défaut : portable)
  --public-key K     Clé publique WireGuard d'un client qui détient déjà la
                     sienne — Orion l'affiche sous « Votre clé publique ».
                     Le profil produit ne porte alors AUCUNE clé privée
                     WireGuard : à l'import, Orion reprend celle du profil
                     local de même nom. C'est le chemin pour ajouter la
                     négociation à un profil existant sans le recréer.
  --server-name N    Nom/IP que le certificat gateway authentifie
                     (défaut : l'hôte SSH)
  --endpoint H:P     Endpoint WireGuard public vu par le client
                     (défaut : <server-name>:51820)
  --port-nego P      Port UDP de négociation (défaut : 51821)
  --mode M           ml-kem (défaut) ou classic
  --remplacer        Ré-enrôle un client existant : révoque son identité
                     précédente, donc coupe le poste qui la détenait
  --rotate-gateway   Remplace l'identité de négociation de la gateway

L'hôte SSH est celui de deploy.sh s'il a déjà été utilisé.
EOF
    exit 1
}

ROTATE_GW=0
while [ $# -gt 0 ]; do
    case "$1" in
        --nom) NOM="${2:-}"; shift 2 ;;
        --public-key) PUBLIC_KEY="${2:-}"; shift 2 ;;
        --server-name) SERVER_NAME="${2:-}"; shift 2 ;;
        --endpoint) ENDPOINT="${2:-}"; shift 2 ;;
        --port-nego) PORT_NEGO="${2:-}"; shift 2 ;;
        --mode) MODE="${2:-}"; shift 2 ;;
        --remplacer) REMPLACER=1; shift ;;
        --rotate-gateway) ROTATE_GW=1; shift ;;
        -h|--help) usage ;;
        -*) echo "option inconnue : $1" >&2; usage ;;
        *) CIBLE="$1"; shift ;;
    esac
done

if [ -z "$CIBLE" ] && [ -f "$ETAT" ]; then
    CIBLE="$(sed -n 's/^cible=//p' "$ETAT")"
fi
if [ -z "$CIBLE" ]; then
    echo "Aucune gateway connue. Premier appel :" >&2
    echo "  ./scripts/key-negotiation-setup.sh utilisateur@adresse" >&2
    exit 1
fi

HOTE="${CIBLE#*@}"
[ -n "$SERVER_NAME" ] || SERVER_NAME="$HOTE"
[ -n "$ENDPOINT" ] || ENDPOINT="$SERVER_NAME:$PORT_WG"

mkdir -p "$SORTIE"

# ── 1. CA opérateur ──────────────────────────────────────────────────────────
# Créée une seule fois, réutilisée pour tous les clients. La recréer invaliderait
# tous les certificats déjà émis.
if [ -f "$CA_DIR/orion-client-ca.der" ]; then
    echo "==> CA opérateur : réutilisée ($CA_DIR)"
else
    echo "==> CA opérateur : création"
    cargo run --quiet -p helios-ctl -- key-nego init-client-ca \
        --name "helios-orion-clients" --output-dir "$CA_DIR"
fi

# ── 2. Identité de négociation de la gateway ─────────────────────────────────
# Seules les moitiés PUBLIQUES des CA partent sur la gateway. Elle en dérive
# ensuite sa propre identité, dont les clés privées sont scellées au TPM et ne
# reviennent jamais ici.
echo "==> Copie des CA publiques vers $CIBLE"
scp -q "$CA_DIR/orion-client-ca.der" "$CA_DIR/orion-client-pq-ca-public.bin" "$CIBLE:/tmp/"

echo "==> Identité de négociation sur la gateway"
ARG_ROTATE=""
[ "$ROTATE_GW" -eq 1 ] && ARG_ROTATE="--rotate"
# `-t` alloue un terminal : sans lui, l'invite de mot de passe de sudo n'a nulle
# part où s'afficher et la commande échoue sans dire pourquoi (même raison que
# dans deploy.sh). Le binaire n'est pas dans le PATH : l'installateur le pose
# sous /opt/helios/current.
HELIOSD='$(command -v heliosd || echo /opt/helios/current/heliosd)'
# Une identité déjà en place n'est pas une erreur : c'est le cas nominal dès le
# deuxième client. La rotation reste un geste explicite.
if ! ssh -t "$CIBLE" "sudo \"$HELIOSD\" init-key-negotiation \
        --server-name '$SERVER_NAME' \
        --client-ca /tmp/orion-client-ca.der \
        --client-pq-ca /tmp/orion-client-pq-ca-public.bin $ARG_ROTATE" 2>&1 \
        | tee "$SORTIE/init-key-negotiation.log"; then
    if grep -q "already exists" "$SORTIE/init-key-negotiation.log"; then
        echo "    identité déjà en place — conservée (--rotate-gateway pour la remplacer)"
    else
        echo "ÉCHEC de l'initialisation ; voir $SORTIE/init-key-negotiation.log" >&2
        exit 1
    fi
fi
ssh "$CIBLE" "rm -f /tmp/orion-client-ca.der /tmp/orion-client-pq-ca-public.bin"

# ── 3. Ouverture du port dans la configuration de la gateway ─────────────────
# Une LIGNE ajoutée au fichier de la gateway, pas un fichier remplacé. Deux
# raisons, et la seconde est un invariant du projet :
#
#   * la config vivante porte les interfaces réelles de CETTE machine, que le
#     modèle du dépôt (eth0/eth1) écraserait ;
#   * on ne reconstruit jamais network.toml depuis la vue expurgée de l'API :
#     elle ne contient ni clé privée ni PSK, et les réécrire les effacerait
#     pour tous les pairs.
#
# L'opération est idempotente et sauvegarde l'existant.
CONF_GW="/var/lib/helios/network.toml"
echo "==> Ouverture du port $PORT_NEGO dans $CONF_GW"
# Le script part par scp plutôt que par l'entrée standard : `ssh -t` occupe
# stdin avec le terminal qu'exige l'invite sudo, les deux ne cohabitent pas.
cat > "$SORTIE/ouvrir-port.sh" <<EOF
set -eu
CONF="$CONF_GW"
PORT="$PORT_NEGO"
EOF
cat >> "$SORTIE/ouvrir-port.sh" <<'EOF'
if [ ! -f "$CONF" ]; then
    echo "$CONF introuvable : la gateway n'est pas installée." >&2
    exit 1
fi
actuel=$(sed -n 's/^[[:space:]]*key_negotiation_port[[:space:]]*=[[:space:]]*//p' "$CONF" | head -1)
if [ "$actuel" = "$PORT" ]; then
    echo "    port déjà déclaré : $actuel"
    exit 0
fi
cp -a "$CONF" "$CONF.bak"
if [ -n "$actuel" ]; then
    sed -i "s/^[[:space:]]*key_negotiation_port[[:space:]]*=.*/key_negotiation_port = $PORT/" "$CONF"
    echo "    port $actuel remplacé par $PORT (sauvegarde : $CONF.bak)"
else
    printf '\n# Ajouté par scripts/key-negotiation-setup.sh\nkey_negotiation_port = %s\n' "$PORT" >> "$CONF"
    echo "    port $PORT ajouté (sauvegarde : $CONF.bak)"
fi
systemctl restart heliosd
EOF
scp -q "$SORTIE/ouvrir-port.sh" "$CIBLE:/tmp/helios-ouvrir-port.sh"
ssh -t "$CIBLE" "sudo sh /tmp/helios-ouvrir-port.sh; rm -f /tmp/helios-ouvrir-port.sh"

# Copie locale, pour garder trace de ce que la gateway porte réellement.
ssh -t "$CIBLE" "sudo cat $CONF_GW" > "$SORTIE/network.toml" 2>/dev/null || true

# ── 4. Matériel public de la gateway ─────────────────────────────────────────
# Récupéré par SSH, pas par l'API : l'API vit derrière le tunnel, et exiger une
# connexion pour mettre en place ce qui protège la PREMIÈRE connexion serait
# circulaire. Ces deux fichiers sont des certificats — publics par construction.
echo "==> Récupération des certificats publics de la gateway"
ssh -t "$CIBLE" "sudo cat /var/lib/helios/key-negotiation-cert.der" \
    > "$SORTIE/gateway-cert.der"
ssh -t "$CIBLE" "sudo cat /var/lib/helios/key-negotiation-pq-cert.json" \
    > "$SORTIE/gateway-pq-cert.json"
[ -s "$SORTIE/gateway-cert.der" ] && [ -s "$SORTIE/gateway-pq-cert.json" ] || {
    echo "ÉCHEC : certificats de négociation vides ou absents sur la gateway." >&2
    exit 1
}

# ── 5. Clé WireGuard du client et certificats ────────────────────────────────
# La paire naît ici quand le client n'en a pas : c'est le poste opérateur qui
# détient déjà la CA, une clé de plus ne change pas le modèle de confiance.
FICHIER_CLE="$SORTIE/$NOM.wg-private"
ARG_CLE_PRIVEE=""
if [ -z "$PUBLIC_KEY" ]; then
    echo "==> Génération de la clé WireGuard du client"
    PAIRE="$(cargo run --quiet -p helios-ctl -- campaign --generate-keys 2>/dev/null)"
    CLE_PRIVEE="$(printf '%s\n' "$PAIRE" | sed -n 's/^WG_PRIVATE_KEY=//p')"
    PUBLIC_KEY="$(printf '%s\n' "$PAIRE" | sed -n 's/^WG_PUBLIC_KEY=//p')"
    [ -n "$CLE_PRIVEE" ] && [ -n "$PUBLIC_KEY" ] || {
        echo "ÉCHEC : génération de clé impossible." >&2; exit 1; }
    # Par fichier, jamais en argument : `ps` expose l'argv de tout processus.
    ( umask 077; printf '%s\n' "$CLE_PRIVEE" > "$FICHIER_CLE" )
    unset CLE_PRIVEE PAIRE
    ARG_CLE_PRIVEE="--private-key-file $FICHIER_CLE"
else
    echo "==> Clé WireGuard existante conservée"
fi

echo "==> Émission des certificats du client"
rm -rf "$SORTIE/client-pki"
cargo run --quiet -p helios-ctl -- key-nego issue-client \
    --name "$NOM" \
    --wireguard-public-key "$PUBLIC_KEY" \
    --ca-certificate "$CA_DIR/orion-client-ca.der" \
    --ca-private-key "$CA_DIR/orion-client-ca-key.der" \
    --ca-pq-private-key "$CA_DIR/orion-client-pq-ca-private.bin" \
    --output-dir "$SORTIE/client-pki" > "$SORTIE/issue-client.log"
SHA_TLS="$(sed -n 's/^sha256: //p' "$SORTIE/issue-client.log")"
SHA_PQ="$(sed -n 's/^PQ certificate sha256: //p' "$SORTIE/issue-client.log")"
[ -n "$SHA_TLS" ] && [ -n "$SHA_PQ" ] || {
    echo "ÉCHEC : empreintes illisibles ; voir $SORTIE/issue-client.log" >&2
    exit 1
}

# ── 6. Admission en console ──────────────────────────────────────────────────
# `heliosd peer add` existe précisément pour amorcer sans tunnel : la mutation
# par API exige d'être un pair admin, donc déjà connecté.
echo "==> Admission du pair sur la gateway"
if [ "$REMPLACER" -eq 1 ]; then
    ssh -t "$CIBLE" "sudo \"$HELIOSD\" peer remove --name '$NOM'" > /dev/null 2>&1 || true
fi
ssh -t "$CIBLE" "sudo \"$HELIOSD\" peer add \
    --name '$NOM' --public-key '$PUBLIC_KEY' \
    --key-negotiation-certificate-sha256 '$SHA_TLS' \
    --key-negotiation-pq-certificate-sha256 '$SHA_PQ' \
    --minimum-mode '$MODE'" 2>&1 | tee "$SORTIE/peer-add.log"
VIP="$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$SORTIE/peer-add.log" | head -1)"
if [ -z "$VIP" ]; then
    # Le pair existait déjà : sa VIP est stable, on la relit dans la config.
    VIP="$(ssh -t "$CIBLE" "sudo grep -A3 'name = \"$NOM\"' $CONF_GW" 2>/dev/null \
        | grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1)"
fi
[ -n "$VIP" ] || {
    echo "ÉCHEC : VIP introuvable ; voir $SORTIE/peer-add.log" >&2
    echo "        (relancer avec --remplacer si le pair existe déjà)" >&2
    exit 1
}
echo "    VIP : $VIP"

# ── 7. Assemblage du profil Orion ────────────────────────────────────────────
PROFIL="$SORTIE/$NOM.orionprofile"
rm -f "$PROFIL"
echo "==> Assemblage du profil « $NOM »"
cargo run --quiet -p helios-ctl -- enroll \
    --name "$NOM" \
    --endpoint "$ENDPOINT" \
    --client-ca-dir "$CA_DIR" \
    --negotiation-endpoint "$SERVER_NAME:$PORT_NEGO" \
    --mode "$MODE" \
    --gateway-certificate "$SORTIE/gateway-cert.der" \
    --gateway-pq-certificate "$SORTIE/gateway-pq-cert.json" \
    --address "$VIP" \
    --public-key "$PUBLIC_KEY" \
    --client-pki-dir "$SORTIE/client-pki" \
    --output "$PROFIL" $ARG_CLE_PRIVEE

# Les secrets intermédiaires sont désormais dans le document : les laisser en
# clair à côté multiplierait les copies de la même chose.
rm -rf "$SORTIE/client-pki"
rm -f "$FICHIER_CLE"

cat <<EOF

──────────────────────────────────────────────────────────────────────────────
Gateway   $CONF_GW — déjà en place, heliosd redémarré.
          Copie locale pour référence : $SORTIE/network.toml

  Orion     $PROFIL
            double-clic, ou écran « Profils » → Importer.
            Il contient les clés privées du client : le détruire après import.
            L'écran doit alors afficher « identité protégée · scellée ».

À rediriger sur la box, vers cette gateway :
  UDP $PORT_WG    → WireGuard
  UDP $PORT_NEGO  → négociation de clé

Empreinte du certificat PQ de la gateway (à comparer avec ce qu'affiche Orion) :
EOF
grep -E "^PQ sha256:" "$SORTIE/init-key-negotiation.log" 2>/dev/null \
    || echo "  (relancer avec --rotate-gateway pour la réafficher)"
echo "──────────────────────────────────────────────────────────────────────────────"
