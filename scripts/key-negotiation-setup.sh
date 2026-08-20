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
# Ce script ne construit ni ne déploie heliosd. La négociation de clé n'est
# plus une feature de compilation : tout heliosd la porte, et seul
# `key_negotiation_port` décide de son ouverture. Pour mettre la gateway à
# jour : ./scripts/deploy.sh
set -euo pipefail

# Un seul mot de passe sudo pour tout le déploiement : voir lib-remote.sh.
# shellcheck source=scripts/lib-remote.sh
. "$(dirname "$0")/lib-remote.sh"

cd "$(dirname "$0")/.."

# La CA opérateur vit HORS du dépôt : c'est une clé privée, elle n'a rien à
# faire dans un arbre versionné où un `git add -A` finirait par l'attraper.
#
# Un seul emplacement, et c'est celui de `target-bootstrap.sh` : la gateway ne
# fait confiance qu'à UNE autorité, alors que ce script en cherchait une à un
# troisième endroit. Ne l'y trouvant pas, il en fabriquait une seconde, puis
# échouait contre celle que la gateway détenait déjà — en laissant derrière lui
# une CA neuve que la fois suivante aurait « réutilisée » sans rien dire.
CERTS_ROOT="${HELIOS_CERTS_ROOT:-$HOME/.helios/certs}"
CA_DIR="${HELIOS_CLIENT_CA_DIR:-$CERTS_ROOT/internal-ca}"
# Vrai seulement si la CA est née de cette exécution : c'est ce qui autorise à
# la retirer quand la gateway la refuse.
CA_CREEE=0
SORTIE="${HELIOS_KEYNEGO_OUT:-$PWD/target/key-negotiation}"
NOM="portable"
SERVER_NAME=""
ENDPOINT=""
ENDPOINT_NEGO=""
PORT_WG="51820"
PORT_NEGO="51821"
MODE="ml-kem"
REMPLACER=0
CIBLE=""
PUBLIC_KEY=""
ADMIN=0
GATEWAY_ONLY=0
SKIP_NETWORK=0
CLIENT_ONLY=0

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
                     (défaut : l'hôte SSH). C'est une IDENTITÉ, pas une
                     adresse : le client la vérifie dans le certificat sans
                     jamais s'y connecter. Elle peut donc rester l'IP LAN
                     alors que les endpoints ci-dessous sont publics.
  --endpoint H:P     Endpoint WireGuard par lequel le client joint la gateway
                     (défaut : <server-name>:51820). Pour un poste hors du
                     LAN, c'est l'adresse publique ou le DynDNS de la box,
                     pas l'IP privée de la machine.
  --negotiation-endpoint H:P
                     Endpoint de négociation (défaut : l'hôte d'--endpoint
                     avec le port de négociation — les deux services vivent
                     sur la même machine, donc ce qui joint l'un joint
                     l'autre)
  --port-nego P      Port UDP de négociation (défaut : 51821)
  --mode M           ml-kem (défaut) ou classic
  --admin            Admit the peer as a control-plane administrator
  --gateway-only     Configure only the gateway and fetch its certificates
  --skip-network     Keep network.toml unchanged
  --client-only      Reuse gateway material already fetched locally
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
        --negotiation-endpoint) ENDPOINT_NEGO="${2:-}"; shift 2 ;;
        --port-nego) PORT_NEGO="${2:-}"; shift 2 ;;
        --mode) MODE="${2:-}"; shift 2 ;;
        --admin) ADMIN=1; shift ;;
        --gateway-only) GATEWAY_ONLY=1; shift ;;
        --skip-network) SKIP_NETWORK=1; shift ;;
        --client-only) CLIENT_ONLY=1; shift ;;
        --remplacer) REMPLACER=1; shift ;;
        --rotate-gateway) ROTATE_GW=1; shift ;;
        -h|--help) usage ;;
        -*) echo "option inconnue : $1" >&2; usage ;;
        *) CIBLE="$1"; shift ;;
    esac
done

FICHIERS_CA="orion-client-ca.der orion-client-ca-key.der \
orion-client-pq-ca-public.bin orion-client-pq-ca-private.bin"

# Reprend une CA laissée par un workflow antérieur plutôt que d'en créer une
# seconde.
#
# La gateway ne connaît qu'une autorité ; en fabriquer une nouvelle parce que
# le chemin par défaut a changé ne produit pas une PKI neuve, ça produit une
# PKI qui ne signe plus rien d'utilisable. La source est **laissée en place** :
# c'est une clé privée, et la déplacer sans que l'opérateur l'ait vu ferait
# disparaître sa seule copie.
adopter_ca() {
    for HERITEE in "$PWD/orion-client-ca" "$HOME/.helios/orion-client-ca"; do
        COMPLETE=1
        for FICHIER in $FICHIERS_CA; do
            [ -f "$HERITEE/$FICHIER" ] || COMPLETE=0
        done
        [ "$COMPLETE" -eq 1 ] || continue
        mkdir -p "$CA_DIR"
        chmod 700 "$CA_DIR"
        install -m 644 "$HERITEE/orion-client-ca.der" "$CA_DIR/"
        install -m 600 "$HERITEE/orion-client-ca-key.der" "$CA_DIR/"
        install -m 644 "$HERITEE/orion-client-pq-ca-public.bin" "$CA_DIR/"
        install -m 600 "$HERITEE/orion-client-pq-ca-private.bin" "$CA_DIR/"
        echo "==> CA opérateur : reprise de $HERITEE"
        echo "    source conservée ; la supprimer à la main une fois la copie vérifiée"
        return 0
    done
    return 1
}

# Retire une CA née de cette exécution et que la gateway refuse.
#
# La laisser serait pire que l'échec : l'exécution suivante la trouverait,
# annoncerait « CA opérateur : réutilisée » et échouerait au même endroit, sans
# que rien ne rappelle qu'elle a été fabriquée par erreur.
retirer_ca_creee() {
    for FICHIER in $FICHIERS_CA; do
        rm -f "$CA_DIR/$FICHIER"
    done
    rmdir "$CA_DIR" 2>/dev/null || true
}

# La gateway de lib-remote.sh, sauf argument explicite. Elle n'est plus relue
# d'un fichier d'état écrit par `deploy.sh` : deux sources pour une adresse,
# c'est une de trop, et c'était la copie périmée qui gagnait.
CIBLE="${CIBLE:-$HELIOS_CIBLE}"
if [ -z "$CIBLE" ]; then
    echo "Aucune gateway : renseigner HELIOS_CIBLE dans scripts/lib-remote.sh," >&2
    echo "ou passer l'hôte en argument :" >&2
    echo "  ./scripts/key-negotiation-setup.sh utilisateur@adresse" >&2
    exit 1
fi

# Une seule invite, prise hors de tout pipeline : `helios_ssh_sudo` y tourne
# en sous-shell, et le mot de passe capturé là y serait perdu.
helios_sudo_init "$CIBLE"

HOTE="${CIBLE#*@}"
[ -n "$SERVER_NAME" ] || SERVER_NAME="$HOTE"
[ -n "$ENDPOINT" ] || ENDPOINT="$SERVER_NAME:$PORT_WG"
# La négociation suit l'endpoint WireGuard, pas le nom du certificat : les deux
# services tournent sur la même machine, donc l'hôte qui joint l'un joint
# l'autre. Les faire suivre `--server-name` produisait un profil qui pointe sur
# l'IP LAN de la gateway — injoignable depuis un poste distant, alors même que
# l'opérateur avait pris soin de passer une adresse publique à `--endpoint`.
[ -n "$ENDPOINT_NEGO" ] || ENDPOINT_NEGO="${ENDPOINT%:*}:$PORT_NEGO"

mkdir -p "$SORTIE"
HELIOSD='$(command -v heliosd || echo /opt/helios/current/heliosd)'
CONF_GW="/var/lib/helios/network.toml"

if [ "$CLIENT_ONLY" -eq 1 ] && [ "$GATEWAY_ONLY" -eq 1 ]; then
    echo "--client-only and --gateway-only are mutually exclusive" >&2
    exit 2
fi

# ── 1. CA opérateur ──────────────────────────────────────────────────────────
# Créée une seule fois, réutilisée pour tous les clients. La recréer invaliderait
# tous les certificats déjà émis.
if [ "$CLIENT_ONLY" -eq 0 ]; then
if [ -f "$CA_DIR/orion-client-ca.der" ]; then
    echo "==> CA opérateur : réutilisée ($CA_DIR)"
elif adopter_ca; then
    :
else
    echo "==> CA opérateur : création"
    cargo run --quiet -p helios-ctl -- key-nego init-client-ca \
        --name "helios-orion-clients" --output-dir "$CA_DIR"
    CA_CREEE=1
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
# Une identité déjà en place n'est pas une erreur : c'est le cas nominal dès le
# deuxième client. La rotation reste un geste explicite.
if [ "$ROTATE_GW" -eq 0 ] &&
   ssh "$CIBLE" "test -f /var/lib/helios/key-negotiation-cert.der &&
       test -f /var/lib/helios/key-negotiation-pq-cert.json &&
       test -f /var/lib/helios/key-negotiation-key.sealed &&
       test -f /var/lib/helios/key-negotiation-client-ca.der &&
       test -f /var/lib/helios/key-negotiation-client-pq-ca-public.bin"; then
    echo "    existing gateway identity reused"
else
    if ! helios_ssh_sudo "$CIBLE" "\"$HELIOSD\" init-key-negotiation \
            --server-name '$SERVER_NAME' \
            --client-ca /tmp/orion-client-ca.der \
            --client-pq-ca /tmp/orion-client-pq-ca-public.bin $ARG_ROTATE" 2>&1 \
            | tee "$SORTIE/init-key-negotiation.log"; then
        if grep -q "already exists" "$SORTIE/init-key-negotiation.log"; then
            echo "    existing partial identity detected; inspect /var/lib/helios/key-negotiation-*"
        else
            echo "FAIL: gateway key-negotiation identity initialization failed." >&2
        fi
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
echo "==> Ouverture du port $PORT_NEGO dans $CONF_GW"
# Le script part par scp plutôt que par l'entrée standard : `ssh -t` occupe
# stdin avec le terminal qu'exige l'invite sudo, les deux ne cohabitent pas.
if [ "$SKIP_NETWORK" -eq 0 ]; then
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
cp -a "$CONF" "$CONF.bak"
TMP="${CONF}.key-negotiation.tmp"
awk -v port="$PORT" '
    /^[[:space:]]*\[\[peers\]\][[:space:]]*$/ {
        if (!declared) {
            print "key_negotiation_port = " port
            print ""
        }
        declared = 1
        in_peers = 1
        print
        next
    }
    /^[[:space:]]*key_negotiation_port[[:space:]]*=/ {
        if (!in_peers && !declared) {
            print "key_negotiation_port = " port
            declared = 1
        }
        next
    }
    { print }
    END {
        if (!declared) {
            print ""
            print "key_negotiation_port = " port
        }
    }
' "$CONF" > "$TMP"
chmod --reference="$CONF" "$TMP"
chown --reference="$CONF" "$TMP"
mv "$TMP" "$CONF"
echo "    key-negotiation port set to $PORT (backup: $CONF.bak)"
EOF
scp -q "$SORTIE/ouvrir-port.sh" "$CIBLE:/tmp/helios-ouvrir-port.sh"
helios_ssh_sudo "$CIBLE" "sh /tmp/helios-ouvrir-port.sh && rm -f /tmp/helios-ouvrir-port.sh"
rm -f "$SORTIE/ouvrir-port.sh"
else
    echo "    network configuration already managed by deploy"
fi

# ── 4. Matériel public de la gateway ─────────────────────────────────────────
# Récupéré par SSH, pas par l'API : l'API vit derrière le tunnel, et exiger une
# connexion pour mettre en place ce qui protège la PREMIÈRE connexion serait
# circulaire. Ces deux fichiers sont des certificats — publics par construction.
echo "==> Récupération des certificats publics de la gateway"
REMOTE_PUBLIC_DIR="/tmp/helios-key-negotiation-public"
# `$SUDO_UID` plutôt que `id -u` : sous `sudo`, ce dernier vaut 0, et les
# fichiers repartiraient vers un `scp` non privilégié qui ne peut plus les lire.
# Le répertoire lui-même est concerné — il est en 700, donc infranchissable pour
# son propriétaire d'origine s'il reste à root.
#
# Le commentaire est **hors** de la commande distante : à l'intérieur, le `$` y
# serait développé par le shell local, et un déploiement s'est arrêté là-dessus.
helios_ssh_sudo "$CIBLE" "
    set -e
    install -d -m 700 '$REMOTE_PUBLIC_DIR'
    install -m 600 /var/lib/helios/key-negotiation-cert.der \
        '$REMOTE_PUBLIC_DIR/gateway-cert.der'
    install -m 600 /var/lib/helios/key-negotiation-pq-cert.json \
        '$REMOTE_PUBLIC_DIR/gateway-pq-cert.json'
    install -m 600 /var/lib/helios/key-negotiation-client-ca.der \
        '$REMOTE_PUBLIC_DIR/client-ca.der'
    install -m 600 /var/lib/helios/key-negotiation-client-pq-ca-public.bin \
        '$REMOTE_PUBLIC_DIR/client-pq-ca-public.bin'
    /opt/helios/current/heliosd peer list \
        > '$REMOTE_PUBLIC_DIR/peer-list.log'
    chown \$SUDO_UID:\$SUDO_GID '$REMOTE_PUBLIC_DIR' '$REMOTE_PUBLIC_DIR/'*
"
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/gateway-cert.der" "$SORTIE/gateway-cert.der"
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/gateway-pq-cert.json" "$SORTIE/gateway-pq-cert.json"
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/client-ca.der" "$SORTIE/installed-client-ca.der"
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/client-pq-ca-public.bin" \
    "$SORTIE/installed-client-pq-ca-public.bin"
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/peer-list.log" "$SORTIE/peer-list.log"
# La liste vient d'être relue : elle décrit la gateway telle qu'elle est, pas
# telle qu'elle était au dernier passage. C'est ce qui autorise à s'y fier pour
# refuser tôt (§4 bis) ; un fichier laissé par une exécution précédente ne le
# permettrait pas.
PEER_LIST_FRAICHE=1
ssh "$CIBLE" "rm -f '$REMOTE_PUBLIC_DIR/gateway-cert.der' \
    '$REMOTE_PUBLIC_DIR/gateway-pq-cert.json' \
    '$REMOTE_PUBLIC_DIR/client-ca.der' \
    '$REMOTE_PUBLIC_DIR/client-pq-ca-public.bin' \
    '$REMOTE_PUBLIC_DIR/peer-list.log'; rmdir '$REMOTE_PUBLIC_DIR'"
[ -s "$SORTIE/gateway-cert.der" ] && [ -s "$SORTIE/gateway-pq-cert.json" ] || {
    echo "ÉCHEC : certificats de négociation vides ou absents sur la gateway." >&2
    exit 1
}

LOCAL_TLS_CA_SHA="$(sha256sum "$CA_DIR/orion-client-ca.der" | awk '{print $1}')"
REMOTE_TLS_CA_SHA="$(sha256sum "$SORTIE/installed-client-ca.der" | awk '{print $1}')"
LOCAL_PQ_CA_SHA="$(sha256sum "$CA_DIR/orion-client-pq-ca-public.bin" | awk '{print $1}')"
REMOTE_PQ_CA_SHA="$(sha256sum "$SORTIE/installed-client-pq-ca-public.bin" | awk '{print $1}')"
rm -f "$SORTIE/installed-client-ca.der" "$SORTIE/installed-client-pq-ca-public.bin"
if [ "$LOCAL_TLS_CA_SHA" != "$REMOTE_TLS_CA_SHA" ] ||
   [ "$LOCAL_PQ_CA_SHA" != "$REMOTE_PQ_CA_SHA" ]; then
    echo "ÉCHEC : la PKI opérateur locale ne correspond pas aux autorités installées" >&2
    echo "        sur la gateway." >&2
    echo "          CA TLS locale   : $LOCAL_TLS_CA_SHA" >&2
    echo "          CA TLS gateway  : $REMOTE_TLS_CA_SHA" >&2
    echo "          CA PQ  locale   : $LOCAL_PQ_CA_SHA" >&2
    echo "          CA PQ  gateway  : $REMOTE_PQ_CA_SHA" >&2
    if [ "$CA_CREEE" -eq 1 ]; then
        retirer_ca_creee
        echo "        La CA venait d'être créée par cette exécution : elle est retirée," >&2
        echo "        sinon la prochaine l'aurait « réutilisée » et aurait échoué ici même." >&2
        echo "        Restaurer la vraie CA dans $CA_DIR — c'est la seule qui signe des" >&2
        echo "        certificats que cette gateway accepte. Chercher une sauvegarde de" >&2
        echo "        $CERTS_ROOT, ou les emplacements des workflows précédents :" >&2
        echo "          $PWD/orion-client-ca" >&2
        echo "          $HOME/.helios/orion-client-ca" >&2
        echo "        À défaut, réenrôler TOUS les clients après avoir réinstallé une CA" >&2
        echo "        neuve sur la gateway : leurs certificats actuels deviendront caducs." >&2
    else
        echo "        Restaurer la PKI d'origine ; ne pas faire tourner l'identité de la" >&2
        echo "        gateway." >&2
    fi
    exit 1
fi

if [ "$GATEWAY_ONLY" -eq 1 ]; then
    echo "==> Gateway identity ready; public certificates are in $SORTIE"
    exit 0
fi
else
    for REQUIRED in \
        "$CA_DIR/orion-client-ca.der" \
        "$CA_DIR/orion-client-ca-key.der" \
        "$CA_DIR/orion-client-pq-ca-private.bin" \
        "$SORTIE/gateway-cert.der" \
        "$SORTIE/gateway-pq-cert.json"; do
        [ -s "$REQUIRED" ] ||
            { echo "client-only input is missing: $REQUIRED" >&2; exit 1; }
    done
fi

# ── 4 bis. Un pair de ce nom est-il déjà admis ? ─────────────────────────────
#
# La gateway refuse une seconde admission du même nom, et elle a raison : la
# remplacer révoque l'identité du poste qui la détient. Mais elle ne le disait
# qu'à l'étape 6, après deux mots de passe sudo, l'émission des certificats
# client et un aller-retour SSH — pour une réponse qui tenait déjà dans la
# liste des pairs relue à l'étape précédente.
if [ "$REMPLACER" -eq 0 ] && [ "${PEER_LIST_FRAICHE:-0}" -eq 1 ]; then
    CLE_ADMISE="$(awk -F'\t' -v nom="$NOM" \
        '$1 == nom { split($3, champ, " "); print champ[1]; exit }' \
        "$SORTIE/peer-list.log")"
    if [ -n "$CLE_ADMISE" ]; then
        echo "ÉCHEC : un pair « $NOM » est déjà admis sur cette gateway." >&2
        echo "        clé admise : $CLE_ADMISE" >&2
        if [ -z "$PUBLIC_KEY" ]; then
            echo "        Relancer avec --remplacer pour lui réémettre une identité, ou" >&2
            echo "        choisir un autre --nom. Sans --public-key, --remplacer lui" >&2
            echo "        fabriquera aussi une clé WireGuard neuve." >&2
        elif [ "$PUBLIC_KEY" = "$CLE_ADMISE" ]; then
            echo "        C'est bien ce poste : sa clé WireGuard est celle passée à" >&2
            echo "        --public-key, et --remplacer la conservera. Ce qu'il perdra," >&2
            echo "        c'est son identité de négociation : le profil déjà importé" >&2
            echo "        cessera d'être accepté, il faudra importer le nouveau." >&2
            echo "        Relancer avec --remplacer." >&2
        else
            echo "        Ce n'est PAS la clé passée à --public-key : --remplacer" >&2
            echo "        couperait le poste qui détient $CLE_ADMISE." >&2
            echo "        Vérifier le nom du pair avant de continuer." >&2
        fi
        exit 1
    fi
fi

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
ARG_ADMIN=""
[ "$ADMIN" -eq 1 ] && ARG_ADMIN="--admin"
BACKUP_GW="/var/lib/helios/network.toml.before-key-negotiation-enroll"
case "$NOM:$PUBLIC_KEY:$SHA_TLS:$SHA_PQ" in
    *[!A-Za-z0-9._:+/=:-]*) echo "unsafe enrollment value" >&2; exit 1 ;;
esac
case "$MODE" in
    classic|static_psk|ml-kem|ml_kem) ;;
    *) echo "unsupported key-negotiation mode: $MODE" >&2; exit 1 ;;
esac

# Les deux feuilles du client partent aussi : une gateway qui porte un domaine
# de confiance enregistre les certificats eux-mêmes, pas leurs empreintes — elle
# vérifie des signatures faites par eux — et refuse une admission sans elles.
# Sur une gateway sans domaine, `peer add` les ignore : rien à enregistrer.
CERT_DISTANT="/tmp/helios-client-cert-$$.der"
PQ_DISTANT="/tmp/helios-client-pq-cert-$$.json"
scp -q "$SORTIE/client-pki/orion-client-cert.der" "$CIBLE:$CERT_DISTANT"
scp -q "$SORTIE/client-pki/orion-client-pq-cert.json" "$CIBLE:$PQ_DISTANT"

LOCAL_ADMISSION_SCRIPT="$SORTIE/admit-peer.sh"
REMOTE_ADMISSION_SCRIPT="/tmp/helios-admit-peer.sh"
cat > "$LOCAL_ADMISSION_SCRIPT" <<EOF
set -eu
restore_network() {
    cp -a '$BACKUP_GW' '$CONF_GW'
}
cp -a '$CONF_GW' '$BACKUP_GW'
trap restore_network EXIT HUP INT TERM
if [ '$REMPLACER' -eq 1 ]; then
    /opt/helios/current/heliosd peer remove --name '$NOM' >/dev/null 2>&1 || true
fi
/opt/helios/current/heliosd peer add \
    --name '$NOM' \
    --public-key '$PUBLIC_KEY' \
    --key-negotiation-certificate-sha256 '$SHA_TLS' \
    --key-negotiation-pq-certificate-sha256 '$SHA_PQ' \
    --certificate '$CERT_DISTANT' \
    --pq-certificate '$PQ_DISTANT' \
    --minimum-mode '$MODE' $ARG_ADMIN
rm -f '$BACKUP_GW' '$CERT_DISTANT' '$PQ_DISTANT'
trap - EXIT HUP INT TERM
EOF
scp -q "$LOCAL_ADMISSION_SCRIPT" "$CIBLE:$REMOTE_ADMISSION_SCRIPT"
rm -f "$LOCAL_ADMISSION_SCRIPT"
if ! helios_ssh_sudo "$CIBLE" "sh '$REMOTE_ADMISSION_SCRIPT'; \
    STATUS=\$?; rm -f '$REMOTE_ADMISSION_SCRIPT'; exit \$STATUS" 2>&1 |
    tee "$SORTIE/peer-add.log"; then
    echo "FAIL: admission refused; the previous peer table was restored." >&2
    exit 1
fi
VIP="$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$SORTIE/peer-add.log" | head -1)"
[ -n "$VIP" ] || {
    echo "ÉCHEC : VIP introuvable ; voir $SORTIE/peer-add.log" >&2
    exit 1
}
echo "    VIP : $VIP"

# ── 7. Assemblage du profil Orion ────────────────────────────────────────────
PROFIL="$SORTIE/$NOM.orion"
rm -f "$PROFIL"
echo "==> Assemblage du profil « $NOM »"
cargo run --quiet -p helios-ctl -- enroll \
    --name "$NOM" \
    --endpoint "$ENDPOINT" \
    --client-ca-dir "$CA_DIR" \
    --negotiation-endpoint "$ENDPOINT_NEGO" \
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
Gateway   $CONF_GW — mis à jour ; le démon relit le fichier tout seul,
          en quelques secondes, sans redémarrage ni coupure des clients
          déjà connectés.

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
