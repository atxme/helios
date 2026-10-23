#!/usr/bin/env bash
# Met en place la négociation de clé PQC de bout en bout, et produit les deux
# fichiers de configuration à charger : celui de la gateway, celui d'Orion.
#
#   ./scripts/key-negotiation-setup.sh christophe@100.72.220.76
#
# Ce que le script enchaîne, dans l'ordre où chaque étape débloque la suivante :
#
#   1. CA opérateur (TLS + ML-DSA-65)     — poste opérateur, une seule fois
#   2. copie des CA PUBLIQUES             — vers la gateway
#   3. `heliosd init-key-negotiation`     — SUR la gateway, scellé au TPM
#   4. `network.toml` avec le port ouvert — chargé dans la gateway
#
# Les clés privées de la CA restent sur le poste opérateur ; celles de la
# gateway naissent sur la gateway et ne sont jamais lues d'ici.
#
# Il n'enrôle plus de client. L'enrôlement v5 (NEGOCIATION-DE-CLE-V5 §15) ne
# transmet aucune clé privée : il passe par une invitation que l'opérateur signe
# sous CA-PQ avec un credential matériel, une demande que le poste produit, et
# un document signé en retour — trois gestes qu'aucun script ne fait à la place
# d'une personne. Le parcours est dans docs/security/OPERATOR-TOOLING.md §6.
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
# shellcheck source=scripts/cargo-budget.sh
source scripts/cargo-budget.sh
helios_budget_enter "$PWD"

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
SERVER_NAME=""
PORT_WG="51820"
PORT_NEGO="51821"
CIBLE=""
SKIP_NETWORK=0

usage() {
    cat >&2 <<'EOF'
Usage : ./scripts/key-negotiation-setup.sh [hôte-ssh] [options]

  --server-name N    Nom/IP que le certificat gateway authentifie
                     (défaut : l'hôte SSH). C'est une IDENTITÉ, pas une
                     adresse : le client la vérifie dans le certificat sans
                     jamais s'y connecter. Elle peut donc rester l'IP LAN
                     alors que les endpoints du profil sont publics.
  --port-nego P      Port UDP de négociation (défaut : 51821)
  --gateway-only     Accepté pour compatibilité : le script ne fait plus que ça
  --skip-network     Keep network.toml unchanged
  --rotate-gateway   Remplace l'identité de négociation de la gateway

L'hôte SSH est celui de deploy.sh s'il a déjà été utilisé. Un client s'enrôle
par une invitation v5 : docs/security/OPERATOR-TOOLING.md §6.
EOF
    exit 1
}

# L'ancien enrôlement, refusé par son nom plutôt que comme une option inconnue :
# l'opérateur qui le tape doit apprendre ce qui le remplace.
refuser_enrolement() {
    cat >&2 <<EOF
$1 : ce script n'enrôle plus de client. L'enrôlement v5 ne transmet aucune
clé privée : invitation signée par astra-signer, demande produite par Orion,
document signé en retour. Voir docs/security/OPERATOR-TOOLING.md §6.
EOF
    exit 2
}

ROTATE_GW=0
while [ $# -gt 0 ]; do
    case "$1" in
        --nom|--public-key|--mode|--admin|--client-only|--remplacer|--endpoint|--negotiation-endpoint)
            refuser_enrolement "$1" ;;
        --server-name) SERVER_NAME="${2:-}"; shift 2 ;;
        --port-nego) PORT_NEGO="${2:-}"; shift 2 ;;
        --gateway-only) shift ;;
        --skip-network) SKIP_NETWORK=1; shift ;;
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

mkdir -p "$SORTIE"
HELIOSD='$(command -v heliosd || echo /opt/helios/current/heliosd)'
CONF_GW="/var/lib/helios/network.toml"

# ── 1. CA opérateur ──────────────────────────────────────────────────────────
# Créée une seule fois, réutilisée pour tous les clients. La recréer invaliderait
# tous les certificats déjà émis.
if [ -f "$CA_DIR/orion-client-ca.der" ]; then
    echo "==> CA opérateur : réutilisée ($CA_DIR)"
elif adopter_ca; then
    :
else
    echo "==> CA opérateur : création"
    cargo run --quiet -p helios -- key-nego init-client-ca \
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
#
# La leaf sous `CA-PQ` ne fait pas partie du test : elle n'est pas produite par
# cette étape mais par la cérémonie hors ligne, plus tard. L'exiger ici faisait
# passer pour « partielle » l'identité qu'un domaine neuf vient tout juste de
# créer, et `init-key-negotiation` refusait alors de rejouer — le premier
# passage ne pouvait pas être relancé. Ce que cette étape produit, et donc ce
# qu'elle vérifie, est la paire scellée, son certificat de transport, les deux
# CA opérateur et la demande d'amorçage. C'est aussi ce que `heliosd` retient
# pour dire qu'une identité existe.
if [ "$ROTATE_GW" -eq 0 ] &&
   ssh "$CIBLE" "test -f /var/lib/helios/key-negotiation-cert.der &&
       test -f /var/lib/helios/key-negotiation-key.sealed &&
       test -f /var/lib/helios/key-negotiation-client-ca.der &&
       test -f /var/lib/helios/key-negotiation-client-pq-ca-public.bin &&
       { test -f /var/lib/helios/key-negotiation-pq-cert.json ||
         test -f /var/lib/helios/gateway-bootstrap-certificate-request.json; }"; then
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
    # La leaf sous \`CA-PQ\` peut ne pas exister encore : \`init-key-negotiation\`
    # n'en émet plus d'auto-signée, et c'est la cérémonie hors ligne qui la
    # produit. Une gateway qui attend la sienne est donc un état normal du
    # premier passage, pas une panne — et \`set -e\` en ferait une.
    if [ -f /var/lib/helios/key-negotiation-pq-cert.json ]; then
        install -m 600 /var/lib/helios/key-negotiation-pq-cert.json \
            '$REMOTE_PUBLIC_DIR/gateway-pq-cert.json'
    fi
    install -m 600 /var/lib/helios/key-negotiation-client-ca.der \
        '$REMOTE_PUBLIC_DIR/client-ca.der'
    install -m 600 /var/lib/helios/key-negotiation-client-pq-ca-public.bin \
        '$REMOTE_PUBLIC_DIR/client-pq-ca-public.bin'
    chown \$SUDO_UID:\$SUDO_GID '$REMOTE_PUBLIC_DIR' '$REMOTE_PUBLIC_DIR/'*
"
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/gateway-cert.der" "$SORTIE/gateway-cert.der"
if ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" \
    "test -f '$REMOTE_PUBLIC_DIR/gateway-pq-cert.json'"; then
    scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/gateway-pq-cert.json" "$SORTIE/gateway-pq-cert.json"
else
    # Et surtout : retirer celle d'avant. Un fichier laissé par un domaine
    # précédent signerait une identité client sous une ancre que cette gateway
    # ne sert plus, et la panne ne se verrait qu'à la première poignée de main.
    rm -f "$SORTIE/gateway-pq-cert.json"
fi
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/client-ca.der" "$SORTIE/installed-client-ca.der"
scp -q "$CIBLE:$REMOTE_PUBLIC_DIR/client-pq-ca-public.bin" \
    "$SORTIE/installed-client-pq-ca-public.bin"
ssh "$CIBLE" "rm -f '$REMOTE_PUBLIC_DIR/gateway-cert.der' \
    '$REMOTE_PUBLIC_DIR/gateway-pq-cert.json' \
    '$REMOTE_PUBLIC_DIR/client-ca.der' \
    '$REMOTE_PUBLIC_DIR/client-pq-ca-public.bin'; rmdir '$REMOTE_PUBLIC_DIR'"
[ -s "$SORTIE/gateway-cert.der" ] || {
    echo "ÉCHEC : certificat de négociation vide ou absent sur la gateway." >&2
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

echo "==> Gateway identity ready; public certificates are in $SORTIE"
if [ ! -s "$SORTIE/gateway-pq-cert.json" ]; then
    # Le premier passage d'un domaine neuf : la leaf sous CA-PQ n'existe pas
    # encore, et aucune invitation ne peut la nommer tant qu'elle manque.
    echo "    Pas encore de leaf sous CA-PQ : astra-signer issue-gateway-bootstrap," >&2
    echo "    puis heliosd init-trust-domain, avant toute invitation." >&2
fi
cat <<EOF

À rediriger sur la box, vers cette gateway :
  UDP $PORT_WG    → WireGuard
  UDP $PORT_NEGO  → négociation de clé

Enrôler un client : docs/security/OPERATOR-TOOLING.md §6
  (astra-signer enroll invite --gateway-certificate $SORTIE/gateway-pq-cert.json …)
EOF
