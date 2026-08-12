#!/usr/bin/env bash
# Provisionne un client Orion de bout en bout, en une commande.
#
#   ./scripts/provision-client.sh poste-windows christophe@192.168.1.44 \
#       --endpoint 86.229.12.86:51820
#   ./scripts/provision-client.sh portable --endpoint 86.229.12.86:51820
#
# L'hôte SSH est retenu après le premier appel ; l'endpoint public, jamais —
# il est trop conséquent pour être hérité en silence.
#
# ── Pourquoi ce script existe ────────────────────────────────────────────────
#
# Admettre un client demande sept gestes répartis sur deux machines, dont
# quatre copies de fichiers dans les deux sens :
#
#   1. créer la CA opérateur                          poste opérateur
#   2. copier ses deux parties publiques              → gateway
#   3. init-key-negotiation                           gateway
#   4. peer add, qui imprime la VIP                   gateway
#   5. copier les deux certificats de la gateway      → poste opérateur
#   6. enroll, en mode hors API                       poste opérateur
#   7. importer dans Orion                            poste client
#
# Chacune de ces copies est un endroit où coller la mauvaise valeur, et la
# panne ne se voit qu'à la fin — une négociation que la gateway refuse sans
# dire pourquoi. Le même argument que `deploy.sh` : la séparation des rôles
# garde son sens pour une flotte, pas pour un opérateur qui les tient tous.
#
# Ce script ne vérifie rien du code ; il provisionne ce qu'on lui donne.
#
# ── Ce qu'il ne fait pas ─────────────────────────────────────────────────────
#
# Il ne remplace pas une CA existante sans qu'on le demande. La gateway épingle
# la CA cliente : en changer invalide **tous** les certificats déjà émis, donc
# tous les clients admis. `--refaire-ca` est le seul moyen de le déclencher, et
# il le dit avant d'agir.
set -euo pipefail

# Un seul mot de passe sudo pour tout le déploiement : voir lib-remote.sh.
# shellcheck source=scripts/lib-remote.sh
. "$(dirname "$0")/lib-remote.sh"

cd "$(dirname "$0")/.."

ETAT="${HELIOS_PROVISION_STATE:-$HOME/.helios/provision.conf}"
SORTIE="${HELIOS_PROVISION_OUT:-$PWD}"
REFAIRE_CA=0
REMPLACER=0
MODE="ml-kem"
ENDPOINT=""
SERVER_NAME=""
TRAFIC=""

usage() {
    cat >&2 <<'EOF'
Usage : ./scripts/provision-client.sh <nom-client> [hôte-ssh] [options]

  --endpoint IP:PORT   Endpoint WireGuard **public**, par lequel les clients
                       joignent la gateway. Obligatoire.
  --server-name NOM    Nom authentifié par le certificat de négociation
                       (défaut : l'hôte de --endpoint)
  --mode MODE          classic | static-psk | ml-kem   (défaut : ml-kem)
  --trafic PLAGES      Trafic capté par le tunnel : une ou plusieurs plages
                       CIDR séparées par des virgules. Absent = tunnel
                       complet (0.0.0.0/0). Le préciser ici plutôt que dans
                       chaque poste évite qu'un parc finisse avec autant de
                       tables de routage que d'utilisateurs.
                         --trafic "100.64.0.0/10, 192.168.1.0/24"
  --remplacer          (sans effet : un pair du même nom est toujours remplacé)
  --refaire-ca         Régénère la CA opérateur ET la négociation de la
                       gateway. Invalide tous les clients déjà admis.
  --sortie RÉPERTOIRE  Où écrire le .orion (défaut : répertoire courant)

L'hôte SSH est retenu après le premier appel.
EOF
    exit 1
}

CLIENT=""
CIBLE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) ENDPOINT="${2:-}"; shift 2 ;;
        --server-name) SERVER_NAME="${2:-}"; shift 2 ;;
        --mode) MODE="${2:-}"; shift 2 ;;
        --trafic|--allowed-ips) TRAFIC="${2:-}"; shift 2 ;;
        --remplacer) REMPLACER=1; shift ;;
        --refaire-ca) REFAIRE_CA=1; shift ;;
        --sortie) SORTIE="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        -*) echo "option inconnue : $1" >&2; usage ;;
        *) if [ -z "$CLIENT" ]; then CLIENT="$1"; else CIBLE="$1"; fi; shift ;;
    esac
done

[ -n "$CLIENT" ] || usage

if [ -z "$CIBLE" ] && [ -f "$ETAT" ]; then
    CIBLE="$(sed -n 's/^cible=//p' "$ETAT")"
fi
if [ -z "$CIBLE" ]; then
    echo "Aucune gateway connue. Premier appel :" >&2
    echo "  ./scripts/provision-client.sh $CLIENT utilisateur@adresse" >&2
    exit 1
fi
# Une seule invite, prise hors de tout pipeline : `helios_ssh_sudo` y tourne
# en sous-shell, et le mot de passe capturé là y serait perdu.
helios_sudo_init "$CIBLE"

mkdir -p "$(dirname "$ETAT")"
printf 'cible=%s\n' "$CIBLE" > "$ETAT"

HOTE="${CIBLE#*@}"

# ── L'hôte SSH n'est pas l'endpoint public ───────────────────────────────────
#
# Deux adresses, deux rôles : l'opérateur administre la gateway par le LAN, les
# clients l'atteignent par le WAN. Faire défaut de l'une vers l'autre grave
# l'adresse interne dans le certificat de négociation et dans le profil — et le
# client échoue depuis l'extérieur, sans que rien ne relie la panne au choix
# fait ici. Une adresse publique ne se devine pas : elle se déclare.
if [ -z "$ENDPOINT" ]; then
    cat >&2 <<EOF
--endpoint est obligatoire.

C'est l'adresse **publique** par laquelle vos clients joignent la gateway, qui
n'est pas celle par laquelle vous l'administrez en SSH ($HOTE). Elle est gravée
dans le certificat de négociation et dans le profil : s'y tromper produit un
client qui ne se connecte que depuis le réseau local.

  ./scripts/provision-client.sh $CLIENT $CIBLE --endpoint 203.0.113.10:51820

Pour un client qui ne sortira jamais du LAN, la déclarer quand même :
  --endpoint $HOTE:51820
EOF
    exit 1
fi

# Le nom que le certificat authentifie. Par défaut l'hôte de l'endpoint public,
# jamais l'hôte SSH : c'est ce nom que le client vérifie, et il le vérifie en
# ayant composé l'adresse publique.
[ -n "$SERVER_NAME" ] || SERVER_NAME="${ENDPOINT%:*}"

# ── Rien de local n'a besoin de privilèges ───────────────────────────────────
# Seules les commandes **distantes** en ont besoin. Lancer ce script sous sudo
# déplace $HOME vers /root : la CA opérateur s'écrirait dans /root/.local, où
# l'appel suivant sans sudo ne la trouverait pas — exactement le défaut de
# chemin flottant que l'emplacement fixe vient de supprimer. Et `cargo` n'est
# en général pas dans le PATH de root.
if [ "$(id -u)" = 0 ] && [ -z "${HELIOS_PROVISION_AUTORISER_ROOT:-}" ]; then
    cat >&2 <<'EOF'
Ne pas lancer ce script avec sudo.

Tout ce qui est local tourne sous votre compte ; seules les commandes sur la
gateway sont privilégiées, et le script demande ce sudo-là par SSH.

Sous sudo, $HOME devient /root : la CA opérateur atterrit dans
/root/.helios/certs et devient introuvable au prochain appel normal.

  ./scripts/provision-client.sh <nom-client> [hôte-ssh]
EOF
    exit 1
fi

# LE MÊME emplacement que `target-bootstrap.sh` et `key-negotiation-setup.sh`,
# et ce n'est pas un détail de rangement : la gateway n'épingle qu'UNE autorité.
#
# Ce script cherchait la sienne dans ~/.local/share/helios-ctl. Ne l'y trouvant
# pas, il en fabriquait une neuve, puis — CA neuve valant `--refaire-ca` — il
# réinitialisait la négociation de la gateway pour l'y installer. Les clients
# déjà admis tombaient, et le déploiement suivant s'arrêtait sur « la PKI
# opérateur locale ne correspond pas aux autorités installées » : il comparait
# la gateway à ~/.helios/certs/internal-ca, restée sur l'autorité précédente.
# Deux répertoires, deux CA, et une rotation déclenchée par la seule absence
# d'un fichier là où ce script le cherchait.
CERTS_ROOT="${HELIOS_CERTS_ROOT:-$HOME/.helios/certs}"
CA_DIR="${HELIOS_CLIENT_CA_DIR:-$CERTS_ROOT/internal-ca}"
CTL=(cargo run --quiet -p helios-ctl --)

ARG_TRAFIC=()
[ -n "$TRAFIC" ] && ARG_TRAFIC=(--allowed-ips "$TRAFIC")

echo "==> Client     $CLIENT"
echo "==> Gateway    $CIBLE   (SSH)"
echo "==> Public     $ENDPOINT   (nom authentifié : $SERVER_NAME, mode $MODE)"
echo "==> CA         $CA_DIR"
echo "==> Trafic     ${TRAFIC:-0.0.0.0/0 (tunnel complet)}"
echo

TRAVAIL="$(mktemp -d)"
trap 'rm -rf -- "$TRAVAIL"' EXIT

# ── 1. CA opérateur ──────────────────────────────────────────────────────────
# Elle porte le pouvoir d'émettre des certificats que la gateway croira. On ne
# la refait jamais par accident : la refaire oblige à refaire la négociation de
# la gateway, ce qui coupe tous les autres clients.
if [ "$REFAIRE_CA" = 1 ]; then
    echo "==> CA opérateur : régénération demandée"
    echo "    Tous les certificats déjà émis deviendront illisibles par la gateway."
    rm -rf -- "$CA_DIR"
fi
if [ ! -f "$CA_DIR/orion-client-ca.der" ]; then
    echo "==> Création de la CA opérateur"
    "${CTL[@]}" key-nego init-client-ca --name "helios-orion-clients" --output-dir "$CA_DIR"
    REFAIRE_CA=1   # une CA neuve impose de réinitialiser la gateway
else
    echo "==> CA opérateur déjà présente"
fi

# ── 2. Identité du client, émise ici ─────────────────────────────────────────
#
# L'ordre compte, et ce n'est pas celui qu'on devine : `heliosd peer add` exige
# la clé publique du client **et** les empreintes de ses deux certificats. La
# gateway n'invente rien — ni clé, ni certificat. Tout naît donc sur le poste
# opérateur, avant l'admission :
#
#   paire WireGuard → certificats client → empreintes → admission → profil
#
# Un enrôlement en ligne masque cette séquence, parce que `enroll` joint l'API
# et admet lui-même. Hors API — le seul chemin possible tant qu'aucun tunnel
# n'existe — elle est à la charge de l'appelant.
echo "==> Génération de la paire WireGuard du client"
PAIRE="$("${CTL[@]}" campaign --generate-keys 2>/dev/null | sed -n 's/^WG_[A-Z_]*=//p')"
WG_PRIVEE="$(printf '%s\n' "$PAIRE" | sed -n 1p)"
WG_PUBLIQUE="$(printf '%s\n' "$PAIRE" | sed -n 2p)"
if [ -z "$WG_PRIVEE" ] || [ -z "$WG_PUBLIQUE" ]; then
    echo "génération de la paire WireGuard impossible" >&2
    exit 1
fi
# Un fichier, jamais un argument : `ps` expose l'argv de tout processus.
printf '%s' "$WG_PRIVEE" > "$TRAVAIL/wg-private.key"
chmod 600 "$TRAVAIL/wg-private.key"
echo "    clé publique $WG_PUBLIQUE"

echo "==> Émission des certificats client"
PKI="$TRAVAIL/pki"
mkdir -p "$PKI"
EMPREINTES="$("${CTL[@]}" key-nego issue-client \
    --name "$CLIENT" \
    --ca-certificate "$CA_DIR/orion-client-ca.der" \
    --ca-private-key "$CA_DIR/orion-client-ca-key.der" \
    --ca-pq-private-key "$CA_DIR/orion-client-pq-ca-private.bin" \
    --wireguard-public-key "$WG_PUBLIQUE" \
    --output-dir "$PKI")"
FP_TLS="$(printf '%s\n' "$EMPREINTES" | sed -n 's/^sha256: //p')"
FP_PQ="$(printf '%s\n' "$EMPREINTES" | sed -n 's/^PQ certificate sha256: //p')"
if [ -z "$FP_TLS" ] || [ -z "$FP_PQ" ]; then
    echo "empreintes de certificat illisibles :" >&2
    printf '%s\n' "$EMPREINTES" >&2
    exit 1
fi

# ── 3 à 5 : tout le travail privilégié, en UNE session ───────────────────────
#
# sudo indexe son horodatage **par terminal** (`tty_tickets`, activé par défaut
# depuis sudo 1.8). Authentifier dans une session SSH puis travailler dans une
# autre échoue sur « interactive authentication is required » : deux connexions,
# deux tty, le ticket de la première ne vaut pas pour la seconde.
#
# D'où une seule session interactive, qui exécute un script déposé à l'avance.
# Elle n'écrit que du texte sur le terminal ; ses résultats — la VIP et les deux
# certificats de la gateway — vont dans un répertoire de dépôt que `scp`
# rapatrie ensuite hors tty. Un DER qui traverserait un pseudo-terminal y verrait
# ses \n traduits en \r\n, et la panne n'apparaîtrait qu'à la première
# négociation.
DEPOT="/tmp/helios-provision-$$"

if [ "$REFAIRE_CA" = 1 ]; then
    echo "==> Envoi de la CA publique à la gateway"
    scp -q "$CA_DIR/orion-client-ca.der" "$CIBLE:/tmp/orion-client-ca.der"
    scp -q "$CA_DIR/orion-client-pq-ca-public.bin" "$CIBLE:/tmp/orion-client-pq-ca-public.bin"
fi

# Garde-fou : ce heredoc n'est pas quote — il ne peut pas l'etre, les valeurs
# locales doivent s'y substituer — donc tout backtick ou $(...) y serait execute
# ICI, a la construction. Le piege s'est referme deux fois : un « scp » entre
# backticks dans un commentaire lancait scp sans argument, puis un « tail -1 »
# faisait bloquer le script sur une lecture d'entree standard. Le test suivant
# echoue tout de suite plutot que de laisser la surprise au poste de l'operateur.
if awk '/^cat > "\$TRAVAIL\/gateway.sh" <<REMOTE$/,/^REMOTE$/' "$0" | grep -q '`'; then
    echo "Bug interne : un backtick subsiste dans le heredoc du script distant." >&2
    echo "Il serait execute a la construction. Le remplacer par des guillemets." >&2
    exit 1
fi

cat > "$TRAVAIL/gateway.sh" <<REMOTE
set -eu
HELIOSD=/opt/helios/current/heliosd
DEPOT="$DEPOT"
rm -rf -- "\$DEPOT" && mkdir -p "\$DEPOT"

if [ "$REFAIRE_CA" = 1 ]; then
    echo "-- init-key-negotiation"
    "\$HELIOSD" init-key-negotiation \
        --server-name '$SERVER_NAME' \
        --client-ca /tmp/orion-client-ca.der \
        --client-pq-ca /tmp/orion-client-pq-ca-public.bin \
        --rotate
    rm -f /tmp/orion-client-ca.der /tmp/orion-client-pq-ca-public.bin
fi

# Le pair du meme nom est retire d'office, et ce n'est pas une commodite :
# provisionner « $CLIENT » signifie faire marcher ce client-la. Une admission
# preexistante porte de toute facon les empreintes d'anciens certificats, que
# la CA courante ne peut plus reproduire — la garder ferait echouer la
# negociation sans que rien ne la designe. L'admission est nominative : elle se
# recree, elle ne se perd pas.
if "\$HELIOSD" peer remove --name '$CLIENT' >/dev/null 2>&1; then
    echo "-- pair « $CLIENT » preexistant retire"
fi
echo "-- peer add"
# « tail -1 » prenait la derniere ligne de stdout — or heliosd y journalise
# aussi, et la VIP se retrouvait remplacee par « INFO heliosd: peer admitted ».
# On extrait le champ, pas une position : awk compare le premier champ au nom
# demande, ce qu'aucune ligne de journal ne peut satisfaire.
"\$HELIOSD" peer add \
    --name '$CLIENT' \
    --public-key '$WG_PUBLIQUE' \
    --key-negotiation-certificate-sha256 '$FP_TLS' \
    --key-negotiation-pq-certificate-sha256 '$FP_PQ' \
    --minimum-mode '$MODE' \
    | awk -F'\t' -v n='$CLIENT' '\$1 == n { print \$2 }' > "\$DEPOT/peer.txt"

# Le port de negociation ne figure dans aucun certificat : hors API, il faut
# aller le lire dans la configuration de la gateway, sans quoi « enroll » refuse
# faute de savoir ou le client devra se presenter.
sed -n 's/^[[:space:]]*key_negotiation_port[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
    /var/lib/helios/network.toml | head -1 > "\$DEPOT/port.txt"

cp /var/lib/helios/key-negotiation-cert.der "\$DEPOT/gw-cert.der"
cp /var/lib/helios/key-negotiation-pq-cert.json "\$DEPOT/gw-pq-cert.json"
# Rendus au compte qui a lance sudo : scp les reprendra sans privilege.
# Ni backticks ni \$(...) dans ce heredoc : il n'est pas quote — il ne peut pas
# l'etre, les valeurs locales doivent s'y substituer — donc tout backtick y
# serait execute ICI, a la construction. Un « scp » entre backticks dans ce
# commentaire lancait scp sans argument a chaque appel du script.
chown -R "\${SUDO_USER:-root}" "\$DEPOT"
REMOTE

scp -q "$TRAVAIL/gateway.sh" "$CIBLE:/tmp/helios-provision-$$.sh"
echo "==> Travail sur la gateway (sudo demandé une fois)"
if ! helios_ssh_sudo "$CIBLE" "bash /tmp/helios-provision-$$.sh; rc=\$?; rm -f /tmp/helios-provision-$$.sh; exit \$rc"; then
    echo "La séquence privilégiée a échoué sur $CIBLE." >&2
    exit 1
fi

echo "==> Récupération des résultats"
scp -q "$CIBLE:$DEPOT/peer.txt" "$TRAVAIL/peer.txt"
scp -q "$CIBLE:$DEPOT/port.txt" "$TRAVAIL/port.txt"
scp -q "$CIBLE:$DEPOT/gw-cert.der" "$TRAVAIL/gw-cert.der"
scp -q "$CIBLE:$DEPOT/gw-pq-cert.json" "$TRAVAIL/gw-pq-cert.json"
ssh "$CIBLE" "rm -rf -- '$DEPOT'"

VIP="$(tr -d '\r' < "$TRAVAIL/peer.txt" | cut -f2)"
if [ -z "$VIP" ]; then
    echo "La gateway n'a pas rendu de VIP. Réponse : $(cat "$TRAVAIL/peer.txt")" >&2
    exit 1
fi
echo "    VIP $VIP"

PORT_NEGO="$(tr -d '\r' < "$TRAVAIL/port.txt")"
if [ -z "$PORT_NEGO" ]; then
    echo "La gateway ne publie aucun key_negotiation_port dans network.toml." >&2
    echo "Le mode $MODE en a besoin : l'y ajouter, puis relancer." >&2
    exit 1
fi
# Le meme hote que le tunnel, l'autre port : si --endpoint designe l'adresse
# publique, la negociation doit y aller aussi — pas sur l'adresse LAN par
# laquelle ce script a joint la gateway en SSH.
NEGOCIATION="${ENDPOINT%:*}:$PORT_NEGO"
echo "    négociation $NEGOCIATION"
[ -s "$TRAVAIL/gw-cert.der" ] || { echo "certificat TLS de la gateway vide" >&2; exit 1; }
[ -s "$TRAVAIL/gw-pq-cert.json" ] || { echo "certificat PQ de la gateway vide" >&2; exit 1; }

# ── 6. Enrôlement ────────────────────────────────────────────────────────────
mkdir -p "$SORTIE"
PROFIL="$SORTIE/$CLIENT.orion"
echo "==> Enrôlement"
"${CTL[@]}" enroll \
    --name "$CLIENT" \
    --endpoint "$ENDPOINT" \
    --client-ca-dir "$CA_DIR" \
    --mode "$MODE" \
    --public-key "$WG_PUBLIQUE" \
    --private-key-file "$TRAVAIL/wg-private.key" \
    --client-pki-dir "$PKI" \
    --negotiation-endpoint "$NEGOCIATION" \
    --gateway-certificate "$TRAVAIL/gw-cert.der" \
    --gateway-pq-certificate "$TRAVAIL/gw-pq-cert.json" \
    --address "$VIP" \
    --output "$PROFIL" "${ARG_TRAFIC[@]}"

echo
echo "==> Profil écrit : $PROFIL"
echo
echo "Il porte les clés privées du client : le transmettre par un canal"
echo "contrôlé, l'importer dans Orion, puis le détruire des deux côtés."
if [ "$REFAIRE_CA" = 1 ]; then
    echo
    echo "⚠  La négociation de la gateway a été réinitialisée : tous les autres"
    echo "   clients doivent être réenrôlés avec ce même script."
fi
