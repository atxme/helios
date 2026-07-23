#!/usr/bin/env bash
# Déploiement complet d'une gateway, en une commande.
#
#   ./scripts/deploy.sh christophe@192.168.1.44   # première fois : l'hôte est retenu
#   ./scripts/deploy.sh                           # ensuite
#
# Enchaîne ce que l'ADR-004 sépare volontairement en trois outils : construire,
# signer hors ligne, archiver — puis copie et installe. La séparation garde son
# sens pour une release publique, où la signature se joue sur un autre poste ;
# pour un opérateur qui détient les trois rôles, la retaper à chaque fois n'a
# aucune valeur.
#
# Ce script ne remplace pas `scripts/regression.sh` : il ne vérifie rien du
# code, il livre ce qu'on lui donne.
set -euo pipefail

cd "$(dirname "$0")/.."

ETAT="${HELIOS_DEPLOY_STATE:-$HOME/.helios/deploy.conf}"
EPOQUE="${HELIOS_PUBLISHER_EPOCH:-$HOME/.helios/publisher-epoch-1}"
CANAL="${HELIOS_DEPLOY_CHANNEL:-production}"
INSTALLER=1
SEQUENCE=""

usage() {
    cat >&2 <<'EOF'
Usage : ./scripts/deploy.sh [hôte-ssh] [options]

  --sequence N     Force la séquence de release (défaut : horodatage Unix)
  --copie-seule    Copie l'archive sans lancer l'installation privilégiée
  --canal C        testing ou production (défaut : production)

L'hôte est retenu après le premier appel ; les appels suivants n'en ont plus
besoin. Variables reconnues : HELIOS_PUBLISHER_EPOCH, HELIOS_DEPLOY_CHANNEL.
EOF
    exit 1
}

CIBLE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --sequence) SEQUENCE="${2:-}"; shift 2 ;;
        --copie-seule) INSTALLER=0; shift ;;
        --canal) CANAL="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        -*) echo "option inconnue : $1" >&2; usage ;;
        *) CIBLE="$1"; shift ;;
    esac
done

# ── Cible : donnée une fois, retenue ensuite ─────────────────────────────────
if [ -z "$CIBLE" ] && [ -f "$ETAT" ]; then
    CIBLE="$(sed -n 's/^cible=//p' "$ETAT")"
fi
if [ -z "$CIBLE" ]; then
    echo "Aucune cible connue. Premier appel :" >&2
    echo "  ./scripts/deploy.sh utilisateur@adresse" >&2
    exit 1
fi
mkdir -p "$(dirname "$ETAT")"
printf 'cible=%s\n' "$CIBLE" > "$ETAT"

# ── Clés éditeur ─────────────────────────────────────────────────────────────
for f in ed25519-private.pk8 ml-dsa-65-private.bin publisher-keyring.json; do
    if [ ! -f "$EPOQUE/$f" ]; then
        echo "Époque éditeur incomplète : $EPOQUE/$f introuvable." >&2
        echo "En créer une :" >&2
        echo "  cargo run -p helios-publisher -- keygen --key-epoch 1 --output-dir $EPOQUE" >&2
        exit 1
    fi
done
EPOQUE_N="$(sed -n 's/.*"key_epoch"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
    "$EPOQUE/publisher-keyring.json" | head -1)"
[ -n "$EPOQUE_N" ] || { echo "époque illisible dans $EPOQUE/publisher-keyring.json" >&2; exit 1; }

# ── Séquence : un horodatage, pas un compteur à tenir ────────────────────────
# L'anti-rollback de l'ADR-003 exige une séquence strictement croissante. Un
# compteur local se désynchronise dès qu'on déploie depuis une autre machine ou
# qu'on réinstalle la gateway ; l'horodatage Unix est croissant par
# construction, sans état à conserver nulle part.
[ -n "$SEQUENCE" ] || SEQUENCE="$(date +%s)"

# ── Traçabilité : un arbre modifié ne doit pas se faire passer pour un commit ─
COMMIT="$(git rev-parse --short=16 HEAD)"
if ! git diff --quiet || ! git diff --cached --quiet; then
    COMMIT="${COMMIT}-dirty"
    echo "⚠  Arbre de travail modifié : le manifeste portera « $COMMIT »." >&2
fi

CIBLE_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml |
    sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
NOM="helios-$VERSION-$CIBLE_TRIPLE"
REP="target/bundle/$NOM"
ARCHIVE="target/bundle/$NOM.tar.gz"

echo "==> Gateway   $CIBLE"
echo "==> Release   $VERSION séquence $SEQUENCE canal $CANAL"
echo "==> Commit    $COMMIT"
echo

echo "==> 1/5  Construction"
# `xtask bundle` rappelle les deux commandes suivantes à taper : elles sont
# redondantes ici, ce script les enchaîne. On coupe à partir de ce rappel.
HELIOS_PUBLISHER_KEYRING_PATH="$EPOQUE/publisher-keyring.json" \
    cargo xtask bundle --target "$CIBLE_TRIPLE" \
    | sed '/^Signer sur le poste éditeur/,$d'

echo "==> 2/5  Signature hors ligne (époque $EPOQUE_N)"
cargo run --quiet -p helios-publisher -- bundle \
    --dir "$REP" \
    --key-epoch "$EPOQUE_N" \
    --release-sequence "$SEQUENCE" \
    --channel "$CANAL" \
    --version "$VERSION" \
    --git-commit "$COMMIT" \
    --target "$CIBLE_TRIPLE" \
    --ed25519-private-key "$EPOQUE/ed25519-private.pk8" \
    --ml-dsa-65-private-key "$EPOQUE/ml-dsa-65-private.bin" \
    --keyring "$EPOQUE/publisher-keyring.json" > /dev/null

echo "==> 3/5  Archivage"
EMPREINTE="$(cargo xtask pack --dir "$REP" 2>/dev/null | awk 'NF==2 {print $1; exit}')"
[ -n "$EMPREINTE" ] || { echo "empreinte de l'archive illisible" >&2; exit 1; }
echo "    $EMPREINTE"

echo "==> 4/5  Copie vers $CIBLE"
scp -q "$ARCHIVE" "$CIBLE:~/"
DISTANTE="$(ssh "$CIBLE" "sha256sum ~/$NOM.tar.gz" | awk '{print $1}')"
if [ "$DISTANTE" != "$EMPREINTE" ]; then
    echo "ÉCHEC : l'archive copiée diffère de l'originale." >&2
    echo "  locale  $EMPREINTE" >&2
    echo "  distante $DISTANTE" >&2
    exit 1
fi
echo "    empreinte identique des deux côtés"

if [ "$INSTALLER" = "0" ]; then
    echo
    echo "==> Copie seule demandée. Sur la gateway :"
    echo "    tar xzf $NOM.tar.gz && sudo ./$NOM/helios-installer bootstrap --archive $NOM.tar.gz"
    exit 0
fi

echo "==> 5/5  Installation privilégiée (mot de passe sudo de la gateway)"
# `-t` alloue un terminal : sans lui, l'invite de mot de passe de sudo n'a nulle
# part où s'afficher et la commande échoue sans dire pourquoi.
# L'ancien répertoire extrait est retiré d'abord : sinon on lancerait
# l'installateur de la version précédente sur l'archive de la nouvelle.
ssh -t "$CIBLE" "
    set -e
    rm -rf ~/$NOM
    tar xzf ~/$NOM.tar.gz
    sudo ~/$NOM/helios-installer bootstrap --archive ~/$NOM.tar.gz
    rm -rf ~/$NOM
"

cat <<EOF

──────────────────────────────────────────────────────────────
  Déployé : $VERSION séquence $SEQUENCE sur $CIBLE

  Le service n'est pas activé. Pour un essai surveillé :
    ssh -t $CIBLE 'sudo /opt/helios/current/heliosd run'

  Une fois validé, pour qu'il survive au redémarrage :
    ssh -t $CIBLE 'sudo systemctl enable --now heliosd helios-update.path'
──────────────────────────────────────────────────────────────
EOF
