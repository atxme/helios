#!/usr/bin/env bash
# Déploiement du conteneur Astra (ADR-008), en une commande.
#
#   ./scripts/deploy-astra.sh              # l'hôte est repris de deploy.sh
#   ./scripts/deploy-astra.sh utilisateur@adresse
#
# Astra n'entre PAS dans le bundle signé de l'ADR-004, et ce n'est pas un
# oubli : c'est un conteneur séparé, avec son propre UID, son propre état et
# aucune capacité. `deploy.sh` livre la gateway ; celui-ci livre l'autorité.
# Les deux se déploient indépendamment, dans cet ordre.
#
# Ce script ne crée aucun domaine de confiance. L'amorçage est un geste
# volontaire, une seule fois, et il est décrit à la fin de son exécution —
# parce qu'il exige des valeurs qui naissent sur le poste opérateur, dans
# `astra-signer`, et qu'aucun script ne peut deviner.
set -euo pipefail

cd "$(dirname "$0")/.."

ETAT="${HELIOS_DEPLOY_STATE:-$HOME/.helios/deploy.conf}"
IMAGE="helios/astra:latest"
CONSTRUIRE_SUR_CIBLE=0

usage() {
    cat >&2 <<'EOF'
Usage : ./scripts/deploy-astra.sh [hôte-ssh] [options]

  --sur-cible      Construit l'image sur la gateway plutôt que localement.
                   Plus lent, mais évite de transférer une image entière.

L'hôte est celui retenu par deploy.sh ; le donner ici le retient aussi.
EOF
    exit 1
}

CIBLE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --sur-cible) CONSTRUIRE_SUR_CIBLE=1; shift ;;
        -h|--help) usage ;;
        -*) echo "option inconnue : $1" >&2; usage ;;
        *) CIBLE="$1"; shift ;;
    esac
done

if [ -z "$CIBLE" ] && [ -f "$ETAT" ]; then
    CIBLE="$(sed -n 's/^cible=//p' "$ETAT")"
fi
if [ -z "$CIBLE" ]; then
    echo "Aucune cible connue. Premier appel :" >&2
    echo "  ./scripts/deploy-astra.sh utilisateur@adresse" >&2
    exit 1
fi
mkdir -p "$(dirname "$ETAT")"
printf 'cible=%s\n' "$CIBLE" > "$ETAT"

ENV_LOCAL="deploy/astra/.env"
if [ ! -f "$ENV_LOCAL" ]; then
    echo "Aucun $ENV_LOCAL." >&2
    echo "  cp deploy/astra/env.example $ENV_LOCAL   puis le remplir" >&2
    echo >&2
    echo "ASTRA_RP_ID s'y choisit UNE fois : en changer rend inouvrables tous" >&2
    echo "les key-slots du coffre d'autorité, définitivement." >&2
    exit 1
fi

echo "==> Astra sur $CIBLE"
echo

# ── Le distant a-t-il de quoi faire tourner un conteneur ? ───────────────────
COMPOSE="$(ssh "$CIBLE" 'if docker compose version >/dev/null 2>&1; then echo "docker compose";
    elif command -v docker-compose >/dev/null 2>&1; then echo docker-compose;
    elif podman compose version >/dev/null 2>&1; then echo "podman compose";
    else echo ""; fi')"
if [ -z "$COMPOSE" ]; then
    echo "Ni docker compose, ni podman compose sur $CIBLE." >&2
    echo "  ssh $CIBLE 'sudo apt-get install -y docker.io docker-compose-v2'" >&2
    exit 1
fi
echo "    moteur : $COMPOSE"

# ── 1. L'image ───────────────────────────────────────────────────────────────
if [ "$CONSTRUIRE_SUR_CIBLE" = "1" ]; then
    echo "==> 1/4  Envoi des sources et construction sur la cible"
    # `git archive` plutôt qu'un rsync du répertoire : ce qui part est ce qui
    # est commité, pas ce qui traîne dans l'arbre de travail — y compris les
    # clés d'un essai local.
    git archive --format=tar HEAD | ssh "$CIBLE" \
        'rm -rf ~/astra-build && mkdir -p ~/astra-build && tar -x -C ~/astra-build'
    ssh "$CIBLE" "cd ~/astra-build && $COMPOSE -f deploy/astra/compose.yaml build"
else
    echo "==> 1/4  Construction locale de $IMAGE"
    docker build -f deploy/astra/Dockerfile -t "$IMAGE" .
    echo "==> 2/4  Transfert de l'image"
    docker save "$IMAGE" | gzip | ssh "$CIBLE" 'gunzip | docker load'
fi

# ── 2. Compose et paramètres ─────────────────────────────────────────────────
echo "==> 3/4  Copie de la configuration"
ssh "$CIBLE" 'mkdir -p ~/astra/deploy/astra'
scp -q deploy/astra/compose.yaml "$CIBLE:~/astra/deploy/astra/compose.yaml"
# Le .env ne porte aucun secret — clés publiques et identifiants — mais il
# décrit le domaine de confiance : 0600 quand même, et jamais dans le dépôt.
scp -q "$ENV_LOCAL" "$CIBLE:~/astra/deploy/astra/.env"
ssh "$CIBLE" 'chmod 600 ~/astra/deploy/astra/.env'

# ── 3. Amorcé, ou pas encore ? ───────────────────────────────────────────────
AMORCE="$(ssh "$CIBLE" "$COMPOSE -f ~/astra/deploy/astra/compose.yaml \
    --env-file ~/astra/deploy/astra/.env run --rm --no-deps astra status \
    >/dev/null 2>&1 && echo oui || echo non")"

if [ "$AMORCE" = "non" ]; then
    echo "==> 4/4  Domaine de confiance non amorcé"
    echo
    echo "L'image est en place ; le registre, non. L'amorçage est un geste"
    echo "unique et il exige des valeurs qui naissent ailleurs :"
    echo
    echo "  1. Sur le poste où la clé de sécurité est branchée :"
    echo "       astra-signer init --rp-id \$ASTRA_RP_ID --label \"YubiKey ...\""
    echo "     → imprime CA-PQ publique et trust_domain_id."
    echo
    echo "  2. Sur $CIBLE :"
    echo "       cd ~/astra && $COMPOSE -f deploy/astra/compose.yaml \\"
    echo "         --env-file deploy/astra/.env run --rm astra bootstrap \\"
    echo "         --ca-public-key <CA-PQ> --trust-domain-id <domaine> \\"
    echo "         --gateway-wireguard-public-key \$(wg show helios0 public-key) \\"
    echo "         --server-name <sujet de la leaf PQ> \\"
    echo "         --authority-url \$ASTRA_AUTHORITY_URL \\"
    echo "         --webauthn-rp-id \$ASTRA_RP_ID"
    echo "     → imprime la clé de service et la tête de chaîne d'audit."
    echo
    echo "  3. Reporter la tête d'audit dans ASTRA_EXPECTED_AUDIT_HEAD, puis"
    echo "     relancer ce script."
    echo
    echo "  4. Sur la gateway, l'autre moitié du domaine :"
    echo "       sudo heliosd init-trust-domain --trust-domain-id <domaine> \\"
    echo "         --ca-public-key <CA-PQ> \\"
    echo "         --astra-service-public-key <clé de service> \\"
    echo "         --authority-url \$ASTRA_AUTHORITY_URL \\"
    echo "         --webauthn-rp-id \$ASTRA_RP_ID"
    echo "       sudo systemctl restart heliosd"
    exit 0
fi

# ── 4. Démarrage ─────────────────────────────────────────────────────────────
echo "==> 4/4  Démarrage"
ssh "$CIBLE" "cd ~/astra && $COMPOSE -f deploy/astra/compose.yaml \
    --env-file deploy/astra/.env up -d"
echo
ssh "$CIBLE" "cd ~/astra && $COMPOSE -f deploy/astra/compose.yaml \
    --env-file deploy/astra/.env run --rm astra status"
echo
echo "Astra écoute sur 127.0.0.1:8443, en HTTP clair : le terminateur TLS se"
echo "met devant. Ce n'est pas son certificat de transport qui l'authentifie,"
echo "c'est sa clé de service ML-DSA-87 épinglée."
