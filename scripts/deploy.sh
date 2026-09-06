#!/usr/bin/env bash
# Déploiement complet d'une gateway, en une commande.
#
#   ./scripts/deploy.sh          # depuis la racine du dépôt
#   ./deploy.sh                  # ou depuis scripts/, les deux marchent
#   ./scripts/deploy.sh root@autre-machine   # ponctuellement ailleurs
#
# L'adresse de la gateway est en dur dans `lib-remote.sh` (`HELIOS_CIBLE`) :
# aucun argument à retaper, et un seul endroit à changer quand elle déménage.
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

# Le répertoire du script, en absolu et **avant** tout `cd`.
#
# `dirname "$0"` est relatif au répertoire courant : le résoudre après avoir
# changé de répertoire le fait désigner autre chose. Lancé par `./deploy.sh`
# depuis `scripts/`, `dirname` vaut « . », le `cd ..` mène à la racine, et le
# « ./lib-remote.sh » qui suivait y était cherché — d'où le « No such file or
# directory » qui ne se produisait que depuis ce répertoire-là.
SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPTS/.."

# Un seul mot de passe sudo pour tout le déploiement, et l'adresse de la
# gateway : voir lib-remote.sh.
# shellcheck source=scripts/lib-remote.sh
. "$SCRIPTS/lib-remote.sh"

EPOQUE="$HOME/.helios/publisher-epoch-1"
CANAL="${HELIOS_DEPLOY_CHANNEL:-production}"
INSTALLER=1
ASTRA=1
ASTRA_ONLY=0
FIREWALL_MODE=preserve
SEQUENCE=""
# Relais public écrit par `astra-signer init` : domaine, RP ID, ancre CA-PQ.
# Rien de secret — le coffre, lui, ne quitte jamais le poste opérateur.
RELAIS="${ASTRA_HANDOFF:-$HOME/.helios/astra/astra-domain.json}"
# Leaf publique rendue par la cérémonie hors ligne du §13.1. Le chemin par
# défaut est à côté du relais : le premier passage y dépose la demande, le
# compagnon y écrit la réponse, puis `--astra` reprend sans valeur à recopier.
CERTIFICAT_AMORCAGE="${HELIOS_GATEWAY_BOOTSTRAP_CERTIFICATE:-$(dirname "$RELAIS")/gateway-bootstrap-certificate.json}"
# L'installation ne met rien dans le PATH : `heliosd` n'existe que sous ce
# chemin, et root ne le trouve pas autrement. Le nommer en clair évite un
# « command not found » là où l'on croirait lire un refus d'amorçage.
HELIOSD=/opt/helios/current/heliosd
# Chemin du binaire Astra **dans** son image. Nécessaire parce que `docker
# compose exec` n'applique pas l'`ENTRYPOINT` : il exécute l'argv tel quel, donc
# « status » y serait cherché dans le PATH comme un programme. Les deux autres
# accès de l'étape 7 (`run` et le conteneur jetable) passent, eux, par
# l'entrypoint et ne le prennent pas.
ASTRA_BIN=/usr/local/bin/astra
# Bout gateway du veth privé Astra ↔ Helios (ROTATION-CERTIFICATS §8.3).
# La même adresse que le réseau `astra-private` de `deploy/astra/compose.yaml` :
# un /29 qui ne contient que ses deux extrémités, sans route par défaut.
# Cette coordonnée fait partie du ruleset atomique Helios et du bridge `astra0`
# de compose. La rendre surchargeable sans recompiler le pare-feu créerait un
# listener que la politique refuse — ou, pire, une ouverture sans listener.
CANAL_PRIVE="10.88.7.1:8444"
# Bout Astra du même veth, pour la direction opposée : c'est Helios qui appelle,
# pour relayer le renouvellement d'un client (§8.1.2). Un second port plutôt
# qu'un second réseau — le ruleset atomique nomme déjà les deux sens, adresses
# et ports exacts, et `helios-firewall::ruleset` refuse tout le reste.
CANAL_AUTORITE="10.88.7.2:8445"

usage() {
    cat >&2 <<'EOF'
Usage : ./scripts/deploy.sh [hôte-ssh] [options]

  --sequence N     Force la séquence de release (défaut : horodatage Unix)
  --copie-seule    Copie l'archive sans lancer l'installation privilégiée
  --canal C        testing ou production (défaut : production)
  --sans-astra     Saute le conteneur d'autorité, même si un relais existe
  --astra           Reprend uniquement l'étape Astra, sans relivrer la gateway
  --sans-firewall   Mode maintenance persistant : firewall Helios désactivé
                    après redémarrage et Astra sauté
  --avec-firewall   Retire explicitement le mode maintenance au redémarrage

Astra (ADR-008) se déploie tout seul dès qu'un relais de domaine existe —
celui qu'écrit `astra-signer init` à côté du coffre. Sans relais, cette
partie est silencieusement sautée : une gateway sans autorité reste une
gateway qui marche.

L'hôte est en dur dans scripts/lib-remote.sh (HELIOS_CIBLE) : la commande
n'en prend aucun. L'argument reste accepté pour viser ponctuellement une
autre machine, sans rien changer aux appels suivants.

Variables reconnues : HELIOS_CIBLE, HELIOS_DEPLOY_CHANNEL, ASTRA_HANDOFF,
HELIOS_GATEWAY_BOOTSTRAP_CERTIFICATE.
EOF
    exit 1
}

CIBLE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --sequence) SEQUENCE="${2:-}"; shift 2 ;;
        --copie-seule) INSTALLER=0; shift ;;
        --sans-astra) ASTRA=0; shift ;;
        --astra) ASTRA_ONLY=1; shift ;;
        --sans-firewall) FIREWALL_MODE=disabled; ASTRA=0; shift ;;
        --avec-firewall) FIREWALL_MODE=enabled; shift ;;
        --canal) CANAL="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        -*) echo "option inconnue : $1" >&2; usage ;;
        *) CIBLE="$1"; shift ;;
    esac
done

# ── Cible : celle de lib-remote.sh, sauf argument explicite ──────────────────
# Un argument l'emporte mais ne s'enregistre pas : un déploiement de dépannage
# vers une autre machine ne doit pas détourner silencieusement les suivants.
CIBLE="${CIBLE:-$HELIOS_CIBLE}"
if [ -z "$CIBLE" ]; then
    echo "Aucune gateway : renseigner HELIOS_CIBLE dans scripts/lib-remote.sh," >&2
    echo "ou passer l'hôte en argument : ./scripts/deploy.sh utilisateur@adresse" >&2
    exit 1
fi
if [ "$ASTRA_ONLY" = "1" ] && [ "$ASTRA" = "0" ]; then
    echo "--astra et --sans-astra sont incompatibles" >&2
    exit 1
fi
if [ "$ASTRA_ONLY" = "1" ] && [ "$FIREWALL_MODE" != "preserve" ]; then
    echo "--astra ne modifie pas le mode firewall ; relivrer la gateway séparément" >&2
    exit 1
fi

# Une seule invite pour tout le déploiement, prise **ici** : dans un pipeline,
# `helios_ssh_sudo` tourne en sous-shell et le mot de passe y serait perdu.
helios_sudo_init "$CIBLE"

# ── Clés éditeur ─────────────────────────────────────────────────────────────
FICHIERS_EPOQUE="publisher-keyring.json"
if [ "$ASTRA_ONLY" = "0" ]; then
    FICHIERS_EPOQUE="ed25519-private.pk8 ml-dsa-65-private.bin $FICHIERS_EPOQUE"
fi
for f in $FICHIERS_EPOQUE; do
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
case "$SEQUENCE" in
    *[!0-9]*)
        echo "Séquence invalide : $SEQUENCE (un entier non signé est attendu)." >&2
        exit 1
        ;;
esac

# ── Traçabilité : un arbre modifié ne doit pas se faire passer pour un commit ─
COMMIT="$(git rev-parse --short=16 HEAD)"
if [ -n "$(git status --porcelain)" ]; then
    COMMIT="${COMMIT}-dirty"
    echo "⚠  Arbre de travail modifié : le manifeste portera « $COMMIT »." >&2
fi

CIBLE_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
# La version du démon, pas celle du workspace : `heliosd` n'hérite pas de
# `version.workspace`, et le marqueur de disponibilité qu'il écrit après une
# mise à jour porte la version de son crate. Un manifeste étiqueté avec la
# version du workspace ne peut jamais être confirmé, et le nom du bundle ne
# correspondrait plus à celui que `xtask bundle` produit. Même source que
# `xtask::release_version`.
VERSION="$(sed -n '/^\[package\]/,/^\[/p' crates/heliosd/Cargo.toml |
    sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
[ -n "$VERSION" ] || { echo "version illisible dans crates/heliosd/Cargo.toml" >&2; exit 1; }
NOM="helios-$VERSION-$CIBLE_TRIPLE"
REP="target/bundle/$NOM"
ARCHIVE="target/bundle/$NOM.tar.gz"

echo "==> Gateway   $CIBLE"
echo "==> Release   $VERSION séquence $SEQUENCE canal $CANAL"
echo "==> Commit    $COMMIT"
echo

if [ "$ASTRA_ONLY" = "0" ]; then
echo "==> 1/7  Construction"
# `xtask bundle` rappelle les deux commandes suivantes à taper : elles sont
# redondantes ici, ce script les enchaîne. On coupe à partir de ce rappel.
HELIOS_PUBLISHER_KEYRING_PATH="$EPOQUE/publisher-keyring.json" \
    cargo xtask bundle --target "$CIBLE_TRIPLE" \
    | sed '/^Signer sur le poste éditeur/,$d'

echo "==> 2/7  Signature hors ligne (époque $EPOQUE_N)"
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

echo "==> 3/7  Archivage"
EMPREINTE="$(cargo xtask pack --dir "$REP" 2>/dev/null | awk 'NF==2 {print $1; exit}')"
[ -n "$EMPREINTE" ] || { echo "empreinte de l'archive illisible" >&2; exit 1; }
echo "    $EMPREINTE"

echo "==> 4/7  Copie vers $CIBLE"
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

echo "==> 5/7  Installation privilégiée"
# L'extraction reste **non privilégiée**, et seul l'installateur passe par
# `sudo` : `~` désigne le répertoire de l'utilisateur qui l'écrit, et sous
# `sudo` il vaudrait `/root`, où l'archive n'a jamais été copiée. Moindre
# privilège et chemin correct, pour la même raison.
#
# L'ancien répertoire extrait est retiré d'abord : sinon on lancerait
# l'installateur de la version précédente sur l'archive de la nouvelle.
ssh "$CIBLE" "set -e; rm -rf ~/$NOM; tar xzf ~/$NOM.tar.gz"
DISTANT_HOME="$(ssh "$CIBLE" 'echo "$HOME"')"
helios_ssh_sudo "$CIBLE" \
    "'$DISTANT_HOME/$NOM/helios-installer' bootstrap --archive '$DISTANT_HOME/$NOM.tar.gz'"
ssh "$CIBLE" "rm -rf ~/$NOM"

echo "==> 6/7  Network, TPM, PKI and Orion identity bootstrap"
FIREWALL_ARG=()
case "$FIREWALL_MODE" in
    disabled) FIREWALL_ARG=(--disable-firewall) ;;
    enabled) FIREWALL_ARG=(--enable-firewall) ;;
esac
./scripts/target-bootstrap.sh "$CIBLE" "${FIREWALL_ARG[@]}"
else
    echo "==> Reprise Astra seule sur $CIBLE"
fi

# ── Le terminateur TLS de l'origine publique ────────────────────────────────
#
# Astra sert du HTTP clair sur `127.0.0.1:8443`. Ce n'est pas un oubli : le
# certificat de transport n'authentifie pas l'autorité — c'est sa clé de
# service ML-DSA-87 épinglée qui le fait (ADR-008 §9.6). Mais la récupération
# d'une identité expirée (§7.5) est le seul chemin qui n'a plus de tunnel : elle
# monte un client HTTPS ordinaire, qui valide la chaîne sous les racines du
# système. Sans terminateur devant, cette origine n'existe pas et §7.5 est
# fermée — c'est exactement la limite que ce dépôt documentait.
#
# Quand l'origine est un nom `*.ts.net`, le terminateur est déjà là. Tailscale
# émet et renouvelle tout seul un certificat publiquement reconnu pour le nom du
# nœud, et `tailscale serve` le présente sur 443 **à l'intérieur du tailnet
# seulement**. Rien à installer sur l'hôte, aucune autorité locale à faire
# approuver dans le magasin racine du poste opérateur, et aucune règle 443 dans
# le pare-feu applicatif : l'écoute appartient à `tailscaled`, pas à Helios, et
# le contrôle d'accès est celui des ACL du tailnet.
#
# Funnel exposerait ce même nom sur l'Internet public. Il n'est jamais activé
# ici, et le trouver activé arrête l'étape plutôt que de la confirmer.
#
# Toute autre origine garde le modèle documenté par l'ADR-008 §2 : un
# terminateur externe, à la charge de l'opérateur.
terminateur_tailscale() {
    local url="$1" hote fqdn sortie
    hote="${url#https://}"
    hote="${hote%%/*}"
    hote="${hote%%:*}"
    case "$hote" in
        *.ts.net) ;;
        *)
            echo "    origine $hote : terminateur TLS externe attendu (ADR-008 §2)"
            return 0
            ;;
    esac

    if ! ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" 'command -v tailscale >/dev/null 2>&1'; then
        echo "    l'origine est $hote mais la cible n'a pas de tailscale : rien ne" >&2
        echo "    termine le TLS, et la récupération §7.5 reste fermée." >&2
        return 1
    fi

    # `tailscale serve` ne sait présenter que le certificat du nœud sur lequel
    # il tourne. Une origine qui nomme une autre machine ne serait donc pas
    # servie ici — et le dire maintenant vaut mieux qu'un échec de validation
    # TLS le jour où une identité est déjà expirée.
    fqdn="$(ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" 'tailscale status --json --peers=false' |
        sed -n 's/.*"DNSName"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    fqdn="${fqdn%.}"
    if [ -z "$fqdn" ]; then
        echo "    nom Tailscale de la cible illisible : MagicDNS est-il actif ?" >&2
        return 1
    fi
    if [ "$fqdn" != "$hote" ]; then
        echo "    l'origine du domaine est $hote, mais cette machine est $fqdn." >&2
        echo "    Tailscale ne peut présenter que son propre nom : servir ici" >&2
        echo "    donnerait un certificat que le client refuserait." >&2
        return 1
    fi

    if ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" 'tailscale serve status --json 2>/dev/null' |
        grep -q '"AllowFunnel"'; then
        echo "    Funnel est configuré sur ce nœud : l'origine de l'autorité serait" >&2
        echo "    exposée sur l'Internet public. Le retirer par « tailscale funnel" >&2
        echo "    reset » avant de reprendre." >&2
        return 1
    fi

    # Idempotent : rejouer la même cartographie ne change rien. `--bg` la rend
    # persistante, donc elle survit au redémarrage de la cible sans unité
    # systemd à écrire.
    if ! sortie="$(helios_ssh_sudo_capture "$CIBLE" \
        'tailscale serve --bg --https=443 http://127.0.0.1:8443 2>&1')"; then
        echo "    « tailscale serve » a échoué :" >&2
        printf '%s\n' "$sortie" | tail -10 >&2
        return 1
    fi

    # La vérification est la première requête que fait §7.5, et pas une sonde
    # inventée pour l'occasion : si celle-ci passe, le chemin complet passe —
    # certificat public, Serve, publication Docker, Astra. `--fail` pour qu'un
    # 502 de `tailscaled` devant un conteneur arrêté ne compte pas comme un
    # succès, et pas de `--insecure` : valider la chaîne est tout l'objet.
    #
    # `--resolve` plutôt que le DNS de la cible : une gateway n'a aucune raison
    # de résoudre son propre nom MagicDNS — son `resolved` peut ne pas pointer
    # vers `100.100.100.100`, et sa propre politique de sortie peut fermer le
    # port 53. Ce que cette étape doit prouver est que l'origine répond à qui
    # l'appelle depuis le tailnet, pas que la machine sait s'appeler elle-même :
    # échouer là-dessus serait un faux négatif sur un déploiement correct.
    local ip4
    ip4="$(ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" 'tailscale ip -4' | head -1 | tr -d '\r')"
    if [ -z "$ip4" ]; then
        echo "    adresse Tailscale de la cible illisible" >&2
        return 1
    fi
    if ! sortie="$(ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" "curl -fsS --max-time 15 \
        --resolve '$hote:443:$ip4' \
        -X POST -H 'content-type: application/json' -d 'null' \
        'https://$hote/v1/client-rotation/challenge' 2>&1")"; then
        echo "    l'origine https://$hote ne répond pas encore :" >&2
        printf '%s\n' "$sortie" | tail -5 >&2
        echo "    la cartographie Serve est posée ; reprendre après le démarrage" >&2
        echo "    d'Astra la vérifiera." >&2
        return 1
    fi
    echo "    origine   https://$hote (Tailscale Serve, tailnet seulement)"
}

# ── 7. Astra et le domaine de confiance (ADR-008) ────────────────────────────
#
# Tout est déduit ou capturé, rien n'est recopié : le relais donne le domaine,
# le RP ID et l'ancre ; la leaf PQ servie donne le nom de serveur et la clé
# WireGuard ; le bootstrap Astra rend la clé de service et la tête d'audit, qui
# repartent aussitôt vers `heliosd init-trust-domain`. Le seul geste manuel de
# toute la chaîne est celui qui exige une clé physique — `astra-signer init` —
# et il a déjà eu lieu.
deployer_astra() {
    local compose etat wg_pub nom_serveur url rp domaine ancre sortie
    local cle_service tete_audit identite moteur compose_env statut_astra
    local tete_attendue registre_gateway statut_tete_ancienne tete_ancienne
    local unite_build etat_build resultat_build code_build tentative astra_lire_frais
    local canal_present cert_astra cert_gateway demande_gateway certificat_distant
    local ca_tls_der empreinte_ca_tls ca_tls_distant arg_ca_tls

    # `docker` n'est utilisable sans privilège ni ici ni sur la gateway :
    # l'utilisateur n'est dans le groupe `docker` d'aucune des deux. Tout ce
    # qui touche au conteneur passe donc par le même sudo distant que le reste
    # du déploiement — et l'image se construit **sur la cible**, ce qui évite
    # d'exiger un docker local et de transférer plusieurs centaines de Mio.
    compose="$(helios_ssh_sudo_capture "$CIBLE" 'if docker compose version >/dev/null 2>&1; then
            echo "docker compose"
        elif command -v docker-compose >/dev/null 2>&1; then
            echo docker-compose
        elif podman compose version >/dev/null 2>&1; then
            echo "podman compose"
        fi' | tr -d "\r" | head -1)"
    if [ -z "$compose" ]; then
        echo "    ni docker compose ni podman compose sur $CIBLE — Astra non déployé" >&2
        echo "    ssh $CIBLE 'sudo apt-get install -y docker.io docker-compose-v2'" >&2
        return 0
    fi
    echo "    moteur  $compose"
    case "$compose" in podman*) moteur="podman" ;; *) moteur="docker" ;; esac

    # Compose ≥ 2.33 délègue par défaut la construction à `docker buildx bake`.
    # Le paquet Ubuntu `docker-compose-v2` n'entraîne pas `docker-buildx`, et
    # compose se contente alors d'un avertissement : la construction ne produit
    # rien, mais ne rend pas d'erreur non plus. `COMPOSE_BAKE=0` la ramène au
    # constructeur BuildKit embarqué dans compose, qui n'exige aucun greffon —
    # plutôt qu'ajouter une dépendance à la gateway pour un Dockerfile qui
    # n'utilise aucune syntaxe propre à buildx.
    compose_env="COMPOSE_BAKE=0"

    domaine="$(sed -n 's/.*"trust_domain_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$RELAIS")"
    rp="$(sed -n 's/.*"rp_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$RELAIS")"
    ancre="$(sed -n 's/.*"ca_pq_public_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$RELAIS")"
    if [ -z "$domaine" ] || [ -z "$rp" ] || [ -z "$ancre" ]; then
        echo "    relais illisible : $RELAIS" >&2
        return 1
    fi
    url="${ASTRA_AUTHORITY_URL:-https://$rp}"
    echo "    domaine $domaine"
    echo "    RP ID   $rp"

    # L'ancre TLS cliente en service, épinglée par son empreinte et non par son
    # époque. Sans elle, `astra` retient le numéro de l'ancre sans retenir
    # l'ancre : une transition du §9.4 ne pourrait être comparée qu'à la valeur
    # que l'objet transporte lui-même — c'est-à-dire à rien — et le binaire la
    # refuse par son nom jusqu'à un `pin-ca-tls`.
    #
    # Elle se calcule ici plutôt que de se retaper : le relais porte déjà le
    # certificat public (`ca_tls_certificate`, DER en base64) dès qu'`astra-signer
    # issue-ca-tls` a tourné, et l'empreinte en est le SHA-256 en hexadécimal
    # minuscule — exactement ce que `Fingerprint::of` calcule sur ces octets.
    ca_tls_der="$(sed -n \
        's/.*"ca_tls_certificate"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$RELAIS")"
    if [ -n "$ca_tls_der" ]; then
        empreinte_ca_tls="$(printf '%s' "$ca_tls_der" | base64 -d | sha256sum | cut -d' ' -f1)"
        echo "    CA-TLS  $empreinte_ca_tls"
    else
        empreinte_ca_tls=""
        echo "    aucune CA TLS cliente dans le relais : la rotation du §9.4 restera" >&2
        echo "    refusée ici. L'émettre par « astra-signer issue-ca-tls », puis" >&2
        echo "    relancer ./scripts/deploy.sh --astra." >&2
    fi

    # Le nom de serveur et la clé WireGuard sortent de la leaf PQ que la
    # gateway sert, lue par `heliosd` lui-même — donc sous privilège, comme
    # tout ce qui touche à /var/lib/helios.
    identite="$(helios_ssh_sudo_capture "$CIBLE" "$HELIOSD show-identity")" || {
        echo "    la gateway n'a pas d'identité de négociation : lancer d'abord" >&2
        echo "      sudo $HELIOSD init-key-negotiation --server-name ..." >&2
        return 1
    }
    nom_serveur="$(printf '%s\n' "$identite" | sed -n 's/^server_name=//p')"
    wg_pub="$(printf '%s\n' "$identite" | sed -n 's/^wireguard_public_key=//p')"
    if [ -z "$nom_serveur" ] || [ -z "$wg_pub" ]; then
        echo "    identité de négociation illisible :" >&2
        printf '%s\n' "$identite" >&2
        return 1
    fi
    echo "    serveur $nom_serveur"

    # La première leaf naît avant tout registre Astra. Le premier passage
    # transporte donc seulement la demande publique vers le poste opérateur et
    # s'arrête ; la reprise reçoit la leaf signée et peut alors amorcer les deux
    # moitiés du domaine. Aucun endpoint en ligne n'est inventé pour franchir
    # une frontière qui n'existe pas encore.
    registre_gateway="$(helios_ssh_sudo_capture "$CIBLE" \
        "if test -f /var/lib/helios/certificates.json; then echo present; else echo absent; fi" \
        | tr -d '\r' | tail -1)"
    if [ "$registre_gateway" = "absent" ] && [ ! -f "$CERTIFICAT_AMORCAGE" ]; then
        demande_gateway="$(dirname "$RELAIS")/gateway-bootstrap-request.json"
        mkdir -p "$(dirname "$demande_gateway")"
        helios_ssh_sudo_capture "$CIBLE" \
            "cat /var/lib/helios/gateway-bootstrap-certificate-request.json" \
            > "$demande_gateway" || {
            echo "    demande d'amorçage gateway introuvable" >&2
            return 1
        }
        echo "    demande publique rapatriée : $demande_gateway"
        echo "    deux credentials distincts doivent maintenant émettre la leaf :" >&2
        echo "      astra-signer issue-gateway-bootstrap --request '$demande_gateway' \\" >&2
        echo "        --out '$CERTIFICAT_AMORCAGE'" >&2
        echo "    puis reprendre : ./scripts/deploy.sh --astra" >&2
        return 1
    fi

    # ── Sources et image, sur la cible ──────────────────────────────────────
    # `git archive` plutôt qu'un rsync : ce qui part est ce qui est commité,
    # jamais ce qui traîne dans l'arbre de travail — y compris les clés d'un
    # essai local.
    echo "    envoi des sources"
    git archive --format=tar HEAD | ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" \
        'rm -rf ~/astra-build && mkdir -p ~/astra-build && tar -x -C ~/astra-build' || {
        echo "    l'envoi des sources a échoué" >&2
        return 1
    }

    local racine
    racine="$(ssh "${HELIOS_SSH_OPTS[@]}" "$CIBLE" 'echo "$HOME"')/astra-build"

    # Le trousseau éditeur **public**, sans lequel `aether/build.rs` refuse
    # toute compilation `--release`. Il ne quitte pas le contexte de
    # construction, qui est jeté avec l'étage builder.
    if [ ! -f "$EPOQUE/publisher-keyring.json" ]; then
        echo "    trousseau éditeur public absent : $EPOQUE/publisher-keyring.json" >&2
        return 1
    fi
    scp -q "${HELIOS_SSH_OPTS[@]}" "$EPOQUE/publisher-keyring.json" \
        "$CIBLE:$racine/publisher-keyring.json" || {
        echo "    envoi du trousseau éditeur impossible" >&2
        return 1
    }
    # Le contexte de compilation est jetable : il est supprimé et recréé à
    # chaque déploiement. La tête d'audit, elle, est un témoin durable. La
    # ranger sous ce contexte la remplaçait donc par « amorcage » à chaque
    # passage ; un volume Astra déjà amorcé redémarrait ensuite en boucle parce
    # que sa vraie tête ne pouvait évidemment pas correspondre à ce marqueur.
    local env_distant="/var/lib/helios/astra-compose.env"

    # Le fichier d'environnement existe avant toute interrogation : compose
    # refuse un `--env-file` absent, et l'échec ressemblerait alors à « domaine
    # non amorcé ». La valeur de passage n'est lue que par `command:`, que
    # `run` remplace.
    helios_ssh_sudo "$CIBLE" "cd '$racine' && [ -f '$env_distant' ] || \
        { printf 'ASTRA_EXPECTED_AUDIT_HEAD=amorcage\n' > '$env_distant'; chmod 600 '$env_distant'; }"

    echo "    construction de l'image (peut prendre plusieurs minutes)"
    # La sortie n'est **pas** jetée. Une construction qui échoue sans rien dire
    # laisse l'image absente, et compose enchaîne alors sur un `pull` du nom
    # local `helios/astra` — qui n'existe dans aucun registre. Le message qu'on
    # lit est « pull access denied », qui désigne un registre alors que la
    # panne est une compilation.
    # Une compilation propre est assez longue pour croiser une reconstruction
    # du pare-feu ou une bascule de lien. Si l'unique session SSH portait aussi
    # BuildKit, sa perte annulait le contexte côté démon (`context canceled`) :
    # Cargo s'arrêtait sans erreur, exactement après « Downloading crates ».
    # Le build vit donc dans une unité transitoire distante ; les connexions
    # suivantes ne font que sonder son résultat et peuvent être recréées.
    unite_build="helios-astra-build-$SEQUENCE"
    helios_ssh_sudo "$CIBLE" "
        systemctl reset-failed '$unite_build' >/dev/null 2>&1 || true
        systemd-run --unit='$unite_build' --working-directory='$racine' \
            --setenv=COMPOSE_BAKE=0 --property=RuntimeMaxSec=30min \
            $compose -f deploy/astra/compose.yaml --env-file '$env_distant' \
            build >/dev/null
    " || {
        echo "    impossible de lancer la construction distante" >&2
        return 1
    }

    etat_build=active
    resultat_build=
    code_build=
    for tentative in $(seq 1 900); do
        if statut_astra="$(helios_ssh_sudo_capture "$CIBLE" \
            "systemctl show '$unite_build' \
                -p ActiveState -p Result -p ExecMainStatus --value")"; then
            etat_build="$(printf '%s\n' "$statut_astra" | sed -n '1p')"
            resultat_build="$(printf '%s\n' "$statut_astra" | sed -n '2p')"
            code_build="$(printf '%s\n' "$statut_astra" | sed -n '3p')"
            case "$etat_build" in
                active|activating|reloading) ;;
                *) break ;;
            esac
        fi
        if [ $((tentative % 15)) -eq 0 ]; then
            echo "      build toujours actif ($((tentative * 2)) s)"
        fi
        sleep 2
    done
    sortie="$(helios_ssh_sudo_capture "$CIBLE" \
        "journalctl -u '$unite_build' --no-pager -o cat -n 200" 2>&1 || true)"

    if [ "$etat_build" = "active" ] || [ "$etat_build" = "activating" ]; then
        echo "    la construction dépasse sa borne de 30 minutes :" >&2
        printf '%s\n' "$sortie" | tail -40 >&2
        return 1
    fi

    if [ "$resultat_build" != "success" ] || [ "$code_build" != "0" ]; then
        # `network: host` est indispensable — voir compose.yaml — mais certaines
        # versions de BuildKit l'exigent habilitée explicitement. Le
        # constructeur direct, lui, prend le drapeau sans condition. On le tente
        # avant d'abandonner : c'est la même image et le même contexte.
        case "$sortie" in
            *entitlement*|*network.host*|*"network mode"*)
                echo "    réseau hôte refusé par BuildKit, seconde tentative" >&2
                # Ce repli ne doit pas réintroduire la dépendance à une session
                # SSH longue : il est détaché pour la même raison que compose.
                unite_build="${unite_build}-direct"
                helios_ssh_sudo "$CIBLE" "
                    systemctl reset-failed '$unite_build' >/dev/null 2>&1 || true
                    systemd-run --unit='$unite_build' --working-directory='$racine' \
                        --property=RuntimeMaxSec=30min $moteur build --network=host \
                        -f deploy/astra/Dockerfile -t helios/astra:latest . >/dev/null
                " || {
                    echo "    impossible de lancer la seconde construction" >&2
                    return 1
                }
                etat_build=active
                resultat_build=
                code_build=
                for tentative in $(seq 1 900); do
                    if statut_astra="$(helios_ssh_sudo_capture "$CIBLE" \
                        "systemctl show '$unite_build' \
                            -p ActiveState -p Result -p ExecMainStatus --value")"; then
                        etat_build="$(printf '%s\n' "$statut_astra" | sed -n '1p')"
                        resultat_build="$(printf '%s\n' "$statut_astra" | sed -n '2p')"
                        code_build="$(printf '%s\n' "$statut_astra" | sed -n '3p')"
                        case "$etat_build" in
                            active|activating|reloading) ;;
                            *) break ;;
                        esac
                    fi
                    sleep 2
                done
                sortie="$(helios_ssh_sudo_capture "$CIBLE" \
                    "journalctl -u '$unite_build' --no-pager -o cat -n 200" 2>&1 || true)"
                if [ "$resultat_build" != "success" ] || [ "$code_build" != "0" ]; then
                    echo "    la construction de l'image a échoué :" >&2
                    printf '%s\n' "$sortie" | tail -40 >&2
                    return 1
                fi
                ;;
            *)
                echo "    la construction de l'image a échoué :" >&2
                printf '%s\n' "$sortie" | tail -40 >&2
                case "$sortie" in
                    *"Temporary failure resolving"*)
                        echo "    le conteneur de construction n'a pas de DNS : vérifier que" >&2
                        echo "    'network: host' est bien dans deploy/astra/compose.yaml —" >&2
                        echo "    le pare-feu jette le forward du pont Docker, par conception." >&2
                        ;;
                    *buildx*|*[Bb]ake*)
                        echo "    le constructeur embarqué a refusé aussi ; installer buildx :" >&2
                        echo "      ssh $CIBLE 'sudo apt-get install -y docker-buildx'" >&2
                        ;;
                esac
                return 1
                ;;
        esac
    fi

    # `build` peut rendre 0 sans rien produire. Ce que la suite exige, c'est
    # l'image ; c'est donc l'image qu'on vérifie, pas le code de retour.
    if ! helios_ssh_sudo "$CIBLE" \
        "$moteur image inspect helios/astra:latest >/dev/null 2>&1"; then
        echo "    l'image helios/astra:latest est absente après construction :" >&2
        printf '%s\n' "$sortie" | tail -40 >&2
        return 1
    fi

    # Le service tourne-t-il déjà ? La question précède l'interrogation, et
    # elle n'est pas une optimisation.
    #
    # `compose run` crée un **second** conteneur du service, donc attaché aux
    # mêmes réseaux — et `astra-private` épingle `ipv4_address: 10.88.7.2`. Si
    # le service tourne, cette adresse est prise, et Docker répond « failed to
    # set up container networking: Address already in use ». C'est-à-dire que
    # `run` échoue systématiquement dans le seul cas où le registre existe
    # vraiment. Un déploiement réel s'est arrêté là en accusant un registre
    # illisible alors que rien n'avait été lu.
    #
    # Un conteneur **arrêté** garde sa réservation jusqu'à sa suppression, donc
    # le cas se produit aussi service éteint. Trois manières de lire, une par
    # situation, et chacune est la seule qui marche dans la sienne :
    #
    #   en marche      → `exec`, qui n'alloue rien ;
    #   présent, arrêté → un conteneur jetable **sans réseau du tout**, monté
    #                     directement sur le volume ;
    #   absent          → `compose run`, sans concurrent possible.
    conteneur_astra="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
        $compose_env $compose -f deploy/astra/compose.yaml --env-file '$env_distant' \
        ps -aq astra 2>/dev/null" | tr -d '\r' | tail -1)"
    astra_en_marche=non
    if [ -n "$conteneur_astra" ] && helios_ssh_sudo "$CIBLE" \
        "$moteur inspect -f '{{.State.Running}}' '$conteneur_astra' 2>/dev/null | grep -qx true"
    then
        astra_en_marche=oui
    fi

    compose_astra="$compose_env $compose -f deploy/astra/compose.yaml \
        --env-file '$env_distant'"
    # Le contrôle de reprise doit exécuter le binaire de l'image fraîche sans
    # toucher au réseau Compose. `docker compose run --network none` n'est pas
    # disponible avec toutes les versions de Compose et son échec était
    # auparavant masqué par le message générique de fork. Récupérer le volume
    # même lorsque le conteneur tourne permet ensuite un `docker run` direct,
    # sans adresse statique ni conflit avec le veth Astra.
    if [ -z "${volume_astra:-}" ] && [ -n "$conteneur_astra" ]; then
        volume_astra="$(helios_ssh_sudo_capture "$CIBLE" "$moteur inspect \
            -f '{{range .Mounts}}{{if eq .Destination \"/var/lib/astra\"}}{{.Name}}{{end}}{{end}}' \
            '$conteneur_astra' 2>/dev/null" | tr -d '\r' | tail -1)"
    fi

    # Le conteneur en marche porte encore la **release précédente** : l'image
    # fraîche ne devient la sienne qu'au `up -d` final. Or l'amorçage ci-dessous
    # écrit dans le registre avec des sous-verbes que la version en place peut
    # ne pas connaître — c'est exactement ce qui a échoué le 2 septembre 2026,
    # sur `pin-ca-tls` : `exec` a atteint le binaire d'août, qui a répondu
    # « unrecognized subcommand » alors que la commande existait dans l'image
    # qu'on venait de construire.
    #
    # L'arrêter ici plutôt que de lancer l'image fraîche à côté : `pin-ca-tls`
    # **écrit**, et deux processus sur `/var/lib/astra` sont une corruption de
    # registre, pas une lecture concurrente. Une fois arrêté, la sélection
    # ci-dessous retombe d'elle-même sur le conteneur jetable monté sur le
    # volume — la branche prévue pour « présent, arrêté ». Le service remonte au
    # `up -d` final, avec la nouvelle image et un registre déjà amorcé, donc
    # sans jamais servir un domaine à moitié écrit.
    if [ "$astra_en_marche" = oui ] && [ -n "${volume_astra:-}" ]; then
        echo "    arrêt d'Astra pendant l'amorçage (l'image fraîche écrit sur le volume)"
        helios_ssh_sudo "$CIBLE" "cd '$racine' && $compose_env $compose \
            -f deploy/astra/compose.yaml --env-file '$env_distant' \
            stop astra" >/dev/null || {
            echo "    Astra n'a pas pu être arrêté : l'amorçage écrirait sur un" >&2
            echo "    volume que le service utilise encore." >&2
            return 1
        }
        astra_en_marche=non
    fi
    # A compatibility check must use the freshly built image. The running
    # container can still be the previous release until the final `up -d`, so
    # `exec` would not know about the status-tail migration below. A direct
    # runtime invocation with `--network none` keeps this disposable read from
    # competing for Astra's static veth address.
    if [ -n "${volume_astra:-}" ]; then
        astra_lire_frais="$moteur run --rm --network none \
            -v '$volume_astra':/var/lib/astra helios/astra:latest"
    else
        # No existing container means no reserved static address; Compose is
        # safe for the initial read and is retained for that one case.
        astra_lire_frais="$compose_astra run --rm --no-deps -T astra"
    fi
    if [ "$astra_en_marche" = oui ]; then
        # Le chemin absolu, et pas le sous-verbe seul : `exec` n'applique pas
        # l'`ENTRYPOINT` de l'image, il exécute l'argv tel quel. « status » y
        # est un nom de programme, que le runtime cherche dans le PATH et ne
        # trouve évidemment pas. `run` et le conteneur jetable, eux, passent
        # bien par l'entrypoint — d'où trois formes et non une.
        astra_lire="$compose_astra exec -T astra $ASTRA_BIN"
        astra_lire_shell="$compose_astra exec -T astra /bin/sh -c"
    elif [ -n "$conteneur_astra" ]; then
        # Le volume se lit sans passer par le service. `--network none` est ce
        # qui rend la lecture toujours possible : aucune adresse n'est demandée,
        # donc aucune ne peut être prise. Le nom du volume est lu sur le
        # conteneur lui-même plutôt que deviné depuis le nom de projet compose,
        # qui dépend du répertoire de travail.
        volume_astra="$(helios_ssh_sudo_capture "$CIBLE" "$moteur inspect \
            -f '{{range .Mounts}}{{if eq .Destination \"/var/lib/astra\"}}{{.Name}}{{end}}{{end}}' \
            '$conteneur_astra' 2>/dev/null" | tr -d '\r' | tail -1)"
        if [ -z "$volume_astra" ]; then
            echo "    le conteneur Astra existant ne monte aucun volume sur /var/lib/astra." >&2
            echo "    Rien n'est su de son état, donc rien n'est amorcé." >&2
            return 1
        fi
        astra_lire="$moteur run --rm -i --network none \
            -v '$volume_astra':/var/lib/astra helios/astra:latest"
        astra_lire_shell="$moteur run --rm -i --network none \
            -v '$volume_astra':/var/lib/astra --entrypoint /bin/sh helios/astra:latest -c"
    else
        astra_lire="$compose_astra run --rm --no-deps -T astra"
        astra_lire_shell="$compose_astra run --rm --no-deps -T --entrypoint /bin/sh astra -c"
    fi

    # Ce que le runtime refuse n'est pas ce qu'Astra refuse.
    #
    # Une sortie qui vient du démon — conteneur arrêté, exécutable introuvable,
    # réseau impossible — dit qu'`astra status` n'a **jamais tourné**. En tirer
    # une conclusion sur le registre revient à lui imputer une panne que
    # personne n'a observée, et c'est exactement ce qu'un déploiement réel a
    # affiché deux fois de suite pour deux causes différentes.
    astra_sonde_muette() {
        echo "    impossible d'interroger le volume Astra : la sonde n'a pas répondu." >&2
        echo "    Rien n'est su du registre, donc rien n'est amorcé." >&2
        [ -z "${1:-}" ] || echo "    Réponse de la sonde : $1" >&2
        printf '%s\n' "$statut_astra" | tail -20 >&2
        case "$statut_astra" in
            *"Address already in use"*|*"address already in use"*)
                echo "    L'adresse 10.88.7.2 du veth privé est déjà prise. Un conteneur" >&2
                echo "    Astra antérieur la retient — même arrêté, sa réservation tient" >&2
                echo "    jusqu'à sa suppression :" >&2
                echo "      ssh $CIBLE 'sudo $moteur ps -a --filter name=astra'" >&2
                echo "      ssh $CIBLE 'sudo $moteur rm <id>'" >&2
                ;;
            *"executable file not found"*)
                echo "    Le runtime n'a pas trouvé le programme à lancer : c'est l'appel qui" >&2
                echo "    est fautif, pas le volume. $ASTRA_BIN est le chemin attendu." >&2
                ;;
        esac
    }

    # Trois états, pas deux. `status` échoue aussi bien parce qu'il n'y a rien
    # à lire que parce que ce qu'il y a est illisible, et confondre les deux
    # est ce qui a mené un déploiement réel à enchaîner sur un `bootstrap` que
    # le registre existant refusait — en n'affichant que ce refus, jamais la
    # cause. On regarde donc le volume avant de conclure.
    statut_astra="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
        $astra_lire status 2>&1")" && etat=amorce || etat=inconnu
    if [ "$etat" = "inconnu" ]; then
        case "$statut_astra" in
            *"OCI runtime"*|*"executable file not found"*|*"Error response from daemon"*|\
            *"failed to set up container networking"*|*"is not running"*|*"No such container"*)
                astra_sonde_muette
                return 1
                ;;
        esac
        registre_present="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
            $astra_lire_shell \
            'test -f /var/lib/astra/registry.json && echo present || echo absent' 2>/dev/null" \
            | tr -d '\r' | tail -1)"
        case "$registre_present" in
            absent) etat=vierge ;;
            present)
                # Astra a bien tourné, a bien lu, et a refusé. C'est la seule
                # combinaison où le registre est en cause. Amorcer par-dessus
                # démarrerait une seconde histoire pour le même domaine, et le
                # binaire le refuse — mais c'est ici qu'il faut s'arrêter, en
                # montrant l'erreur réelle plutôt que celle du refus.
                echo "    Astra a un registre et ne peut pas le lire :" >&2
                printf '%s\n' "$statut_astra" | tail -20 >&2
                echo "    ne pas amorcer par-dessus : ce volume porte déjà une clé de service," >&2
                echo "    une chaîne d'audit et un domaine. Sauvegarder /var/lib/astra avant" >&2
                echo "    toute autre action." >&2
                return 1
                ;;
            *)
                # Quatrième cas, et il ne se confond avec aucun des trois : la
                # sonde du volume n'a pas répondu non plus. Le ranger avec
                # « registre illisible » accuserait le registre ; le ranger avec
                # « vierge » enchaînerait sur un amorçage par-dessus une autorité
                # existante — la seule erreur irrattrapable ici.
                astra_sonde_muette "${registre_present:-<vide>}"
                return 1
                ;;
        esac
    fi

    if [ "$etat" = "vierge" ]; then
        echo "    amorçage du domaine"
        # Le **même** accès que la sonde, pour la même raison : un conteneur
        # arrêté qui retient 10.88.7.2 ferait échouer un `compose run` ici aussi,
        # et l'amorçage est l'étape où un échec obscur coûte le plus cher.
        sortie="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
            $astra_lire bootstrap \
            --ca-public-key '$ancre' --trust-domain-id '$domaine' \
            --gateway-wireguard-public-key '$wg_pub' --server-name '$nom_serveur' \
            --authority-url '$url' --webauthn-rp-id '$rp' \
            ${empreinte_ca_tls:+--ca-tls-fingerprint '$empreinte_ca_tls'}")" || {
            echo "    l'amorçage d'Astra a échoué :" >&2
            printf '%s\n' "$sortie" >&2
            return 1
        }
        cle_service="$(printf '%s\n' "$sortie" | sed -n 's/^service key *: *//p' | head -1)"
        tete_audit="$(printf '%s\n' "$sortie" | sed -n 's/^audit head *: *//p' | head -1)"
        if [ -z "$cle_service" ] || [ -z "$tete_audit" ]; then
            echo "    sortie d'amorçage illisible :" >&2
            printf '%s\n' "$sortie" >&2
            return 1
        fi
        echo "    tête d'audit $tete_audit"

        # Reportée des deux côtés : sans elle, une restauration qui a forké est
        # reprise en silence.
        helios_ssh_sudo "$CIBLE" \
            "printf 'ASTRA_EXPECTED_AUDIT_HEAD=%s\n' '$tete_audit' > '$env_distant'
             chmod 600 '$env_distant'" || {
            echo "    la tête d'audit n'a pas pu être écrite sur la cible :" >&2
            echo "    $tete_audit" >&2
            return 1
        }
        mkdir -p "$(dirname "$RELAIS")"
        printf '%s\n' "$tete_audit" > "$(dirname "$RELAIS")/audit-head"
    else
        # Un déploiement interrompu peut avoir amorcé le volume avant d'avoir
        # écrit le témoin compose ou le registre Helios. `status` rend les deux
        # valeurs publiques nécessaires pour reprendre, sans recréer de clé ni
        # de chaîne.
        cle_service="$(printf '%s\n' "$statut_astra" |
            sed -n 's/^service key[[:space:]]*:[[:space:]]*//p' | head -1)"
        tete_audit="$(printf '%s\n' "$statut_astra" |
            sed -n 's/^audit head[[:space:]]*:[[:space:]]*//p' | head -1)"
        if [ -z "$cle_service" ] || [ -z "$tete_audit" ]; then
            echo "    état Astra illisible :" >&2
            printf '%s\n' "$statut_astra" >&2
            return 1
        fi

        tete_attendue="$(sed -n '1p' "$(dirname "$RELAIS")/audit-head" 2>/dev/null || true)"
        if [ -z "$tete_attendue" ]; then
            echo "    Astra est amorcé mais le témoin d'audit opérateur est absent :" >&2
            echo "      $(dirname "$RELAIS")/audit-head" >&2
            echo "    tête présentée par Astra : $tete_audit" >&2
            echo "    confirmer ce point de reprise hors bande avant de le réenregistrer" >&2
            return 1
        fi
        if [ "$tete_attendue" != "$tete_audit" ]; then
            # Releases before the status-read fix appended `StatusPublished`
            # for every telemetry query. Ask the freshly built image whether
            # the old witness is followed only by that harmless legacy suffix.
            # A renewal, admission, issuer or revocation after the witness
            # remains a hard fork and is never adopted automatically.
            # Conserver la sortie même en cas d'échec : elle nomme l'option
            # de runtime ou le volume qui empêcherait la sonde de s'exécuter,
            # au lieu de transformer cette panne en faux « fork » silencieux.
            statut_tete_ancienne="$(helios_ssh_sudo_capture "$CIBLE" \
                "cd '$racine' && $astra_lire_frais status \
                    --expected-audit-head '$tete_attendue' 2>&1")" || true
            tete_ancienne="$(printf '%s\n' "$statut_tete_ancienne" |
                sed -n 's/^audit head[[:space:]]*:[[:space:]]*//p' | head -1)"
            if [ "$tete_ancienne" != "$tete_audit" ]; then
                echo "    refus de reprendre une histoire Astra différente du témoin opérateur" >&2
                echo "    attendue : $tete_attendue" >&2
                echo "    présente : $tete_audit" >&2
                if [ -n "$statut_tete_ancienne" ] && [ -z "$tete_ancienne" ]; then
                    echo "    sonde de compatibilité Astra :" >&2
                fi
                [ -z "$statut_tete_ancienne" ] ||
                    printf '%s\n' "$statut_tete_ancienne" | tail -20 >&2
                return 1
            fi
            echo "    témoin avancé : l'écart ne contient que d'anciennes publications de statut"
            mkdir -p "$(dirname "$RELAIS")"
            printf '%s\n' "$tete_audit" > "$(dirname "$RELAIS")/audit-head"
        fi
        # Un domaine amorcé avant que cette ancre soit épinglée — ou avant que
        # ce script la calcule — n'en retient que l'époque. `pin-ca-tls`
        # l'enregistre une fois et refuse d'en remplacer une : il est donc
        # idempotent, et une seconde exécution ne dit rien de plus que « rien
        # n'a changé ».
        #
        # Un refus, lui, n'est pas un détail d'exploitation : il signifie que
        # le relais de l'opérateur et le registre d'Astra ne nomment pas la
        # même CA TLS cliente. Deux moitiés du domaine qui se contredisent
        # s'arrêtent, exactement comme pour la tête d'audit — et c'est bien
        # **après** le contrôle du témoin que l'épinglage a lieu, pour ne
        # jamais prolonger une histoire dont le fork n'a pas encore été écarté.
        #
        # L'épinglage ajoute `ClientTlsCaPinned` à la chaîne : la tête bouge, et
        # les deux témoins qui la portent — le `.env` de compose et le fichier
        # opérateur — sont donc réécrits ensuite, jamais avant. Les figer avant
        # ferait refuser `astra run --expected-audit-head` au démarrage suivant.
        if [ -n "$empreinte_ca_tls" ]; then
            sortie="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
                $astra_lire pin-ca-tls --fingerprint '$empreinte_ca_tls' 2>&1")" || {
                echo "    l'ancre CA-TLS du relais n'a pas pu être épinglée :" >&2
                echo "    attendue : $empreinte_ca_tls" >&2
                printf '%s\n' "$sortie" | tail -10 >&2
                return 1
            }
            statut_astra="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
                $astra_lire status 2>&1")" || {
                echo "    état Astra illisible après l'épinglage de l'ancre CA-TLS :" >&2
                printf '%s\n' "$statut_astra" | tail -10 >&2
                return 1
            }
            tete_audit="$(printf '%s\n' "$statut_astra" |
                sed -n 's/^audit head[[:space:]]*:[[:space:]]*//p' | head -1)"
            if [ -z "$tete_audit" ]; then
                echo "    tête d'audit illisible après l'épinglage de l'ancre CA-TLS :" >&2
                printf '%s\n' "$statut_astra" | tail -10 >&2
                return 1
            fi
            mkdir -p "$(dirname "$RELAIS")"
            printf '%s\n' "$tete_audit" > "$(dirname "$RELAIS")/audit-head"
        fi

        helios_ssh_sudo "$CIBLE" \
            "printf 'ASTRA_EXPECTED_AUDIT_HEAD=%s\n' '$tete_audit' > '$env_distant'
             chmod 600 '$env_distant'" || {
            echo "    impossible de restaurer le témoin compose Astra" >&2
            return 1
        }
    fi

    # ── L'autre moitié du domaine, sur la gateway ───────────────────────────
    # Elle peut manquer alors que le volume Astra existe déjà : une coupure
    # entre les deux amorçages ne doit ni fabriquer une seconde autorité, ni
    # laisser les routes de cycle de vie fermées pour toujours.
    if [ "$registre_gateway" = "absent" ]; then
        echo "    amorçage du registre gateway"
        certificat_distant="$(ssh "$CIBLE" 'printf %s "$HOME"')/gateway-bootstrap-certificate.json"
        scp -q "$CERTIFICAT_AMORCAGE" "$CIBLE:$certificat_distant" || {
            echo "    transfert de la leaf gateway impossible" >&2
            return 1
        }
        # L'ancre TLS **du domaine**, et non la CA opérateur qui admet les
        # clients. Sans elle, le registre retient l'autorité d'admission à la
        # place de l'ancre du domaine : plus aucun renouvellement ne se stage,
        # et une rotation du §9.4 ne le répare pas — elle ne sait que quitter
        # une ancre déjà détenue. Le DER est celui que le relais porte déjà et
        # dont l'empreinte a été épinglée dans Astra plus haut.
        arg_ca_tls=""
        if [ -n "$ca_tls_der" ]; then
            ca_tls_distant="$(ssh "$CIBLE" 'printf %s "$HOME"')/domain-client-ca-tls.der"
            printf '%s' "$ca_tls_der" | base64 -d |
                ssh "$CIBLE" "cat > '$ca_tls_distant'" || {
                echo "    transfert de la CA-TLS du domaine impossible" >&2
                return 1
            }
            arg_ca_tls="--client-tls-ca '$ca_tls_distant'"
        else
            echo "    relais sans ca_tls_certificate : le registre gateway va retenir la CA" >&2
            echo "    opérateur comme ancre du domaine, et aucun renouvellement ne pourra" >&2
            echo "    se stager. Émettre la CA-TLS par astra-signer issue-ca-tls." >&2
        fi
        helios_ssh_sudo "$CIBLE" "$HELIOSD init-trust-domain \
            --trust-domain-id '$domaine' --ca-public-key '$ancre' \
            --gateway-certificate '$certificat_distant' \
            --astra-service-public-key '$cle_service' \
            --authority-url '$url' --webauthn-rp-id '$rp' $arg_ca_tls" || {
            echo "    le registre gateway n'a pas été amorcé — Astra tourne, la" >&2
            echo "    gateway ignore encore le domaine. Ses routes de cycle de" >&2
            echo "    vie in-tunnel restent fermées." >&2
            return 1
        }
        ssh "$CIBLE" "rm -f '$certificat_distant' '$ca_tls_distant'"
        helios_ssh_sudo "$CIBLE" "systemd-run --collect --unit=helios-trust-restart \
            systemctl restart heliosd >/dev/null"
    elif [ -n "$ca_tls_der" ]; then
        # Les versions antérieures à `init-trust-domain --client-tls-ca`
        # pouvaient avoir amorcé le registre avec la CA opérateur. Corriger ce
        # cas en place évite de supprimer le registre et de réadmettre tous les
        # pairs. La commande refuse tout état qui a déjà quitté la génération
        # initiale ; elle n'est donc ni une rotation non signée, ni un chemin
        # de récupération général.
        echo "    vérification de l'ancre CA-TLS du registre gateway"
        ca_tls_distant="$(ssh "$CIBLE" 'printf %s "$HOME"')/domain-client-ca-tls.der"
        printf '%s' "$ca_tls_der" | base64 -d |
            ssh "$CIBLE" "cat > '$ca_tls_distant'" || {
            echo "    transfert de la CA-TLS du domaine impossible" >&2
            return 1
        }
        if ! sortie_reparation="$(helios_ssh_sudo_capture "$CIBLE" "
            set -e
            redemarrer_heliosd() { systemctl start heliosd; }
            trap redemarrer_heliosd EXIT HUP INT TERM
            systemctl stop heliosd
            '$HELIOSD' repair-client-tls-ca-bootstrap \
                --client-tls-ca '$ca_tls_distant'
            systemctl start heliosd
            trap - EXIT HUP INT TERM
        ")"; then
            ssh "$CIBLE" "rm -f '$ca_tls_distant'"
            echo "    réparation de l'ancre CA-TLS refusée ; heliosd a été redémarré" >&2
            printf '%s\n' "$sortie_reparation" >&2
            return 1
        fi
        printf '%s\n' "$sortie_reparation"
        ssh "$CIBLE" "rm -f '$ca_tls_distant'"
    fi

    # ── Le canal privé Astra ↔ Helios (ROTATION-CERTIFICATS §8.3) ───────────
    # Deux identités de transport, une de chaque côté du veth, épinglées l'une
    # par l'autre. Aucune n'est recopiée à la main : chaque `init` imprime son
    # certificat et le script le porte à l'autre bout. Les deux commandes sont
    # idempotentes, donc une reprise après coupure finit ce qu'une première a
    # commencé.
    #
    # Non fatal : sans ce canal, Astra sert son endpoint public et la gateway
    # garde ses routes in-tunnel. C'est exactement l'état d'avant ce lot.
    canal_present="$(helios_ssh_sudo_capture "$CIBLE" \
        "if test -f /var/lib/helios/astra-channel.json; then echo present; else echo absent; fi" \
        | tr -d '\r' | tail -1)"
    # Encore le même accès : `init-channel` écrit dans le même volume, et un
    # `compose run` y buterait sur la même adresse retenue.
    if sortie="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
        $astra_lire init-channel 2>&1")"; then
        cert_astra="$(printf '%s\n' "$sortie" |
            sed -n 's/^astra_channel_certificate=//p' | tr -d '\r' | head -1)"
        cert_autorite="$(printf '%s\n' "$sortie" |
            sed -n 's/^astra_authority_certificate=//p' | tr -d '\r' | head -1)"
    fi
    if [ -z "${cert_astra:-}" ]; then
        echo "    identité de transport Astra illisible — canal privé non monté" >&2
        printf '%s\n' "${sortie:-}" | tail -10 >&2
    else
        # Le DER traverse en base64 puis est décodé sur la cible : `heliosd`
        # attend un fichier DER, et faire transiter du binaire par SSH est le
        # genre de détail qui casse une fois sur dix sans dire pourquoi.
        # Les deux certificats d'Astra traversent en base64 puis sont décodés
        # sur la cible : `heliosd` attend des fichiers DER, et faire transiter
        # du binaire par SSH est le genre de détail qui casse une fois sur dix
        # sans dire pourquoi. Le second n'est passé que s'il existe — un Astra
        # antérieur à ce lot n'en imprime pas, et la moitié « relais » reste
        # alors fermée sans que la moitié « staging » en souffre.
        sortie="$(helios_ssh_sudo_capture "$CIBLE" \
            "umask 077 && printf '%s' '$cert_astra' | base64 -d > /run/astra-channel.der && \
             printf '%s' '${cert_autorite:-}' | base64 -d > /run/astra-authority.der 2>/dev/null; \
             if test -s /run/astra-authority.der; then \
                 $HELIOSD init-astra-channel --bind '$CANAL_PRIVE' \
                     --astra-certificate /run/astra-channel.der \
                     --authority '$CANAL_AUTORITE' \
                     --astra-authority-certificate /run/astra-authority.der 2>&1; \
             else \
                 $HELIOSD init-astra-channel --bind '$CANAL_PRIVE' \
                     --astra-certificate /run/astra-channel.der 2>&1; \
             fi; \
             code=\$?; rm -f /run/astra-channel.der /run/astra-authority.der; exit \$code")" && \
            cert_gateway="$(printf '%s\n' "$sortie" |
                sed -n 's/^gateway_channel_certificate=//p' | tr -d '\r' | head -1)" && \
            cert_client="$(printf '%s\n' "$sortie" |
                sed -n 's/^gateway_client_certificate=//p' | tr -d '\r' | head -1)"
        if [ -z "${cert_gateway:-}" ]; then
            echo "    la gateway n'a pas pu monter son bout du canal privé :" >&2
            printf '%s\n' "$sortie" | tail -10 >&2
        else
            helios_ssh_sudo "$CIBLE" \
                "printf 'ASTRA_GATEWAY_CHANNEL=%s\nASTRA_GATEWAY_CERTIFICATE=%s\n' \
                     '$CANAL_PRIVE' '$cert_gateway' >> '$env_distant'" || {
                echo "    le canal privé n'a pas pu être écrit dans l'environnement" >&2
                return 1
            }
            echo "    canal privé $CANAL_PRIVE"
            # La direction opposée, seulement si les deux bouts l'ont produite.
            # Sans elle Astra ne sert pas son listener et la gateway répond 503
            # sur ses quatre routes de renouvellement : un état supporté, et
            # celui de toute installation antérieure à ce lot.
            if [ -n "${cert_client:-}" ]; then
                helios_ssh_sudo "$CIBLE" \
                    "printf 'ASTRA_PRIVATE_BIND=%s\nASTRA_GATEWAY_CLIENT_CERTIFICATE=%s\n' \
                         '$CANAL_AUTORITE' '$cert_client' >> '$env_distant'" || {
                    echo "    le relais de renouvellement n'a pas pu être écrit" >&2
                    return 1
                }
                echo "    relais de renouvellement $CANAL_AUTORITE"
            else
                echo "    relais de renouvellement non monté : la gateway répondra 503"
            fi
            # `heliosd` lit ce document au démarrage et le sert jusqu'à l'arrêt,
            # comme l'identité de négociation : un document neuf sous un démon
            # en marche ne change rien tant qu'il n'a pas redémarré.
            if [ "$canal_present" = "absent" ]; then
                helios_ssh_sudo "$CIBLE" "systemd-run --collect \
                    --unit=helios-channel-restart systemctl restart heliosd >/dev/null"
            fi
        fi
    fi

    # ── Le document de credentials opérateur ────────────────────────────────
    # Sans lui, Astra n'a aucune liste d'autorisation : la demande d'approbation
    # d'un renouvellement ordinaire n'a plus de credential à proposer, et chaque
    # rotation est refusée en le disant. Il est signé par `CA-PQ` et ne porte
    # rien de secret — c'est le consommateur qui le vérifie sous son ancre, pas
    # ce script, pas la gateway et pas Astra.
    #
    # Il vit à côté du coffre, sur le poste opérateur, et `astra-signer` le
    # réémet à chaque geste qui déplace la table de key-slots. Le recopier ici
    # est donc idempotent, et l'oublier est la panne qu'on ne comprend qu'au
    # premier renouvellement.
    #
    # En base64, pour la même raison que les deux certificats plus haut :
    # `helios_ssh_sudo` compose lui-même l'entrée standard de la session, donc
    # rien ne peut y être redirigé.
    credentials_local="$(dirname "$RELAIS")/astra-credentials.json"
    if [ -f "$credentials_local" ]; then
        credentials_b64="$(base64 -w0 < "$credentials_local")"
        if helios_ssh_sudo "$CIBLE" "cd '$racine' && \
            printf '%s' '$credentials_b64' | base64 -d | \
            $astra_lire_shell 'cat > /var/lib/astra/.credentials.tmp && \
                mv /var/lib/astra/.credentials.tmp /var/lib/astra/astra-credentials.json'"; then
            echo "    credentials opérateur copiés"
            # Le document est lu **au démarrage**. Copié dans un conteneur qui
            # tourne déjà, il ne prendrait effet qu'au prochain redémarrage —
            # et `up -d` ne recrée pas un service dont rien n'a changé. Le
            # redémarrage est donc explicite, et seulement dans ce cas.
            if [ "$astra_en_marche" = oui ]; then
                helios_ssh_sudo "$CIBLE" "cd '$racine' && \
                    $compose_astra restart astra" >/dev/null || {
                    echo "    Astra n'a pas redémarré : il sert encore la liste" >&2
                    echo "    d'autorisation précédente." >&2
                }
            fi
            # Le même document, dans le registre de la gateway. Astra s'en
            # sert pour proposer un credential à une approbation ; la gateway
            # s'en sert pour le **distribuer** — le bloc d'enrôlement du §19
            # est la seule chose qu'un client lit avant d'avoir un tunnel, et
            # récupérer une identité expirée commence par nommer le credential
            # qui l'approuvera. Un client qui devrait aller chercher la liste
            # devrait le faire par le lien qu'il vient justement de perdre.
            credentials_distant="$(ssh "$CIBLE" 'printf %s "$HOME"')/astra-credentials.json"
            if printf '%s' "$credentials_b64" | base64 -d |
                ssh "$CIBLE" "cat > '$credentials_distant'"; then
                helios_ssh_sudo "$CIBLE" "$HELIOSD install-astra-credentials \
                    '$credentials_distant'" || {
                    echo "    le registre gateway n'a pas retenu les credentials :" >&2
                    echo "    les profils émis ensuite ne pourront pas récupérer une" >&2
                    echo "    identité expirée." >&2
                }
                ssh "$CIBLE" "rm -f '$credentials_distant'"
            fi
        else
            echo "    les credentials opérateur n'ont pas pu être copiés :" >&2
            echo "      $credentials_local" >&2
            echo "    Astra tournera, mais refusera tout renouvellement ordinaire." >&2
        fi
    else
        echo "    aucun document de credentials à côté du coffre :" >&2
        echo "      $credentials_local" >&2
        echo "    l'émettre par « astra-signer bindings », sinon aucun opérateur ne" >&2
        echo "    peut approuver un renouvellement." >&2
    fi

    echo "    démarrage"
    helios_ssh_sudo "$CIBLE" "cd '$racine' && \
        $compose_env $compose -f deploy/astra/compose.yaml --env-file '$env_distant' \
        up -d" >/dev/null || {
        echo "    le conteneur n'a pas démarré :" >&2
        helios_ssh_sudo "$CIBLE" "cd '$racine' && \
            $compose_env $compose -f deploy/astra/compose.yaml --env-file '$env_distant' \
            logs --tail 40 astra" >&2 || true
        return 1
    }

    terminateur_tailscale "$url"
}

if [ "$ASTRA" = "0" ]; then
    echo "==> 7/7  Astra sauté (--sans-astra)"
elif [ ! -f "$RELAIS" ]; then
    echo "==> 7/7  Astra sauté : aucun relais de domaine"
    echo "    en créer un, sur le poste où la clé de sécurité est branchée :"
    echo "      astra-signer init --rp-id <nom> --label \"YubiKey ...\""
else
    echo "==> 7/7  Astra et domaine de confiance"
    # Non fatal : la gateway est déjà installée à ce point, et l'écraser d'un
    # `set -e` masquerait ce qui a réussi derrière ce qui a échoué.
    deployer_astra || echo "    Astra non déployé — la gateway, elle, est en place" >&2
fi

# La connexion multiplexée a fait son travail ; la laisser ouverte deux minutes
# de plus n'apporte rien et garde un socket sur la gateway.
helios_ssh_close "$CIBLE"

if [ "$ASTRA_ONLY" = "1" ]; then
    cat <<EOF

──────────────────────────────────────────────────────────────
  Astra repris sur $CIBLE — gateway laissée inchangée
──────────────────────────────────────────────────────────────
EOF
else
cat <<EOF

──────────────────────────────────────────────────────────────
  Déployé : $VERSION séquence $SEQUENCE sur $CIBLE

  Network, TPM, internal PKI and the first Orion profile are managed in the
  target state directory printed above. The service is enabled and running.
──────────────────────────────────────────────────────────────
EOF
fi
