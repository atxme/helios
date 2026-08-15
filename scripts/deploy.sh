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

EPOQUE="${HELIOS_PUBLISHER_EPOCH:-$HOME/.helios/publisher-epoch-1}"
CANAL="${HELIOS_DEPLOY_CHANNEL:-production}"
INSTALLER=1
ASTRA=1
ASTRA_ONLY=0
SEQUENCE=""
# Relais public écrit par `astra-signer init` : domaine, RP ID, ancre CA-PQ.
# Rien de secret — le coffre, lui, ne quitte jamais le poste opérateur.
RELAIS="${ASTRA_HANDOFF:-$HOME/.helios/astra/astra-domain.json}"
# L'installation ne met rien dans le PATH : `heliosd` n'existe que sous ce
# chemin, et root ne le trouve pas autrement. Le nommer en clair évite un
# « command not found » là où l'on croirait lire un refus d'amorçage.
HELIOSD=/opt/helios/current/heliosd

usage() {
    cat >&2 <<'EOF'
Usage : ./scripts/deploy.sh [hôte-ssh] [options]

  --sequence N     Force la séquence de release (défaut : horodatage Unix)
  --copie-seule    Copie l'archive sans lancer l'installation privilégiée
  --canal C        testing ou production (défaut : production)
  --sans-astra     Saute le conteneur d'autorité, même si un relais existe
  --astra    Reprend uniquement l'étape Astra, sans relivrer la gateway

Astra (ADR-008) se déploie tout seul dès qu'un relais de domaine existe —
celui qu'écrit `astra-signer init` à côté du coffre. Sans relais, cette
partie est silencieusement sautée : une gateway sans autorité reste une
gateway qui marche.

L'hôte est en dur dans scripts/lib-remote.sh (HELIOS_CIBLE) : la commande
n'en prend aucun. L'argument reste accepté pour viser ponctuellement une
autre machine, sans rien changer aux appels suivants.

Variables reconnues : HELIOS_CIBLE, HELIOS_PUBLISHER_EPOCH,
HELIOS_DEPLOY_CHANNEL.
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
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml |
    sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
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
./scripts/target-bootstrap.sh "$CIBLE"
else
    echo "==> Reprise Astra seule sur $CIBLE"
fi

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
    local tete_attendue registre_gateway
    local unite_build etat_build resultat_build code_build tentative

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
            $compose -f deploy/astra/compose.yaml build >/dev/null
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

    statut_astra="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
        $compose_env $compose -f deploy/astra/compose.yaml --env-file '$env_distant' \
        run --rm --no-deps astra status 2>&1")" && etat=amorce || etat=vierge

    if [ "$etat" = "vierge" ]; then
        echo "    amorçage du domaine"
        sortie="$(helios_ssh_sudo_capture "$CIBLE" "cd '$racine' && \
            $compose_env $compose -f deploy/astra/compose.yaml --env-file '$env_distant' \
            run --rm astra bootstrap \
            --ca-public-key '$ancre' --trust-domain-id '$domaine' \
            --gateway-wireguard-public-key '$wg_pub' --server-name '$nom_serveur' \
            --authority-url '$url' --webauthn-rp-id '$rp'")" || {
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
            echo "    refus de reprendre une histoire Astra différente du témoin opérateur" >&2
            echo "    attendue : $tete_attendue" >&2
            echo "    présente : $tete_audit" >&2
            return 1
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
    registre_gateway="$(helios_ssh_sudo_capture "$CIBLE" \
        "if test -f /var/lib/helios/certificates.json; then echo present; else echo absent; fi" \
        | tr -d '\r' | tail -1)"
    if [ "$registre_gateway" = "absent" ]; then
        echo "    amorçage du registre gateway"
        helios_ssh_sudo "$CIBLE" "$HELIOSD init-trust-domain \
            --trust-domain-id '$domaine' --ca-public-key '$ancre' \
            --astra-service-public-key '$cle_service' \
            --authority-url '$url' --webauthn-rp-id '$rp'" || {
            echo "    le registre gateway n'a pas été amorcé — Astra tourne, la" >&2
            echo "    gateway ignore encore le domaine. Ses routes de cycle de" >&2
            echo "    vie in-tunnel restent fermées." >&2
            return 1
        }
        helios_ssh_sudo "$CIBLE" "systemd-run --collect --unit=helios-trust-restart \
            systemctl restart heliosd >/dev/null"
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
