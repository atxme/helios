# Exécution privilégiée sur la gateway, sans redemander le mot de passe.
#
# À sourcer, jamais à lancer.
#
# # Pourquoi ce n'est pas juste `ssh -t … sudo`
#
# `sudo` retient son ticket **par terminal**, et chaque `ssh -t` alloue un
# nouveau pseudo-terminal. Un déploiement qui enchaîne quatre connexions
# privilégiées demande donc quatre fois le mot de passe — et comme les scripts
# sont enchaînés, l'opérateur ne sait même pas combien il en reste.
#
# `helios_ssh_sudo` le demande une fois, puis le passe à `sudo -S` par l'entrée
# standard. Jamais par la ligne de commande : `ps` la montrerait à tout le monde
# sur la gateway.
#
# # Appeler `helios_sudo_init` tôt, et depuis le shell principal
#
# `helios_ssh_sudo` est souvent utilisé dans un pipeline (`| tee …`), et un
# pipeline s'exécute en sous-shell : une invite déclenchée là y capturerait le
# mot de passe, qui disparaîtrait avec le sous-shell — et reviendrait au coup
# suivant. Chaque script appelle donc `helios_sudo_init` une fois, au début,
# hors de tout pipeline.
#
# # Limite connue
#
# Le mot de passe est **exporté**, pour que les scripts enchaînés
# (`target-bootstrap.sh`, `key-negotiation-setup.sh`) n'aient pas à le
# redemander. Il est donc lisible dans `/proc/<pid>/environ` des processus
# fils, sur le poste de l'opérateur. C'est la machine qui détient déjà les clés
# éditeur et la CA opérateur ; le compromis est assumé, et rien ne l'écrit sur
# disque.

# ── La gateway visée, en dur ─────────────────────────────────────────────────
#
# Un seul endroit pour l'adresse : la changer ici la change pour `deploy.sh`,
# `key-negotiation-setup.sh` et `provision-client.sh`. Elle est écrite dans le
# dépôt plutôt que retenue d'un appel précédent, et c'est délibéré — la version
# précédente la mémorisait sous `~/.helios/*.conf`, ce qui répondait à
# « pourquoi ça déploie sur la mauvaise machine » par un fichier caché que
# personne ne pense à ouvrir. Ici, `grep` la trouve.
#
# `HELIOS_CIBLE` dans l'environnement l'emporte, et chaque script accepte
# toujours un hôte en argument pour un déploiement ponctuel ailleurs — sans
# rien enregistrer : l'appel suivant repart de la valeur ci-dessous.
# Tailscale, pas le LAN : l'opérateur n'est pas sur le réseau de la gateway et
# n'y sera plus. Une adresse LAN par défaut envoie chaque script vers un réseau
# injoignable, et le message d'erreur — « No route to host » — ressemble à une
# gateway en panne plutôt qu'à un défaut de configuration.
#
# Cette adresse est dans `100.64.0.0/10`, que le profil Orion capture vers le
# tunnel : tunnel monté, un déploiement lancé ainsi passerait *par Helios* et se
# couperait au redémarrage du démon. `target-bootstrap.sh` interroge le noyau et
# refuse ce cas — voir docs/testing/PREMIER-DEPLOIEMENT.md.
HELIOS_CIBLE="${HELIOS_CIBLE:-christophe@100.72.220.76}"

# Multiplexage : une seule connexion TCP réutilisée par tous les appels. Ça ne
# change rien au ticket sudo — c'est le pseudo-terminal qui le porte — mais ça
# supprime une poignée de main SSH par commande, et elles sont nombreuses.
HELIOS_SSH_CONTROL="${TMPDIR:-/tmp}/helios-ssh-%r@%h:%p"
HELIOS_SSH_OPTS=(
    -o ControlMaster=auto
    -o "ControlPath=$HELIOS_SSH_CONTROL"
    -o ControlPersist=120
    # Une gateway dont on redémarre le pare-feu peut avaler la connexion sans
    # jamais la fermer. Sans ces deux options, le script attend indéfiniment ;
    # avec, il échoue au bout d'une minute en le disant.
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=4
    # Le redémarrage de `heliosd` reconstruit le pare-feu sous la connexion :
    # une tentative qui tombe dans le vide doit échouer vite, pas au bout d'une
    # minute — le sondage d'état en enchaîne trente.
    -o ConnectTimeout=10
)

# Demande le mot de passe une fois, si ce n'est pas déjà fait.
#
# `$1` : la cible SSH, pour que l'invite dise de quelle machine il s'agit.
helios_sudo_init() {
    [ -n "${HELIOS_SUDO_PASSWORD:-}" ] && return 0
    # Le cas NOPASSWD garde un mot de passe vide : sans ce second test, chaque
    # script enchaîné resonderait la gateway pour rien.
    [ "${HELIOS_SUDO_NOPASSWD:-0}" = "1" ] && return 0
    # Une gateway configurée en NOPASSWD n'a rien à demander : on le vérifie
    # avant d'embêter qui que ce soit.
    if ssh "${HELIOS_SSH_OPTS[@]}" "$1" 'sudo -n true' 2>/dev/null; then
        HELIOS_SUDO_PASSWORD=""
        HELIOS_SUDO_NOPASSWD=1
        export HELIOS_SUDO_PASSWORD HELIOS_SUDO_NOPASSWD
        return 0
    fi
    printf 'Mot de passe sudo de %s (demandé une seule fois) : ' "$1" >&2
    # `read -s` n'existe pas en sh strict ; ce fichier est sourcé par des
    # scripts bash, et l'invite doit rester sans écho.
    stty -echo 2>/dev/null || true
    IFS= read -r HELIOS_SUDO_PASSWORD
    stty echo 2>/dev/null || true
    printf '\n' >&2
    HELIOS_SUDO_NOPASSWD=0
    export HELIOS_SUDO_PASSWORD HELIOS_SUDO_NOPASSWD
}

# Lance une commande shell distante sous `sudo`, sans invite.
#
#   helios_ssh_sudo "$CIBLE" 'systemctl restart heliosd'
#
# La commande est lue par `bash -s` **après** la ligne de mot de passe, donc
# elle n'apparaît ni dans `ps` ni dans l'historique du shell distant.
helios_ssh_sudo() {
    local cible="$1"
    shift
    helios_sudo_init "$cible"
    {
        [ "${HELIOS_SUDO_NOPASSWD:-0}" = "1" ] || printf '%s\n' "$HELIOS_SUDO_PASSWORD"
        printf '%s\n' "$*"
    } | ssh "${HELIOS_SSH_OPTS[@]}" "$cible" \
        "sudo -S -p '' bash -s" 2>&1 |
        # `sudo -S` écrit son éventuel refus sur la sortie d'erreur, qu'on a
        # fusionnée : sans ce filtre, un mot de passe refusé ressemblerait à la
        # sortie normale de la commande.
        #
        # `|| true` : `grep -v` rend 1 quand il ne reste aucune ligne, c'est-à-dire
        # quand la commande distante a réussi **en silence**. Sans lui, `pipefail`
        # ferait échouer précisément les succès les plus ordinaires.
        { grep -v '^sudo: ' || true; }
    return "${PIPESTATUS[1]}"
}

# Comme ci-dessus, mais la sortie est renvoyée à l'appelant telle quelle.
helios_ssh_sudo_capture() {
    local cible="$1"
    shift
    helios_sudo_init "$cible"
    {
        [ "${HELIOS_SUDO_NOPASSWD:-0}" = "1" ] || printf '%s\n' "$HELIOS_SUDO_PASSWORD"
        printf '%s\n' "$*"
    } | ssh "${HELIOS_SSH_OPTS[@]}" "$cible" "sudo -S -p '' bash -s"
}

# Ferme la connexion partagée. À appeler en fin de déploiement.
helios_ssh_close() {
    ssh "${HELIOS_SSH_OPTS[@]}" -O exit "$1" 2>/dev/null || true
    unset HELIOS_SUDO_PASSWORD
}
