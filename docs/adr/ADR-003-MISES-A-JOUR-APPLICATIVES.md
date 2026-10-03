# ADR 003 — Mises à jour applicatives signées de Helios

**Statut** : accepté (2026-07-20)

## Contexte

Helios est déployé sur une distribution Linux existante. L’objectif est de
mettre à jour l’application `heliosd` à distance, pas de fabriquer ni de
remplacer un kernel, un initrd ou un rootfs. Le mécanisme RAUC A/B présent dans
le dépôt répond à un autre problème et impose des slots de boot dont Helios n’a
pas besoin pour ce flux.

L’API et l’interface web vivent derrière `helios0`. WireGuard fournit déjà la
confidentialité, l’intégrité et l’authentification cryptographique du pair. Une
seconde authentification web n’apporte pas de nouvelle identité dans le modèle
actuel, où l’opérateur utilise sa machine habituelle comme client et comme
poste d’administration.

La production ne doit jamais exécuter une campagne de tests. Les campagnes
appartiennent aux gateways de laboratoire et précèdent la signature de
production de l’artefact exact.

## Décision

### 1. Portée applicative uniquement

Une release contient le binaire ELF `heliosd` et un manifeste JSON signé qui
authentifie son contenu et ses paramètres de compilation.

La mise à jour ne remplace ni rootfs, ni kernel, ni bootloader et ne redémarre
pas la machine. Les PCR 0/4/7 auxquels le secret TPM est lié ne changent donc
pas et aucun billet de rescellement n’est nécessaire.

RAUC est retiré du chemin de mise à jour Helios. Une évolution future qui
administrerait aussi l’OS constituerait une fonctionnalité séparée.

### 2. Deux flux sans reconstruction intermédiaire

Le flux de release construit une fois le binaire cible avec le trousseau public
éditeur définitif, signe un premier manifeste de canal `testing`, l’installe
sur une gateway de laboratoire et exécute les campagnes. Après validation, le
même fichier, identifié par son SHA-256, reçoit un nouveau manifeste de canal
`production`, sans recompilation intermédiaire.

Les deux manifestes sont authentifiés par une époque du trousseau éditeur
compilé dans ce même binaire. Leur canal fait partie des octets signés. Une
gateway configurée pour `production` refuse donc un manifeste `testing`, même
valide et portant le même SHA-256. Les campagnes automatisées du dépôt utilisent
une époque éphémère exclusivement pour éprouver le mécanisme ; leurs artefacts
ne sont jamais promus.

En production, l’installation exécute seulement un contrôle transactionnel de
démarrage : le nouveau daemon doit atteindre son point de disponibilité en
mode réel dans le délai imparti. Ce contrôle n’émet aucun trafic de campagne et
ne modifie aucune donnée métier. Un échec réactive le binaire précédent.

### 3. Identité et autorisation administrateur

`WgPeer` porte un booléen `admin`, faux par défaut. Un pair administrateur reste
un client WireGuard ordinaire : aucune machine dédiée n’est requise.

À chaque requête protégée, l’API récupère l’adresse source du socket, exige une
VIP IPv4 unique en `/32`, retrouve le pair correspondant et contrôle `admin`.
Les en-têtes de proxy ne participent jamais à la décision.

Les routes de mutation réseau, tunnel, clé WireGuard, pare-feu et mise à jour
exigent toutes cette autorisation. Protéger la seule route de mise à jour
laisserait un pair ordinaire s’élever via la modification de configuration.

Le provisioning reste accessible aux pairs admis, mais la clé WireGuard portée
par la requête doit être celle du pair appelant. Le mode `--dev` autorise
explicitement la boucle locale comme administrateur simulé ; ce comportement
n’existe pas en mode réel.

Il n’y a ni compte web, ni mot de passe, ni cookie de session, ni WebAuthn. La
confirmation textuelle d’une activation prévient une erreur de manipulation ;
elle ne remplace pas l’authentification WireGuard.

### 4. Manifeste et signature

Le payload `helios-binary-release-v1` contient au minimum :

- produit et canal ;
- compteur `release_sequence` strictement croissant ;
- version applicative et commit Git ;
- triplet cible et liste exacte des features ;
- taille et SHA-256 du binaire ;
- version minimale du programme d’installation.

Il utilise l’enveloppe de l’ADR-002 : Ed25519 **et** ML-DSA-65 obligatoires,
époque de clé signée, encodage canonique et champs JSON inconnus refusés. Les
clés privées éditeur ne quittent jamais la machine de publication.

Le compteur le plus élevé confirmé est persisté par le programme
d’installation. Une séquence inférieure ou égale est refusée, y compris avec
des signatures valides.

### 5. Réception par l’API

Le navigateur ou `helios-ctl app-update` envoie le manifeste puis le binaire
par fragments base64 JSON. Cette forme conserve l'invariant selon lequel toute
mutation de l'API est du JSON, borne la mémoire du daemon et n'ajoute ni
`multipart`, ni URL distante, ni règle de sortie au kill-switch.

Le staging écrit sous `/var/lib/helios/updates`. La finalisation vérifie à
nouveau taille, hash, canal, target et signatures. L’activation exige la chaîne
`INSTALLER <release_sequence>` et produit une demande persistante.

### 6. Séparation de privilèges et rollback

`heliosd` ne peut écrire que son staging. Une unité systemd oneshot lance
`helios-installer`, petit helper sans accès réseau qui :

1. relit et revérifie le manifeste et le binaire ;
2. installe le binaire dans `/opt/helios/releases/<sequence>/heliosd` ;
3. bascule atomiquement `/opt/helios/current` ;
4. redémarre `heliosd` ;
5. attend un fichier de disponibilité neuf sous `/run/helios` ;
6. confirme la séquence ou restaure le lien précédent et redémarre l’ancienne
   version.

Le helper possède uniquement les droits nécessaires sur `/opt/helios`, l’état
de mise à jour et le contrôle du service. Il ne télécharge rien et revérifie les
octets même si `heliosd` les a déjà acceptés.

Deux conséquences de l’étape 5, qui ne se voient qu’en service.

`/run/helios` est le seul point de rendez-vous entre les deux processus, et
c’est un répertoire d’exécution que le démon détruit en s’arrêtant — dont
l’arrêt que l’installateur provoque lui-même à l’étape 4. Les deux unités le
déclarent donc en `RuntimeDirectory` et le préservent : sous
`ProtectSystem=strict`, un `ReadWritePaths` dont le répertoire manque au
montage est ignoré **sans un mot**, et le service démarre avec un `/run` en
lecture seule.

La version que le manifeste porte est celle du **binaire livré**, jamais celle
du workspace : c’est elle que le marqueur de disponibilité publie, et la
comparaison de l’étape 5 lit les deux. Étiqueter une release avec un autre
numéro rend son contrôle de santé structurellement infaisable — le démon
démarre, l’installateur ne le reconnaît pas, et restaure une version qui
n’avait pas échoué.

Avant de sortir sur `SIGTERM`, `heliosd` repasse en `TunnelState::Down`, engage
le pare-feu fail-closed puis démonte WireGuard. Le kill-switch reste installé.

## Conséquences

- Une compromission d’un pair administrateur permet de demander une mise à
  jour ou un redémarrage, mais pas d’installer un binaire non signé par
  l’éditeur.
- La signature protège l’authenticité ; le rôle WireGuard protège
  l’autorisation ; le rollback protège la disponibilité. Aucun de ces trois
  contrôles ne remplace les deux autres.
- La perte du tunnel pendant le redémarrage n’interrompt pas l’installation :
  le helper et son contrôle de disponibilité sont locaux.
- Les gateways existantes sans champ `admin` continuent à charger leur
  configuration, mais aucune mutation distante n’est autorisée tant qu’un
  administrateur n’a pas été déclaré localement.

## Validation

Les tests unitaires couvrent la signature hybride, l’altération du binaire,
l’anti-rollback, l’autorisation par VIP, le refus d’un pair ordinaire, le
staging borné et le rollback du lien.

La campagne dry-run couvre l’API avec un administrateur simulé. La catégorie
`mise-a-jour` de la campagne cible exerce de nouveau, dans un daemon isolé, le
transfert signé, le refus d’une signature altérée, l’ordre des fragments, le
SHA-256 et la demande d’activation. La recette matérielle avec accès console
valide ensuite le service systemd, la reconnexion de l’API, la version confirmée
et le rollback. Ces scénarios restent interdits sur une gateway de production.

## Amendement du 3 octobre 2026 — administration locale par socket Unix

### Contexte

Le terminal opérateur `helios` s'utilise sur la gateway elle-même. Or le §3
ne connaît qu'une identité administrateur, la VIP `/32` d'un pair WireGuard
`admin`, et le pare-feu n'accepte le port de l'API que par `admin_iface`,
boucle locale comprise (`helios-firewall`, `ruleset/administration.rs`). Depuis
le shell de la gateway, l'API ne répond donc pas, et la seule administration
locale existante (`--dev`) est explicitement exclue du mode réel.

Ouvrir la boucle locale TCP ne convient pas : toute connexion locale
deviendrait administratrice, quel que soit le processus, et un filtre par uid
dans nftables disparaîtrait avec le mode maintenance `--sans-firewall`.

### Décision

`heliosd` sert, en mode réel, le même routeur d'API sur un second point
d'entrée : le socket Unix `/run/helios/admin.sock`. Le TCP reste inchangé :
adresse du tunnel, pare-feu limité à `admin_iface`, autorisation par VIP.

1. **Authentification par le noyau, pas par le réseau.** À chaque connexion,
   `heliosd` lit les identifiants du processus appelant fournis par le noyau
   (`SO_PEERCRED`, `SO_PEERGROUPS`). Seuls l'uid 0 et les membres du groupe
   `sudo` sont acceptés. Ce groupe donne déjà l'élévation root sur la gateway :
   l'accès au socket n'accorde aucun privilège nouveau. Sans groupe `sudo`,
   seul root est accepté. Toute autre connexion est fermée avant la première
   requête et journalisée avec son uid et son pid.
2. **Une identité posée par le serveur.** Chaque requête reçue sur ce socket
   porte une marque d'appelant local insérée par le serveur lui-même, après la
   vérification ci-dessus. Aucun en-tête ni aucune donnée de la requête ne la
   produit ; une requête TCP ne peut pas la porter. `require_admin` l'accepte
   comme administrateur et journalise `local:<utilisateur>`.
3. **Un emplacement que seul root contrôle.** `/run/helios` est le
   `RuntimeDirectory` du service, propriété de root et non inscriptible par un
   autre utilisateur ; un utilisateur ordinaire ne peut ni créer ni remplacer
   le socket. Le service n'a pas `CAP_CHOWN` : le socket reste propriété de
   root, et ses droits d'accès sont ouverts (`0666`) parce que l'autorisation
   repose sur les identifiants du noyau, pas sur les droits du fichier.
4. **Un client qui vérifie avant de parler.** `helios` n'utilise le socket que
   si c'est bien un socket, propriété de root, dans un répertoire propriété de
   root et non inscriptible par le groupe ou les autres. Un socket qui échoue à
   ce contrôle est une erreur, jamais un repli silencieux vers le TCP.
5. **Indépendant du pare-feu.** Le socket n'est pas joignable par le réseau. Le
   mode maintenance `--sans-firewall` ne change rien à son autorisation.
6. **Mode réel seulement.** En simulation, l'API reste sur
   `127.0.0.1:8080` avec l'administrateur simulé du §3.

`helios` choisit le socket quand il existe et que ni `--url` ni `HELIOS_URL`
ne désignent une API TCP ; `--url` force toujours le TCP.

### Conséquences

- Un compte membre de `sudo` sur la gateway administre Helios sans tunnel.
  C'était déjà le cas par `sudo` ; ce chemin le rend direct et journalisé.
- Un processus local qui n'est ni root ni membre de `sudo` n'obtient rien, pas
  même les routes de lecture : la connexion est fermée.
- L'invariant du pare-feu ne change pas : le port TCP de l'API reste fermé à
  toute interface autre que `admin_iface`.
- Un service compromis tournant sous un compte dédié reste exclu. Un service
  compromis tournant en root l'était déjà de toute façon.
