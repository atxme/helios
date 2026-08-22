# Déployer Astra et amorcer un domaine de confiance

Guide opératoire de l'[ADR-008](adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md). Il
décrit ce qui existe aujourd'hui et **nomme ce qui manque encore**, parce qu'un
guide qui laisse croire que la rotation fonctionne coûte une journée à celui
qui le suit.

## Deux commandes

```sh
astra-signer init --rp-id astra.helios.local --label "YubiKey du bureau"
./scripts/deploy.sh
```

C'est tout. La première exige une clé de sécurité branchée et ne peut pas être
automatisée — c'est le but d'une clé physique. La seconde fait le reste :
image, transfert, amorçage d'Astra, amorçage du registre gateway, redémarrage.

Aucune valeur n'est recopiée à la main. `init` écrit un **relais** public à côté
du coffre (`~/.helios/astra/astra-domain.json`, `%APPDATA%\astra\` sous Windows) :
domaine, RP ID, ancre `CA-PQ`.
`deploy.sh` le lit, demande à la gateway son identité servie
(`heliosd show-identity`), amorce Astra, **capture** dans sa sortie la clé de
service et la tête de chaîne d'audit, les reporte dans le `.env` distant et
enchaîne sur `heliosd init-trust-domain`.

Sans relais, `deploy.sh` saute cette partie en une ligne et déploie la gateway
comme avant : une gateway sans autorité reste une gateway qui marche.
`--sans-astra` la saute explicitement.

## Ce que ce lot livre, et ce qu'il ne livre pas

Après ce guide, vous avez : un domaine de confiance existant des deux côtés, un
coffre d'autorité ouvert par clé de sécurité, un Astra qui tourne et tient son
registre et sa chaîne d'audit, une gateway dont les routes de cycle de vie
in-tunnel sont ouvertes.

Le **renouvellement client ordinaire se boucle** : Orion ouvre l'opération par
les routes in-tunnel, lit la demande d'approbation, la vérifie sous ce que son
profil épingle, **demande la clé de sécurité lui-même** — pas de second binaire
à lancer — puis committe le grant qu'il a vérifié avant toute écriture. La
gateway enregistre le pair au registre dès l'admission, l'émetteur délégué
s'installe (`astra issuer request` / `issuer install`), et le client présente
l'intermédiaire de la délégation dans sa chaîne. Voir « Ce qui fait qu'une
feuille renouvelée se connecte encore » plus bas.

Ce qui **manque** encore :

- la **récupération d'une identité expirée**, et les trois autres actions du
  §12.2 : sans pilote, refusées en le disant ;
- `authorize-issuer` ne porte **aucune campagne**, donc pas d'opération à
  laquelle se rattacher : ce geste passe par des fichiers, comme décrit ici.
  `approve`, `approve-campaign` et `rotate-ca-pq` ont leur transport ;
- l'**adoption** d'une ancre distribuée. Les clients l'appliquent ; le registre
  Astra et l'épinglage de la gateway restent sur l'ancre sortante jusqu'à ce
  que l'opérateur les avance. Une adoption qui ne toucherait qu'une moitié du
  domaine laisserait les deux en désaccord sur ce qui est courant ;
- une transition de **CA TLS cliente**, qu'aucun geste ne signe et que le
  registre refuserait faute d'épingler cette ancre ; les transitions
  d'identité gateway et les révocations, sans producteur ;
- la **bascule de confiance** du §13, et le discriminant de type de profil
  Orion (§19, §22).

Ce qui est réellement éprouvé ici : la construction de l'image, le démarrage du
conteneur, les volumes, la sauvegarde, le durcissement, la cohérence des deux
moitiés du domaine, et toute la séquence au-dessus du matériel. Ce qui ne l'est
pas en WSL2 : le veth noyau réel, la clé de sécurité (aucun passthrough USB) et
DPAPI — donc un renouvellement complet s'exerce sur Windows, contre une vraie
gateway. Voir [TESTING.md](testing/TESTING.md).

## Faire tourner l'ancre `CA-PQ`

Deux commandes, sur deux machines, et rien à recopier entre elles.

```sh
# sur la gateway, dans le conteneur Astra
astra campaign open --scope trust-authorities \
  --reason "rotation annuelle" --requested-by "prénom.nom"
# → imprime un identifiant d'opération

# sur le poste opérateur
astra-signer rotate-ca-pq --out ca-pq-transition.json \
  --authority-url https://astra.exemple --operation-id <identifiant>
```

La campagne est résolue **sur l'ancre que le registre détient**, et le
compagnon la compare à celle de son propre coffre : deux moitiés du domaine qui
se contredisent sur ce qui est courant s'arrêtent, elles ne se réconcilient pas
par une rotation. Les deux clés autorisées restent branchées le temps de leurs
deux gestes — l'assertion de campagne et l'ouverture du key-slot — plutôt que
d'imposer quatre cycles de branchement.

Le dépôt précède la mutation du coffre. Astra apprend le successeur d'abord, le
coffre l'adopte ensuite, et le journal local rejoue la seconde moitié sans
réseau ni seconde touche. Un dépôt qui échoue est une cérémonie à refaire, pas
un opérateur dont le coffre porte une ancre que personne ne connaît.

`--prepare-days` (1 par défaut) est **la fenêtre dont chaque pair dispose pour
revenir** : §8.1.1 refuse une transaction passé sa première activation, donc un
client qui se connecte après ce délai ne recevra plus la transition et se
répare par l'opérateur. Le choisir plus long qu'un jour est raisonnable pour un
parc dont une part n'est pas allumée tous les jours.

## Le choix qu'on ne refait pas

Le **RP ID WebAuthn**, avant tout le reste.

Un credential FIDO2 est créé *sous* un RP ID, et une assertion doit présenter
le même. Le coffre le mémorise à `astra-signer init` ; en changer rend tous les
key-slots inouvrables, définitivement, sans recours — la spécification refuse
explicitement toute phrase de passe de secours.

Choisissez un nom que vous garderez : `astra.helios.local` en interne, ou un nom
public si Astra sort. Il se propage ensuite tout seul aux trois endroits qui en
ont besoin.

Ce nom reste le RP ID et l'origine logique de l'assertion WebAuthn même quand
le renouvellement ordinaire voyage par l'adresse WireGuard de Helios. Il
n'oblige pas Orion à ouvrir une connexion HTTPS directe vers Astra.

## Prérequis

- La gateway tourne, et `heliosd init-key-negotiation` a déjà été passé. Le
  registre décrit les leaves effectivement servies ; sans elles il n'y a rien à
  décrire, et `deploy.sh` le dit.
- Un moteur de conteneur sur la gateway (`docker compose` ou `podman compose`).
  Absent, l'étape est sautée avec la commande d'installation en clair. `buildx`
  n'est **pas** exigé : compose ≥ 2.33 délègue par défaut la construction à
  `docker buildx bake`, que le paquet Ubuntu n'entraîne pas, et se contente
  alors d'un avertissement — l'image n'est pas construite, mais rien n'échoue.
  `deploy.sh` force donc `COMPOSE_BAKE=0`, vérifie que l'image existe après
  construction, et n'avale plus la sortie du constructeur.
- **Deux** clés de sécurité FIDO2 avec PIN. Une seule suffit pour commencer :
  l'autorité restera « non amorcée » et le dira à chaque commande, jusqu'à
  l'enrôlement de la seconde.
- Le compagnon bâti sur la machine où la clé se branche :
  `cargo build -p astra-signer`. En **debug** : le garde-fou ADR-002 refuse le
  trousseau éditeur de développement dans toute compilation `--release`, et
  rien ici n'y gagne — le déverrouillage d'un key-slot est un HKDF-SHA256.
  Pour un binaire release, fournir `HELIOS_PUBLISHER_KEYRING_PATH`.
- Sous Windows, **aucune élévation n'est nécessaire** : le compagnon passe par
  l'API WebAuthn du système (`--transport platform`, le défaut), qui demande
  elle-même le PIN et le contact — le PIN n'entre donc jamais dans ce
  processus. Elle exige `WEBAUTHN_API_VERSION_4` pour les sels `hmac-secret` ;
  sur un Windows antérieur, le compagnon le dit et renvoie vers
  `--transport hid`, qui parle CTAP2 directement mais **exige une console
  administrateur** — Windows y réserve l'ouverture d'un HID FIDO aux processus
  élevés depuis la 1903. `astra-signer devices` liste ce que la pile HID
  montre, et distingue « aucun HID » de « des HID, mais aucun FIDO ».
  Un credential est celui de la clé, pas celui de l'API : un coffre créé par un
  transport s'ouvre par l'autre, tant que le RP ID est le même — le chemin HID
  applique la même conversion PRF que la plateforme, faute de quoi le même sel
  dériverait deux secrets différents.

## Le détail, si quelque chose casse

### `astra-signer init`

Génère `CA-PQ` (ML-DSA-87) et `CA-TLS`, les scelle sous un key-slot ouvert par
la clé branchée, écrit le coffre et le relais.

Le coffre est à `~/.helios/astra/authority-vault.json`, et sous Windows à
`%APPDATA%\astra\authority-vault.json`. **Sauvegardez-le.** Le perdre entièrement, c'est perdre le domaine ;
il est déjà chiffré, donc une copie hors ligne ne coûte rien.

Le relais, à côté, ne contient que du public. `astra-signer domain` le réécrit
depuis le coffre, sans clé de sécurité.

Quand la seconde clé est en main :

```sh
astra-signer enrol --label "YubiKey de récupération"
astra-signer verify        # à faire avec chacune des deux, séparément
```

`enrol` demande d'abord la clé déjà enregistrée, puis la nouvelle : deux objets,
branchés un à la fois. Une troisième ou une quatrième plus tard, c'est la même
commande — rien ne distingue la seconde de la cinquième.

L'ADR ne tient le bootstrap pour fini qu'« après enregistrement **et essai** des
deux clés ». `verify` est cet essai : il ouvre les ancres, pas seulement le
slot.

### Ce que `deploy.sh` fait à l'étape 7

1. détecte `docker compose` ou `podman compose` sur la gateway ;
2. lit le relais — domaine, RP ID, ancre ;
3. `heliosd show-identity` : nom de serveur et clé WireGuard, lus dans la leaf
   PQ servie plutôt que retapés ;
4. envoie les sources par `git archive HEAD` et construit l'image **sur la
   gateway** — ce qui part est donc ce qui est commité, jamais l'arbre de
   travail. Y compris le trousseau éditeur *public*, sans lequel `aether/build.rs`
   refuse la compilation `--release` de l'image. La construction tourne dans
   une unité systemd transitoire : une coupure SSH n'annule pas BuildKit, et le
   script se reconnecte pour lire son résultat et son journal ;
5. si le domaine n'est pas amorcé : `astra bootstrap`, capture de la clé de
   service et de la tête d'audit, écriture du `.env` distant, puis
   `heliosd init-trust-domain` et `systemctl restart heliosd` ;
6. `compose up -d`.

Le contexte `~/astra-build` est jetable et remplacé à chaque déploiement. Le
témoin durable passé à `--expected-audit-head` vit donc hors de ce contexte,
dans `/var/lib/helios/astra-compose.env`. Sur une reprise, `deploy.sh` relit la
tête du volume et la compare au témoin opérateur `~/.helios/astra/audit-head`.
Les anciennes versions ajoutaient une entrée `StatusPublished` à chaque lecture
de télémétrie ; une extension composée uniquement de ces entrées est reprise et
le témoin est avancé. Tout écart qui contient une admission, une émission, une
rotation ou une révocation reste un fork et est refusé.

Après une panne limitée à cette étape, la reprise ne relivre ni les binaires ni
la configuration de la gateway :

```bash
./scripts/deploy.sh --astra
```

L'URL d'autorité vaut `https://<rp_id>` par défaut ; `ASTRA_AUTHORITY_URL` la
remplace. Elle sert à la récupération et au statut authentifié quand WireGuard
ne peut plus être monté, ainsi qu'aux opérations opérateur hors tunnel, pas au
renouvellement ordinaire. Le veth utilise deux adresses IP statiques locales à
la gateway, absentes du DNS et des profils Orion. Sa moitié Astra → Helios est
livrée ; le client Helios vers l'API Astra opposée reste le lot suivant.

### Pourquoi la construction emprunte le réseau de l'hôte

Le pare-feu Helios tient une chaîne `forward` en `drop` par défaut, et n'y ouvre
que le LAN et le tunnel. Le pont Docker n'y figure pas — les paquets d'un
conteneur sont donc jetés. Comme le premier d'entre eux est une requête DNS, la
panne se lit `Temporary failure resolving 'deb.debian.org'`, qui accuse le
réseau du conteneur alors que c'est la politique de la gateway.

L'ouvrir serait le mauvais geste. Astra n'a besoin d'aucune sortie Internet en
fonctionnement : il écoute sur la boucle locale et parlera à `heliosd` par un
veth privé. Un pont qui traverse le `forward` laisserait en revanche un
conteneur sortir en clair pendant que le kill-switch est engagé.

Seule la **construction** a besoin d'apt et de crates.io, d'où `network: host`
sur le seul bloc `build`. Ce trafic est alors émis localement : il passe par
`output`, que `allow_gateway_egress` régit déjà, et ne touche jamais `forward`.
Le conteneur qui tourne garde son réseau isolé.

Le bridge privé porte le nom stable `astra0`. Le ruleset atomique Helios
n'ouvre que `10.88.7.2 → 10.88.7.1:8444` pour l'API Helios et réserve le sens
opposé `10.88.7.1 → 10.88.7.2:8445` pour l'API Astra. Interface, source,
destination et port sont tous comparés ; aucune règle `forward` n'est ajoutée.
Ces coordonnées ne sont donc pas des paramètres libres de déploiement.

Le `pull` de l'image de base, lui, n'a jamais été concerné : il est émis par le
démon Docker sur l'hôte.

### Pourquoi l'étape 7 ne lit jamais le volume par `compose run`

L'adresse du conteneur Astra sur le veth privé est **épinglée** :
`ipv4_address: 10.88.7.2`. C'est délibéré — `heliosd` écoute sur l'autre bout
et n'accepte qu'une identité épinglée, donc les deux extrémités sont nommées
une fois pour toutes plutôt que découvertes.

La conséquence n'est pas évidente : `docker compose run` crée un **second**
conteneur du service, attaché aux mêmes réseaux, qui redemande donc la même
adresse. Elle est déjà prise, et Docker répond :

```text
failed to set up container networking: Address already in use
```

Autrement dit `compose run` échoue précisément quand Astra est déployé et
fonctionne — le seul cas où son registre existe vraiment. Un conteneur
**arrêté** retient sa réservation de la même façon, jusqu'à sa suppression.

L'étape 7 choisit donc son accès selon l'état du service :

| État du conteneur | Comment le volume est lu |
| --- | --- |
| en marche | `compose exec -T`, qui n'alloue aucune adresse |
| présent, arrêté | un conteneur jetable `--network none` monté sur le volume |
| absent | `compose run --rm --no-deps`, sans concurrent possible |

Le troisième cas est le seul où `run` est sûr. Les trois écritures de l'étape —
sonde, `bootstrap`, `init-channel` — passent par le même accès.

`exec` ne se contente pas d'une forme différente : il **n'applique pas
l'`ENTRYPOINT`** de l'image et exécute l'argv tel quel. `exec -T astra status`
demande donc au runtime un programme nommé « status », qu'il cherche dans le
`PATH` et ne trouve pas. Le chemin complet, `/usr/local/bin/astra status`, est
obligatoire — et seulement là : `run` et le conteneur jetable passent par
l'entrypoint.

Une sortie qui vient du démon — conteneur arrêté, exécutable introuvable,
réseau impossible — dit qu'`astra status` n'a **jamais tourné**, et l'étape la
range avec les sondes muettes plutôt qu'avec les refus d'Astra. La seule
combinaison qui met le registre en cause est celle où Astra a tourné, a lu, et
a refusé.

Si la sonde ne répond malgré tout rien, l'étape **s'arrête**. Elle ne suppose
ni « registre illisible » — cela accuserait le registre d'une panne que
personne n'a observée — ni « volume vierge », qui enchaînerait sur un amorçage
par-dessus une autorité existante. C'est la seule erreur irrattrapable de cette
étape.

### Le document de credentials

Astra n'approuve rien sans liste d'autorisation. `astra-signer bindings` émet
le document signé par `CA-PQ` — et le réémet tout seul à chaque geste qui
déplace la table de key-slots. L'étape 7 le recopie dans le volume d'Astra,
depuis `~/.helios/astra/astra-credentials.json`, à côté du coffre.

Il ne porte rien de secret : ce sont les liaisons publiques des credentials,
et c'est le **consommateur** qui les vérifie sous son ancre — Orion sous le
`CA-PQ` de son profil, le compagnon sous celui de son coffre. Ni ce script, ni
la gateway, ni Astra ne les authentifient.

Il est lu **au démarrage**. Copié dans un conteneur déjà en marche, il n'aurait
d'effet qu'au redémarrage suivant, et `up -d` ne recrée pas un service dont
rien n'a changé : l'étape redémarre donc Astra explicitement, et seulement dans
ce cas.

Sans lui, Astra tourne, sert ses statuts et tient son canal — et refuse chaque
renouvellement ordinaire en le disant. C'est ce à quoi une installation
incomplète doit ressembler.

### Le coffre chiffré, et pourquoi il ne se copie pas tout seul

Une campagne qui fait signer une ancre — la portée `trust_authorities` — exige
que le compagnon **ouvre** le coffre. Il le télécharge par
`GET /v1/vaults/<empreinte>`, sous un jeton de capacité, et Astra ne peut le
servir que s'il en détient une copie : `/var/lib/astra/authority-vault.json`.

Le déploiement ne la fait pas à votre place, et c'est délibéré. Le coffre
contient `CA-PQ` — chiffré, inouvrable sans deux clés de sécurité, mais c'est
le seul fichier du domaine dont la perte ou la fuite compte vraiment. Le poser
sur la gateway est une décision d'exploitation : elle donne une sauvegarde hors
du poste opérateur, et elle met le fichier là où tourne le service. Les deux
sont défendables ; aucune n'est un défaut à choisir dans un script.

Copier :

```sh
scp ~/.helios/astra/authority-vault.json cible:/tmp/vault.json
ssh cible 'sudo docker compose -f /opt/helios/astra/docker-compose.yml     cp /tmp/vault.json astra:/var/lib/astra/authority-vault.json'
ssh cible 'sudo docker compose -f /opt/helios/astra/docker-compose.yml restart astra'
rm ~/…/tmp/vault.json
```

Il est lu au démarrage, comme le document de credentials, et pour la même
raison : ce sont des octets qu'Astra transporte, jamais qu'il interprète.
Son empreinte apparaît au journal de démarrage — c'est elle que la demande
signée nomme, et que le compagnon compare avant d'ouvrir quoi que ce soit.

Sans lui, seules les campagnes qui font signer une ancre sont refusées, en le
disant. Toutes les autres portées sont inchangées.

### L'émetteur délégué

Sans lui, Astra tourne et refuse chaque renouvellement ordinaire en le disant :
il ne détient aucune clé autorisée à émettre. `CA-PQ` ne quitte jamais le
coffre, donc la délégation se signe sur le poste opérateur, à la clé de
sécurité, et fait un aller-retour.

Trois commandes, dans cet ordre :

```sh
# 1. sur la gateway : les deux clés privées naissent dans le volume d'Astra,
#    adressées par époque. Rien n'est installé, rien n'est annoncé.
ssh <gateway> "cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
    --env-file /var/lib/helios/astra-compose.env exec -T astra \
    /usr/local/bin/astra issuer request" > delegation-request.json

# 2. sur le poste opérateur, clé branchée : CA-TLS d'abord si le domaine n'en
#    a pas encore, puis la délégation elle-même.
astra-signer issue-ca-tls
astra-signer authorize-issuer --request delegation-request.json \
    --out delegation.json --days 30 --leaf-days 90

# 3. retour sur la gateway.
ssh <gateway> "cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
    --env-file /var/lib/helios/astra-compose.env exec -T astra \
    /usr/local/bin/astra issuer install" < delegation.json
ssh <gateway> "cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
    --env-file /var/lib/helios/astra-compose.env restart astra"
```

La demande sort sur la **sortie standard** et les journaux d'Astra sur
l'erreur standard, précisément pour que ce `>` fonctionne. `install` lit
l'autorisation sur l'entrée standard quand `--authorization` est absent.

`install` vérifie trois choses qui viennent de trois endroits différents :
l'ancre que le registre épingle, la politique d'émission calculée à l'amorçage,
et la possession — les clés privées de cette époque sont déjà sur le disque et
doivent correspondre à ce que la délégation nomme. Une autorisation qui
satisfait les trois est une délégation avec laquelle cette autorité peut
réellement émettre ; l'alternative est d'annoncer une délégation dont le
premier usage échoue à 80 % de la vie d'une feuille cliente.

La délégation est lue **au démarrage**, d'où le redémarrage explicite.

### Ce qui fait qu'une feuille renouvelée se connecte encore

Trois choses, et il a fallu les trois. Elles se lisent ensemble parce qu'une
seule qui manque produit la même panne : un client qui a renouvelé, qui bascule
à la fin du chevauchement, et qui ne rouvre plus le tunnel — donc plus aucun
canal pour le dire.

1. **La négociation résout dans le registre**, pas dans `network.toml`.
   Ce fichier n'est écrit qu'à l'admission et rien ne le remet à jour ; le
   registre, lui, est ce qui a enregistré la rotation. L'empreinte TLS que mTLS
   vient de prouver désigne le pair, et l'empreinte PQ acceptable est **celle
   appariée** à cette moitié-là — jamais l'union des générations vivantes, qui
   accepterait la paire mixte du §3.3.
2. **L'ensemble d'émetteurs contient l'émetteur délégué.** Une feuille PQ
   renouvelée n'est pas signée par la CA opérateur mais par la délégation, et
   la gateway l'admet parce que le registre la nomme.
   `assert_candidate_is_presentable` construit le **même** ensemble avant de
   mettre un candidat en attente : deux réponses différentes à « cette feuille
   s'authentifierait-elle » n'ont aucune issue correcte.
3. **Le client présente la chaîne.** La feuille TLS déléguée est signée par
   l'intermédiaire de la délégation, et le point d'écoute QUIC ne détient que
   l'ancre : il construit le chemin depuis ce que le client montre. Orion scelle
   donc `[feuille, intermédiaire]`, et seulement quand cet intermédiaire est
   celui qui a signé cette feuille.

**Limite connue** : le jeu d'ancres TLS clientes est lu une fois sur disque au
démarrage, et `heliosd init-trust-domain` amorce le registre depuis ce même
fichier — les deux concordent donc, et l'intermédiaire de la délégation chaîne
vers cette ancre. Ce qui n'est pas câblé, c'est une **rotation de CA TLS
cliente** : `next_client_tls_ca_certificate` n'est pas offert en seconde racine,
et une nouvelle ancre exigerait de toute façon un redémarrage — reconstruire le
point d'écoute sous des sessions vivantes ferait tomber les slots PSK qu'elles
tiennent. Rien n'effectue cette rotation aujourd'hui.

### À la main

Chaque commande imprime la suivante. `astra bootstrap` imprime la ligne
`heliosd init-trust-domain` complète, et `heliosd init-trust-domain` dit ce qui
manque encore.

## Sauvegardes

Trois objets, trois endroits, et aucun ne remplace un autre :

| Quoi | Où | Perdre le seul exemplaire |
|---|---|---|
| Coffre d'autorité | poste opérateur | le domaine est perdu |
| Volume `astra-state` | gateway | registre et chaîne d'audit perdus |
| Clés de sécurité | vos poches | il en reste une autre — c'est le but |

Le coffre est chiffré : une copie hors ligne ne l'expose pas. Le volume Astra
contient la clé de service privée : traitez-le comme un secret.

La **tête de chaîne d'audit** est ce qui distingue une restauration légitime
d'un fork, et `astra run --expected-audit-head` est ce qui refuse le second.
`deploy.sh` la conserve dans `~/.helios/astra/audit-head`.

## Limite connue : retirer une clé ne rattrape pas les sauvegardes

`astra-signer remove` rescelle le corps du coffre sous la table de slots qu'il
laisse : le slot retiré, recollé depuis une sauvegarde, n'ouvre plus le fichier
courant. Mais une sauvegarde **antérieure** au retrait reste ouvrable par la clé
retirée, définitivement — c'est la situation de LUKS avec une phrase supprimée
depuis.

La réponse à un credential réellement compromis n'est donc pas un retrait de
slot, c'est une rotation de `CA-PQ`.

## Essais sur cible

Voir [testing/TESTING.md](testing/TESTING.md), sections « coffre d'autorité
Astra » et « domaine de confiance ». Rien de ce qui touche la clé de sécurité ne
s'exerce en WSL2 : aucun passthrough USB.
