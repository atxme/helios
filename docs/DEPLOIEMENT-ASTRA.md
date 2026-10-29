# Déployer Astra et amorcer un domaine de confiance

Guide opératoire de l'[ADR-008](adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md). Il
décrit ce qui existe aujourd'hui et **nomme ce qui manque encore**, parce qu'un
guide qui laisse croire que la rotation fonctionne coûte une journée à celui
qui le suit.

## Amorçage en deux passages

Les gestes du coffre et du domaine se jouent **dans Orion**, onglet *Astra*
(le lot 3 de F14, livré sur la branche `feat/f14-lot3-coffre-domaine`, validation
Windows à faire). `astra-signer` reste livré comme voie transitoire, jusqu'au
lot 7 ; `issue-gateway-bootstrap` n'est pas encore dans Orion et reste en ligne
de commande jusqu'au lot 6.

1. Orion, « Coffre et clés » : « Créer un domaine ». Nom du domaine (RP ID) et
   origine, libellés des deux clés, « Créer le domaine » : deux YubiKey, branchées
   une à la fois (quatre dialogues Windows en tout). Ce nom ne se change plus :
   prendre le nom Tailscale de la gateway si elle est dans un tailnet. L'écran de
   fin montre l'empreinte du coffre et celle de `CA-PQ` : les noter, et
   sauvegarder le coffre.
2. `./scripts/deploy.sh` : le premier passage installe la gateway et rapatrie sa
   demande publique d'amorçage.
3. `issue-gateway-bootstrap`, toujours en ligne de commande (lot 6) : il émet la
   feuille PQ de la gateway sous `CA-PQ` et inscrit son identité (clé WireGuard,
   nom de service) dans le relais. Ajouter `--vault <chemin>`, avant la
   sous-commande, quand le coffre n'est pas à l'emplacement par défaut (celui que
   « Coffre et clés » affiche) :

```sh
astra-signer issue-gateway-bootstrap \
  --request ~/.helios/astra/gateway-bootstrap-request.json \
  --out ~/.helios/astra/gateway-bootstrap-certificate.json
# coffre ailleurs :
# astra-signer --vault 'E:\astra\authority-vault.json' issue-gateway-bootstrap ...
```

4. Orion, « Domaine » : « Finaliser le domaine ». Un toucher, qui émet la
   `CA-TLS` (à enregistrer : `ca-tls.pem`) et écrit le document de credentials à
   côté du coffre. Il exige que le relais nomme la gateway : c'est l'étape 3 qui
   l'y a inscrite.
5. `./scripts/deploy.sh --astra` : la reprise reporte la feuille sur la gateway,
   amorce Astra en épinglant la `CA-TLS`, puis redémarre.

« Reprendre la gateway connectée » et « Modifier », dans « Domaine », ne font pas
partie de ce parcours : ce sont des outils de **réparation**, pour un relais qui a
perdu l'identité de la gateway (restauré d'une sauvegarde ancienne, réécrit à la
main). « Reprendre » lit la feuille PQ de la gateway connectée au profil, la
vérifie sous le `CA-PQ` du relais et n'inscrit l'identité que si elle y vérifie ;
« Modifier » saisit clé WireGuard, nom de service, clé de service Astra, époque et
origine d'Astra. Ni l'un ni l'autre ne remplace une identité déjà inscrite, ni
celle à laquelle le document de credentials est lié.

Voie transitoire, équivalente aux étapes 1 à 5 tant que `astra-signer` est livré :

```sh
astra-signer init --rp-id <gateway>.<tailnet>.ts.net --label "YubiKey du bureau"
astra-signer enrol --label "YubiKey de récupération"
./scripts/deploy.sh
astra-signer issue-gateway-bootstrap \
  --request ~/.helios/astra/gateway-bootstrap-request.json \
  --out ~/.helios/astra/gateway-bootstrap-certificate.json
# L'ancre TLS cliente, dans la foulée : elle se dépose dans le même relais et
# c'est là que le déploiement va chercher l'empreinte qu'il épingle.
astra-signer issue-ca-tls
./scripts/deploy.sh --astra
```

C'est tout. Chaque geste à clé exige les clés de sécurité et ne peut
pas être automatisé — c'est le but des objets physiques. Le premier
passage du déploiement installe la gateway, puis rapatrie la demande publique
créée et signée par sa clé ML-DSA-87 scellée. Il s'arrête **avant** de créer un
registre Astra. La cérémonie hors ligne émet la leaf sous `CA-PQ` ; la reprise
la reporte sur la gateway, amorce Astra et le registre gateway, puis redémarre.

La `CA-TLS` vient **après** l'identité de la gateway et non avant : l'ancre
TLS cliente est émise sous la politique d'émission du domaine, qui nomme la
gateway. La cérémonie d'amorçage est ce qui apprend cette identité, depuis une
demande que la gateway a signée, et l'inscrit dans le relais — un domaine sert
une gateway et une seule, donc une demande qui en nommerait une autre arrête la
cérémonie au lieu de l'adopter. Dans Orion, l'identité déjà enregistrée ne se
change pas (c'est une transition de gateway, lot 6), et « Reprendre la gateway
connectée » refuse celle d'une autre gateway que le profil connecté.

Aucune valeur n'est recopiée à la main. La création du domaine (Orion, ou `init`) écrit un **relais** public à côté
du coffre (`~/.helios/astra/astra-domain.json`, `%APPDATA%\astra\` sous Windows) :
domaine, RP ID, ancre `CA-PQ`. Les cérémonies suivantes y ajoutent ce qu'elles
apprennent — identité de la gateway, ancre `CA-TLS` et son époque.
`deploy.sh` le lit, demande à la gateway son identité servie
(`heliosd show-identity` lit la demande tant que la leaf n'existe pas), amorce
Astra — en lui épinglant au passage l'empreinte de la `CA-TLS` qu'il calcule
depuis ce relais —, **capture** dans sa sortie la clé de service et la tête de
chaîne d'audit, les reporte dans le `.env` distant et enchaîne sur `heliosd
init-trust-domain --gateway-certificate ...`.

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

Pendant le chevauchement, Orion conserve aussi l'identité sortante dans le
même enregistrement protégé que l'identité servie. L'action « Revenir
temporairement à l'ancienne identité » ne déplace aucun compteur : elle choisit
seulement lequel des deux lots DPAPI est présenté. L'écran montre l'échéance de
ce choix ; à `not_after`, l'ancienne feuille et ses clés sont retirées et une
restauration de fichier ne les rend pas de nouveau sélectionnables.

Ce qui reste **hors** de ce déploiement, et pourquoi :

- l'**ouverture d'une campagne depuis l'origine publique** (`POST
  /v1/campaigns`) : cette route *résout* une campagne sur les cibles courantes,
  donc sur un canal public non authentifié elle répondrait l'inventaire du
  domaine à n'importe quel appelant, et l'authentification qu'elle exigerait
  n'est décrite nulle part. La résolution reste locale, dans ce conteneur ;
- la **bascule de confiance du §13.2** pour un parc v5 déjà déployé : la
  première installation de `CA-PQ` est un amorçage, avec confirmation
  d'empreinte hors bande, et non une rotation `N -> N+1` ;
- le **terminateur TLS devant l'origine publique**. `astra run` sert du HTTP
  clair sur la boucle locale et ADR-008 §2 met un reverse proxy devant lui ; ce
  déploiement n'en pose aucun, et le pare-feu n'ouvre pas le port sur le WAN.
  Tant qu'il manque, tout ce qui passe par l'origine publique — récupération
  d'une identité expirée, statut authentifié hors tunnel, routes compagnon du
  §8.2 — n'est joignable que depuis la gateway elle-même. Le renouvellement
  ordinaire, qui passe par le tunnel puis le veth, n'en dépend pas.

Ce qui est réellement éprouvé ici : la construction de l'image, le démarrage du
conteneur, les volumes, la sauvegarde, le durcissement, la cohérence des deux
moitiés du domaine, et toute la séquence au-dessus du matériel. Ce qui ne l'est
pas en WSL2 : le veth noyau réel, la clé de sécurité (aucun passthrough USB) et
DPAPI — donc un renouvellement complet s'exerce sur Windows, contre une vraie
gateway. Voir [TESTING.md](testing/TESTING.md).

## Récupérer une identité expirée

Un poste resté éteint trop longtemps n'a plus de tunnel : sa feuille est
refusée par mTLS, par QUIC et par tous les validateurs ordinaires. C'est le
seul cas où le client parle à l'**origine publique** d'Astra plutôt qu'à la
gateway.

Dans Orion : « Récupérer le certificat expiré ».

**Si la clé est sur ce poste**, la ligne suivante affiche « Approuver ici avec
la clé » : l'onglet Astra s'allume, montre le pair, la génération et depuis
combien de temps elle est expirée, puis demande le toucher. Rien n'est saisi —
l'origine de l'autorité, le RP ID et les durées viennent du relais de domaine
épinglé à côté du coffre.

**Si la clé est sur un autre poste**, Orion affiche la ligne à y exécuter :

```sh
astra-signer recover --authority-url https://astra.exemple \
  --operation-id <identifiant>
```

L'adaptateur en ligne de commande subsiste pour ce cas, et pour le transport
hors ligne du §8.5. Il exécute exactement la même cérémonie que l'onglet.

Une seule clé suffit, et §7.5 dit pourquoi : elle n'est pas la seule preuve —
la clé privée de la dernière génération admise signe aussi la demande, et une
récupération ne peut changer ni le pair ni le domaine. Une réadmission, elle,
peut créer une continuité neuve, et exige donc deux clés.

Le commit du client repart par le canal privé, parce qu'il n'a toujours pas de
tunnel au moment où il committe. La gateway refuse sur ce lien tout ce dont
l'étape en attente n'a pas été ouverte par l'autorisation `CA-PQ` présentée à
côté : relayer ne donne donc à l'autorité rien qu'elle n'avait déjà.

**La clé privée expirée doit encore exister.** Si elle est partie avec le
stockage protégé qui la tenait, Orion le dit et s'arrête : il reste une
réadmission opérateur à deux clés.

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

### Par le tunnel, quand il est monté

Les quatre commandes de chaîne — `rotate-ca-tls`, `sign-gateway-transition`,
`abort-gateway-transition` et `resume-rotation` — n'avaient que l'origine
publique. Depuis l'amendement du 4 septembre 2026 elles passent par le tunnel
dès qu'il existe, ce qui est le seul chemin praticable quand le nom de
l'autorité n'est pas résoluble publiquement (spécification §8.5) :

```sh
astra-signer rotate-ca-tls --out ca-tls-transition.json \
  --heliosd-url http://<VIP de la gateway>:8080 --operation-id <identifiant>
```

Le poste opérateur doit être un pair **administrateur** du tunnel : les routes
sont derrière la barrière d'administration de la gateway, pas derrière la
simple appartenance au réseau. `--heliosd-url` et `--authority-url` s'excluent,
et un tunnel qui échoue est une erreur — jamais un repli silencieux vers
l'origine publique.

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

Choisissez un nom que vous garderez. Il se propage ensuite tout seul aux trois
endroits qui en ont besoin — l'URL d'autorité vaut `https://<rp_id>` par défaut.

**Prenez le nom Tailscale de la gateway**, `<gateway>.<tailnet>.ts.net`, si elle
est dans un tailnet. C'est le seul choix qui rend l'origine publique joignable
sans rien installer : Tailscale émet et renouvelle un certificat publiquement
reconnu pour ce nom, `deploy.sh` le présente sur 443 par `tailscale serve`, et
la récupération d'une identité expirée (§7.5) marche depuis n'importe quel
poste du tailnet — sans autorité locale à approuver dans le magasin racine de
Windows, sans entrée `hosts`, sans reverse proxy à maintenir et sans jamais
ouvrir 443 sur l'Internet.

Un nom interne comme `astra.helios.local` reste possible et ne change rien au
renouvellement ordinaire, qui passe par le tunnel. Il vous laisse en revanche
le terminateur TLS à poser, et donc à faire approuver un certificat auto-signé
sur chaque poste opérateur.

Ce choix se fait **au premier `init` et ne se rattrape pas** : le RP ID
n'est pas un réglage de déploiement mais la moitié du chemin de dérivation des
key-slots, et l'origine de l'autorité doit être gouvernée par lui — un profil
Orion dont l'hôte n'est ni le RP ID ni l'un de ses sous-domaines est refusé à
l'import. En changer après coup revient à recréer le domaine.

Ce nom reste le RP ID et l'origine logique de l'assertion WebAuthn même quand
le renouvellement ordinaire voyage par l'adresse WireGuard de Helios. Il
n'oblige pas Orion à ouvrir une connexion HTTPS directe vers Astra.

## Prérequis

- La gateway tourne, et `heliosd init-key-negotiation` a déjà été passé. La
  commande scelle les clés privées et exporte une demande publique ; elle
  n'émet plus de leaf PQ auto-signée. `deploy.sh` rapatrie cette demande au
  premier passage.
- Un moteur de conteneur sur la gateway (`docker compose` ou `podman compose`).
  Absent, l'étape est sautée avec la commande d'installation en clair. `buildx`
  n'est **pas** exigé : compose ≥ 2.33 délègue par défaut la construction à
  `docker buildx bake`, que le paquet Ubuntu n'entraîne pas, et se contente
  alors d'un avertissement — l'image n'est pas construite, mais rien n'échoue.
  `deploy.sh` force donc `COMPOSE_BAKE=0`, vérifie que l'image existe après
  construction, et n'avale plus la sortie du constructeur.
- **Deux** clés de sécurité FIDO2 avec PIN, enregistrées et essayées avant
  l'émission de la première leaf gateway. Cette admission ne possède aucune
  continuité sortante ; `CampaignScope::GatewayBootstrap` exige donc deux
  credentials actifs distincts, comme une réadmission sans continuité. Le
  coffre reste 1-sur-N : ce n'est pas un quorum humain, mais deux barrières
  matérielles appliquées par le compagnon honnête.
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

### Créer le domaine : « Créer un domaine » dans Orion, ou `astra-signer init`

Orion fait ce que fait `init`, voie transitoire jusqu'au lot 7. Génère `CA-PQ` (ML-DSA-87) et `CA-TLS`, les scelle sous un key-slot ouvert par
la clé branchée, écrit le coffre et le relais.

Le coffre est à `~/.helios/astra/authority-vault.json`, et sous Windows à
`%APPDATA%\astra\authority-vault.json`. Orion peut le ranger ailleurs
(« Changer… » dans « Coffre et clés » ; le fichier choisi s'appelle
obligatoirement `authority-vault.json`, pour que relais et document de
credentials, rangés à côté, n'appartiennent qu'à un domaine), puis « Emplacement
par défaut » revient à l'emplacement habituel. À l'emplacement par défaut, Orion
crée le dossier, privé, s'il n'existe pas encore ; un dossier choisi n'est jamais
créé. Si le support est débranché, Orion affiche « Emplacement introuvable » au
lieu de proposer un second domaine. Un réglage d'emplacement illisible s'affiche
comme une erreur, avec « Changer… » et « Emplacement par défaut » pour en sortir.
**Sauvegardez-le.** Le perdre entièrement, c'est perdre le domaine ;
il est déjà chiffré, donc une copie hors ligne ne coûte rien.

Le relais, à côté, ne contient que du public. Orion (« Domaine », « Modifier »)
ou `astra-signer domain` l'écrit sans clé de sécurité ; la clé WireGuard et le
nom de service de la gateway ne se remplissent que s'ils sont vides.

Une valeur à y enregistrer une fois pour toutes : l'origine que le domaine
déclare.

```sh
astra-signer domain --astra-authority-url https://astra.exemple
```

Toute demande de signature nomme cette origine, et le compagnon compare les
deux au lieu de croire celle qu'on lui envoie. Sur le canal public, l'URL
composée jouait ce rôle ; dans le tunnel aucune URL n'est composée, donc une
campagne portée par le tunnel s'arrête tant que cette valeur manque — en
nommant cette commande.

Quand la seconde clé est en main, Orion propose « Ajouter une clé » (libellé,
rôle), « Renommer », « Marquer perdue » / « Réactiver » et « Retirer ». Le
retrait ouvre le coffre avec une autre clé que celle retirée : la clé retirée
n'est pas demandée pour ce geste (en présenter une autre ; comportement de
Windows non vérifié, à constater en recette), et le coffre garde au
moins deux clés. Une clé que le document de credentials révoque déjà (retrait
interrompu entre le document et le coffre) ne se marque plus : refaire le
retrait. Équivalent en ligne de commande :

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
3. `heliosd show-identity` : nom de serveur et clé WireGuard, lus dans la
   demande d'amorçage vérifiée tant que la leaf n'existe pas, puis dans la leaf
   servie ; si le registre gateway est absent et la réponse opérateur aussi,
   le script rapatrie la demande et s'arrête avant l'amorçage d'Astra ;
4. envoie les sources par `git archive HEAD` et construit l'image **sur la
   gateway** — ce qui part est donc ce qui est commité, jamais l'arbre de
   travail. Y compris le trousseau éditeur *public*, sans lequel `aether/build.rs`
   refuse la compilation `--release` de l'image. La construction tourne dans
   une unité systemd transitoire : une coupure SSH n'annule pas BuildKit, et le
   script se reconnecte pour lire son résultat et son journal ;
5. à la reprise, la leaf publique issue de
   `astra-signer issue-gateway-bootstrap` est copiée sur la gateway ; si le
   domaine n'est pas amorcé : `astra bootstrap`, capture de la clé de service
   et de la tête d'audit, écriture du `.env` distant, puis
   `heliosd init-trust-domain --gateway-certificate ...` — qui vérifie la
   signature `CA-PQ` et refuse une auto-signature — puis `systemctl restart
   heliosd` ;
6. l'ancre TLS cliente est épinglée par son empreinte, sans laquelle la
   rotation du §9.4 reste invérifiable ici et se refuse par son nom. Elle ne
   se retape pas : le relais porte déjà le certificat public
   (`ca_tls_certificate`) dès qu'`astra-signer issue-ca-tls` a tourné, et le
   script en calcule le SHA-256. Sur un domaine neuf, l'empreinte est passée à
   `astra bootstrap` ; sur un domaine déjà amorcé, elle passe par
   `astra pin-ca-tls`, qui l'enregistre une fois et refuse d'en remplacer une.
   Cet épinglage étend la chaîne d'audit, donc les deux témoins qui en portent
   la tête — le `.env` de compose et `~/.helios/astra/audit-head` — sont
   réécrits après lui, jamais avant. Un relais sans CA TLS ne bloque rien :
   l'étape le dit et continue. Si le registre gateway existe déjà dans la
   forme erronée produite avant `init-trust-domain --client-tls-ca`, le script
   arrête `heliosd`, remplace atomiquement la CA opérateur par la CA-TLS du
   relais et redémarre le service. Cette correction conserve les pairs et les
   distributions signées en attente, mais refuse tout registre qui a quitté
   l'époque et les générations initiales ;
7. `compose up -d`.

Le contexte `~/astra-build` est jetable et remplacé à chaque déploiement. Le
témoin durable passé à `--expected-audit-head` vit donc hors de ce contexte,
dans `/var/lib/helios/astra-compose.env`. Sur une reprise, `deploy.sh` relit la
tête du volume et la compare au témoin opérateur `~/.helios/astra/audit-head`.
Le témoin doit encore apparaître dans la chaîne. Le suffixe peut contenir les
événements de cycle de vie d'un pair qui n'élargissent pas les pouvoirs de
l'autorité — admission transcrite, demande, staging, récupération et adoption
de génération. Une décision de configuration postérieure au témoin (politique,
délégation, rotation d'ancre, campagne approuvée ou révocation) est refusée et
demande l'enregistrement explicite d'une nouvelle tête.

Après une panne limitée à cette étape, la reprise ne relivre ni les binaires ni
la configuration de la gateway :

```bash
./scripts/deploy.sh --astra
```

L'URL d'autorité vaut `https://<rp_id>` par défaut ; `ASTRA_AUTHORITY_URL` la
remplace. Elle sert à la récupération et au statut authentifié quand WireGuard
ne peut plus être monté, ainsi qu'aux opérations opérateur hors tunnel, pas au
renouvellement ordinaire. Le veth utilise deux adresses IP statiques locales à
la gateway, absentes du DNS et des profils Orion. Ses **deux** sens sont
livrés : Astra appelle `10.88.7.1:8444` pour poser un candidat et relire un
reçu, la gateway appelle `10.88.7.2:8445` pour relayer le renouvellement d'un
client (§8.1.2). Chaque moitié est indépendante — absente, elle est journalisée
et l'autre continue ; sans la seconde, la gateway répond `503` à chaque
renouvellement client.

**L'origine publique** est la seule chose qu'`astra run` ne termine pas
lui-même : il sert du HTTP clair sur `127.0.0.1:8443` et attend un terminateur
TLS devant lui (ADR-008 §2). Ni `compose.yaml` ni le ruleset atomique de
`helios-firewall` n'en installent un, et aucune règle `input` n'ouvre le port
sur le WAN.

Quand l'origine du domaine est un nom `*.ts.net`, `deploy.sh` la monte tout
seul : il vérifie que ce nom est bien celui du nœud, refuse de continuer si
Funnel est configuré — ce qui exposerait l'autorité sur l'Internet public —,
pose `tailscale serve --bg --https=443 http://127.0.0.1:8443`, puis vérifie
d'une vraie requête `POST /v1/client-rotation/challenge`, la première que fait
§7.5. Le certificat est celui du tailnet, publiquement reconnu et renouvelé
sans intervention ; l'écoute appartient à `tailscaled`, donc rien n'est ajouté
au pare-feu applicatif et le contrôle d'accès est celui des ACL du tailnet.

Pour toute autre origine, le terminateur reste à la charge de l'opérateur, et
tant qu'il n'est pas posé la récupération d'une identité expirée (§7.5), le
statut authentifié hors tunnel et les trois routes compagnon du §8.2 restent
injoignables depuis une autre machine. Le renouvellement ordinaire, qui passe
par le tunnel et le veth, n'en dépend jamais.

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

Orion le réémet à chaque geste qui déplace la table de key-slots (ajout,
retrait, perdue / réactivée) et l'écrit lors de « Finaliser le domaine ».
« Marquer perdue » et « Réactiver » exigent que le relais nomme la gateway
(sinon il n'y a aucun document à signer). Sur un coffre sans document, l'ajout
et le retrait passent. Mais lorsqu'un document est déjà en place et que le
relais ne nomme plus la gateway, ou que ce document ne se vérifie pas (altéré,
ou signé par une autre ancre), l'ajout, le retrait et le marquage sont refusés
avant tout toucher : « Le relais ne nomme pas encore la gateway, ou le
document de credentials en place ne se vérifie pas : reprendre la gateway
connectée, ou restaurer le document de credentials depuis une sauvegarde. »
Il n'existe aucun chemin dans Orion pour réparer un document illisible :
restaurer `astra-credentials.json` depuis une sauvegarde, à côté du coffre.

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

Copier. Le contexte de compose est celui que `deploy.sh` dépose, et son
`.env` est le témoin durable — les mêmes que toutes les autres commandes de
cette page :

```sh
scp ~/.helios/astra/authority-vault.json cible:/tmp/vault.json
ssh cible "cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
    --env-file /var/lib/helios/astra-compose.env \
    cp /tmp/vault.json astra:/var/lib/astra/authority-vault.json"
ssh cible "cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
    --env-file /var/lib/helios/astra-compose.env restart astra"
ssh cible 'rm -f /tmp/vault.json'
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
#    adressées par époque. Rien n'est installé, rien n'est annoncé. La
#    campagne est déposée dans le même geste, et son identifiant s'affiche.
ssh <gateway> "cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
    --env-file /var/lib/helios/astra-compose.env exec -T astra \
    /usr/local/bin/astra issuer request \
    --reason 'délégation trimestrielle' --requested-by 'prénom.nom'" \
    > delegation-request.json

# 2. sur le poste opérateur, clé branchée : CA-TLS d'abord si le domaine n'en
#    a pas encore, puis la délégation elle-même. Le compagnon récupère la
#    campagne, compare la demande à la matière qu'elle épingle, et redépose la
#    délégation signée.
astra-signer issue-ca-tls
astra-signer authorize-issuer --request delegation-request.json \
    --authority-url https://astra.example --operation-id <identifiant> \
    --days 30 --leaf-days 90

# 3. Astra a enregistré la délégation ; il reste à le redémarrer.
ssh <gateway> "cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
    --env-file /var/lib/helios/astra-compose.env restart astra"
```

La demande sort sur la **sortie standard** — d'où le `>` de l'étape 1 — et
tout le reste, l'identifiant d'opération compris, sur l'erreur standard. Sans
`--reason` ni `--requested-by`, aucune campagne n'est déposée : le compagnon
écrit alors son autorisation avec `--out` et `astra issuer install` la relit
sur l'entrée standard quand `--authorization` est absent. Cette forme de repli
existe pour un domaine dont l'origine publique n'est pas joignable : une
demande de délégation ne porte aucune signature, donc l'opérateur y signe le
fichier qu'on lui présente.

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

**Limite connue** : le jeu d'ancres TLS clientes est construit une fois au
démarrage. Il contient la CA opérateur — nécessaire aux feuilles de première
génération — et les ancres `CA-TLS` que le registre accepte à cet instant. Une
leaf renouvelée chaîne donc vers la CA du domaine via l'intermédiaire qu'Orion
présente. Une rotation `CA-TLS` installée avant `activation_at` demande encore
un redémarrage pendant le chevauchement pour ajouter le successeur au point
d'écoute, puis un autre après le retrait pour en retirer la racine sortante.
La reconstruction automatique du point d'écoute n'est pas câblée : elle ferait
tomber les sessions qui détiennent des slots PSK. Le contrôle applicatif de la
paire TLS/PQ reste, lui, borné par les fenêtres du registre à chaque requête.

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
