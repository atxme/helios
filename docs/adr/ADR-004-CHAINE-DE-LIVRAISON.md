# ADR 004 — Chaîne de livraison et cycle de vie des secrets

**Statut** : accepté (2026-07-21)
**Portée** : outillage de production et de développement — naissance de chaque
secret, admission des clients, remise du profil client, fabrication et
installation des artefacts. Ne modifie ni le protocole d’enrôlement (ADR-001),
ni l’enveloppe de signature hybride (ADR-002), ni le flux de mise à jour
applicative (ADR-003) : cet ADR décrit qui produit quoi, avec quel outil.

## Contexte

L’unité de livraison de Helios est aujourd’hui **le dépôt**.
`scripts/setup-target.sh` installe `npm`, `cargo` et la chaîne de compilation
sur la gateway, puis y construit le frontend et le binaire. C’est acceptable
pour une maquette et intenable pour un produit : la cible embarque un
compilateur, l’artefact installé n’est reproductible que par le poste qui l’a
produit, et rien ne distingue une gateway d’un poste de développement.

Le même flou existe sur les secrets. Trois manques sont concrets :

* la clé privée WireGuard de la gateway se crée avec `wg genkey` puis se colle
  **en clair** dans `network.toml` — c’est le dernier endroit où l’identité de
  la gateway existe en clair sur un disque ;
* la paire X25519 de séquestre a du code (`helio_tpm::escrow`) mais **aucun
  outil** ne l’expose : la ligne `escrow_public_key` de `config/network.toml`
  est un commentaire que personne ne peut honorer ;
* l’admission d’un client est une édition manuelle de `[[peers]]`, et le
  document `orion-profile` v1 a un **consommateur** (`orion-core::profile_import`)
  sans **producteur**.

État d’implémentation : la responsabilité de séquestre appartient désormais à
la crate `helios-escrow`, consommée directement par `heliosd` et
`helios`. La référence à `helio_tpm::escrow` ci-dessus décrit l’état qui a
motivé cette décision, pas l’ownership actuel.

## Décision

### 1. Trois rôles, trois outils, un seul humain possible

| Rôle | Outil | Ce qu’il détient |
|---|---|---|
| **Éditeur** | `helios-publisher` | clés de signature Ed25519 + ML-DSA-65, hors ligne |
| **Opérateur** | `helios` | clé privée de séquestre, admission d’un parc, profils clients |
| **Gateway** | `heliosd`, `helios-installer` | sa seule identité WireGuard, scellée au TPM |

Un même humain tient les trois rôles dans un déploiement personnel. Ce que cet
ADR fixe n’est pas un nombre de machines, c’est le **lieu de vie de chaque
secret** : aucun secret d’un rôle ne doit se retrouver dans le périmètre d’un
autre.

### 2. Inventaire des secrets

| Secret | Naît | Vit | Ne doit jamais |
|---|---|---|---|
| Ed25519 + ML-DSA-65 éditeur | poste éditeur, `publisher keygen` | hors ligne / HSM | entrer en CI, sur une gateway, dans le dépôt |
| Trousseau public éditeur | dérivé du précédent | compilé dans `heliosd` et `orion` | — |
| X25519 séquestre, **privée** | poste opérateur, `ctl escrow keygen` | hors ligne, hors gateway | être présente sur la gateway qu’elle secourt |
| X25519 séquestre, **publique** | idem | `network.toml` | — |
| Clé privée WireGuard gateway | **sur la gateway**, `heliosd init-identity` | coffre scellé TPM | être écrite en clair, sortir autrement que chiffrée dans le séquestre |
| Clé privée WireGuard client | poste client (nominal) ou poste opérateur (mode assisté) | profil Orion | transiter par un canal non maîtrisé |
| PSK ML-KEM | dérivé à l’enrôlement | mémoire et plan de données | être persisté sur disque (invariant existant) |

### 3. L’identité WireGuard de la gateway naît sur la gateway

`heliosd init-identity` génère la clé, la scelle immédiatement dans le coffre
TPM, écrit le séquestre si une clé publique d’opérateur est configurée, et
n’affiche que la clé **publique**. La clé privée n’est jamais écrite en clair,
même transitoirement.

Cette commande est nécessairement **locale et privilégiée**. Le chemin distant
`POST /api/gateway/wireguard-key` ne peut pas servir au premier
provisionnement : l’API vit derrière `admin_iface` (`helios0`), donc derrière un
tunnel qui exige déjà une identité de gateway et un pair administrateur admis.
C’est un chemin de **rotation**, pas de bootstrap — la distinction est
structurelle, pas une commodité d’implémentation.

`wg_private_key` dans `network.toml` devient un **repli hérité et déprécié**. Il
reste accepté, avec l’avertissement existant, pour deux raisons : les gateways
déjà installées, et les campagnes automatisées qui fabriquent une configuration
jetable sans TPM. Il n’est plus un chemin d’installation documenté.

### 4. L’admission a deux chemins, et jamais un *read-modify-write*

* **Local** — `heliosd peer add|list|remove`, sur la gateway, avec accès
  console. Sert au bootstrap du premier pair administrateur et au dépannage.
  Sans lui, ADR-003 §3 crée un blocage : aucune mutation distante n’est
  autorisée tant qu’aucun administrateur n’est déclaré.
* **Distant** — `POST /api/peers` et `POST /api/peers/revoke`, mutation ciblée
  côté gateway, sous la même autorisation administrateur que les autres
  mutations. C’est le chemin nominal, exercé par `helios peer`.

**Une route d’ajout ciblée est une exigence de sécurité, pas un confort.**
`GET /api/network` renvoie une vue sciemment expurgée : ni clé privée, ni PSK.
Un outil qui relirait cette vue, y ajouterait un pair et la reposterait sur
`POST /api/network` écraserait la configuration **sans les PSK des autres
pairs**. Or un slot PSK renseigné d’un seul côté fait échouer tous les
handshakes du pair concerné, sans canal de rattrapage : l’opérateur se
couperait lui-même de son parc en croyant ajouter un client.

### 5. La VIP vient de l’IPAM, y compris à l’admission manuelle

`helios_provisioning::ipam::assign_vip` dérive la VIP de la clé publique et
lève les collisions. Les deux chemins d’admission l’utilisent, en présentant la
liste des pairs déjà déclarés comme table de pairs. Une VIP choisie à la main
créerait une seconde vérité, alors que `AllowedIPs` **est** la table de routage
cryptographique de WireGuard : deux pairs ne peuvent pas revendiquer la même.

### 6. Le profil client : deux modes, et le secret ne voyage pas par défaut

* **Invitation** (défaut) — `helios profile emit` produit un document
  `orion-profile` **sans clé privée** : endpoint, clé publique de la gateway,
  paramètres. Orion génère sa propre clé à l’import et affiche la clé publique
  correspondante, que l’opérateur admet. La clé privée du client ne quitte
  jamais le poste client.
* **Assisté** — `--with-private-key`, explicite. L’opérateur génère la paire,
  admet la publique et remet un profil complet. C’est le seul chemin où une clé
  privée client existe hors du poste client ; il est conservé parce qu’un parc
  où l’utilisateur ne peut rien faire existe réellement, et que l’interdire
  ferait refaire la même chose à la main, plus mal.

Le document reste le format v1 déjà lu par `orion-core::profile_import`. Le
champ `private_key` y devient facultatif : c’est ce qui rend le mode invitation
représentable sans inventer un second format.

### 7. Aucun secret ne traverse la CI hébergée

La CI hébergée construit et publie les artefacts gateway **nus** accompagnés de
leurs empreintes. La signature hybride ADR-002 est jouée hors ligne, depuis le
poste éditeur, sur l’artefact exact publié. Cela conserve l’invariant « les
secrets éditeur n’entrent jamais dans le dépôt » sans demander de HSM ni de
signature sans clé.

Le certificat Authenticode Orion suit une frontière distincte : sa clé privée
non exportable vit dans le magasin d'un compte Windows dédié sur un runner
interne. Seul le workflow de release protégé peut adresser ce runner, depuis un
tag protégé ou `main` après approbation ; aucune pull request n'y est exécutée.
Le PFX, son mot de passe et la clé de l'autorité interne ne traversent jamais
GitHub. Le runner signe pendant le bundling Tauri afin que l'exécutable contenu
dans le MSI et l'enveloppe MSI portent tous deux Authenticode.

Le trousseau **public** de l’éditeur n’est pas un secret : c’est l’ancre de
confiance compilée dans le binaire. Il est fourni à la CI en variable de dépôt,
pas en secret, précisément pour que ce fait reste visible ; le job refuse de
démarrer si le contenu fourni ressemble à une clé privée.

### 7 bis. Le bundle est signé, pas seulement le daemon

Un bundle d’installation porte le daemon, l’installateur, l’outil
d’exploitation et les unités systemd. Le manifeste
(`helios-bundle-v1`, domaine distinct de `helios-binary-release-v1`) énumère
**exhaustivement** son contenu : chemin, taille, empreinte SHA-256, bit
d’exécution.

Signer seulement `heliosd` aurait affiché une garantie fausse : l’unité systemd
décide de la ligne de commande du daemon, de ses capabilities et de ses chemins
d’état — elle est aussi sensible que le binaire qu’elle lance. La vérification
est donc symétrique : un fichier modifié, manquant **ou surnuméraire** fait
échouer l’installation, et un fichier signé dont l’installateur ne connaît pas
la destination la fait échouer aussi, plutôt que d’être ignoré.

Le bundle et le manifeste `heliosd` d’une même release partagent leur
`release_sequence` : installer un bundle sème le compteur d’anti-rollback de
l’ADR-003, ce qui interdit d’y appliquer ensuite une mise à jour applicative
plus ancienne.

### 8. Deux chaînes de signature, deux rôles à ne pas confondre

* **Hybride Ed25519 + ML-DSA-65 (ADR-002)** — autorité sur *ce qui est livré*.
  Vérifiée par `heliosd` et `helios-installer` avant toute installation. C’est
  la seule chaîne qui protège la gateway.
* **Authenticode adossé à une autorité interne** — confiance du *chargeur
  Windows* au moment d’installer Orion. Elle ne dit rien du contenu au sens
  Helios et ne remplace pas la première.

L’amorçage de la chaîne interne est circulaire : un installateur ne peut pas
installer la racine qui le rend digne de confiance. La racine est donc
provisionnée **hors bande**, une fois par machine (stratégie de groupe, ou
script d’administration lancé explicitement), avant le premier installateur.

### 9. Les installateurs Orion portent leur plan de données et leurs privilèges

`cargo xtask orion-deps` télécharge l'archive officielle WireGuardNT avec une
empreinte SHA-256 épinglée, puis extrait hors Git les DLL AMD64 et ARM64 sous
les noms exacts ouverts par `defguard_wireguard_rs`. Tauri les place dans les
ressources du bundle ; Orion sélectionne ce répertoire avant d'initialiser le
backend, car une association de fichier peut fournir un autre répertoire
courant.

Le manifeste Windows demande `requireAdministrator`. Le paquet Debian pose
`cap_net_admin=ep` dans son `postinst`. L'association `.orion` passe par
le plugin single-instance et une lecture Rust bornée à 64 Kio ; l'import manuel
et le double-clic partagent le parseur et la reprise de clé privée du profil
local de même nom.

La petite autorité Authenticode interne se crée par une recette OpenSSL hors du
dépôt. La commande de signature Tauri impose un horodatage RFC 3161 avec
`signtool` et échoue s'il manque. Aucun code X.509 n'entre dans
`helios-publisher`, qui conserve exclusivement le rôle ADR-002.

## Conséquences

* Il devient possible de livrer un binaire sans livrer le dépôt : c’est le
  préalable du lot suivant, qui retire la chaîne de compilation de la gateway.
* `helios` change de statut : ce n’était qu’un outil de diagnostic, il
  devient l’outil d’exploitation d’un parc. Il peut détenir la clé privée de
  séquestre — il ne doit donc jamais être exécuté avec cette clé sur la gateway
  qu’elle est censée secourir. Sa présence dans un bundle de gateway reste
  acceptable : le risque tient au lieu de la clé, pas au lieu de l’outil.
* Retirer un pair de l’admission ne révoque rien cryptographiquement : le
  client tombe au prochain handshake. Il n’y a ni CRL, ni liste de révocation.
* Le mode assisté est le seul chemin où une clé privée client existe hors du
  poste client. Il doit rester visible comme tel dans l’IHM et dans les
  journaux.

## Limites connues

* **Pas de rotation automatique des clés éditeur.** Une rotation reste une
  nouvelle époque, compilée dans un firmware, comme le veut ADR-002.
* **Le premier `bootstrap` n’a pas de racine de confiance locale.**
  `helios-installer` vient alors de l’archive qu’il vérifie : la confiance
  repose sur le canal de transport et sur l’empreinte que l’opérateur compare à
  celle publiée. Les installations suivantes sont vérifiées par un installateur
  déjà installé. Ce qui débloquerait : un paquet système signé par une
  distribution, hors périmètre ici.
* **Le bundle n’est pas reproductible bit à bit.** Deux builds du même commit
  produisent des binaires différents (chemins, horodatages du compilateur), donc
  des empreintes différentes. La signature reste vérifiable, mais un tiers ne
  peut pas reconstruire l’artefact pour le confronter. Ce qui débloquerait :
  `--remap-path-prefix`, `SOURCE_DATE_EPOCH` et un conteneur de build figé.
* **Orion s'exécute entièrement en administrateur sous Windows.** Séparer l'IHM
  du plan de données exigerait un service privilégié, un IPC authentifié et une
  politique d'autorisation ; ces trois éléments doivent être conçus et audités
  ensemble. Ce découplage est hors du lot installateurs et constitue ce qui
  débloquerait la suppression de `requireAdministrator` sur l'IHM.
* **Les capabilities Linux peuvent neutraliser `LD_LIBRARY_PATH`.** Le chargeur
  traite un binaire doté de capabilities comme une exécution sécurisée ; une
  distribution dont WebKitGTK dépend d'un chemin dynamique non standard peut
  donc ne plus lancer Orion après `setcap`. La recette cible vérifie ce cas. Si
  une distribution supportée casse, le remplacement prévu est une opération
  réseau médiée par polkit plutôt que l'ajout de chemins de bibliothèques au
  binaire privilégié.
* **La chaîne interne Windows ne couvre pas la réputation SmartScreen.** Un
  fichier téléchargé porteur du *Mark-of-the-Web* peut encore être signalé,
  même signé et même racine installée. Une distribution interne (partage,
  stratégie de groupe) n’est pas concernée. Ce qui débloquerait : un certificat
  EV auprès d’une autorité publique, décision de coût, pas de conception.
* **Aucun de ces chemins n’est prouvé sur WSL2.** Le scellement TPM de
  `init-identity`, le séquestre réel et l’installation d’un bundle sont
  *target-only* : voir [docs/testing/TESTING.md](../testing/TESTING.md).

## Validation

Les tests unitaires couvrent la dérivation de VIP à l’admission, le refus
d’écraser une identité existante, le refus d’un doublon de clé publique, la
préservation des PSK lors d’un ajout de pair, la forme des deux modes de profil
et le rejet d’un profil d’invitation par un client qui exigerait une clé.

La campagne dry-run exerce l’admission distante et l’émission de profil de bout
en bout. Le scellement réel de `init-identity` et l’ouverture d’un séquestre
produit par une vraie gateway appartiennent à la recette matérielle.
