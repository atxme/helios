# ADR 006 — Chiffrement des secrets au repos

**Statut** : accepté (2026-07-28), amendé après contre-audit de sécurité
(2026-08-01). L'amendement du 1er août remplace toute garantie plus forte
formulée dans la décision initiale sur l'administrateur local, le malware actif,
la récupération TPM, l'interchangeabilité et le rejeu des blobs.

**Portée** : stockage local des secrets sur le poste Orion et sur la gateway
Helios, hygiène mémoire des deux côtés, et durcissement du service. Ne modifie
ni le protocole de négociation de clé ([ADR-005](ADR-005-NEGOCIATION-DE-CLE.md)),
ni l'enveloppe de signature hybride ([ADR-002](ADR-002-SIGNATURES-PQ.md)), ni la
chaîne de livraison ([ADR-004](ADR-004-CHAINE-DE-LIVRAISON.md)) : cet ADR décrit
comment un secret survit sur un disque et dans une mémoire, une fois qu'il y est
arrivé.

## Contexte

La sécurité **en transit** d'Helios est aboutie : QUIC avec mTLS, authentification
ML-DSA-65, PSK dérivé en ML-KEM-1024, plancher anti-downgrade monotone, épinglage
de certificat. La sécurité **au repos**, elle, n'a jamais fait l'objet d'une
décision — elle est le résultat de choix ponctuels, et l'audit du 28 juillet 2026
montre qu'ils ne tiennent pas ensemble.

### Ce que l'audit a trouvé

Côté Orion, le constat central est une **asymétrie** :

* l'identité de négociation — clé PKCS#8 mTLS et clé ML-DSA-65 — est correctement
  scellée par DPAPI, avec portée utilisateur et entropie de domaine
  (`orion-core/src/identity_store.rs`) ;
* la **clé privée WireGuard** du profil, elle, est écrite **en clair** dans
  `%APPDATA%\helios\orion\profiles.toml` (`ClientConfig::save`,
  `orion-core/src/config.rs:343`) — sérialisation TOML, `std::fs::write`, aucun
  chiffrement, aucun mode de fichier ;
* le PSK statique, quand il est utilisé, subit le même sort.

Autrement dit : **la clé qui monte réellement le tunnel est moins protégée que le
certificat qui sert à la négocier.** Elle ne repose que sur les ACL NTFS. Un
disque volé, une sauvegarde, une image système ou un profil itinérant — `%APPDATA%`
est le dossier *Roaming*, synchronisé sur un serveur en environnement AD —
suffisent à usurper le client.

Côté gateway, le modèle est nettement plus solide : la clé privée WireGuard vit
dans un coffre AES-256-GCM dont la clé est scellée au TPM sur PCR 0/4/7, et
l'expurgation avant écriture est systématique sur les quatre chemins qui appellent
`save()`. Trois manques subsistent :

* les PSK **statiques** des pairs ne passent pas par le coffre ;
* `NetworkConfig::save()` écrit un fichier temporaire selon l'umask puis fait un
  `rename` : le `chmod 600` posé par `scripts/target-bootstrap.sh` est **perdu à
  la première écriture**. Non exploitable en pratique — le répertoire parent est
  en `700` et le contenu écrit est expurgé — mais la défense en profondeur tombe
  silencieusement ;
* aucune hygiène mémoire nulle part. `SecretString` le documente lui-même :
  « This type does not replace `zeroize`: it protects against accidental display,
  not memory remanence. » Les clés privées vivent dans des `String` jamais
  effacés.

### Deux conteneurs, ou zéro

Il existe aujourd'hui **un** conteneur chiffré dans le dépôt (`HKS1`, dans
`helio-tpm/src/keystore.rs`) et **aucun** côté Orion. Ajouter un second format
serait la garantie qu'ils divergent, et qu'une revue portant sur l'un manque le
défaut de l'autre.

## Décision

### 1. AES-256-GCM, et pourquoi ce n'est pas XTS

La question du mode a été posée explicitement. **AES-XTS est écarté**, et l'écart
n'est pas marginal.

XTS est conçu pour le chiffrement de **secteurs disque** : il préserve la
longueur, se positionne par numéro de secteur, et **n'authentifie rien**. C'est un
compromis assumé de BitLocker et de LUKS, où il n'existe pas de place pour stocker
un tag par secteur. Nos secrets sont des fichiers : la contrainte qui justifie XTS
n'existe pas ici, mais ses faiblesses, elles, s'appliquent.

| Propriété | XTS | GCM |
|---|---|---|
| Confidentialité | oui | oui |
| **Intégrité / authenticité** | **non** | oui — tag 128 bits |
| Nonce | aucun (position) | 96 bits, tiré au CSPRNG |
| Séparation de domaine | aucune | AAD |
| Détection d'une altération | **aucune** | déchiffrement refusé |

Sans authentification, un attaquant disposant d'un accès en écriture au fichier
peut corrompre le texte clair sans être détecté. XTS ne donne pas en général le
retournement bit à bit prévisible d'un mode compteur, mais cette nuance ne lui
apporte aucune authenticité : une corruption devient un état non fiable au lieu
d'être un refus propre. Sur une clé privée WireGuard, elle rend l'identité
inutilisable ; sur un champ de configuration, elle rend le comportement du client
non fiable. Une même valeur écrite au même emplacement produit en outre la même
sortie et révèle qu'elle n'a pas changé.

**Décision : AES-256-GCM**, pour trois raisons cumulatives :

1. **AEAD** — un fichier modifié échoue au déchiffrement au lieu de produire une
   clé fausse silencieusement.
2. **AAD** — séparation de domaine et liaison à un objet précis. Elle empêche la
   substitution entre usages et entre profils ; elle ne fournit pas, à elle
   seule, la fraîcheur d'un blob valide.
3. **Moteur unique** — `aws-lc-rs` est déjà la seule dépendance cryptographique du
   dépôt, et porte une feature `fips`. Introduire XTS y ferait entrer un second
   moteur sans contrepartie.

**Règle non négociable** : jamais deux fois le même nonce sous la même clé. Elle
est tenue en tirant un nonce de 96 bits au CSPRNG à **chaque** écriture, et en
ré-enveloppant plutôt qu'en réutilisant.

*Alternative examinée et écartée* : XChaCha20-Poly1305, dont le nonce de 192 bits
rendrait la collision statistiquement impossible. Elle sort d'`aws-lc-rs` et
entamerait la trajectoire FIPS pour un gain que le chiffrage ne justifie pas.

**Chiffrage du risque de collision** (contre-audit du 1er août 2026). Pour un
nonce aléatoire de 96 bits, l'approximation anniversaire
`n ≈ sqrt(2 × 2^96 × p)` donne environ **12,6 milliards** d'invocations pour
`p = 10⁻⁹`, et non 13 millions comme l'indiquait la décision initiale. Le
plafond opérationnel reste volontairement beaucoup plus bas : un même DEK ne doit
jamais dépasser **2³² scellements**, et Helios renouvelle le DEK à chaque écriture.
La conclusion pratique ne change pas — quelques milliers d'écritures sont très
loin de la borne — mais l'argument doit être mathématiquement exact. Un échec du
CSPRNG ou de la dérivation est fatal ; aucun nonce fixe ni compteur réinitialisé
n'est utilisé en repli.

### 2. Un conteneur unique — `crates/helios-vault`

```
HVLT │ ver:u8 │ kdf:u8 │ dom_len:u8 │ ctx_len:u16be
     │ domain │ object_context │ salt[16] │ nonce[12] │ ciphertext ‖ tag[16]

AAD = "helios-vault/v1" ‖ <tout l'en-tête, de HVLT au nonce inclus>
```

L'AAD initial ne couvrait qu'un sous-ensemble de l'en-tête. L'amendement du
1er août couvre **chaque octet** du préfixe, de sorte qu'une modification du sel,
du nonce, de la version, de la KDF, du domaine ou du contexte casse le tag.

`domain` sépare les **usages** ; `object_context` sépare les **instances d'un
même usage**. Les contextes sont canoniques, bornés et construits par des types,
jamais par concaténation ambiguë de chaînes :

| Secret | `domain` | `object_context` obligatoire |
|---|---|---|
| Profil Orion complet | `orion.profile` | `profile_id`, clé publique cliente, clé publique gateway |
| Identité gateway | `helios.gateway.wg-key` | clé publique gateway |
| Table de PSK statiques | `helios.peer.static-psk-map` | identifiant gateway et empreinte canonique de la table des clés publiques |
| Identité de négociation | `helios.key-negotiation.identity` | clé publique gateway et époque de certificat |

`profile_id` est un identifiant aléatoire de 128 bits créé une fois, immuable et
distinct du nom d'affichage. Après ouverture, Orion redérive la clé publique
cliente depuis la clé privée et la compare au contexte avant tout réseau. La
gateway vérifie de même que chaque PSK est indexé par la clé publique exacte du
pair. Un blob d'Alice ne peut donc pas être ouvert comme celui de Bob, même si les
deux utilisent la même clé racine.

Le contenu chiffré d'un profil Orion est un **manifeste de sécurité atomique**,
pas seulement ses deux secrets. Il porte la clé privée, le PSK statique éventuel,
la clé publique gateway, les endpoints, `allowed_ips`, l'adresse, les CA et
certificats épinglés, l'identité de négociation, le mode et le plancher
anti-downgrade.

Un **registre Orion chiffré et authentifié** associe chaque `profile_id` à ses
clés publiques attendues, son manifeste, son nom d'affichage et la sélection
courante. Le bootstrap extérieur ne contient que version de format, key-slot TPM
et chemins de blobs. Un contexte n'est jamais validé contre une valeur provenant
du même enregistrement non authentifié : il est comparé au registre ouvert sous
la racine d'installation. Échanger un blob seul ou un enregistrement complet avec
son identifiant échoue donc ; rejouer ensemble un ancien registre et tous ses
blobs reste le rollback global déclaré plus bas. Altérer endpoint, CA, plancher,
nom ou sélection sans connaître la clé devient impossible.

Le conteneur garantit authenticité et contexte, **pas la fraîcheur d'une ancienne
valeur authentique**. Chaque manifeste porte une `security_generation` strictement
croissante lors d'une rotation de clé, d'un changement de PSK, d'ancre de confiance
ou de plancher. Orion et Helios refusent une génération inférieure à celle déjà
observée pendant l'exécution, et la gateway conserve son plancher indépendant.
Une détection durable après restauration simultanée de tous les fichiers exige un
compteur non restaurable. Le choix entre fichier protégé et NV TPM reste celui de
l'amendement 2 d'ADR-002 : tant qu'il n'est pas arbitré, **aucune résistance au
rollback hors ligne complet n'est revendiquée**. Cette limite ne peut jamais
justifier un downgrade : dans le doute, la connexion échoue.

Le lecteur de fichier vérifie la taille **avant** d'allouer le blob : métadonnée
bornée puis lecture limitée à `MAX_VAULT_BYTES + 1`. Vérifier seulement dans
`open(&[u8])`, après un `std::fs::read`, ne satisfait pas cette règle. `seal()`
refuse aussi de produire un blob qui dépasserait la borne. Toute longueur est
validée avant indexation ou allocation ; une version, une KDF ou un encodage de
contexte inconnus sont refusés.

`helio-tpm::keystore` devient un client de ce crate, en conservant une lecture
compatible de `HKS1` : une gateway en production ne doit pas perdre son identité
en se mettant à jour. `HKS1` reste lecture seule et est réécrit en `HVLT` après
une ouverture réussie et vérifiée.

### 3. Orion — hiérarchie de clés

```
                    CSPRNG
                      │
                      ▼
            device_root_key[32]
                      │
         enveloppe TPM obligatoire
       RSA-OAEP-SHA-256, clé non exportable
                      │
                      ▼
       DPAPI-utilisateur(blob_TPM + métadonnées)

registre : HKDF(device_root_key, info = "orion/registry/v1")
profil   : profile_root_key = HKDF(device_root_key,
                                   salt = profile_id,
                                   info = "orion/profile-root/v1")

service : IKM = profile_root_key
nomade  : IKM = profile_root_key ‖ passphrase_key[32]
                      │
    HKDF-SHA-256(salt frais, info = domaine + contexte)
                      │
                      ▼
              DEK AES-256-GCM
```

La hiérarchie est une conjonction, jamais une liste de voies de récupération :

1. `device_root_key` est tirée une fois par installation au CSPRNG. Les clés de
   registre et de profil sont dérivées avec des `info` distincts ; connaître un
   DEK de profil ne permet pas de calculer la racine, le registre ou un autre
   profil.
2. Une clé asymétrique non exportable est créée dans le *Microsoft Platform
   Crypto Provider*. Orion vérifie le fournisseur, la non-exportabilité, l'ACL
   utilisateur et le résultat de l'opération avant de persister quoi que ce soit.
   Le minimum est RSA-3072 avec OAEP-SHA-256 ; un TPM qui ne le porte pas est
   refusé plutôt que ramené silencieusement à RSA-2048 ou au fournisseur logiciel.
3. Le blob TPM et ses métadonnées publiques sont protégés par DPAPI en portée
   utilisateur avec une entropie de domaine constante. DPAPI lie l'accès au
   compte ; il **ne contient jamais une seconde enveloppe de la clé racine**.
   Détenir la clé de sauvegarde DPAPI d'un domaine ne suffit donc pas sans le TPM.
4. Une écriture tire un sel frais et dérive son DEK par HKDF-SHA-256. Les DEK
   sont indépendants avec une probabilité écrasante ; cette défense supplémentaire
   ne relâche jamais l'obligation d'un nonce GCM unique sous une même clé.

Cette définition ferme l'ambiguïté de la décision initiale : **DPAPI ne récupère
pas un TPM perdu**. Si le TPM est réinitialisé, remplacé ou rendu illisible par un
firmware, la racine d'installation est perdue et les profils doivent être
ré-enrôlés. Une enveloppe
DPAPI alternative aurait annulé la liaison matérielle ; elle est donc interdite
dans les profils normaux.

Pour le profil `nomade`, `passphrase_key` est dérivée par
PBKDF2-HMAC-SHA-512 avec **600 000 itérations** et un sel aléatoire de 128 bits.
OWASP publie un repère inférieur pour SHA-512 ; Helios conserve volontairement
600 000 parce que le déverrouillage n'a lieu qu'une fois par session. Ce choix
augmente le coût de chaque essai par rapport à ce repère, mais il n'est pas
justifié par l'affirmation simpliste que « 512 bits est automatiquement plus sûr
que 256 » : la résistance dépend ici de l'entropie de la passphrase, du PRF, de
la longueur de sortie et surtout du coût mesuré. La régression Windows vérifie
que 600 000 reste sous deux secondes sur le matériel minimal supporté ; le coût ne
peut pas être abaissé sous le même identifiant.

Les identifiants de KDF effectivement servis sont `0` (clé brute, déjà détenue
par l'appelant) et `2` (PBKDF2-HMAC-SHA-512, 600 000). L'identifiant **`1` est
brûlé** : il a désigné brièvement PBKDF2-HMAC-SHA-256 dans une révision non
livrée, et il est désormais refusé avec un message qui le dit. Le réutiliser
aurait été techniquement sans risque — aucun coffre passphrase n'a jamais été
persisté — mais aurait fait désigner deux algorithmes différents par un même
identifiant selon la version du binaire, c'est-à-dire exactement ce que l'octet
`kdf` existe pour empêcher. Brûler coûte un entier.

L'identifiant de KDF encode l'algorithme et tous ses paramètres : relever ou
modifier le coût crée un nouvel identifiant et permet de ré-envelopper après une
ouverture réussie sans rendre les anciens profils illisibles. Le sel de
passphrase et ces paramètres vivent dans le key-slot extérieur authentifié ; le
sel de dérivation du DEK reste propre à chaque HVLT.

PBKDF2 reste moins résistant aux GPU qu'Argon2id. Il est conservé pour la
trajectoire FIPS et le moteur cryptographique unique, mais le choix est réversible
grâce au champ `kdf` versionné. La passphrase `nomade` doit compter au moins
20 caractères ou cinq mots tirés aléatoirement, accepter au moins 128 caractères,
les espaces, Unicode normalisé et le collage depuis un gestionnaire ; une valeur
commune ou compromise est refusée. Une simple règle de complexité visuelle ne
remplace pas cette exigence d'entropie.

Deux profils d'exploitation subsistent, parce que connexion automatique et
facteur mémoriel s'excluent :

| Profil | Déverrouillage | Connexion auto | Cible |
|---|---|---|---|
| `service` | DPAPI extérieur → TPM obligatoire | oui | poste fixe, tunnel permanent |
| `nomade` | DPAPI extérieur → TPM obligatoire **et** passphrase | non, saisie au lancement et après reprise | portable, données sensibles |

Le choix est **par profil**, explicite, et affiché dans l'IHM. Aucun défaut caché.

Le profil `nomade` empêche un portable volé et éteint d'ouvrir automatiquement le
tunnel tant que la passphrase reste inconnue. Il ne résiste pas à un malware, un
enregistreur de frappe ou un administrateur actif au moment de la saisie. À la
veille, l'hibernation, le verrouillage de session et la fermeture d'Orion, le
tunnel est fermé, les tampons sont effacés et la passphrase est redemandée.

**Aucun repli silencieux.** TPM absent → Orion refuse, exactement comme `heliosd`
refuse un backend noyau absent hors `--dev`, et comme `identity_store` refuse déjà
d'écrire en clair hors Windows.

Le contournement pour une flotte sans TPM prend la forme d'un drapeau de
configuration locale au nom délibérément désagréable :

```toml
danger_allow_software_keystore = true
```

Dans ce mode seulement, DPAPI enveloppe directement `device_root_key`. Le mode
est une **dégradation**, pas une récupération, et engage quatre conséquences
visibles :

1. un avertissement **persistant** dans l'IHM Orion — « Sécurité matérielle
   désactivée » — dans le panneau de posture, pas une notification qui s'efface ;
2. un journal système de niveau `WARN` **à chaque démarrage**, pas seulement à
   l'activation ;
3. la ligne correspondante dans le panneau de posture passe de « scellés au TPM »
   à « scellés au compte uniquement » ;
4. la résistance à la copie inter-machine, au rollback matériel et à un
   administrateur de domaine détenant les clés de sauvegarde DPAPI n'est plus
   revendiquée.

Le nom du drapeau fait partie de la décision : il doit être impossible de
l'activer par distraction, et embarrassant de le laisser en place.

**Migration.** Une clé déjà écrite en clair est présumée compromise : elle peut
subsister dans un profil itinérant, une sauvegarde ou une image système. Chiffrer
la même clé n'annule pas ces copies. Au premier lancement :

1. Orion détecte le format historique et bloque la connexion automatique.
2. Il crée et vérifie le coffre, y place provisoirement l'ancien profil pour ne
   pas prolonger l'exposition, crée le registre authentifié, puis remplace le TOML
   par un bootstrap sans secret de façon atomique.
3. Le profil reste marqué « rotation obligatoire » et ne devient connectable
   qu'après génération d'une nouvelle clé WireGuard, réadmission de sa clé
   publique et rotation du PSK statique éventuel.
4. Chaque étape est idempotente et journalisée sans secret. Une coupure laisse
   soit l'ancien fichier intact et non connectable, soit le nouveau coffre
   vérifiable ; jamais un profil partiellement migré présenté comme sain.

La migration fait `fsync` du coffre, le rouvre et vérifie clé publique, contexte
et génération avant de publier le registre et le bootstrap expurgé. La rotation,
pas la suppression, est ce qui révoque les anciennes copies.

**Il n'y a pas d'effacement sûr à ce niveau, et l'ADR ne prétend pas le
contraire.** Réécrire sur place est **inopérant** sur un support moderne : le
contrôleur du SSD gère la répartition de l'usure via sa *Flash Translation Layer*,
et une réécriture logique n'atteint pas les blocs NAND physiques. Les octets en
clair subsistent sur les puces jusqu'au passage du ramasse-miettes, et restent
récupérables par analyse forensique matérielle (*chip-off*). Toute astuce d'écriture
serait ici une fausse promesse.

**Conséquence assumée** : le chiffrement applicatif ne couvre ni les anciens blocs
SSD ni toutes les copies du pagefile et de l'hibernation. Le **chiffrement de
volume** — BitLocker sous Windows, dm-crypt sous Linux — est vérifié par
l'installateur et au démarrage sur le volume qui porte profils, pagefile et
hibernation. Orion refuse import, migration et connexion automatique si cette
posture est absente ou indéterminable. La documentation seule ne suffit pas à un
prérequis qualifié d'absolu.

### 4. Helios — combler les trois manques

Les PSK **négociés** restent exclusivement en mémoire. Les PSK **statiques** sont
persistés dans une table chiffrée qui associe chaque valeur à la clé publique
exacte du pair ; `network.toml` n'en contient jamais.

Le secret TPM général change après certains changements de PCR. Chiffrer la table
de PSK directement sous ce secret la rendrait alors irrécupérable, tandis que
l'escrow actuel ne restaure que l'identité WireGuard. La clé de la table est donc
dérivée par HKDF-SHA-256 depuis les 32 octets de la clé privée WireGuard gateway,
avec sel frais et `info = "helios/static-psk-map/v1"`. Cette identité est déjà
protégée par le TPM et couverte par l'escrow existant : la table survit au
resealing si et seulement si l'identité survit ou est restaurée. Compromettre
l'identité gateway compromet déjà l'authentification de tous les tunnels ; cette
dérivation avec séparation de domaine n'élargit donc pas le niveau de compromis.

Une rotation volontaire de l'identité gateway déchiffre la table sous l'ancienne
identité, la ré-enveloppe sous la nouvelle et vérifie le résultat **avant** de
publier la nouvelle clé publique. Si l'ancienne identité n'est ni ouvrable ni
récupérable, les PSK statiques sont déclarés perdus et les pairs concernés sont
désactivés jusqu'à rotation ; aucun démarrage sans PSK ni retour au mode classique
n'est autorisé.

`NetworkConfig::save()`, `ClientConfig::save()` et tous les coffres utilisent le
même écrivain atomique : fichier temporaire unique créé avec `create_new`, mode
**0600 avant le premier octet**, `write_all`, `sync_all`, `rename`, puis `fsync`
du répertoire parent. Un nom temporaire prévisible partagé par deux écritures est
interdit. Le répertoire parent est 0700 et les liens symboliques sont refusés.

`UMask=0077` dans `heliosd.service` couvre à la source toute nouvelle écriture,
mais ne remplace pas les modes explicites ni les vérifications après installation.

### 5. Hygiène mémoire, des deux côtés

`Zeroize` ne répare pas les copies déjà produites. La règle porte donc d'abord sur
les **types et les flux**, puis sur `Drop` :

* un type secret ne dérive jamais `Clone`, `Serialize`, `Display` ou un `Debug`
  révélateur ; les copies nécessaires sont des opérations nommées et revues ;
* `SecretString` possède `Zeroize` et `ZeroizeOnDrop`, mais les clés binaires sont
  conservées en `[u8; 32]` plutôt qu'en base64 `String` dès que le parsing est fini ;
* les tampons de déchiffrement sont `Zeroizing<Vec<u8>>` **avant** l'appel AEAD.
  `open_in_place` rend le même tampon après retrait du tag : copier le texte clair
  dans un second `Vec` puis abandonner le premier est interdit ;
* aucune sérialisation TOML/JSON ne reçoit un type contenant un secret. Le
  manifeste secret est encodé directement dans un tampon `Zeroizing` borné ;
* la passphrase `nomade` est saisie par une boîte native protégée. Elle ne traverse
  ni le DOM WebView2, ni JavaScript, ni un message Tauri sérialisé ;
* sous Windows, les pages sensibles stables sont verrouillées avec `VirtualLock`,
  protégées avec `CryptProtectMemory` lorsqu'elles sont résidentes mais inutilisées,
  puis effacées avec une primitive que le compilateur ne peut élider ; sous Linux,
  les petits tampons équivalents utilisent `mlock` quand disponible ;
* l'échec de verrouillage mémoire est visible dans la posture. Il est fatal pour
  `nomade`, averti pour `service`, où le chiffrement de volume reste obligatoire.

Durée de vie minimale : ouvrir, valider contexte et génération, installer dans le
plan de données, effacer. La gateway ne conserve plus la clé privée ni les PSK
dans `NetworkConfig` partagé après leur installation ; l'état de relecture à chaud
est expurgé. Le noyau ou WireGuard-NT garde nécessairement le secret installé :
son espace mémoire est une frontière distincte que `zeroize` utilisateur ne peut
pas nettoyer.

`WerRegisterExcludedMemoryBlock` et `CryptProtectMemory` sont des défenses en
profondeur, pas une frontière contre un débogueur, une injection ou un malware du
même compte. L'exclusion WER ne vaut que pour les rapports WER et son échec doit
être journalisé sans adresse ni contenu secret.

### 6. Durcissement du service

L'unité actuelle porte déjà `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, et un `CapabilityBoundingSet` réduit à `CAP_NET_ADMIN CAP_NET_RAW`.
S'y ajoutent : `UMask=0077`, `PrivateTmp`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID`,
`LockPersonality`, `ProtectProc=invisible`, et
`RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX`.

La rémanence de crash est configurée sans valeur vide ambiguë :

```ini
LimitCORE=0
CoredumpFilter=0
KeyringMode=private
```

`CoredumpFilter=` vide conserve la valeur héritée et ne filtre rien de plus ; il
est interdit. Au démarrage, `heliosd` pose aussi `PR_SET_DUMPABLE=0` avant de
charger la première clé. Une erreur est fatale hors `--dev`. `ProtectProc` limite
ce que le service voit dans `/proc` ; il ne protège pas, à lui seul, la mémoire du
service contre root et n'est jamais présenté comme tel.

`ProtectClock`, `RestrictRealtime`, `RestrictNamespaces` et un
`SystemCallFilter` en liste blanche sont activés après une trace sur la cible
Linux réelle. Le filtre conserve les appels réseau, netlink, TPM et fichiers
nécessaires et refuse au minimum montage, chargement de modules, redémarrage,
swap, accès brut et débogage. `systemd-analyze security` et un démarrage avec TPM,
Netlink et WireGuard réels deviennent des contrôles de release ; une compilation
WSL2 ne valide pas ce durcissement.

## Modèle de menace

Le modèle distingue l'accès **hors ligne**, un utilisateur local non privilégié,
un code actif sous le même compte et un administrateur actif. Les confondre
produisait la garantie intenable de la décision initiale.

| # | Menace | Garantie après amendement |
|---|---|---|
| T1 | Disque volé, machine éteinte, volume chiffré | secrets courants protégés par TPM + AEAD ; anciennes copies protégées seulement après rotation |
| T2 | Sauvegarde, image système, profil itinérant AD | confidentialité conservée par la liaison TPM ; restauration ancienne détectée seulement dans les limites anti-rejeu déclarées |
| T3 | Autre utilisateur local non privilégié | protégé par ACL, DPAPI, TPM et AEAD |
| T4 | Copie ou échange de blobs entre machines/profils/pairs | refusé par TPM et `object_context` |
| T5 | Altération d'un blob ou des paramètres de tunnel | refusée par l'AEAD du manifeste complet |
| T6 | Rollback hors ligne du blob et de tout son état | **non résolu sans compteur non restaurable** ; aucun downgrade permis, disponibilité seulement |
| T7 | Crash dump, pagefile, hibernation | fortement réduit par durée de vie, verrouillage mémoire, filtre de dump et chiffrement de volume ; jamais éliminé |
| T8 | Fuite par journaux ou télémétrie | interdite par les types, tests et redaction ; WER reste une défense supplémentaire |
| T9 | Malware actif sous le compte Orion | peut invoquer ou observer le déchiffrement et exfiltrer le secret pendant son usage |
| T10 | Administrateur local/domaine actif, root gateway ou noyau compromis | hors garantie du chiffrement au repos ; contrôle total possible |
| T11 | Perte/réinitialisation TPM | profil Orion perdu et ré-enrôlé ; gateway récupérable seulement par les mécanismes déjà arbitrés |

Sur T9 et T10, le texte est volontairement strict. La non-exportabilité TPM
signifie que la **clé TPM** ne sort pas du matériel ; elle ne rend pas non
exportables le DEK et la clé WireGuard rendus à Orion. Un malware capable de lire
ou injecter le processus au bon instant peut les copier. DPAPI ne protège pas
contre du code exécuté sous le même compte, et les clés de sauvegarde DPAPI du
domaine font partie du pouvoir d'un administrateur de domaine.

Une séparation ultérieure dans un service Windows sous SID distinct réduirait le
risque d'un malware utilisateur ; VBS ou une enclave est nécessaire pour viser un
adversaire noyau. Ces architectures ne sont pas requises par cet amendement et
aucune propriété qui en dépend n'est annoncée aujourd'hui.

## Validation

L'ADR n'est déclaré réalisé que lorsque les familles suivantes passent. Un test de
round-trip seul prouve le fonctionnement, pas la sécurité.

**Conteneur et contexte**

* retourner chaque octet de l'en-tête, du ciphertext et du tag provoque un refus ;
* échanger deux blobs du même domaine mais de `profile_id` ou de pair différents
  provoque un refus ;
* clé privée redérivée, clé publique du contexte et clé admise doivent être égales ;
* entrées tronquées, longueurs mensongères, version/KDF/contexte inconnus et blob
  dépassant la borne sont refusés sans panic ni allocation proportionnelle ;
* le lecteur de fichier, et pas seulement le parseur en mémoire, est éprouvé avec
  un fichier creux supérieur à la borne ;
* `seal()` refuse ce que `open()` ne pourrait pas relire ;
* la compatibilité `HKS1` est testée avec des fixtures créées par la dernière
  version livrée, puis réécrites et relues en `HVLT`.

**Persistance et migration**

* un motif reconnaissable représentant clé, PSK et passphrase est absent du
  coffre, du bootstrap, des fichiers temporaires et des journaux ;
* le manifeste chiffre aussi endpoint, CA, certificats, `allowed_ips`, mode et
  plancher : altérer leur copie extérieure éventuelle ne change jamais la valeur
  utilisée ;
* fichiers 0600 et répertoires 0700 dès leur création ; attaques par lien
  symbolique, temporaire préexistant et deux sauvegardes concurrentes échouent ;
* une injection de panne après chaque écriture, `fsync`, `rename`, réouverture et
  rotation laisse un état ancien ou nouveau cohérent, jamais un mélange ;
* un profil historique ne redevient connectable qu'avec une nouvelle clé admise ;
  la clé qui avait vécu en clair est rejetée après migration.

**TPM et modes d'exploitation — cible Windows réelle**

* la clé est créée dans le *Microsoft Platform Crypto Provider*, vérifiée
  non exportable et inaccessible depuis une autre machine ; un fournisseur
  logiciel ou une propriété non vérifiable provoque un refus ;
* effacement TPM, changement de carte mère et firmware invalidant la clé affichent
  « ré-enrôlement requis », sans enveloppe DPAPI de secours ;
* `service` reconnecte sans passphrase ; `nomade` exige TPM et passphrase au
  lancement et après verrouillage, veille ou hibernation ;
* `danger_allow_software_keystore` est visible à chaque démarrage et un test de
  posture interdit d'afficher « TPM » dans ce mode ;
* BitLocker désactivé ou état indéterminable bloque import, migration et connexion
  automatique.

**Gateway et mémoire — cibles réelles**

* un resealing avec identité récupérée rouvre la table des PSK statiques et
  conserve chaque association à sa clé publique ; sans identité récupérable, les
  pairs statiques restent désactivés ;
* après installation, l'état utilisateur partagé ne contient plus clé privée ni
  PSK ; un arrêt, une déconnexion et une erreur effacent tous les tampons ;
* un crash injecté ne produit pas de core exploitable ; la valeur effective de
  `/proc/<pid>/coredump_filter`, `PR_GET_DUMPABLE` et les paramètres systemd sont
  vérifiés, pas seulement le texte de l'unité ;
* la passphrase n'apparaît dans aucune commande Tauri, charge JSON ni mémoire
  JavaScript instrumentée.

**Rejeu connu**

* restaurer un ancien manifeste valide ne peut ni abaisser le plancher gateway ni
  être interprété comme une configuration plus récente ; sans compteur durable,
  le test documente un refus de connexion ou un déni de service, jamais une
  prétendue détection cryptographique du rollback complet.

Les tests portables, le fuzz et les analyses statiques entrent dans
`scripts/regression.sh`. TPM Windows, WireGuard-NT, BitLocker, dumps Windows,
Netlink, TPM Linux, resealing et installation systemd entrent dans les campagnes
target-only de `docs/testing/TESTING.md`. Une compilation croisée ou WSL2 ne les
remplace pas.

## Limites connues

* **Un malware utilisateur actif peut exfiltrer.** Orion remet nécessairement la
  clé en clair à WireGuard-NT. TPM, DPAPI, `CryptProtectMemory`, verrouillage de
  pages et `zeroize` réduisent le temps et les copies ; ils ne protègent pas le
  moment d'utilisation.
* **Un administrateur actif et un noyau compromis sont hors garantie.** Ils
  peuvent remplacer le binaire, injecter Orion, invoquer CNG sous le compte ou
  lire le secret après déchiffrement. La non-exportabilité ne concerne que la clé
  privée TPM.
* **Le rollback hors ligne complet n'est pas résolu.** GCM authentifie un ancien
  blob valide ; il ne date pas son contenu. L'arbitrage du compteur durable reste
  celui déjà bloqué par l'amendement 2 d'ADR-002. En attendant, aucune baisse de
  plancher n'est acceptée et un doute produit un refus.
* **La liaison TPM n'est ni compilable ni éprouvable depuis WSL2.** Comme pour
  l'épinglage de la socket de négociation, seule une cible croisée valide la
  compilation, et seule une campagne sur le poste Windows valide le comportement —
  voir [docs/testing/TESTING.md](../testing/TESTING.md).
* **Perte du TPM Orion** — réinitialisation, changement de carte mère, effacement
  du propriétaire : le profil devient définitivement illisible et doit être
  ré-enrôlé. DPAPI ne constitue pas une récupération. C'est affiché avant
  activation et dans la posture.
* **Orion Linux et macOS restent sans stockage protégé.** Câbler Secret Service
  (`libsecret`) et le Keychain relève d'un lot distinct ; le refus explicite actuel
  reste le bon comportement en attendant.
* **Le DNS d'un client reste hors tunnel** — limite documentée dans
  `helios-firewall::ruleset`, orthogonale à celle-ci, et qui mérite son propre
  arbitrage.
* **PBKDF2 n'a pas la dureté mémoire d'Argon2id.** Un adversaire disposant de GPU
  ou d'ASIC cassera une passphrase faible plus vite qu'il ne le ferait contre
  Argon2id à coût égal. Le compte d'itérations atténue, il ne compense pas. La
  contre-mesure est ailleurs : exiger une passphrase à forte entropie en profil
  `nomade`, et le dire dans l'IHM.
* **La rémanence sur SSD n'est pas traitée** par le chiffrement applicatif, et ne
  peut pas l'être. Voir §3 : le chiffrement de volume est un prérequis, pas une
  option.
* **Les clés historiques restent compromises jusqu'à rotation.** Effacer ou
  chiffrer l'ancien TOML ne révoque ni sauvegarde ni profil itinérant. La posture
  reste rouge et la connexion bloquée jusqu'à nouvelle admission.
* **VBS n'est pas implémenté.** Un service sous SID distinct serait une première
  réduction contre le malware utilisateur ; VBS est la suite identifiée contre
  un adversaire noyau. Aucune propriété de la présente version n'en dépend.

## Arbitrage consolidé (2026-07-28, amendé le 2026-08-01)

Le contre-audit du 1er août conserve AES-GCM, le refus sans TPM et les deux modes
d'exploitation, mais remplace les justifications ou garanties trop fortes de la
décision initiale.

| # | Question | Décision | Fondement |
|---|---|---|---|
| 1 | GCM ou XChaCha20-Poly1305 | **AES-256-GCM** | calcul corrigé : 12,6 milliards d'invocations pour `p = 10⁻⁹`; DEK renouvelé à chaque écriture, en-tête et contexte entièrement authentifiés |
| 2 | Argon2id ou PBKDF2 | **PBKDF2-HMAC-SHA-512, 600 000** | coût volontairement supérieur au repère OWASP SHA-512, validé sur le matériel minimal ; identifiant de KDF versionné et passphrase forte obligatoire |
| 3 | Contournement du refus sans TPM | **`danger_allow_software_keystore = true`** | mode dégradé DPAPI seul, explicite et visible ; aucune propriété TPM, inter-machine ou administrateur de domaine annoncée |
| 4 | Profil `nomade` sans connexion auto | **Retenu** | TPM et passphrase sont tous deux requis ; reprise de session = nouvelle saisie ; malware présent à la saisie hors garantie |
| 5 | Migration du clair historique | **Coffre immédiat puis rotation obligatoire** | suppression SSD non fiable et anciennes sauvegardes non révocables ; seule une nouvelle clé admise clôt l'exposition |
| 6 | Liaison et intégrité | **Manifeste complet + `object_context`** | empêche échange entre profils/pairs et modification d'endpoint, CA, routes ou plancher |
| 7 | PSK statiques gateway | **Table liée aux pairs, clé dérivée de l'identité gateway** | survit au resealing avec l'identité déjà récupérable ; perte d'identité = pairs désactivés, jamais de fallback |
| 8 | Administrateur et malware actif | **Hors garantie au moment d'usage** | TPM rend sa clé non exportable, pas la clé WireGuard déchiffrée ; modèle de menace corrigé |
| 9 | Rollback complet | **Limite explicite, fail-closed** | AEAD ne fournit pas la fraîcheur ; aucun claim durable avant l'arbitrage anti-rejeu d'ADR-002 |

PBKDF2 ne présuppose pas une exigence CMVP actuelle : il conserve seulement une
trajectoire FIPS sans figer le format. L'identifiant de KDF permet une migration
future vers une autre fonction après ouverture authentifiée ; l'algorithme n'est
donc plus présenté comme un choix irréversible.

## Références de sécurité

* [NIST SP 800-38D — GCM et exigence d'unicité des IV](https://csrc.nist.gov/pubs/sp/800/38/d/final)
* [NIST SP 800-132 — dérivation depuis une passphrase](https://csrc.nist.gov/pubs/sp/800/132/final)
* [OWASP Password Storage Cheat Sheet — paramètres PBKDF2](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [Microsoft — utilisation du TPM par Windows](https://learn.microsoft.com/windows/security/hardware-security/tpm/how-windows-uses-the-tpm)
* [Microsoft — limites de `CryptProtectMemory`](https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory)
* [Microsoft — clés de sauvegarde DPAPI en domaine](https://learn.microsoft.com/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers)
* [systemd.exec — sémantique de `CoredumpFilter`](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
