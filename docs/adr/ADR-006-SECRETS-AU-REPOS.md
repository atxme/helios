# ADR 006 — Chiffrement des secrets au repos

**Statut** : accepté (2026-07-28), arbitré en revue de sécurité le même jour
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
peut retourner des bits du texte clair de façon contrôlée, bloc par bloc, sans
jamais être détecté. Sur une clé privée WireGuard, cela ouvre des attaques par clé
corrompue ; sur un champ de configuration, cela permet de manipuler l'état d'un
client. L'absence de nonce fuit en outre le fait qu'un secret n'a pas changé entre
deux écritures.

**Décision : AES-256-GCM**, pour trois raisons cumulatives :

1. **AEAD** — un fichier modifié échoue au déchiffrement au lieu de produire une
   clé fausse silencieusement.
2. **AAD** — séparation de domaine, exactement ce que fait déjà `HKS1` avec
   `b"helios-keystore-v1"`. Un blob ne peut pas être rejoué dans un autre contexte
   du projet.
3. **Moteur unique** — `aws-lc-rs` est déjà la seule dépendance cryptographique du
   dépôt, et porte une feature `fips`. Introduire XTS y ferait entrer un second
   moteur sans contrepartie.

**Règle non négociable** : jamais deux fois le même nonce sous la même clé. Elle
est tenue en tirant un nonce de 96 bits au CSPRNG à **chaque** écriture, et en
ré-enveloppant plutôt qu'en réutilisant.

*Alternative examinée et écartée* : XChaCha20-Poly1305, dont le nonce de 192 bits
rendrait la collision statistiquement impossible. Elle sort d'`aws-lc-rs` et
entamerait la trajectoire FIPS pour un gain que le chiffrage ne justifie pas.

**Chiffrage du risque de collision** (revue de sécurité). Un nonce de 96 bits tiré
aléatoirement est régi par le paradoxe des anniversaires : atteindre une
probabilité de collision de 10⁻⁹ demande environ **13 millions de nonces sous la
même clé**. Un fichier de profil ou de configuration s'écrit à l'enrôlement, aux
rotations de clé et aux modifications de configuration — un volume qui se compte
en **milliers au maximum** sur la durée de vie d'un poste, soit quatre ordres de
grandeur sous le seuil. Le risque est statistiquement inexistant en pratique, et
le moteur cryptographique unique le compense largement.

### 2. Un conteneur unique — `crates/helios-vault`

```
HVLT │ ver:u8 │ kdf:u8 │ dom_len:u8 │ domain │ salt[16] │ nonce[12] │ ciphertext ‖ tag[16]

AAD = "helios-vault/v1" ‖ domain ‖ ver ‖ kdf
```

* `domain` sépare les usages (`orion.profile.wg-key`, `orion.profile.static-psk`,
  `helios.gateway.wg-key`, `helios.peer.static-psk`). Deux secrets ne sont jamais
  interchangeables, même sous la même clé.
* Le parseur est **borné avant toute allocation**, comme `MAX_SEALED_BYTES` le
  fait déjà dans `identity_store.rs` : un fichier corrompu ou substitué ne doit pas
  faire allouer le client aux conditions d'un tiers.
* Une version inconnue est **refusée**, jamais interprétée par défaut — même
  doctrine que le protocole v3 d'ADR-005.

`helio-tpm::keystore` devient un client de ce crate, en conservant une lecture
compatible de `HKS1` : une gateway en production ne doit pas perdre son identité
en se mettant à jour.

### 3. Orion — hiérarchie de clés

```
Secret en clair  (clé privée WireGuard, PSK statique)
      │  AES-256-GCM
      ▼
    DEK  (32 o, CSPRNG, une par profil, re-tirée à chaque écriture)
      │  enveloppée en cascade
      ▼
    KEK ── [1] clé TPM non exportable  (CNG Microsoft Platform Crypto Provider)
        ── [2] DPAPI                   (portée utilisateur + entropie de domaine)
        ── [3] passphrase → PBKDF2-HMAC-SHA512, 600 000 itérations
                                       (mode renforcé, optionnel)
```

**[1] est ce qui élève réellement le niveau.** Une clé créée dans le *Platform
Crypto Provider* vit dans le TPM : elle n'est pas exportable, et déplacer le
fichier sur une autre machine le rend définitivement illisible. C'est la seule
couche qui traite la copie du secret vers une autre machine, et la seule qui borne
une compromission par malware.

**[2] DPAPI en défense en profondeur.** Le code existe et fonctionne. Il couvre
l'indisponibilité du TPM après une mise à jour de firmware et lie au compte.

**[3] PBKDF2-HMAC-SHA512 plutôt qu'Argon2id, et c'est une conséquence d'ADR-002.**
Argon2id est objectivement supérieur contre le cassage hors ligne par GPU ou ASIC,
grâce à sa dureté mémoire — que PBKDF2 n'a pas. Il est pourtant écarté, parce que
la nature du compromis diffère de tout ce que le projet a accepté jusqu'ici :

| | Algorithme | Implémentation | Réversible ? |
|---|---|---|---|
| ML-DSA-65 via `fips204` | **approuvé** (FIPS 204) | non validée CMVP | **oui** — changer d'implémentation |
| Argon2id | **non approuvé** (NIST recommande PBKDF2, SP 800-132) | — | **non** |

[ADR-002](ADR-002-SIGNATURES-PQ.md) a explicitement retenu que la certification
CMVP n'est **pas** un critère d'acceptation, mais tout son arbitrage — prendre
ML-DSA d'un crate pur-Rust plutôt que d'`aws-lc-rs` — visait à « découpler la
racine de confiance de la décision FIPS », c'est-à-dire à **garder la porte
ouverte**. Retenir Argon2id serait le premier choix qui la **ferme
définitivement** : un algorithme non approuvé ne devient pas approuvé en changeant
de bibliothèque.

Le coût de la dureté mémoire perdue est compensé par un compte d'itérations élevé —
**600 000**, le standard OWASP courant pour PBKDF2-HMAC-SHA512 — à réajuster selon
le budget temps-CPU acceptable au déverrouillage, qui n'a lieu qu'une fois par
session en profil `nomade`.

**[3] Deux profils d'exploitation**, parce que sécurité maximale et connexion
automatique s'excluent :

| Profil | Déverrouillage | Connexion auto | Cible |
|---|---|---|---|
| `service` | TPM + DPAPI | oui | poste fixe, tunnel permanent |
| `nomade` | TPM + DPAPI + passphrase | non, saisie au lancement | portable, données sensibles |

Le choix est **par profil**, explicite, et affiché dans l'IHM. Aucun défaut caché.

Ce que le profil `nomade` achète précisément : lier l'ouverture du tunnel à un
secret **purement mémoriel** garantit qu'un portable volé et éteint n'ouvre aucun
accès au SI interne à l'allumage — **même si le TPM et la session Windows sont
compromis**. C'est la seule configuration qui résiste à un adversaire ayant le
matériel entre les mains et tout le temps devant lui.

**Aucun repli silencieux.** TPM absent → Orion refuse, exactement comme `heliosd`
refuse un backend noyau absent hors `--dev`, et comme `identity_store` refuse déjà
d'écrire en clair hors Windows.

Le contournement, nécessaire aux flottes vieillissantes, prend la forme d'un
drapeau de configuration locale au nom délibérément désagréable :

```toml
danger_allow_software_keystore = true
```

Il engage trois conséquences visibles, jamais une seule :

1. un avertissement **persistant** dans l'IHM Orion — « Sécurité matérielle
   désactivée » — dans le panneau de posture, pas une notification qui s'efface ;
2. un journal système de niveau `WARN` **à chaque démarrage**, pas seulement à
   l'activation ;
3. la ligne correspondante dans le panneau de posture passe de « scellés au TPM »
   à « scellés au compte uniquement ».

Le nom du drapeau fait partie de la décision : il doit être impossible de
l'activer par distraction, et embarrassant de le laisser en place.

**Migration.** Au premier lancement, un `profiles.toml` en clair est chiffré, puis
réécrit **sans les secrets**. Le fichier d'origine est supprimé.

**Il n'y a pas d'effacement sûr à ce niveau, et l'ADR ne prétend pas le
contraire.** Réécrire sur place est **inopérant** sur un support moderne : le
contrôleur du SSD gère la répartition de l'usure via sa *Flash Translation Layer*,
et une réécriture logique n'atteint pas les blocs NAND physiques. Les octets en
clair subsistent sur les puces jusqu'au passage du ramasse-miettes, et restent
récupérables par analyse forensique matérielle (*chip-off*). Toute astuce d'écriture
serait ici une fausse promesse.

**Conséquence assumée** : le chiffrement applicatif d'Helios et Orion couvre le vol
logique et l'élévation de privilèges. Le **chiffrement de volume** — BitLocker sous
Windows, dm-crypt sous Linux — reste un **prérequis absolu** pour couvrir la
rémanence matérielle, et doit être documenté comme tel dans le guide
d'installation, pas comme une recommandation optionnelle.

### 4. Helios — combler les trois manques

* Les PSK statiques des pairs entrent dans le coffre, domaine
  `helios.peer.static-psk`.
* `NetworkConfig::save()` et `ClientConfig::save()` posent le mode **0600 sur le
  fichier temporaire, avant le `rename`** — c'est le seul ordre qui ne laisse
  aucune fenêtre.
* `UMask=0077` dans `heliosd.service`, qui corrige la même classe de défaut à la
  source.

### 5. Hygiène mémoire, des deux côtés

* `SecretString` gagne `Zeroize` et `Drop`. Son doc-comment actuel assume de ne pas
  le faire ; ce choix n'est plus tenable maintenant que ces valeurs vivent le temps
  d'une session.
* Tout secret de longue durée passe en `Zeroizing<…>`.
* Durée de vie minimale : charger, poser dans le plan de données, effacer. La clé
  ne reste pas en mémoire entre deux connexions.
* Gateway : `LimitCORE=0` et `CoreDumpFilter` dans l'unité systemd.
* Windows : exclusion des régions sensibles des rapports d'erreur
  (`WerRegisterExcludedMemoryBlock`), et `CryptProtectMemory` sur les fenêtres où
  le secret doit rester résident.

### 6. Durcissement du service

L'unité actuelle porte déjà `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, et un `CapabilityBoundingSet` réduit à `CAP_NET_ADMIN CAP_NET_RAW`.
S'y ajoutent : `UMask=0077`, `PrivateTmp`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectControlGroups`, `RestrictSUIDSGID`,
`LockPersonality`, `ProtectProc=invisible`, et
`RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX`.

## Modèle de menace

C'est ce qui manquait le plus : sans lui, un plan de chiffrement n'est qu'une liste
de courses.

| # | Menace | Avant | Après |
|---|---|---|---|
| T1 | Disque volé, image système, sauvegarde | **échec total** | protégé |
| T2 | Profil itinérant AD synchronisé | **échec total** | protégé |
| T3 | Autre utilisateur local, administrateur du poste | ACL NTFS seule | protégé |
| T4 | Copie du fichier vers une autre machine | **échec total** | protégé (liaison TPM) |
| T5 | Dump mémoire, hibernation, crash dump | échec | fortement réduit |
| T6 | Fuite par journaux ou télémétrie | déjà bon | maintenu et testé |
| T7 | Gateway compromise | déjà bon (ADR-005) | inchangé |
| T8 | **Malware sous le compte utilisateur, Orion en marche** | échec | **réduit, jamais éliminé** |

**Sur T8, il faut être franc.** Orion doit déchiffrer la clé WireGuard pour la
donner au pilote WireGuard-NT. Tout code s'exécutant sous le même compte peut donc,
au minimum, demander au système de déchiffrer à sa place. **Aucun chiffrement au
repos ne corrige cela.** Ce que la liaison TPM apporte est réel mais borné : le
malware peut *utiliser* le secret tant qu'il est présent, il ne peut pas
l'**exfiltrer** pour s'en servir ailleurs ou plus tard. C'est la différence entre
une compromission bornée dans le temps et une clé volée définitivement.

Ce que la revue a précisé sur ce point :

* `CryptProtectMemory` **réduit considérablement la fenêtre d'exposition** en
  mémoire, sans la fermer. C'est retenu pour cette version (§5).
* La seule parade réelle contre un dump mémoire par un attaquant disposant des
  droits de l'utilisateur serait d'isoler le déchiffrement dans une **enclave VBS**
  (*Virtualization-Based Security*), où le secret n'est jamais adressable depuis
  l'espace utilisateur normal. C'est **hors périmètre de cette version**, et
  consigné ici comme la suite naturelle si le niveau exigé monte encore.

## Validation

Cet ADR n'est pas tenable sans les tests qui l'accompagnent, et ces tests n'existent
pas aujourd'hui.

* **« Aucun secret sur le disque »** — écrire un profil dont la clé est un motif
  reconnaissable, sauvegarder, puis **scanner les octets du fichier produit** et
  échouer si le motif s'y trouve. Simple, et il attrape toute régression future, y
  compris un champ ajouté par mégarde. Même test pour `network.toml`.
* **Mode de fichier** — après `save()`, le mode doit être 0600.
  `tools/helios-ctl/src/files.rs` porte déjà exactement ce test
  (`a_secret_is_born_unreadable_by_others`) ; il faut le généraliser.
* **Fuzz du parseur `HVLT`** — entrées tronquées, tag altéré, domaine substitué,
  version inconnue, longueur de domaine mensongère.
* **Compatibilité `HKS1`** — un coffre gateway existant reste lisible après
  migration.
* Le tout entre dans `scripts/regression.sh`.

**Ordre d'exécution recommandé** : durcissement immédiat (§4, §6) → tests de
validation → `helios-vault` → chiffrement Orion → hygiène mémoire → liaison TPM.

Les tests remontent volontairement **avant** le chiffrement : écrire le test
« aucun secret sur le disque » d'abord donne un test qui échoue tout de suite, pour
la bonne raison, et qui passe au vert quand le chiffrement atterrit. C'est la seule
façon de vérifier qu'il fait ce qu'on croit.

## Limites connues

* **T8 n'est pas résolu**, et ne peut pas l'être tant qu'Orion doit remettre une
  clé en clair au pilote WireGuard-NT.
* **La liaison TPM n'est ni compilable ni éprouvable depuis WSL2.** Comme pour
  l'épinglage de la socket de négociation, seule une cible croisée valide la
  compilation, et seule une campagne sur le poste Windows valide le comportement —
  voir [docs/testing/TESTING.md](../testing/TESTING.md).
* **Perte du TPM** — réinitialisation, changement de carte mère, effacement du
  propriétaire : le profil devient définitivement illisible et doit être réimporté
  depuis le fichier d'enrôlement. C'est le comportement correct, et il doit être
  **dit à l'utilisateur avant** qu'il ne le découvre.
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
* **T8 reste ouvert** au-delà de `CryptProtectMemory` ; l'enclave VBS est la suite
  identifiée, hors périmètre de cette version.

## Arbitrage de la revue de sécurité (2026-07-28)

Les cinq points soumis ont été tranchés. Ils sont consignés ici avec leur
justification, pour qu'une revue ultérieure ne les rouvre pas sans motif nouveau.

| # | Question | Décision | Fondement |
|---|---|---|---|
| 1 | GCM ou XChaCha20-Poly1305 | **AES-256-GCM** | 13 M de nonces pour une collision à 10⁻⁹, contre des milliers d'écritures réelles : quatre ordres de grandeur de marge. Moteur unique conservé |
| 2 | Argon2id ou PBKDF2 | **PBKDF2-HMAC-SHA512, 600 000 itérations** | Argon2id est un algorithme **non approuvé**, donc le premier choix irréversible pour FIPS, là où `fips204` ne fait que différer la validation d'un algorithme approuvé. Contraire à la stratégie d'ADR-002 |
| 3 | Contournement du refus sans TPM | **`danger_allow_software_keystore = true`** | Fail-closed conservé. Repli explicite, avertissement IHM persistant et `WARN` à chaque démarrage : débloque les flottes vieillissantes sans fausse promesse de sécurité matérielle |
| 4 | Profil `nomade` sans connexion auto | **Retenu** | Un secret purement mémoriel est la seule chose qu'un portable volé et éteint ne livre pas, TPM et session Windows compromis inclus |
| 5 | Migration destructrice sur SSD | **Abandonnée — remplacée par un prérequis** | L'écrasement sur place est inopérant derrière une *Flash Translation Layer*. Chiffrement de volume (BitLocker / dm-crypt) exigé et documenté |

Le point 2 mérite une note : la question était posée sous condition (« si FIPS 140-3
est un prérequis »). La condition est **déjà tranchée dans le dépôt** — ADR-002
écarte la certification CMVP comme critère d'acceptation, mais organise tout son
choix de bibliothèques pour ne pas la rendre impossible. Retenir PBKDF2 ne
présuppose donc pas que FIPS soit exigé : cela évite seulement d'être le premier
choix à le rendre inatteignable.
