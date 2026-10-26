# Conception — séparation des privilèges d'Orion sous Windows (F11)

Statut : conception, 24 octobre 2026. Feuille de route : F11, décision D10.
Sources : [ADR-004 « Limites connues »](../../adr/ADR-004-CHAINE-DE-LIVRAISON.md),
[ADR-008](../../adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md),
`apps/orion/src-tauri/src/deelevate.rs`, `tools/helios-astra-helper`.

## 1. Intention

Aujourd'hui, Orion tourne **entièrement** en administrateur sous Windows : le
manifeste demande `requireAdministrator`, parce que WireGuard-NT ne se charge
pas autrement. Tout ce qu'Orion contient tourne donc élevé : l'IHM Tauri,
WebView2, le coffre, la négociation de clé, les clés privées.

Deux conséquences en découlent :

- l'API WebAuthn de Windows ne répond qu'à un processus d'intégrité moyenne
  dans la session de l'utilisateur. Les cérémonies YubiKey passent donc par un
  second binaire, `helios-astra-helper`, lancé désélevé ;
- le terminal SSH, lui aussi, doit être désélevé à la main (`deelevate.rs`),
  sans quoi un clic donnerait un shell administrateur.

F11 sépare Orion en deux processus du **même binaire** : un **moteur** élevé
qui porte le tunnel et les secrets, et une **IHM** non élevée qui affiche,
commande et porte les cérémonies WebAuthn. L'utilisateur l'a retenu le 24
octobre 2026 comme la voie la plus stable et la plus sûre, de préférence à une
relance d'Orion en mode compagnon (D10).

## 2. Ce que l'utilisateur voit

Rien ne change dans l'usage, et c'est une exigence :

1. il ouvre Orion à la main ; l'UAC apparaît, comme aujourd'hui ;
2. la fenêtre et l'icône de la zone de notification apparaissent. C'est **une
   seule application** qui se charge, **sans relance visible** : aucune
   seconde fenêtre, aucun clignotement, aucun second UAC ;
3. fermer la fenêtre laisse le tunnel monté ; l'icône permet de la rouvrir ;
4. « Quitter » fait tomber le tunnel et arrête tout ;
5. rien ne tourne avant l'ouverture de session.

## 3. Objectifs

- **Un seul binaire** : `orion.exe` sert de moteur et d'IHM selon son mode de
  lancement. Règle posée le 24 octobre 2026 : côté poste, aucun binaire livré à
  part d'Orion.
- **L'IHM n'est plus élevée** : ni WebView2, ni le code Tauri, ni les commandes
  ne tournent en administrateur.
- **Les secrets restent dans le moteur, en mémoire comme sur disque.**
  Windows interdit à un processus d'intégrité moyenne de lire la mémoire d'un
  processus élevé ou d'y injecter du code. Le coffre sur disque, lui, n'est
  plus ouvrable que par un processus élevé (§7 bis). Un logiciel malveillant
  qui tourne sous le compte de l'utilisateur, sans élévation, ne peut donc plus
  obtenir la clé privée WireGuard, les clés PQ, le PSK ni la racine du coffre,
  ni en lisant le moteur ni en déchiffrant les fichiers. C'est le gain de
  sécurité de F11.
- **Suppression de `helios-astra-helper`** : l'IHM non élevée parle à WebAuthn
  directement. Le binaire, son entrée `externalBin` et son lanceur
  disparaissent.
- **Suppression de la désélévation** : l'IHM n'étant plus élevée, le terminal
  SSH se lance par un `CreateProcess` ordinaire. `deelevate.rs` disparaît.
- **Moteur et IHM sont liés** : aucun ne survit à l'autre, aucun résidu ne
  reste (§6).

## 4. Non-objectifs

- **Pas de service Windows.** Un service installé en permanence supprimerait
  l'UAC, mais laisserait un composant SYSTEM installé hors usage. L'UAC à
  chaque lancement ne gêne pas l'utilisateur.
- **Rien avant l'ouverture de session**, pas de tunnel « toujours actif ».
- **Pas de raccrochage** : une IHM relancée ne retrouve pas un moteur
  survivant, puisque le moteur ne survit pas (§6).
- **Pas de mode « IHM seule »** sans moteur : si l'UAC est refusé, Orion
  s'arrête (§6). Choix du concepteur.
- **Linux et macOS hors périmètre.** Sous Linux, Orion garde son modèle actuel
  (capabilities, ADR-004).
- **Pas de pare-feu ni de blocage hors tunnel nouveau** : Orion reste
  volontairement *fail-open* quand le tunnel est démonté
  (`orion-core/src/backend/mod.rs`). « Pas de résidu » ne crée donc aucune fuite
  nouvelle.
- **F14 n'en fait pas partie.** L'absorption d'`astra-signer` vient après,
  dans l'IHM désélevée que F11 rend possible.

## 5. Anti-objectifs

Il y a échec, même si tout fonctionne, quand :

- l'utilisateur voit Orion se relancer (seconde fenêtre, second UAC) ;
- un secret traverse le canal du moteur vers l'IHM, ou se retrouve dans un
  journal ;
- un autre programme de la machine, même lancé sous le même compte, peut
  commander le moteur à la place de l'IHM qui l'a lancé ;
- un moteur ou un adaptateur survit à l'IHM ;
- l'IHM tourne finalement élevée par un chemin oublié (héritage de jeton,
  manifeste, relance).

## 6. Cycle de vie

Décidé avec l'utilisateur : « c'est une seule app », les deux processus sont
liés, sans résidu si l'un plante.

| Événement | Comportement |
| --- | --- |
| Lancement | L'IHM démarre sans élévation, puis demande l'élévation du moteur (UAC). La fenêtre n'apparaît qu'une fois le moteur joint. |
| UAC refusé ou moteur injoignable | L'IHM affiche un message en français et s'arrête. |
| Fermer la fenêtre | La fenêtre se cache ; l'IHM, l'icône et le moteur restent. |
| « Quitter » | L'IHM demande l'arrêt ; le moteur démonte le tunnel, supprime l'adaptateur, libère le PSK (`release` actuel), puis s'arrête ; l'IHM s'arrête ensuite. |
| L'IHM plante | Le moteur le constate (canal fermé ou processus de l'IHM terminé) et fait exactement comme « Quitter ». |
| Le moteur plante | L'IHM le constate au canal coupé, affiche un message et s'arrête. Un adaptateur orphelin éventuel est supprimé au lancement suivant, comme aujourd'hui (« Removed orphaned adapter »). |
| Second lancement d'Orion pendant qu'il tourne | La fenêtre existante revient au premier plan ; aucun second moteur, aucun second UAC. Choix du concepteur. |
| Fermeture de session ou arrêt de Windows | Comme « Quitter ». |

## 7. Lancement et contrainte technique

Un même exécutable ne peut pas porter à la fois un manifeste
`requireAdministrator` et être lancé non élevé : `CreateProcess` refuse un
exécutable qui exige l'élévation (`ERROR_ELEVATION_REQUIRED`). Le manifeste
d'`orion.exe` passe donc à **`asInvoker`**. L'ordre de lancement s'en déduit :

1. l'utilisateur lance `orion.exe` : il démarre non élevé, en mode IHM ;
2. l'IHM lance `orion.exe` en mode moteur par `ShellExecuteEx` avec le verbe
   `runas`. C'est l'UAC que l'utilisateur voit déjà aujourd'hui ;
3. le moteur, élevé et sans fenêtre, ouvre le canal (§8) ; l'IHM s'y connecte,
   puis affiche sa fenêtre.

L'IHM ne montre rien avant l'étape 3 : l'utilisateur voit l'UAC, puis la
fenêtre. C'est ce qui tient l'exigence « pas de relance visible ».

Le mode moteur se sélectionne par un argument de ligne de commande réservé.
Lancé à la main, sans IHM qui l'attende, le moteur doit s'arrêter seul faute de
client authentifié dans un délai court.

## 7 bis. Coffre et installation réservés à l'élévation

Décidé le 24 octobre 2026 (questions 1 b et 2 a de la relecture). Sans ces deux
règles, F11 ne protégerait que la mémoire.

**Le coffre.** Aujourd'hui, il est scellé par DPAPI en portée utilisateur et
par une clé TPM du conteneur de l'utilisateur, dans
`%APPDATA%\helios\orion`. Tout programme du compte, même non élevé, peut
lire ces fichiers et appeler DPAPI et le TPM pour les ouvrir. Après F11 :

- les fichiers du coffre, le registre des profils et le magasin d'identités
  protégé vivent dans un dossier dont la DACL n'accorde l'accès qu'aux
  administrateurs et à SYSTEM, par exemple sous `%ProgramData%\helios\orion`,
  avec un sous-dossier par SID d'utilisateur pour que deux comptes de la
  machine gardent des coffres distincts ;
- la clé TPM devient une **clé machine** (`NCRYPT_MACHINE_KEY_FLAG`) dont la
  DACL n'accorde l'usage qu'aux administrateurs et à SYSTEM ; un processus non
  élevé ne peut ni l'utiliser ni la lire ;
- DPAPI reste une couche du coffre, mais ce n'est plus lui qui fait la
  barrière : c'est la DACL des fichiers et de la clé TPM ;
- le moteur vérifie au démarrage la DACL du dossier et de la clé, et refuse de
  continuer sur un dossier accessible à un compte non administrateur
  (*fail-closed*).

**Limite acceptée.** Les autres comptes administrateurs de la machine peuvent
eux aussi ouvrir ce coffre. C'est le prix de la barrière contre les programmes
non élevés du compte, et l'ADR-006 doit le dire.

**Élévation par les identifiants d'un autre administrateur.** Décidé le
26 octobre 2026 (revue finale, I2) : ce cas est **pris en charge**. Quand un
compte standard saisit à l'UAC les identifiants d'un administrateur, le moteur
tourne sous ce compte, que la DACL par défaut du processus et du jeton de l'IHM
n'autorise pas. Avant l'UAC, l'IHM accorde donc au groupe Administrateurs
(`S-1-5-32-544`), par fusion dans la DACL existante, `SYNCHRONIZE |
PROCESS_QUERY_LIMITED_INFORMATION` sur son processus et `TOKEN_QUERY` sur son
jeton, et rien d'autre. Les autres administrateurs peuvent ainsi observer le
processus de l'IHM et lire l'identité de son jeton, ce que `SeDebugPrivilege`
leur permet déjà. Le moteur tourne sous l'autre compte, sans migrer l'ancien
coffre, et DPAPI lie le coffre à ce compte. Si l'accès reste refusé, le moteur
s'arrête avec le code 5 et l'IHM le dit.

**Migration.** Au premier lancement du moteur après la mise à jour, l'ancien
coffre est ouvert avec ses protections actuelles, rescellé sous les nouvelles,
écrit dans le nouveau dossier et relu. L'ancien n'est supprimé qu'une fois le
nouveau vérifié. Une migration qui échoue laisse l'ancien coffre intact et le
dit. Les profils et identités existants doivent survivre sans réenrôlement.

**L'installation.** Le MSI, format livré, s'installe déjà pour la machine :
il écrit sous `HKLM` (ORION-DISTRIBUTION) et le gabarit WiX de Tauri installe
dans `Program Files`. Le paquet NSIS facultatif (`cargo xtask orion-msi
--with-nsis`), lui, ne fixe pas `installMode` et s'installe donc par défaut
pour l'utilisateur courant, sous `%LOCALAPPDATA%`, dans un dossier où le compte
écrit : un programme non élevé y remplacerait `orion.exe`, et l'UAC suivant
élèverait son code. Après F11 :

- le NSIS passe à `installMode: perMachine`, comme le MSI ;
- le moteur, en build de release, vérifie au démarrage que le dossier de son
  exécutable n'est pas modifiable par un compte non administrateur, et refuse
  de s'élever sinon (*fail-closed*). La règle ne dépend plus de l'installateur
  employé.

Note : la relecture du 24 octobre 2026 avait d'abord affirmé que l'installation
livrée était par utilisateur ; c'est faux pour le MSI, vrai pour le NSIS. La
décision 2 a reste : installation pour la machine, quel que soit le paquet.

## 8. Canal entre l'IHM et le moteur

L'IHM lance le moteur par `ShellExecuteEx`, qui ne transmet aucun handle : les
tubes anonymes hérités du client WireGuard officiel ne s'appliquent pas dans
ce sens. Le canal est un **tube nommé** que le moteur crée et que l'IHM ouvre.

Exigences :

- **DACL restreinte** au SID de l'utilisateur interactif. Aucun autre compte
  ne peut l'ouvrir.
- **Instance unique** : le moteur crée le tube avec
  `FILE_FLAG_FIRST_PIPE_INSTANCE` et refuse de démarrer si un tube du même nom
  existe déjà. Cela écarte un squat du nom par un autre programme.
- **Le client est l'IHM qui a lancé ce moteur, et nul autre.** L'IHM passe son
  PID au moteur au lancement. Le moteur vérifie à la connexion, par
  `GetNamedPipeClientProcessId`, que le client est ce processus, que son image
  est le même `orion.exe` que lui, et que ce processus a été créé avant le
  moteur, pour écarter un PID réutilisé.
- **Un jeton de session** à usage unique, tiré par l'IHM, s'ajoute à ces
  vérifications. Le moteur le reçoit au lancement, l'IHM le présente au premier
  message. Un échec ferme la connexion et arrête le moteur (*fail-closed*).
- **Une seule connexion** pour toute la vie du moteur. Une seconde est refusée.
- **Aucun secret du moteur vers l'IHM.** Le canal transporte de l'état, des
  événements et des commandes. Les secrets que l'utilisateur saisit ou importe
  (PSK statique, profil `.orion` ou `.conf` portant une clé) vont de l'IHM au
  moteur une fois, et n'en reviennent jamais.

Le format reprend celui de `helios-astra-helper` : un objet JSON par ligne,
avec un plafond de taille par sens et par type de message
(`aether::certificates::operator_session::limits`).

Ce que la vérification **ne couvre pas**, et que le document de menace doit
dire : un programme malveillant du même compte peut **piloter** l'IHM, car elle
est à son niveau d'intégrité, et donc demander une connexion, une
déconnexion ou un renouvellement. Il ne peut pas en extraire de secret. La
politique d'autorisation (§9) borne ce qu'il obtient en pilotant l'IHM.

## 9. Politique d'autorisation

Le moteur n'expose que des **commandes de haut niveau**, chacune bornée :

- état, journal et événements (lecture) ;
- connecter un profil nommé, déconnecter, renouveler la clé post-quantique ;
- importer, enregistrer et retirer un profil ; saisir un PSK statique ;
- enrôlement v5 (créer une demande, la réexporter, l'abandonner, importer le
  document) : la demande est publique, les clés privées naissent et restent
  dans le moteur ;
- télémétrie, test de débit et terminal SSH (la commande SSH reste construite
  par le moteur ; c'est l'IHM qui lance le terminal, non élevé).

Il **n'expose jamais** d'opération qui rende un secret : pas d'export de clé
privée, de PSK, de racine de coffre ou de matériel PQ. Pas de commande
générique : chacune correspond à un geste de l'IHM, comme le sont aujourd'hui
les 51 commandes Tauri. La répartition fine, commande par commande, est laissée
au concepteur (§12).

## 10. Partage des responsabilités

| Moteur (élevé, sans fenêtre) | IHM (non élevée) |
| --- | --- |
| WireGuard-NT, adaptateur, routes, MTU | Fenêtre Tauri, WebView2, icône de notification |
| Coffre (TPM machine, DPAPI, BitLocker, exclusions WER), dossier réservé aux administrateurs | Cérémonies WebAuthn et FIDO2 (ex-`helios-astra-helper`) |
| Négociation de clé, renouvellement, `release` | Lancement du terminal SSH |
| Magasin d'identités protégé, enrôlement v5 | Association `.orion` et ouverture de fichiers |
| Télémétrie heliosd, test de débit | Journal affiché, état, notifications |
| Journal fichier `orion.log` | |

Le coffre change de dossier et de protection (§7 bis) ; la migration rouvre
l'ancien avec ses protections actuelles, qui sont liées au compte et donc
accessibles au moteur élevé du même utilisateur. C'est à vérifier sur Windows
(§13).

Les cérémonies d'opérateur qui ouvrent le coffre maître par PRF le font
aujourd'hui dans `helios-astra-helper`, à intégrité moyenne. Elles passent
dans l'IHM, au même niveau : F11 ne les affaiblit pas.

## 11. Contraintes

Règles du dépôt (AGENTS.md) : aucun secret journalisé, sérialisé ni exposé ;
*fail-closed* ; pas d'`unwrap` ni d'`expect` en production ; pas de nouvelle
dépendance quand un mécanisme existant convient ; identifiants et commentaires
en anglais ; messages de l'IHM en français ; mise à jour de l'ADR et de la spec
quand le contrat change.

Spécifiques à F11 :

- **Emplacement du binaire** : `Program Files`, installation pour la machine
  (§7 bis).
- **DLL.** Le moteur élevé ne charge aucune bibliothèque depuis un chemin
  modifiable par l'utilisateur (`SetDefaultDllDirectories`, recherche
  restreinte au dossier système et au dossier de l'application).
- **Environnement.** Le moteur ne fait confiance à aucune variable
  d'environnement transmise par l'IHM pour choisir un chemin de coffre,
  d'identité ou de journal. Les variables de développement existantes
  (`ORION_IDENTITY_DIR`, etc.) restent réservées aux builds de développement.
- **Mise à jour.** L'ADR-004 décrit la chaîne de livraison ; le moteur ne doit
  pas pouvoir être remplacé pendant qu'il tourne. La mise à jour applicative
  passe par l'arrêt complet d'Orion.

Documents à mettre à jour : ADR-004 (la limite connue disparaît, la nouvelle
frontière et ses limites sont décrites, installation pour la machine), ADR-006
(coffre réservé à l'élévation, clé TPM machine, limite des autres
administrateurs), ADR-008 (le sidecar disparaît), ORION-DISTRIBUTION, TESTING
ou MANUAL-TESTING (recette §13), ROADMAP (F11).

## 12. Laissé au concepteur

- le protocole exact du canal et la répartition des 51 commandes Tauri entre
  passage au moteur et traitement local à l'IHM ;
- la forme du jeton de session et sa transmission (argument ou autre), dans le
  respect du §8 ;
- le nom du tube nommé et l'argument du mode moteur ;
- la manière dont l'IHM surveille le processus moteur, et inversement ;
- le découpage en crates : par exemple un module ou une crate client et serveur
  du canal partagé par l'IHM et le moteur, en suivant
  `docs/architecture/CRATE-REORGANIZATION.md`.

## 13. Validation

Rien de ce lot ne se compile ni ne s'exécute depuis WSL2 : pas de chaîne MSVC,
pas de WebView2, pas de WireGuard-NT. Les parties portables (protocole du
canal, politique d'autorisation, cycle de vie modélisé) se testent sous Linux ;
le reste se valide sur un Windows réel, avec une recette dans
MANUAL-TESTING :

1. lancement : un seul UAC, puis la fenêtre ; dans le Gestionnaire des tâches,
   l'IHM est **non élevée** et le moteur est élevé ;
2. connexion ML-KEM, renouvellement, déconnexion ;
3. fermer la fenêtre, la rouvrir depuis l'icône : le tunnel n'a pas bougé ;
4. « Quitter » : plus aucun processus Orion, plus d'adaptateur `orion0` ;
5. tuer l'IHM depuis le Gestionnaire des tâches : le moteur s'arrête, plus
   d'adaptateur ;
6. tuer le moteur : l'IHM affiche un message et s'arrête ; le lancement
   suivant supprime l'adaptateur orphelin ;
7. refuser l'UAC : message, aucun processus restant ;
8. lancer le moteur à la main, sans IHM : il s'arrête seul ;
9. un programme tiers lancé sous le même compte qui ouvre le tube : refusé,
   et le moteur s'arrête ;
10. cérémonie YubiKey depuis l'IHM, sans `helios-astra-helper` installé ;
11. terminal SSH : le shell ouvert est non élevé ;
12. mise à jour d'une installation existante : le coffre migré dans le
    dossier réservé, profils et identités intacts, ancien coffre supprimé ;
    `orion.exe` copié dans un dossier modifiable par l'utilisateur refuse de
    lancer son moteur ;
13. depuis un programme non élevé du même compte : le dossier du coffre est
    illisible et la clé TPM inutilisable ;
14. un dossier de coffre dont on élargit la DACL à l'utilisateur : le moteur
    refuse de démarrer.
