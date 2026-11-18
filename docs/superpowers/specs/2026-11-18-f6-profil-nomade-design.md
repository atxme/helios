# F6 — Profil Orion `nomade`

Conception du 18 novembre 2026. Source : ROADMAP F6, ADR-006 §3 et §5,
« Limites connues » (« Le profil `nomade` n'est pas câblé »).

## 1. Intention

Un portable volé, éteint, ne doit pas pouvoir monter le tunnel tant que la
passphrase de son profil reste inconnue. ADR-006 a décidé le profil `nomade`
pour cela : déverrouillage par le TPM **et** une passphrase, pas de connexion
sans saisie, et à la veille, à l'hibernation, au verrouillage de session et à
la fermeture d'Orion, le tunnel se ferme, les tampons sont effacés et la
passphrase est redemandée.

Les briques existent et sont testées, mais rien ne les relie :
`aether_vault::Unlock` (dont `Derived`), la politique `vault::passphrase`, la
boîte native `vault::windows::prompt`, `aether::locked::LockedSecret`. Le seul
mode servi aujourd'hui est `service`.

## 2. Buts, non-buts, anti-buts

**Buts**

- un mode par profil, `service` ou `nomade`, affiché dans l'IHM, sans défaut
  caché (ADR-006 §3) ;
- un profil devient `nomade` à sa création, à son import, ou par bascule d'un
  profil existant ; il repasse en `service` ; sa passphrase se change.
  **Décision de l'utilisateur (18 novembre 2026)** : la bascule d'un profil
  existant est dans le lot, pour qu'un portable déjà enrôlé n'ait pas à
  repasser par l'administrateur ;
- la passphrase est demandée par la boîte native à la première connexion d'un
  profil `nomade` verrouillé, et reste valable jusqu'au verrouillage de
  session, la veille, l'hibernation ou la fermeture d'Orion ;
- à chacun de ces événements, le tunnel d'un profil `nomade` est fermé, la clé
  de passphrase gardée en mémoire est effacée, et le profil redevient
  verrouillé.

**Non-buts**

- connexion automatique au démarrage : Orion ne l'a pour aucun profil
  aujourd'hui, ce lot n'en ajoute pas ;
- Orion Linux : sans boîte protégée, `nomade` y reste refusé
  (`VaultError::NoNativePrompt`), comme le stockage protégé lui-même ;
- Argon2id : arbitré par ADR-006 §3, le `kdf` versionné garde la porte ouverte ;
- détection du rollback complet hors ligne : limite connue d'ADR-006, inchangée.

**Anti-buts** (ce qui ferait échouer le lot même s'il « marche »)

- la passphrase, ou une clé qui en dérive, traverse le DOM, JavaScript, un
  message Tauri ou une trame du canal moteur ↔ IHM ;
- un profil `nomade` est un jour rescellé en `service` sans geste explicite
  de l'utilisateur (repli silencieux) ;
- un profil `nomade` s'ouvre avec la passphrase seule, sans le TPM, ou avec le
  TPM seul ;
- le moteur dépend de l'IHM pour apprendre un verrouillage ou une veille : une
  IHM tuée laisserait alors le tunnel et la clé en place ;
- une politique de passphrase durcie plus tard empêche d'ouvrir un profil
  existant.

## 3. Contraintes

- Règles du dépôt (AGENTS.md) : documentation en français, code et journaux
  en anglais, aucun secret dans la WebView ni les journaux.
- ADR-006 §3 : PBKDF2-HMAC-SHA-512, 600 000 itérations, sel aléatoire de
  128 bits, identifiant de KDF `2` ; l'identifiant `1` reste brûlé ; le sel et
  les paramètres vivent dans un key-slot extérieur authentifié.
- ADR-006 §5 : l'échec du verrouillage mémoire est **fatal** pour `nomade`.
- F11 : le moteur est `orion.exe --engine`, élevé, sans fenêtre, dans la
  session de l'utilisateur ; l'IHM est non élevée. Les secrets restent dans le
  moteur.
- Rien de ce qui touche la boîte native, le TPM, la mémoire verrouillée ou les
  notifications de session ne s'éprouve depuis WSL : compilation par la CI
  Windows, comportement par la recette manuelle.

## 4. Approches

| Approche | Principe | Verdict |
|---|---|---|
| **A. Conjonction de l'ADR** | `passphrase_key = PBKDF2(passphrase, sel)`, puis manifeste scellé sous `Unlock::Derived { ikm: profile_root_key ‖ passphrase_key }` ; sel et KDF dans l'entrée du registre | **Retenue** : c'est la hiérarchie qu'ADR-006 §3 décrit, et `Unlock::Derived` existe déjà |
| B. Passphrase seule | manifeste scellé sous `Unlock::Passphrase` | écartée : un disque volé s'attaque hors de la machine, sans le TPM ; casse la conjonction |
| C. Clé de profil enveloppée deux fois | une clé aléatoire par profil, un key-slot sous la racine et un sous la passphrase | écartée : un format de key-slot de plus pour un manifeste de quelques kilo-octets que l'on rescelle aussi bien en entier |

## 5. Conception

### 5.1 Dérivation

Pour un profil `nomade` :

```
passphrase      = vault::passphrase::normalise(saisie)        trim + NFC
passphrase_key  = PBKDF2-HMAC-SHA-512(passphrase, sel[16], 600 000) → 32 octets
ikm             = profile_root_key(id) ‖ passphrase_key       64 octets
manifeste       = aether_vault::seal(DOMAIN_PROFILE, contexte,
                    Unlock::Derived { ikm, info: b"orion/profile-nomade/v1" })
```

- `profile_root_key` est celle d'aujourd'hui : rien ne change pour `service`.
- À l'ouverture, seule la normalisation s'applique, pas la politique : la
  politique (`passphrase::accept`) ne juge qu'une **nouvelle** passphrase. Une
  règle durcie plus tard n'enferme donc personne dehors. Il faut pour cela
  séparer `normalise` de `accept`, qui l'appelle.
- Les dérivations sont épinglées par des vecteurs de référence calculés hors
  du crate, comme `keys.rs` le fait déjà pour HKDF.

### 5.2 Registre (key-slot extérieur)

L'entrée du registre, déjà scellée sous la racine TPM et donc authentifiée,
gagne le mode :

```
mode : Service
     | Nomade { kdf: u8 (= 2), salt: [u8; 16] }
```

- Le registre passe en version 2. Une version 1 se lit, tous ses profils en
  `service`, et la prochaine écriture produit une version 2.
- Le mode entre dans le `security_digest` : une bascule élève la génération,
  comme un changement de PSK ou d'ancre.
- Un `kdf` inconnu, ou `1`, est refusé avec un message qui le dit.

### 5.3 Profil verrouillé

- `ProfileStore::load` ne déchiffre plus que les profils `service`. Un profil
  `nomade` dont la clé de passphrase n'est pas en mémoire est rendu
  **verrouillé** : nom, clés publiques et mode, venus du registre ; aucun champ
  du manifeste. Le démarrage d'Orion ne demande donc aucune passphrase.
- **Choix de conception** : un profil verrouillé est d'un type distinct,
  `LockedProfile { name, client_public_key, gateway_public_key, mode }`,
  porté par une liste à part de `ClientConfig`. `ClientProfile` reste complet,
  et rien ne peut sauvegarder un profil verrouillé par erreur : il n'a pas de
  manifeste à écrire. Les deux clés publiques sont déjà dans l'entrée du
  registre.
- La vue envoyée à l'IHM porte `mode` et `locked`. Un profil verrouillé
  s'affiche « Nomade · verrouillé », sans point de terminaison ni réglages.
- Un registre illisible (dont un `kdf` inconnu ou brûlé) fait échouer le
  chargement entier, comme aujourd'hui : c'est un seul blob. Un échec AEAD au
  déverrouillage ne laisse aucun état : le profil reste verrouillé.
- **Déplacement du coffre** (`relocation.rs`) et migration du fichier hérité :
  la migration ne produit que des profils `service` (ils viennent d'un fichier
  en clair). Le déplacement garde la même racine ; il copie les manifestes
  `nomade` octet pour octet (`copy_is_identical`) et ne vérifie par ouverture
  que les profils `service`, puisque `load` ne déchiffre plus les autres.
- **Choix de conception** : pas de copie du point de terminaison dans le
  registre pour l'afficher verrouillé. Le manifeste existe pour qu'aucune copie
  extérieure ne fasse foi, et le gain est cosmétique.

### 5.4 Déverrouillage et durée de vie

- Toute opération qui a besoin du manifeste d'un profil `nomade` verrouillé
  (connexion depuis l'IHM ou la zone de notification, modification, export du
  profil, bascule) commence par le déverrouiller : le **moteur** ouvre la boîte
  native, dérive, ouvre le manifeste.
- Le moteur passe par une interface (`PassphraseSource`) pour obtenir la
  saisie : la boîte native en production, une source scriptée dans les tests.
- La boîte (`CredUIPromptForWindowsCredentialsW`) est un appel bloquant par
  saisie : nouvelle passphrase, confirmation et nouvelle tentative sont des
  appels distincts, exécutés hors de la boucle asynchrone
  (`spawn_blocking`). Pas de délai : l'utilisateur annule. **Choix de
  conception** : pour que la boîte d'un moteur sans fenêtre passe au premier
  plan, l'IHM, qui l'a, appelle `AllowSetForegroundWindow` avec le PID du
  moteur avant d'émettre un geste qui peut ouvrir une boîte. Le nom
  d'utilisateur pré-rempli par la boîte est sans effet ; le message le dit.
- La zone de notification vit dans l'IHM : une connexion lancée de là est la
  même commande `Connect`, et c'est le moteur qui ouvre la boîte. Sans IHM, il
  n'y a pas de moteur (F11).
- Saisie annulée → l'opération s'arrête sans erreur bruyante. Échec AEAD →
  « Passphrase incorrecte, ou profil altéré » : les deux sont
  indiscernables, et le message ne prétend pas le contraire. Pas de compteur
  d'essais : les 600 000 itérations sont le frein, et un verrou d'essais ne
  serait qu'un déni de service contre l'utilisateur.
- Après un déverrouillage réussi, le moteur garde la `passphrase_key` (32
  octets) du profil dans un `LockedSecret`, protégé par `CryptProtectMemory`
  quand il ne sert pas (Windows). Si le verrouillage des pages échoue, le
  déverrouillage est refusé (ADR-006 §5) et la posture le dit. La passphrase
  elle-même est effacée dès la dérivation faite.
- La clé reste en mémoire d'une connexion à l'autre dans la même session :
  « saisie au lancement et après reprise » (ADR-006 §3) se lit ici « à la
  première connexion après le lancement ou la reprise ».

### 5.5 Verrouillage

- Le moteur écoute lui-même, par une fenêtre de messages invisible sur un fil
  dédié :
  - `WTSRegisterSessionNotification` : `WTS_SESSION_LOCK`,
    `WTS_SESSION_LOGOFF`, et `WTS_SESSION_DISCONNECT` / `WTS_CONSOLE_DISCONNECT`
    (déconnexion RDP, changement rapide d'utilisateur), traités comme un
    verrouillage ;
  - `WM_POWERBROADCAST` `PBT_APMSUSPEND`, et
    `RegisterSuspendResumeNotification` pour la veille moderne.
- À chacun de ces événements, et à la fermeture du moteur :
  1. si le tunnel actif est celui d'un profil `nomade`, il est fermé ;
  2. toutes les `passphrase_key` gardées sont effacées ;
  3. les profils `nomade` de la configuration en mémoire redeviennent
     verrouillés (leur manifeste déchiffré est abandonné) ;
  4. le cache de la racine du poste est oublié lui aussi (**choix de
     conception** : il se reconstruit par le TPM et DPAPI au besoin, et le
     commentaire de `store.rs` l'annonçait).
- Un tunnel `service` n'est pas touché. Le moteur n'a qu'un tunnel actif à la
  fois : l'étape 1 est une seule fermeture.
- Un moteur tué emporte le tunnel : l'adaptateur WireGuard-NT disparaît avec le
  dernier handle du processus. La recette Windows le vérifie.
- Si l'abonnement aux notifications échoue, **aucun** profil `nomade` ne se
  déverrouille, et la posture le dit : un profil qui ne se reverrouille pas ne
  tient pas sa promesse.
- La logique (événement → actions) est une machine portable, testée sous WSL
  avec des événements injectés ; seul l'abonnement Windows est spécifique.

### 5.6 Écriture d'un profil `nomade`

- Toute écriture du manifeste d'un profil `nomade` (sauvegarde, plancher de
  négociation relevé, renouvellement de certificat, rotation de clé) exige sa
  `passphrase_key` en mémoire. Sans elle, l'écriture échoue. Elle ne se replie
  **jamais** sur un scellement `service`.
- Les tâches de fond qui écrivent tournent avec un tunnel monté, donc avec un
  profil déverrouillé ; le verrouillage les arrête avec le tunnel.

### 5.7 Gestes

Dans l'onglet *Profils*, chaque profil affiche son mode (« Service » ou
« Nomade »). Les gestes sont des commandes du moteur. Le protocole moteur ↔ IHM
passe en version 3. Aucune trame ne transporte de passphrase : l'IHM n'émet que
l'intention, et le moteur ouvre les boîtes.

| Geste | Boîtes natives | Effet |
|---|---|---|
| Enregistrer un nouveau profil, ou un import, en `nomade` (choix du mode dans le formulaire) | nouvelle passphrase, confirmation | sel tiré, manifeste scellé en `nomade` |
| « Passer en nomade » | nouvelle passphrase, confirmation | rescellement en `nomade` |
| « Changer la passphrase » | passphrase actuelle, nouvelle, confirmation | nouveau sel, rescellement |
| « Repasser en service » | passphrase actuelle | rescellement en `service` |

- La nouvelle passphrase passe par `passphrase::accept`. Un refus rouvre la
  boîte avec la raison, et l'annulation abandonne le geste.
- La confirmation qui diffère abandonne le geste avec « Les deux saisies
  diffèrent ».
- Chaque boîte a sa légende et son message, pour que l'utilisateur sache
  laquelle il remplit.
- Une bascule est permise tunnel monté : elle ne touche que le stockage.
- Hors Windows, le choix `nomade` est désactivé et en donne la raison.

**Atomicité.** Une bascule écrit un nouveau manifeste et une nouvelle entrée
de registre. Une coupure à n'importe quel point doit laisser le profil
ouvrable, soit dans l'ancien mode, soit dans le nouveau, avec l'entrée qui lui
correspond, jamais un manifeste scellé d'une façon que le registre ne décrit
pas. Le contrôle de génération de `load_manifest` (un manifeste sous la
génération du registre est refusé) reste entier. **Choix de conception**, en
trois écritures :

1. le nouveau manifeste (génération + 1, nouveau mode) est écrit à côté,
   `profiles/<id>.next.hvlt` ;
2. le registre est écrit avec le nouveau mode et la génération + 1 ;
3. `<id>.next.hvlt` est renommé en `<id>.hvlt`.

Au chargement : un `<id>.next.hvlt` dont la génération dépasse celle du
registre est un reste de l'étape 1, et il est supprimé ; un `<id>.next.hvlt` à
la génération du registre est une étape 3 interrompue, et il est promu. Tests
d'injection de panne après chaque écriture, comme ceux du magasin actuel.

**Copies antérieures.** Passer en `nomade` ne protège pas les copies du profil
déjà faites en `service` (sauvegardes, profil itinérant, rémanence du SSD) :
elles s'ouvrent toujours sans passphrase sur ce poste, avec la session Windows
de l'utilisateur et le TPM. **Décision de l'utilisateur (18 novembre 2026)** :
la bascule l'avertit, en une phrase, sans imposer ni conseiller de rotation de
la clé WireGuard ; imposer la rotation renverrait à l'administrateur, ce que le
§2 écarte.

### 5.8 Posture et IHM

- Le panneau de posture indique, par profil `nomade`, s'il est verrouillé ou
  non, et l'état de la mémoire verrouillée et de l'abonnement aux
  notifications, avec un état bloquant quand l'un manque.
- Le formulaire de passage en `nomade` dit, en une phrase, ce que le profil
  protège et ce qu'il ne protège pas (ADR-006 §3 : un portable volé éteint,
  pas un malware ni un enregistreur de frappe présent à la saisie), et qu'une
  passphrase oubliée impose de supprimer le profil et de le ré-enrôler.

## 6. Ce qui est laissé au constructeur

- Le mécanisme d'atomicité de la bascule (§5.7), sous la contrainte posée.
- Le découpage entre `orion-core` (dérivation, registre, magasin, machine de
  verrouillage) et `orion-engine` (commandes, fil des notifications).
- La forme exacte des légendes et messages des boîtes, en français.
- L'emplacement de `CryptProtectMemory` (portée `SAME_PROCESS`) : dans
  `aether::locked` ou dans un enrobage côté `orion-core`, et la forme de l'API
  qui déprotège le temps d'une dérivation puis reprotège.

## 7. Points ouverts

Aucun. Le seul point ouvert (copies antérieures à la bascule) est tranché au
§5.7.

## 8. Vérification

**Portable (WSL, `scripts/regression.sh`)**

- vecteurs de référence de PBKDF2 et de la dérivation `nomade` ;
- registre v2 aller-retour, lecture d'un v1, refus d'un `kdf` inconnu ou brûlé ;
- magasin : `load` rend verrouillé un profil `nomade`, déverrouillage par
  source scriptée, mauvaise passphrase refusée, passphrase seule ou racine
  seule incapables d'ouvrir ;
- bascules dans les trois sens, génération élevée, coupure injectée à chaque
  écriture ;
- écriture d'un profil `nomade` verrouillé refusée, jamais rescellée en
  `service` ;
- machine de verrouillage : chaque événement ferme un tunnel `nomade`, efface
  les clés, laisse un tunnel `service` ;
- une politique durcie n'empêche pas d'ouvrir un profil existant ;
- aucune trame du protocole ni vue de l'IHM ne porte de champ de passphrase ;
- IHM : badge de mode, profil verrouillé, gestes, choix désactivé hors
  Windows.

**Cible Windows (recette MANUAL-TESTING, nouvelle section)**

- boîtes natives des quatre gestes ; annulation ; mauvaise passphrase ;
- verrouillage de session, veille, hibernation, fermeture : tunnel fermé, puis
  nouvelle saisie ;
- échec simulé du verrouillage mémoire : déverrouillage refusé ;
- la passphrase n'apparaît dans aucune commande Tauri, charge JSON ni mémoire
  JavaScript instrumentée (ADR-006, recette existante).

## 9. Documentation

ADR-006 (« Limites connues » : le profil est câblé ; ce qui reste), ROADMAP
(F6, et l'entrée du lot 7 de F14, restée « pas encore fusionné »),
MANUAL-TESTING, et le guide utilisateur d'Orion s'il décrit l'onglet
*Profils*.
