# F14 lot 3 — Coffre, clés et domaine dans Orion — conception

Suite de la [conception F14](2026-10-27-orion-seul-client-design.md) (§5, §7.3).
Elle en reprend les décisions et règles (§4, §8) ; ce document ne dit que ce qui
est propre au lot 3. Rien ici n'a été constaté sous Windows.

## 1. Pourquoi

Créer un domaine, ajouter une clé de récupération, retirer une clé perdue ou
émettre l'ancre `CA-TLS` passe encore par `astra-signer` en console, une commande
par geste et un toucher (souvent deux) par étape. L'opérateur ne se souvient
plus de la séquence ; elle est longue, et un oubli (seconde clé jamais enrôlée,
origine d'Astra absente du relais, document de credentials non émis) ne se voit
que bien plus tard.

Demande de l'utilisateur (28 octobre 2026) : **le rendre ergonomique et moins
pénible à faire**. Le périmètre est celui du §5 de F14, sans ajout.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**

- Les gestes `init`, `enrol`, `remove`, `rename`, `bindings`, `domain`
  (écriture) et `issue-ca-tls` existent dans l'onglet Astra, sous-onglets
  *Coffre et clés* et *Domaine*.
- Moins d'étapes que la console : valeurs préremplies quand elles sont
  connues, gestes enchaînés quand l'un appelle toujours l'autre, un seul toucher
  par clé et par geste chaque fois que la cryptographie le permet.
- Ce qui est impossible se voit **avant** le toucher : bouton désactivé avec sa
  raison (dernière clé de récupération, coffre plein, gateway inconnue du
  relais, `CA-TLS` déjà émise), jamais un refus après le PIN.
- Le coffre peut être ouvert à un autre emplacement que celui par défaut.

**Non-objectifs**

- Approbations, `authorize-issuer` (lot 4), rotations et révocation (lot 5),
  amorçage et transitions de gateway (lot 6), retrait d'`astra-signer` (lot 7).
- `devices` reste servi comme au lot 1.
- Aucun changement de format du coffre, du relais ou du document de
  credentials.

**Anti-objectifs** (échec même si « ça marche »)

- Un domaine laissé à une seule clé sans que l'opérateur l'ait voulu et su.
- Un RP ID choisi sans que l'opérateur ait lu qu'il est définitif.
- Un geste qui demande le PIN puis refuse pour une raison connue d'avance.
- Un chemin de fichier qui passe de la WebView au processus Rust (§4.10 de F14).
- Un secret (PIN, secret de key-slot, clé `CA-PQ`, octets du coffre) journalisé,
  sérialisé ou montré.

## 3. Ce qui existe

- `astra_operator::gestures` : `create_authority`, `open_with_authorized_key`,
  `add_key`, `remove_key`, `prove_anchors_open` ; `signing::sign_credential_bindings`,
  `signing::issue_ca_tls` ; `handoff` (relais), `credentials` (document),
  `store` (coffre). Ce sont les fonctions qu'appelle `astra-signer`
  (`tools/astra-signer/src/commands/vault.rs`, `issuer.rs`) ; Orion les appelle
  directement, comme aux lots 1 et 2.
- La cérémonie de l'IHM (`apps/orion/src-tauri/src/operator/ceremony.rs`) :
  appuis (`Press`) par révision, ouverture de clé par la plateforme WebAuthn
  (PIN et toucher dans la fenêtre de Windows), cérémonies à deux clés avec
  `index`/`of` et refus `KeyRepeated`.
- `aether_fido` sait enregistrer (`register`) par la plateforme WebAuthn.
- Le panneau `VaultPanel.tsx` (lecture, « Vérifier une clé »), `DomainPanel.tsx`
  (lecture du relais).

## 4. Décisions

### 4.1 « Créer un domaine » (`init` puis seconde clé)

Proposé à la place du texte « d'ici là, `astra-signer init` » quand aucun
coffre n'existe à l'emplacement choisi.

1. **Formulaire, avant toute clé** :
   - *Nom WebAuthn (RP ID)* : prérempli avec le nom d'hôte de la gateway du
     profil connecté quand c'est un nom et non une adresse IP, vide sinon.
     Avertissement visible : « Ce nom ne se change plus. Prenez le nom
     Tailscale de la gateway si elle est dans un tailnet. »
   - *Origine d'Astra* : préremplie `https://<RP ID>`, modifiable, `https://`
     exigé. Écrite dans le relais à la création (aujourd'hui, un
     `astra-signer domain --astra-authority-url` séparé qu'on oublie).
   - *Libellé de la première clé* (« Clé principale » par défaut) et *libellé
     de la seconde* (« Clé de récupération » par défaut).
   - L'identifiant de domaine est tiré au hasard, sans champ.
2. **Clé 1** (principale) : enregistrement et dérivation, coffre et relais
   écrits.
3. **Clé 2** (récupération), enchaînée dans la même session : « Débranchez la
   première clé, branchez la seconde ». L'ouverture obtenue à l'étape 2 sert à
   ajouter la seconde : **la première clé n'est pas retouchée**. Une clé déjà
   enrôlée dans ce coffre est refusée (liste d'exclusion de `add_key`).
4. **Fin** : les deux clés ont ouvert les ancres (essai exigé par l'ADR-008 §4,
   `prove_anchors_open` avec chacune des deux ouvertures déjà en main, sans
   toucher de plus si c'est possible). Écran de fin : empreinte du coffre,
   empreinte `CA-PQ` en groupes de quatre, rappel « Sauvegardez le coffre », et
   les étapes suivantes en clair (déploiement, amorçage de la gateway — encore
   `astra-signer issue-gateway-bootstrap` jusqu'au lot 6, puis *Domaine* →
   « Finaliser le domaine »).
5. **Interruption après l'étape 2** (annulation, fenêtre fermée, seconde clé
   refusée) : le coffre existe avec une clé. L'IHM l'affiche comme **non
   amorcé** (bandeau d'alerte permanent dans *Coffre et clés* : « Une seule clé :
   la perdre, c'est perdre le domaine ») avec le bouton « Ajouter la clé de
   récupération ». Pas de retour en arrière automatique : un coffre à une clé
   n'est pas un coffre faux.

### 4.2 Clés du coffre (*Coffre et clés*)

Chaque ligne de la table des clés porte ses actions ; la ligne montre aussi
l'état du document de credentials (active, perdue) quand il existe.

- **« Ajouter une clé »** (`enrol`) : libellé (« Clé de récupération » par
  défaut) et rôle. Une clé déjà enrôlée, puis la nouvelle. Le document de
  credentials est re-signé dans la même session avec une ouverture déjà
  obtenue, sans troisième toucher si la cryptographie le permet ; sinon le
  constructeur le dit dans le plan. Désactivé, avec sa raison, à
  `MAX_SLOTS` clés.
- **« Renommer »** (`rename`) : édition en place, sans clé, enregistrée
  immédiatement.
- **« Marquer perdue » / « Réactiver »** (`bindings --lost/--active`) : une
  clé, un toucher, document re-signé. Désactivé, avec sa raison, tant que le
  relais ne porte pas l'identité de la gateway (le document la nomme).
- **« Retirer »** (`remove`) : confirmation qui nomme la clé et dit que le
  retrait est définitif et ne rattrape pas les sauvegardes antérieures du
  coffre. Désactivé, avec sa raison, sur la dernière clé de récupération.
  Ordre conservé d'`astra-signer` : document signé (ligne `revoked`) **avant**
  l'enregistrement du coffre rescellé, une seule ouverture si elle reste valide
  après le rescellement.
- La clé qui ouvre le coffre pour un geste peut être n'importe quelle clé
  enrôlée active, y compris celle qu'on retire, sauf si la règle d'`astra-operator`
  l'interdit.

### 4.3 Domaine (*Domaine*)

- **Relais** : formulaire des valeurs publiques (`domain`) — clé WireGuard et
  nom de service de la gateway, clé de service Astra et son époque, origine
  d'Astra. Validées côté Rust comme dans `astra-signer domain`. Une valeur déjà
  présente qui change est montrée « avant → après » et confirmée.
- **« Reprendre la gateway connectée »** : remplit la clé WireGuard et le nom de
  service depuis la feuille PQ de la gateway connectée, **vérifiée sous le
  `CA-PQ` du relais** (mécanisme du lot 2). Sans gateway connectée ou sans
  feuille, le bouton est désactivé avec sa raison ; la saisie manuelle reste.
- **« Finaliser le domaine »** : une session, **un toucher**, qui fait ce qui
  manque parmi : émettre `CA-TLS` (`issue-ca-tls`, 3650 jours) et émettre le
  document de credentials. Visible tant que l'un des deux manque ; désactivé,
  avec sa raison, tant que le relais n'a pas l'identité de la gateway. Le PEM
  de `CA-TLS` est proposé à l'enregistrement par la boîte de sauvegarde. Une
  `CA-TLS` existante n'est jamais remplacée (c'est le lot 5).

### 4.4 Emplacement du coffre

- *Coffre et clés* affiche l'emplacement et un bouton « Changer… » qui ouvre le
  **sélecteur de fichier natif de Windows depuis le processus Rust** (feature
  supplémentaire de `windows-sys`, déjà dépendance : pas de nouvelle
  dépendance). Le chemin ne transite jamais par la WebView ; elle n'en reçoit que
  l'affichage. « Emplacement par défaut » y revient.
- Le choix est mémorisé dans les réglages de l'IHM et sert à **tous** les gestes
  opérateur (cérémonies des lots 1 et 2 comprises) ; le relais et le document de
  credentials sont lus et écrits à côté du coffre choisi, comme aujourd'hui.
- « Créer un domaine » sur un autre emplacement est permis (coffre d'essai pour
  la recette, sans toucher au vrai).
- Un emplacement mémorisé dont le dossier n'existe plus (clé USB débranchée) est
  affiché « Emplacement introuvable » : jamais « Aucun coffre », et « Créer un
  domaine » n'y est pas proposé.
- Hors Windows : pas de sélecteur ; le bouton est absent et l'emplacement par
  défaut s'applique.

### 4.5 Contrat

- Nouveaux genres d'opération, liste fermée : `create_domain`, `add_key`,
  `remove_key`, `mark_key`, `finalize_domain` (noms au choix du constructeur,
  un genre par geste à clé). `rename`, l'écriture du relais et le choix de
  l'emplacement sont des commandes sans cérémonie.
- Chaque geste à clé montre un manifeste avant le toucher (ce qui va changer,
  en clair).
- Les refus prévisibles gagnent des variantes de `Refusal`, sans texte, phrase
  française dans `refusalSentence` : au moins coffre déjà présent, coffre
  plein, dernière clé de récupération, identité de gateway absente du relais,
  `CA-TLS` déjà émise. Ils sont aussi vérifiés côté Rust (fail-closed) même
  quand l'IHM désactive le bouton.

### 4.6 Documentation

- `docs/DEPLOIEMENT-ASTRA.md` (amorçage, `init`, `enrol`, document de
  credentials) renvoie aux gestes d'Orion ; `astra-signer` y reste cité comme
  voie transitoire jusqu'au lot 7, `issue-gateway-bootstrap` jusqu'au lot 6.
- MANUAL-TESTING : une recette courte du lot 3 sur un **coffre d'essai** (autre
  emplacement), deux YubiKey : créer, ajouter une troisième clé, renommer,
  marquer perdue puis réactiver, retirer, compter les touchers, puis
  « Finaliser » si une gateway d'essai est connectée.
- ROADMAP : avancement de F14.

## 5. Sécurité

Règles de F14 §8 inchangées. En plus : les ouvertures de clé réutilisées
(§4.1.3, §4.2, §4.3) ne quittent pas la session et sont effacées à sa fin ;
l'IHM ne reçoit jamais qu'empreintes, libellés, rôles et états.

## 6. Tests

- Linux, authentificateur factice d'`astra-operator` : ordre des étapes,
  nombre d'ouvertures par geste, refus avant clé, interruption après la clé 1,
  document signé avant le coffre au retrait, `CA-TLS` jamais remplacée.
- vitest : chaque écran, boutons désactivés et leur raison, confirmation du
  retrait, avertissement du RP ID.
- Non vérifiable ici : sélecteur natif, dialogues WebAuthn d'enregistrement,
  nombre réel de touchers sous Windows. La recette le constate.

## 7. Laissé au constructeur

- Noms exacts des genres, variantes de `Refusal` et commandes Tauri.
- Où vivent les réglages de l'emplacement du coffre.
- Si une ouverture reste valide après `add_slot` ou `remove_slot` (sinon un
  toucher de plus, dit dans le plan).
- Découpage en tâches.

## 8. Choix faits sans l'utilisateur (à relire)

- Enchaînement forcé de la seconde clé à la création, avec un coffre à une clé
  toléré et signalé si on s'arrête.
- Origine d'Astra préremplie `https://<RP ID>` et écrite à la création.
- RP ID prérempli depuis le profil connecté.
- « Finaliser le domaine » regroupe `CA-TLS` et document de credentials en un
  toucher.
- Sélecteur natif côté Rust pour l'emplacement du coffre.

## 9. Précisions du plan (28 octobre 2026)

Issues de la lecture du code au moment du plan ; elles priment sur les sections
ci-dessus là où elles diffèrent.

- **Ouvertures réutilisées** : la clé maîtresse du coffre ne change ni à l'ajout
  ni au retrait d'un key-slot, donc une ouverture obtenue reste valable pour la
  suite du geste. Touchers attendus : création 4 dialogues Windows (clé 1 :
  enregistrement et dérivation ; clé 2 : idem), ajout 3, retrait, état et
  finalisation 1 chacun. À constater en recette.
- **Retrait** : la clé qui ouvre le coffre ne peut pas être celle qu'on retire
  (refus `KeyBeingRemoved`, rien n'est écrit), comme `astra-signer remove` en
  pratique. Le plancher est de deux clés (règle du coffre), pas seulement « la
  dernière clé de récupération ».
- **« Reprendre la gateway connectée »** écrit directement l'identité vérifiée
  sous `CA-PQ` quand le relais n'en a pas ; une identité différente de celle déjà
  enregistrée est refusée (c'est une transition de gateway, lot 6).
- **Emplacement** : le fichier choisi s'appelle obligatoirement
  `authority-vault.json`, pour que relais et document de credentials, rangés à
  côté, n'appartiennent qu'à un domaine. Un réglage d'emplacement illisible est
  une erreur affichée, jamais un retour silencieux à l'emplacement par défaut.

## 10. Amendements (écarts pris pendant l'exécution)

Ils priment sur les sections ci-dessus là où elles diffèrent.

1. **Pas de `CaTlsAlreadyIssued`** : sept nouveaux refus et non huit
   (`VaultExists`, `LocationUnavailable`, `VaultFull`, `MinimumKeys`,
   `KeyBeingRemoved`, `GatewayIdentityMissing`, `DomainComplete`). Aucun geste ne
   peut le produire : la finalisation traite une `CA-TLS` existante comme « rien à
   émettre », et `DomainComplete` couvre le tout-fait.
2. **`resign` échoue fermé** : si un document de credentials existe alors que
   l'identité du relais est absente ou illisible, refus `GatewayIdentityMissing`
   (ajout et retrait refusés jusqu'à réparation du relais ou restauration du
   document). `check_document` est vérifié **avant** le toucher. La phrase du
   refus couvre aussi le document qui ne se vérifie pas.
3. **Retrait** refusé avec la clé qu'on retire (`KeyBeingRemoved`) ; plancher de
   deux clés (`MinimumKeys`).
4. **Clé WireGuard et nom de service de la gateway** : remplissage seul dans
   `write_relay`, affichés en lecture seule dans le formulaire du domaine ; la
   reprise de la gateway est liée à la `peer_public_key` du profil connecté.
5. **Écritures sans clé** (renommer, écrire le relais, reprendre la gateway)
   refusées tant qu'une cérémonie opérateur est ouverte.
6. **`refusal_of`** : `KeyDeclined` seulement pour une erreur d'authentificateur,
   `Internal` sinon, pour ne pas inviter à réessayer après un échec survenu une
   fois l'écriture faite.
7. **RP ID** refusé si son dernier label est numérique ; origine normalisée.
8. **`DomainView`** porte les champs publics `astra_service_public_key`,
   `astra_service_key_epoch` et `astra_authority_url`, pour que la confirmation
   d'écrasement montre « avant → après » ; l'époque doit être un entier sûr.
9. **`SlotView.state`** peut valoir `revoked`, affiché « révoquée ».
10. **Sélecteur Windows** : fil dédié avec son propre appartement COM STA,
    `lpstrDefExt` « json », nom comparé sans casse, un seul sélecteur à la fois.
    `cfg(windows)` n'est pas vérifiable sous WSL2 : à constater en recette.
11. **Écart connu laissé au lot 5** : l'écran de rotation de la `CA-TLS` prend
    encore un chemin de coffre tapé dans la WebView et ignore l'emplacement
    choisi ; le lot 5 remplace ce chemin.
