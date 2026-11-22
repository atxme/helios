# F5 — Fichier de récupération WireGuard signé, compteur NV TPM (décision D1)

Statut : **conception**, 22 novembre 2026. Tranche D1, décrit F5 de la
[feuille de route](../../ROADMAP.md) et le lot 3 d'[ADR-002](../../adr/ADR-002-SIGNATURES-PQ.md).

## 1. Intention

Quand une mise à jour change les PCR 0/4/7 (noyau, chargeur, firmware, clés
Secure Boot), le coffre `wg-key.sealed` ne s'ouvre plus et la gateway perd sa
clé WireGuard, donc son identité. Le séquestre (`helios-escrow`) couvre ce
cas : l'opérateur ouvre `wg-key.escrow` hors de la gateway et dépose la clé
dans `/var/lib/helios/wg-key.recovery`, que `heliosd` rescelle au démarrage
(`crates/heliosd/src/gateway_key.rs`, `try_recovery`).

Ce fichier est aujourd'hui **une clé en clair, sans signature ni anti-rejeu**.
Un attaquant capable d'écrire sur la partition de configuration corrompt le
coffre (il devient indéchiffrable), dépose sa propre clé, et la gateway
l'adopte. Il peut aussi rejouer un ancien fichier légitime pour restaurer une
identité que la rotation avait remplacée (ADR-002 §4).

Par ailleurs, l'anti-rejeu des deux autres artefacts éditeur (billet de
rescellement, restauration firmware) repose sur `TpmState.version`, un fichier
sur cette même partition : il ne résiste pas à l'attaquant qu'ADR-002 vise, ni
à la restauration d'une image disque complète (ADR-002, amendements 2 et 5).

## 2. Décisions de l'utilisateur

- **D1 tranché : compteur monotone en NV du TPM** (option 2 de l'amendement 2
  d'ADR-002), 22 novembre 2026.
- **Un seul compteur NV pour les trois artefacts**, qui remplace
  `TpmState.version` : billet de rescellement, restauration firmware, fichier
  de récupération WireGuard. Choisi comme la solution la plus propre et la plus
  durable : pas deux mécanismes à faire coexister puis à fusionner plus tard.
- **Rupture nette, sans code de migration de la valeur du compteur.** Une
  gateway est déployée ; elle peut être cassée tant que **l'accès n'est pas
  bloqué** (Tailscale garde l'accès hors de `heliosd`).
- **Validation sur TPM réel reportée** avec les autres recettes matérielles ;
  le code est testé sous WSL avec le TPM simulé des tests.
- **Cérémonie opérateur dans Orion**, la CLI et Orion appelant le même cœur
  (§5.6).
- **Conséquence acceptée** : billet et récupération sont signés pour une
  gateway, plus pour un parc (§5.2).

## 3. Objectifs, non-objectifs, anti-objectifs

Objectifs :

1. `heliosd` n'adopte une clé de récupération que si elle porte une
   autorisation éditeur Ed25519 **et** ML-DSA-65 valide, pour cette identité
   de gateway et la valeur courante du compteur NV ;
2. un artefact éditeur (billet, restauration firmware, récupération WireGuard)
   ne sert qu'une fois, même si le disque entier est restauré ;
3. l'opérateur peut produire un fichier de récupération alors que la gateway
   est injoignable (elle n'a plus sa clé) ;
4. l'amendement 2 d'ADR-002 est tranché et documenté, l'amendement 5 mis à
   jour, le tableau « État d'implémentation » d'ADR-002 à jour.

Non-objectifs :

- reprendre la valeur de `TpmState.version` dans le compteur NV ;
- confidentialité du fichier de récupération (ADR-002, « Hors périmètre ») :
  la clé reste en clair le temps d'un démarrage ;
- toucher à la fenêtre de mise à jour d'ADR-007 (son index NV ne change pas) ;
- « claim de fraîcheur des coffres » (autre conséquence de D1 dans la feuille
  de route) : hors lot ;
- signer depuis Orion (la signature reste dans `helios-publisher`) ;
- déposer le fichier sur la gateway depuis Orion : l'opérateur le copie par
  l'accès hors bande.

Anti-objectifs, échecs même si « ça marche » :

- **bloquer l'accès à la gateway** : un compteur NV absent ou en échec ne doit
  jamais empêcher `heliosd` de démarrer, seulement faire refuser les trois
  artefacts ;
- **consommer un fichier de récupération alors que le coffre s'ouvre** (vecteur
  de substitution d'identité, règle actuelle de `try_recovery` conservée) ;
- **accepter une autorisation avec une seule signature**, ou rejouer une
  signature d'un domaine sous un autre ;
- **laisser la clé privée en clair sur disque** après le démarrage qui l'a
  consommée ;
- **garder un chemin de repli vers `TpmState.version`** : une double
  acceptation serait une fenêtre de rejeu (ADR-002, « Migration »).

## 4. Approches considérées

| | Approche | Pour | Contre |
|---|---|---|---|
| A | Compteur NV dédié à F5, billet et firmware restent sur `TpmState.version` | Lot borné, amendement 5 intact | Deux mécanismes, migration à refaire plus tard |
| **B** | **Un compteur NV unique pour les trois artefacts** | Une source de vérité, vraie résistance au rejeu d'image disque, fichier compteur supprimé | Amendement 5 à rouvrir, billet et firmware à recâbler |
| C | Garder `TpmState.version` (option 1 de l'amendement 2) | Trivial | Ne protège pas contre l'attaquant visé : de la sécurité de façade |

**B retenue** par l'utilisateur.

## 5. Conception

### 5.1 Le compteur NV

- Un index NV de type **compteur** (`TPM_NT_COUNTER`) dans la plage
  propriétaire, à une adresse fixe dans `TpmSettings`
  (`anti_rollback_nv_index`, défaut `0x0180_4846`, voisin de
  `update_window_nv_index = 0x0180_4845`).
- Attributs : écriture et lecture sous l'autorisation propriétaire (même
  session à autorisation nulle que l'index de la fenêtre,
  `tpm_real.rs`), `no_da`. Le choix exact des attributs (ex. `OWNERWRITE`,
  `OWNERREAD` ou `AUTHREAD`) est laissé au constructeur, à justifier contre la
  spécification TPM 2.0.
- **Création** : dans le chemin de démarrage de `helios-tpm`
  (`BootController::unlock`), **avant** le dépouillement de la fenêtre, le
  billet et le provisionnement, si l'index est absent ; puis un premier
  `TPM2_NV_Increment` (un compteur non initialisé ne se lit pas). Un échec de
  création est journalisé et ne fait échouer que la consommation des
  artefacts, jamais le démarrage. *Choix du rédacteur* : le billet est vérifié
  dans ce chemin, le compteur doit donc exister avant lui.
- **Accès depuis `heliosd`** : une API de `helios-tpm` (lire, consommer une
  valeur attendue) prend `TpmSettings` et ouvre le TPM elle-même, comme les
  autres points d'entrée du crate ; `gateway_key.rs` l'appelle sans recevoir de
  poignée TPM. *Choix du rédacteur.* Par
  la spécification TPM, un nouveau compteur démarre à une valeur au moins égale
  au plus grand compteur que le TPM a porté : supprimer et recréer l'index ne
  le fait pas reculer. **Propriété à confirmer sur TPM réel** et à écrire dans
  la recette matérielle.
- La valeur n'est jamais remise à zéro ni écrite directement : seuls
  `read` et `increment` existent.
- Le trait `TpmSealer` (`tpm_interface.rs`) gagne les opérations du compteur
  (`ensure`, `read`, `increment`, noms au choix du constructeur) ; le TPM
  simulé des tests les porte, avec un état partageable comme `NvState` de la
  fenêtre.
- `TpmState`, `BlobStore::load_state`/`store_state` et le fichier d'état
  disparaissent. Un fichier d'état résiduel sur une gateway existante est
  ignoré (et peut être supprimé) ; il n'est jamais lu.

### 5.2 La règle de consommation, commune aux trois artefacts

Un compteur matériel ne s'incrémente que de 1 : on ne peut plus « sauter » à
la valeur signée comme le fait aujourd'hui `state.version = ticket.version()`.
D'où la règle :

1. un artefact porte le champ signé `counter` ;
2. il est **valide si et seulement si `counter` est égal à la valeur courante
   du compteur NV** (en plus de ses signatures et de ses autres liaisons) ;
3. la gateway **incrémente le compteur avant d'agir** (rescellement,
   restauration, adoption de la clé). Un artefact ne sert donc qu'une fois ; un
   arrêt brutal entre l'incrément et l'action le grille sans rien accorder :
   l'éditeur en signe un nouveau pour la nouvelle valeur.

Conséquence à documenter pour l'opérateur : quand un démarrage consomme
plusieurs artefacts, chacun vise la valeur laissée par le précédent. Le cas
réel est la mise à jour qui change les PCR : le billet de rescellement est
consommé en premier (compteur `C` → `C+1`), puis le fichier de récupération
WireGuard (`C+1` → `C+2`). L'éditeur signe donc le billet pour `C` et le
fichier pour `C+1`.

Un compteur illisible (TPM absent, index non créé, erreur) fait **refuser
l'artefact**, jamais l'accepter ; `heliosd` continue selon le chemin
d'aujourd'hui pour une gateway sans billet ou sans fichier valide.

**Conséquence imposée par D1 : les artefacts sont signés pour une gateway,
plus pour un parc.** Deux TPM n'ont pas la même valeur de compteur (un
compteur neuf démarre au plus grand compteur que son TPM a porté), donc un
billet unique ne peut plus servir à toutes les gateways d'une mise à jour. Le
billet suit le modèle de la restauration firmware : l'opérateur lit la valeur
et l'ancre de la gateway, l'éditeur signe pour elles. Les campagnes
multi-gateways sont des reportables (ROADMAP §7, « Horizon 5 »).

**D'où vient la valeur à signer.** La source qui fait foi est la gateway
elle-même : à chaque démarrage, `heliosd` journalise la valeur courante et
l'écrit dans un fichier public non secret à côté du séquestre (nom au choix
du constructeur), y compris quand le coffre ne s'ouvre pas et qu'aucun
artefact n'est valide. Ce fichier n'est jamais lu comme autorité par la
gateway (il est informatif). L'opérateur le lit par l'accès hors bande
(Tailscale, console) ou en lit la copie dans le séquestre (§5.5) si la
gateway est entièrement injoignable.

**Toute substitution d'identité incrémente le compteur.** La rotation de la
clé WireGuard (`gateway_key::initialize` avec `rotate`) consomme une valeur :
une autorisation de récupération signée pour l'ancienne identité et jamais
utilisée devient invalide. Si le compteur est indisponible, la rotation se
fait quand même et le journal l'indique (elle ne doit pas bloquer l'accès).
*Choix du rédacteur.*

### 5.3 Rupture des formats éditeur

La sémantique du champ change (égal au lieu de strictement supérieur) : une
signature donnée sous l'ancienne règle ne doit pas pouvoir être vérifiée sous
la nouvelle. Les domaines changent donc, sans période de double acceptation :

| Artefact | Avant | Après |
|---|---|---|
| Billet de rescellement | `helios-tpm-reseal-v2`, champ `version` | `helios-tpm-reseal-v3`, champ `counter` |
| Restauration firmware | `helios-firmware-recovery-v1`, champ `version` | `helios-firmware-recovery-v2`, champ `counter` |
| Récupération WireGuard | aucune signature | `helios-wg-recovery-v1` (déjà réservé, ADR-002 « Domaines de séparation ») |

Les octets canoniques gardent leur forme (`counter` en `u64` gros-boutiste en
tête) ; le domaine, le nom JSON du champ et `FORMAT_VERSION` changent. La
restauration firmware enregistre `counter = valeur courante` dans sa requête
de préparation (aujourd'hui `version + 1`).

Le billet gagne en plus `sealed_blob_anchor: [u8; 32]` (SHA-256 du blob
scellé courant, même définition que la restauration firmware), qui le lie à la
gateway : deux TPM peuvent porter la même valeur de compteur, pas le même
blob. Le blob reste sur disque quand le descellement échoue, la gateway peut
donc recalculer l'ancre au moment de vérifier. Une commande de préparation du
billet (sur la gateway, comme `heliosd tpm` pour la restauration firmware)
produit la requête publique `{counter, sealed_blob_anchor}` ; l'éditeur la
signe, avec le digest PCR attendu s'il le connaît.

### 5.4 L'autorisation de récupération WireGuard

Nouveau payload dans `aether::sig`, `WireGuardRecoveryPayload` :

- `counter: u64` ;
- `gateway_public_key: [u8; 32]` : la clé publique WireGuard de l'identité
  restaurée ;
- `expected_pcr_digest: Option<[u8; 32]>` : « si présent, doit
  correspondre » (amendement 1, même forme que le billet).

L'éditeur **ne voit jamais la clé privée** : il signe la requête publique,
comme pour la restauration firmware.

Fichier déposé à `/var/lib/helios/wg-key.recovery` : une trame comme
`firmware_recovery::encode_restore_frame` (longueur `u32` gros-boutiste,
autorisation JSON, puis les 32 octets bruts de la clé privée), lue dans un
tampon `Zeroizing`. Taille bornée.

Vérification par `heliosd`, dans `try_recovery`, toujours **uniquement quand
le coffre est indéchiffrable** :

1. trame bien formée, sinon fichier ignoré et laissé en place (comportement
   actuel pour un fichier invalide) ;
2. enveloppe valide sous `PUBLISHER_KEYS` (Ed25519 **et** ML-DSA-65, époque
   signée) ;
3. la clé privée dérive exactement `gateway_public_key` ;
4. `expected_pcr_digest`, s'il est présent, égale le digest PCR courant ;
5. `counter` égale le compteur NV courant ;
6. incrément du compteur ; s'il échoue, rien n'est adopté ;
7. rescellement de la clé, puis effacement du fichier (comportement actuel,
   y compris l'alerte si l'effacement échoue).

Tout refus est journalisé avec sa cause (signature, identité, PCR, compteur
attendu et trouvé), sans jamais écrire la clé.

### 5.5 Le séquestre porte le compteur

La gateway est injoignable au moment de la récupération : l'opérateur doit
lire dans le séquestre tout ce que l'éditeur signera.

- Format `HESC` version 2 : l'en-tête ajoute, en clair, la valeur du compteur
  NV au moment de l'écriture et la clé publique WireGuard. L'en-tête entier
  est lié par l'AAD de l'AES-256-GCM, de sorte qu'une valeur modifiée rend le
  séquestre impossible à ouvrir. HESC v1 n'est plus écrit ; son ouverture par
  l'outil opérateur reste possible mais ne donne pas de requête signable
  (message explicite).
- `write_escrow` écrit déjà le séquestre à chaque démarrage qui ouvre le
  coffre : la valeur y est donc celle du dernier démarrage nominal. Elle peut
  être en retard sur le TPM (un billet consommé sans récupération réussie) :
  le fichier public de §5.2 fait foi, le séquestre est le repli quand la
  gateway est entièrement injoignable, et l'outil opérateur le dit.
- La valeur écrite est celle **attendue par le fichier de récupération** : si
  la prochaine récupération suit forcément un billet (§5.2), le séquestre
  l'indique (`counter` du billet = `C`, du fichier = `C+1`). La présentation
  exacte (une valeur et la règle, ou les deux valeurs) est laissée au
  constructeur, pourvu que l'outil opérateur imprime sans ambiguïté la valeur
  à signer pour chaque artefact.

### 5.6 La cérémonie opérateur : un seul cœur, deux façades

**Décision de l'utilisateur** : la cérémonie se fait **dans Orion**, et la CLI
et Orion appellent **la même fonction** qui rend ce service, comme la « porte
unique » d'Astra au lot 5a de F14 (une seule fonction du service, plusieurs
connecteurs).

La gateway est injoignable par le tunnel pendant une récupération (elle n'a
plus sa clé) : ce cœur est donc une **bibliothèque hors ligne**, pas une API
réseau. Il travaille sur des fichiers que l'opérateur détient : le séquestre
`wg-key.escrow`, la clé privée de séquestre, l'autorisation signée.

- **Le cœur** (dans `helios-escrow`, ou un module voisin si le constructeur le
  justifie) expose deux opérations :
  1. *préparer* : ouvre un séquestre v2 avec la clé de séquestre et rend la
     requête publique (`WireGuardRecoveryPayload`, digest PCR optionnel fourni
     par l'appelant), la clé publique de l'identité et les valeurs de compteur
     lues dans l'en-tête ; il ne rend **jamais** la clé privée WireGuard ;
  2. *assembler* : rouvre le séquestre avec la clé de séquestre, vérifie
     l'autorisation (signatures sous le trousseau éditeur compilé, domaine,
     `gateway_public_key` = identité du séquestre, `counter` attendu) et rend
     la trame à déposer dans un tampon `Zeroizing`.
  Rouvrir le séquestre à l'assemblage évite tout fichier intermédiaire de clé
  privée en clair entre les deux étapes, qui peuvent être séparées de
  plusieurs jours par la signature. *Choix du rédacteur* ; l'actuel
  `helios escrow open`, qui écrit la clé en clair dans un fichier, disparaît
  au profit de ces deux opérations.
- **Orion** : un bloc « Récupérer l'identité de la gateway » dans l'espace
  opérateur, sur le modèle des cérémonies par fichiers du lot 6a de F14
  (sélection de fichiers, aucun tunnel). Étape 1 : séquestre + clé de
  séquestre → affiche la clé publique et la valeur à signer, enregistre la
  requête. Étape 2 : séquestre + clé de séquestre + autorisation → enregistre
  le fichier à déposer, en rappelant où le déposer
  (`/var/lib/helios/wg-key.recovery`, par l'accès hors bande) et qu'il
  contient la clé en clair. Refus en classe fermée avec une phrase française
  par cas, comme les autres cérémonies.
- **CLI** : `helios escrow` garde ses sous-commandes en façade mince sur le
  même cœur (noms au choix du constructeur), pour la gateway sans poste Orion
  et pour les tests de bout en bout.
- **Éditeur** : `helios-publisher wg-recovery` (nouvelle sous-commande de
  l'outil existant) signe une requête publique, refuse d'écraser, comme
  `firmware-recovery`. `reseal-ticket` et `firmware-recovery` passent au champ
  `counter` et aux nouveaux domaines. La signature reste hors d'Orion : c'est
  l'outil de l'éditeur, pas un outil de poste.
- **Préparation du billet** (§5.3) : commande côté gateway, comme
  `heliosd tpm` pour la restauration firmware ; pas dans Orion pour ce lot.

### 5.7 Exposition

- `heliosd` journalise au démarrage la valeur du compteur NV (ou son
  indisponibilité).
- Ce qui expose aujourd'hui la posture TPM (la console, `GET /api/trust` ou
  le statut TPM, selon ce qui existe) indique la valeur du compteur et sa
  disponibilité, sans rien de secret. Le constructeur choisit l'endroit
  existant le plus proche ; aucun écran nouveau.

## 6. Contraintes

- ADR-002 est normatif : `REQUIRED_ALGS` (Ed25519 **et** ML-DSA-65, jamais
  « au moins une »), époque de clé dans les octets signés (amendement 3), clés
  éditeur compilées dans le binaire, la gateway ne fait que vérifier.
- ADR-006 §5 : toute copie de la clé privée vit dans un tampon `Zeroizing`.
- La fenêtre de mise à jour d'ADR-007 et son index NV sont inchangés ; les
  deux index ne se recouvrent pas.
- Le TPM réel reste derrière la feature `tpm` de `helios-tpm` (absente sous
  WSL2) ; le code testé sous WSL passe par le trait `TpmSealer`.
- Versions : `scripts/version.py merge` (AGENTS.md, Versions). Le changement
  des formats éditeur est une rupture (commit `!`).
- Documents à mettre à jour : ADR-002 (amendement 2 tranché, amendement 5,
  domaines, état d'implémentation, lot 3), MAINTENANCE.md (procédure de
  récupération et de billet avec le compteur), ROADMAP (D1, F5), TESTING.md et
  MANUAL-TESTING.md (recette matérielle du compteur NV).

## 7. Tests

Sous WSL, avec le TPM simulé :

- le compteur : création au premier démarrage, lecture, incrément ; une
  gateway sans compteur démarre et refuse les trois artefacts ;
- la règle §5.2 pour chaque artefact : valeur égale acceptée, inférieure et
  supérieure refusées, rejeu refusé après consommation, incrément fait avant
  l'action (un échec de l'action après l'incrément ne rend pas l'artefact
  réutilisable) ;
- billet puis récupération dans le même démarrage, avec `C` et `C+1` ;
- billet lié à l'ancre : signé pour un autre blob, refusé ;
- rotation de la clé : le compteur avance, une autorisation de récupération
  signée avant la rotation est refusée ;
- le fichier public du compteur est écrit aussi sur le chemin d'échec
  (coffre indéchiffrable, aucun artefact valide) ;
- récupération : signature manquante ou d'un autre domaine, clé ne dérivant
  pas `gateway_public_key`, PCR attendu différent, trame tronquée ou trop
  longue, coffre qui s'ouvre (fichier jamais consommé) ;
- séquestre v2 : aller-retour, en-tête modifié refusé, v1 ouvert sans requête ;
- cœur de la cérémonie : préparer → `wg-recovery` → assembler → consommation
  par `heliosd`, de bout en bout dans un test ; *assembler* refuse une
  autorisation pour une autre identité, un autre compteur, une signature
  manquante, sans rien écrire ; *préparer* ne rend jamais la clé privée ;
- Orion : les deux étapes de la cérémonie appellent le cœur (tests de
  commande), et l'IHM affiche chaque refus avec sa phrase (Vitest) ;
- les tests existants du billet et de la restauration firmware sont portés à
  la nouvelle règle (amendement 4 : les tests prouvent la bascule).

Recette matérielle (reportée) : compteur créé sur un TPM réel, survit au
redémarrage, ne recule pas après suppression et recréation de l'index, OTA
avec changement de PCR suivie d'une récupération signée.

## 8. Laissé au constructeur

- les attributs NV exacts, à justifier ;
- les noms des opérations du trait et des sous-commandes ;
- la présentation des valeurs de compteur dans l'en-tête du séquestre (§5.5) ;
- l'endroit d'exposition de la valeur (§5.7) ;
- la borne de taille de la trame de récupération.
