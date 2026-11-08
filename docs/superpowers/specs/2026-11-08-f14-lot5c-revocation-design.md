# F14 lot 5c : révoquer un poste depuis Orion

Conception du 8 novembre 2026. Suite des lots 5a (porte unique d'Astra) et 5b
(rotations dans Orion). Branche `feat/f14-lot5c-revocation`.

## 1. Intention

Révoquer un poste se fait aujourd'hui en deux commandes : `astra revocation
open` dans la console d'Astra, puis `astra-signer revoke` sur le poste de
l'opérateur, avec un identifiant et une échéance à recopier
(`RENOUVELLEMENT-CERTIFICATS.md` §7). L'utilisateur ne peut pas s'en servir : les
commandes sont « imbouffables » (lot 5b). Ce lot met la révocation d'un poste
dans Orion, sur le modèle des rotations du 5b : un écran, des prérequis
vérifiés, des libellés courts, les clés validées une par une.

Il lève aussi la limite F14-b du 5b. Pendant un recouvrement `CA-PQ` (37 jours
au plus par défaut), aucune révocation ne se signe : la clé sortante a quitté
le coffre alors qu'Astra et les postes vérifient encore sous elle. Or ce sont
justement les postes administrateurs qu'il faut pouvoir couper à tout moment :
un poste admin volé, avec le tunnel, peut ouvrir des opérations sur la gateway
et remplacer la copie du coffre (F14-f), sans rien pouvoir signer.

## 2. Décisions de l'utilisateur (8 novembre 2026)

- **Lot choisi** : le 5c avant le 6b (« fait celui qui est le mieux »).
- **Identifier un poste par le nom donné à son ajout** (« PC_FIXE ») : le nom
  d'admission que la gateway garde, et qu'Astra recopie dans `PeerRecord.name`
  pour les postes qu'elle connaît.
- **Pas de parcours d'urgence allégé** : l'utilisateur a toutes ses clés sous la
  main ; une révocation n'est pas un cas extrême pour lui. Le parcours est celui
  du 5b.
- **F14-c tranché : les renouvellements restent bloqués pendant un recouvrement
  `CA-PQ`**, avec un avertissement avant « Remplacer la CA-PQ » quand un poste
  arrive en fin de certificat dans la fenêtre. Voir §5.6 pour ce que ce lot
  apprend à ce sujet.

## 3. Objectifs

1. Un onglet *Postes* dans l'espace Astra d'Orion liste les postes du domaine
   et permet de révoquer un poste client, sans commande ni fichier.
2. La révocation coupe le poste **tout de suite** à la gateway, puis signe et
   dépose la révocation qu'Astra distribue, y compris pour un poste qu'Astra
   n'a encore jamais vu (§5.3).
3. La révocation reste possible **pendant un recouvrement `CA-PQ`** (F14-b).
4. Orion avertit avant « Remplacer la CA-PQ » si un poste expire pendant la
   fenêtre.
5. Les deux mineurs laissés par le 5b sont corrigés (§5.8), et `ROADMAP.md` est
   mise à jour (le 5b y est encore « pas fusionné »).

## 4. Non-objectifs et anti-objectifs

- **Révoquer la gateway** : reste dans la console d'Astra (§7 de
  `RENOUVELLEMENT-CERTIFICATS.md`), avec le lot 6b.
- **Réadmettre un poste révoqué** : c'est un nouvel enrôlement (lots 1-2),
  inchangé.
- **Débloquer « Renouveler les postes » pendant un recouvrement `CA-PQ`** :
  décision de l'utilisateur (§2).
- **Révocation à effet futur** : Astra n'accepte que l'effet immédiat
  (`registry/transitions.rs`) ; Orion n'en propose pas d'autre.
- Anti-objectif : un bouton qui révoque d'un clic. Une révocation est
  définitive ; elle se confirme.
- Anti-objectif : une révocation affichée « faite » alors que le poste peut
  encore se connecter, ou l'inverse.

## 5. Conception

### 5.1 L'écran *Postes*

Un onglet de l'espace Astra, à côté de *Rotations*. Une ligne par poste :

```
Postes                                                   ↻
┌───────────────────────────────────────────────────────────┐
│ PC_FIXE          Ce poste   Actif     jusqu'au 03/09/2027  │
│ PORTABLE                    Actif     jusqu'au 12/01/2027  [Révoquer] │
│ PC_BUREAU                   Révoqué   le 08/11/2026        │
└───────────────────────────────────────────────────────────┘
```

- **Nom** : celui donné à l'ajout. La gateway refuse deux postes admis au même
  nom (`helios-provisioning/src/admission.rs`, `NameTaken`) ; un doublon ne
  peut venir que d'un poste révoqué puis réenrôlé sous le même nom. La date
  d'ajout s'affiche alors pour les distinguer *(choix de conception)*.
- **États** : « Actif », « Renouvellement en cours », « Coupé, révocation à
  signer » (§5.3), « Révoqué ». Les postes révoqués restent listés, grisés.
- **Échéance** : celle du certificat actif.
- **« Ce poste »** : le poste où tourne Orion, reconnu par sa clé WireGuard
  dans le profil du domaine. Pas de bouton « Révoquer » sur cette ligne : la
  coupure ôterait le tunnel dont la signature a besoin. La ligne dit « Se
  révoque depuis un autre poste administrateur. » *(choix de conception, §10)*.
- **Sources** :
  - la **gateway** tient l'admission (`/api/network`) et l'état de certificat
    de chaque poste admis ou coupé ; c'est la source de la liste, des noms et
    des échéances ;
  - **Astra** recopie les postes admis (§5.3) ; elle seule sait qu'un poste
    est révoqué.

  Il faut une lecture des postes d'Astra par le tunnel : route en lecture
  seule, pair administrateur, relayée par heliosd comme `operator/status`
  (clé, état, opération de révocation en attente). Sa forme exacte est laissée
  au constructeur. Orion fusionne par clé WireGuard.
- **États calculés, jamais enregistrés localement** *(choix de conception)* :
  - « Actif » : admis à la gateway, non révoqué chez Astra ;
  - « Coupé, révocation à signer » : plus admis à la gateway, non révoqué chez
    Astra. Cela couvre aussi un poste retiré depuis la console web, et un autre
    poste administrateur voit le même état ;
  - « Révoqué » : révoqué chez Astra ;
  - « Révoqué, gateway pas encore informée » : révoqué chez Astra et encore
    admis à la gateway (§5.7).
- Pas de lecture continue : à l'ouverture de l'onglet, au bouton ↻ et après
  chaque geste *(choix de conception, cohérent avec le 5b)*.

### 5.2 Parcours de « Révoquer »

Les quatre étapes du 5b (`RotationSteps.tsx`) :

1. **Prérequis**, en deux groupes :
   - pour **couper** : tunnel, droit d'administration, gateway du domaine. Rien
     d'autre ne peut retarder la coupure (§5.3) ;
   - pour **signer** : service Astra, coffre, domaine concordant, et la
     signature possible (§5.4). S'il manque l'un d'eux, la coupure se fait quand
     même et la ligne reste « Coupé, révocation à signer », avec la raison.
2. **Motif** : quatre choix courts, mappés sur `RevocationReason` *(libellés :
   choix de conception)* :
   - « Volé ou perdu » → `suspected_compromise` ;
   - « Compromis » → `key_compromise` ;
   - « Plus utilisé » → `cessation` ;
   - « Remplacé » → `superseded`.

   Puis la confirmation : « Révoquer PORTABLE ? Le poste sera coupé tout de
   suite. C'est définitif. »
3. **Clés** : la campagne de révocation ouverte par la porte d'Astra (lot 5a,
   action `client_revocation`), les clés validées une par une avec leur état
   affiché, comme au 5b. Autant de clés que la campagne en demande (une
   aujourd'hui). Puis « Approuver » : la révocation est signée sous `CA-PQ` et
   déposée.
4. **Suivi** : « Révoqué ». Astra marque le pair `revoked`, refuse ses
   renouvellements et distribue la décision.

Les deux feuilles sont révoquées (`halves = both`). Pas de choix TLS/PQ à
l'écran.

### 5.3 Couper d'abord, signer ensuite

La spécification est normative : pour un client, le retrait de l'admission est
la révocation immédiate de référence, et l'objet signé « ne doit jamais
retarder le retrait de l'admission » (`ROTATION-CERTIFICATS.md` §10.2).

Donc, **à la confirmation de l'étape 2**, avant les clés, Orion retire
l'admission à la gateway. La route administrateur existante prend un nom
(`POST /api/peers/revoke`). Juste avant, Orion relit `/api/network` et vérifie
que ce nom désigne bien la clé WireGuard visée ; sinon, il refuse sans rien
couper. Comme la gateway interdit deux postes admis au même nom, la
correspondance est unique *(choix de conception : pas de nouvelle route par
clé)*. Le poste est coupé à cet instant. Si la suite
n'aboutit pas (clé absente, cérémonie annulée, Astra injoignable), la ligne
reste « Coupé, révocation à signer » avec « Reprendre », qui recommence à
l'étape 3. Ce qui reste à faire se voit donc toujours, et rien n'est
silencieusement perdu.

**Astra connaît tous les postes admis** (décision de l'utilisateur,
8 novembre 2026 : « astra devrait connaître les pc admis, sinon cela peut
causer ce genre de soucis »). Aujourd'hui, l'enrôlement est hors ligne et
Astra n'inscrit un poste qu'à son premier contact : tout poste dans sa première
année lui est inconnu, et l'ouverture `client_revocation` le refuse
(`door/resolve.rs`, `PeerUnknown`). **Changement côté Astra et gateway** :

- la gateway sert, sur le canal privé, la liste des états de certificat de ses
  postes admis (route nouvelle, voisine de `state/{clé}` ; un poste coupé reste
  servi, son état de certificat n'étant pas effacé par la coupure) ;
- le balayage périodique d'Astra la lit et inscrit chaque poste qu'elle ne
  connaît pas, par le même chemin que le premier contact
  (`reconcile_peer` et ses règles d'adoption) ; un poste déjà connu n'est
  réconcilié que par ses chemins actuels ;
- l'ouverture d'une révocation cliente lit aussi ce poste auprès de la gateway
  s'il est encore inconnu, pour ne pas dépendre du dernier balayage.

ADR-008 le permet : « la gateway reste l'autorité sur l'admission ». Astra
recopie ce que la gateway a admis, elle ne décide rien. Un poste que la gateway
ne connaît pas non plus est refusé par son nom. La période du balayage et la
forme de la route sont laissées au constructeur.

### 5.4 Pendant un recouvrement `CA-PQ` (F14-b)

**Ce qui bloque aujourd'hui.** Pendant le recouvrement, Astra vérifie une
révocation sous `state.ca_public_key`, l'ancre sortante, jusqu'à `not_after`
(`registry/transitions.rs`). Orion vérifie aussi sous `current_ca_public_key`
(`orion-core/src/certificates.rs`). Or `rotate_ca_pq` remplace la clé `CA-PQ` dans le coffre dès la
signature (`signing/anchor.rs`) : c'est ce coffre, porté par le journal, qui
devient le coffre local au stade `Applied`. Le même passage remplace le fichier
de credentials local et l'époque du relais (`rotation_journal.rs`,
`operations/rotation.rs`).

**Ce que dit la spécification.** « L'ancienne clé privée peut être détruite
seulement après la fin de la fenêtre et la publication durable de la
transition » (`ROTATION-CERTIFICATS.md` §9.2). Le code de la rotation `CA-TLS`
le fait déjà (`RetainedCaTls`, `vault.rs`). La rotation `CA-PQ` est en écart.

**Conception.**

- Le coffre **garde la clé `CA-PQ` sortante**, avec sa clé publique et son
  `ca_epoch`, scellée à côté de l'entrante, **dès la signature** de la rotation
  et jusqu'à « Terminer ». C'est l'image inverse de `RetainedCaTls`, qui garde
  l'entrante. Un champ optionnel avec `serde(default)` : un coffre écrit avant
  ce lot se lit tel quel. `AuthoritySecrets` refuse les champs inconnus, donc
  un coffre écrit par ce lot ne s'ouvre plus avec un Orion ou un `astra-signer`
  plus ancien ; c'est accepté, à dire dans les notes de version. Les fonctions
  qui reconstruisent `AuthoritySecrets` champ par champ
  (`replace_anchors`, `stage_ca_tls_successor`) le reportent.
- Elle ne sert qu'à **une** chose : signer une révocation tant que l'ancre
  qu'Astra vérifie est la sortante. Aucun autre chemin ne la lit. Le signataire
  prend la clé **et** l'époque qui correspondent à l'ancre qu'Astra sert
  (`operator/status`), jamais par défaut : `sign_revocation` prend aujourd'hui
  l'époque dans `identity.ca_epoch`, il faudra la lui passer.
- **Marge avant `not_after`** : Astra et la gateway basculent chacune sur leur
  horloge. Une révocation signée sous la sortante dans la dernière heure
  pourrait être acceptée par Astra et refusée par une gateway déjà basculée.
  Dans l'heure qui précède `not_after`, la signature est refusée avec « Révocation
  possible après le JJ/MM HH:MM » ; la coupure, elle, reste possible
  *(choix de conception, une constante)*.
- **La destruction** : « Terminer la rotation CA-PQ » apparaît dès
  `not_after`, comme « Terminer » pour la `CA-TLS` (§5.7 du 5b), avec une clé.
  Elle détruit la clé sortante en une écriture scellée, puis envoie la copie du
  coffre à Astra comme après un geste de clé (5b). Toute rotation d'ancre,
  `CA-PQ` ou `CA-TLS`, est refusée tant que ce n'est pas fait. Limite acceptée
  : la génération précédente de la copie gardée par Astra (F14-f) contient
  encore la clé sortante, scellée sous les mêmes clés de sécurité, jusqu'au
  geste suivant qui change le coffre.
- **Les approbations pendant le recouvrement.** Astra vérifie une
  approbation de campagne contre le document de credentials qu'elle sert
  (`service.rs`, `status/campaign_approval.rs`), et pendant le recouvrement
  c'est encore le document sortant (`daemon.rs`, test
  `the_overlap_keeps_serving_the_outgoing_document`). L'empreinte d'une liaison
  couvre `ca_epoch`, l'époque du registre et la signature `CA-PQ`. Le coffre a
  re-signé ses liaisons sous l'entrante, d'où le refus constaté au 5b (§10.1).
  L'approbation d'une révocation doit donc se faire sous **le document
  sortant, tel qu'Astra le sert**.
  - **D'où il vient** : d'Astra, pas d'une copie locale. Une copie prise avant
    la rotation peut différer de celle d'Astra (geste de clé jamais envoyé), et
    l'époque du registre est dans l'empreinte. Une lecture par le tunnel le
    renvoie entier : champ de `operator/status` ou route voisine, au choix du
    constructeur, relayée par heliosd.
  - **Comment Orion le croit** : il le vérifie sous la clé publique sortante
    gardée dans le coffre et son `ca_epoch` (ci-dessus). Un document qui ne se
    vérifie pas fait refuser la signature par son nom.
  - **Étape Clés** : seules les clés actives du document sortant sont
    proposées. Une clé ajoutée après la rotation dit « Utilisable après le
    JJ/MM ». Une clé marquée perdue après la rotation reste admise par Astra
    jusqu'à `not_after` : c'est la limite déjà connue du 5b, et Orion ne la
    propose pas.
  - Le constructeur prouve par un test de bout en bout côté Astra qu'une
    révocation approuvée sous le document sortant et signée sous la clé
    sortante, pendant un recouvrement, est acceptée par Astra **et** par la
    gateway (`heliosd/src/certificates/astra.rs` vérifie sous son ancre
    courante). S'il n'y arrive pas, il s'arrête et le signale : sans cela,
    F14-b n'est pas levé.
- **La migration.** Une rotation déjà en `Applied` avant ce lot n'a pas gardé
  la clé sortante. Pour elle, la révocation reste impossible jusqu'à
  `not_after`. Le bouton est grisé avec la raison affichée (« Révocation
  possible après le JJ/MM »).
- **L'outil `astra-signer rotate-ca-pq`** partage la fonction de rotation : il
  garde la clé sortante de la même façon.

### 5.5 Avertissement avant « Remplacer la CA-PQ »

Dans les prérequis de « Remplacer la CA-PQ » : si un poste du registre a une
échéance active avant `not_after` de la fenêtre prévue, une ligne
d'avertissement le nomme : « PORTABLE expire le 12/01/2027, pendant le
changement. » C'est un avertissement, pas un blocage *(choix de conception)*.

### 5.6 Ce que ce lot apprend sur F14-c

Le §10.1 du 5b dit aussi que **le renouvellement d'un client par le moteur
d'Orion**, la feuille cliente à 80 %, reste possible pendant le recouvrement.
Ce qui est bloqué, c'est la campagne de parc « Renouveler les postes ».
L'avertissement du §5.5 couvre donc un cas plus rare que celui décrit à
l'utilisateur.

Si le §5.4 marche (approuver sous le document sortant), le même mécanisme
pourrait débloquer « Renouveler les postes ». Ce lot ne le fait pas, par
décision de l'utilisateur. Le suivi F14-c le note.

### 5.7 Erreurs et refus

- **Courts et neutres.** Jamais de « tu » ; un refus dit sa cause et ce qui
  reste à faire. Exemples : « Poste déjà révoqué. » ; « Une révocation de ce
  poste attend déjà. » ; « Astra injoignable. Le poste est coupé ; la
  révocation reste à signer. »
- **Révocation déjà en attente.** Une seconde révocation du même poste est
  refusée tant que la première attend (déjà vrai côté Astra). Orion propose
  alors « Reprendre ».
- **Dépôt perdu.** Le dépôt est idempotent : « Reprendre » renvoie la même
  décision signée, sans redemander de clé, si elle a été signée et non
  confirmée, tant que sa campagne vit. Elle est gardée localement, sur le
  modèle du journal du 5b. Une décision signée ne sert que sous sa campagne
  (règle du 5b) : campagne expirée sans dépôt accepté, la décision est jetée
  et « Reprendre » recommence à l'étape 3.
- **Relais vers la gateway.** Astra marque le pair `revoked` en enregistrant la
  décision, puis la relaie à la gateway (`service.rs`). Si ce relais échoue, rien
  ne le rejoue après la campagne. **Changement côté Astra** : une révocation
  enregistrée et non accusée par la gateway est rejouée par le balayage
  périodique d'Astra jusqu'à l'accusé. Entre-temps la ligne dit « Révoqué,
  gateway pas encore informée » ; le poste, lui, est déjà coupé.

### 5.8 Suivis du lot 5b

- **N1** : la ligne « Copie du coffre » de *Coffre et clés* se relit quand le
  tunnel monte et après chaque geste, pas seulement à l'ouverture de l'onglet.
  Une ligne d'envoi retenu ou échoué, avec son bouton, survit à un changement
  de vue.
- **N2** : pendant un recouvrement `CA-PQ`, la ligne persistante dit que le
  document attend la fin du recouvrement, comme l'annoncent
  `RENOUVELLEMENT-CERTIFICATS.md` §6 et ADR-008.
- **`ROADMAP.md`** : 5b fusionné le 8 novembre 2026 (Helios 3.0.0, Orion 3.0.0),
  5c en cours. F14-b est levé par ce lot ; F14-c reste avec la décision du §2.

## 6. Sécurité

- **Aucun secret dans la WebView** : ni PIN, ni `Opened`, ni octets du coffre,
  ni clé privée. Le parcours réutilise le fil de cérémonie du 5b.
- **Clé `CA-PQ` sortante** : scellée, jamais en clair hors de la cérémonie, lue
  par la seule signature de révocation, détruite à « Terminer ». Un test montre
  qu'aucun autre chemin de signature ne la lit.
- **Retrait d'admission** : une route administrateur existante, par le tunnel.
  Orion vérifie que la gateway jointe est celle du domaine (même garde que
  l'envoi de la copie du coffre au 5b) avant de retirer quoi que ce soit.
- **Liaison de la cible** : la campagne d'Astra fige l'identité, la génération,
  les empreintes et le compteur. Orion affiche ce que la campagne nomme, pas ce
  qu'il a cliqué, et refuse si les deux diffèrent.

## 7. Tests et recette

- **Tests unitaires et d'intégration** :
  - coffre avec et sans clé sortante, dont la lecture d'un coffre ancien ;
  - signature sous la bonne clé et la bonne époque, refus dans la marge avant
    `not_after` ;
  - aucun autre chemin de signature ne lit la clé sortante ;
  - destruction à « Terminer », refus d'une rotation d'ancre avant ;
  - coupure refusée quand le nom ne désigne pas la clé visée ;
  - coupure possible quand Astra ou le coffre manquent ;
  - révocation d'un poste qu'Astra n'a jamais vu, lu auprès de la gateway ;
  - reprise après un dépôt perdu, campagne vivante puis expirée ;
  - rejeu du relais vers la gateway par le balayage d'Astra ;
  - états calculés et écarts entre gateway et Astra.
- **Bout en bout côté Astra** : une révocation signée sous la clé sortante et
  approuvée sous le document sortant, pendant un recouvrement, est acceptée
  (§5.4).
- **Recette** : section « H. Lot 5c » de `MANUAL-TESTING.md`, avec les étapes
  qui ne se jouent que sur la cible (vraies clés, Windows).
- **Régression** : `scripts/regression.sh` verte avant fusion.

## 8. Documentation

- `RENOUVELLEMENT-CERTIFICATS.md` §7 : le geste Orion d'abord, les commandes
  comme recours jusqu'au lot 7.
- `ROTATION-CERTIFICATS.md` : un amendement daté sur la clé sortante gardée,
  qui remet la `CA-PQ` en accord avec le §9.2.
- La conception du 5b (§10.8) et ADR-008 : F14-b levé, par un renvoi daté.
- `ROADMAP.md` : §5.8.

## 9. Laissé au constructeur

- La forme de la lecture des postes par le tunnel (§5.1).
- L'emplacement de la clé sortante dans le coffre, et le nom des types.
- Où garder une révocation signée et non confirmée (§5.7).
- Le découpage en tâches, et l'ordre.

## 10. Choix du concepteur après relecture (8 novembre 2026)

Une relecture contre le code a corrigé quatre affirmations de la première
version et posé huit questions. Choix faits, à vérifier par l'utilisateur :

1. Le document sortant vient d'Astra par le tunnel, vérifié sous la clé
   publique sortante gardée au coffre (§5.4).
2. Astra recopie tous les postes admis par la gateway, par son balayage et à
   l'ouverture d'une révocation (§5.3). Décidé par l'utilisateur le
   8 novembre 2026.
3. « Ce poste » ne se révoque pas depuis lui-même, mais depuis un autre poste
   administrateur (§5.1).
4. La coupure n'attend ni Astra, ni le coffre, ni la fin d'un recouvrement ;
   seule la signature peut attendre (§5.2).
5. Les états sont calculés depuis la gateway et Astra, jamais enregistrés
   localement (§5.1).
6. La coupure passe par la route existante, par nom, après vérification du nom
   contre la clé (§5.3).
7. Le balayage d'Astra rejoue le relais d'une révocation vers la gateway, et la
   signature sous la clé sortante est refusée dans l'heure qui précède
   `not_after` (§5.4, §5.7).
8. « Terminer la rotation CA-PQ » renvoie la copie du coffre ; la génération
   précédente gardée par Astra est une limite acceptée (§5.4).

