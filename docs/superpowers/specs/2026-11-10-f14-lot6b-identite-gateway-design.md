# F14 lot 6b : l'identité de la gateway depuis Orion

Conception du 10 novembre 2026. Suite des lots 5a (porte unique d'Astra), 5b
(rotations dans Orion), 5c (révocation d'un poste) et 6a (amorçage de la
gateway). Dernier lot avant le retrait d'`astra-signer` (lot 7). Branche
`feat/f14-lot6b-identite-gateway`.

## 1. Intention

Changer l'identité de la gateway passe aujourd'hui par trois endroits et des
fichiers à porter (`RENOUVELLEMENT-CERTIFICATS.md` §7.1, §8, §8.1, §10) :

- sur la gateway, préparer la demande (console *Certificats* ou `heliosd
  prepare-gateway-certificate`) ;
- dans le conteneur Astra, `astra gateway-identity open`, puis `publish` ;
- sur le poste de l'opérateur, `astra-signer sign-gateway-transition`,
  `abort-gateway-transition`, `sign-gateway-rollback`, `revoke --scope gateway` ;
- de nouveau sur la gateway, installer le fichier signé.

L'utilisateur ne l'a jamais fait. Le lot ne répond pas à une gêne vécue : il
garantit que, le jour où la gateway doit changer d'identité (échéance de sa
feuille, clé perdue, compromission), le geste existe dans Orion, aussi simple
qu'une rotation de CA au 5b. Sans lui, le lot 7 retirerait `astra-signer` en
perdant ces gestes, et une gateway compromise imposerait de reconstruire le
domaine.

## 2. Décisions de l'utilisateur (10 novembre 2026)

- **But du lot** : couvrir dans Orion tout ce qu'`astra-signer` fait pour
  l'identité de la gateway, pour pouvoir le retirer au lot 7 sans perte.
- **Parcours accepté** tel que proposé : une ligne « Renouveler l'identité de la
  gateway » dans *Rotations*, tout par le tunnel, sans fichier ni commande ;
  « Annuler » avant publication ; « Revenir à l'ancienne identité » pendant le
  recouvrement ; « Révoquer la gateway » avec son remplaçant d'urgence.
- **Conception validée le 10 novembre 2026**, avec les choix du concepteur marqués comme tels.
- **Redémarrage de `heliosd` hors du lot** : Orion le dit, il ne le fait pas.
- Les règles du 5b restent : liste avec ce qui est à faire en premier,
  prérequis vérifiés avant toute ouverture, libellés courts et neutres sans
  « tu », clés validées une par une avec leur état.

## 3. Objectifs

1. **Renouveler l'identité de la gateway** (§5.2) : remplace
   `prepare-gateway-certificate` + `gateway-identity open` +
   `sign-gateway-transition` + installation + `gateway-identity publish`.
   Variantes : feuille TLS remplacée aussi ; clé de la gateway perdue
   (`key_recovery`).
2. **Annuler le renouvellement** (§5.3) : remplace `abort-gateway-transition`
   et l'installation de l'avortement.
3. **Revenir à l'ancienne identité** (§5.4) : remplace `sign-gateway-rollback`
   et sa pose sur la gateway.
4. **Révoquer la gateway** (§5.5) : remplace `revoke --scope gateway` et, par
   défaut, `sign-gateway-transition --emergency-replacement` dans l'ordre imposé.
5. **Tout renouveler** (§5.6) : remplace `astra chain open/next/status/abandon`
   et les quatre commandes d'approbation, retiré de l'écran au 5b en attendant
   ce lot.
6. **La porte d'Astra** ouvre ces actions par le tunnel (§5.1).
7. Documentation et recette (§8).

## 4. Non-objectifs et anti-objectifs

- **Redémarrer `heliosd`** : décision de l'utilisateur. Orion affiche le motif
  que la gateway donne (`gateway_restart_due`) avec « Redémarrer heliosd sur la
  gateway. ». Rien ne redémarre à sa place (RENOUVELLEMENT §11).
- **Retirer `astra-signer`, `helios enroll document`, les commandes `heliosd`
  hors ligne** : lot 7. Les commandes restent le recours, documentées comme
  tel.
- **F14-a** (délai d'installation dépassé), **F14-d** (GUID d'annulation
  WebAuthn), **F14-e** (successeur de `rotate-ca-pq` en reprise),
  **F14-f** (copie du coffre) : hors lot.
- **L'amorçage** (`issue-gateway-bootstrap`, §13.1) : fait au 6a.
- **La bascule de confiance du §13.2** : reste une procédure opérateur
  (RENOUVELLEMENT §11).
- **Anti-objectif** : aucune clé privée de la gateway ne quitte la gateway ; la
  feuille candidate est émise sur une clé que la gateway a scellée elle-même.
- **Anti-objectif** : aucun objet signé n'est saisi ou recopié par la personne
  (empreinte, époque, identifiant d'opération). Tout se lit à la source.
- **Anti-objectif** : jamais d'état affiché qu'Orion « croit » : l'état des
  lignes vient de la vue de la gateway et du statut d'Astra, relus à
  l'ouverture, au bouton ↻ et après chaque geste (comme 5b et 5c).

## 5. Conception

### 5.1 La porte d'Astra

La table de la porte (spec 5a §5.2, amendée au 5b) s'élargit au tunnel pour :

| Action | Console | Tunnel |
| --- | --- | --- |
| `GatewayIdentity` | oui | **oui** |
| `GatewayIdentityPublish` | oui | **oui** |
| `GatewayRevocation` | oui | **oui** |
| `ChainOpen`, `ChainNext`, `ChainAbandon` | oui | **oui** |

Restent à la console seule : `IssuerRequest`, `PinCaTls`, `IssuerInstall`.
Amendement daté à porter dans la spec 5a et l'ADR-008. Le `requested_by` par
le tunnel garde l'identité résolue du pair ajoutée par la porte (5a §5.3).

**Ce n'est pas qu'une ligne de table.** Le tunnel ne transporte aujourd'hui que
quatre ouvertures : `OperatorOpenAction` (`crates/aether/src/certificates/transport.rs`)
et `From<OperatorOpenRequest> for DoorRequest` ne connaissent que `FleetLeafs`,
`TrustAuthorities`, `ClientRevocation` et `IssuerDelegation`. Le lot ajoute :

- les variantes d'ouverture `GatewayIdentity`, `GatewayRevocation` et
  `ChainOpen` sur le fil ;
- trois opérations du tunnel qui ne sont pas des ouvertures :
  `GatewayIdentityPublish { epoch }`, `ChainNext`, `ChainAbandon`, et la lecture
  du plan. Chacune traverse `astra-channel`, le relais d'`helios-api`
  (`OperatorCampaignRelay`), `heliosd` et une route `/api` réservée au pair
  administrateur, avec l'identité résolue du pair, comme les ouvertures.
  *(Choix du concepteur ; c'est une tâche à part entière.)*

**Lectures nécessaires par le tunnel** (au constructeur de trouver la route
existante ou d'en ajouter une, publique, en lecture seule, réservée au pair
administrateur) :

- la feuille PQ gateway en service : la vérification de la signature de
  continuité du §5 en a besoin. Aujourd'hui la porte l'exporte dans un fichier
  du volume d'Astra (`export_active_gateway_certificate`). La porte la lit déjà
  sur le canal privé (`GatewayIdentityView.pq_certificate`) : l'ouverture
  `GatewayIdentity` par le tunnel la renvoie avec l'opération *(choix du
  concepteur)*, et Orion vérifie qu'elle correspond à l'empreinte figée ;
- la transition gateway installée, document signé et public : l'avortement
  (§5.3) et le retour arrière (§5.4) en ont besoin, et le journal local peut ne
  plus l'avoir. La gateway la sert par une nouvelle route `/api` en lecture
  *(choix du concepteur : une seule lecture pour les deux gestes)* ;
- les échéances des feuilles TLS et PQ de la gateway : `CertificateDomainView`
  ne les a pas (`crates/helios-api/src/certificates/views.rs`). Elles y sont
  ajoutées, pour l'état « À faire » du §5.2 *(choix du concepteur)* ;
- la feuille TLS candidate, en DER, quand la TLS change : aujourd'hui
  `--tls-certificate` la copie à la main depuis la gateway. La gateway la sert
  après « préparer », et Orion compare son empreinte à
  `candidate_tls_fingerprint` de la demande ;
- l'état du plan « Tout renouveler » (aujourd'hui `astra chain status`).

### 5.2 Renouveler l'identité de la gateway

Une ligne dans *Rotations*, au même modèle que « Remplacer la CA TLS ».

**Prérequis** (vérifiés avant toute ouverture, en deux groupes comme au 5b) :
tunnel, droit d'administration, Astra joignable, coffre présent et domaine
concordant, aucune transition gateway en cours (`gateway_transition_pending`),
aucun recouvrement `CA-PQ` en cours *(choix du concepteur : deux rotations ne
tournent pas ensemble, règle du 5b ; et la transition gateway se signe sous
`CA-PQ`)*.

**Options**, affichées avant « Approuver » :

- « Remplacer aussi la feuille TLS » (`rotate_tls`), décochée par défaut ;
- « La clé de la gateway est perdue » (`key_recovery`), décochée, avec une
  confirmation qui dit l'effet : « Aucune preuve de continuité. Réservé à une
  clé disparue. » ;
- les termes : préparation 7 jours, recouvrement 7 jours, validité 365 jours
  (valeurs par défaut d'`astra-signer sign-gateway-transition`,
  `tools/astra-signer/src/cli.rs`), modifiables comme au 5b.

**Déroulé** :

1. **Préparer**, par `POST /api/certificates/gateway-renewal`. Une demande déjà
   prête pour cette époque est reprise (`reused`) et Orion le dit ; jamais de
   `new_key` implicite.
2. **Ouvrir** la campagne `GatewayIdentity` par le tunnel. Elle fige les
   empreintes TLS et PQ en service.
3. **Lire** la feuille PQ en service et, si besoin, la feuille TLS candidate
   (§5.1), et les comparer aux empreintes figées et à celles de la demande.
   Toute différence arrête avant les clés.
4. **Cérémonie** : clés une par une, puis « Approuver ». Le coffre émet la
   feuille PQ sous `CA-PQ` et signe la transition dans le même geste
   (`signing::sign_gateway_transition`).
5. **Déposer** le résultat chez Astra.
6. **Installer** sur la gateway (`POST /api/certificates/gateway-transition`),
   qui vérifie sous ses ancres et refuse une feuille dont la clé privée n'est
   pas scellée chez elle.
7. **Publier** (`GatewayIdentityPublish` par le tunnel). Rejouable : la
   publication termine un relais que la précédente n'a pas confirmé.

La décision signée est gardée localement jusqu'à l'installation et la
publication, sur le modèle du journal du 5b. « Reprendre » rejoue les étapes 5
à 7 sans clé tant que la campagne vit. Après, la décision est jetée et tout
recommence à l'étape 1 (la demande est reprise sur la même clé scellée).

**États de la ligne**, lus dans `CertificateDomainView` :

- « À faire » : la plus proche des deux échéances gateway (§5.1) approche
  *(seuil : celui que le 5b emploie pour les autres lignes, au constructeur de
  le reprendre)* ;
- « Installée, publication à faire » : `gateway_transition_pending` et pas
  `gateway_transition_published` ;
- « Bascule le … » : publiée, avant `gateway_activation_at` ;
- « Recouvrement jusqu'au … » : entre `activation_at` et
  `gateway_retire_active_at` ;
- en plus, quand `gateway_restart_due` est présent : son motif et « Redémarrer
  heliosd sur la gateway. ».

### 5.3 Annuler le renouvellement

Un bouton « Annuler » sur la ligne, tant que la transition est installée, non
publiée et avant `activation_at`. Ouvre une campagne `GatewayIdentity`, comme
`abort-gateway-transition` (`tools/astra-signer/src/commands/gateway_identity.rs`),
lit la transition installée (§5.1), vérifie que son époque est celle de la
campagne, puis une clé, signe
l'avortement (`signing::sign_gateway_abort`, motif `operator_cancelled`),
dépose, puis installe par `POST /api/certificates/gateway-transition/abort`.
Libellé de confirmation : « L'époque reste consommée. ». Après publication, le
bouton disparaît ; seul le retour arrière reste. Une opération `GatewayIdentity`
encore vivante (renouvellement abandonné en route) bloque l'ouverture
(`AlreadyOpen`, une opération vivante par famille) : Orion le dit et propose
d'attendre son expiration, sans rien signer.

### 5.4 Revenir à l'ancienne identité

Un bouton « Revenir à l'ancienne identité », visible seulement pendant le
recouvrement d'une transition publiée (après `activation_at`, avant
`not_after`), et absent si la gateway est révoquée.

- Hors campagne Astra, comme la commande : la campagne est résolue localement
  depuis la transition signée, affichée en entier, attestée par une clé, puis
  signée (`signing::sign_service_rollback`).
- La transition signée vient de la lecture de la gateway (§5.1), jamais d'un
  fichier.
- Saisies : durée (24 h par défaut, bornée par `not_after`), motif. Le
  demandeur est l'identité du poste, pas une saisie *(choix du concepteur)*.
- Pose par `POST /api/certificates/gateway-transition/rollback`, puis la phrase
  du redémarrage. La ligne montre « Retour arrière jusqu'au … » tant que
  `gateway_rollback_expires_at` est présent.

### 5.5 Révoquer la gateway

Un bloc « Identité de la gateway » en tête de *Rotations* porte « Révoquer la
gateway ». Geste rare et grave : confirmation qui nomme la conséquence, motif
obligatoire (mêmes motifs que le 5c).

**Avec remplaçant (par défaut)**, dans l'ordre que la machine à états impose
(RENOUVELLEMENT §7.1) :

1. préparer la demande en `key_recovery` (une identité révoquée ne signe pas
   pour sa suivante) ;
2. ouvrir `GatewayIdentity`, signer la transition `emergency_replacement` ;
3. ouvrir `GatewayRevocation`, signer la révocation qui nomme cette transition
   (son empreinte est calculée sur l'objet signé, jamais saisie) ;
4. déposer, puis appliquer la révocation d'abord, la transition ensuite.

Les deux campagnes sont de familles différentes (`GatewayIdentity`,
`Revocation`) et peuvent vivre ensemble. Ordre retenu *(choix du concepteur)* :
la transition est signée et déposée (sa campagne consommée) avant l'ouverture
de `GatewayRevocation`. Le test de bout en bout du §7 tient cet ordre.

Les deux moitiés, TLS et PQ, sont révoquées ; leurs échéances viennent de la
campagne (`revocation_expiries`, que `resolve::gateway_revocation` remplit
pour les deux), jamais d'une saisie.

Deux campagnes, donc deux séries de touchers ; Orion le dit avant de commencer.
La transition de remplacement est servie immédiatement.

**Pendant un recouvrement `CA-PQ`** *(choix du concepteur)* : la révocation
suit la règle du 5c (signée sous l'ancre qu'Astra vérifie, clé sortante gardée
par le coffre ; sinon « Révocation possible après le … »). La transition de
remplacement se signe sous l'ancre que la gateway vérifie pour une transition
pendant ce recouvrement ; au constructeur de le lire dans le code. Si aucune
ne convient, la révocation « avec remplaçant » est refusée avant toute clé,
avec la date, et « sans remplaçant » reste possible. Une révocation d'urgence
n'est jamais bloquée sans le dire.

**Sans remplaçant** : proposé derrière une seconde confirmation, « La gateway
ne servira plus. Le domaine devra être reconstruit. » *(choix du concepteur :
c'est le seul geste juste quand l'hôte lui-même est compromis, et préparer une
clé sur cet hôte n'aurait pas de sens — RENOUVELLEMENT §7.1, limite connue.)*

Reprise : la transition et la révocation signées sont gardées localement
jusqu'à leur application, comme au §5.2.

### 5.6 Tout renouveler

Une ligne « Tout renouveler » (*choix du concepteur : une ligne qui enchaîne
les quatre étapes, plutôt que de laisser l'opérateur lancer les quatre lignes
dans l'ordre*). Elle ouvre le plan par `ChainOpen` et affiche ses quatre
étapes : délégation de l'émetteur, CA TLS cliente, identité de la gateway,
feuilles du parc. `CA-PQ` n'en fait pas partie.

- Chaque étape joue le geste Orion existant (5b pour l'émetteur, la CA TLS et
  le parc ; §5.2 pour la gateway), sous la campagne que le plan a ouverte au
  lieu d'en ouvrir une. Au constructeur de faire accepter cette campagne par
  chaque geste. Si cela demande de refondre les gestes du 5b, « Tout
  renouveler » devient la dernière tâche du plan, détachable *(choix du
  concepteur)* : les §5.2 à §5.5 se livrent sans lui.
- Après chaque étape, Orion appelle `ChainNext`. Le refus d'Astra tant que
  l'effet n'est pas visible est affiché tel quel ; la ligne propose de relire
  plus tard.
- Quatre touchers, annoncés avant de commencer.
- « Abandonner le plan » (`ChainAbandon`) : ce qui est approuvé garde son effet.
- Le plan vit chez Astra : Orion fermé puis rouvert retrouve l'étape en cours.
- La dernière étape n'a pas d'effet observable (RENOUVELLEMENT §10, limite
  connue) : la ligne dit « Parc autorisé ; chaque poste se renouvelle à sa
  prochaine connexion. »

### 5.7 Erreurs

- Messages en français, courts, qui nomment la cause ; aucun secret (PIN,
  `Opened`, octets du coffre, clé privée) dans la WebView ou un journal.
- Un refus de la gateway à l'installation est affiché avec sa raison. Il n'est
  jamais traduit en « réessayer » si la raison est définitive (feuille non
  scellée ici, époque consommée).
- Toute étape qui échoue après une signature laisse « Reprendre » sur la ligne.

## 6. Contraintes

- Le processus élevé (`orion.exe --engine`) ne porte pas les cérémonies : la
  WebAuthn est dans l'IHM non élevée (F11). Le coffre s'ouvre comme au 5b.
- Le tunnel est le seul chemin. L'origine publique d'Astra ne sert aucune de
  ces actions.
- Les objets signés restent liés à leur campagne : une campagne morte n'accepte
  pas un objet signé pour une autre (règle du 5b).
- `heliosd` tient seul son registre : Orion passe par l'API, jamais par les
  commandes hors ligne.
- Pas de version modifiée à la main ; `docs/audits` intouché.

## 7. Tests

- Porte : la table, testée comme donnée (les nouvelles lignes au tunnel, les
  autres inchangées) ; le test d'équivalence des connecteurs couvre les
  nouvelles actions.
- Bout en bout sans `heliosd` réel, sur le modèle de
  `crates/astra/src/door/tests/overlap_revocation.rs` : renouvellement complet
  par le connecteur tunnel ; révocation gateway avec remplaçant, appliquée dans
  l'ordre et refusée dans l'autre.
- Orion : les états de ligne depuis `CertificateDomainView` (tables de cas) ;
  chaque geste avec des fakes, y compris les refus avant les clés (empreinte
  qui ne correspond pas) et la reprise sans clé.
- Le chemin de la cérémonie : pas de secret dans ce qui atteint la WebView.

## 8. Documentation et recette

- `RENOUVELLEMENT-CERTIFICATS.md` §7.1, §8, §8.1, §10 : Orion d'abord, les
  commandes en recours jusqu'au lot 7.
- Spec 5a §5.2 et ADR-008 : amendement daté de la table de la porte.
- `MANUAL-TESTING.md` : section « I. Lot 6b », étapes **[cible]** quand WSL ne
  peut pas les jouer (vraies clés, gateway cible, redémarrage).
- `ROADMAP.md` : F14 lot 6b.

## 9. Laissé au constructeur

- Les routes de lecture du §5.1 : réutiliser si elles existent, sinon les
  ajouter.
- Comment un geste du 5b accepte la campagne ouverte par le plan (§5.6).
- L'ancre de la transition de remplacement pendant un recouvrement `CA-PQ`
  (§5.5).
- Le seuil « À faire » de la ligne gateway (§5.2), repris du 5b.
- Le découpage en tâches.
