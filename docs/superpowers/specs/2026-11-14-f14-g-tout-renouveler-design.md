# F14-g — « Tout renouveler » dans Orion

Date : 14 novembre 2026. Statut : conception, à valider. Suit le lot 6b
(spec `2026-11-10-f14-lot6b-identite-gateway-design.md`, §5.6) et le lot 6c.

## 1. Intention

Le plan « Tout renouveler » (spec 7.6 d'Astra, `crates/astra/src/chain.rs`)
enchaîne quatre campagnes ordinaires, dans un ordre imposé : délégation de
l'émetteur, CA TLS cliente, identité de la gateway, feuilles du parc. `CA-PQ`
n'en fait pas partie. Il se joue aujourd'hui sur la console d'Astra
(`astra chain open|next|status|abandon`), et deux de ses étapes ne peuvent pas
s'approuver dans Orion : la demande de délégation n'arrive qu'à la console, et
le geste gateway d'Orion ouvre toujours sa propre campagne.

F14 veut qu'Orion soit le seul outil de l'opérateur côté poste, et le lot 7
retire `astra-signer`. F14-g met le plan dans Orion, de bout en bout, sans
console ni `astra-signer`.

## 2. Objectifs

1. Une ligne « Tout renouveler » dans l'onglet Rotations d'Orion : commencer
   le plan, jouer chaque étape, la reprendre, la rouvrir, abandonner le plan.
2. Chaque étape joue le geste Orion existant, sous la campagne que le plan a
   ouverte.
3. Aucune campagne n'est ouverte avant que les contrôles de son étape soient
   passés côté Orion.
4. Une étape dont la campagne a expiré sans effet se **rouvre** : Astra
   ouvre une nouvelle campagne pour l'étape en cours, sans refaire les
   étapes faites (choix de l'utilisateur, option A).
5. Documentation et recette.

## 3. Non-objectifs et anti-objectifs

- Pas de nouvelle campagne « large » : le plan reste quatre campagnes de
  quatre familles (`CampaignFamily` est total, `chain.rs`).
- Pas d'enchaînement automatique : Orion s'arrête après chaque étape et
  attend « Continuer ». L'opérateur peut s'interrompre entre deux étapes.
- Pas de refonte des gestes du 5b et du 6b : ils gagnent au plus un frère qui
  part d'une campagne donnée.
- `CA-PQ`, « Terminer la rotation CA TLS », le redémarrage de `heliosd`, la
  copie du coffre : hors plan, comme aujourd'hui.
- Anti-objectif : une étape qui ouvre sa campagne puis échoue sur un contrôle
  qu'Orion pouvait faire avant. La famille resterait bloquée cinq minutes.
- Anti-objectif : relancer le plan refait une étape déjà faite (une seconde
  délégation, une seconde rotation CA TLS).
- Retirer les commandes `astra chain` de la console : non, elles restent.

## 4. Ce qui existe

- **Astra** (`crates/astra/src/door/chain.rs`) : `ChainOpen` résout le plan et
  ouvre l'étape 1 ; `ChainNext` refuse tant que l'effet de l'étape en cours
  n'est pas visible au registre (`ChainStepIncomplete`, 409 avec la phrase),
  puis avance **et ouvre aussitôt** la campagne suivante ; `ChainAbandon`
  supprime le plan. Le plan vit dans le volume d'état
  (`certificate-chain-plan.json`). Une étape déposée sans effet bloque le plan
  pour de bon : rien ne la rouvre.
- **Tunnel** : `chain_open` (par l'ouverture d'opérateur), `chain/next`,
  `chain/abandon` ; `OperatorAuthorityStatus.chain` (`OperatorChainView` :
  étapes, étape courante, opération déposée). `astra-operator::tunnel` a
  `chain_next` et `chain_abandon`. Orion n'appelle rien de tout cela, et son
  type TS de l'autorité ne lit pas `chain`.
- **Effets** (`ChainEffect`) : époque de l'émetteur dépassée ; successeur CA
  TLS cliente tenu ; décision d'identité gateway enregistrée pour la campagne
  de l'étape ; parc : `SpentByPeers`, toujours vrai (limite connue,
  RENOUVELLEMENT §10).
- **Gestes Orion** :
  - parc (`renew_fleet`) : reprend une opération `fleet_leafs` vivante, puis
    `approve_campaign` sur l'opération. Utilisable tel quel.
  - CA TLS (`rotation::open`, `RotationTerms.existing_operation`) : reprend
    une opération donnée. Ses prérequis (clés validées, etc.) se jouent dans
    `RotationSteps` avant l'ouverture. Utilisable tel quel.
  - délégation (`renew_delegation`) : la demande PKCS#10 n'existe que dans la
    réponse d'ouverture (`delegation_request`), puis `begin_issuer_ceremony`
    `authorize_issuer` avec l'opération et la demande. La ligne ne reprend pas
    une opération vivante.
  - gateway (`gateway_identity::open_renewal`) : contrôles, `prepare_renewal`,
    puis ouverture de sa propre campagne. Pas de variante sur une campagne
    donnée.

## 5. Approches

1. **Retenue : une ligne « Tout renouveler » qui conduit le plan.** Elle
   montre les quatre étapes et l'étape en cours ; chaque « Continuer » fait
   d'abord les contrôles de l'étape suivante, puis demande à Astra de l'ouvrir,
   puis joue le geste existant dans sa cérémonie habituelle. Un seul endroit,
   l'ordre garanti, les contrôles toujours avant l'ouverture.
2. Écartée : la ligne suit le plan et chaque étape se joue dans sa ligne
   habituelle (« Reprendre l'opération ouverte »). Moins d'écran neuf, mais
   l'opérateur saute de ligne en ligne, et les lignes délégation et gateway
   devraient quand même prendre une campagne déjà ouverte : leurs contrôles
   viendraient après l'ouverture.
3. Écartée : enchaîner seul les quatre étapes. Les touchers et le refus
   d'Astra tant que l'effet n'est pas visible imposent un arrêt, et
   l'opérateur doit pouvoir s'interrompre.

Pour une étape expirée : **A, Astra rouvre l'étape** (choix de l'utilisateur)
plutôt que B, abandonner le plan et finir les étapes une par une dans leurs
lignes.

## 6. Conception

### 6.1 Astra : rouvrir l'étape en cours

Nouvelle requête de la porte `ChainReopen {}` (`chain_reopen`), permise au
tunnel et à la console comme ses sœurs (table `allowed`, `(true, true)`).

- Refus, dans cet ordre :
  - pas de plan : `NoChain` ;
  - plan fini : `ChainFinished` ;
  - étape courante jamais déposée : refus « l'étape n'a pas été ouverte :
    continuer le plan » (nouvelle variante `ChainStepNotDeposited`) ;
  - effet de l'étape visible au registre : refus « l'étape a pris effet :
    continuer le plan » (`ChainStepLanded`). Exception : l'étape du parc
    (`SpentByPeers`), dont l'effet n'est pas observable, se rouvre toujours
    une fois son opération expirée *(choix du concepteur : autoriser deux
    fois le parc est sans danger, chaque poste ne dépense qu'une
    autorisation)* ;
  - opération de l'étape encore vivante au magasin des opérations (non
    expirée à l'horloge d'Astra) : refus qui nomme l'échéance
    (`ChainStepStillOpen { expires_at }`), « la campagne de l'étape est encore
    ouverte jusqu'à … : l'approuver ».
- Sinon : `chain_deposit_current` sur la même étape, avec les mêmes motif et
  demandeur. L'effet attendu reste celui résolu à l'ouverture du plan
  (`IssuerEpochAbove`, `ClientTlsCaSucceeds`) ; pour la gateway, le
  `campaign_id` est remplacé par celui de la nouvelle campagne
  (`record_deposit` le fait déjà).
- Le plan est relu et écrit sous `volume_writes`, comme `next`.
- `reopen` et `next` portent l'étape attendue par l'appelant
  (`expected_step`, optionnelle pour la console) ; Astra refuse si le plan
  n'est plus sur cette étape (`ChainStepMoved`), pour qu'un plan avancé par
  la console entre la lecture et le clic ne fasse pas jouer à Orion une
  étape avec les contrôles d'une autre *(choix du concepteur)*.
- Une opération oubliée par un redémarrage d'Astra compte comme expirée.
- L'étape délégation rouverte tire une nouvelle demande (nouvelle époque,
  nouvelle clé) ; `open_issuer_delegation` refuse déjà tant qu'une délégation
  vivante existe.
- Fil : `POST /internal/v1/operator/chain/reopen` (`astra-channel`), route
  administrateur `POST /api/certificates/operator/chain/reopen`
  (`helios-api`/`heliosd`), réponse `OperatorChainStep::Opened` comme `next`.
  Les refus portent leur phrase dans un 409, comme `ChainStepIncomplete`.
- `astra-operator::tunnel` gagne `chain_reopen()` et une ouverture du plan
  qui rend l'`OperatorOpened` de l'étape 1 (`delegation_request` compris).
- Console : pas de nouvelle sous-commande *(choix du concepteur : la console
  n'est pas l'outil visé ; la table de la porte la permet par symétrie)*.

### 6.2 La ligne « Tout renouveler »

Dans l'onglet Rotations, au-dessus des lignes par action *(choix du
concepteur)*. Elle lit `authority.chain` (le statut lu par le tunnel) et les
opérations en attente.

Sans plan :
- Titre « Tout renouveler », détail « Quatre étapes, une cérémonie chacune :
  délégation de l'émetteur, CA TLS cliente, identité de la gateway, postes.
  CA-PQ n'en fait pas partie. Chaque cérémonie demande ses clés. » *(Choix du
  concepteur : pas de décompte des clés par étape, celui de la gateway
  dépend d'options choisies plus tard.)*
- Champ « Motif » et bouton « Commencer ».
- Bouton désactivé, avec la raison, si l'une des quatre lignes concernées est
  bloquée maintenant : on réutilise les raisons déjà calculées par
  `rotationRows.ts` (délégation, CA TLS, parc) et `gatewayRows.ts`
  (renouvellement de la gateway), plus « une opération de la même famille est
  ouverte » si l'une des quatre familles a une opération vivante. Un plan
  qu'Orion sait déjà ne pas pouvoir finir n'est pas commencé.

Plan ouvert, la ligne dit « Étape k sur 4 : <nom> » et l'état de l'étape :
- **Campagne ouverte** (l'opération déposée est dans les opérations en
  attente, non expirée) : « Reprendre l'étape », qui mène la cérémonie de
  l'étape sur cette opération. Pour la délégation, la reprise n'est possible
  que si Orion a gardé la demande de cette opération ; sinon la ligne dit
  « Demande de délégation perdue : rouvrir l'étape après <échéance>. »
- **Campagne fermée** (l'opération n'est plus en attente) : « Continuer »
  (l'étape a peut-être pris effet) et « Rouvrir l'étape ». « Continuer »
  refusé par Astra affiche sa phrase telle quelle et laisse « Rouvrir
  l'étape ».
- Toujours : « Abandonner le plan », avec la phrase « Ce qui est déjà approuvé
  garde son effet. »

Plan fini (`OperatorChainStep::Finished`) : « Parc autorisé ; chaque poste se
renouvelle à sa prochaine connexion. » Si une rotation CA TLS a été faite, la
ligne rappelle « Terminer la rotation CA TLS » à son échéance (ligne
existante).

Les lignes par action restent disponibles pendant un plan *(choix du
concepteur)* : Astra lit les effets au registre, donc une étape faite à part
compte pour le plan.

### 6.3 « Commencer » et « Continuer »

- **Commencer** : contrôles de l'étape 1 (ceux de la ligne délégation, plus
  « aucune cérémonie en cours »), puis ouverture `chain_open` par le tunnel,
  puis cérémonie `authorize_issuer` avec l'opération et la demande rendues.
- **Continuer** : contrôles de l'étape k+1 **avant** `chain/next`, puisque
  `next` ouvre aussitôt la campagne suivante. Puis `chain/next`, puis le geste
  de l'étape sur l'opération rendue :
  - CA TLS : les prérequis de `RotationSteps` (clés validées, etc.) se jouent
    avant `chain/next`, puis `rotation::open` avec `existing_operation`.
  - gateway : le frère `open_renewal_in` (§6.4), avec les termes de la ligne
    gateway (durées, feuille TLS remplacée ou non) saisis avant
    `chain/next`.
  - parc : `approve_campaign` sur l'opération.
  - `Finished` : message de fin.
- **Rouvrir l'étape** : mêmes contrôles que l'étape, puis `chain/reopen`,
  puis le geste.
- Aucune étape n'enchaîne la suivante d'elle-même : à la fin d'une
  cérémonie réussie, la ligne revient sur « Continuer ».
- Une cérémonie déjà en cours (un autre geste) bloque ces trois boutons.

### 6.4 Le geste gateway sous la campagne du plan

`astra-operator::operations::gateway_identity` gagne :

```rust
/// Everything `open_renewal` refuses before it opens a campaign.
pub fn check_renewal(remote, vault_path, options, now) -> Result<(), GatewayRefusal>;
/// `open_renewal`, under a campaign the chain opened.
pub fn open_renewal_in(remote, vault_path, opened: OperatorOpened, options, now)
    -> Result<OpenedGatewayRenewal, GatewayRefusal>;
```

`open_renewal_in` refait les contrôles de `check_renewal` (l'état a pu bouger
depuis), puis `prepare_renewal` et la vérification de la demande reprise,
puis part de `opened` au lieu d'ouvrir une campagne. Une campagne dont la
portée n'est pas `GatewayIdentity` est refusée avant toute clé. La suite
(signature, dépôt, installation, publication, reprise) est celle de
`open_renewal`. Une demande reprise qui ne correspond pas aux options, vue
après l'ouverture, est refusée avec la phrase existante ; la campagne expire
et l'étape se rouvre. `open_renewal` et `open_renewal_in` partagent le même
corps.

Côté Tauri : `GatewayGesture::Renew` gagne l'opération du plan, optionnelle ;
`begin_gateway_ceremony` la transmet. Le registre local de la décision en
attente est celui d'aujourd'hui : un échec après signature laisse
« Reprendre » sur la ligne gateway, et l'étape du plan est faite dès que la
décision est déposée chez Astra.

### 6.5 Tauri et types

- `OperatorAuthorityStatus.chain` passe dans le type TS et dans la vue des
  rotations.
- Commandes : `operator_chain_start(reason)`, `operator_chain_next()`,
  `operator_chain_reopen()`, `operator_chain_abandon()`, par le tunnel ;
  `NO_TUNNEL` sans cible, comme les autres.
- La demande de délégation rendue par `start` ou `reopen` reste dans la
  cérémonie en cours (mémoire de l'IHM non élevée), jamais sur disque ni dans
  un journal *(choix du concepteur : c'est une demande PKCS#10 publique, mais
  rien ne gagne à l'écrire)*.

### 6.6 Cas limites

- **Quelle opération, ouverte ou fermée** : `OperatorChainView.operation_id`
  nomme l'opération déposée de l'étape courante. La ligne la cherche dans les
  opérations en attente, avec la règle de `liveOperation` (échéance passée à
  l'horloge de la gateway = fermée). Un écart d'horloge avec Astra est couvert
  par le refus `ChainStepStillOpen`, affiché tel quel.
- **Échec après `next`, avant toute signature** (WebAuthn annulée, PIN faux,
  fenêtre fermée) : la campagne de l'étape reste ouverte, la ligne offre
  « Reprendre l'étape ». CA TLS : la reprise rejoue les prérequis de
  `RotationSteps` comme la reprise d'aujourd'hui par `existing_operation`.
  Délégation après un redémarrage d'Orion : la demande est perdue, la ligne
  attend l'échéance (cinq minutes au plus) puis « Rouvrir l'étape » *(choix du
  concepteur : cas rare, l'attente est bornée ; la demande n'est pas
  re-servie par Astra)*.
- **Contrôles qu'Orion ne peut faire qu'en cérémonie** (présence de la clé,
  PIN) : ils restent après l'ouverture. L'anti-objectif du §3 vise les
  contrôles faisables avant ; le reste se rattrape par « Reprendre l'étape »
  dans la fenêtre, puis « Rouvrir l'étape ».
- **Gateway, décision signée et pas déposée** : le registre local
  (`gateway_identity::pending`) s'efface à l'échéance de sa campagne, et
  `check_renewal` refuse tant qu'il existe (`AlreadyOpen`). « Rouvrir
  l'étape » ne peut donc pas laisser une décision liée à l'ancienne campagne ;
  avant l'échéance, c'est « Reprendre » sur la ligne gateway. Une décision
  déposée fait l'effet de l'étape : `reopen` refuse et « Continuer » avance.
- **Parc** : l'effet est toujours vrai, donc « Continuer » finit le plan même
  si la cérémonie n'a pas abouti. La ligne n'offre « Continuer » sur l'étape
  du parc qu'après une cérémonie réussie dans cette session ; sinon, campagne
  fermée, elle offre « Rouvrir l'étape » et « Terminer le plan » avec « Orion
  ne peut pas savoir si les postes ont été autorisés : rouvrir l'étape si la
  cérémonie n'a pas abouti. » *(choix du concepteur)*.
- **Console ou autre poste sur le même plan** : la ligne relit
  `authority.chain` avant chaque action, et `expected_step` (§6.1) refuse un
  plan qui a bougé. Un affichage en retard entre deux lectures est accepté.

### 6.7 Erreurs

- Phrases en français, courtes, qui nomment la cause ; aucun secret (PIN,
  `Opened`, octets du coffre, clé privée) dans la WebView ou un journal.
- Le refus d'Astra de `next` ou `reopen` est affiché tel quel, avec « Relire
  plus tard » quand l'effet peut encore arriver.
- Une étape qui échoue après une signature laisse « Reprendre » sur la ligne
  du geste concerné (règle du 6b).

## 7. Contraintes

- Le tunnel est le seul chemin ; l'origine publique d'Astra ne sert rien de
  ceci.
- Les objets signés restent liés à leur campagne (règle du 5b).
- La WebAuthn reste dans l'IHM non élevée (F11).
- Aucune version modifiée à la main ; `docs/audits` intouché.

## 8. Tests

- Astra (`door/chain.rs`, `door/tests/tunnel.rs`) : `reopen` refuse sans
  plan, plan fini, étape non déposée, étape qui a pris effet, opération
  encore vivante ; rouvre une étape expirée sans toucher aux autres ; la
  gateway rouverte prend le nouveau `campaign_id` ; une opération oubliée par
  un redémarrage se rouvre. Table de la porte et test d'équivalence des
  connecteurs.
- `astra-channel` / `helios-api` / `heliosd` : la route `reopen` et ses 409.
- `astra-operator` : `check_renewal` refuse ce que refuse `open_renewal` ;
  `open_renewal_in` n'ouvre aucune campagne et refuse une autre portée ;
  `tunnel` : `chain_reopen`, l'ouverture du plan rend la demande.
- Tauri : chaque geste sous l'opération du plan ; les contrôles passent avant
  l'appel qui ouvre ; aucune demande de délégation dans ce qui atteint un
  journal.
- Vitest : états de la ligne (sans plan, bloquée avec sa raison, étape
  ouverte, fermée, délégation perdue, fini) ; « Continuer » ne demande rien à
  Astra quand un contrôle échoue ; « Abandonner » garde ce qui est approuvé.

## 9. Documentation et recette

- `RENOUVELLEMENT-CERTIFICATS.md` §10 (et les mentions des §1 et §7) :
  « Tout renouveler » dans Orion d'abord, la console en recours.
- ADR-008 et spec 5a §5.2 : amendement daté de la table de la porte
  (`chain_reopen`).
- `MANUAL-TESTING.md` : section « K. F14-g », étapes **[cible]** quand WSL ne
  peut pas les jouer.
- `ROADMAP.md` : F14-g levé.

## 10. Laissé au constructeur

- L'extraction des contrôles de chaque étape (fonctions pures sur la vue des
  rotations côté TS, `check_renewal` côté Rust) et leur partage avec les
  lignes existantes.
- La forme exacte des variantes de refus d'Astra et de leurs phrases.
- Où la cérémonie garde la demande de délégation, et comment la ligne sait
  qu'elle l'a pour l'opération affichée.
- Le découpage en tâches.
