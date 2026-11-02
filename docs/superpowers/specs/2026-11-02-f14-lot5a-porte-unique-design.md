# F14 lot 5a : la porte unique d'Astra

Date : 2 novembre 2026. Branche `feat/f14-lot5a-porte-unique`, depuis `main`
78b570e. Premier des trois sous-lots du lot 5 de F14 (5a porte unique, 5b
rotations dans Orion, 5c révocation d'un poste dans Orion).

## 1. Intention

Aujourd'hui, faire tourner une CA ou révoquer un poste est si pénible que
l'opérateur le délègue à un développeur, en ligne de commande, depuis la
machine de développement. La cause principale n'est pas la cérémonie : elle
se joue déjà dans Orion depuis le lot 4. C'est l'**ouverture** de la campagne :
il faut entrer dans le conteneur Astra de la gateway, lancer
`astra campaign open` ou `astra revocation open`, puis recopier un
identifiant d'opération (et, pour une révocation, des échéances) vers le
poste qui tient les clés.

Le lot 5a pose la brique qui manque, sans écran nouveau : **une seule porte
d'ouverture, tenue par Astra**, à laquelle frappent plusieurs connecteurs.
Les sous-lots 5b et 5c y brancheront les écrans d'Orion.

### Principe décidé par l'utilisateur (2 novembre 2026)

- **Une porte, plusieurs outils.** Il n'existe qu'un endroit qui ouvre une
  campagne ; la console, Orion par le tunnel et tout outil futur ne sont que
  des connecteurs vers lui. C'est le seul endroit critique à renforcer.
- **Astra tient la porte.** Ni `heliosd`, ni Orion, ni la console : ce sont
  des moyens d'accès. Astra détient le registre, résout les cibles, signe la
  demande sous sa clé de service et garde l'état des campagnes.
- **La console devient un connecteur** : elle passe par la même interface que
  les autres, et n'écrit plus rien elle-même.
- **Ouvrir n'autorise rien.** Une campagne ouverte est un brouillon de cinq
  minutes au plus. La seule autorisation reste le toucher des clés de sécurité
  sur le manifeste vérifié, puis les signatures `CA-PQ` — et cette cérémonie
  est une fonction d'Orion (lot 4), pas de la porte.
- **Ouvrir par le tunnel** est accepté par l'utilisateur : le pair
  administrateur est une identité déjà établie (clé WireGuard dans la table
  d'admission), et cela retire l'accès SSH au conteneur du chemin ordinaire.

## 2. Constat dans le code (au 2 novembre 2026)

1. **Cinq ouvreurs, tous en console**, dans un second processus que le
   service : `campaign open` (`fleet_leafs`, `trust_authorities`,
   `crates/astra/src/commands/campaign.rs`), `revocation open` (client et
   gateway, `commands/revocation.rs`), `gateway-identity open`
   (`commands/gateway_identity.rs`), `chain open|next|abandon|status`
   (`commands/chain.rs`, plan dans `certificate-chain-plan.json`), et
   `issuer request --reason --requested-by` (`commands/issuer.rs`, campagne
   `issuer_delegation` dont la cible est créée par la commande).
2. **Ces ouvreurs tiennent eux-mêmes des pouvoirs du service.** Chacun relit
   `registry.json` depuis le disque (`AstraRegistry::load`) pendant que le
   service le possède en mémoire, et lit `service-key.bin` pour signer
   l'`AstraSignerRequest` (`campaign_deposit.rs::deposit_campaign`). Le
   résultat est déposé dans `campaign-inbox/`, que le service draine toutes les
   deux secondes en revérifiant la signature (`daemon.rs::spawn_campaign_drain`,
   `signing.rs::adopt_deposit`).
3. **La logique commune existe déjà** : `campaign_deposit.rs::open_campaign`
   (bornes de §7.6, coffre exigé, pin de politique, validation, dépôt), écrite
   « pour qu'une portée ajoutée plus tard n'en acquière pas sa propre version ».
   Les deux révocations (client et gateway, `revocation.rs`) ne l'emploient
   pas : elles appellent `deposit_campaign` directement et refont les
   contrôles de motif, de fenêtre et de coffre. Les amener à la porte est une
   fusion de deux chemins, pas un simple rebranchement.
4. **Ouvrir depuis l'extérieur est refusé exprès** : `POST /v1/campaigns`
   répond `operator_credential_required` (`service.rs:340-347`), faute
   d'authentification « tranchée ». Le canal opérateur du tunnel (§8.5.1)
   compte « quatre routes … et aucune autre » ; une cinquième, `pending`, a
   été ajoutée depuis (`OPERATOR_PENDING_ROUTE`) sans que §8.5.1 le dise.
5. **Les approbations suivent déjà le principe** : « every route here calls
   the same function the public handler calls, so the two channels cannot
   drift » (`crates/astra/src/operator.rs:18-21`) ; l'identité relayée par
   `heliosd` sert au journal, « rather than as a permission » ; le drapeau
   `admin` « borne qui peut faire circuler la cérémonie, pas qui peut
   l'approuver » (§8.5.2).
6. **La révocation fait recopier des échéances** : `--not-after` (ou
   `--tls-not-after`/`--pq-not-after` pour la gateway) est recopié depuis la
   sortie d'`astra revocation open`, « parce que le format partagé
   `CampaignTarget` ne porte pas l'échéance » (RENOUVELLEMENT-CERTIFICATS §7).
   La console imprime déjà la ligne `astra-signer revoke …` complète,
   échéances comprises ; ce qui manque, c'est de faire arriver ces valeurs au
   poste de l'opérateur sans recopie. Astra refuse le dépôt si la valeur est
   fausse.
7. **Le service ne relit jamais le registre** après son démarrage
   (`daemon.rs:59`), alors que trois commandes de la console l'écrivent
   pendant qu'il tourne : `pin-ca-tls` (`commands/trust_domain.rs`),
   `issuer install` (`commands/issuer.rs`) et `gateway-identity publish`
   (`commands/gateway_identity.rs`, qui persiste la marque de publication
   avant le relais). Aujourd'hui chaque
   ouvreur relit `registry.json` et voit donc ces écritures ; une porte qui lit
   l'état en mémoire ne les verrait qu'après un redémarrage d'Astra.
8. **Les ouvreurs gateway** (`gateway-identity open`, `revocation open
   --scope gateway`) prennent l'adresse du canal privé dans leurs propres
   arguments (`--gateway-channel`, `--gateway-certificate`), pas dans ceux du
   service, dont le canal est facultatif (`ASTRA_GATEWAY_CHANNEL` vide par
   défaut dans `deploy/astra/compose.yaml`).
9. **La boucle du drain porte aussi un balayage sans rapport** :
   `forget_expired_transitions`, appelé à chaque tour de `spawn_campaign_drain`,
   et nulle part ailleurs.

## 3. Objectifs

1. **La porte** : une fonction du service Astra, et une seule, ouvre toute
   campagne opérateur. Elle résout les cibles depuis l'état en mémoire, signe
   la demande avec la clé de service qu'elle détient déjà, applique les bornes
   et journalise. Tous les ouvreurs du §2.1 y passent.
2. **La politique par connecteur** est tenue par la porte (§5.2) : elle sait
   qui frappe (console locale, tunnel administrateur) et refuse ce que ce
   connecteur n'a pas le droit de demander.
3. **Connecteur tunnel** : `heliosd` relaie une ouverture d'un pair
   administrateur vers Astra, sur le modèle exact des routes opérateur
   existantes.
4. **Connecteur console** : les sous-commandes `astra … open` deviennent des
   clientes d'un point d'entrée local du service. Elles ne lisent plus ni le
   registre ni la clé de service, et n'écrivent plus dans `campaign-inbox/`.
5. **Plus de recopie d'échéance** : l'ouverture d'une révocation rend les
   échéances signées que l'opérateur devait recopier.
6. **Le service, seul écrivain de son état.** Décidé par l'utilisateur le
   2 novembre 2026 (option « une seule porte jusqu'au bout ») : les trois
   commandes du §2.7 passent elles aussi par la porte. Une fois le lot fait,
   aucune commande de la console n'écrit `registry.json`, le plan de chaîne ni
   le matériel de délégation ; seule exception, `bootstrap` (§5.9).
7. **Spec et ADR amendés** pour dire la porte, le connecteur tunnel
   d'ouverture, la console-connecteur et le service seul écrivain.

## 4. Non-objectifs et anti-objectifs

**Non-objectifs (autres lots)**
- Les écrans d'Orion qui ouvrent une rotation (5b) ou une révocation (5c) ; le
  client Orion de la nouvelle route vient avec eux.
- Le retrait de `companion.rs`, de `spawn_astra_signer` et du mode caché
  `astra-signer orion` (5b).
- La révocation de la gateway avec transition `emergency_replacement` et ses
  écrans (6b). `revocation open --scope gateway`, `gateway-identity open` et
  `gateway-identity publish` passent bien par la porte en 5a, depuis la
  console seulement et sans changement de comportement.
- `bootstrap` et `init-channel` restent hors de la porte (§5.9).
- Le retrait d'`astra-signer` (lot 7).

**Anti-objectifs (échec même si « ça marche »)**
- Une ouverture qui confère un pouvoir : aucun connecteur, aucun drapeau
  `admin`, aucune identité relayée ne remplace le toucher des clés.
- Deux chemins d'ouverture qui décident différemment : la console et le tunnel
  appellent la même fonction, avec la même résolution et les mêmes bornes.
- Un repli silencieux : si le service ne tourne pas, la console refuse ; elle
  ne retombe jamais sur l'écriture directe des fichiers.
- Une route publique d'ouverture : `/v1/campaigns` reste refusée.
- Une ouverture qui expose l'inventaire à un pair non administrateur.

## 5. Conception

### 5.1 La porte

Une fonction du service, par exemple
`AstraService::open_operator_campaign(connector, request, now)`, qui reprend
le contenu d'`open_campaign` et de `deposit_campaign` en remplaçant les
lectures de fichiers par l'état du service :

- **Entrée** : une requête d'ouverture typée, fermée, une variante par action :
  `FleetLeafs`, `TrustAuthorities`, `ClientRevocation { peer }`,
  `GatewayRevocation`, `GatewayIdentity`, `ChainOpen`, `ChainNext`,
  `ChainAbandon`, `IssuerDelegation`, et les trois écritures du §2.7 :
  `PinCaTls { fingerprint }`, `IssuerInstall { authorization }`,
  `GatewayIdentityPublish { epoch }` ; plus, pour les ouvertures, `reason`, `requested_by`,
  `window_secs` (défaut 300). Aucune cible n'est fournie par l'appelant :
  la porte les résout toujours elle-même. Une variante à part,
  `IssuerRequest`, couvre `issuer request` sans `--reason` : elle génère le
  matériel de délégation et n'ouvre aucune campagne, donc ne connaît ni motif
  ni fenêtre. *Choix du concepteur.*
- **Résolution** : registre en mémoire (`service.registry`), sous le verrou
  qu'il a déjà ; les cibles gateway (`GatewayRevocation`, `GatewayIdentity`)
  sont lues en direct sur le canal privé que le service tient déjà
  (`astra run --gateway-channel`). Sans canal privé dans le service, ces deux
  actions sont refusées par leur nom : la console ne transmet plus d'adresse,
  car une adresse fournie par l'appelant serait un élargissement de la porte.
  Un déploiement qui s'appuyait sur `--gateway-channel` de la console seule
  doit renseigner `ASTRA_GATEWAY_CHANNEL` du service ; DEPLOIEMENT-ASTRA le
  dit. *Choix du concepteur.*
- **Signature** : `AstraSignerRequest` signée avec
  `service.service_private_key`, déjà en mémoire. La clé de service ne quitte
  plus le processus du service.
- **Adoption** : l'opération entre directement dans `service.signing`, sans
  passer par le disque. La re-vérification de la signature que faisait
  `adopt_deposit` disparaît avec la frontière qu'elle protégeait (deux
  processus et un fichier) ; `SigningOperation::new` et `store.open` gardent
  leurs contrôles structurels.
- **Sortie** : `operation_id`, `campaign_id`, empreinte de campagne, portée,
  nombre de cibles, `expires_at`, pour une révocation les **échéances
  signées** de chaque moitié (§5.7), et pour `IssuerDelegation`/`IssuerRequest`
  et les pas de chaîne qui en produisent une, la **demande de délégation
  publique**. Le service n'écrit jamais à un chemin choisi par l'appelant :
  c'est la console qui écrit `--out` à partir de la réponse, et qui garde la
  sortie standard d'`issuer request` identique pour les scripts du
  déploiement. Rien qui soit un secret ou une capacité :
  les jetons bearer restent émis par les routes existantes, pour l'appelant
  qui agit sur l'opération.
- **Le plan de chaîne** (`certificate-chain-plan.json`) et la génération du
  matériel de délégation (`issuer request`) se font dans le service, au même
  endroit du volume d'état qu'aujourd'hui. `issuer request` sans `--reason`
  (fichier seul) passe aussi par la porte : c'est la même écriture dans le
  volume.

### 5.2 Politique par connecteur

La porte connaît le connecteur, transmis par le transport et jamais par le
corps de la requête :

| Action | Console locale | Tunnel (pair admin) | Origine publique |
| --- | --- | --- | --- |
| `FleetLeafs` | oui | oui | non |
| `TrustAuthorities` | oui | oui | non |
| `ClientRevocation` | oui | oui | non |
| `GatewayRevocation` | oui | non (6b) | non |
| `GatewayIdentity` | oui | non (6b) | non |
| `ChainOpen/Next/Abandon` | oui | non | non |
| `IssuerDelegation`, `IssuerRequest` | oui | non | non |
| `PinCaTls`, `IssuerInstall`, `GatewayIdentityPublish` | oui | non | non |

Le tableau est une donnée de la porte, testée comme telle. Élargir le tunnel à
une action est un changement explicite de cette table, pas un effet de bord.

### 5.3 Bornes tenues par la porte

- `reason` et `requested_by` non vides ; fenêtre de 1 à 300 s (inchangé).
- **Une opération vivante par famille** (`CampaignFamily`), sauf
  `Revocation` : une par identité visée, pour qu'on puisse révoquer deux
  postes volés dans la même minute. « Vivante » veut dire en attente de
  l'opérateur, l'état que filtre `pending` : une cérémonie échouée ou terminée
  ne bloque pas un nouvel essai. Un pas de chaîne et une campagne
  `fleet_leafs` isolée, de la même famille, se bloquent l'un l'autre, et c'est
  voulu. Une ouverture en double est refusée (`AlreadyOpen`) ; l'opération
  existante est visible par `pending`. *Choix du concepteur.*
- **`requested_by` par le tunnel** : la porte y ajoute l'identité
  réellement résolue (`… — pair wireguard:<clé>`), pour qu'un pair
  administrateur compromis ne puisse pas afficher un autre nom devant le
  toucher. Par la console, le texte reste libre et l'utilisateur local va au
  journal. Le test d'équivalence des connecteurs compare donc les campagnes
  hors `requested_by`. *Choix du concepteur.*
- Plafond global inchangé : `MAX_LIVE_SIGNING_OPERATIONS` (64).
- Les refus d'aujourd'hui sont conservés : aucune cible, plus de 256 cibles,
  coffre absent pour une portée qui l'ouvre, pair inconnu ou déjà révoqué.
- Journal structuré à chaque ouverture et chaque refus : connecteur, identité
  (clé WireGuard ou utilisateur local), action, `operation_id`. Pas d'entrée
  dans l'audit chaîné : une ouverture n'est pas une mutation durable du
  registre, comme aujourd'hui.

### 5.4 Connecteur tunnel

- **Astra** : route privée `POST /internal/v1/operator/campaigns`, constante
  dans `astra-channel` à côté des autres, montée par
  `operator::private_routes`. Corps : l'identité administrateur relayée et la
  requête typée (`RelayedOperatorOpen { operator, request }`). Connecteur =
  tunnel.
- **heliosd** : `POST /api/certificates/operator/campaigns`, nouvelle méthode
  `open` du trait `OperatorCampaignRelay`, derrière `require_admin` puis
  `operator_caller` comme les autres, avec la cohérence d'origine exigée pour
  une mutation administrative (§8.5.2). Bornes de §8.5.1 : 64 Kio en entrée,
  128 Kio en réponse.
- Refus publics grossiers et indistincts (§8.5.4) ; le détail va aux journaux
  de la gateway et d'Astra. Gateway sans canal privé : `503`.

### 5.5 Connecteur console

- Le service ouvre un **socket Unix** dans le volume d'état (par exemple
  `<state_dir>/operator.sock`), mode `0600`, créé au démarrage de `astra run`
  et retiré à l'arrêt. Il ne sert **que** la porte : aucune autre route n'y est
  montée. L'utilisateur local est lu par `SO_PEERCRED` pour le journal.
  Connecteur = console locale. *Choix du concepteur ; l'alternative écartée
  est de garder `campaign-inbox/` en n'y déposant qu'une intention, au prix
  d'une réponse par fichier et d'une attente par sondage.*
- Les sous-commandes gardent leurs arguments (sauf `--gateway-channel` et
  `--gateway-certificate` des ouvreurs gateway, §5.1) et leur sortie actuelle,
  dont la ligne `astra-signer revoke …` complète qu'elles impriment déjà (les
  docs et `astra-signer`, livré jusqu'au lot 7, s'en servent) : elles envoient
  la requête, attendent la réponse et impriment.
- Service arrêté ou socket absent : refus clair (« le service Astra ne tourne
  pas : rien n'a été ouvert »), code de sortie non nul, aucune écriture.
- La console s'emploie par `compose exec` (DEPLOIEMENT-ASTRA, tableau « en
  marche ») : c'est le même conteneur, donc le même socket.
- **Retirés** : `campaign-inbox/`, `spawn_campaign_drain`,
  `CampaignDeposit`, `adopt_deposit`, `deposit_campaign`, et toute lecture de
  `service-key.bin` ou de `registry.json` par un ouvreur. Le balayage
  `forget_expired_transitions` qui partageait la boucle du drain est conservé
  sur son propre intervalle (même période).

### 5.6 Les écritures qui ne sont pas des ouvertures

`PinCaTls`, `IssuerInstall` et `GatewayIdentityPublish` gardent exactement
leurs vérifications actuelles (refus d'écraser une ancre épinglée ;
vérification de la délégation sous l'ancre, la politique et les clés sur
disque ; marque persistée avant le relais, rejouable), mais s'exécutent dans le
service, sur le registre en mémoire, sous son verrou, et le persistent par le
chemin d'écriture du service. Leur effet est donc visible de la porte à
l'ouverture suivante, sans redémarrage. `issuer install` lit toujours sa
délégation dans un fichier ou sur l'entrée standard **côté console**, et en
envoie le contenu, borné, à la porte. Les sorties de la console ne changent
pas.

### 5.7 Échéances de révocation

La sortie de la porte porte, pour une révocation, les `not_after` signés des
moitiés figées (une valeur pour un client, deux pour la gateway). Elles
voyagent hors des octets signés de la campagne : une valeur altérée en route
ne révoque pas la mauvaise chose, Astra refuse le dépôt en la comparant à la
génération active (comportement actuel). Pas de changement de format dans
`aether` : `SigningOperationView` (`deny_unknown_fields`) reste tel quel, car
un champ de plus casserait les `astra-signer` et Orion déjà livrés. Les
échéances ne sont donc que dans la **réponse d'ouverture** ; Orion (5c), qui
ouvre lui-même la révocation, les garde dans sa session. *Choix du
concepteur.*

### 5.8 Documents à amender

- **ROTATION-CERTIFICATS** : §7.6 (qui ouvre une campagne), §8.5.1 (routes :
  `pending` et l'ouverture, et la phrase « aucune autre » réécrite), §8.5.6,
  §11.6 (l'interface demande à Astra un manifeste résolu : c'est la porte),
  §12.3 (état d'implémentation), et un amendement daté du 2 novembre 2026 qui
  énonce le principe « Astra tient la porte, le reste est connecteur ».
- **ADR-008** : même amendement, et la console comme connecteur.
- **RENOUVELLEMENT-CERTIFICATS** et **DEPLOIEMENT-ASTRA** : les commandes
  restent les mêmes mais exigent le service en marche ; l'échéance n'est plus
  recopiée à la main.
- **Commentaires de code** qui justifient l'inbox ou le refus d'ouvrir
  (`service.rs:340`, `signing.rs` « Why an inbox and not a call »,
  `CampaignCommand::Open`, `daemon.rs`).
- **ROADMAP** (F14) et **MANUAL-TESTING** (« F. Lot 5a »).

### 5.9 Le service seul écrivain

- Avec le service en marche, plus aucune commande de la console n'ouvre
  `registry.json` en écriture. Un test (ou un contrôle par recherche dans le
  code) le garantit pour chaque sous-commande hormis `bootstrap`.
- **`bootstrap` reste une commande locale** : c'est l'acte fondateur, il crée
  le registre avant qu'aucun service n'existe, et il refuse déjà un registre
  présent. Il refuse aussi quand le socket de la porte répond (service en
  marche).
- **`init-channel` reste une commande locale** : il écrit l'identité de
  transport du canal privé, que le service ne lit qu'au démarrage et qui exige
  de toute façon de réépingler la gateway. Il refuse quand le service est en
  marche.
- `status` reste une lecture ; le constructeur choisit s'il lit par la porte
  ou le fichier (§9).

## 6. Sécurité

- **Ce qui change de mains** : la clé de service et la résolution du registre
  ne sont plus détenues que par le service. C'est un gain net : deux seconds
  processus de moins qui lisent la clé de service.
- **Ce qui s'ouvre** : un pair administrateur peut ouvrir, par le tunnel, les
  trois actions du §5.2, et lire en retour le résumé d'une campagne (cibles,
  empreintes, générations). Ce sont des objets publics signés, déjà lisibles
  par ce même pair au travers des routes opérateur existantes une fois
  l'opération ouverte. Le refus de la route publique est maintenu.
- **Ce qui ne change pas** : capacités bearer, fenêtres de cinq minutes,
  vérification par Orion du manifeste sous la clé de service épinglée,
  assertion WebAuthn, signatures `CA-PQ`, refus de dépôt par Astra.
- **Abus borné** : un pair administrateur compromis peut ouvrir au plus une
  campagne par famille (une par identité pour les révocations), qui expire
  seule en cinq minutes et ne fait rien sans clé.
- Aucun secret journalisé ni renvoyé ; identifiants et commentaires de code en
  anglais, messages de la console et `docs/` en français.

## 7. Tests attendus

- La porte : chaque action, chaque refus du §5.3, la table du §5.2 testée
  ligne par ligne, une ouverture en double par famille, deux révocations de
  deux postes distincts acceptées.
- Équivalence des connecteurs : la même requête par le socket et par la route
  privée produit la même campagne (hors identifiants tirés au hasard) et
  passe par la même fonction.
- `heliosd` : pair non administrateur refusé avant tout relais, origine
  incohérente refusée, absence de canal privé en `503`, bornes de taille.
- Console : service arrêté refusé sans écriture ; la sortie d'une révocation
  contient les échéances exactes ; aucune lecture de `service-key.bin` ni de
  `registry.json` par les ouvreurs (test ou contrôle par recherche).
- Écritures : `pin-ca-tls` puis `campaign open --scope trust-authorities`,
  sans redémarrage, donne une campagne avec la ligne CA-TLS ; `issuer install`
  et `gateway-identity publish` gardent leurs refus et leur rejouabilité
  actuels ; `bootstrap` et `init-channel` refusent quand le service tourne.
- Bout en bout existant inchangé : une campagne `fleet_leafs` ouverte par le
  tunnel apparaît dans `pending` et s'approuve dans Orion par le chemin du
  lot 4.

## 8. Recette (MANUAL-TESTING, « F. Lot 5a »)

Sur la gateway et sur le poste Windows de l'opérateur :
1. `compose exec -T astra astra campaign open --scope fleet-leafs …` ouvre et
   imprime l'identifiant ; service arrêté, la même commande refuse.
2. Depuis le poste admin, dans le tunnel, `POST
   /api/certificates/operator/campaigns` ouvre une campagne `fleet_leafs` ;
   elle apparaît dans l'onglet Approbations d'Orion et s'approuve.
3. Depuis un pair non administrateur, la même requête est refusée.
4. Par le tunnel, l'ouverture d'une révocation client rend l'identifiant et
   l'échéance signée ; `astra-signer revoke` lancé avec ces valeurs aboutit.
5. Une campagne ouverte par le tunnel affiche `requested_by` suivi de la clé
   WireGuard du pair qui l'a ouverte.
6. Sur un domaine sans CA-TLS épinglée : `astra pin-ca-tls …`, puis sans
   redémarrer `astra campaign open --scope trust-authorities` montre deux
   cibles (CA-PQ et CA-TLS).

## 9. Laissé au constructeur

- Le nom et la forme exacts des types (requête, réponse, connecteur, refus),
  dans l'esprit des types fermés existants.
- Le découpage en tâches et l'ordre des migrations d'ouvreurs, à condition
  que l'inbox ne soit retirée qu'une fois le dernier ouvreur migré.
- Le nom et l'emplacement exacts du socket dans le volume d'état.
- La manière dont `chain status` lit le plan (par la porte ou en lecture
  seule du fichier) : c'est une lecture, pas une ouverture.
