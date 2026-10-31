# F14 lot 4 : approbations dans Orion, retrait du compagnon de renouvellement

Date : 31 octobre 2026. Branche `feat/f14-lot4-approbations`, depuis `main`
79051da.

## 1. Intention

Les lots 1 à 3 et 6a ont fait de l'onglet Astra l'espace opérateur. Il reste
deux endroits où Orion renvoie encore vers `astra-signer` pour approuver :

- **le renouvellement ordinaire** (§8.1.2) : quand un profil attend un
  opérateur, Orion lance automatiquement `astra-signer approve --heliosd-url
  … --operation-id …` (plugin Tauri `companion`) et affiche la ligne de
  commande en repli ;
- **la récupération d'une identité expirée** (§7.5) quand la clé est sur un
  autre poste : l'écran Certificats affiche `astra-signer recover
  --authority-url … --operation-id …` à lancer ailleurs.

S'y ajoute `authorize-issuer` (délégation de l'émetteur d'Astra, §9.5), que
seul `astra-signer` sait signer : l'onglet *Approbations* affiche les
campagnes `issuer_delegation` mais les marque « pas encore disponible ».

Objectif hérité du lot 3 : **ergonomique et moins pénible**. Toute approbation
se fait depuis Orion, en un geste, sans ligne de commande à recopier.

### Constat qui motive l'essentiel du lot

Orion sait déjà approuver un renouvellement lui-même (« Approuver avec la
clé », `approve_certificate_renewal`), mais cette cérémonie s'exécute **dans le
moteur** (`orion-engine`, `VerifiedApproval::run` sur un fil bloquant, dialogue
rattaché à `DialogOwner::Console`). Depuis F11 le moteur est le processus
élevé, et la spec F11 range les cérémonies WebAuthn du côté de l'IHM non
élevée : l'API WebAuthn de Windows ne répond qu'à un processus d'intégrité
moyenne, dans la session de l'utilisateur. Sous Windows, ce bouton ne peut donc
pas aboutir ; le compagnon, lancé depuis l'IHM non élevée, est aujourd'hui le
seul chemin qui fonctionne. **Déduit du code et de la spec F11, non vérifiable
sous WSL2 : à constater en recette.**

Retirer le compagnon impose donc d'abord de déplacer la cérémonie de
renouvellement dans le processus de l'IHM, comme l'ont été les cérémonies
opérateur.

## 2. Objectifs

1. **Renouvellement ordinaire** : la cérémonie (assertion WebAuthn/FIDO2) se
   joue dans le processus de l'IHM, dialogue rattaché à la fenêtre d'Orion. Le
   moteur garde ce qu'il possède : la session de renouvellement, la lecture et
   la vérification de la demande dans le tunnel, le jeton de dépôt, le dépôt.
2. **Retrait du compagnon de renouvellement** : plugin `companion`,
   `launch_certificate_companion`, `EngineCommand::CompanionArguments` et sa
   réponse, `RenewalProgress::AwaitingOperator::companion_command`,
   `CompanionInvocation` et `COMPANION_PROGRAM` d'`orion-core`, lancement
   automatique, bouton « Relancer le compagnon », ligne « compagnon » du
   chemin manuel, permission Tauri correspondante.
3. **Récupération approuvée depuis un autre poste** : l'onglet *Approbations*
   de l'Orion de l'opérateur ouvre une récupération à partir de son
   identifiant d'opération ; l'écran Certificats du poste expiré ne montre plus
   de commande `astra-signer`, mais l'identifiant et le chemin dans Orion.
4. **`authorize-issuer`** dans *Approbations* : en campagne (`issuer_delegation`,
   chemin ordinaire) et hors campagne (dernier recours, signalé comme tel).

## 3. Non-objectifs

- La rotation CA-TLS (écran *Rotations*, `astra.rs`) : elle reste sur
  `astra-signer` en mode `orion` caché jusqu'au lot 5. `companion.rs` et
  `launch::spawn_astra_signer` **restent** donc, avec cet unique appelant
  (voir §6.1).
- Les campagnes d'ancre, de révocation, d'identité de gateway et d'amorçage
  (lots 5 et 6b) : elles restent « pas encore disponible » dans *Approbations*.
- Le transport tunnel (`--heliosd-url`) des campagnes : Orion continue de
  passer par l'origine publique, comme aujourd'hui.
- Le retrait d'`astra-signer` lui-même (lot 7).
- `scripts/deploy.sh`, outil de dev, n'est pas modifié.

## 4. Anti-objectifs

- Un PIN, une assertion, un secret de key-slot ou un octet du coffre journalisé
  ou sérialisé hors de ce que le protocole impose.
- Une approbation signée sans que son manifeste ait été affiché, ou signée sur
  un autre objet que celui affiché.
- Un repli silencieux d'un transport vers un autre (§8.5.5).
- Une nouvelle commande ou un nouveau binaire côté poste.

## 5. Contraintes

Celles d'`AGENTS.md` et de `CLAUDE.md` : fail-closed, pas d'`unwrap` ni
d'`expect` en production, aucun TODO, identifiants/commentaires/tests en
anglais, `docs/` et IHM en français, aucune nouvelle dépendance externe,
ADR et spec mis à jour quand le contrat change. Refus de cérémonie : classe
fermée `Refusal` sans texte, toute nouvelle cause = nouvelle variante + phrase
française dans l'IHM. La fenêtre fait 520 × 560.

## 6. Conception

### 6.1 Renouvellement ordinaire : cérémonie dans l'IHM

**Répartition.**

| Moteur (élevé) | IHM (non élevée) |
| --- | --- |
| session de renouvellement, jeton de dépôt | connexion à la clé, dialogue WebAuthn rattaché à la fenêtre |
| lecture de la demande dans le tunnel, vérification (`VerifiedApproval::verify`) | re-vérification complète par `aether_fido::approve_renewal` avant l'assertion |
| contrôle que l'approbation reçue répond à la demande vérifiée, puis dépôt | PIN (HID hors Windows) : reste dans ce processus |

**Déroulement.**

1. Le profil atteint `awaiting_operator`. L'écran lit **automatiquement** le
   manifeste (`certificate_approval_manifest`, inchangé côté moteur) et
   l'affiche : pair, génération, empreinte, expiration, nombre de clés
   éligibles. Plus de bouton « Lire la demande d'approbation » ; « Relire la
   demande » n'apparaît qu'après un échec de lecture.
2. « Approuver avec la clé » : une commande Tauri de l'IHM demande au moteur le
   **matériel d'approbation** de la demande qu'il a vérifiée — uniquement des
   objets publics : la demande signée par Astra, le registre de credentials,
   l'identité du domaine, la clé de service et son époque, `CA-PQ` public, le
   RP ID épinglé, la génération active persistée. Le moteur ne le rend que pour
   une demande déjà vérifiée et affichée (sinon refus, comme aujourd'hui).
3. L'IHM exécute `aether_fido::approve_renewal` sur un fil bloquant, clé
   ouverte avec `connect_owned(transport, DialogOwner::Window(hwnd))` (même
   source de `hwnd` que les cérémonies opérateur). La fonction re-vérifie la
   signature de service, le registre sous `CA-PQ` et le RP ID avant de
   demander quoi que ce soit à la clé.
4. L'IHM remet l'`AstraRenewalApproval` au moteur. Le moteur vérifie qu'elle
   porte l'`operation_id` et l'empreinte de demande de la demande vérifiée
   qu'il détient, consomme celle-ci (une seule approbation par vérification,
   comme aujourd'hui), puis la dépose par `submit_approval`.

   La demande vérifiée n'est consommée **qu'à ce dépôt**. Tant qu'il n'a pas
   eu lieu (clé absente, annulation, PIN faux), le moteur peut redonner le
   même matériel : réessayer est un clic, sans relire la demande. Une seule
   cérémonie à la fois par profil : l'IHM désactive le bouton pendant qu'elle
   tourne, et le moteur refuse une seconde remise d'approbation pour une
   demande déjà consommée. Une demande expirée entre-temps est refusée par
   `approve_renewal` avant la clé ; l'écran propose alors « Relire la
   demande ».
5. `needs_pin` (faut-il un champ PIN ?) est aussi répondu par l'IHM : c'est elle
   qui parle à la clé.

Le PIN ne traverse plus l'IPC vers le moteur : c'est une amélioration, et la
variante `SecretInput` du protocole moteur qui le portait disparaît de cette
commande.

**Ce qui reste du compagnon.** `companion.rs` et `spawn_astra_signer` restent,
documentés comme servant la seule rotation CA-TLS jusqu'au lot 5 ; tout ce qui
relève du renouvellement (objectif 2) part. Rien d'autre que l'écran
*Rotations* ne lance plus de processus externe.

**La clé est sur un autre poste.** Une opération de renouvellement ordinaire
appartient au pair qui l'a ouverte, authentifié par sa VIP source (§8.1.2) :
un autre poste ne peut ni la lire ni y déposer une assertion. Le chemin
manuel ne montre donc plus de commande ; il dit, en une phrase, que cette
approbation se fait sur ce poste et qu'il faut y brancher la clé d'un
opérateur. (La ligne de compagnon affichée jusqu'ici ne pouvait de toute façon
pas aboutir depuis un autre poste.)

### 6.2 Récupération depuis un autre poste

**Poste expiré (écran Certificats).** L'état `recovery_awaiting_operator` garde
« Approuver ici avec la clé » (inchangé, cérémonie déjà dans l'IHM). Le repli
« La clé est sur un autre poste ? » affiche l'identifiant d'opération,
copiable, et la phrase : « Sur le poste de l'opérateur : Astra › Approbations ›
Approuver une récupération, avec cet identifiant. Puis relancer « Récupérer le
certificat expiré » ici. » Le champ `operator_command` disparaît du protocole
moteur et de l'IHM.

**Poste opérateur (onglet Approbations).** Un bloc « Approuver une
récupération » : un champ « Identifiant d'opération » (32 caractères
hexadécimaux, espaces de bord ignorés, majuscules acceptées puis normalisées)
et un bouton « Ouvrir la cérémonie », actif seulement sur une valeur valide.
Il ouvre la cérémonie `RecoverIdentity` existante avec cet identifiant ;
l'origine d'Astra vient du relais à côté du coffre, jamais d'un champ. Un
identifiant inconnu ou expiré produit le refus existant (`HandoffMismatch`).

Une récupération ouverte depuis ce champ **n'enchaîne pas** sur la
finalisation locale (`resume_certificate_recovery`) : ce poste n'a pas ouvert
cette récupération. L'état final dit « Récupération approuvée. Le poste
concerné reprend de son côté. » La finalisation automatique reste réservée à
une récupération ouverte depuis l'écran Certificats de ce même poste.

### 6.3 `authorize-issuer`

**En campagne (chemin ordinaire).** Dans *Approbations*, une campagne de
portée `issuer_delegation` devient ouvrable. « Ouvrir la cérémonie » demande
d'abord le **fichier de demande de délégation** produit par `astra issuer
request` (bouton de choix de fichier, lecture par `readFileText.ts`, borne
256 Kio ; seul le texte traverse l'IPC). La cérémonie `AuthorizeIssuer` :

1. lit le coffre et le relais, exige la CA-TLS (sinon `CaTlsMissing`) ;
2. récupère la campagne sur l'origine (`astra_operator::origin`), la vérifie
   contre le relais, exige la famille `IssuerDelegation` ;
3. décode la demande et vérifie que la campagne la couvre
   (`covers_issuer_delegation` : époque, clé PQ, `SubjectPublicKeyInfo`) —
   **avant** toute clé ;
4. affiche le manifeste `IssuerManifest` (domaine, époque, `not_before`,
   `not_after`, usages, empreintes) accompagné de la campagne (motif, demandé
   par, empreinte) ;
5. demande **une** clé : assertion de campagne d'abord, puis ouverture du
   coffre **restreinte au credential qui vient d'approuver** (liste
   d'autorisation réduite à ce seul identifiant pour la dérivation, puis
   contrôle `slot_for_credential` sur ce même identifiant). Sous Windows ce
   sont deux dialogues : la restriction garantit qu'une autre clé présentée au
   second ne peut pas répondre, ce qui se solde par `KeyDeclined`. Puis
   signature `signing::authorize_issuer` ;
6. dépose le résultat (approbation + `issuer_authorization`) sur l'origine.

État final : « Délégation enregistrée par Astra. Redémarrer Astra pour qu'il
émette sous elle. »

**Hors campagne (dernier recours).** Un bloc à part dans *Approbations*,
toujours présent (il ne dépend d'aucune campagne listée : un domaine sans
origine n'en a pas), avec un bouton « Signer une délégation sans
campagne… ». Il n'est **offert que si le relais ne nomme aucune origine
Astra** (`astra_authority_url` absent) ; sinon le bloc dit qu'une délégation
passe par une campagne (`astra issuer request --reason --requested-by` sur
l'hôte d'Astra) et la cérémonie, si elle était ouverte quand même, refuse
avec `ManifestMismatch` avant le choix de clé. Avertissement visible
avant le choix du fichier : « Rien ne rattache ce fichier à Astra : il vaut ce
que vaut son transport. À réserver à un domaine sans origine joignable. »
Mêmes étapes 1, 3 (décodage seul) et 4, puis ouverture du coffre et signature,
sans campagne ni dépôt. Le fichier d'autorisation est remis comme
`OperatorArtifact` téléchargeable (`issuer-authorization.json`) et l'état final
indique : « À installer sur l'hôte d'Astra : `astra issuer install
--authorization <fichier>`. »

**Durées.** Délégation 30 jours, comme la CLI. Leaf au plus 90 jours,
**ramené au plafond de la politique épinglée** s'il est plus bas : la
politique se lit dans l'identité du relais, donc avant toute clé, et c'est la
valeur ramenée qui est affichée puis signée. Non modifiables dans ce lot.

**Manifeste.** `IssuerManifest` (`aether::certificates::operator_session`,
jusqu'ici émis par aucune cérémonie) gagne `maximum_leaf_lifetime_secs`, les
empreintes de la clé PQ et du `SubjectPublicKeyInfo` de la demande, et un
champ facultatif `campaign` (le `CampaignManifest` de la campagne, absent hors
campagne). Ce qui est affiché est ainsi tout ce que la clé signe : l'empreinte
de campagne et la délégation. Contrat partagé : `types.ts` et ADR-008 suivent.

**Refus nouveaux.** `DelegationRequestInvalid` (fichier illisible ou qui n'est
pas une demande de délégation) et `DelegationRequestMismatch` (la campagne ne
nomme pas cette demande : époque ou clé substituée), chacun avec sa phrase
française. Une campagne d'une autre famille ouverte comme délégation produit
`ManifestMismatch`.

**Geste.** Le geste porte le texte de la demande ; le localisateur ne porte
rien d'autre que le genre et l'identifiant d'opération, comme les autres
cérémonies.

### 6.4 Liste des campagnes

`HELPER_CAMPAIGN_SCOPES` devient « portées ouvrables dans Orion » et compte
`full_certificate_chain` (famille des leaves clientes, déjà acceptée par la
cérémonie de campagne mais absente de la liste) et `issuer_delegation`.

### 6.5 Documentation

- ADR-008 et `docs/security/OPERATOR-TOOLING.md` : approbation de
  renouvellement dans l'IHM, plus de compagnon de renouvellement ;
  récupération et délégation depuis Orion ; la rotation CA-TLS reste seule sur
  `astra-signer` jusqu'au lot 5.
- `docs/specification/ROTATION-CERTIFICATS.md` : là où le texte décrit Orion
  lançant le compagnon (§12.2) ou la commande `recover` affichée, et
  l'approbation par Orion.
- `docs/testing/MANUAL-TESTING.md` : section « E. Lot 4 ».
- `docs/ROADMAP.md` : F14 lot 4.

## 7. Choix faits sans l'utilisateur

1. La cérémonie de renouvellement passe dans l'IHM (§6.1) : sans cela, retirer
   le compagnon retirerait le seul chemin qui marche sous Windows.
2. Le manifeste se lit automatiquement ; un seul bouton touche la clé.
3. `companion.rs` et `spawn_astra_signer` restent jusqu'au lot 5 pour la seule
   rotation CA-TLS, au lieu de porter cette rotation dans ce lot.
4. Plus de chemin « autre poste » pour un renouvellement ordinaire : impossible
   par construction (§8.1.2).
5. Récupération à distance par saisie de l'identifiant d'opération : les
   récupérations ne sont pas énumérables (§8.5, `operator_pending`), c'est
   donc le seul moyen de les atteindre.
6. `authorize-issuer` hors campagne est porté, avertissement compris, parce
   qu'il est le seul chemin d'un domaine sans origine joignable et qu'il
   disparaîtrait avec `astra-signer` au lot 7.
7. **`approve-campaign` hors ligne (`--campaign`/`--out`) n'est pas porté** :
   aucun composant du dépôt ne lit un fichier `CampaignApproval` (ni `astra`,
   ni `heliosd`, ni Orion — vérifié par recherche). Le porter produirait un
   fichier que rien n'installe. `recover` n'a pas de mode hors ligne : la
   récupération exige un aller-retour avec l'autorité.
8. Durées de délégation fixes (30 j / 90 j), la seconde ramenée au plafond de
   la politique avant la clé.
9. En campagne, une seule clé physique : l'ouverture du coffre n'accepte que le
   credential qui a approuvé la campagne.
10. Délégation hors campagne offerte seulement quand le relais ne nomme aucune
    origine Astra (fail-closed).
11. `IssuerManifest` étendu plutôt qu'une nouvelle variante de manifeste.
12. La demande de renouvellement vérifiée n'est consommée qu'au dépôt de
    l'approbation ; un échec avant permet de réessayer sans relire.

## 8. Laissé au constructeur

- Les noms des nouvelles commandes moteur et Tauri, et la forme exacte du
  matériel d'approbation (structure sérialisable dans `orion-core`).
- Le découpage de `VerifiedApproval` entre vérification (moteur) et assertion
  (IHM), tant que la vérification complète a lieu des deux côtés.
- La disposition exacte des blocs dans *Approbations*, dans la largeur de
  520 px.
- Le nom du fichier de demande attendu (aucun n'est imposé).

## 9. Vérification

- Tests Rust : matériel refusé sans demande vérifiée ; approbation refusée par
  le moteur si `operation_id` ou empreinte diffèrent ; la demande vérifiée est
  consommée une fois ; `AuthorizeIssuer` refuse une demande non couverte avant
  toute clé (`DelegationRequestMismatch`), une campagne d'une autre famille
  (`ManifestMismatch`), une demande illisible (`DelegationRequestInvalid`) ;
  le mode hors campagne remet un artefact et ne dépose rien. Avec les clés
  simulées existantes d'`astra-operator`.
- Tests IHM (vitest) : lecture automatique du manifeste ; plus de compagnon ;
  champ d'identifiant de récupération (validation, normalisation) ;
  récupération à distance sans finalisation locale ; carte `issuer_delegation`
  ouvrable avec choix de fichier ; avertissement du mode hors campagne ;
  phrases des deux refus nouveaux.
- `grep` : plus aucune occurrence de `launch_certificate_companion`,
  `CompanionArguments`, `companion_command`, `operator_command`,
  `CompanionInvocation` ; `companion::launch` n'a plus que l'appelant
  `astra.rs`.
- Régression complète, résultat attendu exit 0 avec les seuls « 7 allowed
  warnings » de cargo audit.
- **Non vérifiable sous WSL2, à constater en recette Windows** : le dialogue
  WebAuthn d'un renouvellement depuis l'IHM, rattaché à la fenêtre ; une
  récupération approuvée depuis un second poste ; une délégation en campagne
  puis le redémarrage d'Astra.
