# F14 lot 6a — Amorcer la gateway depuis Orion — conception

Suite de la [conception F14](2026-10-27-orion-seul-client-design.md) et du
[lot 3](2026-10-28-f14-lot3-coffre-domaine-design.md), dont elle reprend les
règles (cérémonie du processus opérateur, refus fermés `Refusal`, manifeste
montré avant le toucher, aucun chemin de la WebView vers Rust). Ce document ne
dit que ce qui est propre à l'amorçage. Rien ici n'a été constaté sous Windows.

## 1. Pourquoi

Depuis le lot 3, un domaine se crée et se finalise dans Orion, mais il reste un
geste en console entre les deux : `astra-signer issue-gateway-bootstrap`, qui
émet sous `CA-PQ` la première feuille PQ de la gateway (époque 1), avec deux
clés distinctes. Tant qu'il reste, monter un domaine exige encore un outil à
part, ce que la règle du 24 octobre 2026 exclut (Orion seul binaire côté poste).

Demande de l'utilisateur (31 octobre 2026) : faire le lot le plus utile ; le
lot 6 est retenu, en commençant par l'amorçage. Objectif hérité du lot 3 :
**ergonomique et moins pénible**.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**

- Un geste « Amorcer la gateway… » dans *Domaine* remplace
  `astra-signer issue-gateway-bootstrap`, avec les mêmes vérifications.
- Moins d'étapes que la console : sur un domaine neuf, le même geste enchaîne
  la finalisation du lot 3 (`CA-TLS` et document de credentials) quand elle
  manque, sans toucher de plus. Deux clés, un toucher chacune.
- Ce qui est impossible se voit avant le premier toucher : demande illisible
  ou invérifiable, relais qui nomme une autre gateway, moins de deux clés
  actives.
- La feuille émise est remise à l'opérateur comme les artefacts des lots 2-3
  (« Enregistrer… ») et déposée à côté du coffre.

**Non-objectifs**

- Lot 6b, conception à part : `sign-gateway-transition`, `sign-gateway-rollback`,
  `abort-gateway-transition` (campagne Astra, demande préparée sur la gateway,
  installation de la décision).
- `scripts/deploy.sh` : **outil de développement, laissé tel quel** (décision
  de l'utilisateur, 31 octobre 2026). Il continue d'imprimer la commande
  `astra-signer` ; la documentation dit le geste Orion équivalent.
- Aucune route nouvelle sur la gateway, aucun transport en ligne : l'amorçage
  voyage par fichiers (ADR-008, `astra-signer` §« Gestes qui voyagent par
  fichiers » : le domaine neuf n'a encore ni registre, ni clé de service).
- Aucun changement de format du coffre, du relais, de la demande ou de la
  feuille.

**Anti-objectifs**

- Une feuille émise pour une gateway que le relais ne nomme pas, ou dont la
  demande ne se vérifie pas sous sa propre signature.
- Un amorçage approuvé deux fois par la même clé.
- Un PIN demandé puis un refus pour une raison connue d'avance.
- Un chemin de fichier qui passe de la WebView à Rust.
- Un secret (PIN, secret de key-slot, clé `CA-PQ`, octets du coffre) journalisé,
  sérialisé ou montré.

## 3. Ce qui existe

- `tools/astra-signer/src/commands/gateway_identity.rs`, `issue_gateway_bootstrap` :
  lit la demande (`GatewayBootstrapRequest`, exportée par
  `heliosd init-key-negotiation`, sur la gateway
  `/var/lib/helios/gateway-bootstrap-certificate-request.json`), `verify()`,
  inscrit au relais la clé WireGuard et le nom de service (jamais remplacés :
  une autre gateway est refusée), ouvre deux clés, exige deux credentials
  distincts (`CampaignScope::GatewayBootstrap.required_credentials() == 2`),
  prouve que chacune ouvre les ancres (`prove_anchors_open`), puis
  `signing::issue_gateway_bootstrap_certificate` (validité 365 jours, numéro
  aléatoire) et écrit la feuille JSON.
- Lot 3 : `vault_gestures::finalization` / `finalize_with` (`CA-TLS` et document
  de credentials), `adopt_gateway` et `write_relay` (identité en remplissage
  seul, contrôle du document lié à une autre gateway), cérémonie
  `ceremony/vault.rs`, `ArtifactDownloads` dans `AstraView`, `DomainPanel`.
- Lot 2 : la WebView lit un fichier choisi et n'en envoie que le contenu public
  (`EnrollmentOperatorPanel.tsx`, « Accepter une demande »).
- `deploy.sh` rapatrie la demande à côté du relais
  (`gateway-bootstrap-request.json`) et reprend avec
  `gateway-bootstrap-certificate.json` au même endroit.

## 4. Décisions

### 4.1 Le geste

*Domaine* → « Amorcer la gateway… » :

1. L'opérateur choisit le fichier de demande de la gateway (sélecteur de la
   WebView, comme au lot 2) ; la WebView envoie son contenu, jamais un chemin.
2. Avant toute clé, Rust : analyse et `verify()` la demande ; compare la clé
   WireGuard et le nom de service au relais (remplissage seul, règle du lot 3 :
   une valeur enregistrée différente refuse, un document de credentials lié à
   une autre gateway refuse) ; exige au moins deux clés actives dans le coffre ;
   calcule ce que la finalisation émettra encore (`finalization`).
3. Manifeste montré avant le toucher : gateway (nom de service), identité
   WireGuard, empreinte de la demande, époque 1, validité jusqu'à (365 jours),
   « deux clés distinctes », et, s'il y a lieu, « puis : émettre la `CA-TLS` »
   et/ou « signer le document de credentials ».
4. Deux ouvertures de clé (« Brancher la première clé… », puis « Débrancher
   celle-ci, brancher une autre clé… ») ; la seconde refusée `KeyRepeated` si
   c'est le même credential. Chaque ouverture prouve les ancres (ADR-008).
5. Écritures, dans cet ordre : identité au relais si elle manquait ; feuille
   signée écrite à côté du coffre (`gateway-bootstrap-certificate.json`) ;
   puis, si `finalization` l'a demandé, `finalize_with` avec la première
   ouverture. Un échec après la feuille laisse la feuille en place ; le bouton
   « Finaliser le domaine » du lot 3 reprend ce qui manque.
6. Fin : « Enregistrer la feuille de la gateway » (et `ca-tls.pem` si émise),
   l'empreinte de la feuille, et les étapes suivantes (porter la feuille sur la
   gateway ; la documentation dit la commande).

### 4.2 Disponibilité

- Bouton actif dès que le coffre a deux clés actives. Désactivé, avec sa
  raison, sinon (« Il faut deux clés actives pour amorcer la gateway. »).
- Il reste disponible après un premier amorçage : réémettre une feuille
  d'époque 1 pour la **même** gateway est permis, comme en console (la gateway
  n'en installe qu'une ; le geste coûte deux touchers et ne change rien au
  domaine). Une autre gateway est refusée.

### 4.3 Contrat

- `OperationKind::IssueGatewayBootstrap` ; manifeste `GatewayBootstrapManifest`
  (nom de service, clé WireGuard, empreinte de la demande, fin de validité,
  émet `CA-TLS` oui/non, signe le document oui/non).
- Refus nouveaux, chacun avec sa phrase française côté IHM :
  `BootstrapRequestInvalid` (la demande ne s'analyse pas ou ne se vérifie pas),
  `OtherGateway` (le relais ou le document nomme une autre gateway). Les autres
  cas reprennent les refus existants (`MinimumKeys`, `KeyRepeated`,
  `KeyNotEnrolled`, `LocationUnavailable`, `GatewayIdentityMissing`).
- Le geste entre dans `VaultGesture` (lot 3), avec le contenu de la demande
  comme seul paramètre ; taille bornée (même borne que le lot 2 pour un fichier
  lu par la WebView).

### 4.4 Documentation

- `docs/DEPLOIEMENT-ASTRA.md` : l'étape « `issue-gateway-bootstrap`, en ligne de
  commande » devient « Orion, *Domaine* : « Amorcer la gateway… » » ; avec
  `deploy.sh` (développement), choisir la demande qu'il a rapatriée et
  enregistrer la feuille au chemin qu'il imprime. `astra-signer` reste cité comme
  voie transitoire jusqu'au lot 7.
- `docs/testing/MANUAL-TESTING.md` : section « F14 lot 6a », sur un coffre
  d'essai : demande valide, demande altérée (refus avant clé), même clé deux
  fois, demande d'une autre gateway, enchaînement de la finalisation.
- ROADMAP (F14) et ADR-008 (amendement du lot 3 prolongé d'une phrase).

## 5. Sécurité

Mêmes invariants que le lot 3 : la WebView ne fournit que le contenu public de
la demande ; tout est revérifié en Rust et montré avant le toucher ; aucune
ouverture ne quitte le fil de la cérémonie ; la feuille et la `CA-TLS` sont
publiques. Fail-closed : rien n'est écrit avant que les deux clés aient ouvert
le coffre et prouvé les ancres (§9.1) ; une erreur entre l'identité et la
feuille ne laisse que l'identité de relais, déjà vérifiée contre la demande.

## 6. Tests

- `astra-operator` : demande valide (feuille vérifiable sous `CA-PQ`, identité
  inscrite) ; demande altérée ; autre gateway (relais, puis document) ; moins
  de deux clés ; même credential deux fois ; enchaînement de la finalisation
  quand `CA-TLS` manque, et absent quand le domaine est complet ; ordre des
  écritures (la feuille existe quand la finalisation échoue).
- Orion (Rust) : `VaultGesture` refuse un contenu trop gros, refus mappés.
- IHM (vitest) : bouton désactivé avec sa raison, manifeste, artefacts de fin.

## 7. Laissé au constructeur

Découpage des fonctions, libellés exacts des invites (dans l'esprit du lot 3),
emplacement du manifeste dans le contrat, factorisation avec
`astra-signer`.

## 8. Choix faits sans l'utilisateur (à relire)

1. Lot 6 coupé en 6a (amorçage) puis 6b (transition, retour arrière, abandon).
2. Fichiers plutôt qu'une route sur la gateway (ADR-008, et aucune route
   nouvelle à faire valider).
3. L'amorçage enchaîne la finalisation du lot 3 quand elle manque.
4. Réémettre une feuille d'époque 1 pour la même gateway reste permis.
5. La feuille est aussi déposée à côté du coffre, au nom que `deploy.sh` lit.

## 9. Précisions (vérification du constructeur, 31 octobre 2026)

Questions d'un lecteur constructeur, tranchées sans l'utilisateur (aucune ne
change ce qui est construit) :

1. **Plan d'amorçage avant toute clé.** `finalization()` ne convient pas : elle
   refuse `GatewayIdentityMissing` sur un relais neuf et `DomainComplete` sur un
   domaine complet, deux cas normaux ici. Une fonction nouvelle de
   `vault_gestures` (par exemple `bootstrap_plan(vault_path, &request)`) calcule,
   sans rien écrire : l'identité à inscrire (tirée de la demande, comparée au
   relais), `issues_ca_tls` (le relais n'a pas de `CA-TLS`), `issues_credentials`
   (aucun document vérifié ne décrit chaque emplacement). Domaine complet = rien
   à enchaîner, pas un refus. Un document de credentials déjà en place sur un
   relais sans identité : vérifié et lié à la gateway de la demande, il est
   accepté ; lié à une autre gateway, `OtherGateway` ; invérifiable,
   `GatewayIdentityMissing` (restaurer depuis une sauvegarde, comme au lot 3).
   Ordre : les deux ouvertures et `prove_anchors_open` pour chacune
   (`ceremony/vault.rs::open_vault` ne le fait pas : l'appel est ajouté), puis
   identité au relais, puis feuille, puis `finalize_with` (qui recalcule et
   n'émet que ce qui manque ; `DomainComplete` à ce stade = rien à faire).
2. **`OtherGateway` est un `SetupRefusal` typé.** Les deux sites du lot 3 qui
   refusent aujourd'hui une autre gateway par un texte (`write_relay`,
   `adopt_gateway`) passent sur cette variante, avec leurs tests ; le nouveau
   geste partage le même contrôle (`bound_to_another_gateway`).
3. **« Deux clés actives »** = au moins deux emplacements du coffre que le
   document vérifié ne révoque pas (tous, sans document). Une clé révoquée est
   refusée comme signataire (`KeyNotEnrolled`) ; une clé marquée perdue reste
   acceptée, comme au lot 3. Moins de deux : `MinimumKeys`, bouton désactivé
   avec sa raison.
4. **Feuille déjà présente à côté du coffre** : remplacée par écriture privée
   atomique (`write_private_atomic`) ; la plus récente est celle à porter. Le nom
   est celui que lit `deploy.sh` (`scripts/deploy.sh:52`,
   `$(dirname "$RELAIS")/gateway-bootstrap-certificate.json`, le relais étant à
   côté du coffre).
5. **La première ouverture est gardée** pendant que la seconde clé est branchée
   (c'est ce que fait la console) et sert à la feuille et à la finalisation :
   deux touchers en tout, aucun troisième.
6. **Borne de taille** : 256 KiB, celle d'« Accepter une demande »
   (`EnrollmentOperatorPanel.tsx`), appliquée aussi côté Rust, avec un test.
