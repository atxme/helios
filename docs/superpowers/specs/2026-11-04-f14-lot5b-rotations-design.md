# F14 lot 5b : les rotations dans Orion

Date : 4 novembre 2026. Branche `feat/f14-lot5b-rotations`, depuis `main`
b3db983. Deuxième des trois sous-lots du lot 5 de F14 (5a porte unique, livré ;
5b rotations ; 5c révocation d'un poste).

## 1. Intention

L'opérateur ne fait pas ses rotations lui-même : les commandes sont
inutilisables pour lui. Une rotation demande aujourd'hui d'ouvrir une campagne,
de recopier un identifiant, de lancer `astra-signer` avec des durées choisies
sans repère, de transporter un fichier jusqu'à la gateway, de comparer une
empreinte, puis de penser à terminer des semaines plus tard.

Le lot 5b rend ces rotations faisables depuis un seul écran d'Orion, sans
commande, sans fichier à transporter et sans identifiant à recopier. Le toucher
des clés ne change pas : seul ce qui l'entoure disparaît.

**Critère de réussite** : un opérateur qui n'a jamais ouvert de terminal renouvelle
ses postes et remplace une CA depuis Orion, et sait quoi faire quand une étape
bloque.

## 2. Décisions de l'utilisateur (4 novembre 2026)

- **Accueil en liste** : toutes les actions et leur état ; ce qui est à faire
  passe en premier (maquette A, préférée à un assistant).
- **Prérequis vérifiés avant toute ouverture** : Orion contrôle tout seul et dit
  quoi faire s'il manque quelque chose. Rien n'est ouvert à moitié.
- **Textes courts et neutres** : des libellés, pas de phrases, pas de « tu », pas
  de ton familier. Exemples retenus : « Prérequis », « Clé 2 : toucher la clé »,
  « Fin de rotation le 4 déc. ».
- **« Tout renouveler » attend le lot 6b** : il est retiré de l'écran du 5b.

## 3. Objectifs

1. L'onglet **Rotations** existant d'Astra (`AstraView.tsx`, `rotations`), dont le
   formulaire actuel disparaît, devient la liste du §5.1.
2. **Renouveler les postes** : ouvre `fleet_leafs` par le tunnel et enchaîne la
   cérémonie existante.
3. **Remplacer la CA-PQ** et **Remplacer la CA TLS** : ouvrent `trust_authorities`
   par le tunnel, jouent la cérémonie dans Orion, déposent le résultat et
   installent la transition sur la gateway sans fichier.
4. **Terminer la rotation CA TLS** : remplace `promote-ca-tls`.
5. **Reprise sans clé** d'une rotation interrompue (aujourd'hui
   `resume-rotation`).
6. Orion ne lance plus `astra-signer`. Sortent : `apps/orion/src-tauri/src/companion.rs`,
   `apps/orion/src-tauri/src/astra.rs`, `launch::spawn_astra_signer`, le mode caché
   `astra-signer orion`, `crates/astra-operator/src/orion.rs` et ce qui ne sert plus
   qu'à eux dans `aether::certificates::operator_ipc`.
7. Les deux suivis du 5a sur la route d'Orion (§5.6).

## 4. Non-objectifs et anti-objectifs

**Non-objectifs**
- La révocation d'un poste (5c).
- « Tout renouveler », la délégation de l'émetteur et l'identité de la gateway :
  la table de la porte (spec 5a §5.2) les réserve à la console ou au 6b. Elle n'est
  pas élargie ici.
- Le retrait des commandes d'`astra-signer` (lot 7), qui restent utilisables.
- Un rappel hors d'Orion : ni notification système, ni tâche de fond.

**Anti-objectifs (échec même si « ça marche »)**
- Une rotation autorisée autrement que par le toucher des clés sur le manifeste
  vérifié. Les vérifications d'Orion sont un confort et ne remplacent aucun contrôle
  de la porte, d'Astra ou de la gateway.
- Une campagne ouverte alors qu'un prérequis manque : l'opérateur se retrouverait
  avec une famille bloquée pendant cinq minutes pour rien.
- Une décision signée qui peut se perdre : une clé tournée dans le coffre sans trace
  durable de ce qui reste à déposer ou à installer.
- Deux chemins de cérémonie : Orion réutilise la logique d'`astra-operator` et ne
  recopie pas les règles de signature.
- Un secret, un PIN ou une clé dans la WebView.

## 5. Conception

### 5.1 L'écran

Dans cet ordre, une ligne par action, avec son état et un bouton :

| Ligne | État affiché | Bouton |
| --- | --- | --- |
| Terminer la rotation CA TLS | « À faire » (visible à partir de `not_after`) | Terminer |
| Reprendre une rotation | visible si une rotation signée n'est pas allée au bout | Reprendre |
| Renouveler les postes | nombre de postes, échéance la plus proche | Renouveler |
| Remplacer la CA-PQ | « 2 clés », ou date de fin d'une rotation en cours | Remplacer |
| Remplacer la CA TLS | expiration, « 2 clés », ou date de fin d'une rotation en cours | Remplacer |

Une ligne à faire passe en premier et se distingue visuellement. Une action
impossible (une rotation de même nature déjà en cours) a son bouton désactivé et dit
pourquoi en quelques mots. Les données viennent de `GET /api/certificates`
(`CertificateDomainView` : `peers[].not_after`, `client_tls_ca_transition_pending`,
`ca_retire_active_at`, `next_ca_fingerprint`…), du coffre local et du journal de
rotation (§5.4). Style : palette et composants existants d'Orion.

Un clic mène à trois étapes dans le même panneau.

**1. Prérequis.** Une ligne par contrôle, verte ou rouge, avec l'action corrective
en un mot. Un bouton « Vérifier » rejoue le tout. Tant qu'une ligne est rouge, rien
n'est ouvert et l'étape suivante est désactivée.

| Contrôle | Comment |
| --- | --- |
| Tunnel connecté | état du moteur d'Orion |
| Administrateur du tunnel | `GET /api/certificates/operator/pending` ne répond pas `403` |
| Service Astra | la même lecture ne répond pas `503` |
| Coffre présent | `VaultOverview` |
| Deux clés enregistrées (rotations de CA) | `VaultOverview.slots`, `credentials_complete` |
| Domaine concordant | l'ancre du coffre et celle de `CertificateDomainView` sont les mêmes |

**Pas de contrôle « clé branchée ».** Sous Windows, la clé n'est interrogée qu'à
l'intérieur du dialogue WebAuthn, et les deux clés d'une rotation se branchent l'une
après l'autre : aucune des deux n'a à être présente avant le toucher. La première
maquette, qui montrait « Seconde clé absente », ne tient donc pas.

**2. Approbation.** Récapitulatif : action, motif (pré-rempli, modifiable), durées
par défaut. Les durées (préparation 7 jours, recouvrement 30 jours, validité CA TLS
1825 jours) sont repliées derrière « Modifier ». Le bouton « Approuver » ouvre alors
la campagne (§5.2), affiche le manifeste vérifié et enchaîne les touchers. **La
campagne s'ouvre à ce clic et non à l'étape 1**, parce qu'elle expire en cinq
minutes. L'empreinte de la CA-PQ entrante reste montrée, c'est le contrôle du §9.1.

**3. Suivi.** La liste des étapes franchies et de la suivante : signée, déposée,
installée sur la gateway, fin de recouvrement. Fermer Orion ne perd rien.

### 5.2 Ouverture

Orion appelle `POST /api/certificates/operator/campaigns` (route du 5a), avec
`requested_by` tiré du libellé de l'opérateur ; la porte y ajoute l'identité
WireGuard. Si une opération de la même famille est déjà ouverte (`AlreadyOpen`),
Orion la retrouve par `pending` et propose de la reprendre au lieu d'afficher une
erreur. Les refus du tunnel sont des classes : Orion les traduit en libellés courts.

### 5.3 Cérémonies

Portées dans `apps/orion/src-tauri/src/operator/ceremony/`, sur le modèle de
`issuer.rs` et `vault.rs`, avec `rotate_ca_pq` et `rotate_ca_tls`
d'`astra_operator::signing`. Les règles d'`astra-signer`
(`tools/astra-signer/src/commands/ca_pq_rotation.rs`, `ca_tls_rotation.rs`) restent
la référence : deux clés distinctes, comparaison de la cible de campagne à l'ancre du
coffre avant toute clé, approbation prise avant que l'ancre ne bouge. Ce qui peut
être partagé avec `astra-signer` descend dans `astra-operator` plutôt que d'être
copié. **Terminer** réutilise `advance_ca_tls`, une clé, sans nouvelle autorisation.

`OPENABLE_SCOPES` et l'état du panneau *Approbations* restent cohérents : une
campagne `trust_authorities` ouverte ailleurs doit pouvoir être menée depuis Orion,
en choisissant ce qu'elle remplace.

### 5.4 Journal de rotation

La décision est écrite avant d'être annoncée, comme aujourd'hui, à côté du coffre
(`astra_operator::prepared`, journal CA-PQ). Ce journal doit désormais conserver la
transition elle-même jusqu'à ce que la gateway ait confirmé l'installation : sans
fichier `--out`, c'est la seule copie. Il porte quatre états, reprenables dans
l'ordre sans redemander de clé : signé, déposé auprès d'Astra, installé sur la
gateway, terminé. Le dépôt et l'installation sont idempotents : Astra traite un
résultat identique comme le même, la gateway répond `already_present`.

### 5.5 Installation sur la gateway

- **CA-PQ** : la route existe, `POST /api/certificates/ca-transition`.
- **CA TLS** : nouvelle route `POST /api/certificates/client-tls-ca-transition`, sur la
  surface administrateur, à côté de la précédente, avec le même handler
  (`GatewayIdentityHandler`), le même écrit sous le registre du démon et une vue
  équivalente à `AnchorDecisionView`. La commande `heliosd install-client-tls-ca`
  reste pour le démon arrêté. Orion ne fait pas confiance à l'objet qu'il a signé :
  c'est la gateway qui vérifie, comme par la commande.

Après installation, Orion relit `CertificateDomainView` : l'état affiché vient de la
gateway, pas de ce qu'Orion croit avoir fait.

### 5.6 Suivis du lot 5a

- **`pending` sous 128 Kio** : la liste ne porte plus que les 128 premiers caractères
  de `reason` et de `requested_by`, suivis de « … » s'ils sont coupés. Le texte complet
  reste celui du manifeste, seul lu avant le toucher. Un test à 64 opérations aux bornes
  du 5a prouve que la réponse tient dans `MAX_OPERATOR_ANSWER_BYTES`.
- **429** : Astra plein n'est plus un `500`. `TrustUpdateRefusal` gagne une variante
  répondue en `429`, relayée par `heliosd`, et Orion affiche « Trop d'opérations en
  attente ». Le journal d'`heliosd` cesse de parler de « relayed renewal » sur les routes
  opérateur.

### 5.7 Fin de recouvrement

« Terminer » apparaît en tête dès `not_after`, à l'ouverture de l'onglet. C'est le seul
rappel : Orion n'a pas d'ordonnanceur, donc une rotation dont la fin passe pendant
qu'Orion est fermé attend sa prochaine ouverture. Jusque-là, la gateway a avancé son
époque et le coffre émet encore sous l'ancienne : c'est la limite déjà documentée. Sans
la lever, l'écran doit la rendre visible : la ligne reste « À faire » tant que ce n'est
pas fait.

## 6. Sécurité

- **Ce qui s'ajoute** : une route d'installation CA TLS, derrière `require_admin` et le
  contrôle d'origine, qui n'accepte qu'un objet que la gateway vérifie elle-même sous sa
  `CA-PQ`.
- **Ce qui sort** : le lancement d'un binaire externe depuis Orion, son canal loopback et
  son jeton sur la ligne de commande.
- **Ce qui ne change pas** : fenêtre de cinq minutes, une opération vivante par famille,
  deux clés distinctes, manifeste vérifié sous la clé de service épinglée.
- **Sous Windows**, la cérémonie reste dans le processus non élevé de l'IHM, là où WebAuthn
  répond (lot 4).

## 7. Tests et recette

- **Rust** : chaque état du journal et sa reprise, y compris un arrêt entre chaque étape ;
  aucune clé redemandée à la reprise ; refus d'une seconde rotation ; route CA TLS (`403`,
  corps illisible, objet mal signé, idempotence) ; `pending` aux bornes ; 429 relayé.
- **IHM** (Vitest, comme `ApprovalsPanel.test.tsx`) : ordre des lignes, ligne à faire en tête,
  prérequis rouge bloquant et ouverture jamais appelée, `AlreadyOpen` repris, durées
  repliées, libellés.
- **Recette** : `MANUAL-TESTING`, section « G. Lot 5b » : renouveler les postes, remplacer
  chaque CA, couper Orion à chaque étape, terminer une rotation. Rien ne se valide en WSL : la
  cible et Windows sont requis, et le 5a n'a pas encore été joué sur cible.

## 8. Documentation

`RENOUVELLEMENT-CERTIFICATS.md` : Orion devient le chemin par défaut aux §2, §3, §9, les
commandes restant décrites comme recours. Amendement daté dans
`ROTATION-CERTIFICATS.md` et ADR-008. `ROADMAP.md`, `MANUAL-TESTING.md`. Vérifier la « limite
connue » du §3 (registre d'Astra resté sur l'ancre sortante), que le code semble avoir levée
avec `ca_rotation` : la corriger si elle est périmée.

## 9. Laissé au constructeur

- Le découpage des composants React et des commandes Tauri.
- Le format exact du journal étendu, avec une migration des fichiers existants.
- Le texte par défaut du motif et le libellé `requested_by`.
- Le choix de partager ou non les fonctions avec `astra-signer`, tant que rien n'est recopié.

*Choix du concepteur, à relire :* troncature de `pending` à 128 caractères plutôt qu'une
pagination ; ordre dépôt puis installation, repris d'aujourd'hui ; contrôles de prérequis du
§5.1 ; route CA TLS plutôt qu'une distribution par Astra ; maquette sans ligne « clé branchée ».
