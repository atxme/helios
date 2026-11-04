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
- **Validation des clés avant l'opération** : une clé après l'autre, avec l'état de chacune.
- **Re-délégation de l'émetteur dans le 5b** : plus aucun terminal après un remplacement de
  CA. Cette décision élargit la table de la porte (spec 5a §5.2).
- **Copie du coffre envoyée par Orion** : Astra garde son exigence, et sa copie suit chaque
  rotation.
- **Pas de réutilisation d'un objet signé** : une nouvelle campagne n'accepte pas une transition
  signée pour une campagne morte (§5.4).
- **Validation de ce document le 4 novembre 2026**, l'utilisateur laissant au concepteur le
  délai d'installation dépassé et le moment du recouvrement CA-PQ (§5.4, §5.8, §5.9).

## 3. Objectifs

1. L'onglet **Rotations** existant d'Astra (`AstraView.tsx`, `rotations`), dont le
   formulaire actuel disparaît, devient la liste du §5.1.
2. **Renouveler les postes** : ouvre `fleet_leafs` par le tunnel et enchaîne la
   cérémonie existante.
3. **Remplacer la CA-PQ** et **Remplacer la CA TLS** : ouvrent `trust_authorities`
   par le tunnel, jouent la cérémonie dans Orion, déposent le résultat et
   installent la transition sur la gateway sans fichier.
4. **Terminer la rotation CA TLS** : remplace `promote-ca-tls`.
5. **Reprise** d'une rotation interrompue (aujourd'hui `resume-rotation`) : sans clé dans la
   fenêtre de la campagne ; au-delà, une rotation qu'Astra n'a pas acceptée s'abandonne sans
   dommage et se recommence (§5.4).
6. Orion ne lance plus `astra-signer`. Sortent : `apps/orion/src-tauri/src/companion.rs`,
   `apps/orion/src-tauri/src/astra.rs`, `launch::spawn_astra_signer`, le mode caché
   `astra-signer orion`, `crates/astra-operator/src/orion.rs` et ce qui ne sert plus
   qu'à eux dans `aether::certificates::operator_ipc`.
7. Les deux suivis du 5a sur la route d'Orion (§5.6).
8. **Renouveler la délégation** de l'émetteur depuis Orion, sans fichier ni redémarrage
   (§5.8).
9. **Copie du coffre et document de credentials** envoyés par Orion, sans redémarrage (§5.9).

## 4. Non-objectifs et anti-objectifs

**Non-objectifs**
- La révocation d'un poste (5c).
- « Tout renouveler » et l'identité de la gateway : la table de la porte (spec 5a §5.2) les
  réserve à la console ou au 6b. Elle n'est élargie ici que pour §5.8 et §5.9.
- Une sauvegarde du coffre ailleurs que sur la gateway.
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
| Reprendre une rotation | visible si une rotation signée n'est pas allée au bout ; reprise seule à la connexion du tunnel | Reprendre |
| Renouveler les postes | nombre de postes, échéance la plus proche | Renouveler |
| Remplacer la CA-PQ | « 2 clés », ou date de fin d'une rotation en cours | Remplacer |
| Remplacer la CA TLS | expiration, « 2 clés », ou date de fin d'une rotation en cours | Remplacer |
| Renouveler la délégation | échéance ; « À faire » si elle expire bientôt ou ne suit plus la CA | Renouveler |

Une ligne à faire passe en premier et se distingue visuellement. Une action
impossible a son bouton désactivé et dit pourquoi en quelques mots. **Une seule rotation
de CA à la fois** : pendant le recouvrement de l'une, les deux boutons « Remplacer » sont
désactivés. Pendant un recouvrement CA-PQ, le coffre est déjà sous la nouvelle ancre alors
qu'Astra et la gateway vérifient sous l'ancienne : une transition CA TLS y serait refusée
après les touchers. Renouveler les postes reste possible. Les données viennent de `GET /api/certificates`
(`CertificateDomainView` : `peers[].not_after`, `client_tls_ca_transition_pending`,
`ca_retire_active_at`, `next_ca_fingerprint`…), du coffre local et du journal de
rotation (§5.4). Style : palette et composants existants d'Orion.

Un clic mène à ces étapes dans le même panneau.

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
| Copie du coffre (rotations de CA) | empreinte lue par la route du §5.9 ; « Absente » ou « Ancienne », bouton « Envoyer », sans clé |
| Domaine concordant | l'ancre du coffre est celle de `CertificateDomainView`, ou sa suivante (`next_ca_fingerprint`) pendant un recouvrement CA-PQ |

**2. Clés** (rotations de CA ; décidé par l'utilisateur le 4 novembre 2026). Chaque
clé est validée avant toute opération, l'une après l'autre, et l'écran montre l'état de
chacune :

- « Clé 1 : à valider », bouton « Valider » ; un toucher, puis « Clé 1 : validée » et le
  libellé de la clé dans le coffre ;
- « Clé 2 : à valider », de même. La même clé deux fois est refusée (`key_repeated`), une
  clé hors du coffre aussi (`key_not_enrolled`), et l'on peut réessayer.

La validation prouve que la clé ouvre le coffre (`prove_key_opens`, déjà utilisé par
« Vérifier une clé »). Aucune campagne n'existe encore : tant que les deux ne sont pas
validées, rien n'est ouvert. **Aucun toucher de plus au total, mais un changement de clé de
plus** : l'ouverture du coffre obtenue à la validation est gardée en mémoire jusqu'à la
signature, ce qui remplace le toucher d'ouverture de la cérémonie. Il reste un toucher
d'approbation par clé, qui ne peut pas être avancé puisqu'il porte sur le défi de la
campagne. Quatre touchers donc, comme aujourd'hui, mais la clé 1 doit revenir après la clé 2,
alors qu'`astra-signer` fait les deux gestes de chaque clé sans la débrancher. Ces ouvertures vivent dans le
processus de la cérémonie, effacées à son abandon, à son échec, à sa fin, ou après cinq
minutes sans suite ; `astra-signer` les garde déjà ainsi le temps de la seconde clé.

Une validation ne vaut que pour la cérémonie en cours. Renouveler les postes, Terminer et
Renouveler la délégation n'ont pas cette étape : le premier suit le nombre de clés de sa
campagne, les deux autres n'exigent qu'une clé.

**3. Approbation.** Récapitulatif : action, motif (pré-rempli, modifiable), durées
par défaut. Les durées (préparation 7 jours, recouvrement 30 jours, validité CA TLS
1825 jours) sont repliées derrière « Modifier ». Le bouton « Approuver » ouvre alors
la campagne (§5.2), affiche le manifeste vérifié et enchaîne les touchers d'approbation.
**La campagne s'ouvre à ce clic et non avant**, parce qu'elle expire en cinq minutes.
L'approbation accepte les clés validées **dans n'importe quel ordre**, pour que la clé 2,
encore branchée, réponde d'abord : sous Windows, WebAuthn répond avec la clé présente et
non celle que l'on attend (`ca_tls_rotation.rs`). Seuls les credentials validés sont proposés,
et la réponse est rapprochée de l'ouverture correspondante ; une autre clé est refusée. L'empreinte de la CA-PQ entrante reste montrée, c'est le contrôle du §9.1.

**4. Suivi.** La liste des étapes franchies et de la suivante : signée, déposée,
installée sur la gateway, fin de recouvrement, avec la date limite d'installation tant
qu'elle n'est pas faite. Fermer Orion ne perd rien, dans les limites du §5.4.

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

La décision est écrite avant d'être annoncée, à côté du coffre (`astra_operator::prepared`,
journal CA-PQ). `astra-signer` dépose la CA-PQ avant d'écrire, et déplace le coffre CA TLS avant de
déposer : Orion ne reproduit ni l'un ni l'autre, et suit la même règle pour les deux CA.

**Le coffre en place ne bouge qu'après l'acceptation d'Astra.** Le journal porte le coffre suivant,
scellé comme tout coffre, les credentials, le relais, la transition et le résultat à déposer.
Aucune clé privée n'y est en clair. La transition y reste jusqu'à ce que la gateway confirme
l'installation : sans fichier `--out`, c'est la seule copie.

| État | Reprise | Clé ? |
| --- | --- | --- |
| Signé, campagne vivante | rejoue le même dépôt ; Astra traite un résultat identique comme le même | non |
| Signé, campagne morte | lit Astra (`operator/status`, §5.9) ; voir ci-dessous | non |
| Accepté | applique le coffre, les credentials et le relais, chaque écriture étant atomique et rejouable | non |
| Appliqué | installe sur la gateway, qui répond `already_present` au rejeu | non |
| Installé | envoie la copie du coffre (§5.9), puis attend la fin de recouvrement | non |

**Campagne morte** (au-delà des cinq minutes, ou Astra redémarré, ce qui perd l'opération). Un
accord signé pour une campagne n'en sert pas une autre : Orion ne le redépose pas. Astra dit si la
transition du journal est celle qu'il a acceptée, ce qui couvre une réponse perdue.
- **Acceptée** : la reprise continue, sans clé.
- **Aucune transition en cours** : rien n'a été annoncé. Le journal est effacé, le coffre n'a pas
  bougé, et l'écran affiche « Rotation expirée. Recommencer ». Il faut refaire les quatre touchers ;
  rien n'est perdu.
- **Une autre transition en cours** : refus, sans rien effacer. Le domaine se contredit, et ce n'est
  pas à Orion de choisir.

**Installation, sept jours par défaut.** La gateway refuse une transition une fois `activation_at`
passé, et le coffre ne peut plus en signer une autre : la clé sortante n'y est plus. **Ce cas n'a
pas de réparation aujourd'hui**, et ce lot n'en construit pas. Il est donc évité le plus possible :
- Orion installe aussitôt après l'acceptation, par le tunnel qui vient de servir au dépôt ;
- **la reprise est automatique** dès que le tunnel est monté, sans bouton ni clé ;
- le suivi affiche la date limite, et « Modifier » n'accepte pas moins d'un jour de préparation ;
- aucune rotation ne s'ouvre si la gateway a déjà une transition de même nature en cours.

S'il survient malgré tout, l'écran affiche un état bloquant « Délai dépassé » : la date de coupure
(`not_after`, où Astra avance seul et la gateway reste sur l'ancienne ancre) et « Intervention
manuelle requise ». `RENOUVELLEMENT-CERTIFICATS.md` le dit comme limite connue, et `ROADMAP.md`
ouvre le suivi d'une réparation.

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

### 5.8 Délégation de l'émetteur

Après un remplacement de CA, les époques portées par la délégation ne suivent plus celles de
la gateway, et Astra ne peut plus émettre pour les postes (`RENOUVELLEMENT-CERTIFICATS.md` §9).
La ligne « Renouveler la délégation » remplace la commande et son fichier.

- **Ouverture** : `DoorRequest::IssuerDelegation` passe à `(true, true)` dans `allowed`. La porte
  génère les clés dans le volume et renvoie la demande publique, qu'Orion reçoit dans la réponse
  au lieu d'un fichier choisi. `IssuerRequest` et `IssuerInstall` restent à la console. Les
  gardes existantes tiennent : verrou d'écriture, une délégation vivante à la fois, époque suivante.
- **Cérémonie** : `ceremony/issuer.rs` existe déjà ; une clé approuve puis ouvre le coffre.
  Seule l'entrée change.
- **Sans redémarrage** : Astra adopte la délégation à son enregistrement. `service.issuer` devient
  remplaçable en place et le contrôle de `load_issuer` (clés contre délégation, politique) est
  réutilisé. **Orion ne redémarre pas Astra** : Astra n'a pas accès à Docker (ADR-008), et sortir du
  processus perdrait les opérations en mémoire. Si l'adoption échoue, l'émetteur en place reste
  servi et Orion l'affiche.
- **Moment** : Orion compare les époques CA de la délégation (`operator/status`) à celles de la
  gateway. La ligne est « À faire » si elles diffèrent et que le coffre est au même niveau que la
  gateway : à partir de `not_after` pour la CA-PQ, et après « Terminer » pour la CA TLS. Pendant
  un recouvrement, le coffre a une époque d'avance : une délégation signée alors serait refusée,
  donc le bouton est désactivé et dit pourquoi.
- **Limite visible** : de `not_after` à la re-délégation, l'émission en ligne est refusée. Rien ne
  prévient hors d'Orion, comme au §5.7 ; les feuilles déjà émises restent valides jusqu'à leur
  échéance.

### 5.9 Copie du coffre et document de credentials

Astra exige toujours une copie du coffre pour ouvrir une rotation (`DoorRefusal::NoVault`). Elle
sert aussi de sauvegarde hors du poste. Astra la lit au démarrage, comme le document de credentials.

- **Lecture** : `GET /api/certificates/operator/status`, administrateur, sans secret : empreinte
  de la copie, époque du document de credentials, époque, échéance et époques CA de la délégation.
  Elle alimente le prérequis du §5.1 et la ligne du §5.8.
- **Écriture** : `POST /api/certificates/operator/vault-copy`, administrateur, nouvelle variante
  de porte `(false, true)` : la console garde sa procédure. Elle écrit sous le verrou du volume, de
  façon atomique, garde la copie précédente, remplace la valeur en mémoire et journalise l'empreinte
  et l'opérateur. Corps borné. Le coffre reste chiffré : ni Astra ni le tunnel ne l'ouvrent.
- **Contrôles** : Astra refuse un contenu qui n'est pas un coffre de ce domaine, dans la mesure où
  il peut le lire sans clé. Un administrateur du tunnel peut donc remplacer la sauvegarde, mais pas
  ouvrir le coffre ni signer. La copie précédente et le journal limitent ce risque ; il n'est pas
  supprimé. Orion relit l'empreinte après l'envoi.
- **Moment** : au prérequis si elle manque ou diffère, puis après chaque rotation, comme dernière
  étape du suivi. Un échec ne remet pas la rotation en cause : la ligne reste « À faire ».
- **Document de credentials** : deux moments distincts.
  - **Rotation CA-PQ** : le nouveau document est signé sous la nouvelle ancre, et Astra le tient déjà
    dans l'objet accepté. Astra l'adopte lui-même à `not_after`, dans la passe qui promeut l'ancre
    (`forget_expired_transitions`), et le rend durable. Orion ne l'envoie pas pendant le recouvrement.
  - **Clé ajoutée, retirée ou marquée perdue** : Orion l'envoie avec la copie du coffre, et Astra
    l'adopte en mémoire. Aucun terminal, mais hors recouvrement seulement.
- **Renouveler les postes pendant un recouvrement CA-PQ** : le §5.1 l'autorise tant qu'un test de
  bout en bout le confirme. Astra vérifie alors sous l'ancien document, Orion sous le nouveau. Si le
  test échoue, le bouton est désactivé pendant le recouvrement, et cette limite est affichée.

## 6. Sécurité

- **Ce qui s'ajoute** : une route d'installation CA TLS, derrière `require_admin` et le
  contrôle d'origine, qui n'accepte qu'un objet que la gateway vérifie elle-même sous sa
  `CA-PQ`.
- **Ce qui s'élargit (décision de l'utilisateur)** : le tunnel peut ouvrir une délégation, ce qui
  fait générer des clés dans le volume sans rien autoriser sans toucher ; il peut aussi écrire la
  copie du coffre, sans rien pouvoir ouvrir ni signer. Le coffre traverse le tunnel, chiffré.
- **Ce qui change d'exploitation** : Astra se met à jour sans redémarrage pour la délégation, la
  copie et le document de credentials.
- **Limite non levée** : un délai d'installation dépassé n'a pas de réparation (§5.4).
- **Ce qui sort** : le lancement d'un binaire externe depuis Orion, son canal loopback et
  son jeton sur la ligne de commande.
- **Ce qui ne change pas** : fenêtre de cinq minutes, une opération vivante par famille,
  deux clés distinctes, manifeste vérifié sous la clé de service épinglée.
- **Ce qui change de place** : l'ouverture du coffre est faite avant l'ouverture de la campagne,
  et non pendant. Elle reste en mémoire, jamais dans la WebView, et ne signe rien sans l'approbation.
- **Sous Windows**, la cérémonie reste dans le processus non élevé de l'IHM, là où WebAuthn
  répond (lot 4).

## 7. Tests et recette

- **Rust** : une clé validée n'est pas redemandée pour ouvrir le coffre, ouverture effacée à
  l'abandon ; approbation dans les deux ordres, clé non validée refusée ; campagne morte dans les trois
  cas (acceptée, aucune, autre), coffre intact après abandon, réponse perdue ; reprise automatique ;
  date d'installation passée ; adoption du document de credentials à `not_after`, ligne de
  délégation selon les époques ; renouvellement des postes pendant un recouvrement CA-PQ ; chaque état du journal et sa reprise, y compris un arrêt entre chaque étape ;
  aucune clé redemandée à la reprise ; refus d'une seconde rotation ; route CA TLS (`403`,
  corps illisible, objet mal signé, idempotence) ; table de la porte aux nouvelles entrées ; une
  émission sous la nouvelle délégation sans redémarrage, échec d'adoption, délégation vivante ;
  copie du coffre (`403`, trop gros, autre domaine, écriture atomique, copie précédente gardée,
  disponible aussitôt pour la porte) ; `pending` aux bornes ; 429 relayé.
- **IHM** (Vitest, comme `ApprovalsPanel.test.tsx`) : ordre des lignes, ligne à faire en tête,
  prérequis rouge bloquant et ouverture jamais appelée, copie du coffre absente puis envoyée,
  ligne de délégation et ses états, clés validées une à une avec leur état,
  clé répétée refusée, `AlreadyOpen` repris, durées
  repliées, libellés.
- **Recette** : `MANUAL-TESTING`, section « G. Lot 5b » : renouveler les postes, remplacer
  chaque CA, couper Orion à chaque étape, terminer une rotation, renouveler la délégation puis
  un poste, partir d'une gateway sans copie du coffre. Rien ne se valide en WSL : la
  cible et Windows sont requis, et le 5a n'a pas encore été joué sur cible.

## 8. Documentation

`RENOUVELLEMENT-CERTIFICATS.md` : Orion devient le chemin par défaut aux §2, §3, §9, les
commandes restant décrites comme recours. Amendement daté dans
`specification/ROTATION-CERTIFICATS.md`, ADR-008 (tunnel, délégation, copie du coffre, adoption sans
redémarrage) et la spec 5a §5.2. `DEPLOIEMENT-ASTRA.md` : la copie par Orion devient le chemin par
défaut, les commandes restent en recours. `ROADMAP.md`, `MANUAL-TESTING.md`. Vérifier la « limite
connue » du §3 (registre d'Astra resté sur l'ancre sortante), que le code semble avoir levée
avec `ca_rotation` : la corriger si elle est périmée.

## 9. Laissé au constructeur

- Le découpage des composants React et des commandes Tauri.
- Le format exact du journal étendu, avec une migration des fichiers existants.
- Le texte par défaut du motif et le libellé `requested_by`.
- Le choix de partager ou non les fonctions avec `astra-signer`, tant que rien n'est recopié.

*Choix du concepteur, à relire :* troncature de `pending` à 128 caractères plutôt qu'une
pagination ; ordre dépôt puis installation, repris d'aujourd'hui ; contrôles de prérequis du
§5.1 ; route CA TLS plutôt qu'une distribution par Astra ; ouverture du coffre gardée en mémoire
entre validation et signature pour ne pas ajouter de toucher ; approbation dans n'importe quel
ordre ; une seule rotation de CA à la fois ; coffre appliqué seulement après l'acceptation d'Astra,
pour les deux CA ; abandon d'une rotation non acceptée ; reprise automatique à la connexion du
tunnel ; minimum d'un jour de préparation ; moment de la délégation par comparaison des époques ;
adoption du document de credentials par Astra à `not_after` ; « Délai dépassé » sans abandon construit dans ce lot ; adoption en mémoire plutôt
qu'un redémarrage par Orion ; route de lecture unique `operator/status` ; copie précédente gardée
sur la gateway, sans historique plus long ; document de credentials envoyé avec le coffre après
un changement de clé.
