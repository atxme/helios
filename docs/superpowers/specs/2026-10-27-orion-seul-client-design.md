# F14 — Orion seul binaire client : absorption d'`astra-signer` — conception

Date : 27 octobre 2026. Feuille de route : F14 (après F11, D10). Sources : ADR-008,
`tools/astra-signer/src/cli.rs`, `crates/astra-operator`, spec d'enrôlement v5
(`2026-10-19-enrolement-v5-design.md`), spec F11
(`2026-10-24-separation-privileges-windows-design.md`).

## 1. Pourquoi

Règle posée le 24 octobre 2026 et confirmée le 27 : **côté poste, aucun binaire
livré à part d'Orion**. Aujourd'hui, la personne qui administre Helios est à la
fois l'administrateur de la gateway, l'opérateur qui tient la YubiKey et le
coffre d'autorité, et l'utilisateur du VPN, sur le même PC Windows (compte
administrateur). Pour enrôler un poste, elle enchaîne une CLI `astra-signer`,
une CLI `helios enroll document`, une ligne `heliosd peer add` à taper sur la
gateway et des fichiers à déplacer à la main. Elle ne se souvient plus du
parcours : c'est le signe qu'il ne tient pas sans documentation sous les yeux.

F11 a rendu l'absorption possible : l'IHM d'Orion n'est plus élevée, elle est au
niveau d'intégrité où WebAuthn répond, et elle mène déjà deux cérémonies
opérateur (récupération d'identité, approbation de campagne).

**Succès** : tout ce que fait `astra-signer` se fait depuis Orion, à l'écran, et
`astra-signer` n'est plus construit ni livré. L'enrôlement d'un poste se résume
à trois fichiers échangés et à des boutons.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**
- Chaque commande d'`astra-signer` (liste §5) a son geste dans Orion, onglet
  **Astra**.
- L'enrôlement v5 côté opérateur se fait en deux gestes : « Inviter un poste »,
  puis « Accepter une demande », qui enchaîne vérification, consommation de
  l'invitation, émission des deux feuilles, **admission du pair sur la gateway
  par l'API dans le tunnel**, assemblage et signature du document `.orion`.
- Orion ne lance plus aucun programme opérateur extérieur : le lancement
  d'`astra-signer` pour l'approbation de renouvellement (`companion.rs`,
  `launch::spawn_astra_signer`, commande moteur `CompanionArguments`) disparaît.
- `tools/astra-signer` est retiré du workspace, de l'empaquetage et des docs à la
  fin.

**Non-objectifs**
- `helios` (outil d'administration de la gateway) et `heliosd` restent tels
  quels, sauf `helios enroll document`, voir §6.
- Aucun nouveau canal de transport des fichiers entre machines : invitation,
  demande et document passent comme aujourd'hui (clé USB, messagerie,
  presse-papiers).
- Aucune nouvelle route d'API côté gateway : Orion utilise les routes
  d'administration existantes.
- Pas de migration du coffre opérateur ni du registre des invitations : ils
  restent où `astra-signer` les écrit (§4), pour que le domaine existant
  continue de fonctionner tel quel.
- Postes sans droits d'administration : prévus plus tard, hors F14.

**Anti-objectifs** (ce qui ferait échouer F14 même si tout « marche »)
- Un secret opérateur (PIN, secret de key-slot, clé `CA-PQ`, octets du coffre,
  assertion) qui atteint la WebView, un journal, ou le moteur élevé.
- Le moteur élevé qui ouvre le coffre opérateur ou dépend d'`astra-operator`
  (ADR-008 : « Le moteur n'y participe pas »).
- Une WebView qui choisit ce qui est signé : comme aujourd'hui
  (`OperationLocator`), elle ne nomme qu'un genre d'opération, un identifiant
  opaque ou un fichier choisi par la personne ; la cérémonie relit et vérifie
  le reste depuis le coffre et le relais épinglé.
- Un geste qui contourne l'ordre normatif de l'enrôlement (§15.2 : consommer
  l'invitation **avant** d'émettre) pour aller plus vite.
- Un double chemin durable (Orion **et** `astra-signer`) : la CLI ne reste que le
  temps de la transition, jamais livrée à côté d'un Orion qui fait déjà le geste.

## 3. Ce qui existe et sert de base

- **`crates/astra-operator`** porte déjà toute la logique : coffre
  (`AuthorityVault`), gestes (`gestures`), registre des invitations
  (`InvitationRegistry`), relais du domaine (`DomainHandoff`), campagnes,
  récupération, rotations, signatures. `astra-signer` n'en est qu'une coque CLI
  (~1 200 lignes de `cli.rs`/`main.rs`, ~3 300 lignes de `commands/`).
- **L'IHM d'Orion** (`apps/orion/src-tauri/src/operator/`) mène des cérémonies
  dans un fil de l'IHM, publie des états typés (`operator_session` :
  `OperatorStatus`, `RemoteState`, `GestureState`, `Refusal`), rattache le
  dialogue WebAuthn à la fenêtre Orion. `OperationKind` liste six genres ; deux
  sont servis (`RecoverIdentity`, `ApproveCampaign`).
- **L'onglet Astra** (`apps/orion/src/views/AstraView.tsx`) porte déjà les
  rotations et campagnes, avec un champ chemin du coffre.
- **Côté client**, l'enrôlement v5 est complet (import d'invitation, demande
  scellée, demandes en attente, import du document).
- **L'API Helios** répond dans le tunnel (`http://100.64.0.1:8080`) et accepte
  les routes d'administration d'un pair portant le drapeau `admin`
  (`crates/helios-api/src/auth.rs`).

## 4. Décisions

1. **Emplacement dans l'IHM** : l'onglet **Astra** devient l'espace opérateur.
   Le rail ne change pas. Sous-onglets : *Enrôlement*, *Coffre et clés*,
   *Domaine*, *Approbations*, *Rotations*, *Gateways*. Maquettes validées le
   27 octobre (`.superpowers/brainstorm/…/enrolement.html`) ; **la direction
   artistique actuelle d'Orion est conservée** (composants MUI existants,
   palette `theme.ts`, typographie et espacements des vues actuelles).
2. **Processus** : tout geste opérateur vit dans l'IHM non élevée, comme les
   cérémonies actuelles (partition F11 : « coffre maître opérateur → IHM »).
   Le moteur n'apprend rien de nouveau, hormis la suppression de
   `CompanionArguments`.
3. **Coffre et registre** : chemins inchangés, ceux d'`astra-operator`
   (`store::default_path()` : `%APPDATA%\astra\authority-vault.json` sous
   Windows, `~/.helios/astra/authority-vault.json` ailleurs ; registre
   `%APPDATA%\helios\enrollment-invitations`, `~/.helios/enrollment-invitations`,
   ou `$HELIOS_ENROLLMENT_REGISTRY`). Le champ « chemin du coffre » de l'onglet
   Astra est prérempli avec ce chemin ; le changer reste possible (coffre
   sauvegardé ailleurs, clé USB).
4. **Admission du pair** : « Accepter une demande » admet le pair par l'API
   dans le tunnel, avec les deux feuilles publiques, comme
   `heliosd peer add --certificate --pq-certificate` ; jamais avec le drapeau
   `admin`. Si l'API n'est pas joignable ou refuse (pas de tunnel, pair non
   `admin`), le geste s'arrête **après** l'émission des feuilles, les écrit à
   côté de la demande comme aujourd'hui, le dit en clair, **affiche la ligne
   `heliosd peer add …` prête à coller sur la gateway** (décision du 27 octobre :
   `heliosd` reste l'outil de la gateway), et la reprise (admission, document)
   se fait depuis la ligne de l'invitation consommée. Le cas normal suppose que
   le pair du PC opérateur porte le drapeau `admin` et que son tunnel est actif ;
   ce n'est pas vérifiable dans le dépôt et la recette du lot 2 le constate.
5. **Assemblage du document** : ce que fait `helios enroll document` (lecture
   de la gateway, contrôle que les feuilles certifient les clés de la demande,
   brouillon public) passe dans une bibliothèque appelée par Orion ; le binaire
   `tools/helios` n'est pas une dépendance d'Orion.
6. **Ordre de livraison** : par lots (§7), chacun livrable et testable seul,
   chacun avec son plan. Le premier plan couvre les lots 1 et 2 en détail ; les
   lots 3 à 7 n'y figurent qu'en esquisse.
7. **Retrait d'`astra-signer`** : au dernier lot seulement, quand chaque
   commande a son geste. Jusque-là il reste construit pour ne rien casser, mais
   la doc de chaque geste livré renvoie à Orion.
8. **Corps de l'admission** : exactement la `PeerAdmitRequest` de
   `crates/helios-api/src/routes/peers.rs` que produit aujourd'hui la ligne
   `heliosd peer add` imprimée par `enroll accept` : `name` = nom demandé,
   `public_key` = `client_wg_public_key` de la demande, `admin = false`, les deux
   feuilles émises (`key_negotiation_certificate`,
   `key_negotiation_pq_certificate`). La demande `.helios-request`
   (`EnrollmentRequest`) porte déjà le nom et la clé WireGuard : aucun format ne
   change.
9. **Adresse de la gateway** (choix du contrôleur) : l'admission et
   l'assemblage du document appellent l'`heliosd_url` du profil **connecté** au
   moment du geste, lu côté Rust depuis l'état du moteur, jamais une URL
   fournie par la WebView. Pas de profil connecté, ou profil sans
   `heliosd_url` : le geste s'arrête après les feuilles (§4.4). Le champ libre
   `heliosd_url` des rotations actuelles reste tel quel jusqu'au lot 5, qui le
   remplace de la même façon.
10. **Cérémonie d'acceptation** (choix du contrôleur) : « Inviter » et
    « Accepter » sont deux nouveaux genres de la liste fermée de l'IHM. Le
    fichier de demande est lu par la WebView, qui en envoie le contenu (public) au
    geste : aucun chemin ne passe de la WebView à Rust (correction du
    27 octobre 2026, passe finale). Une acceptation est **une** session et
    **un** toucher : le coffre, ouvert après la consommation, sert à émettre
    les deux feuilles puis à signer le document, et se referme à la fin de la
    session. « Annuler » est possible jusqu'à la consommation ; après, le geste
    va au bout ou s'arrête sur une erreur rapportée comme telle.
11. **Reprise** (choix du contrôleur) : l'état « feuilles émises » est celui
    qu'`InvitationRegistry::record_issued` enregistre déjà. L'état « pair
    admis » se lit sur la gateway (liste des pairs) au moment d'afficher. Les
    feuilles émises sont réécrites à côté de la demande et relues pour la
    reprise ; elles ne sont jamais réémises. Si un champ doit s'ajouter à
    l'enregistrement d'une invitation, il est facultatif avec une valeur par
    défaut, lisible par l'ancien format : ce n'est pas une migration.
12. **Accès concurrents** (choix du contrôleur) : Orion et `astra-signer` ne sont
    pas prévus pour tourner en même temps sur le même coffre. La consommation
    d'une invitation reste le renommage atomique de son fichier ; la doc de
    transition le dit.

## 5. Correspondance des commandes

| `astra-signer` | Geste Orion (onglet Astra) | Lot |
|---|---|---|
| `verify`, `list` | *Coffre et clés* : état du coffre, table des key-slots, « Vérifier une clé » | 1 |
| `devices` | *Coffre et clés* : diagnostic des clés FIDO2 visibles, si la lecture HID est possible sans élévation ; sinon message qui l'explique | 1 |
| `domain` (lecture) | *Domaine* : relais public affiché | 1 |
| `enroll invite` | *Enrôlement* : « Inviter un poste… » | 2 |
| `enroll accept` + `helios enroll document` + `heliosd peer add` + `enroll sign-document` | *Enrôlement* : « Accepter une demande… », un geste (§4.4, §4.5) | 2 |
| `enroll list`, `enroll revoke` | *Enrôlement* : liste des invitations, « Révoquer » | 2 |
| `init` | *Coffre et clés* : « Créer un domaine » (premier démarrage opérateur) | 3 |
| `enrol`, `remove`, `rename` | *Coffre et clés* : ajouter, retirer (jamais la dernière récupération), renommer une clé | 3 |
| `bindings` | *Coffre et clés* : marquer une clé perdue / active, réémettre le document de credentials | 3 |
| `domain` (écriture), `issue-ca-tls` | *Domaine* : réécrire le relais, émettre `CA-TLS` client | 3 |
| `approve` | *Approbations* : renouvellement client, dans l'IHM (supprime `companion.rs`) | 4 |
| `approve-campaign`, `recover` | *Approbations* : déjà servis par la cérémonie de l'IHM ; compléter le mode hors ligne (fichier) | 4 |
| `authorize-issuer` | *Approbations* : délégation de l'émetteur | 4 |
| `rotate-ca-pq`, `rotate-ca-tls`, `resume-rotation`, `promote-ca-tls` | *Rotations* | 5 |
| `revoke` | *Rotations* (ou *Approbations*) : révocation d'urgence | 5 |
| `issue-gateway-bootstrap`, `sign-gateway-transition`, `sign-gateway-rollback`, `abort-gateway-transition` | *Gateways* | 6 |
| `orion` (mode compagnon caché) | disparaît | 4 |
| — | Retrait d'`astra-signer`, de `helios enroll document`, de l'empaquetage et des docs | 7 |

## 6. L'enrôlement côté opérateur (lot 2)

**Inviter un poste** — saisie : nom du poste, durée (24 h par défaut et au
plus), « autoriser la réadmission » (exige deux clés distinctes). La gateway et
sa feuille PQ viennent du relais du domaine, pas d'une saisie. Toucher de la
YubiKey, signature sous `CA-PQ`, enregistrement de `<nom>.helios-invite` par la
boîte de dialogue d'enregistrement, affichage de l'empreinte `CA-PQ` en groupes
lisibles à communiquer hors bande.

**Accepter une demande** — la personne choisit un `.helios-request`. Les étapes
s'affichent en liste et s'enchaînent sans autre action que le toucher :
1. vérification de la demande dans l'ordre normatif du §15.2 ;
2. consommation de l'invitation, destruction de la clé X25519, synchronisation
   du registre ;
3. toucher de la YubiKey, émission de la feuille PQ sous `CA-PQ` et de la
   feuille TLS sous `CA-TLS` cliente ;
4. admission du pair par l'API dans le tunnel (§4.4) ;
5. assemblage du brouillon depuis la gateway, contrôles de `sign-document`,
   signature JCS ;
6. enregistrement de `<nom>.orion`.

Un échec après l'étape 2 est rapporté comme tel (l'invitation est consommée) ;
un échec à l'étape 4 ou 5 laisse les feuilles écrites et une reprise possible
depuis la liste.

**Invitations** — liste avec nom, état (émise, consommée, expirée, révoquée),
échéance, et pour une consommée l'état de la suite (feuilles émises, pair admis,
document signé). « Révoquer » sur une invitation émise. La purge des expirées
reste celle d'`InvitationRegistry`.

**`helios enroll document`** (mon choix, à confirmer) : retiré au lot 7 avec
`astra-signer`, puisqu'Orion le remplace et qu'il ne sert que sur le poste.

## 7. Lots

1. **Socle opérateur** : sous-onglets de l'onglet Astra ; résolution du chemin
   du coffre (§4.3) ; ouverture du coffre par la cérémonie de l'IHM ; lecture
   du relais ; état du coffre et des key-slots ; « Vérifier une clé ».
2. **Enrôlement v5** (§6).
3. **Coffre, credentials et domaine** : `init`, `enrol`, `remove`, `rename`,
   `bindings`, `domain`, `issue-ca-tls`.
4. **Approbations** : `approve` dans l'IHM, suppression de `companion.rs`, de
   `launch::spawn_astra_signer`, de `CompanionArguments` et du mode `orion` ;
   `authorize-issuer` ; mode hors ligne de `approve-campaign` et `recover`.
5. **Rotations et révocation**.
6. **Gateways**.
7. **Retrait** : `tools/astra-signer`, `helios enroll document`, empaquetage,
   xtask, docs (ADR-008, OPERATOR-TOOLING, MANUAL-TESTING, ROADMAP, README).

## 8. Erreurs et sécurité

- Tout message d'erreur montré à la personne est en français et nomme la cause ;
  aucun ne contient de secret. Les refus de la cérémonie restent la classe
  fermée `Refusal`.
- Les genres d'opération servis restent une liste fermée côté IHM : chaque lot
  ajoute ses genres à `OperationKind` (ou à une liste parallèle si un geste
  n'est pas une opération Astra), jamais un genre générique.
- Les fichiers lus (demande, brouillon, feuilles) le sont par la WebView, depuis
  un fichier choisi par la personne, et leur contenu public est envoyé au geste ;
  les fichiers écrits, par la boîte d'enregistrement. Aucun chemin ne vient du
  réseau.
- L'API de la gateway est appelée sur l'adresse du tunnel lue dans le profil
  actif (`heliosd_url`), jamais sur une URL saisie librement pour l'admission.
- Les opérations à deux clés (réadmission, rotations, amorçage gateway)
  exigent deux credentials distincts, comme aujourd'hui.

## 9. Tests et validation

- Chaque geste a des tests sous Linux sur la logique (ordre des étapes, refus,
  reprise après échec), avec un authentificateur factice comme ceux
  d'`astra-operator` ; vitest pour chaque écran.
- Une recette Windows par lot dans MANUAL-TESTING : YubiKey réelle, WebAuthn
  dans l'IHM non élevée, gateway réelle pour l'admission. Le parcours
  d'enrôlement v5 de bout en bout (MANUAL-TESTING, « Enrôlement v5 de bout en
  bout ») est réécrit pour se jouer depuis Orion seul.
- Rien de ce qui n'a pas été constaté sous Windows n'est écrit comme acquis.

## 10. Laissé au constructeur

- Où vit l'assemblage du document (crate existant ou nouveau module), du moment
  qu'Orion ne dépend pas du binaire `tools/helios`.
- La forme exacte des écrans au sein de la direction artistique actuelle.
- Le découpage de chaque lot en tâches.

## 11. Amendements du 27 octobre 2026 (lots 1 et 2 réalisés)

Précisions issues de la réalisation ; elles priment sur le §6 là où elles
diffèrent. Validation sous Windows : à valider en recette.

- **Onglet par défaut** : « Enrôlement » ouvre l'onglet *Astra*. « Coffre et clés »
  montre l'état du coffre et « Vérifier une clé » (`verify_key`) ; « Domaine »
  montre le domaine ; « Gateways » n'est qu'un texte d'attente.
- **Étape 1 avant toute clé** : en plus des refus de la demande, si la gateway
  connectée répond, son identité (clé WireGuard, et `server_name` s'il est épinglé)
  est comparée à celle que l'invitation épingle ; une différence est refusée
  `HandoffMismatch` sans rien consommer. Injoignable : on continue et le geste
  s'arrête après les feuilles. L'identité est recomparée à l'admission.
- **Inviter** : la feuille PQ vient de la gateway connectée, ou d'un fichier si
  aucune gateway ne répond (et non « du relais » seul) ; elle est vérifiée sous
  `CA-PQ` contre le relais avant toute clé.
- **Admission** : `admin: false` et plancher ML-KEM. Sans gateway ou sur refus, le
  geste s'arrête après les feuilles ; les artefacts sont les deux feuilles et
  `admission.txt` (la ligne `heliosd peer add …`). Sinon le `.orion` est signé
  avec la même ouverture de clé.
- **Reprendre** : ne réémet jamais les feuilles, revérifie la gateway, saute
  l'admission d'un pair déjà admis, demande une clé. Est reprenable toute
  invitation dont l'acceptation est conservée ici (`<id>.accepted.json`) ; le
  registre ne sait pas si un document a déjà été produit, donc « Reprendre » sur
  une acceptation achevée ne fait que re-signer un document. Une acceptation faite
  par la CLI est refusée (`AcceptedElsewhere`).
- **Contrat** : la classe fermée `Refusal` gagne, sans texte, `InvitationUnknown`,
  `InvitationConsumed`, `InvitationExpired`, `CaTlsMissing`, `GatewayForbidden`,
  `GatewayRefused { status }`, `AcceptanceNotKept` et `AcceptedElsewhere` (la
  phrase française de chacune est dans l'IHM) ; `GatewayUnavailable` reste pour
  « injoignable ou aucune gateway ». `OperationKind` gagne `verify_key`,
  `invite_enrollment` et `accept_enrollment` (manifestes `key_check`,
  `invitation` et `enrollment_acceptance`). `OperatorArtifact` gagne `encoding`
  (`text` | `base64`) : la feuille `.der` est remise en base64 marqué, décodée
  par l'IHM avant l'écriture, pour que `heliosd peer add --certificate` lise le
  DER brut.
- **Passe finale (revue de branche)** : `Refusal` gagne encore, sans texte,
  `GatewayLeafUnavailable` (Inviter : aucune feuille PQ lisible, la gateway ne
  répond pas ou n'a pas de `heliosd_url`, et aucun fichier n'est fourni ; le
  champ « Feuille PQ de la gateway » est donc toujours proposé, facultatif quand
  une gateway est connectée) et `DocumentNotSigned` (le pair est admis, mais le
  document n'a pas pu être construit ou signé : toute défaillance après une
  admission réussie ; la phrase dit de reprendre l'invitation et ne renvoie
  jamais à `admission.txt`). `GatewayUnavailable` ne garde que les chemins qui
  ont réellement remis `admission.txt`. Accepter une invitation consommée hors
  d'Orion (aucun `.accepted.json`) est refusé `AcceptedElsewhere`, pas
  `InvitationConsumed`, puisqu'aucun « Reprendre » n'existe. Le manifeste
  d'acceptation montre `allowed_ips` et `ssh_target` quand ils figurent dans le
  document signé ; celui de l'invitation montre l'empreinte `CA-PQ` en groupes
  de quatre ; l'onglet « Approbations » porte une pastille de compte.
- **`orion_client`** : ne suit aucune redirection et ignore les proxys
  d'environnement (`no_proxy`), car le trafic d'administration doit rester dans
  le tunnel, vers l'adresse du profil et nulle autre.
- **Lecture du coffre** : une clé `CA-PQ` illisible rend une erreur (fail-closed),
  pas un domaine vide.
- **Réseau** : `orion_core::gateway_admin` (admission, lecture de la gateway) est
  appelé par le client d'Orion (10 s de connexion, 20 s au total) ; la cérémonie,
  sur un fil standard, passe par `tauri::async_runtime::block_on`, jamais depuis
  un fil du runtime. `Refused { status, reason }` borne la raison de la gateway
  (200 caractères, sans caractère de contrôle). L'assemblage du brouillon
  (`orion_core::enrollment_draft`) est partagé avec `helios enroll document`.
  `shell_word` et la ligne d'admission vivent dans `astra_operator::admission`.
- **`helios enroll document`** : reste construit et fonctionnel jusqu'au lot 7.
