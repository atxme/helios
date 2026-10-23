# Enrôlement v5 sans transport de clé privée — conception

**Date** : 2026-10-19, révisée le 2026-10-23
**Statut** : implémentée le 2026-10-23 (branche `feat/v5-enrolement`, plan
`docs/superpowers/plans/2026-10-23-enrolement-v5.md`) ; DPAPI réel, YubiKey et
parcours Windows complet non validés depuis WSL2
**Feuille de route** : F2
**Normes** : [NEGOCIATION-DE-CLE-V5 §15](../../specification/NEGOCIATION-DE-CLE-V5.md#15-enrôlement),
§19, §22 ; [ROTATION-CERTIFICATS §2.2, §13.1](../../specification/ROTATION-CERTIFICATS.md) ;
[ADR-008](../../adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md) §3, §4

Cette note dit comment implémenter le §15 dans le code existant. Formats,
octets signés et ordre des contrôles sont ceux du §15, auxquels elle renvoie
plutôt que de les recopier. Elle amende la spécification sur un seul point,
l'outil qui porte chaque geste (§5, §9), pour l'aligner sur ADR-008.

## 1. Pourquoi

`helios enroll` émet aujourd'hui sur le poste opérateur les trois clés
privées du client (WireGuard, TLS, ML-DSA-87) et les place dans le document
`.orion`. Ce document est donc un secret qui existe en clair sur deux
machines et sur le canal qui les relie ; sa protection repose sur une
consigne d'effacement. Le §15 exige l'inverse : les clés naissent sur le poste
Orion, dans son stockage protégé, et n'en sortent jamais ; l'opérateur
n'autorise qu'une demande précise, par une invitation signée à usage unique.

Le second gain est la confiance initiale. Aujourd'hui, le document apporte à
la fois l'ancre et ce qu'elle signe, et cette ancre n'est même pas `CA-PQ` :
c'est la CA cliente du répertoire `--client-ca-dir`, une clé ML-DSA dans un
fichier `0600` du poste opérateur. En v5, Orion épingle `CA-PQ` — l'ancre du
domaine, gardée dans le coffre d'autorité — à l'import de l'invitation, après
une confirmation hors bande bloquante, et vérifie ensuite le document sous
cette ancre déjà fiable (ROTATION-CERTIFICATS §2.2).

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**

- invitation signée par `CA-PQ`, ciblée, vivante 24 h au plus, à usage unique,
  et registre opérateur qui la consomme atomiquement avant toute émission ;
- clés WireGuard, TLS et ML-DSA-87 générées dans Orion et scellées avant
  qu'une demande ne sorte ;
- demande liée à l'invitation, avec trois preuves de possession, dont la
  preuve X25519 du §15.2 ;
- premières leafs émises par les ancres du domaine (`CA-PQ`, `CA-TLS`
  cliente) sur les clés publiques reçues ;
- document `.orion` sans aucun secret, signé par `CA-PQ` sur sa forme JCS,
  lié à la demande ;
- import Orion qui exige la demande locale en attente et retrouve les clés
  privées par leurs clés publiques, jamais par le nom.

**Non-objectifs**

- transport en ligne de l'invitation, de la demande ou du document : les trois
  circulent comme fichiers, par le canal que l'opérateur choisit. Aucun ne
  contient de secret (§15.2) ;
- enrôlement v5 d'une gateway **sans domaine de confiance** : il est refusé
  avec une erreur nommée qui renvoie vers `astra-signer init` et
  `heliosd init-trust-domain` (ROTATION-CERTIFICATS §13.1 fait du domaine le
  point de départ de toute installation neuve) ;
- retrait de la CA cliente fichier de la gateway
  (`/var/lib/helios/key-negotiation-client-ca.der` et sa moitié PQ) : elle
  reste acceptée pour les leafs de première génération déjà admises, et ne
  sert plus à enrôler. Son retrait suppose un audit du parc, hors de ce lot ;
- stockage protégé Linux : il reste refusé (F12). L'enrôlement complet ne
  s'exécute donc que sous Windows ;
- profils `classic` : ils gardent l'import WireGuard ordinaire, sans
  invitation (§15.1), et `helios profile emit`.

**Anti-objectifs** — ce qui serait un échec même si « ça marche »

- une clé privée cliente qui apparaît, même transitoirement, dans un fichier
  écrit par l'outillage opérateur ou par Orion hors du stockage protégé ;
- une CA rendue fiable par le document qu'elle signe, ou par un clic qui ne
  montre pas l'empreinte ;
- une invitation réutilisable après un échec, ou rouverte par une reprise ;
- un appariement document ↔ clés fait sur le nom du profil ;
- une signature `CA-PQ` produite hors d'`astra-operator`, ou une clé maîtresse
  qui transite par `tools/helios` ou par Orion ;
- un second chemin d'enrôlement conservé « pour compatibilité » qui émet
  encore des clés privées ou signe avec la CA fichier.

## 3. Ce qui existe et sert de base

| Brique | Où | Usage ici |
| --- | --- | --- |
| Coffre d'autorité, gestes FIDO2, signatures `CA-PQ` et `CA-TLS` | `astra-operator` (`gestures`, `signing/`, `vault`), CLI `astra-signer` | signature de l'invitation, émission des premières leafs, signature du document |
| Politique de credentials par portée | `gestures::require_scope_credentials`, `aether::certificates::status::CampaignScope` | une portée d'enrôlement (1 credential) et une de réadmission (2 credentials, ADR-008 §4) |
| Relais public du domaine | `astra-signer domain` | clé WireGuard gateway, nom de service, sans les faire retaper |
| Génération locale TLS + CSR + ML-DSA-87 | `orion-core::certificate_renewal::CandidateKeys`, `aether::certificates::x509::client_rotation_csr` | mêmes clés et même CSR pour la demande d'enrôlement |
| Stockage protégé DPAPI | `orion-core::identity_store` (`ProtectedIdentityStore`, `seal`/`unseal`) | scellement de la demande en attente puis de l'identité finale |
| Clé WireGuard générée sur le poste | `staged_key` de `apps/orion/src-tauri/src/commands/profiles.rs`, `aether::wg::generate_keypair` | remplacée par la clé de la demande scellée (le slot en mémoire ne survit pas au délai d'un enrôlement) |
| Signatures ML-DSA-87 à `ctx` | `aether::ml_dsa` | invitation, demande, document ; `ctx` = domaine ASCII du §15.3 |
| Aléa | `aether::random` | `invitation_id`, `request_id`, clé X25519 éphémère |
| Admission | `helios_provisioning::admit_with_key_negotiation`, API ou `heliosd peer add` (file d'admission du registre déjà gérée) | inchangée |
| Bloc de confiance | `heliosd show-trust-enrolment`, `api::trust_enrolment` | inchangé, posé dans le document |
| Rendu du profil | `tools/helios/src/profile.rs` | brouillon public du document, sans identité |
| Import Orion en brouillon | `parse_profile_import`, `complete_profile_import`, `finish_import` | étendu au document v5 |

La gateway n'a rien à changer pour accepter ces leafs : son jeu d'ancres mTLS
ajoute déjà `client_tls_anchors` du registre à la CA fichier, et
`client_leaf_issuers` contient déjà les ancres `CA-PQ` du domaine
(`crates/heliosd/src/key_negotiation/server.rs`,
`crates/helios-provisioning/src/certificates.rs`).

## 4. Objets et où ils vivent

Les trois types publics et leurs transcriptions vont dans un nouveau module
`aether::key_negotiation::enrollment`, partagé par `astra-operator`,
`tools/helios` et `orion-core`. Le nom évite `aether::enroll`, qui désigne
l'ancien provisionnement dans le tunnel.

- `EnrollmentInvitation` : champs et octets signés du §15.2/§15.3,
  `verify(ca_public_key, now)`, `fingerprint()`.
- `EnrollmentRequest` : champs et octets auto-signés du §15.3,
  `wireguard_proof` du §15.2, `verify(invitation, now)` qui contrôle la
  liaison et l'auto-signature (la preuve WireGuard se vérifie côté opérateur,
  seul détenteur de la clé X25519 éphémère).
- `EnrollmentDocument` (`.orion` v5) : schéma fermé du §15.3,
  `deny_unknown_fields`, champs dupliqués refusés, signature opérateur sur la
  forme JCS de l'objet sans le champ `operator_signature`.
- `wireguard_proof(client_wg_private, proof_public, …)` et sa vérification en
  temps constant ; refus d'un secret X25519 tout nul des deux côtés.

**JCS** : `serde_json_canonicalizer = "0.3.2"`, décision du 2026-10-23,
déclarée dans les dépendances de l'espace de travail et employée seulement par
`aether`. La 0.4.1 n'est pas retenue : publiée le 2026-10-13, le même jour
que le retrait de la 0.4.0. La caisse active la fonctionnalité
`float_roundtrip` de `serde_json` et tire `ryu-js` ; l'unification des
fonctionnalités l'étend à tout l'espace de travail, ce qui ne change que la
précision de lecture des flottants. Le schéma du document ne contient aucun
flottant et les refuse : la canonicalisation des nombres de la RFC 8785 n'est
donc jamais sollicitée sur un nombre non entier.

Forme sur disque, par décision de cette note : JSON UTF-8 portant un champ
`format` (`helios-enrollment-invitation`, `helios-enrollment-request`) et les
octets binaires en base64. Extensions `.helios-invite` et `.helios-request` ;
le document final garde `.orion` et son association système. Toutes les
bornes du §15.3 (nom NFC ≤ 255 octets, CSR ≤ 16 384 octets, fenêtre ≤ 24 h)
sont vérifiées au décodage, avant toute signature.

## 5. Côté opérateur

Les gestes se répartissent selon la frontière qu'`astra-operator` pose déjà :
ce qui ouvre le coffre ou signe sous `CA-PQ` vit dans `astra-operator` et se
pilote par `astra-signer` ; ce qui parle à la gateway reste dans
`tools/helios`. Le registre des invitations appartient au premier, puisque la
consommation doit précéder l'émission dans la même commande.

**`astra-signer enroll invite`** — lit la gateway dans le relais public du
domaine, tire `invitation_id` et une paire X25519 éphémère, ouvre le coffre
(une YubiKey ; deux avec `--allow-readmission`), signe l'invitation sous
`CA-PQ`, écrit `<nom>.helios-invite`. Options : `--name`, `--valid-for`
(défaut et maximum 24 h), `--allow-readmission`.

**`astra-signer enroll accept --request <fichier>`** — exécute l'ordre
normatif du §15.2 : invitation signée, ciblée, vivante et `issued` ;
auto-signature ML-DSA ; CSR ; preuve WireGuard ; politique et réadmission.
Puis, dans cet ordre et sans exception : marquer l'invitation `consumed`,
détruire la clé X25519, synchroniser le registre ; seulement ensuite ouvrir le
coffre et émettre la leaf PQ sous `CA-PQ` et la leaf TLS sous `CA-TLS`
cliente, sur les clés reçues, puis les écrire à côté de la demande. Un échec
après la consommation est rapporté comme tel et exige une nouvelle invitation.

**Admission** — inchangée : `heliosd peer add --certificate --pq-certificate`
sur la console, ou `helios` par l'API, avec les deux leafs publiques. La file
d'admission du registre gateway fait déjà le reste.

**`helios enroll document`** — assemble, depuis la gateway (API, ou
`--offline` comme aujourd'hui), le brouillon public du document : profil,
endpoint, VIP, bloc de négociation, bloc de confiance, deux leafs,
`invitation_id`, `request_id`, `request_fingerprint`. Il n'écrit aucune
identité et ne signe rien.

**`astra-signer enroll sign-document <brouillon>`** — vérifie que le
brouillon nomme une invitation `consumed` du registre, la demande qui l'a
consommée et exactement les leafs émises pour elle, que le bloc de confiance
porte la même `CA-PQ`, puis signe la forme JCS et écrit le `.orion`.

**`astra-signer enroll list` / `revoke <id>`** — état du registre ; la
révocation détruit la clé éphémère. Chaque commande purge d'abord les
invitations expirées (clé détruite, état conservé pour l'audit).

**Registre** : `~/.helios/enrollment-invitations/<id>.json`, le chemin du
§15.2, répertoire `0700`, fichiers `0600`, écriture atomique et `fsync` du
répertoire. Un fichier par invitation : la consommation d'une invitation est
le renommage atomique de son seul fichier, sans verrou global.

**Réadmission** (choix de cette note) : `accept` refuse une clé WireGuard
qu'une invitation déjà consommée du registre a admise, sauf invitation
`allow_readmission`, signée sous deux credentials (ADR-008 §4, « réadmission
sans continuité »). La gateway ne garde aucune mémoire des pairs retirés ; le
registre opérateur est la seule source de cette règle, et l'aide de la
commande le dit.

**Ce qui disparaît** : la commande `helios enroll` à un geste, ses options
`--private-key-file`, `--public-key`, `--client-pki-dir` et
`--client-ca-dir`, et l'émission de leafs clientes par
`key_nego::issue_client_material` pour l'enrôlement — §15.2, « il n'existe
plus de pré-admission v5 d'une clé dépourvue de preuve de possession ». Les
sous-commandes `helios key-nego` d'inspection et de sonde restent.

## 6. Côté Orion

**Import d'une invitation** — nouveau geste dans l'écran *Profils*, à côté de
l'import de document, avec les mêmes composants. Orion vérifie la forme,
affiche l'empreinte SHA-256 de `operator_ca_public_key` en groupes lisibles
et exige une confirmation explicite de l'empreinte lue hors bande. Tant
qu'elle manque : aucune clé générée, aucune demande, aucune CA épinglée.
Après confirmation : épinglage, vérification de la signature de l'invitation
sous cette clé, contrôle de la fenêtre.

**Demande** — Orion génère les trois paires (`generate_keypair`,
`CandidateKeys::generate`), calcule la preuve X25519, auto-signe la demande,
puis **scelle d'abord** un enregistrement *demande en attente* dans le
stockage protégé : invitation, CA épinglée, demande signée, trois clés
privées. La demande n'est écrite sur disque (`.helios-request`, boîte de
dialogue d'enregistrement) qu'après le succès du scellement. Si le stockage
protégé est indisponible (Linux), le geste s'arrête avec l'erreur explicite
existante, avant toute génération.

**Demandes en attente** — listées dans *Profils* avec le nom demandé, la
gateway et l'âge, chacune abandonnable (destruction de l'enregistrement
scellé). Elles survivent au redémarrage d'Orion, ce que le `staged_key`
actuel ne fait pas.

**Import du document** — dans l'ordre du §15.3 : CA épinglée retrouvée par
`operator_ca_fingerprint` (une CA apportée par le seul document n'est jamais
une ancre) ; signature opérateur vérifiée avant affichage ; demande en
attente retrouvée par `invitation_id`, `request_id` et `request_fingerprint` ;
clés publiques des deux certificats égales à celles de la demande ; clé
WireGuard gateway et leaf PQ gateway conformes à l'invitation ; `CA-PQ` du
bloc de confiance égale à l'ancre épinglée. Puis, dans une même écriture :
identité scellée comme `ClientIdentityBundle`, clé WireGuard posée dans le
profil, enregistrement en attente détruit. Sans correspondance, le brouillon
s'affiche, nomme les clés attendues et reste non connectable (§19).

**Documents hérités** — décision du 2026-10-23 : un `.orion` qui porte encore
`key_negotiation_identity` est refusé dès ce lot, avec un message qui nomme la
nouvelle procédure, conformément au §19 (« aucun calendrier de sécurité
dépendant de l'horloge »). Les profils déjà importés et scellés continuent de
fonctionner ; un poste qui n'a pas encore importé son document se réenrôle.

## 7. Erreurs et sécurité

- Chaque refus a une erreur typée dans `aether` (forme, signature, fenêtre,
  ciblage, preuve, réutilisation, absence de domaine) ; les messages destinés
  à l'utilisateur restent en français à la frontière Tauri et CLI, comme
  aujourd'hui.
- Le secret X25519, `Z` et les clés privées sont `Zeroizing` ; aucun `Debug`
  ne les expose ; aucune sérialisation générique des enregistrements scellés,
  sur le modèle de `ClientIdentityBundle`.
- La comparaison du HMAC de preuve est en temps constant (`aws_lc_rs`).
- `tools/helios` et `orion-core` ne dépendent pas d'`astra-operator` ; la
  frontière reste une arête de dépendance, comme son en-tête l'exige.
- Aucun `TODO` : ce qui n'est pas livré est refusé par une erreur nommée et
  documenté comme limite.

## 8. Tests et validation

- `aether` : transcriptions octet pour octet sur des vecteurs fixes,
  signatures et `ctx`, refus de chaque champ hors borne, preuve X25519
  (secret nul, clé substituée, nom changé), stabilité JCS du document
  (ordre des clés, échappements, champ dupliqué et flottant refusés).
- `astra-operator` / `astra-signer` : machine d'état du registre —
  consommation avant émission, pas de réouverture après échec, expiration,
  révocation, réadmission sous deux credentials — et refus de signer un
  brouillon qui ne correspond pas à l'invitation consommée.
- `tools/helios` : brouillon public du document, refus sans domaine de
  confiance, absence de tout champ d'identité.
- `orion-core` : enregistrement en attente (sans le backend DPAPI, par
  l'abstraction déjà employée par les tests du stockage), import lié, refus
  du document sans demande, du document hérité, d'une CA non épinglée.
- `apps/orion` : écrans en Vitest au niveau des tests existants de
  `ProfilesView`.
- Validation hors WSL2 : scellement DPAPI réel, YubiKey réelle et parcours
  complet invitation → demande → leafs → admission → document sur Windows
  cible ; à consigner, pas à revendiquer depuis WSL2.

Documentation à mettre à jour avec le code : en-tête de la v5 (retrait de la
limite) ; §15.2 et §22 pour nommer `astra-signer enroll` à la place de
`helios enroll invite` et poser le domaine de confiance en prérequis ;
`OPERATOR-TOOLING` section 6 ; `MANUAL-TESTING` ; `ROADMAP` F2. Les scripts
qui enchaînent l'ancien `helios enroll` (`scripts/provision-client.sh`,
`scripts/key-negotiation-setup.sh`) passent au nouveau parcours ou refusent explicitement.

## 9. Décisions

1. **JCS** — `serde_json_canonicalizer` 0.3.2 (choix de l'utilisateur,
   2026-10-23), voir §4.
2. **Autorité** — le code s'aligne sur la spécification et sur ADR-008 plutôt
   que l'inverse (choix délégué, tranché ici le 2026-10-23). `CA-PQ` du coffre
   signe l'invitation, la leaf PQ et le document ; `CA-TLS` cliente du coffre
   signe la leaf TLS ; un domaine de confiance est exigé. Raisons : ADR-008 §3
   interdit déjà le premier enrôlement à la délégation Astra et ne laisse que
   `CA-PQ` pour le faire ; ROTATION-CERTIFICATS §2.2 veut que l'ancre épinglée
   à l'enrôlement soit `CA-PQ` ; et l'alternative — amender la spécification
   pour bénir la CA fichier — ferait de l'ancre initiale d'Orion une clé
   maîtresse en clair dans un fichier, sous un ADR accepté qui la place dans
   un coffre déverrouillé par YubiKey. La spécification n'est amendée que pour
   nommer les outils (§15.2, §22), sans changer un octet du protocole.
3. **Documents hérités** — refusés dès ce lot (accord de l'utilisateur,
   2026-10-23), voir §6.

Choix de cette note, révisables à la relecture : extensions de fichiers,
registre à un fichier par invitation, règle de réadmission portée par le
registre, enregistrement en attente scellé, découpage
`accept` / `document` / `sign-document`, portées de credentials nouvelles
pour l'enrôlement et la réadmission.
