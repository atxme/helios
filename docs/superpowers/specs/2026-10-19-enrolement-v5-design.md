# Enrôlement v5 sans transport de clé privée — conception

**Date** : 2026-10-19
**Statut** : proposition à valider avant implémentation
**Feuille de route** : F2
**Normes** : [NEGOCIATION-DE-CLE-V5 §15](../../specification/NEGOCIATION-DE-CLE-V5.md#15-enrôlement),
§19 ; [ROTATION-CERTIFICATS §2.2, §13.1](../../specification/ROTATION-CERTIFICATS.md) ;
[ADR-008](../../adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md)

Cette note dit comment implémenter le §15 dans le code existant. Elle ne
modifie pas le protocole : formats, octets signés et ordre des contrôles sont
ceux du §15, auxquels elle renvoie plutôt que de les recopier. Les écarts de
la spécification qu'elle oblige à trancher sont regroupés au §9.

## 1. Pourquoi

`helios enroll` émet aujourd'hui sur le poste opérateur les trois clés
privées du client (WireGuard, TLS, ML-DSA-87) et les place dans le document
`.orion`. Ce document est donc un secret qui existe en clair sur deux
machines et sur le canal qui les relie ; sa protection repose sur une
consigne d'effacement. Le §15 exige l'inverse : les clés naissent sur le poste
Orion, dans son stockage protégé, et n'en sortent jamais ; l'opérateur
n'autorise qu'une demande précise, par une invitation signée à usage unique.

Le second gain est la confiance initiale. Aujourd'hui, le document apporte à
la fois l'ancre `CA-PQ` et ce qu'elle signe. En v5, Orion épingle l'ancre à
l'import de l'invitation, après une confirmation hors bande bloquante, et
vérifie ensuite le document sous cette ancre déjà fiable.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**

- invitation signée, ciblée, vivante 24 h au plus, à usage unique, et registre
  opérateur qui la consomme atomiquement avant toute émission ;
- clés WireGuard, TLS et ML-DSA-87 générées dans Orion et scellées avant
  qu'une demande ne sorte ;
- demande liée à l'invitation, avec trois preuves de possession, dont la
  preuve X25519 du §15.2 ;
- document `.orion` sans aucun secret, signé par `CA-PQ`, lié à la demande ;
- import Orion qui exige la demande locale en attente et retrouve les clés
  privées par leurs clés publiques, jamais par le nom.

**Non-objectifs**

- transport en ligne de l'invitation ou de la demande : les trois objets
  circulent comme fichiers, par le canal que l'opérateur choisit. Aucun ne
  contient de secret (§15.2) ;
- intégration au coffre `astra-signer` et aux YubiKeys (voir §9, décision 2) ;
- stockage protégé Linux : il reste refusé (F12). L'enrôlement complet ne
  s'exécute donc que sous Windows ;
- profils `classic` : ils gardent l'import WireGuard ordinaire, sans
  invitation (§15.1).

**Anti-objectifs** — ce qui serait un échec même si « ça marche »

- une clé privée cliente qui apparaît, même transitoirement, dans un fichier
  écrit par l'outillage opérateur ou par Orion hors du stockage protégé ;
- une CA rendue fiable par le document qu'elle signe, ou par un clic qui ne
  montre pas l'empreinte ;
- une invitation réutilisable après un échec, ou rouverte par une reprise ;
- un appariement document ↔ clés fait sur le nom du profil ;
- un second chemin d'enrôlement conservé « pour compatibilité » qui émet
  encore des clés privées.

## 3. Ce qui existe et sert de base

| Brique | Où | Usage ici |
| --- | --- | --- |
| Génération locale TLS + CSR + ML-DSA-87 | `orion-core::certificate_renewal::CandidateKeys`, `aether::certificates::x509::client_rotation_csr` | mêmes clés et même CSR pour la demande d'enrôlement |
| Stockage protégé DPAPI | `orion-core::identity_store` (`ProtectedIdentityStore`, `seal`/`unseal`) | scellement de la demande en attente puis de l'identité finale |
| Clé WireGuard générée sur le poste | `staged_key` de `apps/orion/src-tauri/src/commands/profiles.rs`, `aether::wg::generate_keypair` | remplacée par la clé de la demande scellée (le slot en mémoire ne survit pas au délai d'un enrôlement) |
| Signatures ML-DSA-87 à `ctx` | `aether::ml_dsa` | invitation, demande, document ; `ctx` = domaine ASCII du §15.3 |
| Aléa | `aether::random` | `invitation_id`, `request_id`, clé X25519 éphémère |
| Émission des leafs clientes | `tools/helios/src/key_nego.rs::issue_client_material_with_validity` | à scinder : émettre sur une clé publique et une CSR reçues au lieu de générer la paire |
| Admission | `helios_provisioning::admit_with_key_negotiation`, API ou `heliosd peer add` | inchangée |
| Bloc de confiance | `heliosd show-trust-enrolment`, `api::trust_enrolment` | inchangé, posé dans le document |
| Import Orion en brouillon | `parse_profile_import`, `complete_profile_import`, `finish_import` | étendu au document v5 |

## 4. Objets et où ils vivent

Les trois types publics et leurs transcriptions vont dans un nouveau module
`aether::key_negotiation::enrollment`, partagé par `tools/helios` et
`orion-core`. Le nom évite `aether::enroll`, qui désigne l'ancien
provisionnement dans le tunnel.

- `EnrollmentInvitation` : champs et octets signés du §15.2/§15.3,
  `verify(ca_public_key, now)`, `fingerprint()`.
- `EnrollmentRequest` : champs et octets auto-signés du §15.3,
  `wireguard_proof` du §15.2, `verify(invitation, now)` qui contrôle la
  liaison et l'auto-signature (la preuve WireGuard se vérifie côté opérateur,
  seul détenteur de la clé X25519 éphémère).
- `EnrollmentDocument` (`.orion` v5) : schéma fermé du §15.3,
  `deny_unknown_fields`, signature opérateur sur la forme JCS sans le champ
  `operator_signature`.
- `wireguard_proof(client_wg_private, proof_public, …)` et sa vérification en
  temps constant ; refus d'un secret X25519 tout nul des deux côtés.

Forme sur disque, par décision de cette note : JSON UTF-8 portant un champ
`format` (`helios-enrollment-invitation`, `helios-enrollment-request`) et les
octets binaires en base64. Extensions `.helios-invite` et `.helios-request` ;
le document final garde `.orion` et son association système. Toutes les
bornes du §15.3 (nom NFC ≤ 255 octets, CSR ≤ 16 384 octets, fenêtre ≤ 24 h)
sont vérifiées au décodage, avant toute signature.

## 5. Côté opérateur : `helios enroll`

Trois sous-commandes remplacent la commande actuelle.

**`helios enroll invite`** — lit le matériel gateway exactement comme
aujourd'hui (API, ou `--offline` depuis les deux certificats rapatriés),
tire `invitation_id` et une paire X25519 éphémère, signe l'invitation sous
`CA-PQ`, écrit `<nom>.helios-invite`. Options : `--name`, `--valid-for`
(défaut et maximum 24 h), `--allow-readmission`.

**`helios enroll accept --request <fichier>`** — exécute l'ordre normatif du
§15.2 : invitation signée, ciblée, vivante et `issued` ; auto-signature
ML-DSA ; CSR ; preuve WireGuard ; politique et réadmission. Puis, dans cet
ordre et sans exception : marquer l'invitation `consumed`, détruire la clé
X25519, synchroniser le registre ; seulement ensuite émettre les deux leafs
sur les clés reçues, admettre le pair (API ou impression de la commande
`heliosd peer add` hors ligne, comme aujourd'hui), lire le bloc de confiance,
écrire le `.orion` signé. Un échec après la consommation est rapporté
comme tel et exige une nouvelle invitation.

**`helios enroll list` / `helios enroll revoke <id>`** — état du registre ;
la révocation détruit la clé éphémère. Chaque commande purge d'abord les
invitations expirées (clé détruite, état conservé pour l'audit).

**Registre** : `~/.helios/enrollment-invitations/<id>.json`, répertoire
`0700`, fichiers `0600`, écriture atomique et `fsync` du répertoire, en
réutilisant les helpers de fichiers privés déjà employés par l'outil. Un
fichier par invitation : la consommation d'une invitation est le
renommage atomique de son seul fichier, sans verrou global.

**Réadmission** (choix de cette note) : `accept` refuse une clé WireGuard
qu'une invitation déjà consommée du registre a admise et que la gateway
n'admet plus, sauf invitation `allow_readmission`. La gateway, elle, ne garde
aucune mémoire des pairs retirés ; le registre opérateur est la seule source
de cette règle, et la note le dit dans l'aide de la commande.

La commande à un geste actuelle disparaît, ainsi que `--private-key-file`,
`--public-key` et `--client-pki-dir` : §15.2, « il n'existe plus de
pré-admission v5 d'une clé dépourvue de preuve de possession ».
`helios profile emit` reste le chemin des profils `classic`.

## 6. Côté Orion

**Import d'une invitation** — nouveau geste dans l'écran *Profils*, à côté de
l'import de document, avec les mêmes composants. Orion vérifie la forme,
affiche l'empreinte SHA-256 de `operator_ca_public_key` en groupes lisibles
et exige une confirmation explicite qui recopie ou coche l'empreinte lue hors
bande. Tant qu'elle manque : aucune clé générée, aucune demande, aucune CA
épinglée. Après confirmation : épinglage, vérification de la signature de
l'invitation sous cette clé, contrôle de la fenêtre.

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
WireGuard gateway et leaf PQ gateway conformes à l'invitation. Puis, dans une
même écriture : identité scellée comme `ClientIdentityBundle`, clé WireGuard
posée dans le profil, enregistrement en attente détruit. Sans correspondance,
le brouillon s'affiche, nomme les clés attendues et reste non connectable
(§19).

**Documents hérités** — un `.orion` qui porte encore
`key_negotiation_identity` est refusé avec un message qui nomme la nouvelle
procédure ; les profils déjà importés et scellés continuent de fonctionner,
puisque leur identité est déjà dans le stockage protégé.

## 7. Erreurs et sécurité

- Chaque refus a une erreur typée dans `aether` (forme, signature, fenêtre,
  ciblage, preuve, réutilisation) ; les messages destinés à l'utilisateur
  restent en français à la frontière Tauri, comme aujourd'hui.
- Le secret X25519, `Z` et les clés privées sont `Zeroizing` ; aucun `Debug`
  ne les expose ; aucune sérialisation générique des enregistrements scellés,
  sur le modèle de `ClientIdentityBundle`.
- La comparaison du HMAC de preuve est en temps constant (`aws_lc_rs`).
- Aucun `TODO` : ce qui n'est pas livré est refusé par une erreur nommée et
  documenté comme limite.

## 8. Tests et validation

- `aether` : transcriptions octet pour octet sur des vecteurs fixes,
  signatures et `ctx`, refus de chaque champ hors borne, preuve X25519
  (secret nul, clé substituée, nom changé), JCS sur les vecteurs de la
  RFC 8785 utiles au schéma.
- `tools/helios` : machine d'état du registre — consommation avant émission,
  pas de réouverture après échec, expiration, révocation, réadmission —
  et `accept` de bout en bout contre une gateway de test.
- `orion-core` : enregistrement en attente (sans le backend DPAPI, par
  l'abstraction déjà employée par les tests du stockage), import lié, refus
  du document sans demande, du document hérité, d'une CA non épinglée.
- `apps/orion` : écrans en Vitest au niveau des tests existants de
  `ProfilesView`.
- Validation hors WSL2 : scellement DPAPI réel et parcours complet
  invitation → demande → document sur un Windows cible ; à consigner, pas à
  revendiquer depuis WSL2.

Documentation à mettre à jour avec le code : en-tête de la v5 (retrait de la
limite), `OPERATOR-TOOLING` section 6, `MANUAL-TESTING`, `ROADMAP` F2.

## 9. Décisions à prendre avant le code

1. **Canonicalisation du document.** Le §15.3 impose JCS (RFC 8785) ; le dépôt
   n'en a aucune implémentation, et AGENTS.md proscrit un nouveau format de
   sérialisation quand un mécanisme existant convient. Proposition :
   implémenter dans `aether` un JCS restreint au schéma — chaînes, entiers,
   booléens, tableaux, objets, **sans flottants**, refusés — sans dépendance,
   testé sur les vecteurs RFC. Alternative : amender le §15.3 pour signer une
   transcription binaire canonique comme l'invitation et la demande.
2. **Autorité qui signe.** Le §15 nomme `CA-PQ`. Aujourd'hui `helios enroll`
   émet avec la CA du répertoire `--client-ca-dir`
   (`orion-client-pq-ca-private.bin`), alors qu'ADR-008 place `CA-PQ` dans le
   coffre HVLT d'`astra-signer`, déverrouillé par YubiKey, et exige deux
   YubiKeys pour une réadmission sans continuité. Proposition : ce lot garde
   la CA du répertoire comme `CA-PQ` (aucun changement de garde) ;
   l'émission depuis le coffre `astra-signer` est un lot séparé.
3. **Rupture des documents hérités.** La proposition du §6 refuse tout
   `.orion` portant des clés privées dès ce lot, ce qui oblige à
   réenrôler tout poste qui n'a pas encore importé son document. Alternative :
   les accepter encore pendant une période bornée — que le §19 écarte
   (« aucun calendrier de sécurité dépendant de l'horloge »).

Les autres choix de cette note — extensions de fichiers, registre à un fichier
par invitation, règle de réadmission portée par le registre, enregistrement en
attente scellé — sont les miens et restent révisables à la relecture.
