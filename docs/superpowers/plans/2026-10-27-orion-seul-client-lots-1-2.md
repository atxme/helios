# F14 lots 1 et 2 — socle opérateur et enrôlement v5 dans Orion — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** l'onglet Astra d'Orion devient l'espace opérateur (lot 1 : coffre, clés, domaine, vérification d'une clé) et porte l'enrôlement v5 complet côté opérateur (lot 2 : inviter, accepter en un geste avec admission du pair et document signé, liste, révocation, reprise), sans `astra-signer`.

**Architecture :** tout geste opérateur tourne dans l'IHM non élevée, dans la cérémonie existante (`apps/orion/src-tauri/src/operator/`), sur la logique d'`astra-operator`. L'assemblage du document v5, aujourd'hui dans `tools/helios`, descend dans `orion-core` ; un petit client asynchrone des routes d'administration de la gateway s'y ajoute. Les fichiers passent comme aujourd'hui dans Orion : la WebView lit le fichier choisi et transmet son **contenu** public, Rust vérifie tout ; les fichiers produits reviennent en contenu et la WebView propose leur enregistrement.

**Tech Stack :** Rust 2021, Tauri 2, `astra-operator`, `aether`, `orion-core` (reqwest async déjà présent), React + MUI + Vitest.

**Spec :** `docs/superpowers/specs/2026-10-27-orion-seul-client-design.md`

## Global Constraints

- AGENTS.md : aucun secret (PIN, secret de key-slot, clé `CA-PQ`, octets du coffre, assertion, clé X25519 d'invitation) journalisé, sérialisé vers la WebView ni exposé ; *fail-closed* ; pas d'`unwrap`/`expect` en production ; aucun TODO/FIXME ; identifiants, commentaires et noms de tests en anglais ; messages de l'IHM en français ; `docs/` en français.
- Aucune nouvelle dépendance externe. Une dépendance interne au workspace (ou une dev-dependency interne) est admise.
- Le moteur élevé (`orion-engine`) n'ouvre pas le coffre opérateur et ne dépend pas d'`astra-operator` (ADR-008).
- La WebView ne choisit pas ce qui est signé : elle transmet un genre de geste fermé, des paramètres typés validés en Rust et le contenu public d'un fichier choisi ; tout est revérifié et montré dans le manifeste avant le toucher.
- L'URL de la gateway pour l'administration est l'`heliosd_url` du profil sélectionné **et connecté** (`ConfigView.selected`, `GetState` = `up`), lue côté Rust ; jamais une URL venue de la WebView.
- Direction artistique d'Orion conservée : composants MUI existants, palette et constantes de `apps/orion/src/theme.ts`, mise en page des vues actuelles.
- `astra-signer` et `helios enroll document` restent construits et fonctionnels jusqu'au lot 7.
- Compilation et tests : `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo …` ; IHM : `cd apps/orion && npx tsc --noEmit -p . && npx vitest run`.
- Commits terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Rulings du plan (écarts à la spec, à reporter dans la spec en tâche 11)

- **Fichiers par contenu, pas par chemin** : la spec §4.10 et §8 parlaient d'une boîte de dialogue côté Rust. Orion n'en a aucune (pas de plugin de dialogue ; l'import de profil et l'enregistrement de la demande passent par `<input type="file">` et un lien de téléchargement). On garde ce motif : aucun chemin ne traverse, le contenu choisi est vérifié en Rust. Ajouter un plugin serait une dépendance nouvelle.
- **Feuilles et demande conservées dans le registre** : pour la reprise, la demande acceptée et ses deux feuilles sont écrites dans `<registre>/<invitation_id>.accepted.json` (public, `0600`, écriture atomique), vérifiées à la relecture contre les empreintes que l'enregistrement de l'invitation porte déjà. L'enregistrement existant n'est pas modifié : ce n'est pas une migration.
- **Chemin du coffre** : les cérémonies utilisent `astra_operator::store::default_path()`, comme celles qui existent ; l'écran l'affiche. Le choix d'un autre chemin est reporté au lot 3 (spec §4.3).
- **Artefacts hors du statut** : les fichiers produits (invitation, feuilles, document) ne passent pas dans `OperatorStatus` (plafonds de `operator_session::limits`) ; la session les garde et une commande Tauri les rend.

## Review Focus

1. **Demande d'un autre domaine ou d'une invitation inconnue** collée dans « Accepter » : refus avant tout toucher, invitation intacte. Test en tâche 9 (`a_request_for_an_unknown_invitation_is_refused_before_the_key`).
2. **Tunnel coupé ou pair non `admin` au moment de l'admission** : arrêt après l'émission, feuilles et ligne `heliosd peer add` rendues, reprise possible sans réémission. Tests en tâche 9 (`an_unreachable_gateway_stops_after_the_leaves`) et 10 (`a_resumed_enrollment_never_reissues_leaves`).
3. **Deuxième acceptation de la même demande** (double clic, ou fichier ré-importé) : refusée par la consommation déjà faite, avec un message qui renvoie à la reprise. Test en tâche 9 (`accepting_a_consumed_invitation_points_to_resume`).
4. **Profil sélectionné mais non connecté, ou sans `heliosd_url`** : le geste dit qu'il faut le tunnel, n'appelle aucune URL. Test en tâche 7 (`no_connected_profile_means_no_gateway_url`).
5. **Ancienne invitation sans fichier `.accepted.json`** (acceptée par `astra-signer`) : listée comme consommée, sans bouton « Reprendre », sans erreur. Test en tâche 5 (`an_invitation_accepted_by_the_cli_lists_without_resume`).

---

## Lot 1 — socle opérateur

### Task 1 : genres d'opération et manifestes de l'enrôlement

**Files :**
- Modify : `crates/aether/src/certificates/operator_session.rs` (+ ses tests)

**Interfaces :**
- Produces :
  - `OperationKind::{VerifyKey, InviteEnrollment, AcceptEnrollment}` (serde `snake_case` : `verify_key`, `invite_enrollment`, `accept_enrollment`).
  - `AstraManifest::{KeyCheck(KeyCheckManifest), Invitation(InvitationManifest), EnrollmentAcceptance(AcceptanceManifest)}` et `AstraManifest::kind()` qui les associe aux trois genres.
  - `pub struct KeyCheckManifest { pub vault_fingerprint: Fingerprint }`.
  - `pub struct InvitationManifest { pub server_name: String, pub gateway_wg_public_key: WireGuardKey, pub not_after_unix: u64, pub allow_readmission: bool, pub ca_pq_fingerprint: Fingerprint }`.
  - `pub struct AcceptanceManifest { pub invitation_id: Id16, pub request_fingerprint: Fingerprint, pub requested_name: String, pub client_wg_public_key: WireGuardKey, pub leaves_not_after_unix: u64, pub endpoint: String }`.
  - `Refusal::GatewayUnavailable` (l'admission ou la lecture de la gateway a échoué ; ne porte aucun texte).
  - Tous `#[serde(deny_unknown_fields)]`, comme les manifestes existants.

- [ ] **Step 1 : tests rouges** dans le module de tests existant : `enrollment_kinds_round_trip` (les trois genres en JSON `snake_case` et retour), `enrollment_manifests_name_their_kind` (`AstraManifest::Invitation(..).kind() == OperationKind::InviteEnrollment`, idem les deux autres), `a_manifest_with_an_unknown_field_is_refused` pour `AcceptanceManifest`, `gateway_unavailable_carries_no_text` (sérialisé : `{"refusal":"gateway_unavailable"}`).
- [ ] **Step 2 :** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether --lib certificates::operator_session` → FAIL (variantes absentes).
- [ ] **Step 3 :** ajouter les variantes et structures ; compléter tout `match` exhaustif qui casse (IHM, `allowed_actions`, rendu Rust) sans changer le comportement des genres existants ; `ceremony::run` refuse encore les nouveaux genres par son bras « pas encore porté ».
- [ ] **Step 4 :** même commande → PASS ; `scripts/wsl-cargo test -p orion` → PASS.
- [ ] **Step 5 :** commit `feat(aether): operator session kinds and manifests for enrollment`.

### Task 2 : état du coffre et du domaine sans clé

**Files :**
- Create : `crates/astra-operator/src/overview.rs` (+ `overview/tests.rs`), déclaré dans `lib.rs`
- Modify : `apps/orion/src-tauri/src/commands/ceremonies.rs`, enregistrement de la commande dans `main.rs`, `apps/orion/src/api.ts`, `apps/orion/src/types.ts`

**Interfaces :**
- Produces (Rust, `astra_operator::overview`) :
  - `pub struct VaultOverview { pub vault_path: String, pub exists: bool, pub vault_fingerprint: Option<String>, pub slots: Vec<SlotView>, pub max_slots: usize, pub domain: Option<DomainView> }` (`Serialize`).
  - `pub struct SlotView { pub slot_id: String /* 32 hex */, pub label: String, pub role: String /* "principale" | "recuperation" */ }`.
  - `pub struct DomainView { pub trust_domain_id: String, pub rp_id: String, pub ca_pq_fingerprint: String /* groupé comme grouped_hex */, pub ca_epoch: Option<u64>, pub ca_tls_epoch: Option<u64>, pub ca_tls_present: bool, pub server_name: Option<String>, pub gateway_wg_public_key: Option<String> }`.
  - `pub fn read(vault_path: &Path) -> anyhow::Result<VaultOverview>` : coffre absent → `exists: false`, le reste vide, `Ok` ; coffre illisible → `Err` ; relais absent ou illisible → `domain: None`.
  - `pub fn grouped_hex(hex: &str) -> String` déplacé depuis `tools/astra-signer/src/commands/enrollment.rs` (qui l'importe désormais d'ici).
- Produces (Tauri) : `operator_overview() -> Result<VaultOverview, String>` sur `store::default_path()`.
- Produces (TS) : `api.operatorOverview(): Promise<VaultOverview>` et les types `VaultOverview`, `SlotView`, `DomainView` (mêmes noms de champs).

- [ ] **Step 1 : tests rouges** (`overview/tests.rs`, avec les fabriques de coffre des tests existants d'`astra-operator`) : `a_missing_vault_reads_as_absent`, `slots_are_listed_with_their_role_and_label`, `the_domain_comes_from_the_relay_beside_the_vault`, `a_vault_without_relay_has_no_domain`, `the_overview_carries_no_secret` (le JSON sérialisé ne contient ni `wrapped`, ni `secret`, ni `salt`, ni octets de key-slot : vérifier sur les noms de champs de `KeySlot` qui portent du matériel chiffré).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p astra-operator --lib overview` → FAIL.
- [ ] **Step 3 :** implémenter `read` sur `store::load`, `AuthorityVault::fingerprint`, `slots`, `DomainHandoff::beside` ; la commande Tauri ; l'API TS.
- [ ] **Step 4 :** `-p astra-operator --lib`, `-p astra-signer`, `-p orion`, `tsc` → PASS.
- [ ] **Step 5 :** commit `feat(orion): read the operator vault and domain without a key`.

### Task 3 : « Vérifier une clé » dans la cérémonie de l'IHM

**Files :**
- Modify : `apps/orion/src-tauri/src/operator/ceremony.rs` (+ `ceremony/tests.rs`)

**Interfaces :**
- Consumes : Task 1 (`OperationKind::VerifyKey`, `AstraManifest::KeyCheck`).
- Produces : `ceremony::run` sert `VerifyKey` : statut `AwaitingKey { index: 1, of: 1, purpose: KeyPurpose::OpenVault }` avec le manifeste `KeyCheck`, puis sur `Continue` ouverture du coffre (`gestures::open_with_authorized_key` avec PIN vide, refus `ProtocolViolation` si le transport demande un PIN, comme `recover`), `gestures::prove_anchors_open`, `keys` = le libellé du key-slot qui a répondu, `Done`. Aucune écriture.

- [ ] **Step 1 : test rouge** `verify_key_is_served` : `run` avec `VerifyKey` sur un coffre absent publie un refus typé (`HandoffMismatch`) et non plus le bras « pas encore porté ». Le chemin heureux dépend d'une clé : il est couvert par la recette.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion operator` → FAIL.
- [ ] **Step 3 :** extraire de `recover` et `approve_campaign` la séquence « attendre Continue, rattacher la fenêtre, connecter la clé, refuser un transport à PIN » dans une fonction partagée `open_key(ceremony, presses, publish, offered) -> Result<Option<Box<dyn Authenticator>>, String>` (`None` = annulé), utilisée par les trois genres. Pas de second exemplaire de ce code.
- [ ] **Step 4 :** même commande → PASS ; tests existants de `recover`/`approve_campaign` → PASS.
- [ ] **Step 5 :** commit `feat(orion): check an operator key from the UI`.

### Task 4 : sous-onglets d'Astra, Coffre et clés, Domaine

**Files :**
- Modify : `apps/orion/src/views/AstraView.tsx` (+ `AstraView.test.tsx`), `apps/orion/src/views/OperatorCeremony.tsx` si un rendu de manifeste manque
- Create : `apps/orion/src/views/astra/VaultPanel.tsx`, `apps/orion/src/views/astra/DomainPanel.tsx` (+ tests vitest)

**Interfaces :**
- Consumes : Task 2 (`api.operatorOverview`), Task 3 (`VerifyKey` par `beginOperatorCeremony({ kind: 'verify_key', operation_id: null })`).
- Produces : `AstraView` avec des onglets MUI `Tabs` dans cet ordre et ces libellés : « Enrôlement », « Coffre et clés », « Domaine », « Approbations », « Rotations », « Gateways ». « Enrôlement » et « Gateways » affichent un texte d'attente jusqu'aux tâches 10 et lot 6. Le contenu actuel (rotation `CA-TLS`, campagnes) passe sous « Rotations », les opérations en attente sous « Approbations », sans changement de comportement.

- [ ] **Step 1 : tests rouges** : `the_astra_tab_lists_six_sections_in_order`, `the_vault_panel_shows_slots_and_fingerprint`, `a_missing_vault_says_how_to_create_one` (texte : « Aucun coffre opérateur à cet emplacement. La création d'un domaine arrivera dans Orion ; d'ici là, `astra-signer init`. »), `verify_key_starts_the_ceremony`, `the_domain_panel_shows_the_ca_pq_fingerprint_grouped`, `the_rotation_flow_still_renders_under_rotations` (les tests existants d'`AstraView` déplacés sous l'onglet).
- [ ] **Step 2 :** `cd apps/orion && npx vitest run src/views` → FAIL.
- [ ] **Step 3 :** implémenter, en réutilisant `OperatorCeremonyPanel` pour la vérification.
- [ ] **Step 4 :** `npx tsc --noEmit -p . && npx vitest run` → PASS.
- [ ] **Step 5 :** commit `feat(orion): the Astra tab becomes the operator space`.

---

## Lot 2 — enrôlement v5 côté opérateur

### Task 5 : la demande acceptée et ses feuilles, gardées pour la reprise

**Files :**
- Modify : `crates/astra-operator/src/enrollment.rs` (+ `enrollment/tests.rs`)

**Interfaces :**
- Produces :
  - `pub struct AcceptedEnrollment { pub request: EnrollmentRequest, pub tls_certificate: DerCertificate, pub pq_certificate: PqCertificate }` (`Serialize`, `Deserialize`, `deny_unknown_fields`).
  - `InvitationRegistry::store_accepted(&self, id: &Id16, accepted: &AcceptedEnrollment) -> Result<()>` : fichier `<id>.accepted.json`, `0600`, écriture atomique et `fsync` du répertoire comme les enregistrements ; refuse si l'invitation n'est pas `Consumed` avec `issued` égal aux empreintes des deux feuilles.
  - `InvitationRegistry::accepted(&self, id: &Id16) -> Result<Option<AcceptedEnrollment>>` : absent → `None` ; présent mais empreintes différentes de l'enregistrement → `Err`.
  - `InvitationRecord` inchangé ; `list` ignore les fichiers `.accepted.json`.

- [ ] **Step 1 : tests rouges** : `accepted_leaves_round_trip`, `accepted_leaves_must_match_the_recorded_fingerprints`, `an_issued_invitation_cannot_store_leaves`, `listing_ignores_accepted_files`, `an_invitation_accepted_by_the_cli_lists_without_resume` (consommée avec `issued`, sans fichier : `accepted` rend `None`).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p astra-operator --lib enrollment` → FAIL.
- [ ] **Step 3 :** implémenter avec les primitives d'écriture privée déjà utilisées par le registre.
- [ ] **Step 4 :** `-p astra-operator --lib`, `-p astra-signer` → PASS.
- [ ] **Step 5 :** commit `feat(astra-operator): keep an accepted request and its leaves for resumption`.

### Task 6 : l'assemblage du document descend dans orion-core

**Files :**
- Create : `crates/orion-core/src/enrollment_draft.rs` (+ `enrollment_draft/tests.rs`)
- Modify : `crates/orion-core/src/lib.rs`, `tools/helios/src/enroll.rs`, `tools/helios/src/profile.rs`

**Interfaces :**
- Produces (`orion_core::enrollment_draft`), déplacés de `tools/helios` sans changement de comportement :
  - `pub struct GatewayMaterial { pub server_name: String, pub gateway_ca_der: String, pub gateway_pq_certificate: String, pub wireguard_public_key: String, pub pq_certificate_sha256: String, pub negotiation_port: Option<u16> }`.
  - `pub struct Admission { pub address: String, pub address_v6: Option<String>, pub heliosd_url: Option<String>, pub trust: Option<TrustMaterial> }`.
  - `pub struct DraftInput<'a> { pub request: &'a EnrollmentRequest, pub tls_certificate: DerCertificate, pub pq_certificate: &'a PqCertificate, pub material: &'a GatewayMaterial, pub admission: Admission, pub endpoint: &'a str, pub negotiation_endpoint: String, pub allowed_ips: Option<&'a str>, pub ssh_target: Option<&'a str>, pub now_unix: u64 }`.
  - `pub fn check_leaves(request, tls_certificate, pq_certificate) -> anyhow::Result<()>`, `pub fn build_draft(input: DraftInput<'_>) -> anyhow::Result<EnrollmentDocument>`, `pub fn resolve_negotiation_endpoint(endpoint: &str, explicit: Option<&str>, port: Option<u16>) -> anyhow::Result<String>` (signature exacte : celle d'aujourd'hui dans `enroll.rs`, à reprendre telle quelle si elle diffère).
  - Ce que `build_draft` utilise de `tools/helios/src/profile.rs` (`public_profile`, `Profile`, `KeyNegotiation`, et ce qu'ils appellent) descend dans le même module ; `profile.rs` le réimporte pour ses autres usages.
- `tools/helios/src/enroll.rs` appelle ces fonctions ; ses commandes et sorties ne changent pas.

- [ ] **Step 1 :** déplacer d'abord les tests existants de ces fonctions (dans `tools/helios`) vers `enrollment_draft/tests.rs` ; ils échouent faute du module : `scripts/wsl-cargo test -p orion-core --lib enrollment_draft` → FAIL (module absent).
- [ ] **Step 2 :** déplacer le code ; `tools/helios` le réimporte.
- [ ] **Step 3 :** `-p orion-core --lib`, `-p helios` (tests et `--help` des commandes `enroll`) → PASS, mêmes nombres de tests qu'avant la tâche à l'unité près des tests déplacés.
- [ ] **Step 4 :** commit `refactor(orion-core): the v5 document draft, shared by Orion and helios`.

### Task 7 : client des routes d'administration de la gateway

**Files :**
- Create : `crates/orion-core/src/gateway_admin.rs` (+ `gateway_admin/tests.rs`)
- Modify : `crates/orion-core/src/lib.rs`, `crates/orion-core/Cargo.toml` (dev-dependency interne `helios-api` pour le test de contrat, si son graphe compile hors Windows ; sinon une copie figée du JSON attendu)
- Modify : `apps/orion/src-tauri/src/commands/ceremonies.rs` (résolution de l'URL)

**Interfaces :**
- Produces (`orion_core::gateway_admin`, async, `reqwest` déjà présent) :
  - `pub struct PeerAdmission { pub name: String, pub public_key: String, pub admin: bool /* toujours false ici */, pub minimum_key_negotiation_mode: ProtectionMode /* MlKem */, pub key_negotiation_certificate: String /* base64 DER */, pub key_negotiation_pq_certificate: String /* base64 JSON */ }`, sérialisée exactement comme `helios_api::routes::peers::PeerAdmitRequest`.
  - `pub async fn admit_peer(base: &str, admission: &PeerAdmission) -> Result<(), GatewayAdminError>`.
  - `pub async fn gateway_material(base: &str, client_key: &str) -> Result<(GatewayMaterial, Admission), GatewayAdminError>` : la logique d'`online_material` de `tools/helios/src/enroll.rs` (réseau, négociation, contrôle de l'identité WireGuard, pair trouvé, bloc de confiance).
  - `pub async fn admitted_keys(base: &str) -> Result<Vec<String>, GatewayAdminError>` (clés publiques des pairs, pour la liste des invitations).
  - `pub enum GatewayAdminError { Unreachable, Forbidden, Refused { status: u16 }, Invalid(String) }` avec `Display` français ; `Forbidden` (401/403) dit que le pair de ce poste doit porter le drapeau `admin`.
  - `pub fn admission_command_line(name: &str, public_key: &str, tls_file: &str, pq_file: &str) -> String` : la ligne `heliosd peer add --name … --public-key … --certificate … --pq-certificate … --minimum-mode ml-kem` avec l'échappement de `shell_word` d'`astra-signer` (fonction déplacée ici, `astra-signer` la réimporte).
- Produces (Tauri, privé au module) : `async fn connected_gateway(state: &AppState) -> Result<String, String>` : `GetState` doit valoir `up` et `ConfigView.selected` nommer un profil avec `heliosd_url` ; sinon `Err("Connectez d'abord le profil de la gateway, avec un pair administrateur : l'admission passe par le tunnel.")`.

- [ ] **Step 1 : tests rouges** : `the_admission_body_matches_the_gateway_contract` (JSON égal à celui de `PeerAdmitRequest`), `a_forbidden_admission_names_the_admin_flag`, `an_unreachable_gateway_is_its_own_error` (port local fermé), `the_command_line_quotes_names` (nom avec espace et apostrophe), `no_connected_profile_means_no_gateway_url` (fonction pure extraite de `connected_gateway` : `gateway_url(state: &str, view: &ConfigView) -> Result<String, String>`).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core --lib gateway_admin` et `-p orion connected` → FAIL.
- [ ] **Step 3 :** implémenter ; tests avec un serveur HTTP local factice si `orion-core` en a déjà un dans ses tests, sinon sur la sérialisation et les codes seulement.
- [ ] **Step 4 :** mêmes commandes, `-p astra-signer` → PASS.
- [ ] **Step 5 :** commit `feat(orion-core): admit a peer and read the gateway through the admin routes`.

### Task 8 : « Inviter un poste »

**Files :**
- Modify : `apps/orion/src-tauri/src/operator/mod.rs`, `apps/orion/src-tauri/src/operator/ceremony.rs` (+ tests), `apps/orion/src-tauri/src/commands/ceremonies.rs`, `main.rs`, `apps/orion/src/api.ts`, `apps/orion/src/types.ts`

**Interfaces :**
- Consumes : Task 1, 3 (`open_key`), 7 (`connected_gateway`, `gateway_material`).
- Produces :
  - `pub enum EnrollmentGesture { Invite { valid_for_hours: u8 /* 1..=24 */, allow_readmission: bool, name: String, gateway_pq_certificate: Option<String> }, Accept { request: String, validity_days: u16 /* 1..=1825, défaut 365 */, endpoint: String, allowed_ips: Option<String>, ssh_target: Option<String> }, Resume { invitation_id: Id16, endpoint: String, allowed_ips: Option<String>, ssh_target: Option<String> } }` (`Deserialize`, `deny_unknown_fields`), dans `operator/mod.rs`.
  - `OperatorCeremony::begin_enrollment(gesture: EnrollmentGesture, gateway: Option<String>) -> Result<OperatorStatus, String>` ; `begin` existant inchangé ; les deux partagent la règle « une cérémonie à la fois ».
  - `pub struct OperatorArtifact { pub file_name: String, pub contents: String }` (`Serialize`) ; `OperatorCeremony::artifacts() -> Vec<OperatorArtifact>` rend ceux de la session courante.
  - Tauri : `begin_enrollment_ceremony(gesture)` (résout `connected_gateway`, `None` en cas d'échec : l'invitation peut alors se faire avec la feuille fournie), `operator_artifacts()`.
  - Invitation : feuille PQ de la gateway lue par `gateway_material` si une gateway connectée est connue, sinon prise dans `gateway_pq_certificate` (contenu d'un fichier choisi) ; vérifiée contre `server_name` et `gateway_wg_public_key` du relais ; manifeste `Invitation` montré avant le toucher ; une ou deux clés selon `signing::enrollment_credentials(allow_readmission)`, la seconde avec `KeyPurpose::SecondApproval` et un credential distinct ; artefact `<name>.helios-invite` (`encode_invitation_file`). Nom vide ou hors `[A-Za-z0-9._-]{1,64}` → refus avant tout.

- [ ] **Step 1 : tests rouges** : `an_invitation_needs_a_gateway_leaf` (ni gateway ni feuille → refus `HandoffMismatch`, rien dans le registre), `a_leaf_for_another_gateway_is_refused`, `an_invitation_lasts_at_most_a_day` (25 h refusé à la désérialisation), `a_bad_invitation_name_is_refused`, `readmission_asks_for_two_distinct_keys` (le statut offert porte `of: 2`), `artifacts_are_empty_without_a_session`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion operator` → FAIL.
- [ ] **Step 3 :** implémenter sur `signing::sign_invitation` et `InvitationRegistry::default_location()`.
- [ ] **Step 4 :** même commande → PASS ; `npx tsc --noEmit -p .`.
- [ ] **Step 5 :** commit `feat(orion): invite a device from the operator space`.

### Task 9 : « Accepter une demande » en un geste

**Files :**
- Modify : `apps/orion/src-tauri/src/operator/ceremony.rs` (+ tests)

**Interfaces :**
- Consumes : Tasks 5, 6, 7, 8.
- Produces : `EnrollmentGesture::Accept` servi, dans cet ordre :
  1. décoder la demande (`decode_request_file`) ; charger l'invitation ; refuser **avant tout toucher** une invitation inconnue, d'un autre `CA-PQ`, non `Issued` (consommée : message « Cette invitation est déjà consommée : la reprendre depuis la liste des invitations. »), ou expirée ; relais sans `CA-TLS` → refus nommant l'émission de `CA-TLS` ;
  2. publier le manifeste `EnrollmentAcceptance`, attendre `Continue` (annulation possible, rien n'est consommé) ;
  3. `open_key`, puis `signing::accept_request` (consommation puis émission), puis `store_accepted` ;
  4. si `gateway` est `None` : arrêt `Refusal::GatewayUnavailable`, artefacts = les deux feuilles (`<request_id>-client-cert.der` en base64, `<request_id>-client-pq-cert.json`) et `admission.txt` (ligne d'`admission_command_line`) ;
  5. sinon `admit_peer` ; échec → même arrêt et mêmes artefacts ;
  6. `gateway_material`, `build_draft` (endpoint saisi, négociation par `resolve_negotiation_endpoint`), `signing::sign_document` avec la même ouverture ; artefact `<requested_name>.orion` ; `Done`.
  Un échec après l'étape 3 est publié comme refus et l'invitation reste consommée.

- [ ] **Step 1 : tests rouges** (registre et coffre de test d'`astra-operator`, authentificateur factice si la cérémonie peut en recevoir un ; sinon les étapes 1, 2 et 4 testées par des fonctions extraites) : `a_request_for_an_unknown_invitation_is_refused_before_the_key`, `accepting_a_consumed_invitation_points_to_resume`, `cancelling_before_the_key_consumes_nothing`, `an_unreachable_gateway_stops_after_the_leaves` (artefacts : deux feuilles + `admission.txt`, fichier `.accepted.json` présent), `the_admission_line_names_the_written_leaves`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion operator` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** même commande → PASS.
- [ ] **Step 5 :** commit `feat(orion): accept an enrollment request, admit the peer and sign its document`.

### Task 10 : invitations, révocation, reprise, et l'écran Enrôlement

**Files :**
- Modify : `apps/orion/src-tauri/src/operator/ceremony.rs` (+ tests), `apps/orion/src-tauri/src/commands/ceremonies.rs`, `main.rs`, `apps/orion/src/api.ts`, `apps/orion/src/types.ts`
- Create : `apps/orion/src/views/astra/EnrollmentOperatorPanel.tsx` (+ test vitest)

**Interfaces :**
- Consumes : Tasks 5, 7, 8, 9.
- Produces :
  - `EnrollmentGesture::Resume` servi : relit `accepted(id)` (absent → refus « Cette invitation a été acceptée hors d'Orion : ses feuilles ne sont pas ici. »), reprend aux étapes 5–6 de la tâche 9 **sans réémettre** ; une clé est demandée pour signer le document.
  - Tauri : `operator_invitations() -> Vec<InvitationView>` avec `pub struct InvitationView { pub invitation_id: String, pub state: String /* label français */, pub not_after_unix: u64, pub requested_name: Option<String>, pub peer_admitted: Option<bool> /* None si gateway illisible */, pub resumable: bool }` ; `revoke_invitation(invitation_id: String)` (sans clé, `InvitationRegistry::revoke`).
  - Écran « Enrôlement » (maquette `enrolement.html`) : état du coffre en tête, « Inviter un poste… » (formulaire : nom, durée, réadmission ; champ fichier de feuille gateway affiché seulement si aucune gateway connectée), « Accepter une demande… » (champ fichier `.helios-request`, durée des feuilles, endpoint prérempli avec celui du profil connecté, routes et cible SSH facultatives), étapes de la cérémonie par `OperatorCeremonyPanel`, liste des invitations (état, échéance, pair admis, « Révoquer » si émise, « Reprendre » si `resumable` et pair ou document manquant), enregistrement de chaque artefact par lien de téléchargement comme `EnrollmentPanel.tsx`.

- [ ] **Step 1 : tests rouges** : Rust `a_resumed_enrollment_never_reissues_leaves` (le coffre de test ne voit aucune émission ; seul `sign_document` est appelé), `resuming_a_cli_acceptance_is_refused_with_a_reason`, `revoking_an_issued_invitation`; vitest `invite_form_limits_the_duration_to_24_hours`, `accept_prefills_the_endpoint_of_the_connected_profile`, `resume_is_offered_only_when_resumable`, `artifacts_are_offered_for_download`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion operator` et `npx vitest run src/views/astra` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** `-p orion`, `npx tsc --noEmit -p . && npx vitest run` → PASS.
- [ ] **Step 5 :** commit `feat(orion): the operator enrollment screen`.

### Task 11 : documentation

**Files :**
- Modify : `docs/security/OPERATOR-TOOLING.md` (§6 : parcours par Orion ; la CLI décrite comme transitoire), `docs/testing/MANUAL-TESTING.md` (« Enrôlement v5 de bout en bout » réécrit depuis Orion seul ; recette du lot 1 : vérifier une clé, état du coffre ; cas de reprise et de gateway injoignable ; constat du drapeau `admin` du poste opérateur), `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md` (gestes d'enrôlement dans l'IHM), `docs/ROADMAP.md` (F11 : « fusionné dans `main` le 27 octobre 2026, validation Windows à faire » ; F14 : lots 1 et 2 livrés sur la branche), la spec (rulings du plan ci-dessus).

- [ ] **Step 1 :** rédiger ; tout ce qui n'a pas été constaté sous Windows est écrit « à valider en recette ».
- [ ] **Step 2 :** `grep -rn "astra-signer enroll" docs --include=*.md | grep -v superpowers` → seules des mentions qui renvoient à Orion ou décrivent la transition.
- [ ] **Step 3 :** commit `docs: operator enrollment from Orion`.

---

## Lots suivants (esquisse, un plan chacun)

- **Lot 3 — coffre, credentials, domaine** : `init` (« Créer un domaine »), `enrol`, `remove` (jamais la dernière récupération), `rename`, `bindings`, `domain` (écriture), `issue-ca-tls` ; choix d'un autre chemin de coffre.
- **Lot 4 — approbations** : `approve` dans l'IHM ; suppression de `companion.rs`, `launch::spawn_astra_signer`, `EngineCommand::CompanionArguments` et du mode `orion` caché ; `authorize-issuer` ; mode hors ligne d'`approve-campaign` et `recover`.
- **Lot 5 — rotations et révocation** : `rotate-ca-pq`, `rotate-ca-tls`, `resume-rotation`, `promote-ca-tls`, `revoke` ; l'URL libre des rotations remplacée par `connected_gateway`.
- **Lot 6 — gateways** : `issue-gateway-bootstrap`, `sign-gateway-transition`, `sign-gateway-rollback`, `abort-gateway-transition`.
- **Lot 7 — retrait** : `tools/astra-signer`, `helios enroll document`, empaquetage, xtask, docs.
