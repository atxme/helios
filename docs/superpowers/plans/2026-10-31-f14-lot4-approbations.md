# F14 lot 4 — Approbations dans Orion — plan d'exécution

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Approuver depuis Orion, sans `astra-signer`, un renouvellement ordinaire (cérémonie déplacée du moteur vers l'IHM), une récupération ouverte sur un autre poste, et une délégation d'émetteur (`authorize-issuer`, en campagne et hors campagne) ; retirer le compagnon de renouvellement.

**Architecture:** `orion-core::certificate_approval` sépare la vérification (moteur) de l'assertion (IHM) par un `ApprovalMaterial` public et sérialisable ; le moteur garde la session, remet ce matériel puis contrôle et dépose l'approbation que l'IHM lui rend. La délégation d'émetteur vit dans un nouveau module `astra_operator::operations::issuer` (plan avant clé, ouverture du coffre restreinte au credential qui a approuvé), qu'Orion orchestre comme une cérémonie de plus (`operator/ceremony/issuer.rs`). L'IHM retire le compagnon de *Certificats* et ajoute à *Approbations* la récupération par identifiant et les deux blocs de délégation.

**Tech Stack:** Rust (aether, aether-fido, orion-core, orion-engine, astra-operator, Tauri 2), React + MUI + vitest.

**Spec:** `docs/superpowers/specs/2026-10-31-f14-lot4-approbations-design.md` (§6 et §7 tranchent les détails).

## Global Constraints

- Worktree `/home/christophe/helios-wt/f14-orion`, branche `feat/f14-lot4-approbations`. Ne jamais travailler dans `~/helios`.
- Compiler et tester uniquement par `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo …` ; jamais `CARGO_TARGET_DIR`, jamais `cargo clean`, ne tuer aucun processus.
- Un test qui attend des appuis fait `drop` de son émetteur (sinon il pend et bloque le cache partagé).
- IHM : `cd apps/orion && node_modules/.bin/tsc --noEmit -p . && npx vitest run` (jamais `npx tsc`).
- Aucune nouvelle dépendance externe.
- `scripts/deploy.sh` n'est pas modifié (décision de l'utilisateur).
- Pas d'`unwrap`/`expect` hors tests ; aucun TODO/FIXME ; identifiants, commentaires et tests en anglais ; messages de l'IHM et `docs/` en français.
- Aucun secret (PIN, secret de key-slot, `Opened`, clé `CA-PQ`, octets du coffre) journalisé, sérialisé ni envoyé à la WebView. L'assertion (`AstraRenewalApproval`) traverse l'IPC IHM → moteur mais n'est jamais journalisée. Le PIN ne traverse plus l'IPC.
- Aucun chemin de fichier ne passe de la WebView au processus Rust : seul le texte de la demande de délégation passe (borne 256 Kio).
- Les refus de cérémonie restent la classe fermée `Refusal`, sans texte ; la phrase française est dans `refusalSentence`.
- Fail-closed : tout refus prévisible est vérifié côté Rust avant la première clé, même quand l'IHM désactive le bouton.
- `cfg(windows)`, WebAuthn plateforme et `DialogOwner::Window` ne sont pas vérifiables sous WSL2 : le dire dans le rapport de tâche.
- Commits terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- **Une approbation rendue au moteur pour une autre demande** (autre opération, autre empreinte, ou après une relecture qui a remplacé la demande) : refusée sans dépôt, la demande vérifiée reste disponible. Test : Task 3 `an_approval_for_another_request_is_refused_and_nothing_is_submitted`.
- **Un échec de cérémonie côté IHM** (clé absente, annulation) : le bouton redevient actif, réessayer redonne le même matériel sans relire. Tests : Task 3 `the_material_can_be_handed_again_until_a_deposit`, Task 7 `a_failed_approval_can_be_retried_without_reading_again`.
- **Une demande de délégation substituée** (autre époque, autre clé PQ, autre CSR) : `DelegationRequestMismatch` avant toute clé. Test : Task 4 `a_substituted_request_is_refused_before_any_key`.
- **Une autre clé présentée au second dialogue** de la délégation en campagne : ne peut pas ouvrir le coffre (`KeyDeclined`), rien n'est signé. Test : Task 4 `only_the_approving_credential_can_open_the_vault`.
- **Un identifiant de récupération mal collé** (espaces, majuscules, 31 ou 33 caractères, non hexadécimal) : normalisé ou refusé dans le champ ; une récupération ouverte depuis *Approbations* n'appelle jamais la finalisation locale. Test : Task 8 `a_recovery_id_is_normalised_or_refused`, `a_remote_recovery_is_not_finished_here`.

---

### Task 1: Contrat de la cérémonie de délégation (aether)

**Files:**
- Modify: `crates/aether/src/certificates/operator_session.rs`

**Interfaces:**
- Produces (serde `snake_case`, comme l'existant) :
  - `Refusal::DelegationRequestInvalid`, `Refusal::DelegationRequestMismatch`, sans champ, insérées avant `Internal`.
  - `IssuerManifest` gagne, en gardant ses champs : `maximum_leaf_lifetime_secs: u64`, `pq_public_key_fingerprint: Fingerprint`, `tls_public_key_info_fingerprint: Fingerprint`, `campaign: Option<CampaignManifest>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`). Reste `deny_unknown_fields`. `AstraManifest::IssuerAuthorization` garde le genre `AuthorizeIssuer`.

- [ ] **Step 1: Write the failing tests** (dans le `mod tests` du fichier) : `the_delegation_refusals_spell_in_snake_case` (`"delegation_request_invalid"`, `"delegation_request_mismatch"`), `an_issuer_manifest_without_campaign_omits_it` (sérialisé sans clé `campaign`, relu à `None`), `an_issuer_manifest_refuses_unknown_fields`, `the_issuer_manifest_has_its_kind` (`AuthorizeIssuer`).
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether operator_session` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** le même test, puis `scripts/wsl-cargo clippy -p aether --all-targets --all-features -- -D warnings` → PASS.
- [ ] **Step 5: Commit** — `feat(aether): describe the issuer delegation the operator signs`

### Task 2: Matériel d'approbation et retrait de l'invocation du compagnon (orion-core)

**Files:**
- Modify: `crates/orion-core/src/certificate_approval.rs`
- Modify: `crates/orion-core/src/certificate_renewal/exchange.rs`, `crates/orion-core/src/certificate_renewal.rs`, `crates/orion-core/src/certificate_renewal/tests/gateway_exchange.rs` (retrait de `CompanionInvocation`, `companion_invocation`, `command_line`, du programme `astra-signer`)
- Modify: `crates/orion-core/src/certificate_actions.rs` (commentaires et textes qui renvoient au compagnon de renouvellement : dire qu'Orion approuve lui-même)
- Test: `mod tests` de `certificate_approval.rs`

**Interfaces:**
- Produces :
  - `pub struct ApprovalMaterial { pub request: Box<AstraCredentialApprovalRequest>, pub registry: Box<CredentialRegistry>, pub identity: DomainIdentity, pub service_key: MlDsa87PublicKey, pub service_key_epoch: u64, pub ca_pq: MlDsa87PublicKey, pub rp_id: String, pub active_generation: u64 }`, `Serialize + Deserialize + Clone` (s'appuyer sur la sérialisation existante des types ; pour un type qui n'en a pas, un champ base64 ou un `serde(with)` local). Que des objets publics.
  - `impl VerifiedApproval { pub fn material(&self) -> ApprovalMaterial; pub fn accepts(&self, approval: &AstraRenewalApproval) -> Result<(), ApprovalError> }` — `accepts` compare `operation_id`, `request_fingerprint` et `approval_request_fingerprint` (empreinte de la demande signée détenue) ; tout écart → `ApprovalError::ApprovalMismatch` (« l'approbation reçue ne répond pas à la demande vérifiée : rien n'est déposé »).
  - `impl ApprovalMaterial { pub fn approve(&self, key: &dyn aether_fido::authenticator::Authenticator, pin: &str, now_unix: u64) -> Result<AstraRenewalApproval, ApprovalError> }` — appelle `aether_fido::approve_renewal` avec `Some(self.active_generation)` (il re-vérifie tout avant la clé).
  - `VerifiedApproval::run` et `VerifiedApproval::needs_pin` disparaissent ; `transport()` reste.
  - `RenewalSession::companion_invocation` et `CompanionInvocation` disparaissent.

- [ ] **Step 1: Write the failing tests** : `the_material_carries_what_was_verified` (matériel de la demande de test existante : même `operation_id`, même RP ID épinglé, même génération active ; aller-retour serde identique), `an_approval_for_another_operation_is_not_accepted`, `an_approval_for_another_request_is_not_accepted` (empreinte de demande modifiée, puis empreinte de demande signée modifiée → `ApprovalMismatch`), `the_material_refuses_a_tampered_request_before_the_key` (`material.request` modifié après coup → `approve` échoue sans appeler la clé : une clé de test qui panique si on lui demande une assertion). S'appuyer sur les fabriques des tests `certificate_renewal/tests` pour la demande signée.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion-core --all-features certificate_approval` → FAIL.
- [ ] **Step 3: Implement** ; retirer l'invocation du compagnon et adapter `gateway_exchange.rs` (le test qui vérifiait la ligne de commande vérifie seulement l'état `AwaitingOperator`).
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-core --all-features`, `scripts/wsl-cargo clippy -p orion-core --all-targets --all-features -- -D warnings` → PASS. `grep -rn "CompanionInvocation\|companion_invocation" crates/orion-core` → vide.
- [ ] **Step 5: Commit** — `feat(orion-core): hand the approval material out instead of running the ceremony`

### Task 3: Le moteur remet le matériel et dépose l'approbation (orion-engine)

**Files:**
- Modify: `crates/orion-engine/src/command.rs`, `crates/orion-engine/src/service.rs`, `crates/orion-engine/src/service/certificates.rs`, `crates/orion-engine/src/view.rs`
- Test: `crates/orion-engine/src/command/tests.rs`, tests de `service/certificates.rs` (ou le module de tests existant du service)

**Interfaces:**
- Consumes: Task 2.
- Produces :
  - `EngineCommand::CertificateApprovalMaterial { name: String }` → `EngineReply::ApprovalMaterial(Box<ApprovalMaterial>)`.
  - `EngineCommand::SubmitCertificateApproval { name: String, approval: Box<AstraRenewalApproval> }` → `EngineReply::RenewalProgress`.
  - Retirés : `EngineCommand::ApproveCertificateRenewal`, `EngineCommand::CertificateApprovalNeedsPin`, `EngineCommand::CompanionArguments`, `EngineReply::CompanionArguments`, `COMPANION_PROGRAM`, `companion_arguments`.
  - `RenewalProgress::AwaitingOperator { operation_id }` (sans `companion_command`) ; `RenewalProgress::RecoveryAwaitingOperator { operation_id }` (sans `operator_command`).
  - `certificate_approval_material(name)` : refuse « lire d'abord la demande d'approbation » sans demande vérifiée ; **ne consomme pas** la demande.
  - `submit_certificate_approval(name, approval)` : `accepts` d'abord (écart → erreur, demande gardée) ; puis `take()` de la demande et `submit_approval` ; une seconde remise après ce `take` → « lire d'abord la demande d'approbation ».
  - Si le protocole moteur porte un numéro de version, l'incrémenter.

- [ ] **Step 1: Write the failing tests** : `command/tests.rs` : les deux nouvelles commandes font l'aller-retour serde, les trois anciennes ne se désérialisent plus ; service : `the_material_is_refused_without_a_verified_request`, `the_material_can_be_handed_again_until_a_deposit`, `an_approval_for_another_request_is_refused_and_nothing_is_submitted` (la demande vérifiée reste : le matériel se redonne), `a_deposited_approval_consumes_the_request` (seconde remise refusée). Utiliser la gateway simulée des tests existants de renouvellement du moteur ; à défaut, tester `submit_certificate_approval` sur une entrée en vol construite comme le font les tests existants de `certificate_approval_manifest`.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion-engine` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-engine`, `scripts/wsl-cargo clippy -p orion-engine --all-targets --all-features -- -D warnings` → PASS. (`-p orion` ne compile plus avant Task 5 : normal, le signaler.)
- [ ] **Step 5: Commit** — `feat(orion-engine): submit the approval the interface obtained`

### Task 4: Délégation d'émetteur (`astra_operator::operations::issuer`)

**Files:**
- Create: `crates/astra-operator/src/operations/issuer.rs`
- Modify: `crates/astra-operator/src/operations.rs` (`pub mod issuer;`), `crates/astra-operator/src/gestures.rs` (ouverture restreinte)
- Test: `crates/astra-operator/tests/issuer_delegation.rs` (helpers de `tests/support` et de `tests/vault_gestures.rs` : domaine à deux clés, relais complété avec `CA-TLS` ; demande de délégation bâtie comme `tests/signing.rs` l.221-260 ; campagne `issuer_delegation` bâtie comme les tests de `covers_issuer_delegation` dans `aether`)

**Interfaces:**
- Consumes: Task 1 (`IssuerManifest` étendu), `signing::{authorize_issuer, approve_campaign, CampaignApprovalSession}`, `handoff::{DomainHandoff, identity_of, verify_campaign_request}`, `origin::Origin`.
- Produces :
  - `pub const DELEGATION_DAYS: u64 = 30;` `pub const LEAF_DAYS: u64 = 90;` `pub const MAX_DELEGATION_REQUEST_BYTES: usize = 256 * 1024;` `pub const AUTHORIZATION_FILE: &str = "issuer-authorization.json";`
  - `pub enum IssuerRefusal { RequestInvalid, RequestMismatch, NotADelegation, OriginRecorded, CaTlsMissing, Vault(String) }`, `Display` en français, `std::error::Error`.
  - `pub struct IssuerPlan { pub request: IssuerDelegationRequest, pub bounds: DelegationBounds, pub manifest: IssuerManifest }`
  - `pub fn plan(vault_path: &Path, request_json: &str, campaign: Option<&AstraRotationCampaign>, now_unix: u64) -> Result<IssuerPlan, IssuerRefusal>` — sans rien écrire ni toucher de clé : coffre, relais, identité lisibles (sinon `Vault`) ; `CA-TLS` au relais (sinon `CaTlsMissing`) ; taille ≤ `MAX_DELEGATION_REQUEST_BYTES`, analyse, CSR décodable et clé PQ lisible (sinon `RequestInvalid`) ; avec campagne : famille `IssuerDelegation` (sinon `NotADelegation`) puis `covers_issuer_delegation` (sinon `RequestMismatch`) ; sans campagne : relais sans `astra_authority_url` (sinon `OriginRecorded`) ; bornes : délégation `now_unix` → `now_unix + DELEGATION_DAYS` jours, leaf `min(LEAF_DAYS jours, politique.maximum_leaf_lifetime_secs)` ; manifeste complet (`campaign` = `CampaignManifest { campaign, fingerprint }` en campagne).
  - `pub fn sign_offline(vault_path: &Path, plan: &IssuerPlan, opened: &Opened, now_unix: u64) -> anyhow::Result<AstraIssuerAuthorization>`.
  - `pub struct CampaignDelegation` (campagne vérifiée, client d'origine, jetons) avec `pub fn begin(vault_path: &Path, operation: Id16, now_unix: u64) -> anyhow::Result<CampaignDelegation>` (même résolution d'origine et même vérification que `operations::campaign::begin`, famille `IssuerDelegation` exigée, origine du relais seulement) et `pub fn campaign(&self) -> &AstraRotationCampaign`.
  - `impl CampaignDelegation { pub fn approve_and_sign(self, vault_path: &Path, plan: &IssuerPlan, key: &dyn Authenticator, pin: &str, now_unix: u64, progress: &mut dyn FnMut(RemoteState)) -> anyhow::Result<()> }` — assertion de campagne (une clé, `required_credentials` de la campagne attendu à 1, sinon erreur), puis `gestures::open_with_credential(key, &vault, &approving_credential_id, pin)`, `authorize_issuer`, dépôt du résultat avec `issuer_authorization` ; `progress(Prepared)` puis `progress(Deposited)`.
  - `pub fn open_with_credential(key: &dyn Authenticator, vault: &AuthorityVault, credential_id: &[u8], pin: &str) -> Result<Opened>` dans `gestures.rs` : `derive` avec une liste d'autorisation réduite à ce seul identifiant, puis `slot_for_credential` sur l'identifiant rendu, qui doit être le même.

- [ ] **Step 1: Write the failing tests** :
  - `an_offline_delegation_is_planned_and_signed` : relais sans origine, `plan(.., None, ..)` → manifeste sans campagne, `not_after - not_before == 30 j`, leaf 90 j ; `sign_offline` rend une autorisation qui vérifie sous le `CA-PQ` du relais.
  - `the_leaf_cap_follows_a_stricter_policy` : politique à 30 j de leaf → `maximum_leaf_lifetime_secs == 30 j` dans le manifeste et les bornes.
  - `a_file_that_is_not_a_delegation_request_is_refused` : `""`, `"{}"`, une feuille en JSON, `MAX_DELEGATION_REQUEST_BYTES + 1` octets → `RequestInvalid`.
  - `a_substituted_request_is_refused_before_any_key` : campagne pour la demande A, demande B (autre clé PQ ; puis autre époque) → `RequestMismatch`.
  - `a_campaign_of_another_family_is_refused` : campagne `orion_profile` → `NotADelegation`.
  - `an_offline_delegation_is_refused_when_the_relay_names_an_origin` → `OriginRecorded`.
  - `a_domain_without_ca_tls_cannot_delegate` → `CaTlsMissing`.
  - `only_the_approving_credential_can_open_the_vault` : `open_with_credential` avec la `FakeKey` de la seconde clé et l'identifiant de la première → erreur ; avec la première → `Opened`.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator --test issuer_delegation` → FAIL.
- [ ] **Step 3: Implement.** Le chemin réseau (`begin`, dépôt) n'a pas de test d'intégration, comme `operations::campaign` ; le dire dans un commentaire de module sur le modèle de « Où sont les tests ».
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p astra-operator --all-features`, `scripts/wsl-cargo clippy -p astra-operator --all-targets --all-features -- -D warnings` → PASS.
- [ ] **Step 5: Commit** — `feat(astra-operator): sign the issuer delegation, in a campaign or offline`

### Task 5: Orion — approbation de renouvellement dans l'IHM, retrait du compagnon de renouvellement

**Files:**
- Modify: `apps/orion/src-tauri/src/commands/certificates.rs`, `apps/orion/src-tauri/src/main.rs` (plugin `companion` retiré, commandes enregistrées), `apps/orion/src-tauri/capabilities/default.json`, `apps/orion/src-tauri/src/security_tests.rs`, `apps/orion/src-tauri/src/companion.rs` (doc : seul appelant, la rotation CA-TLS jusqu'au lot 5), `apps/orion/src-tauri/src/launch.rs` (doc de `spawn_astra_signer`)
- Test: `security_tests.rs`, tests du module `commands/certificates.rs` s'il en a

**Interfaces:**
- Consumes: Task 3.
- Produces (noms Tauri inchangés pour l'IHM) :
  - `approve_certificate_renewal(window, state, name, pin: Option<String>) -> Result<RenewalProgress, String>` : demande `CertificateApprovalMaterial` au moteur, puis sur `spawn_blocking` `connect_owned(transport(), owner)` (même calcul d'`owner` que `commands/ceremonies.rs::owner_window`, à partager) et `material.approve(key, pin, now)`, le PIN gardé en `Zeroizing<String>` ; enfin `SubmitCertificateApproval`. Une clé absente rend le texte de `ApprovalError::NoAuthenticator`.
  - `certificate_approval_needs_pin(window, name) -> Result<bool, String>` : sans moteur, `connect_owned(..)` puis `needs_pin()`.
  - Retirés : `launch_certificate_companion`, `companion_plugin`, la permission `companion` de `default.json`.

- [ ] **Step 1: Write the failing tests** : dans `security_tests.rs`, `no_capability_launches_the_renewal_companion` (aucune permission `companion` dans les capacités, aucune commande `launch_certificate_companion` dans le gestionnaire) ; adapter le test existant qui affirmait la permission étroite du compagnon.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion security` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion`, `scripts/wsl-cargo clippy -p orion --all-targets --all-features -- -D warnings` → PASS ; `grep -rn "launch_certificate_companion\|CompanionArguments\|companion_command\|operator_command\|CompanionInvocation" crates apps/orion/src-tauri` → vide ; `grep -rn "companion::launch" apps/orion/src-tauri/src` → seul `astra.rs`.
- [ ] **Step 5: Commit** — `feat(orion): approve a renewal from the interface process, without the companion`

### Task 6: Orion — cérémonie de délégation

**Files:**
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`IssuerGesture`, `begin_issuer` du gestionnaire de cérémonie)
- Create: `apps/orion/src-tauri/src/operator/ceremony/issuer.rs`, `apps/orion/src-tauri/src/operator/ceremony/issuer/tests.rs`
- Modify: `apps/orion/src-tauri/src/operator/ceremony.rs` (`mod issuer;`, bras `AuthorizeIssuer` du `match` de `run` : s'ouvre par son geste), `apps/orion/src-tauri/src/commands/ceremonies.rs` (`begin_issuer_ceremony`), `apps/orion/src-tauri/src/main.rs`

**Interfaces:**
- Consumes: Task 1, Task 4.
- Produces :
  - `IssuerGesture` (serde `tag = "gesture"`, `deny_unknown_fields`) : `{ "gesture": "authorize_issuer", "operation_id": "<32 hex>", "request": "<texte>" }` et `{ "gesture": "authorize_issuer_offline", "request": "<texte>" }` ; `validate()` refuse un texte vide ou de plus de `MAX_DELEGATION_REQUEST_BYTES` octets (« la demande de délégation est vide ou trop grande (256 Kio au plus) ») et un identifiant non hexadécimal ; `operation()` → `AuthorizeIssuer`.
  - `#[tauri::command] begin_issuer_ceremony(state, gesture: IssuerGesture) -> Result<OperatorStatus, String>`.
  - Correspondance des refus : `RequestInvalid` → `Refusal::DelegationRequestInvalid`, `RequestMismatch` → `DelegationRequestMismatch`, `NotADelegation` et `OriginRecorded` → `ManifestMismatch`, `CaTlsMissing` → `CaTlsMissing`, `Vault` → `VaultUnavailable` ; échec de `begin` (origine, vérification) → `HandoffMismatch` ; échec d'ouverture restreinte → `KeyDeclined` ; refus de l'autorité au dépôt → `AuthorityRefused { status: 0 }`.
  - En campagne : `begin` → `plan(.., Some(campaign), ..)` → `show(AstraManifest::IssuerAuthorization(..))` → une clé `KeyPurpose::ApproveCampaign` index 1 sur 1 → `approve_and_sign` (états distants publiés) → `done()`.
  - Hors campagne : `plan(.., None, ..)` → manifeste → `open_vault` (une clé, `KeyPurpose::OpenVault`) → `sign_offline` → `deposit(OperatorArtifact { file_name: AUTHORIZATION_FILE, contents: <JSON>, encoding: Text })` → `done()`.

- [ ] **Step 1: Write the failing tests** : dans `operator/mod.rs`, `an_issuer_gesture_carries_only_the_request_text` (deux formes, champ inconnu refusé, texte vide / 256 Kio + 1 / identifiant invalide refusés) ; dans `ceremony/issuer/tests.rs`, sur le modèle de `ceremony/vault/tests.rs` (forme hors campagne seulement, la forme en campagne exige l'origine) : `a_wrong_request_is_refused_before_any_key` (`DelegationRequestInvalid`, aucune clé demandée), `an_offline_delegation_is_refused_when_the_relay_names_an_origin` (`ManifestMismatch`, aucune clé demandée), `an_offline_delegation_deposits_the_authorization` (un artefact `issuer-authorization.json`, statut final `done`), `refusals_of_the_delegation_are_named` (les correspondances ci-dessus).
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion operator` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion`, `scripts/wsl-cargo clippy -p orion --all-targets --all-features -- -D warnings` → PASS.
- [ ] **Step 5: Commit** — `feat(orion): authorize Astra's issuer as an operator ceremony`

### Task 7: IHM — *Certificats* sans compagnon

**Files:**
- Modify: `apps/orion/src/api.ts`, `apps/orion/src/types.ts`, `apps/orion/src/views/CertificatesView.tsx`
- Test: `apps/orion/src/views/CertificatesView.test.tsx`

**Interfaces:**
- Consumes: Task 3 (`RenewalProgress` sans `companion_command` ni `operator_command`), Task 5.
- Produces (copie fixée) :
  - Retirés : `launchCertificateCompanion`, `CompanionLaunch`, le lancement automatique, « Relancer le compagnon », les alertes « Compagnon lancé… » et « Lancement du compagnon impossible… », la ligne « compagnon ».
  - `awaiting_operator` : le manifeste est lu à l'apparition de l'étape (une fois par `operation_id`), puis `needsPin` ; pendant la lecture « Lecture de la demande… » ; après un échec, l'erreur et « Relire la demande ». Un seul bouton « Approuver avec la clé » ; après un échec de l'approbation, le manifeste reste affiché et le bouton redevient actif.
  - Repli d'un renouvellement : « La clé est sur un autre poste ? » déplie : « Cette approbation se fait sur ce poste : la gateway n'accepte la réponse que du poste qui a demandé le renouvellement. Branchez ici la clé d'un opérateur. »
  - Repli d'une récupération : déplie l'identifiant (ligne « opération », copiable, déjà présente) et : « Sur le poste de l'opérateur : Astra › Approbations › « Approuver une récupération », avec cet identifiant. Puis relancez « Récupérer le certificat expiré » ici. »

- [ ] **Step 1: Write the failing tests** : `the_request_is_read_when_an_operator_is_awaited` (`certificateApprovalManifest` appelé sans clic), `no_companion_is_launched` (aucune invocation `plugin:companion|…`, pas de texte « compagnon »), `a_failed_approval_can_be_retried_without_reading_again` (`approveCertificateRenewal` rejette puis réussit ; `certificateApprovalManifest` appelé une seule fois), `the_other_workstation_note_names_no_command` (renouvellement et récupération : textes ci-dessus, pas de `astra-signer`). Adapter les tests existants qui attendaient le compagnon.
- [ ] **Step 2: Run** `cd apps/orion && npx vitest run src/views/CertificatesView.test.tsx` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cd apps/orion && node_modules/.bin/tsc --noEmit -p . && npx vitest run` → PASS.
- [ ] **Step 5: Commit** — `feat(orion-ui): approve a renewal without the companion`

### Task 8: IHM — *Approbations* : récupération à distance et délégation

**Files:**
- Modify: `apps/orion/src/api.ts`, `apps/orion/src/types.ts`, `apps/orion/src/views/AstraView.tsx`, `apps/orion/src/views/OperatorCeremony.tsx`
- Create (si `AstraView.tsx` grossit trop) : `apps/orion/src/views/astra/ApprovalsPanel.tsx`
- Test: `apps/orion/src/views/AstraView.test.tsx` (ou `astra/ApprovalsPanel.test.tsx`), `apps/orion/src/views/OperatorCeremony.refusals.test.ts`, `apps/orion/src/views/OperatorCeremony.rows.test.ts`

**Interfaces:**
- Consumes: Task 1 (manifeste et refus en TS), Task 6 (`beginIssuerCeremony(gesture)` → `plugin` / commande `begin_issuer_ceremony`), `readFileText.ts` (borne 256 Kio), aperçu du domaine (`astra_authority_url`).
- Produces (copie fixée) :
  - Portées ouvrables : `orion_profile`, `orion_device`, `fleet_leafs`, `full_certificate_chain` (campagne ordinaire) et `issuer_delegation` (délégation).
  - Carte `issuer_delegation` : « Ouvrir la cérémonie » ouvre le choix du fichier « Choisir la demande de délégation… » ; le texte lu part dans `{ gesture: 'authorize_issuer', operation_id, request }`. Fichier illisible ou trop grand : « Ce fichier est illisible ou trop grand (256 Kio au plus). », aucune cérémonie.
  - Bloc « Approuver une récupération » : champ « Identifiant d'opération », bouton « Ouvrir la cérémonie » actif seulement pour 32 caractères hexadécimaux après `trim()` et passage en minuscules (valeur normalisée envoyée) ; ouvre `beginOperatorCeremony({ kind: 'recover_identity', operation_id })`. Une telle cérémonie n'appelle jamais la finalisation locale (`resume_certificate_recovery`) ; son état final affiche « Récupération approuvée. Le poste concerné reprend de son côté. »
  - Bloc « Délégation sans campagne » : si `astra_authority_url` est absent de l'aperçu, avertissement « Rien ne rattache ce fichier à Astra : il vaut ce que vaut son transport. À réserver à un domaine sans origine joignable. » et bouton « Signer une délégation sans campagne… » (fichier → `{ gesture: 'authorize_issuer_offline', request }`) ; sinon « Ce domaine a une origine Astra : une délégation passe par une campagne (`astra issuer request --reason --requested-by` sur l'hôte d'Astra). »
  - `OperatorCeremony` : titre « Autoriser l'émetteur d'Astra », action « Autoriser avec la clé » ; lignes : Domaine, Époque de l'émetteur, Valide du / jusqu'au, Leaf au plus (jours), Usages, Clé PQ (empreinte), Clé TLS (empreinte), Demande (empreinte) ; puis, en campagne, Campagne, Motif, Demandée par, Empreinte de campagne.
  - `refusalSentence` : `delegation_request_invalid` → « Ce fichier n'est pas une demande de délégation lisible. Rien n'a été signé. » ; `delegation_request_mismatch` → « La campagne ne nomme pas cette demande : époque ou clé substituée. Rien n'a été signé. »
  - Fin : en campagne « Délégation enregistrée par Astra. Redémarrer Astra pour qu'il émette sous elle. » ; hors campagne, `ArtifactDownloads` puis « À installer sur l'hôte d'Astra : astra issuer install --authorization <fichier>. »

- [ ] **Step 1: Write the failing tests** : `a_recovery_id_is_normalised_or_refused` (« ␠ABCDEF…(32)␠ » → envoyé en minuscules ; 31, 33 caractères, `g` → bouton inactif), `a_remote_recovery_is_not_finished_here` (cérémonie `recover_identity` ouverte depuis le champ, statut `done` → aucun appel `resumeCertificateRecovery`, phrase finale), `an_issuer_campaign_asks_for_the_request_file` (le texte du fichier part dans le geste, aucun chemin), `the_offline_delegation_is_offered_only_without_an_origin`, `a_full_chain_campaign_can_be_opened`, `the_delegation_manifest_lists_what_is_signed` (lignes, avec et sans campagne), `the_delegation_refusals_have_their_sentences`.
- [ ] **Step 2: Run** `cd apps/orion && npx vitest run src/views` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cd apps/orion && node_modules/.bin/tsc --noEmit -p . && npx vitest run` → PASS.
- [ ] **Step 5: Commit** — `feat(orion-ui): approve recoveries and delegations from the approvals tab`

### Task 9: Documentation et régression complète

**Files:**
- Modify: `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md` (approbation ordinaire dans l'IHM non élevée ; plus de compagnon de renouvellement ; récupération et délégation depuis Orion ; `IssuerManifest` étendu ; rotation CA-TLS seule sur `astra-signer` jusqu'au lot 5 ; `approve-campaign` hors ligne non porté et pourquoi)
- Modify: `docs/security/OPERATOR-TOOLING.md` (mêmes points, parcours par Orion)
- Modify: `docs/specification/ROTATION-CERTIFICATS.md` (passages qui décrivent Orion lançant le compagnon ou affichant `astra-signer recover` / `approve` : Orion approuve lui-même ; la délégation hors campagne n'est offerte que sans origine)
- Modify: `docs/RENOUVELLEMENT-CERTIFICATS.md` (parcours opérateur : Orion d'abord, `astra-signer` transitoire)
- Modify: `docs/testing/MANUAL-TESTING.md` : section « E. Lot 4 » — renouvellement approuvé depuis *Certificats* sous Windows (dialogue au-dessus de la fenêtre, pas de champ PIN), échec puis nouvel essai, récupération approuvée depuis un second poste, délégation en campagne puis redémarrage d'Astra, délégation hors campagne sur un domaine sans origine ; tout est « à valider en recette »
- Modify: `docs/ROADMAP.md` (F14 : lot 4 livré sur la branche, validation Windows à faire)

- [ ] **Step 1: Rédiger.**
- [ ] **Step 2: Vérifier** `grep -rn "astra-signer approve\b\|astra-signer recover\|astra-signer authorize-issuer" docs --include=*.md | grep -v superpowers` → seules des mentions qui renvoient à Orion ou décrivent la transition.
- [ ] **Step 3: Régression** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh > <espace SDD>/regression.log 2>&1` en arrière-plan → exit 0, seuls les « 7 allowed warnings » de cargo audit.
- [ ] **Step 4: Commit** — `docs: approvals from Orion (F14 lot 4)`
