# F14 lot 5b : les rotations dans Orion — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** un opérateur sans terminal renouvelle ses postes, remplace une CA, termine la rotation et re-délègue l'émetteur depuis l'onglet Rotations d'Orion.

**Architecture:** Astra et `heliosd` gagnent peu de surface, derrière la porte du 5a : ouverture de délégation par le tunnel, lecture `operator/status`, écriture `operator/vault-copy`, installation CA TLS, et adoption en mémoire sans redémarrage. La logique de cérémonie et le journal de reprise descendent dans `astra-operator`, testés avec de fausses clés et un faux distant. Orion n'y ajoute que les touchers et l'écran.

**Tech Stack:** Rust (axum, reqwest bloquant dans le fil de cérémonie), Tauri, React/MUI, Vitest.

**Spec:** `docs/superpowers/specs/2026-11-04-f14-lot5b-rotations-design.md`. La lire avant chaque tâche, en particulier §5.

## Global Constraints

- Worktree `/home/christophe/helios-wt/f14-lot5b`, branche `feat/f14-lot5b-rotations`. Jamais d'édition directe sur `main`.
- Compilation par `scripts/wsl-cargo` uniquement, `CARGO_BUILD_JOBS=2`, `RUST_TEST_THREADS=2` ; jamais de `target/` de worktree ni de `CARGO_TARGET_DIR`.
- Commentaires et identifiants en anglais ; messages de console, IHM et `docs/` en français.
- Textes d'écran courts et neutres : libellés, pas de phrases, pas de « tu ». Exemples fixés : « Prérequis », « Clé 2 : toucher la clé », « Fin de rotation le 4 déc. ».
- Aucun secret, PIN ni clé dans la WebView. Une `Opened` ne quitte pas le fil de cérémonie, n'est ni journalisée ni sérialisée.
- Fenêtre de campagne ≤ 300 s, une opération vivante par famille, deux clés distinctes : inchangés.
- Bornes reprises du 5a : motif ≤ 1024 caractères, demandeur ≤ 256, pas de Cc/Cf/U+2028-9.
- Durées par défaut : préparation 7 jours (minimum 1), recouvrement 30 jours, validité CA TLS 1825 jours.
- Commits conventionnels, finis par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Fusion par `python3 scripts/version.py merge <branche>`, hors de ce plan, sur demande de l'utilisateur.
- `allowed` n'a pas de joker : toute nouvelle variante de porte décide pour chaque connecteur.

## Review Focus

1. **Une troisième clé enrôlée répond à l'approbation** : refus avec nouvel essai, les deux validations restent acquises. Test : Task 8.
2. **Tunnel coupé entre l'acceptation d'Astra et l'installation** : à la remontée, reprise seule et sans clé, jusqu'à la gateway. Test : Task 10.
3. **Disque plein ou arrêt à l'écriture du journal** : rien n'est déposé, le coffre n'a pas bougé, aucun état à moitié écrit au redémarrage. Test : Task 7.
4. **Campagne expirée entre le premier et le second toucher d'approbation** : rien n'est signé, pas de journal, écran « Campagne expirée ». Test : Task 8.
5. **Copie plus ancienne envoyée par un second poste administrateur** : refus si `credential_registry_epoch` recule ; pour le coffre, copie précédente gardée et prérequis « Ancienne » sur l'autre poste. Test : Task 6.

---

## Fichiers

| Zone | Fichiers |
| --- | --- |
| Contrats | `crates/aether/src/certificates/transport.rs`, `operator_session.rs`, `crates/astra-channel/src/authority_routes.rs`, `authority_client.rs` |
| Astra | `crates/astra/src/door/{mod,vault_copy,tests}.rs`, `service.rs`, `issuer.rs`, `operator.rs`, `daemon.rs`, `registry/transitions.rs`, `signing.rs`, `renewal/{stage,approval,companion}.rs` |
| Gateway | `crates/helios-api/src/certificates/{operator_relay,gateway_identity}.rs`, `crates/helios-api/src/lib.rs`, `crates/heliosd/src/astra_channel.rs`, `crates/heliosd/src/certificates/gateway_identity.rs` |
| Opérateur | créés : `crates/astra-operator/src/rotation_journal.rs`, `operations/rotation.rs` ; modifié : `tunnel.rs` ; supprimé : `orion.rs` |
| Orion | créés : `src-tauri/src/operator/ceremony/rotation.rs`, `crates/orion-core/src/operator_rotations.rs`, `src/views/astra/RotationsPanel.tsx`, `rotationRows.ts` et leurs tests ; supprimés : `src-tauri/src/companion.rs`, `astra.rs` |

---

### Task 1: Suivis du 5a : `pending` borné et 429

**Files:**
- Modify: `crates/astra/src/signing.rs:241`, `crates/aether/src/certificates/transport.rs:775`, `crates/heliosd/src/astra_channel.rs:603-630`, `crates/helios-api/src/certificates/operator_relay.rs`
- Test: `crates/astra/src/signing.rs` (module de tests), `crates/heliosd/src/astra_channel.rs`

**Interfaces:**
- Produces: `TrustUpdateRefusal::Throttled`, répondu `429` ; côté Orion, `refusal.status == 429` s'affiche « Trop d'opérations en attente » (Task 12).

- [ ] **Step 1: Écrire les tests en échec**

```rust
#[test] fn pending_list_of_64_longest_operations_fits_the_answer_bound() {
    // 64 operations, reason 1024 chars, requested_by 256 chars (multi-byte included)
    let body = serde_json::to_vec(&list).unwrap();
    assert!(body.len() <= astra_channel::MAX_OPERATOR_ANSWER_BYTES);
}
#[test] fn pending_cuts_reason_and_requester_at_128_chars_with_an_ellipsis() {
    assert_eq!(item.reason.chars().count(), 129);
    assert!(item.reason.ends_with('…'));
    assert_eq!(short.reason, "motif court");
}
#[test] fn relayed_429_is_throttled_and_not_internal() {
    assert_eq!(refuse_status(429), TrustUpdateRefusal::Throttled);
    assert_eq!(TrustUpdateRefusal::Throttled.status(), StatusCode::TOO_MANY_REQUESTS);
}
```

- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra pending_ && scripts/wsl-cargo test -p heliosd relayed_429` : FAIL.
- [ ] **Step 3: Implémenter** : couper en `char` à 128 dans `pending()` avec « … » si coupé ; ajouter la variante, l'arm `429` dans le `match status.as_u16()`, et remplacer « relayed renewal » par un message opérateur sur ces routes.
- [ ] **Step 4: Vérifier** — mêmes commandes : PASS.
- [ ] **Step 5: Commit** — `fix(astra): bound the pending list and relay 429 (F14 lot 5b)`

### Task 2: Installation CA TLS sur la gateway

**Files:**
- Modify: `crates/helios-api/src/certificates/gateway_identity.rs:101-130,222`, `crates/helios-api/src/lib.rs:302`, `crates/heliosd/src/certificates/gateway_identity.rs:141`
- Test: `crates/helios-api/src/security_tests.rs`, tests de `heliosd` à côté de `install_ca_transition`

**Interfaces:**
- Produces: route `POST /api/certificates/client-tls-ca-transition` (groupe `require_admin`) ; `GatewayIdentityHandler::install_client_tls_ca_transition(&self, Box<ClientTlsCaTransition>) -> Result<ClientTlsCaDecisionView, GatewayActionRefusal>` ; `ClientTlsCaDecisionView { ca_tls_epoch, next_ca_tls_epoch, next_ca_tls_fingerprint: String, activation_at, not_after, already_present }`.

- [ ] **Step 1: Écrire les tests en échec** : `client_tls_ca_route_refuses_a_non_admin` (403) ; `..._refuses_an_unreadable_body` (400/422) ; `..._refuses_a_transition_badly_signed` (refus, registre inchangé) ; `..._replay_answers_already_present` (`already_present == true`).
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p helios-api client_tls_ca_route`, `-p heliosd client_tls_ca` : FAIL.
- [ ] **Step 3: Implémenter** sur le modèle de `install_ca_transition`, sous le registre du démon, par `registry.install_client_tls_ca_transition(&transition, now)`.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(heliosd): install a CA-TLS transition over the admin route (F14 lot 5b)`

### Task 3: Astra adopte en mémoire délégation et credentials

**Files:**
- Modify: `crates/astra/src/service.rs:234,260-277,300,803,985-1020`, `crates/astra/src/issuer.rs`, `crates/astra/src/daemon.rs:110-133,224,365,416-470`, `crates/astra/src/renewal/{stage.rs:16,approval.rs:102,companion.rs:75,159}`, `crates/astra/src/door/{open.rs:204,write.rs:84}`, les fixtures qui construisent `AstraService` (`door/tests.rs`, `service/tests.rs`, `recovery/tests/workflow.rs`, `renewal/workflow_tests.rs`)
- Test: `crates/astra/src/renewal/workflow_tests.rs`, `crates/astra/src/door/tests.rs`

**Interfaces:**
- Produces, sur `AstraService` :
  - `issuer: RwLock<Option<Arc<DelegatedIssuer>>>`, `fn issuer(&self) -> Option<Arc<DelegatedIssuer>>`
  - `approval_credentials: RwLock<Arc<ApprovalCredentials>>`, `struct ApprovalCredentials { ids: Vec<Vec<u8>>, epoch: u64, registry: Option<Box<CredentialRegistry>> }`, `fn approval_credentials(&self) -> Arc<ApprovalCredentials>`
  - `encrypted_vault: RwLock<Option<Arc<Vec<u8>>>>`, `fn encrypted_vault(&self) -> Option<Arc<Vec<u8>>>`
- Produces, dans la bibliothèque : `astra::issuer::load_from_registry(state_dir: &Path, registry: &AstraRegistry) -> anyhow::Result<Option<DelegatedIssuer>>` (déplacé de `daemon.rs`, contrôles inchangés) ; `AstraService::adopt_recorded_issuer(&self, registry: &AstraRegistry) -> bool`.
- `std::sync::RwLock`, verrou jamais tenu à travers un `.await`.

- [ ] **Step 1: Écrire les tests en échec**
  - `a_campaign_delegation_issues_without_a_restart` : dépôt d'une délégation, puis une émission porte `issuer_epoch` nouveau, même `AstraService`.
  - `a_failed_adoption_keeps_the_issuer_in_service` : fichiers de clés retirés après `adopt` ; l'ancien émetteur sert encore, `adopt_recorded_issuer` rend `false`.
  - `a_console_install_is_adopted_too` : `DoorRequest::IssuerInstall`, puis `service.issuer()` à la nouvelle époque.
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra --all-targets issues_without_a_restart` : FAIL (compilation).
- [ ] **Step 3: Implémenter** : remplacer les champs et leurs lectures ; appeler `adopt_recorded_issuer` après `issuer::adopt` (service.rs) et après `write::issuer_install` ; le journal dit « delegation adopted », ou l'erreur si l'adoption échoue.
- [ ] **Step 4: Vérifier** — `scripts/wsl-cargo test -p astra --all-targets` : PASS.
- [ ] **Step 5: Commit** — `feat(astra): adopt a delegation without a restart (F14 lot 5b)`

### Task 4: Le document de credentials suit la promotion CA-PQ

**Files:**
- Modify: `crates/astra/src/registry/transitions.rs:351-395`, `crates/astra/src/registry.rs`, `crates/astra/src/daemon.rs:317-331,365`
- Test: `crates/astra/src/registry/` (tests de transitions), `crates/astra/src/daemon.rs`

**Interfaces:**
- Consumes: Task 3 (`approval_credentials`).
- Produces: `AstraState.promoted_credentials: Option<Box<CredentialRegistry>>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`) ; `AstraRegistry::take_promoted_credentials(&mut self) -> Result<Option<Box<CredentialRegistry>>, RegistryError>` ; `daemon::adopt_promoted_credentials(service: &AstraService) -> anyhow::Result<()>`.

- [ ] **Step 1: Écrire les tests en échec**
  - `promotion_keeps_the_rotation_credentials_for_adoption` : à `not_after`, `forget_expired_transitions` conserve le document de la transition, dans la même écriture.
  - `adoption_survives_a_restart_between_promotion_and_file_write` : registre rechargé, le document est encore pris.
  - `the_overlap_keeps_serving_the_outgoing_document` : avant `not_after`, `service.approval_credentials().epoch` ne change pas.
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra promotion_keeps` : FAIL.
- [ ] **Step 3: Implémenter** : capturer `credential_registry` de la transition consommée ; dans la passe du démon, écrire atomiquement `CREDENTIALS_FILE`, remplacer en mémoire, puis `take_promoted_credentials` (ordre rejouable). Au démarrage, adopter d'abord un document en attente.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(astra): adopt the rotated credentials at not_after (F14 lot 5b)`

### Task 5: Délégation par le tunnel et lecture `operator/status`

**Files:**
- Modify: `crates/aether/src/certificates/transport.rs:1157,1245`, `crates/astra-channel/src/authority_routes.rs`, `authority_client.rs`, `crates/astra/src/door/mod.rs:205,529`, `crates/astra/src/operator.rs:58,223`, `crates/helios-api/src/certificates/operator_relay.rs`, `crates/helios-api/src/lib.rs:314`, `crates/heliosd/src/astra_channel.rs`
- Test: `crates/astra/src/door/tests.rs:222`, `crates/helios-api/src/security_tests.rs`

**Interfaces:**
- Produces:
  - `OperatorOpenAction::IssuerDelegation` ; `OperatorOpened.delegation_request: Option<String>` (`serde default`, omis si absent).
  - `allowed` : `IssuerDelegation => (true, true)`. Le reste de la table ne bouge pas.
  - `OPERATOR_STATUS_ROUTE = "/internal/v1/operator/status"` ; `OperatorCampaignRelay::status(&self, operator) -> Result<OperatorAuthorityStatus, TrustUpdateRefusal>` ; `GET /api/certificates/operator/status`, admin.
  - ```rust
    pub struct OperatorAuthorityStatus {
        pub ca_epoch: u64,
        pub ca_fingerprint: Fingerprint,
        pub next_ca_fingerprint: Option<Fingerprint>,
        pub ca_tls_epoch: u64,
        pub ca_tls_fingerprint: Option<Fingerprint>,
        pub next_ca_tls_fingerprint: Option<Fingerprint>,
        pub issuer: Option<OperatorIssuerStatus>,
        pub vault_copy_fingerprint: Option<Fingerprint>,
        pub credential_registry_epoch: u64,
    }
    pub struct OperatorIssuerStatus {
        pub recorded_epoch: u64,
        pub serving_epoch: Option<u64>,
        pub ca_epoch: u64,
        pub ca_tls_epoch: u64,
        pub not_after: u64,
    }
    ```

- [ ] **Step 1: Écrire les tests en échec**
  - Mettre à jour la table de `door/tests.rs:222` ; `tunnel_may_open_a_delegation_and_gets_its_request` : `opened.delegation_request` se parse en `IssuerDelegationRequest`, même époque que la cible.
  - `tunnel_still_cannot_request_or_install_a_delegation` : `IssuerRequest`, `IssuerInstall` → `NotAllowedHere`.
  - `a_second_tunnel_delegation_is_already_open_and_keeps_the_keys` : clés inchangées sur disque.
  - `status_route_refuses_a_non_admin` (403) ; `status_reports_a_rotation_in_flight_and_the_serving_issuer` ; `status_carries_nothing_secret` (sérialisation sans token ni clé privée).
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra tunnel_may_open`, `-p helios-api status_route` : FAIL.
- [ ] **Step 3: Implémenter** : l'arm `DoorOutcome::IssuerRequested { request, opened: Some(opened) }` de `operator.rs::open` place `request` dans la réponse ; `status` lit le registre et les trois valeurs du service.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(astra): open a delegation and read the authority over the tunnel (F14 lot 5b)`

### Task 6: Copie du coffre par le tunnel

**Files:**
- Create: `crates/astra/src/door/vault_copy.rs`
- Modify: `crates/astra/src/door/mod.rs`, `crates/astra/src/operator.rs`, `crates/astra-channel/src/{authority_routes,authority_client}.rs`, `crates/helios-api/src/certificates/operator_relay.rs`, `crates/helios-api/src/lib.rs`, `crates/heliosd/src/astra_channel.rs`
- Test: `crates/astra/src/door/tests.rs`, `crates/helios-api/src/security_tests.rs`

**Interfaces:**
- Consumes: Task 3 (`encrypted_vault`, `approval_credentials`).
- Produces:
  - `DoorRequest::VaultCopy { vault: Vec<u8>, credentials: Option<Box<CredentialRegistry>> }`, action `"vault_copy"`, `allowed => (false, true)`.
  - `DoorOutcome::VaultCopied { fingerprint: Fingerprint, credential_registry_epoch: u64 }`.
  - `DoorRefusal::VaultCopyRefused` (classe `Refused`), `DoorRefusal::CredentialsRollback` (classe `Refused`), `DoorRefusal::CredentialsDuringRotation` (classe `Refused`).
  - `MAX_OPERATOR_VAULT_COPY_BYTES: usize = 256 * 1024` ; `OPERATOR_VAULT_COPY_ROUTE = "/internal/v1/operator/vault-copy"` ; `OperatorVaultCopy { vault_base64: String, credentials: Option<Box<CredentialRegistry>> }` ; `POST /api/certificates/operator/vault-copy`, admin, limite de corps à cette borne ; réponse `OperatorVaultCopied { fingerprint, credential_registry_epoch }`.
  - Fichier gardé : `authority-vault.previous.json`, à côté de `VAULT_FILE`.

- [ ] **Step 1: Écrire les tests en échec**
  - `vault_copy_is_available_to_the_door_at_once` : sans copie, `TrustAuthorities` → `NoVault` ; après l'envoi, l'ouverture passe, même `AstraService`.
  - `vault_copy_keeps_the_previous_one` : le fichier `.previous` a les octets d'avant.
  - `vault_copy_refuses_another_domain_and_garbage` : `trust_domain_id` autre, JSON illisible → `VaultCopyRefused`, fichier intact.
  - `an_older_credentials_document_is_refused` (Review Focus 5) : époque inférieure → `CredentialsRollback`, coffre non écrit.
  - `credentials_are_refused_while_a_ca_pq_rotation_is_in_flight` → `CredentialsDuringRotation` ; le coffre seul passe.
  - `console_cannot_send_a_vault_copy` → `NotAllowedHere`.
  - `vault_copy_route_refuses_a_non_admin_and_an_oversized_body` (403, 413).
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra vault_copy`, `-p helios-api vault_copy_route` : FAIL.
- [ ] **Step 3: Implémenter** : sous `volume_writes`, contrôle structurel par un `struct { format_version: u16, trust_domain_id: TrustDomainId }` (pas de dépendance à `astra-operator`), renommage de l'ancienne copie, écriture atomique, remplacement en mémoire ; journaliser empreinte et opérateur, jamais le contenu. Le contrôle `NoVault` de `open.rs` reste.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(astra): receive the vault copy over the tunnel (F14 lot 5b)`

### Task 7: Journal de rotation

**Files:**
- Create: `crates/astra-operator/src/rotation_journal.rs`
- Modify: `crates/astra-operator/src/lib.rs`, `crates/astra-operator/src/tunnel.rs`, `tools/astra-signer/src/commands/{ca_pq_rotation,ca_tls_rotation}.rs`
- Test: `crates/astra-operator/src/rotation_journal.rs`

**Interfaces:**
- Consumes: Tasks 2, 5, 6 (routes, `OperatorAuthorityStatus`).
- Produces:
  ```rust
  pub const ROTATION_JOURNAL_FILE: &str = "astra-rotation-journal.json";
  pub enum RotationKind { CaPq, CaTls }
  pub enum JournalStage { Signed, Accepted, Applied, Installed }
  pub enum RotationTransition { CaPq(Box<CaTransition>), CaTls(Box<ClientTlsCaTransition>) }
  pub struct NextLocal { pub vault: AuthorityVault, pub credentials: Option<CredentialRegistry>, pub handoff: DomainHandoff }
  pub struct RotationJournal {
      pub format_version: u16, pub kind: RotationKind, pub stage: JournalStage,
      pub operation_id: Id16, pub result_token: String, pub result: AstraSignerResult,
      pub transition: RotationTransition, pub next: Option<NextLocal>,
      pub next_anchor_fingerprint: Fingerprint, pub campaign_expires_at: u64,
      pub activation_at: u64, pub not_after: u64, pub signed_at: u64,
  }
  pub fn path_beside(vault_path: &Path) -> PathBuf;
  pub fn load(path: &Path) -> Result<Option<RotationJournal>>;
  pub fn save(path: &Path, journal: &RotationJournal) -> Result<()>; // atomic, private permissions
  pub fn clear(path: &Path) -> Result<()>;
  pub fn apply_local(vault_path: &Path, journal: &mut RotationJournal) -> Result<()>;
  pub fn adopt_legacy(vault_path: &Path) -> Result<Option<RotationJournal>>;

  pub struct ResumeFacts { pub now: u64, pub deposit_refused: bool,
      pub authority: Option<OperatorAuthorityStatus>, pub gateway_next: Option<Fingerprint> }
  pub enum ResumeStep { Deposit, ReadAuthority, ApplyLocal, Install, SendVaultCopy,
      Finished, Discard, DomainConflict, InstallDeadlinePassed }
  pub fn next_step(journal: &RotationJournal, facts: &ResumeFacts) -> ResumeStep;
  ```
- Produces, sur `Tunnel` : `open_campaign(&self, &OperatorOpenRequest) -> Result<OperatorOpened>`, `authority_status(&self) -> Result<OperatorAuthorityStatus>`, `send_vault_copy(&self, &OperatorVaultCopy) -> Result<OperatorVaultCopied>`, `install_ca_transition(&self, &CaTransition) -> Result<()>`, `install_client_tls_ca_transition(&self, &ClientTlsCaTransition) -> Result<()>`, `gateway_next_anchor(&self, RotationKind) -> Result<Option<Fingerprint>>`.

- [ ] **Step 1: Écrire les tests en échec** (`next_step`, table du spec §5.4)
  - `signed_with_a_live_campaign_replays_the_deposit` → `Deposit`.
  - `signed_refused_or_dead_reads_the_authority` : `campaign_expires_at` passé ou `deposit_refused`, sans `authority` → `ReadAuthority`.
  - `dead_and_accepted_applies` : `next_*_fingerprint` **ou** fingerprint courant égal au journal → `ApplyLocal` (réponse perdue).
  - `dead_and_nothing_in_flight_discards` → `Discard`.
  - `dead_and_another_rotation_in_flight_conflicts` → `DomainConflict`.
  - `applied_past_activation_and_not_on_the_gateway_is_a_dead_end` → `InstallDeadlinePassed` ; `applied_past_activation_but_present_on_the_gateway_moves_on` → `SendVaultCopy`.
  - `installed_sends_the_copy` → `SendVaultCopy`.
  - `the_journal_is_gone_once_the_copy_was_attempted` : `advance` rend `Finished`, journal effacé.
  - `apply_local_is_replayable_after_a_stop_between_writes` : coffre, credentials, relais à jour, `next` retiré.
  - `discard_leaves_the_vault_bytes_untouched`.
  - `a_failed_journal_write_leaves_no_journal_and_the_old_vault` (Review Focus 3) : répertoire en lecture seule → `save` échoue, `load` rend `None` ou l'état précédent, jamais un fichier partiel.
  - `legacy_prepared_is_adopted_with_no_next` : `prepared` et journal CA-PQ d'`astra-signer` → `next: None`, `Discard` jamais rendu pour eux (`DomainConflict`).
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra-operator rotation_journal` : FAIL.
- [ ] **Step 3: Implémenter** : journal au mode privé, comme `prepared::save` ; le fichier ne contient que le coffre scellé, jamais de clé en clair. `astra-signer` refuse `rotate-ca-pq` et `rotate-ca-tls` si ce journal existe.
- [ ] **Step 4: Vérifier** — `scripts/wsl-cargo test -p astra-operator -p astra-signer` : PASS.
- [ ] **Step 5: Commit** — `feat(astra-operator): journal a rotation until the gateway has it (F14 lot 5b)`

### Task 8: Séquence de rotation : valider, approuver, signer

**Files:**
- Create: `crates/astra-operator/src/operations/rotation.rs`
- Modify: `crates/astra-operator/src/operations.rs`, `crates/astra-operator/src/signing/campaign.rs`
- Test: `crates/astra-operator/src/operations/rotation.rs`

**Interfaces:**
- Consumes: Task 7.
- Produces:
  ```rust
  pub enum KeyStep { NotEnrolled, Repeated, NotValidated, Declined, Expired }
  pub struct RotationTerms { pub existing_operation: Option<Id16>, pub reason: String, pub requested_by: String,
      pub prepare_days: u64, pub overlap_days: u64, pub validity_days: u64 }
  pub trait RotationRemote { /* one method per Tunnel call of Task 7, plus fetch_campaign and submit_campaign */ }
  impl RotationRemote for Tunnel;

  pub struct ValidatedKeys { /* vault, openings; never Debug, never Serialize */ }
  impl ValidatedKeys {
      pub fn new(vault_path: &Path) -> Result<Self>;
      pub fn validate(&mut self, key: &dyn Authenticator) -> Result<String, KeyStep>; // label
      pub fn count(&self) -> usize;
  }
  pub struct OpenedRotation { /* verified campaign, approval session, identity */ }
  pub fn open(remote: &dyn RotationRemote, vault_path: &Path, kind: RotationKind,
      keys: ValidatedKeys, terms: &RotationTerms, now: u64) -> anyhow::Result<OpenedRotation>;
  impl OpenedRotation {
      pub fn manifest(&self) -> &AstraManifest;
      pub fn offered(&self) -> Vec<Vec<u8>>; // validated, not yet approved
      pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep>;
      pub fn sign_and_journal(self, vault_path: &Path, now: u64) -> anyhow::Result<RotationJournal>;
  }
  pub fn advance(remote: &dyn RotationRemote, vault_path: &Path,
      journal: &mut RotationJournal, now: u64) -> anyhow::Result<ResumeStep>; // loops until a terminal step
  ```
- `validate` réutilise `open_with_authorized_key` et `prove_anchors_open`. `approve` passe `offered()` à la clé, puis contrôle que le credential est validé avant `accept_for(assertion, None, now)`.
- Avant l'ouverture, comparer la cible de la campagne à l'ancre du coffre (`anchor_probe` déplacé d'`astra-signer`, partagé), et valider les bornes de `RotationTerms` : `prepare_days >= 1`.

- [ ] **Step 1: Écrire les tests en échec** (fausses clés, faux distant)
  - `same_key_twice_is_repeated_and_keeps_the_first` ; `an_unknown_key_is_not_enrolled_and_can_retry`.
  - `validating_opens_no_campaign` : le faux distant n'a reçu aucun appel.
  - `approval_accepts_either_order` : clé 2 puis clé 1, et l'inverse ; `rotate_ca_pq` reçoit deux ouvertures distinctes.
  - `a_third_enrolled_key_is_not_validated_and_nothing_is_lost` (Review Focus 1) : `NotValidated`, puis les deux clés validées passent.
  - `touch_count_for_a_ca_rotation_is_four` : compteur des gestes de la fausse clé, aucune clé n'ouvre le coffre après sa validation.
  - `expiry_between_two_approvals_signs_nothing` (Review Focus 4) : `KeyStep::Expired`, pas de journal, coffre intact.
  - `sign_and_journal_leaves_the_vault_file_untouched` ; `the_journal_is_written_before_any_deposit` (ordre d'appels du faux distant).
  - `refused_deposit_of_a_dead_campaign_not_accepted_discards` ; `accepted_runs_apply_install_copy_in_that_order` ; `a_campaign_naming_another_anchor_is_refused_before_a_key`.
  - `a_failed_copy_does_not_undo_the_rotation` : l'envoi échoue, `advance` rend `Finished`, coffre et gateway restent sur la rotation.
  - `fleet_approval_under_the_rotated_document_is_accepted_by_astra_during_overlap` : approbation sous le nouveau document, vérifiée par `approval.verify` sous l'ancien. **Consigner le résultat** dans le registre de suivi : s'il échoue, garder le test en le renommant `..._is_refused_...` et Task 12 désactive « Renouveler » pendant le recouvrement (spec §5.9).
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra-operator operations::rotation` : FAIL.
- [ ] **Step 3: Implémenter** ; `rotate_ca_tls` et `rotate_ca_pq` opèrent sur le coffre en mémoire, le fichier n'étant remplacé que par `apply_local`.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(astra-operator): validate each key, then approve in any order (F14 lot 5b)`

### Task 9: Cérémonies de rotation dans Orion

**Files:**
- Create: `apps/orion/src-tauri/src/operator/ceremony/rotation.rs`
- Modify: `apps/orion/src-tauri/src/operator/ceremony.rs:49,1637`, `apps/orion/src-tauri/src/operator/mod.rs`, `apps/orion/src-tauri/src/commands/ceremonies.rs`, `apps/orion/src-tauri/src/main.rs:786`, `crates/aether/src/certificates/operator_session.rs:250,714`, `apps/orion/src/types.ts`, `apps/orion/src/api.ts`
- Test: `apps/orion/src-tauri/src/operator/ceremony/tests.rs`, `crates/aether/src/certificates/operator_session.rs`

**Interfaces:**
- Consumes: Task 8.
- Produces:
  - `KeyPurpose::ValidateKey` ; `OperatorStatus.key_retry: Option<Refusal>` (`serde default`, omis si absent), gesture restant `AwaitingKey`.
  - `Refusal::{RotationExpired, DomainConflict, InstallDeadlinePassed}`, terminaux. Une campagne expirée reste `WindowExpired`, un dépôt plein `AuthorityRefused { status: 429 }`.
  - `enum RotationGesture { ReplaceCaPq, ReplaceCaTls, FinishCaTls, Resume }` (`#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]`).
  - `OperatorCeremony::begin_rotation(&self, gesture, gateway: Option<String>, vault_path) -> Result<OperatorStatus, String>`.
  - `Press.terms: Option<RotationTerms>` ; `OperatorCeremony::approve_rotation(&self, terms, revision)`.
  - Commandes Tauri : `begin_rotation_ceremony(gesture)`, `approve_rotation_ceremony(terms, revision)`, et leurs jumeaux dans `api.ts`.
  - `const VALIDATION_IDLE_SECS: u64 = 300` : au-delà, ouvertures effacées, refus `WindowExpired`.
- Déroulé du fil : validations (`AwaitingKey{index,of:2,purpose:ValidateKey}`, `keys` rempli, `key_retry` sur `Repeated`/`NotEnrolled`) → `GestureState::Idle` en attente de `approve_rotation` → `open` → manifeste publié → approbations (`purpose: ApproveCampaign`) → `Signing` → `RemoteState::Prepared` → `advance` → `Deposited` → `Done`. Les refus de `next_step` donnent : `Discard` → `Refusal::RotationExpired`, `DomainConflict` → `Refusal::DomainConflict`, `InstallDeadlinePassed` → `Refusal::InstallDeadlinePassed`.
- `FinishCaTls` : une clé, `advance_ca_tls`, sauvegarde du coffre, puis envoi de la copie.
- Sans tunnel, `begin_rotation` refuse `GatewayUnavailable` avant toute clé.

- [ ] **Step 1: Écrire les tests en échec**
  - `a_repeated_key_publishes_a_retry_not_a_refusal` : `gesture` reste `AwaitingKey`, `key_retry == Some(KeyRepeated)`, terminal faux.
  - `idle_validation_past_the_bound_expires` (temps injecté) ; `cancel_at_each_stage_is_terminal_and_clears_the_keys`.
  - `the_webview_status_carries_labels_only` : sérialisation de `OperatorStatus` sans `secret`, `pin`, ni octet d'ouverture.
  - `allowed_actions` couvre `ValidateKey` ; `a_stale_revision_is_refused` sur `approve_rotation_ceremony`.
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p orion rotation` (crate Tauri ; adapter le nom si le paquet diffère, `cargo metadata` le donne) : FAIL.
- [ ] **Step 3: Implémenter** ; `ceremony/rotation.rs` ne contient que les touchers, les publications et les traductions de refus. Variantes `Refusal` et `KeyPurpose` reportées dans `types.ts`.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(orion): run CA rotations in the operator ceremony (F14 lot 5b)`

### Task 10: Reprise automatique

**Files:**
- Modify: `apps/orion/src-tauri/src/operator/ceremony/rotation.rs`, `apps/orion/src-tauri/src/operator/mod.rs`, `apps/orion/src-tauri/src/main.rs`, `apps/orion/src-tauri/src/commands/ceremonies.rs`
- Test: `apps/orion/src-tauri/src/operator/ceremony/tests.rs`, `crates/astra-operator/src/operations/rotation.rs`

**Interfaces:**
- Consumes: Tasks 7, 8, 9 (`rotation_journal::{adopt_legacy, load}`, `advance`, `RotationGesture::Resume`).
- Produces: `operator::resume_on_tunnel_up(app: &AppHandle)`, appelée quand le moteur passe à l'état tunnel monté ; lance `RotationGesture::Resume` si un journal existe et qu'aucune cérémonie n'est ouverte, ne demande jamais de clé.

- [ ] **Step 1: Écrire les tests en échec**
  - `resume_after_a_stop_at_each_stage_asks_no_key` : pour chaque `JournalStage`, `advance` conclut, fausse clé jamais sollicitée.
  - `tunnel_cut_between_acceptance_and_install_resumes_alone` (Review Focus 2) : `Accepted`, faux distant indisponible puis disponible, `already_present` accepté, journal effacé à la fin.
  - `resume_waits_for_a_running_ceremony` ; `no_journal_means_no_ceremony`.
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p astra-operator resume_`, et le paquet Orion : FAIL.
- [ ] **Step 3: Implémenter** : un échec réseau laisse le journal, et la tentative suivante vient de la prochaine montée du tunnel ou du bouton « Reprendre » ; pas de boucle ni de tâche de fond.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(orion): resume a rotation as soon as the tunnel is up (F14 lot 5b)`

### Task 11: Lecture pour l'écran

**Files:**
- Create: `crates/orion-core/src/operator_rotations.rs`
- Modify: `crates/orion-core/src/lib.rs`, `apps/orion/src-tauri/src/commands/ceremonies.rs`, `apps/orion/src-tauri/src/main.rs`, `apps/orion/src/types.ts`, `apps/orion/src/api.ts`
- Test: `crates/orion-core/src/operator_rotations.rs`

**Interfaces:**
- Consumes: Task 5.
- Produces:
  ```rust
  pub enum Reach<T> { Ok(T), NotAdmin, AstraUnavailable, Unreachable, Throttled }
  pub struct GatewayDomainRead { /* tolerant subset of CertificateDomainView: ca_fingerprint,
      ca_epoch, ca_tls_epoch, ca_transition_pending, ca_retire_active_at, next_ca_fingerprint,
      client_tls_ca_transition_pending, peers[].not_after */ }
  pub async fn authority_status(gateway: &str) -> Reach<OperatorAuthorityStatus>;
  pub async fn domain(gateway: &str) -> Reach<GatewayDomainRead>;
  ```
  Commande `operator_rotations_overview() -> RotationsOverview`, et `api.operatorRotationsOverview()` :
  ```ts
  type Reach<T> = { state: 'ok'; value: T } | { state: 'not_admin' | 'astra_unavailable' | 'unreachable' | 'throttled' }
  interface RotationsOverview {
    tunnel: boolean
    pending: Reach<OperatorPendingOperation[]>
    authority: Reach<OperatorAuthorityStatus>
    domain: Reach<GatewayDomainRead>
    vault: VaultOverview | null
    localVaultFingerprint: string | null
    localCaEpoch: number | null
    localCaTlsEpoch: number | null
    journal: { kind: 'ca_pq' | 'ca_tls'; stage: string; activationAt: number; notAfter: number; nextFingerprint: string } | null
    caTlsCloseDue: boolean
  }
  ```
  Commandes `operator_open_campaign(action, reason, requestedBy) -> OperatorOpened` et `operator_send_vault_copy() -> OperatorVaultCopied`, celle-ci lisant le coffre et les credentials locaux, sans jamais recevoir de chemin de la WebView. Après un changement de clés, le document n'est envoyé que si `next_ca_fingerprint` est vide.

- [ ] **Step 1: Écrire les tests en échec** : `http_403_is_not_admin`, `http_503_is_astra_unavailable`, `http_429_is_throttled`, `unknown_fields_of_the_domain_view_are_ignored`, `the_overview_exposes_no_token_and_no_path`.
- [ ] **Step 2: Vérifier l'échec** — `scripts/wsl-cargo test -p orion-core operator_rotations` : FAIL.
- [ ] **Step 3: Implémenter**, avec le client et les bornes d'`operator_pending` (sans proxy, sans redirection).
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(orion): read what the rotations screen shows (F14 lot 5b)`

### Task 12: Écran : la liste et les prérequis

**Files:**
- Create: `apps/orion/src/views/astra/rotationRows.ts`, `rotationRows.test.ts`, `apps/orion/src/views/astra/RotationsPanel.tsx`, `RotationsPanel.test.tsx`
- Modify: `apps/orion/src/views/AstraView.tsx:412,584`, `apps/orion/src/views/astra/ApprovalsPanel.tsx:22`

**Interfaces:**
- Consumes: Task 11, résultat consigné de Task 8 (recouvrement).
- Produces:
  ```ts
  type RotationAction = 'finish_ca_tls' | 'resume' | 'renew_fleet' | 'replace_ca_pq' | 'replace_ca_tls' | 'renew_delegation'
  interface RotationRow { action: RotationAction; title: string; state: string; due: boolean; disabledReason: string | null }
  function rotationRows(o: RotationsOverview, now: number): RotationRow[]
  interface Prerequisite { label: string; ok: boolean; fix: string | null; fixAction: 'send_vault_copy' | null }
  function prerequisites(o: RotationsOverview, action: RotationAction): Prerequisite[]
  ```
- Libellés de ligne : « Terminer la rotation CA TLS », « Reprendre une rotation », « Renouveler les postes », « Remplacer la CA-PQ », « Remplacer la CA TLS », « Renouveler la délégation ».
- Prérequis : « Tunnel connecté », « Administrateur du tunnel », « Service Astra », « Coffre présent », « Deux clés enregistrées », « Copie du coffre », « Domaine concordant ».
- Délégation : `due` si les époques CA de `authority.issuer` diffèrent de celles de `domain` **et** que `localCaEpoch == domain.ca_epoch` ; désactivée si le coffre a une époque d'avance ; `state` signale aussi `serving_epoch != recorded_epoch`.

- [ ] **Step 1: Écrire les tests en échec**
  - `a due row comes first` : ordre du spec §5.1, ligne due en tête.
  - `one CA rotation at a time` : pendant un recouvrement CA-PQ ou CA TLS, deux « Remplacer » désactivés, avec motif ; « Renouveler les postes » suit Task 8.
  - `finish appears at not_after only` ; `resume appears with a journal`.
  - `delegation follows the epochs` : les trois cas ci-dessus, dont « Le coffre a une époque d'avance ».
  - `concordance accepts the current or next anchor` ; `a red prerequisite disables the next step and never calls open`.
  - `the vault copy is sent from the prerequisite` : « Absente » et « Ancienne » → `api.operatorSendVaultCopy` puis relecture.
  - `the screen has no second-person text` : aucun libellé ne contient « tu », « te », « ton ».
- [ ] **Step 2: Vérifier l'échec** — `npm run test:unit --prefix apps/orion -- rotationRows RotationsPanel` : FAIL.
- [ ] **Step 3: Implémenter**, avec le style des panneaux existants. L'onglet Rotations rend `RotationsPanel` à la place du formulaire. Ajouter `trust_authorities` à `OPENABLE_SCOPES`, en menant vers ce panneau.
- [ ] **Step 4: Vérifier** : PASS.
- [ ] **Step 5: Commit** — `feat(orion): list rotations with their prerequisites (F14 lot 5b)`

### Task 13: Écran : clés, approbation, suivi

**Files:**
- Create: `apps/orion/src/views/astra/RotationSteps.tsx`, `RotationSteps.test.tsx`
- Modify: `apps/orion/src/views/astra/RotationsPanel.tsx`, `apps/orion/src/views/OperatorCeremony.tsx`

**Interfaces:**
- Consumes: Tasks 9, 11, 12.
- Produces: `<RotationSteps action overview onClose />`.
- Clés : « Clé 1 : à valider », bouton « Valider » ; « Clé 1 : validée » + libellé ; « Même clé que la clé 1 » et « Clé absente du coffre », bouton « Réessayer » ; « Continuer » actif quand tout est validé.
- Approbation : action, motif pré-rempli modifiable, durées 7 / 30 / 1825 repliées derrière « Modifier », bouton « Approuver » ; puis manifeste et, après signature, empreinte de la CA-PQ entrante. Note « Garder la clé 2 branchée » avant le premier toucher.
- Suivi : « Signée », « Déposée », « Installée sur la gateway », « Copie du coffre », « Fin de rotation le … », « À installer avant le … ». Refus terminaux : « Rotation expirée. Recommencer », « Campagne expirée », « Domaine incohérent », « Délai dépassé » (avec date de coupure et « Intervention manuelle requise »), « Trop d'opérations en attente ».
- Renouveler les postes : `operator_open_campaign('fleet_leafs')` puis `beginOperatorCeremony({ kind: 'approve_campaign', operation_id })`.
- Renouveler la délégation : `operator_open_campaign('issuer_delegation')` puis `beginIssuerCeremony({ gesture: 'authorize_issuer', operation_id, request: opened.delegation_request })`.
- Une opération de même portée déjà dans `pending` est proposée par « Reprendre l'opération ouverte », sans nouvelle ouverture (`existing_operation`).

- [ ] **Step 1: Écrire les tests en échec**
  - `keys validate one after the other with their state` ; `a repeated key offers retry and keeps key 1` ; `continue stays disabled until both are valid`.
  - `the campaign opens at Approuver and not before` : `approveRotationCeremony` jamais appelé avant le clic.
  - `durations are folded and refuse less than one day` ; `reason over 1024 chars is refused before the call`.
  - `an already open operation is offered instead of an error`.
  - `delegation sends the request from the opening, with no file picker`.
  - `each terminal refusal has its label` ; `Délai dépassé shows the cut date`.
  - `the follow-up shows the install deadline until installed`.
- [ ] **Step 2: Vérifier l'échec** — `npm run test:unit --prefix apps/orion -- RotationSteps` : FAIL.
- [ ] **Step 3: Implémenter** ; le récapitulatif réutilise les rendus de manifeste d'`OperatorCeremony`.
- [ ] **Step 4: Vérifier** — `npm run test:unit --prefix apps/orion && npm run build --prefix apps/orion` : PASS.
- [ ] **Step 5: Commit** — `feat(orion): guide a rotation through keys, approval and follow-up (F14 lot 5b)`

### Task 14: Retirer le compagnon

**Files:**
- Delete: `apps/orion/src-tauri/src/companion.rs`, `apps/orion/src-tauri/src/astra.rs`, `crates/astra-operator/src/orion.rs`
- Modify: `apps/orion/src-tauri/src/launch.rs:128`, `apps/orion/src-tauri/src/main.rs:89,98,116,707,782-785`, `apps/orion/src-tauri/src/commands/ceremonies.rs:14-52`, `tools/astra-signer/src/{main.rs:330,cli.rs:495}` (mode caché `orion`), `crates/aether/src/certificates/operator_ipc` (ce qui ne sert plus), `crates/astra-operator/src/lib.rs`, `apps/orion/src/{api.ts,types.ts}`, `apps/orion/src/views/AstraView.tsx`
- Test: suites existantes

**Interfaces:**
- Consumes: Tasks 9-13.
- Garde `AstraCaTlsManifest` si `prepared.rs` l'emploie encore ; les commandes publiques d'`astra-signer` restent.

- [ ] **Step 1: Écrire le test en échec** : `orion_no_longer_spawns_astra_signer` dans `apps/orion/src-tauri/src/security_tests.rs`, qui échoue tant que `spawn_astra_signer` existe dans `launch.rs`.
- [ ] **Step 2: Vérifier l'échec** : FAIL.
- [ ] **Step 3: Supprimer** les fichiers, les commandes `*_astra_ca_tls_rotation`, leurs entrées dans `generate_handler!`, le mode caché, et les types TS `AstraRotation*`.
- [ ] **Step 4: Vérifier** — `scripts/wsl-cargo check --locked --workspace --all-targets`, `scripts/wsl-cargo test -p astra-operator -p astra-signer`, `npm run test:unit --prefix apps/orion` : PASS ; `grep -rn 'spawn_astra_signer\|astra_ca_tls_rotation' apps crates tools` vide.
- [ ] **Step 5: Commit** — `refactor(orion)!: stop launching astra-signer (F14 lot 5b)`

### Task 15: Documentation et recette

**Files:**
- Modify: `docs/RENOUVELLEMENT-CERTIFICATS.md` (§2, §3, §4, §9), `docs/DEPLOIEMENT-ASTRA.md:672-705`, `docs/specification/ROTATION-CERTIFICATS.md`, `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md`, `docs/superpowers/specs/2026-11-02-f14-lot5a-porte-unique-design.md` (§5.2), `docs/ROADMAP.md`, `docs/testing/MANUAL-TESTING.md`
- Modify: `deploy/astra/` seulement si une aide y parle encore du redémarrage après délégation

- [ ] **Step 1: Mettre à jour**
  - Orion devient le chemin par défaut, les commandes restent en recours.
  - Amendement daté dans la spécification, l'ADR-008 et la spec 5a : tunnel, délégation, copie du coffre, adoption sans redémarrage, document de credentials à `not_after`.
  - Limites connues : « Délai dépassé » sans réparation ; émission en ligne refusée de `not_after` à la re-délégation ; remplacement possible de la copie par un administrateur du tunnel ; sauvegarde hors gateway non couverte.
  - Vérifier la limite du §3 (registre d'Astra sur l'ancre sortante), que `ca_rotation` semble avoir levée, et la corriger si elle est périmée.
  - `ROADMAP.md` : état de F14 et suivi « réparer un délai d'installation dépassé ».
  - `MANUAL-TESTING.md`, section « G. Lot 5b » : renouveler les postes, remplacer chaque CA, couper Orion à chaque étape, terminer une rotation, renouveler la délégation puis un poste, partir d'une gateway sans copie du coffre, clé répétée, campagne expirée.
- [ ] **Step 2: Vérifier** — `grep -rn "Redémarrer Astra pour qu'il émette" docs crates apps tools` : aucune consigne restante hors historique daté.
- [ ] **Step 3: Commit** — `docs: rotations run from Orion (F14 lot 5b)`

### Task 16: Régression

- [ ] **Step 1: Lancer** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/regression.sh`, en arrière-plan : tests Rust, frontends, clippy `--all-features`, campagnes, audit, tous au vert.
- [ ] **Step 2: Vérifier la version** — `python3 scripts/version.py check --base main` : conforme au moment de la fusion, sans édition manuelle.
- [ ] **Step 3: Relire la branche** contre le spec, section par section, et lister les validations impossibles en WSL : cible, Windows, WebAuthn réel, `flock` entre conteneurs. Les signaler explicitement à l'utilisateur.
