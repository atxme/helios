# F14 lot 6a — Amorcer la gateway depuis Orion — plan d'exécution

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Émettre depuis l'onglet Astra d'Orion la première feuille PQ de la gateway (`astra-signer issue-gateway-bootstrap`), avec deux clés distinctes, en enchaînant la finalisation du lot 3 quand elle manque.

**Architecture:** La séquence (plan avant clé, vérifications, ordre des écritures) vit dans un nouveau module `astra_operator::bootstrap`, testé avec la `FakeKey` d'`astra-operator`, qui réutilise les contrôles de `vault_gestures` (lot 3). Orion l'orchestre comme un geste de plus de la cérémonie du coffre (`operator/ceremony/vault.rs`). L'IHM ajoute le bouton et le choix du fichier dans `DomainPanel`, la WebView n'envoyant que le contenu de la demande.

**Tech Stack:** Rust (aether, astra-operator, Tauri 2), React + MUI + vitest.

**Spec:** `docs/superpowers/specs/2026-10-31-f14-lot6a-amorcage-gateway-design.md` (lire §4 et §9, qui tranchent les détails), suite de `docs/superpowers/specs/2026-10-28-f14-lot3-coffre-domaine-design.md`.

## Global Constraints

- Worktree `/home/christophe/helios-wt/f14-orion`, branche `feat/f14-lot6a-amorcage-gateway`. Ne jamais travailler dans `~/helios`.
- Compiler et tester uniquement par `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo …` ; jamais `CARGO_TARGET_DIR`, jamais `cargo clean`, ne tuer aucun processus.
- Un test qui attend des appuis fait `drop` de son émetteur (sinon il pend et bloque le cache partagé).
- IHM : `cd apps/orion && node_modules/.bin/tsc --noEmit -p . && npx vitest run` (jamais `npx tsc`).
- Aucune nouvelle dépendance externe.
- `scripts/deploy.sh` n'est pas modifié (décision de l'utilisateur).
- Pas d'`unwrap`/`expect` hors tests ; aucun TODO/FIXME ; identifiants, commentaires et tests en anglais ; messages de l'IHM et `docs/` en français.
- Aucun secret (PIN, secret de key-slot, `Opened`, clé `CA-PQ`, octets du coffre) journalisé, sérialisé, ni envoyé à la WebView. La demande, la feuille et la `CA-TLS` sont publiques.
- Aucun chemin de fichier ne passe de la WebView au processus Rust : la WebView n'envoie que le texte de la demande.
- Les refus restent la classe fermée `Refusal`, sans texte ; la phrase française est dans `refusalSentence`.
- Fail-closed : tout refus prévisible est vérifié côté Rust avant la première clé, même quand l'IHM désactive le bouton.
- `cfg(windows)` et la vraie plateforme WebAuthn ne sont pas vérifiables sous WSL2 : le dire dans le rapport de tâche.
- Commits terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- **Le mauvais fichier choisi** (la feuille au lieu de la demande, une demande de transition, du texte quelconque, un fichier tronqué) : `BootstrapRequestInvalid` avant toute clé, rien d'écrit. Tests : Task 2 `a_file_that_is_not_a_bootstrap_request_is_refused_before_any_key`, Task 4 `a_wrong_file_is_refused_inline`.
- **La même clé présentée deux fois** : `KeyRepeated` après le second toucher, rien d'écrit (ni identité, ni feuille). Tests : Task 2 `the_same_key_cannot_approve_twice`, Task 3 `the_second_key_must_be_another_credential`.
- **Un second amorçage sur un domaine complet** : une nouvelle feuille, aucune nouvelle `CA-TLS`, aucun refus `DomainComplete`. Test : Task 2 `bootstrapping_again_issues_a_leaf_and_nothing_else`.
- **Une demande d'une autre gateway** (relais qui en nomme une autre, ou relais vide mais document lié à une autre) : `OtherGateway` avant toute clé. Test : Task 2 `another_gateway_is_refused_before_any_key`.
- **La finalisation qui échoue après la feuille** : la feuille reste à côté du coffre, « Finaliser le domaine » reprend ensuite. Test : Task 2 `a_failed_finalization_keeps_the_leaf` (`#[cfg(unix)]`, lien symbolique à la place du document de credentials comme le test d'ordre du lot 3).

---

### Task 1: Contrat de la cérémonie (aether)

**Files:**
- Modify: `crates/aether/src/certificates/operator_session.rs`

**Interfaces:**
- Produces (serde `snake_case`, comme l'existant) :
  - `OperationKind::IssueGatewayBootstrap` (après `FinalizeDomain`).
  - `Refusal::BootstrapRequestInvalid`, `Refusal::OtherGateway`, sans champ, insérées avant `Internal`.
  - `AstraManifest::GatewayBootstrap(GatewayBootstrapManifest)` avec
    `GatewayBootstrapManifest { vault_fingerprint: Fingerprint, server_name: String, gateway_wg_public_key: WireGuardKey, request_fingerprint: Fingerprint, leaf_days: u64, issues_ca_tls: bool, ca_tls_days: u64, issues_credentials: bool }`, `#[serde(deny_unknown_fields)]`.
  - `kind()` → `IssueGatewayBootstrap` ; `trust_domain_id()` → `None` (le coffre le lie, comme `DomainFinalization`).

- [ ] **Step 1: Write the failing tests** (dans le `mod tests` du fichier) : `the_bootstrap_manifest_has_its_kind` (le manifeste rend `IssueGatewayBootstrap` et `None`), `the_bootstrap_refusals_spell_in_snake_case` (`"bootstrap_request_invalid"`, `"other_gateway"`), `the_bootstrap_manifest_refuses_unknown_fields`.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether operator_session` → FAIL (types absents).
- [ ] **Step 3: Implement** les variantes et le manifeste.
- [ ] **Step 4: Run** le même test, puis `scripts/wsl-cargo clippy -p aether --all-targets --all-features -- -D warnings` → PASS.
- [ ] **Step 5: Commit** — `feat(aether): name the gateway bootstrap in the operator contract`

### Task 2: La séquence d'amorçage (`astra_operator::bootstrap`)

**Files:**
- Create: `crates/astra-operator/src/bootstrap.rs`
- Modify: `crates/astra-operator/src/lib.rs` (`pub mod bootstrap;`)
- Modify: `crates/astra-operator/src/vault_gestures.rs` (variantes de `SetupRefusal`, `GATEWAY_TRANSITION` retypé, helpers `pub(crate)`)
- Test: `crates/astra-operator/tests/gateway_bootstrap.rs` (helpers copiés au besoin depuis `tests/vault_gestures.rs` : `create`, `add`, `complete_relay`, `clear_gateway`, `emit_document`, `domain_leaf` pour bâtir une demande signée)
- Modify: `crates/astra-operator/tests/vault_gestures.rs` (les tests du lot 3 qui attendaient le texte d'une autre gateway attendent `SetupRefusal::OtherGateway`)

**Interfaces:**
- Consumes: `vault_gestures::{finalize_with, Finalized, CA_TLS_DAYS}`, `gestures::{prove_anchors_open, require_scope_credentials}`, `signing::issue_gateway_bootstrap_certificate`, `aether::private_file::write_private_atomic`.
- Produces:
  - `SetupRefusal::OtherGateway` (message : « le domaine nomme déjà une autre gateway ; en changer est une transition de gateway »), `SetupRefusal::BootstrapRequestInvalid` (« ce fichier n'est pas une demande d'amorçage de gateway qui se vérifie »), `SetupRefusal::SignerRevoked` (« le document de credentials révoque cette clé : en présenter une autre »). `write_relay` et `adopt_gateway` rendent `OtherGateway` là où ils faisaient `bail!(GATEWAY_TRANSITION)` (même texte affiché).
  - `vault_gestures::{bound_to_another_gateway, verified_document, describes_every_slot}` passent `pub(crate)`.
  - `pub const BOOTSTRAP_LEAF_DAYS: u64 = 365;`
  - `pub const BOOTSTRAP_CERTIFICATE_FILE: &str = "gateway-bootstrap-certificate.json";`
  - `pub const MAX_BOOTSTRAP_REQUEST_BYTES: usize = 256 * 1024;`
  - `pub struct BootstrapPlan { pub request: GatewayBootstrapRequest, pub records_identity: bool, pub issues_ca_tls: bool, pub issues_credentials: bool }`
  - `pub fn bootstrap_plan(vault_path: &Path, request_json: &str) -> Result<BootstrapPlan, SetupRefusal>` — sans rien écrire : taille ≤ `MAX_BOOTSTRAP_REQUEST_BYTES`, analyse et `verify()` (sinon `BootstrapRequestInvalid`) ; coffre lisible (sinon `LocationUnavailable`) ; au moins deux emplacements non révoqués par le document vérifié (tous sans document ; sinon `MinimumKeys`) ; relais : clé ou nom enregistrés différents → `OtherGateway` ; document lié à une autre gateway → `OtherGateway` ; document présent mais invérifiable → `GatewayIdentityMissing` ; `issues_ca_tls` = relais sans `CA-TLS` ; `issues_credentials` = aucun document vérifié ne décrit chaque emplacement ; `records_identity` = clé ou nom absents du relais.
  - `pub fn path_beside(vault_path: &Path) -> PathBuf` (le fichier `BOOTSTRAP_CERTIFICATE_FILE` dans le dossier du coffre).
  - `pub struct Bootstrapped { pub leaf_json: String, pub leaf_fingerprint: String, pub finalized: Option<Finalized> }`
  - `pub fn bootstrap_with(vault_path: &Path, plan: &BootstrapPlan, first: &Opened, second: &Opened, now_unix: u64) -> anyhow::Result<Bootstrapped>` — refait les contrôles de relais, de document et de nombre de clés sur `plan.request` (une fonction interne `plan_for(vault_path, &GatewayBootstrapRequest)`, que `bootstrap_plan` appelle après l'analyse) ; `require_scope_credentials(CampaignScope::GatewayBootstrap, &[first, second])` ; un signataire révoqué par le document → `SignerRevoked` ; `prove_anchors_open` pour chacun ; puis, dans cet ordre : identité au relais si `records_identity` ; feuille signée avec `first` (validité `now_unix - 300` → `now_unix + BOOTSTRAP_LEAF_DAYS` jours, numéro aléatoire 16 octets) écrite par `write_private_atomic` à `path_beside` ; enfin `finalize_with(vault_path, first, now_unix)` si `issues_ca_tls || issues_credentials`, un `SetupRefusal::DomainComplete` y valant « rien à faire ». `leaf_fingerprint` par `aether::certificates::gateway::pq_certificate_fingerprint`.

- [ ] **Step 1: Write the failing tests** (`tests/gateway_bootstrap.rs`, `NOW` comme le lot 3) :
  - `a_fresh_domain_is_bootstrapped_and_finalized_in_one_gesture` : domaine à deux clés, relais sans gateway ; `bootstrap_plan` → `records_identity && issues_ca_tls && issues_credentials` ; après `bootstrap_with`, le relais nomme la gateway de la demande, la feuille de `path_beside` vérifie sous le `CA-PQ` du relais pour ce nom et cette clé, `finalized.unwrap().ca_tls_pem.is_some()`.
  - `a_file_that_is_not_a_bootstrap_request_is_refused_before_any_key` : `""`, `"{}"`, une feuille `PqCertificate` en JSON, une demande dont `server_name` est modifié après signature, un texte de `MAX_BOOTSTRAP_REQUEST_BYTES + 1` octets → `Err(BootstrapRequestInvalid)` ; relais et dossier inchangés.
  - `another_gateway_is_refused_before_any_key` : relais complété pour une gateway A, demande de B → `OtherGateway` ; relais vidé (`clear_gateway`) mais document émis pour A → `OtherGateway`.
  - `fewer_than_two_usable_keys_are_refused` : coffre à une clé → `MinimumKeys` ; trois clés dont deux révoquées dans le document → `MinimumKeys`.
  - `the_same_key_cannot_approve_twice` : `bootstrap_with(.., &first, &first, ..)` → erreur, relais sans identité, pas de fichier à `path_beside`.
  - `bootstrapping_again_issues_a_leaf_and_nothing_else` : après un premier amorçage complet, second plan → `!records_identity && !issues_ca_tls && !issues_credentials` ; `bootstrap_with` réussit, `finalized.is_none()`, la feuille du fichier a changé de numéro, la `CA-TLS` du relais est la même.
  - `a_failed_finalization_keeps_the_leaf` (`#[cfg(unix)]`) : le document de credentials remplacé par un lien symbolique, `bootstrap_with` échoue, la feuille existe à `path_beside` et vérifie.
  - Dans `tests/vault_gestures.rs`, les tests du lot 3 sur l'adoption et `write_relay` d'une autre gateway vérifient `refusal(..) == Some(SetupRefusal::OtherGateway)`.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator --test gateway_bootstrap --test vault_gestures` → FAIL.
- [ ] **Step 3: Implement** `bootstrap.rs` et les changements de `vault_gestures.rs` selon les Interfaces.
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p astra-operator --all-features`, puis `scripts/wsl-cargo clippy -p astra-operator --all-targets --all-features -- -D warnings` → PASS.
- [ ] **Step 5: Commit** — `feat(astra-operator): bootstrap the gateway from the vault, then finish the domain`

### Task 3: Le geste dans la cérémonie d'Orion

**Files:**
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`VaultGesture`)
- Modify: `apps/orion/src-tauri/src/operator/ceremony/vault.rs`
- Test: `apps/orion/src-tauri/src/operator/ceremony/vault/tests.rs`, tests de `operator/mod.rs` existants pour `VaultGesture`

**Interfaces:**
- Consumes: Task 1 (contrat), Task 2 (`bootstrap_plan`, `bootstrap_with`, `MAX_BOOTSTRAP_REQUEST_BYTES`, `BOOTSTRAP_LEAF_DAYS`, `BOOTSTRAP_CERTIFICATE_FILE`, nouvelles `SetupRefusal`).
- Produces:
  - `VaultGesture::BootstrapGateway { request: String }` (serde `"gesture": "bootstrap_gateway"`, `"request"`), `validate()` refuse un texte vide ou de plus de `MAX_BOOTSTRAP_REQUEST_BYTES` octets avec « la demande d'amorçage est vide ou trop grande (256 Kio au plus) » ; `operation()` → `IssueGatewayBootstrap`.
  - `refusal_of_setup` : `OtherGateway` → `Refusal::OtherGateway`, `BootstrapRequestInvalid` → `Refusal::BootstrapRequestInvalid`, `SignerRevoked` → `Refusal::KeyNotEnrolled`.
  - `VaultRun::bootstrap_gateway(&mut self, request: &str, deposit: &mut dyn FnMut(OperatorArtifact))` : `bootstrap_plan` (refus publié sans clé) → `show(AstraManifest::GatewayBootstrap(..))` (`leaf_days: BOOTSTRAP_LEAF_DAYS`, `ca_tls_days: CA_TLS_DAYS`) → `open_vault(&vault, 1, 2, None)` → seconde clé `KeyPurpose::SecondApproval`, index 2 sur 2 ; même `credential_id` que la première → `Refusal::KeyRepeated`, rien d'écrit → `signing()` → `bootstrap_with` → `deposit` de `OperatorArtifact { file_name: BOOTSTRAP_CERTIFICATE_FILE, contents: leaf_json, encoding: Text }`, puis `ca-tls.pem` si émise → `done()`.

- [ ] **Step 1: Write the failing tests** : dans `operator/mod.rs`, `a_bootstrap_gesture_carries_only_the_request_text` (désérialisation, champ inconnu refusé, texte vide et texte de 256 Kio + 1 refusés par `validate`) ; dans `ceremony/vault/tests.rs`, sur le modèle des tests de finalisation existants : `a_wrong_request_is_refused_before_any_key` (statut final `Refusal::BootstrapRequestInvalid`, aucune clé demandée), `the_second_key_must_be_another_credential` (même jeton deux fois → `Refusal::KeyRepeated`, relais inchangé), `the_bootstrap_deposits_the_leaf_and_the_ca_tls` (deux artefacts, noms `gateway-bootstrap-certificate.json` et `ca-tls.pem`), `refusals_of_the_bootstrap_are_named` (les trois nouvelles correspondances de `refusal_of_setup`).
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion operator` → FAIL.
- [ ] **Step 3: Implement** selon les Interfaces.
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion`, `scripts/wsl-cargo clippy -p orion --all-targets --all-features -- -D warnings` → PASS.
- [ ] **Step 5: Commit** — `feat(orion): bootstrap the gateway as a vault ceremony`

### Task 4: IHM — « Amorcer la gateway… »

**Files:**
- Modify: `apps/orion/src/types.ts`, `apps/orion/src/views/OperatorCeremony.tsx`, `apps/orion/src/views/astra/DomainPanel.tsx`, `apps/orion/src/views/AstraView.tsx`
- Create (si la lecture de fichier est partagée) : `apps/orion/src/views/astra/readFileText.ts`, extraite d'`EnrollmentOperatorPanel.tsx` (même borne `256 * 1024`, même repli `FileReader`), `EnrollmentOperatorPanel` l'importe
- Test: `apps/orion/src/views/astra/DomainPanel.test.tsx`, `apps/orion/src/views/OperatorCeremony.vault.test.ts`

**Interfaces:**
- Consumes: Task 3 (`{ gesture: 'bootstrap_gateway', request: string }`, genre `issue_gateway_bootstrap`, refus `bootstrap_request_invalid` / `other_gateway`, manifeste `gateway_bootstrap`).
- Produces (copie fixée) :
  - Bouton « Amorcer la gateway… » dans *Domaine* ; désactivé quand moins de deux clés de l'aperçu ne sont pas `revoked`, avec « Il faut deux clés actives pour amorcer la gateway. ».
  - `OperatorCeremony` : titre « Amorcer la gateway » ; action « Amorcer avec les deux clés » ; lignes du manifeste : Gateway, Identité WireGuard, Demande (empreinte), Validité de la feuille (`leaf_days` jours), puis « Émettre la CA-TLS (`ca_tls_days` jours) » si `issues_ca_tls`, « Signer le document de credentials » si `issues_credentials`.
  - `refusalSentence` : `bootstrap_request_invalid` → « Ce fichier n'est pas une demande d'amorçage de gateway valide, ou sa signature ne se vérifie pas. Rien n'a été signé. » ; `other_gateway` → « Le domaine nomme déjà une autre gateway : en changer est une transition de gateway. Rien n'a été écrit. »
  - `AstraView` : `ArtifactDownloads` aussi pour `issue_gateway_bootstrap` ; à la fin, sous les téléchargements : « Portez la feuille sur la gateway : elle s'installe à son amorçage (voir DEPLOIEMENT-ASTRA). »
  - Un fichier illisible ou trop grand est refusé dans la WebView, avant toute cérémonie, avec « Ce fichier est illisible ou trop grand (256 Kio au plus). ».

- [ ] **Step 1: Write the failing tests** : `the_bootstrap_button_needs_two_usable_keys` (une clé, puis deux dont une révoquée → désactivé avec la phrase ; deux actives → actif), `the_bootstrap_sends_the_file_text_only` (`beginVaultCeremony` appelé avec `{ gesture: 'bootstrap_gateway', request: <texte> }`, aucun chemin), `a_wrong_file_is_refused_inline` (fichier de 256 Kio + 1 → phrase, aucune cérémonie), `the_bootstrap_manifest_lists_what_it_will_issue`, `the_bootstrap_refusals_have_their_sentences`, `the_bootstrap_offers_its_artifacts` (AstraView).
- [ ] **Step 2: Run** `cd apps/orion && npx vitest run src/views/astra/DomainPanel.test.tsx src/views/OperatorCeremony.vault.test.ts` → FAIL.
- [ ] **Step 3: Implement** selon les Interfaces.
- [ ] **Step 4: Run** `cd apps/orion && node_modules/.bin/tsc --noEmit -p . && npx vitest run` → PASS.
- [ ] **Step 5: Commit** — `feat(orion-ui): bootstrap the gateway from the domain section`

### Task 5: Documentation et régression complète

**Files:**
- Modify: `docs/DEPLOIEMENT-ASTRA.md` : l'étape `issue-gateway-bootstrap` devient Orion, *Domaine*, « Amorcer la gateway… » (choisir la demande, deux clés, enregistrer la feuille) ; la finalisation est enchaînée sur un domaine neuf ; avec `deploy.sh` (outil de développement, inchangé), choisir la demande qu'il a rapatriée et enregistrer la feuille au chemin qu'il imprime ; `astra-signer issue-gateway-bootstrap` cité comme voie transitoire jusqu'au lot 7.
- Modify: `docs/testing/MANUAL-TESTING.md` : section « F14 lot 6a — amorcer la gateway », sur un coffre d'essai, non vérifiée sous WSL2 : demande valide (deux dialogues Windows attendus), feuille et `ca-tls.pem` enregistrées, demande altérée (refus avant clé), même clé deux fois, demande d'une autre gateway, second amorçage (feuille seule).
- Modify: `docs/ROADMAP.md` (F14 : lot 6a livré sur la branche, validation Windows à faire ; 6b à concevoir) et `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md` (l'amendement F14 gagne une phrase : l'amorçage gateway se joue dans Orion, par fichiers, deux clés).
- Modify: la spec, section « Amendements » pour tout écart pris pendant l'exécution.

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Run the full regression in the background** : `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh > .superpowers/sdd/2026-10-31-f14-lot6a-amorcage-gateway/regression.log 2>&1` → exit 0, aucun `FAILED`, avertissements `cargo audit` seulement ceux déjà autorisés.
- [ ] **Step 3: Commit** — `docs: bootstrap the gateway from Orion`
