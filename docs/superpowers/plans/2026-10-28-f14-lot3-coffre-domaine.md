# F14 lot 3 — Coffre, clés et domaine dans Orion — plan d'exécution

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Créer un domaine, gérer les clés du coffre et finaliser le domaine depuis l'onglet Astra d'Orion, en moins d'étapes et de touchers que `astra-signer`.

**Architecture:** La logique des gestes (étapes, refus avant clé, ordre des écritures) vit dans un nouveau module `astra_operator::vault_gestures`, testé avec la `FakeKey` d'`astra-operator`. Orion l'orchestre dans une nouvelle cérémonie (`operator/ceremony/vault.rs`), avec les appuis, la plateforme WebAuthn et la classe fermée `Refusal`. L'IHM ajoute les formulaires et les actions dans `VaultPanel` et `DomainPanel`. Un emplacement de coffre choisi par un sélecteur natif côté Rust sert à tous les gestes opérateur.

**Tech Stack:** Rust (aether, astra-operator, aether-fido, Tauri 2, windows-sys 0.61), React + MUI + vitest.

**Spec:** `docs/superpowers/specs/2026-10-28-f14-lot3-coffre-domaine-design.md`, elle-même suite de `docs/superpowers/specs/2026-10-27-orion-seul-client-design.md`.

## Global Constraints

- Worktree `/home/christophe/helios-wt/f14-orion`, branche `feat/f14-lot3-coffre-domaine`. Ne jamais travailler dans `~/helios`.
- Compiler et tester uniquement par `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo …` ; jamais `CARGO_TARGET_DIR`, jamais `cargo clean`, ne tuer aucun processus.
- Un test qui attend des appuis fait `drop` de son émetteur (sinon il pend et bloque le cache partagé).
- IHM : `cd apps/orion && node_modules/.bin/tsc --noEmit -p . && npx vitest run` (jamais `npx tsc`).
- Aucune nouvelle dépendance externe. Ajouter une *feature* à `windows-sys` (déjà dépendance) est permis.
- Pas d'`unwrap`/`expect` hors tests ; aucun TODO/FIXME ; identifiants, commentaires et tests en anglais ; messages de l'IHM et `docs/` en français.
- Aucun secret (PIN, secret de key-slot, `Opened`, clé `CA-PQ`, octets du coffre) journalisé, sérialisé, ni envoyé à la WebView.
- Aucun chemin de fichier ne passe de la WebView au processus Rust.
- Les refus restent la classe fermée `Refusal`, sans texte ; la phrase française est dans `refusalSentence`.
- Les genres d'opération restent une liste fermée (`OperationKind`), un genre par geste à clé.
- Fail-closed : tout refus prévisible est vérifié côté Rust même quand l'IHM désactive le bouton.
- `cfg(windows)` n'est pas vérifiable sous WSL2 : le dire dans le rapport de tâche, ne pas l'écrire comme acquis.
- Commits terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- **La même clé branchée deux fois à la création** : l'enregistrement de la seconde est exclu, le coffre reste valide avec une clé, l'IHM affiche le bandeau « non amorcé » et « Ajouter la clé de récupération ». Tests : Task 2 `the_same_token_cannot_take_the_second_slot`, Task 7 `a_single_key_vault_shows_the_unbootstrapped_banner`.
- **Le support du coffre débranché** (emplacement choisi, dossier absent) : « Emplacement introuvable », jamais « Créer un domaine ». Tests : Task 3 `a_missing_folder_is_not_an_absent_vault`, Task 7 `an_unavailable_location_offers_no_creation`.
- **Retirer la clé même qui ouvre le coffre** : refus `KeyBeingRemoved`, rien n'est écrit. Test : Task 2 `the_opening_key_cannot_remove_itself`.
- **Libellé vide ou trop long au renommage** : erreur, coffre inchangé. Test : Task 2 `a_blank_or_long_label_is_refused_and_nothing_moves`.
- **Finalisation interrompue après la `CA-TLS`** : une seconde finalisation n'émet que le document, jamais une seconde `CA-TLS`. Test : Task 3 `finalizing_twice_never_reissues_ca_tls`.

---

### Task 1: Contrat de la cérémonie (aether)

**Files:**
- Modify: `crates/aether/src/certificates/operator_session.rs`

**Interfaces:**
- Produces (serde `snake_case`, comme l'existant) :
  - `OperationKind` gagne `CreateDomain`, `AddKey`, `RemoveKey`, `MarkKey`, `FinalizeDomain`.
  - `KeyPurpose` gagne `RegisterKey` (une clé neuve à enregistrer).
  - `Refusal` gagne, sans champ : `VaultExists`, `LocationUnavailable`, `VaultFull`, `MinimumKeys`, `KeyBeingRemoved`, `GatewayIdentityMissing`, `CaTlsAlreadyIssued`, `DomainComplete`. Insérées avant `Internal`, qui reste la dernière.
  - `AstraManifest` gagne (tag `operation`) :
    - `DomainCreation(DomainCreationManifest { rp_id: String, authority_url: String, first_label: String, second_label: String })`
    - `KeyAddition(KeyAdditionManifest { vault_fingerprint: Fingerprint, label: String, role: String })`
    - `KeyRemoval(KeyRemovalManifest { vault_fingerprint: Fingerprint, slot_id: String, label: String, role: String })`
    - `KeyMarking(KeyMarkingManifest { vault_fingerprint: Fingerprint, slot_id: String, label: String, lost: bool })`
    - `DomainFinalization(DomainFinalizationManifest { vault_fingerprint: Fingerprint, server_name: String, gateway_wg_public_key: WireGuardKey, issues_ca_tls: bool, ca_tls_days: u64, issues_credentials: bool })`
    - toutes `#[serde(deny_unknown_fields)]` ; `role` vaut `principale` ou `recuperation`.
  - `AstraManifest::kind()` les associe aux cinq genres ; `trust_domain_id()` rend `None` pour les cinq (le coffre les lie, comme les manifestes d'enrôlement).

- [ ] **Step 1: Write the failing tests** (dans le `mod tests` du fichier)

```rust
#[test]
fn the_vault_gestures_have_their_kinds() {
    let fp = Fingerprint::of(b"vault");
    let cases = [
        (AstraManifest::DomainCreation(DomainCreationManifest { rp_id: "astra.example".into(), authority_url: "https://astra.example".into(), first_label: "a".into(), second_label: "b".into() }), OperationKind::CreateDomain),
        (AstraManifest::KeyAddition(KeyAdditionManifest { vault_fingerprint: fp.clone(), label: "c".into(), role: "recuperation".into() }), OperationKind::AddKey),
        (AstraManifest::KeyRemoval(KeyRemovalManifest { vault_fingerprint: fp.clone(), slot_id: "00".repeat(16), label: "c".into(), role: "principale".into() }), OperationKind::RemoveKey),
        (AstraManifest::KeyMarking(KeyMarkingManifest { vault_fingerprint: fp.clone(), slot_id: "00".repeat(16), label: "c".into(), lost: true }), OperationKind::MarkKey),
    ];
    for (manifest, kind) in cases {
        assert_eq!(manifest.kind(), kind);
        assert_eq!(manifest.trust_domain_id(), None);
    }
}

#[test]
fn the_new_refusals_and_purpose_are_spelled_for_the_window() {
    assert_eq!(serde_json::to_value(Refusal::KeyBeingRemoved).unwrap(), serde_json::json!({"refusal": "key_being_removed"}));
    assert_eq!(serde_json::to_value(Refusal::LocationUnavailable).unwrap(), serde_json::json!({"refusal": "location_unavailable"}));
    assert_eq!(serde_json::to_value(KeyPurpose::RegisterKey).unwrap(), serde_json::json!("register_key"));
    assert_eq!(serde_json::to_value(OperationKind::FinalizeDomain).unwrap(), serde_json::json!("finalize_domain"));
}

#[test]
fn a_creation_manifest_with_an_extra_field_is_refused() {
    let text = r#"{"operation":"domain_creation","rp_id":"a.example","authority_url":"https://a.example","first_label":"a","second_label":"b","extra":1}"#;
    assert!(serde_json::from_str::<AstraManifest>(text).is_err());
}
```

- [ ] **Step 2: Run, expect a compile failure** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether operator_session` → erreurs « no variant named CreateDomain ».
- [ ] **Step 3: Add the variants and the five manifest structs** décrits ci-dessus, avec un commentaire d'une ligne chacun dans le style du fichier.
- [ ] **Step 4: Run** la même commande → PASS. Puis `CARGO_BUILD_JOBS=2 scripts/wsl-cargo check --workspace --all-targets` → aucun `match` non exhaustif ailleurs (le `other =>` de `ceremony.rs` les absorbe pour l'instant).
- [ ] **Step 5: Commit** — `feat(aether): name the vault and domain gestures of the operator ceremony`

---

### Task 2: Gestes de clés (`astra_operator::vault_gestures`, partie clés)

**Files:**
- Modify: `crates/astra-operator/src/gestures.rs` (ouvertures rendues)
- Create: `crates/astra-operator/src/vault_gestures.rs`
- Modify: `crates/astra-operator/src/lib.rs` (`pub mod vault_gestures;`)
- Test: `crates/astra-operator/tests/vault_gestures.rs` (utilise `mod support;` et `FakeKey`, `RP_ID`, `PIN`)

**Interfaces:**
- Consumes: `gestures::{create_authority, open_with_authorized_key, add_key, remove_key, prove_anchors_open, NewAuthority, NewKey}`, `signing::sign_credential_bindings`, `handoff`, `credentials`, `store`.
- Produces :
  - `gestures::Created` gagne `pub opening: Opened` (l'ouverture de la clé 1, obtenue par la dérivation qui existe déjà). `astra-signer` l'ignore.
  - `pub struct AddedKey { pub slot_id: [u8; 16], pub opening: Opened }` et `pub fn add_key_opened(new, vault, opening, request, pin, now_unix) -> Result<AddedKey>` dans `gestures.rs` ; `add_key` devient `add_key_opened(..).map(|added| added.slot_id)`.
  - Dans `vault_gestures` :

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SetupRefusal { VaultExists, LocationUnavailable, VaultFull, MinimumKeys, UnknownSlot,
                        KeyBeingRemoved, GatewayIdentityMissing, CaTlsAlreadyIssued, DomainComplete }
// messages #[error("…")] en français, une phrase chacun

pub fn check_creation(vault_path: &Path) -> Result<(), SetupRefusal>;
pub fn create_first_key(vault_path: &Path, request: &NewAuthority, authority_url: &str,
                        key: &dyn Authenticator, pin: &str, now_unix: u64) -> anyhow::Result<Opened>;
pub fn check_addition(vault: &AuthorityVault) -> Result<(), SetupRefusal>;
pub fn add_key_with(vault_path: &Path, opening: &Opened, key: &dyn Authenticator,
                    request: &NewKey, pin: &str, now_unix: u64) -> anyhow::Result<AddedKey>;
pub fn prove_opens(vault_path: &Path, openings: &[&Opened]) -> anyhow::Result<()>;
pub fn check_removal<'v>(vault: &'v AuthorityVault, slot_id: &[u8; 16]) -> Result<&'v KeySlot, SetupRefusal>;
pub fn remove_key_with(vault_path: &Path, opening: &Opened, slot_id: &[u8; 16], now_unix: u64) -> anyhow::Result<()>;
pub fn check_marking<'v>(vault_path: &Path, vault: &'v AuthorityVault, slot_id: &[u8; 16]) -> Result<&'v KeySlot, SetupRefusal>;
pub fn mark_key_with(vault_path: &Path, opening: &Opened, slot_id: &[u8; 16], lost: bool, now_unix: u64) -> anyhow::Result<u64>; // époque du document
pub fn rename_key(vault_path: &Path, slot_id: &[u8; 16], label: &str) -> anyhow::Result<()>;
```

Règles que les tests figent :
- `check_creation` : dossier parent absent → `LocationUnavailable` ; fichier présent → `VaultExists`.
- `create_first_key` : `store::save_new`, puis relais `handoff::DomainHandoff::of(&vault)` avec `astra_authority_url = Some(authority_url sans '/' final)`, enregistré par `handoff::save`. `authority_url` doit commencer par `https://`.
- `check_addition` : `slots.len() >= MAX_SLOTS` → `VaultFull`.
- `add_key_with` : `add_key_opened`, `store::save`, puis, si `handoff::identity_of` réussit sur le relais, document re-signé **avec `opening`** (pas d'ouverture de plus) et enregistré ; sinon rien d'autre.
- `check_removal` : slot inconnu → `UnknownSlot` ; `slots.len() <= REQUIRED_SLOTS` → `MinimumKeys`.
- `remove_key_with` : `opening.credential_id` = credential du slot retiré → `KeyBeingRemoved`, rien écrit. Sinon `remove_key` en mémoire ; si identité connue, document signé et **enregistré avant** `store::save` du coffre (ordre d'`astra-signer remove`).
- `check_marking` : slot inconnu → `UnknownSlot` ; relais sans identité → `GatewayIdentityMissing`.
- `mark_key_with` : override `(credential_id, CredentialState::Lost | Active)`, document re-signé et enregistré.
- Les `*_with` refont leur `check_*` (fail-closed) et rendent l'erreur `SetupRefusal` dans l'`anyhow::Error`, récupérable par `downcast_ref::<SetupRefusal>()`.

- [ ] **Step 1: Write the failing tests** dans `tests/vault_gestures.rs`. Chaque test crée son dossier temporaire et l'efface.
  - `creating_a_domain_takes_one_assertion_per_key` : `create_first_key` avec `FakeKey::new(1)` puis `add_key_with` avec `FakeKey::new(2)` → `key1.assertions() == 1`, `key2.assertions() == 1`, coffre `is_bootstrapped()`, relais `astra_authority_url == Some("https://astra.helios.test")`, `prove_opens(&[&first, &added.opening])` OK sans nouvelle assertion.
  - `the_same_token_cannot_take_the_second_slot` : `add_key_with` avec la **même** `FakeKey` → `Err` ; coffre relu : 1 slot, `!is_bootstrapped()`.
  - `creation_refuses_an_existing_vault_and_a_missing_folder` : `check_creation` → `VaultExists` puis `LocationUnavailable`.
  - `adding_a_key_resigns_the_document_without_another_touch` : relais complété (clé WireGuard et `server_name`) et document émis au départ ; `add_key_with` → `key1.assertions() == 1` au total pour le geste, document relu avec une ligne par slot.
  - `a_full_vault_refuses_before_any_key` : coffre à `MAX_SLOTS` → `check_addition == Err(VaultFull)`.
  - `the_opening_key_cannot_remove_itself` : 3 slots, ouverture par la clé du slot visé → erreur `KeyBeingRemoved` ; octets du coffre et du document inchangés.
  - `removal_writes_the_document_before_the_vault` : 3 slots, retrait par une autre clé → document relu avec une ligne `revoked` pour le credential retiré, coffre à 2 slots.
  - `two_keys_are_the_floor` : `check_removal` à 2 slots → `MinimumKeys`.
  - `marking_needs_the_gateway_and_moves_the_state` : sans identité → `GatewayIdentityMissing` ; avec → `mark_key_with(lost = true)` puis `false`, état relu `Lost` puis `Active`, époque strictement croissante.
  - `a_blank_or_long_label_is_refused_and_nothing_moves` : `rename_key` avec `"  "` et 65 caractères → `Err`, octets du coffre inchangés ; avec `"Bureau"` → libellé relu.
- [ ] **Step 2: Run, expect failure** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator --test vault_gestures` → module `vault_gestures` introuvable.
- [ ] **Step 3: Implement** `Created.opening`, `AddedKey`, `add_key_opened`, puis le module `vault_gestures` selon les règles ci-dessus. Le re-signement de document est une seule fonction privée `resign_if_known(vault_path, vault, opening, overrides, now) -> anyhow::Result<Option<u64>>`.
- [ ] **Step 4: Run** la commande du Step 2 → PASS ; `scripts/wsl-cargo test -p astra-operator` et `-p astra-signer` → PASS (aucune régression).
- [ ] **Step 5: Commit** — `feat(astra-operator): key gestures that reuse the opening they already hold`

---

### Task 3: Gestes de domaine et vue du coffre

**Files:**
- Modify: `crates/astra-operator/src/vault_gestures.rs`
- Modify: `crates/astra-operator/src/overview.rs`
- Test: `crates/astra-operator/tests/vault_gestures.rs`, tests existants d'`overview` (dans le fichier ou son `tests` voisin)

**Interfaces:**
- Consumes: Task 2.
- Produces :

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayUpdate { pub gateway_wg_public_key: Option<String>, pub server_name: Option<String>,
    pub astra_service_public_key: Option<String>, pub astra_service_key_epoch: Option<u64>,
    pub astra_authority_url: Option<String> }

pub fn write_relay(vault_path: &Path, update: &RelayUpdate) -> anyhow::Result<DomainHandoff>;
pub fn adopt_gateway(vault_path: &Path, leaf: &PqCertificate, now_unix: u64) -> anyhow::Result<DomainHandoff>;
pub struct Finalization { pub server_name: String, pub gateway_wg_public_key: WireGuardKey,
    pub issues_ca_tls: bool, pub issues_credentials: bool }
pub const CA_TLS_DAYS: u64 = 3650;
pub fn finalization(vault_path: &Path) -> Result<Finalization, SetupRefusal>;
pub struct Finalized { pub ca_tls_pem: Option<String>, pub credentials_epoch: Option<u64> }
pub fn finalize_with(vault_path: &Path, opening: &Opened, now_unix: u64) -> anyhow::Result<Finalized>;
```

- `overview::VaultOverview` gagne `bootstrapped: bool`, `location_available: bool`, `credentials_complete: bool` ; `SlotView` gagne `state: Option<String>` (`active` | `lost`).

Règles :
- `write_relay` : mêmes validations et normalisations qu'`astra-signer domain` (`tools/astra-signer/src/commands/vault.rs`, fonction `domain`) ; relit le relais existant avant d'écrire, rien n'est écrit si une valeur est invalide.
- `adopt_gateway` : `subject` et `wireguard_public_key` de la feuille ; `leaf.verify(ca_pq du relais, PqCertificateRole::Gateway, Some(subject), wireguard, now)` ; relais sans gateway → écrit les deux valeurs ; mêmes valeurs → inchangé ; valeurs différentes → `Err` « le domaine nomme déjà une autre gateway ; en changer est une transition de gateway ».
- `finalization` : relais sans identité → `GatewayIdentityMissing` ; `issues_ca_tls = relais sans ca_tls_certificate` ; `issues_credentials = document absent, ou qui ne vérifie pas sous CA-PQ, ou qui n'a pas de ligne pour un slot du coffre` ; les deux faux → `DomainComplete`.
- `finalize_with` : refait `finalization` ; `CA-TLS` d'abord (`signing::issue_ca_tls` sur `CA_TLS_DAYS`, relais mis à jour avec `ca_tls_epoch` et `ca_tls_certificate` dans la même écriture, comme `astra-signer issue-ca-tls`), puis le document ; `ca_tls_pem` est le PEM du certificat public (même format que `pem_of` d'`astra-signer`).
- `overview::read` : dossier parent absent → `exists: false, location_available: false` ; `state` d'un slot = état de sa ligne dans le document **seulement si** le document vérifie sous le `CA-PQ` du coffre, sinon `None` ; `credentials_complete` comme `issues_credentials == false`.

- [ ] **Step 1: Write the failing tests**
  - `the_relay_takes_only_valid_values` : `astra_authority_url = "http://x"` → `Err` et fichier inchangé ; clé WireGuard valide + `server_name` → relus.
  - `adopting_takes_the_gateway_the_domain_signed` : feuille signée par le `CA-PQ` du domaine → relais complété ; feuille signée par une autre CA → `Err`, relais inchangé ; seconde adoption d'une autre identité → `Err`.
  - `finalizing_issues_what_is_missing_in_one_touch` : relais avec identité, sans `CA-TLS` ni document → `key1.assertions() == 1`, relais avec `ca_tls_certificate`, document relu, `ca_tls_pem` commence par `-----BEGIN CERTIFICATE-----`.
  - `finalizing_twice_never_reissues_ca_tls` : document supprimé après une finalisation → `finalization().issues_ca_tls == false`, `issues_credentials == true` ; second `finalize_with` → `ca_tls_pem == None`, certificat du relais identique ; troisième appel → `DomainComplete`.
  - `finalization_needs_the_gateway` → `GatewayIdentityMissing`.
  - `a_missing_folder_is_not_an_absent_vault` (overview) : `location_available == false`.
  - `the_overview_shows_states_only_from_a_verified_document` : ligne `lost` signée → `state == Some("lost")` ; document altéré → `state == None`, `credentials_complete == false`.
- [ ] **Step 2: Run, expect failure** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator`.
- [ ] **Step 3: Implement** ce qui précède. Ajouter `Serialize` est inutile : `RelayUpdate` ne fait qu'entrer.
- [ ] **Step 4: Run** → PASS. Puis `scripts/wsl-cargo test -p orion operator` → PASS (la vue a grandi, aucun test d'Orion ne casse).
- [ ] **Step 5: Commit** — `feat(astra-operator): finalize a domain and describe its keys' states`

---

### Task 4: Emplacement du coffre dans Orion

**Files:**
- Create: `apps/orion/src-tauri/src/operator/location.rs` (+ `location/tests.rs` si le fichier dépasse ~200 lignes)
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`pub mod location;`, `begin`/`begin_enrollment` prennent `vault_path: PathBuf`)
- Modify: `apps/orion/src-tauri/src/operator/ceremony.rs` (`run` et `run_enrollment` prennent `vault_path: &Path` au lieu d'appeler `store::default_path()` ; `run_with_vault` fusionne dans `run`)
- Modify: `apps/orion/src-tauri/src/commands/ceremonies.rs` (overview et cérémonies lisent l'emplacement de l'état)
- Modify: `apps/orion/src-tauri/src/main.rs` (`AppState.vault_location: operator::location::VaultLocation`, chargé au démarrage ; trois commandes enregistrées)
- Modify: `apps/orion/src-tauri/Cargo.toml` (feature `Win32_UI_Controls_Dialogs` de `windows-sys`, avec un commentaire comme les autres)

**Interfaces:**
- Produces :

```rust
pub const VAULT_FILE_NAME: &str = "authority-vault.json";
pub struct VaultLocation { /* Mutex<Result<Option<PathBuf>, String>> : choix lu, ou réglage illisible */ }
impl VaultLocation {
    pub fn load() -> Self;                                   // lit settings_path()
    pub fn at(settings: PathBuf) -> Self;                    // pour les tests
    pub fn path(&self) -> Result<PathBuf, String>;           // choix, sinon store::default_path() ; réglage illisible → Err
    pub fn view(&self) -> Result<VaultLocationView, String>;
    pub fn choose(&self, path: PathBuf) -> Result<VaultLocationView, String>; // absolu, nom == VAULT_FILE_NAME, persiste
    pub fn reset(&self) -> Result<VaultLocationView, String>;
}
#[derive(Serialize)] pub struct VaultLocationView { pub path: String, pub is_default: bool, pub picker_available: bool }
fn settings_path() -> anyhow::Result<PathBuf>; // <APPDATA>\helios\orion-operator.json, ~/.helios/orion-operator.json ailleurs
#[cfg(windows)] pub fn pick(owner: isize, current: &Path) -> Result<Option<PathBuf>, String>;
```

  - Réglages : `{"vault_path": "<chemin>"}` en `#[serde(deny_unknown_fields)]`, écrits de façon atomique (fichier temporaire + renommage).
  - `pick` : `GetSaveFileNameW`, propriétaire `owner`, titre « Emplacement du coffre opérateur », nom proposé `authority-vault.json`, filtre « Coffre opérateur (authority-vault.json) », drapeaux `OFN_PATHMUSTEXIST | OFN_NOREADONLYRETURN` (sans `OFN_OVERWRITEPROMPT` : choisir un coffre existant est le cas normal). Annulé → `Ok(None)`. Tourne dans `spawn_blocking`.
  - Commandes Tauri : `operator_vault_location() -> VaultLocationView`, `choose_vault_location(window) -> Option<VaultLocationView>` (hors Windows : `Err("le choix d'emplacement n'existe que sous Windows")`), `reset_vault_location() -> VaultLocationView`. Le propriétaire vient d'`owner_window(&window)`.

- [ ] **Step 1: Write the failing tests** (`location` et `ceremony/tests.rs`)
  - `the_default_applies_until_a_choice_is_made` : `VaultLocation::at(tmp/settings.json)` absent → `is_default`, `path() == store::default_path()`.
  - `a_choice_survives_a_reload` : `choose(tmp/x/authority-vault.json)` puis `VaultLocation::at(même réglage).path()` identique.
  - `only_an_absolute_vault_file_is_accepted` : chemin relatif et `tmp/autre.json` → `Err`, réglage inchangé.
  - `an_unreadable_setting_is_an_error_not_the_default` : réglage `"{"` → `path()` est `Err`.
  - `verify_key_is_served` et les tests d'enrôlement passent le chemin explicitement (adapter leurs appels à la nouvelle signature, sans changer leurs assertions).
- [ ] **Step 2: Run, expect failure** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion operator`.
- [ ] **Step 3: Implement** ; aucune autre occurrence de `store::default_path()` ne doit rester dans `apps/orion/src-tauri/src/operator` ni dans `commands/ceremonies.rs` (vérifier par `grep -rn default_path apps/orion/src-tauri/src`). Le registre d'invitations garde son emplacement.
- [ ] **Step 4: Run** → PASS ; `scripts/wsl-cargo clippy -p orion --all-targets -- -D warnings` → aucun avertissement. Le code `cfg(windows)` n'est pas compilé ici : le signaler.
- [ ] **Step 5: Commit** — `feat(orion): let the operator choose where the vault lives`

---

### Task 5: Cérémonies du coffre et commandes sans clé (Orion)

**Files:**
- Create: `apps/orion/src-tauri/src/operator/ceremony/vault.rs`
- Modify: `apps/orion/src-tauri/src/operator/ceremony.rs` (`mod vault;`, `pub use vault::run_vault;`)
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`VaultGesture`, `OperatorCeremony::begin_vault`)
- Modify: `apps/orion/src-tauri/src/commands/ceremonies.rs`, `apps/orion/src-tauri/src/main.rs` (commandes)
- Test: `apps/orion/src-tauri/src/operator/ceremony/tests.rs`, tests de `operator/mod.rs`

**Interfaces:**
- Consumes: Tasks 1 à 4 ; `open_key`, `Ceremony`, `awaited_action` de `ceremony.rs` (accessibles depuis le sous-module).
- Produces :

```rust
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultGesture {
    CreateDomain { rp_id: String, authority_url: String, first_label: String, second_label: String },
    AddKey { label: String, role: KeyRole },          // KeyRole: serde "principale" | "recuperation"
    RemoveKey { slot_id: String },
    MarkKey { slot_id: String, lost: bool },
    FinalizeDomain,
}
impl VaultGesture { fn validate(&self) -> Result<(), String>; fn operation(&self) -> OperationKind; }
impl OperatorCeremony { pub async fn begin_vault(&self, gesture: VaultGesture, vault_path: PathBuf) -> Result<OperatorStatus, String>; }
pub fn run_vault(session_id: Id16, gesture: VaultGesture, presses: Receiver<Press>,
                 publish: &mut dyn FnMut(OperatorStatus), deposit: &mut dyn FnMut(OperatorArtifact),
                 vault_path: &Path) -> Result<(), String>;
```

  - `validate` : `rp_id` 1 à 253 caractères, minuscules ASCII, chiffres, `-` et `.`, au moins un point, aucun libellé vide ni bordé de `-`, et pas une adresse IP (`str::parse::<std::net::IpAddr>` échoue) ; `authority_url` commence par `https://`, sans espace, 256 caractères au plus ; libellés non vides après `trim`, `MAX_LABEL_CHARS` au plus ; `slot_id` 32 hexadécimaux.
  - Déroulé (chaque étape publie son état ; tout refus avant la clé n'en demande aucune) :
    - `CreateDomain` : `check_creation` → manifeste → `AwaitingKey{1,2,RegisterKey}` → `create_first_key` → `AwaitingKey{2,2,RegisterKey}` → `add_key_with` → `prove_opens` → `Done`. Arrêt après la clé 1 : `Cancelled` ou `Failed` selon le cas ; le coffre à une clé reste.
    - `AddKey` : `check_addition` → manifeste → `AwaitingKey{1,2,OpenVault}` → `open_with_authorized_key` → `AwaitingKey{2,2,RegisterKey}` → `add_key_with` → `Done`.
    - `RemoveKey` / `MarkKey` : `check_*` → manifeste → `AwaitingKey{1,1,OpenVault}` → `*_with` → `Done`.
    - `FinalizeDomain` : `finalization` → manifeste (`ca_tls_days = CA_TLS_DAYS`) → `AwaitingKey{1,1,OpenVault}` → `finalize_with` → artefact `ca-tls.pem` (`ArtifactEncoding::Text`) quand émis → `Done`.
    - `SetupRefusal` → `Refusal` du même nom ; `UnknownSlot` → `HandoffMismatch` ; ouverture ou enregistrement refusé par la clé → `KeyDeclined` ; coffre illisible → `VaultUnavailable`.
    - `keys` : le libellé de chaque clé qui a répondu, comme `verify_key`.
  - Commandes Tauri (toutes lisent `state.vault_location.path()`) :
    - `begin_vault_ceremony(gesture: VaultGesture) -> OperatorStatus` ;
    - `rename_operator_key(slot_id: String, label: String) -> ()` ;
    - `write_domain_relay(update: RelayUpdate) -> ()` ;
    - `adopt_connected_gateway() -> ()` : `connected_gateway` + `gateway_negotiation` + `decode_pq_certificate` + `adopt_gateway`, sans gateway connectée → `Err(NO_CONNECTED_GATEWAY)` ;
    - `operator_domain_defaults() -> DomainDefaults { rp_id: Option<String> }` : hôte de l'`endpoint` du profil sélectionné, sans port, en minuscules, `None` si c'est une adresse IP ou s'il ne passe pas `validate`.

- [ ] **Step 1: Write the failing tests** (émetteur d'appuis abandonné par `drop` dans chaque test)
  - `a_creation_over_an_existing_vault_asks_for_no_key` → `Refusal::VaultExists`, `no_key_was_asked`.
  - `a_creation_in_a_missing_folder_asks_for_no_key` → `LocationUnavailable`.
  - `abandoning_before_the_first_key_creates_nothing` : appuis abandonnés au premier `AwaitingKey` → `GestureState::Cancelled`, aucun fichier dans le dossier.
  - `a_full_vault_refuses_an_addition_before_the_key` → `VaultFull`.
  - `removing_down_to_one_key_is_refused_before_the_key` → `MinimumKeys`.
  - `marking_without_the_gateway_is_refused_before_the_key` → `GatewayIdentityMissing`.
  - `a_finished_domain_has_nothing_to_finalize` → `DomainComplete`.
  - `the_creation_manifest_shows_what_will_be_fixed` : premier état offert porte `DomainCreation` avec le RP ID et l'origine saisis, `AwaitingKey{1,2,RegisterKey}`.
  - `gestures_with_invalid_values_open_no_ceremony` : `rp_id` `"192.168.1.1"`, `"Astra.Example"`, `"astra"` ; `authority_url` `"http://astra.example"` ; libellé `" "` ; `slot_id` `"xyz"` → `validate` est `Err`.
  - `the_rp_id_is_suggested_only_from_a_name` : endpoint `gw.tail1234.ts.net:51820` → `Some("gw.tail1234.ts.net")` ; `10.0.0.1:51820` et `[fd00::1]:51820` → `None`.
- [ ] **Step 2: Run, expect failure** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion operator`.
- [ ] **Step 3: Implement** ; le `other =>` de `run` ne doit plus absorber aucun des cinq genres (ils passent par `run_vault`, jamais par `run`, qui les refuse `Internal` comme aujourd'hui).
- [ ] **Step 4: Run** → PASS ; clippy `-D warnings` → propre.
- [ ] **Step 5: Commit** — `feat(orion): run the vault and domain gestures in the operator ceremony`

---

### Task 6: Contrat de l'IHM et fenêtre de cérémonie

**Files:**
- Modify: `apps/orion/src/types.ts`, `apps/orion/src/api.ts`, `apps/orion/src/views/OperatorCeremony.tsx`
- Test: `apps/orion/src/views/OperatorCeremony.test.tsx` (existant ou créé)

**Interfaces:**
- Produces (TS, miroir exact des Tasks 1, 3, 4, 5) : `OperationKind` (+5), `KeyPurpose` (+`register_key`), `Refusal` (+8), `AstraManifest` (+5 formes), `VaultOverview.bootstrapped/location_available/credentials_complete`, `SlotView.state?: 'active' | 'lost'`, `VaultGesture`, `RelayUpdate`, `VaultLocationView`, `DomainDefaults` ; dans `api.ts` : `beginVaultCeremony`, `renameOperatorKey`, `writeDomainRelay`, `adoptConnectedGateway`, `operatorDomainDefaults`, `operatorVaultLocation`, `chooseVaultLocation`, `resetVaultLocation`.
- Textes fixés :
  - `TITLES` : `create_domain` « Créer un domaine », `add_key` « Ajouter une clé », `remove_key` « Retirer une clé », `mark_key` « Changer l’état d’une clé », `finalize_domain` « Finaliser le domaine ».
  - `VERBS` : « Créer avec les clés », « Ajouter avec les clés », « Retirer avec la clé », « Signer avec la clé », « Finaliser avec la clé ».
  - `register_key` : « Brancher la nouvelle clé{ (i sur n)}, pour l’enregistrer dans le coffre. », précédé de « Débrancher la clé précédente. » quand `index > 1`.
  - `refusalSentence` :
    - `vault_exists` « Un coffre existe déjà à cet emplacement : ajouter une clé plutôt que créer un second domaine. »
    - `location_unavailable` « L’emplacement du coffre est introuvable : rebrancher son support ou choisir un autre emplacement. »
    - `vault_full` « Le coffre porte déjà huit clés : en retirer une avant d’en ajouter. »
    - `minimum_keys` « Le coffre doit garder au moins deux clés : en ajouter une avant d’en retirer. »
    - `key_being_removed` « La clé qui a ouvert le coffre est celle à retirer : recommencer avec une autre clé. »
    - `gateway_identity_missing` « Le relais ne nomme pas encore la gateway : reprendre la gateway connectée, ou terminer son amorçage. »
    - `ca_tls_already_issued` « Ce domaine a déjà sa CA-TLS : la remplacer est une rotation. »
    - `domain_complete` « Le domaine est déjà finalisé : CA-TLS et document de credentials sont en place. »
  - Lignes de manifeste : création (`nom WebAuthn`, `origine d’Astra`, `première clé`, `seconde clé`) ; ajout (`coffre`, `libellé`, `rôle`) ; retrait (`coffre`, `clé`, `rôle`) ; état (`coffre`, `clé`, `nouvel état` : « perdue » | « active ») ; finalisation (`coffre`, `nom serveur`, `gateway`, `CA-TLS` : « émise, 3650 jours » | « déjà en place », `credentials` : « émis » | « à jour »).

- [ ] **Step 1: Write the failing tests** : `every_new_refusal_has_its_sentence` (les huit phrases ci-dessus), `a_new_key_is_asked_for_by_name` (`register_key`, `index 2 of 2` → contient « Débrancher la clé précédente » et « nouvelle clé »), `the_finalization_manifest_says_what_it_issues`.
- [ ] **Step 2: Run, expect failure** — `cd apps/orion && npx vitest run src/views/OperatorCeremony.test.tsx`.
- [ ] **Step 3: Implement** ; `tsc` impose l'exhaustivité des `Record<OperationKind, …>` et des `switch`.
- [ ] **Step 4: Run** `node_modules/.bin/tsc --noEmit -p . && npx vitest run` → PASS.
- [ ] **Step 5: Commit** — `feat(orion-ui): speak the vault gestures in the ceremony window`

---

### Task 7: *Coffre et clés* (IHM)

**Files:**
- Modify: `apps/orion/src/views/astra/VaultPanel.tsx`, `apps/orion/src/views/astra/useOverview.ts` (ajoute `refresh()`)
- Create si `VaultPanel.tsx` dépasse ~300 lignes : `apps/orion/src/views/astra/CreateDomainForm.tsx`, `apps/orion/src/views/astra/KeyRow.tsx`
- Test: `apps/orion/src/views/astra/VaultPanel.test.tsx`

**Interfaces:**
- Consumes: Task 6. `onCeremony(status)` comme aujourd'hui ; la vue rappelle `refresh()` quand une cérémonie se termine (prop `ceremonyRevision` ou rappel d'`AstraView`, au choix du constructeur).
- Comportement :
  - Emplacement : chemin, « Changer… » (si `picker_available`), « Emplacement par défaut » (si `!is_default`). Erreur de réglage affichée telle quelle.
  - `!location_available` → alerte « Emplacement introuvable », aucun formulaire de création.
  - `!exists` (emplacement disponible) → formulaire « Créer un domaine » : RP ID prérempli par `operatorDomainDefaults`, avertissement « Ce nom ne se change plus. Prenez le nom Tailscale de la gateway si elle est dans un tailnet. », origine préremplie `https://<RP ID>` qui suit le RP ID tant qu'on ne l'a pas modifiée, libellés « Clé principale » et « Clé de récupération ». Le texte « d’ici là, `astra-signer init` » disparaît.
  - `exists && !bootstrapped` → bandeau d'alerte permanent « Une seule clé : la perdre, c’est perdre le domaine. » avec « Ajouter la clé de récupération » (geste `add_key`, rôle `recuperation`).
  - Table des clés : libellé, rôle, état (« perdue » si `state === 'lost'`) ; actions « Renommer » (édition en place, Entrée valide, Échap annule), « Marquer perdue » / « Réactiver » (désactivé avec « La gateway n’est pas encore dans le relais. » si `domain?.server_name` ou `domain?.gateway_wg_public_key` manque), « Retirer » (désactivé avec « Le coffre doit garder au moins deux clés. » à 2 clés ; sinon boîte de confirmation : « Retirer « {libellé} » ? Le retrait est définitif. Une sauvegarde antérieure du coffre reste ouvrable par cette clé. »).
  - « Ajouter une clé » : libellé et rôle ; désactivé avec « Le coffre porte déjà huit clés. » à `max_slots`.
  - « Vérifier une clé » inchangé.

- [ ] **Step 1: Write the failing tests** : `an_absent_vault_offers_the_domain_creation_with_a_suggested_name`, `the_origin_follows_the_rp_id_until_edited`, `an_unavailable_location_offers_no_creation`, `a_single_key_vault_shows_the_unbootstrapped_banner`, `removal_is_disabled_at_two_keys_and_confirmed_above`, `marking_waits_for_the_gateway`, `renaming_saves_on_enter_and_refreshes`, `adding_is_disabled_when_full`.
- [ ] **Step 2: Run, expect failure** — `npx vitest run src/views/astra/VaultPanel.test.tsx`.
- [ ] **Step 3: Implement** dans la direction artistique existante (MUI, tailles de police des panneaux actuels, fenêtre 520×560, `minWidth` 500 : rien ne déborde horizontalement).
- [ ] **Step 4: Run** `tsc` + `vitest` → PASS.
- [ ] **Step 5: Commit** — `feat(orion-ui): create a domain and manage its keys from the vault section`

---

### Task 8: *Domaine* (IHM)

**Files:**
- Modify: `apps/orion/src/views/astra/DomainPanel.tsx`
- Test: `apps/orion/src/views/astra/DomainPanel.test.tsx`

**Interfaces:**
- Consumes: Task 6, `useOverview().refresh`.
- Comportement :
  - Lecture du relais inchangée, plus un bouton « Modifier » qui ouvre le formulaire (clé WireGuard de la gateway, nom de service, clé de service Astra, époque, origine d'Astra). À l'enregistrement, toute valeur déjà présente qui change est listée « avant → après » dans une confirmation ; seules les valeurs modifiées partent dans `RelayUpdate`.
  - « Reprendre la gateway connectée » : visible tant que le relais n'a pas la gateway ; erreur rendue sous le bouton.
  - « Finaliser le domaine » : visible tant que `!ca_tls_present || !credentials_complete` ; désactivé avec « La gateway n’est pas encore dans le relais. » sans identité ; lance le geste `finalize_domain`. Le PEM est proposé à l'enregistrement par `ArtifactDownloads` à la fin de la cérémonie, comme les artefacts d'enrôlement.

- [ ] **Step 1: Write the failing tests** : `only_changed_values_are_sent_and_overwrites_are_confirmed`, `the_connected_gateway_is_offered_until_the_relay_names_one`, `finalizing_waits_for_the_gateway_and_hides_when_complete`.
- [ ] **Step 2: Run, expect failure** — `npx vitest run src/views/astra/DomainPanel.test.tsx`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tsc` + `vitest` → PASS.
- [ ] **Step 5: Commit** — `feat(orion-ui): complete and finalize the domain from its section`

---

### Task 9: Documentation et régression complète

**Files:**
- Modify: `docs/DEPLOIEMENT-ASTRA.md` (« Amorçage en deux passages », « `astra-signer init` », le document de credentials) : gestes d'Orion d'abord, `astra-signer` cité comme voie transitoire jusqu'au lot 7, `issue-gateway-bootstrap` jusqu'au lot 6.
- Modify: `docs/testing/MANUAL-TESTING.md` : section « F14 lot 3 — coffre, clés et domaine », sur un **coffre d'essai** (« Changer… » vers un dossier vide), deux YubiKey puis une troisième si possible : créer (compter les dialogues Windows, attendu 4), ajouter, renommer, marquer perdue puis réactiver, retirer (refus en retirant avec la clé visée, puis succès avec une autre), clé débranchée du support (emplacement introuvable), « Finaliser » si une gateway d'essai est connectée, retour à l'emplacement par défaut.
- Modify: `docs/ROADMAP.md` (ligne F14 : lot 3 livré sur la branche, validation Windows à faire).
- Modify: `docs/superpowers/specs/2026-10-28-f14-lot3-coffre-domaine-design.md` : section « Amendements » pour tout écart pris pendant l'exécution.

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Run the full regression in the background**, journal dans l'espace SDD de la branche : `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh > .superpowers/sdd/2026-10-28-f14-lot3/regression.log 2>&1` → exit 0, aucun `FAILED`, avertissements `cargo audit` seulement ceux déjà autorisés.
- [ ] **Step 3: Commit** — `docs: play F14 lot 3 from Orion`
