# Enrôlement v5 sans transport de clé privée — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remplacer `helios enroll` à un geste par l'enrôlement du §15 : invitation `CA-PQ`, clés nées dans Orion, demande à trois preuves, leafs émises par les ancres du domaine, document `.orion` v5 signé JCS et lié à la demande.

**Architecture:** Les trois objets publics et leurs transcriptions vivent dans `aether::key_negotiation::enrollment`. Tout ce qui ouvre le coffre (signature de l'invitation, émission des leafs, signature du document, registre des invitations) va dans `astra-operator`, piloté par `astra-signer enroll`. `tools/helios` ne garde que le côté gateway (brouillon public du document). `orion-core` porte la demande en attente scellée et l'import v5 ; l'app Tauri expose les gestes à l'écran *Profils*.

**Tech Stack:** Rust 2021 (MSRV 1.95), `fips204` via `aether::ml_dsa`, `x25519-dalek` 3, `aws-lc-rs` (HMAC, SHA-256), `rcgen` 0.14, `serde_json_canonicalizer` 0.3.2, Tauri 2 + React/MUI, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-19-enrolement-v5-design.md`, qui renvoie à `docs/specification/NEGOCIATION-DE-CLE-V5.md` §15 pour les octets.

## Global Constraints

- Identifiants, commentaires, logs et noms de tests en anglais ; `docs/` en français ; messages utilisateur CLI/Tauri en français, comme le code voisin.
- Aucun `TODO`/`FIXME`/`todo!()`/`unimplemented!()` ; pas de `unwrap`/`expect` hors tests.
- Toute compilation passe par `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo …` depuis `/home/christophe/helios-wt/f4-classic` ; jamais de `CARGO_TARGET_DIR`. `web/dist` doit exister pour `clippy --all-features` de `helios-api` (`npm run build --prefix web`).
- Seule dépendance nouvelle : `serde_json_canonicalizer = "0.3.2"` dans `[workspace.dependencies]`, utilisée par `aether` seulement.
- Tout aléa par `aether::random` ; toute signature ML-DSA-87 par `aether::ml_dsa` avec un `ctx` du registre `SUPPORTED_CONTEXTS`.
- Domaines (`ctx` et préfixe) exacts : `helios-key-negotiation-enrollment-invitation-v5`, `helios-key-negotiation-enrollment-request-v5`, `helios-key-negotiation-orion-document-v5` ; preuve WireGuard : `helios-key-negotiation-wireguard-pop-v5` (HMAC, pas un `ctx`).
- Bornes : `format_version = 1` et `protocol_version = 5` pour invitation et demande ; document `format_version = 5` ; fenêtre d'invitation `0 < not_after - not_before ≤ 86 400` s ; `requested_name` UTF-8 NFC, 1 à 255 octets ; CSR DER ≤ 16 384 octets ; `minimum_mode = ml_kem` ; `invitation_id`, `request_id` 16 octets non nuls.
- Empreinte d'invitation/demande = `SHA-256(signed_bytes || len(signature):u32 || signature)` ; `u16`/`u32`/`u64` en big-endian, comme `aether::certificates::encoding::CanonicalBytes`.
- Secrets (`Z`, clés privées, clé X25519 éphémère) en `Zeroizing`/`SecretString`, jamais dans un `Debug`, jamais sérialisés par une dérive générique.
- `tools/helios`, `orion-core` et l'app Orion ne dépendent pas d'`astra-operator`.
- Registre opérateur : `~/.helios/enrollment-invitations/<invitation_id hex>.json`, répertoire `0700`, fichiers `0600`, écriture atomique + `fsync` du répertoire.
- Fichiers échangés : `<nom>.helios-invite` (`format = "helios-enrollment-invitation"`), `<nom>.helios-request` (`format = "helios-enrollment-request"`), `.orion` (document v5).

## Review Focus

1. **Invitation présentée deux fois** (même demande rejouée, ou seconde demande sur la même invitation) : le second `accept` est refusé sans rien émettre, et l'état reste `consumed`. Test dans la tâche 3.
2. **Arrêt brutal après la consommation** (échec d'ouverture du coffre ou d'émission) : l'invitation reste `consumed`, sa clé X25519 est détruite, aucun `accept` ne la rouvre. Test dans la tâche 4.
3. **Document importé alors qu'Orion n'a aucune demande en attente** (autre poste, demande abandonnée, Orion réinstallé) : brouillon non connectable qui nomme la clé attendue, rien n'est scellé. Test dans la tâche 7.
4. **Fichier réencodé en transit** (BOM UTF-8, UTF-16 PowerShell) pour `.helios-invite` et `.helios-request` : lu comme le `.orion` aujourd'hui, par le même `decode_document`. Test dans la tâche 6.
5. **Clé publique gateway ou leaf PQ gateway du document différente de l'invitation** : import refusé avant tout scellement, message qui nomme les deux valeurs. Test dans la tâche 7.

---

### Task 1: Types d'invitation et de demande dans `aether`

**Files:**
- Create: `crates/aether/src/key_negotiation/enrollment.rs`, `crates/aether/src/key_negotiation/enrollment/tests.rs`
- Modify: `crates/aether/src/key_negotiation/mod.rs` (module + `pub use`), `crates/aether/src/ml_dsa.rs` (`SUPPORTED_CONTEXTS`), `crates/aether/Cargo.toml` (`x25519-dalek` si absent), `docs/specification/NEGOCIATION-DE-CLE-V5.md` (table des domaines du §8)

**Interfaces:**
- Produces (module `aether::key_negotiation::enrollment`, réexporté par `aether::key_negotiation`) :
  - `pub struct EnrollmentInvitation { format_version: u16, protocol_version: u16, invitation_id: Id16, gateway_wg_public_key: WireGuardKey, gateway_certificate_fingerprint: Fingerprint, server_name: String, operator_ca_public_key: MlDsa87PublicKey, wireguard_proof_public_key: WireGuardKey, not_before_unix: u64, not_after_unix: u64, minimum_mode: ProtectionMode, allow_readmission: bool, operator_signature: MlDsa87Signature }` (`Serialize`, `Deserialize`, `deny_unknown_fields`).
  - `impl EnrollmentInvitation { pub fn signed_bytes(&self) -> Vec<u8>; pub fn fingerprint(&self) -> Fingerprint; pub fn validate(&self) -> Result<(), EnrollmentError>; pub fn verify(&self, pinned_ca: &MlDsa87PublicKey, now_unix: u64) -> Result<(), EnrollmentError>; #[cfg(feature = "key-negotiation-signing")] pub fn sign(self, ca_pq_private_key: &[u8]) -> Result<Self, EnrollmentError> }`.
  - `pub struct EnrollmentRequest { format_version: u16, protocol_version: u16, invitation_id: Id16, invitation_fingerprint: Fingerprint, request_id: Id16, timestamp_unix: u64, requested_name: String, client_wg_public_key: WireGuardKey, tls_csr: DerCertificate, client_ml_dsa_87_public_key: MlDsa87PublicKey, wireguard_proof: [u8; 32] (hex en JSON), client_signature: MlDsa87Signature }` avec `signed_bytes`, `fingerprint`, `validate`, `verify(&self, invitation: &EnrollmentInvitation) -> Result<(), EnrollmentError>` (liaison, fenêtre, auto-signature, CSR signée par sa clé et `ClientAuth`), et `#[cfg(signing)] pub fn sign(self, client_ml_dsa_private_key: &[u8]) -> Result<Self, EnrollmentError>`.
  - `pub fn wireguard_proof(client_wg_private_key: &[u8; 32], invitation: &EnrollmentInvitation, request: &EnrollmentRequest) -> Result<[u8; 32], EnrollmentError>` et `pub fn verify_wireguard_proof(proof_private_key: &[u8; 32], invitation: &EnrollmentInvitation, request: &EnrollmentRequest) -> Result<(), EnrollmentError>` (data du §15.2, `request.wireguard_proof` ignoré dans le calcul, comparaison temps constant).
  - `pub struct InvitationFile` / `RequestFile` : enveloppes `{ format, invitation | request }`, et `pub fn decode_invitation_file(text: &str) -> Result<EnrollmentInvitation, EnrollmentError>`, `pub fn decode_request_file(text: &str) -> Result<EnrollmentRequest, EnrollmentError>`, `pub fn encode_invitation_file(&EnrollmentInvitation) -> String`, `pub fn encode_request_file(&EnrollmentRequest) -> String`.
  - `#[derive(Debug, thiserror::Error)] pub enum EnrollmentError { Format(&'static str), Window, Signature, Binding(&'static str), Proof, Csr, ZeroSharedSecret, Random, Signing }` — messages anglais ; la traduction se fait aux frontières.

- [ ] **Step 1: Write the failing tests** in `enrollment/tests.rs`, keypairs from `aether::ml_dsa::generate_keypair` and `aether::wg::generate_keypair`:
  - `an_invitation_signs_and_verifies_under_its_ca` ; `an_invitation_verified_under_another_ca_is_refused` (`EnrollmentError::Signature`).
  - `the_invitation_transcript_is_byte_exact` : invitation à champs fixes (ids `[1;16]`, clés `[2;32]`, `[3;32]`, nom `vpn.example.net`, fenêtre `1_000..87_400`), `signed_bytes()` comparé à un vecteur construit à la main dans le test dans l'ordre du §15.3 (préfixe ASCII, `u16` BE, longueurs `u32` BE, `minimum_mode` octet `2`, `allow_readmission` octet `0`).
  - `an_invitation_window_above_24_hours_is_refused` (`86_401`), `an_empty_window_is_refused`, `an_expired_invitation_is_refused` (`now = not_after + 1`), `a_zero_invitation_id_is_refused`.
  - `a_request_bound_to_its_invitation_verifies` ; `a_request_naming_another_invitation_fingerprint_is_refused` ; `a_request_outside_the_invitation_window_is_refused` ; `a_non_nfc_or_long_name_is_refused` (`"e\u{301}"`, 256 octets) ; `an_oversized_csr_is_refused` (16 385 octets) ; `a_csr_not_signed_by_its_key_is_refused`.
  - `the_wireguard_proof_verifies_with_the_ephemeral_private_key` ; `a_proof_for_another_name_is_refused` ; `a_low_order_point_yields_zero_secret_and_is_refused` (clé publique éphémère tout à zéro → `ZeroSharedSecret`).
  - `invitation_and_request_files_round_trip_through_bom_and_unknown_fields` : `decode_*_file` accepte un BOM UTF-8 en tête, refuse un champ inconnu et un `format` étranger.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether --all-features enrollment` — expected: compile failure (module absent).
- [ ] **Step 3: Implement** the types in `enrollment.rs`, transcripts with `CanonicalBytes` (ou son équivalent local s'il est privé : même encodage BE + `u32` de longueur), CSR checked by the existing x509 helpers of `aether::certificates::x509` (signature PKCS#10 vérifiée, clé publique extraite), NFC via the crate already used for names if any (sinon comparer à `unicode_normalization` seulement s'il est déjà au lockfile ; à défaut, refuser tout octet non ASCII imprimable — consigner ce choix dans le module). Add the three domains to `SUPPORTED_CONTEXTS` and to the §8 table of the spec.
- [ ] **Step 4: Run** the same test command — expected: all `enrollment` tests PASS; then `scripts/wsl-cargo test -p aether` (sans `--all-features`) — expected: PASS (les `sign` sont derrière la feature).
- [ ] **Step 5: Commit** `feat(aether): add the v5 enrollment invitation and request`.

### Task 2: Document `.orion` v5 signé JCS dans `aether`

**Files:**
- Modify: `Cargo.toml` (workspace dep), `crates/aether/Cargo.toml`, `crates/aether/src/key_negotiation/enrollment.rs`, `crates/aether/src/key_negotiation/enrollment/tests.rs`

**Interfaces:**
- Consumes: Task 1 types.
- Produces:
  - `pub const ENROLLMENT_DOCUMENT_FORMAT: &str = "orion-profile"`, `pub const ENROLLMENT_DOCUMENT_VERSION: u16 = 5`.
  - `pub struct EnrollmentDocument { format: String, format_version: u16, invitation_id: Id16, request_id: Id16, request_fingerprint: Fingerprint, operator_ca_fingerprint: Fingerprint, issued_at_unix: u64, profile: serde_json::Map<String, serde_json::Value>, client_tls_certificate: DerCertificate, client_pq_certificate: String /* JSON du PqCertificate, base64 */, operator_signature: Option<MlDsa87Signature> }` — `deny_unknown_fields` ; `profile` est opaque ici et validé par `orion-core` (tâche 7).
  - `impl EnrollmentDocument { pub fn parse(text: &str) -> Result<Self, EnrollmentError>; pub fn canonical_unsigned(&self) -> Result<Vec<u8>, EnrollmentError>; pub fn signed_bytes(&self) -> Result<Vec<u8>, EnrollmentError>; pub fn verify(&self, pinned_ca: &MlDsa87PublicKey) -> Result<(), EnrollmentError>; #[cfg(signing)] pub fn sign(self, ca_pq_private_key: &[u8]) -> Result<Self, EnrollmentError>; pub fn to_json(&self) -> Result<String, EnrollmentError> }`.
  - `parse` refuse : champ dupliqué à tout niveau (pré-passe `serde_json::Value` insuffisante — utiliser un `Deserialize` de `Map` qui échoue sur doublon, ou le refus de doublons de `serde_json_canonicalizer` s'il en a un), tout nombre non entier n'importe où, `format`/`format_version` étrangers, `operator_ca_fingerprint` ≠ `operator_ca.authority_fingerprint()` à la vérification.
  - `signed_bytes = b"helios-key-negotiation-orion-document-v5" || len(jcs):u32 BE || jcs`, où `jcs = serde_json_canonicalizer::to_vec(&document_without_operator_signature)`.

- [ ] **Step 1: Write the failing tests**:
  - `a_document_signs_and_verifies_after_key_reordering` : signer, réordonner les clés du JSON et l'espacement, reparser, vérifier — PASS.
  - `any_byte_change_in_the_profile_invalidates_the_signature` : modifier `profile.name`.
  - `a_duplicate_field_is_refused` (`"request_id"` deux fois, et doublon dans `profile`).
  - `a_float_anywhere_is_refused` (`profile.persistent_keepalive: 25.5`).
  - `a_document_under_an_unpinned_ca_is_refused`.
  - `the_canonical_form_matches_rfc8785_ordering` : objet `{"b":1,"a":"é\u{2028}"}` → octets attendus littéraux `{"a":"é ","b":1}` (forme JCS).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p aether --all-features enrollment` — expected: FAIL (types absents).
- [ ] **Step 3: Implement**; add `serde_json_canonicalizer = "0.3.2"` to `[workspace.dependencies]` and `serde_json_canonicalizer.workspace = true` to `aether`.
- [ ] **Step 4: Run** the tests — PASS; `cargo deny`/`cargo audit` étant dans la régression, ne rien lancer d'autre ici.
- [ ] **Step 5: Commit** `feat(aether): sign the v5 Orion document over its JCS form`.

### Task 3: Registre des invitations dans `astra-operator`

**Files:**
- Create: `crates/astra-operator/src/enrollment.rs`, `crates/astra-operator/src/enrollment/tests.rs`
- Modify: `crates/astra-operator/src/lib.rs`

**Interfaces:**
- Consumes: `EnrollmentInvitation`, `EnrollmentRequest` (tâche 1).
- Produces:
  - `pub enum InvitationState { Issued, Consumed { request_fingerprint: Fingerprint, client_wg_public_key: WireGuardKey, consumed_at: u64 }, Revoked { at: u64 }, Expired }` (sérialisé `snake_case`).
  - `pub struct InvitationRecord { invitation: EnrollmentInvitation, state: InvitationState, proof_private_key: Option<SecretString> /* base64, détruit hors Issued */ }` — pas de `Debug` dérivé.
  - `pub struct InvitationRegistry { directory: PathBuf }` avec `pub fn default_location() -> Result<Self>` (`~/.helios/enrollment-invitations`), `pub fn at(directory: PathBuf) -> Self`, `pub fn issue(&self, record: InvitationRecord) -> Result<()>` (refuse un id existant), `pub fn load(&self, id: &Id16) -> Result<InvitationRecord>`, `pub fn list(&self, now_unix: u64) -> Result<Vec<InvitationRecord>>` (purge d'abord les expirées), `pub fn consume(&self, id: &Id16, request: &EnrollmentRequest, now_unix: u64) -> Result<ConsumedInvitation>` et `pub fn revoke(&self, id: &Id16, now_unix: u64) -> Result<()>`, `pub fn readmits(&self, key: &WireGuardKey) -> Result<bool>` (une invitation consommée a déjà admis cette clé).
  - `pub struct ConsumedInvitation { pub invitation: EnrollmentInvitation }` — rendu seulement après écriture + `fsync`.
  - `consume` fait, dans cet ordre : charger ; refuser si l'état n'est pas `Issued` ou si `now > not_after` ; `request.verify(&invitation)` ; `verify_wireguard_proof` avec la clé éphémère ; si `readmits(client_wg_public_key)` et `!allow_readmission` → refus ; écrire l'état `Consumed` **sans** clé éphémère (fichier temporaire, `rename`, `fsync` du répertoire).

- [ ] **Step 1: Write the failing tests** (registre dans un `tempfile::tempdir()`) :
  - `an_issued_invitation_is_consumed_once` : second `consume` avec la même demande → erreur, état toujours `Consumed`.
  - `a_second_request_on_a_consumed_invitation_is_refused`.
  - `consumption_destroys_the_ephemeral_key_on_disk` : relire le fichier brut, aucune trace de la clé base64.
  - `a_bad_proof_leaves_the_invitation_issued` (refus avant écriture).
  - `an_expired_invitation_is_purged_by_list_and_cannot_be_consumed`.
  - `a_revoked_invitation_cannot_be_consumed`.
  - `a_key_already_enrolled_needs_allow_readmission`.
  - `registry_files_are_private` (`#[cfg(unix)]`, modes `0700`/`0600`).
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator enrollment` — FAIL.
- [ ] **Step 3: Implement**, reusing the crate's existing private-file write helper (`store.rs`) for `0600` + atomic rename.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(astra-operator): add the single-use enrollment invitation registry`.

### Task 4: Gestes d'enrôlement sous `CA-PQ`

**Files:**
- Create: `crates/astra-operator/src/signing/enrollment.rs`
- Modify: `crates/astra-operator/src/signing/mod.rs`, `crates/astra-operator/src/gestures.rs` (extraire `require_distinct_credentials(required: usize, openings: &[&Opened])` de `require_scope_credentials`, qui l'appelle), tests à côté des existants

**Interfaces:**
- Consumes: tâches 1–3, `with_anchors`, `AuthorityVault`, `Opened`, `DomainHandoff`.
- Produces:
  - `pub fn enrollment_credentials(allow_readmission: bool) -> usize` → `1` ou `2` (ADR-008 §4). Pas de nouvelle `CampaignScope` : le geste est hors campagne, comme l'amorçage avant Astra.
  - `pub struct InvitationDraft<'a> { identity: &'a DomainIdentity /* ou les champs du hand-off */, gateway_certificate: &'a PqCertificate, name: &'a str, not_before_unix: u64, not_after_unix: u64, allow_readmission: bool }`.
  - `pub fn sign_invitation(vault: &AuthorityVault, openings: &[&Opened], draft: &InvitationDraft<'_>, registry: &InvitationRegistry) -> Result<EnrollmentInvitation>` : vérifie la leaf gateway sous `CA-PQ` (rôle gateway, nom de service et clé WireGuard du hand-off), exige `enrollment_credentials`, tire `invitation_id` et la paire X25519, signe, puis `registry.issue` — l'invitation n'est rendue qu'une fois enregistrée.
  - `pub struct IssuedLeaves { pub tls_certificate: DerCertificate, pub pq_certificate: PqCertificate }`.
  - `pub fn accept_request(vault: &AuthorityVault, opening: &Opened, registry: &InvitationRegistry, ca_tls_certificate: &DerCertificate, request: &EnrollmentRequest, leaf_validity: (u64, u64), now_unix: u64) -> Result<IssuedLeaves>` : `registry.consume` **d'abord**, puis `with_anchors` émet la leaf TLS sur la CSR (même code que `recover_expired_identity`, à factoriser en `fn issue_client_tls_leaf(secrets, ca_tls_certificate, csr, validity)`) et la leaf PQ rôle client sous `CA-PQ` (`subject = requested_name`, `issuer = "helios-ca-pq"`, `serial` aléatoire), puis vérifie les deux sur les clés de la demande.
  - `pub fn sign_document(vault: &AuthorityVault, opening: &Opened, registry: &InvitationRegistry, draft: EnrollmentDocument) -> Result<EnrollmentDocument>` : refuse si l'invitation n'est pas `Consumed` par `draft.request_fingerprint`, si les leafs du brouillon ne certifient pas les clés de cette demande, si `operator_ca_fingerprint` ≠ empreinte de `CA-PQ`, si `profile.key_negotiation.trust.ca_pq_public_key` ≠ `CA-PQ` ; puis signe.

- [ ] **Step 1: Write the failing tests**, sur le modèle des tests de gestes existants (coffre de test et authentificateur simulé déjà présents dans le crate) :
  - `an_invitation_is_recorded_before_it_is_returned`.
  - `readmission_invitations_need_two_distinct_credentials` (une ouverture → refus ; deux identiques → refus).
  - `an_invitation_for_a_gateway_leaf_not_signed_by_ca_pq_is_refused`.
  - `accept_consumes_before_issuing` : authentificateur qui échoue à l'ouverture du coffre (ou `with_anchors` forcé en erreur) → invitation `Consumed`, aucun fichier de leaf, second `accept` refusé.
  - `accepted_leaves_certify_the_request_keys` : clé publique TLS de la leaf = celle de la CSR ; `ml_dsa_87_public_key` et `wireguard_public_key` de la leaf PQ = ceux de la demande ; les deux vérifient sous `CA-TLS`/`CA-PQ`.
  - `a_document_for_leaves_this_invitation_did_not_receive_is_refused`.
  - `a_document_whose_trust_block_names_another_ca_is_refused`.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p astra-operator` — FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** — PASS ; `scripts/wsl-cargo clippy -p astra-operator --all-targets --all-features -- -D warnings` — clean.
- [ ] **Step 5: Commit** `feat(astra-operator): sign enrollment invitations, leaves and documents under CA-PQ`.

### Task 5: `astra-signer enroll`

**Files:**
- Create: `tools/astra-signer/src/commands/enrollment.rs`
- Modify: `tools/astra-signer/src/cli.rs` (sous-commande `Enroll { #[command(subcommand)] command: EnrollCommand }`), `tools/astra-signer/src/commands/mod.rs`, `tools/astra-signer/src/main.rs`, `tools/astra-signer/src/tests.rs`

**Interfaces:**
- Consumes: tâche 4.
- Produces (CLI, aide en français comme le reste du fichier) :
  - `enroll invite --name <nom> --gateway-certificate <leaf PQ gateway JSON> [--valid-for-hours <1..=24, défaut 24>] [--allow-readmission] --out <fichier.helios-invite>` — affiche l'empreinte `CA-PQ` (`authority_fingerprint`) à faire confirmer hors bande.
  - `enroll accept --request <fichier.helios-request> [--validity-days <défaut = celui de l'émission cliente actuelle>] --out-dir <répertoire>` — écrit `<nom>-client-cert.der` et `<nom>-client-pq-cert.json`, imprime la commande `heliosd peer add --name … --public-key … --certificate … --pq-certificate …` à exécuter.
  - `enroll sign-document --draft <brouillon.json> --out <nom>.orion`.
  - `enroll list` (tableau id, nom, état, échéance) et `enroll revoke <invitation_id>`.
  - Le registre se résout par `InvitationRegistry::default_location()` ; `HELIOS_ENROLLMENT_REGISTRY` le remplace pour les tests.

- [ ] **Step 1: Write the failing test** `enroll_subcommands_parse` dans `tests.rs` (clap `try_parse_from` des cinq formes, refus de `--valid-for-hours 25`).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p astra-signer` — FAIL.
- [ ] **Step 3: Implement** the commands on the model of `issue_gateway_bootstrap` (`store::load`, `handoff::DomainHandoff::beside`, `open_vault`/`connect_authorized_key`, `read_json`).
- [ ] **Step 4: Run** tests + clippy for `astra-signer` — PASS/clean.
- [ ] **Step 5: Commit** `feat(astra-signer): drive the v5 enrollment ceremony`.

### Task 6: Demande en attente dans `orion-core`

**Files:**
- Create: `crates/orion-core/src/enrollment.rs`, `crates/orion-core/src/enrollment/tests.rs`
- Modify: `crates/orion-core/src/lib.rs`, `crates/orion-core/src/identity_store.rs` (exposer `pub(crate) fn seal_named(&self, name: &str, plaintext: &[u8])`, `open_named`, `remove_named`, `list_named(prefix)` réutilisant `path_of`, l'écriture atomique et `seal`/`unseal`), `crates/orion-core/src/profile_import/document.rs` (rendre `decode_document` `pub(crate)`)

**Interfaces:**
- Consumes: tâche 1.
- Produces:
  - `pub struct InvitationPreview { pub invitation: EnrollmentInvitation, pub ca_fingerprint: String /* hex groupé par 4 */, pub server_name: String, pub expires_at_unix: u64 }` et `pub fn preview_invitation(text: &str, now_unix: u64) -> Result<InvitationPreview>` (forme et fenêtre ; **pas** de vérification de signature : la CA n'est pas encore épinglée).
  - `pub struct PendingEnrollment { pub invitation_id: Id16, pub request_id: Id16, pub requested_name: String, pub server_name: String, pub created_at_unix: u64 }` (public, sans secret).
  - `pub fn begin_enrollment(store: &ProtectedIdentityStore, invitation: &EnrollmentInvitation, confirmed_ca_fingerprint: &str, requested_name: &str, now_unix: u64) -> Result<(PendingEnrollment, String /* .helios-request */)>` : compare `confirmed_ca_fingerprint` (insensible aux espaces et à la casse) à `operator_ca_public_key.authority_fingerprint()`, vérifie la signature de l'invitation sous cette clé, génère WireGuard + `CandidateKeys::generate(requested_name)` (`certificate_renewal`), calcule la preuve, signe la demande, **scelle** l'enregistrement `pending-enrollment-<request_id hex>` (invitation, demande, trois clés privées), puis seulement encode le fichier demande.
  - `pub fn pending_enrollments(store: &ProtectedIdentityStore) -> Result<Vec<PendingEnrollment>>`, `pub fn discard_enrollment(store: &ProtectedIdentityStore, request_id: &Id16) -> Result<()>`.
  - `pub(crate) struct PendingSecrets { wg_private_key: SecretString, tls_private_key_der: Zeroizing<Vec<u8>>, ml_dsa_private_key: Zeroizing<Vec<u8>>, invitation: EnrollmentInvitation, request: EnrollmentRequest }` et `pub(crate) fn open_pending(store, request_id) -> Result<PendingSecrets>` (tâche 7).

- [ ] **Step 1: Write the failing tests**:
  - `a_wrong_confirmation_generates_nothing` : empreinte différente → erreur, répertoire du store vide.
  - `an_invitation_signed_by_another_key_than_its_ca_is_refused`.
  - `the_request_is_not_produced_when_sealing_is_unavailable` (`#[cfg(not(windows))]` : `begin_enrollment` rend l'erreur `UnsupportedPlatform`, aucun texte de demande).
  - `preview_reads_a_bom_or_utf16_invitation` (Review Focus 4).
  - `#[cfg(windows)] a_pending_enrollment_survives_reopening_the_store_and_can_be_discarded`.
  - `#[cfg(windows)] the_request_file_carries_no_private_material` : le texte ne contient aucune des trois clés privées encodées.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-core enrollment` — FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** — PASS (les tests `cfg(windows)` sont compilés seulement sous Windows : le signaler dans le rapport final).
- [ ] **Step 5: Commit** `feat(orion-core): seal a pending enrollment before its request leaves`.

### Task 7: Import du document v5 et refus des documents Helios hérités

**Files:**
- Modify: `crates/orion-core/src/profile_import/json.rs`, `crates/orion-core/src/profile_import/document.rs`, `crates/orion-core/src/profile_import.rs`, `crates/orion-core/src/enrollment.rs`, tests de `crates/orion-core/src/profile_import/tests/` (convertir ceux qui importent un document v1 `helios_key_negotiation` : soit en refus, soit en document v5 signé par une CA de test épinglée)

**Interfaces:**
- Consumes: tâches 2 et 6.
- Produces:
  - `parse_profile_import` : `version = 1` + `type = "classic"` inchangé ; `version = 1` + `type = "helios_key_negotiation"` (avec ou sans `key_negotiation_identity`) → erreur « document Helios non signé : demander une invitation d'enrôlement v5 à l'opérateur » ; `format_version = 5` → `ProfileImport` avec `enrollment: Option<EnrollmentDocument>` (nouveau champ) et `identity: None`.
  - `pub fn complete_enrollment(store: &ProtectedIdentityStore, document: &EnrollmentDocument, profile: ClientProfile, now_unix: u64) -> Result<EnrollmentOutcome>` dans `enrollment.rs`, avec `pub enum EnrollmentOutcome { Completed { profile: ClientProfile }, Unmatched { profile: ClientProfile, expected: String } }` : ordre du §15.3 (CA épinglée de la demande en attente retrouvée par `invitation_id`/`request_id` ; `operator_ca_fingerprint` égal ; signature ; `request_fingerprint` égal ; clés publiques des deux leafs = demande ; `peer_public_key` du profil = `gateway_wg_public_key` de l'invitation ; empreinte de la leaf PQ gateway épinglée = `gateway_certificate_fingerprint` ; `trust.ca_pq_public_key` = CA épinglée) ; en cas de succès : `ProtectedIdentityStore::store(ClientIdentityBundle { identity: format!("enrollment-{request_id_hex}"), … })`, `profile.private_key` = clé WireGuard, `key_negotiation.identity` = ce nom, enregistrement en attente supprimé — dans cet ordre, la suppression en dernier.
  - Le bloc `key_negotiation` d'un document v5 ne porte pas `identity` : Orion le pose.

- [ ] **Step 1: Write the failing tests**:
  - `a_v1_helios_document_is_refused_with_the_new_procedure_named` (avec et sans identité).
  - `a_v1_classic_document_still_imports`.
  - `a_v5_document_without_pending_request_is_an_unmatched_draft` (Review Focus 3) : `Unmatched`, `expected` nomme la clé WireGuard de la leaf, rien n'est scellé.
  - `a_v5_document_naming_another_gateway_key_is_refused_before_sealing` et `…another_gateway_leaf…` (Review Focus 5).
  - `a_v5_document_under_an_unpinned_ca_is_refused`.
  - `#[cfg(windows)] a_matching_v5_document_completes_and_consumes_the_pending_request`.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-core` — FAIL.
- [ ] **Step 3: Implement**, then convert the existing v1-Helios tests.
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-core` and clippy — PASS/clean.
- [ ] **Step 5: Commit** `feat(orion-core): import the signed v5 enrollment document`.

### Task 8: Brouillon public du document dans `tools/helios`

**Files:**
- Modify: `tools/helios/src/enroll.rs` (réécrit), `tools/helios/src/main.rs` (CLI `Enroll`), `tools/helios/src/profile.rs` (le rendu Helios avec identité disparaît ; `render` ne sert plus qu'au `classic`), tests du crate, `scripts/provision-client.sh`, `scripts/key-negotiation-setup.sh`

**Interfaces:**
- Consumes: tâche 2 (`EnrollmentDocument`), `EnrollmentRequest` (tâche 1).
- Produces: `helios enroll document --request <fichier.helios-request> --tls-certificate <der> --pq-certificate <json> --endpoint <hôte:port> [--negotiation-endpoint …] [--allowed-ips …] [--ssh-target …] [--offline …mêmes entrées qu'aujourd'hui…] --out <brouillon.json>` : lit la gateway (API ou hors ligne), exige un bloc de confiance (sinon erreur « cette gateway n'a pas de domaine de confiance : `astra-signer init` puis `heliosd init-trust-domain` »), vérifie que les leafs certifient les clés de la demande, écrit un `EnrollmentDocument` sans `operator_signature`, `issued_at_unix = now`, `operator_ca_fingerprint` = empreinte de `trust.ca_pq_public_key`. Les anciennes options `--private-key-file`, `--public-key`, `--client-pki-dir`, `--client-ca-dir`, `--identity`, `--mode` disparaissent.
- Les deux scripts refusent l'ancien enchaînement avec un message qui renvoie vers `OPERATOR-TOOLING` section 6, ou passent au nouveau si le changement reste local ; ne pas inventer de cérémonie YubiKey scriptée.

- [ ] **Step 1: Write the failing tests**: `a_draft_without_a_trust_domain_is_refused` ; `a_draft_for_leaves_that_do_not_certify_the_request_is_refused` ; `a_draft_carries_no_identity_and_no_signature` (le JSON ne contient ni `key_negotiation_identity` ni `private_key`, `operator_signature` absent) ; `the_old_one_shot_options_are_gone` (clap refuse `--private-key-file`).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p helios` — FAIL.
- [ ] **Step 3: Implement**; supprimer le code devenu mort (`resolve_keys`, identité dans `profile::render`) sans toucher `key-nego` d'inspection/sonde ni `issue-client` (outil de laboratoire, lié au retrait futur de la CA fichier — voir la note de conception).
- [ ] **Step 4: Run** tests + clippy `-p helios` ; `bash -n` sur les deux scripts — PASS/clean.
- [ ] **Step 5: Commit** `feat(helios): build the public v5 enrollment draft instead of shipping keys`.

### Task 9: Commandes Tauri

**Files:**
- Modify: `apps/orion/src-tauri/src/commands/profiles.rs`, `apps/orion/src-tauri/src/main.rs` (`invoke_handler`), `apps/orion/src-tauri/src/security_tests.rs`

**Interfaces:**
- Consumes: tâches 6 et 7.
- Produces (`#[tauri::command]`, erreurs `String` en français comme les voisines) :
  - `preview_enrollment_invitation(contents: String) -> Result<InvitationPreviewView, String>` (`{ server_name, ca_fingerprint, expires_at_unix, invitation_token }` où `invitation_token` est le texte de l'invitation renvoyé tel quel, pour ne garder aucun état serveur entre deux appels).
  - `begin_enrollment(invitation: String, confirmed_ca_fingerprint: String, requested_name: String) -> Result<String /* contenu .helios-request */, String>`.
  - `list_pending_enrollments() -> Result<Vec<PendingEnrollmentView>, String>` et `discard_pending_enrollment(request_id: String) -> Result<(), String>`.
  - `finish_import` : si `imported.enrollment` est présent, appeler `complete_enrollment` au lieu de `seal_identity` / `staged_key` ; `Unmatched` → `private_key_missing = Some(expected)`.
- [ ] **Step 1: Write the failing test** in `security_tests.rs`: `enrollment_commands_never_return_private_material` (la vue de prévisualisation et la liste ne contiennent aucun champ `private`/`secret` ; vérification par sérialisation JSON des types de vue).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion` (nom de paquet de `apps/orion/src-tauri/Cargo.toml`) — FAIL.
- [ ] **Step 3: Implement** and register the four commands.
- [ ] **Step 4: Run** tests + clippy — PASS/clean (la compilation Windows reste du ressort de la CI native).
- [ ] **Step 5: Commit** `feat(orion): expose the enrollment gestures to the shell`.

### Task 10: Écran *Profils*

**Files:**
- Modify: `apps/orion/src/views/ProfilesView.tsx`, `apps/orion/src/api.ts`, `apps/orion/src/types.ts`, `apps/orion/src/profileDocument.ts` (lecture BOM/UTF-16 réutilisée pour `.helios-invite`), `apps/orion/src/views/ProfilesView.test.tsx`

**Interfaces:**
- Consumes: tâche 9.
- Produces: bouton « Importer une invitation » à côté de l'import de document ; dialogue qui affiche serveur, échéance et empreinte `CA-PQ` en groupes, champ où l'utilisateur recopie l'empreinte lue hors bande, bouton « Créer la demande » désactivé tant que la saisie normalisée diffère ; puis boîte d'enregistrement du `.helios-request` ; section « Demandes en attente » (nom, serveur, âge, bouton « Abandonner »). Composants, espacements et libellés du reste de l'écran.
- [ ] **Step 1: Write the failing tests**: `the_request_button_stays_disabled_until_the_fingerprint_matches` ; `a_pending_enrollment_is_listed_and_can_be_discarded` ; `an_invitation_preview_error_is_shown_in_place`.
- [ ] **Step 2: Run** `npm run test:unit --prefix apps/orion` — FAIL.
- [ ] **Step 3: Implement**.
- [ ] **Step 4: Run** the unit tests and `npx tsc --noEmit -p apps/orion` — PASS.
- [ ] **Step 5: Commit** `feat(orion): enroll from an invitation in the Profiles screen`.

### Task 11: Documentation et régression

**Files:**
- Modify: `docs/specification/NEGOCIATION-DE-CLE-V5.md` (en-tête : retirer la limite « enrôlement sans clé privée », ajouter un amendement daté ; §15.2 : `astra-signer enroll invite` remplace `helios enroll invite`, domaine de confiance requis ; §22 : lignes `astra-operator`, `astra-signer`, `helios::enroll`), `docs/security/OPERATOR-TOOLING.md` section 6, `docs/testing/MANUAL-TESTING.md` (parcours Windows cible), `docs/ROADMAP.md` (F2 fait, branche, non fusionné), `docs/superpowers/specs/2026-10-19-enrolement-v5-design.md` (statut implémenté)
- [ ] **Step 1:** Écrire ces mises à jour.
- [ ] **Step 2:** `cargo fmt --all --check` puis `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh` — expected: exit 0 ; consigner les avertissements `cargo audit` non bloquants.
- [ ] **Step 3: Commit** `docs: record the v5 enrollment as implemented`.
