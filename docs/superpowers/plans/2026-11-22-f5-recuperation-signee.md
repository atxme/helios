# F5 — Fichier de récupération signé et compteur NV TPM — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `heliosd` n'adopte une clé WireGuard de récupération que sur autorisation éditeur hybride, et les trois artefacts éditeur (billet, restauration firmware, récupération WireGuard) consomment un compteur monotone en NV du TPM au lieu de `TpmState.version`.

**Architecture:** `aether::sig` porte les formats (domaines `helios-tpm-reseal-v3`, `helios-firmware-recovery-v2`, `helios-wg-recovery-v1`). `helios-tpm` porte le compteur (trait `TpmSealer`, module `anti_rollback`) et la vérification gateway de la récupération. `helios-escrow` porte le séquestre HESC v2 et le cœur hors ligne de la cérémonie, appelé par la CLI `helios escrow` et par Orion. `heliosd` câble le tout dans `gateway_key.rs`.

**Tech Stack:** Rust (aether, helios-tpm + tss-esapi 7.x derrière la feature `tpm`, helios-escrow, heliosd, tools/helios, tools/helios-publisher), Tauri + React/MUI (apps/orion), Vitest.

**Spec:** `docs/superpowers/specs/2026-11-22-f5-recuperation-signee-design.md`

## Global Constraints

- ADR-002 normatif : `REQUIRED_ALGS` = Ed25519 **et** ML-DSA-65, jamais « au moins une » ; `key_epoch` dans les octets signés ; clés éditeur compilées (`aether::sig::PUBLISHER_KEYS`) ; la gateway ne fait que vérifier.
- Règle de consommation commune : un artefact est valide **si et seulement si** son `counter` est **égal** à la valeur courante du compteur NV ; la gateway **incrémente avant d'agir**.
- Compteur illisible ou absent → l'artefact est **refusé**, `heliosd` démarre quand même (ne jamais bloquer l'accès).
- Aucun repli vers `TpmState.version`, aucune double acceptation des anciens domaines.
- Un fichier de récupération n'est lu **que si** le coffre `wg-key.sealed` est indéchiffrable.
- Toute copie de clé privée dans un tampon `Zeroizing` (ADR-006 §5) ; jamais de clé dans un journal.
- Index NV du compteur : `anti_rollback_nv_index = 0x0180_4847` ; index jetable des essais matériels du compteur : `0x0180_4848`. `0x0180_4845` (fenêtre) et `0x0180_4846` (essai fenêtre) ne sont pas touchés.
- Fichiers par défaut : `/var/lib/helios/anti-rollback.json` (statut public), `/var/lib/helios/simulated-nv-counter` (TPM simulé seulement), `/var/lib/helios/wg-key.recovery`, `/var/lib/helios/wg-key.escrow`.
- Compilation et tests via `scripts/wsl-cargo` depuis le worktree, `CARGO_BUILD_JOBS=2` ; jamais `target/` local.
- `cargo test --all-features` doit rester exécutable sans TPM ; les essais réels sont derrière `HELIOS_TPM_MATERIEL=1`.
- Copie UI en français ; refus en classe fermée, une phrase par cas.
- Commits conventionnels en anglais ; la rupture des formats éditeur porte `!`.

## Review Focus

1. Le TPM refuse de définir l'index (NV plein, autorisation propriétaire non nulle) → `heliosd` démarre, journalise, et refuse billet / restauration / récupération — test Task 3.
2. Arrêt brutal entre l'incrément et l'action (rescellement qui échoue après incrément) → l'artefact est grillé, son rejeu est refusé — tests Task 3 et Task 6.
3. Un fichier de récupération valide présent alors que le coffre s'ouvre → jamais lu, compteur inchangé — test Task 6.
4. Un séquestre dont l'en-tête a été modifié (compteur ou clé publique) → ouverture refusée, pas une requête fausse — test Task 5.
5. L'opérateur assemble avec une autorisation signée pour une autre gateway ou un autre compteur → refus avant toute écriture, dans la CLI comme dans Orion — tests Task 5 et Task 8.

---

### Task 1: Formats éditeur dans `aether::sig`

**Files:**
- Modify: `crates/aether/src/sig.rs` (payloads `ResealPayload` ~265, `FirmwareRecoveryPayload` ~297)
- Modify: `crates/aether/src/sig/tests.rs`
- Modify (mécanique, renommage `version` → `counter` et nouveau champ) : `crates/helios-tpm/src/{reseal_ticket,provisioning,firmware_recovery,boot_controller}.rs`, `tools/helios-publisher/src/main.rs`, `tools/helios/src/firmware.rs`, et tout autre site que `scripts/wsl-cargo check --workspace --all-targets` signale.

**Interfaces:**
- Produces:
  - `ResealPayload { counter: u64, sealed_blob_anchor: [u8; 32], expected_pcr_digest: Option<[u8; 32]> }`, `DOMAIN = b"helios-tpm-reseal-v3"`, `FORMAT_VERSION = 3`. Canonique : `counter` u64 BE, `sealed_blob_anchor` 32 octets, puis l'option PCR comme aujourd'hui (0 | 1 + 32 octets). Sérialisation JSON de l'ancre comme `FirmwareRecoveryPayload::sealed_blob_anchor` (`serialize_digest`).
  - `FirmwareRecoveryPayload` : champ `version` renommé `counter` (même place canonique), `DOMAIN = b"helios-firmware-recovery-v2"`, `FORMAT_VERSION = 2`. `validate()` n'exige plus `counter > 0` (un compteur NV peut valoir 0) ; le reste inchangé.
  - Nouveau `WireGuardRecoveryPayload { counter: u64, gateway_public_key: [u8; 32], expected_pcr_digest: Option<[u8; 32]> }`, `DOMAIN = b"helios-wg-recovery-v1"`, `FORMAT_VERSION = 1`. Canonique : `counter` u64 BE, 32 octets de clé, option PCR. JSON : `gateway_public_key` en base64 standard (même encodage que les clés WireGuard), PCR en hex comme le billet. `deny_unknown_fields`.
  - `pub type SignedWireGuardRecovery = SignedEnvelope<WireGuardRecoveryPayload>;`
  - `pub fn verify_wireguard_recovery(envelope: &SignedWireGuardRecovery, keyring: &[PublisherPublicKeys], private_key: &[u8; 32]) -> Result<(), WireGuardRecoveryError>` : signatures (`envelope.verify`) puis dérivation X25519 de `private_key` = `gateway_public_key`. `WireGuardRecoveryError { Signature(SignatureError), ForeignKey }` (thiserror).
- Ruling de la tâche : l'essai `domain_and_format_version_are_part_of_the_signature` (tests.rs ~285) utilise déjà la chaîne `helios-wg-recovery-v1` pour un type de test : lui donner un domaine de test (`b"helios-test-other-v1"`), le domaine réel appartient désormais à `WireGuardRecoveryPayload`.
- Les sites mécaniques gardent **provisoirement** leur logique actuelle (comparaison `>` contre `TpmState.version`) en lisant `counter` ; les billets de test fournissent `sealed_blob_anchor: [0; 32]`. La sémantique change en Task 3.

- [ ] **Step 1: Tests (rouges)** dans `sig/tests.rs` :
  - `reseal_v3_canonical_bytes_are_fixed` : pour `counter = 7`, ancre `[0xAB; 32]`, PCR `None`, `signing_bytes(&p, 1)` commence par `b"helios-tpm-reseal-v3"` et contient, après l'en-tête de format, `7u64.to_be_bytes()`, puis `[0xAB; 32]`, puis `0u8`.
  - `a_v2_reseal_signature_does_not_verify_as_v3` : signer les octets d'un domaine `helios-tpm-reseal-v2` reconstruits à la main et vérifier qu'ils ne valident pas l'enveloppe v3 (`InvalidSignature`).
  - `wireguard_recovery_round_trips_and_binds_the_key` : signer un `WireGuardRecoveryPayload` avec `PublisherSigner::generate(1)` ; `verify_wireguard_recovery` accepte la bonne clé privée, rend `ForeignKey` pour une autre clé, `Signature(_)` si une des deux signatures est retirée.
  - `wireguard_recovery_json_refuses_unknown_fields`.
  - `firmware_recovery_v2_domain_and_counter_zero_validate`.
- [ ] **Step 2:** `scripts/wsl-cargo test -p aether --all-features sig::` → FAIL (types absents).
- [ ] **Step 3:** Implémenter les payloads et `verify_wireguard_recovery` dans `sig.rs` ; réparer les sites mécaniques jusqu'à `scripts/wsl-cargo check --workspace --all-targets --all-features` vert (hors `helios-api --all-features`, qui exige `web/dist` : le vérifier sans `embed-ui`).
- [ ] **Step 4:** `scripts/wsl-cargo test -p aether --all-features`, `-p helios-tpm`, `-p helios-publisher`, `-p helios` → PASS ; clippy `-D warnings` sur aether et helios-tpm.
- [ ] **Step 5: Commit** `feat(aether)!: counter-based publisher formats and the WireGuard recovery payload`

### Task 2: Le compteur NV dans `helios-tpm`

**Files:**
- Modify: `crates/helios-tpm/src/tpm_interface.rs` (trait + `DryRunTpm`)
- Modify: `crates/helios-tpm/src/tpm_real.rs` (implémentation ESAPI)
- Modify: `crates/helios-tpm/src/settings.rs`
- Modify: `crates/helios-tpm/src/boot_controller.rs` (`open_tpm`, doubles de test qui implémentent le trait), `crates/helios-tpm/src/firmware_recovery.rs` (`FaultTpm`)
- Create: `crates/helios-tpm/src/anti_rollback.rs`
- Modify: `crates/helios-tpm/src/lib.rs` (module, erreurs)
- Test: `crates/helios-tpm/tests/materiel.rs`

**Interfaces:**
- Produces (trait `TpmSealer`, trois méthodes nouvelles) :
  - `fn ensure_counter(&mut self) -> Result<()>` : définit l'index s'il manque (type compteur, lecture/écriture propriétaire, `no_da`) puis fait le premier incrément ; idempotente.
  - `fn read_counter(&mut self) -> Result<u64>`
  - `fn increment_counter(&mut self) -> Result<u64>` : rend la nouvelle valeur.
  - Doubles de test existants : délèguent à un `DryRunTpm` interne ou rendent une valeur fixe ; aucun test existant ne change de sens.
- `DryRunTpm` : compteur dans un état partageable `CounterState` (comme `NvState`, `sharing_counter(&CounterState)` en test). `DryRunTpm::from_env(cfg: &TpmSettings)` (signature changée, appelée par `open_tpm`) persiste le compteur dans `cfg.simulated_counter_path` (u64 décimal, écriture atomique), parce que chaque `open_tpm` crée une nouvelle instance.
- `TpmSettings` : retirer `state_path` ; ajouter `anti_rollback_nv_index: u32` (défaut `0x0180_4847`), `simulated_counter_path: String` (défaut `/var/lib/helios/simulated-nv-counter`), `counter_status_path: String` (défaut `/var/lib/helios/anti-rollback.json`). Si `state_path` a des lecteurs, ils restent jusqu'à la Task 3 via un champ conservé : dans ce cas ne retirer `state_path` qu'en Task 3 (le dire dans le rapport).
- `TpmError` : `CounterUnavailable(String)`, `CounterMismatch { artifact: u64, current: u64 }` (message : « artifact counter {artifact} does not match the TPM counter {current} »).
- Module `anti_rollback` :
  - `pub fn current(cfg: &TpmSettings) -> Result<u64>` (ouvre le TPM, lit) ;
  - `pub(crate) fn consume<T: TpmSealer>(tpm: &mut T, cfg: &TpmSettings, artifact: u64) -> Result<u64>` : lit ; si différent → `CounterMismatch` ; sinon incrémente, publie le statut, rend la nouvelle valeur ; une erreur de lecture ou d'incrément → `CounterUnavailable` ;
  - `pub fn advance(cfg: &TpmSettings) -> Result<u64>` : incrément inconditionnel (rotation d'identité), publie ;
  - `pub(crate) fn publish_status(cfg: &TpmSettings, value: Result<u64, &TpmError>)` : écrit atomiquement `{"counter": N}` ou `{"counter": null, "error": "<cause>"}` dans `counter_status_path` ; un échec d'écriture est journalisé, jamais propagé.
- Réel (`tpm_real.rs`, feature `tpm`) : sur le modèle de `define_nv_index` (~690) mais **sans** `nv_undefine_space` d'un index existant (un compteur ne se recrée pas) : `NvIndexType::Counter`, `with_owner_write(true)`, `with_owner_read(true)`, `with_no_da(true)`, taille 8 ; `nv_increment(NvAuth::Owner, handle)` ; `nv_read(NvAuth::Owner, handle, 8, 0)` → u64 BE. Lire la source de `tss-esapi` dans `~/.cargo/registry` avant d'écrire contre son API (ADR-002, règle de travail).

- [ ] **Step 1: Tests (rouges)**, module `anti_rollback` (DryRunTpm) :
  - `ensure_then_read_starts_a_counter` ; `ensure_is_idempotent` (deux `ensure` ne bougent pas la valeur) ;
  - `consume_accepts_only_the_current_value` : valeur `c` → `consume(c+1)` et `consume(c-1)` (si `c > 0`) rendent `CounterMismatch`, `consume(c)` rend `c+1` ;
  - `a_consumed_value_cannot_be_consumed_again` ;
  - `the_simulated_counter_survives_a_new_instance` : deux `DryRunTpm::from_env(&cfg)` sur le même `simulated_counter_path` voient la même valeur ;
  - `publish_status_writes_the_value_and_the_failure` (JSON lu en retour).
- [ ] **Step 2:** `scripts/wsl-cargo test -p helios-tpm anti_rollback` → FAIL.
- [ ] **Step 3:** Implémenter.
- [ ] **Step 4: Essai réel** dans `tests/materiel.rs`, `fn the_anti_rollback_counter_only_moves_forward_on_the_tpm()` derrière `hardware_requested`, index jetable `0x0180_4848` : `ensure`, lire `v`, incrémenter → `v+1`, nouvelle connexion → `v+1`. Documenter en commentaire de tête l'index ajouté et sa suppression (`tpm2_nvundefine 0x01804848`). Le lancer sur swtpm : `swtpm socket --tpmstate dir=$(mktemp -d) --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &` puis `HELIOS_TPM_MATERIEL=1 HELIOS_TPM_TCTI=swtpm:host=127.0.0.1,port=2321 scripts/wsl-cargo test -p helios-tpm --features tpm --test materiel the_anti_rollback_counter` → PASS. Si swtpm ne démarre pas dans l'environnement, le dire dans le rapport (DONE_WITH_CONCERNS) au lieu de sauter l'essai.
- [ ] **Step 5:** `scripts/wsl-cargo test -p helios-tpm --all-features`, `scripts/wsl-cargo check -p helios-tpm --features tpm --all-targets`, clippy `-D warnings` (avec et sans `tpm`) → verts.
- [ ] **Step 6: Commit** `feat(helios-tpm): a monotonic NV counter behind the sealing trait`

### Task 3: Billet, restauration firmware et démarrage sur le compteur

**Files:**
- Modify: `crates/helios-tpm/src/{boot_controller,provisioning,reseal_ticket,firmware_recovery,blob_store,lib}.rs`
- Modify: `crates/heliosd/src/commands/tpm.rs`, la définition de `TpmCommand` (grep `enum TpmCommand` dans `crates/heliosd/src`)
- Test: les modules de test de ces fichiers ; `crates/heliosd/tests/cli.rs` si les commandes `tpm` y sont couvertes

**Interfaces:**
- Consumes: Task 1 (`ResealPayload.counter/sealed_blob_anchor`, `FirmwareRecoveryPayload.counter`), Task 2 (`anti_rollback::{consume, publish_status}`, `ensure_counter`).
- Produces:
  - `BootController::unlock` : quand `cfg.enabled`, appelle `ensure_counter` puis `read_counter` **avant** `run_flow` ; succès ou échec → `publish_status` et une ligne de journal (`info!` avec la valeur, `warn!` avec la cause) ; un échec est journalisé (`warn!`) et **ne fait pas échouer** le démarrage.
  - `provisioning::reseal` : ticket vérifié (signatures, ancre = SHA-256 du blob courant, PCR optionnel), puis `anti_rollback::consume(tpm, cfg, ticket.counter())` **avant** `SecretKey::generate`/`seal`/`store_blob` ; `CounterMismatch` et `CounterUnavailable` remontent comme refus du billet (même effet que `TicketRollback` aujourd'hui). `ResealTicket::verify(current_pcr, current_anchor)` ne prend plus de version.
  - `firmware_recovery::export` : `counter = anti_rollback current value` (plus de `+ 1`). `restore_with` : vérifie `counter` égal avant de sceller, puis `consume` **avant** `store_blob` (l'ordre « compteur d'abord » existant est conservé).
  - `TpmState`, `load_state`, `store_state`, `TpmError::TicketRollback`, `TpmSettings.state_path` : supprimés.
  - `pub fn helios_tpm::prepare_reseal_request(cfg: &TpmSettings) -> Result<aether::sig::ResealRequest>` où `ResealRequest { counter: u64, sealed_blob_anchor: [u8; 32] }` (struct JSON publique ajoutée dans `aether::sig`, `deny_unknown_fields`, ancre en hex comme `sealed_blob_anchor`).
  - `heliosd tpm prepare-reseal` : imprime le JSON de `ResealRequest`. `heliosd tpm counter-status` : imprime la valeur courante ou l'erreur. Noms clap : `PrepareReseal`, `CounterStatus`.

- [ ] **Step 1: Tests (rouges)**, `boot_controller` :
  - `ota_with_a_ticket_for_the_current_counter_reseals` (porte `ota_with_valid_ticket_reseals`) : le compteur avance de 1 ;
  - `a_ticket_for_another_counter_is_refused` (valeurs `c-1` et `c+1`) ;
  - `replayed_ticket_is_rejected` porté : même billet rejoué après consommation → refus ;
  - `a_ticket_for_another_sealed_blob_is_refused` (ancre différente) ;
  - `a_counter_that_cannot_be_created_refuses_the_ticket_but_boot_continues_nominally` : double de TPM dont `ensure_counter` échoue → un démarrage nominal (unseal OK) rend `Unsealed`, le statut publié porte l'erreur ; un démarrage avec PCR changés et billet valide rend une erreur de billet, pas un panic ;
  - `the_counter_is_consumed_before_the_new_secret_is_sealed` : double dont `seal` échoue après l'incrément → le billet rejoué ensuite est refusé (`CounterMismatch`).
  - `firmware_recovery` : porter les tests existants (`version` → égalité au compteur), plus `a_firmware_authorization_for_a_spent_counter_is_refused`.
- [ ] **Step 2:** `scripts/wsl-cargo test -p helios-tpm` → FAIL sur les nouveaux tests.
- [ ] **Step 3:** Implémenter ; supprimer `TpmState` et ses appels.
- [ ] **Step 4:** Commandes `heliosd tpm prepare-reseal` et `counter-status` ; test dans le module des commandes ou `tests/cli.rs` selon l'existant (sortie JSON parsable en `ResealRequest`).
- [ ] **Step 5:** `scripts/wsl-cargo test -p helios-tpm --all-features`, `-p heliosd`, clippy `-D warnings` → verts.
- [ ] **Step 6: Commit** `feat(helios-tpm)!: reseal tickets and firmware restores consume the NV counter`

### Task 4: `helios-publisher`

**Files:**
- Modify: `tools/helios-publisher/src/main.rs`
- Test: `tools/helios-publisher/tests/cli_security.rs`

**Interfaces:**
- Consumes: Task 1 (`WireGuardRecoveryPayload`), Task 3 (`ResealRequest`).
- Produces:
  - `reseal-ticket --request <ResealRequest JSON> [--expected-pcr-digest <hex>] --key-epoch --ed25519-private-key --ml-dsa-65-private-key --keyring --output` : `--version` disparaît.
  - `wg-recovery --request <WireGuardRecoveryPayload JSON> --key-epoch --ed25519-private-key --ml-dsa-65-private-key --keyring --output` : signe la requête **telle quelle**, refuse d'écraser `--output`, comme `firmware-recovery` (réutiliser son chemin de code).
  - `firmware-recovery` : inchangé en surface (nouveau domaine par Task 1).

- [ ] **Step 1: Tests (rouges)** : `wg_recovery_command_signs_the_exact_public_request_and_refuses_overwrite` (modèle : `firmware_recovery_command_signs_the_exact_public_request_and_refuses_overwrite`, ~206) ; `reseal_ticket_signs_the_prepared_request` (payload signé = counter et ancre de la requête, PCR de l'option) ; `reseal_ticket_refuses_a_request_with_unknown_fields`.
- [ ] **Step 2:** `scripts/wsl-cargo test -p helios-publisher` → FAIL.
- [ ] **Step 3:** Implémenter.
- [ ] **Step 4:** `scripts/wsl-cargo test -p helios-publisher` + clippy → verts.
- [ ] **Step 5: Commit** `feat(helios-publisher)!: sign prepared reseal requests and WireGuard recoveries`

### Task 5: Séquestre HESC v2 et cœur de la cérémonie

**Files:**
- Modify: `crates/helios-escrow/src/lib.rs`
- Create: `crates/helios-escrow/src/recovery.rs`
- Modify: `crates/helios-escrow/Cargo.toml` si une dépendance manque (serde_json, base64 : déjà dans le workspace)

**Interfaces:**
- Consumes: Task 1 (`WireGuardRecoveryPayload`, `SignedWireGuardRecovery`, `verify_wireguard_recovery`, `PUBLISHER_KEYS`).
- Produces (`helios_escrow`) :
  - `pub struct EscrowMetadata { pub counter: Option<u64>, pub gateway_public_key: [u8; 32] }`
  - `pub fn seal_to_operator(operator_public_key: &[u8], plaintext: &[u8], metadata: &EscrowMetadata) -> Result<Vec<u8>>` : écrit **HESC v2** : `MAGIC`, version `2`, en-tête métadonnées (drapeau 0/1 + u64 BE du compteur, 32 octets de clé), clé éphémère, nonce, chiffré ; **AAD = `b"helios-escrow-v2"` suivi de l'en-tête complet jusqu'au nonce inclus**. KDF info `b"helios-escrow-kdf-v2"`.
  - `pub struct OpenedEscrow { pub metadata: Option<EscrowMetadata>, pub plaintext: Zeroizing<Vec<u8>> }` ; `pub fn open_as_operator(operator_private_key: &[u8], blob: &[u8]) -> Result<OpenedEscrow>` : v1 → `metadata: None` ; v2 → `Some`.
  - `helios_escrow::recovery` :
    - `pub enum CounterSource { Given, EscrowAfterTicket }`
    - `pub struct RecoveryRequest { pub payload: WireGuardRecoveryPayload, pub counter_source: CounterSource, pub gateway_public_key_b64: String }`
    - `pub fn prepare(escrow: &[u8], operator_private_key: &[u8], counter: Option<u64>, expected_pcr_digest: Option<[u8; 32]>) -> Result<RecoveryRequest, RecoveryError>` : ouvre ; v1 → `RecoveryError::LegacyEscrow` ; clé privée du séquestre doit dériver `metadata.gateway_public_key` sinon `RecoveryError::EscrowInconsistent` ; `counter` donné → `Given` ; sinon `metadata.counter + 1` → `EscrowAfterTicket` (une récupération suit toujours un billet consommé, spec §5.2) ; sinon (`None` des deux côtés) `RecoveryError::CounterUnknown`. Ne rend jamais la clé privée.
    - `pub fn assemble(escrow: &[u8], operator_private_key: &[u8], authorization: &SignedWireGuardRecovery) -> Result<Zeroizing<Vec<u8>>, RecoveryError>` : rouvre ; `verify_wireguard_recovery(authorization, PUBLISHER_KEYS, &key)` ; `gateway_public_key` de l'autorisation = celle du séquestre ; rend la trame.
    - `pub const MAX_RECOVERY_FRAME: usize = 65_536;` ; `pub fn encode_recovery_frame(authorization: &SignedWireGuardRecovery, private_key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, RecoveryError>` et `pub fn decode_recovery_frame(frame: &[u8]) -> Result<(SignedWireGuardRecovery, Zeroizing<[u8; 32]>), RecoveryError>` : même forme que `firmware_recovery::{encode,decode}_restore_frame` (u32 BE longueur, JSON, 32 octets bruts) ;
    - `pub enum RecoveryError` (thiserror), variantes fermées : `EscrowUnreadable`, `LegacyEscrow`, `EscrowInconsistent`, `CounterUnknown`, `AuthorizationInvalid`, `ForeignGateway`, `FrameMalformed`. Le plaintext du séquestre est la clé WireGuard en base64 (ce qu'écrit `write_escrow`) : la décoder en 32 octets dans un `Zeroizing`.

- [ ] **Step 1: Tests (rouges)** :
  - `hesc_v2_round_trips_with_its_metadata` ; `a_tampered_v2_header_is_undecipherable` (changer un octet du compteur, puis de la clé publique : `Undecipherable`) ; `a_v1_escrow_still_opens_without_metadata` ;
  - `prepare_uses_the_given_counter` ; `prepare_defaults_to_the_counter_after_a_ticket` (`metadata.counter = Some(5)` → payload `counter = 6`, `EscrowAfterTicket`) ; `prepare_refuses_a_legacy_escrow` ; `prepare_without_any_counter_is_refused` ;
  - `assemble_produces_a_frame_that_decodes_to_the_key` ; `assemble_refuses_an_authorization_for_another_gateway` ; `assemble_refuses_a_single_signature` ; `decode_refuses_truncated_and_oversized_frames`.
  - Pour signer en test : `aether::sig::PublisherSigner` avec les graines de dev utilisées dans `boot_controller` (`DEV_ED_SEED`, `DEV_ML_SEED`) pour que `PUBLISHER_KEYS` de développement vérifie ; le dire en commentaire.
- [ ] **Step 2:** `scripts/wsl-cargo test -p helios-escrow` → FAIL.
- [ ] **Step 3:** Implémenter. Mettre à jour la doc de module (`//!`) : le mécanisme devient « préparer / signer / assembler », la clé ne passe plus par un fichier intermédiaire.
- [ ] **Step 4:** `scripts/wsl-cargo test -p helios-escrow` + clippy ; `scripts/wsl-cargo check --workspace --all-targets` (les appelants de `seal_to_operator`/`open_as_operator` cassent : les réparer au minimum — `heliosd::gateway_key::write_escrow` passe provisoirement `EscrowMetadata { counter: None, gateway_public_key }`, `tools/helios/src/escrow.rs` lit `.plaintext`) → verts.
- [ ] **Step 5: Commit** `feat(helios-escrow)!: HESC v2 carries the counter, and one offline recovery core`

### Task 6: `heliosd` — récupération vérifiée, séquestre v2, rotation

**Files:**
- Modify: `crates/heliosd/src/gateway_key.rs`
- Modify: `crates/heliosd/src/daemon.rs` (~169-200), `crates/heliosd/src/commands/identity.rs`, `crates/heliosd/src/orchestrator/commands.rs` (~50) : passer `&TpmSettings`
- Create: `crates/helios-tpm/src/wg_recovery.rs` ; Modify: `crates/helios-tpm/src/lib.rs`

**Interfaces:**
- Consumes: Task 2 (`anti_rollback::{current, advance}`), Task 5 (`decode_recovery_frame`, `EscrowMetadata`, `seal_to_operator`), Task 1 (`verify_wireguard_recovery`).
- Produces:
  - `pub fn helios_tpm::wg_recovery::accept(cfg: &TpmSettings, authorization: &SignedWireGuardRecovery, private_key: &[u8; 32]) -> Result<()>` : ouvre le TPM ; `verify_wireguard_recovery(…, PUBLISHER_KEYS, …)` ; PCR attendu (si présent) = `current_pcr_digest()` ; `anti_rollback::consume(tpm, cfg, authorization.payload.counter)`. Erreurs : `TpmError::RecoveryRefused(String)` pour signature/clé/PCR, `CounterMismatch`/`CounterUnavailable` pour le compteur. Journalise l'alerte de clés de développement comme `ResealTicket::verify`.
  - `gateway_key::resolve(network, boot, tpm: &TpmSettings)`, `initialize(network, boot, rotate, tpm: &TpmSettings)`, `update_sealed(network, boot, new_private_key, tpm: &TpmSettings)`.
  - `try_recovery(secret, tpm)` : lit `wg-key.recovery` (borne `MAX_RECOVERY_FRAME`) en `Zeroizing`, `decode_recovery_frame` ; trame invalide → ignorée, **laissée en place** (comportement actuel) ; `wg_recovery::accept` ; refus → journal avec la cause (jamais la clé), fichier laissé en place ; succès → rescellement (base64 de la clé, comme aujourd'hui), puis effacement (alerte existante si l'effacement échoue).
  - `write_escrow(network, private_key, tpm)` : `EscrowMetadata { counter: anti_rollback::current(tpm).ok(), gateway_public_key }`.
  - Rotation : `initialize` avec `rotate = true` et `update_sealed` appellent `anti_rollback::advance(tpm)` **avant** `write_escrow` (le séquestre porte la valeur après rotation) ; un échec est journalisé (`warn!`) et n'arrête pas la rotation.

- [ ] **Step 1: Tests (rouges)** dans `gateway_key::tests` (scénarios isolés existants, `run_isolated_identity_scenario`, avec un `TpmSettings` dont `simulated_counter_path` et `counter_status_path` sont dans le répertoire temporaire) :
  - `a_signed_recovery_for_the_current_counter_is_resealed_and_erased` ;
  - `an_unsigned_or_foreign_recovery_is_left_in_place` (trame d'un autre domaine ; clé ne dérivant pas `gateway_public_key`) ;
  - `a_recovery_for_another_counter_is_refused` ;
  - `a_consumed_recovery_cannot_be_replayed` (redéposer la même trame après succès et nouvelle perte de coffre → refus) ;
  - `a_recovery_file_without_a_locked_vault_is_not_consumed_or_used` (existant, porté : compteur inchangé) ;
  - `rotation_advances_the_counter_and_invalidates_an_older_authorization` ;
  - `the_escrow_carries_the_counter_and_the_public_key`.
  - Adapter les tests de format texte de `read_recovery_key` (~834-880) à la trame : ils deviennent des tests de `decode_recovery_frame` côté lecture (absent → `None`, illisible → laissé, invalide → laissé).
- [ ] **Step 2:** `scripts/wsl-cargo test -p heliosd gateway_key` → FAIL.
- [ ] **Step 3:** Implémenter ; réparer les appelants.
- [ ] **Step 4:** `scripts/wsl-cargo test -p heliosd`, `-p helios-tpm --all-features`, clippy `-D warnings` → verts.
- [ ] **Step 5: Commit** `feat(heliosd)!: adopt a recovered identity only on a signed, counter-bound authorization`

### Task 7: CLI `helios escrow`

**Files:**
- Modify: `tools/helios/src/escrow.rs`, `tools/helios/src/main.rs` (`EscrowCmd` ~321, dispatch ~760)
- Test: `tools/helios/src/escrow.rs` (module de test), `tools/helios/tests/offline_cli.rs`

**Interfaces:**
- Consumes: Task 5 (`recovery::{prepare, assemble}`).
- Produces:
  - `helios escrow prepare-recovery --escrow <wg-key.escrow> --private-key <escrow-private.key> [--counter <u64>] [--expected-pcr-digest <hex>] --output <request.json>` : écrit le JSON du payload (création sans écrasement, `crate::files::write_new`), imprime sur stdout la clé publique, et sur stderr la valeur signée et son origine (« lue dans le séquestre, suppose un billet consommé — vérifier `/var/lib/helios/anti-rollback.json` sur la gateway » pour `EscrowAfterTicket`).
  - `helios escrow assemble-recovery --escrow … --private-key … --authorization <auth.json> --output <wg-key.recovery>` : écrit la trame (sans écrasement, permissions 0600), rappelle sur stderr où la déposer et qu'elle contient la clé en clair.
  - `helios escrow open` est **supprimé** (spec §5.6).

- [ ] **Step 1: Tests (rouges)** : `prepare_then_assemble_produces_a_frame_heliosd_accepts` (de bout en bout : séquestre v2 écrit par `seal_to_operator`, `prepare`, signature avec les clés de dev, `assemble`, `helios_escrow::recovery::decode_recovery_frame`, puis `aether::sig::verify_wireguard_recovery`) ; `assemble_refuses_to_overwrite_and_writes_nothing_on_a_foreign_authorization` ; `the_recovered_key_is_never_printed` (stdout/stderr ne contiennent pas la clé privée base64) ; adapter `offline_cli.rs` aux nouvelles sous-commandes.
- [ ] **Step 2:** `scripts/wsl-cargo test -p helios` → FAIL.
- [ ] **Step 3:** Implémenter.
- [ ] **Step 4:** `scripts/wsl-cargo test -p helios` + clippy → verts.
- [ ] **Step 5: Commit** `feat(helios)!: prepare and assemble a signed recovery from the escrow`

### Task 8: Cérémonie dans Orion

**Files:**
- Modify: `apps/orion/src-tauri/Cargo.toml` (`helios-escrow.workspace = true`)
- Create: `apps/orion/src-tauri/src/commands/gateway_recovery.rs` ; Modify: `apps/orion/src-tauri/src/commands/mod.rs`, `apps/orion/src-tauri/src/main.rs` (`generate_handler!` ~739)
- Modify: `apps/orion/src/api.ts`, `apps/orion/src/types.ts`
- Create: `apps/orion/src/views/astra/GatewayRecoveryBlock.tsx`, `apps/orion/src/views/astra/GatewayRecoveryBlock.test.tsx`
- Modify: `apps/orion/src/views/AstraView.tsx` (placer le bloc)

**Interfaces:**
- Consumes: Task 5.
- Produces (Tauri, dans le processus IHM non élevé : aucune élévation ni coffre opérateur requis) :
  - `gateway_recovery_prepare(escrow_b64: String, escrow_private_key: String, counter: Option<u64>, expected_pcr_digest: Option<String>) -> Result<RecoveryPrepared, RecoveryRefusalView>` ; `RecoveryPrepared { gateway_public_key: String, counter: u64, counter_source: "given" | "escrow_after_ticket", request: OperatorArtifact }` (artefact texte `wg-recovery-request.json`).
  - `gateway_recovery_assemble(escrow_b64: String, escrow_private_key: String, authorization: String) -> Result<OperatorArtifact, RecoveryRefusalView>` (artefact base64 `wg-key.recovery`).
  - `RecoveryRefusalView` sérialisé `{ "refusal": "<code>" }`, codes snake_case 1:1 avec `RecoveryError` (`escrow_unreadable`, `legacy_escrow`, `escrow_inconsistent`, `counter_unknown`, `authorization_invalid`, `foreign_gateway`, `frame_malformed`) ; aucune chaîne libre ne traverse.
  - Réutiliser `OperatorArtifact` et `saveArtifact` existants (`views/astra/ArtifactDownloads.tsx`).
- UI `GatewayRecoveryBlock` : titre « Récupérer l'identité de la gateway ». Étape 1 : champs fichier « Séquestre (wg-key.escrow) » et « Clé de séquestre », champ optionnel « Valeur du compteur (lue sur la gateway) » ; bouton « Préparer la requête » → affiche la clé publique, la valeur et son origine (pour `escrow_after_ticket` : « Valeur déduite du séquestre, en supposant qu'un billet a été consommé. Vérifiez anti-rollback.json sur la gateway. »), propose la requête au téléchargement. Étape 2 : « Autorisation signée » ; bouton « Assembler le fichier » → téléchargement de `wg-key.recovery` et rappel : « À déposer dans /var/lib/helios/wg-key.recovery par l'accès hors bande, puis redémarrer heliosd. Ce fichier contient la clé privée en clair : supprimez-le après usage. » Lecture du séquestre binaire : `File.arrayBuffer()` → base64 (borne `MAX_FILE_BYTES` de `readFileText.ts`). Phrases de refus, une par code :
  - `escrow_unreadable` « Séquestre illisible avec cette clé. »
  - `legacy_escrow` « Séquestre d'un ancien format : redémarrez la gateway pour qu'elle l'écrive au nouveau format, puis recommencez. »
  - `escrow_inconsistent` « Le séquestre ne correspond pas à la clé qu'il contient. »
  - `counter_unknown` « Valeur du compteur inconnue : lisez-la sur la gateway et saisissez-la. »
  - `authorization_invalid` « Autorisation non valide : signature manquante ou d'un autre éditeur. »
  - `foreign_gateway` « Cette autorisation vise une autre gateway. »
  - `frame_malformed` « Fichier de récupération mal formé. »
- Placement : dans `AstraView`, à côté de `GatewayIdentityBlock`, visible même sans coffre opérateur ouvert (la cérémonie n'en a pas besoin).

- [ ] **Step 1: Tests (rouges)** :
  - Rust (`commands/gateway_recovery.rs` `#[cfg(test)]`) : `prepare_returns_the_public_request_only` (l'artefact ne contient pas la clé privée) ; `assemble_maps_a_foreign_authorization_to_its_refusal_code` ; `every_recovery_error_has_a_refusal_code` (match exhaustif).
  - Vitest (`GatewayRecoveryBlock.test.tsx`, `api` mocké) : `prepares then offers the request with its counter origin` ; `assembles and reminds where to deposit the file` ; `shows the French sentence for each refusal code` (itère les 7 codes).
- [ ] **Step 2:** `scripts/wsl-cargo test -p orion gateway_recovery` et `cd apps/orion && npx vitest run src/views/astra/GatewayRecoveryBlock.test.tsx` → FAIL.
- [ ] **Step 3:** Implémenter.
- [ ] **Step 4:** `scripts/wsl-cargo test -p orion`, `cd apps/orion && npx vitest run && npx tsc --noEmit`, clippy `-D warnings` → verts.
- [ ] **Step 5: Commit** `feat(orion): recover the gateway identity from its escrow`

### Task 9: Documentation et recette

**Files:**
- Modify: `docs/adr/ADR-002-SIGNATURES-PQ.md` (état d'implémentation : récupération « fait » ; amendement 2 : **tranché le 22 novembre 2026, compteur NV**, avec la règle d'égalité et d'incrément préalable ; amendement 5 : le compteur NV remplace `TpmState.version`, la phrase « une telle garantie exige un compteur NV TPM et reste absente » devient la garantie obtenue ; domaines : `helios-tpm-reseal-v3`, `helios-firmware-recovery-v2`, `helios-wg-recovery-v1` ; migration : rupture nette ; lot 3 de l'estimation : fait)
- Modify: `docs/MAINTENANCE.md` (procédures billet et récupération : `heliosd tpm prepare-reseal`, `helios-publisher reseal-ticket --request`, `helios escrow prepare-recovery` / Orion, `helios-publisher wg-recovery`, assemblage, dépôt ; ordre `C` puis `C+1` dans un même démarrage ; `heliosd tpm counter-status` et `anti-rollback.json`)
- Modify: `docs/ROADMAP.md` (D1 : tranché le 22 novembre 2026, compteur NV ; F5 : implémenté sur `feat/f5-recovery-signed`, recette matérielle à faire)
- Modify: `docs/testing/TESTING.md` (essai matériel du compteur, index jetable `0x01804848`, swtpm) et `docs/testing/MANUAL-TESTING.md` (recette « Q. F5 » : compteur créé sur TPM réel, survit au redémarrage, ne recule pas après `tpm2_nvundefine` + recréation, OTA avec changement de PCR → billet `C` puis récupération `C+1`, gateway joignable par Tailscale à chaque étape)
- Modify: `crates/helios-escrow/src/lib.rs` doc si la Task 5 ne l'a pas fait ; `crates/heliosd/src/gateway_key.rs` doc de module (§ « Recovery without SSH »)

- [ ] **Step 1:** Rédiger. Vérifier chaque commande citée contre `--help` réel (`scripts/wsl-cargo run -p heliosd -- tpm --help`, `-p helios -- escrow --help`, `-p helios-publisher -- --help`).
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh` → exit 0 (`cargo audit` absent n'est pas une régression).
- [ ] **Step 3: Commit** `docs(f5): D1 decided, signed recovery procedure and NV counter recipe`
