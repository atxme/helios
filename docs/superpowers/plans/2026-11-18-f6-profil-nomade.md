# F6 — Profil Orion `nomade` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** wire the `nomade` profile of ADR-006: a profile that opens only with the TPM **and** a passphrase entered in the native Windows dialog, and that locks again on session lock, sleep, disconnect or engine exit.

**Architecture:** `orion-core::vault` gains the passphrase key (PBKDF2, locked memory), a v2 registry carrying each profile's mode, a store that keeps nomad profiles locked until `unlock`, and atomic mode switches. `orion-engine` asks for the passphrase through a `PassphraseSource`, exposes three new commands (protocol v3) and a portable lock state machine fed by a Windows session/power watcher. The Orion UI shows the mode, the locked state and the gestures; it never sees a passphrase.

**Tech Stack:** Rust (orion-core, orion-engine, aether, aether-vault, aws-lc-rs, windows-sys 0.61), Tauri 2 shell (`apps/orion/src-tauri`), React + TypeScript + vitest (`apps/orion/src`).

**Spec:** `docs/superpowers/specs/2026-11-18-f6-profil-nomade-design.md`

## Global Constraints

- Work only in the worktree `/home/christophe/helios-wt/f6-nomade`, branch `feat/f6-profil-nomade`.
- Build and test only through `scripts/wsl-cargo` with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`; never set `CARGO_TARGET_DIR`, never run `clean-wsl-targets`.
- Documentation in French; code, comments, identifiers and log messages in English; user-facing strings (errors shown on screen, UI copy, dialog text) in French.
- No `TODO`/`FIXME` markers. Never edit crate/package versions by hand. Never touch `docs/audits`.
- No secret (passphrase, passphrase key, IKM, private key, manifest bytes) in the WebView, a Tauri command payload, an engine wire frame, a `Debug`/`Display` output or a log line.
- KDF: PBKDF2-HMAC-SHA-512, `aether_vault::PBKDF2_ITERATIONS` (600 000), 16-byte random salt, 32-byte output, KDF identifier `2`; identifier `1` stays burned (refused, named).
- Nomad manifest key: `Unlock::Derived { ikm: profile_root_key(id) ‖ passphrase_key, info: b"orion/profile-nomade/v1" }`.
- A nomad manifest is **never** sealed as `service` except by the explicit « Repasser en service » gesture. Any write of a nomad profile without its passphrase key in memory fails.
- The passphrase policy (`passphrase::accept`) judges only a **new** passphrase; opening uses `passphrase::normalise` only.
- Memory-lock failure is fatal for a nomad unlock (`LockState` other than `Locked` → refusal).
- Engine ↔ UI protocol: `PROTOCOL_VERSION` becomes `3`.
- `cfg(windows)` code does not compile from WSL (`aws-lc-sys`, docs/testing/TESTING.md). Keep it thin, put decisions in portable code, write `#[cfg(windows)] mod imp` with `use super::*;`, and check every `windows-sys` symbol and feature by reading the crate source under `~/.cargo/registry/src/*/windows-sys-0.61*/`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. A passphrase typed with trailing spaces, or in NFD where it was set in NFC, must open the profile (Task 1 and Task 3 tests).
2. A lock event that arrives while an unlock is in progress (dialog open, PBKDF2 running) must not leave the key in memory afterwards (Task 3 epoch test, Task 6 test).
3. Renaming, selecting or deleting a locked nomad profile must work without asking for its passphrase, and the in-memory key is keyed by `ProfileId`, never by name (Task 3 tests).
4. Saving or importing a profile under the name of a locked nomad profile must refuse with `ProfileLocked`, never replace it (Task 3 test).
5. Two nomad profiles with the same passphrase derive different keys (Task 1 test).

---

### Task 1: Passphrase key and nomad derivation

**Files:**
- Modify: `crates/orion-core/src/vault/passphrase.rs` (split `normalise` out of `accept`)
- Create: `crates/orion-core/src/vault/nomad.rs`
- Modify: `crates/orion-core/src/vault/mod.rs` (`pub mod nomad;`, `seal_manifest`/`open_manifest` take a `ManifestKey`, new `VaultError` variants)
- Modify: every caller of `seal_manifest`/`open_manifest` (pass `ManifestKey::Service`)
- Test: in-file `#[cfg(test)] mod tests` of `nomad.rs` and `passphrase.rs`

**Interfaces:**
- Produces:
  - `pub fn passphrase::normalise(raw: &str) -> Zeroizing<String>` (trim + NFC; `accept` calls it then applies the policy).
  - `pub const nomad::SALT_LEN: usize = 16;`, `pub const nomad::NOMAD_INFO: &[u8] = b"orion/profile-nomade/v1";`
  - `pub struct nomad::PassphraseKey` — 32 bytes in an `aether::locked::LockedSecret`; no `Clone`/`Serialize`/`Display`, redacting `Debug`.
    - `pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<PassphraseKey, VaultError>`: normalises, then PBKDF2-HMAC-SHA-512 with `aether_vault::PBKDF2_ITERATIONS`, through `aws_lc_rs::pbkdf2::derive(PBKDF2_HMAC_SHA512, …)`. If the buffer's `lock_state()` is not `LockState::Locked` → `Err(VaultError::MemoryHygiene("verrouillage mémoire refusé : le profil nomade ne peut pas être déverrouillé"))`.
    - `pub fn with_exposed<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R` — the only read access (Task 7 wraps it with `CryptProtectMemory`).
  - `pub fn nomad::new_salt() -> Result<[u8; SALT_LEN], VaultError>` (CSPRNG via `aether::random::fill_public`).
  - `pub enum ManifestKey<'a> { Service, Nomad(&'a PassphraseKey) }` in `vault/mod.rs`.
  - `pub fn seal_manifest(root, id, manifest, client_public_key, key: ManifestKey<'_>) -> Result<Vec<u8>, VaultError>` and `pub fn open_manifest(root, id, client_public_key, gateway_public_key, blob, key: ManifestKey<'_>) -> Result<ProfileManifest, VaultError>`. `Nomad` uses `Unlock::Derived` with IKM = `profile_root_key(id)` (32) ‖ passphrase key (32), built in a `Zeroizing<[u8; 64]>`.
  - New `VaultError` variants (French messages, verbatim):
    - `ProfileLocked(String)` — `"le profil « {0} » est verrouillé : sa passphrase est demandée à la connexion"`
    - `WrongPassphrase` — `"Passphrase incorrecte, ou profil altéré."`
    - `PassphraseMismatch` — `"Les deux saisies diffèrent."`
    - `LockWatchUnavailable` — `"le moteur ne reçoit pas les notifications de verrouillage et de veille : un profil nomade ne peut pas être déverrouillé"`
    - `NewPassphraseRefused(passphrase::PassphraseError)` — `"{0}"`

- [ ] **Step 1: Write the failing tests** in `nomad.rs`:

```rust
#[test]
fn the_passphrase_key_matches_its_reference_vector() {
    // hashlib.pbkdf2_hmac('sha512', b'cheval agrafe batterie correcte orion', bytes(range(16)), 600000, 32)
    let key = PassphraseKey::derive("cheval agrafe batterie correcte orion", &core::array::from_fn(|i| i as u8)).unwrap();
    key.with_exposed(|bytes| assert_eq!(hex(bytes), "040228c878145844af777e8ff6f99aa97d22ee190289607864e6785e2ac9d93b"));
}
#[test]
fn another_salt_gives_another_key() {
    // salt bytes(range(1, 17))
    let key = PassphraseKey::derive("cheval agrafe batterie correcte orion", &core::array::from_fn(|i| i as u8 + 1)).unwrap();
    key.with_exposed(|bytes| assert_eq!(hex(bytes), "fbef8869e778136c3d04a0a45dfc148d5ad21085e192faeeae1885817d529e12"));
}
#[test]
fn trailing_spaces_and_nfd_derive_the_same_key() { /* "  …orion  " and an NFD "é" vs NFC "é" give equal bytes */ }
#[test]
fn a_nomad_manifest_needs_both_the_root_and_the_passphrase() {
    // seal with ManifestKey::Nomad(k); open with Service → Err; with another root + k → Err;
    // with root + other passphrase key → Err(Container(..)); with root + k → Ok, same manifest
}
#[test]
fn the_debug_output_names_no_byte() { assert!(!format!("{key:?}").contains("04")); }
```

- [ ] **Step 2: Run them, expect compile failure**

Run: `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion-core vault::nomad`
Expected: FAIL (module `nomad` missing).

- [ ] **Step 3: Implement** the interfaces above; pass `ManifestKey::Service` at every existing call site (`store.rs`, `relocation.rs`, tests).

- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-core vault::` — all pass, existing `keys.rs` vectors unchanged.

- [ ] **Step 5: Commit** `feat(orion-core): derive the nomad passphrase key under the TPM root`

---

### Task 2: Registry v3 with the profile mode

**Files:**
- Modify: `crates/orion-core/src/vault/registry.rs`
- Test: in-file tests of `registry.rs`

**Interfaces:**
- Consumes: `nomad::SALT_LEN` (Task 1).
- Produces:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ProfileMode { Service, Nomad { kdf: u8, salt: [u8; SALT_LEN] } }` with `pub fn as_str(&self) -> &'static str` returning `"service"` / `"nomade"`, and `pub fn is_nomad(&self) -> bool`.
  - `RegistryEntry.mode: ProfileMode` (new field, last).
  - `REGISTRY_VERSION = 3` (v2 is the current on-disk format, without mode). Encoding per entry, after `rotation_required`: `0` for `Service`; `1, kdf, salt[16]` for `Nomad`.
  - Decoding: version `2` reads the current layout with every entry `Service`; version `3` reads the mode; version `1` stays refused as today; `kdf == 1` → `Err(VaultError::Container(aether_vault::VaultError::BurnedKdf(1)))`; any `kdf` other than `2` → `Err(VaultError::Container(aether_vault::VaultError::UnsupportedKdf(kdf)))`; unknown mode byte → `ManifestEncoding`. `encode` always writes v3.

- [ ] **Step 1: Write the failing tests**: `a_v3_registry_round_trips_both_modes`, `a_v2_registry_reads_as_service` (bytes built with the v2 layout by hand), `a_burned_kdf_is_refused_and_named`, `an_unknown_kdf_is_refused`, `an_unknown_mode_byte_is_refused`.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-core vault::registry` — FAIL.
- [ ] **Step 3: Implement.** Update the `entry()` test helper and every `RegistryEntry { .. }` literal in the crate (`mode: ProfileMode::Service`).
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-core vault::` — PASS.
- [ ] **Step 5: Commit** `feat(orion-core): record each profile's mode in the registry (v2)`

---

### Task 3: Store — locked profiles and unlock

**Files:**
- Modify: `crates/orion-core/src/config.rs` (`LockedProfile`, `ClientConfig.locked`)
- Modify: `crates/orion-core/src/vault/store.rs`
- Modify: `crates/orion-core/src/vault/relocation.rs` (verification count)
- Test: `crates/orion-core/src/vault/store/tests.rs`, `crates/orion-core/src/vault/relocation/tests.rs`

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces:
  - `pub struct LockedProfile { pub name: String, pub client_public_key: String, pub gateway_public_key: String }` in `config.rs` (no secret; `Debug, Clone`).
  - `ClientConfig.locked: Vec<LockedProfile>` with `#[serde(skip)]`.
  - In `ProfileStore`:
    - private `unlocked: Mutex<HashMap<ProfileId, PassphraseKey>>`, `lock_epoch: AtomicU64`, `lock_watch: AtomicBool` (default `false`).
    - `pub fn set_lock_watch(&self, active: bool)` / `pub fn lock_watch_active(&self) -> bool`.
    - `pub fn mode_of(&self, name: &str) -> Result<Option<ProfileMode>, VaultError>`.
    - `pub fn unlock(&self, name: &str, passphrase: &str) -> Result<(), VaultError>`: refuse with `LockWatchUnavailable` when the watch is off; read `lock_epoch` first; derive, open the manifest with `ManifestKey::Nomad`; an AEAD/container failure → `WrongPassphrase`; if `lock_epoch` changed meanwhile, drop the key and return `Err(VaultError::ProfileLocked(name))`; else keep the key under the entry's `ProfileId`. Unlocking a `service` profile is a no-op `Ok(())`.
    - `pub fn forget_unlocked(&self)`: increments `lock_epoch`, clears `unlocked` and `root_cache`.
    - `pub fn is_unlocked(&self, name: &str) -> bool`.
  - `load()` opens `service` manifests and the nomad ones whose key is held; other nomad entries go to `ClientConfig.locked` (from the registry, no manifest read).
  - Writes of a nomad profile (`save_profile`, and every path that reseals a manifest) use its held key; without it → `Err(ProfileLocked(name))`. `save_profile` on a name whose entry is a locked nomad profile → `ProfileLocked`. `remove_profile` and `select` never need a key.
  - The security digest stored in the registry becomes `entry_digest(manifest.security_digest(), &mode)` (SHA-256 over both), so a mode change raises the generation (used by Task 4).
  - `.next` recovery at the start of `load()` (spec §5.7), from file names only, nothing decrypted: `profiles/<id>.g<generation>.next.hvlt` with a generation above the registry entry's is deleted; one equal to it is renamed to `<id>.hvlt`. The normal open then checks the authenticated generation. `pub(crate) fn next_manifest_path(&self, id: ProfileId, generation: SecurityGeneration) -> PathBuf` is the single place that builds the name. `count_manifests` in relocation ignores `*.next.hvlt`.
  - Relocation: `verified.profiles.len() + verified.locked.len()` must equal `registered`.

- [ ] **Step 1: Write the failing tests** (scripted root as in the existing tests; nomad entries created through a test helper that seals with `ManifestKey::Nomad` and writes a `Nomad` registry entry, until Task 4 adds the real gesture):
  - `load_keeps_a_nomad_profile_locked` — `config.locked` has it, `config.profiles` does not, and no manifest is opened (counting provider unchanged beyond the registry).
  - `unlock_opens_it_and_load_then_returns_it`
  - `a_wrong_passphrase_is_refused_and_leaves_it_locked` → `WrongPassphrase`, `!is_unlocked`.
  - `unlock_is_refused_without_the_lock_watch` → `LockWatchUnavailable`.
  - `a_lock_during_unlock_discards_the_key` — call `forget_unlocked()` from a hook between derivation and storage (expose a `#[cfg(test)]` hook or split the function) → `ProfileLocked`, `!is_unlocked`.
  - `forget_unlocked_locks_every_nomad_profile_again`
  - `a_locked_nomad_profile_is_never_written` — `save_profile` → `ProfileLocked`; the manifest bytes on disk are unchanged.
  - `saving_over_a_locked_nomad_name_is_refused`
  - `rename_select_and_remove_need_no_passphrase`
  - `trailing_spaces_and_nfd_open_the_profile`
  - `a_next_manifest_above_the_registry_is_deleted` / `a_next_manifest_at_the_registry_generation_is_promoted`
  - relocation: `a_vault_with_a_locked_nomad_profile_relocates`.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-core vault::` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-core` — PASS; then `scripts/wsl-cargo clippy -p orion-core --all-targets -- -D warnings`.
- [ ] **Step 5: Commit** `feat(orion-core): keep nomad profiles locked until their passphrase opens them`

---

### Task 4: Store — mode switches

**Files:**
- Modify: `crates/orion-core/src/vault/store.rs`
- Test: `crates/orion-core/src/vault/store/tests.rs`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces (all on `ProfileStore`; `new_passphrase` is raw, passed through `passphrase::accept` → `NewPassphraseRefused` on refusal):
  - `pub fn save_new_nomad_profile(&self, profile: &ClientProfile, new_passphrase: &str) -> Result<(), VaultError>` — only for a name absent from the registry (else `ProfileLocked` if locked, or a refusal saying to use the switch); seals directly as nomad, never writes a service manifest; the key stays unlocked.
  - `pub fn make_nomad(&self, name: &str, new_passphrase: &str) -> Result<(), VaultError>` — from `service`, or from an **unlocked** nomad profile (= change of passphrase: new salt). Locked nomad → `ProfileLocked`.
  - `pub fn make_service(&self, name: &str) -> Result<(), VaultError>` — from an unlocked nomad profile only; forgets its key afterwards.
  - Every switch: generation + 1, digest recomputed with the new mode, and the three writes of spec §5.7 in this order: `next_manifest_path(id, generation + 1)`, registry, rename to `<id>.hvlt`. The held key is replaced only after the registry write.
- [ ] **Step 1: Write the failing tests**:
  - `service_to_nomad_then_load_is_locked_after_forget` — after `make_nomad` + `forget_unlocked`, `load()` lists it in `locked`; `unlock` with the new passphrase works, the old service blob path holds a nomad blob.
  - `changing_the_passphrase_refuses_the_old_one`
  - `back_to_service_opens_without_passphrase`
  - `each_switch_raises_the_generation`
  - `a_weak_new_passphrase_is_refused_and_nothing_changes` — `"motdepasse"` → `NewPassphraseRefused(TooCommon)`; files byte-identical.
  - `a_new_nomad_profile_never_touches_disk_as_service` — inspect the written blob header: the kdf byte (offset 5, after `HVLT` and the version, see the layout comment at the top of `crates/aether-vault/src/lib.rs`) is the HKDF identifier, never the raw-key one.
  - `a_crash_after_each_write_leaves_an_openable_profile` — for each of the three steps, stop after it (split the switch into `pub(crate)` steps or inject a failing writer), reopen a fresh store on the same dir, and assert the profile opens in the old mode (after step 1) or the new mode (after steps 2 and 3).
  - `a_tightened_policy_still_opens_an_existing_profile` — seal with a passphrase that `accept` would now refuse (build the key directly with `PassphraseKey::derive`), then `unlock` succeeds.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-core vault::store` — FAIL.
- [ ] **Step 3: Implement.** Replace Task 3's test helper by these gestures where it simplifies the tests.
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-core` and clippy — PASS.
- [ ] **Step 5: Commit** `feat(orion-core): switch a profile between service and nomad atomically`

---

### Task 5: Engine — passphrase source, view, commands, protocol v3

**Files:**
- Create: `crates/orion-engine/src/service/nomad.rs`
- Modify: `crates/orion-engine/src/service.rs` (field `passphrases: Arc<dyn PassphraseSource>`, constructor parameter, command dispatch)
- Modify: `crates/orion-engine/src/service/connection.rs` (unlock before connecting)
- Modify: `crates/orion-engine/src/service/profiles.rs` (`save_profile` honours `draft.nomad`)
- Modify: `crates/orion-engine/src/command.rs`, `crates/orion-engine/src/wire.rs` (`PROTOCOL_VERSION = 3`), `crates/orion-engine/src/view.rs`
- Modify: `apps/orion/src-tauri/src/engine_host.rs` (pass the production source — on Windows the native one from Task 7; off Windows a source that returns `VaultError::NoNativePrompt`)
- Test: `crates/orion-engine/src/service/tests.rs` (or `service/nomad/tests.rs`)

**Interfaces:**
- Consumes: Tasks 3–4.
- Produces:
  - `pub enum PromptPurpose { Unlock, Current, New, Confirm, Retry(String) }` and
    `pub trait PassphraseSource: Send + Sync { fn ask(&self, profile: &str, purpose: &PromptPurpose) -> Result<Zeroizing<String>, VaultError>; }`
    in `orion_core::vault::prompt_source` (portable, so Task 7's native source lives in orion-core next to `windows::prompt`). Re-exported by orion-engine.
  - `EngineCommand::{MakeNomad { name: String }, ChangePassphrase { name: String }, MakeService { name: String }}` (serde `make_nomad`, `change_passphrase`, `make_service`), each replying with the `ConfigView`.
  - `ProfileDraft.nomad: bool` (`#[serde(default)]`).
  - `ProfileView.mode: String` (`"service"`/`"nomade"`), `ConfigView.locked: Vec<LockedProfileView { name, client_public_key, peer_public_key }>`.
  - `VaultPosture.lock_watch_active: bool` and `VaultPosture.nomad_available: bool` (`true` only when the engine's passphrase source is the native dialog, i.e. on Windows).
  - Flows (each prompt call runs in `tokio::task::spawn_blocking`):
    - unlock: `ask(Unlock)` → `store.unlock` → reload `config` from `store.load()`.
    - new passphrase: `ask(New)`; `passphrase::accept` refusal → `ask(Retry(reason))`, looping until accepted or cancelled; then `ask(Confirm)`; different → `PassphraseMismatch`.
    - `Connect` on a locked profile: unlock, then connect. `MakeNomad` from service: new passphrase. `ChangePassphrase`: unlock if locked (purpose `Current`), then new passphrase, `store.make_nomad`. `MakeService`: unlock if locked (purpose `Current`), then `store.make_service`. `SaveProfile` with `nomad: true` for a new name: new passphrase, `save_new_nomad_profile`; on an existing name `nomad` is ignored (the switch is its own gesture).
    - `PassphraseCancelled` reaches the UI as the error string `"Saisie annulée."`.
- [ ] **Step 1: Write the failing tests** with a scripted `PassphraseSource` (queue of answers, records purposes):
  - `connect_on_a_locked_profile_asks_once_then_connects` (purposes `[Unlock]`, fake backend connected).
  - `a_second_connect_in_the_session_does_not_ask`
  - `cancel_leaves_the_profile_locked_and_says_so` → `Err("Saisie annulée.")`.
  - `make_nomad_asks_new_then_confirm` / `a_mismatch_changes_nothing` / `a_refused_passphrase_is_asked_again_with_its_reason` (purposes `[New, Retry("…trop courante…"), Confirm]`).
  - `change_passphrase_on_a_locked_profile_asks_current_first`
  - `make_service_on_a_locked_profile_asks_current`
  - `save_a_new_profile_as_nomad`
  - `no_frame_carries_a_passphrase` — serialise every new command and the `ConfigView` of a nomad profile and assert the JSON has no key containing `passphrase`, and no value equal to the scripted passphrase.
  - `the_protocol_version_is_3`
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-engine` — FAIL.
- [ ] **Step 3: Implement**, then update `apps/orion/src-tauri` for the new constructor parameter and the new view fields so it compiles (Tauri commands for the three gestures come in Task 8).
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-engine -p orion-core`, `scripts/wsl-cargo clippy -p orion-engine -p orion --all-targets -- -D warnings` — PASS.
- [ ] **Step 5: Commit** `feat(orion-engine): unlock and switch nomad profiles through a passphrase source`

---

### Task 6: Engine — lock state machine

**Files:**
- Create: `crates/orion-engine/src/service/lock.rs`
- Modify: `crates/orion-engine/src/service.rs`
- Test: `crates/orion-engine/src/service/lock.rs` tests or `service/tests.rs`

**Interfaces:**
- Consumes: Tasks 3, 5.
- Produces:
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum LockEvent { SessionLock, SessionLogoff, SessionDisconnect, Suspend, EngineExit }`.
  - `pub async fn EngineService::on_lock_event(&self, event: LockEvent, events: &EventQueue)`: (1) if the active tunnel's profile is nomad, `stop_connection`; (2) `store.forget_unlocked()`; (3) reload `config` from `store.load()` so nomad profiles return to `locked`. A `service` tunnel is untouched. Logs `tracing::info!(event = ?event, "nomad profiles locked")`, no profile secret.
  - `pub fn EngineService::set_lock_watch(&self, active: bool)` forwarding to the store.
- [ ] **Step 1: Write the failing tests**: `each_event_closes_a_nomad_tunnel_and_locks` (table over the five events), `a_service_tunnel_survives_a_lock`, `after_a_lock_connect_asks_again`, `a_lock_while_the_dialog_is_open_wins` (scripted source that calls `on_lock_event` before returning the passphrase → connect fails with the profile still locked).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-engine lock` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-engine` — PASS.
- [ ] **Step 5: Commit** `feat(orion-engine): lock nomad profiles on session and power events`

---

### Task 7: Windows — watcher, protected memory, native dialogs, foreground

**Files:**
- Create: `crates/orion-engine/src/lock_watch.rs` (`#[cfg(windows)] mod imp`, portable translation function)
- Modify: `apps/orion/src-tauri/src/engine_host.rs` (start the watcher; spawn on the engine runtime a task that reads the receiver and calls `on_lock_event` for each event; `set_lock_watch(true)` only once `start` returned `Ok`; `on_lock_event(EngineExit)` before `runtime.shutdown_background()`)
- Modify: `crates/orion-core/src/vault/nomad.rs` (Windows: `CryptProtectMemory`/`CryptUnprotectMemory` with `CRYPTPROTECTMEMORY_SAME_PROCESS` around `with_exposed`)
- Modify: `crates/orion-core/src/vault/windows/prompt.rs` (`ask_with(caption, message)`, native `PassphraseSource`)
- Modify: `apps/orion/src-tauri/src/engine_launch.rs` and the Tauri commands that may prompt (`connect`, tray connect, `save_profile`, the three gestures): call `AllowSetForegroundWindow(engine_pid)` before sending the command.
- Modify: `Cargo.toml` features of `windows-sys` in the touched crates as needed.
- Test: portable tests of the translation function.

**Interfaces:**
- Consumes: Task 6 (`LockEvent`, `on_lock_event`, `set_lock_watch`), Task 5 (`PassphraseSource`, `PromptPurpose`).
- Produces:
  - `pub fn lock_watch::translate(message: u32, wparam: usize) -> Option<LockEvent>` (portable): `WM_WTSSESSION_CHANGE` (0x02B1) with `WTS_SESSION_LOCK` (7) → `SessionLock`, `WTS_SESSION_LOGOFF` (6) → `SessionLogoff`, `WTS_CONSOLE_DISCONNECT` (2) and `WTS_REMOTE_DISCONNECT` (4) → `SessionDisconnect`; `WM_POWERBROADCAST` (0x0218) with `PBT_APMSUSPEND` (4) → `Suspend`; anything else `None`.
  - `pub fn lock_watch::start(sender: tokio::sync::mpsc::UnboundedSender<LockEvent>) -> Result<LockWatch, String>` (Windows): a dedicated thread with a message-only window (`HWND_MESSAGE`), `WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)`, `RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE)`; returns only after both registrations succeed. Off Windows `start` returns `Err`, and the engine keeps `lock_watch_active = false`.
  - Native source: captions `"Orion — profil nomade"`; messages (verbatim, `{p}` = profile name):
    - Unlock: `"Passphrase du profil « {p} ». Le nom d'utilisateur affiché est sans effet."`
    - Current: `"Passphrase actuelle du profil « {p} »."`
    - New: `"Nouvelle passphrase du profil « {p} » : au moins 20 caractères, ou 5 mots. Elle n'est stockée nulle part ; oubliée, le profil doit être supprimé puis ré-enrôlé."`
    - Confirm: `"Confirmez la nouvelle passphrase du profil « {p} »."`
    - Retry(reason): `"{reason}. Nouvelle passphrase du profil « {p} »."`
- [ ] **Step 1: Write the failing test** `translate_maps_each_notification` (all listed codes, plus `WTS_SESSION_UNLOCK` (8) and `PBT_APMRESUMEAUTOMATIC` (0x12) → `None`).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-engine lock_watch` — FAIL.
- [ ] **Step 3: Implement.** Verify every `windows-sys` path and feature name in the 0.61 sources before using it, and list them in the report. Mark in the report that the Windows code is uncompiled locally.
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-engine -p orion-core` and `scripts/wsl-cargo clippy -p orion-engine -p orion-core -p orion --all-targets -- -D warnings` — PASS.
- [ ] **Step 5: Commit** `feat(orion): watch session and power events, protect the held key, native nomad dialogs`

---

### Task 8: Orion UI

**Files:**
- Modify: `apps/orion/src/types.ts` (`ProfileView.mode`, `ConfigView.locked`, `LockedProfileView`, `ProfileDraft.nomad`, `VaultPosture.lock_watch_active`, `VaultPosture.nomad_available`)
- Modify: `apps/orion/src/api.ts` (`makeNomad`, `changePassphrase`, `makeService`)
- Modify: `apps/orion/src-tauri/src/commands/profiles.rs` and the Tauri command registry (`make_nomad`, `change_passphrase`, `make_service`)
- Modify: `apps/orion/src/views/ProfilesView.tsx`, `apps/orion/src/components/PosturePanel.tsx`
- Test: `apps/orion/src/views/ProfilesView.test.tsx`, `apps/orion/src/components/rendering.test.tsx` (or the posture test file in use)

**Interfaces:**
- Consumes: Task 5 view and commands.
- UI copy (verbatim):
  - mode badge `Service` / `Nomade`; locked row `Nomade · verrouillé` with no endpoint or settings, and only « Se connecter », « Changer la passphrase », « Repasser en service », « Supprimer ».
  - buttons `Passer en nomade`, `Changer la passphrase`, `Repasser en service`.
  - form field « Mode » with the choices `Service` / `Nomade` (new profiles and imports only).
  - next to `Passer en nomade` and the « Nomade » choice: `Le profil nomade protège un portable volé éteint : sans la passphrase, le tunnel ne monte pas. Il ne protège pas d'un logiciel malveillant ni d'un enregistreur de frappe présent à la saisie. Passphrase oubliée : supprimez le profil et faites-le ré-enrôler.`
  - with `Passer en nomade` only: `Les copies de ce profil faites avant ce changement (sauvegardes, profil itinérant) s'ouvrent encore sans passphrase sur ce poste.`
  - when `VaultPosture.nomad_available` is `false`, the « Nomade » choice and `Passer en nomade` are disabled with `Le profil nomade exige la boîte de saisie protégée de Windows.`
  - posture: `Verrouillage des profils nomades : actif` / `Verrouillage des profils nomades : indisponible — aucun profil nomade ne peut être déverrouillé` (blocking style).
  - `Saisie annulée.` is shown as a neutral notice, not an error.
- [ ] **Step 1: Write the failing vitest tests**: badge per mode; locked row hides endpoint and shows the four actions; each gesture calls its API with only the profile name; the form sends `nomad: true`; the two warnings render; disabled state with its sentence; posture lines; no input of type `password` exists anywhere in the view.
- [ ] **Step 2: Run** `npm --prefix apps/orion test -- --run ProfilesView` — FAIL.
- [ ] **Step 3: Implement**, plus the three Tauri commands (each calls `AllowSetForegroundWindow` per Task 7 before the engine call).
- [ ] **Step 4: Run** `npm --prefix apps/orion test -- --run`, `npm --prefix apps/orion run build` (tsc), `scripts/wsl-cargo clippy -p orion --all-targets -- -D warnings` — PASS.
- [ ] **Step 5: Commit** `feat(orion): show and switch the nomad profile mode`

---

### Task 9: Documentation

**Files:**
- Modify: `docs/adr/ADR-006-SECRETS-AU-REPOS.md` (« Limites connues » : remplacer « Le profil `nomade` n'est pas câblé » par ce qui est livré et ce qui reste à éprouver sur cible ; la limite `CryptProtectMemory` devient « appliqué à la clé de passphrase gardée, pas encore aux autres secrets »)
- Modify: `docs/ROADMAP.md` (F6 : livré sur la branche `feat/f6-profil-nomade`, validation Windows à faire ; F14 lot 7 : « fusionné dans `main` le 18 novembre 2026 (Helios 3.6.0, Orion 4.6.0) », F14 complet)
- Modify: `docs/testing/MANUAL-TESTING.md` (nouvelle section « O. F6 — profil nomade » : les quatre gestes, annulation, mauvaise passphrase, verrouillage de session, veille, hibernation, déconnexion RDP, fermeture d'Orion, moteur tué → tunnel tombé, échec simulé du verrouillage mémoire, passphrase absente des commandes Tauri et de la mémoire JavaScript)
- Modify: the Orion user guide if it documents the *Profils* tab (`grep -rl "Profils" docs`).
- [ ] **Step 1:** Write the changes, in French.
- [ ] **Step 2:** Run `bash scripts/check.sh` (doc links and guards) — PASS.
- [ ] **Step 3: Commit** `docs(f6): profil nomade livré, recette Windows, ROADMAP`
