# F14-f : copie du coffre — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Astra refuses a vault copy older than (or diverging from) the one it holds, Orion says so and offers « Remplacer quand même », Orion exports the vault to a file, and the relay write is guarded.

**Architecture:** A clear `revision` counter in `AuthorityVault`, outside the sealed payload's context, bumped by `store::save`. Astra's door reads it from the header without a key and refuses with a new `412` class, which the gateway relay carries through. Orion maps the `412` to a `Stale` outcome, shows it on the « Copie du coffre » row, and resends with `replace_newer` on request.

**Tech Stack:** Rust (astra-operator, astra, aether, astra-channel, helios-api, heliosd, Orion Tauri), TypeScript/React (Orion), Vitest.

**Spec:** `docs/superpowers/specs/2026-11-15-f14-f-copie-coffre-design.md`

## Global Constraints

- Build/test only via `scripts/wsl-cargo` with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`; never `CARGO_TARGET_DIR`, `HELIOS_WSL_BUILD_OVER_BUDGET`, `clean-wsl-targets`.
- Code, comments, logs in English; docs in French. No TODO markers. Never edit versions. Don't touch `docs/audits`.
- No vault byte, PIN or secret in the WebView or any log; the export path comes from the native dialog, never from the WebView.
- `revision`: `#[serde(default, skip_serializing_if = "is_zero")]`, outside `payload_context`.
- `store::save` writes `max(value.revision, on-disk revision) + 1` (`saturating_add`); on-disk revision read without a key, 0 if absent or unreadable; signature unchanged.
- `store::save_new` writes a new vault at revision 1.
- Astra rule, for a copy different from the one held: held revision 0 (old, none, unreadable header) → accepted; sent < held → refused; sent == held and bytes differ → refused. Identical copy always passes.
- Order in the door: size, header and domain, identical, then the stale refusal (`412`), then the live-operation `409`. With `replace_newer`, the stale rule is lifted, everything else applies.
- `OperatorVaultCopy.replace_newer: bool`, `#[serde(default, skip_serializing_if = "std::ops::Not::not")]`.
- `OperatorAuthorityStatus.vault_copy_revision: Option<u64>`, `#[serde(default)]`.
- Status code: `412 PRECONDITION_FAILED`, same class for late and diverging; the sentence stays in Astra's log.
- Copy (exact): row detail « Plus récente sur Astra » (wins over « Ancienne » and « Document ancien »); refusal « Astra tient un coffre plus récent que celui de ce poste, ou qui a divergé. Récupérez le coffre à jour sur le poste qui le tient. »; button « Remplacer quand même »; warning « La copie d'Astra sera remplacée par ce coffre. À ne faire que si vous savez que la copie d'Astra est fausse. »; button « Exporter le coffre »; result « Coffre exporté »; default file name `authority-vault-AAAA-MM-JJ.json`.
- A refused copy never puts a rotation back in question: the resume finishes and the row stays « À faire ». « Remplacer quand même » is never offered automatically nor during a rotation's resume; it re-reads the vault from disk at click time.

## Review Focus

1. A rotation applied from a journal sealed before the counter existed (next vault at 0) must land above Astra's copy — Task 1 test `apply_local_lands_above_the_vault_it_replaces`.
2. A vault never re-saved since the upgrade (no `revision` field) must still serialize without the field, so a lagging binary reads it — Task 1 test `an_old_vault_round_trips_without_the_field`.
3. An older gateway without `replace_newer` support must still accept an ordinary send: the field is absent from the JSON when false — Task 2 test `an_ordinary_copy_carries_no_replace_newer`.
4. A `412` on the automatic end-of-rotation send must finish the rotation, not loop — Task 4 test `a_stale_copy_at_the_end_of_a_rotation_finishes_it`.
5. The export must refuse the vault's own path, also when spelled differently (`./`, `..`) — Task 4 test `export_refuses_the_vault_itself`.

---

### Task 1: Vault revision counter and relay guard (`astra-operator`)

**Files:**
- Modify: `crates/astra-operator/src/vault.rs` (`AuthorityVault`, ~l.413; `create`)
- Modify: `crates/astra-operator/src/store.rs` (`save`, `save_new`, tests)
- Modify: `crates/astra-operator/src/vault_gestures.rs` (`write_relay`, ~l.362)
- Test: `crates/astra-operator/src/store.rs` tests module; `crates/astra-operator/src/rotation_journal.rs` tests; `crates/astra-operator/tests/rotation_journal_legacy.rs` (relay guard, next to `write_relay_refuses_an_origin_during_a_rotation_without_campaign`)

**Interfaces:**
- Produces: `AuthorityVault::revision: u64` (pub field); `store::save(path: &Path, vault: &AuthorityVault) -> Result<()>` writes the bumped revision; `pub fn revision_on_disk(path: &Path) -> u64` in `store.rs` (keyless header read, 0 on any failure).

- [ ] **Step 1: Write the failing tests** in `store.rs` tests:
  - `an_old_vault_reads_at_zero_and_is_rewritten_at_one`: serialize a vault, strip `"revision"` from the JSON, load → `revision == 0`; `save` → reloaded `revision == 1`.
  - `two_saves_from_the_same_value_count_on`: `save_new` (→ 1), then `save(&v)` twice from the same in-memory `v` → on disk 2 then 3.
  - `a_vault_at_zero_written_over_one_at_n_lands_above`: on disk at 5, `save` a value at 0 → 6.
  - `an_old_vault_round_trips_without_the_field`: a value at 0 serialized by `serde_json::to_vec_pretty` contains no `"revision"`.
  - `the_revision_does_not_change_opening`: after `save`, `vault.open(credential, secret)` still succeeds (use the existing fixture pattern of `vault.rs` tests if `store.rs` lacks one).
- [ ] **Step 2: Write the failing test** `apply_local_lands_above_the_vault_it_replaces` in `rotation_journal.rs` tests: a journal whose `next.vault.revision == 0`, live vault on disk at 4; after `apply_local`, `revision_on_disk == 5`.
- [ ] **Step 3: Write the failing test** `write_relay_refuses_while_a_sealed_vault_waits` in `tests/rotation_journal_legacy.rs`: with a journal at `Accepted` holding `next`, `vault_gestures::write_relay` returns `Err` with the same sentence `ensure_vault_not_awaiting_overwrite` gives, and the relay file is unchanged.
- [ ] **Step 4: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator` — expected: the new tests fail (field missing / guard absent).
- [ ] **Step 5: Implement**: field `revision` on `AuthorityVault` (doc comment: clear, unauthenticated, outside the sealed context, orders copies for Astra); `revision_on_disk`; `save` clones the value, sets `revision = max(value.revision, revision_on_disk(path)).saturating_add(1)`, writes; `save_new` writes at 1 (it refuses an existing path, so `revision_on_disk` is 0 there); `write_relay` calls `crate::rotation_journal::ensure_vault_not_awaiting_overwrite(vault_path)?` first.
- [ ] **Step 6: Run** the crate's tests and `scripts/wsl-cargo clippy -p astra-operator --all-targets -- -D warnings` — expected: PASS, clean. Fix any existing test that compared a reloaded vault to the in-memory value (the revision now differs): compare with the revision set, never by dropping the assertion.
- [ ] **Step 7: Commit** `feat(astra-operator): the vault carries a revision, and the relay waits for a sealed vault`

### Task 2: Astra refuses a stale copy (`aether`, `astra`)

**Files:**
- Modify: `crates/aether/src/certificates/transport.rs` (`OperatorVaultCopy` ~l.1380 + its `Debug`; `OperatorAuthorityStatus` ~l.1302)
- Modify: `crates/astra/src/door/vault_copy.rs` (`VaultHeader`, `copy_vault`)
- Modify: `crates/astra/src/door/mod.rs` (`DoorRequest::VaultCopy` gets `replace_newer: bool`; `DoorRefusal::VaultCopyStale`; `class()`)
- Modify: `crates/astra/src/service.rs` (`ServiceError::Stale` → `StatusCode::PRECONDITION_FAILED`)
- Modify: `crates/astra/src/operator.rs` (`vault_copy` passes `replace_newer`, maps `VaultCopyStale` → `ServiceError::Stale`; status builds `vault_copy_revision`)
- Test: `crates/astra/src/door/tests.rs` (beside the existing vault-copy tests), `crates/aether` transport tests

**Interfaces:**
- Consumes: the `revision` JSON field from Task 1 (Astra reads the header only; `astra` must not depend on `astra-operator` for this).
- Produces: `OperatorVaultCopy { vault_base64, credentials, replace_newer: bool }`; `OperatorAuthorityStatus.vault_copy_revision: Option<u64>`; HTTP `412` from `POST .../operator/vault-copy` for a stale copy.

- [ ] **Step 1: Write the failing tests** in `door/tests.rs`, each asserting nothing written (vault file, previous file, memory) on refusal:
  - `a_late_copy_is_refused`: held at 3, sent at 2 → `Err(DoorRefusal::VaultCopyStale)`.
  - `a_diverging_copy_is_refused`: held at 3, sent at 3 with other bytes → `VaultCopyStale`.
  - `an_identical_copy_passes`: same bytes → `VaultCopied`.
  - `a_held_copy_at_zero_or_unreadable_accepts_any`: held without `revision` → sent at 0 different accepted; held unparseable bytes → accepted.
  - `replace_newer_lifts_the_stale_rule_and_keeps_the_previous`: held at 3, sent at 2 with `replace_newer` → copied, previous file holds the old copy.
  - `stale_comes_before_held_back`: live operation awaiting a vault AND sent < held → `VaultCopyStale`, not `AlreadyOpen`.
  - `the_status_carries_the_revision`: status `vault_copy_revision == Some(3)` with a held copy at 3; `None` without copy.
- [ ] **Step 2: Write the failing test** `an_ordinary_copy_carries_no_replace_newer` in aether: `serde_json::to_string(&OperatorVaultCopy{replace_newer:false,..})` has no `replace_newer`; a JSON without it parses to `false`.
- [ ] **Step 3: Run** `scripts/wsl-cargo test -p astra -p aether` (with the env vars) — expected: new tests fail.
- [ ] **Step 4: Implement** per Global Constraints. `VaultHeader` gains `#[serde(default)] revision: u64`; the held header is parsed the same way (unreadable → 0). Log line on refusal names the operator, the two revisions and late/diverging; on a forced replacement, logs `forced = true` with operator and fingerprint. Update every constructor of `OperatorVaultCopy` / `DoorRequest::VaultCopy` in the workspace (`grep -rn "OperatorVaultCopy {"`) with `replace_newer: false`.
- [ ] **Step 5: Run** tests and clippy for `astra`, `aether` — expected: PASS, clean.
- [ ] **Step 6: Commit** `feat(astra): a vault copy behind the one held is refused`

### Task 3: The gateway relays the `412` (`aether`, `astra-channel`, `heliosd`, `helios-api`)

**Files:**
- Modify: `crates/aether/src/certificates/transport.rs` (`TrustUpdateRefusal` ~l.775: new variant `Stale`, doc: the copy is behind or diverges from the one the authority holds; answered only to an administrator)
- Modify: `crates/helios-api/src/certificates/trust_update.rs` (~l.102: `Stale => StatusCode::PRECONDITION_FAILED`)
- Modify: `crates/heliosd/src/astra_channel.rs` (`refuse`, ~l.628: `412 => TrustUpdateRefusal::Stale`; table test ~l.1078)
- Modify: `crates/astra-channel/src/gateway_routes.rs` (~l.36-49 mapping, if it maps `TrustUpdateRefusal` exhaustively)
- Test: `crates/heliosd/src/astra_channel.rs` tests; `crates/helios-api` route test for `operator_vault_copy` if one exists for `409`

**Interfaces:**
- Consumes: `412` from Task 2.
- Produces: `POST /api/certificates/operator/vault-copy` on the gateway answers `412` when Astra does.

- [ ] **Step 1: Write the failing tests**: `relayed_412_is_stale_and_not_internal` (mirror of `relayed_409_is_a_conflict_and_not_internal`), and add `(StatusCode::PRECONDITION_FAILED, Refusal::Stale)` to `authority_statuses_map_to_their_coarse_refusal_classes`; a helios-api test that a relay answering `TrustUpdateRefusal::Stale` gives `412` (follow the existing `409` test of that route if present, otherwise the status mapping unit test).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p heliosd -p helios-api astra_channel` — expected: FAIL.
- [ ] **Step 3: Implement** the variant and the three mappings; fix every exhaustive `match` on `TrustUpdateRefusal` the compiler names.
- [ ] **Step 4: Run** tests and clippy for the four crates — expected: PASS, clean.
- [ ] **Step 5: Commit** `feat(heliosd): the gateway relays a stale vault copy as 412`

### Task 4: Orion backend — stale outcome, forced send, revision, export

**Files:**
- Modify: `crates/astra-operator/src/tunnel.rs` (`VaultCopySent::Stale`; `send_vault_copy` maps `412`)
- Modify: `crates/astra-operator/src/operations/rotation.rs` (`advance` ~l.1082: `Stale` finishes like `Copied`/`Err`; `vault_copy(vault_path)` unchanged, `replace_newer: false`)
- Modify: `apps/orion/src-tauri/src/operator/rotations.rs` (`send_copy_with` gains `replace_newer: bool`; `VaultCopyOutcome::Stale`; overview gains `local_vault_revision: Option<u64>`; `pub fn export_vault(vault_path: &Path, target: &Path) -> Result<(), String>`)
- Modify: `apps/orion/src-tauri/src/operator/ceremony/rotation.rs` (~l.537: handle `Stale` like a failed send)
- Modify: `apps/orion/src-tauri/src/operator/location.rs` (`pick` takes the dialog's title, filter and proposed file name, or a sibling `pick_export(owner, proposed: &Path)`; the existing caller keeps its texts)
- Modify: `apps/orion/src-tauri/src/commands/ceremonies.rs` (`operator_send_vault_copy(state, replace_newer: bool)`; new `operator_export_vault(state, window) -> Result<bool, String>`, `false` on cancel; register in the command list)
- Test: `apps/orion/src-tauri/src/operator/rotations.rs` tests (or its tests module), `crates/astra-operator/src/operations/rotation.rs` tests

**Interfaces:**
- Consumes: `OperatorVaultCopy.replace_newer`, `OperatorAuthorityStatus.vault_copy_revision` (Task 2), `412` (Task 3), `store::revision_on_disk` (Task 1).
- Produces (wire, serde as today, camelCase on the overview): `VaultCopyOutcome` variant `stale` (tag `state: 'stale'`); `RotationsOverview.localVaultRevision: number | null`; commands `operator_send_vault_copy({ replaceNewer: boolean })`, `operator_export_vault() -> boolean`.

- [ ] **Step 1: Write the failing tests**:
  - `a_stale_copy_at_the_end_of_a_rotation_finishes_it` (astra-operator): fake remote answering `Stale` at `Installed` → `ResumeStep::Finished`, journal cleared.
  - `a_stale_send_is_an_answer` (Orion): fake remote answering `Stale` → `Ok(VaultCopyOutcome::Stale)`; with `replace_newer: true` the copy the fake receives has `replace_newer == true` and the bytes read from disk at call time (change the file between two calls and assert the second carries the new bytes).
  - `the_overview_reads_the_local_revision`: vault at 4 → `local_vault_revision == Some(4)`; unreadable vault → `None`.
  - `export_writes_the_vault_bytes`: target file bytes equal the vault file bytes.
  - `export_refuses_the_vault_itself`: target `= vault path`, and the same path spelled `dir/./authority-vault.json` and `dir/sub/../authority-vault.json` → `Err`, vault unchanged.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p astra-operator -p orion <filters>` (find the Orion package name in `apps/orion/src-tauri/Cargo.toml`) — expected: FAIL.
- [ ] **Step 3: Implement.** `export_vault`: canonicalize the vault path and the target's parent joined with its file name; equal → `Err("le coffre ne peut pas être exporté sur lui-même")`; else `aether::private_file::write_private_atomic(target, &std::fs::read(vault)?)`. Never log the bytes. `operator_export_vault` follows `choose_vault_location`'s Windows thread/COM pattern and its non-Windows branch; the proposed name is `authority-vault-AAAA-MM-JJ.json` with today's local date. The forced send is refused while a rotation is resumable (`something_to_resume`), with the same sentence the screen gives for a rotation in progress.
- [ ] **Step 4: Run** tests and clippy (`-D warnings`) for both packages — expected: PASS, clean.
- [ ] **Step 5: Commit** `feat(orion): a stale vault copy is said, can be forced, and the vault exports`

### Task 5: Orion screens

**Files:**
- Modify: `apps/orion/src/types.ts` (`VaultCopyOutcome` gains `{ state: 'stale' }`; `OperatorAuthorityStatus.vault_copy_revision: number | null`; `RotationsOverview.localVaultRevision: number | null`)
- Modify: `apps/orion/src/api.ts` (`operatorSendVaultCopy(replaceNewer = false)`; `operatorExportVault()`)
- Modify: `apps/orion/src/views/astra/rotationRows.ts` (`vaultCopyPrerequisite` ~l.560)
- Modify: `apps/orion/src/views/astra/VaultCopy.tsx` (stale line, « Remplacer quand même » + warning)
- Modify: `apps/orion/src/views/astra/VaultPanel.tsx` (« Exporter le coffre » next to the location button)
- Modify: `apps/orion/src/views/astra/rotationFixtures.ts` (fixture fields)
- Test: `rotationRows.test.ts`, `VaultCopy.test.tsx`, `VaultPanel.test.tsx` (existing files beside them)

**Interfaces:**
- Consumes: Task 4 wire names.

- [ ] **Step 1: Write the failing tests**:
  - `rotationRows`: authority `vault_copy_revision: 5`, `localVaultRevision: 4`, fingerprints different → detail `'Plus récente sur Astra'`, `fix: 'Envoyer'` kept; also with the same vault and `documentAhead` true → still `'Plus récente sur Astra'`; `vault_copy_revision: null` or `localVaultRevision: null` → today's details unchanged.
  - `VaultCopy`: a send resolving `{ state: 'stale' }` shows the exact refusal sentence and the button `Remplacer quand même` with the exact warning; clicking it calls `api.operatorSendVaultCopy(true)` once; the button never appears for `held_back` or `copied`; with `resumable: true` the button is absent.
  - `VaultPanel`: `Exporter le coffre` calls `api.operatorExportVault` once; `true` → `Coffre exporté`; `false` → nothing shown; a rejection shows its message.
- [ ] **Step 2: Run** `npx vitest run src/views/astra` from `apps/orion` — expected: FAIL.
- [ ] **Step 3: Implement** with the exact copy from Global Constraints. The stale entry goes into the `unsettled` store like a held-back one, so it survives a change of view.
- [ ] **Step 4: Run** `npx vitest run` and `npx tsc --noEmit` from `apps/orion` — expected: PASS.
- [ ] **Step 5: Commit** `feat(orion): Plus récente sur Astra, Remplacer quand même, Exporter le coffre`

### Task 6: Documentation

**Files:**
- Modify: `docs/RENOUVELLEMENT-CERTIFICATS.md` (limits block ~l.1485-1505)
- Modify: `docs/MANUAL-TESTING.md` (new section « M. F14-f » after « L. F14-e », steps numbered after the last one)
- Modify: `docs/superpowers/specs/2026-11-04-f14-lot5b-rotations-design.md` (italic amendment of 15 novembre 2026 under the « Copie du coffre » limit, ~l.614)
- Modify: `docs/ROADMAP.md` (F14-f row ~l.156: lifted, branch `feat/f14-f-copie-coffre`, not yet merged, recipe « M. F14-f », spec path; F14-e row ~l.155: merged into `main` on 15 novembre 2026, Helios 3.4.8 / Orion 4.4.0)

- [ ] **Step 1:** RENOUVELLEMENT: replace the « copie du coffre » limit with what holds now — a late or diverging copy is refused (`412`), « Plus récente sur Astra », « Remplacer quand même » and when to use it, the tunnel administrator can still replace the copy (and inflate the counter; « Remplacer quand même » is the recourse), one previous generation kept, « Exporter le coffre » for a backup off the gateway, recovery of a late workstation = export from the up-to-date one then « Choisir l'emplacement du coffre »; compatibility: an older Orion or `astra-signer` no longer reads a vault carrying the counter. Replace the `write_domain_relay` limit by a line saying the relay write now waits like the key gestures.
- [ ] **Step 2:** MANUAL-TESTING « M. F14-f »: export; two workstations, the late one's « Envoyer » refused with the exact sentence and the row « Plus récente sur Astra »; « Remplacer quand même » replaces; end of a rotation with a stale copy finishes the rotation; relay write refused while a sealed vault waits. Each step with its expected result, as the sections before it.
- [ ] **Step 3:** Spec 5b amendment and ROADMAP rows.
- [ ] **Step 4: Commit** `docs: F14-f recipe, limits and roadmap`
