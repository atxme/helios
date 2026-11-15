# F14-e — Remplacer la CA-PQ sans campagne : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a domain whose relay names no Astra origin replaces its CA-PQ from Orion (*Rotations*), two keys, no campaign, the transition posed on the gateway through the tunnel, with a resume that never calls Astra.

**Architecture:** astra-operator gains a no-campaign journal mark and an opening/signature without campaign (`operations/rotation.rs`, `rotation_journal.rs`); Orion's rotation ceremony gains one gesture that runs validate → terms → sign → carry with no approval; the TS rotations screen gains one row, offered only when the relay names no origin.

**Tech Stack:** Rust (astra-operator, Orion Tauri), TypeScript/React (Orion), vitest.

**Spec:** `docs/superpowers/specs/2026-11-15-f14-e-ca-pq-sans-campagne-design.md` (approved 2026-11-15). Read §5 before any task.

## Global Constraints

- Work only in the worktree `/home/christophe/helios-wt/f14-e`, branch `feat/f14-e-ca-pq-sans-campagne`; never touch `~/helios`.
- Build only through `scripts/wsl-cargo`, with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`. Never set `CARGO_TARGET_DIR` or `HELIOS_WSL_BUILD_OVER_BUDGET`, never run `clean-wsl-targets`. A "field does not exist" error that contradicts the source is the shared cache: `touch` the crate's sources and rebuild.
- Before each Rust commit: `scripts/wsl-cargo fmt --all -- --check`, and clippy of the touched crates with `--all-targets --all-features -- -D warnings`.
- Vitest: `cd apps/orion && npx vitest run <file>`; types: `npx tsc --noEmit`.
- Code, comments and logs in English; on-screen sentences and `docs/` in French, short, naming the cause.
- No secret (PIN, `Opened`, vault bytes, private key) in the WebView or a log.
- No TODO markers; never edit versions by hand; never touch `docs/audits`.
- Every commit ends with `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`.
- A domain **with** an origin (`relay.astra_authority_url` is `Some`, whatever its value) never reaches the no-campaign path: fail closed.
- A no-campaign path never calls Astra: no `authority_status`, no `fetch_campaign`, no `submit_campaign`, no `send_vault_copy`.
- Journals written before F14-e read exactly as before (the new field is absent ⇒ `false`).

## Review Focus

1. A legacy `astra-signer` hors-campagne journal in a domain **with** an origin keeps today's behaviour (reads Astra, `DomainConflict` if Astra does not hold the anchor) — Task 1 test `legacy_ca_pq_with_origin_still_awaits_confirmation`.
2. The legacy CA-PQ file is not removed before the vault is applied, for a no-campaign journal — Task 1 test `legacy_file_stays_until_applied_without_campaign`.
3. A no-campaign rotation whose gateway already names a next CA-PQ or CA TLS anchor is refused before any signature — Task 2 test `open_without_campaign_refuses_a_gateway_in_transition`.
4. A domain with no credential document can still rotate without campaign — Task 2 test `open_without_campaign_without_credentials`.
5. The no-campaign row never shows when the relay could not be read (`relayNamesOrigin === null`) — Task 4 test.

---

### Task 1: the no-campaign journal and its resume (astra-operator)

**Files:**
- Modify: `crates/astra-operator/src/rotation_journal.rs` (struct `RotationJournal` ~l.196, `validate`, `awaits_confirmation` ~l.270, `ensure_ca_pq_may_run` ~l.409, `apply_local` ~l.483, `adopt_legacy` ~l.744)
- Modify: `crates/astra-operator/src/operations/rotation.rs` (`advance` ~l.762)
- Test: the existing test modules of both files (`rotation_journal.rs` `mod tests`, `operations/rotation/tests.rs`)

**Interfaces:**
- Produces: `RotationJournal.without_campaign: bool` — `#[serde(default, skip_serializing_if = "std::ops::Not::not")]`, doc: no campaign exists; the operator's gesture stands for the acceptance; resumes never read Astra.
- Produces: `RotationJournal::without_deposit_unapplied(&self) -> bool` = `self.deposit.is_none() && self.stage == JournalStage::Accepted`.
- Produces: `awaits_confirmation()` = `without_deposit_unapplied() && !self.without_campaign`.
- Produces: `advance` returns `Ok(ResumeStep::Finished)` with the journal cleared when a `without_campaign` journal reaches `ResumeStep::SendVaultCopy` (no `Installed` written, no `send_vault_copy` call).

- [ ] **Step 1: Write the failing tests**
  - `without_campaign_journal_round_trips_and_old_journals_read_false`: a journal saved with `without_campaign: true` loads back equal; a JSON journal with no `without_campaign` key loads with `false`; a journal with `false` serializes with no `without_campaign` key.
  - `validate_refuses_without_campaign_with_a_deposit_or_ca_tls_or_signed`: `without_campaign: true` with `deposit: Some(..)`, or `kind: CaTls`, or `stage: Signed` is refused by `save`/`load`.
  - `without_campaign_accepted_applies_without_reading_astra`: `next_step` of an `Accepted`, `deposit: None`, `without_campaign: true` journal with `facts.authority: None` is `ResumeStep::ApplyLocal`.
  - `advance_without_campaign_finishes_without_the_copy`: with a fake `RotationRemote` whose `authority_status`, `send_vault_copy`, `submit_campaign`, `fetch_campaign` panic, `advance` of an `Accepted` no-campaign journal whose gateway names the next anchor after install returns `Finished`, the journal file is gone, and `install_ca_transition` was called once.
  - `adopt_legacy_without_origin_marks_without_campaign`: a legacy CA-PQ file beside a vault whose relay in place has `astra_authority_url: None` is adopted with `without_campaign: true`.
  - `legacy_ca_pq_with_origin_still_awaits_confirmation`: same with an origin in the relay → `without_campaign: false`, `awaits_confirmation()` true (Review Focus 1).
  - `legacy_file_stays_until_applied_without_campaign`: after `adopt_legacy` (no origin), a second `adopt_legacy` still leaves the legacy file; after `apply_local`, the legacy file is removed (Review Focus 2).

- [ ] **Step 2: Run them, see them fail**
Run: `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator rotation`
Expected: compile errors on `without_campaign`, then FAIL.

- [ ] **Step 3: Implement**
  - Field, predicates and `validate` rules as in Interfaces / Step 1.
  - `apply_local`: remove the legacy file when `journal.without_deposit_unapplied()` held before applying (was `awaits_confirmation`).
  - `adopt_legacy`: read the relay in place with `handoff::load(&handoff::path_beside(vault_path))`; set `adopted.without_campaign = relay.astra_authority_url.is_none()` before saving; the "older file remains to go" removal runs only when `!in_place.without_deposit_unapplied()`.
  - `ensure_ca_pq_may_run`: its exception keys on `without_deposit_unapplied()`.
  - `advance`: the `SendVaultCopy` arm, for `journal.without_campaign`, clears the journal and returns `Finished`.
  - Every other `awaits_confirmation` / `deposit.is_none()` use: read it and keep or switch with a one-line comment saying why.

- [ ] **Step 4: Run the tests, see them pass**
Run: `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator`
Expected: PASS, including every pre-existing rotation test unchanged.

- [ ] **Step 5: fmt, clippy, commit** — `feat(astra-operator): a rotation journal without campaign resumes without Astra (F14-e)`

---

### Task 2: open and sign a CA-PQ rotation without campaign (astra-operator)

**Files:**
- Modify: `crates/astra-operator/src/operations/rotation.rs`
- Test: `crates/astra-operator/src/operations/rotation/tests.rs`

**Interfaces:**
- Consumes: Task 1's `without_campaign` field.
- Produces: `RotationRemote::gateway_identity(&self) -> Result<GatewayIdentityRead>` (Tunnel impl delegates to `Tunnel::gateway_identity`); every test fake implements it.
- Produces: `OpenRefusal::OriginRecorded` — `#[error("le relais nomme une origine Astra : ce remplacement passe par une campagne. Rien n'a été signé.")]`; `OpenRefusal::CaPqToFinish` — `#[error("la rotation CA-PQ précédente reste à terminer. Rien n'a été signé.")]`.
- Produces: `ValidatedKeys::ensure_domain_readable_without_campaign(&self, vault_path: &Path) -> Result<()>` — what `open_without_campaign` would refuse of the files, before any key (relay readable, origin absent ⇒ else `OriginRecorded`, identity readable, credential document verified when present).
- Produces: `pub fn open_without_campaign(remote: &dyn RotationRemote, vault_path: &Path, keys: ValidatedKeys, terms: &RotationTerms, now: u64) -> Result<OpenedWithoutCampaign>`.
- Produces: `pub struct OpenedWithoutCampaign` with `pub fn manifest(&self) -> &AstraManifest` (a `CaRotation` manifest, `campaign: None`, `next_anchor_fingerprint: None`) and `pub fn sign_and_journal(self, vault_path: &Path, now: u64) -> Result<RotationJournal>`.

`open_without_campaign` checks, in this order, before returning (none calls Astra): `ensure_nothing_outstanding`; `ensure_same_vault`; two keys; `Schedule::of(RotationKind::CaPq, ..)`; relay origin absent (`OriginRecorded`); credential document verified and `ensure_keys_may_approve` **when present**; `ensure_no_window_open`; vault keeps no outgoing CA-PQ (`retained_outgoing_ca_pq_public().is_some()` ⇒ `CaPqToFinish`); `remote.gateway_identity()`: `next_ca_fingerprint` or `next_client_tls_ca_fingerprint` present ⇒ `RotationInFlight`; `ca_pq_fingerprint != current_ca.authority_fingerprint()` ⇒ `AnchorsDisagree`.

`sign_and_journal`: `ensure_none_in_flight`, `ensure_same_vault`, `signing::rotate_ca_pq(&mut vault, &[&o0, &o1], &identity, registry.as_ref(), window, now)`, relay `ca_epoch` and `adopt` as `OpenedRotation::sign_and_journal` does; journal `stage: Accepted`, `deposit: None`, `without_campaign: true`, `next: Some(NextLocal{ vault, credentials: rotated.bindings when a registry was present else None, handoff })`, `campaign_expires_at: now`, `signed_at: now`; saved with `rotation_journal::save`. Share code with the campaign path where it does not weaken it; `LocalDomain::read` itself keeps requiring the document and the origin.

- [ ] **Step 1: Write the failing tests**
  - `open_without_campaign_signs_and_journals_without_astra`: fake remote whose Astra methods panic; gateway identity names the vault's CA-PQ, no next; open + sign returns a journal `Accepted`, `without_campaign`, `deposit: None`, `next_anchor_fingerprint` equal to the transition's; the vault on disk is unchanged.
  - `open_without_campaign_refuses_an_origin`: relay with `astra_authority_url: Some(..)` → `OpenRefusal::OriginRecorded` (downcast), and `ensure_domain_readable_without_campaign` refuses it too.
  - `open_without_campaign_refuses_a_gateway_in_transition`: `next_ca_fingerprint: Some` → `RotationInFlight`; `next_client_tls_ca_fingerprint: Some` → `RotationInFlight` (Review Focus 3).
  - `open_without_campaign_refuses_another_anchor`: gateway `ca_pq_fingerprint` differs → `AnchorsDisagree`.
  - `open_without_campaign_refuses_a_kept_outgoing_ca_pq`: → `CaPqToFinish`.
  - `open_without_campaign_without_credentials`: no credential document beside the vault → signs; journal `next.credentials` is `None` (Review Focus 4).
  - `open_without_campaign_with_credentials_resigns_them`: a document present → `next.credentials` is `Some`, and a key marked lost there → `KeyNotApprovable`.

- [ ] **Step 2: Run, see them fail** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator rotation`
- [ ] **Step 3: Implement** as in Interfaces.
- [ ] **Step 4: Run, see them pass** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-operator`; then `scripts/wsl-cargo check -p orion` (the new trait method must not break Orion's fakes; fix them in this task if it does).
- [ ] **Step 5: fmt, clippy (astra-operator, orion), commit** — `feat(astra-operator): open and sign a CA-PQ rotation without campaign (F14-e)`

---

### Task 3: the Orion gesture (Tauri)

**Files:**
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`RotationGesture` ~l.414, `begin_rotation` ~l.960 passes the artifacts sink)
- Modify: `apps/orion/src-tauri/src/operator/ceremony/rotation.rs`
- Modify: `apps/orion/src-tauri/src/operator/rotations.rs` (`Local`, `RotationsOverview`, `JournalView`)
- Test: `apps/orion/src-tauri/src/operator/ceremony/rotation/tests.rs`, the tests of `operator/rotations.rs`

**Interfaces:**
- Consumes: Task 2's `open_without_campaign`, `OpenedWithoutCampaign`, `ensure_domain_readable_without_campaign`, `OpenRefusal::{OriginRecorded, CaPqToFinish}`; Task 1's `without_campaign`.
- Produces: `RotationGesture::ReplaceCaPqWithoutCampaign` (wire `{"gesture":"replace_ca_pq_without_campaign"}`), operation `OperationKind::RotateAnchor`.
- Produces: `RotationsOverview.relay_names_origin: Option<bool>` (camelCase `relayNamesOrigin`; `None` when the relay cannot be read) and `JournalView.without_campaign: bool` (`withoutCampaign`).
- Produces: artifact `ca-pq-transition.json` (`OperatorArtifact`, `ArtifactEncoding::Text`, the transition's JSON as `documents::write` would write it, `fingerprint: None`), deposited when a carry of a `without_campaign` journal stops before `Finished` (error or stop step), from the new gesture and from `Resume`.

Ceremony flow of the new gesture (`RotationRun::replace_without_campaign`): `ensure_nothing_outstanding` → `ValidatedKeys::new` → `ensure_domain_readable_without_campaign` (refuse `ManifestMismatch` for `OriginRecorded`, `HandoffMismatch` otherwise) → `validate_keys` → `await_terms(RotationKind::CaPq)` → `Verifying`, `open_without_campaign` (map `OriginRecorded` → `Refusal::ManifestMismatch`, `CaPqToFinish` → `Refusal::RotationInFlight`, others as `refusal_of_open`), manifest shown → `Signing`, `sign_and_journal`, next anchor shown → `carry`. No `approve_campaign`, no chain step, `operation_id` stays `None`. `is_deposited` is `false` for a `without_campaign` journal (the screen never says « Déposée »).

- [ ] **Step 1: Write the failing tests**
  - `replace_without_campaign_runs_two_keys_and_poses_the_transition`: the ceremony with a fake remote (Astra methods panic) asks two `ValidateKey` keys and no `ApproveCampaign`, ends `Done`, the journal is gone, the vault on disk is the rotated one, `install_ca_transition` was called once.
  - `replace_without_campaign_refuses_an_origin_before_any_key`: origin in the relay → failed with `Refusal::ManifestMismatch`, no key asked.
  - `replace_without_campaign_offers_the_transition_when_the_gateway_fails`: install errors (unreachable) → failed, journal kept at `Applied`, artifacts hold one `ca-pq-transition.json` whose JSON parses as the journal's `CaTransition`.
  - `resume_without_campaign_never_reads_astra`: an `Accepted` no-campaign journal resumed with Astra methods panicking → `Done`.
  - `overview_says_whether_the_relay_names_an_origin`: `relay_names_origin` is `Some(false)` without origin, `Some(true)` with one, `None` with an unreadable relay; `JournalView.without_campaign` mirrors the journal.
  - The wire test of `RotationGesture` covers `replace_ca_pq_without_campaign`.

- [ ] **Step 2: Run, see them fail** — `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p orion operator::`
- [ ] **Step 3: Implement** as in Interfaces.
- [ ] **Step 4: Run, see them pass** — same command, all `operator::` tests.
- [ ] **Step 5: fmt, clippy (orion), commit** — `feat(orion): replace the CA-PQ without campaign, in the rotation ceremony (F14-e)`

---

### Task 4: the row in *Rotations* (Orion TS)

**Files:**
- Modify: `apps/orion/src/types.ts` (`RotationGesture` ~l.992, `RotationsOverview` ~l.1153, `RotationJournalView` ~l.1141)
- Modify: `apps/orion/src/views/astra/rotationRows.ts`, `RotationSteps.tsx`, `RotationsPanel.tsx`, `rotationFixtures.ts`
- Test: `apps/orion/src/views/astra/rotationRows.test.ts`, `RotationSteps.test.tsx`, `RotationsPanel.test.tsx` (the existing files)

**Interfaces:**
- Consumes: Task 3's wire names `replace_ca_pq_without_campaign`, `relayNamesOrigin`, `withoutCampaign`, artifact `ca-pq-transition.json`.
- Produces: `RotationAction` gains `'replace_ca_pq_without_campaign'`; title « Remplacer la CA-PQ sans campagne », button « Remplacer ».

Rules:
- `rotationRows`: when `o.relayNamesOrigin === false`, the row `replace_ca_pq_without_campaign` stands **in place of** `replace_ca_pq`; otherwise (`true` or `null`) it is absent and `replace_ca_pq` is unchanged.
- Its `disabledReason`: `replaceBlock` minus the `AUTHORITY_UNREAD` line (Astra is never read for it).
- `prerequisites(o, 'replace_ca_pq_without_campaign')`: tunnel, « Administrateur du tunnel », vault, keys, domain — no « Service Astra », no vault copy.
- A `withoutCampaign` journal resumes on the gateway alone (`resumesOnTheGatewayAlone` true for it).
- `RotationSteps`: gesture mapping and start label « Continuer »; it reads no `pending` before starting (`opensCampaign` false).
- `RotationsPanel`: for the chosen row, the warning above the start button, verbatim: « Aucune autorité ne vérifie ce remplacement : le coffre avance sur votre seul geste. À réserver à un domaine sans Astra. » The CA-PQ expiring-workstation warnings show for it as for `replace_ca_pq`.
- The rotation ceremony, once ended, shows `ArtifactDownloads` (already used by `AstraView`), so `ca-pq-transition.json` can be saved.

- [ ] **Step 1: Write the failing tests**
  - rows: `relayNamesOrigin: false` → the no-campaign row present, `replace_ca_pq` absent; `true` → the reverse; `null` → no no-campaign row (Review Focus 5).
  - rows: `caPqOverlap: null` does not disable the no-campaign row; `retainedCaPqNotAfter` set disables it with `PQ_KEPT`.
  - prerequisites: the list for the new action has no « Service Astra » line.
  - panel: the warning sentence is shown for the new row and not for `replace_ca_pq`.
  - steps: starting the new row calls `beginRotationCeremony({ gesture: 'replace_ca_pq_without_campaign' })` without reading `pending`.
- [ ] **Step 2: Run, see them fail** — `cd apps/orion && npx vitest run src/views/astra/rotationRows.test.ts src/views/astra/RotationSteps.test.tsx src/views/astra/RotationsPanel.test.tsx`
- [ ] **Step 3: Implement** as in the rules.
- [ ] **Step 4: Run, see them pass** — same, plus `npx tsc --noEmit` and `npx vitest run src/views/astra`.
- [ ] **Step 5: Commit** — `feat(orion): « Remplacer la CA-PQ sans campagne » in Rotations (F14-e)`

---

### Task 5: documentation and ROADMAP

**Files:**
- Modify: `docs/RENOUVELLEMENT-CERTIFICATS.md` (the CA-PQ section ~l.225-262; « Le recours en ligne de commande » ~l.1452)
- Modify: `docs/DEPLOIEMENT-ASTRA.md` (~l.300)
- Modify: `docs/superpowers/specs/2026-11-04-f14-lot5b-rotations-design.md` (the limit ~l.606: one amendment line dated 15 novembre 2026)
- Modify: `docs/testing/MANUAL-TESTING.md` (new section « L. F14-e », numbered after the last step)
- Modify: `docs/ROADMAP.md` (l.137 F14 row; l.155 F14-e row; l.163 F14-g row)

Content (French):
- RENOUVELLEMENT: for a domain with no Astra origin, « Remplacer la CA-PQ sans campagne… » in *Rotations* replaces `astra-signer rotate-ca-pq` hors campagne: two keys, the vault moves on the operator's gesture, Orion poses the transition on the gateway through the tunnel, `ca-pq-transition.json` is offered while the pose has not landed (`heliosd install-ca-transition` stays the manual path). The limit says the successor is named, and that the exception to « le coffre ne bouge qu'après l'acceptation » holds only without origin.
- MANUAL-TESTING « L. F14-e »: (1) domain without origin: the row replaces « Remplacer la CA-PQ », warning shown; (2) full run, the gateway names the new anchor, the vault keeps the outgoing CA-PQ until « Terminer la rotation CA-PQ »; (3) tunnel cut after signing: failure, file offered, « Reprendre » finishes without Astra; (4) domain with origin: the row is absent; (5) a legacy `astra-signer rotate-ca-pq` hors-campagne journal left interrupted in a domain without origin: « Reprendre » finishes it.
- ROADMAP: F14-g reads « fusionné dans `main` le 14 novembre 2026 (Helios 3.4.0, Orion 4.3.0) » in the F14 row and the F14-g row (and « Au 14 novembre 2026, `main` est à Helios 3.4.0 / Orion 4.3.0 »); F14-e reads « Levé par F14-e, livré sur la branche `feat/f14-e-ca-pq-sans-campagne`, pas encore fusionné dans `main` », with its one-line summary and the spec path; its status column « Code : **oui** ; validation : **non** (cible) ».

- [ ] **Step 1: Edit the docs.**
- [ ] **Step 2: Check** — `grep -n "F14-e\|sans campagne" docs/ROADMAP.md docs/RENOUVELLEMENT-CERTIFICATS.md docs/testing/MANUAL-TESTING.md` shows the new lines; no reference to a CLI the user must keep for this case.
- [ ] **Step 3: Commit** — `docs: the CA-PQ replaced without a campaign in Orion, and F14-g read as merged (F14-e)`
