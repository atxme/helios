# F14 lot 7 — retrait d'`astra-signer` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove `tools/astra-signer` and `helios enroll document`, after giving Orion an offline « Reprendre » that signs the first administrator's document from one file printed by `heliosd export-enrolment`.

**Architecture:** One envelope type `EnrollmentExport` in `aether::key_negotiation::enrollment` (the one crate both `heliosd` and `orion-core` already use). `heliosd export-enrolment` builds it from local files with a pure function. `orion-core` turns it into the same `(GatewayMaterial, Admission)` the online read produces. Orion's resume uses that pair when no gateway is connected. Then the retired code goes, every user-facing pointer to it is rewritten, and a Python guard keeps it out.

**Tech Stack:** Rust (serde, anyhow, clap), Tauri 2, React/TypeScript (vitest), Python unittest, French docs.

**Spec:** `docs/superpowers/specs/2026-11-15-f14-lot7-retrait-astra-signer-design.md`

## Global Constraints

- Worktree `/home/christophe/helios-wt/f14-lot7`, branch `feat/f14-lot7-retrait-astra-signer`; never work in `~/helios`.
- Build/test only through `scripts/wsl-cargo` with `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2`; never set `CARGO_TARGET_DIR`, `HELIOS_WSL_BUILD_OVER_BUDGET`, never run `clean-wsl-targets`.
- No TODO markers. Code, comments, logs in English; docs and Orion UI text in French; `heliosd` messages in English.
- No secret (PIN, `Opened`, private key, vault bytes) in the WebView or logs. The export file is public.
- Never edit versions by hand. Never touch `docs/audits`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Export format value, verbatim: `helios-enrolment-export-v1`. Command, verbatim: `heliosd export-enrolment --public-key <clé>`.
- Unreadable or foreign export, Orion message, verbatim: `Ce fichier n'est pas un export d'enrôlement de `heliosd export-enrolment`.`
- Resume dialog hint, verbatim: `Sans tunnel : le fichier de `heliosd export-enrolment`.`
- Stop sentence, verbatim: `Domaine en désaccord. Intervention manuelle requise.`
- The constant `helios-astra-signer-request-v5` (aether `ml_dsa.rs`, `status/mod.rs`) never changes.
- `heliosd install-*` commands stay. Reading journals an old `astra-signer` left stays (comments about them stay, in the past tense).
- Orion tests in `orion-core` need `--features certificate-signing`.

## Review Focus

1. An export taken on the gateway **before** `heliosd peer add` (peer absent) → `heliosd` refuses with "admit it first"; never an empty admission. (Task 2 test.)
2. A UTF-8 BOM or UTF-16 file saved by Windows Notepad → decoded like `.helios-request` (BOM stripped); UTF-16 handled by the WebView's `readFileText`, as for the other files. (Task 1 test for BOM.)
3. An export of the right gateway for **another** peer (operator exported the wrong key) → refused before any key, by name. (Task 4 test.)
4. A tunnel up **and** an export chosen → the gateway is read, the file ignored, the online path unchanged. (Task 4 test.)
5. An export whose trust block names another domain or another `CA-PQ` than the vault → refused before any key. (Task 4 test.)

---

### Task 1: `EnrollmentExport` envelope (aether)

**Files:**
- Modify: `crates/aether/src/key_negotiation/enrollment.rs` (beside `InvitationFile`/`RequestFile`)
- Test: `crates/aether/src/key_negotiation/enrollment/tests.rs`

**Interfaces:**
- Produces:
  - `pub const ENROLMENT_EXPORT_FILE_FORMAT: &str = "helios-enrolment-export-v1";`
  - `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)] #[serde(deny_unknown_fields)] pub struct EnrollmentExport { pub server_name: String, pub gateway_ca_der: String /* base64 DER */, pub gateway_pq_certificate: String /* base64 of the PQ leaf JSON, as /api/key-negotiation */, pub pq_certificate_sha256: String, pub wireguard_public_key: String, pub negotiation_port: Option<u16>, pub gateway_wg_address: String, pub peer_public_key: String, pub address: String, #[serde(default)] pub address_v6: Option<String>, pub trust: serde_json::Value }`
  - `pub fn encode_enrolment_export_file(export: &EnrollmentExport) -> String` — envelope `{"format": ENROLMENT_EXPORT_FILE_FORMAT, "export": {…}}`, envelope struct private and `deny_unknown_fields`, like `InvitationFile`.
  - `pub fn decode_enrolment_export_file(text: &str) -> Result<EnrollmentExport, EnrollmentError>` — strips the BOM, `EnrollmentError::Format("not an enrolment export")` for bad JSON, wrong `format`, unknown field, or `trust` that is not a JSON object.

- [ ] **Step 1: Write the failing tests** — `enrolment_export_round_trips_exactly` (encode then decode equals the input, with and without `address_v6`); `enrolment_export_refuses_another_format` (`format` = `helios-enrollment-request`); `enrolment_export_refuses_unknown_fields` (extra key in `export`, and in the envelope); `enrolment_export_refuses_a_trust_that_is_not_an_object` (`"trust": null`); `enrolment_export_accepts_a_leading_bom`.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether --all-features enrolment_export` — expect FAIL (not defined).
- [ ] **Step 3: Implement** the items above.
- [ ] **Step 4: Run** the same command — expect PASS; also `scripts/wsl-cargo test -p aether --lib` (without the signing feature) passes.
- [ ] **Step 5: Commit** `feat(aether): enrolment export envelope`.

### Task 2: `material_from_export` (orion-core)

**Files:**
- Modify: `crates/orion-core/src/gateway_admin.rs`
- Modify: `crates/orion-core/src/enrollment_draft.rs:78-82` (message: `astra-signer init` → « Créer le domaine » dans Orion)
- Modify: `crates/orion-core/src/config.rs:229` and `crates/orion-core/src/config/tests.rs:151` (`show-trust-enrolment` → `export-enrolment`)
- Test: the `gateway_admin` test module

**Interfaces:**
- Consumes: Task 1 `EnrollmentExport`.
- Produces: `pub fn material_from_export(export: &EnrollmentExport) -> Result<(GatewayMaterial, Admission), GatewayAdminError>`:
  - `GatewayMaterial` fields copied from the export (`negotiation_port` ← `negotiation_port`);
  - `Admission { address, address_v6 (trimmed, empty → None, as online), heliosd_url: heliosd_url(&export.gateway_wg_address), trust: Some(serde_json::from_value::<TrustMaterial>(export.trust.clone()) → GatewayAdminError::Invalid("le bloc de confiance illisible") on error) }`;
  - the online consistency check of `negotiate` is **not** repeated here (no network view offline): Orion checks the key against the invitation pin (Task 4).

- [ ] **Step 1: Write the failing tests** — `material_from_export_matches_the_online_shape` (an export built from the same values as an online fixture gives equal `GatewayMaterial` and `Admission`, `heliosd_url` = `http://100.64.0.1:<API_PORT>` for `gateway_wg_address = "100.64.0.1/24"`); `material_from_export_refuses_an_unreadable_trust_block`; `material_from_export_drops_an_empty_ipv6`.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion-core --features certificate-signing material_from_export` — FAIL.
- [ ] **Step 3: Implement**, and update the two messages: `enrollment_draft.rs` « cette gateway n'a pas de domaine de confiance : créer le domaine dans Orion (Astra › Coffre et clés, « Créer le domaine »), puis `heliosd init-trust-domain`. … » (keep the rest of the sentence); `config.rs` « … Le réimprimer avec `heliosd export-enrolment --public-key <clé>` » and its test.
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion-core --features certificate-signing` — PASS.
- [ ] **Step 5: Commit** `feat(orion-core): read the gateway material from an enrolment export`.

### Task 3: `heliosd export-enrolment` replaces `show-trust-enrolment`

**Files:**
- Modify: `crates/heliosd/src/commands/trust.rs` (remove `show_trust_enrolment`; add the export), `crates/heliosd/src/main.rs:340-355, 631` (subcommand), `crates/heliosd/src/main.rs:141-170` (help texts that name `astra-signer`: point to Orion, Astra › Coffre et clés / « Amorcer la gateway… »), `crates/heliosd/src/main.rs:321` (`install-astra-credentials` help: the document Orion keeps beside the vault).
- Test: `crates/heliosd/src/commands/trust.rs` test module (or its existing tests file).

**Interfaces:**
- Consumes: Task 1; `crate::certificates::views::enrolment_view`; `aether::config::NetworkConfig` (`load()`, `peers`, `wg_address`, `wg_private_key`); `aether::wg::public_from_private`.
- Produces:
  - `pub(crate) fn enrolment_export(network: &NetworkConfig, certificate_der: &[u8], pq_certificate_json: &[u8], registry: &CertificateRegistry, public_key: &str) -> anyhow::Result<EnrollmentExport>` — pure, no file access;
  - `pub(crate) fn export_enrolment(public_key: &str) -> anyhow::Result<()>` — reads `NetworkConfig::load()`, the files at `key_negotiation::CERTIFICATE_PATH` / `PQ_CERTIFICATE_PATH` (make them `pub(crate)` if needed), the registry like `show_trust_enrolment` did, prints `encode_enrolment_export_file`.
  - CLI: `ExportEnrolment { #[arg(long)] public_key: String }`, kebab name `export-enrolment`; `ShowTrustEnrolment` removed.
- Rules, in order: key parse (`WireGuardKey::parse`) → "invalid WireGuard public key"; peer absent from `network.peers` → "no such peer in network.toml — admit it first, with `heliosd peer add`"; no registry → the same message `show_trust_enrolment` gave; peer absent from the registry → its message; PQ leaf unreadable → "the gateway PQ certificate on disk is unreadable"; `server_name` = leaf `subject`, `pq_certificate_sha256` = leaf fingerprint, `wireguard_public_key` = leaf `wireguard_public_key`; **if** `wg_private_key` is non-empty and `public_from_private` succeeds and differs from the leaf's key → refuse "the negotiation certificate is bound to another WireGuard identity — run `heliosd init-key-negotiation --rotate`"; `negotiation_port` = `network.key_negotiation_port`; `trust` = `serde_json::to_value(enrolment_view(..))`.
- Missing negotiation files → "this gateway has no key-negotiation material — run `heliosd init-key-negotiation`".

- [ ] **Step 1: Write the failing tests** — `export_carries_what_the_online_routes_serve` (fixture network + leaf + registry: every field equals what `key_negotiation_get`/network view/`enrolment_view` give for the same state); `export_refuses_a_peer_not_in_network_toml`; `export_refuses_without_a_trust_domain`; `export_refuses_an_unreadable_key`; `export_refuses_a_leaf_bound_to_another_identity` (clear private key whose public differs); `export_ignores_a_sealed_identity` (empty private key → no comparison, export produced); `an_export_is_one_orion_reads` (dev-dep `orion-core`: `decode_enrolment_export_file(encode(..))` then `orion_core::gateway_admin::material_from_export` succeeds and its `trust` validates — like the existing `certificates.rs` interop test).
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p heliosd --all-features export` — FAIL.
- [ ] **Step 3: Implement**; remove `show_trust_enrolment`, `ShowTrustEnrolment`, their tests and every reference (`trust.rs:~270-285` comments).
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p heliosd --all-features` and `scripts/wsl-cargo clippy -p heliosd --all-targets --all-features -- -D warnings` — PASS.
- [ ] **Step 5: Commit** `feat(heliosd): export-enrolment replaces show-trust-enrolment`.

### Task 4: Orion resume from an export (backend)

**Files:**
- Modify: `apps/orion/src-tauri/src/operator/mod.rs:79-115` (`EnrollmentGesture::Resume`)
- Modify: `apps/orion/src-tauri/src/operator/ceremony.rs` (`run_enrollment_with`, `Resume`, `prepare_resumption:833-922`, `Resuming`, `draft_delivery:1219`, `hand_over_leaves:~1160-1190`)
- Test: `apps/orion/src-tauri/src/operator/ceremony/tests.rs`

**Interfaces:**
- Consumes: Task 1 decode; Task 2 `material_from_export`; existing `GatewayPin::check`, `orion_core::enrollment_draft::verify_pinned_gateway_certificate`, `build_draft`.
- Produces: `EnrollmentGesture::Resume { …, #[serde(default)] enrolment_export: Option<String> }` (snake_case on the wire: `enrolment_export`).
- Behaviour:
  - gateway connected → exactly today's path; the export is ignored;
  - no gateway and an export → in `prepare_resumption`, before any key: decode (failure → `Refusal::HandoffMismatch`, message verbatim from Global Constraints); `material_from_export`; `pin.check(&material)`; `export.peer_public_key` parses and equals `accepted.request.client_wg_public_key`, else `HandoffMismatch` « cet export nomme un autre poste que la demande acceptée »; trust `ca_pq_public_key` equals `vault.ca_pq_public_key` (trimmed) and trust `trust_domain_id` equals `vault.trust_domain_id` (hex, `TrustDomainId`), else `HandoffMismatch` « cet export vient d'un autre domaine que ce coffre »; `orion_core::config::verify_pinned_gateway_certificate(&leaf, &material.server_name, &material.wireguard_public_key, Some(&trust), now)` (leaf decoded from `gateway_pq_certificate`), and `pq_certificate_sha256` equal to the decoded leaf's fingerprint, else `HandoffMismatch`; then `admitted = true` (the existing `admit: false` path) and the `(material, admission)` pair kept in `Resuming` for `draft_delivery`, which uses it instead of reading the gateway (same `build_draft`);
  - no gateway and no export → today's `stop_with_leaves`.
  - `admission.txt` becomes three lines: the `heliosd peer add …` line; `heliosd export-enrolment --public-key <client key> > <requested_name>.enrolment.json`; « Ajouter --admin à la première ligne pour le premier administrateur, puis « Reprendre » avec ce fichier. » (`<requested_name>` passed through the existing `shell_word`).

- [ ] **Step 1: Write the failing tests** — `resume_offline_signs_the_same_document_as_online` (same fixture, export built from the fixture gateway: the signed document's draft equals the online one); `resume_offline_refuses_an_export_of_another_gateway` (no key asked: the ceremony never reaches the open step); `resume_offline_refuses_an_export_of_another_peer`; `resume_offline_refuses_an_export_of_another_domain`; `resume_offline_refuses_a_gateway_leaf_that_does_not_verify`; `resume_offline_refuses_an_unreadable_export` (message verbatim); `resume_online_ignores_the_export` (reader called, export garbage, success); `resume_without_gateway_or_export_stops_with_the_leaves` (unchanged); `admission_artifact_names_the_export_command`; the `EnrollmentGesture` deserialization test gains `enrolment_export`.
- [ ] **Step 2: Run** `scripts/wsl-cargo test -p orion --all-features resume` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/wsl-cargo test -p orion --all-features` and clippy on `orion` — PASS.
- [ ] **Step 5: Commit** `feat(orion): resume an enrolment from heliosd export-enrolment`.

### Task 5: Orion resume from an export (screen)

**Files:**
- Modify: `apps/orion/src/types.ts:~975` (resume gesture), `apps/orion/src/views/astra/EnrollmentOperatorPanel.tsx:528-585` (`ResumeDialog`), its call site (~207, pass `connected`)
- Modify: `apps/orion/src/views/astra/DomainCreated.tsx:59-62` (« Amorcer la gateway, encore en ligne de commande : astra-signer … » → point to the « Amorcer la gateway… » button)
- Test: `apps/orion/src/views/astra/EnrollmentOperatorPanel.test.tsx`, `DomainCreated.test.tsx`

**Interfaces:**
- Consumes: Task 4 wire field `enrolment_export`.
- Behaviour: `ResumeDialog` gets `connected: boolean`. A file field « Export d'enrôlement de la gateway » (same `TextField type="file"` + `readFileText` + error `Alert` as the invite's leaf). Hint under it: connected → « Facultatif : la gateway connectée est lue. »; not connected → `Sans tunnel : le fichier de `heliosd export-enrolment`.` The submitted gesture carries `enrolment_export` only when a file was read. The submit button stays enabled without a file (today's stop-with-leaves path remains reachable).

- [ ] **Step 1: Write the failing tests** — not connected: hint verbatim shown, a chosen file's text sent as `enrolment_export`; no file: gesture has no `enrolment_export` key; connected: hint « Facultatif : la gateway connectée est lue. »; `DomainCreated` no longer contains `astra-signer`.
- [ ] **Step 2: Run** `npm run test:unit --prefix apps/orion -- EnrollmentOperatorPanel DomainCreated` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npm run test:unit --prefix apps/orion` and `npm run build --prefix apps/orion` — PASS.
- [ ] **Step 5: Commit** `feat(orion): choose an enrolment export when resuming without a tunnel`.

### Task 6: Remove `astra-signer` and `helios enroll document`

**Files:**
- Delete: `tools/astra-signer/` (whole directory)
- Delete: `tools/helios/src/enroll.rs`; modify `tools/helios/src/main.rs` (subcommand, the `show-trust-enrolment` mention at ~352), `tools/helios/src/profile.rs:17,76,248` (point to Orion's enrolment: Astra › Enrôlement), `tools/helios/src/tests.rs` if it covers `enroll`
- Modify: `Cargo.toml:34` (workspace member), `Cargo.lock` (let cargo rewrite it by building), `scripts/ci-plan.py:10`, `AGENTS.md:68` (drop `astra-signer` from the tooling list)

- [ ] **Step 1:** Delete and edit as listed. Search `grep -rn "astra-signer\|astra_signer\|enroll document\|EnrollDocument\|enroll::" --include=*.rs --include=*.toml --include=*.py .` (excluding `target`, `docs`) and fix every build reference.
- [ ] **Step 2: Run** `scripts/wsl-cargo build --workspace --all-features`, `scripts/wsl-cargo test -p helios --all-features`, `scripts/wsl-cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `python3 scripts/ci-plan.py --help` (or its unit tests if any) — PASS. `Cargo.lock` no longer lists `astra-signer`; note any dependency it alone pulled that left the lock.
- [ ] **Step 3: Commit** `chore(f14): remove astra-signer and helios enroll document`.

### Task 7: Rewrite the pointers, and guard them

**Files:**
- Modify (messages shown to a person): `crates/astra/src/commands/campaign.rs:48`, `commands/gateway_identity.rs:65,73`, `commands/revocation.rs:67,116`, `commands/issuer.rs:136,148`, `door/mod.rs:478`, `daemon.rs:510`, `renewal/mod.rs:128`, `crates/astra/src/main.rs:86`; `apps/orion/src/views/astra/rotationRows.ts:717-745` (stop sentence verbatim; drop the `offline` branch, keep the field), `apps/orion/src/types.ts:1152` and `apps/orion/src-tauri/src/operator/rotations.rs:455` (doc comments: past tense), `rotationRows.test.ts`; `scripts/deploy.sh`, `scripts/provision-client.sh`, `scripts/key-negotiation-setup.sh`, `scripts/target-bootstrap.sh:543-547`, `scripts/setup-dev.sh:78`, `deploy/astra/Dockerfile:7`, `deploy/astra/compose.yaml:9`.
- Create: `scripts/tests/test_retired_operator_tools.py`; modify `scripts/check.sh` (run it next to `test_gateway_hardening.py`).

**Interfaces:** replacement wording names Orion's place, e.g. « dans Orion : Astra › Approbations » (campaign approval), « Astra › Rotations » (rotations, delegation renewal), « Astra › Postes » (revocation), « Astra › Coffre et clés » (bindings, CA-TLS, domain), « Amorcer la gateway… » (bootstrap), « Astra › Enrôlement » (enrolment, with `heliosd export-enrolment` for the first administrator). Astra console messages keep their current language per file.

- [ ] **Step 1: Write the failing guard** — `test_retired_operator_tools.py` walks `crates`, `apps/orion/src`, `apps/orion/src-tauri/src`, `tools`, `scripts`, `deploy`, `web/src` (skip `node_modules`, `target`); for `*.rs, *.ts, *.tsx, *.sh, *.py, Dockerfile, *.yaml, *.yml`, it fails on any line containing `astra-signer` or `enroll document` that is not a comment (stripped line starting with `//`, `/*`, `*`, `#`), excluding test files (`tests.rs`, any path under a `tests/` directory, `*.test.ts`, `*.test.tsx`, `security_tests.rs`, `scripts/tests/`) and the literal `helios-astra-signer-request-v5`. Run `python3 -m unittest discover -s scripts/tests -p 'test_retired_operator_tools.py'` — FAIL, listing the lines above.
- [ ] **Step 2:** Rewrite each listed line. Comments that describe a legacy `astra-signer` file stay, in the past tense.
- [ ] **Step 3: Run** the guard (PASS), `scripts/wsl-cargo test -p astra --all-features` (its `tests/cli.rs` may assert old strings), `npm run test:unit --prefix apps/orion`, `bash -n` on each edited script — PASS.
- [ ] **Step 4: Commit** `chore(f14): point every message to Orion, and guard it`.

### Task 8: Operator docs

**Files:** `docs/security/OPERATOR-TOOLING.md`, `docs/RENOUVELLEMENT-CERTIFICATS.md`, `docs/DEPLOIEMENT-ASTRA.md`, `docs/testing/MANUAL-TESTING.md`

- [ ] **Step 1:** OPERATOR-TOOLING: remove « CLI transitoire »; add, in the enrolment section, the first administrator without a tunnel (invitation by leaf file, acceptance stops with `admission.txt`, `heliosd peer add … --admin` then `heliosd export-enrolment --public-key <clé> > <nom>.enrolment.json` on the gateway, « Reprendre » with the file; checks: same gateway as the invitation, same peer, same domain and `CA-PQ`); the limit of spec §4.2 « Ce que le fichier peut tromper »; update « Hors périmètre » and every « jusqu'au lot 7 ».
- [ ] **Step 2:** RENOUVELLEMENT and DEPLOIEMENT-ASTRA: each `astra-signer …` recipe becomes the Orion gesture (tab › button) or is removed when Orion already describes it; `heliosd install-*` examples stay with the source of the file (Orion, Astra console); the `recover` HTTPS transport paragraph (DEPLOIEMENT ~l.268-272) is removed.
- [ ] **Step 3:** MANUAL-TESTING: new section « N. Lot 7 » after « M. F14-f », steps continuing the numbering: first administrator without a tunnel (end to end, document imported, tunnel up); export of another gateway refused before any key; export of another peer refused before any key; `heliosd export-enrolment` before `peer add` refused; resume online unchanged with a file chosen. Rewrite earlier steps that launch `astra-signer` or `helios enroll document` to the Orion gesture.
- [ ] **Step 4: Verify** `grep -n "astra-signer\|enroll document\|show-trust-enrolment" <the four files>` returns only historical mentions (« retiré au lot 7 », legacy journals).
- [ ] **Step 5: Commit** `docs(f14): operator docs after astra-signer`.

### Task 9: Reference docs and ROADMAP

**Files:** `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md`, `docs/specification/ROTATION-CERTIFICATS.md`, `docs/specification/NEGOCIATION-DE-CLE-V5.md`, `docs/architecture/CRATE-REORGANIZATION.md`, `docs/architecture/overview.md`, `docs/testing/TESTING.md`, `docs/ROADMAP.md`, `docs/superpowers/specs/2026-10-27-orion-seul-client-design.md`

- [ ] **Step 1:** ADR-008, specs, architecture, TESTING: the operator tool is Orion; `astra-signer` is named only as retired at lot 7 (15 novembre 2026); `show-trust-enrolment` → `export-enrolment`. Normative statements keep their meaning: only the tool's name changes.
- [ ] **Step 2:** ROADMAP: F14 row — lot 7 delivered on branch `feat/f14-lot7-retrait-astra-signer`, not yet merged, `astra-signer` and `helios enroll document` removed, first administrator via `heliosd export-enrolment` (recipe MANUAL-TESTING « N. Lot 7 », design `docs/superpowers/specs/2026-11-15-f14-lot7-retrait-astra-signer-design.md`); remove « restent livrés, à titre transitoire, jusqu'au lot 7 » and the other « recours jusqu'au lot 7 »; F14-f row (l.156): « fusionné dans `main` le 15 novembre 2026 (Helios 3.5.0 / Orion 4.5.0) » instead of « livré sur la branche … pas encore fusionné ».
- [ ] **Step 3:** F14 spec: « Amendement du 15 novembre 2026 » under §7 lot 7 — the enrolment export and the offline resume, pointing to the lot 7 design.
- [ ] **Step 4: Verify** `grep -rn "jusqu'au lot 7" docs --include=*.md | grep -v audits | grep -v superpowers` returns nothing.
- [ ] **Step 5: Commit** `docs(f14): reference docs and roadmap after lot 7`.
