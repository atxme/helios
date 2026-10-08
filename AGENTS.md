# AGENTS.md

Repository-wide instructions for coding agents working on Helios.

## Purpose

Helios is a Linux WireGuard gateway; Orion is its Tauri desktop client; `aether` owns shared contracts. This file is a **map and guardrail**, not an architecture manual or project journal.

## Keep this file lean

This file is hot context for coding agents. Keep it short, current, and actionable.

When modifying `AGENTS.md`:

* Preserve the structure and concise style already used here.
* Prefer replacing or tightening an existing rule over appending another paragraph.
* Add only repository-wide facts an agent needs in most sessions.
* Do not add implementation history, incident narratives, review chronology, temporary status dumps, or long rationale.
* Put architecture rationale and protocol details in `docs/` and link them from here.
* Put subsystem-only instructions in a nested `AGENTS.md` close to that subtree instead of growing the root file.
* Delete or update obsolete instructions when behavior changes.
* Avoid duplicating information already obvious from code, `Cargo.toml`, package scripts, or an ADR.
* Aim to keep this root file below roughly 200 lines.

The same rule applies to `CLAUDE.md`: it must remain a thin adapter to this file, not a second copy.

## Source of truth

Use these sources deliberately:

1. Accepted ADRs: architectural intent and security decisions.
2. Current code/tests: implementation that actually exists.
3. Specifications: protocol/wire behavior and tracked incomplete work.
4. `docs/testing/TESTING.md`: what each environment proves.
5. `README.md`: overview only.

If code and an accepted ADR disagree, do not silently choose one. Identify the discrepancy, preserve fail-closed behavior, and resolve it explicitly. Do not infer current status from historical docs or this file.

## Read before changing

Read only the documents relevant to the touched area:

| Area                            | Required context                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------- |
| WireGuard, routing, firewall    | `docs/adr/ADR-001-WIREGUARD.md`, `docs/ARCHITECTURE.md`                                        |
| Publisher signatures / recovery | `docs/adr/ADR-002-SIGNATURES-PQ.md`                                                            |
| Application updates             | `docs/adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md`                                                |
| Delivery, admission, secrets    | `docs/adr/ADR-004-CHAINE-DE-LIVRAISON.md`                                                      |
| Pre-WireGuard key negotiation   | `docs/adr/ADR-005-NEGOCIATION-DE-CLE.md`, `docs/specification/NEGOCIATION-DE-CLE-V5.md`        |
| Secrets at rest                 | `docs/adr/ADR-006-SECRETS-AU-REPOS.md`                                                         |
| TPM update window               | `docs/adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md`                                                   |
| Astra / certificate lifecycle   | `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md`, `docs/specification/ROTATION-CERTIFICATS.md` |
| Testing / target limitations    | `docs/testing/TESTING.md`                                                                      |

`docs/README.md` is the documentation index.

## Workspace map

* `aether`: shared canonical config/state/protocol/crypto contracts.
* `astra` / `astra-channel`: certificate-authority coordinator and trust-domain state; private Astra–gateway veth channel (mTLS, ALPN, lifecycle API).
* `helios-firewall` / `helios-wireguard`: nftables and WireGuard data plane.
* `helios-provisioning` / `aether-key-negotiation`: admission, IPAM, ML-KEM orchestration and authenticated QUIC transport.
* `helios-api`: Axum REST/WebSocket API and embedded-web integration.
* `helios-update` / `aether-vault` / `helios-escrow` / `helios-tpm`: signed updates, encrypted secrets, operator-held recovery and TPM support.
* `orion-core` / `apps/orion`: portable client logic and Tauri/React desktop shell.
* `heliosd`: gateway CLI and orchestration.
* `web`: React/MUI gateway administration console.
* `astra-signer`, `helios`, `helios-publisher`, `helios-installer`, `xtask`: operator, publisher, installer and build tooling.
* `fuzz`: libFuzzer targets, **outside the workspace** (nightly only). The harnesses themselves live in `aether::fuzzing` and run with the ordinary test suite.

Do not duplicate logic already owned by one of these components.

## Change discipline

Before writing code, inspect the nearest analogous implementation, follow its naming/layering/error/state/test patterns, search for the canonical type/function, and read the relevant ADR/spec for security/protocol/persistence/trust changes.

While implementing:

* Prefer the smallest coherent change that fully solves the requested problem.
* Respect the requested scope: do not modify unrelated components, runtime
  configuration, packaging or deployment without explicit authorization.
* Do not move or rename files or directories unless the task requires it and the
  impact has been documented.
* Keep commits atomic and never commit generated artifacts, credentials or
  local environment files.
* Extend existing patterns instead of introducing parallel architecture.
* Do not add a dependency, framework, state store, crypto primitive or serialization format when an existing project mechanism fits.
* Do not perform unrelated refactors or formatting churn.
* Preserve backward compatibility only where the repository explicitly requires it; never silently weaken validation to make old data pass.
* Keep behavior explicit and fail closed at security boundaries.
* Make invalid states unrepresentable when practical; prefer typed validation over comments and conventions.
* Do not hide errors, silently downgrade behavior, or convert a required backend into a best-effort path.
* Add or update tests at the same abstraction level as the behavior being changed.
* Update the relevant ADR/spec/user-facing documentation when the contract changes.

For UI changes, matching the existing product is a requirement:

* Reuse adjacent components, spacing, typography, layout, interactions and wording before inventing new patterns.
* Gateway UI is React + MUI; no Tailwind/second UI framework and no CDN assets.
* Reuse theme tokens and semantic state helpers; avoid one-off styling.
* New screens/controls must look and behave like the surrounding Helios/Orion UI, not a standalone redesign.

## Security invariants

Detailed rationale belongs in the ADRs/specs.

### Gateway and data plane

* Gateway traffic is allowed only for `TunnelState::Up`.
* Engage the kill-switch before networking and keep it engaged on shutdown/failure.
* Outside explicit development mode, an unavailable real kernel/WireGuard backend is a startup error. Never fall back silently to simulation/dry-run.
* Build the complete nftables ruleset first, then apply filtering and NAT atomically. Never apply rules incrementally.
* Negotiated PSKs are installed on the data plane before they are announced and are never persisted to disk.
* Removal clears the data plane before forgetting state; do not leave orphaned PSKs.
* A static PSK is operator configuration and must not be treated as a negotiated transactional PSK.
* `network.toml` hot reload must preserve runtime-only secrets/state through the existing adoption path. Do not reconstruct runtime state from the persisted file alone.

### Key negotiation

* The served Helios negotiation protocol is v5. The v4 document is historical; do not reintroduce v4 behavior.
* `classic` is not a negotiable v5 protection mode.
* QUIC carries one negotiation transaction and is closed after commit. It is not a tunnel-liveness channel.
* Tunnel liveness comes from WireGuard data-plane handshake state, never from silence/activity on the control channel.
* Commit requires proof of a WireGuard handshake observed after candidate installation.
* Per-peer generations are ownership tokens: stale generations must not mutate newer state.
* Reserve generation + `preparing` atomically before candidate installation; preserve existing serialization of ownership/install/state transitions.
* Rollback must survive task/future cancellation; normal async return paths are insufficient cleanup.
* Post-commit `release` belongs inside the WireGuard tunnel, not on the public negotiation endpoint.
* Public negotiation errors must not expose admission state or policy details.

### Identity, trust and crypto

* Resolve authenticated peer identity from trusted gateway state established by mTLS; never use a client-controlled WireGuard key as the lookup authority.
* Where TLS/PQ generations are paired, verify the paired generation required by the protocol; do not accept a union that permits mixed generations.
* `aether::ml_dsa` is the single application entry point for ML-DSA-87 behavior owned there.
* `aether::random` is the single application entry point for protocol randomness owned there. Do not add direct RNG calls elsewhere without changing that architecture explicitly.
* ML-DSA-65 release signatures and ML-DSA-87 negotiation/PKI signatures are separate domains and are not interchangeable.
* Never log, serialize through read APIs, or expose private keys, PSKs, vault plaintext, publisher secrets or equivalent secret material.
* Publisher private material must never enter the repository or gateway.
* Gateway WireGuard identity is created on the gateway and sealed through the established TPM path; plaintext config keys are legacy compatibility, not the installation path.
* Escrow private-key material belongs on the operator side, not on the gateway it is intended to recover.

### API, admission and routing

* Administrative API mutations stay authenticated through the established tunnel/interface boundary and use the existing typed API paths.
* Never rebuild and persist `network.toml` from an API view that intentionally omits secrets.
* Admission must go through the shared provisioning/admission implementation.
* Do not claim the whole `100.64.0.0/10` CGNAT range for Helios routing; preserve the existing per-peer routing design.
* Treat `wan_iface` as the existing multi-uplink set semantics; firewall/NAT behavior must continue to work per resolved uplink.

## Incomplete work: no TODO markers

Do not introduce `TODO`, `FIXME`, `XXX`, `HACK`, `TBD`, `todo!()` or `unimplemented!()`.

For incomplete behavior: implement it; reject it explicitly with a named/typed/tested error; or document a known limitation in the owning module and relevant ADR/spec. Known limitations must state why and what unblocks them; user-visible ones must appear in UI/CLI.

## Code conventions

* Rust edition 2021; workspace MSRV is Rust 1.95.
* Code identifiers, comments, doc-comments, logs and test names are in English.
* Documentation under `docs/` is in French.
* Follow existing `thiserror`/`anyhow` boundaries instead of inventing a new error convention.
* Do not use panics or `unwrap`/`expect` as routine runtime error handling. Existing test/build-time uses are not a pattern for fallible production paths.
* Keep protocol/domain validation close to canonical types.
* Keep ownership of secrets and state explicit; do not duplicate caches/stores across layers without an architectural reason.

## Validation

Run the narrowest relevant checks while iterating, then broaden according to impact:

```sh
cargo fmt --check
scripts/wsl-cargo test -p <crate>
scripts/wsl-cargo clippy -p <crate> --all-targets --all-features -- -D warnings
npm run test:unit --prefix web
npm run test:unit --prefix apps/orion
```

Build disk budget (WSL): every Cargo build goes through `scripts/wsl-cargo` or a script that sources `scripts/cargo-budget.sh`. They share one cache, `~/.cache/helios-target`, and refuse to build once all Helios target directories together reach 65 GiB.

* Never open another target directory: no `CARGO_TARGET_DIR` override, no build inside a worktree's own `target/`.
* Exceeding or raising the budget (`HELIOS_WSL_BUILD_OVER_BUDGET=1`) happens only on the user's explicit request. On a refusal, stop and report; run `scripts/clean-wsl-targets` only with the user's agreement.

For cross-crate, security/protocol, release-tooling changes, or before claiming repository-wide regression safety, run `bash scripts/regression.sh`. It is the canonical full check.

Do not claim hardware validation from WSL2 or dry-run tests. Kernel networking, TPM, WireGuard-NT and installation behavior require the target environments described in `docs/testing/TESTING.md`.

If an expected check cannot run, report exactly what was not run and why. Do not silently treat an environment limitation as a passing test.

## Finish work cleanly

Before finishing: review the diff for scope creep/duplication/secret leakage; confirm existing architectural and visual patterns were followed; ensure tests cover behavior + failure paths; update docs/specs when contracts changed; state checks run and target-only validation still required.

For documentation-only work, verify that no source or test file changed and
report the exact validation commands that were run.
