# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ⚠ État : migration IKEv2 → WireGuard actée, non commencée

**`docs/ADR-001-WIREGUARD.md` acte l'abandon d'IKEv2/IPsec au profit de WireGuard.** Aucune ligne n'a encore bougé : **tout ce que décrit ce fichier est l'état réel du dépôt** (VICI, charon, XFRM, RFC 9370). Ne pas confondre les deux.

Règles pendant la migration :

- **Ne pas « corriger » le code vers WireGuard au coup par coup.** Le code IKEv2 n'est pas un bug à réparer, c'est l'état courant. La bascule suit le plan de l'ADR, pas des retouches opportunistes.
- **Ne pas réécrire ce fichier ni `docs/ARCHITECTURE.md` / `docs/POST-QUANTUM.md` en WireGuard tant que le code ne l'est pas.** Ils décrivent le code, pas l'intention. Ils sont mis à jour *au fur et à mesure* que la bascule avance.
- **Nomenclature — renommage fait** : **Helios** = la gateway (`heliosd`, `helios-*`), **Orion** = le client (`orion-core`, `apps/orion`), **`aether`** = le milieu partagé par les deux (types communs, zéro dépendance système). Les anciens noms (`helios-core`, `helios-client-core`, `apps/helios-client`) n'existent plus.

Ce qui est condamné par l'ADR (~820 lignes) : `helios-vici` en entier, `aether/src/profiles.rs`, et dans `heliosd/src/orchestrator.rs` : `bring_up_real`, `load_connection`, `initiate` et l'appareillage MOBIKE (lignes 560-738). Inutile d'y investir.

## What this is

Helios is an IPsec VPN gateway **orchestrator** (control plane) for a Linux appliance, in Rust. It does **not** do crypto or packet forwarding itself — the kernel does (XFRM/ESP + Netfilter). `heliosd` orchestrates: it drives strongSwan's `charon` over VICI, programs the nftables kill-switch over Netlink, and manages A/B OTA updates via RAUC.

## Interface web (React + Axum)

`heliosd` embarque un serveur HTTP Axum qui expose REST + WebSocket + l'app React statique.

**Flux de données** :
- `GET /api/status` → JSON de l'état courant (lu depuis `Arc<RwLock<TunnelState>>`)
- `GET /api/network` → JSON de la config réseau courante (`Arc<RwLock<NetworkConfig>>`)
- `POST /api/network` → recharge la config réseau à chaud (JSON) → envoie `LoadNetworkConfig` à l'orchestrateur
- `POST /api/tunnel/start|stop` → envoie un `OrchestratorCmd` via `mpsc` → l'orchestrateur réagit
- `WS /ws` → flux de `HeliosEvent` JSON temps réel (`broadcast::Sender` côté orchestrateur, `subscribe()` par handler WS)

**Câblage dans `main.rs`** : le `broadcast::channel` et le `mpsc::channel` sont créés là, le `Arc<RwLock<TunnelState>>` et le `Arc<RwLock<NetworkConfig>>` sont partagés entre `AppState` (API) et `orchestrator::run`. La fonction `transition()` dans l'orchestrateur met à jour les trois en une seule opération atomique.

**Config réseau** : un seul fichier TOML (`/var/lib/helios/network.toml`) chargé au démarrage. Tous les autres paramètres (TPM, VICI socket `/var/run/charon.vici`, API bind `127.0.0.1:8080`, profil IKE hybride par défaut, fail-closed) sont des constantes compilées dans le binaire.

**Feature `embed-ui`** : rust-embed embarque `web/dist/` dans le binaire. Sans cette feature, `/` renvoie 503 (pratique en dev où Vite tourne séparément et proxy `/api` + `/ws` vers `:8080`).

**Invariant — le serveur web vit DERRIÈRE le tunnel.** Sur la passerelle (`admin_iface = "ipsec0"`), nftables ne laisse atteindre l'API REST/WS qu'à travers l'interface IPsec : elle n'est joignable **qu'une fois le tunnel établi**. Conséquence directe pour tout client : on **ne pilote jamais** la montée d'un tunnel via cette API (poule/œuf) — un client IPsec se connecte à la gateway par son **endpoint IKE** (IP/FQDN), pas par une URL HTTP. L'API web ne sert qu'à la supervision/télémétrie *post-connexion*.

## Commands

```sh
cargo build                      # whole workspace (default features = no kernel deps)
cargo test                       # no system dependencies — runs anywhere incl. WSL2
cargo test -p helios-vici        # one crate
cargo test round_trip_keyvalue   # one test by name
cargo clippy --all-targets

# Run the daemon (auto-detects WSL2 → dry-run mode):
cargo run -p heliosd -- status
cargo run -p heliosd -- run              # API on http://127.0.0.1:8080
cargo run -p heliosd -- run --dev        # force dev mode (simulation sans charon ni nftables)
cargo run -p heliosd -- check-update

# Target-only build (needs libnftnl/libmnl + nf_tables kernel; will NOT build on WSL2):
cargo build -p heliosd --features netlink

# UI dev workflow (React app):
cd web && npm install && npm run dev   # Vite on :5173, proxies /api + /ws to heliosd on :8080
# Production embed (run AFTER npm run build):
cargo build -p heliosd --features embed-ui

# Dev/test CLI (in a second terminal while heliosd is running):
cargo run -p helios-ctl -- status
cargo run -p helios-ctl -- watch                               # live WebSocket event stream
cargo run -p helios-ctl -- network show                        # affiche la config réseau courante
cargo run -p helios-ctl -- network load config/network.toml   # charge une config réseau
cargo run -p helios-ctl -- scenario nominal    # connect → Up → disconnect, checks timing
cargo run -p helios-ctl -- scenario flap       # connect/disconnect ×5, measures latency
cargo run -p helios-ctl -- --url http://192.168.1.1:8080 status  # remote target

# Client VPN (app web Tauri, apps/orion) — VRAI client IPsec autonome :
cargo test -p orion-core             # logique testable PARTOUT (config, dry-run) incl. WSL2
cd apps/orion && npm install && npm run build   # frontend React (tsc + vite), pas de webkit
# Lancer l'app complète (NÉCESSITE libwebkit2gtk-4.1-dev — ne build PAS sur WSL2 sans) :
cd apps/orion && npm run tauri dev   # dry-run par défaut (aucune pile IKEv2 requise)
# Build du shell Rust seul (webkit requis) — exclu du build workspace par défaut :
cargo build -p orion
# Backends IPsec réels (target-only, comme la feature netlink) :
cargo build -p orion --features linux-strongswan   # | native-windows | native-macos
```

## The WSL2 vs target split — read this first

Development happens on WSL2, deployment on a dedicated Linux box. **The WSL2 kernel lacks the data plane**: no `nf_tables`, ESP modules not loaded, no `nft`/`charon`/`rauc` binaries. This split is the single most important thing to internalize:

- **Testable on WSL2 (~80% of code, all in `dry_run` mode):** the tunnel state machine, the full VICI wire codec (round-trip tested), kill-switch rule *rendering*, and all orchestration logic.
- **Target-only (deliberately stubbed):** the real Netlink backend (`crates/helios-firewall/src/netlink.rs`) and the live VICI event loop (`bring_up_real` in the orchestrator). These cannot be compiled/exercised on WSL2.

When asked to "make the firewall actually apply rules" or similar, remember it can only be validated on the target — don't assume a green `cargo build` here proves the `netlink` feature works.

## Architecture

Control plane (user space) drives the kernel data plane. Crate dependency flows one way: everything depends on `aether`; `heliosd` ties them together.

- **`aether`** — pure types, zero system deps. Owns the **central security invariant** in `state.rs`: traffic is allowed *only* in `Up`/`Rekeying`; every other state engages the kill-switch (`kill_switch_engaged()`). `TunnelState::on(event)` is the state machine. `config.rs` maps `Config` → `FirewallPolicy`. `profiles.rs` holds the static `PROFILES` array of named IKE presets (classic, hybrid, hybrid-max, full-pqc).
- **`helios-vici`** — native strongSwan VICI client, no C dependency. `codec.rs` implements the element wire format (the testable centerpiece); `client.rs` does length-prefixed packet framing over a Unix socket.
- **`helios-firewall`** — `FirewallBackend` trait + `ruleset::render(policy, state)` which turns intent into an nftables ruleset (default verdict `Drop` = fail-closed). Two backends: `DryRunBackend` (logs, default) and `NetlinkBackend` (feature `netlink`, rustables).
- **`helios-update`** — `UpdateChannel` trait + `RaucChannel` (shells to `rauc`, A/B + rollback) and `DryRunChannel`.
- **`helios-api`** — Axum HTTP server crate: REST routes (`routes.rs`), WebSocket handler (`ws.rs`), optional static asset embedding (`embed.rs`, feature `embed-ui`). Shares `Arc<RwLock<TunnelState>>` and channels with the orchestrator via `AppState`.
- **`helio-tpm`** — TPM 2.0 boot integrity: seals a 256-bit secret against PCR 0/4/7 at provisioning; unseal at boot proves the bootchain is unmodified. The secret decrypts IPsec credentials before `load-conn`. Re-sealing after OTA requires a signed Ed25519 ticket (anti-rollback). `DryRunTpm` is fully testable on WSL2; `TpmDevice` (feature `tpm`) only on the target.
- **`heliosd`** — `orchestrator.rs` wires it together: engage kill-switch *before* any network, then `simulate_bringup` (dry-run) or `bring_up_real` (VICI), plus the OTA loop.
- **`helios-ctl`** (`tools/`) — developer CLI for scripting and scenario testing against a running `heliosd`; not part of the deployed appliance.
- **`orion-core`** — cœur **portable** du client VPN (côté road-warrior, pas la gateway) : `config.rs` (le profil VPN `ClientProfile` éditable/persisté : endpoint IKE, identités, credentials, profil IKE/ESP), `backend/` (trait `VpnBackend` qui **monte réellement** le tunnel via la pile IKEv2 native de l'OS — `DryRunBackend` par défaut/testable WSL2, `linux`/`windows`/`macos` derrière des features target-only), `telemetry.rs` (consomme l'API heliosd **uniquement post-`Up`**). Zéro dépendance Tauri → testé sur WSL2 (`cargo test -p orion-core`).
- **`apps/orion`** (`src-tauri` + frontend React) — shell **Tauri** mince : commandes `invoke` (connect/disconnect, CRUD profils), relais des `ClientEvent` vers l'IHM (`emit`). Lie `webkit2gtk-4.1` → **exclu des `default-members`** du workspace (ne build pas sur WSL2 sans webkit), comme la feature `netlink` est target-only. Note PQ : les piles IKEv2 natives Windows/macOS ne supportent pas l'échange ML-KEM (RFC 9370) — réservé aux clients strongSwan ≥ 6.

### Fail-closed is a hard rule, not a default

This is the project's reason for existing — preserve it in any change:
1. The kill-switch is engaged at startup **before** any network contact.
2. On shutdown it is **left engaged** (never "unlock" on exit).
3. `NetlinkBackend` returns an error rather than applying a *partial* policy — refusing to open a gap is correct behavior, not a bug to "fix" by making it succeed.

**Portée après ADR-001** : cette règle ne vaudra plus que pour **Helios**, la gateway. Le client **Orion** sera délibérément *fail-open* (CWE-636) : aucun pare-feu, aucun WFP. Sa protection reposera sur une invariante de cycle de vie — *l'adaptateur Wintun (`AllowedIPs = 0.0.0.0/0`) n'est jamais démonté sur échec, seulement sur déconnexion explicite* — qui laisse WireGuard jeter les paquets au lieu de fuir. Détail et justification en §3 bis de l'ADR. Le kill-switch de la gateway ne protège **pas** le client : deux machines, deux modèles de menace.

## Conventions

- Comments, log messages, and doc-strings are in **French** (the project's working language). Match this.
- Platform-specific code that can't build on WSL2 goes behind a cargo feature (`netlink`), wired through from `heliosd`'s feature of the same name.
- `dry_run = true` is the safe default in config; real kernel mutation requires both `dry_run = false` and the relevant feature compiled.

## Post-quantum

> **Condamné par ADR-001.** Le mécanisme ci-dessous (RFC 9370, `ke1_mlkem768` dans la proposition IKE) décrit le code actuel mais disparaît avec IKEv2. Il sera remplacé par un échange **ML-KEM-768 (`ml-kem`, RustCrypto)** mené sur le canal de contrôle TLS *à l'intérieur du tunnel*, dont le secret alimente le slot **`PresharedKey`** de WireGuard — sans jamais toucher au handshake. Voir §2 et la cinématique de l'ADR.

Key exchange is hybrid ECDHE + ML-KEM, carried in the `ike_proposal` string (e.g. `aes256gcm16-prfsha384-ecp384-ke1_mlkem768`, where `ke1_mlkem768` is the RFC 9370 additional exchange). It's passed verbatim to charon via `load-conn`; strongSwan ≥ 6 on the target must provide the ML-KEM plugin. See `docs/POST-QUANTUM.md`.

The four built-in profiles (`classic`, `hybrid`, `hybrid-max`, `full-pqc`) are defined in `aether/src/profiles.rs` and selected via `OrchestratorCmd::ConnectWithProfile(id)`. Custom proposals bypass the profile table via `OrchestratorCmd::ConnectWithCustom { ike_proposal, esp_proposal }`.
