# Helios

Orchestrateur de passerelle **VPN IPsec** pour appliance Linux, écrit en Rust.

Helios applique le principe **control plane / data plane** : tout le chiffrement
reste dans le noyau (XFRM/ESP), et un daemon Rust orchestre la sécurité —
négociation via **strongSwan/VICI**, **kill-switch** nftables (fail-closed) et
mises à jour **OTA A/B** (RAUC).

```
                 ┌──────────────────────────────────────────────┐
                 │                heliosd (Rust)                 │  ← plan de contrôle
                 │  état tunnel · kill-switch · OTA · orchestr.  │     (user space)
                 └───┬───────────────┬───────────────────┬──────┘
            VICI     │        Netlink │            rauc   │
         (UnixSock)  │      (nf_tables)│        (A/B+rollback)
                 ┌───▼───┐       ┌────▼────┐         ┌────▼────┐
                 │charon │       │nftables │         │  RAUC   │
                 │(IKEv2)│       │kill-sw. │         │ slots   │
                 └───┬───┘       └────┬────┘         └─────────┘
   ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  kernel space
                 ┌───▼─────────────────▼──────────────────────┐
                 │   XFRM (ESP) · Netfilter · pile réseau       │  ← plan de données
                 └──────────────────────────────────────────────┘
```

## Pourquoi la pile Linux native ?

Pas de DPDK ni d'AF_XDP : pour du Gigabit (Realtek RTL8111HS), la pile native
(XFRM + Netfilter, par interruptions) est efficace, économe en CPU, ultra-auditée,
et conserve tous les outils standard (`ip xfrm`, `nft`, `tcpdump`). Voir
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Crates

| Crate             | Rôle                                                            |
|-------------------|-----------------------------------------------------------------|
| `helios-core`     | Types métier : machine à états du tunnel, politique, config     |
| `helios-vici`     | Client natif du protocole VICI de strongSwan (codec + client)   |
| `helios-firewall` | Kill-switch : rendu de règles + backends `dry-run` / `netlink`  |
| `helios-update`   | OTA A/B : trait `UpdateChannel` + backends `rauc` / `dry-run`   |
| `heliosd`         | Daemon : CLI + orchestration                                    |

## Démarrage (WSL2, dev)

```sh
cargo test                                   # 13 tests (codec VICI, états, règles)
cargo run -p heliosd -- --config config/helios.toml status
cargo run -p heliosd -- --config config/helios.toml run
```

En `dry_run = true` (défaut), aucune écriture kernel : `heliosd` simule la montée
du tunnel et journalise le jeu de règles nftables à chaque transition d'état.

## Déploiement (machine dédiée)

WSL2 n'a ni `nf_tables` ni les modules ESP : seul le plan de contrôle se teste
ici. Le backend Netlink réel et le tunnel de bout en bout se valident sur la
cible. Voir [docs/WSL2-DEV.md](docs/WSL2-DEV.md).

```sh
./scripts/setup-target.sh        # strongSwan, nftables, rauc, build --features netlink
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — control/data plane, XFRM, kill-switch
- [Dev sur WSL2](docs/WSL2-DEV.md) — ce qui marche ici vs sur la cible
- [Post-quantique](docs/POST-QUANTUM.md) — ML-KEM + ECDHE hybride
- [OTA RAUC](docs/OTA-RAUC.md) — image A/B et rollback

## Interface web

`heliosd` embarque un serveur Axum sur `http://127.0.0.1:8080` (configurable).

| Endpoint             | Rôle                                                   |
|----------------------|--------------------------------------------------------|
| `GET  /api/status`   | État courant du tunnel + config (JSON)                 |
| `POST /api/tunnel/start` | Demande de connexion → `OrchestratorCmd::Connect`  |
| `POST /api/tunnel/stop`  | Déconnexion → `OrchestratorCmd::Disconnect`        |
| `WS   /ws`           | Flux temps réel de `HeliosEvent` (JSON)                |

**Types d'événements WebSocket :**
- `state_changed` — transition d'état du tunnel
- `log` — message structuré (info / warn / error) de l'orchestrateur
- `telemetry` — compteurs réseau WAN (Rx/Tx bps + pps) lus depuis `/proc/net/dev`, émis toutes les secondes

**Stack frontend :** React 18 + TypeScript + Vite + Tailwind CSS · lucide-react · sparklines SVG natif

```sh
cd web && npm install && npm run dev   # Vite sur :5173, proxy /api + /ws → :8080
cargo build -p heliosd --features embed-ui  # embed l'app dans le binaire
```

## État du projet

Plan de contrôle fonctionnel. Composants à finaliser sur cible :
- Backend Netlink (`crates/helios-firewall/src/netlink.rs`) — règles nftables réelles
- Boucle d'événements VICI temps réel (`bring_up_real` dans l'orchestrateur)

**Feuille de route IHM :**
- `list-sas` VICI — afficher les algorithmes *négociés* (vs configurés) une fois le tunnel monté
- Compteurs nftables — paquets rejetés par le kill-switch (confirmation d'isolation)
- Sélecteur de profils — `OrchestratorCmd::ConnectWithProfile(String)` + dropdown UI
