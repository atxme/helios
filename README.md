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

## État du projet

Squelette fonctionnel du plan de contrôle. À finaliser sur la cible : la
traduction des règles dans le backend Netlink (`crates/helios-firewall/src/netlink.rs`)
et la boucle d'événements VICI temps réel.
