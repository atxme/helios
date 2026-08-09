# Helios

Passerelle VPN **WireGuard** pour appliance Linux, pilotée par un daemon Rust.
**Orion** est son client de bureau Tauri, `aether` porte les contrats partagés.

Avant tout paquet WireGuard, Orion négocie avec la gateway sur un port UDP dédié
(QUIC/mTLS, PKI **ML-DSA-87**) et en ressort avec le PSK post-quantique que le
**premier** handshake utilisera — protocole v5,
[ADR-005](docs/adr/ADR-005-NEGOCIATION-DE-CLE.md).

```text
Orion ── QUIC/mTLS ──► heliosd   négociation de clé (avant le tunnel)
Orion ── WireGuard ──► heliosd   trafic + API d'administration

heliosd : orchestrateur · API Axum/WS · IPAM ML-KEM · pare-feu nftables
          backend WireGuard · TPM/coffres · mise à jour signée
```

## Fonctionnement

La gateway crée `helios0`, écoute en UDP 51820 et attend les clients admis.
WireGuard n'ayant pas de connexion persistante, l'état est inféré du handshake :
`up` sous 150 s, `connecting` au-delà, plus `down`, `failed` et `captive_portal`.

Le pare-feu est **fail-closed** : seul `up` autorise le trafic LAN, et le
kill-switch reste engagé partout ailleurs, y compris à l'arrêt. Le backend
Netlink traduit tout le ruleset puis l'applique — filtrage **et** NAT — en une
seule transaction atomique.

Orion n'a pas de pare-feu local : avec `AllowedIPs = 0.0.0.0/0`, son adaptateur
reste monté après un échec pour que WireGuard jette les paquets. Seule une
déconnexion explicite le démonte.

## Workspace

| Composant | Rôle |
|---|---|
| `aether` | Types, états, politique, ML-KEM, protocole de négociation, signatures hybrides |
| `helios-firewall` | Rendu nftables, backends `dry-run` / `netlink` |
| `helios-wireguard` | Plan de données gateway et table de pairs |
| `helios-provisioning` | IPAM CGNAT, admission, session ML-KEM |
| `helios-key-negotiation` | Transport QUIC authentifié (ni CA, ni backend WireGuard) |
| `helios-api` | API Axum, WebSocket, IHM embarquée |
| `helios-update` | Manifeste hybride, staging, anti-rollback |
| `helio-tpm` | Scellement PCR, séquestre, fenêtre de mise à jour |
| `helios-vault` | Conteneur AEAD unique des secrets au repos (ADR-006) |
| `heliosd` | CLI et orchestration de la gateway |
| `orion-core` / `apps/orion` | Cœur portable et shell Tauri du client |
| `web` | Console d'administration React (MUI seul, polices auto-hébergées) |
| `helios-ctl` | Outil du poste opérateur — et `update` sur la gateway |
| `helios-publisher` | Outil éditeur hors gateway (Ed25519 + ML-DSA-65) |
| `helios-installer` | Helper privilégié sans réseau : activation et rollback |
| `xtask` | Bundles d'installation et installateur Windows d'Orion |

## Démarrage

Prérequis : Rust 1.82+, Node.js 20.19+ ou 22.12+. Shell Tauri Linux :
WebKitGTK 4.1 et GTK3 (`scripts/setup-dev.sh`).

```sh
cargo test --workspace --all-features
cargo run -p heliosd -- run --dev      # gateway en simulation
npm run dev --prefix web               # console, proxy vers :8080
bash scripts/lab.sh --keep             # banc jetable + profil importable
```

`scripts/regression.sh` est la référence avant chaque version : fmt, Clippy,
tests toutes features, audits Cargo/npm, Vitest et builds frontend.

## Exploitation

```sh
# sur la gateway
heliosd init-identity                  # identité WireGuard scellée au TPM
heliosd init-key-negotiation           # identité de négociation TLS + ML-DSA-87
helios-ctl update                      # mise à jour de l'OS (ADR-007)

# sur le poste opérateur
helios-ctl peer add|revoke|list        # admission
helios-ctl enroll                      # clés, certificats, admission et profil
helios-ctl profile emit|check          # document `.orion`
helios-ctl escrow ...                  # séquestre — jamais sur la gateway secourue

# scripts d'enchaînement
./scripts/deploy.sh                    # construit, signe, copie, installe
./scripts/provision-client.sh nom      # CA, négociation, admission, profil
```

La configuration unique est `/var/lib/helios/network.toml`, relue à chaud
(modèle : [config/network.toml](config/network.toml)). `key_negotiation_port`
ouvre le service de négociation ; absent, il reste fermé. L'identité de
négociation, elle, est lue une fois au démarrage : une rotation s'applique par
`systemctl restart heliosd`.

La CA opérateur vit dans `~/.helios/certs/internal-ca`, et à **un seul** endroit :
la gateway n'en épingle qu'une.

## Compilation cible

```sh
npm run build --prefix web
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
cd apps/orion && npm run tauri build -- --features wireguard
```

Features matérielles : `netlink`, `wireguard`, `tpm`, `embed-ui` côté gateway,
`wireguard` côté Orion. La négociation de clé n'en fait pas partie : tout binaire
la porte.

Hors `--dev`, un backend noyau absent est une **erreur de démarrage** — aucun
repli implicite vers une simulation. Compiler sous WSL2 ne valide que le code ;
les essais noyau, TPM et WireGuard-NT sont target-only
([TESTING.md](docs/testing/TESTING.md)).

Livraison : `cargo xtask bundle`, `helios-publisher bundle`, `cargo xtask pack`,
`helios-installer bootstrap`, et `cargo xtask orion-msi` sous Windows.

## État et limites

La négociation v5 est **partiellement implémentée** ; la
[spécification](docs/specification/NEGOCIATION-DE-CLE-V5.md) nomme les lots
ouverts. Le **cycle de vie des certificats n'est pas implémenté** : la leaf PQ de
la gateway est encore auto-signée, sans slot actif/suivant ni génération
anti-rollback (cible :
[ROTATION-CERTIFICATS](docs/specification/ROTATION-CERTIFICATS.md) et
[ADR-008](docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md)).

Par ailleurs :

- le câblage PSK est validé en **dry-run seulement** — aucun essai noyau, et la
  fenêtre de mise à jour n'a jamais tourné sur un TPM réel ;
- le **DNS d'un client n'est pas tunnelé**, même `allow_client_internet` actif ;
- la VIP dérivée par l'IPAM n'est pas réconciliée avec l'adresse déclarée en
  configuration : l'écart est journalisé ;
- le fichier de récupération WireGuard reste bloqué jusqu'à l'arbitrage du
  compteur anti-rejeu (ADR-002, amendement 2) ;
- DPAPI ne se compile ni ne s'exerce en WSL2 : hors Windows, le scellement de
  l'identité cliente échoue explicitement.

Une compilation WSL2 n'est jamais une validation matérielle.

## Documentation

[Index complet](docs/README.md) — architecture, ADR, spécifications, sécurité et
tests. En cas de doute, le code et les ADR acceptés font foi.
