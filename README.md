# Helios

Helios est une passerelle VPN WireGuard pour appliance Linux, pilotée par un
daemon Rust. Orion est son client de bureau Tauri ; `aether` porte les contrats
partagés.

Avant tout paquet WireGuard, Orion négocie avec la gateway sur un port UDP dédié
(QUIC/mTLS, PKI **ML-DSA-87**) et en ressort avec le PSK post-quantique que le
**premier** handshake utilisera — protocole v5,
[ADR-005](docs/adr/ADR-005-NEGOCIATION-DE-CLE.md).

## Fonctionnalités principales

- passerelle WireGuard Linux avec routage, IPAM CGNAT, multi-uplink et règles
  nftables atomiques ;
- kill-switch fail-closed et suivi réel de l'état des tunnels par handshake ;
- négociation de clé v5 avant WireGuard, via QUIC/mTLS, avec ML-KEM-1024 et
  signatures ML-DSA-87 ;
- PKI Astra avec coffre chiffré, clés opérateur YubiKey, registre de confiance,
  renouvellement et rotation des certificats ;
- client Orion pour Windows et Linux : profils, coffre sécurisé, tunnel
  WireGuard, certificats, renouvellement et récupération d'identité ;
- console web d'administration avec gestion des pairs, réseau, certificats,
  télémétrie et tests de débit ;
- mises à jour signées avec anti-rollback, TPM et outils de déploiement ;
- support NordVPN Meshnet comme chemin d'accès réseau de secours.

```text
Orion ── QUIC/mTLS ──► heliosd   négociation de clé (avant le tunnel)
Orion ── WireGuard ──► heliosd   trafic + API d'administration

heliosd : orchestrateur · API Axum/WS · IPAM ML-KEM · pare-feu nftables
          backend WireGuard · TPM · séquestre · mise à jour signée
```

## Composants principaux

| Composant | Rôle |
|---|---|
| `aether` | Types, états, politique, ML-KEM, protocole de négociation, signatures hybrides |
| `helios-firewall` | Rendu nftables, backends `dry-run` / `netlink` |
| `helios-wireguard` | Plan de données gateway et table de pairs |
| `helios-provisioning` | IPAM CGNAT, admission, session ML-KEM |
| `aether-key-negotiation` | Transport QUIC authentifié (ni CA, ni backend WireGuard) |
| `astra` | Coordinateur PKI, registre de confiance et renouvellement des certificats |
| `astra-channel` | Canal privé Astra–gateway sur le veth : mTLS, ALPN, API de cycle de vie |
| `helios-api` | API Axum, WebSocket, IHM embarquée |
| `helios-update` | Manifeste hybride, staging, anti-rollback |
| `helios-escrow` | Séquestre opérateur de l'identité WireGuard |
| `helios-tpm` | Scellement PCR et fenêtre de mise à jour |
| `aether-vault` | Conteneur AEAD unique des secrets au repos (ADR-006) |
| `heliosd` | CLI et orchestration de la gateway |
| `orion-core` / `apps/orion` | Cœur portable et shell Tauri du client |
| `web` | Console d'administration React (MUI seul, polices auto-hébergées) |
| `helios` | Terminal d'administration, sur le poste opérateur ou sur la gateway |
| `helios-publisher` | Outil éditeur hors gateway (Ed25519 + ML-DSA-65) |
| `helios-installer` | Helper privilégié sans réseau : activation et rollback |
| `xtask` | Bundles d'installation et installateur Windows d'Orion |

## Construire et tester

Prérequis : Rust 1.95+, Node.js 22.22.2+, 24.15+ ou 26+. Shell Tauri Linux :
WebKitGTK 4.1 et GTK3 (`scripts/setup-dev.sh`).

```sh
cargo build
cargo test --workspace --all-features
bash scripts/regression.sh             # campagne complète locale et CI

# Développement local
cargo run -p heliosd -- run --dev      # gateway en simulation
npm run dev --prefix web               # console, proxy vers :8080
bash scripts/lab.sh --keep             # banc jetable + profil importable
```

`scripts/regression.sh` est la référence avant chaque version : fmt, Clippy,
tests toutes features, audits Cargo/npm, Vitest et builds frontend.

## Développement et exploitation

```sh
# sur la gateway
heliosd init-identity                  # identité WireGuard scellée au TPM
heliosd init-key-negotiation           # identité de négociation TLS + ML-DSA-87
helios                            # terminal d'administration interactif
helios update --check              # inventaire OS + firmware, sans installation
helios update                      # mise à jour de l'OS (ADR-007)
helios firmware list               # versions proposées par fwupd

# sur le poste opérateur
helios peer add|revoke|list        # admission
helios enroll                      # clés, certificats, admission et profil
helios profile emit|check          # document `.orion`
helios escrow ...                  # séquestre — jamais sur la gateway secourue

# scripts d'enchaînement
./scripts/deploy.sh                    # construit, signe, copie, installe
./scripts/provision-client.sh nom      # CA, négociation, admission, profil
```

Le terminal et le parcours de mise à jour firmware sont décrits dans
[le guide de maintenance](docs/MAINTENANCE.md).

La configuration unique est `/var/lib/helios/network.toml`, relue à chaud
(modèle : [config/network.toml](config/network.toml)). `key_negotiation_port`
ouvre le service de négociation ; absent, il reste fermé. L'identité de
négociation, elle, est lue une fois au démarrage : une rotation s'applique par
`systemctl restart heliosd`.

La CA opérateur vit dans `~/.helios/certs/internal-ca`, et à **un seul** endroit :
la gateway n'en épingle qu'une.

## Compilation cible et limites

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

La négociation v5 est opérationnelle pour l'établissement initial d'un tunnel :
challenge, authentification, dérivation du PSK ML-KEM, preuve WireGuard et
rollback sont en place. Le renouvellement de PSK en place, négocié dans le
tunnel à 80 % de la durée de vie ou du volume, est livré ; sa validation sur
cible (V1) reste à mener. Restent notamment l'enrôlement sans transport de clé
privée et certaines validations sur matériel réel ; le détail est dans la
[spécification v5](docs/specification/NEGOCIATION-DE-CLE-V5.md).

Le cycle de vie des certificats est un chantier distinct, déjà partiellement
livré avec Astra, le registre de confiance, le renouvellement client, la
récupération d'une identité expirée et plusieurs rotations. Les lots ouverts
sont listés dans [ROTATION-CERTIFICATS](docs/specification/ROTATION-CERTIFICATS.md).

Par ailleurs :

- le câblage PSK est validé en **dry-run seulement** — aucun essai noyau, et la
  fenêtre de mise à jour n'a jamais tourné sur un TPM réel ;
- le **DNS d'un client n'est pas tunnelé**, même `allow_client_internet` actif ;
- le fichier de récupération WireGuard reste bloqué jusqu'à l'arbitrage du
  compteur anti-rejeu (ADR-002, amendement 2) ;
- DPAPI ne se compile ni ne s'exerce en WSL2 : hors Windows, le scellement de
  l'identité cliente échoue explicitement.

Une compilation WSL2 n'est jamais une validation matérielle.

L'IPAM alloue la VIP à l'admission ; l'adresse enregistrée dans `network.toml`
fait ensuite autorité. Le provisioning retourne cette adresse, sans la
redériver, et le plan de données la conserve. Si un rechargement de
configuration crée un écart avec une requête en cours, l'écart est journalisé
et l'adresse déclarée est conservée
([adressage, §3 bis.2](docs/specification/ADRESSAGE-IPV6.md#3-bis2-règles)).

## Documentation

- [Architecture](docs/architecture/overview.md) — composants et responsabilités.
- [Développement](docs/development/build.md) — construire, tester et travailler
  localement.
- [Contribution](CONTRIBUTING.md) — branches, commits et pull requests.
- [Sécurité](SECURITY.md) — signalement et gestion des secrets.
- [Index technique](docs/README.md) — ADR, spécifications, sécurité et tests.

En cas de doute, le code et les ADR acceptés font foi.
