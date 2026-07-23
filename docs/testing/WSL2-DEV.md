# Développement sous WSL2

WSL2 permet de compiler et tester l’essentiel du projet, y compris les features
`netlink`, `wireguard` et `tpm` lorsque les bibliothèques de développement sont
installées. Son noyau ne fournit toutefois pas le plan de données nécessaire à
leur exécution réelle.

| Élément | Compilation WSL2 | Exécution WSL2 |
|---|---:|---:|
| états, politique, IPAM, ML-KEM, signatures | oui | oui |
| API Axum, WebSocket, dry-run | oui | oui |
| rendu nftables | oui | oui |
| backend Netlink nftables | oui | non sans `nf_tables` |
| backend WireGuard noyau | oui | non sans module WireGuard/droits |
| backend TPM TSS2 | oui | seulement avec TPM accessible |
| staging et vérification du binaire | oui | oui |
| activation systemd et rollback du service | oui | non sans gateway installée |
| shell Tauri Orion | oui avec WebKitGTK 4.1 | oui avec WSLg, sinon build seulement |

Un build vert d’une feature matérielle prouve donc que l’API utilisée compile,
pas que l’effet noyau, TPM ou bootloader fonctionne.

## Installation

```sh
./scripts/setup-dev.sh
```

Pour installer aussi les outils de compilation cible :

```sh
./scripts/setup-dev.sh --target
```

WSL2 affiche un avertissement avant ce second mode. Les modules noyau absents
ne sont pas contournés.

## Boucle quotidienne

```sh
bash scripts/regression.sh

HELIOS_NETWORK_CONFIG=/tmp/helios-network.toml \
  cargo run -p heliosd -- run --dev

npm run dev --prefix web
```

Orion peut être exercé en simulation via Tauri/WSLg, ou seulement au niveau
Rust et frontend :

```sh
cargo test -p orion-core
npm run test:unit --prefix apps/orion
npm run build --prefix apps/orion

# Application complète en dry-run ; démarre Vite automatiquement
cargo run -p orion
```

Le dernier lancement requiert WSLg (`xdpyinfo` doit réussir). Il utilise le
backend Orion simulé mais le véritable shell Tauri et son pont IPC. Sans WSLg,
les trois commandes de test et de build restent utilisables, pas l'IHM native.

## Ce qui doit rester sur la cible

Avant livraison, une machine isolée avec accès console doit valider :

- la transaction nftables et le fail-closed avant/après handshake ;
- la création et la reconfiguration réelles des interfaces WireGuard ;
- l’expiration de handshake et la conservation des routes Orion sur échec ;
- le scellement/déscellement PCR 0/4/7 et le billet de rescellement ;
- l’activation par l’unité systemd, le health check réel et le rollback du lien
  `/opt/helios/current`.

La procédure détaillée se trouve dans [TESTING.md](TESTING.md) et
[MANUAL-TESTING.md](MANUAL-TESTING.md).
