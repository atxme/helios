# Construire le projet

## Prérequis

Le workspace déclare Rust 1.95 comme version minimale. Les interfaces demandent
Node.js `^22.22.2 || ^24.15.0 || >=26.0.0`. Sous Debian/Ubuntu, le script existant installe
les dépendances de développement :

```sh
./scripts/setup-dev.sh
./scripts/setup-dev.sh --build
```

`--target` ajoute les dépendances nftables, WireGuard et TPM pour une machine
cible. WSL2 ne valide pas le fonctionnement matériel.

## Builds courants

```sh
cargo build
cargo build -p heliosd
npm run build --prefix web
npm run build --prefix apps/orion
cargo build -p heliosd --features netlink,wireguard,tpm,embed-ui
```

Le dernier build nécessite les dépendances de la cible et un trousseau éditeur
public fourni par `HELIOS_PUBLISHER_KEYRING_PATH` pour un build release :

```sh
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/publisher-keyring.json \
  cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
```

Le build du shell Tauri Orion sous Linux dépend de WebKitGTK et GTK3. Sous
Windows, la production d'installateurs passe par la commande existante :

```sh
cargo xtask orion-msi
```

Les commandes de bundling et de signature sont décrites dans les guides de
sécurité et de déploiement existants ; la CI ne signe pas les artefacts.
