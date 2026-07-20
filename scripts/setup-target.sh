#!/usr/bin/env bash
# Prépare une gateway Linux dédiée. À ne pas exécuter sur WSL2 : le build y est
# possible, mais les effets nf_tables/WireGuard/TPM/systemd ne le sont pas.
set -euo pipefail

if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "Refus : setup-target.sh doit être exécuté sur la gateway dédiée." >&2
    exit 1
fi

if [[ -z "${HELIOS_PUBLISHER_KEYRING_PATH:-}" ]]; then
    echo "HELIOS_PUBLISHER_KEYRING_PATH doit désigner le trousseau public de production." >&2
    exit 1
fi

echo "==> Installation des dépendances (Debian/Ubuntu)"
sudo apt-get update
sudo apt-get install -y \
    nftables wireguard-tools \
    libnftnl-dev libmnl-dev \
    tpm2-tools libtss2-dev \
    build-essential pkg-config

echo "==> Chargement des modules kernel"
sudo modprobe wireguard
sudo modprobe nf_tables

echo "==> Build release avec ancre éditeur explicite"
npm ci --prefix web
npm run build --prefix web
cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
cargo build --release -p helios-installer

echo "==> Installation"
sudo install -Dm755 target/release/heliosd /opt/helios/releases/bootstrap/heliosd
sudo ln -sfn /opt/helios/releases/bootstrap /opt/helios/current
sudo install -Dm755 target/release/helios-installer /usr/libexec/helios-installer
sudo install -Dm644 deploy/systemd/heliosd.service /etc/systemd/system/heliosd.service
sudo install -Dm644 deploy/systemd/helios-update.service /etc/systemd/system/helios-update.service
sudo install -Dm644 deploy/systemd/helios-update.path /etc/systemd/system/helios-update.path
sudo install -Dm600 config/network.toml /var/lib/helios/network.toml
sudo systemctl daemon-reload

echo "==> Terminé"
echo "Éditez /var/lib/helios/network.toml, conservez un accès console, puis :"
echo "  sudo systemctl enable --now heliosd helios-update.path"
echo "Exécutez ensuite la recette matérielle de docs/testing/TESTING.md."
