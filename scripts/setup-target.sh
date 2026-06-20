#!/usr/bin/env bash
# Prépare une machine Linux dédiée pour exécuter Helios en mode réel.
# À NE PAS exécuter sur WSL2 (le kernel n'a pas nf_tables/ESP).
set -euo pipefail

echo "==> Installation des dépendances (Debian/Ubuntu)"
sudo apt-get update
sudo apt-get install -y \
    strongswan strongswan-swanctl \
    nftables \
    libnftnl-dev libmnl-dev \
    rauc \
    build-essential

echo "==> Chargement des modules kernel IPsec"
sudo modprobe esp4 esp6 xfrm_user af_key || true

echo "==> Build de heliosd avec le backend Netlink"
cargo build --release -p heliosd --features netlink

echo "==> Installation"
sudo install -Dm755 target/release/heliosd /usr/local/bin/heliosd
sudo install -Dm644 config/helios.toml /etc/helios/helios.toml
sudo install -Dm644 deploy/systemd/heliosd.service /etc/systemd/system/heliosd.service
sudo mkdir -p /var/lib/helios

echo "==> Terminé. Éditez /etc/helios/helios.toml (dry_run = false) puis :"
echo "    sudo systemctl enable --now heliosd"
