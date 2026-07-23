#!/usr/bin/env bash
# Prépare une gateway Linux dédiée à recevoir un bundle Helios.
#
# Ce script n'installe PLUS de chaîne de compilation et ne construit rien : la
# gateway ne reçoit que des binaires signés (ADR-004). Il n'installe que les
# dépendances système dont `heliosd` a besoin à l'exécution.
#
# Depuis le poste de build :
#
#   HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
#     cargo xtask bundle
#   helios-publisher bundle --dir target/bundle/helios-<v>-<target> …
#   cargo xtask pack --dir target/bundle/helios-<v>-<target>
#
# puis, sur la gateway, après avoir comparé l'empreinte publiée :
#
#   sudo ./helios-installer bootstrap --archive helios-<v>-<target>.tar.gz
#
# Voir docs/security/OPERATOR-TOOLING.md et docs/testing/TESTING.md.
set -euo pipefail

if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "Refus : setup-target.sh doit être exécuté sur la gateway dédiée." >&2
    exit 1
fi

echo "==> Dépendances d'exécution (Debian/Ubuntu)"
# Les paquets `-dev` sont installés délibérément : ils garantissent la présence
# des sonames attendus sans avoir à deviner le nom du paquet runtime, qui change
# d'une version de distribution à l'autre. Un paquet `.deb` Helios déclarerait
# un jour ces dépendances exactement ; ce script ne le remplace pas.
sudo apt-get update
sudo apt-get install -y \
    nftables wireguard-tools \
    libnftnl-dev libmnl-dev \
    tpm2-tools libtss2-dev

echo "==> Modules noyau"
sudo modprobe wireguard
sudo modprobe nf_tables

echo "==> Arborescence"
sudo install -d -m 0700 /var/lib/helios
sudo install -d -m 0755 /opt/helios/releases

echo
echo "==> Terminé — la gateway est prête à recevoir un bundle."
echo
echo "Sur cette machine, une fois l'archive copiée :"
echo "  sha256sum helios-<version>-<target>.tar.gz    # comparer à l'empreinte publiée"
echo "  sudo ./helios-installer bootstrap --archive helios-<version>-<target>.tar.gz"
echo
echo "L'installateur vérifie la signature hybride et l'empreinte de chaque"
echo "fichier avant d'écrire quoi que ce soit. Il n'active aucun service :"
echo "conserver un accès console pour la suite (provision-tpm, init-identity)."
