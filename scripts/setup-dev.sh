#!/usr/bin/env bash
# Installation des dépendances pour heliosd (daemon) et helios-client (GUI).
#
# Usage :
#   ./scripts/setup-dev.sh           # mode dev WSL2 — daemon + client GUI
#   ./scripts/setup-dev.sh --target  # machine dédiée : ajoute netlink/TPM/strongSwan
#   ./scripts/setup-dev.sh --build   # installe ET compile tout
set -euo pipefail

# ── Couleurs ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}==>${NC} $*"; }
success() { echo -e "${GREEN}  ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC} $*"; }
die()     { echo -e "${RED}  ✗${NC} $*" >&2; exit 1; }

# ── Args ────────────────────────────────────────────────────────────────────
TARGET_MODE=false
BUILD_MODE=false
for arg in "$@"; do
    case $arg in
        --target) TARGET_MODE=true ;;
        --build)  BUILD_MODE=true  ;;
        --help|-h)
            echo "Usage: $0 [--target] [--build]"
            echo "  (aucun flag)  Dépendances dev WSL2 : daemon (dry-run) + client GUI"
            echo "  --target      Ajoute les dépendances cible : netlink, TPM, strongSwan, rauc"
            echo "  --build       Installe les dépendances ET compile les binaires"
            exit 0 ;;
        *) die "Argument inconnu : $arg. Utilisez --help pour l'aide." ;;
    esac
done

# ── Environnement ───────────────────────────────────────────────────────────
IS_WSL=false
grep -qi microsoft /proc/version 2>/dev/null && IS_WSL=true

if $IS_WSL && $TARGET_MODE; then
    warn "WSL2 détecté avec --target : les dépendances nf_tables/TPM ne fonctionneront pas ici."
    warn "Exécutez ce script sur la machine dédiée pour --target."
    read -r -p "Continuer quand même ? [o/N] " resp
    [[ "$resp" =~ ^[oO]$ ]] || exit 0
fi

# ── Distro ──────────────────────────────────────────────────────────────────
if ! command -v apt-get &>/dev/null; then
    die "Ce script cible Debian/Ubuntu (apt-get non trouvé)."
fi

# ── 1. Rust toolchain ───────────────────────────────────────────────────────
info "Vérification de Rust..."
if ! command -v rustup &>/dev/null; then
    info "Installation de rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    success "rustup installé"
else
    rustup update stable --quiet
    success "Rust $(rustc --version)"
fi

RUST_MIN="1.82"
RUST_VER=$(rustc --version | grep -oP '\d+\.\d+' | head -1)
if [[ "$(printf '%s\n' "$RUST_MIN" "$RUST_VER" | sort -V | head -1)" != "$RUST_MIN" ]]; then
    die "Rust ≥ $RUST_MIN requis (installé : $RUST_VER). Lancez : rustup update stable"
fi

# ── 2. Dépendances système communes ─────────────────────────────────────────
info "Installation des dépendances système communes..."
sudo apt-get update -qq
sudo apt-get install -y \
    build-essential pkg-config curl git \
    libssl-dev \
    ca-certificates
success "Outils de base OK"

# ── 3. Dépendances helios-client (egui + GTK) ───────────────────────────────
info "Dépendances helios-client (egui/glow + GTK3)..."
sudo apt-get install -y \
    libgtk-3-dev \
    libgl1-mesa-dev libgles2-mesa-dev \
    libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
    libxkbcommon-dev \
    libfontconfig1-dev \
    libglib2.0-dev
success "GTK3 + OpenGL OK"

# Alerte WSL2 : l'affichage graphique nécessite WSLg ou un serveur X
if $IS_WSL; then
    warn "WSL2 : helios-client requiert WSLg (Windows 11) ou un serveur X (VcXsrv/X410)."
    warn "Vérifiez que DISPLAY est défini avant de lancer le client."
fi

# ── 4. Node.js (UI web React) ────────────────────────────────────────────────
info "Vérification de Node.js..."
NODE_MIN=18
if command -v node &>/dev/null; then
    NODE_VER=$(node --version | tr -d 'v' | cut -d. -f1)
    if [[ "$NODE_VER" -ge "$NODE_MIN" ]]; then
        success "Node.js $(node --version) + npm $(npm --version)"
    else
        warn "Node.js $NODE_VER détecté, ≥ $NODE_MIN requis. Mise à jour via NodeSource..."
        curl -fsSL https://deb.nodesource.com/setup_${NODE_MIN}.x | sudo -E bash -
        sudo apt-get install -y nodejs
        success "Node.js $(node --version) installé"
    fi
else
    info "Installation de Node.js $NODE_MIN via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MIN}.x | sudo -E bash -
    sudo apt-get install -y nodejs
    success "Node.js $(node --version) + npm $(npm --version)"
fi

# ── 5. Dépendances cible uniquement ─────────────────────────────────────────
if $TARGET_MODE; then
    info "Dépendances cible (Netlink/nftables, TPM, strongSwan, RAUC)..."
    sudo apt-get install -y \
        libnftnl-dev libmnl-dev \
        nftables \
        strongswan strongswan-swanctl \
        rauc \
        tpm2-tools libtss2-dev
    success "Dépendances cible OK"

    info "Chargement des modules kernel IPsec..."
    sudo modprobe esp4 esp6 xfrm_user af_key 2>/dev/null || warn "Certains modules kernel non disponibles (normal en VM/WSL2)."
fi

# ── 6. Dépendances npm (UI web) ──────────────────────────────────────────────
info "Installation des dépendances npm (web/)..."
(cd "$(dirname "$0")/../web" && npm install --silent)
success "node_modules OK"

# ── 7. Build (optionnel) ─────────────────────────────────────────────────────
if $BUILD_MODE; then
    REPO_ROOT="$(dirname "$0")/.."

    info "Compilation de heliosd (dry-run, sans features noyau)..."
    cargo build -p heliosd 2>&1 | tail -5
    success "heliosd OK → target/debug/heliosd"

    info "Compilation de helios-client..."
    cargo build -p helios-client 2>&1 | tail -5
    success "helios-client OK → target/debug/helios-client"

    if $TARGET_MODE; then
        info "Compilation de heliosd --features netlink (cible)..."
        cargo build --release -p heliosd --features netlink 2>&1 | tail -5
        success "heliosd (release + netlink) OK → target/release/heliosd"
    fi
fi

# ── Récapitulatif ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Installation terminée.${NC}"
echo ""
echo "Prochaines étapes :"
echo "  # Daemon (dry-run) :"
echo "  cargo run -p heliosd -- --config config/helios.toml run"
echo ""
echo "  # Client GUI :"
if $IS_WSL; then
    echo "  export DISPLAY=:0  # ou laisser WSLg gérer"
fi
echo "  cargo run -p helios-client"
echo ""
echo "  # UI web (dev) :"
echo "  cd web && npm run dev"
if $TARGET_MODE; then
    echo ""
    echo "  # Daemon en mode réel (machine dédiée) :"
    echo "  cargo build --release -p heliosd --features netlink"
fi
