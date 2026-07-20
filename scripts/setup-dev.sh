#!/usr/bin/env bash
# Installation des dépendances pour heliosd (daemon) et orion (GUI).
#
# Usage :
#   ./scripts/setup-dev.sh           # mode dev WSL2 — daemon + client GUI
#   ./scripts/setup-dev.sh --target  # ajoute nftables/WireGuard/TPM/RAUC
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
            echo "  --target      Ajoute les dépendances cible : nftables, WireGuard, TPM, RAUC"
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
    rustup update stable
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

# ── 3. Dépendances apps/orion (app Tauri = webkit2gtk) ──────────────
info "Dépendances client Tauri (webkit2gtk-4.1 + GTK3)..."
sudo apt-get install -y \
    libwebkit2gtk-4.1-dev \
    libgtk-3-dev \
    librsvg2-dev \
    libayatana-appindicator3-dev \
    patchelf \
    libglib2.0-dev
success "webkit2gtk + GTK3 OK"

# Alerte WSL2 : l'affichage graphique nécessite WSLg ou un serveur X
if $IS_WSL; then
    warn "WSL2 : l'app orion (Tauri) requiert WSLg (Windows 11) ou un serveur X."
    warn "La LOGIQUE du client reste testable sans affichage : cargo test -p orion-core."
fi

# ── 4. Node.js (UI web React) ────────────────────────────────────────────────
info "Vérification de Node.js..."
NODE_MIN=22
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
    info "Dépendances cible (Netlink/nftables, WireGuard, TPM, RAUC)..."
    sudo apt-get install -y \
        libnftnl-dev libmnl-dev \
        nftables wireguard-tools \
        rauc \
        tpm2-tools libtss2-dev
    success "Dépendances cible OK"

    info "Chargement des modules kernel WireGuard/nf_tables..."
    sudo modprobe wireguard 2>/dev/null || warn "Module WireGuard indisponible (normal en WSL2)."
    sudo modprobe nf_tables 2>/dev/null || warn "Module nf_tables indisponible (normal en WSL2)."
fi

# ── 6. Dépendances npm verrouillées ──────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for app in web apps/orion; do
    info "Installation npm verrouillée ($app)..."
    npm ci --silent --prefix "$REPO_ROOT/$app"
done
success "node_modules Helios et Orion OK"

# ── 7. Build (optionnel) ─────────────────────────────────────────────────────
if $BUILD_MODE; then
    info "Compilation de heliosd (dry-run, sans features noyau)..."
    cargo build -p heliosd 2>&1 | tail -5
    success "heliosd OK → target/debug/heliosd"

    info "Build du frontend gateway (web)..."
    npm run build --prefix "$REPO_ROOT/web" 2>&1 | tail -8
    success "frontend gateway OK → web/dist"

    info "Tests de la logique client (orion-core, sans webkit)..."
    cargo test -p orion-core 2>&1 | tail -5
    success "orion-core OK"

    info "Build du frontend client (apps/orion)..."
    (cd "$REPO_ROOT/apps/orion" && npm run build 2>&1 | tail -5)
    success "frontend client OK → apps/orion/dist"

    # Le shell Tauri (cargo build -p orion) lie webkit2gtk : tenté seulement
    # si la lib de dev est présente (sinon échec attendu, hors WSL2 minimal).
    if pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
        info "Compilation du shell Tauri orion..."
        cargo build -p orion 2>&1 | tail -5
        success "orion OK → target/debug/orion"
    else
        warn "webkit2gtk-4.1 absent → shell Tauri non compilé (cargo build -p orion sauté)."
    fi

    if $TARGET_MODE; then
        info "Compilation des features matérielles (debug)..."
        cargo build -p heliosd --features netlink,wireguard,tpm,embed-ui 2>&1 | tail -5
        success "features netlink/WireGuard/TPM/embed-ui compilées"
    fi
fi

# ── Récapitulatif ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Installation terminée.${NC}"
echo ""
echo "Prochaines étapes :"
echo "  # Daemon (dry-run) :"
echo "  HELIOS_NETWORK_CONFIG=config/network.toml cargo run -p heliosd -- run --dev"
echo ""
echo "  # Client VPN (app Tauri) :"
if $IS_WSL; then
    echo "  export DISPLAY=:0  # ou laisser WSLg gérer"
fi

echo "  cargo run -p orion"
echo ""
echo "  # UI web (dev) :"
echo "  cd web && npm run dev"
if $TARGET_MODE; then
    echo ""
    echo "  # Daemon en mode réel (machine dédiée) :"
    echo "  HELIOS_PUBLISHER_KEYRING_PATH=/chemin/keyring.json cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui"
fi
