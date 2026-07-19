#!/usr/bin/env bash
# Campagne de non-régression reproductible, exécutable localement et en CI.
# Les features noyau/TPM sont compilées et testées sans effet réel ; leur recette
# d'exécution reste sur la cible, voir docs/TESTING.md.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo '==> Formatage Rust'
cargo fmt --check

for app in web apps/orion; do
  echo "==> Dépendances verrouillées : $app"
  npm ci --prefix "$app"
  echo "==> Audit de sécurité : $app"
  npm audit --prefix "$app" --audit-level=moderate
  echo "==> Tests frontend : $app"
  npm run test:unit --prefix "$app"
  echo "==> Build frontend : $app"
  npm run build --prefix "$app"
done

echo '==> Analyse Rust, toutes les features'
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo '==> Tests Rust, toutes les features'
cargo test --workspace --all-features

echo '==> Campagne de provisioning post-quantique (dry-run)'
# Monte un daemon isolé et joue la campagne de bout en bout : c'est le seul
# point de la régression qui exerce le chemin complet client -> HTTP ->
# orchestrateur -> plan de données. Les scénarios de plan de données s'y
# déclarent hors de portée : ils exigent la cible (docs/TESTING.md).
bash "$repo_root/scripts/campaign.sh"

echo '==> Refus release du trousseau éditeur de développement'
if HELIOS_PUBLISHER_KEYRING_PATH="$repo_root/crates/aether/publisher-keyring.dev.json" \
  cargo check --release -p aether >/dev/null 2>&1; then
  echo 'ERREUR : le trousseau de développement a été accepté en release' >&2
  exit 1
fi

echo '==> Build release avec trousseau éditeur explicitement fourni'
publisher_test_dir="$(mktemp -d)"
trap 'rm -rf -- "$publisher_test_dir"' EXIT
cargo run --quiet -p helios-publisher -- keygen \
  --key-epoch 4294967295 --output-dir "$publisher_test_dir/keys"
HELIOS_PUBLISHER_KEYRING_PATH="$publisher_test_dir/keys/publisher-keyring.json" \
  cargo check --release -p aether

echo '==> Audit des dépendances Rust'
if ! command -v cargo-audit >/dev/null 2>&1; then
  echo 'cargo-audit absent : cargo install cargo-audit --locked' >&2
  exit 1
fi
cargo audit
