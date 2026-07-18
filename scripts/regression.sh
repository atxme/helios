#!/usr/bin/env bash
# Campagne de non-régression reproductible, exécutable localement et en CI.
# Les tests de backends noyau (nf_tables, WireGuard, TPM) restent sur la cible :
# voir docs/TESTING.md avant une livraison matérielle.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo '==> Formatage Rust'
cargo fmt --check

echo '==> Analyse Rust'
cargo clippy --workspace --all-targets -- -D warnings

echo '==> Tests Rust'
cargo test --workspace

for app in web apps/orion; do
  echo "==> Dépendances verrouillées : $app"
  npm ci --prefix "$app"
  echo "==> Tests frontend : $app"
  npm run test:unit --prefix "$app"
  echo "==> Build frontend : $app"
  npm run build --prefix "$app"
done
