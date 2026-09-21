#!/usr/bin/env bash
# Vérifications rapides communes aux pull requests et à la campagne complète.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo '==> Formatage Rust'
cargo fmt --check

for app in web apps/orion; do
  echo "==> Dépendances verrouillées : $app"
  npm ci --prefix "$app"
  echo "==> Tests frontend : $app"
  npm run test:unit --prefix "$app"
  echo "==> Build frontend : $app"
  npm run build --prefix "$app"
done

echo '==> Analyse Rust, toutes les features'
"$repo_root/scripts/wsl-cargo" clippy --workspace --all-targets --all-features -- -D warnings

echo '==> Tests Rust, toutes les features'
"$repo_root/scripts/wsl-cargo" test --workspace --all-features
