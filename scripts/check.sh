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

echo '==> aether sans la feature de signature'
# Le workspace unifie les features : un test d'aether qui appelle une fonction
# signante sans la conditionner compile ici, et casse `cargo test -p aether`
# partout ailleurs. Ce contrôle est le seul à construire aether sans elle.
"$repo_root/scripts/wsl-cargo" test -p aether --lib

echo '==> Tests Rust, toutes les features'
"$repo_root/scripts/wsl-cargo" test --workspace --all-features
