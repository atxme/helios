# Tester le projet

## Vérifications ciblées

```sh
cargo fmt --check
cargo test -p <crate>
cargo clippy -p <crate> --all-targets --all-features -- -D warnings
npm run test:unit --prefix web
npm run test:unit --prefix apps/orion
```

Pour la logique cliente portable, `cargo test -p orion-core` évite de dépendre
de l'affichage Tauri. Les tests frontend et les builds correspondants sont
définis dans les `package.json` de `web` et `apps/orion`.

## Campagne complète

```sh
bash scripts/regression.sh
```

Cette campagne exécute notamment le formatage Rust, les audits npm et Cargo,
les tests et builds frontend, Clippy et les tests Rust toutes features, puis la
campagne de provisioning en dry-run. Elle reste locale ; le workflow GitHub
sélectionne les composants modifiés et leurs dépendants, sans campagne complète
ni couverture. Le détail du découpage est dans
[`TESTING.md`](../testing/TESTING.md).

## Limites d'environnement

Les features noyau, TPM et certaines intégrations WireGuard sont compilées ou
testées sans effet matériel dans la CI. Les validations réelles doivent suivre
la matrice de [`docs/testing/TESTING.md`](../testing/TESTING.md). Ne pas déduire
une validation du noyau, du TPM, de WireGuard-NT ou de l'installation à partir
d'un test WSL2 ou dry-run.
