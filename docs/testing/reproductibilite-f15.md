# Procès-verbal de reproductibilité du bundle passerelle (F15)

Acceptation de la promesse de la spec F15 §5.1 : des builds conteneur
indépendants du même commit donnent un bundle identique octet pour octet.

- Commit construit : `6ad5b278`
- Image de build : `helios-build:5bb81bf45afc`
- Commande : `HELIOS_PUBLISHER_KEYRING_PATH=<trousseau> CARGO_BUILD_JOBS=2 scripts/wsl-cargo xtask bundle`
- Trousseau : époque jetable 9 (`helios-publisher keygen`), public seulement
  monté dans le conteneur, non marqué `development`.

## Builds

| Build | Origine | Particularité | Durée | SHA-256 de `heliosd` |
|-------|---------|---------------|-------|----------------------|
| A | worktree `f15-repro` | volumes `helios-build-*` supprimés avant | 5 min 20 s | `c9429c46f76c9d0a638cbe36d9a67f260e18e88f237071b5f6348b4d4a12e568` |
| B | second clone, autre chemin | `TZ=Pacific/Auckland`, `umask 077`, volumes réutilisés | 4 min 13 s | `c9429c46f76c9d0a638cbe36d9a67f260e18e88f237071b5f6348b4d4a12e568` |
| C | worktree `f15-repro` | volumes supprimés à nouveau | 10 min 29 s | `c9429c46f76c9d0a638cbe36d9a67f260e18e88f237071b5f6348b4d4a12e568` |

Les durées sont celles du build complet avec `CARGO_BUILD_JOBS` plafonné par
`scripts/wsl-cargo` (1 job faute de mémoire WSL disponible).

## Résultat

Les listes `sha256sum` triées des 11 fichiers de
`target/bundle/helios-5.0.0-x86_64-unknown-linux-gnu/` (`heliosd`, `helios`,
`helios-installer`, `network.toml.example`, 7 unités `systemd/`) sont
identiques entre A, B et C.

## Écarts corrigés

Aucun : les normalisations de la spec §5.4 suffisent, aucune source d'écart
nouvelle n'a été trouvée.

## Limite

Mesure sur une seule machine (même noyau, même démon Docker). Le build B
partageait les volumes de A ; C repart de volumes neufs.
