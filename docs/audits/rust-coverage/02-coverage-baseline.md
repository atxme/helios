# Baseline de couverture

Cette section conserve la **baseline historique avant développement**. Le nouveau collecteur COV-001/COV-002 est validé séparément dans la synthèse ; ces chiffres ne sont pas remplacés silencieusement par un changement d’algorithme de projection.

## Résultats et niveau de confiance

Révision auditée : `7ebc020d0425de4a30d64a93af1ead048c3f0fc7`, branche dédiée `audit/coverage-plan-2026-10-23`, 23 octobre 2026. Aucun changement fonctionnel ni test ajouté. Deux collectes globales instrumentées et une collecte bibliothèques ont réussi. Les **lignes et fonctions globales sont identiques sur les deux collectes** ; une région supplémentaire est exécutée au second passage dans `aether/src/private_file.rs` (68 879 puis 68 880 régions). Le résultat est reproductible sur cet hôte avec cache chaud, pas encore validé sur un environnement vierge/MSRV.

| Vue | Lignes couvertes / total | Taux | Non couvertes | Manque vers 80 % à périmètre constant |
|---|---:|---:|---:|---:|
| Globale Rust Linux, résumé LLVM brut | 46 706 / 70 663 | 66,10 % | 23 957 | 9 825 |
| Bibliothèques seules, résumé LLVM brut | 33 988 / 47 106 | 72,15 % | 13 118 | 3 697 |
| Globale Rust Linux, lignes `DA` distinctes avant retrait tests | 45 525 / 67 816 | 67,13 % | 22 291 | 8 728 |
| **Globale production Linux reconstituée**, lignes `DA` hors tests/harnais | **30 901 / 53 040** | **58,26 %** | **22 139** | **11 531** |
| Bibliothèques production reconstituées, collecte `--lib` | 22 804 / 34 883 | 65,37 % | 12 079 | 5 103 |

La vue de production reconstituée est le point de départ recommandé de la roadmap, **à ratifier dans COV-001**. Elle mesure les lignes individuelles exportées, puis retire les items de tests identifiés syntaxiquement. Elle n’est pas le résumé standard LLVM et n’est pas une couverture globale de toutes les plateformes. La vue bibliothèques ne remplace aucune des vues globales.

| Mesure brute | Globale | Bibliothèques |
|---|---:|---:|
| Fonctions | 4 471 / 6 978 = 64,07 % | 3 241 / 4 657 = 69,59 % |
| Fonctions non exécutées selon résumé | 2 507 | 1 416 |
| Régions, premier passage | 68 879 / 104 960 = 65,62 % | 49 528 / 68 181 = 72,64 % |
| Régions non couvertes | 36 081 | 18 653 |
| Branches / MC/DC | **Non mesurées** | **Non mesurées** |
| Tests réussis rapportés par les harnesses | 2 172 | 1 688 |
| Échecs / ignorés / filtrés | 0 / 0 / 0 | 0 / 0 / 0 |

Les tableaux `branches.count=0` et `mcdc.count=0` du JSON signifient absence d’instrumentation correspondante, pas 0 % ni 100 % de branches couvertes. L’aide installée propose `--branch`, `--mcdc`, `--doctests` comme options instables ; elles n’ont pas été activées. Les tableaux de fonctions JSON détaillées contiennent des instanciations/closures : ne pas assimiler leurs 14 613 entrées au total de 6 978 fonctions. La projection de production ne recalcule pas artificiellement fonctions/régions : les métriques ci-dessus restent celles du résumé brut, tests inline compris.

## Environnement exact

- Linux WSL2 `6.18.33.2-microsoft-standard-WSL2`, `x86_64-unknown-linux-gnu`.
- `rustc 1.99.0 (b940084d7 2026-09-28)`, Cargo `1.99.0 (5f94df478 2026-08-27)`, LLVM `23.1.1` fourni avec Rust.
- `cargo-llvm-cov 0.9.1` ; `cargo-machete 0.9.2` ; composants LLVM et Clippy déjà installés.
- MSRV workspace 1.95 ; CI épinglée 1.95.0, non installée dans l’inventaire de cet hôte. Aucun téléchargement ni changement de toolchain effectué.
- SHA-256 `Cargo.lock` : `bad8f47642d52aef834882c71871052f9dc02e2c6f9198e1e87cfa0bf58dc28b`.
- Features : toutes les features du workspace, dont les backends optionnels, la signature de fixtures et `aether/fuzzing` ; debug/test, pas release ; aucun ajout de filtre d’exclusion de production.
- Cache unique contrôlé par `scripts/wsl-cargo` : `~/.cache/helios-target` (sous-répertoire d’instrumentation géré par llvm-cov). Totaux du garde-fou : 50,9 Gio avant première collecte, 56,6 après ; 55,6 après libs ; 58,7 après répétition. Aucun dépassement de 65 Gio ni nettoyage manuel ni second cache demandé.

Les commandes de build et tests ont été annoncées puis exécutées avec l’autorisation d’écriture au cache hors workspace, sans réseau Cargo (`--frozen`). Les sockets locales de tests ont été autorisées. Aucun service externe, modification nftables, commande privilégiée système ou interaction TPM/FIDO matériel n’a été lancé. La création de branche a exigé l’autorisation d’écriture des métadonnées Git. Le wrapper a d’abord refusé une commande metadata en sandbox sur son fichier de verrou ; l’inventaire a ensuite été obtenu directement en lecture seule avec `cargo metadata --frozen --no-deps`.

## Commandes réellement exécutées et artefacts

```sh
rustc -Vv
cargo -V
cargo llvm-cov --version
cargo machete --version
rustup component list --installed
rustup toolchain list
cargo metadata --frozen --no-deps --format-version 1 > /tmp/helios-audit-metadata.json
scripts/wsl-cargo llvm-cov --workspace --all-features --frozen --json --output-path /tmp/helios-audit-workspace-coverage.json --quiet > /tmp/helios-audit-coverage.log 2>&1
CARGO_NET_OFFLINE=true scripts/wsl-cargo llvm-cov report --html --output-dir /tmp/helios-audit-rust-html > /tmp/helios-audit-html.log 2>&1
CARGO_NET_OFFLINE=true scripts/wsl-cargo llvm-cov report --lcov --output-path /tmp/helios-audit-workspace.lcov > /tmp/helios-audit-lcov.log 2>&1
scripts/wsl-cargo llvm-cov --workspace --all-features --lib --frozen --json --output-path /tmp/helios-audit-libraries-coverage.json > /tmp/helios-audit-libraries.log 2>&1
CARGO_NET_OFFLINE=true scripts/wsl-cargo llvm-cov report --lcov --output-path /tmp/helios-audit-libraries.lcov > /tmp/helios-audit-libraries-lcov.log 2>&1
scripts/wsl-cargo clippy --workspace --all-targets --all-features --frozen -- -D warnings > /tmp/helios-audit-clippy.log 2>&1
scripts/wsl-cargo llvm-cov --workspace --all-features --frozen --json --output-path /tmp/helios-audit-workspace-repeat.json > /tmp/helios-audit-repeat.log 2>&1
cargo machete --skip-target-dir crates tools apps/orion/src-tauri
```

Clippy a réussi sans avertissement ; il couvre ici la compilation toutes cibles/features sur Linux, pas Windows/MSRV. `cargo check --workspace --all-targets` n’a pas été relancé séparément : cette compilation est déjà incluse dans Clippy. Les deux premiers essais d’export `report --all-features` ont échoué sur option non acceptée par le sous-commande ; les exports ont ensuite réussi **sans** cette option. Aucun de ces échecs d’export n’a été interprété comme résultat de tests.

Rapport HTML local : `/tmp/helios-audit-rust-html/html/index.html`. Les JSON, LCOV et journaux restent dans `/tmp`, non versionnés. Les résultats essentiels sont conservés dans les tableaux de ce document ; archiver les artefacts dans un emplacement local durable est une tâche des scripts proposés, pas un commit de fichiers générés. La deuxième collecte contient la liste nominative de tous les tests exécutés dans `/tmp/helios-audit-repeat.log`.

## Périmètre réel de la commande existante

`scripts/coverage.sh:26` lance `cargo llvm-cov --workspace --all-features --json ... --quiet`. Il mesure les packages et cibles testables par défaut, incluant les binaires et tests d’intégration, sur l’hôte. `--lib` restreint aux tests unitaires des bibliothèques et perd les sous-processus CLI, binaires et intégrations. `--all-targets` ajouterait exemples/benches ; ce n’est pas une commande « tous scénarios système ». Aucun exemple/bench Cargo n’a été identifié par metadata dans les 23 packages actuels. Les doc-tests demandent le mode d’instrumentation instable dédié ; aucun doc-test n’a été exécuté par ces collectes llvm-cov.

Le script exporte ensuite HTML, lance la couverture **UI Orion**, puis un résumé Helios/Orion ; il ne produit pas de LCOV et ne couvre pas l’UI `web`. Il ne fige ni version Rust/llvm-cov ni lockfile par `--locked`. Il source le budget WSL mais n’utilise pas son contrôle de fin/verrou comme le wrapper. Nous avons exécuté la partie Rust via le wrapper avec `--frozen`, pas le script entier : aucun npm install/test/UI n’a été lancé. Le périmètre principal de la mission est Rust ; les interfaces JS restent des indicateurs distincts.

## Projection des lignes de production et exclusions justifiées

**Fait de mesure** : le résumé global JSON et les sommes `LF/LH` du LCOV valent 70 663/46 706, alors que les entrées individuelles `DA` valent 67 816/45 525. Le tableau HTML détaillé d’`apps/orion/src-tauri/src/astra.rs` confirme 367 lignes individuelles, contre 404 dans son résumé. L’écart global est de **2 847 lignes comptées et 1 181 couvertes**. La cause exacte (agrégation/instanciations ou outillage) n’a pas été démontrée ; ne pas attribuer arbitrairement ces lignes à du code mort. COV-001 devra trancher la sémantique du gate.

**Autre fait** : des régions de `astra/src/recovery.rs` après `:739`, `orion-core/src/certificate_recovery.rs` après `:599` et `aether/src/state.rs` dans `mod tests` ont des compteurs. Exclure uniquement les fichiers nommés `tests.rs` ne retire donc pas les tests inline.

La projection part des **lignes `DA` distinctes** puis retire 14 776 lignes, dont 14 624 exécutées, déterminées par :

1. AST Rust obtenu par `rust-analyzer parse --json` (outil déjà installé), sans exécuter les builds ni macros ; items annotés test ou `cfg` inactifs pour production Linux, `test=false`, toutes features, x86_64/gnu/64/little/unix.
2. Les configurations inconnues sont conservées, jamais exclues silencieusement ; aucune exception pour production non couverte.
3. Trois fichiers entiers de harnais/fixtures : `aether/src/fuzzing.rs` (déclaration `aether/src/lib.rs:24`), `astra-operator/src/vault/tests_support.rs` (`vault.rs:994`), `orion-core/src/test_domain.rs` (`lib.rs:43`). Ces fichiers ne sont pas du code livré pertinent ; leur retrait ne doit pas permettre d’exclure les validateurs qu’ils appellent.

Cette projection **fait baisser** le taux de 67,13 à 58,26 % et retire seulement 152 lignes non exécutées. Elle n’a nécessité aucun `cfg(coverage)` dans les sources, aucune modification de code et aucune exclusion d’un backend difficile. Les bornes AST sont inclusives au niveau ligne ; les macros ne sont pas développées. C’est une reconstitution vérifiable, à revoir et à figer avant contrôle local automatisé, pas un certificat d’exhaustivité du code livré. Le dénominateur de production Windows reste inconnu ici ; son absence ne vaut ni exclusion métier ni réussite.

Les retraits par fichier sont chiffrés dans le tableau intégral ci-dessous. Les fonctions/régions projetées ne sont pas publiées faute de définition indépendante revue pour closures/instanciations. Les chiffres bruts restent disponibles.

## Collecte effective par cible

Les lignes ci-dessous viennent du second journal, chaque résumé à zéro échec/ignoré/filtré. Les tests d’intégration qui lancent un binaire ne sont pas des simples tests de bibliothèque. Les six essais TPM apparaissent « réussis » mais leurs corps matériels quittent si `HELIOS_TPM_MATERIEL` manque ; `tpm_real.rs` reste sans exécution. **2 172 succès de harness ne signifie donc pas 2 172 scénarios matériels exercés.**

| Exécutable de test | Type/cible | Tests réussis |
|---|---|---:|
| `aether-44cc9c03e10dfbfa` | `unittests src/lib.rs` | 487 |
| `aether_fido-3e4f7ea7adb6ff59` | `unittests src/lib.rs` | 6 |
| `aether_key_negotiation-d152cf45994030e1` | `unittests src/lib.rs` | 27 |
| `aether_vault-104cc75d52131c31` | `unittests src/lib.rs` | 39 |
| `astra-3e8c9e7d6514d445` | `unittests src/lib.rs` | 142 |
| `astra-15ca04f9b9b510e2` | `unittests src/main.rs` | 0 |
| `cli-89e066de9111ed4d` | `tests/cli.rs` | 7 |
| `private_channel-c2d4234ba2ac2111` | `tests/private_channel.rs` | 6 |
| `astra_channel-59897e4c00c011f2` | `unittests src/lib.rs` | 14 |
| `astra_operator-f9224385dd1fdb96` | `unittests src/lib.rs` | 60 |
| `enrolment-0aaf77d4514d7738` | `tests/enrolment.rs` | 7 |
| `signing-dfc1e7a60895a7ed` | `tests/signing.rs` | 14 |
| `tunnel-26491e6dd0978553` | `tests/tunnel.rs` | 8 |
| `astra_signer-e2f22232c599711e` | `unittests src/main.rs` | 2 |
| `helios-1f532ef11e289ebc` | `unittests src/main.rs` | 134 |
| `helios_api-5808dc9a9ec8edfe` | `unittests src/lib.rs` | 98 |
| `helios_astra_helper-9aa1118e076b0b10` | `unittests src/main.rs` | 15 |
| `helios_escrow-160764ff662c9118` | `unittests src/lib.rs` | 8 |
| `helios_firewall-529f850850cf7e7f` | `unittests src/lib.rs` | 128 |
| `helios_installer-208d646b81ff78d9` | `unittests src/main.rs` | 5 |
| `helios_provisioning-83dd26c873556b19` | `unittests src/lib.rs` | 117 |
| `helios_publisher-56a4191a59f1421e` | `unittests src/main.rs` | 0 |
| `cli_security-af47ddfb3f77db7f` | `tests/cli_security.rs` | 4 |
| `helios_tpm-6b3df2fd75b87758` | `unittests src/lib.rs` | 55 |
| `materiel-8a7464f5d168e603` | `tests/materiel.rs` | 6 |
| `helios_update-7ed89ea6c45a01e5` | `unittests src/lib.rs` | 23 |
| `helios_wireguard-5d15e5531689f808` | `unittests src/lib.rs` | 18 |
| `heliosd-3061f39d8a1aa1f7` | `unittests src/main.rs` | 218 |
| `orion-f27ee5303be65f72` | `unittests src/main.rs` | 44 |
| `orion_core-0fae31b46aba3a17` | `unittests src/lib.rs` | 464 |
| `xtask-3a74ccaa41cb2504` | `unittests src/lib.rs` | 2 |
| `xtask-5e6ae3dcd5b4ad36` | `unittests src/main.rs` | 14 |

## Couverture par crate

LLVM = résumé brut ; Prod = lignes `DA` de production reconstituées. Les marges/non-couvertes ne s’additionnent qu’à l’intérieur d’une même vue. Toutes les fonctions/régions ci-dessous sont brutes.

| Crate | Lignes LLVM couvertes/total | Taux | Fonctions | Régions | Prod couvertes/total | Taux prod | Prod non couvertes |
|---|---:|---:|---:|---:|---:|---:|---:|
| `aether` | 10019/11367 | 88.14 % | 960/1022 | 13838/15499 | 7943/9162 | 86.70 % | 1219 |
| `aether-fido` | 188/577 | 32.58 % | 13/43 | 253/711 | 183/553 | 33.09 % | 370 |
| `aether-key-negotiation` | 670/865 | 77.46 % | 61/81 | 910/1185 | 651/828 | 78.62 % | 177 |
| `aether-vault` | 212/216 | 98.15 % | 16/17 | 355/375 | 212/216 | 98.15 % | 4 |
| `astra` | 3242/6967 | 46.53 % | 245/541 | 4214/9503 | 2215/5763 | 38.43 % | 3548 |
| `astra-channel` | 396/750 | 52.80 % | 53/124 | 491/952 | 383/692 | 55.35 % | 309 |
| `astra-operator` | 2216/3755 | 59.01 % | 181/326 | 3157/5492 | 1671/3108 | 53.76 % | 1437 |
| `astra-signer` | 10/2330 | 0.43 % | 2/110 | 13/3757 | 10/2267 | 0.44 % | 2257 |
| `helios` | 5305/8103 | 65.47 % | 501/780 | 8896/13754 | 3000/5620 | 53.38 % | 2620 |
| `helios-api` | 2285/3107 | 73.54 % | 257/353 | 3078/4201 | 1300/2054 | 63.29 % | 754 |
| `helios-astra-helper` | 273/531 | 51.41 % | 31/45 | 422/869 | 106/356 | 29.78 % | 250 |
| `helios-escrow` | 154/164 | 93.90 % | 14/17 | 324/341 | 89/94 | 94.68 % | 5 |
| `helios-firewall` | 2086/2169 | 96.17 % | 164/179 | 2805/2963 | 1292/1368 | 94.44 % | 76 |
| `helios-installer` | 169/287 | 58.89 % | 16/28 | 235/434 | 63/175 | 36.00 % | 112 |
| `helios-provisioning` | 1961/2178 | 90.04 % | 160/182 | 3078/3386 | 1126/1320 | 85.30 % | 194 |
| `helios-publisher` | 297/411 | 72.26 % | 23/43 | 414/625 | 288/383 | 75.20 % | 95 |
| `helios-tpm` | 1555/2405 | 64.66 % | 166/320 | 3001/4596 | 652/1368 | 47.66 % | 716 |
| `helios-update` | 1071/1237 | 86.58 % | 90/120 | 1977/2284 | 624/763 | 81.78 % | 139 |
| `helios-wireguard` | 411/469 | 87.63 % | 65/89 | 608/703 | 142/193 | 73.58 % | 51 |
| `heliosd` | 3881/7385 | 52.55 % | 410/749 | 5745/10837 | 2390/5640 | 42.38 % | 3250 |
| `orion` | 565/2550 | 22.16 % | 74/404 | 850/3573 | 281/2065 | 13.61 % | 1784 |
| `orion-core` | 9432/12065 | 78.18 % | 929/1299 | 13783/17696 | 6215/8568 | 72.54 % | 2353 |
| `xtask` | 308/775 | 39.74 % | 40/106 | 432/1224 | 65/484 | 13.43 % | 419 |

## Vue bibliothèques par crate

Cette collecte exécute seulement 16 cibles lib ; les autres packages sont **hors de cette vue**, pas couverts à zéro ni réputés inutiles. L’absence des appels inter-crates depuis les tests de binaires explique certaines baisses de couverture par rapport au global. Une application exécutée par campagne externe n’est pas ajoutée automatiquement.

| Crate | Lignes LLVM | Taux | Fonctions | Régions | Prod DA couvertes/total |
|---|---:|---:|---:|---:|---:|
| `aether` | 9946/11367 | 87.50 % | 951/1022 | 13760/15499 | 7864/9162 |
| `aether-fido` | 85/577 | 14.73 % | 7/43 | 149/711 | 83/553 |
| `aether-key-negotiation` | 656/865 | 75.84 % | 60/81 | 895/1185 | 637/828 |
| `aether-vault` | 209/216 | 96.76 % | 15/17 | 352/375 | 209/216 |
| `astra` | 2933/5590 | 52.47 % | 227/449 | 3798/7450 | 1906/4442 |
| `astra-channel` | 271/750 | 36.13 % | 36/124 | 318/952 | 265/692 |
| `astra-operator` | 1224/3755 | 32.60 % | 122/326 | 1954/5492 | 697/3108 |
| `helios-api` | 2285/3107 | 73.54 % | 257/353 | 3078/4201 | 1300/2054 |
| `helios-escrow` | 154/164 | 93.90 % | 14/17 | 324/341 | 89/94 |
| `helios-firewall` | 2086/2169 | 96.17 % | 164/179 | 2805/2963 | 1292/1368 |
| `helios-provisioning` | 1961/2178 | 90.04 % | 160/182 | 3078/3386 | 1125/1320 |
| `helios-tpm` | 1540/2405 | 64.03 % | 165/320 | 2979/4596 | 636/1368 |
| `helios-update` | 1056/1237 | 85.37 % | 87/120 | 1955/2284 | 610/763 |
| `helios-wireguard` | 392/469 | 83.58 % | 62/89 | 599/703 | 123/193 |
| `orion-core` | 9164/12065 | 75.96 % | 909/1299 | 13448/17696 | 5954/8568 |
| `xtask` | 26/192 | 13.54 % | 5/36 | 36/347 | 14/154 |

## Calcul des paliers

Pour une vue donnée de taille `N`, couverture courante `C` et seuil `p` : `gain_requis = max(0, ceil(p × N) − C)`. Ne pas utiliser une somme de pourcentages, ni la moyenne non pondérée des crates.

| Palier | Global brut N=70 663, C=46 706 | Production DA N=53 040, C=30 901 |
|---|---:|---:|
| 70 % | 2 759 | 6 227 |
| 75 % | 6 292 | 8 879 |
| 80 % | 9 825 | 11 531 |

Ces nombres sont des **lignes actuellement non couvertes à couvrir**, pas des lignes de tests à écrire. Ajouter/refactoriser/supprimer du code change `N` ; recalculer ensuite et publier séparément l’effet de dénominateur. Les gains de la roadmap sont des estimations de chemins utiles, jamais une garantie.

## Limitations et reproduction sur environnement propre

Non exécutés : couverture Windows et branches/MC/DC, doc-tests instrumentés, MSRV 1.95, npm/UI, `scripts/regression.sh`, campagne système/FIDO/TPM/installation réelle, second hôte WG. La régression complète aurait déclenché réseau, installations npm et campagnes ; cet audit documentaire ne revendique pas de sûreté de régression globale.

Pour reproduire hors de cet hôte : provisionner explicitement Rust 1.99.0 + LLVM/Clippy et llvm-cov 0.9.1, dépendances natives TSS/HID/WebKitGTK et prérequis frontend `embed-ui`, récupérer les dépendances verrouillées et construire `web` si nécessaire. Ces étapes **modifient l’environnement et peuvent utiliser réseau/privilèges** : les identifier avant exécution. Vérifier SHA et lockfile, isoler variables de configuration/compte, conserver les limites Cargo, puis reprendre les commandes Rust ci-dessus. Une version MSRV constitue une campagne distincte à comparer, sans prétendre avoir obtenu les chiffres 1.99 avec 1.95.

Les exports HTML/LCOV doivent précéder la collecte `--lib` suivante, car llvm-cov nettoie les profils entre campagnes par défaut. Éviter `--no-clean` et la fusion implicite d’anciens profils pour « reproduire ». Ne pas exporter un rapport global depuis les profils libs et le nommer global. Les essais d’audit n’ont nettoyé aucun cache via `cargo clean` ni `scripts/clean-wsl-targets`.

## Couverture intégrale par fichier

336 fichiers présents dans le rapport global, triés par chemin. `Retrait tests` = couvertes/total retirées de la vue `DA`, **pas** soustraction au résumé LLVM. Un `0/0` projeté identifie un fichier purement fixture/harnais, pas une exclusion de code de production. Les fichiers absents pour `cfg` ou sans région instrumentée ne sont pas inventés comme lignes à zéro.

| Fichier | Lignes LLVM | % LLVM | Prod DA | Non couvertes prod | Retrait tests DA | Fonctions LLVM | Régions LLVM |
|---|---:|---:|---:|---:|---:|---:|---:|
| `apps/orion/src-tauri/src/astra.rs` | 258/404 | 63.86 % | 98/223 | 125 | 143/144 | 27/50 | 398/603 |
| `apps/orion/src-tauri/src/commands/app.rs` | 19/108 | 17.59 % | 18/95 | 77 | 0/0 | 3/24 | 30/144 |
| `apps/orion/src-tauri/src/commands/ceremonies.rs` | 0/96 | 0.00 % | 0/86 | 86 | 0/0 | 0/29 | 0/99 |
| `apps/orion/src-tauri/src/commands/certificates.rs` | 0/542 | 0.00 % | 0/487 | 487 | 0/0 | 0/82 | 0/696 |
| `apps/orion/src-tauri/src/commands/connection.rs` | 0/190 | 0.00 % | 0/174 | 174 | 0/0 | 0/26 | 0/311 |
| `apps/orion/src-tauri/src/commands/profiles.rs` | 81/448 | 18.08 % | 79/406 | 327 | 0/0 | 6/81 | 113/607 |
| `apps/orion/src-tauri/src/companion.rs` | 23/79 | 29.11 % | 9/57 | 48 | 14/14 | 2/14 | 24/103 |
| `apps/orion/src-tauri/src/main.rs` | 24/279 | 8.60 % | 20/260 | 240 | 0/0 | 6/35 | 34/427 |
| `apps/orion/src-tauri/src/operator.rs` | 91/325 | 28.00 % | 31/241 | 210 | 51/51 | 15/46 | 121/442 |
| `apps/orion/src-tauri/src/tray.rs` | 69/79 | 87.34 % | 26/36 | 10 | 41/41 | 15/17 | 130/141 |
| `crates/aether-fido/src/authenticator.rs` | 85/464 | 18.32 % | 83/445 | 362 | 0/0 | 7/36 | 149/598 |
| `crates/aether-fido/src/lib.rs` | 103/113 | 91.15 % | 100/108 | 8 | 0/0 | 6/7 | 104/113 |
| `crates/aether-key-negotiation/src/client.rs` | 139/177 | 78.53 % | 133/168 | 35 | 0/0 | 10/13 | 133/188 |
| `crates/aether-key-negotiation/src/endpoint.rs` | 152/176 | 86.36 % | 152/168 | 16 | 0/0 | 12/20 | 245/310 |
| `crates/aether-key-negotiation/src/framing.rs` | 37/47 | 78.72 % | 34/43 | 9 | 0/0 | 5/7 | 47/66 |
| `crates/aether-key-negotiation/src/identity.rs` | 34/42 | 80.95 % | 34/40 | 6 | 0/0 | 6/9 | 44/56 |
| `crates/aether-key-negotiation/src/rate_limit.rs` | 24/25 | 96.00 % | 23/24 | 1 | 0/0 | 4/4 | 33/34 |
| `crates/aether-key-negotiation/src/server.rs` | 239/350 | 68.29 % | 232/339 | 107 | 0/0 | 15/19 | 355/474 |
| `crates/aether-key-negotiation/src/transaction.rs` | 45/48 | 93.75 % | 43/46 | 3 | 0/0 | 9/9 | 53/57 |
| `crates/aether-vault/src/lib.rs` | 212/216 | 98.15 % | 212/216 | 4 | 0/0 | 16/17 | 355/375 |
| `crates/aether/src/certificates/approval/campaign.rs` | 49/51 | 96.08 % | 49/51 | 2 | 0/0 | 2/2 | 40/42 |
| `crates/aether/src/certificates/approval/credentials.rs` | 164/198 | 82.83 % | 165/196 | 31 | 0/0 | 12/12 | 177/197 |
| `crates/aether/src/certificates/approval/mod.rs` | 12/12 | 100.00 % | 12/12 | 0 | 0/0 | 2/2 | 16/16 |
| `crates/aether/src/certificates/approval/policy.rs` | 161/170 | 94.71 % | 160/169 | 9 | 0/0 | 14/15 | 152/166 |
| `crates/aether/src/certificates/approval/recovery.rs` | 80/85 | 94.12 % | 78/83 | 5 | 0/0 | 6/6 | 74/78 |
| `crates/aether/src/certificates/approval/renewal.rs` | 213/285 | 74.74 % | 215/284 | 69 | 0/0 | 13/14 | 235/282 |
| `crates/aether/src/certificates/approval/signing.rs` | 12/12 | 100.00 % | 12/12 | 0 | 0/0 | 3/3 | 21/24 |
| `crates/aether/src/certificates/authority.rs` | 325/416 | 78.12 % | 325/416 | 91 | 0/0 | 20/24 | 380/483 |
| `crates/aether/src/certificates/capability.rs` | 364/372 | 97.85 % | 199/207 | 8 | 163/163 | 32/32 | 609/645 |
| `crates/aether/src/certificates/client/commit.rs` | 72/89 | 80.90 % | 72/89 | 17 | 0/0 | 3/3 | 76/86 |
| `crates/aether/src/certificates/client/grant.rs` | 262/417 | 62.83 % | 260/414 | 154 | 0/0 | 9/12 | 239/393 |
| `crates/aether/src/certificates/client/mod.rs` | 53/55 | 96.36 % | 53/55 | 2 | 0/0 | 6/6 | 53/55 |
| `crates/aether/src/certificates/client/recovery.rs` | 104/129 | 80.62 % | 102/127 | 25 | 0/0 | 6/7 | 125/143 |
| `crates/aether/src/certificates/client/request.rs` | 73/90 | 81.11 % | 73/90 | 17 | 0/0 | 3/3 | 84/93 |
| `crates/aether/src/certificates/client/signing.rs` | 42/42 | 100.00 % | 42/42 | 0 | 0/0 | 6/6 | 65/76 |
| `crates/aether/src/certificates/client/stage.rs` | 306/357 | 85.71 % | 303/354 | 51 | 0/0 | 12/12 | 322/368 |
| `crates/aether/src/certificates/encoding.rs` | 433/458 | 94.54 % | 313/338 | 25 | 116/116 | 82/89 | 763/834 |
| `crates/aether/src/certificates/gateway.rs` | 280/347 | 80.69 % | 280/346 | 66 | 0/0 | 18/22 | 324/402 |
| `crates/aether/src/certificates/mod.rs` | 51/51 | 100.00 % | 51/51 | 0 | 0/0 | 2/2 | 121/121 |
| `crates/aether/src/certificates/operator_ipc.rs` | 16/40 | 40.00 % | 3/27 | 24 | 13/13 | 3/6 | 30/55 |
| `crates/aether/src/certificates/operator_session.rs` | 212/220 | 96.36 % | 63/71 | 8 | 149/149 | 21/21 | 278/289 |
| `crates/aether/src/certificates/revocation.rs` | 177/187 | 94.65 % | 89/98 | 9 | 87/87 | 16/17 | 318/337 |
| `crates/aether/src/certificates/state/astra.rs` | 59/154 | 38.31 % | 63/151 | 88 | 0/0 | 6/10 | 76/172 |
| `crates/aether/src/certificates/state/client_identity.rs` | 314/377 | 83.29 % | 313/376 | 63 | 0/0 | 19/19 | 349/425 |
| `crates/aether/src/certificates/state/gateway_identity.rs` | 373/389 | 95.89 % | 366/381 | 15 | 0/0 | 25/26 | 436/469 |
| `crates/aether/src/certificates/state/ledger.rs` | 251/292 | 85.96 % | 243/282 | 39 | 0/0 | 21/23 | 290/339 |
| `crates/aether/src/certificates/state/revocation_schedule.rs` | 12/12 | 100.00 % | 10/10 | 0 | 0/0 | 4/4 | 16/16 |
| `crates/aether/src/certificates/status/campaign.rs` | 299/331 | 90.33 % | 298/322 | 24 | 0/0 | 27/27 | 294/319 |
| `crates/aether/src/certificates/status/campaign_approval.rs` | 58/62 | 93.55 % | 57/61 | 4 | 0/0 | 3/3 | 64/70 |
| `crates/aether/src/certificates/status/certificate_status.rs` | 106/125 | 84.80 % | 106/125 | 19 | 0/0 | 8/9 | 104/118 |
| `crates/aether/src/certificates/status/rollback.rs` | 51/59 | 86.44 % | 51/59 | 8 | 0/0 | 3/3 | 51/57 |
| `crates/aether/src/certificates/status/signer.rs` | 79/128 | 61.72 % | 78/127 | 49 | 0/0 | 3/5 | 111/157 |
| `crates/aether/src/certificates/status/signing.rs` | 8/12 | 66.67 % | 8/12 | 4 | 0/0 | 2/3 | 14/24 |
| `crates/aether/src/certificates/transport.rs` | 420/481 | 87.32 % | 418/479 | 61 | 0/0 | 30/31 | 525/617 |
| `crates/aether/src/certificates/webauthn.rs` | 425/444 | 95.72 % | 221/239 | 18 | 202/202 | 38/39 | 657/723 |
| `crates/aether/src/certificates/window.rs` | 252/256 | 98.44 % | 162/166 | 4 | 88/88 | 29/30 | 340/365 |
| `crates/aether/src/certificates/x509.rs` | 437/452 | 96.68 % | 236/251 | 15 | 195/195 | 35/35 | 806/836 |
| `crates/aether/src/config.rs` | 588/678 | 86.73 % | 575/654 | 79 | 0/0 | 59/65 | 762/828 |
| `crates/aether/src/display_time.rs` | 51/54 | 94.44 % | 32/35 | 3 | 19/19 | 6/6 | 91/100 |
| `crates/aether/src/enroll.rs` | 163/163 | 100.00 % | 54/54 | 0 | 109/109 | 15/15 | 291/296 |
| `crates/aether/src/events.rs` | 30/30 | 100.00 % | 0/0 | 0 | 30/30 | 1/1 | 33/33 |
| `crates/aether/src/fuzzing.rs` | 161/210 | 76.67 % | 0/0 | 0 | 161/209 | 12/14 | 228/294 |
| `crates/aether/src/key_negotiation/authentication.rs` | 243/260 | 93.46 % | 243/258 | 15 | 0/0 | 16/17 | 321/364 |
| `crates/aether/src/key_negotiation/derivation.rs` | 90/91 | 98.90 % | 90/91 | 1 | 0/0 | 5/5 | 155/162 |
| `crates/aether/src/key_negotiation/messages.rs` | 378/429 | 88.11 % | 367/418 | 51 | 0/0 | 29/29 | 382/435 |
| `crates/aether/src/key_negotiation/mod.rs` | 43/44 | 97.73 % | 42/42 | 0 | 0/0 | 8/9 | 59/63 |
| `crates/aether/src/locked.rs` | 119/125 | 95.20 % | 69/74 | 5 | 49/50 | 21/21 | 192/196 |
| `crates/aether/src/ml_dsa.rs` | 164/164 | 100.00 % | 70/70 | 0 | 93/93 | 21/21 | 367/373 |
| `crates/aether/src/mtu.rs` | 72/72 | 100.00 % | 17/17 | 0 | 54/54 | 18/18 | 125/125 |
| `crates/aether/src/net.rs` | 155/155 | 100.00 % | 150/150 | 0 | 0/0 | 29/29 | 224/225 |
| `crates/aether/src/policy.rs` | 3/3 | 100.00 % | 3/3 | 0 | 0/0 | 1/1 | 4/4 |
| `crates/aether/src/pq.rs` | 62/62 | 100.00 % | 32/32 | 0 | 30/30 | 9/9 | 130/140 |
| `crates/aether/src/private_file.rs` | 162/170 | 95.29 % | 56/60 | 4 | 101/101 | 21/23 | 318/339 |
| `crates/aether/src/random.rs` | 191/236 | 80.93 % | 95/112 | 17 | 86/113 | 34/42 | 278/337 |
| `crates/aether/src/secret.rs` | 104/104 | 100.00 % | 40/40 | 0 | 62/62 | 21/21 | 164/164 |
| `crates/aether/src/secret/json.rs` | 76/80 | 95.00 % | 53/56 | 3 | 24/24 | 11/12 | 138/150 |
| `crates/aether/src/sig.rs` | 318/333 | 95.50 % | 310/322 | 12 | 0/0 | 38/40 | 478/507 |
| `crates/aether/src/speedtest.rs` | 100/102 | 98.04 % | 43/44 | 1 | 56/56 | 15/15 | 180/182 |
| `crates/aether/src/state.rs` | 72/76 | 94.74 % | 28/32 | 4 | 44/44 | 12/12 | 122/126 |
| `crates/aether/src/wg.rs` | 69/69 | 100.00 % | 25/25 | 0 | 42/42 | 14/14 | 161/164 |
| `crates/astra-channel/src/authority_client.rs` | 15/191 | 7.85 % | 15/174 | 159 | 0/0 | 3/34 | 19/180 |
| `crates/astra-channel/src/authority_routes.rs` | 0/5 | 0.00 % | 0/5 | 5 | 0/0 | 0/1 | 0/9 |
| `crates/astra-channel/src/gateway_client.rs` | 15/89 | 16.85 % | 14/74 | 60 | 0/0 | 3/24 | 22/138 |
| `crates/astra-channel/src/gateway_routes.rs` | 72/129 | 55.81 % | 68/121 | 53 | 0/0 | 14/20 | 94/205 |
| `crates/astra-channel/src/transport.rs` | 294/336 | 87.50 % | 286/318 | 32 | 0/0 | 33/45 | 356/420 |
| `crates/astra-operator/src/campaign.rs` | 25/53 | 47.17 % | 7/35 | 28 | 18/18 | 3/7 | 41/86 |
| `crates/astra-operator/src/credentials.rs` | 91/122 | 74.59 % | 26/51 | 25 | 65/65 | 9/18 | 152/203 |
| `crates/astra-operator/src/documents.rs` | 48/53 | 90.57 % | 20/21 | 1 | 27/27 | 7/11 | 110/127 |
| `crates/astra-operator/src/gestures.rs` | 141/150 | 94.00 % | 125/132 | 7 | 15/15 | 11/13 | 181/201 |
| `crates/astra-operator/src/handoff.rs` | 109/178 | 61.24 % | 49/108 | 59 | 59/59 | 12/24 | 213/330 |
| `crates/astra-operator/src/operations.rs` | 21/34 | 61.76 % | 9/22 | 13 | 12/12 | 2/3 | 46/53 |
| `crates/astra-operator/src/operations/campaign.rs` | 0/103 | 0.00 % | 0/100 | 100 | 0/0 | 0/10 | 0/155 |
| `crates/astra-operator/src/operations/recovery.rs` | 22/179 | 12.29 % | 0/147 | 147 | 22/22 | 2/14 | 33/247 |
| `crates/astra-operator/src/origin.rs` | 229/384 | 59.64 % | 80/233 | 153 | 146/146 | 19/31 | 354/570 |
| `crates/astra-operator/src/orion.rs` | 43/468 | 9.19 % | 17/436 | 419 | 25/25 | 5/27 | 91/820 |
| `crates/astra-operator/src/prepared.rs` | 72/81 | 88.89 % | 29/32 | 3 | 43/43 | 7/13 | 115/142 |
| `crates/astra-operator/src/signing/anchor.rs` | 87/98 | 88.78 % | 86/96 | 10 | 0/0 | 2/2 | 101/116 |
| `crates/astra-operator/src/signing/bindings.rs` | 137/145 | 94.48 % | 132/139 | 7 | 0/0 | 9/10 | 158/177 |
| `crates/astra-operator/src/signing/ca_tls.rs` | 36/129 | 27.91 % | 35/120 | 85 | 0/0 | 2/11 | 52/191 |
| `crates/astra-operator/src/signing/campaign.rs` | 160/200 | 80.00 % | 154/192 | 38 | 0/0 | 15/16 | 177/205 |
| `crates/astra-operator/src/signing/gateway.rs` | 38/188 | 20.21 % | 37/182 | 145 | 0/0 | 2/10 | 42/209 |
| `crates/astra-operator/src/signing/issuer.rs` | 87/107 | 81.31 % | 86/102 | 16 | 0/0 | 2/6 | 121/151 |
| `crates/astra-operator/src/signing/mod.rs` | 29/32 | 90.62 % | 29/29 | 0 | 0/0 | 5/8 | 42/49 |
| `crates/astra-operator/src/signing/recovery.rs` | 147/227 | 64.76 % | 145/215 | 70 | 0/0 | 3/10 | 177/267 |
| `crates/astra-operator/src/signing/revocation.rs` | 37/41 | 90.24 % | 36/40 | 4 | 0/0 | 2/2 | 43/49 |
| `crates/astra-operator/src/store.rs` | 68/85 | 80.00 % | 26/38 | 12 | 42/42 | 7/13 | 132/166 |
| `crates/astra-operator/src/tunnel.rs` | 130/208 | 62.50 % | 130/202 | 72 | 0/0 | 9/13 | 153/285 |
| `crates/astra-operator/src/vault.rs` | 422/453 | 93.16 % | 413/436 | 23 | 0/0 | 40/48 | 578/648 |
| `crates/astra-operator/src/vault/tests_support.rs` | 37/37 | 100.00 % | 0/0 | 0 | 37/37 | 6/6 | 45/45 |
| `crates/astra/src/audit.rs` | 175/181 | 96.69 % | 85/91 | 6 | 87/87 | 18/18 | 252/259 |
| `crates/astra/src/campaign_deposit.rs` | 0/129 | 0.00 % | 0/118 | 118 | 0/0 | 0/14 | 0/198 |
| `crates/astra/src/chain.rs` | 229/261 | 87.74 % | 111/141 | 30 | 116/117 | 19/21 | 284/321 |
| `crates/astra/src/commands/campaign.rs` | 0/80 | 0.00 % | 0/79 | 79 | 0/0 | 0/6 | 0/87 |
| `crates/astra/src/commands/chain.rs` | 0/193 | 0.00 % | 0/185 | 185 | 0/0 | 0/16 | 0/312 |
| `crates/astra/src/commands/gateway_identity.rs` | 0/90 | 0.00 % | 0/87 | 87 | 0/0 | 0/5 | 0/122 |
| `crates/astra/src/commands/issuer.rs` | 60/145 | 41.38 % | 60/141 | 81 | 0/0 | 2/6 | 90/222 |
| `crates/astra/src/commands/revocation.rs` | 0/151 | 0.00 % | 0/147 | 147 | 0/0 | 0/4 | 0/231 |
| `crates/astra/src/commands/trust_domain.rs` | 104/134 | 77.61 % | 104/130 | 26 | 0/0 | 2/8 | 136/201 |
| `crates/astra/src/daemon.rs` | 0/239 | 0.00 % | 0/227 | 227 | 0/0 | 0/18 | 0/383 |
| `crates/astra/src/distribution.rs` | 297/431 | 68.91 % | 59/189 | 130 | 234/234 | 18/25 | 388/565 |
| `crates/astra/src/gateway.rs` | 75/126 | 59.52 % | 74/115 | 41 | 0/0 | 6/23 | 93/165 |
| `crates/astra/src/issuer.rs` | 226/271 | 83.39 % | 226/270 | 44 | 0/0 | 10/11 | 231/297 |
| `crates/astra/src/main.rs` | 52/134 | 38.81 % | 50/132 | 82 | 0/0 | 4/4 | 69/177 |
| `crates/astra/src/operations.rs` | 325/498 | 65.26 % | 323/492 | 169 | 0/0 | 28/39 | 384/612 |
| `crates/astra/src/operator.rs` | 0/111 | 0.00 % | 0/105 | 105 | 0/0 | 0/16 | 0/180 |
| `crates/astra/src/planner.rs` | 167/172 | 97.09 % | 59/64 | 5 | 108/108 | 12/13 | 215/226 |
| `crates/astra/src/private_channel.rs` | 0/82 | 0.00 % | 0/75 | 75 | 0/0 | 0/11 | 0/120 |
| `crates/astra/src/reconciliation.rs` | 126/147 | 85.71 % | 55/74 | 19 | 67/67 | 17/19 | 257/286 |
| `crates/astra/src/recovery.rs` | 111/502 | 22.11 % | 37/408 | 371 | 73/73 | 11/40 | 164/665 |
| `crates/astra/src/registry.rs` | 37/38 | 97.37 % | 37/37 | 0 | 0/0 | 7/8 | 40/44 |
| `crates/astra/src/registry/challenge.rs` | 25/25 | 100.00 % | 24/24 | 0 | 0/0 | 5/5 | 33/33 |
| `crates/astra/src/registry/delegation.rs` | 41/42 | 97.62 % | 41/42 | 1 | 0/0 | 2/2 | 37/39 |
| `crates/astra/src/registry/peer_lifecycle.rs` | 154/249 | 61.85 % | 152/246 | 94 | 0/0 | 8/13 | 168/300 |
| `crates/astra/src/registry/persistence.rs` | 129/152 | 84.87 % | 128/142 | 14 | 0/0 | 10/16 | 183/222 |
| `crates/astra/src/registry/transitions.rs` | 357/394 | 90.61 % | 341/377 | 36 | 0/0 | 23/25 | 397/447 |
| `crates/astra/src/renewal/approval.rs` | 49/178 | 27.53 % | 49/174 | 125 | 0/0 | 1/9 | 60/205 |
| `crates/astra/src/renewal/companion.rs` | 0/167 | 0.00 % | 0/164 | 164 | 0/0 | 0/6 | 0/278 |
| `crates/astra/src/renewal/mod.rs` | 0/23 | 0.00 % | 0/22 | 22 | 0/0 | 0/5 | 0/29 |
| `crates/astra/src/renewal/request.rs` | 0/183 | 0.00 % | 0/178 | 178 | 0/0 | 0/8 | 0/272 |
| `crates/astra/src/renewal/router.rs` | 0/73 | 0.00 % | 0/69 | 69 | 0/0 | 0/11 | 0/99 |
| `crates/astra/src/renewal/stage.rs` | 0/174 | 0.00 % | 0/169 | 169 | 0/0 | 0/8 | 0/269 |
| `crates/astra/src/service.rs` | 77/634 | 12.15 % | 73/593 | 520 | 0/0 | 11/67 | 97/851 |
| `crates/astra/src/signing.rs` | 426/558 | 76.34 % | 127/256 | 129 | 297/297 | 31/41 | 636/786 |
| `crates/helios-api/src/auth.rs` | 351/363 | 96.69 % | 117/128 | 11 | 172/172 | 47/49 | 414/435 |
| `crates/helios-api/src/certificates/gateway_identity.rs` | 0/72 | 0.00 % | 0/67 | 67 | 0/0 | 0/13 | 0/90 |
| `crates/helios-api/src/certificates/operator_relay.rs` | 82/157 | 52.23 % | 79/150 | 71 | 0/0 | 9/14 | 95/236 |
| `crates/helios-api/src/certificates/renewal.rs` | 9/80 | 11.25 % | 8/76 | 68 | 0/0 | 3/11 | 8/109 |
| `crates/helios-api/src/certificates/trust_update.rs` | 45/46 | 97.83 % | 41/42 | 1 | 0/0 | 7/7 | 63/66 |
| `crates/helios-api/src/certificates/views.rs` | 0/32 | 0.00 % | 0/30 | 30 | 0/0 | 0/4 | 0/36 |
| `crates/helios-api/src/embed.rs` | 34/36 | 94.44 % | 14/16 | 2 | 13/13 | 8/9 | 53/55 |
| `crates/helios-api/src/health.rs` | 54/90 | 60.00 % | 35/65 | 30 | 15/16 | 11/19 | 92/180 |
| `crates/helios-api/src/key_negotiation.rs` | 195/195 | 100.00 % | 29/29 | 0 | 140/140 | 17/17 | 201/201 |
| `crates/helios-api/src/lib.rs` | 177/213 | 83.10 % | 173/208 | 35 | 0/0 | 11/17 | 242/284 |
| `crates/helios-api/src/local.rs` | 95/122 | 77.87 % | 78/100 | 22 | 14/14 | 11/17 | 172/238 |
| `crates/helios-api/src/provision.rs` | 278/297 | 93.60 % | 68/87 | 19 | 191/191 | 28/28 | 384/397 |
| `crates/helios-api/src/routes/commands.rs` | 25/26 | 96.15 % | 23/24 | 1 | 0/0 | 6/6 | 29/30 |
| `crates/helios-api/src/routes/firewall.rs` | 88/116 | 75.86 % | 84/109 | 25 | 0/0 | 5/10 | 156/187 |
| `crates/helios-api/src/routes/network.rs` | 80/115 | 69.57 % | 73/104 | 31 | 0/0 | 11/16 | 101/134 |
| `crates/helios-api/src/routes/peers.rs` | 136/165 | 82.42 % | 128/153 | 25 | 0/0 | 15/18 | 174/206 |
| `crates/helios-api/src/routes/status.rs` | 53/88 | 60.23 % | 48/78 | 30 | 0/0 | 8/12 | 81/121 |
| `crates/helios-api/src/speedtest.rs` | 337/613 | 54.98 % | 240/501 | 261 | 80/80 | 31/51 | 477/834 |
| `crates/helios-api/src/update.rs` | 178/205 | 86.83 % | 47/65 | 18 | 118/122 | 20/26 | 198/216 |
| `crates/helios-api/src/ws.rs` | 68/76 | 89.47 % | 15/22 | 7 | 47/48 | 9/9 | 138/146 |
| `crates/helios-escrow/src/lib.rs` | 154/164 | 93.90 % | 89/94 | 5 | 64/64 | 14/17 | 324/341 |
| `crates/helios-firewall/src/dryrun.rs` | 41/44 | 93.18 % | 4/7 | 3 | 33/33 | 7/8 | 50/53 |
| `crates/helios-firewall/src/lib.rs` | 2/2 | 100.00 % | 2/2 | 0 | 0/0 | 1/1 | 2/2 |
| `crates/helios-firewall/src/netlink/expressions.rs` | 362/370 | 97.84 % | 154/160 | 6 | 194/196 | 41/41 | 607/625 |
| `crates/helios-firewall/src/netlink/maintenance.rs` | 3/32 | 9.38 % | 0/27 | 27 | 3/3 | 1/8 | 3/40 |
| `crates/helios-firewall/src/netlink/transaction.rs` | 535/558 | 95.88 % | 136/156 | 20 | 379/380 | 43/49 | 899/943 |
| `crates/helios-firewall/src/ruleset.rs` | 73/73 | 100.00 % | 72/72 | 0 | 0/0 | 5/5 | 137/140 |
| `crates/helios-firewall/src/ruleset/administration.rs` | 64/64 | 100.00 % | 64/64 | 0 | 0/0 | 3/3 | 51/51 |
| `crates/helios-firewall/src/ruleset/astra_channel.rs` | 42/42 | 100.00 % | 42/42 | 0 | 0/0 | 1/1 | 42/48 |
| `crates/helios-firewall/src/ruleset/client_ipv6_egress.rs` | 38/38 | 100.00 % | 38/38 | 0 | 0/0 | 1/1 | 28/28 |
| `crates/helios-firewall/src/ruleset/gateway_wan.rs` | 123/123 | 100.00 % | 123/123 | 0 | 0/0 | 2/2 | 73/73 |
| `crates/helios-firewall/src/ruleset/kill_switch.rs` | 88/88 | 100.00 % | 86/86 | 0 | 0/0 | 3/3 | 102/102 |
| `crates/helios-firewall/src/ruleset/link_ipv6.rs` | 90/90 | 100.00 % | 84/84 | 0 | 0/0 | 9/9 | 107/107 |
| `crates/helios-firewall/src/ruleset/meshnet.rs` | 98/98 | 100.00 % | 98/98 | 0 | 0/0 | 2/2 | 117/124 |
| `crates/helios-firewall/src/ruleset/nftables.rs` | 320/340 | 94.12 % | 182/202 | 20 | 132/132 | 41/42 | 445/484 |
| `crates/helios-firewall/src/ruleset/transport.rs` | 130/130 | 100.00 % | 130/130 | 0 | 0/0 | 3/3 | 84/85 |
| `crates/helios-firewall/src/ruleset/tunnel_interface.rs` | 77/77 | 100.00 % | 77/77 | 0 | 0/0 | 1/1 | 58/58 |
| `crates/helios-provisioning/src/admission.rs` | 503/504 | 99.80 % | 130/130 | 0 | 367/367 | 42/43 | 863/876 |
| `crates/helios-provisioning/src/certificates.rs` | 55/77 | 71.43 % | 54/74 | 20 | 0/0 | 10/14 | 81/102 |
| `crates/helios-provisioning/src/certificates/distribution.rs` | 83/91 | 91.21 % | 83/90 | 7 | 0/0 | 3/3 | 100/109 |
| `crates/helios-provisioning/src/certificates/persistence.rs` | 95/126 | 75.40 % | 94/109 | 15 | 0/0 | 7/21 | 153/210 |
| `crates/helios-provisioning/src/certificates/staging.rs` | 285/426 | 66.90 % | 284/423 | 139 | 0/0 | 9/11 | 359/522 |
| `crates/helios-provisioning/src/certificates/transitions.rs` | 123/127 | 96.85 % | 121/125 | 4 | 0/0 | 10/10 | 152/166 |
| `crates/helios-provisioning/src/certificates/trust.rs` | 158/166 | 95.18 % | 157/165 | 8 | 0/0 | 5/5 | 187/202 |
| `crates/helios-provisioning/src/ipam.rs` | 375/375 | 100.00 % | 107/107 | 0 | 258/258 | 43/43 | 709/716 |
| `crates/helios-provisioning/src/rotation.rs` | 121/121 | 100.00 % | 49/49 | 0 | 72/72 | 13/13 | 216/219 |
| `crates/helios-provisioning/src/session.rs` | 163/165 | 98.79 % | 47/48 | 1 | 114/114 | 18/19 | 258/264 |
| `crates/helios-tpm/src/blob_store.rs` | 91/118 | 77.12 % | 73/91 | 18 | 16/16 | 16/26 | 193/257 |
| `crates/helios-tpm/src/boot_controller.rs` | 474/556 | 85.25 % | 98/157 | 59 | 376/395 | 43/58 | 1082/1256 |
| `crates/helios-tpm/src/firmware_recovery.rs` | 294/374 | 78.61 % | 126/189 | 63 | 168/179 | 19/34 | 555/708 |
| `crates/helios-tpm/src/keystore.rs` | 213/254 | 83.86 % | 98/135 | 37 | 115/115 | 26/34 | 460/538 |
| `crates/helios-tpm/src/provisioning.rs` | 84/91 | 92.31 % | 88/91 | 3 | 0/0 | 5/5 | 140/175 |
| `crates/helios-tpm/src/reseal_ticket.rs` | 107/108 | 99.07 % | 37/38 | 1 | 67/67 | 16/16 | 161/170 |
| `crates/helios-tpm/src/secret.rs` | 11/15 | 73.33 % | 11/14 | 3 | 0/0 | 3/5 | 14/22 |
| `crates/helios-tpm/src/settings.rs` | 41/41 | 100.00 % | 17/17 | 0 | 23/23 | 4/4 | 49/49 |
| `crates/helios-tpm/src/tpm_interface.rs` | 81/83 | 97.59 % | 6/6 | 0 | 74/76 | 15/15 | 116/118 |
| `crates/helios-tpm/src/tpm_real.rs` | 0/601 | 0.00 % | 0/527 | 527 | 0/0 | 0/104 | 0/1063 |
| `crates/helios-tpm/src/update_window.rs` | 159/164 | 96.95 % | 98/103 | 5 | 61/61 | 19/19 | 231/240 |
| `crates/helios-update/src/bundle.rs` | 547/611 | 89.53 % | 254/309 | 55 | 284/284 | 44/54 | 1024/1122 |
| `crates/helios-update/src/lib.rs` | 524/626 | 83.71 % | 370/454 | 84 | 147/150 | 46/66 | 953/1162 |
| `crates/helios-wireguard/src/dryrun.rs` | 212/217 | 97.70 % | 85/88 | 3 | 105/106 | 41/43 | 338/347 |
| `crates/helios-wireguard/src/kernel.rs` | 181/234 | 77.35 % | 54/102 | 48 | 120/120 | 21/43 | 248/334 |
| `crates/helios-wireguard/src/lib.rs` | 18/18 | 100.00 % | 3/3 | 0 | 15/15 | 3/3 | 22/22 |
| `crates/heliosd/src/astra_channel.rs` | 300/489 | 61.35 % | 161/322 | 161 | 136/136 | 19/69 | 622/928 |
| `crates/heliosd/src/certificates/admission.rs` | 22/49 | 44.90 % | 22/44 | 22 | 0/0 | 2/8 | 31/80 |
| `crates/heliosd/src/certificates/astra.rs` | 54/126 | 42.86 % | 52/122 | 70 | 0/0 | 5/25 | 65/146 |
| `crates/heliosd/src/certificates/gateway_identity.rs` | 0/34 | 0.00 % | 0/34 | 34 | 0/0 | 0/12 | 0/42 |
| `crates/heliosd/src/certificates/mod.rs` | 39/53 | 73.58 % | 38/51 | 13 | 0/0 | 4/7 | 39/63 |
| `crates/heliosd/src/certificates/service.rs` | 112/206 | 54.37 % | 109/191 | 82 | 0/0 | 8/21 | 146/277 |
| `crates/heliosd/src/certificates/trust_update.rs` | 14/49 | 28.57 % | 14/48 | 34 | 0/0 | 2/13 | 17/57 |
| `crates/heliosd/src/certificates/views.rs` | 118/123 | 95.93 % | 114/118 | 4 | 0/0 | 7/9 | 145/152 |
| `crates/heliosd/src/commands/identity.rs` | 0/91 | 0.00 % | 0/88 | 88 | 0/0 | 0/6 | 0/107 |
| `crates/heliosd/src/commands/ipv6_prefix.rs` | 95/110 | 86.36 % | 26/37 | 11 | 63/64 | 15/17 | 172/191 |
| `crates/heliosd/src/commands/peer.rs` | 49/150 | 32.67 % | 23/118 | 95 | 25/25 | 5/11 | 62/208 |
| `crates/heliosd/src/commands/tpm.rs` | 58/169 | 34.32 % | 7/116 | 109 | 51/51 | 3/12 | 76/274 |
| `crates/heliosd/src/commands/trust.rs` | 39/373 | 10.46 % | 14/336 | 322 | 24/24 | 6/25 | 88/579 |
| `crates/heliosd/src/commands/wan.rs` | 0/39 | 0.00 % | 0/39 | 39 | 0/0 | 0/2 | 0/57 |
| `crates/heliosd/src/daemon.rs` | 0/211 | 0.00 % | 0/204 | 204 | 0/0 | 0/8 | 0/353 |
| `crates/heliosd/src/gateway_key.rs` | 319/427 | 74.71 % | 115/219 | 104 | 194/194 | 45/51 | 504/686 |
| `crates/heliosd/src/gateway_rotation.rs` | 150/404 | 37.13 % | 148/381 | 233 | 0/0 | 10/40 | 193/535 |
| `crates/heliosd/src/key_negotiation/candidate.rs` | 4/193 | 2.07 % | 4/189 | 185 | 0/0 | 1/11 | 6/280 |
| `crates/heliosd/src/key_negotiation/identity.rs` | 103/438 | 23.52 % | 103/429 | 326 | 0/0 | 5/30 | 85/563 |
| `crates/heliosd/src/key_negotiation/mod.rs` | 28/47 | 59.57 % | 27/40 | 13 | 0/0 | 6/13 | 32/71 |
| `crates/heliosd/src/key_negotiation/origin.rs` | 88/88 | 100.00 % | 23/23 | 0 | 63/63 | 11/11 | 112/112 |
| `crates/heliosd/src/key_negotiation/protocol.rs` | 70/91 | 76.92 % | 66/86 | 20 | 0/0 | 17/23 | 78/103 |
| `crates/heliosd/src/key_negotiation/server.rs` | 0/116 | 0.00 % | 0/111 | 111 | 0/0 | 0/7 | 0/167 |
| `crates/heliosd/src/key_negotiation/transaction.rs` | 247/327 | 75.54 % | 231/309 | 78 | 0/0 | 32/35 | 299/410 |
| `crates/heliosd/src/main.rs` | 144/332 | 43.37 % | 6/116 | 110 | 138/140 | 6/10 | 166/329 |
| `crates/heliosd/src/orchestrator/commands.rs` | 73/197 | 37.06 % | 72/196 | 124 | 0/0 | 2/2 | 107/316 |
| `crates/heliosd/src/orchestrator/data_plane.rs` | 310/423 | 73.29 % | 294/402 | 108 | 0/0 | 31/39 | 342/479 |
| `crates/heliosd/src/orchestrator/mod.rs` | 37/310 | 11.94 % | 36/304 | 268 | 0/0 | 5/17 | 42/459 |
| `crates/heliosd/src/orchestrator/observation.rs` | 89/113 | 78.76 % | 82/104 | 22 | 0/0 | 10/13 | 116/147 |
| `crates/heliosd/src/orchestrator/probes.rs` | 73/116 | 62.93 % | 69/107 | 38 | 0/0 | 9/17 | 95/174 |
| `crates/heliosd/src/orchestrator/reload.rs` | 0/44 | 0.00 % | 0/43 | 43 | 0/0 | 0/3 | 0/67 |
| `crates/heliosd/src/orchestrator/telemetry.rs` | 0/21 | 0.00 % | 0/20 | 20 | 0/0 | 0/2 | 0/37 |
| `crates/heliosd/src/orchestrator/uplinks.rs` | 78/115 | 67.83 % | 75/111 | 36 | 0/0 | 7/9 | 97/153 |
| `crates/heliosd/src/process_guards.rs` | 39/47 | 82.98 % | 26/34 | 8 | 12/12 | 8/8 | 49/58 |
| `crates/heliosd/src/static_psk.rs` | 554/606 | 91.42 % | 228/270 | 42 | 315/315 | 52/66 | 981/1073 |
| `crates/heliosd/src/uplink.rs` | 311/325 | 95.69 % | 112/125 | 13 | 189/189 | 34/37 | 558/581 |
| `crates/heliosd/src/vip_routing.rs` | 264/333 | 79.28 % | 93/153 | 60 | 157/157 | 43/60 | 420/523 |
| `crates/orion-core/src/backend/controller.rs` | 344/478 | 71.97 % | 330/460 | 130 | 0/0 | 35/45 | 420/586 |
| `crates/orion-core/src/backend/dryrun.rs` | 170/174 | 97.70 % | 51/55 | 4 | 100/100 | 34/36 | 285/289 |
| `crates/orion-core/src/backend/mod.rs` | 0/6 | 0.00 % | 0/5 | 5 | 0/0 | 0/2 | 0/8 |
| `crates/orion-core/src/backend/negotiation.rs` | 77/284 | 27.11 % | 71/270 | 199 | 0/0 | 13/22 | 83/299 |
| `crates/orion-core/src/backend/renewal.rs` | 93/99 | 93.94 % | 36/42 | 6 | 55/55 | 14/15 | 196/202 |
| `crates/orion-core/src/backend/slot_renewal.rs` | 94/160 | 58.75 % | 91/155 | 64 | 0/0 | 7/14 | 104/173 |
| `crates/orion-core/src/backend/wireguard.rs` | 680/785 | 86.62 % | 228/315 | 87 | 429/433 | 85/120 | 1003/1140 |
| `crates/orion-core/src/certificate_actions.rs` | 383/394 | 97.21 % | 170/181 | 11 | 206/206 | 32/32 | 385/393 |
| `crates/orion-core/src/certificate_approval.rs` | 8/113 | 7.08 % | 4/107 | 103 | 4/5 | 2/7 | 9/120 |
| `crates/orion-core/src/certificate_inventory.rs` | 243/364 | 66.76 % | 131/238 | 107 | 107/107 | 23/39 | 300/486 |
| `crates/orion-core/src/certificate_recovery.rs` | 292/589 | 49.58 % | 84/357 | 273 | 203/203 | 17/53 | 340/769 |
| `crates/orion-core/src/certificate_renewal/exchange.rs` | 186/562 | 33.10 % | 186/520 | 334 | 0/0 | 14/78 | 217/773 |
| `crates/orion-core/src/certificate_renewal/promotion.rs` | 30/201 | 14.93 % | 30/183 | 153 | 0/0 | 2/25 | 31/293 |
| `crates/orion-core/src/certificate_renewal/trust_store.rs` | 251/283 | 88.69 % | 249/265 | 16 | 0/0 | 10/27 | 313/395 |
| `crates/orion-core/src/certificates.rs` | 360/534 | 67.42 % | 356/529 | 173 | 0/0 | 21/25 | 414/606 |
| `crates/orion-core/src/config.rs` | 338/375 | 90.13 % | 318/335 | 17 | 10/11 | 41/60 | 486/565 |
| `crates/orion-core/src/config/legacy_fixture.rs` | 31/31 | 100.00 % | 31/31 | 0 | 0/0 | 2/2 | 29/29 |
| `crates/orion-core/src/endpoint_resolution.rs` | 176/188 | 93.62 % | 166/175 | 9 | 0/0 | 26/26 | 265/285 |
| `crates/orion-core/src/events.rs` | 44/44 | 100.00 % | 15/15 | 0 | 29/29 | 6/6 | 74/74 |
| `crates/orion-core/src/identity_store.rs` | 277/381 | 72.70 % | 267/366 | 99 | 0/0 | 38/48 | 438/654 |
| `crates/orion-core/src/key_negotiation.rs` | 343/488 | 70.29 % | 331/460 | 129 | 0/0 | 27/47 | 483/704 |
| `crates/orion-core/src/mtu.rs` | 46/53 | 86.79 % | 12/19 | 7 | 33/33 | 9/10 | 82/102 |
| `crates/orion-core/src/net_pin.rs` | 59/61 | 96.72 % | 20/20 | 0 | 39/39 | 8/10 | 110/114 |
| `crates/orion-core/src/operator_pending.rs` | 10/36 | 27.78 % | 4/26 | 22 | 6/6 | 2/7 | 13/47 |
| `crates/orion-core/src/profile_import/document.rs` | 166/169 | 98.22 % | 158/159 | 1 | 0/0 | 16/18 | 240/257 |
| `crates/orion-core/src/profile_import/field_rules.rs` | 239/253 | 94.47 % | 222/234 | 12 | 0/0 | 30/32 | 378/397 |
| `crates/orion-core/src/profile_import/json.rs` | 69/70 | 98.57 % | 67/68 | 1 | 0/0 | 5/5 | 81/83 |
| `crates/orion-core/src/profile_import/validation.rs` | 136/140 | 97.14 % | 119/121 | 2 | 0/0 | 22/24 | 236/251 |
| `crates/orion-core/src/profile_import/wg_quick.rs` | 135/144 | 93.75 % | 132/140 | 8 | 0/0 | 9/10 | 218/235 |
| `crates/orion-core/src/provisioning.rs` | 168/199 | 84.42 % | 64/90 | 26 | 101/101 | 16/21 | 251/312 |
| `crates/orion-core/src/speedtest/failure.rs` | 37/40 | 92.50 % | 37/40 | 3 | 0/0 | 7/8 | 42/45 |
| `crates/orion-core/src/speedtest/http.rs` | 351/393 | 89.31 % | 328/364 | 36 | 0/0 | 47/54 | 504/591 |
| `crates/orion-core/src/speedtest/mod.rs` | 34/65 | 52.31 % | 33/59 | 26 | 0/0 | 6/13 | 54/91 |
| `crates/orion-core/src/speedtest/raw.rs` | 340/386 | 88.08 % | 333/370 | 37 | 0/0 | 15/24 | 459/542 |
| `crates/orion-core/src/speedtest/udp.rs` | 232/274 | 84.67 % | 230/270 | 40 | 0/0 | 5/6 | 304/359 |
| `crates/orion-core/src/speedtest/wire.rs` | 85/85 | 100.00 % | 85/85 | 0 | 0/0 | 7/7 | 100/103 |
| `crates/orion-core/src/telemetry.rs` | 175/194 | 90.21 % | 61/78 | 17 | 96/97 | 14/16 | 252/265 |
| `crates/orion-core/src/test_domain.rs` | 227/227 | 100.00 % | 0/0 | 0 | 227/227 | 11/11 | 307/307 |
| `crates/orion-core/src/trust_update.rs` | 398/473 | 84.14 % | 106/161 | 55 | 280/284 | 31/47 | 597/745 |
| `crates/orion-core/src/vault/codec.rs` | 105/108 | 97.22 % | 73/73 | 0 | 32/32 | 14/17 | 176/184 |
| `crates/orion-core/src/vault/keys.rs` | 81/81 | 100.00 % | 30/30 | 0 | 49/49 | 13/13 | 159/162 |
| `crates/orion-core/src/vault/manifest.rs` | 736/753 | 97.74 % | 300/315 | 15 | 432/432 | 38/40 | 1425/1483 |
| `crates/orion-core/src/vault/mod.rs` | 234/236 | 99.15 % | 85/87 | 2 | 143/143 | 31/31 | 367/377 |
| `crates/orion-core/src/vault/passphrase.rs` | 104/105 | 99.05 % | 40/41 | 1 | 61/61 | 17/17 | 179/181 |
| `crates/orion-core/src/vault/registry.rs` | 158/169 | 93.49 % | 77/87 | 10 | 77/77 | 19/20 | 316/332 |
| `crates/orion-core/src/vault/settings.rs` | 86/104 | 82.69 % | 21/36 | 15 | 65/65 | 9/12 | 140/157 |
| `crates/orion-core/src/vault/store.rs` | 333/406 | 82.02 % | 325/387 | 62 | 0/0 | 34/48 | 560/687 |
| `crates/orion-core/src/vault/windows/bitlocker.rs` | 43/44 | 97.73 % | 23/24 | 1 | 20/20 | 8/8 | 52/54 |
| `crates/orion-core/src/vault/windows/dpapi.rs` | 16/16 | 100.00 % | 12/12 | 0 | 4/4 | 5/5 | 22/24 |
| `crates/orion-core/src/vault/windows/dumps.rs` | 45/46 | 97.83 % | 24/25 | 1 | 21/21 | 10/10 | 56/58 |
| `crates/orion-core/src/vault/windows/mod.rs` | 85/123 | 69.11 % | 37/71 | 34 | 48/48 | 11/15 | 114/191 |
| `crates/orion-core/src/vault/windows/prompt.rs` | 9/9 | 100.00 % | 6/6 | 0 | 3/3 | 3/3 | 12/13 |
| `crates/orion-core/src/vault/windows/tpm.rs` | 70/70 | 100.00 % | 6/6 | 0 | 63/63 | 8/8 | 102/104 |
| `tools/astra-signer/src/cli.rs` | 0/27 | 0.00 % | 0/27 | 27 | 0/0 | 0/5 | 0/27 |
| `tools/astra-signer/src/commands/ca_pq_rotation.rs` | 0/273 | 0.00 % | 0/265 | 265 | 0/0 | 0/14 | 0/417 |
| `tools/astra-signer/src/commands/ca_tls_rotation.rs` | 0/238 | 0.00 % | 0/232 | 232 | 0/0 | 0/10 | 0/421 |
| `tools/astra-signer/src/commands/campaign.rs` | 0/196 | 0.00 % | 0/189 | 189 | 0/0 | 0/7 | 0/345 |
| `tools/astra-signer/src/commands/gateway_identity.rs` | 7/501 | 1.40 % | 7/482 | 475 | 0/0 | 1/23 | 9/805 |
| `tools/astra-signer/src/commands/issuer.rs` | 0/204 | 0.00 % | 0/199 | 199 | 0/0 | 0/7 | 0/340 |
| `tools/astra-signer/src/commands/mod.rs` | 3/96 | 3.12 % | 3/92 | 89 | 0/0 | 1/15 | 4/144 |
| `tools/astra-signer/src/commands/recovery.rs` | 0/37 | 0.00 % | 0/34 | 34 | 0/0 | 0/3 | 0/51 |
| `tools/astra-signer/src/commands/revocation.rs` | 0/164 | 0.00 % | 0/156 | 156 | 0/0 | 0/8 | 0/250 |
| `tools/astra-signer/src/commands/vault.rs` | 0/337 | 0.00 % | 0/335 | 335 | 0/0 | 0/15 | 0/610 |
| `tools/astra-signer/src/main.rs` | 0/257 | 0.00 % | 0/256 | 256 | 0/0 | 0/3 | 0/347 |
| `tools/helios-astra-helper/src/main.rs` | 122/375 | 32.53 % | 47/293 | 246 | 75/75 | 12/25 | 186/621 |
| `tools/helios-astra-helper/src/owner.rs` | 12/12 | 100.00 % | 7/7 | 0 | 5/5 | 3/3 | 18/18 |
| `tools/helios-astra-helper/src/session.rs` | 139/144 | 96.53 % | 52/56 | 4 | 86/86 | 16/17 | 218/230 |
| `tools/helios-installer/src/main.rs` | 169/287 | 58.89 % | 63/175 | 112 | 101/101 | 16/28 | 235/434 |
| `tools/helios-publisher/src/main.rs` | 297/411 | 72.26 % | 288/383 | 95 | 0/0 | 23/43 | 414/625 |
| `tools/helios/src/api.rs` | 232/295 | 78.64 % | 50/106 | 56 | 166/169 | 24/32 | 367/468 |
| `tools/helios/src/app_update.rs` | 318/430 | 73.95 % | 127/222 | 95 | 180/183 | 24/43 | 502/711 |
| `tools/helios/src/campaign.rs` | 138/480 | 28.75 % | 81/408 | 327 | 56/56 | 17/48 | 221/763 |
| `tools/helios/src/campaign_key_nego.rs` | 222/410 | 54.15 % | 217/392 | 175 | 4/4 | 13/36 | 346/691 |
| `tools/helios/src/enroll.rs` | 190/413 | 46.00 % | 60/263 | 203 | 130/130 | 11/30 | 283/607 |
| `tools/helios/src/escrow.rs` | 143/148 | 96.62 % | 52/53 | 1 | 91/91 | 7/11 | 288/302 |
| `tools/helios/src/files.rs` | 52/54 | 96.30 % | 22/22 | 0 | 27/27 | 7/9 | 90/98 |
| `tools/helios/src/firmware.rs` | 476/906 | 52.54 % | 232/646 | 414 | 235/238 | 46/84 | 809/1583 |
| `tools/helios/src/inspect.rs` | 664/920 | 72.17 % | 630/864 | 234 | 0/0 | 54/88 | 1226/1757 |
| `tools/helios/src/inspect/firewall.rs` | 336/352 | 95.45 % | 257/273 | 16 | 74/74 | 23/23 | 568/603 |
| `tools/helios/src/interactive.rs` | 181/420 | 43.10 % | 88/319 | 231 | 80/80 | 27/46 | 310/730 |
| `tools/helios/src/interactive/palette.rs` | 226/240 | 94.17 % | 138/151 | 13 | 69/69 | 32/34 | 392/408 |
| `tools/helios/src/interactive/presentation.rs` | 361/394 | 91.62 % | 209/241 | 32 | 136/136 | 38/40 | 724/802 |
| `tools/helios/src/key_nego.rs` | 510/643 | 79.32 % | 270/386 | 116 | 235/237 | 35/52 | 792/1028 |
| `tools/helios/src/main.rs` | 72/392 | 18.37 % | 68/372 | 304 | 0/0 | 13/38 | 95/564 |
| `tools/helios/src/monitor.rs` | 21/140 | 15.00 % | 21/134 | 113 | 0/0 | 2/13 | 41/294 |
| `tools/helios/src/peer.rs` | 227/231 | 98.27 % | 67/68 | 1 | 146/149 | 24/24 | 341/347 |
| `tools/helios/src/profile.rs` | 458/543 | 84.35 % | 123/205 | 82 | 330/330 | 33/39 | 694/857 |
| `tools/helios/src/transport.rs` | 92/110 | 83.64 % | 53/66 | 13 | 33/34 | 12/16 | 147/182 |
| `tools/helios/src/ui.rs` | 217/238 | 91.18 % | 168/189 | 21 | 43/43 | 32/33 | 415/445 |
| `tools/helios/src/update.rs` | 169/344 | 49.13 % | 67/240 | 173 | 92/92 | 27/41 | 245/514 |
| `tools/xtask/src/main.rs` | 282/583 | 48.37 % | 51/330 | 279 | 216/216 | 35/70 | 396/877 |
| `tools/xtask/src/orion_deps.rs` | 0/125 | 0.00 % | 0/104 | 104 | 0/0 | 0/26 | 0/242 |
| `tools/xtask/src/orion_helper.rs` | 26/67 | 38.81 % | 14/50 | 36 | 12/12 | 5/10 | 36/105 |

## Reconstitution reproductible des lignes de production

Après les exports globaux, copier le bloc Python suivant dans un fichier temporaire et l’exécuter depuis la racine. Il lit uniquement les sources, le JSON et le LCOV ci-dessus, appelle le parseur syntaxique installé et écrit un JSON d’analyse dans `/tmp`. Les noms/fichiers entiers retirés sont explicitement visibles. Pour la vue libs, appliquer les mêmes plages AST aux `DA` du LCOV libs ; sommer par chemin de package. Le code est inclus dans la documentation pour rendre les nombres vérifiables, sans ajouter de script au produit.

```python
import json,subprocess,re,pathlib,collections,math
ROOT=pathlib.Path.cwd()
DATA=json.load(open('/tmp/helios-audit-workspace-coverage.json'))['data'][0]
# Explicit whole-file fixtures/harnesses, confirmed by their declaring module.
WHOLE={'crates/aether/src/fuzzing.rs','crates/astra-operator/src/vault/tests_support.rs','crates/orion-core/src/test_domain.rs'}
def tokens(n):
 if n['type']=='Token':return n.get('text','')
 return ''.join(tokens(c) for c in n.get('children',[]))
def cfg_value(s):
 s=re.sub(r'\s+','',s)
 if s in ['test','windows']:return False
 if s in ['unix','debug_assertions']:return True
 m=re.fullmatch(r'(all|any|not)\((.*)\)',s)
 if m:
  parts=[];level=0;begin=0
  for i,ch in enumerate(m[2]):
   if ch=='(':level+=1
   if ch==')':level-=1
   if ch==',' and level==0:parts.append(m[2][begin:i]);begin=i+1
  parts.append(m[2][begin:]);values=[cfg_value(p) for p in parts if p]
  if m[1]=='all':return all(values)
  if m[1]=='any':return any(values)
  return not values[0]
 if s.startswith('feature='):return True  # --all-features
 m=re.fullmatch(r'(\w+)="([^"]*)"',s)
 if m and m[1] in {'target_os','target_family','target_arch','target_env','target_pointer_width','target_endian'}:
  return m[2]=={'target_os':'linux','target_family':'unix','target_arch':'x86_64','target_env':'gnu','target_pointer_width':'64','target_endian':'little'}[m[1]]
 # Unknown cfgs are deliberately kept, never silently excluded.
 return True
rows=[]; exclusions=[]; definitions={}; ranges_out={}
for f in DATA['files']:
 p=pathlib.Path(f['filename']);rel=str(p.relative_to(ROOT));src=p.read_text(); ast=json.loads(subprocess.run(['rust-analyzer','parse','--json'],input=src,text=True,capture_output=True,check=True).stdout);ranges=[];fns=[]
 def walk(n,parent_excluded=False):
  attrs=[tokens(c) for c in n.get('children',[]) if c['kind']=='ATTR']
  excluded=parent_excluded
  for a in attrs:
   a=re.sub(r'\s+','',a)
   if a in ['#[test]','#[tokio::test]'] or a.startswith('#[tokio::test('):excluded=True
   m=re.fullmatch(r'#!?\[cfg\((.*)\)\]',a)
   if m and not cfg_value(m[1]):excluded=True
  if excluded and not parent_excluded:ranges.append((n['start'][1]+1,n['end'][1]+1))
  if n['kind']=='FN' and not excluded:
   name=next((tokens(c) for c in n.get('children',[]) if c['kind']=='NAME'),'?');fns.append((name,n['start'][1]+1,n['end'][1]+1))
  for c in n.get('children',[]):
   if c['type']=='Node':walk(c,excluded)
 walk(ast)
 if rel in WHOLE:ranges=[(1,len(src.splitlines()))];fns=[]
 # DA records from the LCOV export give LLVM line membership/counts exactly.
 ranges_out[rel]=ranges;definitions[rel]=fns
rows_by_file={};current=None
for l in pathlib.Path('/tmp/helios-audit-workspace.lcov').read_text().splitlines():
 if l.startswith('SF:'):
  current=str(pathlib.Path(l[3:]).relative_to(ROOT));rows_by_file[current]={}
 elif l.startswith('DA:'):
  a,b,*_=l[3:].split(',');rows_by_file[current][int(a)]=int(b)
for f in DATA['files']:
 rel=str(pathlib.Path(f['filename']).relative_to(ROOT));ds=rows_by_file[rel];raw=f['summary']['lines'];pass  # LLVM summaries and DA entries are distinct views
 # No equality is assumed between LLVM summary and individual DA records.
 ranges=ranges_out[rel];drop={n:v for n,v in ds.items() if any(a<=n<=b for a,b in ranges)};keep={n:v for n,v in ds.items() if n not in drop};row={'path':rel,'raw_total':len(ds),'raw_covered':sum(v>0 for v in ds.values()),'total':len(keep),'covered':sum(v>0 for v in keep.values()),'removed_total':len(drop),'removed_covered':sum(v>0 for v in drop.values()),'ranges':ranges,'uncovered_lines':[n for n,v in keep.items() if not v]};rows.append(row)
json.dump({'files':rows,'definitions':definitions},open('/tmp/helios-audit-production.json','w'))
for k in ['raw_total','raw_covered','total','covered','removed_total','removed_covered']:print(k,sum(x[k] for x in rows))
n=sum(x['total'] for x in rows);c=sum(x['covered'] for x in rows);print('prod%',100*c/n,'gap80',math.ceil(.8*n)-c)
print('top production uncovered')
for x in sorted(rows,key=lambda x:x['total']-x['covered'],reverse=True)[:25]:print(x['path'],x['covered'],x['total'],x['total']-x['covered'])
```
