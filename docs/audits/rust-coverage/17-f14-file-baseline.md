# Baseline après intégration F14 : workspace Linux

Collectes locales du 28 octobre 2026 sur `e6b96c1c14aa3e988172c17e9fcc530f03c37dd6`, rebasé sur main `5ab3670`. Rust 1.99.0, cargo-llvm-cov 0.9.1, LLVM 23.1.1, Linux x86_64 WSL2. Les 23 packages sont sélectionnés avec toutes leurs features ; la seconde collecte ajoute `--lib`. Le workspace et les seules bibliothèques sont deux vues distinctes.

La production est la projection syntaxique `rust-ast-da-v1` des lignes LCOV `DA` uniques, avec retrait documenté des tests/harnais. Les résumés LLVM bruts sont conservés séparément. Aucun retrait opportuniste ni nouveau `cfg` de couverture ne modifie le périmètre. Les exports complets et leur provenance sont conservés localement hors de `/tmp`, sans être commités.

Le global conserve les cibles Cargo par défaut, sans `--lib` ni `--all-targets`. Les scripts `build.rs`, les dépendances non membres (dont le code vendored `rustables`) et le C/C++ externe ne sont pas inclus : les options `--include-build-script`, `--dep-coverage` et `--include-ffi` ne sont pas activées. Leur dénominateur instrumenté et leur impact ne sont pas établis par cette campagne ; ils ne sont pas comptés artificiellement à 0 %. Les contrôles de livraison de la régression exercent certains build scripts sans en mesurer les lignes. Le TypeScript et le code natif exclu par `cfg` ont également des vues/recettes distinctes. La vue « globale » est donc celle du Rust de production mesurable du workspace Linux, pas de tout le logiciel sur toutes plateformes.

## Résultats vérifiés

| Vue | Production couverte / retenue | Couverture | Non couvertes | Écart à 80 % à périmètre constant | Tests de collecte |
| --- | ---: | ---: | ---: | ---: | ---: |
| Globale Linux | 37 200 / 57 886 | 64,26 % | 20 686 | 9 109 | 2 674 |
| Bibliothèques Linux | 28 314 / 39 293 | 72,06 % | 10 979 | 3 121 | 2 102 |

Pour le global, les jalons 70 % et 75 % demandent respectivement **3 321** et **6 215** lignes supplémentaires. Les **20 686** lignes restantes vers 100 % restent une réserve de comportements à examiner ; aucune estimation de gain ne les transforme en tests garantis.

| Vue LLVM brute | Lignes | Fonctions | Fonctions jamais exécutées | Régions |
| --- | ---: | ---: | ---: | ---: |
| Globale Linux | 55 073 / 77 642 (70,93 %) | 5 337 / 7 831 (68,15 %) | 2 494 | 80 905 / 115 350 (70,14 %) |
| Bibliothèques Linux | 41 506 / 53 623 (77,40 %) | 4 015 / 5 422 (74,05 %) | 1 407 | 60 599 / 78 297 (77,40 %) |

Les branches et MC/DC ne sont pas instrumentés : leurs champs nuls sont **non mesurés**, pas une couverture à 0 %. Les 2 674 tests instrumentés passent sans échec ni ignoré ; la régression classique passe 2 681 tests Rust, dont sept doc-tests non instrumentés par cette campagne. Les 98 tests web et 201 tests TypeScript Orion sont séparés ; aucune couverture TypeScript n’a été collectée.

La projection retire 16 442 lignes `DA` de tests/harnais du global (dont 16 267 exécutées), et 12 192 de la vue bibliothèques (dont 12 038 exécutées). Avant projection, les `DA` uniques donnent respectivement 53 467 / 74 328 et 40 352 / 51 485. L’écart avec `LF/LH` LLVM est conservé et ne doit pas être effacé en choisissant le dénominateur le plus favorable. Les preuves de retrait sont détaillées par fichier dans `report.json`.

## Par crate

| Crate | Production globale couverte / retenue | Couverture globale | Production bibliothèques couverte / retenue | Couverture bibliothèques |
| --- | ---: | ---: | ---: | ---: |
| `aether` | 8 623 / 9 684 | 89,04 % | 8 552 / 9 684 | 88,31 % |
| `aether-fido` | 183 / 553 | 33,09 % | 83 / 553 | 15,01 % |
| `aether-key-negotiation` | 653 / 827 | 78,96 % | 639 / 827 | 77,27 % |
| `aether-vault` | 212 / 216 | 98,15 % | 209 / 216 | 96,76 % |
| `astra` | 3 782 / 5 872 | 64,41 % | 3 551 / 4 551 | 78,03 % |
| `astra-channel` | 426 / 692 | 61,56 % | 419 / 692 | 60,55 % |
| `astra-operator` | 2 311 / 3 797 | 60,86 % | 1 055 / 3 797 | 27,79 % |
| `astra-signer` | 10 / 2 492 | 0,40 % | Non collecté | — |
| `helios` | 2 932 / 5 395 | 54,35 % | Non collecté | — |
| `helios-api` | 1 300 / 2 054 | 63,29 % | 1 300 / 2 054 | 63,29 % |
| `helios-escrow` | 89 / 94 | 94,68 % | 89 / 94 | 94,68 % |
| `helios-firewall` | 1 292 / 1 368 | 94,44 % | 1 292 / 1 368 | 94,44 % |
| `helios-installer` | 63 / 175 | 36,00 % | Non collecté | — |
| `helios-provisioning` | 1 126 / 1 320 | 85,30 % | 1 125 / 1 320 | 85,23 % |
| `helios-publisher` | 288 / 383 | 75,20 % | Non collecté | — |
| `helios-tpm` | 652 / 1 368 | 47,66 % | 636 / 1 368 | 46,49 % |
| `helios-update` | 624 / 763 | 81,78 % | 610 / 763 | 79,95 % |
| `helios-wireguard` | 142 / 193 | 73,58 % | 123 / 193 | 63,73 % |
| `heliosd` | 2 507 / 5 758 | 43,54 % | Non collecté | — |
| `orion` | 1 035 / 2 750 | 37,64 % | Non collecté | — |
| `orion-core` | 7 666 / 9 908 | 77,37 % | 7 410 / 9 908 | 74,79 % |
| `orion-engine` | 1 233 / 1 801 | 68,46 % | 1 221 / 1 801 | 67,80 % |
| `xtask` | 51 / 423 | 12,06 % | 0 / 104 | 0,00 % |

## Par fichier

Les pourcentages portent sur tout le fichier mesuré. Un module Windows absent n’est pas compté à 0 % ; le 100 % d’un repli Linux n’est pas celui du chemin Win32. « Non collecté » signifie absent de l’export bibliothèques, jamais absence de tests. Un fichier à 0 % peut avoir des tests sur une autre cible ou hors de cette campagne. Les différences de dénominateurs entre vues proviennent des cibles et instanciations, pas d’une fusion arbitraire des exports.

| Fichier | Production globale couverte / retenue | Couverture globale | Production bibliothèques couverte / retenue | Couverture bibliothèques |
| --- | ---: | ---: | ---: | ---: |
| [apps/orion/src-tauri/src/astra.rs](../../../apps/orion/src-tauri/src/astra.rs) | 118 / 226 | 52,21 % | Non collecté | — |
| [apps/orion/src-tauri/src/commands/app.rs](../../../apps/orion/src-tauri/src/commands/app.rs) | 18 / 92 | 19,57 % | Non collecté | — |
| [apps/orion/src-tauri/src/commands/ceremonies.rs](../../../apps/orion/src-tauri/src/commands/ceremonies.rs) | 13 / 157 | 8,28 % | Non collecté | — |
| [apps/orion/src-tauri/src/commands/certificates.rs](../../../apps/orion/src-tauri/src/commands/certificates.rs) | 0 / 130 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/commands/connection.rs](../../../apps/orion/src-tauri/src/commands/connection.rs) | 0 / 45 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/commands/enrollment.rs](../../../apps/orion/src-tauri/src/commands/enrollment.rs) | 0 / 65 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/commands/mod.rs](../../../apps/orion/src-tauri/src/commands/mod.rs) | 0 / 3 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/commands/profiles.rs](../../../apps/orion/src-tauri/src/commands/profiles.rs) | 0 / 197 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/companion.rs](../../../apps/orion/src-tauri/src/companion.rs) | 0 / 10 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/engine_host.rs](../../../apps/orion/src-tauri/src/engine_host.rs) | 4 / 4 | 100,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/engine_launch.rs](../../../apps/orion/src-tauri/src/engine_launch.rs) | 0 / 7 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/launch.rs](../../../apps/orion/src-tauri/src/launch.rs) | 0 / 7 | 0,00 % | Non collecté | — |
| [apps/orion/src-tauri/src/main.rs](../../../apps/orion/src-tauri/src/main.rs) | 43 / 287 | 14,98 % | Non collecté | — |
| [apps/orion/src-tauri/src/operator/ceremony.rs](../../../apps/orion/src-tauri/src/operator/ceremony.rs) | 671 / 1 204 | 55,73 % | Non collecté | — |
| [apps/orion/src-tauri/src/operator/invitations.rs](../../../apps/orion/src-tauri/src/operator/invitations.rs) | 32 / 48 | 66,67 % | Non collecté | — |
| [apps/orion/src-tauri/src/operator/mod.rs](../../../apps/orion/src-tauri/src/operator/mod.rs) | 91 / 213 | 42,72 % | Non collecté | — |
| [apps/orion/src-tauri/src/tray.rs](../../../apps/orion/src-tauri/src/tray.rs) | 45 / 55 | 81,82 % | Non collecté | — |
| [apps/orion/src-tauri/src/ui_access.rs](../../../apps/orion/src-tauri/src/ui_access.rs) | 0 / 0 | Sans ligne retenue | Non collecté | — |
| [crates/aether-fido/src/authenticator.rs](../../../crates/aether-fido/src/authenticator.rs) | 83 / 445 | 18,65 % | 83 / 445 | 18,65 % |
| [crates/aether-fido/src/lib.rs](../../../crates/aether-fido/src/lib.rs) | 100 / 108 | 92,59 % | 0 / 108 | 0,00 % |
| [crates/aether-key-negotiation/src/client.rs](../../../crates/aether-key-negotiation/src/client.rs) | 133 / 168 | 79,17 % | 133 / 168 | 79,17 % |
| [crates/aether-key-negotiation/src/endpoint.rs](../../../crates/aether-key-negotiation/src/endpoint.rs) | 152 / 168 | 90,48 % | 138 / 168 | 82,14 % |
| [crates/aether-key-negotiation/src/framing.rs](../../../crates/aether-key-negotiation/src/framing.rs) | 34 / 43 | 79,07 % | 34 / 43 | 79,07 % |
| [crates/aether-key-negotiation/src/identity.rs](../../../crates/aether-key-negotiation/src/identity.rs) | 34 / 40 | 85,00 % | 34 / 40 | 85,00 % |
| [crates/aether-key-negotiation/src/rate_limit.rs](../../../crates/aether-key-negotiation/src/rate_limit.rs) | 23 / 24 | 95,83 % | 23 / 24 | 95,83 % |
| [crates/aether-key-negotiation/src/server.rs](../../../crates/aether-key-negotiation/src/server.rs) | 234 / 338 | 69,23 % | 234 / 338 | 69,23 % |
| [crates/aether-key-negotiation/src/transaction.rs](../../../crates/aether-key-negotiation/src/transaction.rs) | 43 / 46 | 93,48 % | 43 / 46 | 93,48 % |
| [crates/aether-vault/src/lib.rs](../../../crates/aether-vault/src/lib.rs) | 212 / 216 | 98,15 % | 209 / 216 | 96,76 % |
| [crates/aether/src/certificates/approval/campaign.rs](../../../crates/aether/src/certificates/approval/campaign.rs) | 49 / 51 | 96,08 % | 49 / 51 | 96,08 % |
| [crates/aether/src/certificates/approval/credentials.rs](../../../crates/aether/src/certificates/approval/credentials.rs) | 165 / 196 | 84,18 % | 165 / 196 | 84,18 % |
| [crates/aether/src/certificates/approval/mod.rs](../../../crates/aether/src/certificates/approval/mod.rs) | 12 / 12 | 100,00 % | 12 / 12 | 100,00 % |
| [crates/aether/src/certificates/approval/policy.rs](../../../crates/aether/src/certificates/approval/policy.rs) | 160 / 169 | 94,67 % | 160 / 169 | 94,67 % |
| [crates/aether/src/certificates/approval/recovery.rs](../../../crates/aether/src/certificates/approval/recovery.rs) | 79 / 83 | 95,18 % | 79 / 83 | 95,18 % |
| [crates/aether/src/certificates/approval/renewal.rs](../../../crates/aether/src/certificates/approval/renewal.rs) | 256 / 284 | 90,14 % | 256 / 284 | 90,14 % |
| [crates/aether/src/certificates/approval/signing.rs](../../../crates/aether/src/certificates/approval/signing.rs) | 12 / 12 | 100,00 % | 12 / 12 | 100,00 % |
| [crates/aether/src/certificates/authority.rs](../../../crates/aether/src/certificates/authority.rs) | 325 / 416 | 78,12 % | 325 / 416 | 78,12 % |
| [crates/aether/src/certificates/capability.rs](../../../crates/aether/src/certificates/capability.rs) | 203 / 207 | 98,07 % | 203 / 207 | 98,07 % |
| [crates/aether/src/certificates/client/commit.rs](../../../crates/aether/src/certificates/client/commit.rs) | 72 / 89 | 80,90 % | 72 / 89 | 80,90 % |
| [crates/aether/src/certificates/client/grant.rs](../../../crates/aether/src/certificates/client/grant.rs) | 372 / 414 | 89,86 % | 372 / 414 | 89,86 % |
| [crates/aether/src/certificates/client/mod.rs](../../../crates/aether/src/certificates/client/mod.rs) | 53 / 55 | 96,36 % | 53 / 55 | 96,36 % |
| [crates/aether/src/certificates/client/recovery.rs](../../../crates/aether/src/certificates/client/recovery.rs) | 102 / 127 | 80,31 % | 102 / 127 | 80,31 % |
| [crates/aether/src/certificates/client/request.rs](../../../crates/aether/src/certificates/client/request.rs) | 73 / 90 | 81,11 % | 73 / 90 | 81,11 % |
| [crates/aether/src/certificates/client/signing.rs](../../../crates/aether/src/certificates/client/signing.rs) | 42 / 42 | 100,00 % | 42 / 42 | 100,00 % |
| [crates/aether/src/certificates/client/stage.rs](../../../crates/aether/src/certificates/client/stage.rs) | 303 / 354 | 85,59 % | 303 / 354 | 85,59 % |
| [crates/aether/src/certificates/encoding.rs](../../../crates/aether/src/certificates/encoding.rs) | 322 / 338 | 95,27 % | 315 / 338 | 93,20 % |
| [crates/aether/src/certificates/gateway.rs](../../../crates/aether/src/certificates/gateway.rs) | 280 / 346 | 80,92 % | 280 / 346 | 80,92 % |
| [crates/aether/src/certificates/mod.rs](../../../crates/aether/src/certificates/mod.rs) | 51 / 51 | 100,00 % | 51 / 51 | 100,00 % |
| [crates/aether/src/certificates/operator_ipc.rs](../../../crates/aether/src/certificates/operator_ipc.rs) | 3 / 27 | 11,11 % | 3 / 27 | 11,11 % |
| [crates/aether/src/certificates/operator_session.rs](../../../crates/aether/src/certificates/operator_session.rs) | 66 / 75 | 88,00 % | 66 / 75 | 88,00 % |
| [crates/aether/src/certificates/revocation.rs](../../../crates/aether/src/certificates/revocation.rs) | 89 / 98 | 90,82 % | 89 / 98 | 90,82 % |
| [crates/aether/src/certificates/state/astra.rs](../../../crates/aether/src/certificates/state/astra.rs) | 63 / 151 | 41,72 % | 63 / 151 | 41,72 % |
| [crates/aether/src/certificates/state/client_identity.rs](../../../crates/aether/src/certificates/state/client_identity.rs) | 317 / 376 | 84,31 % | 317 / 376 | 84,31 % |
| [crates/aether/src/certificates/state/gateway_identity.rs](../../../crates/aether/src/certificates/state/gateway_identity.rs) | 366 / 381 | 96,06 % | 366 / 381 | 96,06 % |
| [crates/aether/src/certificates/state/ledger.rs](../../../crates/aether/src/certificates/state/ledger.rs) | 286 / 300 | 95,33 % | 286 / 300 | 95,33 % |
| [crates/aether/src/certificates/state/revocation_schedule.rs](../../../crates/aether/src/certificates/state/revocation_schedule.rs) | 10 / 10 | 100,00 % | 10 / 10 | 100,00 % |
| [crates/aether/src/certificates/status/campaign.rs](../../../crates/aether/src/certificates/status/campaign.rs) | 298 / 322 | 92,55 % | 298 / 322 | 92,55 % |
| [crates/aether/src/certificates/status/campaign_approval.rs](../../../crates/aether/src/certificates/status/campaign_approval.rs) | 57 / 61 | 93,44 % | 57 / 61 | 93,44 % |
| [crates/aether/src/certificates/status/certificate_status.rs](../../../crates/aether/src/certificates/status/certificate_status.rs) | 106 / 125 | 84,80 % | 106 / 125 | 84,80 % |
| [crates/aether/src/certificates/status/rollback.rs](../../../crates/aether/src/certificates/status/rollback.rs) | 51 / 59 | 86,44 % | 51 / 59 | 86,44 % |
| [crates/aether/src/certificates/status/signer.rs](../../../crates/aether/src/certificates/status/signer.rs) | 78 / 127 | 61,42 % | 78 / 127 | 61,42 % |
| [crates/aether/src/certificates/status/signing.rs](../../../crates/aether/src/certificates/status/signing.rs) | 8 / 12 | 66,67 % | 8 / 12 | 66,67 % |
| [crates/aether/src/certificates/transport.rs](../../../crates/aether/src/certificates/transport.rs) | 418 / 479 | 87,27 % | 418 / 479 | 87,27 % |
| [crates/aether/src/certificates/webauthn.rs](../../../crates/aether/src/certificates/webauthn.rs) | 221 / 239 | 92,47 % | 220 / 239 | 92,05 % |
| [crates/aether/src/certificates/window.rs](../../../crates/aether/src/certificates/window.rs) | 162 / 166 | 97,59 % | 162 / 166 | 97,59 % |
| [crates/aether/src/certificates/x509.rs](../../../crates/aether/src/certificates/x509.rs) | 236 / 251 | 94,02 % | 236 / 251 | 94,02 % |
| [crates/aether/src/config.rs](../../../crates/aether/src/config.rs) | 656 / 741 | 88,53 % | 650 / 741 | 87,72 % |
| [crates/aether/src/display_time.rs](../../../crates/aether/src/display_time.rs) | 32 / 35 | 91,43 % | 32 / 35 | 91,43 % |
| [crates/aether/src/enroll.rs](../../../crates/aether/src/enroll.rs) | 54 / 54 | 100,00 % | 50 / 54 | 92,59 % |
| [crates/aether/src/events.rs](../../../crates/aether/src/events.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/aether/src/fuzzing.rs](../../../crates/aether/src/fuzzing.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/aether/src/key_negotiation/authentication.rs](../../../crates/aether/src/key_negotiation/authentication.rs) | 243 / 258 | 94,19 % | 243 / 258 | 94,19 % |
| [crates/aether/src/key_negotiation/derivation.rs](../../../crates/aether/src/key_negotiation/derivation.rs) | 90 / 91 | 98,90 % | 89 / 91 | 97,80 % |
| [crates/aether/src/key_negotiation/enrollment.rs](../../../crates/aether/src/key_negotiation/enrollment.rs) | 247 / 257 | 96,11 % | 247 / 257 | 96,11 % |
| [crates/aether/src/key_negotiation/enrollment/document.rs](../../../crates/aether/src/key_negotiation/enrollment/document.rs) | 99 / 123 | 80,49 % | 99 / 123 | 80,49 % |
| [crates/aether/src/key_negotiation/messages.rs](../../../crates/aether/src/key_negotiation/messages.rs) | 365 / 416 | 87,74 % | 351 / 416 | 84,38 % |
| [crates/aether/src/key_negotiation/mod.rs](../../../crates/aether/src/key_negotiation/mod.rs) | 42 / 42 | 100,00 % | 42 / 42 | 100,00 % |
| [crates/aether/src/locked.rs](../../../crates/aether/src/locked.rs) | 69 / 74 | 93,24 % | 69 / 74 | 93,24 % |
| [crates/aether/src/ml_dsa.rs](../../../crates/aether/src/ml_dsa.rs) | 70 / 70 | 100,00 % | 70 / 70 | 100,00 % |
| [crates/aether/src/mtu.rs](../../../crates/aether/src/mtu.rs) | 17 / 17 | 100,00 % | 17 / 17 | 100,00 % |
| [crates/aether/src/net.rs](../../../crates/aether/src/net.rs) | 150 / 150 | 100,00 % | 150 / 150 | 100,00 % |
| [crates/aether/src/policy.rs](../../../crates/aether/src/policy.rs) | 3 / 3 | 100,00 % | 3 / 3 | 100,00 % |
| [crates/aether/src/pq.rs](../../../crates/aether/src/pq.rs) | 32 / 32 | 100,00 % | 32 / 32 | 100,00 % |
| [crates/aether/src/private_file.rs](../../../crates/aether/src/private_file.rs) | 56 / 60 | 93,33 % | 56 / 60 | 93,33 % |
| [crates/aether/src/random.rs](../../../crates/aether/src/random.rs) | 95 / 112 | 84,82 % | 93 / 112 | 83,04 % |
| [crates/aether/src/secret.rs](../../../crates/aether/src/secret.rs) | 40 / 40 | 100,00 % | 40 / 40 | 100,00 % |
| [crates/aether/src/secret/json.rs](../../../crates/aether/src/secret/json.rs) | 53 / 56 | 94,64 % | 52 / 56 | 92,86 % |
| [crates/aether/src/sig.rs](../../../crates/aether/src/sig.rs) | 310 / 322 | 96,27 % | 275 / 322 | 85,40 % |
| [crates/aether/src/speedtest.rs](../../../crates/aether/src/speedtest.rs) | 43 / 44 | 97,73 % | 43 / 44 | 97,73 % |
| [crates/aether/src/state.rs](../../../crates/aether/src/state.rs) | 40 / 41 | 97,56 % | 40 / 41 | 97,56 % |
| [crates/aether/src/transit_text.rs](../../../crates/aether/src/transit_text.rs) | 26 / 26 | 100,00 % | 26 / 26 | 100,00 % |
| [crates/aether/src/wg.rs](../../../crates/aether/src/wg.rs) | 25 / 25 | 100,00 % | 25 / 25 | 100,00 % |
| [crates/astra-channel/src/authority_client.rs](../../../crates/astra-channel/src/authority_client.rs) | 15 / 174 | 8,62 % | 15 / 174 | 8,62 % |
| [crates/astra-channel/src/authority_routes.rs](../../../crates/astra-channel/src/authority_routes.rs) | 0 / 5 | 0,00 % | 0 / 5 | 0,00 % |
| [crates/astra-channel/src/gateway_client.rs](../../../crates/astra-channel/src/gateway_client.rs) | 41 / 74 | 55,41 % | 41 / 74 | 55,41 % |
| [crates/astra-channel/src/gateway_routes.rs](../../../crates/astra-channel/src/gateway_routes.rs) | 81 / 121 | 66,94 % | 81 / 121 | 66,94 % |
| [crates/astra-channel/src/transport.rs](../../../crates/astra-channel/src/transport.rs) | 289 / 318 | 90,88 % | 282 / 318 | 88,68 % |
| [crates/astra-operator/src/admission.rs](../../../crates/astra-operator/src/admission.rs) | 21 / 21 | 100,00 % | 21 / 21 | 100,00 % |
| [crates/astra-operator/src/campaign.rs](../../../crates/astra-operator/src/campaign.rs) | 7 / 35 | 20,00 % | 7 / 35 | 20,00 % |
| [crates/astra-operator/src/credentials.rs](../../../crates/astra-operator/src/credentials.rs) | 26 / 51 | 50,98 % | 26 / 51 | 50,98 % |
| [crates/astra-operator/src/documents.rs](../../../crates/astra-operator/src/documents.rs) | 20 / 21 | 95,24 % | 20 / 21 | 95,24 % |
| [crates/astra-operator/src/enrollment.rs](../../../crates/astra-operator/src/enrollment.rs) | 280 / 318 | 88,05 % | 278 / 318 | 87,42 % |
| [crates/astra-operator/src/enrollment/test_support.rs](../../../crates/astra-operator/src/enrollment/test_support.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/astra-operator/src/gestures.rs](../../../crates/astra-operator/src/gestures.rs) | 133 / 140 | 95,00 % | 25 / 140 | 17,86 % |
| [crates/astra-operator/src/handoff.rs](../../../crates/astra-operator/src/handoff.rs) | 51 / 108 | 47,22 % | 51 / 108 | 47,22 % |
| [crates/astra-operator/src/operations.rs](../../../crates/astra-operator/src/operations.rs) | 9 / 22 | 40,91 % | 9 / 22 | 40,91 % |
| [crates/astra-operator/src/operations/campaign.rs](../../../crates/astra-operator/src/operations/campaign.rs) | 0 / 100 | 0,00 % | 0 / 100 | 0,00 % |
| [crates/astra-operator/src/operations/recovery.rs](../../../crates/astra-operator/src/operations/recovery.rs) | 0 / 147 | 0,00 % | 0 / 147 | 0,00 % |
| [crates/astra-operator/src/origin.rs](../../../crates/astra-operator/src/origin.rs) | 80 / 233 | 34,33 % | 80 / 233 | 34,33 % |
| [crates/astra-operator/src/orion.rs](../../../crates/astra-operator/src/orion.rs) | 17 / 436 | 3,90 % | 17 / 436 | 3,90 % |
| [crates/astra-operator/src/overview.rs](../../../crates/astra-operator/src/overview.rs) | 52 / 54 | 96,30 % | 52 / 54 | 96,30 % |
| [crates/astra-operator/src/prepared.rs](../../../crates/astra-operator/src/prepared.rs) | 29 / 32 | 90,62 % | 29 / 32 | 90,62 % |
| [crates/astra-operator/src/signing/anchor.rs](../../../crates/astra-operator/src/signing/anchor.rs) | 86 / 96 | 89,58 % | 0 / 96 | 0,00 % |
| [crates/astra-operator/src/signing/bindings.rs](../../../crates/astra-operator/src/signing/bindings.rs) | 132 / 139 | 94,96 % | 0 / 139 | 0,00 % |
| [crates/astra-operator/src/signing/ca_tls.rs](../../../crates/astra-operator/src/signing/ca_tls.rs) | 35 / 120 | 29,17 % | 0 / 120 | 0,00 % |
| [crates/astra-operator/src/signing/campaign.rs](../../../crates/astra-operator/src/signing/campaign.rs) | 154 / 192 | 80,21 % | 0 / 192 | 0,00 % |
| [crates/astra-operator/src/signing/enrollment.rs](../../../crates/astra-operator/src/signing/enrollment.rs) | 260 / 274 | 94,89 % | 0 / 274 | 0,00 % |
| [crates/astra-operator/src/signing/gateway.rs](../../../crates/astra-operator/src/signing/gateway.rs) | 37 / 182 | 20,33 % | 0 / 182 | 0,00 % |
| [crates/astra-operator/src/signing/issuer.rs](../../../crates/astra-operator/src/signing/issuer.rs) | 86 / 102 | 84,31 % | 0 / 102 | 0,00 % |
| [crates/astra-operator/src/signing/mod.rs](../../../crates/astra-operator/src/signing/mod.rs) | 51 / 51 | 100,00 % | 0 / 51 | 0,00 % |
| [crates/astra-operator/src/signing/recovery.rs](../../../crates/astra-operator/src/signing/recovery.rs) | 140 / 207 | 67,63 % | 0 / 207 | 0,00 % |
| [crates/astra-operator/src/signing/revocation.rs](../../../crates/astra-operator/src/signing/revocation.rs) | 36 / 40 | 90,00 % | 0 / 40 | 0,00 % |
| [crates/astra-operator/src/store.rs](../../../crates/astra-operator/src/store.rs) | 26 / 38 | 68,42 % | 26 / 38 | 68,42 % |
| [crates/astra-operator/src/tunnel.rs](../../../crates/astra-operator/src/tunnel.rs) | 130 / 202 | 64,36 % | 12 / 202 | 5,94 % |
| [crates/astra-operator/src/vault.rs](../../../crates/astra-operator/src/vault.rs) | 413 / 436 | 94,72 % | 402 / 436 | 92,20 % |
| [crates/astra-operator/src/vault/tests_support.rs](../../../crates/astra-operator/src/vault/tests_support.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/astra/src/audit.rs](../../../crates/astra/src/audit.rs) | 85 / 91 | 93,41 % | 85 / 91 | 93,41 % |
| [crates/astra/src/campaign_deposit.rs](../../../crates/astra/src/campaign_deposit.rs) | 0 / 118 | 0,00 % | Non collecté | — |
| [crates/astra/src/chain.rs](../../../crates/astra/src/chain.rs) | 111 / 141 | 78,72 % | 111 / 141 | 78,72 % |
| [crates/astra/src/commands/campaign.rs](../../../crates/astra/src/commands/campaign.rs) | 0 / 79 | 0,00 % | Non collecté | — |
| [crates/astra/src/commands/chain.rs](../../../crates/astra/src/commands/chain.rs) | 0 / 185 | 0,00 % | Non collecté | — |
| [crates/astra/src/commands/gateway_identity.rs](../../../crates/astra/src/commands/gateway_identity.rs) | 0 / 87 | 0,00 % | Non collecté | — |
| [crates/astra/src/commands/issuer.rs](../../../crates/astra/src/commands/issuer.rs) | 60 / 141 | 42,55 % | Non collecté | — |
| [crates/astra/src/commands/revocation.rs](../../../crates/astra/src/commands/revocation.rs) | 0 / 147 | 0,00 % | Non collecté | — |
| [crates/astra/src/commands/trust_domain.rs](../../../crates/astra/src/commands/trust_domain.rs) | 104 / 130 | 80,00 % | Non collecté | — |
| [crates/astra/src/daemon.rs](../../../crates/astra/src/daemon.rs) | 0 / 227 | 0,00 % | Non collecté | — |
| [crates/astra/src/distribution.rs](../../../crates/astra/src/distribution.rs) | 72 / 189 | 38,10 % | 72 / 189 | 38,10 % |
| [crates/astra/src/gateway.rs](../../../crates/astra/src/gateway.rs) | 89 / 115 | 77,39 % | 89 / 115 | 77,39 % |
| [crates/astra/src/issuer.rs](../../../crates/astra/src/issuer.rs) | 258 / 270 | 95,56 % | 252 / 270 | 93,33 % |
| [crates/astra/src/main.rs](../../../crates/astra/src/main.rs) | 50 / 132 | 37,88 % | Non collecté | — |
| [crates/astra/src/operations.rs](../../../crates/astra/src/operations.rs) | 470 / 520 | 90,38 % | 470 / 520 | 90,38 % |
| [crates/astra/src/operator.rs](../../../crates/astra/src/operator.rs) | 10 / 105 | 9,52 % | 10 / 105 | 9,52 % |
| [crates/astra/src/planner.rs](../../../crates/astra/src/planner.rs) | 59 / 64 | 92,19 % | 59 / 64 | 92,19 % |
| [crates/astra/src/private_channel.rs](../../../crates/astra/src/private_channel.rs) | 0 / 75 | 0,00 % | Non collecté | — |
| [crates/astra/src/reconciliation.rs](../../../crates/astra/src/reconciliation.rs) | 57 / 74 | 77,03 % | 57 / 74 | 77,03 % |
| [crates/astra/src/recovery.rs](../../../crates/astra/src/recovery.rs) | 377 / 416 | 90,62 % | 377 / 416 | 90,62 % |
| [crates/astra/src/registry.rs](../../../crates/astra/src/registry.rs) | 37 / 37 | 100,00 % | 37 / 37 | 100,00 % |
| [crates/astra/src/registry/challenge.rs](../../../crates/astra/src/registry/challenge.rs) | 24 / 24 | 100,00 % | 24 / 24 | 100,00 % |
| [crates/astra/src/registry/delegation.rs](../../../crates/astra/src/registry/delegation.rs) | 41 / 42 | 97,62 % | 41 / 42 | 97,62 % |
| [crates/astra/src/registry/peer_lifecycle.rs](../../../crates/astra/src/registry/peer_lifecycle.rs) | 217 / 265 | 81,89 % | 217 / 265 | 81,89 % |
| [crates/astra/src/registry/persistence.rs](../../../crates/astra/src/registry/persistence.rs) | 128 / 142 | 90,14 % | 117 / 142 | 82,39 % |
| [crates/astra/src/registry/transitions.rs](../../../crates/astra/src/registry/transitions.rs) | 341 / 377 | 90,45 % | 341 / 377 | 90,45 % |
| [crates/astra/src/renewal/approval.rs](../../../crates/astra/src/renewal/approval.rs) | 172 / 174 | 98,85 % | 172 / 174 | 98,85 % |
| [crates/astra/src/renewal/companion.rs](../../../crates/astra/src/renewal/companion.rs) | 154 / 163 | 94,48 % | 154 / 163 | 94,48 % |
| [crates/astra/src/renewal/mod.rs](../../../crates/astra/src/renewal/mod.rs) | 20 / 22 | 90,91 % | 20 / 22 | 90,91 % |
| [crates/astra/src/renewal/request.rs](../../../crates/astra/src/renewal/request.rs) | 145 / 181 | 80,11 % | 145 / 181 | 80,11 % |
| [crates/astra/src/renewal/router.rs](../../../crates/astra/src/renewal/router.rs) | 55 / 69 | 79,71 % | 55 / 69 | 79,71 % |
| [crates/astra/src/renewal/stage.rs](../../../crates/astra/src/renewal/stage.rs) | 206 / 221 | 93,21 % | 206 / 221 | 93,21 % |
| [crates/astra/src/renewal/test_support.rs](../../../crates/astra/src/renewal/test_support.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/astra/src/renewal/workflow_tests/companion.rs](../../../crates/astra/src/renewal/workflow_tests/companion.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/astra/src/renewal/workflow_tests/concurrency.rs](../../../crates/astra/src/renewal/workflow_tests/concurrency.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/astra/src/renewal/workflow_tests/router.rs](../../../crates/astra/src/renewal/workflow_tests/router.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/astra/src/service.rs](../../../crates/astra/src/service.rs) | 313 / 593 | 52,78 % | 313 / 593 | 52,78 % |
| [crates/astra/src/signing.rs](../../../crates/astra/src/signing.rs) | 127 / 256 | 49,61 % | 127 / 256 | 49,61 % |
| [crates/helios-api/src/auth.rs](../../../crates/helios-api/src/auth.rs) | 117 / 128 | 91,41 % | 117 / 128 | 91,41 % |
| [crates/helios-api/src/certificates/gateway_identity.rs](../../../crates/helios-api/src/certificates/gateway_identity.rs) | 0 / 67 | 0,00 % | 0 / 67 | 0,00 % |
| [crates/helios-api/src/certificates/operator_relay.rs](../../../crates/helios-api/src/certificates/operator_relay.rs) | 79 / 150 | 52,67 % | 79 / 150 | 52,67 % |
| [crates/helios-api/src/certificates/renewal.rs](../../../crates/helios-api/src/certificates/renewal.rs) | 8 / 76 | 10,53 % | 8 / 76 | 10,53 % |
| [crates/helios-api/src/certificates/trust_update.rs](../../../crates/helios-api/src/certificates/trust_update.rs) | 41 / 42 | 97,62 % | 41 / 42 | 97,62 % |
| [crates/helios-api/src/certificates/views.rs](../../../crates/helios-api/src/certificates/views.rs) | 0 / 30 | 0,00 % | 0 / 30 | 0,00 % |
| [crates/helios-api/src/embed.rs](../../../crates/helios-api/src/embed.rs) | 14 / 16 | 87,50 % | 14 / 16 | 87,50 % |
| [crates/helios-api/src/health.rs](../../../crates/helios-api/src/health.rs) | 35 / 65 | 53,85 % | 35 / 65 | 53,85 % |
| [crates/helios-api/src/key_negotiation.rs](../../../crates/helios-api/src/key_negotiation.rs) | 29 / 29 | 100,00 % | 29 / 29 | 100,00 % |
| [crates/helios-api/src/lib.rs](../../../crates/helios-api/src/lib.rs) | 173 / 208 | 83,17 % | 173 / 208 | 83,17 % |
| [crates/helios-api/src/local.rs](../../../crates/helios-api/src/local.rs) | 78 / 100 | 78,00 % | 78 / 100 | 78,00 % |
| [crates/helios-api/src/provision.rs](../../../crates/helios-api/src/provision.rs) | 68 / 87 | 78,16 % | 68 / 87 | 78,16 % |
| [crates/helios-api/src/routes/commands.rs](../../../crates/helios-api/src/routes/commands.rs) | 23 / 24 | 95,83 % | 23 / 24 | 95,83 % |
| [crates/helios-api/src/routes/firewall.rs](../../../crates/helios-api/src/routes/firewall.rs) | 84 / 109 | 77,06 % | 84 / 109 | 77,06 % |
| [crates/helios-api/src/routes/network.rs](../../../crates/helios-api/src/routes/network.rs) | 73 / 104 | 70,19 % | 73 / 104 | 70,19 % |
| [crates/helios-api/src/routes/peers.rs](../../../crates/helios-api/src/routes/peers.rs) | 128 / 153 | 83,66 % | 128 / 153 | 83,66 % |
| [crates/helios-api/src/routes/status.rs](../../../crates/helios-api/src/routes/status.rs) | 48 / 78 | 61,54 % | 48 / 78 | 61,54 % |
| [crates/helios-api/src/speedtest.rs](../../../crates/helios-api/src/speedtest.rs) | 240 / 501 | 47,90 % | 240 / 501 | 47,90 % |
| [crates/helios-api/src/update.rs](../../../crates/helios-api/src/update.rs) | 47 / 65 | 72,31 % | 47 / 65 | 72,31 % |
| [crates/helios-api/src/ws.rs](../../../crates/helios-api/src/ws.rs) | 15 / 22 | 68,18 % | 15 / 22 | 68,18 % |
| [crates/helios-escrow/src/lib.rs](../../../crates/helios-escrow/src/lib.rs) | 89 / 94 | 94,68 % | 89 / 94 | 94,68 % |
| [crates/helios-firewall/src/dryrun.rs](../../../crates/helios-firewall/src/dryrun.rs) | 4 / 7 | 57,14 % | 4 / 7 | 57,14 % |
| [crates/helios-firewall/src/lib.rs](../../../crates/helios-firewall/src/lib.rs) | 2 / 2 | 100,00 % | 2 / 2 | 100,00 % |
| [crates/helios-firewall/src/netlink/expressions.rs](../../../crates/helios-firewall/src/netlink/expressions.rs) | 154 / 160 | 96,25 % | 154 / 160 | 96,25 % |
| [crates/helios-firewall/src/netlink/maintenance.rs](../../../crates/helios-firewall/src/netlink/maintenance.rs) | 0 / 27 | 0,00 % | 0 / 27 | 0,00 % |
| [crates/helios-firewall/src/netlink/transaction.rs](../../../crates/helios-firewall/src/netlink/transaction.rs) | 136 / 156 | 87,18 % | 136 / 156 | 87,18 % |
| [crates/helios-firewall/src/ruleset.rs](../../../crates/helios-firewall/src/ruleset.rs) | 72 / 72 | 100,00 % | 72 / 72 | 100,00 % |
| [crates/helios-firewall/src/ruleset/administration.rs](../../../crates/helios-firewall/src/ruleset/administration.rs) | 64 / 64 | 100,00 % | 64 / 64 | 100,00 % |
| [crates/helios-firewall/src/ruleset/astra_channel.rs](../../../crates/helios-firewall/src/ruleset/astra_channel.rs) | 42 / 42 | 100,00 % | 42 / 42 | 100,00 % |
| [crates/helios-firewall/src/ruleset/client_ipv6_egress.rs](../../../crates/helios-firewall/src/ruleset/client_ipv6_egress.rs) | 38 / 38 | 100,00 % | 38 / 38 | 100,00 % |
| [crates/helios-firewall/src/ruleset/gateway_wan.rs](../../../crates/helios-firewall/src/ruleset/gateway_wan.rs) | 123 / 123 | 100,00 % | 123 / 123 | 100,00 % |
| [crates/helios-firewall/src/ruleset/kill_switch.rs](../../../crates/helios-firewall/src/ruleset/kill_switch.rs) | 86 / 86 | 100,00 % | 86 / 86 | 100,00 % |
| [crates/helios-firewall/src/ruleset/link_ipv6.rs](../../../crates/helios-firewall/src/ruleset/link_ipv6.rs) | 84 / 84 | 100,00 % | 84 / 84 | 100,00 % |
| [crates/helios-firewall/src/ruleset/meshnet.rs](../../../crates/helios-firewall/src/ruleset/meshnet.rs) | 98 / 98 | 100,00 % | 98 / 98 | 100,00 % |
| [crates/helios-firewall/src/ruleset/nftables.rs](../../../crates/helios-firewall/src/ruleset/nftables.rs) | 182 / 202 | 90,10 % | 182 / 202 | 90,10 % |
| [crates/helios-firewall/src/ruleset/transport.rs](../../../crates/helios-firewall/src/ruleset/transport.rs) | 130 / 130 | 100,00 % | 130 / 130 | 100,00 % |
| [crates/helios-firewall/src/ruleset/tunnel_interface.rs](../../../crates/helios-firewall/src/ruleset/tunnel_interface.rs) | 77 / 77 | 100,00 % | 77 / 77 | 100,00 % |
| [crates/helios-provisioning/src/admission.rs](../../../crates/helios-provisioning/src/admission.rs) | 130 / 130 | 100,00 % | 130 / 130 | 100,00 % |
| [crates/helios-provisioning/src/certificates.rs](../../../crates/helios-provisioning/src/certificates.rs) | 54 / 74 | 72,97 % | 54 / 74 | 72,97 % |
| [crates/helios-provisioning/src/certificates/distribution.rs](../../../crates/helios-provisioning/src/certificates/distribution.rs) | 83 / 90 | 92,22 % | 82 / 90 | 91,11 % |
| [crates/helios-provisioning/src/certificates/persistence.rs](../../../crates/helios-provisioning/src/certificates/persistence.rs) | 94 / 109 | 86,24 % | 94 / 109 | 86,24 % |
| [crates/helios-provisioning/src/certificates/staging.rs](../../../crates/helios-provisioning/src/certificates/staging.rs) | 284 / 423 | 67,14 % | 284 / 423 | 67,14 % |
| [crates/helios-provisioning/src/certificates/transitions.rs](../../../crates/helios-provisioning/src/certificates/transitions.rs) | 121 / 125 | 96,80 % | 121 / 125 | 96,80 % |
| [crates/helios-provisioning/src/certificates/trust.rs](../../../crates/helios-provisioning/src/certificates/trust.rs) | 157 / 165 | 95,15 % | 157 / 165 | 95,15 % |
| [crates/helios-provisioning/src/ipam.rs](../../../crates/helios-provisioning/src/ipam.rs) | 107 / 107 | 100,00 % | 107 / 107 | 100,00 % |
| [crates/helios-provisioning/src/rotation.rs](../../../crates/helios-provisioning/src/rotation.rs) | 49 / 49 | 100,00 % | 49 / 49 | 100,00 % |
| [crates/helios-provisioning/src/session.rs](../../../crates/helios-provisioning/src/session.rs) | 47 / 48 | 97,92 % | 47 / 48 | 97,92 % |
| [crates/helios-tpm/src/blob_store.rs](../../../crates/helios-tpm/src/blob_store.rs) | 73 / 91 | 80,22 % | 73 / 91 | 80,22 % |
| [crates/helios-tpm/src/boot_controller.rs](../../../crates/helios-tpm/src/boot_controller.rs) | 98 / 157 | 62,42 % | 97 / 157 | 61,78 % |
| [crates/helios-tpm/src/firmware_recovery.rs](../../../crates/helios-tpm/src/firmware_recovery.rs) | 126 / 189 | 66,67 % | 111 / 189 | 58,73 % |
| [crates/helios-tpm/src/keystore.rs](../../../crates/helios-tpm/src/keystore.rs) | 98 / 135 | 72,59 % | 98 / 135 | 72,59 % |
| [crates/helios-tpm/src/provisioning.rs](../../../crates/helios-tpm/src/provisioning.rs) | 88 / 91 | 96,70 % | 88 / 91 | 96,70 % |
| [crates/helios-tpm/src/reseal_ticket.rs](../../../crates/helios-tpm/src/reseal_ticket.rs) | 37 / 38 | 97,37 % | 37 / 38 | 97,37 % |
| [crates/helios-tpm/src/secret.rs](../../../crates/helios-tpm/src/secret.rs) | 11 / 14 | 78,57 % | 11 / 14 | 78,57 % |
| [crates/helios-tpm/src/settings.rs](../../../crates/helios-tpm/src/settings.rs) | 17 / 17 | 100,00 % | 17 / 17 | 100,00 % |
| [crates/helios-tpm/src/tpm_interface.rs](../../../crates/helios-tpm/src/tpm_interface.rs) | 6 / 6 | 100,00 % | 6 / 6 | 100,00 % |
| [crates/helios-tpm/src/tpm_real.rs](../../../crates/helios-tpm/src/tpm_real.rs) | 0 / 527 | 0,00 % | 0 / 527 | 0,00 % |
| [crates/helios-tpm/src/update_window.rs](../../../crates/helios-tpm/src/update_window.rs) | 98 / 103 | 95,15 % | 98 / 103 | 95,15 % |
| [crates/helios-update/src/bundle.rs](../../../crates/helios-update/src/bundle.rs) | 254 / 309 | 82,20 % | 240 / 309 | 77,67 % |
| [crates/helios-update/src/lib.rs](../../../crates/helios-update/src/lib.rs) | 370 / 454 | 81,50 % | 370 / 454 | 81,50 % |
| [crates/helios-wireguard/src/dryrun.rs](../../../crates/helios-wireguard/src/dryrun.rs) | 85 / 88 | 96,59 % | 66 / 88 | 75,00 % |
| [crates/helios-wireguard/src/kernel.rs](../../../crates/helios-wireguard/src/kernel.rs) | 54 / 102 | 52,94 % | 54 / 102 | 52,94 % |
| [crates/helios-wireguard/src/lib.rs](../../../crates/helios-wireguard/src/lib.rs) | 3 / 3 | 100,00 % | 3 / 3 | 100,00 % |
| [crates/heliosd/src/astra_channel.rs](../../../crates/heliosd/src/astra_channel.rs) | 161 / 322 | 50,00 % | Non collecté | — |
| [crates/heliosd/src/certificates/admission.rs](../../../crates/heliosd/src/certificates/admission.rs) | 22 / 44 | 50,00 % | Non collecté | — |
| [crates/heliosd/src/certificates/astra.rs](../../../crates/heliosd/src/certificates/astra.rs) | 52 / 122 | 42,62 % | Non collecté | — |
| [crates/heliosd/src/certificates/gateway_identity.rs](../../../crates/heliosd/src/certificates/gateway_identity.rs) | 0 / 34 | 0,00 % | Non collecté | — |
| [crates/heliosd/src/certificates/mod.rs](../../../crates/heliosd/src/certificates/mod.rs) | 38 / 51 | 74,51 % | Non collecté | — |
| [crates/heliosd/src/certificates/service.rs](../../../crates/heliosd/src/certificates/service.rs) | 109 / 191 | 57,07 % | Non collecté | — |
| [crates/heliosd/src/certificates/trust_update.rs](../../../crates/heliosd/src/certificates/trust_update.rs) | 14 / 48 | 29,17 % | Non collecté | — |
| [crates/heliosd/src/certificates/views.rs](../../../crates/heliosd/src/certificates/views.rs) | 114 / 118 | 96,61 % | Non collecté | — |
| [crates/heliosd/src/commands/identity.rs](../../../crates/heliosd/src/commands/identity.rs) | 0 / 88 | 0,00 % | Non collecté | — |
| [crates/heliosd/src/commands/ipv6_prefix.rs](../../../crates/heliosd/src/commands/ipv6_prefix.rs) | 26 / 37 | 70,27 % | Non collecté | — |
| [crates/heliosd/src/commands/peer.rs](../../../crates/heliosd/src/commands/peer.rs) | 21 / 117 | 17,95 % | Non collecté | — |
| [crates/heliosd/src/commands/tpm.rs](../../../crates/heliosd/src/commands/tpm.rs) | 7 / 116 | 6,03 % | Non collecté | — |
| [crates/heliosd/src/commands/trust.rs](../../../crates/heliosd/src/commands/trust.rs) | 14 / 336 | 4,17 % | Non collecté | — |
| [crates/heliosd/src/commands/wan.rs](../../../crates/heliosd/src/commands/wan.rs) | 0 / 39 | 0,00 % | Non collecté | — |
| [crates/heliosd/src/daemon.rs](../../../crates/heliosd/src/daemon.rs) | 0 / 204 | 0,00 % | Non collecté | — |
| [crates/heliosd/src/gateway_key.rs](../../../crates/heliosd/src/gateway_key.rs) | 115 / 219 | 52,51 % | Non collecté | — |
| [crates/heliosd/src/gateway_rotation.rs](../../../crates/heliosd/src/gateway_rotation.rs) | 148 / 381 | 38,85 % | Non collecté | — |
| [crates/heliosd/src/key_negotiation/candidate.rs](../../../crates/heliosd/src/key_negotiation/candidate.rs) | 4 / 189 | 2,12 % | Non collecté | — |
| [crates/heliosd/src/key_negotiation/identity.rs](../../../crates/heliosd/src/key_negotiation/identity.rs) | 103 / 429 | 24,01 % | Non collecté | — |
| [crates/heliosd/src/key_negotiation/mod.rs](../../../crates/heliosd/src/key_negotiation/mod.rs) | 27 / 40 | 67,50 % | Non collecté | — |
| [crates/heliosd/src/key_negotiation/origin.rs](../../../crates/heliosd/src/key_negotiation/origin.rs) | 23 / 23 | 100,00 % | Non collecté | — |
| [crates/heliosd/src/key_negotiation/protocol.rs](../../../crates/heliosd/src/key_negotiation/protocol.rs) | 69 / 89 | 77,53 % | Non collecté | — |
| [crates/heliosd/src/key_negotiation/server.rs](../../../crates/heliosd/src/key_negotiation/server.rs) | 0 / 112 | 0,00 % | Non collecté | — |
| [crates/heliosd/src/key_negotiation/transaction.rs](../../../crates/heliosd/src/key_negotiation/transaction.rs) | 348 / 413 | 84,26 % | Non collecté | — |
| [crates/heliosd/src/main.rs](../../../crates/heliosd/src/main.rs) | 5 / 127 | 3,94 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/commands.rs](../../../crates/heliosd/src/orchestrator/commands.rs) | 72 / 196 | 36,73 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/data_plane.rs](../../../crates/heliosd/src/orchestrator/data_plane.rs) | 294 / 402 | 73,13 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/mod.rs](../../../crates/heliosd/src/orchestrator/mod.rs) | 36 / 304 | 11,84 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/observation.rs](../../../crates/heliosd/src/orchestrator/observation.rs) | 82 / 104 | 78,85 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/probes.rs](../../../crates/heliosd/src/orchestrator/probes.rs) | 69 / 107 | 64,49 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/reload.rs](../../../crates/heliosd/src/orchestrator/reload.rs) | 0 / 43 | 0,00 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/telemetry.rs](../../../crates/heliosd/src/orchestrator/telemetry.rs) | 0 / 20 | 0,00 % | Non collecté | — |
| [crates/heliosd/src/orchestrator/uplinks.rs](../../../crates/heliosd/src/orchestrator/uplinks.rs) | 75 / 111 | 67,57 % | Non collecté | — |
| [crates/heliosd/src/process_guards.rs](../../../crates/heliosd/src/process_guards.rs) | 26 / 34 | 76,47 % | Non collecté | — |
| [crates/heliosd/src/static_psk.rs](../../../crates/heliosd/src/static_psk.rs) | 228 / 270 | 84,44 % | Non collecté | — |
| [crates/heliosd/src/uplink.rs](../../../crates/heliosd/src/uplink.rs) | 112 / 125 | 89,60 % | Non collecté | — |
| [crates/heliosd/src/vip_routing.rs](../../../crates/heliosd/src/vip_routing.rs) | 93 / 153 | 60,78 % | Non collecté | — |
| [crates/orion-core/src/backend/controller.rs](../../../crates/orion-core/src/backend/controller.rs) | 391 / 475 | 82,32 % | 391 / 475 | 82,32 % |
| [crates/orion-core/src/backend/dryrun.rs](../../../crates/orion-core/src/backend/dryrun.rs) | 54 / 55 | 98,18 % | 54 / 55 | 98,18 % |
| [crates/orion-core/src/backend/mod.rs](../../../crates/orion-core/src/backend/mod.rs) | 0 / 5 | 0,00 % | 0 / 5 | 0,00 % |
| [crates/orion-core/src/backend/negotiation.rs](../../../crates/orion-core/src/backend/negotiation.rs) | 71 / 269 | 26,39 % | 71 / 269 | 26,39 % |
| [crates/orion-core/src/backend/renewal.rs](../../../crates/orion-core/src/backend/renewal.rs) | 40 / 42 | 95,24 % | 40 / 42 | 95,24 % |
| [crates/orion-core/src/backend/slot_renewal.rs](../../../crates/orion-core/src/backend/slot_renewal.rs) | 123 / 157 | 78,34 % | 123 / 157 | 78,34 % |
| [crates/orion-core/src/backend/wireguard.rs](../../../crates/orion-core/src/backend/wireguard.rs) | 228 / 315 | 72,38 % | 228 / 315 | 72,38 % |
| [crates/orion-core/src/certificate_actions.rs](../../../crates/orion-core/src/certificate_actions.rs) | 170 / 181 | 93,92 % | 170 / 181 | 93,92 % |
| [crates/orion-core/src/certificate_approval.rs](../../../crates/orion-core/src/certificate_approval.rs) | 84 / 107 | 78,50 % | 84 / 107 | 78,50 % |
| [crates/orion-core/src/certificate_http.rs](../../../crates/orion-core/src/certificate_http.rs) | 17 / 17 | 100,00 % | 17 / 17 | 100,00 % |
| [crates/orion-core/src/certificate_inventory.rs](../../../crates/orion-core/src/certificate_inventory.rs) | 136 / 238 | 57,14 % | 136 / 238 | 57,14 % |
| [crates/orion-core/src/certificate_recovery.rs](../../../crates/orion-core/src/certificate_recovery.rs) | 102 / 360 | 28,33 % | 102 / 360 | 28,33 % |
| [crates/orion-core/src/certificate_renewal/exchange.rs](../../../crates/orion-core/src/certificate_renewal/exchange.rs) | 235 / 515 | 45,63 % | 235 / 515 | 45,63 % |
| [crates/orion-core/src/certificate_renewal/promotion.rs](../../../crates/orion-core/src/certificate_renewal/promotion.rs) | 38 / 183 | 20,77 % | 38 / 183 | 20,77 % |
| [crates/orion-core/src/certificate_renewal/trust_store.rs](../../../crates/orion-core/src/certificate_renewal/trust_store.rs) | 249 / 265 | 93,96 % | 249 / 265 | 93,96 % |
| [crates/orion-core/src/certificates.rs](../../../crates/orion-core/src/certificates.rs) | 356 / 529 | 67,30 % | 356 / 529 | 67,30 % |
| [crates/orion-core/src/config.rs](../../../crates/orion-core/src/config.rs) | 316 / 339 | 93,22 % | 316 / 339 | 93,22 % |
| [crates/orion-core/src/config/legacy_fixture.rs](../../../crates/orion-core/src/config/legacy_fixture.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/orion-core/src/endpoint_resolution.rs](../../../crates/orion-core/src/endpoint_resolution.rs) | 166 / 175 | 94,86 % | 159 / 175 | 90,86 % |
| [crates/orion-core/src/enrollment.rs](../../../crates/orion-core/src/enrollment.rs) | 301 / 342 | 88,01 % | 301 / 342 | 88,01 % |
| [crates/orion-core/src/enrollment_draft.rs](../../../crates/orion-core/src/enrollment_draft.rs) | 114 / 117 | 97,44 % | 113 / 117 | 96,58 % |
| [crates/orion-core/src/events.rs](../../../crates/orion-core/src/events.rs) | 15 / 15 | 100,00 % | 15 / 15 | 100,00 % |
| [crates/orion-core/src/gateway_admin.rs](../../../crates/orion-core/src/gateway_admin.rs) | 216 / 223 | 96,86 % | 216 / 223 | 96,86 % |
| [crates/orion-core/src/identity_store.rs](../../../crates/orion-core/src/identity_store.rs) | 306 / 425 | 72,00 % | 306 / 425 | 72,00 % |
| [crates/orion-core/src/key_negotiation.rs](../../../crates/orion-core/src/key_negotiation.rs) | 337 / 458 | 73,58 % | 105 / 458 | 22,93 % |
| [crates/orion-core/src/mtu.rs](../../../crates/orion-core/src/mtu.rs) | 12 / 19 | 63,16 % | 12 / 19 | 63,16 % |
| [crates/orion-core/src/net_pin.rs](../../../crates/orion-core/src/net_pin.rs) | 20 / 20 | 100,00 % | 4 / 20 | 20,00 % |
| [crates/orion-core/src/operator_pending.rs](../../../crates/orion-core/src/operator_pending.rs) | 4 / 26 | 15,38 % | 4 / 26 | 15,38 % |
| [crates/orion-core/src/profile_import/document.rs](../../../crates/orion-core/src/profile_import/document.rs) | 115 / 132 | 87,12 % | 115 / 132 | 87,12 % |
| [crates/orion-core/src/profile_import/field_rules.rs](../../../crates/orion-core/src/profile_import/field_rules.rs) | 223 / 234 | 95,30 % | 223 / 234 | 95,30 % |
| [crates/orion-core/src/profile_import/json.rs](../../../crates/orion-core/src/profile_import/json.rs) | 118 / 122 | 96,72 % | 118 / 122 | 96,72 % |
| [crates/orion-core/src/profile_import/validation.rs](../../../crates/orion-core/src/profile_import/validation.rs) | 119 / 121 | 98,35 % | 119 / 121 | 98,35 % |
| [crates/orion-core/src/profile_import/wg_quick.rs](../../../crates/orion-core/src/profile_import/wg_quick.rs) | 132 / 140 | 94,29 % | 132 / 140 | 94,29 % |
| [crates/orion-core/src/protected_root.rs](../../../crates/orion-core/src/protected_root.rs) | 49 / 54 | 90,74 % | 49 / 54 | 90,74 % |
| [crates/orion-core/src/provisioning.rs](../../../crates/orion-core/src/provisioning.rs) | 64 / 90 | 71,11 % | 64 / 90 | 71,11 % |
| [crates/orion-core/src/speedtest/failure.rs](../../../crates/orion-core/src/speedtest/failure.rs) | 37 / 40 | 92,50 % | 37 / 40 | 92,50 % |
| [crates/orion-core/src/speedtest/http.rs](../../../crates/orion-core/src/speedtest/http.rs) | 328 / 364 | 90,11 % | 328 / 364 | 90,11 % |
| [crates/orion-core/src/speedtest/mod.rs](../../../crates/orion-core/src/speedtest/mod.rs) | 33 / 59 | 55,93 % | 33 / 59 | 55,93 % |
| [crates/orion-core/src/speedtest/raw.rs](../../../crates/orion-core/src/speedtest/raw.rs) | 346 / 383 | 90,34 % | 346 / 383 | 90,34 % |
| [crates/orion-core/src/speedtest/udp.rs](../../../crates/orion-core/src/speedtest/udp.rs) | 230 / 270 | 85,19 % | 230 / 270 | 85,19 % |
| [crates/orion-core/src/speedtest/wire.rs](../../../crates/orion-core/src/speedtest/wire.rs) | 85 / 85 | 100,00 % | 85 / 85 | 100,00 % |
| [crates/orion-core/src/telemetry.rs](../../../crates/orion-core/src/telemetry.rs) | 61 / 78 | 78,21 % | 61 / 78 | 78,21 % |
| [crates/orion-core/src/test_domain.rs](../../../crates/orion-core/src/test_domain.rs) | 0 / 0 | Sans ligne retenue | 0 / 0 | Sans ligne retenue |
| [crates/orion-core/src/trust_update.rs](../../../crates/orion-core/src/trust_update.rs) | 123 / 165 | 74,55 % | 123 / 165 | 74,55 % |
| [crates/orion-core/src/vault/codec.rs](../../../crates/orion-core/src/vault/codec.rs) | 73 / 73 | 100,00 % | 73 / 73 | 100,00 % |
| [crates/orion-core/src/vault/keys.rs](../../../crates/orion-core/src/vault/keys.rs) | 30 / 30 | 100,00 % | 30 / 30 | 100,00 % |
| [crates/orion-core/src/vault/manifest.rs](../../../crates/orion-core/src/vault/manifest.rs) | 298 / 313 | 95,21 % | 298 / 313 | 95,21 % |
| [crates/orion-core/src/vault/mod.rs](../../../crates/orion-core/src/vault/mod.rs) | 85 / 87 | 97,70 % | 85 / 87 | 97,70 % |
| [crates/orion-core/src/vault/passphrase.rs](../../../crates/orion-core/src/vault/passphrase.rs) | 40 / 41 | 97,56 % | 40 / 41 | 97,56 % |
| [crates/orion-core/src/vault/registry.rs](../../../crates/orion-core/src/vault/registry.rs) | 77 / 87 | 88,51 % | 77 / 87 | 88,51 % |
| [crates/orion-core/src/vault/relocation.rs](../../../crates/orion-core/src/vault/relocation.rs) | 390 / 432 | 90,28 % | 390 / 432 | 90,28 % |
| [crates/orion-core/src/vault/settings.rs](../../../crates/orion-core/src/vault/settings.rs) | 21 / 36 | 58,33 % | 21 / 36 | 58,33 % |
| [crates/orion-core/src/vault/store.rs](../../../crates/orion-core/src/vault/store.rs) | 353 / 423 | 83,45 % | 353 / 423 | 83,45 % |
| [crates/orion-core/src/vault/windows/bitlocker.rs](../../../crates/orion-core/src/vault/windows/bitlocker.rs) | 23 / 24 | 95,83 % | 23 / 24 | 95,83 % |
| [crates/orion-core/src/vault/windows/dpapi.rs](../../../crates/orion-core/src/vault/windows/dpapi.rs) | 12 / 12 | 100,00 % | 12 / 12 | 100,00 % |
| [crates/orion-core/src/vault/windows/dumps.rs](../../../crates/orion-core/src/vault/windows/dumps.rs) | 24 / 25 | 96,00 % | 24 / 25 | 96,00 % |
| [crates/orion-core/src/vault/windows/mod.rs](../../../crates/orion-core/src/vault/windows/mod.rs) | 45 / 80 | 56,25 % | 45 / 80 | 56,25 % |
| [crates/orion-core/src/vault/windows/prompt.rs](../../../crates/orion-core/src/vault/windows/prompt.rs) | 6 / 6 | 100,00 % | 6 / 6 | 100,00 % |
| [crates/orion-core/src/vault/windows/tpm.rs](../../../crates/orion-core/src/vault/windows/tpm.rs) | 25 / 30 | 83,33 % | 25 / 30 | 83,33 % |
| [crates/orion-engine/src/client.rs](../../../crates/orion-engine/src/client.rs) | 99 / 106 | 93,40 % | 96 / 106 | 90,57 % |
| [crates/orion-engine/src/command.rs](../../../crates/orion-engine/src/command.rs) | 15 / 15 | 100,00 % | 15 / 15 | 100,00 % |
| [crates/orion-engine/src/events.rs](../../../crates/orion-engine/src/events.rs) | 33 / 33 | 100,00 % | 33 / 33 | 100,00 % |
| [crates/orion-engine/src/legacy_cleanup.rs](../../../crates/orion-engine/src/legacy_cleanup.rs) | 3 / 3 | 100,00 % | 3 / 3 | 100,00 % |
| [crates/orion-engine/src/lifecycle.rs](../../../crates/orion-engine/src/lifecycle.rs) | 102 / 103 | 99,03 % | 102 / 103 | 99,03 % |
| [crates/orion-engine/src/pipe.rs](../../../crates/orion-engine/src/pipe.rs) | 48 / 72 | 66,67 % | 48 / 72 | 66,67 % |
| [crates/orion-engine/src/serve.rs](../../../crates/orion-engine/src/serve.rs) | 145 / 155 | 93,55 % | 145 / 155 | 93,55 % |
| [crates/orion-engine/src/service.rs](../../../crates/orion-engine/src/service.rs) | 95 / 119 | 79,83 % | 95 / 119 | 79,83 % |
| [crates/orion-engine/src/service/app.rs](../../../crates/orion-engine/src/service/app.rs) | 20 / 51 | 39,22 % | 17 / 51 | 33,33 % |
| [crates/orion-engine/src/service/certificates.rs](../../../crates/orion-engine/src/service/certificates.rs) | 203 / 423 | 47,99 % | 203 / 423 | 47,99 % |
| [crates/orion-engine/src/service/connection.rs](../../../crates/orion-engine/src/service/connection.rs) | 90 / 164 | 54,88 % | 90 / 164 | 54,88 % |
| [crates/orion-engine/src/service/enrollment.rs](../../../crates/orion-engine/src/service/enrollment.rs) | 30 / 57 | 52,63 % | 24 / 57 | 42,11 % |
| [crates/orion-engine/src/service/profiles.rs](../../../crates/orion-engine/src/service/profiles.rs) | 204 / 316 | 64,56 % | 204 / 316 | 64,56 % |
| [crates/orion-engine/src/session.rs](../../../crates/orion-engine/src/session.rs) | 72 / 72 | 100,00 % | 72 / 72 | 100,00 % |
| [crates/orion-engine/src/view.rs](../../../crates/orion-engine/src/view.rs) | 32 / 70 | 45,71 % | 32 / 70 | 45,71 % |
| [crates/orion-engine/src/wire.rs](../../../crates/orion-engine/src/wire.rs) | 42 / 42 | 100,00 % | 42 / 42 | 100,00 % |
| [tools/astra-signer/src/cli.rs](../../../tools/astra-signer/src/cli.rs) | 0 / 27 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/ca_pq_rotation.rs](../../../tools/astra-signer/src/commands/ca_pq_rotation.rs) | 0 / 265 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/ca_tls_rotation.rs](../../../tools/astra-signer/src/commands/ca_tls_rotation.rs) | 0 / 232 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/campaign.rs](../../../tools/astra-signer/src/commands/campaign.rs) | 0 / 189 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/enrollment.rs](../../../tools/astra-signer/src/commands/enrollment.rs) | 0 / 224 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/gateway_identity.rs](../../../tools/astra-signer/src/commands/gateway_identity.rs) | 7 / 482 | 1,45 % | Non collecté | — |
| [tools/astra-signer/src/commands/issuer.rs](../../../tools/astra-signer/src/commands/issuer.rs) | 0 / 199 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/mod.rs](../../../tools/astra-signer/src/commands/mod.rs) | 3 / 92 | 3,26 % | Non collecté | — |
| [tools/astra-signer/src/commands/recovery.rs](../../../tools/astra-signer/src/commands/recovery.rs) | 0 / 34 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/revocation.rs](../../../tools/astra-signer/src/commands/revocation.rs) | 0 / 156 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/commands/vault.rs](../../../tools/astra-signer/src/commands/vault.rs) | 0 / 335 | 0,00 % | Non collecté | — |
| [tools/astra-signer/src/main.rs](../../../tools/astra-signer/src/main.rs) | 0 / 257 | 0,00 % | Non collecté | — |
| [tools/helios-installer/src/main.rs](../../../tools/helios-installer/src/main.rs) | 63 / 175 | 36,00 % | Non collecté | — |
| [tools/helios-publisher/src/main.rs](../../../tools/helios-publisher/src/main.rs) | 288 / 383 | 75,20 % | Non collecté | — |
| [tools/helios/src/api.rs](../../../tools/helios/src/api.rs) | 50 / 77 | 64,94 % | Non collecté | — |
| [tools/helios/src/app_update.rs](../../../tools/helios/src/app_update.rs) | 127 / 222 | 57,21 % | Non collecté | — |
| [tools/helios/src/campaign.rs](../../../tools/helios/src/campaign.rs) | 81 / 408 | 19,85 % | Non collecté | — |
| [tools/helios/src/campaign_key_nego.rs](../../../tools/helios/src/campaign_key_nego.rs) | 217 / 392 | 55,36 % | Non collecté | — |
| [tools/helios/src/enroll.rs](../../../tools/helios/src/enroll.rs) | 26 / 134 | 19,40 % | Non collecté | — |
| [tools/helios/src/escrow.rs](../../../tools/helios/src/escrow.rs) | 52 / 53 | 98,11 % | Non collecté | — |
| [tools/helios/src/files.rs](../../../tools/helios/src/files.rs) | 22 / 22 | 100,00 % | Non collecté | — |
| [tools/helios/src/firmware.rs](../../../tools/helios/src/firmware.rs) | 232 / 646 | 35,91 % | Non collecté | — |
| [tools/helios/src/inspect.rs](../../../tools/helios/src/inspect.rs) | 631 / 861 | 73,29 % | Non collecté | — |
| [tools/helios/src/inspect/firewall.rs](../../../tools/helios/src/inspect/firewall.rs) | 257 / 273 | 94,14 % | Non collecté | — |
| [tools/helios/src/interactive.rs](../../../tools/helios/src/interactive.rs) | 88 / 319 | 27,59 % | Non collecté | — |
| [tools/helios/src/interactive/palette.rs](../../../tools/helios/src/interactive/palette.rs) | 138 / 151 | 91,39 % | Non collecté | — |
| [tools/helios/src/interactive/presentation.rs](../../../tools/helios/src/interactive/presentation.rs) | 209 / 241 | 86,72 % | Non collecté | — |
| [tools/helios/src/key_nego.rs](../../../tools/helios/src/key_nego.rs) | 257 / 359 | 71,59 % | Non collecté | — |
| [tools/helios/src/main.rs](../../../tools/helios/src/main.rs) | 68 / 357 | 19,05 % | Non collecté | — |
| [tools/helios/src/monitor.rs](../../../tools/helios/src/monitor.rs) | 21 / 134 | 15,67 % | Non collecté | — |
| [tools/helios/src/peer.rs](../../../tools/helios/src/peer.rs) | 64 / 66 | 96,97 % | Non collecté | — |
| [tools/helios/src/profile.rs](../../../tools/helios/src/profile.rs) | 104 / 186 | 55,91 % | Non collecté | — |
| [tools/helios/src/transport.rs](../../../tools/helios/src/transport.rs) | 53 / 66 | 80,30 % | Non collecté | — |
| [tools/helios/src/ui.rs](../../../tools/helios/src/ui.rs) | 168 / 188 | 89,36 % | Non collecté | — |
| [tools/helios/src/update.rs](../../../tools/helios/src/update.rs) | 67 / 240 | 27,92 % | Non collecté | — |
| [tools/xtask/src/main.rs](../../../tools/xtask/src/main.rs) | 51 / 319 | 15,99 % | Non collecté | — |
| [tools/xtask/src/orion_deps.rs](../../../tools/xtask/src/orion_deps.rs) | 0 / 104 | 0,00 % | 0 / 104 | 0,00 % |

## Provenance et reproduction

Les deux statuts sont `completed`, les 548 empreintes Rust et toutes les entrées Cargo de chaque collecte correspondent au commit annoncé. Les empreintes du JSON LLVM, LCOV et metadata ont été revérifiées. Les sources étaient propres pendant les collectes ; les modifications ultérieures du journal sont documentaires.

| Vue | Export complet local | SHA-256 du rapport projeté | SHA-256 de provenance |
| --- | --- | --- | --- |
| workspace | `/home/christophe/helios/.tmp/audit-20261028-workspace` | `0101bcb9493148f5939d554c762a6230126434f749c067ea2811f46fbf9ba2d0` | `856079c6f4a8f2ce91fea6549e4c0d39d0bb045a919175cd4309f671722f7d58` |
| libraries | `/home/christophe/helios/.tmp/audit-20261028-libraries` | `365f72f2f2d30c1a9b611ae6c9b5333f5a00cc42b16eb28dc679522069bde1e1` | `2766e75829971b41306760dbf75be920a850bfb9b0e3b986685f138db018d660` |

Chaque dossier contient `workspace.json`, `workspace.lcov`, `rust-html/html`, `metadata.json`, `provenance.json`, `report.json` et `status.json`. Les logs et archives des deux révisions sont dans `.tmp/audit-20261028/` du worktree d’audit, ignoré par Git. Conserver ces dossiers pour une contre-vérification ; ils ne font pas partie de la livraison. Les exports F11 sous `/tmp` avaient disparu à la reprise, ce qui a motivé ce stockage persistant.

Commandes utilisées depuis la racine du worktree :

```sh
bash scripts/audit-rust.sh collect --view workspace --output-dir /home/christophe/helios/.tmp/audit-20261028-workspace
bash scripts/audit-rust.sh collect --view libraries --output-dir /home/christophe/helios/.tmp/audit-20261028-libraries
```

Pour reproduire, utiliser le même commit et les mêmes outils, construire les frontends selon `docs/testing/TESTING.md`, puis choisir **de nouvelles destinations hors des sources**, car le collecteur refuse un dossier non vide. Le build passe par le cache unique avec son budget 65 Gio. Aucun seuil de couverture ni workflow CI n’a été changé.

La [baseline F11](15-f11-file-baseline.md) reste historique : ses 56 421 lignes de production diffèrent des 57 886 actuelles. Ne pas attribuer la variation globale à nos trois tests de profils ni calculer un gain à dénominateur constant entre ces deux révisions. Le [journal après F14](16-f14-integration.md) décrit le rebase, les tests, les tailles et les validations natives restantes.
