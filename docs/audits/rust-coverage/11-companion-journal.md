# Journal du compagnon et refus recovery — troisième lot

Référence : `a4bdf1b`, branche `feat/local-rust-audit`. Corrections du journal : `85c87f5` ; refus recovery : `51dc912`. Les sources Rust de la baseline globale et bibliothèques du journal 10 concordent avec cette référence ; aucun lockfile, profil ou workflow n’est modifié.

## Mesures finales

| Mesure | Avant | Après |
|---|---:|---:|
| **Production globale Linux** | 32 339 / 53 087 = 60,92 % | **32 604 / 53 102 = 61,40 %** |
| **Production bibliothèques, collecte distincte** | 24 438 / 34 930 = 69,96 % | **24 706 / 34 945 = 70,70 %** |
| Lignes globales brutes LLVM | 48 518 / 71 049 = 68,29 % | 49 246 / 71 524 = 68,85 % |
| Fonctions globales brutes LLVM | 4 611 / 7 011 = 65,77 % | 4 648 / 7 039 = 66,03 % |
| Fonctions globales brutes jamais exécutées | 2 400 | 2 391 |
| Régions globales brutes LLVM | 71 366 / 105 614 = 67,57 % | 72 529 / 106 492 = 68,11 % |
| Tests réussis, collecte globale | 2 221 | 2 228 |
| Tests réussis, bibliothèques seules | 1 737 | 1 744 |

Les deux collectes finales sont `completed`, sans échec/ignoré. Branches/MC/DC non instrumentées, donc **non mesurées**. Le brut LLVM bibliothèques atteint 36 729 / 47 967 = 76,57 %, distinct de sa projection de production. Rust 1.99.0, LLVM 23.1.1, cargo-llvm-cov 0.9.1, Linux x86_64 WSL2 ; mêmes options `--workspace --all-features`, puis `--lib` pour la seconde vue. Aucune hausse de couverture globale à 70 % n’est revendiquée : seule la vue bibliothèques franchit ce jalon.

La projection `rust-ast-da-v1` conserve son périmètre de production et ses preuves AST d’exclusion des seuls tests/harnais. Aucun fichier de production n’est retiré pour améliorer la métrique. La factorisation déplace du code couvert et change légitimement le dénominateur : **+265 lignes couvertes et +15 lignes de production**. L’alignement textuel exact des blocs inchangés, sans autojunk et avec les `DA` de production des deux côtés, trouve **243 lignes existantes devenues couvertes et zéro perte sur ces lignes alignées**. Les 22 autres lignes couvertes supplémentaires sont nouvelles ou modifiées ; aucune ligne supprimée ou déplacée n’est créditée comme nouveau test. Ce rapprochement ne prouve pas l’équivalence sémantique des lignes réécrites. Le comparateur strict renvoie **2**, car périmètre/dénominateur changent : nouvelle référence explicite à établir, pas de verdict comparable vert.

Il reste **20 498 lignes non couvertes** vers 100 %, soit 250 de moins. À dénominateur 53 102 constant : 4 568 lignes supplémentaires pour 70 %, 7 223 pour 75 %, **9 878 pour 80 %**, puis poursuite vers la couverture pertinente maximale. Chaque modification de production imposera un nouveau calcul.

| Module Astra | Production avant | Production après | Non couvert après |
|---|---:|---:|---:|
| `renewal/companion.rs` | 22 / 164 = 13,41 % | 154 / 163 = 94,48 % | 9 |
| `renewal/approval.rs` | 115 / 174 = 66,09 % | 172 / 174 = 98,85 % | 2 |
| `operations.rs` | 428 / 492 = 86,99 % | 470 / 520 = 90,38 % | 50 |
| `recovery.rs` | 372 / 416 = 89,42 % | 377 / 416 = 90,63 % | 39 |
| `renewal/stage.rs` | 174 / 180 = 96,67 % | 162 / 168 = 96,43 % | 6 |

La baisse du compteur du seul fichier stage provient du déplacement de la logique commune vers le magasin, pas d’un chemin abandonné : mêmes six lignes non couvertes ; tests de ses trois coupes d’écriture conservés. Astra passe de 3 402 / 5 804 à **3 626 / 5 819 = 62,31 %**. Le gain est distribué : Aether approval/renewal gagne 40 lignes existantes, approval/recovery une ; Astra companion 126, approval 57, operations 14 et recovery cinq. Ces familles ne s’additionnent pas à nouveau aux 243 lignes.

## Défauts et périmètre vérifiés

Deux erreurs avant publication du fichier ont été reproduites avant correction : le refresh du challenge et l’acceptation de l’approbation avançaient en mémoire malgré le refus de persistance. Les quatre tests compagnon donnaient deux succès et deux échecs. Après rollback, trois succès et un échec ont exposé une troisième incohérence : le rechargement comparait l’empreinte de soumission entrante à celle de la preuve contresignée, et refusait un journal produit par Astra lui-même.

Les empreintes ont des rôles distincts : `approved_with` conserve la soumission exacte pour l’idempotence ; une autorisation legacy se lie à l’empreinte de la preuve contresignée. Les liaisons automatiques et de campagne gardent leur règle existante. Aucun choix entre plusieurs empreintes n’est accepté ; les journaux altérés restent refusés.

Les quatre mutations (challenge, approbation, autorisation de stage et reçu/grant) utilisent un helper synchrone du magasin existant : copie d’une seule opération publique, mutation et validation, identité/demande immuables, persistance sous le verrou existant, restauration mémoire sur erreur. Aucun nouveau framework, format ou dépendance n’est introduit. La sérialisation du magasin complet reste celle de `persist()` ; seule la préparation de la mutation copie une opération.

Ce chemin est celui d’opérations historiques rechargeables. Les nouvelles demandes ordinaires restent automatiques ; les anciennes approbations par demande ne rétablissent pas le droit de stage retiré par l’ADR-008. Le vrai validateur gateway du test les refuse avec 403, vérifié par compteur d’appels et réponse exacte. Aucun grant n’est remis.

## Limites de preuve

L’injection de faute remplace la destination par un répertoire : échec avant renommage, octets antérieurs intacts. Une erreur de `fsync` du répertoire après renommage peut déjà avoir publié un fichier complet. Le rollback mémoire n’est donc pas une preuve de retour du disque à l’ancien contenu pour toute erreur d’E/S. La validation de ces coupes et de la perte d’alimentation exige un harnais de fautes de système de fichiers ; elle reste dans COV-020. Aucun succès n’est annoncé à l’appelant sur une telle erreur.

Le stage legacy refusé laisse actuellement une réservation exacte non accordée, bornée par sa lease. Le test le constate explicitement ; il ne revendique ni nettoyage immédiat ni abandon après un résultat réseau ambigu. Un nettoyage éventuel doit distinguer refus, réponse perdue, grant déjà accordé et concurrence avant d’utiliser `abandon_rotation`.

Les tests recovery ajoutent mauvaise origine WebAuthn, domaine de registre incohérent, empreinte de reçu du grant incohérente et pair révoqué, avec états/audits/intents vérifiés. mTLS loopback et signatures réelles de test, assertion ES256 logicielle : aucune preuve FIDO/TPM/noyau/Windows supplémentaire.

## Taille des binaires et ressources

Même chemin de reconstruction `/tmp/helios-round4/reference`, Rust/target/profil release inchangés, mêmes lockfiles et même trousseau de test hors dépôt. Ensemble de features explicites identique pour les trois packages : `heliosd/netlink,heliosd/wireguard,heliosd/tpm,heliosd/embed-ui`. Les artefacts de référence du lot 10 sont préservés dans `/tmp/helios-round5/sizes-before` ; leurs sources Rust concordent avec l’archive `a4bdf1b`. Les nouvelles sources ont été copiées puis touchées au même chemin avant reconstruction. Aucun flag d’instrumentation n’est présent dans cette commande release ; sorties de couverture exclues de la comparaison.

| Artefact | Avant, octets | Après, octets | Delta |
|---|---:|---:|---:|
| astra | 12 318 168 | 12 303 280 | **−14 888** |
| helios | 13 701 408 | 13 701 408 | 0, SHA identique |
| heliosd | 22 639 544 | 22 639 544 | 0, SHA identique |

Le contrôle strict `binary-size.py` valide les trois contre **134 217 728 octets**, sans changement de seuil. La baisse est mesurée, sans attribution à un unique choix du compilateur. Les attestations sont déclarées par le constructeur ; l’outil ne prouve pas lui-même les flags. Aucun test ou nouveau framework n’entre dans la fermeture runtime ; aucune dépendance n’est ajoutée. Le helper valide les liaisons avant persistance, un coût supplémentaire non benchmarké.

Builds via le cache unique et les garde-fous existants. Maximum observé dans les logs de ce lot : **59,6 Gio**, sous 65 Gio. Aucun nouveau target, nettoyage ou dépassement demandé par cette session ; les diminutions de cache observées ne sont pas revendiquées comme notre action. Ces tailles ne prouvent pas un build Windows/MSI.

## Validation et conservation

`/tmp/helios-round5-companion-before.log` : deux succès/deux échecs attendus avant correction. `/tmp/helios-round5-companion-after-rollback.log` : trois succès/un échec attendu de rechargement avant correction de l’empreinte. Les fixtures utilisent une approbation CA-PQ et une assertion ES256 réellement vérifiées, puis un magasin effectivement rechargé avant rejeu. Les corruptions testent séparément l’empreinte de dépôt substituée à celle de preuve et une empreinte étrangère. Les opérations automatiques/campagnes conservent leurs tests de liaison et de refus ; aucune union permissive n’est acceptée.

La suite Astra finale réussit : **175 tests unitaires et 13 tests d’intégration**. La première régression s’est arrêtée sur les 13 paramètres d’un nouveau helper de fixture ; une structure nommée l’a ramené à six, sans désactivation de lint. La régression finale `bash scripts/regression.sh` retourne **0** : Clippy workspace strict, Aether sans signature, tests workspace toutes features, 98 tests web et 162 Orion, deux builds frontend, campagne dry-run et garde-fous release. Les audits npm ne signalent aucune vulnérabilité ; RustSec conserve **sept avertissements autorisés**. Logs initial/final : `/tmp/helios-round5-regression{,-final}.log`. Les essais de fixture dont le serveur était détruit trop tôt ont été corrigés en conservant son `ServerTask` pendant tout le workflow ; leur échec reste dans le log intermédiaire, sans être présenté comme succès.

MSRV 1.95 non installée, Windows natif, FIDO physique, TPM, nftables/WireGuard noyau et WireGuard-NT non exécutés. Les ajouts sont des tests unitaires ordinaires, environ 1,3 seconde pour l’ensemble des 175 tests Astra mesurés ; aucune nouvelle campagne CI. Couverture et tailles restent locales. Aucun verdict matériel ou de sûreté globale ne découle des taux.

```sh
scripts/wsl-cargo test --frozen -p astra --all-features --lib workflow_tests::companion
scripts/wsl-cargo test --frozen -p astra --all-features
bash scripts/regression.sh
bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-round5-after
bash scripts/audit-rust.sh collect --view libraries --output-dir /tmp/helios-round5-after-libs
python3 scripts/audit-report.py compare --baseline /tmp/helios-round4-after/report.json --current /tmp/helios-round5-after/report.json
```

La première commande a servi à la reproduction avant correction ; les destinations de collecte étaient neuves. Régression/audits/installation frontend ont des interactions réseau identifiées ; les collectes sont hors ligne et gelées, sans installation implicite. Les 477 empreintes Rust de la référence du journal 10 ont été comparées à `git show a4bdf1b:<fichier>` ; les entrées de build sont inchangées. L’archive de référence est `/tmp/helios-round5/reference.tar`. La provenance finale rapporte HEAD `51dc912` et un arbre sale documentaire ; ses 478 empreintes Rust correspondent au code final.

JSON, LCOV, HTML, sources/provenances : `/tmp/helios-round5-after{,-libs}` ; références précédentes `/tmp/helios-round4-after{,-libs}`. Alignement : `/tmp/helios-round5/analyze.py` et `aligned-lines.json`. Ces artefacts temporaires ne constituent pas une politique de rétention durable et ne sont pas commités. Le journal 10 reste historique.

## Suites prioritaires

COV-005/COV-006/COV-020 restent partielles. Les prochaines preuves utiles sont : annulation réelle pendant staging déjà appliqué, concurrence propriétaire/révocation/grant, routeur renewal, coupes post-renommage, puis négociation v5 et workflows clients sur leurs cibles. Le nettoyage des réservations refusées doit être testé avec état exact, grant irrévocable et résultat réseau ambigu avant tout changement. Les efforts des fiches 07 restent des estimations historiques ; aucun effort vers 100 % n’est déduit du seul taux courant.

Pour reproduire les tailles, conserver le même trousseau `HELIOS_PUBLISHER_KEYRING_PATH=/tmp/helios-round4/keys/publisher-keyring.json` et exécuter avant/après au même chemin :

```sh
scripts/wsl-cargo build --release --frozen -p helios -p astra -p heliosd --features heliosd/netlink,heliosd/wireguard,heliosd/tpm,heliosd/embed-ui
python3 scripts/binary-size.py --artifacts /tmp/helios-round5/sizes-after --provenance /tmp/helios-round5/size-provenance-after.json --baseline /tmp/helios-round5/size-before.json --output <nouveau-rapport>
```

Rapports de tailles `size-{before,after}.json`, provenance après `size-provenance-after.json` et copies `sizes-{before,after}` dans `/tmp/helios-round5`. La référence reprend la provenance de construction `ed661fb` du lot 10, identique en Rust à `a4bdf1b` ; l’attestation après désigne `51dc912`. Les vérifications finales comparent les 478 empreintes de chacune des deux collectes aux sources présentes, vérifient les liens, les 36 fiches à 14 champs, le diff et l’absence de source modifiée depuis les commits. Le commit final ne porte que sur cinq documents d’audit.
