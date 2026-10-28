# F11 — couverture réelle du moteur Orion

Lot du 27 octobre 2026, branche `feat/local-rust-audit`. Le journal décrit la reprise de F11 depuis la branche de travail et la mesure comparable des tests de `orion-engine` et de ses contrats proches. Il distingue le résultat LLVM mesuré des estimations de couverture de production et des vérifications qui restent à exécuter.

## Reprise et intégration du lot

La sauvegarde `backup/rust-audit-before-f11-20261027`, au commit `600a392`, contenait 18 anciens commits au-dessus de la base. Ils ont été rejoués sur `cb6d1ae` : 16 commits ont été conservés et deux doublons de dépendance ont été ignorés. Les conflits finaux de négociation ont conservé les changements de settlement et de plancher de sécurité.

Les changements de production sont dans `2f3d17b` puis `d41835e`. Les ajouts et ajustements de tests sont dans `6abd497`, `4d8efe1` et `e3d0d28`. Le dernier de ces commits ne change que l’initialisation de fixture requise par Clippy. Aucun workflow CI, profil release ni dépendance runtime supplémentaire n’a été ajouté. La feature Tokio `test-util`, déjà employée par Core et Engine, a été activée uniquement en dev-dependency de `heliosd` pour le temps virtuel ; le resolver Cargo 2 sépare cette activation des builds release.

## Méthode et périmètre de comparaison

La comparaison cible exactement **trois packages parmi les 23 du workspace** : `orion-core`, `orion-engine` et le shell Rust `orion`. Elle active toutes leurs features, conserve les cibles de test Cargo par défaut et utilise `--frozen`. Elle ne constitue jamais une mesure globale du workspace. Elle collecte LLVM brut — sans `--lib` — puis LCOV, HTML et les métadonnées dans `measurement.json`, avec empreintes des sources. Elle n’est pas une projection AST limitée au code de production.

Références ciblées : avant `0b9adc1`, après `4d8efe1`. La mesure comparable utilise `/tmp/helios-f11/before` et `/tmp/helios-f11/after-comparable`, avec les sources de référence sous `/tmp/helios-f11/source`. Les inventaires de sources suivies dans le dépôt contiennent respectivement 583 et 587 empreintes Rust ; ce ne sont pas des nombres de fichiers compilés ou instrumentés. L’archive avant est `/tmp/helios-f11/before.tar`; le script `analyze.py` et `comparison.json` accompagnent les mesures. Le JSON fourni par l’utilisateur est conservé sous `/tmp/helios-f11/claude-f11-cov.json`.

## Résultat LLVM comparable

| Mesure | Avant | Après | Écart |
| --- | ---: | ---: | ---: |
| Lignes exécutées / instrumentées | 12 562 / 17 644 | 12 814 / 17 644 | +252 |
| Couverture de lignes | 71,19700748 % | 72,62525504 % | +1,42824756 points |
| Fonctions exécutées / instrumentées | 1 383 / 2 147 | 1 416 / 2 147 | +33 |
| Régions exécutées / instrumentées | 18 411 / 25 624 | 18 690 / 25 624 | +279 |

Le LCOV comparable compte 228 gains de lignes uniques et aucune perte. Ni les branches ni MC/DC ne sont instrumentés. Ces nombres décrivent l’exécution des trois packages sélectionnés, pas la couverture de toute la logique de production ni la preuve d’un chemin de sécurité complet.

| Fichier ciblé | Avant | Après |
| --- | ---: | ---: |
| `crates/orion-core/src/certificate_approval.rs` | 8 / 113 | 89 / 113 |
| `crates/orion-engine/src/service/certificates.rs` | 126 / 478 | 238 / 478 |
| `crates/orion-engine/src/service/app.rs` | 16 / 57 | 21 / 57 |
| `crates/orion-engine/src/view.rs` | 26 / 71 | 32 / 71 |
| `crates/orion-core/src/certificate_renewal/exchange.rs` | 259 / 607 | 293 / 607 |
| `crates/orion-core/src/certificate_renewal/promotion.rs` | 30 / 201 | 38 / 201 |

Le compte de tests est passé de 780 à 798 : Orion Core 571→576, Orion Engine 136→149, shell Rust `orion` 73→73. Les neuf nouveaux tests `heliosd` portent la suite ciblée `key_negotiation::tests` de 49 à 58 tests, pas tout le package. Le lot ajoute donc 27 tests Rust (18 Orion et neuf gateway). Les tests TypeScript/Vitest sont comptés séparément dans la régression.

## Renforcement de F11 et limites des scénarios

Le moteur possède maintenant des tests de refus par profil pour l’action de renouvellement globale, d’absence d’identité protégée, de sélection d’une récupération inexistante, de refus d’approbation sans manifeste vérifié et de non-exposition des sentinelles de clé privée et PSK dans la vue certificats. Un test prépare une véritable `RenewalSession` avec le constructeur public de Core, la place dans la map du service, puis vérifie qu’un échec de reprise Linux conserve l’empreinte exacte de la demande, la clé publique candidate, les réglages d’origine, l’état et les octets persistés du magasin. Les DER et certificats PQ de ce magasin servent uniquement au test d’orchestration : ils ne constituent pas une preuve d’acceptation cryptographique.

Les tests de `certificate_approval` vérifient les signatures Astra et le registre CA-PQ contre les pins locaux, le RP ID, l’identifiant d’opération, l’expiration avant et à l’échéance, les mutations et les champs du manifeste. Le test de domaine étranger re-signe le document modifié avec la clé de service afin d’atteindre la validation du domaine plutôt que de ne tester qu’une signature invalide. Ces tests portent sur le vérificateur d’approbation conservé dans Core ; ils ne démontrent pas que l’approbation matérielle est le chemin du renouvellement ordinaire. La spécification actuelle déclare ce renouvellement automatique à 80 % sans cérémonie YubiKey.

Les constructions publiques de `RecoverySession` ne sont pas disponibles : ses champs et son constructeur de requête sont privés à Core. Commencer une récupération exige aussi le magasin d’identité protégé et un challenge distant. La couverture positive d’une récupération client complète, avec reprise et commit, reste donc ouverte. Tester les reprises positives sous Linux demande un point d’injection interne du magasin/transport, sans backend plaintext livré ni contournement de la vérification cryptographique. Le scellement réel, la promotion puis reconnexion et le cycle complet Windows demandent leur cible native.

## Réconciliation des chiffres antérieurs

Le JSON utilisateur confirme 12 219 / 17 368 = 70,3535 % pour les mêmes trois crates. Son dénominateur diffère de notre référence rebasée (17 644) ; ses commandes et empreintes de sources ne sont pas jointes. Aucun gain n’est calculé entre ce rapport et notre référence. La comparaison chiffrée ci-dessus porte uniquement sur nos deux campagnes explicites. L’estimation F11 « 62 % » provenant d’une liste qui n’était pas fournie n’a pas été recréée indépendamment. Les dossiers `/tmp/helios-round6-after` et `/tmp/helios-round7-after` étaient absents le 27 octobre ; la valeur historique globale de 61,63 % n’est donc pas mise à jour ni présentée comme une référence recalculée.

Les reproductions avant correction des paniques de génération 232/241 sont consignées dans `/tmp/helios-f11-admission-before.log`. La clarification normative de `NEGOCIATION-DE-CLE-V5.md` §11.1 fixe le traitement de l’épuisement. Après correction, une révocation à `u64::MAX` passe à un état terminal sans wrap, renvoie une erreur interne, efface la propriété transactionnelle et le cache PSK statique, et interdit la réadmission à MAX. La sweep continue sur les autres pairs ; l’oracle à deux pairs MAX vérifie la révocation et l’effacement des deux caches sans écriture au plan de données. Une revue indépendante n’a pas relevé de chemin de réouverture, d’inversion de verrou ni d’arrêt prématuré de cette sweep.

## Correctifs de négociation issus des tests et de la revue

Le lot ne se limite pas au compteur de tests. Les reproductions puis les revues ont isolé trois défauts supplémentaires :

* Une annulation pendant l’attente du verrou du cache pouvait laisser l’état révoqué avec l’ancienne PSK encore en cache. Le verrou est désormais acquis avant la transition synchrone et l’effacement ; une reprise répare également un cache ancien encore attaché à un pair révoqué.
* Une préparation mise en attente pouvait utiliser la politique ou la PSK statique lue avant une révocation/réadmission. La réservation relit la configuration courante sous le sérialiseur transactionnel, avant mutation du pair/rejeu/état Preparing. La clé WireGuard du pair authentifié reste issue de l’identité mTLS de confiance.
* La PSK statique apprise était publiée après libération du sérialiseur transactionnel. Son insertion appartient maintenant à `install_candidate`, sous le même propriétaire, après succès du backend. La condition d’apprentissage est conservée ; aucune PSK ML-KEM n’entre dans ce cache statique.

Un test de future interrogée manuellement puis abandonnée vérifie le premier cas ; les autres imposent l’interleaving avec verrous et temps virtuel. Les oracles vérifient les clés effectivement remises au backend, la propriété de génération et l’absence de mutation des nouveaux propriétaires. La revue a aussi vérifié les sites d’écriture restants du cache et l’ordre des verrous. La spécification v5 §11.1 décrit l’épuisement terminal, la réconciliation atomique état/cache et la relecture de politique. Le protocole et ses garanties ne sont pas assouplis pour les tests.

## Baseline globale finale du lot F11

Collectes terminées sur **`d41835e6ac24f5ef80c56fa78e3d8a7e34f0cc3a`**, Linux WSL2, Rust 1.99.0, cargo-llvm-cov 0.9.1, LLVM 23.1.1. Les deux collectes `scripts/audit-rust.sh` sont distinctes de la comparaison Orion brute précédente. Chacune a enregistré 537 empreintes de sources du workspace ; leurs sources, entrées Cargo et SHA d’artefacts ont été revérifiés avant la reprise du 28 octobre.

| Vue | Production couverte / retenue | Couverture | Tests réussis | Reliquat vers 80 % |
| --- | ---: | ---: | ---: | ---: |
| Workspace Linux, toutes features | 36 131 / 56 421 | 64,04 % | 2 596 | 9 006 |
| Bibliothèques Linux, toutes features, `--lib` | 27 833 / 38 808 | 71,72 % | 2 056 | 3 214 |

Le global conserve **20 290 lignes non couvertes**. À périmètre constant, les jalons 70 % et 75 % demandent respectivement 3 364 et 6 185 lignes supplémentaires. Les bibliothèques ne sont jamais présentées comme l’ensemble du projet. La [baseline par crate et fichier](15-f11-file-baseline.md) conserve les 23 crates et les 370 fichiers globaux ; 270 fichiers figurent dans la vue bibliothèques.

Le résumé LLVM brut global donne 53 920 / 76 038 lignes (70,91 %), 5 197 / 7 623 fonctions (2 426 jamais exécutées), 79 480 / 113 307 régions. Pour les bibliothèques : 40 890 / 52 993 lignes, 3 940 / 5 340 fonctions et 59 729 / 77 387 régions. Ces dénominateurs incluent du code de test instrumenté et diffèrent de la projection de production. Branches et MC/DC restent non mesurés.

## Contrôles et limites

| Contrôle exécuté sur le code F11 final | Résultat |
| --- | --- |
| `cargo fmt --check`, `git diff --check` | Réussis |
| Tests Core / Engine / négociation ciblée | 576 / 149 / 58, tous réussis |
| Clippy strict ciblé, toutes cibles/features | Réussi |
| `bash scripts/regression.sh` | Réussi après `d41835e` : workspace, campagnes dry-run, builds frontend, 98 tests web et 169 tests Orion TypeScript |
| Audits de cette régression | npm sans vulnérabilité ; sept avertissements RustSec autorisés restent présents, dont Tokio RUSTSEC-2026-0386, GTK et clipboard-win |
| Compilation MSVC `orion-core` + `orion-engine`, toutes cibles/features | Réussie avec les outils/SDK déjà installés ; quatre imports inutilisés préexistants, fichiers inchangés par ce lot |
| MSRV 1.95 | Non vérifiée : toolchain absente ; Rust 1.99 ne la prouve pas |
| Windows natif, TPM/FIDO, WireGuard/nftables réels | Non exécutés ; requis sur leurs cibles |

La compilation MSVC a utilisé `clang-cl` Linux ciblant Windows, `llvm-lib`, `lld-link-20`, MSVC 14.51.36231 et le SDK 10.0.26100.0 montés depuis Windows. Le premier essai avec le compilateur hôte `cc` échouait dans AWS-LC ; le choix explicite de ces outils a corrigé la configuration sans changer le code ni désactiver la cryptographie. Cela ne couvre pas le shell Tauri Windows : son build appelle `xtask::orion_deps::prepare`, qui crée un `target/orion-deps` local et peut télécharger WireGuard-NT. Un contrôle conforme au cache unique demande d’abord de corriger ce chemin d’outillage (COV-002), puis de compiler le shell. Aucune exécution native ni téléchargement de WireGuard-NT n’est revendiqué.

Les replis Linux à 100 % de `engine_host`, `ui_access` ou `legacy_cleanup` ne prouvent pas le pipe Windows, la DACL, le contrôle du processus client ni le scellement TPM. La couverture TypeScript n’a pas été mesurée ; les nombres Vitest sont des résultats de tests, pas un taux de couverture.

## Artefacts temporaires et tailles des binaires

Les exports originaux étaient dans `/tmp/helios-f11/{before,after-comparable,global-final,libraries-final}` ; les campagnes de régression et de compilation avaient leurs logs sous `/tmp/helios-f11-*.log`. Ils étaient vérifiés à la fin du 27 octobre, mais **ne sont plus présents lors de la reprise du 28 octobre**. Les tableaux Markdown conservent le relevé ; une contre-vérification des exports exige une nouvelle collecte. Cette perte d’artefacts temporaires ne transforme pas une mesure historique en mesure de la branche après F14.

Avant F11 (`0b9adc1`), quatre ELF Linux release non instrumentés avaient été relevés avec le même trousseau de test, les features gateway netlink/WireGuard/TPM/embed-ui et Orion WireGuard : Astra 12 395 872 octets, Helios 14 421 360, heliosd 22 886 368, Orion 28 119 608. Ils étaient tous sous 128 Mio. Le build de comparaison après avait été lancé, mais sa session et ses sorties ne sont plus disponibles à la reprise : **aucune taille après ni absence de hausse n’est attestée pour F11**. La prochaine comparaison doit reconstruire les deux révisions avec des entrées identiques ; ne pas comparer des binaires laissés par un autre worktree dans le cache partagé.

Pour reproduire les collectes, employer les commandes du document 15 sur la révision annoncée. Pour la comparaison ciblée : `scripts/wsl-cargo llvm-cov --frozen -p orion-core -p orion-engine -p orion --all-features --json --output-path <destination>/coverage.json --quiet`, puis `llvm-cov report` avec les mêmes trois packages pour LCOV/HTML. Destinations neuves, même chemin de sources de référence, features et outils identiques ; conserver les exports et sources sur un stockage durable avant d’effacer les temporaires.

## Priorités après ce lot

Les risques prioritaires restent : (1) cycles positifs renewal/recovery dans le moteur et magasin protégé, (2) frontières de privilège Windows non exécutées sous WSL, (3) annulation/orchestration et effets réels sur le noyau, (4) coexistence des anciennes API d’approbation et des nouvelles cérémonies opérateur, (5) reprise de persistance corrompue ou partiellement appliquée. Les tests précédents réduisent des lacunes précises sans démontrer une sécurité exhaustive.

L’ordre proposé est COV-007, COV-008, COV-010 et le prérequis de cache COV-002, puis COV-013/COV-014/COV-012, COV-011, COV-034/COV-035, COV-019. Les gains et efforts des fiches restent des estimations à réévaluer avec la baseline courante. Les modules déplacés par F14 doivent être réinventoriés avant tout crédit supplémentaire.

`helios-astra-helper` a déjà été retiré sur main : ne pas proposer de le supprimer à nouveau. L’ancienne approbation ordinaire est un candidat B (obsolescence à valider et API publiques à inventorier), pas du code mort confirmé. Les fonctions privées de probes formant un sous-graphe fermé restent un candidat de suppression COV-031 après décision produit. Les relais Tauri ne dupliquent pas le métier du moteur ; conserver cette frontière. Les factorisations crypto inter-domaines ne sont pas proposées. Les décisions humaines portent sur les cibles matérielles disponibles, le retrait coordonné des API anciennes et le périmètre durable de mesure.
