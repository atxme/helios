# Audit Rust Helios — couverture, code mort et duplications

Audit du **23 octobre 2026**, révision `7ebc020d0425de4a30d64a93af1ead048c3f0fc7`, branche d’audit initiale `audit/coverage-plan-2026-10-23`. Le développement se déroule dans `/home/christophe/helios-wt/rust-audit`, branche `feat/local-rust-audit`, créée depuis `main` ; la branche locale d’audit a été supprimée après transfert des documents.

**Le responsable a autorisé le démarrage du développement. COV-001/COV-002 ont livré la mesure et les scripts locaux. Le lot suivant corrige les réponses HTTP et l’atomicité du ledger, avec des tests supplémentaires sur les grants et routes Astra. Son état vérifié et ses limites figurent dans le [journal de développement](09-implementation-progress.md).** Aucun code Rust de production, manifeste Cargo ou workflow n’est modifié par ce premier lot. Le dossier s’appelle `rust-coverage` car le motif existant `**/coverage/` de `.gitignore` ignorerait l’emplacement suggéré `docs/audits/coverage/` ; aucune règle d’exclusion du dépôt n’a été changée.

**Objectif actualisé : viser 100 % des lignes de production pertinentes, et améliorer les fonctions/branches lorsque mesurables.** Les jalons 70/75/80 restent utiles au suivi ; aucun ne constitue une fin de mission. Le reliquat initial vers 100 % est de 22 139 lignes à périmètre constant. Les résultats ci-dessous restent la baseline historique, pas la mesure du lot en cours.

**Lot de développement mesuré : 58,98 % de production globale (31 287 / 53 046), 2 200 tests réussis.** La vue bibliothèques séparée atteint 66,47 %. La gateway avec features de livraison reste sous 128 Mio et diminue de 6 032 octets. La régression complète reste bloquée par les audits de dépendances ; détails, reliquats et commandes dans le [journal 09](09-implementation-progress.md).

## Diagnostic et résultats de référence

Les 23 packages du workspace ont été inventoriés, manifestes et sources inspectés, ainsi que les tests, CI, campagnes et harnais fuzz. Les modules signalés dans la mission ont des tests, souvent répartis entre crates ; leurs lacunes concernent surtout **les séquences async, les reprises et les effets concrets**, pas simplement l’absence de tests unitaires.

| Indicateur | Résultat vérifié | Portée |
|---|---:|---|
| Global Rust, résumé LLVM | **66,10 %**, 46 706 / 70 663 lignes | Linux, workspace toutes features, binaires et intégrations inclus |
| Bibliothèques seules, résumé LLVM | **72,15 %**, 33 988 / 47 106 | Collecte `--lib` distincte ; jamais présentée comme total projet |
| Global production Linux, collecteur v1 | **58,24 %**, 30 870 / 53 009 | Lignes LCOV `DA`, retrait AST des tests/harnais avec preuves |
| Bibliothèques production, collecteur v1 | **65,34 %**, 22 773 / 34 852 | Même projection v1, collecte `--lib` distincte |
| Fonctions / régions globales brutes | **64,07 % / 65,62 %** | Incluent les tests inline présents dans le rapport |
| Fonctions non exécutées, résumé brut | **2 507** | Indice de testabilité, pas preuve de code mort |
| Branches / MC/DC | **Non mesurées** | Instrumentation instable non activée |
| Écart vers 80 %, production v1 | **11 538 lignes existantes supplémentaires** | À dénominateur 53 009 constant |
| Écart vers 80 %, résumé brut | **9 825 lignes** | Autre métrique et autre dénominateur |

Deux collectes globales donnent exactement les mêmes compteurs de lignes/fonctions ; une seule région varie dans `aether::private_file`. Les harnesses rapportent **2 172 succès, zéro échec/ignoré**, et 1 688 succès pour les seules bibliothèques. Six essais TPM quittent sans effet matériel quand leur activation manque : ils ne constituent pas six validations matérielles. Clippy strict toutes cibles/features et `cargo-machete` ont réussi.

La projection initiale conservée dans 02 retirait 14 776 lignes `DA`, dont 14 624 exécutées. Le collecteur v1 ajoute le retrait justifié des 31 lignes couvertes de `orion-core/src/config/legacy_fixture.rs`, déclaré sous `cfg(test)` : **14 807 lignes retirées**, dont **14 655 couvertes**. La variation de 58,26 à 58,24 % provient de cette correction de périmètre, sans ajout de test métier. Un écart distinct existe entre les totaux `LF/LH` LLVM et les entrées individuelles `DA`. Les deux métriques sont conservées ; la cause exacte de l’écart n’est pas supposée. **Le choix de la métrique du contrôle local reste à ratifier.**

Ces mesures proviennent de WSL2/Rust 1.99, pas de la MSRV 1.95 ni d’un environnement propre reconstruit. Elles n’incluent pas le dénominateur Win32 exclu par `cfg`. Elles ne prouvent ni TPM physique, FIDO, nftables/WireGuard réel, WireGuard-NT, installation ni sûreté cryptographique. Les couvertures JS des deux interfaces ne sont pas agrégées au Rust.

## Cinq risques techniques prioritaires

1. **Lecture HTTP non bornée au point de consommation.** `orion-core/src/trust_update.rs:206` lit `response.bytes()` sans le plafond protocolaire 64 KiB ; recovery lit aussi intégralement, renewal vérifie après lecture. Risque de ressource à corriger/tester avec corps chunkés, pas seulement `Content-Length` — COV-009.
2. **Routes et orchestration Astra exposées mais peu exercées.** Routeur public et nombreux handlers ont des compteurs nuls ; les tests actuels de budget/bearer ne prouvent pas montage HTTP, limites, isolation des magasins et refus sans divulgation — COV-004/005/006.
3. **Reprise des cycles de certificats non démontrée de bout en bout.** Les primitives CSR/grant/store existent et sont testées ; étapes async et promotion concrète restent à zéro. Le rejeu après réponse de commit perdue est un risque précis à reproduire, avec état Astra `Committed` face au chemin Orion de réinstallation. Pas de défaut exploitable annoncé sans reproduction — COV-005/007/008/010.
4. **Garanties d’écriture divergentes.** Helper privé robuste et autres writers à `.tmp` fixe ou sans la même synchronisation coexistent ; vérifier permissions, contenu, concurrence et reprise avant mutualisation. L’écart source est vérifié ; son exploitation ne l’est pas — COV-019/020/028.
5. **Assurance d’environnement incomplète.** Des taux élevés sur règles/refus de plateforme masquent l’absence d’effets matériels ; DPAPI a des tests Windows, mais son enchaînement jusqu’à reconnexion et les cérémonies/opérations réelles demandent des cibles dédiées — COV-010/011/012/034.

## Dix premières tâches et ordre

| Ordre | Tâche | Résultat attendu |
|---|---|---|
| 1 | COV-001 | Définition ratifiée et mesure production/global/libs reproductible |
| 2 | COV-009 | Réponses HTTP bornées et vraie transaction trust-update appliquée atomiquement |
| 3 | COV-003 | Matrice négative de grant et invariants du ledger |
| 4 | COV-004 | Routeur public Astra vérifié par HTTP |
| 5 | COV-005 | Recovery Astra, réconciliation et réponse de commit perdue |
| 6 | COV-006 | Renouvellement Astra, journal et grant durable |
| 7 | COV-013 | Négociation v5, annulation et propriété de génération |
| 8 | COV-007 | Renouvellement client complet et coupures |
| 9 | COV-008 | Recovery client complète et reprise idempotente |
| 10 | COV-010 | DPAPI, promotion puis reconnexion Windows |

COV-014 (orchestration), COV-034 (FIDO) et COV-035 (opérateur) sont également P0 et peuvent être préparées en parallèle quand leurs prérequis sont satisfaits. COV-002 prépare les scripts locaux de collecte, comparaison et taille binaire ; aucun temps CI supplémentaire n’est prévu. L’ordre ne repose pas sur les seuls pourcentages.

## Chemin critique et effort

Fixer le périmètre et l’outillage local → sécuriser contrats/lecture HTTP → tester routes et workflows Astra → tester workflows Orion et négociation/annulation → prouver scellement/promotion/reconnexion sur cible → étendre CLI/démons/API/contrôleur → mesurer les paliers 70/75/80 → relever progressivement les seuils locaux. Préparer tôt les cibles TPM/Windows/FIDO pour éviter leur arrivée en fin de parcours.

À périmètre constant, la vue de production active demande **6 237 lignes** supplémentaires à 70 %, **8 887** à 75 %, **11 538** à 80 %. Chaque changement de code impose de recalculer le dénominateur. Les 35 tâches du plan offrent un potentiel estimé de **13 365 à 17 455 lignes utiles**, avec incertitude ; les facteurs de recouvrement sont explicités et les factorisations n’ont aucun gain automatiquement crédité. Le seuil sera accepté sur mesure, pas sur cette somme.

Effort total additionné, assurance cible et consolidation incluses : **135 à 237 jours-personne**. Pour deux développeurs, ordre de grandeur **4 à 8 mois**, dépendant de la disponibilité matérielle et des validations ; aucune date garantie. Il peut être possible d’atteindre 80 % avant tous les lots, mais cela ne ferme pas les risques de sécurité restants.


## Exécution locale et taille des binaires

Décision du responsable : **aucun temps CI supplémentaire**. COV-002 propose trois scripts locaux (`audit-rust.sh`, `audit-report.py`, `binary-size.py`), en réutilisant les scripts de couverture et le garde-fou Cargo présents. Ils sont maintenant implémentés, avec le helper interne `audit-collect.py` ; les workflows ne sont pas étendus. Leurs tests restent dans `scripts/local-tests/`, hors de la collecte CI existante.

La borne existante est de **128 Mio par fichier concerné par update/bundle**, définie dans `helios-update`. Le plan ajoute un relevé avant/après des artefacts livrables comparables et impose de garder fixtures, dépendances de test et instrumentation hors des binaires livrés. Les profils release actuels restent la référence ; la limite de taille ne sera pas relevée pour atteindre une métrique de couverture.

## Code mort et factorisations

Trois fonctions privées constituent un sous-graphe sans point d’entrée : `probe_captive_portal`, `tcp_http_probe`, `get_default_gateway` dans `heliosd/src/orchestrator/probes.rs`. Suppression potentielle **après décision produit** ; conserver les fonctions MTU utiles du fichier. Les commentaires de raccordement futur sont probablement obsolètes. Aucun autre retrait de fonction publique, feature, enum ou dépendance n’est suffisamment démontré. `cargo-machete` n’a signalé aucune dépendance inutilisée.

Factorisations proposées après tests protecteurs : framing speedtest dans `aether`, calcul pur de fenêtre CA-TLS dans `astra-operator`, réutilisation raisonnée de `private_file`, éventuellement vérification commune de l’identité gateway servie. Conserver les distinctions signature release65/PKI87, renouvellement ordinaire/récupération expirée, DPAPI client/TPM gateway, hello/session des deux protocoles sidecar. La ressemblance n’autorise pas fusion des pouvoirs.

## Décisions humaines nécessaires

- Le développement est autorisé ; restent à ratifier le périmètre et les contrôles locaux Linux et Windows.
- Définir emplacement/rétention locale des rapports et référence de tailles par cible ; aucun temps CI supplémentaire n’est alloué.
- Réserver VM/cibles à console, poste Windows, TPM et clés opérateur de test ; autoriser explicitement leurs effets matériels au moment des campagnes.
- Décider suppression des sondes captives ou mission de raccordement séparée.
- Statuer seulement si nécessaire sur une dépendance **dev** de propriétés/routeur ; privilégier d’abord les outils/patterns présents.

## Documents et preuves

| Document | Contenu |
|---|---|
| [01-workspace-inventory.md](01-workspace-inventory.md) | 23 packages, dépendances, features/cibles/tests, environnements et architecture |
| [02-coverage-baseline.md](02-coverage-baseline.md) | Commandes exactes, versions, tests réellement exécutés, métriques globales/libs/crates et 336 fichiers, projection reproductible |
| [03-coverage-gaps.md](03-coverage-gaps.md) | Chemins critiques, tests existants, inventaire fonctionnel et lignes sans hits des modules prioritaires |
| [04-dead-code-audit.md](04-dead-code-audit.md) | Catégories A/B/C/D, preuves et faux positifs exclus |
| [05-duplication-audit.md](05-duplication-audit.md) | Comparaisons exactes/sémantiques, écarts de comportement et décisions |
| [06-test-strategy.md](06-test-strategy.md) | Oracles, unités/intégration/propriétés/fuzz/sécurité/système et isolation/nettoyage |
| [07-roadmap-to-80.md](07-roadmap-to-80.md) | 35 fiches initiales et COV-036, dépendances, priorités, estimations et critères |
| [08-ci-quality-gates.md](08-ci-quality-gates.md) | Scripts locaux, comparaison, taille binaire et CI existante |
| [09-implementation-progress.md](09-implementation-progress.md) | Lot développé, mesures avant/après, tailles et blocages réels |

Les artefacts bruts restent localement dans `/tmp/helios-audit-*` ; le HTML global se lit à `/tmp/helios-audit-rust-html/html/index.html`. Ils ne sont pas committés. Un sous-agent Luna a contribué aux inventaires et à la revue, sans modifier les sources ni lancer de build.

Les commandes de validation et la revue finale du diff sont consignées ci-dessous. Les campagnes instrumentées/clippy/machete et leurs sorties sont détaillées dans la baseline. La régression complète, la MSRV, Windows, les UI et les cibles matérielles n’ont pas été exécutés ; aucune sûreté de régression globale n’est revendiquée pour cet audit documentaire.

## Validation initiale documentaire (historique)

Commandes exécutées, toutes sans diagnostic bloquant final :

```sh
cargo fmt --check
python3 /tmp/helios-audit-validate-docs.py
git diff --check
git diff --name-only HEAD
git status --short --untracked-files=all
```

Le vérificateur documentaire a contrôlé les neuf fichiers attendus, les 35 fiches avec leurs 14 champs, les liens/identifiants, les 336 entrées de fichiers de baseline, les calculs et l’identité des compteurs lignes/fonctions des deux campagnes. Il a aussi exécuté `git diff --no-index --check` contre `/dev/null` pour chaque nouveau document : différences normales de fichier nouveau, aucun diagnostic de whitespace. `git diff --name-only HEAD` est vide ; la liste des fichiers non suivis contient exactement les neuf Markdown de ce dossier. Aucune source, aucun test, manifeste, workflow ou fichier de configuration existant n’a changé.

Revue manuelle et seconde lecture Luna : correction d’une référence de ligne erronée, séparation stricte des métriques brutes/reconstituées et des preuves hôte/cible, vérification des estimations par réserves de lignes, et examen des duplications pour conserver les frontières de sécurité. Aucun secret ni artefact généré n’est ajouté au dépôt. Les rapports bruts et scripts d’analyse restent temporaires.

La validation ci-dessus concerne la livraison initiale des documents. La validation du premier lot de développement est consignée dans la section suivante.


## Premier lot de développement local

COV-001/COV-002 fournissent `audit-rust.sh collect/static`, `audit-report.py summarize/compare` et `binary-size.py`, en réutilisant le garde-fou Cargo et le pipeline de couverture existants. Ils n’ajoutent aucune dépendance runtime Rust, modification de profil release ou étape CI. La borne de taille est lue dans sa constante canonique et les sorties de rapports ne peuvent pas remplacer des binaires ou entrées existantes.

Les commandes d’utilisation, les formats de provenance et les codes de retour sont documentés dans `docs/testing/TESTING.md`. Les mesures historiques de cet audit restent séparées de la validation de ce nouveau collecteur ; une collecte en échec reste `partial` et ne remplace pas une référence.


### Validation du premier lot COV-001/COV-002

Les **64 tests locaux** du nouvel outillage et les **51 tests de scripts préexistants** passent. Les nouveaux tests ne sont pas collectés par la CI.

Les deux collectes globales du nouveau pilote ont terminé avec `status=completed`, chacune avec **2 172 tests réussis, zéro échec/ignoré** ; la collecte bibliothèques a terminé avec **1 688 succès**. Les lignes/fonctions globales et les compteurs de production sont identiques entre les deux passes. Une seule région varie dans `aether::private_file` : 68 880 puis 68 879 régions couvertes sur 104 960 ; cette variation n’est pas masquée.

Baseline active v1 : **30 870/53 009 = 58,24 %** pour la production Linux, et **22 773/34 852 = 65,34 %** pour la vue bibliothèques. Le brut LLVM reste 46 706/70 663 = 66,10 % global et 33 988/47 106 = 72,15 % bibliothèques. Le retrait supplémentaire des 31 lignes de fixture est documenté ci-dessus ; le prochain objectif 80 % demande **11 538 lignes supplémentaires**, à dénominateur constant.

Commandes exécutées depuis le worktree :

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/local-tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v
bash -n scripts/coverage.sh scripts/audit-rust.sh
bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-rust-audit-dev-global
bash scripts/audit-rust.sh collect --view libraries --output-dir /tmp/helios-rust-audit-dev-libs
bash scripts/audit-rust.sh collect --view workspace --output-dir /tmp/helios-rust-audit-dev-repeat
bash scripts/audit-rust.sh static
python3 scripts/audit-report.py compare --baseline /tmp/helios-rust-audit-dev-global/report.json --current /tmp/helios-rust-audit-dev-repeat/report.json
python3 scripts/audit-report.py compare --baseline /tmp/helios-rust-audit-dev-global/report.json --current /tmp/helios-rust-audit-dev-repeat/report.json --fail-under-lines 80
python3 scripts/audit-report.py compare --baseline /tmp/helios-rust-audit-dev-global/report.json --current /tmp/helios-rust-audit-dev-libs/report.json
```

Les trois dernières commandes renvoient respectivement **0, 1 et 2**, les résultats attendus. Clippy strict et cargo-machete réussissent via `static`. Les tests du contrôle de taille vérifient la borne exacte, son dépassement, les fichiers/provenances invalides, les références incompatibles et la protection contre l’écrasement des entrées. Le contrôle refuse un fichier trop gros avant lecture de son contenu. Les sorties instrumentées, tests et dépendances dev ne sont pas liés à un binaire livré.

Les prérequis frontend du worktree neuf ont été préparés explicitement avec `npm ci --offline --ignore-scripts --no-audit --no-fund`, pour `web` et `apps/orion`, puis `npm run build --prefix web`. Aucun manifeste/lockfile/asset source n’a changé. Le cache Cargo est resté sous 65 Gio ; aucun nettoyage ni dépassement n’a été demandé par cette session.

Aucun artefact release comparable n’était disponible dans le cache : aucune taille de binaire livré ni variation release n’est revendiquée. L’outil est validé sur ses fixtures et ne construit ni ne modifie un exécutable. Il n’y a aucun changement Rust/Cargo susceptible d’ajouter les scripts à la fermeture runtime. Windows natif, matériel et `scripts/regression.sh` n’ont pas été exécutés ; ce lot modifie uniquement l’outillage local et sa documentation, sans modification métier ou de chaîne de livraison opérationnelle.
