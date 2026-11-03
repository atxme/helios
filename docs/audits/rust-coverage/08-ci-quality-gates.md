# Contrôles locaux, rapports et taille des binaires

## Décision du responsable et état vérifié

**Aucun temps CI supplémentaire pour cet audit et son suivi.** La collecte de couverture, la comparaison des rapports, les contrôles de tailles et les campagnes complémentaires seront lancés localement à la demande. Les tests unitaires ordinaires peuvent rejoindre les suites ciblées existantes, conformément à la clarification du responsable. Les nouvelles campagnes lourdes, dont fuzzing et couverture, restent locales. Les workflows existants gardent leur périmètre ; aucune nouvelle étape de couverture, campagne nocturne, publication d’artefact ou vérification supplémentaire sur PR n’est proposée.

Le nom de ce document conserve celui du livrable demandé initialement. Son contenu remplace la proposition d’extension CI de la première version du plan.

`.github/workflows/regression.yml` exécute actuellement les contrôles ciblés Linux/Windows et interfaces selon `scripts/ci-plan.py`. Il n’appelle ni `coverage.sh`, ni `regression.sh`. `docs/testing/TESTING.md:109` explique le coût de l’instrumentation ; `tools/xtask/src/main.rs:872` protège même l’absence de campagnes lourdes dans ce workflow. Les tests natifs Windows et les cinq budgets fuzz hebdomadaires existants restent le socle actuel. Aucun changement de ces workflows n’est réalisé pendant l’audit.

## Scripts locaux de COV-002

Le premier lot implémente ces commandes. Le helper `scripts/audit-collect.py` prépare la provenance et vérifie les prérequis sans installation implicite. Les tests de ces outils sont uniquement sous `scripts/local-tests/`, lancés localement.

| Script | Responsabilité | Réutilisation et limites |
|---|---|---|
| `scripts/audit-rust.sh` | Piloter à la demande collecte, analyse statique ou comparaison ; conserver provenance et état d’échec | Réutiliser `coverage.sh` avec sélection Rust/vue/sortie à ajouter ; tous les appels Cargo passent par `wsl-cargo` et son verrou/budget ; aucune installation ou campagne réseau/matérielle implicite |
| `scripts/audit-report.py` | Agréger JSON/LCOV, séparer global/libs et brut/production, classer les écarts par crate/fichier, comparer une référence | Python standard ; extraction AST via outil déjà provisionné pour la projection ; aucun parseur approximatif silencieux ni métrique d’exclusion opportuniste |
| `scripts/binary-size.py` | Lire tailles/hashes/provenance des artefacts livrables, vérifier limites applicables et deltas avant/après | Python standard ; pas de code lié aux exécutables Rust, pas de compilation ou de strip implicite, pas de dépendance runtime nouvelle |

`coverage-summary.mjs` continue de porter son résumé Helios/Orion existant. Éviter de copier le pipeline de compilation dans plusieurs scripts : `coverage.sh` possède la collecte, le pilote sélectionne et ordonne les opérations, l’analyseur travaille sur les exports. Les profils workspace doivent être exportés en JSON/LCOV/HTML **avant** une collecte libs qui les remplace.

Commandes disponibles, avec répertoires de collecte neufs hors de l’arbre source :

```sh
bash scripts/audit-rust.sh collect --view workspace --output-dir <rapport-local>
bash scripts/audit-rust.sh collect --view libraries --output-dir <rapport-local-libs>
bash scripts/audit-rust.sh static
python3 scripts/audit-report.py compare --baseline <reference> --current <rapport>
python3 scripts/binary-size.py --artifacts <livrables-release> --baseline <reference-tailles>
```

`collect` concerne Rust ; les UI restent des campagnes explicitement choisies. Un mode de contrôle retourne un code d’échec en cas de régression confirmée ; une référence non comparable ou un export incomplet produit un état d’erreur distinct, sans présenter le résultat comme valide. Les scripts n’effectuent ni push, publication, déploiement ou modification de seuil à distance.

## Rapports reproductibles et comparaison locale

Conserver ensemble SHA du dépôt/lockfile, versions Rust/LLVM/llvm-cov, OS/target, profil/features, commande, cibles/tests collectés, compteurs d’exécution et JSON/LCOV/HTML issus des mêmes profils. Enregistrer uniquement les variables de test autorisées, pas l’environnement complet ni des secrets.

Le contrôle doit vérifier la cohérence des totaux JSON et `LF/LH`, puis distinguer les lignes individuelles `DA` : la baseline présente un écart entre ces deux sémantiques. La projection de production par AST et ses limitations doivent être ratifiées avant de définir le seuil. Aucun fichier critique à zéro ni backend difficile n’est retiré pour augmenter le pourcentage.

Comparer à une référence locale du même SHA de base ou merge-base, reconstruite avec le même environnement si nécessaire. Publier dans le rapport les nouvelles lignes, suppressions, gains/pertes sur lignes existantes et changements de périmètre. Ne pas comparer directement une sélection de crates à un workspace complet, ni une bibliothèque au produit global.

Après stabilisation, le contrôle local bloque d’abord les régressions, puis les seuils mesurés passent à 70, 75, 80, 90, 95 puis 100 % visés, sans faire du franchissement de 80 % un critère d’arrêt. Un rapport d’échec de tests reste disponible pour diagnostic, avec statut partiel ; il ne remplace pas la référence. Comparer les compteurs entiers pour éviter qu’un arrondi masque une perte. Les lignes modifiées peuvent être affichées sans promettre qu’une simple métrique constitue une preuve de sécurité.

Les rapports restent dans un emplacement local ignoré des builds ou hors du dépôt, choisi explicitement. Ne pas créer une autre arborescence de compilation, un autre cache Cargo ou un nettoyage automatique pour stocker les rapports. Les références utiles sont conservées selon une politique locale à décider ; aucune rétention payante ou publication CI n’est requise.

## Contrôle de taille binaire

La borne existante est `helios_update::MAX_BINARY_SIZE = 128 * 1024 * 1024`, soit **134 217 728 octets (128 Mio)**, définie dans `crates/helios-update/src/lib.rs:26`. Le publisher (`tools/helios-publisher/src/main.rs:427`) et le parcours des fichiers du bundle (`crates/helios-update/src/bundle.rs:106`) la contrôlent déjà. Elle ne doit pas être relevée pour accepter un artefact de test ou une hausse produite par les futurs travaux.

Le script doit reprendre cette source canonique ou un mécanisme existant qui l’expose ; si une extraction de constante est retenue, son analyse doit être explicite et refuser une forme inconnue. Ne pas dupliquer une valeur indépendante qui dériverait silencieusement du contrôle réel. Vérifier artefact présent, non vide et dans la borne pour les fichiers concernés par le contrat update/bundle. Aucun plafond universel nouveau n’est inventé pour les autres formats, par exemple un installateur compressé Orion.

Comparer avant/après par binaire : nom, target/architecture, SHA et taille en octets, delta absolu et relatif, marge à la borne applicable. Exiger même toolchain, mêmes features et profil de livraison. Une différence de provenance rend la comparaison non concluante. Les artefacts release ne sont construits que sur demande explicite et via le budget Cargo ; l’analyse des tailles existantes ne doit pas déclencher de build.

`Cargo.toml` utilise `lto = "thin"` et `strip = true` en release. Préserver ces réglages ; ne pas modifier l’optimisation ou compresser artificiellement les sorties pour faire passer la comparaison. `scripts/campaign.sh:54` fournit déjà un précédent : copier puis stripper les binaires debug de campagne, sans toucher les originaux, pour respecter le contrat de mise à jour. Cette recette de campagne ne devient pas une mesure release comparable par simple renommage.

Les binaires instrumentés llvm-cov, caches/debug/PDB et archives d’installation sont distingués des exécutables livrés. Aucune sortie instrumentée n’est signée ou distribuée. Maintenir fixtures et dépendances de test dans les cibles de test/dev ; ne pas ajouter de framework ou générateur à la fermeture des dépendances runtime pour faciliter la couverture.

Respecter 128 Mio ne suffit pas à justifier toute hausse : les deltas doivent rester visibles et expliqués. Le responsable décidera si une tolérance chiffrée de croissance est souhaitée ; aucun pourcentage arbitraire n’est imposé dans cette mission. Le budget **65 Gio du cache Cargo** est une autre contrainte, maintenue indépendamment de la taille des livrables.

## Contrôles de plateforme et ressources

Les scripts locaux permettent des campagnes distinctes : Linux workspace/toutes features, `aether --lib` sans signature, configurations réellement livrées, Windows natif, TPM logiciel puis matériel, réseau noyau et WireGuard-NT. Branches/MC/DC restent une expérimentation nightly séparée si demandée ; aucune augmentation des campagnes CI existantes.

Ne pas sommer Linux et Windows comme deux exemplaires d’une même ligne. Afficher deux vues ou une union explicitement définie. Un stub non-Windows ne valide pas le code Win32. Les scénarios nécessitant privilèges, réseau externe, paquets système ou matériel sont identifiés avant exécution ; un test sans précondition active reste hors portée, pas validé.

Le cache unique/budget WSL de 65 Gio, le verrou et les contrôles avant/après build existants restent obligatoires. Aucun dépassement, nettoyage ou réinstallation automatique. Ne pas fusionner des profils concurrents ou anciens. Les tests instables sont diagnostiqués et isolés, sans répétition jusqu’à réussite comme politique de mesure.

La campagne locale canonique `bash scripts/regression.sh` reste requise pour les futures modifications transversales/protocole/sécurité, avec les validations cible pertinentes. Les nouveaux scripts l’accompagnent sans ajouter son exécution à la CI. Ce premier lot ajoute les scripts et leurs tests locaux ; il ne corrige pas encore les workflows métier identifiés dans l’audit. Les sorties de taille sont protégées contre l’écrasement des entrées et des artefacts.
