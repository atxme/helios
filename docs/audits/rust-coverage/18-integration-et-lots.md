# Consolidation et lots de couverture au 3 novembre 2026

## Base de travail

La branche `integration/test-coverage-20261103` réunit `main` à `78b570e`
et `feat/local-rust-audit` à `4509256`. Avant fusion, les branches avaient
respectivement 62 et 25 commits propres depuis leur ancêtre commun.
L'ancienne référence distante `origin/audit/coverage-plan-2026-10-23`
(`7ebc020`) est déjà ancêtre de main : aucun rejeu de ses commits n'est requis.
Les branches de développement F14 postérieures à main restent hors périmètre.

Une fusion conserve l'historique partagé et les preuves attachées aux anciennes
révisions. Les deux conflits concernent `orion-engine/service/certificates` :
les helpers d'approbation de main sont conservés, avec leurs tests portables ;
les tests de cycle de vie de l'audit sont regroupés sous un module réservé aux
plateformes hors Windows, comme dans la branche d'origine. Aucun test existant
n'est supprimé ni désactivé sur une plateforme où il s'exécutait auparavant.
Le test de conservation de session appelle maintenant
`certificate_approval_material`, l'ancienne commande d'approbation ayant été
remplacée par F14. La première exécution complète a aussi révélé que le test
proxy de Core modifiait l'environnement d'autres tests HTTP : sa vérification
est désormais exécutée dans un sous-processus isolé, sans sérialiser les suites.

## Acquis et limite des chiffres

L'audit livre le collecteur local, la comparaison de rapports et de tailles,
ainsi que des tests et corrections des contrats de certificats, du journal
Astra, de la concurrence des renouvellements, des réponses HTTP bornées, de
l'annulation et des générations de négociation et des vues/profils du moteur.
Main apporte les évolutions F14 et leurs tests, en particulier l'approbation
depuis Orion. Ces apports sont conservés ensemble ; leur auteur ne se déduit
pas du champ Git `author`, les commits récents portant le même compte.

La dernière mesure publiée reste celle du 28 octobre : **37 200 / 57 886
lignes de production Linux, soit 64,26 %**, et 20 686 lignes non couvertes.
Elle concerne `e6b96c1`, pas cette fusion. Les 36 fiches COV restent une réserve
historique de scénarios : leurs gains et charges ne sont plus un devis du
travail restant. Les nouvelles fonctionnalités modifient le dénominateur.

## Découpage opérationnel

Chaque ligne correspond à un chantier pouvant produire plusieurs petites PR.
Avant chaque PR, vérifier dans le code actuel si les tests de main couvrent déjà
le scénario. Les identifiants COV renvoient aux critères détaillés de la
[roadmap](07-roadmap-to-80.md), qui restent applicables.

| Lot | Périmètre et fiches | Livrable et critère de sortie | Prérequis |
| --- | --- | --- | --- |
| L0 — Référence intégrée | COV-001/002/036 | Régression verte sur la fusion, nouvelles collectes workspace et bibliothèques avec provenance propre ; écarts par fichier, dépendances réellement bloquantes réévaluées | Fusion |
| L1 — Contrats purs | COV-003/015/027 | Matrice des refus/transitions encore sans test dans aether ; tests déterministes des frontières et absence de mutation en cas d'échec | L0 |
| L2 — Astra durable | COV-004/005/006/020 | Tests ciblés des trous restants : journal, redémarrage/reprise, échecs de persistance, concurrence et publication ; état durable et visible cohérent | L0, contrats L1 concernés |
| L3 — Certificats Orion | COV-007/008/009 | Renouvellement/récupération : réponse perdue, reprise, promotion refusée, sélection de session et HTTP borné ; état conservé ou nettoyé selon le contrat | L0, protocoles L2 concernés |
| L4 — Négociation et orchestration | COV-013/014/019 | Annulation aux frontières restantes, propriété de génération, hot reload, arrêt et adoption de l'identité ; kill-switch et rollback vérifiés | L0, L1 |
| L5 — Opérateur et coffre | COV-034/035 | Tests des refus et transitions F14 actuels avec fixtures existantes ; reprise du coffre et autorisation liées à la demande exacte | L0, contrats L1/L2 concernés |
| L6 — Moteur, IPC et commandes | COV-022/023/026 | Tests des commandes réelles et de leurs refus, profils, timers, droits IPC et approbations ; garder les tests portables actifs sur Windows | L0, L3/L5 selon commande |
| L7 — API et canal privé | COV-021 | Routes authentifiées, mTLS/ALPN, réponses publiques et cycle de vie des listeners ; refus sans fuite de secrets | L0, L2 |
| L8 — CLI et livraison | COV-016/017/018/024/025 | Commandes et erreurs observables, bundle/update/rollback ; fixtures dans des répertoires isolés, aucune modification de déploiement | L0, L2/L4/L5 selon outil |
| L9 — Interfaces React | Suites web et Orion existantes | Inventaire des parcours non exercés, tests d'interaction et d'erreur selon les composants actuels ; rapports JS séparés du Rust | L0, contrats UI actuels |
| L10 — Windows natif | COV-010 et parties Windows de L5/L6 | Compilation et tests natifs, puis recette DPAPI/reconnexion/WireGuard-NT et cérémonies sur poste équipé ; résultats séparés de Linux | Poste Windows ; L3/L5/L6 pour parcours complets |
| L11 — Gateway et matériel | COV-011/012 et parties réelles de L4/L7 | Recettes noyau/nftables/WireGuard, TPM et veth Astra, avec constats avant/après et échecs fail-closed | Cibles dédiées ; suites logiques concernées |

L1, les scénarios indépendants de L2/L4/L5/L7/L8 et l'inventaire L9 peuvent
avancer après L0 sans attendre la totalité des autres chantiers. Les dépendances
portent sur le contrat effectivement testé, pas sur la fermeture de toute une
famille COV. Préparer Windows et les cibles matérielles dès le début.

Les consolidations COV-028/029/030 et la décision produit COV-031 restent des
changements séparés, après tests protecteurs. COV-032 suit les contrats modifiés ;
COV-033 réévalue les jalons après chaque collecte comparable.

## Règle de clôture d'une PR

Décrire le comportement et les refus couverts, les fichiers propriétaires et
les scénarios explicitement restants. Exécuter les tests ciblés, puis les
contrôles requis par `AGENTS.md` ; les changements transversaux ou de sécurité
exigent la régression complète. Mesurer le gain seulement entre deux rapports
comparables, sans créditer un retrait de code comme un test ajouté. Ne pas
annoncer de gain chiffré pour un lot avant collecte. Les effets matériels et
Windows restent des preuves séparées selon `docs/testing/TESTING.md`.

## Validation de la consolidation

Commandes exécutées :

```sh
cargo fmt --check
git diff --check
python3 -m unittest discover -s scripts/local-tests
python3 -m unittest discover -s scripts/tests
bash -n scripts/coverage.sh scripts/audit-rust.sh
bash scripts/regression.sh
```

Les 64 tests locaux d'audit et les 50 tests de scripts passent. La dernière
régression complète termine avec le code 0 : Clippy strict, tests Rust du
workspace et sans signature aether, tests/builds des deux interfaces, audits
npm, provisioning dry-run et contrôles release. L'audit Rust affiche huit
avertissements autorisés ; une commande réussie ne signifie pas leur résolution.
Les deux échecs intermédiaires (ancienne méthode F14, puis concurrence du test
proxy) ont été corrigés avant cette passe finale. Le log de session est
`/tmp/helios-coverage-integration-regression.log`, non versionné.

Aucune nouvelle collecte de couverture ni comparaison release de tailles n'a
été exécutée : L0 reste ouvert sur ces mesures. Aucun test natif Windows,
TPM/FIDO ou réseau noyau réel n'est revendiqué. Le cache partagé reste sous le
budget de 65 Gio, sans nettoyage ni second target.
