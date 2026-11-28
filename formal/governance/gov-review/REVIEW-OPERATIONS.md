# Revue opérationnelle indépendante

Révision examinée `922c782be2c5d9f13355b69a43339ef7818e00ed`.
Revue effectuée en lecture seule par un agent dédié, avant consultation de
la revue scientifique.

## Contrôles sur le registre examiné

107 tâches, 23 vagues topologiques, aucun doublon, aucune dépendance
absente et aucun cycle. Le maximum est de 13 tâches à la vague 11, avec
12 à la vague 10. Toute tâche appartient à la clôture de `IND-04`. Ces
vagues décrivent des dépendances statiques sans tenir compte des durées,
des ressources ni des revues.

PyYAML 6.0.3 et Ruby Psych 5.1.2 ont interprété les codes de phase comme des
chaînes. Les clés `08` et `09` et leurs 22 références étaient écrites sans
guillemets. Le schéma Core YAML 1.2.2 résout ces scalaires décimaux en
entiers. Contrôles effectués avec `python3 -` (chargement strict et
`graphlib.TopologicalSorter`) et `ruby -ryaml -e`.
[Registre examiné](https://github.com/atxme/helios/blob/922c782be2c5d9f13355b69a43339ef7818e00ed/formal/TASK-REGISTRY.yaml#L47) ·
[Schéma Core YAML](https://yaml.org/spec/1.2.2/#1032-tag-resolution)

## P0 · Exécution autonome

| Constat sur la révision examinée | Correction proposée |
| --- | --- |
| La règle « prérequis accepté » laisse `GOV-REVIEW` attendre `GOV-PLAN`, dont le statut est `proposed`. Le registre ne permet pas de déterminer les tâches exécutables et mélange potentiellement acceptation de tâche et verdict scientifique. | Définir l’admission de la revue sur une révision figée. Valider le registre et calculer l’exécutabilité avec statut, prérequis, affectation et ressources. Un travail accepté peut rendre un verdict ouvert ou contredit. |
| Les budgets figurent comme résultat prévu de `TOOLS-PIN`, avec peu de détail sur leur application. | Fixer avant les exécutions notées les limites CPU, mémoire, durée et disque par outil et pour la campagne. Gérer l’accès aux cibles, conserver les résultats partiels et respecter le budget Cargo du dépôt. |
| `PROP-SCHEMA` prévoit le format des résultats alors que `DEC-05` le place en phase 11. | Faire de `PROP-SCHEMA` la source du format machine minimal avant les premières remises. Consacrer `IND-01` à l’import et au suivi. |
| Le périmètre `formal/` de `GOV-PLAN` contient ceux des 106 autres tâches. L’affectation de personnes distinctes n’est pas mécaniquement contrôlée. | Restreindre ce périmètre après remise. Isoler chaque lot à un SHA de départ avec une branche et un checkout propres. Vérifier la portée du diff et l’indépendance du relecteur à l’affectation. |

## P1 · Reprise, invalidation et cohérence

- Conserver les tentatives et les points de reprise. Associer les résultats
  aux empreintes des entrées et propager la péremption aux consommateurs
  transitifs, tout en conservant les preuves historiques.
- Nommer un intégrateur pour chaque noyau Tamarin et TLA+. Exiger une
  référence au noyau et une justification pour toute extension qui diverge.
- Laisser les modèles `ETAT-03` progresser tôt. Pour les conclusions sur le
  backend, identifier la garantie versionnée d’`IFC-04` consommée par
  TLA+ et Rust et la portée de sa validation. `CMP-03` dépend déjà de
  `EXP-03`. [Contrats IFC](../../specification/INTERFACE-CONTRACTS.md)

## P2 · Suivi et avis

Générer le suivi après stabilisation des formats. Distinguer affichage des
tâches prêtes, verdicts revus et résultats périmés. Le graphe examiné est
cohérent comme plan statique. Les résultats de cette revue ne valident
pas le contenu scientifique des dépendances ni la disponibilité des
outils ou des cibles.
