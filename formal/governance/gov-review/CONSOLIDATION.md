# Consolidation de la revue de préparation

La [revue scientifique](REVIEW-SCIENTIFIC.md) et la
[revue opérationnelle](REVIEW-OPERATIONS.md) ont été menées séparément à
`922c782be2c5d9f13355b69a43339ef7818e00ed`, par deux agents disponibles
dans cette session. Elles constituent des entrées pour Fable au lancement.

## Décision de coordination

Le [plan directeur](../../MASTER-PLAN.md) applique la délégation initiale
unique. Fable orchestre la revue automatique, arbitre les ambiguïtés pour
le travail de modélisation et conduit les jalons intermédiaires. Les
relecteurs indépendants valident la portée des résultats. Le responsable
humain autorise le lancement puis statue sur le dossier remis. Les
questions qui restent ouvertes limitent seulement les travaux concernés.

Le registre cite explicitement les codes de phase sous forme de chaînes,
distingue la mise à disposition du plan de l’autorisation de lancement
et restreint le périmètre de `GOV-PLAN`. Les règles d’exécution prévoient
des checkouts isolés, un intégrateur des noyaux et des points de reprise
dans Git. Le format machine initial relève de `PROP-SCHEMA`, avec
intégration du suivi en phase 11.

## Suites à instruire par Fable

| Sujet | Travail et portée |
| --- | --- |
| Provenance du handshake · `Q-01`, `ETAT-03` | Traiter tôt les contrats Linux et Windows, la lecture Rust et la preuve de liaison au candidat. Continuer la modélisation sous les interprétations compatibles. Les conclusions importées restent ouvertes ou conditionnelles suivant le backend. |
| Provenance et invalidation · `SPEC-INTERFACES`, `PROP-SCHEMA` | Définir une entrée machine par garantie importée et son état de revue. Propager l’ouverture et la péremption à travers les consommateurs, indépendamment de l’état de réalisation des tâches. |
| Prêt à exécuter, budgets et preuves · `TOOLS-PIN`, `PROP-SCHEMA` | Définir les transitions des tâches et le validateur de registre, les limites et l’exclusivité des cibles, ainsi que le format de résultats. Les lots d’audit et de préparation indépendants peuvent avancer pendant leur mise en place. |
| Composition, autorisations et durabilité · `Q-03`, `Q-07`, `Q-08` | Séparer les revendications post-quantiques par objet. Instruire la réévaluation concurrente de l’admission et les garanties du plancher après panne. Préserver les conclusions par mode, génération, stockage et instant de divulgation. |
| Exigences de revue par lot | Examiner la non-vacuité, le raffinement Rust, les mutants et la progression du nettoyage. Consigner les désaccords et ce qui permettrait de les trancher. |

Les rapports de préparation n’enregistrent ni une autorisation de lancement
ni un verdict sur une obligation du protocole. Les suites scientifiques et
opérationnelles relèvent de la campagne, avec son budget et ses conditions
d’exécution.
