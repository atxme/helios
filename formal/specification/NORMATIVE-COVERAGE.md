# Couverture normative initiale

Cette matrice indexe le catalogue gelé. Elle vérifie la présence d’un
point d’entrée pour chaque ligne du §17.1. Pendant `AUD-03`, relire les
clauses, comparer leurs quantificateurs, leurs exceptions et leurs
hypothèses avec les obligations correspondantes, puis enregistrer les
écarts. Le contrôle transversal des obligations hors §17.1 relève des
autres tâches d’audit.

## Propriétés énumérées au §17.1

| Revendication | Obligations candidates |
| --- | --- |
| Protection du premier handshake | `CLE-02`, `ETAT-02`, `ETAT-03` |
| Intégrité de la clé publique KEM | `AUT-01`, `FIL-02` |
| Intégrité du ciphertext | `AUT-01`, `FIL-02` |
| Liaison au bon pair | `IDE-02`, `AUT-01`, `CLE-01` |
| Rejeu de requête authentifiée | `FRA-01`, `FRA-02` |
| Rejeu vers une autre gateway | `AUT-01`, `FRA-02` |
| Réponse d’une autre transaction | `AUT-01`, `FRA-03` |
| Changement de mode | `AUT-01`, `FIL-03`, `ETAT-09` |
| Modification de l’horodatage | `AUT-01`, `FRA-04` |
| Corrélation en mode statique | `CLE-03` |
| Recherche exhaustive du PSK statique | `CLE-03`, `CLE-04`, `CLE-06` |
| Énumération des pairs par les erreurs | `IDE-02`, `OBS-01` |
| Immobilisation par délai signé | `FIL-03`, `OBS-03` |
| Source UDP falsifiée | `OBS-03` |
| Coût CPU par source réelle | `OBS-03`, `OBS-04` |
| Rétention des permis QUIC | `OBS-03`, `VIE-05` |
| Concurrence par pair | `ETAT-01`, `ETAT-07` |
| Pose avant annonce | `ETAT-02` |
| Preuve de possession à la confirmation | `AUT-03`, `ETAT-03` |
| Point de non-retour du commit | `ETAT-05`, `ETAT-06` |
| Vieillissement et remplacement du PSK | `VIE-02`, `VIE-03` |
| Récupération du slot sans client | `VIE-05`, `VIE-06` |
| Renégociation après redémarrage | `ETAT-08`, `VIE-07` |
| Retrait demandé par un autre pair | `VIE-04`, `OBS-02` |
| Rejeu d’un retrait d’ancien propriétaire | `VIE-04`, `ETAT-01` |
| Protection du routage après échec Orion | `VIE-09` |
| Downgrade réseau | `ETAT-04`, `ETAT-08`, `ETAT-09` |
| Vol du fichier d’identité Windows | `OBS-05` |
| Confidentialité des clés à l’enrôlement | `ENR-07`, `CLE-05` |
| Autorisation et rejeu d’une demande d’enrôlement | `ENR-02`, `ENR-04`, `ENR-05` |
| Preuve de possession WireGuard à l’enrôlement | `ENR-03` |
| Authenticité du document d’enrôlement | `ENR-01`, `ENR-06`, `FIL-02` |

## Audit au-delà du tableau

| Source | Couverture à contrôler | Tâche |
| --- | --- | --- |
| Contrat v5 §2–§16, §17.2–§17.3 et §18–§21 | Exigences filaires, contrôles d’entrée, cycle complet, conditions de progression, limites et fermeture des chemins hérités. Lister les exclusions motivées. | `AUD-01`, `AUD-03` à `AUD-06`, `AUD-09` |
| Amendements v5 de l’ADR-005 | Vérifier la hiérarchie des décisions de négociation, retrait et renouvellement avec le contrat. Le corps v4 est historique. | `AUD-02`, `AUD-04` |
| Spécification de rotation Astra | État de confiance visible, réévaluation de l’admission, activation, révocation, chevauchement et reprise. | `AUD-07` |
| Rust et tests, en s’appuyant sur le §22 | Inventorier les transitions et frontières effectives. Vérifier chaque écart à la révision étudiée et séparer conformité et couverture de tests. | `AUD-08`, `RUST-08` |
| Contrat v5 §20 et documentation de test | Lier les conditions observables et les limites de chaque environnement à une vérification sur cible. | `EXP-PLAN` |

Lors de l’audit, attribuer à chaque clause une référence stable, une ou
plusieurs obligations ou une exclusion motivée, un statut d’audit et
l’éventuel arbitrage ouvert. Utiliser le
[journal des questions](../governance/OPEN-QUESTIONS.md) pour les écarts
déjà repérés. Le [registre des tâches](../TASK-REGISTRY.yaml) rattache les
livrables aux responsables de lot.

Sources.
[Contrat v5](../../docs/specification/NEGOCIATION-DE-CLE-V5.md) ·
[ADR-005](../../docs/adr/ADR-005-NEGOCIATION-DE-CLE.md) ·
[Catalogue](../../docs/specification/VERIFICATION-FORMELLE-NEGOCIATION-V5.md) ·
[Rotation Astra](../../docs/specification/ROTATION-CERTIFICATS.md) ·
[Validation sur cible](../../docs/testing/TESTING.md)
