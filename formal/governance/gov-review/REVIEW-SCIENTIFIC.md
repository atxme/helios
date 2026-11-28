# Revue scientifique indépendante

Révision examinée `922c782be2c5d9f13355b69a43339ef7818e00ed`.
Revue effectuée en lecture seule par un agent dédié, avant consultation de
la revue opérationnelle. Les priorités qualifient les conditions
d’acceptation des résultats concernés.

## P0 · Résultats critiques

- **ETAT-03 et provenance du handshake.** Le §11.2 décrit une séquence
  monotone de nouvelles observations. Le Rust examiné lit deux valeurs
  `Option<SystemTime>` et traite comme progression une valeur présente
  après une valeur absente ou une valeur supérieure à la précédente.
  Établir par backend le lien entre handshake réel, candidat effectivement
  sélectionné, génération et observation. En mode statique, l’égalité du
  PSK ne suffit pas à rattacher le handshake à une transaction. Produire
  un rapprochement entre sources du backend, modèle, traces sur cible
  et transitions Rust. Les mesures qualifient les configurations et cas
  exécutés. Les conclusions plus générales exigent un argument distinct.
  [Contrat v5](../../../docs/specification/NEGOCIATION-DE-CLE-V5.md#112-ordre-des-opérations-au-commit) ·
  [Comparaison Rust](https://github.com/atxme/helios/blob/922c782be2c5d9f13355b69a43339ef7818e00ed/crates/heliosd/src/key_negotiation/protocol.rs#L531)
- **Composition entre modèles.** Le graphe de tâches décrit l’ordre du
  travail. Pour chaque garantie importée, enregistrer l’interface, le
  résultat producteur, les consommateurs, les révisions, le profil et le
  backend, la projection d’événements, les hypothèses transitives et le
  verdict. Contrôler les cycles et propager les ouvertures et l’invalidation
  à ce niveau. [Contrats IFC](../../specification/INTERFACE-CONTRACTS.md)

## P1 · Précisions à intégrer au référentiel commun

- **VIE-08.** Distinguer l’équité de l’ordonnanceur, le déclenchement d’un
  nouveau nettoyage et la possibilité d’aboutir côté backend. Après un
  échec de restauration, le Rust examiné maintient le slot en préparation
  et demande une intervention. Séparer la sûreté de cet état fermé,
  la reprise automatique quand elle existe et le rétablissement après
  intervention. [Restauration dans le Rust](https://github.com/atxme/helios/blob/922c782be2c5d9f13355b69a43339ef7818e00ed/crates/heliosd/src/key_negotiation/transaction.rs#L566)
- **Non-vacuité.** Attester un antécédent atteignable et une capacité
  adverse pertinente pour chaque mode ou exception. Pour une équivalence,
  définir les deux mondes et examiner leur faisabilité. Le parcours
  `static_psk` commence avec une configuration compatible avec ce mode.
  Toute nouvelle admission reçoit le plancher `ml_kem`.
  [Critères de preuve](../../ACCEPTANCE-CRITERIA.md) ·
  [Contrat v5](../../../docs/specification/NEGOCIATION-DE-CLE-V5.md#14-plancher-anti-downgrade)
- **IFC-08.** Séparer cartographie statique, conformité d’une trace et
  raffinement démontré. Le transfert d’un invariant, d’une propriété
  temporelle et d’une équivalence exige des conditions propres à la
  propriété, notamment sur les entrelacements, l’équité ou les observables.
  [Contrats IFC](../../specification/INTERFACE-CONTRACTS.md)
- **CMP-03.** Distinguer confidentialité du PSK, des clés de transport et
  du trafic capturé. Pour chacune, consigner le mode, l’ordre des divulgations
  et le passage du raisonnement symbolique à l’argument computationnel.
  Les revendications sans argument validé restent ouvertes.
  [Catalogue](../../../docs/specification/VERIFICATION-FORMELLE-NEGOCIATION-V5.md)

## P2 · Traçabilité de FRA-02

Fixer les occurrences distinctes d’acceptation et la projection entre
émission, consommation locale et acceptation applicative. Traiter
séparément la portabilité entre connexions, le redémarrage et
l’indépendance vis-à-vis du cache secondaire.
[Sémantique commune](../../specification/MODEL-SEMANTICS.md)

## Contrôles et avis

Les contrôles `python3 -`, `git diff --check` et
`git status --short --branch` ont confirmé les 51 obligations, 30 scénarios,
20 hypothèses, 9 interfaces et 20 événements. Les tableaux du §17.1 ont
32 lignes de couverture, associées à 43 obligations distinctes valides.
Cette revue recommande de poursuivre l’audit normatif et la préparation
des validations, avec les conditions ci-dessus avant d’accepter les
conclusions critiques. Elle ne fournit ni verdict formel ni validation de
backend.
