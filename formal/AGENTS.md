# Règles pour la vérification formelle d’Helios–Orion v5

Appliquer les [règles du dépôt](../AGENTS.md). Utiliser le
[registre](TASK-REGISTRY.yaml) pour les lots, le
[plan](MASTER-PLAN.md) pour l’ordonnancement et les
[critères d’acceptation](ACCEPTANCE-CRITERIA.md) pour la revue.

## Autonomie du coordinateur scientifique

Après l’autorisation initiale unique `GOV-APPROVAL`, Fable orchestre toute
la campagne jusqu’à la remise du dossier `IND-04`. Les points de contrôle
intermédiaires relèvent de Fable et de la revue scientifique indépendante.
Fable traite les demandes de clarification et les arbitrages méthodologiques
dans sa délégation. Le responsable humain décide de l’acceptation finale
du dossier.

- Fable peut créer, subdiviser, réordonner et réaffecter les tâches,
  mobiliser des spécialistes et des relecteurs, choisir les outils,
  modifier la stratégie, ajuster les ressources dans les limites autorisées
  et relancer les vérifications.
- Fable arbitre la méthode et les interprétations de travail. Il peut
  explorer plusieurs interprétations et introduire des hypothèses
  identifiées et justifiées. Chaque décision est motivée, versionnée,
  reliée à ses sources et soumise à la revue appropriée. Toute
  divergence avec les sources normatives ou le Rust reste visible. Les
  sources normatives ne sont pas modifiées pour obtenir une preuve.
- Une ambiguïté, un résultat négatif, un désaccord ou une dépendance
  indisponible limite les seuls résultats qui en dépendent. Isoler le
  périmètre concerné, chercher des alternatives, produire un résultat
  conditionnel ou ouvert si nécessaire, et poursuivre les travaux
  indépendants avec les interfaces déjà instruites.
- La campagne se termine lorsque les obligations sont instruites et
  revues, lorsque les travaux encore réalisables sont épuisés ou
  lorsqu’une limite autorisée empêche la poursuite. Présenter au
  responsable humain les limites, contre-exemples et arbitrages résiduels.

## Exécution et revue

- Attribuer chaque lot à un propriétaire et à un relecteur distinct.
  Utiliser une branche et un checkout isolé par agent d’écriture.
  Protéger le périmètre du lot et désigner un intégrateur pour les
  noyaux partagés de modèles.
- Relier la clause normative, l’obligation, les scénarios, les hypothèses,
  les contrats, le modèle et la correspondance Rust. Toute restriction
  ou modification de portée doit être visible. Une hypothèse ne peut
  pas imposer le résultat recherché.
- Vérifier la non-vacuité et employer les mutations uniquement sur les
  modèles de vérification. Garder les résultats négatifs et les
  résultats ouverts. Une recherche interrompue reste ouverte. Une
  correspondance de trace n’établit pas à elle seule la conformité du Rust.
- Conserver dans Git des points de reprise réguliers. Indiquer les
  versions, décisions, paramètres, résultats partiels, lots affectés et
  prochaines opérations reproductibles. Garder les secrets et artefacts
  volumineux hors Git.
