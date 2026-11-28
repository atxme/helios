# Programme de vérification Helios–Orion v5

Le programme part du [catalogue v5](../docs/specification/VERIFICATION-FORMELLE-NEGOCIATION-V5.md)
avec 51 obligations, 30 scénarios de menace et 20 hypothèses. Le catalogue
reste l'entrée commune pour ces trois ensembles. L'espace `formal/`
organise la construction des modèles, les preuves et leur validation.

- [Prompt Claude Fable](CLAUDE-PROMPT.md) — mission complète à copier,
  sous-agents à lancer et livrables à remettre.
- [Plan directeur](MASTER-PLAN.md) — phases, responsabilités, dépendances et
  conditions de lancement.
- [Règles de travail](AGENTS.md) et [critères d'acceptation](ACCEPTANCE-CRITERIA.md)
  — contrat d'exécution et de revue.
- [Registre des tâches](TASK-REGISTRY.yaml) — lots prévus, pilotes, preuves
  attendues et dépendances.
- [Couverture normative initiale](specification/NORMATIVE-COVERAGE.md) —
  index de traçabilité à contrôler pendant l'audit.
- [Sémantique commune](specification/MODEL-SEMANTICS.md) et
  [contrats d'interface](specification/INTERFACE-CONTRACTS.md) — propositions
  à valider avant les modèles.
- [Autorisation initiale](governance/gov-approval/APPROVAL.md) — moyens,
  plafonds, outils et cibles à signer avant le lancement.
- [Décisions](governance/DECISIONS.md) et
  [questions ouvertes](governance/OPEN-QUESTIONS.md) — arbitrages et effets sur
  les conclusions.
- [Revue de préparation](governance/gov-review/CONSOLIDATION.md) — rapports
  indépendants et suites proposées pour la coordination.

Le dossier décrit une campagne autonome après l’autorisation initiale
`GOV-APPROVAL`. Fable organise les contrôles intermédiaires et poursuit les
lots indépendants des questions encore ouvertes. Le responsable humain
décide de l’acceptation du dossier remis via `IND-04`. Les verdicts et
mesures seront associés aux révisions effectivement vérifiées.
