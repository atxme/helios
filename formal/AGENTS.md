# Règles pour la vérification formelle d’Helios–Orion v5

Appliquer les [règles du dépôt](../AGENTS.md). Utiliser le
[registre](TASK-REGISTRY.yaml) pour les lots, le
[plan](MASTER-PLAN.md) pour l’ordonnancement et les
[critères d’acceptation](ACCEPTANCE-CRITERIA.md) pour la revue.

- Travailler sur un lot identifié avec un propriétaire, un relecteur distinct
  et un périmètre d’écriture. Utiliser une branche issue de la branche du
  programme pour le lot. Une autre équipe réutilise ses interfaces après
  acceptation du jalon correspondant.
- Référencer la clause normative, les identifiants du catalogue, les
  scénarios, les hypothèses et les contrats d’interface. Ouvrir une question
  si deux sources divergent ou si un contrat est incomplet.
- Toute restriction, abstraction, hypothèse supplémentaire ou modification
  de la propriété doit être visible et revue. Une restriction de modèle
  ne peut pas imposer le résultat recherché.
- Garder l’historique des résultats négatifs et des propriétés ouvertes.
  Indiquer la portée réelle d’un résultat, sa reproductibilité et le
  caractère fini ou non des instances évaluées. Vérifier la non-vacuité.
- Lier séparément la propriété normative aux fonctions, transitions et tests
  Rust. Documenter les garanties qui exigent une validation sur cible.
- Exécuter les mutations de sensibilité uniquement sur les modèles de
  vérification. Demander une revue indépendante pour les résultats critiques.
- Remettre les artefacts et références reproductibles sous les chemins du
  lot. Si une dépendance, une décision ou la limite de calcul empêche de
  conclure, consigner le blocage, les résultats partiels et ce qui permet
  de reprendre. Une recherche interrompue reste ouverte.
- Lancer un lot de campagne après validation des jalons indiqués au registre.
  Les validations normatives et les affirmations finales appartiennent à
  la personne responsable du projet.
