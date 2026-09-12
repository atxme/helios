# Architecture Decision Records

Les ADR documentent les décisions d'architecture et de sécurité acceptées.
Les fichiers existants sont numérotés et nommés selon le format
`ADR-NNN-SUJET.md`. Une décision doit rester courte, traçable et liée aux
spécifications ou à la documentation opérationnelle concernée.

## Modèle minimal

```markdown
# ADR-NNN — Titre

## Context

Décrire le problème, les contraintes et les faits établis.

## Decision

Décrire la décision retenue et ses frontières.

## Alternatives

Lister les solutions considérées et la raison de leur rejet.

## Consequences

Décrire les effets positifs, coûts, risques et limites connues.
```

Une modification d'un contrat existant doit mettre à jour l'ADR concerné ou
ajouter un ADR amendé, sans réécrire l'historique silencieusement. En cas de
désaccord entre code et documentation, signaler explicitement l'écart et
préserver les contrôles fail-closed jusqu'à résolution.
