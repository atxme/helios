# Sécurité

## Signaler une vulnérabilité

Ne pas publier un exploit non corrigé, une clé ou un secret dans une issue ou
une pull request. Le dépôt ne contient pas, à ce jour, de canal privé de
signalement explicitement configuré. À compléter par le mainteneur avec une
adresse ou un mécanisme privé vérifiable avant publication.

Un signalement utile contient la version ou le commit, la plateforme, les
préconditions, l'impact, une reproduction minimale et, si possible, un test de
non-régression proposé.

## Secrets

- ne jamais committer de clé privée, PSK, mot de passe, jeton, certificat privé
  ou fichier de configuration local sensible ;
- conserver les clés éditeur hors du dépôt et de la gateway ;
- utiliser uniquement des exemples et trousseaux publics explicitement prévus
  pour le développement ;
- vérifier le diff et l'état Git avant chaque commit ;
- si un secret est exposé, le considérer compromis, le révoquer ou le remplacer
  selon le processus de son propriétaire, puis prévenir les mainteneurs.

Les invariants détaillés et le modèle de menace sont documentés dans
[`docs/security/SECURITY.md`](docs/security/SECURITY.md) et les ADR associés.

## Bonnes pratiques du dépôt

Les changements doivent rester ciblés, préserver le comportement fail-closed
aux frontières de sécurité et inclure des tests adaptés lorsqu'un contrat
change. Ne pas désactiver un audit, affaiblir une validation ou masquer une
erreur pour faire passer la CI.
