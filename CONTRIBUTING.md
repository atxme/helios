# Contribuer à Helios

## Workflow Git

Créer une branche de travail à partir de `main`, avec un nom court et explicite,
par exemple `feat/key-negotiation`, `fix/firewall-state` ou
`docs/contributing-guide`. Une branche ne doit porter qu'un changement cohérent.
Mettre régulièrement la branche à jour avec `main`, puis ouvrir une pull request
vers `main`.

Les commandes de publication et de release sont décrites dans
[`docs/development/git-workflow.md`](docs/development/git-workflow.md). Ne pas
committer de secrets, de fichiers locaux ni de sortie de build.

## Commits

Utiliser un préfixe de type court, suivi d'un périmètre facultatif et d'un
message à l'impératif, par exemple :

```text
docs(readme): clarify local development commands
fix(firewall): reject incomplete ruleset
test(orion): cover profile import failure
```

Garder les commits atomiques. Éviter les commits de formatage ou de refactoring
sans rapport avec le changement décrit.

## Pull requests

Une pull request doit expliquer le problème, le changement, les limites connues
et les éventuelles conséquences de sécurité ou de compatibilité. Elle doit
indiquer les commandes de vérification exécutées et signaler les validations
non disponibles dans l'environnement courant.

Avant de demander une revue :

- vérifier le diff et l'absence de fichiers générés ou de secrets ;
- exécuter `cargo fmt --check` ;
- exécuter les tests et le lint du périmètre touché ;
- pour un changement transversal, de sécurité, de protocole ou de release,
  exécuter `bash scripts/regression.sh` ;
- mettre à jour la documentation ou l'ADR concerné si le contrat change.

Les limitations liées au noyau, au TPM, à WireGuard-NT ou à l'installation
doivent être validées sur les environnements décrits dans
[`docs/testing/TESTING.md`](docs/testing/TESTING.md), et non présentées comme
validées par WSL2 ou un dry-run.
