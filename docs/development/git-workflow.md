# Workflow Git

## Branche de travail

Partir de `main` et travailler sur une branche dédiée. Les noms existants et
recommandés utilisent un préfixe court (`feat/`, `fix/`, `docs/`, `test/`,
`chore/`) suivi d'un sujet en kebab-case. Garder une branche limitée à un
objectif cohérent.

```sh
git switch main
git pull --ff-only
git switch -c docs/contributing-guide
```

Avant une pull request, vérifier l'état et le diff :

```sh
git status --short
git diff --check
git diff --stat
git diff --name-only
```

## Commits et pull requests

Les commits suivent le style Conventional Commits observé dans l'historique :
`type(scope): message`. Les types courants sont `feat`, `fix`, `docs`, `test`,
`refactor` et `chore`. Les commits doivent rester atomiques et ne contenir ni
artefacts générés ni secrets.

Une pull request cible `main`, décrit son périmètre et indique les vérifications
exécutées. Les changements de sécurité, protocole, release ou plusieurs crates
doivent passer `bash scripts/regression.sh` lorsque l'environnement le permet.

Les pushes et tags de release sont opérés selon les workflows GitHub existants.
La CI de release produit des artefacts non signés ; la signature reste une
opération hors CI décrite dans la documentation de sécurité.
