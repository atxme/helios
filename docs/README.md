# Documentation Helios

Index central de la documentation du dépôt. Le code et les ADR acceptés font
foi en cas de doute (voir [AGENTS.md](../AGENTS.md)).

## Gouvernance et contribution

- [README](../README.md) — présentation, démarrage et points d'entrée.
- [CONTRIBUTING](../CONTRIBUTING.md) — branches, commits et pull requests.
- [SECURITY](../SECURITY.md) — signalement, secrets et pratiques de sécurité.
- [AGENTS.md](../AGENTS.md) — règles communes pour les agents et développeurs.
- [CLAUDE.md](../CLAUDE.md) — adaptateur d'instructions spécifique à Claude.

## Architecture

- [Vue d'ensemble](architecture/overview.md) — composants, responsabilités et
  flux principaux.
- [Architecture opérationnelle](ARCHITECTURE.md) — démarrage de la gateway,
  états WireGuard, kill-switch, API, secrets et validation.
- [Firewall v2](architecture/FIREWALL-V2.md) — audit Policy/IR/Netlink,
  capacités, limites backend et recette de validation cible.
- [Étude IPv6](architecture/ETUDE-IPV6.md) — audit des dépendances IPv4,
  architecture dual-stack cible, risques et roadmap par tickets.

## Développement

- [Build](development/build.md) — prérequis et commandes de compilation.
- [Tests](development/testing.md) — vérifications ciblées, régression et
  limites d'environnement.
- [Workflow Git](development/git-workflow.md) — branches, commits et contrôles
  avant pull request.

## Exploitation

- [RENOUVELLEMENT-CERTIFICATS.md](RENOUVELLEMENT-CERTIFICATS.md) — commandes de
  renouvellement et de rotation des certificats.
- [DEPLOIEMENT-ASTRA.md](DEPLOIEMENT-ASTRA.md) — déploiement de l'autorité et
  état réellement éprouvé.

## Décisions (ADR)

- [README ADR](adr/README.md) — format et modèle minimal des décisions.
- [ADR-001 — WireGuard](adr/ADR-001-WIREGUARD.md) — choix du plan de données.
- [ADR-002 — Signatures PQ](adr/ADR-002-SIGNATURES-PQ.md) — signatures des
  artefacts de confiance.
- [ADR-003 — Mises à jour applicatives](adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md)
  — mises à jour signées et rollback.
- [ADR-004 — Chaîne de livraison](adr/ADR-004-CHAINE-DE-LIVRAISON.md) — secrets,
  admission, profils et artefacts.
- [ADR-005 — Négociation de clé](adr/ADR-005-NEGOCIATION-DE-CLE.md) — protocole
  pré-WireGuard et modèle de menace.
- [ADR-006 — Secrets au repos](adr/ADR-006-SECRETS-AU-REPOS.md) — stockage
  chiffré et protection des secrets.
- [ADR-007 — Fenêtre de mise à jour](adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md) —
  secret scellé et redémarrage planifié.
- [ADR-008 — Astra](adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md) — autorité de
  certificats et renouvellement.

## Spécifications

- [Négociation v4](specification/NEGOCIATION-DE-CLE-V4.md) — protocole
  historique.
- [Négociation v5](specification/NEGOCIATION-DE-CLE-V5.md) — protocole servi,
  avec ses lots encore ouverts.
- [Rotation des certificats](specification/ROTATION-CERTIFICATS.md) — cycle de
  vie cible des certificats TLS/PQ.
- [Adressage IPv6](specification/ADRESSAGE-IPV6.md) — modèle d'adressage
  IPv6 du tunnel (ULA `/64`, VIP `/128`) et IPAM unifié, validé, en cours
  d'implémentation.
- [Sortie IPv6](specification/SORTIE-IPV6.md) — politique de sortie Internet
  IPv6 des clients du tunnel (rejet explicite en V1, NAT66 écarté), validée.

## Sécurité

- [SECURITY.md](../SECURITY.md) — règles de contribution et signalement.
- [security/SECURITY.md](security/SECURITY.md) — contrôles automatisés et dette
  suivie.
- [POST-QUANTUM.md](security/POST-QUANTUM.md) — mécanismes post-quantiques.
- [PUBLISHER-SIGNING.md](security/PUBLISHER-SIGNING.md) — signature éditeur.
- [OPERATOR-TOOLING.md](security/OPERATOR-TOOLING.md) — outillage opérateur.

## Tests et validation

- [Guide de test](development/testing.md) — commandes ciblées et campagne
  complète.
- [TESTING.md](testing/TESTING.md) — stratégie, matrice et limites de cible.
- [PREMIER-DEPLOIEMENT.md](testing/PREMIER-DEPLOIEMENT.md) — première gateway
  réelle et client Windows.
- [MANUAL-TESTING.md](testing/MANUAL-TESTING.md) — recette interactive des
  binaires et interfaces.
- [WSL2-DEV.md](testing/WSL2-DEV.md) — ce que WSL2 valide ou non.
