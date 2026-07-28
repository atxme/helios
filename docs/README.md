# Documentation Helios

Point d'entrée de la documentation. Le code et les ADR acceptés font foi en
cas de doute (voir [AGENTS.md](../AGENTS.md)).

## Architecture

- [ARCHITECTURE.md](ARCHITECTURE.md) — vue opérationnelle courante du système
  (Helios, Orion, `aether`).
- [adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md](adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md)
  — architecture de mise à jour du binaire `heliosd`.

## Décisions (ADR)

- [adr/ADR-001-WIREGUARD.md](adr/ADR-001-WIREGUARD.md) — bascule d'IKEv2/IPsec
  vers WireGuard.
- [adr/ADR-002-SIGNATURES-PQ.md](adr/ADR-002-SIGNATURES-PQ.md) — signatures
  post-quantiques hybrides des artefacts de confiance.
- [adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md](adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md)
  — mises à jour applicatives signées, autorisation WireGuard et rollback.
- [adr/ADR-004-CHAINE-DE-LIVRAISON.md](adr/ADR-004-CHAINE-DE-LIVRAISON.md) —
  cycle de vie des secrets, admission, profils clients et livraison
  d'artefacts.
- [adr/ADR-005-NEGOCIATION-DE-CLE.md](adr/ADR-005-NEGOCIATION-DE-CLE.md) —
  spécification et modèle de menace de la négociation de clé pré-WireGuard :
  port public, PKI ML-DSA-65, PSK ML-KEM du **premier** handshake, plancher
  anti-downgrade et identité cliente scellée.
- [adr/ADR-006-SECRETS-AU-REPOS.md](adr/ADR-006-SECRETS-AU-REPOS.md) —
  chiffrement AES-256-GCM des secrets sur disque, hiérarchie de clés Orion liée
  au TPM, hygiène mémoire et modèle de menace du stockage local. Le chiffrement
  de volume (BitLocker / dm-crypt) y devient un **prérequis d'installation**.

## Sécurité

- [security/SECURITY.md](security/SECURITY.md) — contrôles automatisés et
  dette suivie.
- [security/POST-QUANTUM.md](security/POST-QUANTUM.md) — les deux mécanismes
  post-quantiques (PSK WireGuard, signatures éditeur) et ce qui les distingue.
- [security/PUBLISHER-SIGNING.md](security/PUBLISHER-SIGNING.md) — guide
  opératoire de `helios-publisher` (poste éditeur).
- [security/OPERATOR-TOOLING.md](security/OPERATOR-TOOLING.md) — guide
  opératoire du poste opérateur : identité de la gateway, séquestre, admission
  et profils clients.

## Tests et validation

- [testing/TESTING.md](testing/TESTING.md) — stratégie de test, matrice
  automatisée, référence `scripts/regression.sh`.
- [testing/PREMIER-DEPLOIEMENT.md](testing/PREMIER-DEPLOIEMENT.md) — marche à
  suivre pour installer une vraie gateway et y connecter un client Windows.
- [testing/MANUAL-TESTING.md](testing/MANUAL-TESTING.md) — recette
  interactive pour les binaires et les IHM.
- [testing/WSL2-DEV.md](testing/WSL2-DEV.md) — ce que WSL2 prouve et ne prouve
  pas (compilation vs exécution réelle).
