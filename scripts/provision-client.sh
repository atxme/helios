#!/usr/bin/env bash
# Provisionnait un client Orion de bout en bout, en une commande.
#
# Il enchaînait la CA opérateur sur fichier, `key-nego issue-client`,
# `heliosd peer add` et l'ancien `helios enroll`, qui livrait les clés privées
# du poste dans le profil. L'enrôlement v5 (NEGOCIATION-DE-CLE-V5 §15) ne
# transmet plus aucune clé privée : l'opérateur signe une invitation sous CA-PQ
# avec un credential matériel, le poste produit sa demande, et un document
# signé revient. Ces gestes demandent une personne à chaque bout ; aucun script
# ne les fait à sa place.
#
# Le script refuse donc, et dit où est le parcours qui le remplace.
set -euo pipefail

cat >&2 <<'EOF'
provision-client.sh n'enrôle plus de client : l'ancien enchaînement livrait les
clés privées du poste dans le profil.

L'enrôlement v5 se fait en trois gestes, décrits dans
docs/security/OPERATOR-TOOLING.md §6 :
  1. astra-signer enroll invite      — invitation signée sous CA-PQ
  2. Orion « Demande d'enrôlement »  — le poste génère ses clés et sa demande
  3. astra-signer enroll accept, helios enroll document,
     astra-signer enroll sign-document — le document signé revient au poste

La préparation de la gateway reste scriptée : ./scripts/key-negotiation-setup.sh
EOF
exit 2
