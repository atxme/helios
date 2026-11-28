# Autorisation initiale `GOV-APPROVAL`

**Statut : non signée.** Tant que la section *Signature* est vide, aucun lot
de la campagne ne démarre. Le responsable humain complète ou corrige les
valeurs proposées ci-dessous, puis signe. Fable consigne ensuite ce document
comme autorisation unique, sans nouvelle sollicitation jusqu’à `IND-04`.

La campagne s’exécute dans l’environnement de Fable, pas sur le poste du
responsable humain. Les valeurs proposées ne valent qu’une fois confirmées
par la signature.

## Délégation

- Coordinateur scientifique : Fable, selon [les règles](../../AGENTS.md)
  et [le prompt de mission](../../CLAUDE-PROMPT.md).
- Branche de coordination : `docs/verification-formelle-v5` sur
  `atxme/helios`. Chaque agent d’écriture travaille dans un worktree
  dédié créé à partir de cette branche.
- Publication sur la branche de coordination : [ ] autorisée · [ ] commits
  locaux seulement, publication par le responsable humain.
- Exclus du mandat : code produit, mécanismes cryptographiques, sources
  normatives, fusion vers `main`, étiquettes `v*` et déclencheurs de CI
  supplémentaires.

## Environnement d’exécution

Au démarrage, `TOOLS-PIN` relève l’environnement réel (processeurs, mémoire,
disque, système) et l’enregistre avec les plafonds ci-dessous. Si
l’environnement ne permet pas un plafond, Fable retient la valeur inférieure
et borne les lots concernés.

| Ressource | Plafond proposé |
| --- | --- |
| Mémoire par exécution lourde (Tamarin, Maude, TLC, UPPAAL, Kani) | Fixée par `TOOLS-PIN` d’après l’environnement relevé, appliquée par un mécanisme de l’OS (cgroup ou équivalent). |
| Exécutions lourdes simultanées | 2. |
| Durée d’une exécution notée | 4 h, avec point de réévaluation à 1 h. |
| Builds Cargo | Règles de validation du dépôt ([`AGENTS.md`](../../../AGENTS.md)). |
| Artefacts volumineux | Hors Git, avec empreinte citée dans les résultats. |

## Outils

Tamarin, Maude, ProVerif, TLC, UPPAAL et Kani sont installés et épinglés
par `TOOLS-PIN` dans l’environnement d’exécution.

- Installation des outils : [ ] autorisée · [ ] refusée, lots concernés bornés.
- UPPAAL exige une licence. [ ] Licence disponible · [ ] `TIM-00`
  choisit le temps discret en TLA+ ou un autre outil libre.

## Cibles de validation

[`TESTING.md`](../../../docs/testing/TESTING.md) exclut toute conclusion
sur le noyau, WireGuard-NT ou le matériel depuis WSL2. Sans cible réelle,
`EXP-01` à `EXP-12` produisent des limites documentées et `ETAT-03` reste
au mieux conditionnelle.

| Cible | Accès |
| --- | --- |
| Gateway Linux avec WireGuard noyau | [ ] machine de test réservée : … · [ ] aucune |
| Poste Windows avec WireGuard-NT et Orion | [ ] machine de test réservée : … · [ ] aucune |
| Données | Matériel de test uniquement, aucune identité ni PSK de production. |

## Agents et coût

- Agents actifs simultanés : 6 au plus, dont 2 exécutions lourdes.
- Budget global de la campagne : … (durée calendaire, coût ou volume
  d’usage). À l’épuisement, Fable prépare `IND-03` et `IND-04` avec les
  éléments disponibles, comme prévu par le registre.

## Signature

| Champ | Valeur |
| --- | --- |
| Responsable humain | |
| Date | |
| Révision autorisée | |
| Réserves | |
