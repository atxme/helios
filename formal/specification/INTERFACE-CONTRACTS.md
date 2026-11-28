# Contrats d’interface pour les modèles

Proposition pour `SPEC-GATE`. Une hypothèse de frontière indique le
producteur de la garantie, ses conditions de validité et les travaux qui
doivent la justifier. Le statut initial de ces contrats est **à instruire**.

| ID | Producteur → consommateur | Données transférées et garantie à instruire | Obligations et validation |
| --- | --- | --- | --- |
| IFC-01 | QUIC/mTLS → protocole | Connexion, empreinte, identité vérifiée et événements de livraison. La politique d’admission et l’appartenance TLS/PQ à la même génération restent dans la v5. | `HYP-01`, `IDE-01` à `IDE-03`. Audit QUIC et correspondance Rust. |
| IFC-02 | Astra et opérateur → protocole | État de confiance effectif par acteur avec génération, ancre, validité et révocation. Modéliser la diffusion de la décision et son activation comme des étapes distinctes lorsque le contrat le permet. | `IDE-03`, `ETAT-07`. Audit de la rotation et points de réévaluation. |
| IFC-03 | Cryptographie → Tamarin, état, composition | Garanties des signatures et du KEM, connaissances adverses, contexte HKDF et fraîcheur. Distinguer secret de PSK, authentification et confidentialité des clés de transport. | `HYP-02` à `HYP-04`, `HYP-12` à `HYP-14`, `HYP-17`, `HYP-19`, `HYP-20`. Argument de composition et revue. |
| IFC-04 | WireGuard et backend → protocole | Événements distincts de pose réelle, acquittement, handshake, publication et lecture. Déclarer la provenance de l’observation, son retard possible, sa relation au pair et les effets d’une remise à zéro. | `HYP-08`, `HYP-09`, `HYP-18`, `ETAT-02`, `ETAT-03`. Modèles et mesures Linux/Windows. |
| IFC-05 | Stockage → état et reprise | Écriture demandée, point d’effet, synchronisation, acquittement et état relu après crash. Délimiter redémarrage ordinaire, restauration d’une sauvegarde et administration autorisée. | `HYP-05`, `HYP-11`, `ENR-04`, `ETAT-04`, `ETAT-08`. Modèle de pannes et validation du stockage. |
| IFC-06 | Horloges, compteurs et ordonnanceur → état et temps | Temps mural et écoulé, suspension, âge du handshake, volumes, retard de lecture et conditions de disponibilité ou d’équité. | `HYP-06`, `HYP-15`, `HYP-16`, `VIE-03`, `VIE-07`, `VIE-08`. Modèle temporel et mesures ciblées. |
| IFC-07 | Tunnel, pare-feu et routage → retrait et renouvellement | Origine WireGuard, résolution VIP vers le pair admis, route et canal effectifs. La v5 décide si l’identité ainsi résolue est autorisée à agir sur le slot. | `HYP-08`, `VIE-01`, `VIE-04`, `VIE-09`. Linux et Windows, familles d’adresses applicables. |
| IFC-08 | Modèles → validation Rust | Événements partagés, correspondance des paramètres, état lu ou modifié, et condition de raffinement. Une transition abstraite peut correspondre à plusieurs opérations concrètes, incluant des points d’annulation. | Cartographie versionnée, tests existants et validation de ce qu’ils couvrent. |
| IFC-09 | Opérateur et enrôlement → admission | Ancre confirmée hors bande, preuves de possession, événement durable de consommation et publication de l’admission. Le transport des fichiers peut être observé selon le scénario. | `HYP-10`, `HYP-20`, `ENR-01` à `ENR-08`. Modèle symbolique, état et audit. |

## Frontière de ETAT-03

Le modèle doit pouvoir représenter un handshake antérieur à l’installation
dont l’observation est publiée ou lue après celle-ci, tant que ce cas
n’est pas exclu par une garantie indépendante justifiée. Une opération
backend peut prendre effet avant la réception de sa réponse. Une
observation porte ce que le backend expose effectivement. L’énoncé
« cette observation prouve un handshake avec le candidat de cette
transaction » est la propriété à vérifier.

L’équipe de validation fournit une trace datée et la provenance de chaque
observation. L’équipe modèle décrit les comportements admis par le contrat,
avec une portée par backend. L’équipe Rust examine où les instantanés, leur
comparaison et la génération sont utilisés. La revue statue sur ce que ces
éléments permettent d’établir et sur les cas encore ouverts. `CMP-05`
assemble ces quatre apports en un argument par backend.

## Règle de composition

Tout import de garantie identifie l’interface, les scénarios, les
hypothèses, la révision du résultat producteur et la correspondance de ses
événements avec le modèle consommateur. Si une garantie importée est
ouverte, les résultats qui en dépendent restent conditionnels. Le
[registre des tâches](../TASK-REGISTRY.yaml) et le
[journal des arbitrages](../governance/OPEN-QUESTIONS.md) permettent de
suivre ces dépendances.
