# Sémantique commune des modèles

Proposition pour `SPEC-GATE`. Les champs indiquent la provenance minimale
à conserver dans une correspondance de trace. Deux modèles peuvent projeter
des champs différents si la projection préserve les propriétés qui en
dépendent.

## Identités et domaines d’état

Identifier indépendamment la gateway, le pair, chaque rôle et génération
d’identité (TLS/PQ), la connexion, le challenge, l’identifiant de
transaction, la génération propriétaire du slot, le candidat et le
démarrage du processus. Le candidat est désigné par un identifiant de
modèle. Les preuves et traces publiques ne contiennent aucun PSK réel.

| Domaine | État à représenter | Divergences permises à examiner |
| --- | --- | --- |
| État applicatif Helios | Connexion et challenge, décision d’admission, propriétaire et état du slot, données de restauration, confirmation et verdict signé. | Le propriétaire logique et le slot backend peuvent évoluer à des instants distincts. |
| État applicatif Orion | Profil et confiance locale, candidat local, reçu du commit et politique de reprise. | Orion peut conserver un verdict différent après perte du commit alors que les deux slots correspondent. |
| Plans de données WireGuard | Candidat effectivement installé de chaque côté, génération pertinente, handshakes et observations, clés de transport actives dans la portée du modèle. | Une ancienne observation ou une ancienne clé de transport peut survivre à une transition applicative selon le contrat de backend. |
| État durable et confiance | Invitations, ancres et admissions installées, planchers, écritures en cours et révision visible par chaque acteur. | Une valeur en mémoire peut différer de la valeur durable. Un redémarrage et un rechargement préservent des ensembles d’états différents. |

Les valeurs initiales doivent refléter l’origine de l’état considéré.
Une propriété couvrant l’enrôlement part d’un état compatible avec le
bootstrap. Un modèle qui commence avec un pair admis documente les
garanties importées.

## Catalogue initial des événements

| Événement | Instant et paramètres déterminants | Référence |
| --- | --- | --- |
| `PeerAdmitted` | Le registre effectif autorise le pair et sa génération TLS/PQ pour la gateway. | §3.3–3.4, §15 |
| `ChannelAuthenticated` | Une connexion accepte l’identité de transport, avant la décision applicative. Inclure côté, connexion et empreinte. | §3.3, §4.1, §5.3 |
| `ChallengeIssued` | La gateway émet le challenge lié à sa connexion et au démarrage courant. | §6 |
| `ChallengeConsumed` | Le point d’usage unique retire l’autorisation attachée au challenge. | §6, §13 |
| `RequestAccepted` | La décision d’acceptation applicative a été prise. Retenir gateway, pair, connexion, challenge, transaction et mode. | §6, §7.1, §13 |
| `SlotReserved` | Le propriétaire générationnel du pair est réservé. | §11.1 |
| `PSKDerived` | Le côté désigné produit le candidat à partir du contexte de la transaction. L’association d’un PSK statique configuré reçoit un événement distinct si le modèle en a besoin. | §9–10 |
| `PSKInstalled` | Le backend du côté indiqué a effectivement posé le candidat. Associer pair, transaction et candidat selon la provenance disponible. | §11.1–11.2, §13 |
| `BackendAcknowledged` | L’appelant reçoit le résultat de l’opération identifiée. Enregistrer succès ou erreur si le modèle les distingue. | §11, interface backend |
| `HandshakeOccurred` | WireGuard réussit un handshake réel, avec l’identité et les éléments effectivement utilisés selon le contrat WireGuard. | §11.2, §13 |
| `HandshakePublished` | Le backend expose une observation associée à un pair et à une provenance permise par son interface. | §11.2, interface backend |
| `HandshakeObserved` | Le processus lit une valeur ou une séquence. Enregistrer la valeur et l’instant de lecture sans présumer un lien au candidat. | §11.2 |
| `ConfirmationAccepted` | La gateway valide la confirmation reçue et sa liaison à la transaction. La validation de la preuve backend reste représentée séparément. | §7.3, §8.4, §11.2 |
| `FloorPersisted` | Le nouveau plancher remplit la condition de durabilité selon le contrat de stockage. | §11.2, §14 |
| `CommitSigned` | La signature a réussi. Cet instant est le point de non-retour côté gateway. | §7.4, §11.2 |
| `CommitReceived` | Orion reçoit le commit. Sa validation est une étape distincte si l’énoncé porte sur le verdict client. | §7.4, §11.5 |
| `SlotReleased` | Le plan de données a effectivement retiré le slot visé. Enregistrer la cause et le propriétaire autorisé. | §7.5, §11–12 |
| `PeerRevoked` | L’autorisation d’admission est retirée sur le côté concerné. La suppression effective du slot est observée séparément. | §11.1, §12.4 |
| `SecretRevealed` | Le profil adversaire obtient une donnée ou une capacité de signature identifiée. Lier détenteur, génération, portée et instant. | Catalogue, scénarios et HYP |
| `ProcessCrashed` | Le processus s’arrête au point choisi. Le modèle note les effets qui ont déjà eu lieu et les états qui survivent. | §11, §12.5 |

Les numéros renvoient au [contrat v5](../../docs/specification/NEGOCIATION-DE-CLE-V5.md).
Le point de correspondance exact entre consommation du challenge, refus et
acceptation est un sujet d’audit. Une transition d’un outil peut produire
plusieurs événements si son atomicité normative est justifiée.

## Correspondances par outil

| Domaine | Traduction attendue |
| --- | --- |
| Tamarin | Les faits d’action portent les événements pertinents. Les règles représentent les transitions autorisées et les capacités de divulgation. Les restrictions ont une justification normative identifiée. |
| TLA+ | Les actions portent les transitions effectives et les points où le monde externe peut évoluer indépendamment. Les variables persistantes et volatiles sont distinctes. Les hypothèses d’équité appartiennent à la portée déclarée. |
| Modèle temporel | Les horloges et compteurs sont attachés aux événements d’origine. La mesure, les points de lecture, la suspension et les retards font partie de l’abstraction. |
| Rust et expériences | Associer un événement à une transition, une instrumentation ou une observation qualifiée. Les événements inférés indiquent quelles autres observations et hypothèses justifient l’inférence. |

Les [acteurs, menaces et hypothèses](../../docs/specification/VERIFICATION-FORMELLE-NEGOCIATION-V5.md)
restent dans le catalogue canonique. Les
[contrats d’interface](INTERFACE-CONTRACTS.md) précisent les frontières
à respecter lors d’un transfert entre modèles.

## Exemple de décomposition · FRA-02

Ces identifiants sont proposés pour `PROP-FRA`. Ils prolongent la fiche
de traçabilité du catalogue au lieu de remplacer ses symboles existants.

| Propriété élémentaire | Objectif et portée initiale |
| --- | --- |
| `FRA-02-P01` | Au plus une consommation de l’autorisation du challenge par émission honnête. |
| `FRA-02-P02` | Unicité de l’acceptation applicative pour le couple gateway–challenge. Symbole existant `FRA_02_unique_acceptance`. |
| `FRA-02-P03` | Une acceptation a été précédée d’une émission pour la même connexion et la même gateway. Symbole existant `FRA_02_connection_binding`. |
| `FRA-02-P04` | La gateway acceptante correspond à la gateway visée par le message authentifié. Ce résultat dépend de la liaison couverte par `AUT-01`. |
| `FRA-02-P05` | Une acceptation après redémarrage requiert une émission du challenge appartenant au nouveau démarrage. |
| `FRA-02-P06` | L’émission, la consommation et l’acceptation respectent l’ordre et l’atomicité définis pour leur portée. Inclure le cas où elles partagent une transition et distinguer la fin refusée. |
| `FRA-02-E01` | Une exécution honnête atteint la consommation et l’acceptation dans chaque mode applicable. |

La propriété locale de consommation et la propriété de liaison entre
connexions n’emploient pas nécessairement les mêmes hypothèses. La revue
doit comparer la portée des énoncés, les traces nominales et les résultats
attendus des mutations avant exécution.
