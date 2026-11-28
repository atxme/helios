# Critères d’acceptation

## Définition d’un lot livrable

- Identifie ses clauses, obligations, menaces, hypothèses, sources et
  dépendances. Nomme un propriétaire, un relecteur distinct et son champ
  d’écriture. Consigne tout changement approuvé de portée.
- Fournit l’énoncé attendu, la révision et les fichiers du modèle, la
  commande, la version exacte des outils et dépendances, la configuration,
  les bornes, les paramétrages d’ordonnancement et, le cas échéant, la graine.
  Identifie la cible et le backend pour les observations expérimentales.
- Conserve la sortie déterminante, la preuve, le scénario nominal ou le
  contre-exemple, le résultat des mutations de modèle, ainsi que le lien et
  l’empreinte de tout artefact externe. Associe la correspondance Rust à une
  révision distincte identifiée.
- Porte un verdict, sa justification et une trace de la revue. Un lot ouvert
  doit préciser ce qui a été essayé, pourquoi la conclusion manque et ce qui
  permet de reprendre.

## Contrôles de validité

| Contrôle | Élément attendu |
| --- | --- |
| Fidélité normative | Examiner l’énoncé et ses exceptions avant l’exécution. Un changement de quantificateur, de population, d’observable ou de condition de compromission est une révision de propriété à approuver. |
| Absence de circularité | Examiner les restrictions, faits initiaux et garanties supposées. Une abstraction ne peut garantir par construction l’obligation qu’elle doit vérifier. Pour `ETAT-03`, le modèle sépare le handshake réel, sa publication, sa lecture et l’appartenance au PSK candidat. |
| Non-vacuité | Obtenir une exécution qui atteint les événements pertinents et satisfait l’antécédent dans chaque mode ou profil nécessaire. Une implication peut être vraie parce que son antécédent est inaccessible. |
| Sensibilité | Dans une copie du modèle, modifier le mécanisme censé assurer la propriété. Comparer résultat nominal et résultat muté. Si la propriété tient encore, expliquer le mécanisme redondant ou l’abstraction qui masque son effet, puis faire revoir cette conclusion. |
| Contre-exemples | Conserver la trace et la rattacher aux événements, hypothèses et clauses concernés. Qualifier le résultat comme divergence du modèle, ambiguïté normative ou écart d’implémentation confirmé par les éléments appropriés. |
| Composition | Pour une garantie importée, identifier le producteur, la portée et le verdict. Un cycle entre résultats conditionnels doit être rompu par un contrat indépendant ou par un argument de composition validé. |
| Portée | Distinguer vérité sous abstraction symbolique, exploration finie, argument computationnel, test ou mesure. Les bornes, états exclus et causes d’interruption figurent dans le verdict. |
| Revue | Faire reproduire le résultat critique et revoir les hypothèses par une personne ou un agent distinct de l’auteur. Les désaccords non résolus apparaissent dans le dossier. |

Mutations de référence sur les modèles de vérification. Retirer la
consommation du challenge ou la liaison à la gateway, ajouter une divulgation
du PSK, rendre la signature possible sans handshake correspondant, autoriser
un rollback après signature, retirer la persistance préalable du plancher
ou laisser agir un propriétaire obsolète. Le registre des propriétés
précisera le résultat négatif attendu pour chaque mutation retenue.

## Interprétation des verdicts

- **Établie sous hypothèses** si les éléments acceptés couvrent l’énoncé avec
  sa portée déclarée. Pour un model checker, une exploration porte sur
  l’espace indiqué. Pour un argument de composition, décrire les preuves
  et garanties externes utilisées.
- **Contredite dans le modèle** si une trace viole l’énoncé dans la portée
  examinée. Avec les correspondances et les validations requises,
  consigner séparément si la contradiction vaut pour l’implémentation.
- **Ouverte** si l’outil s’arrête, si les bornes ou les observations sont
  insuffisantes, si l’argument n’est pas validé ou si une décision normative
  manque. Identifier les travaux ou garanties nécessaires.

Le verdict d’une obligation agrégée tient compte de toutes ses propriétés
élémentaires requises. Une preuve positive sur une composante et une
question ouverte sur une autre donnent un verdict agrégé ouvert. Une trace
qui contredit une composante nécessaire peut contredire l’obligation dans la
portée de cette trace.
