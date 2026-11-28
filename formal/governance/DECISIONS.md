# Journal des décisions méthodologiques

Le statut **proposée** indique une décision que Fable peut instruire et
arbitrer dans la délégation initiale. Les interprétations et écarts restent
visibles dans les [questions ouvertes](OPEN-QUESTIONS.md).

| ID | Statut | Décision soumise à validation |
| --- | --- | --- |
| DEC-01 | Proposée | Référentiel initial épinglé à `fced071d8946c6a9c04ce050b06a9d36b11aafc3`. Le catalogue reste canonique pour obligations, menaces et hypothèses. |
| DEC-02 | Proposée | Une propriété élémentaire a la forme `<obligation>-Pnn`. Une atteignabilité associée utilise `<obligation>-Enn`. Les symboles propres aux outils ont une correspondance explicite au registre. |
| DEC-03 | Proposée | Les résultats distinguent preuve symbolique, exploration d’état, argument computationnel, audit et expérience. Les conclusions sur Rust et sur cible ont leur propre provenance. |
| DEC-04 | Proposée | Les modèles partagent des événements et contrats. Ils peuvent raffiner ces contrats ou invoquer une garantie externe après revue, avec sa provenance et ses conditions. |
| DEC-05 | Proposée | La révision du code, les versions d’outils et la configuration sont fixées pour chaque exécution. `PROP-SCHEMA` fixe le format minimal avant les premiers résultats. La phase 11 intègre le suivi, la génération et la CI. |
| DEC-06 | Retenue | `GOV-APPROVAL` consigne l’autorisation initiale unique. Fable arbitre les étapes intermédiaires et la décision humaine suivante porte sur le dossier remis via `IND-04`. |
| DEC-07 | Retenue | Une dépendance ouverte borne les seuls résultats qui l’importent. Les jalons publient les portions utilisables, conditionnelles ou ouvertes. La campagne continue sur résolutions alternatives et lots indépendants. |
| DEC-08 | Retenue | La coordination conserve dans Git des points de reprise réguliers et remet un dossier indiquant ce qui reste ouvert ou incomplet si une limite autorisée met fin à la campagne. |

Pour enregistrer une décision, indiquer l’auteur, le relecteur, la
portée de l’arbitrage de Fable, la révision des sources et les
propriétés ou résultats à réexaminer. Conserver les propositions
supplantées pour expliquer les résultats historiques.
