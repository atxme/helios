# Questions ouvertes avant la campagne

Les observations ci-dessous délimitent l’audit. Elles ne constituent pas
des constats de vulnérabilité. Une interprétation de travail identifie la
clause, les variantes, l’arbitrage de Fable et les résultats à réexécuter.
Une question ouverte limite les conclusions concernées et reste visible
dans le dossier remis pour acceptation finale.

| ID | Question et source | Travaux ou arbitrage | Conclusion concernée |
| --- | --- | --- | --- |
| Q-01 | Le §11.2 décrit une séquence monotone d’observations. Le chemin Rust examiné compare deux valeurs optionnelles de type `SystemTime` rapportées par le backend. Leur relation au candidat reste à établir. | Définir la provenance et l’ordre des événements. Vérifier Linux et WireGuard-NT, observation ancienne, réinitialisation et lecture autour d’une pose. | `ETAT-03`, `IFC-04`, `EXP-01` à `EXP-04`. |
| Q-02 | Le §11.4 indique deux secondes entre tentatives. Le §12.5 indique onze secondes entre essais de sa boucle et distingue tentative de réparation et négociation. | Déterminer si les portées diffèrent, et établir pour chaque boucle les délais, le repos imposé et le budget. Documenter tout écart avec Orion. | `VIE-07`, `TIM-08`, `IFC-06`. |
| Q-03 | Le §17 revendique la protection du premier handshake et le §2.1 la protection contre le déchiffrement tardif. Les termes ne fixent pas à eux seuls les données observées ni les divulgations autorisées. | Séparer les deux modes et documenter la composition jusqu’aux clés de transport, les connaissances adverses et l’horizon de sécurité. | `CLE-02`, `CLE-03`, `IFC-03`, `CMP-03`. |
| Q-04 | Les §5.3 et §17.3 bornent la divulgation par les rejets. Les mesures possibles comprennent le code, le format, la fermeture et le temps. | Fixer les observables et les paires d’exécutions à comparer. Distinguer la revendication de trace de la mesure temporelle. | `OBS-01`, `CLE-03`, `TAM-11`, `EXP-10`. |
| Q-05 | Le §6.1 distingue acceptation et refus qui termine la phase. Dans le Rust actuel, `consume_challenge` intervient avant la validation et `prepare`. | Fixer les points de trace `ChallengeConsumed` et `RequestAccepted` et vérifier la conformité observable, en particulier sur refus et fermeture. | `FRA-02`, `TAM-FRA-02`, `RUST-08`. |
| Q-06 | Les §4.5 et §12 donnent des seuils de retrait et de récupération alors que l’observation est périodique et qu’une opération peut être en cours. | Préciser début, franchissement, observation et retrait effectif. Fixer le retard admissible et le traitement des événements différés. | `VIE-03`, `VIE-06`, `TIM-03` à `TIM-07`. |
| Q-07 | Une identité peut être autorisée à l’ouverture du canal puis expirer, être remplacée ou révoquée avant une mutation. | Établir les points de réévaluation côté Helios et Orion, et la portée d’une session ouverte sous un état antérieur. | `IDE-03`, `ETAT-07`, `IFC-02`, `AUD-07`. |
| Q-08 | La persistance avant signature ou émission est distincte de la restauration d’un ancien instantané ou de l’abaissement local explicite du plancher. | Définir le modèle de panne et de durabilité pour chaque état. Délimiter les actions administratives et les garanties externes nécessaires. | `ENR-04`, `ETAT-04`, `ETAT-08`, `IFC-05`. |
| Q-09 | La liste des méthodes est initiale. Les versions d’outils, limites de calcul, cibles Linux/Windows et accès aux backends restent à fixer. | Fable fixe versions, conditions d’exécution et affectations dans les limites de l’autorisation initiale. Une cible indisponible borne la validation correspondante. | `GOV-APPROVAL`, `TOOLS-PIN`, `EXP-01`, `EXP-02`. |

Références de ces questions.
[Contrat v5](../../docs/specification/NEGOCIATION-DE-CLE-V5.md) ·
[Rotation Astra](../../docs/specification/ROTATION-CERTIFICATS.md) ·
[Serveur de négociation](../../crates/aether-key-negotiation/src/server.rs)
