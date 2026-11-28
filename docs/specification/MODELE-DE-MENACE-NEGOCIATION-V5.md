# Modèle de menace de la négociation v5

Ce document définit les capacités à représenter, les frontières de confiance
et les scénarios à examiner pour la vérification de la v5. Les références
comme `IDE-02` et `ETAT-03` désignent les obligations du
[catalogue de vérification](VERIFICATION-FORMELLE-NEGOCIATION-V5.md). Les
garanties attendues viennent du [contrat v5](NEGOCIATION-DE-CLE-V5.md) et des
amendements v5 de l'[ADR-005](../adr/ADR-005-NEGOCIATION-DE-CLE.md).
Les scénarios n'ont pas encore de verdict de vérification.

## Acteurs, actifs et frontières de confiance

| Frontière | Acteurs et état | Actifs ou décisions à protéger |
| --- | --- | --- |
| Enrôlement hors bande | Opérateur, Orion, registre local d'invitations, canal de distribution des fichiers | Empreinte CA confirmée, autorisation d'émettre, état de consommation et droit de réadmission, possession des trois clés, liaison de la demande au profil livré. |
| WAN et QUIC | Adversaire réseau, Orion et listener de chaque gateway | Validation de source, ressources de négociation, rattachement du canal mTLS à un seul pair, identité de la gateway visée. |
| Messages v5 | Orion, authentification applicative PQ, registre d'admission Helios | Contexte signé, challenge, identités et générations admises, mode, secret ML-KEM éphémère et PSK candidat. |
| Tunnel WireGuard | Backends Orion et Helios, API interne, QUIC de renouvellement | Possession WireGuard, identité source issue du tunnel, état réel du slot et observation du handshake, autorisation de retrait et de renouvellement. |
| État local et durable | Processus, backend, fichiers de configuration, TPM ou stockage protégé, journal | Génération propriétaire, ancien slot de restauration, plancher durable, décision de commit, clés privées, compteurs et diagnostics. |
| Confiance en rotation | CA et registres d'identités, Astra à l'interface de la v5, Orion et Helios | Ancre retenue, génération autorisée, échéance et révocation. L'état visible par la v5 peut changer à des instants différents sur les deux bouts. |

Distinguer au minimum un client honnête, un second pair admis, une identité non
admise même si elle possède un certificat valide, deux gateways qui peuvent
partager une CA, et un opérateur autorisé à enrôler ou retirer un pair. Étudier
les sessions simultanées d'un même pair et celles de pairs différents.
Les règles des cérémonies Astra restent dans la
[spécification de rotation](ROTATION-CERTIFICATS.md). À la frontière de la v5,
le modèle précise quel état de confiance est installé, autorisé et visible, et
quand une mise à jour ou une révocation devient effective sur chaque bout.

## Capacités adverses de référence

- **Observateur passif.** Enregistre le WAN, les sessions WireGuard et les
  fichiers publics auxquels il a accès. Les adresses, tailles, temps et
  fermetures restent des observations distinctes des contenus protégés.
  Considérer séparément un observateur disposant après coup des transcriptions
  applicatives en clair.
- **Adversaire réseau actif.** Contrôle la livraison, avec suppression,
  duplication, retard, réordonnancement, partition et redirection. Il peut
  injecter des entrées sur les surfaces accessibles, ouvrir des sessions sur
  plusieurs gateways et présenter une source UDP non validée. Avec QUIC/mTLS
  et WireGuard intacts, ces capacités n'accordent ni l'injection de données
  authentifiées sur un canal honnête ni l'identité admise d'un autre pair.
- **Pair admis malveillant.** Contrôle son poste et peut signer avec ses
  propres clés. Il choisit ses messages, leur ordre dans les limites du
  transport et ses canaux autorisés. Il peut réutiliser son nonce, ignorer les
  délais prévus et cumuler sessions et adresses. Il a accès aux fonctions que
  lui ouvre son identité, avec ou sans rôle opérateur selon le scénario.
- **Gateway adversaire ou partiellement compromise.** Distinguer une gateway
  distincte, valide sous la même CA, la divulgation d'une ou plusieurs clés
  de la gateway visée, et le contrôle complet de son hôte. Dans le dernier
  cas, la sémantique d'un commit signé par cette gateway dépend de son propre
  comportement. Les garanties entre autres acteurs honnêtes restent à
  évaluer selon leurs hypothèses.
- **Pannes et ordonnancement.** L'adversaire réseau peut provoquer des pertes
  et des délais, donc modifier l'ordre relatif des événements. Pour les
  propriétés de robustesse, le modèle fait aussi varier les annulations, les
  réponses tardives et les pannes du processus, du disque ou du backend.
  La possibilité d'échecs d'E/S n'accorde pas l'écriture arbitraire dans un
  état local protégé. Une restauration de stockage ou une falsification de
  l'horloge par un hôte compromis se traite avec des hypothèses distinctes.

## Compromissions à distinguer

Pour chaque secret, relever le détenteur, la portée et le moment de la
divulgation. Tester la divulgation avant la session, pendant la transaction et
après la fin ou l'effacement pertinent. Une divulgation inclut la capacité
d'utiliser une clé via un hôte ou une interface qui continue à la protéger
contre l'export. Les garanties doivent changer explicitement lorsque les
autres clés du même acteur sont également disponibles.

| Capacité supplémentaire | Question à instruire |
| --- | --- |
| Clé TLS cliente ou gateway seule | Le canal ainsi authentifié suffit-il à franchir une étape applicative ? Vérifier les protections qui dépendent encore des clés PQ et WireGuard et les conséquences pour les ressources et la confidentialité du canal. |
| Clé ML-DSA cliente ou gateway seule | Quels énoncés d'authenticité de message tombent ? Quels énoncés requièrent encore le mTLS, la possession WireGuard et la bonne génération ? |
| Clé WireGuard cliente ou gateway seule | Que reste-t-il de la preuve de possession à l'enrôlement, à la confirmation et sur l'API du tunnel ? Distinguer un slot vide, statique ou négocié et la connaissance du PSK correspondant. |
| Clés TLS et ML-DSA d'un même pair, ou autre sous-ensemble de ses trois clés | Examiner ce que chaque étape peut établir sur le pair quand une des trois preuves reste indépendante. Inclure les clés de générations différentes et les identités retirées ou expirées. |
| Clé privée ML-KEM éphémère ou secret partagé d'une session | Délimiter la confidentialité de cette transaction et des autres sessions, selon les transcriptions disponibles et la fraîcheur du matériel. L'effacement à la frontière de l'implémentation conditionne ce scénario. |
| PSK négocié d'une transaction | Délimiter l'effet sur cette transaction, les sessions WireGuard qui en dérivent et les PSK négociés avant ou après. Étudier séparément la disponibilité des clés WireGuard. |
| PSK statique | Tenir compte de sa réutilisation. Examiner les sessions passées et futures qui utilisent ce secret et la capacité à relier les engagements enregistrés après divulgation. |
| Clé X25519 d'une invitation ou accès au fichier d'invitation | Distinguer un artefact public portant une autorisation valide, le secret éphémère de preuve, l'état de consommation et le pouvoir de signer une invitation. |
| Clé d'une CA TLS, clé d'émission PQ déléguée, `CA-PQ` ou confirmation hors bande contrôlée | Identifier précisément la confiance qui tombe et le domaine touché. Considérer encore l'admission locale, les épinglages et les autres preuves indépendantes lorsque leurs ancres restent saines. La reprise après perte de l'ancre suit le contrat de rotation. |
| Contrôle complet du poste Orion, de la gateway, du poste opérateur ou de l'administration | Consigner les garanties perdues par l'acteur contrôlé et examiner l'isolation des autres pairs et gateways lorsque leurs clés, registres et contrôles restent indépendants. |

Pour « récolter maintenant, déchiffrer plus tard », modéliser une capture faite
pendant une session honnête, puis la connaissance acquise plus tard lorsque
les mécanismes classiques de TLS et de WireGuard deviennent déchiffrables.
Vérifier quelles données restent protégées par le PSK dans chaque mode,
compte tenu de la possession du PSK, de l'effacement de la clé éphémère et
des hypothèses post-quantiques sur les primitives. Une analyse de secret
symbolique peut établir une propriété sur la connaissance modélisée. La
revendication sur le trafic WireGuard capturé demande en plus un argument
sur la composition avec le handshake et les clés de transport WireGuard.

## Scénarios à couvrir

| ID | Scénario et hypothèses à faire varier | Garantie ou question à vérifier |
| --- | --- | --- |
| MEN-01 | L'adversaire présente une invitation ou un profil sous une autre ancre, ou vers une autre gateway. Faire varier la confiance confirmée hors bande. | Origine de la confiance et liaison entre invitation, identité cible et profil importé. `ENR-01`, `ENR-02`, `ENR-06` |
| MEN-02 | Un demandeur compose une demande à partir de preuves ou de clés publiques de personnes, invitations ou demandes distinctes. | Possession des trois clés de la même demande, liaison au contexte et autorisation opérateur indépendante. `ENR-02`, `ENR-03`, `ENR-04` |
| MEN-03 | Deux demandes concurrentes visent la même invitation. Faire varier révocation, expiration, panne avant ou après la persistance, et réadmission d'une clé retirée. | Une seule consommation durable, aucun retour à l'état disponible après échec, réadmission explicite et plancher correct. `ENR-02`, `ENR-04`, `ENR-05` |
| MEN-04 | Des fichiers d'enrôlement circulent sur un canal public ou sont modifiés, intervertis ou remis au mauvais poste. Inclure les documents partiels et les différences d'interprétation JSON. | Aucune clé privée sur le fil. L'import valide l'objet signé, le rapproche de la demande et des clés locales et refuse un profil non correspondant. `ENR-06`, `ENR-07`, `FIL-01`, `FIL-02` |
| MEN-05 | L'amorçage gateway reçoit une preuve rattachée à une autre identité, une autorisation insuffisante ou une leaf sous une ancre non approuvée. | L'identité et l'émission restent liées aux preuves, autorisations et ancres prescrites. `ENR-08`, `IDE-04` |
| MEN-06 | Client muni d'un certificat valide mais non admis, pair admis distinct ou identité retirée après établissement du canal. Faire varier l'empreinte TLS et la clé WireGuard déclarée. | L'état de confiance local commande l'admission. Préciser à quels points elle est réévaluée avant une mutation. `IDE-01`, `IDE-02`, `IDE-04`, `ETAT-07` |
| MEN-07 | Une session chevauche une activation, une expiration ou une révocation. TLS et PQ peuvent provenir de générations différentes, et les deux bouts peuvent avoir reçu des états de confiance différents. | Seules les paires de génération prévues et les leafs autorisées valent. Préciser le sort d'une transaction en vol à chaque transition. `IDE-03`, `IDE-04`, `FRA-03`, `ETAT-07` |
| MEN-08 | Une transaction atteint une autre gateway, par changement de chemin, relais ou réutilisation de messages. Les gateways peuvent partager une CA. | Accord sur la gateway, sa clé WireGuard, le nom et la leaf prévue. Un accord TLS seul ne fixe pas le contexte applicatif. `IDE-01`, `IDE-03`, `AUT-01`, `FRA-02` |
| MEN-09 | Des messages sont transférés entre sessions, redélivrés au voisinage de l'expiration ou présentés après fermeture, redémarrage ou rotation. Varier le cache secondaire indépendamment de l'état de connexion. | Au plus une acceptation par challenge et session. Les messages des phases suivantes restent liés à la transaction d'origine. `FRA-01`, `FRA-02`, `FRA-03`, `FRA-04`, `AUT-02` |
| MEN-10 | Une entrée présente des champs inattendus, valeurs hors limites, représentations alternatives, types d'objet, versions ou domaines différents. | Une seule interprétation de l'objet authentifié, contrôles d'entrée et absence de repli vers un chemin hérité. `FIL-01`, `FIL-02`, `IDE-04`, `ETAT-09` |
| MEN-11 | Un participant disposant de sa clé de signature propose un mode, un délai ou une durée de vie différents de ceux permis. Le réseau perturbe une tentative au mode fort. | Validation de la politique indépendamment de la validité de signature. Le plancher demeure effectif sur les échecs, la réimportation et les changements de profil. `FIL-03`, `AUT-01`, `ETAT-04`, `ETAT-08`, `ETAT-09` |
| MEN-12 | Une transaction réutilise un nonce client ou rencontre un aléa indisponible, une collision modélisée ou un changement de processus du fournisseur. | Conditionner la fraîcheur à l'aléa des bonnes parties, à la consommation du challenge et à la fermeture en cas d'échec du fournisseur. `FRA-01`, `CLE-01`, `CLE-02`, `CLE-04`, `CLE-06` |
| MEN-13 | Capture du trafic QUIC et WireGuard, puis accès différé au clair classique ou à un secret de session selon la matrice de compromission. | Accord et confidentialité du PSK, portée du secret divulgué et protection revendiquée des données WireGuard capturées. `CLE-01`, `CLE-02`, `CLE-05` |
| MEN-14 | Comparaison d'engagements statiques de sessions séparées, avec ou sans identités déjà visibles, puis divulgation éventuelle du PSK. | Isoler le signal dû à l'engagement, les hypothèses de résistance à la recherche hors ligne et la portée d'une divulgation statique. `CLE-03`, `CLE-04`, `OBS-01` |
| MEN-15 | Un partenaire présente une confirmation valide sans preuve WireGuard correspondante. Faire varier le PSK statique ou négocié, la génération, un ancien handshake et la livraison tardive de son observation. | Relier le commit et le handshake réel au même candidat, au bon pair et à la bonne transaction. Préserver la distinction entre la pose et sa publication. `AUT-02`, `AUT-03`, `ETAT-02`, `ETAT-03` |
| MEN-16 | L'ordonnancement entre réserve, pose, confirmation et rollback change. Une opération backend peut agir avant que son retour soit reçu, ou échouer pendant la restauration. | Propriété unique du slot, publication après pose, persistance de la responsabilité du nettoyage et restauration conditionnelle. `ETAT-01`, `ETAT-02`, `ETAT-05`, `VIE-08` |
| MEN-17 | Révocation, réadmission, échéance, rechargement ou fin du compteur de générations arrivent autour d'une mutation concurrente. | Aucun retour d'un propriétaire obsolète ou d'un secret retiré. Conserver l'autorisation courante et le plancher spécifié. `ETAT-01`, `ETAT-07`, `VIE-03`, `VIE-06` |
| MEN-18 | Le disque ou le processus s'arrête autour de la persistance, de la signature ou de l'envoi du commit. Le réseau ne livre qu'une partie du résultat. | Ordre durable avant signature, absence de rollback après signature et maîtrise de la divergence au redémarrage. `ETAT-04`, `ETAT-05`, `ETAT-06`, `ETAT-08`, `VIE-07` |
| MEN-19 | Le réveil d'Orion, le recul de l'heure, une observation ancienne ou une remise à zéro des compteurs affectent les seuils. Inclure le remplacement en cours, le retour du réseau et l'indisponibilité prolongée. | Seuils et retrait du bon slot, indépendance de QUIC pour la vivacité et reconnexion bornée avec hypothèses de progression. `FRA-04`, `VIE-02`, `VIE-03`, `VIE-05`, `VIE-06`, `VIE-07` |
| MEN-20 | Une commande de retrait arrive par un chemin différent, avec un pair source différent, vise un ancien propriétaire ou revient pendant une préparation. Inclure perte de la réponse. | Autorisation du canal et du propriétaire courant. Les no-op sont idempotents et la déconnexion locale reste possible. `VIE-04`, `VIE-05`, `OBS-02` |
| MEN-21 | Un renouvellement arrive avec une identité de tunnel et une identité mTLS différentes, sur un slot non committé ou sur un chemin public. Examiner aussi une défaillance pendant le renouvellement légitime. | Pas d'amorçage ni de baisse de mode sur le chemin interne. Fraîcheur du secret de remplacement et maintien des protections de routage à l'échec. `VIE-01`, `VIE-02`, `VIE-09` |
| MEN-22 | L'observateur compare erreurs, fermetures, quantités de trafic ou temps pour des états privés différents. Distinguer le WAN anonyme, le pair admis et les réponses de l'API interne. | Préciser quelles observations sont équivalentes. Un code uniforme n'établit à lui seul ni une équivalence de traces ni un temps constant. `OBS-01`, `OBS-02` |
| MEN-23 | Sources non validées, nombreuses sources réelles ou pair admis multipliant ses sessions. Inclure les entrées lentes, tronquées et surdimensionnées ainsi que l'expiration ou l'abandon. | Bornes par source, identité, connexion et gateway. Distinguer capacité de traitement, mémoire, équité entre pairs et saturation hors contrat. `OBS-03`, `OBS-04`, `FRA-01`, `ETAT-05` |
| MEN-24 | Accès à un fichier de profil, au stockage local, au journal ou à un processus en cours. Faire varier le compte, les droits et l'étape du cycle de vie du secret. | Distinguer la confidentialité des objets du protocole, la protection au repos, la zéroïsation et les garanties perdues avec l'accès au processus. `ENR-07`, `CLE-05`, `OBS-05` |
| MEN-25 | Après une livraison perdue ou une interruption, Orion, Helios et l'opérateur disposent de preuves et d'observations différentes sur l'issue. Un journal peut manquer ou n'être visible que localement. | Distinguer demande signée, commit signé, réception, et retrait effectif. Établir les conclusions qu'un acteur peut tirer de chaque événement. La v5 tolère la divergence et ne revendique pas de non-répudiation externe. `AUT-02`, `ETAT-06`, `VIE-05`, `VIE-07`, `OBS-02` |
| MEN-26 | Une sauvegarde durable antérieure est restaurée ou une configuration locale est changée. Distinguer la panne qui interrompt une écriture, la restauration administrative et l'altération non autorisée du stockage. | Préciser quels états doivent résister à un redémarrage ordinaire, quelles restaurations sont couvertes, et quelles protections externes sont nécessaires pour les invitations, la confiance et le plancher. `ENR-04`, `ETAT-04`, `ETAT-07`, `ETAT-08`, `ETAT-09` |
| MEN-27 | Des paquets peuvent emprunter le WAN ou le tunnel autour d'une transition d'interface ou d'un changement d'adresse. Distinguer l'identité du pair établie et l'adresse source observée, avec IPv4 et IPv6 lorsque le chemin l'autorise. | Vérifier les hypothèses qui rendent fiables la frontière du tunnel, la classification de la connexion et la résolution VIP vers un pair. Les essais sur cible établissent les garanties de routage et de pare-feu. `IDE-02`, `VIE-01`, `VIE-04`, `VIE-09`, `OBS-05` |
| MEN-28 | Un acteur divulgue successivement plusieurs clés ou secrets, dont certains seulement après l'expiration, la révocation ou le remplacement du PSK. Distinguer l'identité toujours admise de l'identité désormais retirée. | Rattacher chaque revendication à l'état de confiance au moment de l'événement et au moment de chaque divulgation. Examiner l'isolation entre sessions et entre pairs, y compris si un secret statique a été réutilisé. `IDE-03`, `CLE-02`, `CLE-03`, `ETAT-07`, `VIE-02` |
| MEN-29 | Versions incompatibles, profils anciens et états d'admission différents coexistent pendant une migration. L'adversaire peut perturber la disponibilité du chemin v5. | Un refus de la v5 ne rend pas acceptable un objet hérité, ne requalifie pas un profil Helios et ne fait pas redescendre le plancher. `IDE-01`, `FIL-01`, `FIL-02`, `ENR-06`, `ETAT-09` |
| MEN-30 | Le premier tunnel fonctionne puis l'un des processus disparaît pendant la bascule vers un nouveau PSK. Les clés de transport WireGuard précédentes peuvent encore avoir des effets observables. | Distinguer installation du PSK, validité des clés de transport existantes et effet du prochain handshake. Vérifier les délais de retrait et de reprise selon le comportement du plan de données. `ETAT-03`, `ETAT-08`, `VIE-03`, `VIE-06`, `VIE-07`, `VIE-09` |

Examiner également les combinaisons qui traversent plusieurs frontières. Les
cas à couvrir incluent une capture suivie de divulgations successives, une
identité encore valide lors du mTLS puis révoquée avant une mutation, ainsi
qu'une panne après écriture backend pendant le remplacement d'un PSK dont
l'échéance approche. Chaque combinaison conserve l'ordre réel des événements
et indique quelles garanties doivent tenir aussi pendant l'interruption.

Cette liste couvre les angles STRIDE à l'échelle du protocole. L'usurpation
et l'élévation de privilèges portent sur l'identité et l'autorisation, la
modification sur les messages et les états, la répudiation sur la portée des
preuves, la divulgation sur les secrets et observations, et le déni de
service sur les ressources et la progression.

## Hypothèses que chaque vérification doit déclarer

- **Canaux.** Pour QUIC/mTLS, indiquer la liaison entre identité authentifiée,
  connexion et données livrées. Pour WireGuard, indiquer les garanties
  d'identité source, d'anti-rejeu, de réception via le tunnel et d'observation
  d'un handshake. Pour l'enrôlement, préciser la confirmation hors bande et
  l'autorisation indépendantes du transport des fichiers.
- **Observations du backend.** Distinguer l'installation effective, son
  acquittement, le handshake, la publication de sa valeur et sa lecture.
  Décrire le comportement de ces événements lors d'un changement de
  génération, d'une remise à zéro ou d'un effacement de slot. Traiter la
  relation de l'observation au candidat comme une obligation `ETAT-03`.
- **Durabilité.** Identifier les écritures considérées durables et les
  états susceptibles de survivre à chaque panne. Distinguer redémarrage,
  rechargement, restauration d'un instantané et action locale autorisée sur
  la politique. Vérifier les garanties d'invitation et de plancher sous le
  contrat de persistance effectivement retenu.
- **Cryptographie et aléa.** Indiquer les hypothèses de signature, KEM, KDF,
  HMAC, empreintes et canonisation, ainsi que les cas de divulgation et leur
  ordre temporel. Si les valeurs fraîches sont toujours distinctes dans le
  modèle, déclarer cette abstraction et relier la probabilité de collision
  et les défaillances au contrat du fournisseur.
- **Temps et progression.** Fixer la sémantique des horloges et compteurs,
  la fréquence d'observation, l'exécution éventuelle des nettoyages et le
  niveau de disponibilité du réseau ou du backend. La sûreté reste examinée
  en cas d'arrêt prolongé. Les bornes de récupération dépendent de ces
  hypothèses.
- **Interprétation du résultat.** Associer à chaque propriété les scénarios
  concernés, le profil d'adversaire, les clés divulguées avec leur instant, les
  observations et les hypothèses sur les autres acteurs. Pour une propriété
  d'accord ou de progression, vérifier qu'au moins une trace nominale atteint
  les événements concernés. Signaler les questions ouvertes et les preuves
  externes nécessaires pour relier le modèle à QUIC, WireGuard, au stockage
  protégé et au comportement observé sur cible.
