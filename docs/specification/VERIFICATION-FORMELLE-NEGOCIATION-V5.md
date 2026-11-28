# Catalogue initial de vérification de la négociation v5

Le travail porte sur le protocole Helios–Orion v5, de l'enrôlement et de
l'admission au retrait du PSK. Le [contrat v5](NEGOCIATION-DE-CLE-V5.md) et les
amendements v5 de l'[ADR-005](../adr/ADR-005-NEGOCIATION-DE-CLE.md) donnent les
règles à vérifier. Le §17 du contrat fournit la liste minimale à couvrir. Le
catalogue inclut aussi les règles normatives qui conditionnent ces garanties.
Chaque ligne est une obligation à examiner. Aucun verdict de preuve n'est
encore attaché à ce catalogue.

Les cérémonies de rotation Astra, les primitives cryptographiques et les
internes de QUIC, de TLS et de WireGuard interviennent par leurs contrats
d'interface. Le mode WireGuard générique `classic` intervient uniquement comme
frontière de version et de profil. La migration v4 intervient par le refus des
anciens formats et par l'absence de repli vers un protocole retiré.

## Modèle de menace

Les scénarios précisent les capacités adverses et les hypothèses à
retenir pour vérifier la v5. Leurs références renvoient aux
[obligations de vérification](#obligations).

### Acteurs, actifs et frontières de confiance

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

### Capacités adverses de référence

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

### Compromissions à distinguer

Pour chaque secret, relever le détenteur, la portée et le moment de la
divulgation. Tester la divulgation avant la session, pendant la transaction et
après la fin ou l'effacement pertinent. Une divulgation inclut la capacité
d'utiliser une clé via un hôte ou une interface qui continue à la protéger
contre l'export. Les garanties doivent changer explicitement lorsque les
autres clés du même acteur sont également disponibles.

Les objectifs ci-dessous sont **candidats**. Chaque énoncé concerne les
exécutions où la capacité nommée est disponible et où les hypothèses
indiquées sur les autres acteurs restent satisfaites.

| Compromission ou capacité | Garantie candidate et condition déterminante | Obligations |
| --- | --- | --- |
| Clé TLS du client uniquement, avant ou pendant la session | Une gateway honnête ne signe aucun commit attribué à ce client sans exécution Orion correspondante, liée par la confirmation PQ authentique et le handshake du candidat. L'accès à la couche mTLS peut encore consommer des ressources. | `IDE-02`, `AUT-01`, `AUT-02`, `ETAT-03`, `OBS-03` |
| Clé ML-DSA cliente uniquement | Une signature valide ne suffit ni à ouvrir une session mTLS au nom du pair admis ni à autoriser un retrait depuis une source WireGuard distincte. Les capacités TLS et WireGuard du pair restent intactes. | `IDE-01`, `IDE-02`, `IDE-03`, `VIE-04` |
| Clé WireGuard cliente uniquement | La possession WireGuard ne suffit ni à terminer une nouvelle négociation au nom du client ni à autoriser seule un retrait. Pour le trafic du slot courant, distinguer la connaissance du PSK, le mode et les clés de transport. | `IDE-02`, `AUT-02`, `ETAT-03`, `VIE-04` |
| Clés TLS et ML-DSA du même client, clé WireGuard intacte | Malgré une requête et une confirmation applicatives authentiques, le commit ne peut être signé sans le handshake du candidat. La réservation, les quotas et la récupération restent à examiner avec ces identités. | `ETAT-01`, `ETAT-03`, `ETAT-05`, `OBS-03` |
| Autres sous-ensembles de clés du client ou mélange de générations | Une clé de la mauvaise génération ne vaut jamais preuve pour la génération choisie. Chaque phase exige encore les preuves indépendantes applicables et l'état d'admission courant à son point de décision. | `IDE-03`, `AUT-02`, `ETAT-07`, `VIE-04` |
| Clé TLS de la gateway uniquement, ou clé ML-DSA gateway uniquement | Orion ne termine pas une négociation avec une gateway usurpée sur la base d'une seule couche compromise. Examiner séparément l'authenticité du transcript, l'épinglage et le rôle d'un relais vers la vraie gateway. | `IDE-01`, `IDE-03`, `AUT-01`, `AUT-02`, `AUT-03` |
| Clé TLS divulguée après une session honnête | Le PSK ML-KEM demeure confidentiel même si la transcription applicative est ensuite disponible, sous les hypothèses de confidentialité du KEM et de la KDF et sans divulgation du matériel éphémère ou du PSK. | `CLE-02`, `CLE-05` |
| Clé privée ML-KEM éphémère ou secret partagé d'une transaction | La transaction touchée peut perdre sa confidentialité. Les PSK des autres sessions honnêtes restent indépendants lorsque leur matériel éphémère et leurs secrets restent intacts. | `CLE-01`, `CLE-02`, `CLE-04`, `CLE-05` |
| PSK négocié d'une transaction | Sa divulgation ne révèle pas les PSK des autres transactions à matériel indépendant. L'effet sur les sessions WireGuard de la transaction touchée se formule séparément selon les clés WireGuard et de transport disponibles. | `CLE-02`, `VIE-02` |
| PSK statique | Les sessions qui emploient ce même secret perdent la garantie fondée sur sa confidentialité et les engagements peuvent devenir corrélables. Un PSK ML-KEM indépendant demeure secret sous ses propres hypothèses. | `CLE-02`, `CLE-03` |
| Invitation valide copiée ou clé X25519 d'invitation divulguée | L'artefact valide conserve la portée que lui donne la politique opérateur, à préciser si elle impose un destinataire. La capacité supplémentaire ne permet pas de signer une nouvelle invitation, de modifier ses contraintes ou de rouvrir une consommation durable. La preuve WireGuard d'une invitation dont la clé éphémère est divulguée exige une analyse distincte. | `ENR-02`, `ENR-03`, `ENR-04`, `ENR-05` |
| CA TLS, émetteur PQ délégué ou `CA-PQ` compromis, ou confirmation hors bande contrôlée | Les affirmations fondées sur l'ancre compromise perdent leur justification. Les admissions, épinglages et preuves sous des ancres indépendantes devraient continuer à borner l'effet sur les autres identités ou domaines. Examiner chaque autorité séparément. | `ENR-01`, `ENR-06`, `IDE-01`, `IDE-02`, `IDE-03`, `IDE-04` |
| Pair admis malveillant sans droit de modifier un autre pair | Il ne peut modifier, retirer ni renouveler le slot d'un autre pair par la négociation ou l'API interne. Inclure les changements de canal, les identités distinctes et les requêtes sous sa propre clé. | `IDE-02`, `ETAT-01`, `ETAT-07`, `VIE-01`, `VIE-04` |
| Hôte Orion, gateway ou opérateur entièrement contrôlé | L'objectif résiduel est l'isolation des autres pairs et gateways dont les clés, registres et autorisations restent indépendants. Restreindre les conclusions sur le comportement ou les secrets de l'hôte contrôlé. | `IDE-02`, `AUT-01`, `CLE-02`, `ETAT-07`, `OBS-05` |

Pour « récolter maintenant, déchiffrer plus tard », modéliser une capture faite
pendant une session honnête, puis la connaissance acquise plus tard lorsque
les mécanismes classiques de TLS et de WireGuard deviennent déchiffrables.
Vérifier quelles données restent protégées par le PSK dans chaque mode,
compte tenu de la possession du PSK, de l'effacement de la clé éphémère et
des hypothèses post-quantiques sur les primitives. Une analyse de secret
symbolique peut établir une propriété sur la connaissance modélisée. La
revendication sur le trafic WireGuard capturé demande en plus un argument
sur la composition avec le handshake et les clés de transport WireGuard.

### Scénarios à couvrir

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

### Hypothèses avec identifiants

Chaque résultat cite les hypothèses qu'il emploie et leurs paramètres.
Indiquer les acteurs concernés, la période de validité, les exceptions et,
pour un contrat externe, la preuve ou la validation attendue à la frontière.
Les hypothèses d'un résultat peuvent former un sous-ensemble de cette liste.
Une capacité de compromission retire les hypothèses correspondantes pour
l'acteur, la clé et la période concernés.

| ID | Hypothèse | Portée ou justification à fournir |
| --- | --- | --- |
| HYP-01 | Un canal QUIC/mTLS honnête lie la livraison authentifiée à sa connexion et à l'identité TLS vérifiée tant que ses conditions de sécurité tiennent. | Fixer les ancres et capacités TLS supposées intactes. La résolution TLS vers un pair admis et la liaison TLS/PQ restent `IDE-02` et `IDE-03`. |
| HYP-02 | Une signature ML-DSA honnête ne se forge pas sans la capacité de signature correspondante, dans le modèle et la fenêtre retenus. | Indiquer les clés et rôles couverts. La liaison exacte des octets au message est une obligation d'encodage. |
| HYP-03 | ML-KEM protège le secret partagé sous les conditions retenues de génération, d'encapsulation, de décapsulation et de divulgation. | Préciser le modèle cryptographique et les requêtes adverses admises. La composition avec la KDF demeure à établir. |
| HYP-04 | Les valeurs fraîches honnêtes sont symboliquement distinctes pour les portées déclarées. | Expliciter la portée entre connexions, gateways et redémarrages. Les collisions concrètes et le fournisseur relèvent de `CLE-04` et `CLE-06`. |
| HYP-05 | Une écriture durable, reconnue comme telle par le contrat de persistance, survit à un redémarrage ordinaire. | Préciser le point de durabilité et les garanties du stockage. Une restauration d'instantané ou une altération hors contrat constitue un scénario distinct. |
| HYP-06 | Une opération de nettoyage qui reste exécutable finit par être planifiée sous les conditions d'ordonnancement retenues. | Nommer les transitions concernées. L'obligation d'avoir un nettoyage exécutable et la convergence de `preparing` restent `ETAT-05` et `VIE-08`. |
| HYP-07 | Le profil adversaire exerce les capacités réseau et les droits définis pour le scénario. | Préciser l'accès aux canaux, les participants contrôlés, les observations et toute divulgation. La perte, le retard et les répétitions restent représentables. |
| HYP-08 | Sous les conditions de sécurité WireGuard retenues, le tunnel authentifie son pair et protège l'intégrité et le rejeu de ses données. | L'identification d'un pair à partir d'une VIP ou d'une interface est une propriété de la frontière déployée et requiert ses propres garanties. |
| HYP-09 | Un handshake WireGuard réussi utilise les clés et le PSK effectivement sélectionnés par WireGuard pour ce handshake. | Préciser la sémantique des rekeys et des clés de transport. Cette hypothèse ne rattache aucun handshake observé par Helios à un candidat. |
| HYP-10 | La confirmation hors bande honnête identifie l'ancre opérateur attendue indépendamment du canal de fichiers. | Le protocole doit encore l'exiger au bon moment et respecter l'autorisation de l'invitation. Voir `ENR-01` et `ENR-02`. |
| HYP-11 | Les limites de contrôle local et de lecture ou modification de l'état protégé suivent le scénario retenu. | Distinguer l'accès à une copie, l'accès au processus, les droits administratifs, l'écriture arbitraire et les pannes ordinaires. |
| HYP-12 | Les propriétés de résistance aux collisions des empreintes sont celles du modèle retenu. | Le découpage et la canonisation corrects des octets restent des obligations, notamment `FIL-02`. |
| HYP-13 | HMAC possède la propriété retenue pour l'engagement statique ou la preuve de possession, pour une clé de distribution et de confidentialité déclarées. | Préciser la propriété utilisée, par exemple PRF pour étudier la corrélation ou authenticité pour la preuve. |
| HYP-14 | HKDF possède la propriété d'extraction et de séparation retenue avec un secret d'entrée satisfaisant les conditions déclarées. | L'accord sur les entrées, le domaine et la portée par session reste `CLE-01` et `CLE-02`. |
| HYP-15 | Les horloges et compteurs satisfont les bornes d'erreur, de suspension et de réinitialisation déclarées par le modèle. | Indiquer quelle horloge est utilisée par chaque acteur. Les comparaisons et garanties de délai restent des obligations. |
| HYP-16 | Le réseau et le backend redeviennent disponibles selon les conditions de progression déclarées. | Indiquer les opérations qui aboutissent éventuellement et les bornes supposées pour un résultat temporel. Une sûreté sans disponibilité est un résultat distinct. |
| HYP-17 | Dans le scénario de déchiffrement tardif, l'adversaire obtient les captures et les capacités classiques déclarées aux instants spécifiés. | Distinguer TLS, WireGuard, clés de transport et primitives PQ. Relier séparément le secret symbolique au trafic capturé. |
| HYP-18 | Le backend expose les observations, les acquittements et les échecs selon le contrat d'interface retenu. | Déclarer la provenance, le retard et les remises à zéro possibles ainsi que l'effet d'une réponse tardive. Distinguer application, acquittement, handshake, publication et lecture. |
| HYP-19 | Les secrets tirés honnêtement, notamment le PSK statique, satisfont la distribution et l'entropie prévues dans l'argument cryptographique. | Préciser le modèle et la justification côté fournisseur. La fermeture en cas d'échec reste `CLE-04` et `CLE-06`. |
| HYP-20 | Le secret X25519 d'une preuve d'enrôlement honnête reste inconnu sous les conditions cryptographiques et de divulgation déclarées. | Préciser les clés nécessaires et les contrôles retenus. La validation des entrées et la liaison de la preuve à la demande restent `ENR-03` et `FIL-01`. |

**Frontière de ETAT-03.** `HYP-09` porte sur ce que fait WireGuard lors
d'un handshake et `HYP-18` sur les données que le backend restitue.
Établir qu'une observation précise atteste l'usage du candidat de la
transaction courante reste le résultat recherché. Si la frontière est
insuffisamment spécifiée, le verdict de `ETAT-03` reste ouvert et
nomme le contrat ou l'élément de validation manquant.

## Obligations

Les références de section renvoient au [contrat v5](NEGOCIATION-DE-CLE-V5.md).
Les identifiants servent à rattacher les résultats et les traces à une
propriété précise.

### Natures de propriété et méthodes envisagées

Chaque obligation indique une ou plusieurs natures. Lorsque plusieurs
méthodes sont nécessaires, le verdict précise la part établie par chacune.

| Nature | Méthode envisagée |
| --- | --- |
| Secret | Vérification symbolique de la connaissance adverse dans Tamarin. Un argument cryptographique distinct couvre les revendications quantitatives et la composition avec WireGuard. |
| Authentification, Accord, Accord injectif | Propriétés de trace dans Tamarin. L'authentification établit l'origine, l'accord fixe les données communes et l'accord injectif exige une session correspondante distincte par achèvement. |
| Unicité | Propriété de trace dans Tamarin ou invariant de transition en TLA+. Un événement ne se produit qu'une fois pour l'identifiant et la portée annoncés. |
| Équivalence | Tamarin ou ProVerif sur deux systèmes qui diffèrent par l'information privée. Définir les observables avant la preuve. Les canaux temporels réels demandent des mesures propres. |
| État, Vivacité, Atteignabilité | TLA+ et TLC pour les invariants, les conditions de progression et les parcours nominaux. Déclarer la portée des instances explorées et les hypothèses d'équité. |
| Persistance | Modèle d'état et de pannes en TLA+, puis validation système des garanties après interruption ou redémarrage. |
| Temps | Modèle à horloges explicites, par exemple automates temporisés avec UPPAAL. Préciser la granularité, les bornes et les sémantiques de temps. |
| Fonctions | Vérification des fonctions de validation, d'encodage et de comparaison. Choisir la preuve selon la portée des entrées. Utiliser des vecteurs pour valider la correspondance des représentations. |
| Composition | Argument reliant les garanties des primitives ou d'un backend aux événements et aux propriétés du protocole. Documenter les contrats et les preuves externes nécessaires. |
| Audit | Inspection de l'implémentation et vérifications ciblées pour l'aléa, la zéroïsation, les journaux et les appels aux dépendances par exemple. |
| Cible | Expériences sur les backends et plateformes pertinents. Pour une propriété temporelle, distinguer une mesure d'une borne établie dans le modèle. |

Références pour les méthodes proposées.
[Manuel Tamarin](https://tamarin-prover.com/manual/master/book/007_property-specification.html) ·
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) ·
[Outils TLA+](https://lamport.azurewebsites.net/tla/tools.html) ·
[Documentation UPPAAL](https://docs.uppaal.org/)

### Enrôlement, admission et confiance

| ID | Propriété à examiner | Contrat | Nature |
| --- | --- | --- | --- |
| ENR-01 | L'ancre opérateur provient de la confirmation hors bande qui précède la demande. Un document reçu ne crée pas sa propre ancre. | §15.2–15.3 | Authentification |
| ENR-02 | L'invitation signée lie la gateway, son nom, son empreinte, sa fenêtre, le plancher et le droit éventuel de réadmission. Seule une invitation issue, valide et non révoquée autorise l'émission. | §15.2–15.3 | Authentification, État |
| ENR-03 | La CSR TLS, l'auto-signature ML-DSA et la preuve X25519/HMAC établissent la possession des trois clés de la même demande. La preuve WireGuard dépend de la clé éphémère dédiée à l'invitation, et un résultat X25519 nul est refusé. | §15.2 | Accord, Fonctions |
| ENR-04 | Les preuves de possession ne suffisent pas à autoriser l'admission. La consommation est atomique et durable avant émission ou modification de l'admission, et un échec ultérieur ne rouvre pas l'invitation. | §15.1–15.2 | État, Persistance |
| ENR-05 | La réadmission d'une clé révoquée exige une invitation qui l'autorise explicitement. Toute nouvelle admission conforme exige un certificat PQ et le plancher `ml_kem`. | §14, §15.2, §19 | État, Authentification |
| ENR-06 | L'import vérifie la signature JCS sous l'ancre épinglée et lie le profil aux identifiants, à l'empreinte de la demande locale et aux trois clés. Sans correspondance, le profil reste non connectable. Les changements de confiance suivent les transitions autorisées ou la confirmation hors bande prévue. | §15.2–15.3 | Authentification, Accord, Fonctions |
| ENR-07 | Les fichiers échangés ne contiennent aucune clé privée. Les clés du client restent chez Orion, la clé privée CA côté opérateur et la clé privée X25519 de l'invitation est détruite selon son cycle de vie. | §15.1–15.3 | Secret, Audit |
| ENR-08 | L'amorçage gateway lie la demande publique et la preuve de possession à la bonne clé WireGuard. L'émission exige l'autorisation opérateur prévue. L'initialisation du domaine vérifie la leaf sous l'ancre et refuse une leaf auto-signée. | §3.4, §15.4 | Authentification, État |

### Transport, identité et messages authentifiés

| ID | Propriété à examiner | Contrat | Nature |
| --- | --- | --- | --- |
| IDE-01 | Une session QUIC v5 utilise l'ALPN v5, TLS 1.3 mutuel et une authentification courante. Ni reprise ni 0-RTT ne réintroduisent une identité ancienne. Orion vérifie le nom et l'épinglage de la gateway. | §3.3, §4.1 | Authentification, Audit |
| IDE-02 | L'identité TLS admise détermine un unique pair avant le challenge. La clé WireGuard déclarée doit correspondre à ce pair. L'unicité des empreintes tient également au chargement et au rechargement. | §3.2–3.4, §5.3 | Authentification, État |
| IDE-03 | Côté gateway, TLS et PQ appartiennent à la même génération cliente admise. Côté Orion, la leaf gateway est autorisée par le profil et la transaction se lie à la leaf exacte employée. Inclure le chevauchement et le retrait des identités côté v5. | §3.3–3.4, §7.1–7.2 | Authentification, État |
| IDE-04 | Le certificat PQ vérifie la version, le rôle, la série, l'ancre, l'identité liée, la fenêtre de validité et la forme des clés. L'empreinte canonique fait foi. | §3.4, §4.2, §8.1, §19 | Authentification, Fonctions |
| FIL-01 | Le décodage applique les tailles, représentations et champs autorisés, ainsi que les contrôles cryptographiques d'entrée. Les versions, modes, représentations et champs incompatibles sont rejetés avant mutation du slot. | §4.1–4.2, §5, §7, §19 | Fonctions, Audit |
| FIL-02 | Les octets authentifiés distinguent les objets et les versions. Les longueurs, champs optionnels et règles de canonisation empêchent deux objets de sens différent d'être vérifiés comme un même objet. | §4.1, §8, §10, §15.3 | Fonctions |
| FIL-03 | Orion refuse un délai de confirmation hors de `[1, 45]` secondes et une durée de PSK incompatible avec le mode, même dans une réponse correctement signée. Les champs propres au mode sont mutuellement exclusifs. | §4.5, §7.1–7.2 | Fonctions, État |
| AUT-01 | La requête engage la transaction, le challenge, le mode, le matériel de clé, les deux identités WireGuard, la gateway attendue et les certificats visés. La réponse correspond à la requête et engage notamment le ciphertext, le mode, les identités et les délais signés. | §7.1–7.2, §8.2–8.3 | Accord injectif, Fonctions |
| AUT-02 | Confirmation et commit correspondent à la même transaction et au même challenge, avec le signataire et le domaine attendus. Relier ces garanties aux messages précédents et à la génération courante du slot. | §7.3–7.4, §8.4, §11.2 | Authentification, Accord |
| AUT-03 | Orion installe le candidat et obtient le handshake attendu avant d'envoyer la confirmation. Il déclare la négociation terminée après vérification du commit. | §7.3–7.4, §13 | État, Cible |

### Fraîcheur, dérivation et confidentialité

| ID | Propriété à examiner | Contrat | Nature |
| --- | --- | --- | --- |
| FRA-01 | Le challenge est frais, spécifique à la connexion, unique pour elle et détruit à expiration, au refus ou à la fermeture selon la phase. Une nouvelle demande ne rafraîchit ni le challenge ni l'échéance absolue. | §4.5, §6 | État, Temps |
| FRA-02 | Chaque challenge autorise au plus une acceptation. La consommation est atomique même sous concurrence. Une requête enregistrée reste inutilisable sur une autre connexion, sur une autre gateway ou après redémarrage, indépendamment du cache secondaire. | §6, §7.1, §8.2 | Unicité, Accord injectif, État |
| FRA-03 | Une réponse, une confirmation ou un commit ne peut servir dans une autre transaction. Vérifier les liaisons à chaque réception, y compris à travers une rotation ou un renouvellement. | §7.1–7.4, §8 | Accord injectif, Authentification |
| FRA-04 | Les horodatages signés restent soumis à la fenêtre et aux bornes arithmétiques de la v5. L'anti-rejeu dépend du challenge, y compris lorsque plusieurs messages sont encore dans la fenêtre temporelle. | §4.5, §6, §17.2 | Fonctions, Temps |
| CLE-01 | En `ml_kem`, deux transactions correspondantes obtiennent le même PSK et l'associent aux mêmes identités, au mode et au contexte. L'entrée de la KDF suit les octets et domaines prescrits. | §7–10 | Accord, Fonctions |
| CLE-02 | En `ml_kem`, la fraîcheur du matériel éphémère et du contexte isole les secrets de transactions distinctes. La confidentialité du PSK et la protection du premier handshake contre l'enregistrement suivi d'un déchiffrement tardif ont des hypothèses explicites. | §2.1, §4.2–4.4, §9.2–10, §16–17 | Secret, Composition |
| CLE-03 | En `static_psk`, l'engagement lie le secret au contexte. Seul le PSK configuré correspondant est installé, sans dérivation ML-KEM. Évaluer la corrélation par l'engagement lui-même en présence de métadonnées visibles, la résistance à la recherche hors ligne et les conséquences de la divulgation du PSK statique. | §7.1, §9.1, §17 | Équivalence, Secret, Audit |
| CLE-04 | Les challenges, nonces, identifiants et clés satisfont les exigences de génération et de traitement de l'échec d'aléa. Les garanties cryptographiques documentent les hypothèses de fraîcheur, d'entropie et de faible probabilité de collision. | §4.3, §6, §9, §15 | Composition, Audit |
| CLE-05 | Le PSK négocié ne passe ni sur le fil ni sur disque. Les secrets ne figurent pas dans les diagnostics et sont effacés aux étapes spécifiées. Distinguer la propriété du protocole sur ses sorties de la garantie effective de zéroïsation. | §9.2–10, §12.5, §15, §16 | Secret, Audit |
| CLE-06 | Le fournisseur d'aléa respecte les exigences d'instanciation, de reseed, de fork et de résistance à la prédiction. Les pannes empêchent l'émission de matériel et tout repli. Vérifier le choix et l'annonce du mécanisme séparément de sa validation éventuelle. | §4.3 | Audit |

### Pose, commit, état et persistance

| ID | Propriété à examiner | Contrat | Nature |
| --- | --- | --- | --- |
| ETAT-01 | La réservation de la génération et de `preparing` est atomique. Une seule transaction possède le slot du pair, chaque écriture respecte la propriété courante et le débordement ne réutilise aucun jeton. | §11.1 | État |
| ETAT-02 | La réponse n'annonce le candidat qu'après sa pose côté gateway. Le modèle distingue pose réelle, acquittement backend et publication de l'état logique, y compris si une écriture réussit avant une annulation ou une erreur de réponse. | §11.1–11.3, §13 | État, Cible |
| ETAT-03 | Un commit signé implique une confirmation valide et une observation établissant un handshake du pair avec le candidat de la transaction courante. Distinguer moment du handshake, instant de pose et instant d'observation. Justifier la relation entre la preuve demandée et le contrat du backend. | §11.2, §13 | Composition, État, Cible |
| ETAT-04 | Le plancher requis est durable avant la signature du commit. Une panne avant ou après la synchronisation ne valide jamais un commit dont le plancher manque. Une élévation durable peut survivre à l'échec de la livraison ou de la transaction. | §11.2–11.3, §14 | Persistance, État |
| ETAT-05 | Avant le point de non-retour, échec, timeout et annulation restaurent le slot précédent ou le vident selon l'état de départ et la génération. Une restauration échouée ou interrompue garde une responsabilité de nettoyage. Le repos post-rollback s'applique après une pose. | §4.5, §11.1–11.3 | État, Vivacité, Audit |
| ETAT-06 | Après la signature, la perte du commit, une erreur d'envoi ou la fermeture QUIC ne déclenchent pas de rollback. Le modèle admet la divergence temporaire avec Orion. Orion accepte le commit seulement pour sa transaction courante. | §7.4, §11.2, §11.4–11.5, §12.1 | État, Accord |
| ETAT-07 | Révocation, réadmission et rechargement ne permettent pas à une opération obsolète de restaurer un pair retiré, son ancien PSK ou un état moins protecteur. Vérifier le retrait effectif du plan de données lorsque la révocation aboutit. Le rechargement adopte les secrets runtime et le plancher selon le contrat. Inclure la révocation en fin d'espace de générations. | §11.1, §14 | État, Persistance |
| ETAT-08 | Le redémarrage nettoie les slots négociés et invalide les transactions pendantes. Il restaure la configuration statique et conserve le plancher durable, sous réserve de l'abaissement local explicite suivi d'un redémarrage prévu par le §14. | §11.1, §12.5, §14 | Persistance, État, Cible |
| ETAT-09 | Les deux côtés refusent la baisse réseau du mode. Orion conserve le plancher d'un profil Helios et refuse sa conversion implicite en `classic`. Aucun mode v5 ni format hérité ne permet de contourner le refus. | §10, §14, §18–19 | État, Persistance |

### Renouvellement, retrait et vivacité

| ID | Propriété à examiner | Contrat | Nature |
| --- | --- | --- | --- |
| VIE-01 | Le renouvellement automatique utilise le tunnel et exige l'accord entre identité VIP, pair mTLS et slot `ml_kem` committé. Les vérifications du canal et du mode empêchent l'amorçage ou le downgrade par ce chemin. Aucun renouvellement ne se replie sur le port public. | §7.6, §12.3–12.5 | Authentification, État, Cible |
| VIE-02 | Le renouvellement rejoue la transaction complète avec un nouveau contexte et un nouveau secret. Son échec respecte l'ancien propriétaire, les échéances et les règles de reprise. | §11, §12.2–12.3 | Accord, Secret, État |
| VIE-03 | Orion déclenche le renouvellement au premier seuil de temps ou d'octets atteint. La gateway retire au premier plafond. Vérifier suspension, recul d'horloge, réinitialisation de compteur, événement différé pendant `preparing` et latence de la boucle d'observation. | §4.5, §11.1, §12.3 | Temps, État, Cible |
| VIE-04 | Le `release` utilise le tunnel et vérifie le pair issu de la source, le certificat PQ et la signature. Il n'efface que le slot `ml_kem` committé du propriétaire nommé, plan de données d'abord. Un retrait périmé, répété ou concernant un slot statique ou en préparation est inoffensif. | §7.5, §8.4, §11.1 | Authentification, État, Cible |
| VIE-05 | La perte de la réponse au `release` ne bloque pas la déconnexion locale. Le retrait reste possible par vieillissement, remplacement, révocation ou échéance. La fermeture QUIC libère les ressources de négociation et la vivacité s'appuie sur WireGuard. | §7.5, §12.1–12.5 | État, Vivacité |
| VIE-06 | La récupération d'un pair absent dépend d'une observation valide et de la politique de keep-alive. Un instantané antérieur au commit du propriétaire courant ne retire pas prématurément son slot. | §11.1, §12.1, §12.4 | État, Temps, Cible |
| VIE-07 | Après perte du commit, échec ou redémarrage, le client peut rétablir l'accord sous les conditions annoncées. Les tentatives sont bornées et le dernier reçu valide reste utilisable selon le contrat jusqu'à son remplacement. Expliciter les hypothèses nécessaires à toute borne de récupération. | §11.4–11.5, §12.3–12.5 | Vivacité, Temps |
| VIE-08 | Une négociation annulée finit par quitter `preparing` si le backend répond et que le nettoyage progresse. Un scénario nominal doit pouvoir aller de l'admission au commit, puis au renouvellement ou au retrait, pour chaque chemin applicable. | §7, §11–13, §15 | Vivacité, Atteignabilité |
| VIE-09 | Un échec de négociation côté Orion conserve la protection de routage annoncée. La durée et l'effet de la coupure au renouvellement relèvent aussi d'un essai sur WireGuard Linux et WireGuard-NT. | §11.4, §12.3, §20 | État, Cible |

### Exposition publique, ressources et frontières de validation

| ID | Propriété à examiner | Contrat | Nature |
| --- | --- | --- | --- |
| OBS-01 | Les codes et formes de rejet ne révèlent pas les motifs privés. Un pair admis ne choisit pas un autre pair à sonder. Définir les observations couvertes et identifier les garanties temporelles qui demandent des mesures. | §5.3, §17.1, §17.3 | Équivalence, Audit, Cible |
| OBS-02 | Les statuts du `release` respectent la convention prévue, notamment la réponse uniforme entre retrait réussi et commande authentifiée sans effet. Le port de négociation public ne traite pas le `release` historique. | §4.5, §7.5 | Équivalence, État |
| OBS-03 | Retry précède les opérations protégées par validation d'adresse. Les budgets par source et par identité, ainsi que le plafond global, bornent l'admission de travail dans leurs fenêtres respectives. L'échéance absolue libère le permis sans extension par progrès partiel. | §4.5, §13, §17.1 | État, Temps, Cible |
| OBS-04 | Les flux, trames, datagrammes et corps de retrait ont les limites prévues. Les longueurs sont contrôlées avant allocation et les flux supplémentaires échouent. Vérifier séparément la capacité requise par le pire message valide et le comportement réel de QUIC. | §4.1, §5, §7.5, §20 | Fonctions, Audit, Cible |
| OBS-05 | Le stockage protégé des clés et l'effacement effectif des copies sont traçables aux garanties de l'OS, du TPM et des bibliothèques. Les contrôles d'entrée FIPS prescrits, le comportement du pare-feu sur les interfaces autorisées et les garanties du plan de données exigent les preuves ou essais propres à ces dépendances. | §4.2–4.4, §7.6, §15.4, §16–17, §20 | Audit, Cible |

## Traçabilité et verdict attendu

Pour chaque propriété, utiliser la fiche suivante. Un contre-exemple ou
un résultat doit être rattaché à l'identifiant formel de la propriété, à
la version du modèle et à la clause normative applicable. La correspondance
Rust indique séparément l'état de validation de l'implémentation.

| Champ | Contenu attendu |
| --- | --- |
| Spécification normative | Document, section et clause précise. Signaler les écarts de contrat avant d'interpréter un résultat. |
| Scénarios de menace | Identifiants `MEN-XX` et capacités adverses retenues, avec divulgations et instants le cas échéant. |
| Obligation | Identifiant du catalogue, objectif attendu et nature de la propriété. |
| Hypothèses applicables | Identifiants `HYP-XX`, paramètres et exceptions. Identifier les hypothèses qui conditionnent encore le résultat. |
| Propriété formelle | Identifiant stable, événements, portée, quantificateurs et énoncé. Ajouter une trace nominale atteignable lorsque l'énoncé le requiert. |
| Résultat | **Établie sous les hypothèses indiquées**, **contredite dans le modèle**, ou **ouverte** avec motif. Consigner le modèle et sa version, la commande, les bornes, et la preuve ou la trace correspondante. |
| Correspondance Rust | Fonctions, transitions, points d'observation et tests associés. Indiquer la révision examinée, les écarts et les validations qui restent à faire. |

### Exemple FRA-02 — Unicité d'acceptation et liaison à la connexion

| Champ | Exemple de fiche |
| --- | --- |
| Spécification normative | [Contrat v5](NEGOCIATION-DE-CLE-V5.md), §6.1 règles 3 à 7, §7.1 et §8.2. |
| Scénarios de menace | `MEN-09` pour le rejeu entre connexions ou après redémarrage, `MEN-08` pour le rejeu vers une autre gateway. |
| Obligation | `FRA-02` exige qu'un challenge ne permette qu'une acceptation et que l'acceptation reste dans la connexion et la gateway visées. |
| Hypothèses applicables | `HYP-04` pour distinguer les émissions honnêtes entre connexions et redémarrages, `HYP-07` pour l'adversaire actif. `HYP-01` et `HYP-02` concernent la liaison authentifiée au canal et au transcript, à distinguer de la consommation locale à usage unique. |
| Propriété formelle | `FRA_02_unique_acceptance` exige que deux événements d'acceptation portant le même couple gateway–challenge coïncident en instant, connexion et transaction. `FRA_02_connection_binding` exige que chaque acceptation ait une émission antérieure du challenge sur cette connexion et cette gateway. Vérifier qu'une demande valide peut être acceptée. |
| Résultat | **Ouverte.** Les noms et énoncés sont proposés. Aucun modèle exécuté ni verdict de preuve n'est associé à cette fiche. |
| Correspondance Rust | Dans [le serveur de négociation](../../crates/aether-key-negotiation/src/server.rs), `handle_connection` porte l'état du challenge et `consume_challenge` le retire avant les vérifications suivantes. Distinguer cette consommation et l'acceptation applicative via `handler.prepare` lors du raccordement aux événements du modèle. [Le test de transport](../../crates/aether-key-negotiation/src/tests/transport.rs) contient `a_challenge_cannot_be_replayed_on_another_connection`. |

Pour cette fiche, `Issue(g,s,c)` désigne l'émission par la gateway `g`
sur la connexion `s` du challenge `c`. `Accept(g,s,c,r)` désigne
l'acceptation de la requête authentifiée dont l'identifiant de transaction
est `r`. Le modèle enregistre chaque acceptation à son propre instant,
après la décision d'admission applicative. La réception d'une trame et
la consommation du challenge sont des événements distincts.

```text
FRA_02_unique_acceptance
∀ g,s,s',c,r,r',i,j.
  Accept(g,s,c,r)@i ∧ Accept(g,s',c,r')@j ⇒ i = j ∧ s = s' ∧ r = r'

FRA_02_connection_binding
∀ g,s,c,r,i. Accept(g,s,c,r)@i ⇒ ∃ j. Issue(g,s,c)@j ∧ j < i
```

L'unicité ne suffit pas à établir l'accord sur la gateway que visait
le signataire. La liaison de la requête authentifiée à cette identité
se vérifie avec `AUT-01`. L'expiration exige aussi les conditions de
temps d'`HYP-15` dans un résultat qui la couvre.

## Questions à trancher avant de fixer les modèles

- Quel contrat exact d'observation WireGuard relie le handshake au candidat
  installé, y compris si une mise à jour de l'observation arrive après la pose ?
- Quels cas de compromission doivent conserver quelles garanties, mode par mode ?
  Quel argument justifiera la protection du trafic capturé quand les mécanismes
  classiques deviennent déchiffrables ?
- Comment interpréter les bornes de retrait et de reconnexion avec observation
  périodique, opérations en cours et échecs backend ? Les délais de tentative
  décrits aux §11.4 et §12.5 doivent être rapprochés avant d'en faire un invariant.
- Quelles observations exactes définissent la confidentialité des rejets et
  l'absence de corrélation par l'engagement statique ? Le choix peut changer
  la propriété à vérifier.
