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

Le [modèle de menace v5](MODELE-DE-MENACE-NEGOCIATION-V5.md) définit les
acteurs, les frontières de confiance, les capacités adverses et les cas
de compromission. Ses scénarios référencent les obligations ci-dessous.
Chaque résultat de vérification doit déclarer les hypothèses qu'il utilise.

## Obligations

Les références de section renvoient au [contrat v5](NEGOCIATION-DE-CLE-V5.md).
Les identifiants servent à rattacher les résultats et les traces à une
propriété précise.

### Enrôlement, admission et confiance

| ID | Propriété à examiner | Contrat |
| --- | --- | --- |
| ENR-01 | L'ancre opérateur provient de la confirmation hors bande qui précède la demande. Un document reçu ne crée pas sa propre ancre. | §15.2–15.3 |
| ENR-02 | L'invitation signée lie la gateway, son nom, son empreinte, sa fenêtre, le plancher et le droit éventuel de réadmission. Seule une invitation issue, valide et non révoquée autorise l'émission. | §15.2–15.3 |
| ENR-03 | La CSR TLS, l'auto-signature ML-DSA et la preuve X25519/HMAC établissent la possession des trois clés de la même demande. La preuve WireGuard dépend de la clé éphémère dédiée à l'invitation, et un résultat X25519 nul est refusé. | §15.2 |
| ENR-04 | Les preuves de possession ne suffisent pas à autoriser l'admission. La consommation est atomique et durable avant émission ou modification de l'admission, et un échec ultérieur ne rouvre pas l'invitation. | §15.1–15.2 |
| ENR-05 | La réadmission d'une clé révoquée exige une invitation qui l'autorise explicitement. Toute nouvelle admission conforme exige un certificat PQ et le plancher `ml_kem`. | §14, §15.2, §19 |
| ENR-06 | L'import vérifie la signature JCS sous l'ancre épinglée et lie le profil aux identifiants, à l'empreinte de la demande locale et aux trois clés. Sans correspondance, le profil reste non connectable. Les changements de confiance suivent les transitions autorisées ou la confirmation hors bande prévue. | §15.2–15.3 |
| ENR-07 | Les fichiers échangés ne contiennent aucune clé privée. Les clés du client restent chez Orion, la clé privée CA côté opérateur et la clé privée X25519 de l'invitation est détruite selon son cycle de vie. | §15.1–15.3 |
| ENR-08 | L'amorçage gateway lie la demande publique et la preuve de possession à la bonne clé WireGuard. L'émission exige l'autorisation opérateur prévue. L'initialisation du domaine vérifie la leaf sous l'ancre et refuse une leaf auto-signée. | §3.4, §15.4 |

### Transport, identité et messages authentifiés

| ID | Propriété à examiner | Contrat |
| --- | --- | --- |
| IDE-01 | Une session QUIC v5 utilise l'ALPN v5, TLS 1.3 mutuel et une authentification courante. Ni reprise ni 0-RTT ne réintroduisent une identité ancienne. Orion vérifie le nom et l'épinglage de la gateway. | §3.3, §4.1 |
| IDE-02 | L'identité TLS admise détermine un unique pair avant le challenge. La clé WireGuard déclarée doit correspondre à ce pair. L'unicité des empreintes tient également au chargement et au rechargement. | §3.2–3.4, §5.3 |
| IDE-03 | Côté gateway, TLS et PQ appartiennent à la même génération cliente admise. Côté Orion, la leaf gateway est autorisée par le profil et la transaction se lie à la leaf exacte employée. Inclure le chevauchement et le retrait des identités côté v5. | §3.3–3.4, §7.1–7.2 |
| IDE-04 | Le certificat PQ vérifie la version, le rôle, la série, l'ancre, l'identité liée, la fenêtre de validité et la forme des clés. L'empreinte canonique fait foi. | §3.4, §4.2, §8.1, §19 |
| FIL-01 | Le décodage applique les tailles, représentations et champs autorisés, ainsi que les contrôles cryptographiques d'entrée. Les versions, modes, représentations et champs incompatibles sont rejetés avant mutation du slot. | §4.1–4.2, §5, §7, §19 |
| FIL-02 | Les octets authentifiés distinguent les objets et les versions. Les longueurs, champs optionnels et règles de canonisation empêchent deux objets de sens différent d'être vérifiés comme un même objet. | §4.1, §8, §10, §15.3 |
| FIL-03 | Orion refuse un délai de confirmation hors de `[1, 45]` secondes et une durée de PSK incompatible avec le mode, même dans une réponse correctement signée. Les champs propres au mode sont mutuellement exclusifs. | §4.5, §7.1–7.2 |
| AUT-01 | La requête engage la transaction, le challenge, le mode, le matériel de clé, les deux identités WireGuard, la gateway attendue et les certificats visés. La réponse correspond à la requête et engage notamment le ciphertext, le mode, les identités et les délais signés. | §7.1–7.2, §8.2–8.3 |
| AUT-02 | Confirmation et commit correspondent à la même transaction et au même challenge, avec le signataire et le domaine attendus. Relier ces garanties aux messages précédents et à la génération courante du slot. | §7.3–7.4, §8.4, §11.2 |
| AUT-03 | Orion installe le candidat et obtient le handshake attendu avant d'envoyer la confirmation. Il déclare la négociation terminée après vérification du commit. | §7.3–7.4, §13 |

### Fraîcheur, dérivation et confidentialité

| ID | Propriété à examiner | Contrat |
| --- | --- | --- |
| FRA-01 | Le challenge est frais, spécifique à la connexion, unique pour elle et détruit à expiration, au refus ou à la fermeture selon la phase. Une nouvelle demande ne rafraîchit ni le challenge ni l'échéance absolue. | §4.5, §6 |
| FRA-02 | Chaque challenge autorise au plus une acceptation. La consommation est atomique même sous concurrence. Une requête enregistrée reste inutilisable sur une autre connexion, sur une autre gateway ou après redémarrage, indépendamment du cache secondaire. | §6, §7.1, §8.2 |
| FRA-03 | Une réponse, une confirmation ou un commit ne peut servir dans une autre transaction. Vérifier les liaisons à chaque réception, y compris à travers une rotation ou un renouvellement. | §7.1–7.4, §8 |
| FRA-04 | Les horodatages signés restent soumis à la fenêtre et aux bornes arithmétiques de la v5. L'anti-rejeu dépend du challenge, y compris lorsque plusieurs messages sont encore dans la fenêtre temporelle. | §4.5, §6, §17.2 |
| CLE-01 | En `ml_kem`, deux transactions correspondantes obtiennent le même PSK et l'associent aux mêmes identités, au mode et au contexte. L'entrée de la KDF suit les octets et domaines prescrits. | §7–10 |
| CLE-02 | En `ml_kem`, la fraîcheur du matériel éphémère et du contexte isole les secrets de transactions distinctes. La confidentialité du PSK et la protection du premier handshake contre l'enregistrement suivi d'un déchiffrement tardif ont des hypothèses explicites. | §2.1, §4.2–4.4, §9.2–10, §16–17 |
| CLE-03 | En `static_psk`, l'engagement lie le secret au contexte. Seul le PSK configuré correspondant est installé, sans dérivation ML-KEM. Évaluer la corrélation par l'engagement lui-même en présence de métadonnées visibles, la résistance à la recherche hors ligne et les conséquences de la divulgation du PSK statique. | §7.1, §9.1, §17 |
| CLE-04 | Les challenges, nonces, identifiants et clés satisfont les exigences de génération et de traitement de l'échec d'aléa. Les garanties cryptographiques documentent les hypothèses de fraîcheur, d'entropie et de faible probabilité de collision. | §4.3, §6, §9, §15 |
| CLE-05 | Le PSK négocié ne passe ni sur le fil ni sur disque. Les secrets ne figurent pas dans les diagnostics et sont effacés aux étapes spécifiées. Distinguer la propriété du protocole sur ses sorties de la garantie effective de zéroïsation. | §9.2–10, §12.5, §15, §16 |
| CLE-06 | Le fournisseur d'aléa respecte les exigences d'instanciation, de reseed, de fork et de résistance à la prédiction. Les pannes empêchent l'émission de matériel et tout repli. Vérifier le choix et l'annonce du mécanisme séparément de sa validation éventuelle. | §4.3 |

### Pose, commit, état et persistance

| ID | Propriété à examiner | Contrat |
| --- | --- | --- |
| ETAT-01 | La réservation de la génération et de `preparing` est atomique. Une seule transaction possède le slot du pair, chaque écriture respecte la propriété courante et le débordement ne réutilise aucun jeton. | §11.1 |
| ETAT-02 | La réponse n'annonce le candidat qu'après sa pose côté gateway. Le modèle distingue pose réelle, acquittement backend et publication de l'état logique, y compris si une écriture réussit avant une annulation ou une erreur de réponse. | §11.1–11.3, §13 |
| ETAT-03 | Un commit signé implique une confirmation valide et une observation établissant un handshake du pair avec le candidat de la transaction courante. Distinguer moment du handshake, instant de pose et instant d'observation. Justifier la relation entre la preuve demandée et le contrat du backend. | §11.2, §13 |
| ETAT-04 | Le plancher requis est durable avant la signature du commit. Une panne avant ou après la synchronisation ne valide jamais un commit dont le plancher manque. Une élévation durable peut survivre à l'échec de la livraison ou de la transaction. | §11.2–11.3, §14 |
| ETAT-05 | Avant le point de non-retour, échec, timeout et annulation restaurent le slot précédent ou le vident selon l'état de départ et la génération. Une restauration échouée ou interrompue garde une responsabilité de nettoyage. Le repos post-rollback s'applique après une pose. | §4.5, §11.1–11.3 |
| ETAT-06 | Après la signature, la perte du commit, une erreur d'envoi ou la fermeture QUIC ne déclenchent pas de rollback. Le modèle admet la divergence temporaire avec Orion. Orion accepte le commit seulement pour sa transaction courante. | §7.4, §11.2, §11.4–11.5, §12.1 |
| ETAT-07 | Révocation, réadmission et rechargement ne permettent pas à une opération obsolète de restaurer un pair retiré, son ancien PSK ou un état moins protecteur. Vérifier le retrait effectif du plan de données lorsque la révocation aboutit. Le rechargement adopte les secrets runtime et le plancher selon le contrat. Inclure la révocation en fin d'espace de générations. | §11.1, §14 |
| ETAT-08 | Le redémarrage nettoie les slots négociés et invalide les transactions pendantes. Il restaure la configuration statique et conserve le plancher durable, sous réserve de l'abaissement local explicite suivi d'un redémarrage prévu par le §14. | §11.1, §12.5, §14 |
| ETAT-09 | Les deux côtés refusent la baisse réseau du mode. Orion conserve le plancher d'un profil Helios et refuse sa conversion implicite en `classic`. Aucun mode v5 ni format hérité ne permet de contourner le refus. | §10, §14, §18–19 |

### Renouvellement, retrait et vivacité

| ID | Propriété à examiner | Contrat |
| --- | --- | --- |
| VIE-01 | Le renouvellement automatique utilise le tunnel et exige l'accord entre identité VIP, pair mTLS et slot `ml_kem` committé. Les vérifications du canal et du mode empêchent l'amorçage ou le downgrade par ce chemin. Aucun renouvellement ne se replie sur le port public. | §7.6, §12.3–12.5 |
| VIE-02 | Le renouvellement rejoue la transaction complète avec un nouveau contexte et un nouveau secret. Son échec respecte l'ancien propriétaire, les échéances et les règles de reprise. | §11, §12.2–12.3 |
| VIE-03 | Orion déclenche le renouvellement au premier seuil de temps ou d'octets atteint. La gateway retire au premier plafond. Vérifier suspension, recul d'horloge, réinitialisation de compteur, événement différé pendant `preparing` et latence de la boucle d'observation. | §4.5, §11.1, §12.3 |
| VIE-04 | Le `release` utilise le tunnel et vérifie le pair issu de la source, le certificat PQ et la signature. Il n'efface que le slot `ml_kem` committé du propriétaire nommé, plan de données d'abord. Un retrait périmé, répété ou concernant un slot statique ou en préparation est inoffensif. | §7.5, §8.4, §11.1 |
| VIE-05 | La perte de la réponse au `release` ne bloque pas la déconnexion locale. Le retrait reste possible par vieillissement, remplacement, révocation ou échéance. La fermeture QUIC libère les ressources de négociation et la vivacité s'appuie sur WireGuard. | §7.5, §12.1–12.5 |
| VIE-06 | La récupération d'un pair absent dépend d'une observation valide et de la politique de keep-alive. Un instantané antérieur au commit du propriétaire courant ne retire pas prématurément son slot. | §11.1, §12.1, §12.4 |
| VIE-07 | Après perte du commit, échec ou redémarrage, le client peut rétablir l'accord sous les conditions annoncées. Les tentatives sont bornées et le dernier reçu valide reste utilisable selon le contrat jusqu'à son remplacement. Expliciter les hypothèses nécessaires à toute borne de récupération. | §11.4–11.5, §12.3–12.5 |
| VIE-08 | Une négociation annulée finit par quitter `preparing` si le backend répond et que le nettoyage progresse. Un scénario nominal doit pouvoir aller de l'admission au commit, puis au renouvellement ou au retrait, pour chaque chemin applicable. | §7, §11–13, §15 |
| VIE-09 | Un échec de négociation côté Orion conserve la protection de routage annoncée. La durée et l'effet de la coupure au renouvellement relèvent aussi d'un essai sur WireGuard Linux et WireGuard-NT. | §11.4, §12.3, §20 |

### Exposition publique, ressources et frontières de validation

| ID | Propriété à examiner | Contrat |
| --- | --- | --- |
| OBS-01 | Les codes et formes de rejet ne révèlent pas les motifs privés. Un pair admis ne choisit pas un autre pair à sonder. Définir les observations couvertes et identifier les garanties temporelles qui demandent des mesures. | §5.3, §17.1, §17.3 |
| OBS-02 | Les statuts du `release` respectent la convention prévue, notamment la réponse uniforme entre retrait réussi et commande authentifiée sans effet. Le port de négociation public ne traite pas le `release` historique. | §4.5, §7.5 |
| OBS-03 | Retry précède les opérations protégées par validation d'adresse. Les budgets par source et par identité, ainsi que le plafond global, bornent l'admission de travail dans leurs fenêtres respectives. L'échéance absolue libère le permis sans extension par progrès partiel. | §4.5, §13, §17.1 |
| OBS-04 | Les flux, trames, datagrammes et corps de retrait ont les limites prévues. Les longueurs sont contrôlées avant allocation et les flux supplémentaires échouent. Vérifier séparément la capacité requise par le pire message valide et le comportement réel de QUIC. | §4.1, §5, §7.5, §20 |
| OBS-05 | Le stockage protégé des clés et l'effacement effectif des copies sont traçables aux garanties de l'OS, du TPM et des bibliothèques. Les contrôles d'entrée FIPS prescrits, le comportement du pare-feu sur les interfaces autorisées et les garanties du plan de données exigent les preuves ou essais propres à ces dépendances. | §4.2–4.4, §7.6, §15.4, §16–17, §20 |

## Verdict attendu par propriété

Pour chaque identifiant, relever la clause normative, formuler l'énoncé
vérifiable, indiquer les acteurs, les hypothèses et les observations, puis
donner l'élément qui justifie le verdict. La vérification peut porter sur
l'accord et le secret, sur les transitions et la progression, ou sur une
propriété d'encodage ou d'implémentation. Une propriété peut demander plusieurs
éléments complémentaires. Un résultat doit préciser la portée du modèle, les
bornes explorées et, lorsque c'est pertinent, une exécution nominale qui
atteint les événements utilisés dans la propriété.

Les verdicts attendus sont **établie sous les hypothèses indiquées**,
**contredite dans le modèle**, ou **ouverte** avec le motif et ce qu'il reste à
établir. Préciser si une limite vient du temps, des bornes du modèle, d'une
garantie externe ou d'un écart de spécification. Pour le Rust, conserver une
colonne de correspondance distincte afin qu'une propriété établie sur la v5
cible ne soit pas attribuée au comportement livré sans validation.

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
