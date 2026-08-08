# Spécification — cycle de vie et rotation des certificats v5

**Statut** : cible spécifiée — **cycle de vie non implémenté**. Le protocole de
négociation servi est déjà la v5 ; cette note décrit le lot certificat restant.

**Version du format** : `1`

**Date de la note** : 2026-08-08

Cette note complète la
[spécification de négociation de clé v5](NEGOCIATION-DE-CLE-V5.md) et
[ADR-005](adr/ADR-005-NEGOCIATION-DE-CLE.md). La v5 filaire, ML-DSA-87 et le
certificat `PqCertificate` v2 sont déjà servis. Le code reste toutefois figé
autour d'une seule identité gateway auto-signée et d'une seule génération
cliente. Cette note définit les formats et transitions qui ferment ce manque.
L'ordonnancement automatique, les alertes et les campagnes de parc pourront
être livrés ensuite sans changer les objets signés ni le modèle de confiance.

Les exigences de cette note s'appliquent seulement à la branche cible
`helios_key_negotiation` des profils Orion. Le discriminant explicite de cette
branche n'est pas encore implémenté : aujourd'hui, un profil porte encore un
bloc `key_negotiation` facultatif. La migration de format décrite par la
spécification v5 doit donc être livrée avant, ou atomiquement avec, le présent
lot. L'absence d'un bloc ne doit jamais permettre de reclasser comme `classic`
un profil déjà connu comme Helios. Un vrai profil `classic` reste un profil
WireGuard générique, sans certificat de négociation, sans `CA-PQ` et sans mise
à jour de confiance Helios.

## 0. État de départ et décisions

### 0.1 État effectivement servi au 8 août 2026

Le point de départ de l'implémentation est précisément le suivant :

- l'ALPN `helios-key-negotiation/5`, les messages de négociation v5 et
  `PqCertificate.version = 2` sont en service ;
- la leaf PQ gateway est encore **auto-signée** et directement épinglée dans
  chaque profil Orion ; Orion n'épingle pas encore la clé publique `CA-PQ` ni
  de `trust_domain_id` ;
- la leaf TLS gateway est auto-signée et son DER unique est épinglé dans le
  profil ;
- les leafs TLS et PQ clientes sont émises par les CA opérateur, mais
  l'admission ne conserve qu'un couple d'empreintes sans génération
  active/suivante ;
- le profil Orion conserve un seul certificat TLS gateway, un seul certificat
  PQ gateway et un seul nom d'identité cliente ; le format `.orion` courant
  peut encore transporter les clés privées de cette identité ;
- `heliosd` charge une identité unique au démarrage. La commande
  `init-key-negotiation --rotate` remplace les fichiers ; elle ne prépare ni
  transition, ni slot suivant, et tous les profils qui épinglent l'ancienne
  identité cessent alors de se connecter après le redémarrage ;
- aucun compteur de certificat, objet de transition, route interne de mise à
  jour de confiance, import `orion-trust-update` ou registre de révocation
  décrit ici n'existe encore.

Cette note ne doit donc pas être lue comme une capacité cachée de la v5
actuelle. En particulier, `init-key-negotiation --rotate` n'est pas le chemin
de rotation de parc défini ci-dessous.

### 0.2 Décisions normatives

| Sujet | Décision normative |
| --- | --- |
| identité stable de la gateway | clé publique WireGuard et `server_name`, tous deux inchangés pendant une rotation |
| certificat PQ gateway | émis par `CA-PQ` dans l'état cible ; l'auto-signature actuelle n'est admise que jusqu'à la bascule de §13 |
| certificat TLS gateway | épinglage actif/suivant ; une transition peut remplacer TLS, PQ ou les deux atomiquement |
| état d'un profil | certificat actif et certificat suivant, jamais davantage |
| état d'un client admis | génération active et suivante, chacune associant exactement une empreinte TLS et une empreinte PQ |
| fenêtre | `not_before < activation_at < not_after`, chevauchement limité à 30 jours |
| anti-rollback | génération `u64` strictement séquentielle et persistée avant activation |
| autorité d'une transition leaf | signature ML-DSA-87 par la `CA-PQ` déjà épinglée |
| garde des CA | clés privées `CA-PQ` et `CA-TLS` confinées dans l'autorité opérateur, jamais sur une gateway ni dans Orion |
| rotation de `CA-PQ` | transition signée par l'ancienne **et** la nouvelle CA, générations consécutives |
| rotation de `CA-TLS` cliente | deux ancres au plus, transition autorisée par `CA-PQ` avant toute nouvelle leaf mTLS |
| compromission | révocation sans grâce ; si `CA-PQ` est compromise, réinitialisation hors bande |
| automatisation | reportable après le socle ; formats, parseurs, états doubles et import manuel appartiennent au lot certificat v5 |

Le choix de faire émettre le certificat PQ gateway par `CA-PQ` est retenu à la
place d'une simple cosignature par l'ancienne leaf. Une leaf compromise ne peut
ainsi autoriser seule sa remplaçante. Les clés privées `CA-PQ` et `CA-TLS`
restent exclusivement dans une **autorité de signature opérateur isolée** ;
elles n'entrent ni sur une gateway, ni dans Orion. Cette note fixe cette
frontière de confiance, pas la topologie de l'autorité : poste hors ligne, HSM
ou service dédié relèvent d'une décision d'architecture séparée. Un simple
canal chiffré ne modifie ni cette frontière ni les exigences d'autorisation,
d'audit et d'anti-rejeu.

## 1. Périmètre

Cinq cycles de vie sont distincts :

1. l'identité gateway, composée d'une leaf TLS et d'une leaf PQ ;
2. l'identité cliente, composée d'une leaf TLS et d'une leaf PQ ;
3. l'ancre opérateur `CA-PQ` ;
4. la CA TLS qui émet les leafs mTLS clientes ;
5. la révocation urgente d'une leaf ou d'une admission.

La rotation de la clé WireGuard gateway n'est **pas** une rotation de
certificat. Elle change l'identité du pair, la dérivation du PSK et la cible
signée des requêtes ; elle exige un nouveau profil et une confirmation hors
bande. Il en va de même d'un changement de `server_name`.

Cette note ne transforme pas `CA-PQ` en service en ligne et n'introduit ni CRL
publique ni OCSP. Elle définit des objets de transition et de révocation
signés, distribuables par un canal non fiable. Leur fraîcheur reste bornée par
les dates, les générations et la capacité du client à recevoir l'objet.

## 2. Ancres et identifiants

### 2.1 Identité gateway stable

Toute transition gateway couvre obligatoirement :

- `gateway_wg_public_key`, sous sa forme binaire canonique de 32 octets ;
- `server_name`, sous la forme DNS canonique de la v5 ;
- `trust_domain_id`, identifiant aléatoire de 16 octets créé avec la première
  `CA-PQ` ;
- l'empreinte de l'identité active et celle de l'identité suivante ;
- une génération monotone ;
- la période de transition.

Un objet dont l'un des trois premiers champs diffère du profil est refusé avant
toute écriture. L'IHM ne propose jamais d'assimiler cette différence à une
rotation ordinaire.

### 2.2 Ancre déjà fiable

À l'enrôlement initial, Orion confirme hors bande l'empreinte de `CA-PQ`, puis
conserve sa clé publique et `trust_domain_id` dans le stockage protégé du
profil. Une transition leaf est valide seulement si elle est signée par cette
CA active ou, pendant une rotation de CA déjà acceptée, par l'une des deux CA
explicitement autorisées pour la période considérée.

Un objet de mise à jour ne peut jamais apporter à la fois une CA inconnue et la
signature qui la rendrait fiable. La seule exception est `CaTransition`, dont
la nouvelle CA est autorisée par la signature de l'ancienne ancre déjà fiable
et prouve sa propre possession par une seconde signature.

### 2.3 Empreintes

- empreinte PQ : SHA-256 de la représentation canonique du certificat définie
  par la v5 ;
- empreinte TLS : SHA-256 du DER complet de la leaf ;
- empreinte CA-PQ : SHA-256 de la clé publique ML-DSA-87 canonique, préfixée par
  le domaine `helios-key-negotiation-ca-fingerprint-v5`.

Toutes les empreintes occupent 32 octets dans les données signées et sont
rendues en hexadécimal minuscule dans JSON.

## 3. Certificats et état borné

### 3.1 Certificat PQ gateway

Dans l'état cible, le `PqCertificate` v2 de rôle `gateway` est signé par
`CA-PQ`. Son champ `issuer` désigne cette CA. La vérification contrôle la
signature de CA, le rôle, la clé WireGuard stable, `server_name`, la période de
validité et la forme ML-DSA-87. Après la bascule de §13, la vérification
auto-signée d'une leaf gateway est absente du chemin
`helios_key_negotiation`. Le lecteur de migration peut encore reconnaître
l'ancien pin pour préparer la bascule, mais il ne l'installe jamais dans un
slot actif ou suivant du nouveau format.

La gateway génère chaque nouvelle clé privée ML-DSA-87 sur la gateway, la
scelle au TPM et exporte une demande publique signée par la nouvelle clé.
L'autorité opérateur vérifie cette preuve de possession avant d'émettre la
leaf. La clé privée ne quitte jamais la gateway.

### 3.2 État gateway dans Orion

Le bloc public du profil contient au minimum :

```text
GatewayCertificateState {
    trust_domain_id: [u8; 16],
    ca_epoch: u64,
    current_ca_public_key: MlDsa87PublicKey,
    next_ca_public_key: Option<MlDsa87PublicKey>,

    gateway_identity_epoch: u64,
    active_gateway_tls_certificate: DerCertificate,
    next_gateway_tls_certificate: Option<DerCertificate>,
    active_gateway_certificate: PqCertificate,
    next_gateway_certificate: Option<PqCertificate>,

    active_gateway_tls_certificate_fingerprint: [u8; 32],
    next_gateway_tls_certificate_fingerprint: Option<[u8; 32]>,
    active_gateway_certificate_fingerprint: [u8; 32],
    next_gateway_certificate_fingerprint: Option<[u8; 32]>,

    activation_at: Option<u64>,
    retire_active_at: Option<u64>
}
```

Les noms sans qualificatif TLS désignent la leaf PQ applicative, pour rester
compatibles avec le vocabulaire de la négociation v5. Les certificats complets
sont conservés : une empreinte seule ne permettrait pas de vérifier la chaîne,
le rôle, la clé WireGuard ou la validité.

Les champs `next_*` sont soit tous absents pour une famille inchangée, soit
tous cohérents avec le même objet de transition. Il n'existe jamais une liste
ouverte d'empreintes. Pendant une transition, Orion accepte au plus deux leafs
TLS gateway et deux leafs PQ gateway.

### 3.3 État client dans l'admission

TLS et PQ forment une **génération indivisible** :

```text
ClientCertificateGeneration {
    generation: u64,
    ca_tls_epoch: u64,
    tls_ca_certificate_fingerprint: [u8; 32],
    tls_certificate_fingerprint: [u8; 32],
    pq_certificate_fingerprint: [u8; 32],
    not_before: u64,
    not_after: u64
}

ClientCertificateState {
    active: ClientCertificateGeneration,
    next: Option<ClientCertificateGeneration>,
    activation_at: Option<u64>,
    retire_active_at: Option<u64>
}
```

La gateway ne traite pas les empreintes TLS et PQ comme deux ensembles
indépendants. Une connexion mTLS reconnue sous la génération `N+1` doit
présenter et utiliser le certificat PQ de cette même génération. Les couples
TLS `N` / PQ `N+1` et TLS `N+1` / PQ `N` sont refusés. Cette liaison empêche une
attaque de mélange entre deux transitions pourtant valides séparément.

Une empreinte TLS ou PQ reste unique dans toute la table des pairs, génération
active et suivante comprises. Le chargement initial, le hot-reload et
l'admission refusent les doublons.

## 4. Temps, générations et persistance

### 4.1 Fenêtre de transition

Tout objet de transition ordinaire contient :

```text
not_before < activation_at < not_after
```

- avant `not_before`, l'objet est futur et n'est pas installé ;
- de `not_before` à `activation_at`, la nouvelle identité est préparée mais ne
  doit pas être servie ;
- de `activation_at` à `not_after`, la nouvelle identité peut être servie et
  l'ancienne reste acceptée pour rollback opérationnel ;
- à `not_after`, l'ancienne identité est retirée définitivement et la suivante
  devient l'active unique.

Le chevauchement `not_after - activation_at` est strictement positif et ne
dépasse jamais `2_592_000` secondes, soit 30 jours. Le nouveau certificat doit
être valide au plus tard à `activation_at` et rester valide au-delà de
`not_after`. L'ancien doit être valide au moins jusqu'à `activation_at` ; une
transition ne prolonge jamais sa validité cryptographique propre.

Le client prend une seule valeur d'horloge au début de la validation et
l'utilise pour toutes les comparaisons. Les additions et soustractions sont
vérifiées. Une horloge invalide fait échouer fermement l'installation de la
transition ; elle ne produit aucune extension implicite.

### 4.2 Générations

Les espaces de génération et de révocation sont indépendants :

| Portée | Compteur |
| --- | --- |
| identité gateway TLS/PQ | `gateway_identity_epoch` par clé WireGuard gateway |
| identité cliente TLS/PQ | `client_identity_generation` par clé WireGuard cliente |
| ancre opérateur | `ca_epoch` par `trust_domain_id` |
| CA TLS cliente | `ca_tls_epoch` par `trust_domain_id` |
| révocation | `revocation_epoch` par identité WireGuard, indépendant des générations de certificat |

Une transition ordinaire doit porter exactement `current + 1`. Une valeur
égale est un rejeu idempotent seulement si tous les octets signés sont
identiques ; sinon c'est un conflit. Une valeur inférieure est un rollback. Une
valeur supérieure à `current + 1` est un saut refusé : les transitions
intermédiaires doivent être validées dans l'ordre.

L'état et le compteur sont écrits atomiquement puis synchronisés avant qu'une
nouvelle leaf soit acceptée ou servie. Une erreur d'écriture laisse l'état
précédent intact. Après promotion, un recul de l'horloge ne réactive jamais
l'ancienne empreinte : le compteur persistant et l'absence du slot retiré
dominent le temps mural.

## 5. Demande de certificat gateway

`GatewayCertificateRequest` permet à l'autorité opérateur d'émettre une leaf
sans recevoir de clé privée :

| Champ | Contrainte |
| --- | --- |
| `format_version` | `1` |
| `trust_domain_id` | domaine de la CA visée |
| `gateway_identity_epoch` | génération demandée, active + 1 |
| `gateway_wg_public_key` | identité stable |
| `server_name` | identité stable |
| `new_ml_dsa_87_public_key` | clé générée et scellée sur la gateway |
| `request_id` | 16 octets aléatoires non nuls |
| `created_at`, `expires_at` | durée positive de 24 heures au plus |
| `new_key_proof` | signature ML-DSA-87 par la nouvelle clé |
| `current_key_authorization` | signature de la leaf active pour un renouvellement normal |

Les deux signatures couvrent les mêmes octets :

```text
"helios-gateway-certificate-request-v5"
|| format_version:u16
|| trust_domain_id:16
|| gateway_identity_epoch:u64
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| len(new_ml_dsa_87_public_key):u32 || new_ml_dsa_87_public_key
|| request_id:16
|| created_at:u64 || expires_at:u64
```

`new_key_proof` prouve la possession de la nouvelle clé. La signature courante
prouve la continuité en renouvellement normal, mais ne remplace pas
l'autorisation opérateur : seule `CA-PQ` émet le certificat. En récupération
après perte de l'ancienne clé, l'opérateur peut accepter une demande sans
`current_key_authorization` après procédure locale explicite ; l'objet de
transition final reste signé par `CA-PQ` et porte le motif `key_recovery`.

## 6. Transition de l'identité gateway

### 6.1 Objet

`GatewayIdentityTransition` transporte une nouvelle leaf PQ, une nouvelle leaf
TLS, ou les deux :

| Champ | Contrainte |
| --- | --- |
| `format_version` | `1` |
| `protocol_version` | `5` |
| `trust_domain_id` | identique au profil |
| `gateway_identity_epoch` | active + 1 |
| `gateway_wg_public_key` | identique au profil et aux leafs |
| `server_name` | identique au profil et aux leafs |
| `active_gateway_tls_certificate_fingerprint` | empreinte TLS active attendue |
| `next_gateway_tls_certificate` | DER complet, facultatif si TLS ne change pas |
| `active_gateway_certificate_fingerprint` | empreinte PQ active attendue |
| `next_gateway_certificate` | certificat PQ complet, facultatif si PQ ne change pas |
| `not_before`, `activation_at`, `not_after` | fenêtre de §4.1 |
| `reason` | `scheduled`, `key_recovery` ou `emergency_replacement` |
| `ca_epoch` | CA qui autorise la transition |
| `ca_signature` | signature ML-DSA-87 par la CA déjà fiable |

Au moins une des deux leafs suivantes est présente. Chaque leaf est vérifiée
avant la signature de transition : rôle, nom, clé WireGuard, validité, usages
TLS, forme canonique et signature d'émetteur. La leaf PQ suivante doit être
émise par la `CA-PQ` désignée. La leaf TLS peut rester auto-signée et épinglée ;
sa transition est alors autorisée par `CA-PQ`, car le pin TLS seul ne peut pas
s'autoriser lui-même.

### 6.2 Octets signés

```text
"helios-gateway-identity-transition-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16 || ca_epoch:u64
|| gateway_identity_epoch:u64
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| active_gateway_tls_certificate_fingerprint:32
|| optional(SHA-256(next_gateway_tls_certificate_der))
|| active_gateway_certificate_fingerprint:32
|| optional(next_gateway_certificate_fingerprint)
|| not_before:u64 || activation_at:u64 || not_after:u64
|| reason:u8
```

Le document transporte les certificats complets, mais signe leurs empreintes
canoniques. Une substitution de certificat modifie donc la signature. Le
parseur recalcule chaque empreinte et la compare en temps constant avant toute
vérification de chaîne.

### 6.3 Machine d'état

```text
active
  -> staged
  -> overlap
  -> promoted

staged | overlap -> revoked
```

1. `active` : une seule identité est admise.
2. `staged` : la transition est vérifiée et persistée ; l'ancienne seule est
   servie avant `activation_at`.
3. `overlap` : Orion accepte les deux identités ; la gateway sert normalement
   la nouvelle, mais peut redémarrer temporairement sur l'ancienne.
4. `promoted` : à `not_after`, la suivante devient active et l'ancienne est
   supprimée, même si le client ne l'a jamais observée.
5. `revoked` : la règle d'urgence de §10 retire immédiatement l'empreinte
   nommée et domine les dates.

Orion marque `next_observed` seulement après un commit v5 signé par la nouvelle
leaf PQ et un handshake WireGuard réussi vers la clé gateway stable. Ce constat
n'autorise pas à supprimer l'ancienne avant `not_after` : d'autres clients ou
un rollback de la gateway peuvent encore en dépendre.

La gateway prépare et synchronise la clé privée suivante, le certificat et
l'objet de transition avant de les annoncer. Elle continue de servir
l'ancienne identité jusqu'à `activation_at`. Le passage à la clé suivante
nécessite toujours un redémarrage de `heliosd`, puisque l'identité est chargée
une fois ; l'automatisation v5.x pourra planifier ce redémarrage, pas en changer
l'ordre de sûreté.

## 7. Rotation de l'identité cliente

### 7.1 Demande

Les nouvelles clés TLS et ML-DSA-87 naissent dans le stockage protégé d'Orion.
`ClientCertificateRotationRequest` contient :

- `format_version = 1`, `protocol_version = 5` ;
- `request_id` aléatoire de 16 octets ;
- `trust_domain_id`, `gateway_wg_public_key`, `server_name` ;
- `client_wg_public_key`, qui ne change pas ;
- la génération active et la génération demandée, exactement active + 1 ;
- les empreintes TLS/PQ actives ;
- une CSR TLS signée par la nouvelle clé TLS ;
- la nouvelle clé publique ML-DSA-87 ;
- `created_at`, `expires_at`, avec 24 heures au plus ;
- une signature par la clé PQ active ;
- une signature de possession par la nouvelle clé PQ.

Les deux signatures PQ couvrent :

```text
"helios-client-certificate-rotation-request-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16
|| request_id:16
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| client_wg_public_key:32
|| active_generation:u64 || requested_generation:u64
|| active_tls_certificate_fingerprint:32
|| active_pq_certificate_fingerprint:32
|| SHA-256(tls_csr_der):32
|| len(new_ml_dsa_87_public_key):u32 || new_ml_dsa_87_public_key
|| created_at:u64 || expires_at:u64
```

La signature active autorise la continuité ; la CSR et la nouvelle signature
prouvent les deux nouvelles clés. Aucun nom de profil ne participe à la
correspondance.

### 7.2 Émission et grant

L'autorité opérateur vérifie la demande, émet les deux certificats et construit
un `ClientCertificateRotationGrant` signé par `CA-PQ`. Le grant lie :

- les identités gateway et cliente ;
- les générations active et suivante ;
- les quatre empreintes TLS/PQ ;
- la génération et l'empreinte de la `CA-TLS` qui émet la nouvelle leaf ;
- les certificats complets suivants ;
- `not_before`, `activation_at`, `not_after` ;
- le hash de la demande ;
- `ca_epoch` et `trust_domain_id`.

L'empreinte de demande est le SHA-256 des octets signés de §7.1, suivis de la
signature active et de la signature suivante, chacune préfixée par sa longueur
`u32`. La signature du grant couvre :

```text
"helios-client-certificate-rotation-grant-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16 || ca_epoch:u64 || ca_tls_epoch:u64
|| request_fingerprint:32
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| client_wg_public_key:32
|| active_generation:u64 || next_generation:u64
|| active_tls_certificate_fingerprint:32
|| active_pq_certificate_fingerprint:32
|| next_tls_ca_certificate_fingerprint:32
|| SHA-256(next_tls_certificate_der):32
|| next_pq_certificate_fingerprint:32
|| not_before:u64 || activation_at:u64 || not_after:u64
```

Le grant transporte les deux certificats complets. Orion recalcule leurs
empreintes, vérifie la chaîne TLS, la signature `CA-PQ`, les usages, les clés
publiques de la demande, la génération `CA-TLS` exacte et les périodes avant de
vérifier `ca_signature` sur les octets ci-dessus.

L'opérateur installe et synchronise la génération suivante dans l'admission
gateway **avant** de signer et de remettre le grant à Orion. L'ordre inverse
pourrait faire basculer le client vers une identité que la gateway refuse.

Orion vérifie le grant sous une CA déjà fiable, retrouve les deux clés privées
locales correspondantes puis persiste la génération suivante. À partir de
`activation_at`, il utilise la nouvelle génération. La première connexion v5
réussie sous ce couple prouve son observation à la gateway. L'ancienne reste
admise jusqu'à `not_after`, puis la gateway et Orion la retirent.

Un changement de clé WireGuard cliente suit le protocole de réadmission, pas ce
grant.

### 7.3 Compromission cliente

Une identité cliente soupçonnée compromise ne bénéficie pas du chevauchement
normal. L'opérateur exécute la révocation d'admission existante `peer remove`,
qui domine tout état `next`, puis réadmet le poste avec une invitation portant
explicitement `allow_readmission`. Une demande signée seulement par une clé
soupçonnée compromise n'autorise jamais une rotation d'urgence.

## 8. Distribution des mises à jour

### 8.1 Mise à jour de confiance dans le tunnel

Le port QUIC public de la v5 est réservé à l'établissement pré-WireGuard d'un
PSK. Une fois le tunnel monté, Orion récupère les transitions ordinaires par :

```text
POST http://<adresse-WireGuard-gateway>:8080/api/key-negotiation/trust-update
Content-Type: application/json
```

L'adresse vient de `heliosd_url` dans le profil et doit être routée dans le
tunnel. Orion n'essaie jamais cette route sur l'adresse publique de la gateway
et ne retombe pas sur QUIC. La requête est limitée à 32 Kio avant
désérialisation ; la réponse JSON est limitée à 64 Kio.

La route n'est **pas** reconnue par le code v5 actuel. Elle n'est appelée
qu'après mise à niveau des deux bouts. Une gateway ancienne répond `404` ;
Orion conserve alors sa confiance actuelle et propose le document hors ligne
de §8.2. Il n'accepte jamais pour autant un certificat expiré, une génération
ancienne ou un repli vers un pin unique. Les messages de négociation PSK et
leurs transcriptions signées ne changent pas.

Avant toute vérification ML-DSA, l'API résout l'adresse source réelle vers son
unique pair admis, selon la même règle que les autres routes authentifiées de
`helios-api`. Aucun en-tête de proxy n'est accepté. La clé WireGuard cliente du
corps est ensuite comparée à ce pair ; elle ne sert jamais d'index dans la
table. Cette résolution prouve que l'appel traverse un tunnel établi par la
clé WireGuard admise.

`AuthenticatedTrustUpdateRequest` contient la requête, le certificat PQ client
de la génération courante et une signature ML-DSA-87. La requête contient un
`request_id` aléatoire de 16 octets non nuls, les identités WireGuard, les
générations connues et les empreintes actives. Elle ne contient ni challenge
public, ni horodatage : l'anti-rejeu du transport WireGuard protège le paquet,
et les générations ainsi que les empreintes signées empêchent tout rollback de
l'état applicatif. La signature couvre :

```text
"helios-in-tunnel-trust-update-request-v5"
|| protocol_version:u16
|| request_id:16
|| trust_domain_id:16
|| gateway_wg_public_key:32 || client_wg_public_key:32
|| ca_epoch:u64 || ca_tls_epoch:u64
|| gateway_identity_epoch:u64
|| client_identity_generation:u64
|| active_gateway_tls_certificate_fingerprint:32
|| active_gateway_certificate_fingerprint:32
|| active_client_tls_certificate_fingerprint:32
|| active_client_pq_certificate_fingerprint:32
|| client_pq_certificate_fingerprint:32
```

La gateway exige que le pair WireGuard résolu, le certificat PQ présenté et
les deux empreintes clientes de la requête désignent le même couple autorisé à
l'instant courant : actif, ou suivant seulement à partir de son
`activation_at`. Une répétition de `request_id` peut être servie de manière
idempotente ; sa mémorisation est une borne opérationnelle et non la défense
anti-rejeu principale. Les objets de réponse restent rejouables sans rollback
grâce à leurs générations et signatures.

La réponse `200 OK` contient au plus une transition `CA-PQ`, une transition
`CA-TLS`, une transition gateway et un grant client. Tous sont pré-signés ; la
gateway n'appelle jamais `CA-PQ` et ne réalise aucune signature de CA à la
demande. Une réponse vide est valide. Les erreurs HTTP sont volontairement
grossières : `400` pour le JSON ou la version, `401` si la source n'est pas un
pair admis, `403` pour une identité, un certificat ou une signature refusés,
`413` au-delà de 32 Kio, `415` hors JSON et `500` après une erreur interne.
Le motif détaillé reste dans le journal protégé de la gateway.

Le client vérifie chaque objet indépendamment, puis applique l'ensemble dans
l'ordre `CA-PQ -> CA-TLS -> gateway -> client` sous une transaction locale
atomique. Si un objet échoue, aucun des quatre états n'est modifié. Une réponse
qui dépasserait 64 Kio est refusée par l'émetteur et doit être scindée entre
plusieurs requêtes successives.

### 8.2 Document hors ligne

Les mêmes objets peuvent être placés dans un document JSON
`orion-trust-update` signé et transféré par un canal non fiable. Le document
porte `format_version = 1`, `trust_domain_id`, au plus une transition de chaque
type, leurs empreintes ordonnées et une signature `CA-PQ` sur sa forme JCS. La
signature doit se vérifier sous la CA active au **début** de l'import ; cette CA
vient du profil local, jamais du document seul. Chaque objet embarqué conserve
en plus sa propre signature normative.

Un client dont le certificat PQ applicatif a expiré, dont le tunnel ne peut
plus être établi ou qui est resté hors ligne au-delà du chevauchement utilise
ce document. Une leaf expirée n'est jamais réacceptée pour télécharger sa
propre mise à jour.

Une réponse réseau ou un document hors ligne contient une seule transition de
CA. Une opération d'import hors ligne peut accepter au plus trois documents
strictement consécutifs, chacun signé sous la CA devenue active à l'étape
précédente et persisté avant le suivant. À aucun instant le magasin de confiance
ne contient plus de deux CA. Au-delà de trois générations manquées, une
réinitialisation opérateur explicite est exigée afin de borner taille, temps de
vérification et complexité de récupération.

## 9. Rotation de `CA-PQ`

### 9.1 Objet à double signature

`CaTransition` contient :

| Champ | Contrainte |
| --- | --- |
| `format_version` | `1` |
| `trust_domain_id` | identique à l'ancre locale |
| `current_ca_epoch` | génération locale |
| `next_ca_epoch` | exactement actuelle + 1 |
| `current_ca_fingerprint` | ancre locale attendue |
| `next_ca_public_key` | clé ML-DSA-87 canonique |
| `next_ca_fingerprint` | dérivée et vérifiée |
| `not_before`, `activation_at`, `not_after` | fenêtre de §4.1 |
| `current_ca_signature` | continuité depuis l'ancre fiable |
| `next_ca_signature` | preuve de possession de la nouvelle clé |

Les deux signatures couvrent les mêmes octets :

```text
"helios-ca-transition-v5"
|| format_version:u16
|| trust_domain_id:16
|| current_ca_epoch:u64 || next_ca_epoch:u64
|| current_ca_fingerprint:32
|| len(next_ca_public_key):u32 || next_ca_public_key
|| next_ca_fingerprint:32
|| not_before:u64 || activation_at:u64 || not_after:u64
```

Orion et la gateway vérifient d'abord la signature de l'ancienne CA déjà
fiable, puis celle de la nouvelle. Une seule signature ne suffit pas. Cette
règle suit le principe de continuité séquentielle : la génération suivante est
autorisée par la racine actuelle et prouve elle-même la nouvelle clé.

### 9.2 État et émission

Pendant le chevauchement, `current_ca` et `next_ca` sont les deux seules ancres
admises. Les nouvelles leafs peuvent être préparées sous la nouvelle CA, mais
ne sont activées qu'à partir de `activation_at`. Les leafs sous l'ancienne CA
restent vérifiables jusqu'à `not_after`. À cette date, la nouvelle CA devient
l'unique ancre et l'ancienne est supprimée.

Chaque transition est conservée par l'outillage opérateur sous son numéro de
génération afin qu'un client hors ligne puisse reconstruire une chaîne
séquentielle. Les fichiers sont publics mais signés ; les clés privées des deux
CA restent confinées dans l'autorité de signature. L'ancienne clé privée peut
être détruite seulement après la fin de la fenêtre et la publication durable
de la transition.

### 9.3 CA compromise

Si la clé privée `CA-PQ` actuelle est compromise, sa signature ne prouve plus
une continuité honnête. La rotation automatique normale est donc interdite.
L'opérateur crée un nouveau `trust_domain_id`, fait confirmer la nouvelle
empreinte hors bande et réémet les identités concernées. Selon l'étendue de la
compromission, cela peut imposer le ré-enrôlement du parc.

Une double signature ne répare pas une ancienne CA déjà contrôlée par
l'attaquant : celui-ci pourrait choisir et cosigner sa propre nouvelle clé. La
confirmation hors bande est la seule nouvelle autorité dans ce cas.

### 9.4 Rotation de la CA TLS cliente

`CA-TLS` authentifie le transport mTLS avant que la signature PQ cliente soit
vérifiée. Sa rotation doit donc être préparée sur la gateway avant d'émettre
des leafs clientes sous la nouvelle CA. La gateway conserve au plus
`active_client_tls_ca_certificate` et `next_client_tls_ca_certificate`, avec
`ca_tls_epoch`, `activation_at` et `retire_active_at`.

`ClientTlsCaTransition` lie `trust_domain_id`, les générations TLS actuelle et
suivante, les empreintes SHA-256 DER des deux CA, le certificat public complet
de la suivante et la fenêtre de §4.1. Elle est signée par `CA-PQ` sous le
domaine `helios-client-tls-ca-transition-v5`. Le nouveau certificat CA TLS est
également auto-signé afin de prouver la possession et sa capacité de
certification ; cette auto-signature classique ne remplace jamais
`ca_pq_signature` comme autorisation Helios.

```text
"helios-client-tls-ca-transition-v5"
|| format_version:u16
|| trust_domain_id:16 || ca_epoch:u64
|| current_ca_tls_epoch:u64 || next_ca_tls_epoch:u64
|| active_client_tls_ca_fingerprint:32
|| SHA-256(next_client_tls_ca_certificate_der):32
|| not_before:u64 || activation_at:u64 || not_after:u64
```

Pendant le chevauchement, le vérificateur mTLS accepte les deux chaînes, puis
résout toujours la leaf vers une génération cliente TLS/PQ exacte. À
`not_after`, l'ancienne CA TLS est retirée. Si `CA-TLS` est soupçonnée
compromise, la transition normale avec chevauchement est interdite : la gateway
retire l'ancienne CA, les clients concernés reçoivent de nouvelles leafs et la
signature PQ continue d'empêcher qu'un certificat TLS forgé suffise à négocier.

## 10. Révocation urgente

### 10.1 Objet

`EmergencyCertificateRevocation` est distinct d'une transition ordinaire :

| Champ | Contrainte |
| --- | --- |
| `format_version` | `1` |
| `trust_domain_id`, `ca_epoch` | ancre qui signe |
| `scope` | `gateway` ou `client` |
| `identity_key` | clé WireGuard gateway ou cliente |
| `server_name` | obligatoire pour la gateway |
| `revocation_epoch` | compteur de révocation local + 1 dans la portée visée |
| `revoked_tls_fingerprint` | facultative si TLS n'est pas concerné |
| `revoked_pq_fingerprint` | facultative si PQ n'est pas concerné |
| `effective_at` | effet immédiat ou futur explicite |
| `reason` | `key_compromise`, `suspected_compromise`, `cessation` ou `superseded` |
| `replacement_transition_fingerprint` | facultative |
| `ca_signature` | signature de la CA fiable |

Au moins une empreinte est présente. L'objet est signé sous le domaine
`helios-certificate-emergency-revocation-v5` avec tous les champs ci-dessus,
dans l'ordre et l'encodage binaire canonique de la v5.

### 10.2 Effet

À `effective_at`, l'empreinte nommée est retirée même si sa validité ou son
chevauchement n'est pas terminé. La révocation domine `staged`, `overlap`, un
rollback de service et tout callback d'une génération antérieure. Si aucune
identité de remplacement déjà vérifiée ne reste disponible, la connexion
échoue fermement.

Le compteur de révocation est persisté avec les empreintes retirées et avance
indépendamment des générations de certificat. Une rotation ultérieure ne peut
donc ni réintroduire une leaf révoquée, ni faire disparaître la décision par un
numéro de génération concurrent. Une empreinte révoquée reste mémorisée au
moins jusqu'à la fin de sa validité cryptographique.

Pour une gateway compromise, la révocation doit atteindre Orion par un canal
que l'attaquant ne peut pas falsifier : import du document signé, distribution
d'entreprise ou connexion à une gateway encore honnête. Une gateway compromise
peut retenir un objet public et provoquer une attaque de gel. Sans service de
fraîcheur indépendant, la v5 ne peut garantir une révocation instantanée à un
client isolé ; l'expiration et la distribution hors bande bornent seulement la
fenêtre.

Pour un client, `peer remove` reste la révocation immédiate de référence. Le
présent objet sert surtout à distribuer et auditer la décision ; il ne doit
jamais retarder le retrait de l'admission.

## 11. Ordre des opérations

### 11.1 Renouvellement gateway normal

1. Générer et sceller la nouvelle clé sur la gateway.
2. Exporter et vérifier `GatewayCertificateRequest`.
3. Émettre la leaf PQ sous `CA-PQ` et, si nécessaire, la nouvelle leaf TLS.
4. Produire et signer `GatewayIdentityTransition` dans l'autorité opérateur.
5. Installer et synchroniser clé, certificats et transition sur la gateway sans
   modifier l'identité servie.
6. Distribuer la transition aux clients et mesurer ceux qui l'ont persistée.
7. À `activation_at`, redémarrer `heliosd` sur la nouvelle identité.
8. Pendant le chevauchement, autoriser un rollback vers l'ancienne identité.
9. À `not_after`, promouvoir la nouvelle et détruire l'ancienne clé privée
   scellée après synchronisation de l'état promu.

Une étape ne peut être inversée avec la suivante. En particulier, la gateway
ne sert jamais une leaf dont la transition n'est pas déjà publiée, et Orion ne
supprime jamais l'ancien pin avant la fin du chevauchement.

### 11.2 Renouvellement client normal

1. Générer les nouvelles clés dans le stockage protégé Orion.
2. Produire la demande et les trois preuves de possession/continuité.
3. Émettre les deux certificats dans l'autorité opérateur.
4. Installer et synchroniser la génération suivante dans l'admission gateway.
5. Signer puis distribuer le grant.
6. Orion persiste le grant et bascule à `activation_at`.
7. Une connexion v5 réussie marque la nouvelle génération observée.
8. Les deux bouts retirent l'ancienne à `not_after`.

### 11.3 Rotation de CA normale

1. Créer la nouvelle CA dans l'autorité isolée en conservant le même
   `trust_domain_id`.
2. Produire la transition `N -> N+1`, signée par les deux CA.
3. Publier durablement la transition numérotée.
4. La distribuer aux gateways et clients avant toute leaf sous la nouvelle CA.
5. Préparer les nouvelles leafs, puis les activer dans leur propre transition.
6. À `not_after`, promouvoir la CA et retirer l'ancienne ancre.

### 11.4 Rotation de la CA TLS cliente

1. Produire la nouvelle CA TLS et `ClientTlsCaTransition` dans l'autorité
   opérateur.
2. Installer et synchroniser la CA suivante sur la gateway.
3. Émettre les grants clients dont la leaf TLS chaîne vers cette CA.
4. Activer la CA et les générations clientes à leurs dates liées.
5. Retirer l'ancienne CA seulement après la fin du chevauchement.

## 12. Socle certificat v5 et automatisation ultérieure

### 12.1 Obligatoire pour déclarer le cycle de vie implémenté

- émission du certificat PQ gateway par `CA-PQ` ;
- `trust_domain_id` et les cinq compteurs monotones ;
- migration explicite du profil Orion vers le discriminant
  `helios_key_negotiation`, sans reclassement par absence de champ ;
- enrôlement v5 sans clé privée dans le document et signature opérateur, afin
  que la confiance initiale en `CA-PQ` ne soit pas apportée par l'objet qu'elle
  signe elle-même ;
- deux ancres `CA-TLS` clientes au plus ;
- états `active + next` bornés pour gateway, client et CA ;
- association atomique des empreintes TLS/PQ clientes ;
- formats signés des §§5 à 10 et parseurs stricts ;
- route interne authentifiée `POST /api/key-negotiation/trust-update` ;
- import manuel d'un document `orion-trust-update` ;
- persistance atomique, promotion et suppression définitive ;
- sérialisation de la révocation d'admission, de la génération cliente et du
  retrait du plan de données, afin que l'état terminal `revoked` domine aussi
  en concurrence ;
- affichage clair de l'état `active`, `staged`, `overlap`, `expired` ou
  `revoked` ;
- tests du §14.

La première release du lot certificat peut n'émettre automatiquement aucune
transition après l'enrôlement. Elle doit néanmoins savoir les représenter, les
vérifier et les appliquer manuellement. C'est ce qui permet à une extension
ultérieure d'automatiser le cycle sans changer le protocole ou ré-enrôler le
parc.

### 12.2 Reportable dans une extension opérationnelle v5.x

- planificateur de renouvellement automatique ;
- alertes à J-90, J-30 et J-7 ;
- commandes ergonomiques `helios-ctl rotate gateway-cert` et
  `helios-ctl rotate client-cert` ;
- tableau de bord de conformité et mesure du déploiement ;
- relance des clients hors ligne ;
- redémarrage planifié de `heliosd` à `activation_at` ;
- rotation automatique déclenchée par proximité d'expiration ou signal
  d'incident.

Ces fonctions orchestrent les objets normatifs. Elles ne peuvent augmenter le
nombre de slots, ignorer une génération, prolonger le chevauchement ou accepter
une CA apportée seulement par la mise à jour.

## 13. Migration depuis la v5 actuellement servie

### 13.1 Installation neuve après implémentation du lot

Une installation neuve ne doit plus émettre de profil avec une leaf PQ gateway
auto-signée. L'enrôlement initial crée directement :

- `trust_domain_id` aléatoire ;
- `ca_epoch = 1` avec `current_ca_public_key` ;
- `ca_tls_epoch = 1` avec la CA TLS cliente active ;
- `gateway_identity_epoch = 1` ;
- les leafs gateway actives et aucun slot suivant ;
- `client_identity_generation = 1` pour chaque admission ;
- `revocation_epoch = 0` pour chaque identité.

### 13.2 Parc v5 existant

Le parc actuel ne possède pas l'ancre nécessaire pour vérifier une transition
ordinaire : Orion épingle la leaf PQ gateway auto-signée, pas `CA-PQ`. Un
`CaTransition` ne peut pas réparer cette absence, puisqu'il doit être vérifié
par une CA déjà fiable. La première installation de `CA-PQ` constitue donc un
**bootstrap de confiance**, pas la génération `N -> N+1` d'une rotation.

Ce bootstrap exige une confirmation hors bande de l'empreinte `CA-PQ`, comme
un enrôlement neuf. Ni la leaf gateway actuellement épinglée, ni un document
signé seulement par la CA qu'il transporte ne suffisent à étendre la confiance
à tout le domaine opérateur. Cette règle évite qu'une compromission de la leaf
d'une seule gateway puisse créer une nouvelle CA valable pour tout le parc.

La migration suit cet ordre :

1. Déployer les lecteurs du nouveau profil, les états bornés et les compteurs,
   sans modifier l'identité encore servie.
2. Créer `trust_domain_id` et fixer `ca_epoch = 1`. La clé opérateur qui signe
   déjà les leafs PQ clientes peut devenir cette première `CA-PQ` si elle est
   ML-DSA-87, disponible dans l'autorité de signature et confirmée hors bande ;
   son emplacement historique ne vaut jamais preuve d'identité.
3. Générer dans un chemin de staging une nouvelle identité gateway, obtenir sa
   leaf PQ signée par `CA-PQ`, puis préparer l'état gateway de génération `1`.
   L'ancienne leaf auto-signée n'entre pas dans cet état cible.
4. Convertir chaque couple TLS/PQ client admis en génération cliente `1`, après
   vérification de sa chaîne, de ses clés et de l'unicité globale des deux
   empreintes. Une identité dont l'émetteur ou la clé privée locale ne peut pas
   être prouvé est ré-enrôlée ; elle n'est pas réparée par supposition.
5. Préparer pour chaque Orion un profil `helios_key_negotiation` épinglant
   `CA-PQ`, `trust_domain_id` et la nouvelle identité gateway. Le document ne
   transporte aucune clé privée et Orion ne l'active qu'après la confirmation
   hors bande. Il peut réutiliser une identité locale dont les clés publiques
   correspondent exactement à la génération cliente convertie.
6. Une fois tous les profils préparés, promouvoir atomiquement l'identité de
   staging et redémarrer `heliosd`, puis activer les profils préparés. Après ce
   point, le chemin cible refuse toute leaf gateway auto-signée.

Les étapes 6 côté gateway et Orion forment une bascule coordonnée, avec une
indisponibilité possible. Les slots actif/suivant ne la suppriment pas : ils ne
peuvent fonctionner qu'après établissement d'une ancre commune. Inventer une
transition automatique depuis la leaf auto-signée actuelle contredirait la
frontière de confiance de §2.2.

`init-key-negotiation --rotate` ne réalise aucune de ces étapes. Tant que le
staging, le bootstrap de profil et la promotion atomique ne sont pas
implémentés, cette commande reste un remplacement coupant qui exige la remise
à jour manuelle de tous les profils.

### 13.3 Champ filaire conservé

Le champ signé de la requête v5 reste
`gateway_certificate_fingerprint` au singulier : il désigne **la leaf PQ
exactement utilisée pour cette transaction**, active ou suivante pendant le
chevauchement. Le profil, lui, porte les champs
`active_gateway_certificate_fingerprint` et
`next_gateway_certificate_fingerprint`. Helios accepte la requête seulement si
l'empreinte demandée est autorisée à l'instant courant et correspond à la leaf
qu'il sert.

## 14. Plan de validation

### 14.1 Tests déterministes et propriétés

- rejet d'une leaf gateway PQ auto-signée dans le chemin cible après bascule,
  sans empêcher le lecteur de migration d'identifier l'ancien pin ;
- acceptation d'une leaf gateway PQ signée par la CA épinglée et refus sous une
  CA seulement apportée par le document ;
- bootstrap du parc actuel refusé sans confirmation hors bande de `CA-PQ`, y
  compris si l'objet est signé par l'ancienne leaf gateway ;
- conversion d'un couple client existant en génération `1` seulement si la
  chaîne, les empreintes et les clés locales correspondent exactement ;
- liaison obligatoire de chaque transition à la clé WireGuard, au
  `server_name` et au `trust_domain_id` du profil ;
- refus des générations égales avec contenu différent, inférieures, sautées et
  proches de `u64::MAX` ;
- rejeu idempotent d'un objet strictement identique ;
- bornes exactes de `not_before`, `activation_at`, `not_after` et des 30 jours,
  sans overflow ;
- deux leafs maximum par famille, y compris après hot-reload et reprise après
  crash ;
- transition gateway TLS seule, PQ seule et TLS + PQ atomique ;
- rollback vers l'ancienne leaf autorisé seulement pendant le chevauchement ;
- promotion définitive malgré un recul simulé de l'horloge ;
- refus de tous les couples mixtes TLS/PQ entre générations clientes ;
- unicité globale des empreintes actives et suivantes ;
- demande cliente : signature active, CSR TLS et preuve PQ suivante toutes
  obligatoires ;
- grant jamais émis avant persistance de l'admission suivante ;
- transition CA refusée sans l'une des deux signatures ou avec un saut de
  génération ;
- transition `CA-TLS` refusée sans signature `CA-PQ`, avec une CA suivante
  incapable de vérifier sa propre auto-signature ou avant persistance gateway ;
- application séquentielle de trois transitions CA hors ligne sans jamais
  conserver trois ancres simultanément ;
- révocation dominante dans chaque état et callback obsolète sans effet ;
- transaction locale `CA-PQ -> CA-TLS -> gateway -> client` entièrement annulée
  si son dernier objet échoue ;
- document JCS modifié, membre inconnu, membre dupliqué ou représentation non
  canonique refusé ;
- mélange d'un document destiné à une autre gateway ou à un autre domaine de
  confiance refusé ;
- taille de trame, nombre d'objets et coûts ML-DSA bornés ;
- réponse `404` d'une ancienne gateway à la route de mise à jour, sans repli
  vers QUIC, une leaf expirée, un pin unique ou un mode plus faible ;
- refus de la route depuis une source hors tunnel, une VIP inconnue, un pair
  différent de la clé signée ou une identité PQ d'une autre génération ;
- fuzzing de tous les objets signés, de leurs certificats embarqués et de la
  machine d'état temporelle.

### 14.2 Essais d'intégration

- client resté hors ligne avant activation, pendant le chevauchement et après
  son terme ;
- import hors ligne après expiration du certificat PQ applicatif ou perte du
  tunnel ;
- bascule coordonnée d'un parc v5 actuel : profil préparé, identité gateway de
  staging promue, ancien certificat auto-signé définitivement refusé ;
- redémarrage de `heliosd` sur la nouvelle identité, puis rollback pendant la
  fenêtre ;
- crash avant et après chaque synchronisation de l'ordre §11 ;
- rotation cliente sous trafic, sans changement de clé WireGuard ni du PSK
  négocié courant ;
- rotation de CA suivie d'une rotation leaf sous la nouvelle CA ;
- révocation urgente gateway distribuée en ligne puis hors ligne ;
- attaque de gel simulée : la limite est visible et aucun état ne prétend avoir
  reçu une révocation absente ;
- coexistence inchangée d'un profil Orion `classic`, qui n'émet aucune requête
  de mise à jour Helios.

Les essais TPM réels, DPAPI, WireGuard-NT et redémarrage de la gateway restent
target-only. Une compilation WSL2 ne valide aucun de leurs effets.

## 15. Limites connues

**Un client hors ligne au-delà du chevauchement peut nécessiter un document
hors ligne.** Deux slots bornent volontairement la complexité et la surface
d'attaque. Maintenir indéfiniment toutes les anciennes leafs annulerait le
bénéfice de la rotation.

**La révocation n'est pas instantanée sans canal de fraîcheur indépendant.** Un
attaquant qui contrôle la gateway ou le réseau peut retenir un objet signé et
provoquer un gel. Le résoudre complètement demanderait un service de statut
hautement disponible, une distribution d'entreprise ou un autre canal déjà
fiable. La v5 fournit un document hors ligne et échoue fermement après les
échéances ; elle ne prétend pas avoir une information qu'elle n'a pas reçue.

**La compromission de `CA-PQ` rompt la continuité automatique.** Une transition
signée par une CA compromise ne restaure pas la confiance. Une nouvelle
confirmation hors bande et, selon le périmètre, un ré-enrôlement sont
obligatoires.

**Le redémarrage de `heliosd` reste nécessaire pour une leaf gateway.** Le
format permet de préparer et distribuer la confiance sans coupure, mais
l'identité servie est toujours chargée une fois au démarrage. Le planificateur
v5.x pourra ordonner le redémarrage ; il ne le supprime pas.

**La CA reste mono-clé par génération.** La double signature de transition
protège la continuité, pas la compromission de la clé courante. Passer à un
seuil multi-signatures pour `CA-PQ` serait une nouvelle décision
d'architecture et un nouveau format.

**La forme d'exploitation de l'autorité opérateur n'est pas décidée ici.** Le
code actuel utilise un poste opérateur et `~/.helios/certs/internal-ca`. Un
service dédié isolé pourrait supprimer cette dépendance au poste, mais il
changerait la disponibilité et la surface d'attaque de la CA. Le choisir exige
un ADR qui fixe au minimum la garde des clés, l'authentification mutuelle,
l'autorisation humaine ou automatique, l'anti-rejeu, le journal d'audit, la
sauvegarde et la reprise après compromission. Cette note n'assimile jamais le
seul chiffrement du lien à ces propriétés.

## 16. Correspondance cible avec le code

| Composant | Responsabilité |
| --- | --- |
| `aether::key_negotiation` | certificats gateway émis par CA, objets signés, encodage canonique et empreintes |
| `aether::config` | états bornés, générations, invariants temporels et union active/suivante |
| `helios-api` | route interne de mise à jour, authentification de la source WireGuard et limites HTTP |
| `heliosd::key_negotiation` | chargement de l'identité active, publication de transition et preuve de leaf servie |
| `helios-provisioning::admission` | générations clientes TLS/PQ atomiques, unicité et révocation dominante |
| configuration TLS de `heliosd` | deux CA clientes au plus, promotion par `ca_tls_epoch` et vérification mTLS avant résolution de génération |
| `orion-core::config` | ancres, pins actifs/suivants, compteurs persistants et anti-rollback |
| `orion-core::key_negotiation` | récupération, validation et application transactionnelle des mises à jour |
| `orion-core::identity_store` | clés et certificats clients actifs/suivants protégés, promotion atomique |
| autorité opérateur | garde des clés privées CA, politique d'émission, signatures, anti-rejeu et journal d'audit |
| `helios-ctl` | export des demandes, contrôle des réponses, registre des transitions et documents de récupération ; client de l'autorité si celle-ci devient un service |

## 17. Références de conception

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) — validité,
  certification et modèle de révocation X.509 ;
- [RFC 9810](https://www.rfc-editor.org/rfc/rfc9810.html) — preuve de
  possession, transition de clé de CA et distribution hors bande ;
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA ;
- [The Update Framework, spécification](https://theupdateframework.github.io/specification/latest/)
  — générations séquentielles, signatures ancienne/nouvelle et persistance
  anti-rollback ; la présente spécification reprend ces propriétés, pas son
  format de dépôt.
