# Spécification — cycle de vie et rotation des certificats v5

**Statut** : cible spécifiée — **cycle de vie non implémenté**. Le protocole de
négociation servi est déjà la v5 ; cette note décrit le lot certificat restant.

**Version du format** : `1`

**Date de la note** : 2026-08-09

Cette note complète la
[spécification de négociation de clé v5](NEGOCIATION-DE-CLE-V5.md) et
[ADR-005](../adr/ADR-005-NEGOCIATION-DE-CLE.md), puis fixe avec
[ADR-008](../adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md) l'exploitation de
l'autorité. La v5 filaire, ML-DSA-87 et le
certificat `PqCertificate` v2 sont déjà servis. Le code reste toutefois figé
autour d'une seule identité gateway auto-signée et d'une seule génération
cliente. Cette note définit les formats et transitions qui ferment ce manque.
Elle définit également Astra, l'ordonnancement automatique, la récupération
d'une identité expirée, les approbations YubiKey et les campagnes manuelles.

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
| abandon | un staging gateway peut être annulé avant toute publication et avant `activation_at` par un objet signé ; son époque reste consommée et mémorisée |
| staging client | lease signée de 24 heures au plus, puis purge atomique si Orion n'a pas committé le grant |
| autorité d'une transition leaf | `CA-PQ` pour gateway, récupération et autorités ; émetteur Astra délégué pour renouvellement client ordinaire |
| exploitation | coordinateur Astra co-implanté dans un conteneur séparé sur la gateway, canal public HTTPS et veth privé vers Helios |
| garde des CA | clés maîtresses `CA-PQ` et `CA-TLS` dans un coffre HVLT chiffré ; déverrouillage hors de la gateway par une YubiKey opérateur |
| émission ordinaire | clé Astra déléguée, bornée à une gateway, un domaine, une fenêtre et aux leafs de pairs déjà admis |
| YubiKey | deux credentials matériels 1-sur-2 au bootstrap ; présence obligatoire pour récupération expirée, rollback et campagne manuelle ; ce modèle mono-opérateur n'est pas un quorum humain |
| renouvellement | ouverture automatique à 80 % de la validité écoulée ; aucune présence humaine pour une rotation ordinaire encore authentifiée |
| expiration | une leaf expirée reste refusée par la négociation ; elle peut seulement prouver une continuité historique dans la récupération Astra |
| rotation de `CA-PQ` | transition signée par l'ancienne **et** la nouvelle CA, générations consécutives |
| rotation de `CA-TLS` cliente | deux ancres au plus, transition autorisée par `CA-PQ` avant toute nouvelle leaf mTLS |
| clé de service Astra | slot actif/suivant et transition signée par `CA-PQ`, avec preuve de la nouvelle clé et époque séquentielle |
| statut Astra | jamais accessible par empreinte seule ; requête authentifiée dans WireGuard ou challenge public signé par la clé PQ cliente |
| réponses fractionnées | chunks d'une même transaction signée, invisibles aux slots actifs/suivants jusqu'au commit atomique local |
| compromission | révocation sans grâce ; si `CA-PQ` est compromise, réinitialisation hors bande |
| commandes manuelles | Orion renouvelle un profil ou tous ses profils locaux ; Helios renouvelle les leafs du parc ou toute la chaîne ; campagne Astra et YubiKey obligatoires |

Le choix de faire émettre le certificat PQ gateway par `CA-PQ` est retenu à la
place d'une simple cosignature par l'ancienne leaf. Une leaf compromise ne peut
ainsi autoriser seule sa remplaçante. Astra conserve le coffre chiffré et le
registre sur la machine gateway, mais une clé maîtresse n'y est jamais
déchiffrée : le compagnon de signature opérateur ouvre le coffre localement à
l'aide d'une YubiKey, signe puis zéroïse. La seule clé utilisable sans présence
humaine sur la gateway est l'émetteur délégué, dont portée et durée sont
vérifiées par chaque consommateur. Docker, le veth et le chiffrement interne
séparent les services ; ils ne sont pas présentés comme une défense contre
`root` sur l'hôte.

### 0.3 Résolution de la revue de sécurité du 9 août 2026

| Constat | Verdict et résolution |
| --- | --- |
| absence d'avortement | confirmé ; `GatewayTransitionAbort` existe seulement avant publication et consomme l'époque |
| staging client orphelin | confirmé ; lease, commit Orion signé par les deux clés et purge sérialisée |
| rotation de clé de service Astra | confirmé ; transition active/suivante et remplacement d'urgence sous `CA-PQ` |
| statut public par empreinte | confirmé ; supprimé au profit du tunnel ou d'un challenge signé |
| deux clés assimilées à deux opérateurs | promesse incorrecte retirée ; le coffre v1 est explicitement 1-sur-N et mono-opérateur |
| une clé pour récupération, deux pour réadmission | maintenu ; la récupération exige en plus la clé PQ historique et conserve l'identité, avec risque résiduel explicite |
| fractionnement au-delà de 64 Kio | confirmé ; chunks pending d'une transaction signée unique, commit local atomique |

La même revue rend également explicites l'asymétrie de la leaf TLS gateway,
le risque de la bascule initiale et l'attaque de gel déjà acceptée. La forward
secrecy du veth devient une exigence normative plutôt qu'une hypothèse.

## 1. Périmètre

Huit cycles de vie sont distincts :

1. l'identité gateway, composée d'une leaf TLS et d'une leaf PQ ;
2. l'identité cliente, composée d'une leaf TLS et d'une leaf PQ ;
3. l'ancre opérateur `CA-PQ` ;
4. la CA TLS qui émet les leafs mTLS clientes ;
5. la révocation urgente d'une leaf ou d'une admission.
6. la délégation de l'émetteur opérationnel Astra ;
7. les credentials YubiKey qui autorisent les mutations manuelles.
8. l'identité applicative du service Astra épinglée par Orion et Helios.

La rotation de la clé WireGuard gateway n'est **pas** une rotation de
certificat. Elle change l'identité du pair, la dérivation du PSK et la cible
signée des requêtes ; elle exige un nouveau profil et une confirmation hors
bande. Il en va de même d'un changement de `server_name`.

Cette note ne transforme pas `CA-PQ` en clé en ligne et n'introduit ni CRL
publique ni OCSP. Astra publie son propre état signé et des fenêtres de
renouvellement, mais aucun statut ne prolonge la validité d'un certificat. Les
objets de transition et de révocation restent distribuables par un canal non
fiable ; leur fraîcheur est bornée par les dates, les générations, les
challenges et la capacité du client à les recevoir.

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

### 2.4 Identité Astra et liaison aux YubiKeys

Chaque profil Helios contient :

```text
AstraProfile {
    authority_url: HttpsUrl,
    webauthn_rp_id: DnsName,
    active_astra_service_public_key: MlDsa87PublicKey,
    next_astra_service_public_key: Option<MlDsa87PublicKey>,
    astra_service_key_epoch: u64,
    service_key_activation_at: Option<u64>,
    service_key_retire_active_at: Option<u64>
}
```

`authority_url` est une origine HTTPS distincte de l'API Helios et du port
QUIC. `webauthn_rp_id` est un suffixe DNS valide de cette origine et ne change
pas pendant une rotation du certificat TLS du service. Deux clés de service au
plus sont conservées pendant la transition de §9.6. Elles signent les statuts,
challenges, reçus de campagne et réponses opérationnelles ; elles n'émettent
aucune leaf et ne remplacent ni `CA-PQ` ni l'émetteur délégué.

Le registre Astra associe un credential FIDO2 à :

```text
AstraCredentialBinding {
    credential_id: BoundedBytes,
    credential_public_key: WebAuthnPublicKey,
    aaguid: [u8; 16],
    trust_domain_id: [u8; 16],
    gateway_wg_public_key: [u8; 32],
    state: active | lost | revoked,
    credential_epoch: u64
}
```

Tous les credentials enregistrés ici sont opérateur et couvrent le domaine.
Les opérations qui touchent une ancre ou une réadmission sans continuité
exigent deux credentials distincts. Un compteur WebAuthn nul ou non croissant
n'est jamais la défense anti-rejeu principale : le challenge Astra à usage
unique et la génération applicative la fournissent.

Le coffre v1 est **1-sur-N** : chaque key-slot actif peut ouvrir seul la même
clé maîtresse afin que la perte de la YubiKey principale soit récupérable par
la secondaire. Demander deux credentials sur une opération sensible est une
politique d'approbation appliquée par le compagnon honnête ; elle protège
contre une action accidentelle et l'usage d'une seule clé volée par les API,
mais ne constitue ni un partage de secret, ni un quorum humain, ni une défense
contre un poste qui extrait la CA après un déverrouillage légitime. Les IHM et
l'ADR doivent l'appeler « confirmation par deux clés », jamais « M-sur-N » ou
« double contrôle ». Un vrai seuil impose des parts cryptographiques et des
identités d'opérateurs distinctes ; il reste hors de la v1.

Une opération nécessitant la clé maîtresse transporte une requête pour le
compagnon local :

```text
AstraSignerRequest {
    format_version: 1,
    operation_id: [u8; 16],
    campaign_fingerprint: [u8; 32],
    authority_url: HttpsUrl,
    encrypted_vault_fingerprint: [u8; 32],
    required_credentials: u8,
    created_at: u64,
    expires_at: u64,
    astra_service_key_epoch: u64,
    astra_signature: MlDsa87Signature
}
```

`astra-signer` vérifie cette signature sous la clé de service déjà épinglée,
télécharge le coffre dont l'empreinte est fixée, affiche le manifeste exact et
utilise CTAP localement. Le secret de déverrouillage et les clés privées
maîtresses ne quittent jamais ce processus ; seul le résultat signé est
renvoyé. Orion et l'IHM Helios ne reçoivent qu'un `operation_id` et suivent son
état par interrogation.

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
Le compagnon maître Astra vérifie cette preuve de possession avant d'émettre
la leaf. La clé privée ne quitte jamais la gateway.

### 3.2 État gateway dans Orion

Le bloc public du profil contient au minimum :

```text
GatewayCertificateState {
    trust_domain_id: [u8; 16],
    ca_epoch: u64,
    current_ca_public_key: MlDsa87PublicKey,
    next_ca_public_key: Option<MlDsa87PublicKey>,

    active_gateway_identity_epoch: u64,
    gateway_decision_epoch: u64,
    next_gateway_identity_epoch: Option<u64>,
    last_aborted_transition: Option<GatewayTransitionAbortTombstone>,
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

`active_gateway_identity_epoch` nomme la leaf actuellement servie ;
`gateway_decision_epoch` est le plus grand numéro de transition ou
d'avortement accepté. Ils sont égaux hors d'un avortement non encore suivi
d'une nouvelle promotion. Une restauration ne peut donc réutiliser l'époque
d'une tentative annulée. `last_aborted_transition` suffit à rendre idempotent
le dernier avortement ; toute époque plus ancienne est déjà refusée par le
compteur de décision.

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
    pending: Option<ClientCertificatePendingStage>,
    next: Option<ClientCertificateGeneration>,
    activation_at: Option<u64>,
    retire_active_at: Option<u64>
}

ClientCertificatePendingStage {
    stage_id: [u8; 16],
    request_fingerprint: [u8; 32],
    candidate: ClientCertificateGeneration,
    state: pending_grant | pending_commit,
    stage_expires_at: u64
}
```

La gateway ne traite pas les empreintes TLS et PQ comme deux ensembles
indépendants. Une connexion mTLS reconnue sous la génération `N+1` doit
présenter et utiliser le certificat PQ de cette même génération. Les couples
TLS `N` / PQ `N+1` et TLS `N+1` / PQ `N` sont refusés. Cette liaison empêche une
attaque de mélange entre deux transitions pourtant valides séparément.

Une empreinte TLS ou PQ reste unique dans toute la table des pairs, génération
active et suivante comprises. Le chargement initial, le hot-reload et
l'admission refusent les doublons, y compris dans `pending`. `pending` et
`next` ne sont jamais renseignés simultanément : le commit remplace le premier
par le second sous une seule écriture.

### 3.4 Émetteur opérationnel Astra

L'autonomie d'Astra repose sur deux clés subordonnées, une ML-DSA-87 et une CA
TLS intermédiaire, jamais sur les clés maîtresses directement :

```text
AstraIssuerState {
    issuer_epoch: u64,
    pq_public_key: MlDsa87PublicKey,
    tls_intermediate_certificate: DerCertificate,
    authorization: AstraIssuerAuthorization,
    private_material_sealed: true,
    state: active | expiring | revoked
}
```

`AstraIssuerAuthorization` contient :

| Champ | Contrainte |
| --- | --- |
| `format_version` | `1` |
| `trust_domain_id`, `ca_epoch`, `ca_tls_epoch` | ancres exactes |
| `gateway_wg_public_key`, `server_name` | unique gateway autorisée |
| `issuer_epoch` | époque locale + 1 à l'installation |
| `pq_issuer_public_key` | ML-DSA-87 canonique |
| `tls_intermediate_certificate` | CA intermédiaire, usage client-auth seulement |
| `allowed_usage` | valeur unique `admitted_client_leaf_renewal` |
| `maximum_leaf_lifetime_secs` | positive et bornée par la politique du domaine |
| `policy_fingerprint` | SHA-256 de la politique canonique Astra |
| `not_before`, `not_after` | fenêtre de délégation positive |
| `ca_pq_signature` | signature par `CA-PQ` |
| `ca_tls_signature` | chaîne TLS depuis `CA-TLS` |

La signature PQ couvre :

```text
"helios-astra-issuer-authorization-v5"
|| format_version:u16
|| trust_domain_id:16 || ca_epoch:u64 || ca_tls_epoch:u64
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| issuer_epoch:u64
|| len(pq_issuer_public_key):u32 || pq_issuer_public_key
|| SHA-256(tls_intermediate_certificate_der):32
|| allowed_usage:u8 || maximum_leaf_lifetime_secs:u64
|| policy_fingerprint:32
|| not_before:u64 || not_after:u64
```

Une leaf ou un grant signé par Astra transporte l'autorisation complète et
`issuer_epoch`. Le vérificateur contrôle d'abord `CA-PQ`, puis la portée de la
délégation, puis la signature opérationnelle. L'émetteur refuse et les
consommateurs rejettent un premier enrôlement, une récupération expirée, une
réadmission, une rotation gateway ou CA, un pair révoqué, une génération autre
que `active + 1` et une validité supérieure au plafond. Sa révocation domine
toute émission non encore installée.

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
| décisions d'identité gateway TLS/PQ | `gateway_decision_epoch` par clé WireGuard gateway ; la leaf active conserve `active_gateway_identity_epoch` |
| identité cliente TLS/PQ | `client_identity_generation` par clé WireGuard cliente |
| ancre opérateur | `ca_epoch` par `trust_domain_id` |
| CA TLS cliente | `ca_tls_epoch` par `trust_domain_id` |
| émetteur Astra | `issuer_epoch` par gateway et domaine |
| identité de service Astra | `astra_service_key_epoch` par domaine |
| registre YubiKey | `credential_epoch` par credential et `credential_registry_epoch` par domaine |
| statut Astra | couple lexicographique `(astra_service_key_epoch, status_epoch)` par cible certifiée |
| révocation | `revocation_epoch` par identité WireGuard, indépendant des générations de certificat |

Une transition ordinaire doit porter exactement `current + 1`. Une valeur
égale est un rejeu idempotent seulement si tous les octets signés sont
identiques ; sinon c'est un conflit. Une valeur inférieure est un rollback. Une
valeur supérieure à `current + 1` est un saut refusé : les transitions
intermédiaires doivent être validées dans l'ordre.

`current` désigne ici le plus grand numéro de décision persisté, pas
nécessairement celui de la leaf encore active. Un avortement signé consomme
l'époque de la transition qu'il nomme et laisse un tombstone contenant époque,
empreinte de transition, empreinte d'avortement et date. L'identité active ne
change pas, mais la tentative suivante emploie `current + 1`. Cette séparation
évite de réutiliser une même époque avec deux jeux de certificats devant un
client qui aurait observé la première tentative.

Le staging client non committé est différent : sa génération candidate n'est
pas publiée comme décision de certificat. Sa lease et son `stage_id` empêchent
le rejeu ; après purge synchronisée, `active + 1` peut être demandé à nouveau.
Un grant ancien ne peut pas ressusciter ce staging parce que son commit nomme
le `stage_id`, l'empreinte du grant et une lease encore ouverte.

L'état et le compteur sont écrits atomiquement puis synchronisés avant qu'une
nouvelle leaf soit acceptée ou servie. Une erreur d'écriture laisse l'état
précédent intact. Après promotion, un recul de l'horloge ne réactive jamais
l'ancienne empreinte : le compteur persistant et l'absence du slot retiré
dominent le temps mural.

`status_epoch` peut repartir à `1` sous une nouvelle clé de service : l'époque
de clé est comparée en premier. Une clé compromise ne peut donc pas bloquer son
remplacement en publiant artificiellement `status_epoch = u64::MAX`; dès que la
transition de §9.6 est persistée, tout statut de l'ancienne époque est plus
ancien, quelle que soit sa valeur locale.

### 4.3 Fenêtre de renouvellement Astra

La date ordinaire d'ouverture se calcule sur la validité cryptographique de la
leaf active :

```text
lifetime = not_after - not_before
renewal_at = not_before + floor(lifetime * 80 / 100)
```

`not_after > not_before` est vérifié avant la soustraction, la multiplication
est vérifiée avant la division et le résultat reste strictement antérieur à
`not_after`. Astra publie une `suggested_window` contenue entre `renewal_at` et
l'échéance. Orion choisit et persiste un instant pseudo-aléatoire stable dans
cette fenêtre ; un redémarrage ne le retire pas et ne regroupe pas tout le parc
au même instant.

À 80 %, Orion génère puis scelle les clés candidates avant d'émettre la
demande. À 90 %, un renouvellement inachevé devient une alerte persistante ; à
95 %, il devient critique et se représente quotidiennement. Ces seuils ne
modifient ni la validité, ni la fenêtre de chevauchement de 30 jours, ni le
refus après expiration.

Le planificateur ordinaire n'exige pas de YubiKey. Il ne peut employer que
l'émetteur Astra actif, pour un pair admis et non révoqué, avec les preuves de
la génération active et suivante. Astra peut avancer la fenêtre par un statut
signé en cas d'incident ; elle ne peut jamais la repousser au-delà du calcul
local d'Orion.

### 4.4 Rollback de service, jamais rollback d'état

Pendant `overlap`, une sélection manuelle peut demander de servir ou présenter
temporairement l'ancienne leaf. Elle ne modifie aucun compteur, n'efface pas le
slot suivant et porte une échéance au plus égale au `not_after` de la
transition. Elle est refusée dans `active`, `promoted`, `expired` ou `revoked`.

Après promotion, l'ancienne leaf et sa clé privée ne peuvent pas être
réintroduites. Une restauration de fichier qui tenterait de les ramener reste
un rollback de génération et échoue avant toute écriture.

## 5. Demande de certificat gateway

`GatewayCertificateRequest` permet au compagnon maître Astra d'émettre une leaf
sans recevoir de clé privée :

| Champ | Contrainte |
| --- | --- |
| `format_version` | `1` |
| `trust_domain_id` | domaine de la CA visée |
| `gateway_identity_epoch` | époque demandée, `gateway_decision_epoch + 1` |
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
| `gateway_identity_epoch` | `gateway_decision_epoch + 1` |
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
  -> published
  -> overlap
  -> promoted

staged -> aborted
staged | published | overlap -> revoked
```

1. `active` : une seule identité est admise.
2. `staged` : la transition est vérifiée et persistée ; l'ancienne seule est
   servie et aucun octet de la transition n'a encore été distribué.
3. `published` : Astra a persisté le fait que la transition a pu quitter la
   gateway ; l'ancienne seule reste servie avant `activation_at`, mais
   l'avortement n'est plus sûr.
4. `overlap` : Orion accepte les deux identités ; la gateway sert normalement
   la nouvelle, mais peut redémarrer temporairement sur l'ancienne.
5. `promoted` : à `not_after`, la suivante devient active et l'ancienne est
   supprimée, même si le client ne l'a jamais observée.
6. `aborted` : avant publication et `activation_at`, la tentative est annulée,
   le slot suivant est supprimé et synchronisé, l'ancienne identité reste seule
   active et un tombstone conserve l'époque consommée.
7. `revoked` : la règle d'urgence de §10 retire immédiatement l'empreinte
   nommée et domine les dates.

L'avortement emploie un `GatewayTransitionAbort` contenant
`format_version`, `trust_domain_id`, `ca_epoch`, la gateway, le
`gateway_identity_epoch` avorté, l'empreinte complète de
`GatewayIdentityTransition`, `aborted_at`, le motif `operator_cancelled` ou
`superseded_before_activation`, l'empreinte de la campagne YubiKey et une
signature `CA-PQ` sous le domaine
`helios-gateway-identity-transition-abort-v5`. Il est accepté uniquement dans
`staged`, pour la transition exacte, tant qu'aucun marqueur `published` n'a été
persisté, avec `aborted_at < activation_at` **et** une horloge locale lue sous
verrou encore strictement antérieure à `activation_at`. Antidater l'objet ne
permet donc pas d'annuler une transition distribuée ou un overlap. Le
rejeu identique est idempotent ; toute autre valeur à la même époque est un
conflit. La suppression du slot et la persistance du tombstone forment une
seule écriture atomique.

```text
"helios-gateway-identity-transition-abort-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16 || ca_epoch:u64
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| gateway_identity_epoch:u64
|| gateway_transition_fingerprint:32
|| aborted_at:u64 || reason:u8
|| campaign_fingerprint:32
```

Le tombstone d'avortement est ensuite distribué comme la décision séquentielle
de cette époque, sans transporter les leafs annulées. Orion le persiste avant
d'accepter une transition à l'époque suivante. Un client qui ne l'a pas encore
reçu refuse correctement le saut ; il peut récupérer le tombstone signé dans
la transaction de confiance suivante.

Avant d'émettre le premier octet vers Orion ou d'exporter un document hors
ligne, Astra persiste irréversiblement `published`; une erreur après cette
écriture reste publiée, car le destinataire peut avoir reçu la réponse. Une
transition `published` ou entrée dans `overlap` ne peut plus être avortée : un
client peut avoir persisté la décision, repartir hors ligne puis promouvoir
seul à `not_after`. Annuler seulement sur la gateway créerait alors deux
vérités. Jusqu'à `not_after`, le rollback de service de §4.4 reste possible ;
pour revenir durablement, il faut promouvoir la transition puis préparer une
nouvelle transition vers une nouvelle leaf. Une compromission utilise
`revoked`, jamais `aborted`.

Orion marque `next_observed` seulement après un commit v5 signé par la nouvelle
leaf PQ et un handshake WireGuard réussi vers la clé gateway stable. Ce constat
n'autorise pas à supprimer l'ancienne avant `not_after` : d'autres clients ou
un rollback de la gateway peuvent encore en dépendre.

La gateway prépare et synchronise la clé privée suivante, le certificat et
l'objet de transition avant de les annoncer. Elle continue de servir
l'ancienne identité jusqu'à `activation_at`. Le passage à la clé suivante
nécessite toujours un redémarrage de `heliosd`, puisque l'identité est chargée
une fois ; Astra planifie ce redémarrage sans en changer l'ordre de sûreté.

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

### 7.2 Émission et autorisation de staging

L'empreinte de demande est le SHA-256 des octets signés de §7.1, suivis de la
signature active et de la signature suivante, chacune préfixée par sa longueur
`u32`. Astra vérifie la demande, la fenêtre de §4.3, l'admission et l'absence de
révocation avant d'émettre les deux certificats.

Un renouvellement ordinaire peut être signé par l'émetteur délégué de §3.4.
Toute autre raison exige `CA-PQ`. Astra construit d'abord un
`ClientCertificateStageAuthorization` :

```text
"helios-client-certificate-stage-authorization-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16 || ca_epoch:u64 || ca_tls_epoch:u64
|| issuer_kind:u8 || issuer_epoch:u64
|| issuer_authorization_fingerprint:32
|| stage_id:16 || request_fingerprint:32
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| client_wg_public_key:32
|| active_generation:u64 || next_generation:u64
|| active_tls_certificate_fingerprint:32
|| active_pq_certificate_fingerprint:32
|| next_tls_ca_certificate_fingerprint:32
|| SHA-256(next_tls_certificate_der):32
|| next_pq_certificate_fingerprint:32
|| issued_at:u64 || stage_expires_at:u64
|| not_before:u64 || activation_at:u64 || not_after:u64
|| reason:u8
```

`stage_id` est aléatoire, non nul et unique. `issuer_kind` vaut `master` ou
`astra`; dans le premier cas `issuer_authorization_fingerprint` est nul et la
signature se vérifie directement sous `CA-PQ`. Dans le second, l'autorisation
complète de §3.4 est transportée et son empreinte est vérifiée avant la
signature opérationnelle. Les raisons `expired_recovery`, `readmission`,
`emergency_replacement` et `manual_global` sont interdites à l'émetteur Astra,
sauf que `manual_global` peut viser des leafs actives si la campagne YubiKey ne
change ni admission, ni autorité, ni politique.

Orion remet cette autorisation à Helios dans WireGuard quand le tunnel existe.
Pour la récupération de §7.5, Astra la remet par son veth privé. Helios vérifie
la propriété du pair, les empreintes, la génération, la révocation et la
signature. Il exige
`issued_at < stage_expires_at <= min(request.expires_at, activation_at)` et une
lease d'au plus 24 heures, puis persiste le candidat dans l'état
`pending_grant` avant toute réponse. Ce candidat n'est pas encore un slot
`next` activable.

### 7.3 Reçu Helios et grant final

Après synchronisation de l'admission, Helios produit :

```text
GatewayCertificateStageReceipt {
    format_version: 1,
    protocol_version: 5,
    trust_domain_id,
    stage_id,
    stage_authorization_fingerprint,
    request_fingerprint,
    gateway_wg_public_key,
    client_wg_public_key,
    active_generation,
    staged_generation,
    staged_tls_certificate_fingerprint,
    staged_pq_certificate_fingerprint,
    persisted_at,
    stage_expires_at,
    active_gateway_identity_epoch,
    gateway_decision_epoch,
    gateway_certificate_fingerprint,
    gateway_signature
}
```

La signature ML-DSA-87 de la leaf gateway active couvre tous les champs sous le
domaine `helios-gateway-certificate-stage-receipt-v5`. Un reçu n'est émis
qu'après écriture atomique, `fsync` du fichier et de son répertoire compris. Un
rejeu strictement identique est idempotent ; le même `stage_id` avec d'autres
octets est un conflit.

Astra vérifie la leaf gateway, le reçu et l'égalité de chaque champ avec
l'autorisation, puis construit `ClientCertificateRotationGrant`. Sa signature
couvre :

```text
"helios-client-certificate-rotation-grant-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16 || ca_epoch:u64 || ca_tls_epoch:u64
|| issuer_kind:u8 || issuer_epoch:u64
|| issuer_authorization_fingerprint:32
|| request_fingerprint:32 || stage_receipt_fingerprint:32
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| client_wg_public_key:32
|| active_generation:u64 || next_generation:u64
|| active_tls_certificate_fingerprint:32
|| active_pq_certificate_fingerprint:32
|| next_tls_ca_certificate_fingerprint:32
|| SHA-256(next_tls_certificate_der):32
|| next_pq_certificate_fingerprint:32
|| stage_expires_at:u64
|| not_before:u64 || activation_at:u64 || not_after:u64
|| reason:u8
```

Le grant transporte les deux certificats, le reçu, et éventuellement
`AstraIssuerAuthorization`. Orion recalcule leurs empreintes, vérifie la chaîne
TLS, la chaîne PQ, les usages, la demande locale, le reçu Helios, les périodes
et la signature finale avant toute écriture. Il retrouve les deux clés privées
locales correspondantes puis persiste la génération candidate, encore marquée
`pending_commit`. Elle ne peut pas être présentée à `activation_at` avant le
commit ci-dessous.

Orion envoie ensuite un `ClientCertificateStageCommit` qui lie `stage_id`,
l'empreinte du grant et du reçu, la clé WireGuard cliente, les générations
active et candidate, les deux nouvelles empreintes, `stage_expires_at` et
`committed_at`. Les octets canoniques sous le domaine
`helios-client-certificate-stage-commit-v5` portent une signature de la clé PQ
active et une de la clé PQ candidate. En renouvellement ordinaire, le commit
voyage dans WireGuard et Helios exige la source exacte du pair. En récupération
expirée, Orion le remet à Astra avec l'opération YubiKey encore valide ; Astra
le relaie par le veth et Helios exige en plus l'autorisation de récupération
signée. Ce repli précis n'est accepté pour aucun stage ordinaire.

```text
"helios-client-certificate-stage-commit-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16 || stage_id:16
|| grant_fingerprint:32 || stage_receipt_fingerprint:32
|| gateway_wg_public_key:32 || client_wg_public_key:32
|| active_generation:u64 || staged_generation:u64
|| staged_tls_certificate_fingerprint:32
|| staged_pq_certificate_fingerprint:32
|| stage_expires_at:u64 || committed_at:u64
```

Helios exige dans les deux cas le candidat `pending_grant` exact, les deux
signatures et le grant complet. Sous le même sérialiseur que la révocation et
la purge, il lit l'horloge une fois et exige à la fois
`committed_at < stage_expires_at` et `now < stage_expires_at`; un client ne
peut pas antidater un commit arrivé trop tard. Il transforme atomiquement le
candidat en `next_committed`, synchronise, puis répond de façon idempotente.
Orion ne transforme son propre candidat en `next` activable qu'après ce succès.

À `stage_expires_at`, Helios purge automatiquement un `pending_grant` non
committé : retrait du candidat puis persistance de l'état vide sous le verrou,
avant de notifier Astra. Orion purge de même `pending_commit` dès qu'un état
Helios signé confirme l'expiration. Un commit tardif, un ancien grant et une
autorisation de staging expirée sont refusés. Après la purge, une nouvelle
demande peut réutiliser `active + 1` avec un nouveau `stage_id` ; aucun objet de
l'ancien stage n'est valable pour ce nouvel identifiant. `revoked` domine la
purge comme le commit.

À partir de `activation_at`, seule une génération `next_committed` peut être
utilisée ; l'ancienne reste admise jusqu'à `not_after`.

Un changement de clé WireGuard cliente suit le protocole de réadmission, pas ce
grant.

### 7.4 Compromission cliente

Une identité cliente soupçonnée compromise ne bénéficie pas du chevauchement
normal. L'opérateur exécute la révocation d'admission existante `peer remove`,
qui domine tout état `next`, puis réadmet le poste avec une invitation portant
explicitement `allow_readmission`. Une demande signée seulement par une clé
soupçonnée compromise n'autorise jamais une rotation d'urgence.

### 7.5 Récupération d'une identité expirée

Une leaf expirée reste refusée par mTLS, QUIC et les validateurs ordinaires.
Elle peut seulement être la preuve historique d'une
`ExpiredCertificateRecoveryRequest`, envoyée à l'origine HTTPS Astra puisque
WireGuard peut ne plus exister. L'objet reprend les champs et preuves de §7.1,
ajoute les certificats actifs expirés complets, un `astra_challenge` de 32
octets, `credential_id`, `created_at` et `expires_at` avec cinq minutes au plus.

Les signatures ancienne et suivante couvrent :

```text
"helios-expired-client-certificate-recovery-request-v5"
|| trust_domain_id:16 || astra_challenge:32
|| request_id:16
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| client_wg_public_key:32
|| expired_generation:u64 || requested_generation:u64
|| expired_tls_certificate_fingerprint:32
|| expired_pq_certificate_fingerprint:32
|| SHA-256(tls_csr_der):32
|| len(new_ml_dsa_87_public_key):u32 || new_ml_dsa_87_public_key
|| credential_id_fingerprint:32
|| created_at:u64 || expires_at:u64
```

Le challenge WebAuthn présenté à la YubiKey est :

```text
SHA-256(
  "helios-astra-expired-recovery-approval-v5"
  || request_fingerprint:32
  || astra_challenge:32
  || expires_at:u64
)
```

Astra exige `userVerification` et `userPresence`, l'origine exacte et le RP ID
du profil, et un credential opérateur `active` du domaine, puis consomme le
challenge. Le manifeste présenté par `astra-signer` borne cette autorisation au
pair, aux empreintes et à la génération demandée. Le validateur historique
contrôle signature, chaîne, identités, empreintes et dernière génération
enregistrée, mais ne contrôle pas la période ; il est un type séparé et ne peut
pas être appelé par la négociation.

La récupération est refusée si le pair est absent ou `revoked`, si une
génération plus récente existe, si l'ancienne clé n'est plus possédée ou si les
nouvelles preuves échouent. `CA-PQ`, jamais l'émetteur Astra, autorise alors le
staging de §7.2 : `astra-signer` ouvre localement le coffre, signe
l'autorisation exacte puis Astra la remet à Helios par le veth privé. Astra
attend le reçu §7.3 avant de remettre le grant. Si l'ancienne clé privée a
disparu avec le stockage DPAPI/TPM, cette procédure ne s'applique pas : il faut
une réadmission opérateur à deux YubiKeys.

Une seule YubiKey suffit ici parce qu'elle ne constitue pas l'unique preuve :
la clé PQ privée de la dernière génération admise signe aussi le challenge, la
clé WireGuard et les nouvelles clés, et la récupération ne peut changer ni le
pair ni le domaine. La réadmission sans cette preuve historique peut créer une
nouvelle continuité et exige donc la confirmation de deux YubiKeys. Voler
l'ancienne clé **et** obtenir l'approbation d'une YubiKey compromet néanmoins
ce chemin ; c'est le risque résiduel explicitement accepté du modèle v1. Une
politique de domaine peut exiger deux YubiKeys aussi pour la récupération, mais
ne peut jamais descendre sous une.

### 7.6 Campagnes manuelles et rollback

Une action manuelle crée un `AstraRotationCampaign` qui contient :

- `campaign_id`, `trust_domain_id`, la gateway et la période de cinq minutes ;
- `scope` : `orion_profile`, `orion_device`, `fleet_leafs`,
  `full_certificate_chain` ou `trust_authorities` ;
- pour chaque cible, type, clé WireGuard, époque, génération et empreintes
  actives exactes ;
- `reason`, `requested_by` et le hash de politique Astra ;
- le nombre de credentials opérateur exigé.

La YubiKey approuve le SHA-256 de la représentation canonique complète sous le
domaine `helios-astra-rotation-campaign-approval-v5`. Astra refuse toute cible
ajoutée, retirée ou modifiée après cette approbation. `orion_device` ne vise que
les profils Helios présents sur cet appareil ; `fleet_leafs` ne tourne aucune
CA ; `full_certificate_chain` ordonne émetteur, CA TLS, gateway puis clients ;
`trust_authorities` tourne aussi `CA-PQ` et exige deux credentials opérateur.

Astra signe ensuite `AstraSignerRequest` de §2.4. Orion ou la console ouvre le
compagnon local avec seulement `authority_url` et `operation_id` ; le compagnon
récupère lui-même la requête et le manifeste, vérifie leurs signatures et
affiche au minimum le scope, le nombre de cibles, les empreintes actives, les
générations et les autorités touchées. Pour une simple opération déléguée, il
renvoie l'assertion FIDO liée au manifeste. Quand `CA-PQ` ou `CA-TLS` doit
signer, il télécharge aussi le coffre chiffré, l'ouvre avec le ou les key-slots
exigés, produit localement les signatures puis zéroïse les clés. Il ne renvoie
jamais le secret PRF, une clé de déverrouillage ou une clé privée.

Un rollback manuel produit `CertificateServiceRollbackAuthorization`, lié à
la transition, au slot sélectionné, à la campagne YubiKey et à une échéance au
plus égale à `not_after`. Il ne change ni génération ni contenu des slots. La
sélection de l'ancienne identité est refusée après promotion ou révocation.

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
de §8.4. Il n'accepte jamais pour autant un certificat expiré, une génération
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
|| astra_service_key_epoch:u64 || issuer_epoch:u64
|| active_gateway_identity_epoch:u64 || gateway_decision_epoch:u64
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

La réponse `200 OK` contient le statut Astra signé de l'identité cliente et,
facultativement, un `TrustUpdateChunk`; l'absence de chunk signifie que la
confiance est à jour. Tous les objets sont pré-signés par Astra ou l'autorité
maîtresse ; la gateway n'appelle jamais une clé CA et ne réalise aucune
signature de CA à la demande. Les erreurs HTTP sont volontairement grossières :
`400` pour le JSON ou la version, `401` si la source n'est pas un pair admis,
`403` pour une identité, un certificat ou une signature refusés, `413` au-delà
de 32 Kio, `415` hors JSON et `500` après une erreur interne. Le motif détaillé
reste dans le journal protégé de la gateway.

Une suite qui ne tient pas dans 64 Kio reste **une seule transaction logique**.
Son `TrustUpdateTransactionManifest` contient un `transaction_id`, la cible et
son snapshot complet de compteurs et d'empreintes, `created_at`, `expires_at`,
`chunk_count`, la liste ordonnée des empreintes d'objets, leurs dépendances,
l'instant d'activation minimal et l'autorité du manifeste. Une transaction qui
touche CA, clé de service ou identité gateway est signée par `CA-PQ`; une
transaction limitée à un renouvellement client ordinaire peut être signée par
la clé de service Astra active. La signature couvre le manifeste canonique
complet. Chaque chunk répète son empreinte, porte son index et contient des
objets complets contigus ; un objet individuel encodé au-delà de 60 Kio est
refusé à l'émission et n'est jamais fragmenté.

```text
"helios-trust-update-transaction-manifest-v5"
|| format_version:u16 || protocol_version:u16
|| transaction_id:16 || trust_domain_id:16
|| gateway_wg_public_key:32 || client_wg_public_key:32
|| SHA-256(base_state_canonical):32
|| created_at:u64 || expires_at:u64 || minimum_activation_at:u64
|| chunk_count:u16 || object_count:u16
|| repeated(object_kind:u8 || object_fingerprint:32
            || prerequisite_bitmap:u64)
|| manifest_authority_kind:u8 || manifest_authority_epoch:u64

"helios-trust-update-chunk-v5"
|| manifest_fingerprint:32
|| chunk_index:u16 || chunk_count:u16
|| first_object_index:u16 || contained_object_count:u16
|| repeated(object_length:u32 || complete_object_bytes)
```

`base_state_canonical` contient tous les compteurs et empreintes actives,
suivantes, pending et tombstones connus de la cible. `prerequisite_bitmap`
référence uniquement des objets d'indice inférieur, `object_count` est borné à
64 et les bits hors de cette borne sont refusés. Le manifeste et chaque objet
ont leur signature propre ; le chunk est lié par les empreintes du manifeste
et des objets.

Orion vérifie le manifeste sous une autorité déjà fiable, puis stocke les
chunks dans un espace `pending_transaction` invisible aux slots actifs et
suivants. Chaque chunk est rejouable à l'identique ; même index ou même
`transaction_id` avec d'autres octets est un conflit. Quand tous les chunks
sont présents, Orion reconstruit une vue temporaire, vérifie chaque objet et
ses dépendances dans l'ordre `CA-PQ -> CA-TLS -> clé de service Astra ->
gateway -> client`, puis compare de nouveau le snapshot à l'état vivant. Une
seule écriture atomique publie alors simultanément les slots de confiance
suivants et, s'il existe, le candidat client en `pending_commit`, avec un reçu
local de transaction. Ce candidat ne devient `next` qu'après le commit Helios
de §7.3. Un échec laisse l'état vivant intact.

Les chunks incomplets sont supprimés à `expires_at`. Si l'horloge a atteint
l'instant d'activation minimal avant le commit, ou si le snapshot vivant a
changé, la transaction entière est refusée et doit être réémise ; aucun objet
pending ne devient actif avec le temps. Ainsi, une coupure après la CA mais
avant la gateway ne produit jamais un magasin de confiance mixte visible. La
limite de 64 Kio fractionne le transport, pas l'atomicité ni la décision.

### 8.2 Canal public Astra

Le profil contient `authority_url` et `webauthn_rp_id`. Orion contacte Astra
directement, jamais à travers le port QUIC, sur des routes versionnées :

```text
POST /v1/status/challenge
POST /v1/status/query
POST /v1/client-rotation/request
POST /v1/client-rotation/recovery
POST /v1/client-rotation/stage-commit
POST /v1/campaigns
GET  /v1/operations/<operation_id>
GET  /v1/signer-requests/<operation_id>
GET  /v1/vaults/<encrypted_vault_fingerprint>
POST /v1/signer-results/<operation_id>
```

Le service exige HTTPS, refuse toute origine WebAuthn différente et n'active
aucun CORS permissif. Les corps sont limités à 64 Kio avant désérialisation,
les réponses à 128 Kio, les identifiants opaques à 128 octets et les listes de
campagne à 256 cibles. Les budgets s'appliquent par IPv4 ou préfixe IPv6 `/64`,
credential, pair et domaine. Les erreurs publiques ne distinguent pas pair
inconnu, révoqué ou credential absent avant une preuve valide.

Aucun statut n'est indexable publiquement par une empreinte seule. Un Orion
actif le récupère dans WireGuard par §8.1. Hors tunnel,
`POST /v1/status/challenge` produit 32 octets aléatoires, valables 60 secondes
et à usage unique sans confirmer l'existence d'une cible. La requête
`POST /v1/status/query` contient le challenge, le certificat PQ complet, le
domaine, les deux clés WireGuard, l'empreinte visée, un `request_id` et une
signature fraîche par la clé PQ correspondante sous le domaine
`helios-astra-certificate-status-query-v5`. Le validateur ordinaire est employé
pour une leaf valide ; le validateur historique séparé de §7.5 peut seulement
répondre sur cette même identité expirée. Un opérateur interroge le parc par une
campagne YubiKey, jamais par énumération d'empreintes.

Astra consomme le challenge avant de produire le statut. Une preuve invalide,
une cible absente ou un certificat remplacé sans preuve de la dernière
génération renvoient la même réponse bornée ; le détail reste dans l'audit
protégé. Une preuve valide de la dernière identité peut recevoir le statut
signé `revoked`, sans droit de rotation. Connaître une empreinte observée sur le
réseau ne révèle donc ni génération, ni fenêtre, ni calendrier de rotation.

Les trois routes du compagnon exigent un jeton de capacité court lié à
`operation_id`, au hash du manifeste et à cinq minutes au plus. Le coffre n'y
est servi que chiffré et son empreinte appartient à `AstraSignerRequest`. Le
résultat contient assertions et objets signés, jamais une sortie PRF ou du
matériel privé. Un résultat rejoué à l'identique est idempotent ; tout écart
sur le même identifiant est un conflit. Le navigateur ne reçoit pas ce jeton
et ne décide jamais qu'une signature a réussi : les IHM interrogent l'état
signé de l'opération.

Astra publie un statut signé :

```text
AstraCertificateStatus {
    format_version: 1,
    trust_domain_id,
    certificate_fingerprint,
    certificate_kind,
    generation,
    status: active | renewal_due | pending_grant | pending_commit | staged |
            published | aborted | overlap | expired | revoked,
    suggested_window_start,
    suggested_window_end,
    produced_at,
    next_update,
    status_epoch,
    astra_service_key_epoch,
    astra_signature
}
```

La signature couvre la forme canonique sous le domaine
`helios-astra-certificate-status-v5`. `status_epoch` monte pour chaque mutation
de la cible sous une même clé. Orion vérifie la signature, les identités et la
monotonie lexicographique `(astra_service_key_epoch, status_epoch)` avant
d'afficher ou planifier, mais calcule toujours lui-même la validité du
certificat. `active` signifie « non révoqué dans l'état Astra », jamais
« acceptable hors de `not_before..not_after` ».

Une réponse Astra peut avancer `suggested_window_start`, par exemple pour une
campagne d'incident, mais ne peut pas placer son début après le `renewal_at`
local de §4.3 ni sa fin après l'expiration. Orion choisit un instant stable
uniformément distribué dans la fenêtre et persiste son choix.

### 8.3 Canal privé Astra–Helios

Astra et Helios communiquent sur une paire veth dédiée. Le namespace Astra n'a
ni route par défaut sur cette interface, ni forwarding, ni accès aux adresses
de pairs. Le pare-feu autorise exclusivement une API privée mutuellement
authentifiée :

```text
POST /internal/v1/certificates/stage
POST /internal/v1/certificates/stage-commit
POST /internal/v1/certificates/revoke
GET  /internal/v1/certificates/state/<identity>
POST /internal/v1/campaigns/apply
```

Les clés du transport sont des identités de service séparées, rotables sans
modifier `CA-PQ`. Elles authentifient le processus et chiffrent le lien ; les
objets de mutation restent signés par l'autorité appropriée et les reçus par la
leaf gateway. Le canal ne sérialise jamais de clé privée, de PSK, de secret TPM
ou de vue complète non expurgée de `network.toml`.

Le transport impose TLS 1.3 avec échange éphémère `(EC)DHE`; le mode
`psk_ke` sans Diffie-Hellman, TLS 1.2, le 0-RTT et les tickets de reprise sont
désactivés. Les certificats mTLS ne servent qu'à authentifier l'échange et ne
doivent pas permettre de reconstruire les clés de session après leur
compromission. Cette forward secrecy protège les captures contre une perte
ultérieure des clés de service ; les signatures applicatives restent
nécessaires pour l'autorisation et l'anti-rollback.

Helios vérifie l'autorisation puis applique admission, génération et
révocation par `helios_provisioning::admission`. Astra ne réalise jamais de
*read-modify-write* du fichier de configuration. Une réponse de succès n'est
envoyée qu'après la persistance décrite au §7.3.

Ce canal est le chemin de staging d'une récupération expirée, parce que le
tunnel WireGuard n'existe alors potentiellement plus. Il n'est pas un repli
pour une demande ordinaire venant d'un Orion actif : celle-ci passe dans
WireGuard afin de conserver la preuve du pair source.

### 8.4 Document hors ligne

Les mêmes objets peuvent être placés dans un document JSON
`orion-trust-update` signé et transféré par un canal non fiable. Le document
porte `format_version = 1`, `trust_domain_id`, au plus une transition de chaque
type, leurs empreintes ordonnées et une signature `CA-PQ` sur sa forme JCS. La
signature doit se vérifier sous la CA active au **début** de l'import ; cette CA
vient du profil local, jamais du document seul. Chaque objet embarqué conserve
en plus sa propre signature normative.

Un client qui ne peut joindre Astra, qui a manqué une transition de CA ou qui
est resté hors ligne au-delà du chevauchement utilise ce document. La
récupération ordinaire d'une leaf cliente expirée suit §7.5 ; le document reste
le chemin contrôlé lorsque le service public est indisponible. Une leaf expirée
n'est jamais réacceptée pour télécharger sa propre mise à jour.

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
CA restent confinées dans le coffre maître ouvert par le compagnon Astra.
L'ancienne clé privée peut
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

### 9.5 Rotation de l'émetteur Astra

L'émetteur opérationnel est renouvelé avant son `not_after`, sous une nouvelle
`issuer_epoch`. La campagne exige une YubiKey opérateur parce qu'elle modifie
la capacité de signature en ligne, même si elle ne tourne aucune ancre. Astra
génère et scelle localement ses nouvelles clés, le compagnon opérateur ouvre le
coffre maître et produit `AstraIssuerAuthorization`, puis Helios et Orion
installent l'autorisation suivante avant toute leaf sous le nouvel émetteur.

Deux émetteurs sont acceptés au plus pendant le chevauchement. Une délégation
expirée ou révoquée ne peut plus émettre ; les leafs déjà installées restent
vérifiables sous leur chaîne jusqu'à leur propre échéance ou révocation. Une
rotation d'émetteur n'avance aucun compteur de leaf.

### 9.6 Rotation de la clé de service Astra

La clé de service épinglée est distincte de l'émetteur et du certificat HTTPS.
Elle suit `AstraServiceKeyTransition`, qui contient `trust_domain_id`,
`ca_epoch`, les époques courante et suivante, l'empreinte courante, la nouvelle
clé publique ML-DSA-87, sa preuve de possession, la fenêtre de §4.1, le motif et
trois signatures sur les mêmes octets canoniques : clé de service courante,
nouvelle clé et `CA-PQ`.

```text
"helios-astra-service-key-transition-v5"
|| format_version:u16 || trust_domain_id:16 || ca_epoch:u64
|| current_service_key_epoch:u64 || next_service_key_epoch:u64
|| current_service_key_fingerprint:32
|| len(next_service_public_key):u32 || next_service_public_key
|| next_service_key_fingerprint:32
|| not_before:u64 || activation_at:u64 || not_after:u64
|| reason:u8
```

Une rotation planifiée exige exactement `current + 1` et les trois signatures.
Le profil conserve les clés active et suivante au plus. Pendant le
chevauchement, chaque réponse indique explicitement
`astra_service_key_epoch`; après `retire_active_at`, l'ancienne clé est refusée
même pour un `status_epoch` supérieur. La transition arrive dans la transaction
de confiance de §8.1 ou dans un document hors ligne signé ; elle n'est jamais
apprise d'une réponse publique autorisée seulement par la clé qu'elle remplace.

Si la clé courante est compromise, sa signature n'a plus de valeur. Un
`EmergencyAstraServiceKeyReplacement` signé par `CA-PQ` et par la nouvelle clé
porte l'empreinte retirée, `current + 1`, un `revocation_epoch` et un effet
immédiat. Il est distribué dans WireGuard ou hors ligne, retire l'ancienne clé
sans chevauchement et invalide challenges, opérations et callbacks qu'elle a
signés. Une réponse en cours doit alors être recommencée avec un nouvel
`operation_id`. L'URL HTTPS et le RP ID restent stables ; leur certificat de
transport suit sa PKI Web et ne peut modifier la clé applicative épinglée.

```text
"helios-astra-service-key-emergency-replacement-v5"
|| format_version:u16 || trust_domain_id:16 || ca_epoch:u64
|| current_service_key_epoch:u64 || next_service_key_epoch:u64
|| revoked_service_key_fingerprint:32
|| len(next_service_public_key):u32 || next_service_public_key
|| next_service_key_fingerprint:32
|| revocation_epoch:u64 || effective_at:u64
|| reason:u8
```

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

Astra publie immédiatement le nouvel état signé et refuse toute rotation,
récupération expirée, campagne ou rollback visant l'identité révoquée. La route
privée sérialise la révocation avec un staging concurrent ; si la révocation
gagne, aucun reçu de staging valide n'est produit, et si le staging avait été
persisté elle retire les deux générations. Aucun credential YubiKey ne peut
lever `revoked` : seule une réadmission explicite crée une nouvelle admission.

## 11. Ordre des opérations

### 11.1 Renouvellement gateway normal

1. Générer et sceller la nouvelle clé sur la gateway.
2. Exporter et vérifier `GatewayCertificateRequest`.
3. Créer une campagne Astra liée aux empreintes actives et obtenir
   l'approbation d'une YubiKey opérateur.
4. Émettre la leaf PQ sous `CA-PQ` et, si nécessaire, la nouvelle leaf TLS,
   puis signer `GatewayIdentityTransition` dans le compagnon opérateur.
5. Installer et synchroniser clé, certificats et transition sur la gateway sans
   modifier l'identité servie. Tant que l'étape 6 n'a pas commencé, l'opérateur
   peut encore appliquer l'avortement signé de §6.3 ; l'époque est consommée.
6. Persister `published` avant de distribuer la transition aux clients, puis
   mesurer ceux qui l'ont persistée. Après ce point, aucun avortement ordinaire
   n'est permis.
7. À `activation_at`, redémarrer `heliosd` sur la nouvelle identité.
8. Pendant le chevauchement, autoriser un rollback vers l'ancienne identité.
9. À `not_after`, promouvoir la nouvelle et détruire l'ancienne clé privée
   scellée après synchronisation de l'état promu.

Une étape ne peut être inversée avec la suivante. En particulier, la gateway
ne sert jamais une leaf dont la transition n'est pas déjà publiée, et Orion ne
supprime jamais l'ancien pin avant la fin du chevauchement.

### 11.2 Renouvellement client normal

1. À l'instant choisi dans la fenêtre ouverte à 80 %, générer puis sceller les
   nouvelles clés dans Orion.
2. Produire la demande et les trois preuves de possession/continuité.
3. Astra vérifie admission, révocation, fenêtre, délégation et génération, puis
   émet les deux certificats et `ClientCertificateStageAuthorization`.
4. Orion remet l'autorisation à Helios dans le tunnel WireGuard.
5. Helios installe et synchronise la génération suivante, puis signe
   `GatewayCertificateStageReceipt`.
6. Astra vérifie le reçu, signe et distribue le grant.
7. Orion vérifie reçu et grant, persiste le candidat puis envoie
   `ClientCertificateStageCommit` dans WireGuard.
8. Helios committe atomiquement le slot et Orion ne le rend activable qu'après
   le succès ; sans commit avant `stage_expires_at`, les deux purgent le stage.
9. Orion bascule à `activation_at` et une connexion v5 réussie marque la
   nouvelle génération observée.
10. Les deux bouts retirent l'ancienne à `not_after`.

### 11.3 Récupération cliente après expiration

1. Orion contacte Astra en HTTPS, obtient un challenge frais, génère et scelle
   les nouvelles clés.
2. Il produit `ExpiredCertificateRecoveryRequest` avec les preuves ancienne et
   nouvelle.
3. Orion lance `astra-signer`, qui affiche la cible ; la YubiKey opérateur
   approuve le hash exact et ouvre localement le coffre maître.
4. Astra vérifie la dernière génération historique et l'absence de révocation,
   puis le compagnon signe l'autorisation exacte par `CA-PQ`.
5. Astra remet l'autorisation à Helios par le veth privé.
6. Helios persiste la génération suivante et signe le reçu.
7. Astra signe le grant seulement après ce reçu et le remet à Orion.
8. Orion persiste le candidat et signe le commit ; Astra le relaie à Helios sur
   le veth sous l'autorisation de récupération encore valide.
9. Après le commit Helios, Orion active la nouvelle identité, négocie le PSK v5
   puis monte WireGuard.

La leaf expirée ne franchit aucune étape de négociation. Elle prouve seulement
la continuité au point 2. Sans ancienne clé privée, le chemin s'arrête avant le
point 3 et devient une réadmission à deux YubiKeys.

### 11.4 Rotation de CA normale

1. Créer une campagne `trust_authorities` et recueillir deux approbations
   YubiKey opérateur distinctes.
2. Créer la nouvelle CA dans le compagnon opérateur en conservant le même
   `trust_domain_id`.
3. Produire la transition `N -> N+1`, signée par les deux CA.
4. Publier durablement la transition numérotée dans Astra.
5. La distribuer aux gateways et clients avant toute leaf sous la nouvelle CA.
6. Préparer les nouvelles leafs, puis les activer dans leur propre transition.
7. À `not_after`, promouvoir la CA et retirer l'ancienne ancre.

### 11.5 Rotation de la CA TLS cliente

1. Produire la nouvelle CA TLS et `ClientTlsCaTransition` dans l'autorité
   opérateur.
2. Installer et synchroniser la CA suivante sur la gateway.
3. Émettre les grants clients dont la leaf TLS chaîne vers cette CA.
4. Activer la CA et les générations clientes à leurs dates liées.
5. Retirer l'ancienne CA seulement après la fin du chevauchement.

### 11.6 Campagne manuelle globale

1. L'IHM Orion ou Helios demande à Astra un manifeste de campagne résolu sur
   les cibles et générations actuelles.
2. L'utilisateur vérifie le résumé sur l'origine Astra et approuve avec la ou
   les YubiKeys exigées.
3. Astra fige le manifeste ; toute évolution concurrente d'une cible la marque
   en conflit au lieu de recalculer silencieusement la campagne.
4. Les objets sont produits dans l'ordre `CA-PQ -> CA-TLS -> émetteur Astra ->
   clé de service Astra -> gateway -> clients`, en omettant les familles hors
   du scope choisi.
5. Chaque cible passe par son staging et son reçu propre. Un échec n'annule pas
   une cible déjà promue, mais arrête ses dépendants et laisse un bilan signé.
6. Les IHM affichent succès, conflit, refus et action de récupération par cible.

« Renouveler les leafs du parc » ne tourne ni CA ni émetteur. « Renouveler toute
la chaîne » tourne l'émetteur, la CA TLS, la gateway et les leafs clientes mais
pas `CA-PQ`. « Tourner les autorités » est une campagne distincte à deux
YubiKeys ; aucune formulation courte ne l'assimile à un renouvellement banal.

## 12. Périmètre d'implémentation du cycle complet

### 12.1 Obligatoire pour déclarer le cycle de vie implémenté

- émission du certificat PQ gateway par `CA-PQ` ;
- `trust_domain_id` et tous les compteurs monotones de §4.2 ;
- migration explicite du profil Orion vers le discriminant
  `helios_key_negotiation`, sans reclassement par absence de champ ;
- enrôlement v5 sans clé privée dans le document et signature opérateur, afin
  que la confiance initiale en `CA-PQ` ne soit pas apportée par l'objet qu'elle
  signe elle-même ;
- deux ancres `CA-TLS` clientes au plus ;
- coordinateur Astra co-implanté, état sauvegardé et conteneur durci ;
- canal HTTPS public, identité de service et veth privé mutuellement
  authentifié sans forwarding, TLS 1.3 `(EC)DHE` sans reprise ni 0-RTT ;
- coffre maître HVLT à deux key-slots YubiKey, compagnon de signature et
  procédures d'ajout, perte et remplacement d'un credential ;
- `AstraIssuerAuthorization`, intermédiaire TLS et émetteur ML-DSA-87 délégué,
  avec portée et validité vérifiées par Helios et Orion ;
- états `active + next` bornés pour gateway, client et CA ;
- association atomique des empreintes TLS/PQ clientes ;
- formats signés des §§3.4 à 10 et parseurs stricts ;
- rotation planifiée et remplacement d'urgence de la clé de service Astra ;
- requête de statut authentifiée, sans lecture publique par empreinte ;
- route interne authentifiée `POST /api/key-negotiation/trust-update` ;
- transaction de confiance chunkée mais atomique, dont les fragments restent
  invisibles avant le commit local ;
- staging client à lease bornée, reçu signé Helios, commit Orion et purge
  automatique ; grant impossible avant le reçu et activation impossible avant
  le commit ;
- planificateur à 80 %, fenêtres Astra et alertes 90/95 % ;
- récupération publique d'une identité expirée avec ancienne preuve, nouvelle
  preuve et YubiKey opérateur, sans réacceptation dans QUIC ;
- campagnes manuelles et rollback de service borné ;
- import manuel d'un document `orion-trust-update` ;
- persistance atomique, promotion et suppression définitive ;
- sérialisation de la révocation d'admission, de la génération cliente et du
  retrait du plan de données, afin que l'état terminal `revoked` domine aussi
  en concurrence ;
- affichage clair de l'état `active`, `pending_grant`, `pending_commit`,
  `staged`, `published`, `aborted`, `overlap`, `expired` ou `revoked` ;
- tests du §14.

Une livraison partielle peut être testée et déployée derrière un refus
explicite, mais ne doit pas être présentée comme « cycle de vie implémenté ».
En particulier, fournir seulement les types `active + next` sans le staging
avec reçu, ou Astra sans récupération expirée, laisse encore le parc se couper
sur une absence prolongée.

### 12.2 Surfaces Orion et Helios obligatoires

Orion ajoute une destination ou un sous-écran **Certificats** dans la surface
Profils. Il affiche, sans exposer de secret :

- leafs TLS/PQ active et suivante, générations, échéances et état Astra ;
- date choisie de renouvellement et dernière erreur ;
- credentials YubiKey opérateur enregistrés et disponibilité de la
  récupération ;
- actions « Renouveler maintenant », « Renouveler tous les profils Helios de
  cet appareil », « Récupérer le certificat expiré » et « Revenir
  temporairement à l'ancienne identité » quand la machine d'état l'autorise.

La console Helios ajoute **Certificats** à la destination Sécurité. Elle
affiche gateway, CA, émetteur Astra, couverture de sauvegarde, credentials
opérateur et synthèse du parc. Elle expose « Renouveler la gateway »,
« Renouveler les leafs du parc », « Renouveler toute la chaîne », « Tourner les
autorités », « Annuler la transition préparée » avant publication et le
rollback gateway pendant chevauchement. L'annulation explique qu'elle consomme
l'époque et qu'elle n'est plus disponible dès que la transition a pu être
distribuée.

Chaque action manuelle commence par créer une campagne ; l'IHM lance ensuite
le compagnon `astra-signer` avec seulement l'origine Astra et un
`operation_id`. Le compagnon dialogue directement avec la YubiKey et affiche
le manifeste ; l'IHM ignore un callback non signé, interroge l'état, vérifie le
résultat sous la clé de service Astra puis vérifie chaque objet sous sa propre
autorité. Le libellé montre avant approbation le nombre de cibles, les
générations et si une CA sera tournée. Aucune action globale n'est placée
derrière un bouton au libellé ambigu « Renouveler ».

### 12.3 Fonctions reportables après le cycle complet

- notifications par courrier ou messagerie externe ;
- coffre cryptographique M-sur-N et approbation par plusieurs identités
  d'opérateurs, plutôt que plusieurs clés 1-sur-N d'un même opérateur ;
- HSM ML-DSA-87 ou environnement attesté protégeant l'émetteur du noyau hôte ;
- campagnes multi-gateways sous un même domaine ;
- mesure de conformité exportée vers un SIEM.

Ces extensions ne peuvent augmenter le nombre de slots, ignorer une
génération, prolonger le chevauchement, réactiver une leaf expirée ou révoquée,
ni élargir une délégation Astra déjà signée.

## 13. Migration depuis la v5 actuellement servie

### 13.1 Installation neuve après implémentation du lot

Une installation neuve ne doit plus émettre de profil avec une leaf PQ gateway
auto-signée. L'enrôlement initial crée directement :

- `trust_domain_id` aléatoire ;
- `ca_epoch = 1` avec `current_ca_public_key` ;
- `ca_tls_epoch = 1` avec la CA TLS cliente active ;
- `active_gateway_identity_epoch = 1` et `gateway_decision_epoch = 1` ;
- les leafs gateway actives et aucun slot suivant ;
- `client_identity_generation = 1` pour chaque admission ;
- `revocation_epoch = 0` pour chaque identité ;
- deux credentials YubiKey opérateur vérifiés ;
- `astra_service_key_epoch = 1`, `issuer_epoch = 1`,
  `credential_registry_epoch = 1` et une délégation bornée ;
- `authority_url` et `webauthn_rp_id` dans chaque profil Helios.

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
   ML-DSA-87, importable dans le coffre maître Astra et confirmée hors bande ;
   son emplacement historique ne vaut jamais preuve d'identité.
3. Déployer Astra sans capacité de signature, importer le registre historique,
   enregistrer et tester les deux YubiKeys, puis sauvegarder le coffre HVLT et
   son audit avant toute mutation.
4. Créer la clé de service, l'émetteur opérationnel et
   `AstraIssuerAuthorization`, mais ne permettre aucune émission tant que
   Helios et Orion ne savent pas vérifier la délégation.
5. Générer dans un chemin de staging une nouvelle identité gateway, obtenir sa
   leaf PQ signée par `CA-PQ`, puis préparer l'état gateway de génération `1`.
   L'ancienne leaf auto-signée n'entre pas dans cet état cible.
6. Convertir chaque couple TLS/PQ client admis en génération cliente `1`, après
   vérification de sa chaîne, de ses clés et de l'unicité globale des deux
   empreintes. Une identité dont l'émetteur ou la clé privée locale ne peut pas
   être prouvé est ré-enrôlée ; elle n'est pas réparée par supposition.
7. Préparer pour chaque Orion un profil `helios_key_negotiation` épinglant
   `CA-PQ`, `trust_domain_id`, Astra et la nouvelle identité gateway. Le
   document ne transporte aucune clé privée et Orion ne l'active qu'après la
   confirmation hors bande. Il peut réutiliser une identité locale dont les
   clés publiques correspondent exactement à la génération cliente convertie.
8. Une fois tous les profils préparés, promouvoir atomiquement l'identité de
   staging et redémarrer `heliosd`, puis activer les profils préparés. Après ce
   point, le chemin cible refuse toute leaf gateway auto-signée.

L'étape 8 côté gateway et Orion forme une bascule coordonnée, avec une
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
- avortement gateway accepté seulement avant publication et activation,
  tombstone persisté, époque consommée et transition suivante obligatoirement
  séquentielle ;
- avortement refusé dans `published`, `overlap`, après promotion et pour une
  autre empreinte de transition ;
- avortement antidaté mais reçu après `activation_at` refusé sous l'horloge
  locale ;
- rollback vers l'ancienne leaf autorisé seulement pendant le chevauchement ;
- promotion définitive malgré un recul simulé de l'horloge ;
- refus de tous les couples mixtes TLS/PQ entre générations clientes ;
- unicité globale des empreintes actives et suivantes ;
- demande cliente : signature active, CSR TLS et preuve PQ suivante toutes
  obligatoires ;
- `AstraIssuerAuthorization` refusée sous une autre gateway, hors période, avec
  un usage ou plafond élargi, une politique différente ou une époque reculée ;
- émetteur Astra incapable d'enrôler, réadmettre, récupérer une leaf expirée,
  tourner une CA ou signer une génération sautée ;
- calcul exact de 80 %, sans overflow, instant dispersé stable après
  redémarrage et fenêtre Astra incapable de retarder le calcul local ;
- grant jamais émis avant un reçu Helios valide postérieur à la persistance de
  l'admission suivante ;
- candidat client jamais activable avant un commit signé par les clés active
  et suivante ; commit ordinaire refusé hors du tunnel du pair et commit de
  récupération refusé sans l'opération YubiKey exacte ;
- stage orphelin purgé à sa lease, commit tardif refusé et génération
  `active + 1` réutilisable seulement sous un nouveau `stage_id` ;
- commit arrivé à l'échéance ou antidaté après elle perdant la course face à
  la purge sous le même sérialiseur ;
- crash avant et après commit ou purge laissant exactement `pending_grant`,
  `next_committed` ou aucun candidat, jamais un état intermédiaire ;
- reçu refusé sous une autre leaf gateway, pour un autre `stage_id`, avec une
  empreinte ou génération différente ;
- même `stage_id` identique idempotent et conflit d'octets refusé ;
- récupération expirée refusée sans preuve ancienne, nouvelle preuve,
  YubiKey opérateur, challenge frais ou dernière génération exacte ;
- validateur historique inaccessible depuis mTLS et QUIC, où la leaf expirée
  reste refusée ;
- récupération et rollback refusés pour `revoked`, même avec deux YubiKeys ;
- récupération à une YubiKey refusée sans l'ancienne clé PQ et incapable de
  changer la clé WireGuard ; réadmission sans continuité exigeant deux
  confirmations ;
- mutation d'un octet de campagne, d'une cible ou de son ordre après
  approbation WebAuthn refusée ;
- ajout et retrait de YubiKey incapables de laisser zéro credential de secours ;
- rollback de service borné au chevauchement, sans baisse de compteur ni
  réapparition d'un slot supprimé ;
- transition CA refusée sans l'une des deux signatures ou avec un saut de
  génération ;
- transition `CA-TLS` refusée sans signature `CA-PQ`, avec une CA suivante
  incapable de vérifier sa propre auto-signature ou avant persistance gateway ;
- rotation planifiée de clé de service Astra refusée sans signatures ancienne,
  nouvelle et `CA-PQ`; remplacement compromis refusé sans `CA-PQ`, preuve de
  la nouvelle clé et avancement du compteur de révocation ;
- `status_epoch = u64::MAX` sous l'ancienne clé incapable de bloquer un statut
  à l'époque de service suivante ;
- statut public refusé avec une empreinte seule, un challenge expiré ou rejoué,
  et accepté seulement sous la preuve PQ de l'identité exacte ;
- application séquentielle de trois transitions CA hors ligne sans jamais
  conserver trois ancres simultanément ;
- révocation dominante dans chaque état et callback obsolète sans effet ;
- transaction chunkée `CA-PQ -> CA-TLS -> clé Astra -> gateway -> client`
  invisible tant qu'un chunk manque, publiée par une seule écriture si tout est
  valide et entièrement purgée à l'expiration ;
- transaction complète refusée si le snapshot vivant change ou si son instant
  d'activation est atteint avant le commit ;
- document JCS modifié, membre inconnu, membre dupliqué ou représentation non
  canonique refusé ;
- mélange d'un document destiné à une autre gateway ou à un autre domaine de
  confiance refusé ;
- taille de trame, nombre d'objets et coûts ML-DSA bornés ;
- réponse `404` d'une ancienne gateway à la route de mise à jour, sans repli
  vers QUIC, une leaf expirée, un pin unique ou un mode plus faible ;
- refus de la route depuis une source hors tunnel, une VIP inconnue, un pair
  différent de la clé signée ou une identité PQ d'une autre génération ;
- API Astra bornée par taille, nombre de cibles, identité et préfixe réseau,
  avec erreurs indifférenciées avant authentification ;
- route veth incapable d'atteindre un pair, le plan de données, les coffres ou
  une autre API Helios ;
- TLS veth refusant TLS 1.2, `psk_ke`, tickets de reprise et 0-RTT, avec clés de
  session différentes après chaque reconnexion ;
- fuzzing de tous les objets signés, de leurs certificats embarqués et de la
  machine d'état temporelle.

### 14.2 Essais d'intégration

- client resté hors ligne avant activation, pendant le chevauchement et après
  son terme ;
- client éteint pendant toute la fenêtre, revenu après expiration, récupéré par
  ancienne preuve + YubiKey + staging veth avant sa première nouvelle
  négociation ;
- même scénario avec ancienne clé DPAPI/TPM perdue, refusé puis réadmis par la
  procédure opérateur sans prétendre à une continuité ;
- import hors ligne après expiration du certificat PQ applicatif ou perte du
  tunnel ;
- bascule coordonnée d'un parc v5 actuel : profil préparé, identité gateway de
  staging promue, ancien certificat auto-signé définitivement refusé ;
- redémarrage de `heliosd` sur la nouvelle identité, puis rollback pendant la
  fenêtre ;
- avortement d'une identité gateway staged avant publication, client ayant
  persisté le tombstone puis nouvelle tentative à l'époque suivante ;
- crash avant et après chaque synchronisation de l'ordre §11 ;
- rotation cliente sous trafic, sans changement de clé WireGuard ni du PSK
  négocié courant ;
- rotation automatique à 80 % sans YubiKey et campagne manuelle identique avec
  YubiKey, toutes deux convergeant vers les mêmes objets ;
- campagne Orion sur tous les profils locaux et campagnes Helios
  `fleet_leafs`, `full_certificate_chain`, `trust_authorities`, avec bilan
  signé et conflits par cible ;
- perte de la YubiKey courante, ouverture par la clé de récupération,
  enregistrement d'une remplaçante puis révocation de la clé perdue ;
- panne Astra avant émission, après staging et après grant, sans leaf annoncée
  avant admission ni génération orpheline ;
- Orion disparu après reçu ou après grant : lease expirée, candidat Helios
  purgé, commit tardif refusé puis renouvellement suivant réussi ;
- redémarrage du conteneur Astra avec coffre maître toujours verrouillé et
  émetteur délégué borné inchangé ;
- rotation de CA suivie d'une rotation leaf sous la nouvelle CA ;
- rotation de clé de service Astra avec chevauchement, puis remplacement
  d'urgence sans accepter une réponse signée seulement par l'ancienne clé ;
- téléchargement d'une transaction de confiance en plusieurs chunks avec
  coupure entre chacun, aucun état partiel visible et commit atomique final ;
- révocation urgente gateway distribuée en ligne puis hors ligne ;
- attaque de gel simulée : la limite est visible et aucun état ne prétend avoir
  reçu une révocation absente ;
- coexistence inchangée d'un profil Orion `classic`, qui n'émet aucune requête
  de mise à jour Helios.

Les essais TPM réels, DPAPI, WireGuard-NT et redémarrage de la gateway restent
target-only. Une compilation WSL2 ne valide aucun de leurs effets.

## 15. Limites connues

**La récupération expirée exige encore l'ancienne clé et une YubiKey opérateur
du domaine.** Un client qui perd son stockage DPAPI/TPM ne prouve plus la
continuité ; il doit être réadmis. Un client qui a manqué une transition de CA
ou ne peut joindre Astra peut nécessiter un document hors ligne. Deux slots
bornent volontairement la complexité et la surface d'attaque.

**Astra co-implantée n'est pas un canal de fraîcheur indépendant de la
gateway.** Elle améliore la diffusion et l'audit quand l'hôte est honnête, mais
un attaquant qui contrôle la machine peut retenir à la fois statut et objet de
révocation. Le résoudre complètement demanderait un service extérieur
hautement disponible ou une distribution d'entreprise. La v5 échoue fermement
après les échéances ; elle ne prétend pas avoir reçu une révocation absente.

**La compromission de `CA-PQ` rompt la continuité automatique.** Une transition
signée par une CA compromise ne restaure pas la confiance. Une nouvelle
confirmation hors bande et, selon le périmètre, un ré-enrôlement sont
obligatoires.

**Le redémarrage de `heliosd` reste nécessaire pour une leaf gateway.** Le
format permet de préparer et distribuer la confiance sans coupure, mais
l'identité servie est toujours chargée une fois au démarrage. Astra peut
ordonner et observer le redémarrage ; elle ne le supprime pas.

**La CA reste mono-clé par génération.** La double signature de transition
protège la continuité, pas la compromission de la clé courante. Passer à un
seuil multi-signatures pour `CA-PQ` serait une nouvelle décision
d'architecture et un nouveau format.

**Deux YubiKeys de secours ne sont pas deux opérateurs.** Les key-slots v1 sont
1-sur-N afin qu'une clé perdue n'emporte pas le coffre. La confirmation par
deux clés limite les erreurs et l'usage API d'une clé volée avec un compagnon
honnête, mais un poste compromis après un déverrouillage peut extraire la CA.
Un vrai quorum exige un coffre à seuil et des identités humaines distinctes ;
la v1 ne revendique pas cette propriété.

**La leaf TLS gateway reste auto-signée et épinglée.** `CA-PQ` autorise son
remplacement, alors que la leaf PQ chaîne directement vers `CA-PQ`. Cette
asymétrie est volontaire : TLS fournit le transport épinglé et ML-DSA-87 porte
l'autorité applicative post-quantique. Un implémenteur ne doit ni tenter de
chaîner la leaf TLS vers `CA-TLS` cliente, ni laisser son ancien pin
s'auto-autoriser.

**La migration initiale reste une bascule coordonnée.** Avant que le profil
porte son discriminant et `CA-PQ`, aucun objet signé par la nouvelle CA ne peut
créer rétroactivement cette confiance. La promotion atomique de §13.2 est donc
le point de disponibilité le plus risqué du lot et peut provoquer une coupure ;
les slots et Astra ne suppriment pas cette frontière de bootstrap.

**Docker et le veth n'isolent pas Astra de `root`.** Un contrôle du noyau peut
voler ou employer la clé opérationnelle, modifier le coordinateur et présenter
une campagne mensongère au compagnon. La délégation en borne la durée et les
usages, et le compagnon empêche l'ouverture silencieuse du coffre maître sans
YubiKey ; protéger aussi l'émetteur demanderait un HSM ou un environnement
attesté portant ML-DSA-87. Cette limite est acceptée par ADR-008 pour une
gateway physiquement protégée et un domaine lié à une seule gateway.

**La perte simultanée des deux YubiKeys coupe l'autorité maîtresse.** Aucun
reset de compte Astra ou mot de passe ne contourne cette perte. Elle impose la
procédure de récupération physique du coffre prévue lors du bootstrap ou une
nouvelle ancre confirmée hors bande. La clé de récupération doit donc être
conservée séparément et testée.

**La co-implantation lie les disponibilités.** Une panne disque de la gateway
emporte Helios, Astra et son registre local. Un backup chiffré, atomique et
synchronisé du coffre, du registre et de l'audit sur un stockage extérieur est
obligatoire ; il reste inutilisable sans YubiKey. La restauration doit vérifier
le dernier hash d'audit connu et refuser un fork de génération.

## 16. Correspondance cible avec le code

| Composant | Responsabilité |
| --- | --- |
| `aether::key_negotiation` | certificats gateway émis par CA, objets signés, encodage canonique et empreintes |
| `aether::config` | états bornés, pending/next, tombstones, générations, profil Astra et invariants temporels |
| `astra` | coordinateur HTTPS, statut authentifié, planificateur, campagnes, émetteur délégué, transactions chunkées, registre et audit |
| compagnon `astra-signer` | ouverture locale du coffre par FIDO2 PRF, signatures maîtresses et zéroïsation |
| `helios-vault` | coffre maître et key-slots multiples liés aux credentials YubiKey |
| `helios-api` | routes dans WireGuard et API veth privée, statut/commit, authentification de source et limites HTTP |
| `heliosd::key_negotiation` | identité active, staging gateway, marqueur publié, avortement, reçu signé et preuve de leaf servie |
| `helios-provisioning::admission` | pending client, lease, commit/purge, générations TLS/PQ atomiques, unicité et révocation dominante |
| configuration TLS de `heliosd` | deux CA clientes au plus, promotion par `ca_tls_epoch` et vérification mTLS avant résolution de génération |
| `orion-core::config` | ancres, pins actifs/suivants, compteurs persistants et anti-rollback |
| `orion-core::key_negotiation` | planificateur 80 %, récupération, chunks pending, commit atomique et staging client |
| `orion-core::identity_store` | clés et certificats clients actifs/suivants protégés, promotion atomique |
| IHM Orion | état local, renouvellement profil/appareil, récupération expirée et rollback borné |
| IHM Helios | état du parc, campagnes leafs/chaîne/autorités, avortement pré-publication et rollback gateway |
| `helios-ctl` | diagnostic, import/export hors ligne et commandes de campagne Astra non interactives |

## 17. Références de conception

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) — validité,
  certification et modèle de révocation X.509 ;
- [RFC 9810](https://www.rfc-editor.org/rfc/rfc9810.html) — preuve de
  possession, transition de clé de CA et distribution hors bande ;
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html) — statut de
  révocation OCSP, dont Astra reprend la fraîcheur signée sans étendre la
  validité ;
- [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html) — fenêtre de
  renouvellement conseillée et dispersion des clients ;
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA ;
- [FIDO CTAP 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
  — authentificateurs itinérants et extension `hmac-secret` ;
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) — RP ID, vérification
  utilisateur et extension PRF ;
- [The Update Framework, spécification](https://theupdateframework.github.io/specification/latest/)
  — générations séquentielles, signatures ancienne/nouvelle et persistance
  anti-rollback ; la présente spécification reprend ces propriétés, pas son
  format de dépôt.
