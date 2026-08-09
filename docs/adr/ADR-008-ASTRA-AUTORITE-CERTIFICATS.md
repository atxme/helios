# ADR 008 — Astra, autorité et cycle de vie des certificats

**Statut** : accepté (2026-08-09).

**Portée** : exploitation de la PKI de négociation v5, renouvellement distant,
récupération d'une identité expirée et commandes manuelles de rotation. Les
formats détaillés et les machines d'état sont fixés par la
[spécification de rotation](../specification/ROTATION-CERTIFICATS.md).

## Contexte

La spécification de rotation du 8 août fixait les ancres, les générations et
les transitions, mais laissait volontairement ouverte la forme de l'autorité
opérateur. Le chemin historique conservait `CA-PQ` et `CA-TLS` sur le poste
opérateur. Cette topologie ne répond pas au fonctionnement attendu d'une
gateway distante : une rotation dépendrait d'un poste précis, et un Orion
resté hors ligne jusqu'à l'expiration de son certificat ne pourrait plus
établir le tunnel dans lequel la mise à jour ordinaire doit circuler.

Trois contraintes déterminent la décision :

1. la gateway est une appliance distante que l'opérateur ne doit pas avoir à
   visiter pour renouveler un certificat ;
2. les clés privées TLS et ML-DSA-87 d'Orion naissent et restent dans son
   stockage protégé Windows ; une autorité ne reçoit que leurs parties
   publiques et preuves de possession ;
3. une autorité en ligne doit pouvoir renouveler automatiquement un pair déjà
   admis sans pour autant détenir sans limite le pouvoir de créer un pair, de
   ressusciter une identité expirée ou de tourner l'ancre du parc.

## Décision

### 1. Astra est co-implantée, mais reste un service distinct

Le service de PKI se nomme **Astra**. Son coordinateur s'exécute dans un
conteneur dédié sur la même machine physique que `heliosd` :

```text
                         TCP HTTPS dédié
Orion  <------------------------------------------>  Astra
  |                                                   |
  | WireGuard + API interne                           | veth privé
  v                                                   v
helios0  <---------------------------------------->  heliosd
```

La co-implantation répond à la réalité d'exploitation : sans cette gateway,
ce domaine de confiance et ses admissions ne servent plus le trafic. Elle ne
fait toutefois pas de Docker une frontière contre `root`. Elle isole les
processus, les fichiers, les capacités et les interfaces dans le modèle où un
parseur ou un service applicatif est compromis sans prise de contrôle du noyau.
Une compromission de l'hôte reste une compromission possible de l'émetteur
opérationnel et une attaque de disponibilité contre la PKI.

Astra possède :

- le registre des domaines, certificats, générations et révocations ;
- les demandes et campagnes en cours ;
- le journal d'audit chaîné ;
- les objets publics de transition et de récupération ;
- un coffre HVLT chiffré de l'autorité maîtresse ;
- une clé d'émission opérationnelle déléguée et bornée.

Astra ne monte jamais le socket Docker, `network.toml`, les coffres de
`heliosd`, le plan de données WireGuard ni les secrets TPM d'Helios. Son
conteneur s'exécute sans capacité Linux, avec système de fichiers racine en
lecture seule, UID propre, répertoire d'état propre et limites de ressources.

### 2. Deux canaux, deux fonctions

Le canal public Astra est un endpoint HTTPS distinct, avec un nom DNS stable
qui sert aussi de RP ID WebAuthn. Un déploiement peut exposer directement un
`astra_port` ou placer le conteneur derrière un reverse proxy sur TCP 443. Ce
canal porte les demandes publiques, les statuts, les cérémonies d'approbation
et les objets signés ; il ne porte jamais de clé privée cliente, de PSK ou de
clé CA en clair.

Le canal Astra–Helios utilise une paire veth dans un réseau sans route par
défaut et sans forwarding. Le pare-feu n'y autorise que l'API privée de cycle
de vie. Le transport est mutuellement authentifié et chaque mutation conserve
en plus son autorisation ML-DSA-87 propre. Le chiffrement du lien protège la
séparation des processus ; il n'est jamais présenté comme une défense contre
`root`, qui contrôle les deux extrémités et le noyau.

Le canal WireGuard reste prioritaire dès qu'il existe. Une opération ordinaire
initiée par Orion passe par l'API interne du tunnel. Le canal public Astra ne
contourne ce chemin que pour la récupération d'une identité qui ne peut plus
négocier et pour l'approbation WebAuthn.

### 3. Une ancre maîtresse et un émetteur Astra délégué

`CA-PQ` reste l'ancre du domaine et autorise les transitions de confiance. Sa
clé privée, ainsi que la clé racine `CA-TLS`, demeure dans un coffre HVLT
verrouillé. Astra n'utilise pas ces clés pour chaque renouvellement ordinaire.

La CA maîtresse signe une `AstraIssuerAuthorization` qui lie :

- `trust_domain_id` et une unique clé publique WireGuard gateway ;
- la clé publique ML-DSA-87 de l'émetteur Astra ;
- l'intermédiaire TLS client correspondant ;
- une époque d'émetteur strictement croissante ;
- une période de validité ;
- les usages autorisés et les durées maximales de leaf ;
- l'empreinte de la politique d'émission.

Cette délégation autorise seulement le renouvellement séquentiel de leafs de
clients déjà admis et non révoqués. Elle interdit le premier enrôlement, la
réadmission, la récupération d'une identité expirée, la rotation gateway, la
rotation de CA, la révocation et toute génération autre que `active + 1`.

La clé opérationnelle est scellée dans l'état Astra de la gateway. Une
compromission de l'hôte peut donc abuser de cette délégation jusqu'à son
échéance, mais ne donne pas le pouvoir non borné de `CA-PQ`. Orion et Helios
vérifient la délégation, son époque, sa fenêtre et ses usages avant toute leaf
ou grant signé par l'émetteur Astra.

### 4. Deux YubiKeys obligatoires pour l'autorité

Le bootstrap Astra enregistre au moins deux authentificateurs matériels
FIDO2 : une YubiKey d'usage courant et une YubiKey de récupération conservée
séparément. Les appellations « principale » et « secondaire » sont des rôles
d'exploitation ; cryptographiquement, ce sont deux credentials indépendants.

La clé maîtresse aléatoire du coffre est enveloppée dans un key-slot distinct
pour chaque credential, à partir de l'extension CTAP2 `hmac-secret` ou de son
équivalent WebAuthn PRF, avec vérification utilisateur et présence physique.
Le PIN seul, une assertion WebAuthn non liée au coffre ou un mot de passe de
secours ne déverrouillent pas l'autorité.

Le coffre chiffré peut résider dans l'état Astra et ses sauvegardes, mais il
n'est jamais ouvert dans le conteneur. Une application portable
`astra-signer`, exécutée sur le poste où la YubiKey est branchée, récupère le
coffre chiffré et une requête de signature Astra. Elle vérifie la clé de
service épinglée, l'empreinte du coffre, l'échéance et le manifeste canonique,
affiche l'opération exacte, puis utilise CTAP directement pour ouvrir un
key-slot. Elle signe localement, zéroïse le matériel maître et ne renvoie que
les objets signés. Ni la clé de déverrouillage ni une clé privée de CA ne
transitent par Astra, Helios ou le navigateur.

Orion et la console Helios ne parlent pas directement à CTAP. Ils créent une
opération Astra puis ouvrent `astra-signer` par un lien local enregistré qui ne
contient que l'URL d'autorité et l'identifiant opaque de l'opération. Le
compagnon récupère lui-même la requête signée ; l'IHM ignore tout callback non
signé et suit ensuite l'opération par interrogation d'Astra. Le même compagnon
peut être copié sur un autre poste : l'autorité reste transportable avec le
coffre chiffré et l'une des deux YubiKeys, sans dépendre du poste d'origine.

Règles de gestion :

- le bootstrap n'est finalisé qu'après enregistrement et essai des deux clés ;
- ajouter une clé exige une clé autorisée existante et la présence de la
  nouvelle ;
- retirer une clé exige une autre clé autorisée et ne peut laisser aucun slot
  de récupération ;
- perdre la clé courante permet de réenvelopper le coffre avec la clé de
  récupération ;
- tourner `CA-PQ`, remplacer la politique d'émetteur ou effectuer une
  réadmission sans preuve de l'ancienne clé exige deux credentials opérateur
  distincts ;
- les credentials synchronisés dans un cloud ne satisfont pas une politique
  qui exige un authentificateur matériel.

Les deux credentials sont des credentials opérateur liés au
`trust_domain_id` et à la clé WireGuard de la gateway. Orion peut demander une
récupération avec l'un d'eux depuis la machine cliente, mais la campagne reste
bornée au pair, à ses empreintes et à sa génération avant que le compagnon ne
l'affiche et ne la signe.

### 5. Renouvellement ordinaire automatique à 80 %

Pour une leaf active :

```text
renewal_at = not_before + 0,80 * (not_after - not_before)
```

Les calculs utilisent des entiers vérifiés. Astra publie une fenêtre conseillée
et Orion choisit un instant stable dispersé dans cette fenêtre. À l'ouverture,
Orion génère les nouvelles clés TLS et ML-DSA-87, les scelle, puis produit la
CSR et les preuves de continuité et de possession.

Le renouvellement ordinaire n'exige pas de YubiKey : il est autorisé seulement
par l'identité encore active, la nouvelle preuve de possession, l'admission
non révoquée, l'émetteur Astra borné et le reçu de staging Helios. Exiger une
présence humaine ici recréerait le risque d'expiration que le planificateur
doit supprimer.

Astra annonce la fenêtre avant son ouverture, renforce l'alerte après 90 % de
durée écoulée et passe en état critique après 95 %. Une panne d'Astra ne coupe
jamais un tunnel ni ne prolonge une leaf : Orion conserve son échéance locale
et réessaie avec backoff.

### 6. Une leaf expirée reste expirée

OCSP inspire l'état signé publié par Astra, pas une prolongation de validité.
Un statut `active` ou `not_revoked` ne rend jamais acceptable une leaf hors de
sa période. Le chemin QUIC v5 continue de la refuser.

Après une longue absence, Orion peut néanmoins utiliser l'ancienne identité
comme **preuve historique** dans une récupération publique. La demande doit
réunir :

- le certificat expiré exact de la dernière génération connue ;
- une signature ML-DSA-87 fraîche par son ancienne clé privée ;
- une CSR TLS et une preuve par la nouvelle clé ML-DSA-87, toutes deux déjà
  scellées localement ;
- un challenge Astra unique et borné ;
- une approbation par une YubiKey opérateur liée au hash canonique de toute la
  demande.

Astra refuse si le pair est absent, révoqué, déjà remplacé, si une génération
plus récente existe ou si l'un des liens d'identité diffère. La vérification
historique ignore seulement l'échéance après avoir vérifié toutes les autres
propriétés ; elle n'appelle jamais le validateur du chemin de négociation en
mode dégradé.

Astra fait persister la nouvelle génération par Helios et exige un
`GatewayCertificateStageReceipt` signé avant de remettre le grant. Orion peut
alors négocier avec la nouvelle leaf et seulement ensuite établir WireGuard.
Une identité révoquée ne suit jamais ce chemin.

### 7. Commandes manuelles et rollback borné

Orion et la console Helios exposent une surface « Certificats ». Les deux IHM
créent une campagne Astra, lancent le compagnon `astra-signer` et vérifient
ensuite les objets signés ; elles ne manipulent pas elles-mêmes une YubiKey et
ne font pas confiance à un simple callback de navigateur.

Orion expose :

- l'état, les échéances et la génération de chaque profil ;
- « Renouveler maintenant » pour un profil ;
- « Renouveler tous les profils Helios de cet appareil » ;
- la récupération d'une identité expirée ;
- le retour temporaire à l'ancienne génération pendant le chevauchement.

La console Helios expose :

- l'état de la gateway, des CA, de l'émetteur Astra et du parc client ;
- « Renouveler les leafs du parc », qui ne tourne aucune ancre ;
- « Renouveler toute la chaîne », qui ordonne émetteur, CA TLS, identité
  gateway et identités clientes ;
- « Tourner les autorités », action distincte qui tourne `CA-PQ` et `CA-TLS` ;
- le rollback temporaire de l'identité gateway pendant le chevauchement.

Toute commande manuelle ci-dessus exige au moins une YubiKey opérateur. Une
rotation de `CA-PQ`, une réadmission sans ancienne preuve ou une campagne qui
change la politique d'autorité en exige deux. Le challenge WebAuthn couvre le
hash d'un `AstraRotationCampaign` qui énumère chaque cible, empreinte et
génération ; approuver une campagne ne signe jamais une liste modifiable en
aval.

Un rollback ne décrémente aucun compteur. Il sélectionne temporairement le
slot encore actif dans un chevauchement existant, conserve le slot suivant et
expire au plus tard à `not_after`. Après promotion, révocation ou suppression
de l'ancien slot, il est refusé.

## Conséquences

Astra rend le renouvellement ordinaire indépendant de la présence de
l'opérateur et ferme le cas du client revenu après expiration, tant que celui-ci
possède encore son ancienne clé et une YubiKey préalablement liée. La gateway
reste l'autorité sur l'admission et doit persister la génération avant que le
client ne la reçoive.

La co-implantation réduit la dépendance opérationnelle à un second serveur,
mais lie la disponibilité d'Astra à celle de la gateway. Une sauvegarde
chiffrée et synchronisée du coffre, du registre et du journal est donc
obligatoire. Elle reste inutilisable sans l'une des YubiKeys et sert à
reconstruire la gateway, pas à exploiter silencieusement une seconde autorité.

Le risque résiduel principal est explicite : `root` sur la gateway peut voler
ou employer la clé opérationnelle Astra et modifier le coordinateur. La
délégation en borne les usages et la durée, mais ne fabrique pas une enclave.
Il peut aussi présenter une campagne mensongère, que le compagnon rend visible
avant signature, mais il ne peut pas déchiffrer silencieusement le coffre
maître. Protéger également l'émetteur opérationnel contre le noyau hôte
demanderait un HSM ou un environnement d'exécution attesté portant ML-DSA-87.
Aucun simple conteneur, veth, mTLS ou vTPM contrôlé par cet hôte ne fournit
cette propriété.

## Alternatives écartées

**Autorité complète sur le poste opérateur.** Frontière forte pendant son
absence, mais dépendance à une machine et aucune récupération distante sans
transfert manuel.

**Autorité complète déchiffrée dans Astra.** Simple et autonome, mais une
compromission de la gateway obtient immédiatement le pouvoir permanent de
l'ancre du parc. La délégation bornée réduit ce pouvoir.

**VM ou vTPM comme frontière contre `root`.** L'hyperviseur contrôle mémoire,
stockage et périphériques virtuels ; cette topologie sépare l'exploitation,
pas l'autorité du propriétaire de l'hôte.

**Réacceptation d'une leaf expirée dans QUIC.** Elle transformerait une
échéance cryptographique en simple indication et ouvrirait un chemin public de
downgrade. La récupération Astra émet une nouvelle leaf avant toute nouvelle
négociation.

**YubiKey obligatoire à chaque renouvellement.** Elle ferait de l'absence
humaine une cause normale d'expiration. La présence matérielle est réservée aux
mutations manuelles ou aux chemins où la continuité temporelle est déjà rompue.

## Références

- [Spécification FIDO CTAP 2.0, extension `hmac-secret`](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [WebAuthn Level 3, extension PRF](https://www.w3.org/TR/webauthn-3/)
- [RFC 6960 — OCSP](https://www.rfc-editor.org/rfc/rfc6960.html)
- [RFC 9773 — ACME Renewal Information](https://www.rfc-editor.org/rfc/rfc9773.html)
