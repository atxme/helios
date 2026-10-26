# ADR 008 — Astra, autorité et cycle de vie des certificats

**Statut** : accepté (2026-08-09).

**Révision de sécurité du 2026-08-09** : ajout de l'avortement pré-publication,
des leases de staging, de la rotation de clé de service, des statuts
authentifiés, du transport atomique chunké et clarification du modèle YubiKey
1-sur-2.

**Amendement du 2026-08-15** : un Orion dont l'identité est encore active reste
intégralement dans WireGuard et `heliosd` relaie les échanges nécessaires vers
Astra sur le veth privé. Chaque renouvellement exige désormais une approbation
YubiKey liée à sa demande exacte ; cette approbation autorise l'émetteur
délégué et n'ouvre pas les clés maîtresses.

**Amendement du 2026-09-06** : l'approbation YubiKey par demande introduite le
15 août est retirée du renouvellement client ordinaire. À 80 % de la validité,
Orion génère une identité candidate et le renouvellement s'exécute
automatiquement dans le tunnel sous la délégation Astra bornée. La YubiKey
reste obligatoire pour une récupération après expiration, une réadmission,
une campagne anticipée ou globale et toute mutation d'autorité.
Cette réduction de cérémonie modifie l'empreinte de politique : elle exige une
nouvelle confirmation hors bande et une nouvelle délégation. Une mise à jour
logicielle seule ne réinterprète jamais l'ancienne empreinte comme une
autorisation automatique.

**Amendement du 2026-09-12** : une récupération expirée n'attend plus la fin
de sa lease de staging pour devenir utilisable. Son `activation_at` est
l'instant de la cérémonie ; la génération reste néanmoins inaccessible dans
`pending_grant` jusqu'au commit signé par l'ancienne et la nouvelle clé. La
lease borne seulement l'arrivée de ce commit. Après son succès, Helios admet
immédiatement `next_committed` et Orion promeut dans la même opération la paire
de clés scellée. Les renouvellements ordinaires conservent leur activation
différée et la contrainte `stage_expires_at <= activation_at`.

La confirmation hors bande prend la forme que les clés de l'opérateur
produisent déjà : une `AstraIssuerAuthorization` signée par `CA-PQ` et portant
l'empreinte de la politique courante. Astra l'adopte en installant cette
délégation, dans la même écriture durable ; la gateway, qui épingle la
politique pour son propre compte, l'adopte par `heliosd
adopt-issuance-policy`, sur la même délégation et sous la même ancre. Un
registre épinglé à autre chose que la politique remplacée n'est pas déplacé :
il n'appartient pas à cette migration, et le deviner serait l'élargissement
silencieux que cet amendement refuse.

**Clarification du 2026-08-16** : dans ce relais, la demande et le commit Orion
passent dans WireGuard ; l'autorisation de stage et le reçu passent directement
entre Astra et Helios sur le veth. Le reçu laisse le candidat en
`pending_grant`; seul le commit crée `next_committed`.

La clarification ferme aussi les contrats cryptographiques : discriminants
explicites des deux leafs gateway optionnelles, `ctx` ML-DSA-87 non vide fixé
par type, HVLT v1 sous AES-256-GCM/HKDF-SHA-256, politique confirmée hors bande,
capacités HKDF/HMAC du compagnon et aléa fourni par un DRBG SP 800-90A dont
l'implémentation porte une validation CAVP/ACVP à 256 bits —
HMAC-DRBG-SHA-512 ou CTR-DRBG-AES-256 avec DF — semé
par la plateforme en mode fail-closed, sans DRBG applicatif maison. Leur forme
normative est dans la spécification §§2.3, 2.4, 6.2 et 8.2.

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
3. une autorité en ligne doit renouveler automatiquement un pair encore actif
   et déjà admis, sans pour autant détenir le pouvoir de créer un pair, de
   ressusciter une identité expirée ou de tourner l'ancre du parc.

## Décision

### 1. Astra est co-implantée, mais reste un service distinct

Le service de PKI se nomme **Astra**. Son coordinateur s'exécute dans un
conteneur dédié sur la même machine physique que `heliosd` :

```text
Orion  -------- WireGuard + API interne -------->  heliosd
  ^                                                   |
  |                                                   | veth privé + mTLS
  |                                                   v
  +------ HTTPS public, secours/opérateur --------- Astra
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
canal ne porte que la récupération ou une consultation de statut authentifiée
quand WireGuard ne peut plus être établi, ainsi que les campagnes opérateur
hors tunnel et leurs cérémonies d'approbation. Il ne porte jamais le
renouvellement ordinaire d'une identité encore active, ni une clé privée
cliente, un PSK ou une clé CA en clair. Un statut client n'y est jamais lisible
par empreinte seule : il exige un challenge frais signé par la clé PQ de
l'identité ou une campagne YubiKey.

Le canal Astra–Helios utilise une paire veth dans un réseau sans route par
défaut et sans forwarding. Ses deux adresses IP statiques sont de la
configuration locale de la gateway : elles n'entrent dans aucun profil Orion
et n'exigent ni DNS ni certificat HTTPS public. Le pare-feu n'y autorise que
l'API privée de cycle de vie. Le transport mTLS est mutuellement authentifié et
chaque mutation conserve en plus son autorisation ML-DSA-87 propre. Le
chiffrement du lien protège la séparation des processus ; il n'est jamais
présenté comme une défense contre `root`, qui contrôle les deux extrémités et
le noyau.

Ce transport impose TLS 1.3 avec échange `(EC)DHE` éphémère, sans TLS 1.2,
0-RTT, tickets de reprise ni mode PSK sans Diffie-Hellman. Une compromission
ultérieure des clés mTLS ne doit pas déchiffrer une capture ancienne ; les
signatures applicatives restent l'autorisation normative.

Toutes ces signatures emploient ML-DSA-87 pur, jamais HashML-DSA. Le `ctx`
FIPS 204 est non vide et fixé par type : il vaut exactement le domaine ASCII
qui préfixe déjà la transcription canonique, sans NUL final. Préfixer seulement
le message avec `ctx = ""` n'est pas équivalent et est refusé, en particulier
pour toute signature de `CA-PQ`.

Le canal WireGuard est obligatoire dès qu'il existe. Une opération ordinaire
initiée par Orion passe par des routes typées de l'API interne du tunnel, sans
appel à `astra-signer` ni assertion WebAuthn. `heliosd` résout d'abord la VIP
source vers l'unique pair
admis, compare la clé WireGuard portée par l'objet, puis relaie l'objet
canonique vers Astra par le veth. Il n'est jamais un reverse proxy générique et
n'accepte aucun en-tête de proxy. Le canal public Astra ne contourne ce chemin
que pour une identité qui ne peut plus négocier et pour les opérations
opérateur explicitement lancées hors tunnel.

Les trois routes du compagnon n'acceptent pas un simple identifiant comme
autorité. Elles exigent une capacité bearer MACée, distincte par scope, liée à
l'opération, au manifeste, au coffre éventuel et à cinq minutes au plus. La clé
racine de ces capacités est éphémère au processus Astra : un redémarrage les
invalide, sans dériver aucun droit d'une CA ou de la clé de service.

#### Amendement du 4 septembre 2026 — le tunnel porte aussi les campagnes opérateur

La réserve « et pour les opérations opérateur explicitement lancées hors
tunnel » se lisait comme une dispense : toute campagne passait par l'origine
publique, y compris depuis une machine dont le tunnel était monté. Sur un
déploiement dont le nom d'autorité n'est pas publiquement résoluble — le cas
attendu, puisque le RP ID est fixé avant l'amorçage et ne peut plus changer
sans invalider les key-slots — cette origine n'existe pas, et les quatre
commandes de chaîne devenaient inatteignables. La rotation de la CA TLS
cliente en fait partie ; elle est aussi ce qui débloque §9.4. Une autorité
qu'on ne peut joindre qu'en publiant un port ou en ajoutant un terminateur
TLS n'est pas un modèle de récupération, c'est une dépendance de déploiement.

La règle devient la même que pour un renouvellement ordinaire : **le canal
WireGuard est obligatoire dès qu'il existe**, pour les campagnes opérateur
comme pour le reste. L'origine publique ne sert plus qu'un opérateur qui n'a
réellement aucun tunnel, et le document hors ligne reste le dernier recours.

Trois transports, un seul geste. Ce qui diffère est le chemin ; la
vérification est identique, parce que ce sont les objets qui portent les
signatures :

* **Tunnel** — `--heliosd-url` et `--operation-id`, chemin prioritaire.
* **HTTPS** — `--authority-url` et `--operation-id`, pour un opérateur sans
  tunnel, sur un déploiement qui a choisi un nom public avant l'amorçage.
* **Hors ligne** — `--request` / `--campaign` et `--out`, dernier recours.

Le choix est explicite et ne se rattrape pas : un transport tunnel qui échoue
est une erreur, jamais un repli silencieux vers l'origine publique. Un repli
ferait dépendre le chemin réellement emprunté d'une panne, et l'opérateur
croirait avoir approuvé dans le tunnel une cérémonie partie ailleurs.

Le relais opérateur de `heliosd` n'est pas celui du §8.1.2 et ne s'y confond
pas. Une opération de renouvellement appartient à un pair, résolu par sa VIP
source ; une opération de campagne n'appartient à aucun pair et son autorité
est ailleurs — dans l'assertion YubiKey et les signatures applicatives. Le
relais opérateur exige donc un pair **administrateur**, jamais un simple pair
admis, et son identité est établie avant toute lecture comme avant tout
relais. L'identité transmise est sa clé publique WireGuard, unique et stable,
jamais son nom convivial ; le loopback de développement possède une variante
explicite et ne peut pas être confondu avec un pair réel. Il ne donne accès à
aucune opération de renouvellement : les deux surfaces adressent deux magasins
distincts chez Astra, et la séparation est structurelle plutôt que vérifiée.

Ce relais reste ce que le §2 exige déjà de l'autre : il transporte des objets
canoniques et rien d'autre. Pas de chemin choisi par l'appelant, pas de
méthode transmise, pas d'en-tête relayé. La seule valeur qui traverse hors du
corps est la capacité bearer, qui reste liée à son opération, à son manifeste,
à son coffre éventuel et à cinq minutes — les mêmes capacités, les mêmes
fenêtres et les mêmes `operation_id` que sur l'origine publique, puisque c'est
le même magasin d'opérations qui les émet.

Les refus publics restent grossiers : un pair non administrateur, une origine
incohérente, une opération inconnue et une opération expirée reçoivent des
réponses qui ne se distinguent pas entre elles. Un refus antérieur au relais
n'existe que dans le journal structuré de la gateway ; un refus rendu par
l'autorité existe aussi dans le journal structuré d'Astra. Ces sondes en
lecture n'avancent pas l'audit chaîné : sa tête est un témoin des mutations
durables du registre, et la faire changer à chaque appel refusé rendrait le
témoin anti-fork caduc sans changement d'autorité.

Ce que cet amendement ne fait **pas** : il n'ajoute aucune ancre de confiance.
En particulier, aucune CA TLS privée d'Astra n'entre dans un profil Orion.
Réutiliser `CA-TLS` serait pire encore — elle appartient aux certificats
clients, et l'employer comme ancre de transport créerait une dépendance
circulaire au moment précis où on la fait tourner. Le HTTPS natif reste
possible pour une installation ayant choisi un vrai domaine public avant son
amorçage ; il est une option de déploiement, jamais la racine du modèle de
récupération.

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

L'empreinte de politique n'est pas une valeur que la délégation choisit pour
elle-même. Le document d'enrôlement la présente avec `CA-PQ`; l'opérateur la
confirme hors bande et Orion comme Helios la scellent dans leur profil. Tout
objet — délégation, campagne ou grant — portant une autre empreinte est refusé,
même sous une signature `CA-PQ` valide. La v1 ne tourne pas ce pin en ligne :
changer la politique impose de réémettre et reconfirmer le profil. Sa forme
canonique est fixée par la spécification §2.4.

La clé opérationnelle est scellée dans l'état Astra de la gateway. Une
compromission de l'hôte peut donc abuser de cette délégation jusqu'à son
échéance, mais ne donne pas le pouvoir non borné de `CA-PQ`. Orion et Helios
vérifient la délégation, son époque, sa fenêtre et ses usages avant toute leaf
ou grant signé par l'émetteur Astra.

La clé applicative qui signe statuts, challenges et opérations possède son
propre slot actif/suivant. Sa rotation planifiée exige continuité ancienne,
preuve de la nouvelle clé et signature `CA-PQ`. Si elle est compromise,
`CA-PQ` autorise un remplacement immédiat sans sa signature. Orion n'apprend
jamais une nouvelle clé de service depuis une réponse autorisée uniquement par
la clé remplacée.

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

Le renouvellement ordinaire n'emploie ni `astra-signer`, ni assertion FIDO2,
ni ouverture du coffre. La demande signée par l'identité active et par la clé
candidate, son empreinte, le seuil de 80 %, l'admission non révoquée et la
délégation bornée forment son autorisation. Astra, Helios et Orion vérifient
indépendamment que la demande vise exactement `active + 1` et que
l'autorisation de stage est liée à son empreinte.

La récupération expirée, qui doit employer `CA-PQ`, combine au contraire les
deux fonctions dans une seule cérémonie `GetAssertion` par credential : le
challenge signe le hash exact de la récupération et l'extension PRF/
`hmac-secret` dérive simultanément le secret du key-slot. Le compagnon vérifie
l'assertion avant d'ouvrir le coffre. Une opération exigeant deux credentials
répète cette cérémonie avec deux clés distinctes. Cette combinaison ne vaut
jamais pour le renouvellement ordinaire, qui n'ouvre aucun coffre maître.

Depuis F11 (séparation des privilèges Windows, ADR-004 §9), le sidecar
`helios-astra-helper` **a disparu** : `orion.exe` n'est plus un processus élevé
unique, mais une IHM non élevée et un moteur élevé qui seul charge WireGuardNT et
ouvre le coffre du client. La cérémonie opérateur vit dans l'IHM non élevée,
qui est déjà dans la session interactive de l'utilisateur, au niveau
d'intégrité où l'API WebAuthn de Windows répond ; la boîte de dialogue est
rattachée à la fenêtre Orion. Le moteur n'y participe pas et ne dépend pas de
`astra-operator`. La WebView ne transmet à la cérémonie qu'un genre d'opération
et son identifiant opaque : la cérémonie résout elle-même l'origine, le RP ID,
le domaine et la clé de service depuis le hand-off épinglé au coffre, puis
publie des états et un manifeste typés (`operator_session`). Aucun secret ni PIN
ne traverse vers la WebView. Le comportement sous Windows réel de cette
cérémonie dans l'IHM est **à valider en recette** (MANUAL-TESTING, point 10 de
« Séparation des privilèges (F11) »). `astra-signer` reste l'adaptateur portable des flux hors ligne
et des cérémonies qui n'ont pas encore atteint cette parité dans Orion.

Règles de gestion :

- le bootstrap n'est finalisé qu'après enregistrement et essai des deux clés ;
- le renouvellement client planifié à 80 % n'emploie aucun credential
  opérateur ; une campagne anticipée ou globale en exige au moins un ;
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

Le coffre v1 reste 1-sur-2 : chacune des deux clés peut ouvrir seule un
key-slot, puisque la secondaire doit réellement secourir la perte de la
principale. Exiger deux confirmations pour une rotation d'autorité est une
barrière opératoire contre l'erreur et l'usage d'une seule clé volée avec un
compagnon honnête ; ce n'est ni un partage de secret ni une séparation entre
deux personnes. Un poste compromis après un déverrouillage peut extraire la CA.
Un vrai M-sur-N demanderait au moins un coffre à seuil et des identités
d'opérateurs distinctes ; Astra v1 ne revendique pas cette propriété.

Les deux credentials sont des credentials opérateur liés au
`trust_domain_id` et à la clé WireGuard de la gateway. Orion peut demander une
récupération avec l'un d'eux depuis la machine cliente, mais la campagne reste
bornée au pair, à ses empreintes et à sa génération avant que le compagnon ne
l'affiche et ne la signe.

#### Amendement du 11 août 2026 — deux est un plancher, pas un plafond

« Au moins deux » se lit à la lettre : `astra::vault` exige deux credentials
avant de tenir l'autorité pour amorcée et en accepte huit. Enrôler une
troisième clé est le **même** geste que la seconde, avec les mêmes arguments —
une clé autorisée ouvre, la nouvelle reçoit un slot. Aucune n'est distinguée
cryptographiquement ; « principale » et « récupération » restent des libellés
d'exploitation, et un libellé n'entre dans aucune dérivation.

Le corps du coffre est scellé sous une empreinte de la table de slots. Retirer
une clé rescelle donc le corps, ce qui n'exige **qu'une seule** clé restante :
les enveloppes des autres slots ne bougent pas. Sans cette liaison, retirer un
slot ne ferait qu'effacer une ligne, et la ligne recollée depuis une sauvegarde
rouvrirait le fichier courant — la clé maîtresse, elle, n'aurait pas changé.

**Limite connue** : cette liaison protège le fichier *courant*, pas les copies
déjà faites. Une sauvegarde antérieure au retrait reste ouvrable par la clé
retirée, définitivement, comme toute sauvegarde LUKS l'est par une phrase
supprimée depuis. La réponse à un credential réellement compromis est une
rotation de `CA-PQ`, pas un retrait de slot.

Un sel **WebAuthn** unique par coffre, et non par slot : `hmac-secret` rend
`HMAC(CredRandom, sel)` et `CredRandom` est tiré par l'authentificateur pour
chaque credential, donc deux slots d'un même coffre dérivent déjà deux secrets
distincts. Un sel WebAuthn par slot n'ajouterait rien et coûterait la résolution
en une seule assertion — le jeton nomme le credential qu'il détient parmi ceux
proposés, et rend son secret, d'un seul contact.

Ce sel WebAuthn partagé par le coffre ne doit pas être confondu avec le sel de
KDF interne de chaque key-slot. Chaque enveloppe est un conteneur HVLT v1
AES-256-GCM séparé : HKDF-SHA-256 dérive sa clé depuis la sortie
`hmac-secret`, avec un sel aléatoire frais de 16 octets et le label
`helios/astra-authority-slot-wrapping/v1`; son contexte authentifié lie
`vault_id` et `slot_id`. Le payload est un second HVLT v1 sous la clé maîtresse
aléatoire de 32 octets ; son contexte lie `vault_id`, `trust_domain_id` et le
digest canonique de la table de slots. L'AAD couvre l'en-tête HVLT complet,
sel et nonce inclus. Le format exact et les métadonnées qui ne portent aucune
autorité sont fixés par la spécification §2.4.1.

### 5. Renouvellement ordinaire automatique à 80 %

Pour une leaf active :

```text
renewal_at = not_before + 0,80 * (not_after - not_before)
```

Les calculs utilisent des entiers vérifiés. À cet instant exact, Orion génère
les nouvelles clés TLS et ML-DSA-87, les scelle, puis produit la CSR et les
preuves de continuité et de possession. Il n'attend ni dispersion dans les
20 % restants, ni présence opérateur.

L'identité encore active, la preuve de possession candidate, l'admission non
révoquée, la génération strictement `active + 1`, l'émetteur Astra borné et le
reçu de staging Helios sont tous obligatoires. L'empreinte de la demande tient
lieu de liaison d'autorisation dans le stage, le reçu et le grant. Une
compromission d'Astra peut renouveler silencieusement les identités encore
admissibles jusqu'à l'échéance de la délégation, mais ne peut sortir de ce
périmètre ; ce risque est accepté pour supprimer la dépendance humaine du
maintien en service.

Astra annonce la fenêtre avant son ouverture, renforce l'alerte après 90 % de
durée écoulée et passe en état critique après 95 %. Une panne d'Astra ne coupe
jamais un tunnel ni ne prolonge une leaf : Orion
conserve son échéance locale et réessaie avec backoff.

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

Astra fait persister par Helios un candidat `pending_grant`, sans slot `next`,
et exige un `GatewayCertificateStageReceipt` signé avant de remettre le grant.
Orion persiste ce grant puis signe le commit ; Astra le relaie sur le veth et
seul son succès fait créer `next_committed` par Helios. Orion peut alors
négocier avec la nouvelle leaf et seulement ensuite établir WireGuard. Une
identité révoquée ne suit jamais ce chemin.

Une YubiKey suffit à cette récupération parce que l'ancienne clé PQ privée est
une seconde preuve indépendante et que la clé WireGuard, le domaine et la
dernière génération restent inchangés. Une réadmission privée de cette preuve
peut créer une nouvelle continuité et demande deux confirmations YubiKey. Le
vol simultané de l'ancienne clé et l'approbation d'une YubiKey compromet ce
chemin ; une politique plus stricte peut en exiger deux, jamais zéro.

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
- l'annulation signée d'une transition gateway préparée mais non publiée ;
- le rollback temporaire de l'identité gateway pendant le chevauchement.

Un renouvellement ordinaire « Renouveler maintenant » arrivé dans sa fenêtre
suit le même chemin automatique. Une commande qui anticipe cette fenêtre, une
campagne globale ou une autre mutation ci-dessus exige au moins une YubiKey
opérateur. Une
rotation de `CA-PQ`, une réadmission sans ancienne preuve ou une campagne qui
change la politique d'autorité en exige deux. Le challenge WebAuthn couvre le
hash d'un `AstraRotationCampaign` qui énumère chaque cible, empreinte et
génération ; approuver une campagne ne signe jamais une liste modifiable en
aval.

Un rollback ne décrémente aucun compteur. Il sélectionne temporairement le
slot encore actif dans un chevauchement existant, conserve le slot suivant et
expire au plus tard à `not_after`. Après promotion, révocation ou suppression
de l'ancien slot, il est refusé.

### 8. Avortement, leases et atomicité logique

Une transition gateway peut être avortée sans révocation seulement tant
qu'elle est `staged`, avant `activation_at` **et avant toute publication**.
Astra persiste `published` avant d'émettre le premier octet ou document ; après
ce point, un client hors ligne pourrait conserver la décision initiale puis la
promouvoir à `not_after`. L'avortement signé retire le slot suivant, laisse
l'identité courante active, consomme définitivement l'époque et publie un
tombstone séquentiel sans les leafs annulées. Après publication, le rollback
temporaire ou une nouvelle transition en avant sont les seules sorties
ordinaires.

Un staging client n'occupe pas indéfiniment `next`. Il porte une lease de
24 heures au plus et reste `pending_grant` jusqu'à ce qu'Orion ait persisté le
grant puis envoyé un commit signé par les clés active et candidate. Sans commit
avant l'échéance, Helios purge atomiquement le candidat et refuse tout callback
tardif. La récupération expirée relaie ce commit par Astra et le veth ; le
renouvellement ordinaire l'envoie dans WireGuard.

L'autorisation de stage suit, elle, un porteur unique : Astra la remet toujours
directement à Helios par le veth mTLS et Helios lui retourne le reçu sur cette
même relation. Orion ne transporte jamais cet objet. Pour un renouvellement
ordinaire, seule la demande initiale et le commit Orion passent dans WireGuard ;
pour une récupération expirée, la demande arrive en HTTPS public et le commit
est relayé par Astra sous l'autorisation de récupération.

La limite de 64 Kio fractionne seulement le transport d'une mise à jour de
confiance. Tous les chunks appartiennent à un manifeste signé unique et restent
dans un espace pending invisible. Orion publie `CA-PQ`, `CA-TLS`, clé de
service Astra, gateway et client par une seule écriture locale après réception
et validation de l'ensemble. Une transaction incomplète expire sans état de
confiance mixte.

## Conséquences

Astra rend le renouvellement ordinaire indépendant des clés maîtresses et de
la présence de l'opérateur. Elle ferme aussi le cas du client revenu après
expiration, tant que celui-ci possède encore son ancienne clé et une YubiKey
opérateur. La gateway reste l'autorité sur l'admission et doit persister la
génération avant que le client ne la reçoive.

La co-implantation réduit la dépendance opérationnelle à un second serveur,
mais lie la disponibilité d'Astra à celle de la gateway. Une sauvegarde
chiffrée et synchronisée du coffre, du registre et du journal est donc
obligatoire. Elle reste inutilisable sans l'une des YubiKeys et sert à
reconstruire la gateway, pas à exploiter silencieusement une seconde autorité.

Le risque résiduel principal est explicite : `root` sur la gateway peut voler
ou employer la clé opérationnelle Astra et modifier le coordinateur. La
délégation en borne les usages et la durée, et une leaf cliente ordinaire reste
inacceptable sans une demande cliente valide liée de bout en bout, mais aucune
de ces bornes ne fabrique une enclave. `root` peut aussi présenter
une campagne mensongère, que le compagnon rend visible avant approbation, mais
il ne peut ni forger l'assertion du credential ni déchiffrer silencieusement le
coffre maître. Protéger la disponibilité de l'émetteur opérationnel contre le
noyau hôte demanderait un HSM ou un environnement d'exécution attesté portant
ML-DSA-87. Aucun simple conteneur, veth, mTLS ou vTPM contrôlé par cet hôte ne
fournit cette propriété.

La leaf TLS gateway reste auto-signée et épinglée, tandis que la leaf PQ chaîne
vers `CA-PQ`. Cette asymétrie est volontaire : TLS protège le transport par un
pin dont le remplacement est autorisé par `CA-PQ`; ML-DSA-87 porte l'autorité
applicative post-quantique. `CA-TLS` reste exclusivement l'autorité des leafs
mTLS clientes.

La migration depuis le pin auto-signé actuel reste une bascule coordonnée du
discriminant de profil et de l'identité gateway. C'est le point de
disponibilité le plus risqué du lot et une coupure y est acceptée : Astra ne
peut pas faire naître rétroactivement la confiance en `CA-PQ`. De même, Astra
co-implantée ne supprime pas l'attaque de gel sur les révocations ; un hôte qui
retient statut et objets signés reste borné seulement par les échéances et les
canaux hors ligne.

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

**Approbation YubiKey à chaque renouvellement.** Elle ajoute une preuve humaine
d'intention indépendante d'Astra, mais transforme une opération de maintien en
service bornée en cérémonie répétitive et permet à l'absence de l'opérateur de
faire expirer le parc. Elle reste réservée aux récupérations, campagnes et
mutations qui dépassent le renouvellement ordinaire d'une identité active.

**Ouverture du coffre maître à chaque renouvellement.** Elle satisferait aussi
la présence matérielle, mais exposerait inutilement `CA-PQ` et `CA-TLS` pour une
opération que la délégation borne déjà. Les opérations d'autorité et de
récupération continuent, elles, de déverrouiller le coffre hors gateway.

## Références

- [Spécification FIDO CTAP 2.0, extension `hmac-secret`](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [WebAuthn Level 3, extension PRF](https://www.w3.org/TR/webauthn-3/)
- [RFC 6960 — OCSP](https://www.rfc-editor.org/rfc/rfc6960.html)
- [RFC 9773 — ACME Renewal Information](https://www.rfc-editor.org/rfc/rfc9773.html)
