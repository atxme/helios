# Spécification — cycle de vie et rotation des certificats v5

**Statut** : **cycle de vie implémenté** (revu le 2026-08-09, amendé les
2026-08-15, 2026-08-16, 2026-08-22, 2026-08-30, 2026-09-06 et 2026-09-29,
clos le 2026-10-08). Le protocole de négociation servi est la v5. Le §12.3
détaille ce qui est livré ; le §12.5 dit ce qui reste, et rien n'y est du
développement : deux décisions prises et la validation sur les machines
cibles du §14.2.

Le chemin « demande → autorisation → persistance gateway → reçu → grant →
commit » est fermé de bout en bout, sur les deux démons et dans les deux IHM.
Le transport hors tunnel du compagnon (§8.2), la distribution des objets de
transition (§0.6), la récupération d'une identité expirée en une seule
cérémonie FIDO2 (§7.5), le cycle complet de l'identité gateway (§5, §6,
§11.1), les rotations d'ancres (§9.1, §9.4), les révocations d'urgence (§10)
et les campagnes des quatre familles (§7.6) sont livrés.

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
| exploitation | coordinateur Astra co-implanté dans un conteneur séparé sur la gateway ; opérations ordinaires relayées de WireGuard vers un veth privé mTLS, HTTPS public réservé aux chemins sans tunnel et aux campagnes opérateur hors tunnel |
| garde des CA | clés maîtresses `CA-PQ` et `CA-TLS` dans un coffre HVLT chiffré ; déverrouillage hors de la gateway par une YubiKey opérateur |
| émission ordinaire | clé Astra déléguée, bornée à une gateway, un domaine, une fenêtre et aux leafs de pairs déjà admis ; émission automatique seulement à partir de 80 %, pour `active + 1`, sous une demande signée par les clés active et candidate |
| YubiKey | deux credentials matériels 1-sur-N au bootstrap ; aucun credential pour un renouvellement client ordinaire dans sa fenêtre ; un credential actif pour une récupération expirée avec continuité, un rollback gateway ou une campagne anticipée/globale ; le sélecteur local de l'identité cliente précédente n'est pas une nouvelle décision d'autorité ; deux credentials actifs distincts pour une ancre, `trust_authorities` ou une réadmission sans continuité ; une campagne applique le maximum exigé par ses cibles ; ce modèle mono-opérateur n'est pas un quorum humain |
| renouvellement | déclenchement automatique à 80 % exact de la validité écoulée, génération et scellement d'une nouvelle paire de clés, staging puis commit avant l'expiration de l'active |
| expiration | une leaf expirée reste refusée par la négociation ; elle peut seulement prouver une continuité historique dans la récupération Astra |
| rotation de `CA-PQ` | transition signée par l'ancienne **et** la nouvelle CA, générations consécutives |
| rotation de `CA-TLS` cliente | deux ancres au plus, transition autorisée par `CA-PQ` avant toute nouvelle leaf mTLS |
| clé de service Astra | slot actif/suivant et transition signée par `CA-PQ`, avec preuve de la nouvelle clé et époque séquentielle |
| statut Astra | jamais accessible par empreinte seule ; requête authentifiée dans WireGuard ou challenge public signé par la clé PQ cliente |
| réponses fractionnées | chunks d'une même transaction signée par la clé de service Astra, liés à l'empreinte exhaustive que le client a déclarée dans sa requête signée, invisibles aux slots actifs/suivants jusqu'au commit atomique local ; chaque objet conserve sa propre autorité normative |
| compromission | révocation sans grâce ; si `CA-PQ` est compromise, réinitialisation hors bande |
| commandes manuelles | Orion peut relancer un renouvellement ordinaire déjà dû sans YubiKey ; toute anticipation, campagne Helios, récupération ou mutation d'autorité porte les empreintes immuables approuvées par YubiKey |

L'empreinte de la politique fait partie de cette décision. Le passage de la
politique historique « une approbation par demande » à la politique
automatique exige donc la confirmation hors bande de la nouvelle empreinte,
sa distribution dans les profils et registres, puis une délégation Astra qui
la porte. Tant que cette migration n'est pas achevée, le renouvellement
automatique est indisponible ; aucun binaire mis à jour ne peut élargir
silencieusement l'autorité d'une ancienne empreinte.

La délégation est elle-même le véhicule de la migration. Signée par `CA-PQ`
et portant l'empreinte de la politique courante, elle déplace l'épingle
d'Astra au moment de son installation, et celle de la gateway par `heliosd
adopt-issuance-policy`. Les deux extrémités vérifient la signature sous
l'ancre qu'elles détiennent déjà avant de lire la politique nommée, refusent
une délégation qui en nomme une troisième, et laissent intacte une épingle
qui n'est ni la politique courante ni celle qu'elle remplace. L'empreinte de
la politique remplacée reste calculable pour la reconnaître ; aucun chemin ne
l'accepte comme autorisation.

Le choix de faire émettre le certificat PQ gateway par `CA-PQ` est retenu à la
place d'une simple cosignature par l'ancienne leaf. Une leaf compromise ne peut
ainsi autoriser seule sa remplaçante. Astra conserve le coffre chiffré et le
registre sur la machine gateway, mais une clé maîtresse n'y est jamais
déchiffrée : le compagnon de signature opérateur ouvre le coffre localement à
l'aide d'une YubiKey, signe puis zéroïse. L'émetteur délégué reste chargé sur
la gateway, mais sa politique refuse chaque émission ordinaire tant qu'une
demande cliente valide dans la fenêtre de renouvellement n'a pas été vérifiée.
Docker, le veth et le chiffrement interne
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

### 0.4 Amendement d'exploitation du 15 août 2026

La règle d'approbation par demande de cette section est remplacée par §0.7 ;
la contrainte de transport WireGuard reste applicable.

Deux ambiguïtés antérieures sont closes :

- « WireGuard prioritaire » signifie que **toute** opération ordinaire d'un
  client actif, approbation `astra-signer` comprise, entre par `helios-api` et
  est relayée sous forme typée à Astra. Les anciennes routes HTTPS publiques
  de demande et de commit ordinaires sont retirées ;
- le seuil de 80 % prépare une demande, mais n'autorise plus son émission.
  Chaque demande cliente exige une assertion YubiKey opérateur liée à son hash
  exact. Cette assertion ouvre le droit d'utiliser l'émetteur délégué et ne
  déverrouille pas le coffre maître.

Le veth conserve TLS 1.3 mTLS même avec deux adresses IP statiques : cette
protection authentifie les processus et protège les captures, tandis que les
signatures applicatives portent l'autorisation. DNS et certificat HTTPS public
ne participent pas à ce lien privé.

### 0.5 Fermeture de la revue de cohérence du 16 août 2026

La projection opérationnelle est alignée sur l'amendement précédent :

- le stage ordinaire suit un seul flux, Astra → Helios sur le veth ; Orion ne
  transporte jamais `ClientCertificateStageAuthorization` ;
- le reçu Helios atteste un candidat `pending_grant`, pas un slot `next` ; seul
  `ClientCertificateStageCommit` crée `next_committed` ;
- la requête de confiance distingue le snapshot TLS/PQ actif de l'empreinte de
  la leaf PQ effectivement présentée ;
- la révocation gateway vise une empreinte depuis toute phase : atteindre
  l'active rend l'identité terminale, atteindre seulement la suivante retire
  le candidat sans révoquer l'active.

La même revue fixe l'époque candidate gateway, l'égalité
`retire_active_at = transition.not_after`, les sous-ensembles d'état par
famille, les champs de l'avortement, les versions de la récupération et la
cérémonie unique qui lie son approbation à l'ouverture du coffre.

Elle ferme aussi les contrats cryptographiques laissés implicites : chaque
empreinte gateway optionnelle possède son propre discriminant `0|1`, chaque
type signé possède un `ctx` ML-DSA-87 non vide et exhaustivement fixé, HVLT v1
fixe AEAD, KDF, sels et AAD, la politique Astra est épinglée hors bande, les
capacités du compagnon ont un format HKDF/HMAC exact et tout aléa provient d'un
DRBG SP 800-90A certifié à 256 bits, semé par la plateforme en mode fail-closed.

### 0.6 Amendement de production des transactions du 22 août 2026

Deux exigences de §8.1.1 rendaient la production des transactions impossible,
alors que leur transport était déjà défini : Astra ne peut pas reconstruire
l'état local complet d'Orion, et sa partie en ligne ne détient jamais
`CA-PQ`. Elles sont tranchées sans réduire l'anti-rollback ni déplacer une clé
maîtresse vers la gateway.

- `base_state_fingerprint` reste le SHA-256 de l'état de confiance **local
  complet** d'Orion. Il n'est ni remplacé par les seuls compteurs du registre,
  ni recalculé par Astra. Orion le place dans
  `AuthenticatedTrustUpdateRequest`, donc sous la signature de sa leaf PQ
  présentée. Astra le traite comme un jeton opaque de comparaison-et-échange,
  le recopie dans le manifeste et n'a besoin d'en connaître aucun préimage.
  Au commit, Orion le recalcule sur son état vivant ; toute mutation intervenue
  depuis la requête invalide la transaction entière et provoque une nouvelle
  demande avec une nouvelle empreinte ;
- quand Helios constate que le client est en retard et ne détient aucune
  transaction correspondant à cette empreinte, il relaie une demande de
  préparation **typée** vers Astra sur le canal privé Helios → Astra. Le relais
  contient la requête cliente authentifiée et le snapshot de pair que le
  registre gateway possède déjà ; il ne relaie ni méthode, ni chemin, ni
  en-tête du client. Astra sélectionne les objets depuis ses registres, lie la
  réponse à l'empreinte opaque et rend une transaction que Helios place dans
  la file existante. Un même `request_id` et les mêmes octets rendent la même
  décision ; le même identifiant avec d'autres octets est un conflit ;
- tout `TrustUpdateTransactionManifest` servi **en ligne** est signé par la
  clé de service Astra active. Le manifeste autorise l'attribution à un pair,
  le snapshot de base, l'ordre, les dépendances et l'atomicité ; il n'autorise
  aucune mutation de confiance. Chaque objet conserve sa signature normative :
  une transition de CA ou de clé de service, une identité gateway, une
  révocation ou une récupération porte toujours la preuve `CA-PQ` exigée par
  sa propre machine d'état. La valeur `ca_pq` de `manifest_authority_kind` est
  réservée et refusée pour ce canal ; le document hors ligne de §8.4 conserve
  sa signature globale `CA-PQ` ;
- pour une campagne qui touche une ancre, `astra-signer` ouvre le coffre et
  rend les **objets de transition signés une fois**, liés à la campagne. Astra
  les vérifie et les persiste, puis sa clé de service construit autant de
  manifestes par client que nécessaire. Le compagnon ne signe donc jamais un
  manifeste par destinataire, et Astra ne reçoit jamais une clé privée de CA.

La compromission de la clé de service peut toujours retarder, omettre ou
réordonner la livraison — disponibilité déjà dans son périmètre — mais elle ne
peut fabriquer aucun objet de transition. Les compteurs, fenêtres, portées et
signatures propres des objets continuent de décider ce qu'Orion peut publier.

**Migration filaire** : le champ ajouté appartient à la transcription signée
v5 et le décodeur strict refuse une requête qui ne le porte pas. Aucun client
ne produisait encore cette requête en exploitation au moment de l'amendement ;
il n'existe donc pas de transaction distribuée à préserver ni de forme
historique à négocier.

### 0.7 Amendement d'automatisation du 6 septembre 2026

Le renouvellement client ordinaire n'est plus une cérémonie opérateur. Orion
le déclenche à 80 % exact de la validité de la génération active, après avoir
établi WireGuard et appliqué les mises à jour de confiance disponibles. Astra
vérifie l'admission, la non-révocation, la validité courante, la génération
`active + 1`, les preuves de continuité et de possession, puis utilise son
émetteur délégué sans demander d'assertion YubiKey.

L'empreinte de la demande signée devient la liaison d'autorisation commune au
stage, au reçu et au grant. Elle ne remplace aucune preuve pour une opération
plus puissante. Une récupération expirée, une réadmission, une anticipation
avant 80 %, une campagne globale, une rotation gateway ou d'autorité et une
révocation suivent leurs cérémonies YubiKey existantes.

La dispersion dans les 20 % restants est supprimée : elle réduisait de façon
imprévisible la marge de reprise d'un client. Si le seuil est atteint hors
ligne, Orion agit à la prochaine connexion ; une identité déjà expirée ne
bascule jamais vers ce chemin et exige la récupération du §7.5.

### 0.8 Amendement de découpage du 29 septembre 2026

Le canal privé Astra–Helios du §8.3 change de propriétaire dans le code, pas
de comportement. Le §16 attribuait à `helios-api` « l'API privée appelée par
Astra » ; il l'attribue désormais à une bibliothèque `astra-channel`, qui ne
dépend que d'`aether` et que consomment `astra`, `heliosd` et `helios-api`.
`helios-api` garde les routes typées dans WireGuard, le relais vers l'API Astra
du veth, l'authentification de source et les limites HTTP.

La raison est une règle de dépendance, pas une propriété de sécurité : Astra ne
dépend ni de `helios-api` ni d'aucun package `helios-*`
([CRATE-REORGANIZATION.md §7](../architecture/CRATE-REORGANIZATION.md)). Les
deux extrémités du canal partagent les mêmes contrats et les mêmes bornes TLS ;
les héberger dans la façade HTTP de la gateway obligeait le coordinateur à lier
toute cette façade pour parler au veth.

Rien ne change sur le fil : paire veth sans route par défaut, mTLS mutuel entre
certificats épinglés, ALPN `helios-astra-lifecycle/1`, préfixe et routes de
l'API privée, autorisation ML-DSA-87 propre à chaque mutation. L'ALPN est une
valeur de protocole et garde son nom.

La bibliothèque est livrée dans `crates/astra-channel` : elle reprend tel quel
l'ancien module `helios_api::internal`, tests compris. L'état du découpage est
tenu au §13 de CRATE-REORGANIZATION.md, pas dans cette spécification.

## 1. Périmètre

Huit cycles de vie sont distincts :

1. l'identité gateway, composée d'une leaf TLS et d'une leaf PQ ;
2. l'identité cliente, composée d'une leaf TLS et d'une leaf PQ ;
3. l'ancre opérateur `CA-PQ` ;
4. la CA TLS qui émet les leafs mTLS clientes ;
5. la révocation urgente d'une leaf ou d'une admission.
6. la délégation de l'émetteur opérationnel Astra ;
7. les credentials YubiKey qui autorisent récupération, campagnes et
   mutations manuelles sensibles.
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

#### 2.3.1 Contexte ML-DSA-87

Toute signature ML-DSA-87 de ce cycle emploie **ML-DSA pur** de FIPS 204, avec
un contexte externe non vide. HashML-DSA est interdit : ni le signataire ni le
vérificateur ne préhachent le message par une variante HashML-DSA.

Pour chaque type, `ctx` est exactement la chaîne ASCII qui ouvre sa
transcription canonique, par exemple
`helios-gateway-identity-transition-v5`. Elle est passée telle quelle à
`ML-DSA.Sign`/`ML-DSA.Verify`, sans NUL final, normalisation ni encodage de
longueur, et sa longueur doit être comprise entre 1 et 255 octets. Le message
`M` conserve aussi ce même préfixe comme premiers octets de sa transcription :
le contexte externe et le préfixe interne sont deux contrôles distincts.

Le tableau suivant est exhaustif. Deux signatures portant le même type d'objet
emploient le même contexte, même lorsqu'elles sont produites par des clés
différentes :

| Type signé ou preuve signée | `ctx` ML-DSA-87 exact |
| --- | --- |
| `TrustBaseState` | `helios-trust-base-state-v5` |
| `GatewayBootstrapRequest` | `helios-gateway-bootstrap-request-v5` |
| `GatewayCertificateRequest` | `helios-gateway-certificate-request-v5` |
| `GatewayIdentityTransition` | `helios-gateway-identity-transition-v5` |
| `GatewayTransitionAbort` | `helios-gateway-identity-transition-abort-v5` |
| `ClientCertificateRotationRequest` | `helios-client-certificate-rotation-request-v5` |
| `ClientCertificateStageAuthorization` | `helios-client-certificate-stage-authorization-v5` |
| `GatewayCertificateStageReceipt` | `helios-gateway-certificate-stage-receipt-v5` |
| `ClientCertificateRotationGrant` | `helios-client-certificate-rotation-grant-v5` |
| `ClientCertificateStageCommit` | `helios-client-certificate-stage-commit-v5` |
| `ExpiredCertificateRecoveryRequest` | `helios-expired-client-certificate-recovery-request-v5` |
| `AstraCredentialBinding` | `helios-astra-credential-binding-v5` |
| `AstraCredentialApprovalRequest` | `helios-astra-credential-approval-request-v5` |
| `AstraRenewalApproval` | `helios-astra-renewal-approval-v5` |
| `AstraIssuerAuthorization` | `helios-astra-issuer-authorization-v5` |
| `AuthenticatedTrustUpdateRequest` | `helios-in-tunnel-trust-update-request-v5` |
| `TrustUpdateTransactionManifest` | `helios-trust-update-transaction-manifest-v5` |
| `TrustUpdateChunk` | `helios-trust-update-chunk-v5` |
| `OrionTrustUpdateDocument` | `helios-orion-trust-update-document-v5` |
| `AstraCertificateStatus` | `helios-astra-certificate-status-v5` |
| requête authentifiée de statut | `helios-astra-certificate-status-query-v5` |
| `AstraSignerRequest` | `helios-astra-signer-request-v5` |
| `CertificateServiceRollbackAuthorization` | `helios-certificate-service-rollback-authorization-v5` |
| `CaTransition`, pour chacune des deux signatures | `helios-ca-transition-v5` |
| `ClientTlsCaTransition` | `helios-client-tls-ca-transition-v5` |
| `AstraServiceKeyTransition`, pour chacune des trois signatures | `helios-astra-service-key-transition-v5` |
| `EmergencyAstraServiceKeyReplacement`, pour chacune de ses signatures | `helios-astra-service-key-emergency-replacement-v5` |
| `CertificateEmergencyRevocation` | `helios-certificate-emergency-revocation-v5` |

Le `ctx` est indépendant des octets `M` : chacun des domaines ci-dessus reste
aussi le préfixe de la transcription canonique correspondante. Un type absent
du tableau est non signable jusqu'à un amendement de version. Une bibliothèque
qui ne permet que `ctx = ""` ne peut pas émuler cette exigence en préfixant le
message : elle est non conforme. En particulier, toute signature produite par
`CA-PQ` avec un contexte vide est refusée.

Les domaines `helios-astra-client-renewal-approval-v5`,
`helios-astra-expired-recovery-approval-v5` et
`helios-astra-rotation-campaign-approval-v5` forment des challenges WebAuthn
hachés ; `helios-astra-issuance-policy-v1` et
`helios-astra-webauthn-assertion-fingerprint-v5` forment une empreinte et
`helios-astra-capability-token-v1` dérive une clé MAC. Aucun n'est un `ctx`
ML-DSA par lui-même.

`helios-astra-webauthn-assertion-fingerprint-v5` couvre les trois champs de
l'assertion — `authenticator_data`, `clientDataJSON`, `signature` — chacun
préfixé par sa longueur `u32`, et produit l'`assertion_fingerprint` que
`AstraRenewalApproval` transporte. Le §2.4 nommait ce champ sans fixer sa
transcription ; elle l'est ici parce qu'Astra, Helios et Orion la recalculent
tous les trois à partir des mêmes octets.

#### 2.3.2 Aléa

Les identifiants, challenges, sels, nonces, secrets de capacité et clés privées
de ce cycle suivent la même règle que la négociation v5 :

```text
source d'entropie plateforme fail-closed
    -> DRBG SP 800-90A de la bibliothèque cryptographique, force 256 bits
    -> octets consommés
```

Deux mécanismes seulement sont admis :

- **HMAC-DRBG-SHA-512** ;
- **CTR-DRBG-AES-256**, soit avec fonction de dérivation (`use_df = true`,
  SP 800-90Ar1 §10.2.1.3.2), soit avec une entrée d'entropie pleine
  d'exactement un `seedlen` (§10.2.1.3.1). Le démarrage annonce laquelle est en
  service.

Le mécanisme fournit une force de sécurité de 256 bits et vient de la
bibliothèque cryptographique du projet. Le choix est local, explicite et
journalisé ; il ne change aucun format filaire et deux pairs peuvent employer
des mécanismes autorisés différents. L'absence de fournisseur utilisable est
une erreur de démarrage. Il n'existe ni bascule silencieuse vers l'autre
mécanisme, ni acceptation d'un générateur au seul motif qu'une API le nomme
« CSPRNG ».

**La validation CAVP/ACVP n'est pas exigée par cette version.** Un déploiement
qui la veut construit la même bibliothèque dans sa variante validée : mécanisme
et format filaire identiques, seule la paperasse change. Tant que cette
variante n'est pas celle qui tourne, aucun code, journal ni document du projet
ne présente le pipeline comme validé.

Le démarrage journalise sans secret le fournisseur, sa version, le mécanisme
choisi, l'activation de `use_df` pour CTR-DRBG et l'intervalle de reseed
annoncé.

Helios, Astra et Orion **n'implémentent pas le DRBG** : aucun état
HMAC-DRBG/CTR-DRBG, primitive de mise à jour, dérivation de seed ou test de
santé n'est recodé dans le projet. Ils appellent l'interface du fournisseur
validé, configurent le profil ci-dessous et propagent ses erreurs sans produire
d'octets. Une mince adaptation de type et de configuration est permise ; elle
ne génère aucun octet elle-même. Un faux fournisseur déterministe est admis
uniquement sous `cfg(test)`, ne peut pas être sélectionné par un binaire livré
et n'est jamais présenté comme un DRBG conforme.

Un processus n'émet un identifiant, une clé ou un challenge que si le DRBG du
fournisseur est `instantiated` dans un mécanisme autorisé et que sa dernière
opération d'apport d'entropie plateforme — instanciation initiale ou reseed — a
réussi. Sinon l'appel retourne une erreur fatale et n'écrit aucun octet de
sortie.

```text
instantiate : entropy_input >= 32 octets issus de la source plateforme
              + nonce >= 16 octets issu d'un tirage distinct
reseed      : intervalle fournisseur configuré <= 2^20 appels generate,
              après chaque fork, et avant toute génération de clé privée
              ML-DSA-87, ML-KEM ou TLS
generate    : prediction_resistance = true pour une clé privée ;
              false admis pour un request_id ou un identifiant public
```

Une « génération » désigne un appel au DRBG, quelle que soit la longueur
demandée. La borne de `2^20` est configurée dans le fournisseur ou garantie par
son profil validé ; elle n'est pas réalisée par un second DRBG applicatif.
Dans le processus enfant d'un fork, le contexte fournisseur hérité est invalide
et aucun octet n'est rendu avant réinstanciation ou reseed réussi. Un échec de
la source plateforme, de son test de santé, d'instanciation, de reseed ou de
génération est ferme ; il n'existe ni repli vers l'heure, un UUID, un PRNG
généraliste ou un compteur, ni sortie partielle.

Un `request_id`, `operation_id`, `stage_id`, `transaction_id`, `vault_id`,
`slot_id`, challenge ou nonce entièrement nul est refusé à la réception. Ce
contrôle de forme ne remplace jamais le DRBG : un générateur défaillant n'a pas
le droit de produire puis de filtrer la valeur. Les octets AEAD, sels HVLT et
clés maîtresses suivent la même règle, avec `prediction_resistance = true`
pour toute clé ou secret durable.

### 2.4 Identité Astra et liaison aux YubiKeys

Chaque profil Helios contient :

```text
AstraProfile {
    authority_url: HttpsUrl,
    webauthn_rp_id: DnsName,
    astra_policy_fingerprint: [u8; 32],
    active_astra_service_public_key: MlDsa87PublicKey,
    next_astra_service_public_key: Option<MlDsa87PublicKey>,
    astra_service_key_epoch: u64,
    credential_registry_epoch: u64,
    service_key_activation_at: Option<u64>,
    service_key_retire_active_at: Option<u64>
}
```

`astra_policy_fingerprint` n'est pas appris depuis une délégation. Il est remis
dans le document d'enrôlement, affiché avec l'empreinte `CA-PQ`, confirmé hors
bande par l'opérateur puis scellé dans le profil Orion et dans le registre
Helios. Il est non nul et vaut SHA-256 de :

```text
"helios-astra-issuance-policy-v1"
|| format_version:u16=1
|| trust_domain_id:16
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| allowed_usage:u8=1
|| maximum_leaf_lifetime_secs:u64
|| maximum_stage_lease_secs:u64
|| maximum_overlap_secs:u64
|| renewal_start_percent:u8=80
|| scheduled_renewal_credentials:u8=0
|| expired_recovery_credentials:u8
|| authority_mutation_credentials:u8=2
```

`maximum_stage_lease_secs` est compris entre 1 et 86 400,
`maximum_overlap_secs` entre 1 et 2 592 000, et
`expired_recovery_credentials` vaut 1 ou 2. La valeur `allowed_usage = 1`
signifie uniquement `admitted_client_leaf_renewal`. La
délégation `AstraIssuerAuthorization`, toute campagne et tout grant doivent
porter cette
empreinte exacte ; Helios et Orion la comparent au pin avant de vérifier les
droits délégués. Une signature `CA-PQ` sur une autre politique ne remplace pas
ce pin. La v1 ne définit pas de transition en ligne de politique : la modifier
exige un document de profil réémis et une nouvelle confirmation hors bande.

`authority_url` est l'origine HTTPS de récupération et d'exploitation hors
tunnel, distincte de l'API Helios et du port QUIC. Elle n'est jamais utilisée
par un renouvellement ordinaire quand WireGuard fonctionne : Orion emploie
`heliosd_url`, et `heliosd` relaie des objets typés vers l'adresse IP privée
d'Astra. `webauthn_rp_id` est un suffixe DNS
valide de l'origine publique et reste le RP ID de l'assertion même quand ses
octets voyagent par le relais ; il ne change pas pendant une rotation du
certificat TLS du service. Deux clés de service au plus sont conservées pendant
la transition de §9.6. Elles signent les statuts, challenges, reçus de campagne
et réponses opérationnelles ; elles n'émettent aucune leaf et ne remplacent ni
`CA-PQ` ni l'émetteur délégué.

Le registre Astra associe un credential FIDO2 à :

```text
AstraCredentialBinding {
    format_version: 1,
    credential_id: BoundedBytes,
    credential_public_key: WebAuthnPublicKey,
    aaguid: [u8; 16],
    trust_domain_id: [u8; 16],
    gateway_wg_public_key: [u8; 32],
    state: active | lost | revoked,
    credential_epoch: u64,
    credential_registry_epoch: u64,
    ca_epoch: u64,
    created_at: u64,
    ca_pq_signature: MlDsa87Signature
}
```

Tous les credentials enregistrés ici sont opérateur et couvrent le domaine.
Un renouvellement client ordinaire n'emploie aucun credential. Les
récupérations, campagnes et rollbacks en exigent au moins un ; les opérations
qui touchent une ancre ou une réadmission sans continuité en exigent deux
distincts.
Un compteur WebAuthn nul ou non croissant n'est jamais la défense anti-rejeu
principale : le challenge Astra à usage unique, l'empreinte de demande et la
génération applicative la fournissent.

`ca_pq_signature` couvre tous les champs précédents sous le domaine
`helios-astra-credential-binding-v5`. Ajouter, perdre ou révoquer un credential
avance `credential_registry_epoch` et produit une nouvelle décision signée par
`CA-PQ`; `revoked` domine définitivement une ancienne liaison `active`. Le
compagnon ouvre déjà le coffre pour modifier ses key-slots et produit cette
décision dans la même opération. Helios et Orion conservent l'époque maximale
vue et refusent un binding plus ancien. Cette ancre permet de vérifier une
assertion de renouvellement sans faire confiance au seul registre en ligne
d'Astra.

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

#### 2.4.1 Format cryptographique du coffre HVLT

Le document `AuthorityVault` est un JSON strict qui transporte des conteneurs
binaires HVLT v1 en base64. Chaque conteneur suit exactement :

```text
HVLT || version:u8=1 || kdf_id:u8 || domain_len:u8 || context_len:u16be
     || domain || object_context || kdf_salt:16 || nonce:12
     || ciphertext || tag_AES_GCM:16

AAD = "helios-vault/v1" || tous les octets de l'en-tête,
      depuis HVLT jusqu'au nonce inclus
AEAD = AES-256-GCM
```

Une version, un KDF ou une longueur inconnus sont refusés ; chaque conteneur
binaire HVLT est borné à 256 Kio avant allocation. Le nonce de 96 bits et
chaque sel interne de 16 octets proviennent du DRBG de §2.3.2 et sont neufs à
chaque scellement. Une même clé AES ne réalise jamais plus de `2^32`
scellements.

Le contexte est une suite de champs sans ambiguïté :

```text
label_len:u8 || label_ASCII || value_len:u32be || value
```

L'ordre des champs fait partie du contexte. Deux usages emploient les règles
suivantes :

| Conteneur | `domain` | KDF et clé | `object_context` |
| --- | --- | --- | --- |
| `KeySlot.wrapped_master` | `helios/astra-authority-slot/v1` | `kdf_id = 3`, HKDF-SHA-256 ; IKM = sortie PRF/`hmac-secret` de 32 octets ; sel = `kdf_salt` propre à ce slot et à ce scellement ; `info = "helios/astra-authority-slot-wrapping/v1"` ; sortie 32 octets | `vault = vault_id`, puis `slot = slot_id` |
| `sealed_payload` | `helios/astra-authority-payload/v1` | `kdf_id = 0`, clé brute = clé maîtresse aléatoire de 32 octets ; le `kdf_salt` reste présent et authentifié mais n'entre pas dans la dérivation | `vault = vault_id`, puis `domain = trust_domain_id`, puis `slots = slot_table_digest` |

Le sel WebAuthn de 32 octets porté en clair par `AuthorityVault.salt` est tiré
une fois **par coffre** et remis à l'extension PRF/`hmac-secret`. Il n'est pas
le `kdf_salt` HVLT : chaque credential possède son propre secret interne et
chaque `wrapped_master` possède en plus son sel HKDF frais de 16 octets. Un sel
WebAuthn par slot empêcherait de résoudre le credential et dériver son secret
dans une seule assertion sans ajouter d'isolation cryptographique utile.

`slot_table_digest` vaut SHA-256 de la forme suivante, les lignes étant triées
lexicographiquement par `slot_id` :

```text
slot_count:u32be
|| repeated(
     slot_id:16
     || len(credential_id_base64):u32be || credential_id_base64
     || len(wrapped_master_base64):u32be || wrapped_master_base64
   )
```

Le tag de chaque slot authentifie son en-tête complet, son contexte et la clé
maîtresse enveloppée. Le tag du payload authentifie son en-tête complet, les
clés privées, la copie scellée de la clé publique `CA-PQ`, le domaine, le
`vault_id` et le digest exact de la table de slots. Après ouverture, la copie
publique `ca_pq_public_key` doit égaler la copie scellée. `rp_id`, le sel
WebAuthn et `credential_id` participent nécessairement à l'obtention du secret
qui ouvre le slot ; leur modification fait échouer l'ouverture.

`label`, `role`, `enrolled_at` et `created_at` sont des métadonnées
opérationnelles en clair et ne prennent part ni au contexte AEAD ni à une
décision d'autorisation ; aucune règle de sécurité ne peut les consulter.
Renommer un slot ne rescelle donc pas le coffre. L'empreinte du document complet
permet de détecter leur modification dans un relais ou une sauvegarde, mais ne
les transforme pas en autorité cryptographique.

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

Les deux objets suivants décrivent l'ancienne approbation par demande. Ils
restent décodables pour diagnostiquer un journal antérieur à §0.7, mais Astra
n'en produit plus et Helios/Orion les refusent comme autorité d'un
renouvellement planifié courant :

```text
AstraCredentialApprovalRequest {
    format_version: 1,
    operation_id: [u8; 16],
    request_fingerprint: [u8; 32],
    trust_domain_id: [u8; 16],
    gateway_wg_public_key: [u8; 32],
    client_wg_public_key: [u8; 32],
    active_generation: u64,
    requested_generation: u64,
    credential_registry_epoch: u64,
    webauthn_rp_id: DnsName,
    webauthn_origin: HttpsOrigin,
    allowed_credential_ids: BoundedList<BoundedBytes, 8>,
    required_credentials: 1,
    created_at: u64,
    expires_at: u64,
    astra_service_key_epoch: u64,
    astra_signature: MlDsa87Signature
}
```

`expires_at` est au plus cinq minutes après `created_at`. Le challenge WebAuthn
est le SHA-256 de la forme canonique ci-dessous :

```text
"helios-astra-client-renewal-approval-v5"
|| format_version:u16 || operation_id:16 || request_fingerprint:32
|| trust_domain_id:16 || gateway_wg_public_key:32 || client_wg_public_key:32
|| active_generation:u64 || requested_generation:u64
|| credential_registry_epoch:u64
|| len(webauthn_rp_id):u32 || webauthn_rp_id
|| len(webauthn_origin):u32 || webauthn_origin
|| repeated(len(credential_id):u32 || credential_id)
|| created_at:u64 || expires_at:u64
```

Dans ce format historique, `astra-signer` vérifie d'abord la signature de
service et affiche ces champs,
puis demande `userPresence` et `userVerification` sous le `webauthn_rp_id` et
l'origine signés, avec au plus les huit credentials actifs énumérés. L'origine
WebAuthn signée reste l'origine Astra attendue et ne devient jamais l'URL HTTP
de la gateway.

Après vérification de l'origine, du RP ID, du credential actif, du challenge et
de sa consommation unique, Astra persiste :

```text
AstraRenewalApproval {
    format_version: 1,
    operation_id: [u8; 16],
    request_fingerprint: [u8; 32],          # ClientCertificateRotationRequest
    approval_request_fingerprint: [u8; 32], # AstraCredentialApprovalRequest signé
    credential_binding: AstraCredentialBinding,
    credential_fingerprint: [u8; 32],
    assertion_fingerprint: [u8; 32],
    webauthn_assertion: BoundedWebAuthnAssertion,
    approved_at: u64,
    expires_at: u64,
    astra_service_key_epoch: u64,
    astra_signature: MlDsa87Signature
}
```

La signature de service couvre :

```text
"helios-astra-renewal-approval-v5"
|| format_version:u16 || operation_id:16
|| request_fingerprint:32 || approval_request_fingerprint:32
|| credential_fingerprint:32 || assertion_fingerprint:32
|| approved_at:u64 || expires_at:u64 || astra_service_key_epoch:u64
```

Les deux empreintes ne sont pas interchangeables. La première désigne la
demande de rotation cliente de §7.1 ; la seconde désigne la demande
d'approbation signée qui a produit le challenge WebAuthn. Chaque consommateur
recalcule les deux, puis recalcule le challenge depuis la seconde demande.

`approved_at <= expires_at <= min(request.expires_at, approved_at + 300)` est
vérifié sous l'horloge Astra.

L'approbation est indissociable de la demande et n'est consommable que pour
son émission `active + 1`. Son empreinte entre dans l'autorisation de staging
et le grant. Astra, Helios et Orion vérifient tous le binding sous `CA-PQ`, son
époque non reculée, le `rpIdHash`, les drapeaux de présence et vérification
utilisateur, le challenge de l'assertion et sa validité cryptographique sous la
clé publique du credential. L'assertion autorise l'usage de l'émetteur délégué ;
elle ne contient aucune sortie PRF, n'ouvre aucun key-slot et n'est pas un champ
de signature ML-DSA produit par la YubiKey.

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

Dans une demande ou une transition, le champ filaire
`gateway_identity_epoch` nomme l'époque **candidate**, donc la décision
`gateway_decision_epoch + 1`; il ne prétend pas nommer la leaf encore servie.
Un avortement consomme cette époque sans modifier
`active_gateway_identity_epoch`. Les époques des leafs effectivement promues
peuvent par conséquent contenir des trous, tandis que les décisions restent
strictement séquentielles.

Quand un slot suivant existe, `retire_active_at` n'est pas une seconde source
de calendrier : il vaut obligatoirement le `not_after` de la transition exacte
qui a créé ce slot. Il est absent avec le slot suivant et est effacé avec lui à
l'avortement, la révocation ou la promotion.

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

Ce type est partagé, mais ses états sont propres au détenteur. Helios ne
persiste qu'un `pending_grant` et le conserve ainsi jusqu'au commit ; Orion ne
passe son candidat à `pending_commit` qu'après avoir vérifié et persisté le
grant. Le champ `next` signifie normativement `next_committed` : aucun reçu,
grant ou écoulement du temps ne le renseigne. Quand il existe,
`retire_active_at` vaut exactement le `not_after` de la fenêtre du grant qui a
été committé.

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
| `allowed_usage` | valeur unique `operator_approved_admitted_client_leaf_renewal` |
| `maximum_leaf_lifetime_secs` | positive et bornée par la politique du domaine |
| `policy_fingerprint` | pin exact `astra_policy_fingerprint` de §2.4 |
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
délégation, l'égalité de `policy_fingerprint` avec le pin local, puis la
signature opérationnelle. L'émetteur refuse et les
consommateurs rejettent un premier enrôlement, une récupération expirée, une
réadmission, une rotation gateway ou CA, un pair révoqué, une génération autre
que `active + 1`, une validité supérieure au plafond ou, pour le chemin
ordinaire, une liaison différente entre `renewal_authorization_fingerprint` et
`request_fingerprint`. Sa
révocation domine toute émission non encore installée.

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

Les objets signés et les API conservent ces instants sous forme de secondes
Unix. Leur affichage destiné à l'opérateur est uniformisé sur l'heure civile
`Europe/Paris` : CET en hiver et CEST en été. Ce rendu ne participe ni aux
comparaisons ni aux signatures.

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
`not_after`. Astra peut publier une `suggested_window` qui anticipe
`renewal_at`, mais ne peut jamais le retarder. Orion utilise l'instant exact de
80 % afin de conserver toute la marge restante pour les reprises.

À 80 %, Orion génère puis scelle les clés candidates, émet la demande et
conduit automatiquement le stage et le commit dans WireGuard. À 90 %, un
renouvellement inachevé devient une alerte persistante ; à 95 %, il devient
critique et se représente quotidiennement. Ces seuils ne modifient ni la
validité, ni la fenêtre de chevauchement de 30 jours, ni le refus après
expiration.

Le planificateur ordinaire n'emploie aucune YubiKey et ne peut employer que
l'émetteur Astra actif, pour un pair admis et non révoqué, avec les preuves de
continuité par la génération active et les preuves de possession des clés
**candidates** TLS et PQ. À ce stade, aucune génération `next` n'existe encore :
elle ne naît qu'au commit de §7.3. Un refus ou une coupure laisse la leaf
actuelle inchangée ; Orion réessaie à la connexion suivante. Astra peut avancer
la fenêtre par une campagne signée en cas d'incident ; elle ne peut jamais la
repousser au-delà du calcul local d'Orion.

### 4.4 Rollback de service, jamais rollback d'état

Pendant `overlap`, une sélection manuelle peut demander de servir ou présenter
temporairement l'ancienne leaf. Elle ne modifie aucun compteur, n'efface pas le
slot suivant et porte une échéance au plus égale au `not_after` de la
transition. Elle est refusée dans `active`, `promoted`, `expired` ou `revoked`.

Sur une gateway, cette sélection reste une décision de service signée par
`CA-PQ` et approuvée avec un credential actif. Dans Orion, elle sélectionne
localement une identité cliente dont les deux générations ont déjà été
autorisées par le grant approuvé et acceptées par la gateway pendant le
chevauchement : elle ne requiert donc pas un second objet signé. Ce sélecteur
local ne peut ni ouvrir une rotation, ni modifier une génération, une époque
ou une révocation.

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
| `request_id` | 16 octets produits selon §2.3.2 ; la valeur nulle est refusée à la réception sans tenir lieu de contrôle du DRBG |
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
|| next_gateway_tls_certificate_present:u8
|| SHA-256(next_gateway_tls_certificate_der):32 si present == 1
|| active_gateway_certificate_fingerprint:32
|| next_gateway_certificate_present:u8
|| next_gateway_certificate_fingerprint:32 si present == 1
|| not_before:u64 || activation_at:u64 || not_after:u64
|| reason:u8
```

Chaque discriminant `present` vaut exactement `0` ou `1`; toute autre valeur
est refusée. À `0`, aucun octet de valeur ne suit. À `1`, exactement 32 octets
suivent. Les deux optionnels sont décodés indépendamment et dans l'ordre
ci-dessus. Ainsi, une transition TLS seule et une transition PQ seule ne
partagent jamais la même transcription, même si elles ont la même longueur.

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
7. `revoked` : état terminal de l'identité gateway quand la règle d'urgence de
   §10 nomme une leaf de la génération active ; il domine toutes les phases et
   toutes les dates.

La révocation n'est pas une simple arête de cette machine, car elle vise une
empreinte et non une phase. Depuis `active`, `staged`, `published`, `aborted`,
`overlap` ou `promoted`, une révocation qui atteint la génération active place
l'identité gateway entière en `revoked`, retire tout candidat et interdit
rotation, récupération et rollback. Si elle n'atteint que la génération
suivante en `staged`, `published` ou `overlap`, cette transition est retirée et
son tombstone de révocation empêche sa réintroduction, mais l'identité active
non visée reste `active`. Si les deux générations sont visées, la règle de la
génération active gagne. Ces effets sont atomiques avec l'avancement de
`revocation_epoch`.

L'avortement emploie un `GatewayTransitionAbort` contenant
`format_version`, `protocol_version`, `trust_domain_id`, `ca_epoch`,
`gateway_wg_public_key`, `server_name`, le
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
Au démarrage, `heliosd` ne sélectionne le slot suivant qu'après
`activation_at` et si `published` est durable. À `not_after`, sa maintenance
persiste d'abord `promoted`, compose le nouveau slot actif avec les seules
moitiés nommées par la transition, puis remplace atomiquement le coffre actif
et supprime l'ancien. Le slot candidat et un marqueur de promotion restent
jusqu'à la fin de cette séquence afin qu'une coupure puisse la rejouer sans
réactiver l'ancienne génération.

## 7. Rotation de l'identité cliente

### 7.1 Demande

Les nouvelles clés TLS et ML-DSA-87 naissent dans le stockage protégé d'Orion.
`ClientCertificateRotationRequest` contient :

- `format_version = 1`, `protocol_version = 5` ;
- `request_id` de 16 octets produit selon §2.3.2 ; la valeur nulle est refusée
  à la réception sans tenir lieu de contrôle du DRBG ;
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
révocation. À partir de 80 %, l'empreinte exacte de cette demande signée
autorise l'émetteur délégué ; aucune assertion YubiKey n'est créée.

Un renouvellement ordinaire peut être signé par l'émetteur délégué de §3.4.
Toute autre raison exige `CA-PQ`. Astra construit d'abord un
`ClientCertificateStageAuthorization` :

```text
"helios-client-certificate-stage-authorization-v5"
|| format_version:u16 || protocol_version:u16
|| trust_domain_id:16 || ca_epoch:u64 || ca_tls_epoch:u64
|| issuer_kind:u8 || issuer_epoch:u64
|| issuer_authorization_fingerprint:32
|| stage_id:16 || request_fingerprint:32 || renewal_authorization_fingerprint:32
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
signature opérationnelle. `renewal_authorization_fingerprint` n'est jamais nul :
il est égal à `request_fingerprint` pour un renouvellement ordinaire
automatique, ou désigne l'autorisation de campagne/récupération correspondante
pour les autres chemins.
Les raisons `expired_recovery`, `readmission`, `emergency_replacement` et
`manual_global` sont interdites à l'émetteur Astra, sauf que `manual_global`
peut viser des leafs actives si la campagne YubiKey ne change ni admission, ni
autorité, ni politique.

Dans tous les chemins, Astra remet cette autorisation **directement à Helios**
par le veth privé mTLS et attend le reçu sur cette même relation. Orion ne voit
jamais cette autorisation et ne sert jamais de messager entre Astra et Helios.
Ce qui change selon le chemin est seulement l'entrée de la demande : Helios la
reçoit de la VIP du pair dans WireGuard pour un renouvellement ordinaire ;
Astra la reçoit en HTTPS public pour la récupération de §7.5. Helios vérifie
la propriété du pair déjà liée à l'opération, les empreintes, la génération, la
révocation, la signature et la liaison d'autorisation exacte transportée avec
l'autorisation. Il exige une lease positive d'au plus 24 heures et
`stage_expires_at <= request.expires_at` lorsque la demande lui est accessible.
Pour toute raison autre que `expired_recovery`, il exige aussi
`stage_expires_at <= activation_at`. Une récupération expirée peut porter un
`activation_at` déjà atteint : sa lease borne uniquement le délai du commit,
et l'état `pending_grant` interdit encore de présenter le candidat. Helios
persiste ce candidat dans `pending_grant` avant toute réponse ; ce candidat
n'est pas encore un slot `next` activable.

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
    renewal_authorization_fingerprint,
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

Le préfixe `Gateway` nomme ici **l'émetteur et le signataire du reçu**. L'objet
atteste toujours le staging d'un certificat client ; ce n'est ni une demande,
ni un reçu de rotation du certificat gateway.

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
|| request_fingerprint:32 || renewal_authorization_fingerprint:32
|| stage_receipt_fingerprint:32
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

Le grant transporte les deux certificats, le reçu, l'autorisation applicable
et éventuellement `AstraIssuerAuthorization`. Orion recalcule leurs
empreintes, vérifie la chaîne TLS, la chaîne PQ, les usages, la demande locale,
la liaison automatique ou la preuve YubiKey exigée par le motif, le reçu
Helios, les périodes et la signature finale avant toute écriture. Il retrouve
les deux clés privées
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
utilisée ; l'ancienne reste admise jusqu'à `not_after`. Si `activation_at` est
déjà atteint lors d'une récupération expirée, le commit est donc l'événement
qui rend la nouvelle génération immédiatement utilisable.

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
|| format_version:u16 || protocol_version:u16
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

La récupération emploie une seule cérémonie `GetAssertion` pour le credential
requis. Le challenge est celui ci-dessus et la même requête transporte le sel
PRF/`hmac-secret` du coffre : le toucher et le PIN produisent à la fois
l'assertion vérifiable liée à la demande et le secret qui ouvre le key-slot.
Le compagnon vérifie l'assertion avant d'employer ce secret, puis le zéroïse
avec les clés maîtresses. Une politique exigeant deux credentials répète cette
cérémonie une fois par credential distinct. Le renouvellement ordinaire, lui,
ne demande aucun sel de coffre et n'ouvre jamais `CA-PQ` ni `CA-TLS`.

La récupération est refusée si le pair est absent ou `revoked`, si une
génération plus récente existe, si l'ancienne clé n'est plus possédée ou si les
nouvelles preuves échouent. `CA-PQ`, jamais l'émetteur Astra, autorise alors le
staging de §7.2 : `astra-signer` ouvre localement le coffre, signe
l'autorisation exacte puis Astra la remet à Helios par le veth privé. Astra
attend le reçu §7.3 avant de remettre le grant. La fenêtre porte
`activation_at` à l'instant de la cérémonie : le candidat reste bloqué en
`pending_grant` jusqu'au double commit, puis Helios l'admet et Orion promeut sa
paire scellée sans attendre l'expiration de la demande. Si l'ancienne clé
privée a disparu avec le stockage DPAPI/TPM, cette procédure ne s'applique pas :
il faut une réadmission opérateur à deux YubiKeys.

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
  `full_certificate_chain`, `trust_authorities`, `emergency_revocation` ou
  `gateway_identity` ;
- pour chaque cible, type, clé WireGuard, époque, génération et empreintes
  actives exactes ;
- `reason`, `requested_by` et le pin exact `astra_policy_fingerprint` de
  §2.4 ;
- le nombre de credentials opérateur exigé.

La YubiKey approuve le SHA-256 de la représentation canonique complète sous le
domaine `helios-astra-rotation-campaign-approval-v5`. Astra refuse toute cible
ajoutée, retirée ou modifiée après cette approbation. `orion_device` ne vise que
les profils Helios présents sur cet appareil ; `fleet_leafs` ne tourne aucune
CA ; `full_certificate_chain` ordonne émetteur, CA TLS, gateway puis clients ;
`trust_authorities` tourne aussi `CA-PQ` et exige deux credentials opérateur.
`emergency_revocation` ne renouvelle rien : il fige exactement une identité,
ses empreintes actives et son compteur courant pour produire l'objet du §10 ;
il n'autorise ni une rotation cliente ni une transition d'ancre.
`gateway_identity` fige l'identité gateway en service — ses deux empreintes
actives et l'époque de décision courante — pour produire soit la
`GatewayIdentityTransition` de §6.1, soit le `GatewayTransitionAbort` de §6.3.
Il ne tourne aucune ancre et n'autorise aucune rotation cliente. La relation
d'époque diffère entre les deux objets : une transition porte
`decision_epoch + 1`, un avortement porte l'époque déjà mise en attente, parce
que sa campagne s'ouvre après le staging. Accepter les deux relations pour un
même objet laisserait une ligne approuvée autoriser deux décisions
différentes.

Ces portées forment quatre familles d'objets, et une campagne n'en produit
qu'une : aucun objet signé, pour les portées clientes ; une transition d'ancre ;
une décision d'identité gateway ; une révocation. Un objet déposé sous une
campagne d'une autre famille est refusé, dans les deux sens.

`CampaignScope::GatewayBootstrap` porte uniquement la politique à deux
credentials du §13.1. `AstraRotationCampaign::validate` le refuse : avant le
premier registre il n'existe ni campagne en ligne, ni état sortant à figer, ni
clé de service capable de signer `AstraSignerRequest`.

Astra signe ensuite `AstraSignerRequest` de §2.4. Pour un profil actif, Orion
ouvre le compagnon avec `heliosd_url` et `operation_id`; la requête et le
résultat suivent le relais de §8.1.2. Une récupération ou une console opérateur
hors tunnel emploie `authority_url`. Le compagnon récupère lui-même la requête
et le manifeste, vérifie leurs signatures et affiche au minimum le scope, le
nombre de cibles, les empreintes actives, les générations et les autorités
touchées. Pour une simple opération déléguée, il renvoie l'assertion FIDO liée
au manifeste. Quand `CA-PQ` ou `CA-TLS` doit signer, il télécharge aussi le
coffre chiffré, l'ouvre avec le ou les key-slots exigés, produit localement les
signatures puis zéroïse les clés. Il ne renvoie jamais le secret PRF, une clé
de déverrouillage ou une clé privée.

Un rollback manuel produit `CertificateServiceRollbackAuthorization`, lié à
la transition, au slot sélectionné, à la campagne YubiKey et à une échéance au
plus égale à `not_after`. Il ne change ni génération ni contenu des slots. La
sélection de l'ancienne identité est refusée après promotion ou révocation.

## 8. Distribution des mises à jour

### 8.1 Canal ordinaire dans le tunnel

#### 8.1.1 Mise à jour de confiance

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

Une gateway ancienne répond `404` ; Orion conserve alors sa confiance actuelle
et propose le document hors ligne de §8.4. La route actuelle répond `503`
quand elle sait le client en retard mais ne détient encore aucun objet Astra
signé à distribuer. Orion n'accepte jamais pour autant un certificat expiré,
une génération ancienne ou un repli vers un pin unique. Les messages de
négociation PSK et leurs transcriptions signées ne changent pas.

Avant toute vérification ML-DSA, l'API résout l'adresse source réelle vers son
unique pair admis, selon la même règle que les autres routes authentifiées de
`helios-api`. Aucun en-tête de proxy n'est accepté. La clé WireGuard cliente du
corps est ensuite comparée à ce pair ; elle ne sert jamais d'index dans la
table. Cette résolution prouve que l'appel traverse un tunnel établi par la
clé WireGuard admise.

`AuthenticatedTrustUpdateRequest` contient la requête, le certificat PQ client
d'une génération admissible à l'instant courant et une signature ML-DSA-87.
La requête contient un `request_id` de 16 octets produit selon §2.3.2 — la
valeur nulle est refusée à la réception sans tenir lieu de contrôle du DRBG —,
les identités WireGuard, les générations connues et les empreintes actives.
Elle contient aussi `base_state_fingerprint`, empreinte de l'état local complet
calculée par Orion selon la forme canonique ci-dessous. Astra la traite comme
un jeton opaque : sa présence sous la signature du client suffit à lier la
décision au magasin qui la recevra. Elle ne contient ni challenge public, ni
horodatage : l'anti-rejeu du transport WireGuard protège le paquet, et les
générations ainsi que les empreintes signées empêchent tout rollback de l'état
applicatif. La signature couvre :

```text
AuthenticatedTrustUpdateRequest {
    request: TrustUpdateRequest,
    certificate: PqCertificate,
    ml_dsa_87_signature: MlDsa87Signature
}
```

L'enveloppe n'ajoute aucun champ signé implicite. Les octets signés sont
exactement la forme suivante ; le certificat complet est lié par
`client_pq_certificate_fingerprint`, recalculée avant vérification de la
signature :

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
|| base_state_fingerprint:32
```

Les trois empreintes clientes ont des rôles distincts. Les champs
`active_client_tls_certificate_fingerprint` et
`active_client_pq_certificate_fingerprint` forment le snapshot indivisible de
la génération encore enregistrée comme `active`, dont le numéro est
`client_identity_generation`. Le champ
`client_pq_certificate_fingerprint` nomme la leaf PQ complète transportée avec
la requête et dont la clé signe ces octets. Hors chevauchement, cette troisième
empreinte est donc égale à l'empreinte PQ active. Pendant le chevauchement,
elle peut être celle de `next`, mais seulement à partir de `activation_at`,
tandis que les deux champs `active_*` continuent de décrire l'ancien slot
jusqu'à sa promotion atomique.

`base_state_fingerprint` n'est pas une seconde description de ces champs. Les
compteurs et empreintes explicites permettent à Helios et Astra de déterminer
les objets manquants ; l'empreinte exhaustive protège la comparaison finale
contre tout état local non transporté — tombstones, statuts déjà vus,
révocations différées, slots pending et fenêtres. Un client ne peut mentir sur
cette valeur qu'à lui-même : le manifeste ainsi produit ne committera que sur
le magasin qui hache vers cette valeur.

La gateway exige que le pair WireGuard résolu, le certificat PQ présenté, sa
génération retrouvée par son empreinte et le snapshot TLS/PQ désignent cet
unique état autorisé. Elle refuse un snapshot actif mélangé, une leaf présentée
qui ne correspond pas à un des slots admissibles ou un `next` présenté trop
tôt. Une répétition de `request_id` peut être servie de manière idempotente ;
sa mémorisation est une
borne opérationnelle et non la défense anti-rejeu principale. Les objets de
réponse restent rejouables sans rollback grâce à leurs générations et
signatures.

La réponse `200 OK` contient facultativement un manifeste et son
`TrustUpdateChunk`; leur absence signifie que la confiance est à jour. Elle ne
contient pas de statut Astra signé : la gateway ne détient pas la clé de
service et ne fabrique aucune fraîcheur. Tous les objets sont pré-signés par
Astra ou l'autorité maîtresse ; la gateway n'appelle jamais une clé CA et ne
réalise aucune signature de CA à la demande. Si le client est en retard et
qu'aucune transaction liée à son `base_state_fingerprint` n'est en file,
Helios remet la requête authentifiée et son propre snapshot de pair à la route
privée typée de préparation :

```text
POST https://<adresse-veth-Astra>:8445/internal/v1/trust-update/prepare
```

Le corps est un `RelayedTrustUpdatePreparation` construit par Helios : clé du
pair résolue depuis la VIP, `AuthenticatedTrustUpdateRequest` exacte et
`PeerCertificateStateView` lu sous le même verrou que la décision « en
retard ». Astra compare les trois copies de l'identité et refuse tout écart.
La réponse est soit une `TrustDistribution` complète que Helios place dans sa
file, soit un refus grossier ; elle n'est jamais un proxy HTTP. Une
indisponibilité d'Astra ou l'absence d'un objet d'autorité déjà signé rend
`503`, jamais un faux « à jour ». Les erreurs HTTP sont volontairement
grossières :
`400` pour le JSON ou la version, `401` si la source n'est pas un pair admis,
`403` pour une identité, un certificat ou une signature refusés, `413` au-delà
de 32 Kio, `415` hors JSON et `500` après une erreur interne. Le motif détaillé
reste dans le journal protégé de la gateway.

Une suite qui ne tient pas dans 64 Kio reste **une seule transaction logique**.
Son `TrustUpdateTransactionManifest` contient un `transaction_id`, la cible,
le `base_state_fingerprint` déclaré par cette cible, `created_at`, `expires_at`,
`chunk_count`, la liste ordonnée des empreintes d'objets, leurs dépendances,
l'instant d'activation minimal et l'autorité du manifeste. Sur le canal en
ligne, cette autorité est toujours la clé de service Astra active. Sa signature
couvre le manifeste canonique complet, mais ne remplace jamais les signatures
propres des objets : toucher une CA, la clé de service ou l'identité gateway
continue d'exiger l'objet `CA-PQ` correspondant, produit par le compagnon si le
coffre est nécessaire. Chaque chunk répète son empreinte, porte son index et
contient des objets complets contigus ; un objet individuel encodé au-delà de
60 Kio est refusé à l'émission et n'est jamais fragmenté.

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
suivantes, pending et tombstones connus **localement par Orion**. Seul son hash
voyage ; Astra ne reconstruit ni n'adopte ce préimage. Pour une transaction en
ligne, `manifest_authority_kind` vaut obligatoirement `astra_service_key` et
son époque est celle que le client déclare encore active. La valeur `ca_pq` est
réservée et refusée dans ce type de réponse. `prerequisite_bitmap` référence
uniquement des objets d'indice inférieur, `object_count` est borné à 64 et les
bits hors de cette borne sont refusés. Le manifeste et chaque objet ont leur
signature propre ; le chunk est lié par les empreintes du manifeste et des
objets.

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

#### 8.1.2 Renouvellement client relayé

Quand la leaf cliente est encore valide et que WireGuard fonctionne, Orion ne
contacte jamais l'origine publique Astra. Il utilise exclusivement :

```text
POST http://<adresse-WireGuard-gateway>:8080/api/key-negotiation/certificate-renewal/request
GET  http://<adresse-WireGuard-gateway>:8080/api/key-negotiation/certificate-renewal/operations/<operation_id>
POST http://<adresse-WireGuard-gateway>:8080/api/key-negotiation/certificate-renewal/stage-commit
```

Ces routes partagent l'authentification de §8.1.1 : la VIP source est résolue
avant désérialisation cryptographique, l'opération est liée à ce pair, puis la
clé WireGuard du corps est seulement comparée au pair résolu. Un autre pair ne
peut ni lire l'opération, ni récupérer le challenge du compagnon, ni déposer
une assertion ou un commit. Aucun en-tête de proxy, cookie de navigateur ou
jeton porteur non lié au pair ne remplace cette preuve.

`heliosd` n'est pas un reverse proxy vers Astra. Chaque route accepte un type
et une taille propres, vérifie les identifiants, générations et empreintes
qu'elle sait vérifier, puis relaie la représentation canonique sur le veth.
Les redirections, méthodes, chemins et en-têtes choisis par le client ne sont
jamais relayés. Les erreurs retournées à Orion restent grossières ; le motif
détaillé est journalisé côté Helios et Astra.

Le déroulement normal est :

1. Orion dépose `ClientCertificateRotationRequest` par la route `request` ;
2. Helios authentifie le pair et transmet la demande à Astra par le veth ;
3. Astra vérifie la fenêtre, l'admission, la révocation, la délégation, la
   génération et les signatures, puis persiste l'opération autorisée ;
4. Astra émet les leafs et
   `ClientCertificateStageAuthorization`, puis la renvoie à Helios ;
5. Helios vérifie et persiste le stage, signe
   `GatewayCertificateStageReceipt` et le transmet à Astra par le veth ;
6. Astra vérifie le reçu, persiste et signe le grant ; l'interrogation de
   l'opération le remet à Orion à travers Helios ;
7. Orion vérifie et persiste le candidat, puis envoie
   `ClientCertificateStageCommit` par `stage-commit` ; Helios committe avant de
   confirmer. La synchronisation d'admission suivante rend ce commit visible à
   Astra ; cette observation tardive ne conditionne pas le succès déjà persisté
   par Helios.

Une coupure après une étape se reprend par le même `operation_id` et les mêmes
empreintes. Un octet différent sous le même identifiant est un conflit. Une
reprise ne change ni génération, ni clés candidates et ne bascule vers le
canal public.

### 8.2 Canal public Astra

Le profil contient `authority_url`, `webauthn_rp_id` et le pin
`astra_policy_fingerprint`. Orion ne contacte cette origine directement que
lorsqu'il ne peut plus établir WireGuard. Une opération opérateur ne l'emprunte
que depuis une machine réellement hors tunnel : depuis un tunnel monté, elle
passe par §8.5, et l'échec de ce chemin ne se rabat pas ici. Le port QUIC n'est
jamais un repli. Les routes
publiques versionnées sont :

```text
POST /v1/status/challenge
POST /v1/status/query
POST /v1/client-rotation/recovery
POST /v1/campaigns
GET  /v1/operations/<operation_id>
GET  /v1/signer-requests/<operation_id>
GET  /v1/vaults/<encrypted_vault_fingerprint>
POST /v1/signer-results/<operation_id>
```

Les routes ordinaires `client-rotation/request` et `stage-commit` ne sont pas
exposées sur ce canal. Les routes génériques d'opération et du compagnon ne
servent publiquement que les opérations créées par récupération ou campagne
hors tunnel ; un `operation_id` de renouvellement ordinaire y reçoit le même
refus grossier qu'un identifiant inconnu. Le service exige HTTPS, refuse toute
origine WebAuthn différente et n'active aucun CORS permissif. Les corps sont
limités à 64 Kio avant désérialisation,
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

Le jeton v1 est un bearer MACé, transmis uniquement dans
`Authorization: Bearer <base64url-sans-padding>` et jamais dans une URL, un
cookie ou un journal. Au démarrage, Astra tire avec §2.3.2 une clé
`K_capability` de 32 octets avec `prediction_resistance = true`, conservée
seulement en mémoire et zéroïsée à l'arrêt. Un redémarrage invalide les jetons
encore vivants ; une opération authentifiée peut en faire émettre de nouveaux.

Chaque scope possède un jeton distinct : `0 = signer_request_read` pour
`GET /v1/signer-requests/<operation_id>`, `1 = encrypted_vault_read` pour
`GET /v1/vaults/<fingerprint>` et `2 = signer_result_submit` pour
`POST /v1/signer-results/<operation_id>`. Le scope vaut exactement ces valeurs
et lie donc aussi la méthode et le gabarit de route. Le payload canonique est :

```text
token_version:u8=1
|| scope:u8
|| operation_id:16
|| operation_manifest_fingerprint:32
|| vault_present:u8
|| encrypted_vault_fingerprint:32 si vault_present == 1
|| issued_at:u64 || expires_at:u64
|| token_nonce:16
```

`vault_present` vaut seulement 0 ou 1. Le scope `encrypted_vault_read` exige 1
et les deux autres répètent la valeur de l'opération. `token_nonce` vient du
DRBG et n'est jamais nul. La clé MAC est dérivée ainsi :

```text
PRK = HKDF-Extract-SHA-256(salt = operation_id, IKM = K_capability)
K_token = HKDF-Expand-SHA-256(
    PRK,
    info = "helios-astra-capability-token-v1"
           || scope:u8
           || operation_manifest_fingerprint:32
           || vault_present:u8
           || encrypted_vault_fingerprint:32 si vault_present == 1
           || issued_at:u64 || expires_at:u64,
    L = 32
)
tag = HMAC-SHA-256(K_token, payload_canonique)
jeton = base64url_sans_padding(payload_canonique || tag:32)
```

Les entiers sont big-endian et l'optionnel suit le même discriminant strict que
§6.2. Astra compare le tag en temps constant, exige
`issued_at <= now < expires_at <= operation.expires_at` et
`expires_at - issued_at <= 300`. Les lectures peuvent être rejouées à
l'identique pendant cette fenêtre ; `signer_result_submit` est consommé
atomiquement au premier résultat accepté. Le jeton ne dérive ni d'une clé CA,
ni de la clé de service Astra, et ne confère aucun droit sur une autre
opération, un autre manifeste, un autre coffre, scope, chemin ou méthode.

Astra publie un statut signé :

```text
AstraCertificateStatus {
    format_version: 1,
    trust_domain_id,
    certificate_fingerprint,
    certificate_kind,
    generation,
    status: active | renewal_due | pending_grant |
            pending_commit | staged | published | aborted | overlap |
            promoted | expired | revoked,
    suggested_window_start,
    suggested_window_end,
    produced_at,
    next_update,
    status_epoch,
    astra_service_key_epoch,
    astra_signature
}
```

Le champ reste une chaîne sur le fil, mais son type logique est sélectionné par
`certificate_kind`; il n'existe pas un enum libre commun à toutes les familles.
Le décodeur **doit** refuser une combinaison absente de ce tableau :

| Famille issue de `certificate_kind` | États admis |
| --- | --- |
| `client_tls`, `client_pq` | `active`, `renewal_due`, `pending_grant`, `pending_commit`, `overlap`, `promoted`, `expired`, `revoked` |
| `gateway_tls`, `gateway_pq` | `active`, `renewal_due`, `staged`, `published`, `aborted`, `overlap`, `promoted`, `expired`, `revoked` |
| `ca_pq`, `ca_tls`, `astra_service_key` | `active`, `renewal_due`, `staged`, `overlap`, `promoted`, `expired`, `revoked` |
| `astra_issuer` | `active`, `renewal_due`, `expired`, `revoked` |

`pending_grant` et `pending_commit` décrivent le candidat exact.
`awaiting_operator` reste réservé aux récupérations et campagnes opérateur ;
il n'est jamais émis pour une leaf cliente active arrivée à 80 %.
`promoted` atteste la
mutation qui vient de rendre la génération active ; un statut ultérieur sans
nouvelle mutation la décrit comme `active`. `aborted` ne s'applique qu'à
l'empreinte candidate de la transition gateway annulée, jamais à la leaf
active restée servie.

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

Astra et Helios communiquent sur une paire veth dédiée. Chaque extrémité reçoit
une adresse IP statique issue d'un préfixe privé propre à la gateway. Cette
adresse n'est ni publiée dans le DNS, ni transportée dans les profils : Helios
est le seul client de l'API Astra privée et Astra le seul client de l'API
Helios privée. Le namespace Astra n'a ni route par défaut sur cette interface,
ni forwarding, ni accès aux adresses de pairs.

L'API Helios appelée par Astra porte le staging de **tout** candidat client,
ainsi que le commit de récupération et les campagnes qui ne peuvent pas
provenir d'un tunnel actif :

```text
POST /internal/v1/certificates/stage
POST /internal/v1/certificates/stage-commit   # récupération seulement
POST /internal/v1/certificates/revoke
GET  /internal/v1/certificates/state/<identity>
GET  /internal/v1/certificates/gateway-identity
POST /internal/v1/certificates/gateway-transition/published
POST /internal/v1/certificates/distribution
```

`gateway-identity` rend la leaf que le démon **sert**, jamais celle qu'un
registre a enregistrée : un reçu se vérifie sous la clé qui l'a signé, et une
campagne d'identité gateway se fige sur l'état réellement en service.
`gateway-transition/published` porte le marqueur de §6.3 ; il nomme la
transition exacte, parce qu'un opérateur peut en avoir installé une à la main
pendant que l'autorité en publiait une autre. `distribution` met en file une
transaction déjà signée pour le pair que son manifeste nomme.

`POST /internal/v1/campaigns/apply`, nommé dans une version antérieure de ce
document, n'est **pas** routé : une campagne s'applique sous une approbation
opérateur que ce chemin ne porte pas, et la route publique `/v1/campaigns`
répond `501` pour la même raison. Il est refusé par le repli comme tout chemin
inconnu, plutôt que réservé par un gestionnaire vide.

L'API Astra appelée par Helios porte le relais ordinaire et la préparation des
transactions de confiance :

```text
POST /internal/v1/client-rotation/request
GET  /internal/v1/client-rotation/operations/<operation_id>
GET  /internal/v1/client-rotation/signer-requests/<operation_id>
POST /internal/v1/client-rotation/signer-results/<operation_id>
POST /internal/v1/trust-update/prepare
```

Deux routes nommées dans une version antérieure de ce document n'existent pas
et ne sont pas attendues. `POST /internal/v1/client-rotation/stage-receipt` a
été remplacée par l'amendement du 16 août : le reçu revient dans la **réponse**
au staging, sur le même appel, ce qui supprime la fenêtre où une autorisation
est posée sans que son reçu soit revenu. `POST /internal/v1/admissions/synchronize`
supposait une poussée de la gateway vers l'autorité ; la transcription du
registre se fait dans l'autre sens, par tirage d'Astra sur
`GET /internal/v1/certificates/state/<identity>`. Astra enregistre ainsi ce
que la gateway lui répond, et ne décide jamais une admission.

Le pare-feu limite chaque adresse à l'API opposée et à ces chemins. Aucun des
deux services n'accepte un chemin arbitraire à relayer depuis Orion.

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

Ce canal est l'unique chemin de
`ClientCertificateStageAuthorization` et du reçu correspondant, renouvellement
ordinaire compris. Pour une récupération expirée, il porte aussi le commit,
parce que le tunnel WireGuard n'existe alors potentiellement plus. Il n'est pas
un repli pour **l'entrée de la demande** ordinaire venant d'un Orion actif, ni
pour son commit : tous deux passent dans WireGuard afin de conserver la preuve
du pair source.

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

### 8.5 Canal opérateur dans le tunnel

Amendement du 4 septembre 2026, ADR-008 §2. Une campagne opérateur emprunte le
tunnel dès qu'il existe. L'origine publique de §8.2 ne sert qu'un opérateur qui
n'en a aucun ; le document hors ligne de §8.4 reste le dernier recours.

#### 8.5.1 Routes

`heliosd` sert quatre routes typées, image exacte des quatre surfaces
opérateur d'Astra et d'aucune autre :

```text
GET  /api/certificates/operator/operations/<operation_id>
GET  /api/certificates/operator/signer-requests/<operation_id>
GET  /api/certificates/operator/vaults/<encrypted_vault_fingerprint>
POST /api/certificates/operator/signer-results/<operation_id>
```

Elles relaient vers un préfixe privé propre, distinct de celui du
renouvellement client et de celui de la mise à jour de confiance :

```text
POST /internal/v1/operator/operations/<operation_id>
POST /internal/v1/operator/signer-requests/<operation_id>
POST /internal/v1/operator/vaults/<encrypted_vault_fingerprint>
POST /internal/v1/operator/signer-results/<operation_id>
```

Un préfixe séparé et non une cinquième route sous celui de la rotation : un
renouvellement est un pair qui demande à être recertifié, une campagne est
l'autorité qui tourne sur elle-même. Un journal de refus doit pouvoir dire
laquelle des deux surfaces a été sondée.

Le corps relayé porte l'identité résolue par la gateway et l'objet canonique,
jamais le chemin, la méthode ni un en-tête de l'appelant. Cette identité est la
clé publique WireGuard, unique dans la table d'admission, et non le nom
convivial mutable ; le loopback de développement est une variante explicite.

Les bornes de §8.2 s'appliquent à l'objet canonique : 64 Kio avant
désérialisation et 128 octets par identifiant opaque. L'enveloppe privée d'un
résultat ajoute au plus 256 octets d'identité typée et de structure JSON : son
plafond est donc 64 Kio + 256 octets. Toutes les réponses, pas seulement le
coffre chiffré, sont limitées à 128 Kio.

#### 8.5.2 Autorisation

Ces routes exigent un pair **administrateur**. La résolution est celle de
§8.1 : l'adresse source de la socket est comparée à l'unique `/32` de la
configuration, aucun en-tête de proxy n'est consulté, et le drapeau `admin` du
pair est exigé en plus. Un pair admis non administrateur est refusé ; la
cohérence d'origine du navigateur est exigée comme sur toute mutation
administrative.

L'identité est établie **avant** toute lecture comme avant tout relais :
aucune de ces routes ne consulte l'autorité pour un appelant qu'elle n'a pas
d'abord résolu en administrateur.

Une opération de campagne n'appartient à aucun pair, et rien ici ne prétend le
contraire : l'autorisation normative reste l'assertion WebAuthn de la YubiKey
et les signatures applicatives ML-DSA-87 que les objets portent. Le drapeau
`admin` borne qui peut faire circuler la cérémonie, pas qui peut l'approuver.

Ces routes ne donnent accès à aucune opération de renouvellement client. La
séparation est structurelle : le préfixe `/internal/v1/operator/` adresse le
magasin des opérations de campagne, un `operation_id` de renouvellement
ordinaire y est absent et reçoit le refus grossier d'un identifiant que
personne n'a émis.

#### 8.5.3 Capacités et fenêtres

Rien n'est assoupli pour être passé dans le tunnel. Les mêmes
`operation_id`, les mêmes capacités bearer MACées par scope, liées à
l'opération, au manifeste, au coffre éventuel et à cinq minutes au plus, la
même clé racine éphémère au processus Astra. La capacité est la seule valeur
qui traverse hors du corps ; elle voyage en `Authorization: Bearer`, jamais
dans une URL, un cookie ou un journal.

La lecture du coffre reste liée à son opération : l'empreinte du chemin est
comparée à celle que nomme la demande **signée**, comme sur l'origine
publique.

#### 8.5.4 Refus

Les réponses publiques sont grossières et ne se distinguent pas entre elles :
pair non administrateur, origine incohérente, opération inconnue, opération
expirée, capacité absente ou hors scope. Le détail d'un refus antérieur au
relais reste dans le journal structuré de la gateway ; celui d'un refus rendu
par l'autorité existe aussi dans le journal structuré d'Astra. Un refus de
lecture n'avance pas l'audit chaîné : sa tête témoigne des mutations durables
du registre, pas des sondes réseau. Une gateway sans canal privé répond
`503` et le dit dans son journal, comme en §8.1.2 : la route existe et
l'appelant a raison de l'employer.

#### 8.5.5 Choix du transport, sans repli

`astra-signer` porte trois transports pour une campagne, et le choix est
explicite :

| Transport   | Arguments                            | Emploi                     |
| ----------- | ------------------------------------ | -------------------------- |
| Tunnel      | `--heliosd-url` et `--operation-id`  | Chemin prioritaire         |
| HTTPS       | `--authority-url` et `--operation-id`| Opérateur sans tunnel      |
| Hors ligne  | `--request`/`--campaign` et `--out`  | Dernier recours            |

Les trois sont mutuellement exclusifs. Un transport tunnel qui échoue est une
erreur ; il ne se rabat jamais sur l'origine publique. Un repli ferait
dépendre le chemin réellement emprunté d'une panne, et l'opérateur croirait
avoir approuvé dans le tunnel une cérémonie partie ailleurs.

La vérification ne dépend pas du transport. `authority_url` et
`webauthn_rp_id` servis par une réponse sont **affichés, jamais adoptés** : le
RP ID vient du hand-off que le compagnon détient, sinon une gateway pourrait
faire répondre la clé de l'opérateur à un challenge d'un autre domaine.

#### 8.5.6 Couverture

Le transport tunnel couvre les quatre commandes de chaîne qui n'avaient que
l'origine publique, et qui étaient donc inatteignables sur un déploiement sans
nom public : `rotate-ca-tls` (§9.4), `sign-gateway-transition` (§6),
`abort-gateway-transition` (§8 de l'ADR) et `resume-rotation`.

Les commandes qui disposent déjà d'un mode hors ligne — `rotate-ca-pq` (§9.1),
`approve-campaign` (§7.6), `sign-gateway-rollback` (§4.4) — ne sont bloquées
par rien et conservent leurs deux transports. Le canal partagé les accepte
sans changement de contrat lorsqu'un déploiement le demandera ; ce n'est pas
une obligation de cette section.

La récupération d'une identité expirée (§7.5) reste sur l'origine publique par
construction : ce qui a expiré est précisément le tunnel.

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

#### 9.4.0 Amorçage de l'ancre, avant toute rotation

Deux autorités distinctes se ressemblent et ont été confondues :

* la **CA opérateur** (`CN=helios-orion-clients`), fichier local de la gateway,
  ancre mTLS du listener de négociation : elle décide qui a le droit de se
  connecter, et elle émet la feuille de première génération d'un client ;
* la **CA-TLS du domaine**, auto-signée depuis le coffre d'autorité par
  `astra-signer issue-ca-tls`, portée par le relais de domaine sous
  `ca_tls_certificate` et épinglée dans Astra par `astra pin-ca-tls` : c'est
  l'ancre à laquelle une feuille **renouvelée** se rattache, au travers de
  l'intermédiaire délégué d'Astra.

Le registre de la gateway retient la seconde. `heliosd init-trust-domain
--client-tls-ca <der>` l'enregistre en génération 1 ; le déploiement la lui
passe depuis le relais.

Sans elle, le registre retient l'autorité d'admission à la place de l'ancre du
domaine, et toute mise en attente d'un renouvellement est refusée — la feuille
candidate ne se rattache à aucune ancre que la gateway détient. Une rotation
du §9.4 ne répare pas cet état : une transition ne sait que **quitter** une
ancre déjà détenue. `heliosd repair-client-tls-ca-bootstrap` couvre uniquement
la migration des registres historiques encore à l'époque 1, dont l'ancre et
toutes les générations clientes actives désignent exactement la CA opérateur,
sans candidat, successeur ni chevauchement. Exécutée daemon arrêté, elle
remplace atomiquement l'ancre et les empreintes de ces générations 1, sans
toucher aux identités, certificats PQ, révocations ni distributions signées en
attente. Tout état ayant déjà évolué est refusé : hors de cette correction
bornée, seule une transition signée du §9.4 peut déplacer l'ancre.

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
| `revoked_tls_not_after` | présente si et seulement si l'empreinte TLS l'est ; expiration cryptographique signée |
| `revoked_pq_fingerprint` | facultative si PQ n'est pas concerné |
| `revoked_pq_not_after` | présente si et seulement si l'empreinte PQ l'est ; expiration cryptographique signée |
| `effective_at` | effet immédiat ou futur explicite |
| `reason` | `key_compromise`, `suspected_compromise`, `cessation` ou `superseded` |
| `replacement_transition_fingerprint` | facultative |
| `ca_signature` | signature de la CA fiable |

Au moins une empreinte est présente. L'objet est signé sous le domaine
`helios-certificate-emergency-revocation-v5`. Ses octets canoniques sont :

```text
"helios-certificate-emergency-revocation-v5"
|| format_version:u16
|| trust_domain_id:16 || ca_epoch:u64
|| scope:u8 || identity_key:32
|| len(server_name):u32 || server_name
|| revocation_epoch:u64
|| revoked_tls_present:u8
|| revoked_tls_fingerprint:32 || revoked_tls_not_after:u64
                                                   si revoked_tls_present == 1
|| revoked_pq_present:u8
|| revoked_pq_fingerprint:32 || revoked_pq_not_after:u64
                                                   si revoked_pq_present == 1
|| effective_at:u64 || reason:u8
|| replacement_transition_present:u8
|| replacement_transition_fingerprint:32
                                                   si replacement_transition_present == 1
```

`scope` vaut `0` pour `gateway` et `1` pour `client`, toute autre valeur étant
refusée. `server_name` est non vide et canonique pour `gateway`; pour `client`,
sa longueur vaut zéro et aucun octet de valeur ne suit. `reason` vaut
respectivement `0`, `1`, `2` ou `3` pour `key_compromise`,
`suspected_compromise`, `cessation` ou `superseded`. Chacun des trois
discriminants `present` vaut exactement `0` ou `1`. À `0`, aucun octet du champ
optionnel ne suit ; à `1`, le couple TLS ou PQ contient exactement `32 + 8`
octets et l'empreinte de remplacement exactement 32 octets. Les couples
empreinte/`not_after` sont donc derrière un seul drapeau et ne peuvent jamais
être décodés séparément. Au moins un des deux drapeaux `revoked_*_present` vaut
`1`.

Les couples `empreinte/not_after` sont indivisibles. L'expiration est portée
par la décision signée même lorsque le destinataire n'a jamais détenu la leaf :
elle ne peut être devinée localement, mais elle est nécessaire pour libérer de
façon sûre un registre de tombstones borné. Quand le destinataire détient la
leaf, son expiration DER/PQ doit être identique à la valeur signée ; un écart
fait refuser toute la transaction.

### 10.2 Effet

À `effective_at`, l'empreinte nommée est retirée même si sa validité ou son
chevauchement n'est pas terminé. La révocation domine `staged`, `overlap`, un
rollback de service et tout callback d'une génération antérieure. Si aucune
identité de remplacement déjà vérifiée ne reste disponible, la connexion
échoue fermement.

Le compteur de révocation est persisté avec les empreintes retirées et avance
indépendamment des générations de certificat. Une rotation ultérieure ne peut
donc ni réintroduire une leaf révoquée, ni faire disparaître la décision par un
numéro de génération concurrent. Une empreinte révoquée reste mémorisée
jusqu'à la fin de sa validité cryptographique signée. À capacité maximale, les
tombstones expirés sont retirés avant toute décision ; si toutes les entrées
sont encore vivantes, la nouvelle révocation est refusée sans éviction.

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

Ce chapitre est la projection opérationnelle des machines et transports des
§§6 à 10, pas un second protocole. Il ne peut changer ni le porteur d'un objet,
ni l'instant où un slot devient `next`; toute divergence avec les sections
normatives précédentes est une erreur de spécification.

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

1. À 80 % exact de la validité, générer puis sceller les
   nouvelles clés dans Orion.
2. Produire la demande et les trois preuves de possession/continuité, puis la
   remettre à Helios dans le tunnel WireGuard ; Helios authentifie la VIP et la
   relaie à Astra sur le veth privé.
3. Astra vérifie admission, révocation, fenêtre, délégation, génération et
   liaison à l'empreinte exacte de la demande.
4. Astra émet automatiquement les deux certificats et
   `ClientCertificateStageAuthorization`, puis renvoie l'ensemble à Helios sur
   le veth.
5. Helios vérifie l'autorisation, persiste et synchronise le
   candidat en `pending_grant` — sans créer de slot `next` —, puis signe
   `GatewayCertificateStageReceipt`.
6. Helios relaie le reçu à Astra ; Astra le vérifie, signe le grant et le remet
   à Orion à travers Helios.
7. Orion vérifie reçu et grant, persiste le candidat puis envoie
   `ClientCertificateStageCommit` dans WireGuard.
8. Helios committe atomiquement le slot et Orion ne rend le candidat activable
   qu'après le succès ; la synchronisation d'admission suivante informe Astra.
   Sans commit avant `stage_expires_at`, les deux purgent le stage.
9. Orion bascule à `activation_at` et une connexion v5 réussie marque la
   nouvelle génération observée.
10. Les deux bouts retirent l'ancienne à `not_after`.

### 11.3 Récupération cliente après expiration

1. Orion contacte Astra en HTTPS, obtient un challenge frais, génère et scelle
   les nouvelles clés.
2. Il produit `ExpiredCertificateRecoveryRequest` avec les preuves ancienne et
   nouvelle.
3. Orion lance son sidecar désélevé `helios-astra-helper`, qui affiche dans
   l'onglet Astra le manifeste vérifié ; une seule cérémonie `GetAssertion` de
   la YubiKey opérateur approuve le hash exact et dérive le secret qui ouvre
   localement le coffre maître. Le jeton de session et l'état passent par le
   canal IPC local borné, jamais par la WebView.
4. Astra vérifie la dernière génération historique et l'absence de révocation,
   puis le compagnon signe l'autorisation exacte par `CA-PQ`.
5. Astra remet l'autorisation à Helios par le veth privé.
6. Helios persiste le candidat en `pending_grant`, sans créer de slot `next`,
   et signe le reçu.
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
- canal HTTPS public limité à la récupération et aux opérations hors tunnel,
  identité de service et veth privé bidirectionnel mutuellement authentifié
  sans forwarding, TLS 1.3 `(EC)DHE` sans reprise ni 0-RTT ;
- coffre maître HVLT à deux key-slots YubiKey, compagnon de signature et
  procédures d'ajout, perte et remplacement d'un credential ;
- conteneurs HVLT v1 stricts sous AES-256-GCM, dérivation HKDF-SHA-256 des
  key-slots, sels frais et AAD/contextes exacts de §2.4.1 ;
- ML-DSA-87 pur avec le `ctx` non vide fixé pour chaque type au §2.3.1, sans
  HashML-DSA ;
- DRBG SP 800-90A à 256 bits de la bibliothèque cryptographique,
  HMAC-DRBG-SHA-512 ou
  CTR-DRBG-AES-256 avec DF, et erreurs fermes de §2.3.2 pour tout identifiant,
  challenge, nonce, sel, secret et clé, sans DRBG applicatif maison ;
- `astra_policy_fingerprint` confirmé hors bande et épinglé dans les profils
  Orion et le registre Helios ;
- jetons de capacité du compagnon liés au scope, à l'opération, au manifeste,
  au coffre et à une fenêtre de cinq minutes selon §8.2 ;
- `AstraIssuerAuthorization`, intermédiaire TLS et émetteur ML-DSA-87 délégué,
  avec portée et validité vérifiées par Helios et Orion ;
- liaison automatique de l'empreinte de demande jusqu'au stage, au reçu et au
  grant pour chaque renouvellement client ordinaire ;
- états `active + next` bornés pour gateway, client et CA ;
- association atomique des empreintes TLS/PQ clientes ;
- formats signés des §§3.4 à 10 et parseurs stricts ;
- rotation planifiée et remplacement d'urgence de la clé de service Astra ;
- requête de statut authentifiée, sans lecture publique par empreinte ;
- route interne authentifiée `POST /api/key-negotiation/trust-update` ;
- routes typées de renouvellement dans WireGuard et relais Helios–Astra sur le
  veth, sans proxy générique ni repli public ;
- transaction de confiance chunkée mais atomique, dont les fragments restent
  invisibles avant le commit local ;
- staging client à lease bornée, reçu signé Helios, commit Orion et purge
  automatique ; grant impossible avant le reçu et activation impossible avant
  le commit ;
- planificateur automatique à 80 % exact, reprise à la connexion suivante,
  fenêtres Astra et alertes 90/95 % ;
- récupération publique d'une identité expirée avec ancienne preuve, nouvelle
  preuve et YubiKey opérateur, sans réacceptation dans QUIC ;
- campagnes manuelles et rollback de service borné ;
- import manuel d'un document `orion-trust-update` ;
- persistance atomique, promotion et suppression définitive ;
- sérialisation de la révocation d'admission, de la génération cliente et du
  retrait du plan de données, afin que l'état terminal `revoked` domine aussi
  en concurrence ;
- affichage clair de l'état `active`, `renewal_due`,
  `pending_grant`, `pending_commit`, `staged`, `published`, `aborted`,
  `overlap`, `promoted`, `expired` ou `revoked`, limité au sous-ensemble légal
  de la famille visée ;
- tests du §14.

Une livraison partielle peut être testée et déployée derrière un refus
explicite, mais ne doit pas être présentée comme « cycle de vie implémenté ».
En particulier, fournir seulement les types `active + next` sans le staging
avec reçu, ou Astra sans récupération expirée, laisse encore le parc se couper
sur une absence prolongée.

### 12.2 Surfaces Orion et Helios obligatoires

Orion ajoute une destination ou un sous-écran **Certificats** dans la surface
Profils. Il affiche, sans exposer de secret :

- leafs TLS/PQ active et suivante, générations, échéances et état Astra, dont
  l'attente de la YubiKey ;
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

Chaque renouvellement, planifié ou manuel, crée une opération ; chaque action
globale crée une campagne. L'approbation a deux chemins, et l'IHM les offre
tous les deux. Quand la clé de sécurité est sur le poste, **Orion mène la
cérémonie lui-même** : il lit d'abord le manifeste vérifié — pair, générations
active et demandée, empreinte de la demande, échéance, nombre de credentials
du domaine habilités à répondre — puis exécute l'unique `GetAssertion` et
dépose l'assertion. L'ordre est la garantie, pas une commodité : ce qui est
signé est ce qui a été montré, et la cérémonie est refusée tant que le
manifeste n'a pas été lu. Quand la clé est ailleurs, ou que la politique du
poste refuse à Orion l'accès au transport, l'IHM lance `astra-signer` avec
`heliosd_url` et `operation_id`; hors tunnel elle emploie l'origine Astra. Le
compagnon dialogue alors directement avec la YubiKey et affiche le même
manifeste ; l'IHM ignore un callback non signé, interroge l'état, vérifie le
résultat sous la clé de service Astra puis vérifie chaque objet sous sa propre
autorité. Le
libellé montre avant approbation le nombre de cibles, les générations et si une
CA sera tournée. Aucune action globale n'est placée derrière un bouton au
libellé ambigu « Renouveler ».

Les actions d'autorité de cette console — rotation des autorités, annulation
d'une transition préparée, rollback gateway — sont des campagnes opérateur et
suivent §8.5 : le compagnon est lancé avec `heliosd_url` et `operation_id`, et
l'origine publique n'est proposée que si aucun tunnel n'existe. La console
n'offre pas de bascule automatique entre les deux.

### 12.3 État de l'implémentation au 30 août 2026

**Livré et testé.**

- `aether::certificates` : les objets signés du chemin
  « demande → autorisation → reçu → grant → commit » antérieurs à l'amendement
  du 15 août, l'encodage canonique, les empreintes, les générations, les
  fenêtres, le calcul 80 % et les états bornés actif/suivant. L'idempotence
  porte sur l'empreinte du **document** signé, pas sur son contenu. Les
  empreintes optionnelles utilisent déjà un octet de présence strict ; §6.2
  décrit désormais les octets réellement produits.
- `aether::certificates::x509` : CA réelle, auto-émise et auto-signée,
  `basicConstraints`, `keyCertSign`, `clientAuth`, `serverAuth`,
  `digitalSignature` dès qu'un `keyUsage` est déclaré, SAN DNS et
  auto-signature de la leaf TLS gateway épinglée, chaîne
  `leaf → intermédiaire → CA-TLS` vers une ancre déjà détenue et liaison CSR ↔
  clé certifiée. La validité est lue sur
  **chaque maillon** et sur **toute la fenêtre**, `not_before <= activation_at`
  et `not_after > window.not_after` (§4.1) : un seul instant laisserait une
  leaf ou une ancre expirer au milieu du chevauchement qu'elle porte, une fois
  la génération sortante déjà programmée pour le retrait. La CA-TLS entrante et
  l'intermédiaire délégué et les deux leafs gateway sont soumis à la même règle
  sur leur propre fenêtre.
- Deux axes de révocation distincts, l'un pour la gateway et l'autre par
  client, plus un troisième pour la clé de service Astra. Une révocation porte
  sa portée et l'identité qu'elle nomme ; elle est refusée si elle en désigne
  une autre, et appliquée à l'état que cette portée nomme. Un compteur consommé
  ne redescend jamais : deux décisions datées différemment prennent effet dans
  l'ordre de l'horloge, pas dans celui des numéros.
- Les empreintes retirées sont **mémorisées** après leur instant (§10.2), avec
  portée, famille, compteur, expiration cryptographique portée par la décision
  signée et empreinte du document signé. Tous les chemins d'installation
  les consultent — transition gateway, rotation de `CA-PQ` et de `CA-TLS`,
  transition et remplacement d'urgence de la clé de service, staging d'un
  candidat client — et le registre en pose aussi à `peer remove`. Sans cela, une
  révocation visant une empreinte que le porteur ne détient pas *encore* est
  consommée puis oubliée : son époque est dépensée, l'objet n'est plus jamais
  distribuable, et la transition suivante réinstalle la leaf. La liste est
  plafonnée, purge les entrées arrivées à leur expiration signée, puis
  **refuse** plutôt que d'évincer une entrée encore vivante. Une seconde
  révocation de la même leaf remplace compteur, expiration et provenance comme
  une seule décision cohérente.
- Les compteurs de statut sont tenus **par cible**, comme Astra les émet : une
  génération fraîche repart à son propre compteur au lieu d'être bloquée
  derrière celui de la leaf qu'elle remplace. Un statut doit nommer une famille,
  une génération et une empreinte que le porteur détient réellement.
- `helios-provisioning::certificates` : staging à lease, reçu signé après
  écriture et `fsync`, commit qui **exige le grant**, purge, révocation
  dominante, unicité globale des empreintes. Toute mutation est calculée sur
  une copie, écrite, puis adoptée : un échec d'écriture laisse le registre
  décrivant ce que le disque contient.
- **les deux autorisations du §7.2** : l'automatisme lie directement
  `request_fingerprint`, tandis qu'une campagne lie l'état courant d'un jeu de
  cibles. `covers_client` exige la clé WireGuard, la génération et les deux
  empreintes actives exactes ; une campagne ne se rejoue donc pas d'une
  génération sur la suivante. Côté émetteur, `DelegatedApproval` dérive la
  raison de la famille ; côté gateway, staging et commit choisissent le
  contrôle sur cette raison signée. Une autorisation automatique accompagnée
  d'une preuve WebAuthn est refusée au lieu de réintroduire l'ancien chemin.
- `helios-api` : `trust-update`, `stage` et `stage-commit` dans le tunnel,
  derrière la résolution de source. La route `stage` décrit ici l'état du code
  antérieur à §0.5 : elle doit disparaître du canal Orion et ne doit pas être
  ouverte en exploitation.
- `heliosd::certificates` : propriétaire unique du registre, signature des
  reçus par la leaf servie, boucle de balayage des leases et des
  chevauchements. Le listener de négociation charge au démarrage la CA
  opérateur et les ancres `CA-TLS` alors acceptables dans ce registre, afin
  qu'une leaf renouvelée présentée avec l'intermédiaire délégué franchisse le
  mTLS. L'ajout et le retrait automatiques d'une racine aux bornes d'une
  rotation exigent encore un redémarrage du listener ; la résolution de la
  paire TLS/PQ reste bornée par l'horloge à chaque requête.
- `astra` : registre, audit chaîné dont la tête distingue une restauration d'un
  fork, émetteur délégué borné qui fixe lui-même la validité des leafs,
  planificateur, statut signé, budgets plafonnés par source et par identité.
  Au démarrage, les deux clés privées de l'émetteur sont prouvées appartenir à
  la délégation que le registre porte — signature ML-DSA-87 vérifiée sous
  `pq_issuer_public_key`, `SubjectPublicKeyInfo` comparé à celui de
  l'intermédiaire — plutôt que constatées présentes. Le binaire a ses propres
  essais : `bootstrap`, refus d'une seconde histoire, refus d'une ancre
  illisible, `status`.
- `orion-core::certificates` : ancre, slots, planificateur dispersé stable,
  vérification complète d'une transaction chunkée et application par une seule
  écriture, révocations différées appliquées à leur instant.
- `orion-core::certificate_renewal` : la **moitié cliente** du §8.1.2, du
  magasin de confiance au commit. `open_or_seed` amorce l'état borné depuis le
  profil et l'identité scellée — rien n'y est inventé ni récupéré sur le
  réseau : les ancres viennent du document que l'opérateur a signé, les
  empreintes de la génération active viennent des certificats du magasin
  protégé. Une fois le fichier écrit, c'est **lui** qui fait foi : un profil
  réémis ne le réamorce pas, et un magasin décrivant un autre domaine ou un
  autre client est refusé plutôt qu'adopté ou remplacé. Le candidat est scellé
  sous `<identité>-next` **avant** le commit, jamais par-dessus l'actif — qui
  continue de monter le tunnel pendant tout le chevauchement — et
  `promote_due` remet les deux en place à l'activation, clés d'abord, état
  ensuite. Les
  deux clés candidates naissent dans le processus et n'en sortent pas — ce qui
  voyage est une PKCS#10 et une clé publique, chacune couverte par une
  signature de la moitié privée correspondante. La requête est bâtie depuis le
  magasin de confiance et depuis rien d'autre, signée deux fois (continuité par
  la génération sortante, possession par celle qui demande à être certifiée),
  puis remise à la route `request`. L'interrogation de l'opération refuse une
  vue qui nomme une autre demande, un autre pair ou un autre identifiant.
  À l'arrivée du grant, la vérification passe **avant** toute écriture : elle
  lie le grant à la requête locale, et `assert_csr_matches` refuse une leaf qui
  certifierait une clé que cette machine ne détient pas. Le candidat est
  ensuite persisté en `pending_commit`, le commit signé part, et seul son
  succès promeut le slot en `next`. Une interruption ne laisse donc rien : ni
  identité à demi scellée, ni clé orpheline, ni slot nommant un certificat sans
  clé privée. Le prix est qu'un arrêt perd les clés candidates et rouvre
  l'opération — l'échec bon marché, la génération active étant intacte.
- `astra::vault` et `astra-signer` : coffre maître HVLT, key-slots FIDO2
  `hmac-secret`/PRF et commandes `init`, `enrol`, `verify`, `list`, `remove`,
  `rename`, `issue-ca-tls`, `authorize-issuer`, `bindings`, `approve`,
  `approve-campaign`, `rotate-ca-pq`, `recover`, `revoke`,
  `sign-gateway-transition` et `abort-gateway-transition`.
  Le coffre exige deux credentials avant
  d'être tenu pour amorcé et en accepte huit. Les deux
  couches AES-256-GCM, HKDF-SHA-256, sels, contextes et AAD sont celles figées
  au §2.4.1.
- la **moitié serveur du renouvellement relayé**, et sa moitié cliente : les
  routes Orion → Helios
  authentifient la VIP, Helios relaie des objets typés vers Astra, Astra
  vérifie le seuil de 80 %, puis persiste les octets exacts du stage avant
  émission. L'autorisation et le reçu restent sur le veth, le grant
  n'est libéré qu'après le reçu, et une reprise réutilise le même
  `operation_id`. Les deux directions mTLS emploient
  deux identités distinctes, TLS 1.3 `(EC)DHE`, sans reprise ni 0-RTT.

**Non livré.** Ces points sont refusés explicitement à l'exécution, jamais
contournés :

- l'**alignement filaire du 16 août**, désormais livré sauf pour ce qui dépend
  de la récupération. Sont en place : le portage exclusif de
  `ClientCertificateStageAuthorization` et du reçu sur le veth, le retrait de
  la route `stage` Orion — un `404` explicite, pour que le repli SPA ne
  réponde pas une page en `200` —, la liaison de
  `renewal_authorization_fingerprint` dans le reçu, que
  `GatewayCertificateStageReceipt::verify` compare à l'autorisation avant tout
  grant, les sous-ensembles de statut par famille avec `promoted`, et
  l'encodage de chaque couple révoqué empreinte/`not_after`
  derrière un seul drapeau de présence.
  Ce dernier point mérite d'être dit : deux drapeaux indépendants laissaient la
  forme canonique décrire une paire à moitié remplie — une empreinte sans
  échéance, donc une révocation sans fin — que `validate` refuse mais qu'un
  vérificateur l'ayant omis aurait acceptée, puisque les octets restent bien
  formés. Un seul drapeau rend l'état impossible inexprimable dans la
  transcription elle-même.
  `promoted` est accepté et jamais émis : l'affirmer demande un journal de
  mutations par cible, et Astra tient un compteur monotone qui dit qu'un
  changement a eu lieu, pas lequel.
  Restent liés à la récupération, non livrée : les versions dans ses octets
  signés et sa cérémonie combinée. Les invariants déjà présents — trois
  empreintes de la requête de confiance, `pending_grant` jusqu'au commit,
  révocation de l'active depuis toute phase et égalité de `retire_active_at` —
  restent la base à conserver ;

- l'**alignement cryptographique du 16 août**, partiellement livré. Ce qui est
  fait : toute signature ML-DSA-87 du cycle passe par `aether::ml_dsa`, un
  point d'entrée unique qui exige le `ctx` ASCII non vide du §2.3.1 et refuse
  un contexte vide, celui d'un autre type, un NUL ou un octet non imprimable —
  y compris sous `CA-PQ`. Le contexte n'est plus un paramètre qu'un appelant
  choisit : `CanonicalBytes::finish_signed` rend un `SignedTranscript` qui
  porte son domaine, et signer ou vérifier refuse un message qui ne s'ouvre pas
  dessus. Le préfixe interne et le contexte externe restent donc deux contrôles,
  et les deux s'appliquent. HashML-DSA n'est appelé nulle part et ne vérifie pas
  sous ce chemin. Tout tirage passe par `aether::random`, qui **ne réimplémente
  aucun DRBG** — pas d'état, pas de fonction de mise à jour, pas de dérivation
  de seed, pas de test de santé : une adaptation de type vers le fournisseur,
  un refus ferme quand il échoue, un faux fournisseur déterministe sous
  `cfg(test)` seulement, et la bannière de démarrage exigée par §2.3.2.
  La source est `aws_lc_rs::rand::SystemRandom` — le `RAND_bytes` d'AWS-LC déjà
  employé pour AES-GCM, HKDF et HMAC : CTR-DRBG-AES-256 sans DF, avec un seed
  de pleine entropie, état par thread, reseed toutes les 4096 générations et
  réinstanciation avant toute sortie après fork ou reprise d'instantané.
  La validation CAVP/ACVP est hors
  périmètre et rien ne la revendique.
  Les tirages secrets appellent l'API native AWS-LC
  `RAND_bytes_with_user_prediction_resistance`, alimentée par les 32 octets
  du DRBG public séparé ; l'adaptation ne détient aucun état DRBG. Cet apport
  est une donnée additionnelle, pas un reseed avec entropie fraîche.
  **Limite connue** : la garantie de résistance à la prédiction par appel et
  le reseed avant chaque clé privée exigé par §2.3.2 restent non satisfaits.
  La bannière ne les revendique pas ; leur levée exige une API fournisseur
  garantissant le reseed, y compris pour ses clés internes ML-KEM/TLS.
  `astra_policy_fingerprint`, le RP ID et l'époque du registre
  de credentials sont présents dans le profil et dans son manifeste scellé.
  Les jetons de capacité HKDF/HMAC sont livrés. Aucun de ces contrôles ne peut être remplacé par le seul préfixe du
  message, une signature `CA-PQ`, un UUID, un filtre de valeurs nulles ou un
  DRBG réimplémenté dans Helios ;

  **Migration** : le `ctx` entre dans la vérification, donc tout certificat PQ
  émis avant ce changement cesse de vérifier et le parc se ré-émet ;

- l'**ouverture d'une campagne depuis l'origine publique**. Le transport hors
  tunnel du compagnon, lui, est livré : `GET /v1/operations/<id>`,
  `GET /v1/signer-requests/<id>`, `GET /v1/vaults/<empreinte>` et
  `POST /v1/signer-results/<id>` servent les opérations opérateur, avec un
  jeton de capacité par scope, lié à l'opération, à l'empreinte de campagne —
  qui est aussi le challenge de la clé — et à cinq minutes. Le jeton de coffre
  n'est émis que pour une portée qui fait signer une ancre, et le coffre est
  servi chiffré : Astra ne détient aucun secret de key-slot. Les opérations
  opérateur vivent dans un magasin distinct de celui des renouvellements
  clients, ce qui rend structurelle la règle « un `operation_id` de
  renouvellement ordinaire reçoit le même refus grossier qu'un identifiant
  inconnu » : il y est absent, pas écarté. `astra campaign open` résout la
  campagne sur les cibles courantes et la dépose ; `astra-signer
  approve-campaign --authority-url --operation-id` la récupère, l'affiche,
  recueille les assertions et les dépose.
  Ce qui manque est `POST /v1/campaigns`, et le §11.6 dit pourquoi : cette
  route **résout** une campagne sur les cibles et générations courantes, donc
  sur un canal public non authentifié elle répondrait l'inventaire du domaine à
  n'importe quel appelant. L'authentification qu'elle exige — « les budgets
  s'appliquent par IPv4 ou préfixe IPv6 `/64`, credential, pair et domaine » —
  n'est décrite nulle part pour ce cas, et l'inventer serait construire le
  trou. La résolution se fait donc localement.
  `rotate-ca-pq` porte désormais une campagne (`--authority-url`,
  `--operation-id`) et emprunte les quatre routes du §8.2 comme
  `approve-campaign`. `authorize-issuer` aussi : `astra issuer request
  --reason --requested-by` résout la campagne `issuer_delegation` sur la
  demande qu'il vient de produire et la dépose, le compagnon la récupère, la
  montre, prend l'assertion et **redépose la délégation signée**, qu'Astra
  enregistre après avoir prouvé la possession des deux moitiés privées
  scellées à côté de son registre. Ce n'est pas une portée de `astra campaign
  open` : la cible de cette campagne n'existe pas avant que la commande ne la
  crée — l'époque, la clé ML-DSA-87 et la PKCS#10 naissent là, à côté des clés
  privées qu'elles nomment. Ce que la campagne épingle est la **matière
  exacte** qui sera certifiée : l'époque, la clé PQ, et le
  `SubjectPublicKeyInfo` dont la PKCS#10 prouve la possession — la même valeur
  se dérive de la demande avant la signature et de l'intermédiaire après elle.
  Une demande de délégation ne porte aucune signature ; hors campagne, le
  compagnon signe donc le fichier qu'on lui présente, et cette forme survit
  pour un domaine sans origine joignable, en le disant. Réinstaller la même
  délégation est un rejeu du §8.2, pas un retour en arrière : seule une
  délégation *différente* à une époque dépensée est refusée ;
- la **production** des transactions de transition, pour les objets qu'aucune
  cérémonie hors ligne ne signe. Le chemin complet du §0.6 est livré :
  `aether::certificates::transport::signing::build_transaction` construit et
  signe un manifeste sous la clé de service, découpe les objets en fragments
  par taille sérialisée et y recopie le jeton opaque du client ;
  `astra::distribution::prepare` sélectionne dans le registre ce que les
  compteurs du pair disent lui manquer, après avoir vérifié la signature de la
  requête sous la feuille PQ active que **la gateway** détient — jamais sous
  une clé que la requête porte ; `POST /internal/v1/trust-update/prepare` sert
  cette préparation sur le canal privé Helios → Astra, sous son propre préfixe ;
  et la gateway, quand sa file ne contient rien pour l'empreinte de base que ce
  client vient de signer, relaie un objet **canonique qu'elle construit** — la
  requête authentifiée, le pair qu'elle a résolu depuis la VIP source, et
  l'instantané que son registre possède déjà —, met en file ce qui revient et
  sert le premier fragment dans le même appel. Côté client,
  `orion_core::trust_update` écrit la requête depuis son propre magasin,
  empreinte de base comprise, collecte les fragments et n'applique rien avant
  le dernier — un manifeste qui change en cours de collecte est un conflit, pas
  une reprise. Orion l'**appelle** : le tunnel passe à `Up`, la route devient
  joignable, et une seule demande part par connexion — `Up` est réémis à chaque
  reprise de handshake après une pause, et redemander à chacune ferait sonder
  la gateway pendant toute la session. Le résultat est écrit dans le journal
  que l'utilisateur lit, refus compris : un client qui ne rattrape jamais une
  révocation en silence est le seul échec que tout ce chemin existe pour
  éviter, et « rien ne s'est passé » ne se distingue de « rien n'était dû » que
  si l'un des deux est écrit.
  **Le magasin d'objets de transition existe** : `astra-signer rotate-ca-pq
  --authority-url --operation-id` exécute une campagne `trust_authorities`,
  rend la `CaTransition` signée par `CA-PQ` **dans le même dépôt** que
  l'approbation, et `AstraRegistry::accept_transitions` la vérifie sous l'ancre
  et l'époque que ce registre épingle déjà avant d'écrire un octet. C'est
  précisément ce qui rend inoffensive une copie en ligne d'un objet `CA-PQ` :
  l'autorité ne peut pas en fabriquer un, elle re-dérive la preuve. Un pair en
  retard sur l'ancre reçoit donc sa transition, et `select_objects` la lui
  propose tant qu'elle n'est pas entrée en vigueur.
  **Limite connue** : une transition n'atteint un pair que pendant
  `[not_before, activation_at)`. §8.1.1 refuse une transaction passé sa
  première activation — installer comme à venir ce qui devrait déjà être en
  vigueur est exactement ce que cette règle interdit — donc le délai de
  préparation choisi par `rotate-ca-pq --prepare-days` est la fenêtre dont
  chaque pair dispose pour revenir. Au-delà, il se répare par l'opérateur, pas
  par une livraison tardive.
  **Sept familles d'objets sont produites** : la délégation, la transition
  `CA-PQ`, la transition `CA-TLS`, la révocation cliente, la révocation
  gateway, la transition d'identité gateway et son avortement.
  Le blocage de `CA-TLS` est levé : le registre épingle désormais
  `ca_tls_fingerprint`, reçu à `astra bootstrap --ca-tls-fingerprint` ou
  enregistré une fois par `astra pin-ca-tls`, et refuse de le remplacer par
  commande — remplacer une ancre est une rotation, et une rotation se signe.
  Un domaine antérieur à ce champ est refusé **par son nom** plutôt que
  contrôlé contre un défaut qui accepterait tout. `astra-signer rotate-ca-tls`
  crée l'ancre entrante, la fait auto-signer, signe la transition sous `CA-PQ`
  et **scelle la clé suivante à côté** de celle qui émet plutôt que par-dessus :
  le coffre porte `active` et `next`, et `astra-signer promote-ca-tls` les
  échange à `not_after` en détruisant la sortante dans la même écriture
  scellée. C'est ce que le §9.2 autorise et rien de plus. L'autorité émet sous
  l'ancre sortante pendant tout le recouvrement, parce que la gateway compare
  `ca_tls_epoch` à l'identique et ne l'avance qu'à `retire_active_at` : les
  deux côtés basculent donc à la même seconde, et le successeur ne certifie
  rien avant elle. Astra conserve lui aussi un slot entrant — empreinte,
  génération et fenêtre — dès qu'il accepte la transition signée. Sa passe
  horodatée ne promeut ni à `not_before`, ni à `activation_at` : à
  `not_after`, elle avance ensemble `ca_tls_epoch` et le pin actif, referme le
  slot et oublie la transition consommée dans une seule écriture atomique du
  registre. Une seconde rotation est alors vérifiée contre l'ancre réellement
  en service, sans commande capable de déplacer le pin. La décision
  est écrite avant d'être annoncée : la cérémonie dépose `astra-prepared.json`
  — les octets exacts du dépôt — avant de contacter l'autorité, et
  `astra-signer resume-rotation` rejoue ce dépôt à l'identique après une panne,
  sans redemander de clé (§8.2). `heliosd install-client-tls-ca` met la
  transition en attente, les deux chaînes sont acceptées pendant le
  chevauchement, et l'ancienne est retirée par la même passe qui promeut les
  générations. La révocation d'une **gateway**
  s'exécute désormais : `astra revocation open --scope gateway` lit les deux
  feuilles et leurs échéances signées **en direct** sur le canal privé, auprès
  du démon qui les sert, parce que ce registre ne les a jamais détenues ;
  `astra-signer revoke --scope gateway` nomme chaque moitié avec sa propre
  échéance — les deux feuilles gateway n'expirent pas ensemble, contrairement à
  une génération cliente — et la gateway applique la décision sur son propre
  axe de compteur, terminale.
  La gateway adopte désormais l'ancre `CA-PQ` distribuée :
  `heliosd install-ca-transition` — ou la route console équivalente, qui écrit
  par le processus détenant le registre — étage la rotation, les deux ancres
  vérifient à partir de `activation_at`, et la sortante est retirée à
  `not_after` par la passe d'entretien, dans la même écriture que les
  promotions clientes et celle de la CA TLS. **Limite connue** : le registre
  Astra, lui, reste sur l'ancre sortante jusqu'à ce qu'un opérateur l'avance,
  si bien que la campagne suivante repartirait de l'ancre retirée. `CA-TLS`
  est adoptée à `not_after` par Astra comme par la gateway.
  La réponse ne porte par ailleurs **jamais** de statut signé, parce qu'un
  statut est signé par la clé de service Astra, que `heliosd` ne détient pas et
  ne doit pas détenir. La comparaison qui décide « à jour » couvre en revanche
  tous les compteurs et toutes les empreintes actives, gateway comme client :
  une omission y répondrait « rien à récupérer » à un client en retard, et
  c'est le seul refus dont il ne se relève pas ;
- la **récupération d'une identité expirée** est livrée de bout en bout. Le
  validateur historique était déjà éprouvé ; ses consommateurs le sont
  désormais aussi. Orion (`orion_core::certificate_recovery`) demande un
  challenge à l'origine publique, signe la demande avec la clé privée
  **expirée** et la clé neuve, et la dépose ;
  `POST /v1/client-rotation/recovery` la passe au validateur historique contre
  le pair que le registre enregistre déjà, consomme le challenge, et ouvre une
  opération de récupération dans un **troisième** magasin — un identifiant de
  récupération ne doit jamais se résoudre là où un renouvellement ordinaire
  s'autorise. `astra-signer recover --authority-url … --operation-id …` lit la
  demande, l'affiche, prend l'assertion de l'opérateur, la **vérifie avant**
  d'employer la sortie PRF de la même session pour ouvrir le coffre, émet les
  deux feuilles sous `CA-TLS` et `CA-PQ`, signe l'autorisation de staging sous
  `IssuerKind::Master`, la dépose ; Astra la relaie par le veth, récupère le
  reçu, et le compagnon signe le grant sous `CA-PQ` contre ce reçu exact.
  Enfin le commit du client repart par
  `POST /internal/v1/certificates/stage-commit` : la gateway refuse sur ce lien
  tout ce dont l'étape en attente n'a pas été ouverte par l'autorisation
  `CA-PQ` présentée à côté, ce qui empêche ce chemin d'être une seconde voie
  pour un renouvellement ordinaire.
  **Limite connue** : la clé privée expirée doit encore exister. Si elle est
  partie avec le stockage DPAPI ou TPM qui la tenait, aucune preuve historique
  n'est produisible et `RecoveryError::NoHistoricalProof` le dit — il reste la
  réadmission opérateur à deux credentials, qui crée une continuité neuve au
  lieu d'en prolonger une.
  L'approbation et l'ouverture du coffre sont **une seule** cérémonie
  `GetAssertion` : `Authenticator::approve_and_derive` porte le
  `clientDataJSON` de la récupération et le sel du coffre dans la même
  requête, sur les deux transports (CTAP HID et `webauthn.dll`). Le secret
  n'est employé qu'après vérification de l'assertion sous la ligne du
  credential signée par `CA-PQ`. `approve` reste sans sel, ce qui fait
  toujours tenir §14.1 par construction pour le renouvellement ordinaire. Le
  grant, signé plus tard contre le reçu de la gateway, rouvre le coffre : il
  ne tient pas le secret pendant l'attente réseau ;
- l'**exécution d'une campagne d'autorité**. Une campagne sur les **leafs
  clientes** s'exécute désormais : quand un pair couvert envoie sa demande de
  rotation, `astra::renewal::open` retrouve l'opération approuvée par
  `SigningOperationStore::approved_for_client`, ouvre une opération **déjà
  approuvée** — elle ne passe jamais par `awaiting_operator`, puisque personne
  n'a rien à répondre — et émet dans le même appel. La campagne est aussi la
  seule chose qui surcharge légitimement le seuil de 80 % : renouveler *avant*
  est ce à quoi sert une action manuelle. Elle ne surcharge pas l'expiration —
  une rotation ordinaire prouve la possession par une feuille qu'aucun
  validateur n'accepte, et §7.5 est le seul retour.
  **Limite connue** : une leaf cliente ne tourne pas sans son client, qui
  détient la clé privée et écrit le CSR. Une campagne autorise donc des
  rotations, et c'est la demande de chaque pair qui dépense cette autorisation,
  dans la fenêtre de campagne — 300 s au plus (§7.6). Un pair hors ligne
  pendant ces cinq minutes n'est pas renouvelé, et l'opérateur rouvre une
  campagne : atteindre un parc absent voudrait dire une autorisation qui
  survit au texte que son opérateur a lu.
  La moitié **autorité** s'exécute désormais aussi, et par une seule
  cérémonie : `astra campaign open --scope trust-authorities` résout la
  campagne sur l'ancre que le registre détient, `astra-signer rotate-ca-pq
  --authority-url --operation-id` la vérifie contre l'ancre de son propre
  coffre — deux moitiés du domaine qui se contredisent sur ce qui est courant
  s'arrêtent, elles ne se réconcilient pas par une rotation —, prend les deux
  confirmations, et dépose l'approbation **et** la `CaTransition` signée dans
  le même document. `AstraSignerResult::validate` lie chaque objet à une cible
  que l'opérateur a lue, refuse un objet nommé deux fois, répartit chaque objet
  sur la **famille** de sa portée — les quatre du §7.6, chacune refusant les
  trois autres dans les deux sens —, et exige qu'une transition de
  `CA-PQ` porte le document de credentials ré-signé sous son successeur — une
  ancre neuve laissée avec un registre que seule l'ancienne vérifie
  n'approuverait plus jamais rien. Le dépôt précède la mutation du coffre :
  l'autorité apprend le successeur d'abord, et un dépôt qui échoue est une
  cérémonie à refaire plutôt qu'un opérateur dont le coffre porte une ancre que
  personne ne connaît. `covers_client` refuse toujours de lire une campagne
  d'autorité comme une autorisation par client, et `covers_authority_object`
  refuse la réciproque.
  La famille **identité gateway** s'exécute aussi ; elle a sa propre ligne
  ci-dessous.
  La famille **délégation d'émetteur** s'exécute aussi, et elle a sa propre
  famille : l'objet qu'elle autorise n'est pas un `TrustUpdateObject`, aucun
  détenteur ne le reçoit, l'autorité émet dessous et tous les autres le
  vérifient sous l'ancre qu'ils épinglent déjà. La replier dans l'une des trois
  autres aurait laissé une campagne de celles-ci le livrer, ou l'inverse.
  La **chaîne complète** s'exécute enfin, et pas comme une campagne :
  `astra chain open`, puis `astra chain next` entre chaque étape, déposent
  quatre campagnes ordinaires dans l'ordre du §12.2 — émetteur, CA TLS,
  identité gateway, leafs du parc —, chacune avec sa propre famille, ses
  propres cibles et son propre toucher. `CampaignFamily` est totale, chaque
  famille refusant les trois autres dans les deux sens ; une campagne portant
  un *ensemble* de familles transformerait chacune de ces gardes en un contrôle
  de sous-ensemble, c'est-à-dire exactement la forme que ce modèle supprime.
  `AstraRotationCampaign::validate` **refuse** donc désormais la portée
  `full_certificate_chain` par son nom : « rien ne la fabrique » est un constat
  sur les appelants du jour, ce refus est une règle sur le document.
  L'ordre n'est pas une préférence : l'émetteur signe les feuilles clientes,
  l'ancre TLS est ce à quoi elles se chaînent, et l'identité gateway est ce que
  chaque client épingle — commencer par les feuilles les émettrait sous un
  émetteur et une ancre sur le point d'être remplacés, et chaque pair
  reviendrait deux fois. La campagne CA TLS de la chaîne ne porte **pas** de
  ligne `CA-PQ`, et c'est cette absence qui porte l'exclusion du §7.6 :
  `covers_authority_object` compare le type de certificat, donc une campagne
  sans ligne d'ancre refuse une transition `CA-PQ` par construction.
  « Franchie » ne veut pas dire « approuvée » : `astra chain next` lit l'**effet**
  dans le registre — l'époque d'émetteur a bougé, l'ancre TLS a un successeur,
  la décision gateway a été stockée — parce que le plan vit dans le volume
  d'état et les opérations dans la mémoire du service, et parce que c'est la
  question la plus forte des deux. Une étape approuvée dont l'objet n'a jamais
  atterri n'a pas déplacé le domaine.
  **Limite connue** : la dernière étape, les feuilles du parc, n'a aucun effet
  observable ici — une campagne autorise des rotations et chaque pair dépense
  cette autorisation en revenant (§7.6). Le plan le nomme au lieu de rapporter
  une réussite qu'il n'a pas vue. **Le prix est quatre touchers** au lieu d'un,
  et c'est le prix honnête de l'ordonnancement : le §7.6 borne une fenêtre de
  campagne à cinq minutes, donc les étapes suivantes ne pouvaient de toute
  façon pas être résolues d'avance ;
- le **cycle complet de l'identité gateway**, §5, §6 et les neuf étapes de
  §11.1, est livré. La gateway génère et scelle sa clé suivante **à côté** de
  celle en service et exporte une `GatewayCertificateRequest`
  (`heliosd prepare-gateway-certificate`) ; relancer la commande est une
  reprise, jamais une seconde demande — une demande encore valide pour la même
  époque est rendue telle quelle, parce que l'opérateur en tient déjà
  l'empreinte et qu'une seconde ne se distinguerait pas d'une substitution.
  `astra gateway-identity open` fige l'identité **lue en direct** sur le veth :
  ce registre n'a jamais détenu les feuilles de la gateway, et une valeur
  retapée produirait une campagne que le compagnon signe et que la gateway
  refuse. `astra-signer sign-gateway-transition` émet la leaf sous `CA-PQ` et
  signe la transition dans le **même geste**, parce que la signature lie la
  leaf exacte. `heliosd install-gateway-transition` la vérifie sous les ancres
  que ce registre épingle déjà et refuse toute leaf dont la moitié privée n'est
  pas scellée ici — le seul contrôle qu'aucune signature ne fait, et sans lui
  tout paraîtrait correct jusqu'à `activation_at`. `astra gateway-identity
  publish` persiste `published` puis le relaie, dans cet ordre : écrit après le
  relais, il laisserait la gateway fermer sa fenêtre d'avortement pendant que
  l'autorité croit encore la décision annulable. Un redémarrage après
  `activation_at` sert la candidate, et seulement si `published` est durable ;
  à `not_after`, la maintenance persiste le registre promu, remplace
  atomiquement le coffre actif, puis détruit l'ancienne clé scellée. Un
  marqueur nommant la transition exacte couvre la fenêtre de coupure entre ces
  écritures. L'avortement de §6.3 est produit par
  `astra-signer abort-gateway-transition` et appliqué par
  `heliosd abort-gateway-transition` ; il consomme l'époque.
  **Limite connue** : un client qui n'a jamais reçu la transition reste à
  l'époque précédente et refuse correctement le saut vers la suivante, sans
  pouvoir récupérer ce tombstone par la distribution — lui servir un avortement
  qu'il ne peut pas appliquer ferait échouer toute la transaction plutôt qu'une
  partie.
  **Limite connue** : la leaf TLS candidate voyage à part. La demande de §5 ne
  porte pas de champ TLS, donc son DER se copie depuis la gateway ; une leaf
  substituée est refusée à l'installation.
  Le motif `emergency_replacement` de §6.1 est livré, et avec lui la sortie
  d'une révocation gateway — qui était jusque-là une panne de service
  définitive, aucun détenteur n'acceptant plus la moindre transition.
  `astra-signer sign-gateway-transition --emergency-replacement` signe le
  remplacement, `astra-signer revoke --replacement-transition <fichier>` le
  nomme dans le champ `replacement_transition_fingerprint` du §10.1 — le
  fichier est lu, jamais l'empreinte saisie —, et l'état n'accepte ensuite que
  ce document exact. Il est **servi immédiatement** : il n'y a plus d'identité
  sortante avec laquelle se recouvrir, et l'étager laisserait le service à
  terre jusqu'à `activation_at`. Le compteur de révocation garde sa valeur, et
  les feuilles retirées restent refusées par le registre des tombstones. La
  réciproque tient aussi : le motif est refusé sur une identité saine, où il
  serait une bascule immédiate que personne n'a planifiée. `heliosd
  prepare-gateway-certificate` accepte une identité révoquée **sous
  `--key-recovery` seulement** : une identité retirée ne signe pas la
  continuité de sa suivante. `verify` accepte les trois motifs et refuse les
  trois autres de `RotationReason`, qui décrivent une décision cliente.
  **Limite connue** : préparer la clé de remplacement sur la machine qui vient
  d'être révoquée ne vaut que si l'hôte est sain ; après une compromission de
  clé, c'est le geste à ne pas faire, et rien ici ne prend cette décision à la
  place de l'opérateur.
  Le **rollback de service** de §11.1 étape 8 est livré :
  `astra-signer sign-gateway-rollback` résout la campagne localement depuis la
  transition signée — un rollback ne distribue rien, et le garde d'Astra
  l'impose, un résultat `gateway_identity` devant porter exactement un objet
  distribuable —, l'affiche, la fait attester par une clé autorisée puis signe
  `CertificateServiceRollbackAuthorization` sous `CA-PQ`. La gateway la vérifie
  contre l'ancre, la transition et la feuille qu'elle détient déjà, la refuse
  hors chevauchement, et la sélection expire par l'horloge, au plus tard avec
  le recouvrement. Rien d'autre ne bouge : aucun compteur, aucun slot, et la
  promotion a toujours lieu à `not_after`. La sélection est lue au démarrage,
  parce que la feuille en service est descellée une fois et tenue pour la vie
  du processus : la recharger reconstruirait le point d'accès QUIC pendant que
  des négociations y détiennent des slots de PSK. Toute bascule programmée est
  donc un redémarrage — `activation_at`, `not_after`, et l'expiration d'un
  rollback borné pareillement. Ce qui manquait n'était pas la bascule, c'était
  **de le dire** : la passe d'entretien compare maintenant, à chaque tour, le
  slot que ce processus a choisi à celui qu'un démarrage neuf choisirait, et
  quand ils diffèrent elle porte la raison dans le journal et dans la vue que
  la console affiche. Un démarrage qui *refuserait* — identité révoquée,
  chevauchement passé `not_after` sans promotion — transmet son erreur plutôt
  qu'un verdict : redémarrer à l'aveugle est précisément ce qu'il ne faut pas
  faire là. **Limite connue** : rien ne redémarre le démon à la place de
  l'opérateur, et rien ne doit le faire tant que la feuille servie est
  descellée une seule fois ;
- la **bascule coordonnée du §13.2** d'un parc existant, depuis la leaf gateway
  auto-signée vers `CA-PQ`, reste une procédure opérateur hors bande. Le
  bootstrap neuf du §13.1 est livré : `init-key-negotiation` ne produit plus
  de leaf PQ, mais une `GatewayBootstrapRequest` publique avec preuve de
  possession ; `astra-signer issue-gateway-bootstrap` l'émet sous `CA-PQ` par
  fichiers après deux credentials distincts ; `init-trust-domain` vérifie la
  leaf sous l'ancre fournie et refuse par son nom une auto-signature. Le
  **discriminant de profil Orion** `helios_key_negotiation`, lui,
  est livré : le document `.orion` porte `type`, le manifeste de coffre le
  scelle en v5, l'écran *Profils* le montre, et le chemin de connexion lit le
  type déclaré plutôt que la présence du bloc — une leaf perdue ne dégrade donc
  plus un profil Helios en profil classique sans le dire. Ce qui reste de cette
  ligne est la variante `classic` de `ProtectionMode`, qui survit pour relire un
  `network.toml` existant, et l'octet `mode_id = 0` du manifeste.
  Le **bloc de confiance** est livré aussi : la gateway le
  sert sur `GET /api/key-negotiation/trust-enrolment/<clé>` et l'imprime par
  `heliosd show-trust-enrolment`, `helios enroll` le pose dans le document
  — en ligne depuis l'API, hors ligne depuis `--trust-material` —, et
  `provision-client.sh` le rapatrie à côté des deux certificats qu'il copie
  déjà. Onze valeurs publiques lues sous un seul verrou : une époque prise à un
  instant à côté d'une ancre prise à un autre épinglerait un couple qui n'a
  jamais existé ensemble, et l'écart ne se verrait qu'au premier
  renouvellement. Un profil émis avant ce lot n'en porte pas ; Orion le dit
  plutôt que d'offrir un bouton qui échouerait à sa dernière étape ;
- les **surfaces IHM** du §12.2, partiellement. Côté Orion, la destination
  *Certificats* existe : elle liste les quatre certificats par profil avec
  leurs échéances et leur phase 80/90/95 %, les quatre actions avec la raison
  de chaque refus, la dernière erreur, et — depuis ce lot — l'étape où le
  renouvellement s'est arrêté, avec la ligne exacte qui l'approuve. Le bouton
  « Renouveler maintenant » **agit** : il ouvre l'opération, la reprend au
  clic suivant et committe le grant. `RenewEveryProfile` **agit** aussi : il
  avance tous les profils Helios de l'appareil d'un pas, chacun gardant sa
  propre place d'attente — une réponse par profil, parce qu'attribuer toute la
  campagne au profil d'où part le clic aurait ouvert cinq renouvellements sans
  rien montrer, et masqué l'approbation que chacun attend. Le refus d'un profil
  n'arrête pas les autres : ils sont indépendants, et s'arrêter au premier
  ferait dépendre le résultat de l'ordre d'une liste.
  `RecoverExpired` **agit** aussi désormais : elle ouvre la récupération du
  §7.5, rend l'identifiant que l'utilisateur lit à voix haute à qui détient une
  clé de sécurité — il n'existe plus aucun autre canal — puis, lorsque la
  cérémonie intégrée libère le grant, Orion reprend automatiquement la session
  cliente conservée en mémoire jusqu'au commit relayé. Le résultat revient
  dans *Certificats* avec l'heure d'activation ; aucun second clic de
  récupération n'est requis. Elle n'est proposée que si une feuille
  **cliente** est expirée : un certificat gateway périmé est le côté opérateur
  du domaine, qu'aucun credential client ne déplace.
  Avant chaque négociation pré-WireGuard, Orion applique aussi toute promotion
  locale arrivée à échéance. Cette lecture précède le chargement de l'identité
  TLS/PQ : une génération récupérée pendant que le tunnel est absent ne dépend
  donc pas d'une mise à jour de confiance dans ce même tunnel pour devenir la
  génération servie. Avant `activation_at`, la connexion est refusée localement
  avec cette heure plutôt que tentée avec la leaf expirée. L'écran
  *Certificats* programme la même relecture à cette échéance afin de remplacer
  la leaf expirée affichée par la génération effectivement promue.
  `RollbackToPrevious` **agit** pendant le chevauchement : l'écriture qui sert
  le candidat conserve dans la même enveloppe protégée l'identité sortante et
  l'échéance `not_after`; l'action ne change que le sélecteur de service. Le
  magasin de confiance, ses générations et ses compteurs restent inchangés.
  Passé l'échéance, la lecture répond par l'identité courante et la clé
  sortante est retirée. Ce choix est local au poste : les deux générations ont
  déjà été autorisées par le grant approuvé et la gateway les accepte pendant
  le chevauchement ; contrairement au rollback gateway, aucune clé privée de
  service détenue par un autre composant n'est dégradée et aucun nouvel objet
  `CA-PQ` n'ajouterait d'autorité.
  Orion arme désormais un timer à chaque établissement du tunnel. Après la
  mise à jour de confiance authentifiée, il attend `renewal_at`, ouvre le
  renouvellement ordinaire et conduit stage, reçu, grant et commit sans
  interaction. Le timer est annulé à la déconnexion ; la connexion suivante
  recalcule le seuil depuis l'état durable. Un Astra ancien qui renvoie
  `awaiting_operator` est refusé explicitement : Orion ne relance pas
  silencieusement la cérémonie supprimée.
  La section opérateur affiche aussi l'époque du registre de credentials portée
  par le profil et la disponibilité de la récupération, avec le motif canonique
  de son indisponibilité. Orion conserve désormais le `CredentialRegistry`
  vérifié dans le magasin de confiance et affiche les empreintes stables,
  états et époques des credentials, sans identifiant brut ni clé COSE.
  Le snapshot est reconstruit à l'enrôlement uniquement lorsque toutes les
  liaisons appartiennent à l'ancre et à l'époque courantes ; signatures,
  doublons et limite de 64 liaisons sont vérifiés. L'installation d'un registre
  conserve les décisions terminales (une ligne révoquée peut être reprise dans
  un snapshot ultérieur, jamais restaurée active ou perdue), refuse les
  régressions, l’omission d’une liaison conservée et les conflits
  de même époque et persiste avant adoption. Un ancien magasin sans ce seul
  champ est migré depuis ses liaisons vérifiées, sans modifier ses compteurs
  ni ses tombstones. Un snapshot absent ou historique ne produit jamais une
  liste vide présentée comme le registre du domaine : l'IHM affiche l'époque
  seule et nomme un snapshot illisible ou périmé. Le fichier de confiance est
  borné à 8 Mio avant désérialisation. L'inventaire reste une lecture locale.
  Côté console Helios, `CertificateDomainPanel` montre le
  domaine — gateway, CA, émetteur délégué, synthèse du parc — et
  `GatewayIdentityActions` **agit** sur les gestes que cette gateway possède :
  « Renouveler la gateway », l'installation d'une transition signée et
  « Annuler la transition préparée », par
  `POST /api/certificates/gateway-renewal` et
  `POST /api/certificates/gateway-transition[/abort]` sur la surface admin.
  Ces routes passent par le processus qui **détient** le registre ; les
  commandes équivalentes de `heliosd` restent celles d'un démon arrêté, deux
  écrivains sur un fichier étant exactement ce que ce module évite par
  ailleurs. Une décision signée se colle telle quelle : le compagnon la produit
  dans un coffre que cette machine ne détient pas, donc la console applique,
  elle ne signe pas. Ses refus portent leur raison — la surface est
  authentifiée comme le pare-feu, et l'inverse enverrait un opérateur dans les
  journaux du démon au pire moment.
  La console dit aussi quand la feuille **en service** n'est plus celle qu'un
  démarrage neuf choisirait, et nomme le geste — l'identité servie ne se
  recharge pas à chaud, et un écran qui tairait cela laisserait une gateway
  présenter l'ancienne identité sans trace du pourquoi.
  Une transition en vol y porte enfin ses deux instants : `activation_at`,
  `not_after`, l'ancre entrante à comparer au compagnon (§9.1), et l'état de
  distribution — parce que c'est lui, et non une date, qui dit s'il reste
  l'avortement du §6.3 ou seulement le rollback borné du §4.4. Ces valeurs
  voyageaient déjà dans `GET /api/certificates`; elles n'apparaissaient que
  dans l'écho du document qu'on venait de coller, et un rechargement les
  perdait. Un domaine au repos n'affiche rien : la carte n'existe que tant
  qu'une transition ou un rollback court.
  **Reste ouvert** : « Renouveler les leafs du parc », « Renouveler toute la
  chaîne » et « Tourner les autorités » ouvrent une campagne **Astra**, dont
  §11.6 garde la résolution locale parce qu'une campagne est l'inventaire du
  domaine ; la console les nomme avec leur commande — `astra campaign open`,
  `astra chain open` — plutôt que d'inventer la surface qui les porterait ;
- les **essais d'intégration** du §14.2, qui supposent un vrai plan de données ;
- toute **migration de format** des états persistés. `TrustState` et
  `RegistryState` portent `deny_unknown_fields`, et la forme de leur état borné
  a changé pendant ce lot. Il n'y a pas de chemin de migration parce qu'il n'y a
  rien à migrer : hors tests, rien n'écrit ces deux fichiers, donc aucune
  instance d'une forme antérieure n'existe sur aucun disque. C'est un constat
  daté, pas une décision à conserver — dès qu'un Orion publié écrit un magasin
  de confiance, le format est figé et tout changement ultérieur exige une
  migration explicite avec des fixtures de la version précédente. En attendant,
  un document illisible échoue franchement plutôt que de se désérialiser en un
  état qui aurait silencieusement perdu les révocations qu'il portait.

Tant que ces points ne sont pas livrés, cette livraison **ne doit pas** être
présentée comme « cycle de vie implémenté » (§12.1). Le §12.5 fait le compte
de ce qui reste, et distingue le travail restant des décisions prises.

### 12.4 Fonctions reportables après le cycle complet

- notifications par courrier ou messagerie externe ;
- coffre cryptographique M-sur-N et approbation par plusieurs identités
  d'opérateurs, plutôt que plusieurs clés 1-sur-N d'un même opérateur ;
- HSM ML-DSA-87 ou environnement attesté protégeant l'émetteur du noyau hôte ;
- campagnes multi-gateways sous un même domaine ;
- mesure de conformité exportée vers un SIEM.

Ces extensions ne peuvent augmenter le nombre de slots, ignorer une
génération, prolonger le chevauchement, réactiver une leaf expirée ou révoquée,
ni élargir une délégation Astra déjà signée.

### 12.5 Arbitrage du §12.1, au 8 octobre 2026

Le §12.1 est **atteint pour l'implémentation**. La cérémonie `GetAssertion`
unique du §7.5, dernier point de développement, est livrée (§12.3). Ce qui
subsiste n'est pas du travail en attente, et le nommer comme tel serait aussi
trompeur que le taire :

- **Le §13.2**, l'amorçage de confiance d'un parc v5 déjà déployé. La première
  installation de `CA-PQ` n'est pas la génération `N -> N+1` d'une rotation :
  elle exige une confirmation d'empreinte hors bande, faute de quoi la
  compromission de la leaf d'une seule gateway créerait une CA valable pour
  tout le parc. C'est une cérémonie humaine, et aucune commande ne peut la
  remplacer. Elle reste une procédure opérateur documentée. Une installation
  neuve reçoit sa feuille gateway de `CA-PQ` (§13.1) et n'en a pas besoin.
- **`POST /v1/campaigns`**, l'ouverture d'une campagne depuis l'origine
  publique. Le §11.6 dit pourquoi : cette route *résout* une campagne sur les
  cibles et générations courantes, donc sur un canal public non authentifié
  elle répondrait l'inventaire du domaine à n'importe quel appelant.
  L'authentification qu'elle exigerait n'est décrite nulle part, et l'inventer
  serait construire le trou. La résolution reste locale — ce qui entraîne que
  les trois actions de campagne du §12.2 restent nommées par leur commande
  dans la console plutôt que portées par un bouton.
- **Le redémarrage après une bascule** reste un geste opérateur, par décision
  (§12.3) : la feuille servie est descellée une seule fois, et le démon dit
  quand un redémarrage est dû plutôt que de le faire.

**La validation sur cible reste à mener** : les essais d'intégration du §14.2
supposent un vrai plan de données, un TPM et une clé FIDO2. Aucun ne peut
tourner dans l'environnement de développement, et le `docs/testing/TESTING.md`
dit quel environnement prouve quoi. Cette note ne porte aucune revendication
de validation matérielle : le cycle est implémenté et testé au-dessus du
matériel, sa preuve sur les machines cibles est une campagne d'essais, pas un
chantier de développement.

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
- `authority_url`, `webauthn_rp_id` et `astra_policy_fingerprint` confirmé hors
  bande dans chaque profil Helios.

Le geste est entièrement hors ligne. `heliosd init-key-negotiation` génère et
scelle les clés TLS et ML-DSA-87 sur la gateway, installe les seules ancres
clientes publiques et exporte `GatewayBootstrapRequest`. Sa transcription est :

```text
"helios-gateway-bootstrap-request-v5"
|| format_version:u16
|| gateway_wg_public_key:32
|| len(server_name):u32 || server_name
|| len(ml_dsa_87_public_key):u32 || ml_dsa_87_public_key
```

`key_possession_proof` est la signature ML-DSA-87 de cette transcription sous
la clé privée gateway nouvellement scellée. La demande ne porte ni
`trust_domain_id` ni époque : ces deux valeurs appartiennent au coffre
opérateur qui émet directement l'époque 1. Elle ne transporte aucune clé
privée.

Le poste opérateur exécute `astra-signer issue-gateway-bootstrap --request
<demande> --out <leaf>`. Cette cérémonie n'est pas une campagne Astra en ligne :
le domaine neuf n'a encore ni registre, ni clé de service, ni veth. Elle exige
néanmoins **deux credentials actifs distincts**. C'est une réadmission sans
continuité au sens de §0.2, et non une rotation `gateway_identity` ordinaire :
aucune identité sortante et aucun état de domaine ne bornent la nouvelle clé.
La décision réside dans `CampaignScope::GatewayBootstrap` et son
`required_credentials() = 2`; aucun appelant ne fixe ce nombre séparément.
Chaque credential doit ouvrir le coffre courant, puis le premier slot ouvert
sert à l'émission sous `CA-PQ`.

La leaf publique revient seule sur la gateway. `heliosd init-trust-domain
--gateway-certificate <leaf>` vérifie la preuve locale, l'identité WireGuard,
le `server_name`, la clé ML-DSA-87 et la signature sous l'ancre fournie avant
d'écrire la leaf et le registre. Une leaf dont la signature vérifie sous sa
propre clé est refusée par l'erreur nommée
`SelfSignedGatewayCertificate`. Ce refus ne s'exécute que lors de la création
du registre : le chargement d'un registre existant reste inchangé et les
installations antérieures continuent donc de redémarrer. Sans registre, le
lecteur historique exige encore une leaf auto-signée ; une leaf `CA-PQ`
installée à mi-amorçage ne devient jamais un repli silencieux.

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
- transcriptions TLS seule et PQ seule distinctes grâce aux deux octets de
  présence, refus de `present > 1`, d'une valeur après `present = 0` et d'une
  valeur tronquée après `present = 1` ;
- révocation TLS seule, PQ seule et TLS + PQ produisant trois transcriptions
  distinctes ; refus d'un discriminant supérieur à 1, d'un couple
  empreinte/`not_after` incomplet ou séparé et d'une empreinte de remplacement
  dont le discriminant ne correspond pas aux octets présents ;
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
- autorisation de stage ordinaire acceptée seulement depuis l'API veth Astra,
  sans route permettant à Orion de la remettre dans WireGuard ; reçu renvoyé
  uniquement à Astra ;
- `AstraIssuerAuthorization` refusée sous une autre gateway, hors période, avec
  un usage ou plafond élargi, une politique différente ou une époque reculée ;
- délégation refusée quand `policy_fingerprint` diffère du pin hors bande du
  profil, même sous une signature `CA-PQ` valide ; profil refusé avec une
  empreinte de politique nulle ;
- chaque type ML-DSA-87 accepté sous son `ctx` ASCII exact et refusé avec
  `ctx = ""`, le contexte d'un autre type, un NUL final ou HashML-DSA ; même
  refus obligatoire pour une signature cryptographiquement valide de `CA-PQ` ;
- émetteur Astra incapable d'enrôler, réadmettre, récupérer une leaf expirée,
  tourner une CA, signer une génération sautée ou émettre une leaf ordinaire
  avant 80 % sans campagne YubiKey exacte ;
- calcul exact de 80 %, sans overflow, déclenchement stable après redémarrage
  et fenêtre Astra incapable de retarder le calcul local ;
- approbation refusée sous un autre RP ID, credential, domaine, pair,
  `operation_id`, hash de demande ou couple de générations, ainsi qu'après cinq
  minutes ou après consommation ;
- binding de credential refusé sans signature `CA-PQ`, avec une époque de
  registre reculée ou un état `lost`/`revoked`; assertion refusée si Astra ne
  transporte que son empreinte sans les octets WebAuthn vérifiables par Helios
  et Orion ;
- grant ordinaire jamais émis avant une demande active/candidate valide et un
  reçu Helios valide ; grant sensible jamais émis avant son approbation
  opérateur et ce même reçu ;
- candidat client jamais activable avant un commit signé par les clés active
  et suivante ; commit ordinaire refusé hors du tunnel du pair et commit de
  récupération refusé sans l'opération YubiKey exacte ;
- réception et signature du reçu laissant Helios en `pending_grant`, sans slot
  `next`, puis commit seul produisant `next_committed` et
  `retire_active_at = grant.not_after` ;
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
- mutation de `format_version` ou `protocol_version` dans la récupération, ou
  de `protocol_version`/`server_name` dans l'avortement gateway, rompant la
  signature canonique ;
- récupération à un credential exerçant une seule cérémonie `GetAssertion`
  liée au challenge et au sel du coffre, tandis qu'un renouvellement ordinaire
  n'obtient aucune sortie PRF et n'ouvre aucun key-slot ;
- validateur historique inaccessible depuis mTLS et QUIC, où la leaf expirée
  reste refusée ;
- récupération et rollback refusés pour `revoked`, même avec deux YubiKeys ;
- récupération à une YubiKey refusée sans l'ancienne clé PQ et incapable de
  changer la clé WireGuard ; réadmission sans continuité exigeant deux
  confirmations ;
- mutation d'un octet de campagne, d'une cible ou de son ordre après
  approbation WebAuthn refusée ;
- mutation de `request_fingerprint` ou de
  `renewal_authorization_fingerprint`, du stage ou du grant rompant leur chaîne
  d'empreintes ;
- ajout et retrait de YubiKey incapables de laisser zéro credential de secours ;
- fixtures HVLT vérifiant AES-256-GCM, identifiants de KDF, HKDF-SHA-256, sels
  et AAD ; permutation de `vault_id`, `slot_id`, domaine, table de slots, sel,
  nonce, ciphertext ou tag rendant le coffre illisible ; mutation d'un libellé
  n'influençant aucune décision cryptographique ;
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
- statut refusé quand son état n'appartient pas à la famille de
  `certificate_kind`, avec `promoted` accepté pour gateway, client, CA et clé
  de service mais refusé pour l'émetteur Astra ;
- application séquentielle de trois transitions CA hors ligne sans jamais
  conserver trois ancres simultanément ;
- révocation dominante dans chaque état et callback obsolète sans effet ;
- révocation de la génération gateway active depuis chaque phase produisant
  l'état terminal, et révocation de la seule suivante supprimant le candidat
  sans retirer l'active ;
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
- requête de confiance refusée si le snapshot actif TLS/PQ est mélangé, si
  l'empreinte PQ présentée ne correspond pas au certificat complet ou si la
  leaf suivante est présentée avant `activation_at` ;
- routes de renouvellement ordinaires absentes du canal public Astra et aucun
  repli vers celui-ci après une erreur du relais ;
- relais Helios refusant méthode, chemin, en-tête ou corps non typé et liant
  lecture d'opération, requête de compagnon, assertion et commit au même pair ;
- API Astra bornée par taille, nombre de cibles, identité et préfixe réseau,
  avec erreurs indifférenciées avant authentification ;
- jeton de capacité refusé sous un autre scope, chemin, méthode, opération,
  manifeste ou coffre, après cinq minutes, après redémarrage d'Astra ou après
  consommation de `signer_result_submit`; comparaison du tag en temps constant ;
- l'un des deux mécanismes DRBG autorisés, fourni par la bibliothèque
  cryptographique, refusant
  toute sortie avant instanciation ou après échec de la source
  plateforme/reseed, avec au plus
  `2^20` appels entre deux apports d'entropie, réinstanciation ou reseed dans
  l'enfant après fork et aucun octet partiel écrit ; fournisseur absent,
  CTR-DRBG ni dérivé ni semé en pleine entropie, et DRBG applicatif maison
  refusés ;
- identifiants et challenges nuls refusés à la réception, sans que le test de
  non-nullité puisse remplacer les garanties du fournisseur ;
- route veth incapable d'atteindre un pair, le plan de données, les coffres ou
  une autre API Helios ;
- TLS veth refusant TLS 1.2, `psk_ke`, tickets de reprise et 0-RTT, avec clés de
  session différentes après chaque reconnexion ;
- fuzzing de tous les objets signés, de leurs certificats embarqués et de la
  machine d'état temporelle.

Les harnais de fuzzing sont livrés. Ils vivent dans `aether::fuzzing`, que la
compilation stable vérifie et que la suite ordinaire exécute sur ses graines ;
`fuzz/`, hors espace de travail, ne porte que quatre enveloppes libFuzzer de
trois lignes. Du code que seule une chaîne *nightly* compile est du code que
personne n'exécute sur la branche qui part en production, et un harnais devenu
inerte parce qu'un type a été renommé doit échouer avec le reste, pas au
prochain `cargo fuzz`. Quatre cibles : les objets signés, la transaction
chunkée, les certificats embarqués, et la machine d'état temporelle — cette
dernière étant la seule à **asserter** plutôt qu'à seulement survivre, sur les
invariants du §4 : un compteur de révocation ne redescend jamais, `revoked`
est terminal, un rollback de service ne déplace aucun compteur et ne survit
pas au chevauchement qui le porte.

**Limites connues** : aucune cible ne vérifie une signature valide — un fuzzer
n'en produit pas —, il n'existe pas de corpus de graines versionné, et aucune
exécution `cargo fuzz` n'a encore eu lieu. `fuzz/README.md` le dit aussi.

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
- préparation à 80 % convergeant automatiquement sans YubiKey, avec nouvelle
  tentative à la connexion suivante après une coupure ;
- renouvellement ordinaire complet Orion → WireGuard → Helios → veth → Astra,
  reçu et grant en retour, sans
  aucune connexion d'Orion à l'origine HTTPS Astra ;
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
s'auto-autoriser. L'épinglage ne dispense pas de valider le DER : la leaf doit
être auto-émise et auto-signée, non-CA, porter `serverAuth`, `digitalSignature`
si `keyUsage` est présent, nommer exactement le `server_name` dans son SAN DNS
et couvrir toute la fenêtre de transition.

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
| `astra` | coordinateur public HTTPS et privé veth, statut authentifié, renouvellements automatiques, campagnes, contrôle des approbations sensibles, émetteur délégué, transactions chunkées, registre et audit |
| bibliothèque `astra-operator` | vérification et exécution des cérémonies sans dépendre d'une ligne de commande |
| sidecar `helios-astra-helper` | assertions FIDO2 des récupérations/campagnes lancées par Orion ; ouverture locale du coffre par PRF, puis zéroïsation |
| adaptateur `astra-signer` | flux portables et hors ligne tant que leur parité Orion n'est pas validée sur Windows |
| `aether-vault` | coffre maître et key-slots multiples liés aux credentials YubiKey |
| `helios-api` | routes typées dans WireGuard, relais vers l'API Astra du veth, authentification de source et limites HTTP |
| `astra-channel` | canal privé Astra–Helios du §8.3 : contrats échangés, configurations mTLS client et serveur des deux extrémités, ALPN, routeur de l'API privée de cycle de vie appelée par Astra, que `heliosd` héberge sur le veth ; ne dépend que d'`aether` (§0.8) |
| `heliosd::key_negotiation` | identité active, staging gateway, marqueur publié, avortement, reçu signé et preuve de leaf servie |
| `helios-provisioning::admission` | pending client, lease, commit/purge, générations TLS/PQ atomiques, unicité et révocation dominante |
| configuration TLS de `heliosd` | deux CA clientes au plus, promotion par `ca_tls_epoch` et vérification mTLS avant résolution de génération |
| `orion-core::config` | ancres, pins actifs/suivants, compteurs persistants et anti-rollback |
| `orion-core::key_negotiation` | planificateur automatique à 80 %, récupération, chunks pending, commit atomique et staging client |
| `orion-core::identity_store` | clés et certificats clients actifs/suivants protégés, promotion atomique |
| IHM Orion | état local, renouvellement profil/appareil, récupération expirée et rollback borné |
| IHM Helios | état du parc, campagnes leafs/chaîne/autorités, avortement pré-publication et rollback gateway |
| `helios` | diagnostic, import/export hors ligne et commandes de campagne Astra non interactives |

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
