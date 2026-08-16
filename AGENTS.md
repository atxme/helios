# AGENTS.md

Instructions pour les agents de code travaillant dans ce dépôt.

## État courant

Helios est une gateway WireGuard Linux ; Orion est son client Tauri ; `aether`
porte les types et contrats communs. La rupture avec IKEv2 est terminée dans le
code. [ADR-001](docs/adr/ADR-001-WIREGUARD.md) conserve le raisonnement de migration
et [ADR-002](docs/adr/ADR-002-SIGNATURES-PQ.md) fixe la signature hybride des
artefacts éditeur. [ADR-004](docs/adr/ADR-004-CHAINE-DE-LIVRAISON.md) fixe le
cycle de vie des secrets et la chaîne de livraison. En cas de doute, le code et
les ADR acceptés font foi.

Le provisioning ML-KEM, l’IPAM et les backends WireGuard existent. Le PSK
post-quantique est négocié et posé de bout en bout : la gateway l’installe sur
le plan de données **avant** de l’annoncer au client, et refuse la demande si
la pose échoue. Trois limites restent explicites : la VIP dérivée par l’IPAM
n’est pas réconciliée avec l’adresse déclarée en config (chaque bout garde la
sienne, l’écart est journalisé) ; le fichier de récupération signé est bloqué
jusqu’au choix du compteur anti-rejeu fichier ou NV TPM ; le **DNS d’un client
n’est pas tunnelé**, même `allow_client_internet` actif — ses requêtes sortent
hors du tunnel (voir le doc-comment de `helios-firewall::ruleset`).

L’outillage d’exploitation existe (ADR-004, lot 1) : `heliosd init-identity`
crée l’identité WireGuard scellée sans jamais l’écrire en clair, `heliosd peer`
et `helios-ctl peer` admettent les clients par le **même** code
(`helios-provisioning::admission`), `helios-ctl profile emit` produit le
document `orion-profile` que l’import Orion consomme, et `helios-ctl escrow`
expose enfin le séquestre.

La négociation de clé pré-WireGuard existe de bout en bout, en **protocole v5**
([ADR-005](docs/adr/ADR-005-NEGOCIATION-DE-CLE.md), amendements des 6 et 8 août 2026 ;
spécification [NEGOCIATION-DE-CLE-V5.md](docs/specification/NEGOCIATION-DE-CLE-V5.md)) : port
UDP dédié, phase de challenge anti-rejeu, authentification **ML-DSA-87**, deux
modes négociables — `static_psk` et `ml_kem` — et plancher anti-downgrade qui
monte seul et ne redescend pas. La v4 est décrite par
[NEGOCIATION-DE-CLE-V4.md](docs/specification/NEGOCIATION-DE-CLE-V4.md), conservée
comme trace de ce qui tournait avant la bascule — le code ne la sert plus, et
les deux versions ne négocient pas ensemble (ALPN, domaines de signature et
format de certificat distincts). Les deux IHM exposent la négociation —
plancher par pair côté gateway ; côté Orion l’écran *Profils* édite tout le
bloc, certificats compris, avec empreinte PQ dérivée en Rust et état de
l’identité. Seul le plancher n’y est pas librement modifiable : il ne descend
jamais sous la valeur avec laquelle le profil a été chargé.

**La v5 est partiellement implémentée**, et la spécification nomme ce qui
manque. Ne pas la présenter comme terminée : la mention « implémentée à trois
exceptions » portée ici jusqu’au 6 août 2026 était fausse, et une revue a dû
l’établir. Une seconde revue, le 7 août 2026, a montré que la machine d’état
générationnelle posée en réponse à la première était elle-même incomplète — la
génération n’était pas réservée avant la pose du candidat, et l’échéance
absolue de connexion détruisait la tâche sans rollback. Les deux sont corrigés.
Restent ouverts :

- le **discriminant de type de profil Orion** (§19, §22). `classic` est refusé
  à la validation d’une requête v5 et à la préparation — serde le décode, puis
  `validate()` le rejette, donc aucun message v5 ne peut le sélectionner — mais
  la variante subsiste dans `ProtectionMode` et un profil Orion reste un bloc
  `key_negotiation` facultatif, dont l’absence signifie encore implicitement
  « classique ». La retirer est une migration de format : `network.toml`,
  document `.orion`, manifeste de coffre (`mode_id = 0`) et les deux IHM ;
- l’état **`revoked`** du §11.1 : une révocation se lit à l’absence du pair
  dans `network.peers`, pas à un marqueur terminal dans le slot. Hors
  concurrence le pair ne négocie plus, mais l’absence de transition atomique
  entre admission, génération et plan de données ne fournit pas encore la
  priorité normative de `revoked` ;
- le **renouvellement de PSK en place** (§12.3), suspendu à l’essai bloquant du
  §20.0 qui doit d’abord établir sur un vrai plan de données qu’une session
  WireGuard réinitialisée handshake dans les délais ;
- la **renégociation d’Orion sur vieillissement de handshake** (§12.5) : la
  gateway récupère bien son slot, mais un client dont le PSK a été retiré ne
  s’en aperçoit qu’à la déconnexion ;
- l’**enrôlement sans clé privée avec signature opérateur** (§15), qui reste au
  modèle v4 décrit plus bas ;
- la **libération à la désinstallation d’un profil** (§12.2) : le `release` du
  §7.5 part bien à la déconnexion, mais retirer un profil dont le tunnel est
  monté n’en envoie aucun — le slot tient jusqu’à la récupération à 300 s. Seul
  le contrôleur détient le reçu de commit, et le chemin de suppression ne l’a
  pas ;
- l'**exploitation** du cycle de vie des certificats
  ([ROTATION-CERTIFICATS](docs/specification/ROTATION-CERTIFICATS.md) §12.3,
  [ADR-008](docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md)). Le chemin
  « demande → autorisation → persistance gateway → reçu → grant → commit » est
  livré et branché : `aether::certificates` porte les objets signés, les états
  bornés et les contrôles X.509 ; `helios-provisioning::certificates` exige le
  grant au commit ; `heliosd::certificates` est le propriétaire unique du
  registre et signe les reçus par la leaf servie ; le binaire **`astra`** porte
  registre, audit chaîné et émetteur délégué borné ;
  `orion-core::certificates` vérifie une transaction chunkée entière avant de
  l'appliquer par une seule écriture. Le **coffre d'autorité** existe aussi :
  `astra::vault` enveloppe `CA-PQ` et `CA-TLS` sous un key-slot par credential
  FIDO2, et le compagnon **`astra-signer`** crée le coffre, y enrôle des clés,
  les éprouve et en retire — `init`, `enrol`, `verify`, `list`, `remove`,
  `rename`. Restent ouverts : les **commandes de signature** du compagnon
  (certificat auto-signé `CA-TLS`, `AstraIssuerAuthorization`, campagnes) et
  donc toute approbation opérateur (routes en `501`), le veth privé
  Astra–Helios — `heliosd` n'a aucun client HTTP vers Astra, donc la gateway ne
  détient encore **aucun objet pré-signé à distribuer** et répond `503` à un
  client qu'elle sait en retard —, la récupération d'une identité expirée, le
  discriminant de profil Orion et la bascule du §13, et les deux surfaces IHM.
  La leaf PQ gateway servie reste auto-signée tant que cette bascule n'a pas eu
  lieu.
  L'amendement du 15 août 2026 tranche le transport et l'approbation du chemin
  restant : un Orion dont le tunnel fonctionne ne contacte jamais Astra
  directement. Il appelle des routes typées de `helios-api` dans WireGuard ;
  `heliosd` authentifie la VIP du pair puis relaie les objets canoniques vers
  l'IP privée d'Astra sur le veth mTLS. Le canal HTTPS public est réservé à la
  récupération sans tunnel et aux opérations opérateur hors tunnel. Chaque
  renouvellement client, planifié ou manuel, attend une approbation YubiKey
  liée au hash exact de la demande. Le grant transporte l'assertion WebAuthn et
  le binding public du credential signé par `CA-PQ`, afin qu'Helios et Orion ne
  fassent pas confiance à la seule affirmation d'Astra. Cette assertion
  autorise l'émetteur délégué, n'ouvre pas le coffre maître et ne produit aucune
  signature ML-DSA.
  Le seuil de 80 % prépare donc une opération `awaiting_operator`; il ne peut
  plus achever silencieusement la rotation.
  L'amendement du 16 août 2026 ferme les contradictions relevées dans le document :
  `ClientCertificateStageAuthorization` voyage toujours d'Astra vers Helios
  sur le veth et le reçu revient à Astra sur ce même lien ; Orion ne transporte
  aucun des deux. Helios reste en `pending_grant` après le reçu et ne crée
  `next_committed` qu'au commit. Les trois empreintes clientes de
  `AuthenticatedTrustUpdateRequest` sont intentionnelles — snapshot TLS/PQ de
  l'active, puis leaf PQ effectivement présentée — et les statuts sont validés
  par famille. La révocation de l'active domine depuis toute phase ; celle de
  la seule suivante retire le candidat sans révoquer l'active. Le code n'est
  pas encore aligné sur tous ces écarts filaires : voir §12.3 de la
  spécification avant de poursuivre le développement.
  La fermeture cryptographique du même jour ajoute six invariants. Les deux
  optionnels de `GatewayIdentityTransition` portent chacun un octet de présence
  `0|1` avant leur empreinte — le code le faisait déjà, la transcription ne le
  disait pas. Toute signature ML-DSA-87 de la négociation v5 et du cycle de vie
  emploie l'algorithme pur avec un `ctx` FIPS 204 non vide égal au domaine
  ASCII du type ; HashML-DSA et `ctx = ""` sont refusés, y compris sous
  `CA-PQ`. Le coffre Astra est exactement les deux
  couches HVLT v1 AES-256-GCM/HKDF-SHA-256 décrites au §2.4.1 : sel WebAuthn
  par coffre, mais sel HKDF frais dans chaque enveloppe de slot. La politique
  Astra possède une empreinte confirmée hors bande et épinglée dans le profil ;
  une signature `CA-PQ` ne peut la remplacer. Les capacités du compagnon sont
  des jetons HKDF-SHA-256 + HMAC-SHA-256, bornés à cinq minutes, une opération,
  un manifeste, un coffre et un scope. Enfin tout aléa du protocole vient du
  DRBG SP 800-90A à 256 bits de la bibliothèque cryptographique —
  HMAC-DRBG-SHA-512 ou CTR-DRBG-AES-256 —, semé par la source
  plateforme en mode fail-closed, reseed au plus tard toutes les `2^20`
  générations et après fork ; un échec ne rend aucun octet. Aucun DRBG
  applicatif n'est écrit dans Helios, et la validation CAVP/ACVP du fournisseur
  n'est pas exigée par cette version.
  **Le socle de cet alignement est livré.** `aether::ml_dsa` est le point
  d'entrée unique des signatures ML-DSA-87 : il exige le `ctx` du type, refuse
  contexte vide, contexte d'un autre type, NUL et octet non imprimable, et
  refuse un message qui ne s'ouvre pas sur son domaine — le contexte n'est plus
  un paramètre libre, `CanonicalBytes::finish_signed` rend un
  `SignedTranscript` qui porte le sien. HashML-DSA n'est appelé nulle part et
  ne vérifie pas. `aether::random` porte l'autre moitié et **ne réimplémente
  aucun DRBG** : interface vers le fournisseur, refus ferme, faux fournisseur
  déterministe sous `cfg(test)` seulement, bannière de démarrage nommant
  fournisseur, version, mécanisme, `use_df` et intervalle de reseed.
  Plus aucun appel direct au CSPRNG système ne subsiste hors de ce module —
  négociation, cycle de vie, HVLT, coffres Orion, séquestre TPM et outils
  compris.
  La source est **`aws_lc_rs::rand::SystemRandom`**, c'est-à-dire le
  `RAND_bytes` d'AWS-LC déjà utilisé pour AES-GCM, HKDF et HMAC. Le lot a été
  audité contre la source vendorée plutôt que contre la réputation de la
  bibliothèque : CTR-DRBG-AES-256, état par thread, seed issu d'un arbre DRBG
  enraciné dans le jitter CPU et personnalisation par l'OS — les deux rôles
  s'échangeant sous hyperviseur —, reseed toutes les 4096 générations
  (`kCtrDrbgReseedInterval`, 256 fois sous le plafond de `2^20`), et
  réinstanciation avant toute sortie après fork ou reprise d'instantané de VM
  (`crypto/ube`, bâti sur `MADV_WIPEONFORK`). C'est précisément pourquoi
  `aether::random` n'a **pas** de détection de fork à lui : le fournisseur la
  fait, et mieux qu'une comparaison de PID — et quand cette détection est
  indisponible, elle échoue fermée et impose un reseed avant *chaque*
  génération. Un échec d'entropie n'est pas une erreur rendue : AWS-LC
  `abort()`, et `RAND_bytes` retourne 1 inconditionnellement, donc le refus est
  plus strict que ce que la spécification demande.
  **Trois écarts sont nommés plutôt que masqués.** Le fournisseur n'emploie
  **pas** de fonction de dérivation — `CTR_DRBG_init` consomme exactement un
  seedlen de pleine entropie, SP 800-90Ar1 §10.2.1.3.1 —, alors que les deux
  spécifications n'admettent CTR-DRBG qu'avec `use_df = true` ; la bannière
  annonce donc `use_df=false` et l'arbitrage reste à rendre. La **résistance à
  la prédiction par appel** existe en C
  (`RAND_bytes_with_user_prediction_resistance`) mais pas dans le binding Rust,
  donc `fill_secret` porte l'intention sans changer l'appel. Enfin le **matériel
  de session TLS** de `rustls`/`quinn` reste sur le CSPRNG de `ring` : `reqwest`
  0.12 n'offre que le fournisseur `ring`, et sa variante `-no-provider` exige un
  `CryptoProvider::install_default` dans chaque binaire. En revanche les **clés
  privées X.509** produites par `rcgen` sont passées sur AWS-LC (feature
  `aws_lc_rs` épinglée au manifeste), et ML-KEM comme ML-DSA tirent déjà du même
  `RAND_bytes`.
  La **validation FIPS est hors périmètre** et assumée comme telle : la
  construction `aws-lc-fips-sys` porte les certificats CAVP/CMVP mais exige les
  chaînes CMake et Go qu'ADR-001 §2 tient hors du build, pour le même mécanisme.
  Rien dans le code ne revendique de validation.
  **Migration** : le `ctx` entre dans la vérification, donc tout certificat PQ
  émis avant ce lot cesse de vérifier et le parc se ré-émet.
  Les **deux moitiés du domaine s'amorcent** : `astra bootstrap` d'un côté,
  `heliosd init-trust-domain` de l'autre. La seconde n'ouvre aucun coffre et ne
  génère aucune clé — elle relit les leaves servies sur disque et reçoit les
  ancres de l'opérateur, donc elle tourne TPM indisponible. Sans elle le
  registre est absent, et un registre absent n'est **pas** un registre vide :
  les routes de cycle de vie in-tunnel restent fermées et le démarrage le dit.
  Le tout se déploie en **deux commandes** — `astra-signer init`, puis
  `./scripts/deploy.sh` — et aucune valeur ne se recopie : `init` écrit un
  relais public à côté du coffre, `deploy.sh` le lit, interroge la gateway par
  `heliosd show-identity`, amorce Astra, capture clé de service et tête d'audit
  dans sa sortie, et enchaîne sur `init-trust-domain`. Voir
  [DEPLOIEMENT-ASTRA](docs/DEPLOIEMENT-ASTRA.md).
  **Aucune clé de sécurité ne signe quoi que ce soit** : une YubiKey 5 ne
  produit pas d'ML-DSA, et tout champ de signature du cycle de vie est un
  `MlDsa87Signature`. Le jeton authentifie et dérive — `hmac-secret` ouvre un
  key-slot, rien d'autre. Le coffre exige deux credentials (`REQUIRED_SLOTS`)
  et en accepte huit ; enrôler la troisième est le **même** geste que la
  seconde. Le corps est scellé sous une empreinte de la table de slots, donc un
  slot retiré puis recollé depuis une sauvegarde n'ouvre plus le fichier
  courant — une sauvegarde antérieure, elle, reste ouvrable par la clé retirée.
  CTAP n'est **pas** une feature de compilation, pas plus que la négociation de
  clé : tout binaire `astra-signer` porte la pile, et aucun chemin n'ouvre le
  coffre sans clé. **Deux transports**, choisis explicitement et jamais déduits
  (`--transport`) : `platform` sous Windows passe par `webauthn.dll` — aucune
  élévation, et le PIN est saisi par le système donc n'entre jamais dans le
  processus ; `hid` parle CTAP2 directement, partout, mais sous Windows exige
  un processus administrateur — pour un programme qui tient `CA-PQ` en clair,
  c'est le privilège qu'on ne veut pas. Un credential appartient à la clé, pas
  à l'API : un coffre créé par un transport s'ouvre par l'autre à RP ID égal —
  mais seulement parce que le chemin HID applique **lui aussi** la conversion
  PRF de WebAuthn, `SHA-256("WebAuthn PRF" || 0x00 || sel)`. Windows l'applique
  par défaut dans `pHmacSecretSaltValues` ; le code laisse volontairement
  `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` désactivé, car demander les
  sels CTAP bruts ferait dériver deux secrets différents selon le transport.
  L'API WebAuthn 4 sait fournir ces sels avec `GetAssertion` v6, mais ne sait
  créer qu'avec
  `MakeCredential` v5 : ce chemin demande l'extension historique
  `hmac-secret`. À partir de l'API 6 seulement, `MakeCredential` v6 et
  `bEnablePrf` la remplacent. Annoncer v5 tout en remplissant `bEnablePrf`
  laisse Windows ignorer silencieusement le champ et crée un credential qui ne
  déverrouille rien.
  Le prix du transport HID est `libudev` en dépendance de compilation, posée par
  `scripts/setup-dev.sh` — sans elle le workspace ne se bâtit plus ; celui du
  transport plateforme est `WEBAUTHN_API_VERSION_4`, exigé par les sels
  `hmac-secret` et refusé en nommant la version trouvée.
  **Limite connue** : le matériel ne s'exerce pas en WSL2 (aucun passthrough
  USB), et le module `webauthn` ne s'y compile même pas — il est type-vérifié
  contre `x86_64-pc-windows-msvc` dans une caisse isolée, `aws-lc-sys` empêchant
  le cross-check du workspace entier. La séquence au-dessus du matériel, elle,
  est éprouvée par `tools/astra-signer/tests/enrolment.rs`.
L’identité cliente est scellée par DPAPI au compte Windows ; `helios-ctl
enroll` fait l’enrôlement d’un trait (clés, certificats, admission, profil et
identité en un document) en lisant le matériel public de la gateway par
`GET /api/key-negotiation`.
**Limite connue** : DPAPI ne se compile ni ne s’exerce en WSL2 — hors Windows le
scellement échoue explicitement plutôt que d’écrire ces clés en clair.

Une invitation (`enroll --public-key`) ne porte pas de clé privée : l’import la
reprend du profil local qui détient la **clé admise**, quel que soit son nom —
la correspondance se fait sur la clé, jamais sur le nom. À défaut, le brouillon
s’affiche quand même et le message nomme la clé attendue, celle qu’imprime
`helios-ctl profile check`.

Les profils portent l’extension **`.orion`** (`.orionprofile` jusqu’en août
2026 : encore lue à l’import, plus écrite ni enregistrée auprès de Windows), et
une icône de document qui leur est propre — posée par un fragment WiX, le
gabarit de Tauri n’écrivant qu’un ProgID sans icône. Sous Windows, la zone de
notification est une surface à part entière : état du tunnel, liste de profils
que l’on coche pour connecter, import, journal et « À propos ». Elle vit dans
`apps/orion/src-tauri/src/tray.rs`, dont seul le câblage est propre à Windows ;
le modèle et les libellés se compilent et se testent partout.

La gateway se livre en binaires (ADR-004, lot 2) : `cargo xtask bundle` assemble,
`helios-publisher bundle` signe hors ligne, `cargo xtask pack` archive, et
`helios-installer bootstrap` vérifie tout avant d’écrire. `setup-target.sh` ne
compile plus rien. L’installateur Orion se bâtit par `cargo xtask orion-msi`,
sur Windows uniquement — WiX n’a pas d’équivalent croisé.

La mise à jour de l’OS de la gateway ne perd plus l’identité scellée
([ADR-007](docs/adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md)) : `heliosd tpm
prepare-update --reboot` porte le **même** secret à travers un redémarrage
planifié, dans un slot NV lisible sous PCR 0/7 par le seul `TPM2_NV_Read`, puis
écrasé après rescellement durable. Les coffres survivent donc, et aucun client n’est
ré-enrôlé. Le billet de rescellement reste le chemin du changement de PCR
**subi**. Trois limites explicites : pendant qu’une fenêtre est ouverte, un
attaquant ayant l’accès physique qui démarre un autre OS signé descelle le
secret (`TPM2_PolicyCounterTimer` n’est pas exposé par `tss-esapi` 7.7) ; une
mise à jour de firmware ou de base Secure Boot déplace PCR 0/7 et sort du
périmètre ; et l’identité de négociation reste **sans séquestre**, donc un
changement de PCR subi impose encore une rotation et le ré-enrôlement du parc.

Le câblage PSK est validé en dry-run seulement. Aucun essai noyau n’a encore eu
lieu, et la fenêtre de mise à jour n’a jamais été exercée sur un TPM réel — voir
[docs/testing/TESTING.md](docs/testing/TESTING.md).

## Invariants de sécurité

- Gateway : seul `TunnelState::Up` autorise le trafic. Engager le kill-switch
  avant tout réseau et le laisser engagé à l’arrêt.
- Hors `--dev`, un backend noyau absent est une erreur de démarrage ; aucun
  repli implicite vers un backend simulé.
- Netlink : traduire tout le ruleset puis envoyer une transaction atomique ; ne
  jamais appliquer règle par règle. Le NAT entre dans la **même** transaction
  que le filtrage : un masquerade qui survivrait au kill-switch laisserait
  sortir en clair ce qu’il vient de couper.
- Orion : lire le doc-comment de `orion-core/src/backend/mod.rs` avant toute
  modification. L’adaptateur reste monté sur échec et `down()` n’est appelé que
  sur déconnexion explicite.
- Un Orion compilé avec `wireguard` refuse de démarrer si le backend réel est
  indisponible ; aucun repli implicite vers le dry-run. Réciproquement, un
  Orion **pour Windows** bâti sans cette feature ne compile pas : le repli
  vers le backend simulé y produirait un client qui n’ouvre aucun tunnel tout
  en affichant un profil et un mode négocié.
- La session QUIC de négociation **est fermée après le commit** : elle porte
  une transaction, puis disparaît. Sa fermeture ne dit **rien** du tunnel et ne
  retire aucun PSK. C’est l’inverse de la v4, où elle était un lien de
  vivacité — et où toute coupure réseau de plus de 35 s tuait un tunnel sain.
  Ne réintroduire ni keep-alive QUIC, ni délai d’inactivité qui servirait à
  déduire qu’un pair est encore là. Le seul délai restant
  (`TRANSACTION_IDLE_TIMEOUT`, 60 s) borne la transaction et couvre l’attente
  de confirmation, rien d’autre.
- La vivacité se lit sur le **plan de données**, jamais sur un canal de
  contrôle. Trois seuils, trois questions distinctes :
  `HANDSHAKE_STALE_AFTER_SECS` (150 s) décide de l’état du tunnel et donc du
  kill-switch ; `PSK_RECLAIM_AFTER_STALE_SECS` (300 s) décide que la gateway
  détruit le secret d’un pair disparu ; `MAX_PSK_LIFETIME` (24 h) borne l’âge
  d’un PSK même sur un tunnel sain. Les deux premiers encadrent les 180 s au
  bout desquelles WireGuard abandonne lui-même une session : à 300 s la
  gateway ne détruit jamais quelque chose qui marchait encore.
- Tout cela suppose un keep-alive persistant, et la gateway le **pose
  elle-même** (`WgPeer::persistent_keepalive_secs`, 25 s) plutôt que de faire
  confiance à celui du client, qu’elle ne peut pas inspecter. L’admission
  refuse un `0` explicite et le chargement de `network.toml` échoue en nommant
  le pair : sans keep-alive, un tunnel inactif ne produit aucun handshake et
  les deux seuils ci-dessus liraient un horodatage ancien sur un pair
  parfaitement sain.
- L’empreinte TLS est résolue vers **son** unique pair admis dès la fin du
  mTLS, avant qu’un challenge soit émis. La clé WireGuard d’une requête est
  ensuite comparée à ce pair ; elle n’est jamais la clé de recherche dans la
  table. Chercher par le champ du client puis comparer l’empreinte refuse les
  mêmes messages, mais fait d’une valeur choisie par le client l’index de la
  table — une comparaison manquante en aval laisserait alors une identité
  admise viser un autre pair. Le budget par identité ne se débite qu’après
  cette résolution.
- Un PSK négocié n’est retiré que par un `release` signé, un remplacement
  atomique, une révocation d’admission, le vieillissement du handshake ou
  l’échéance. Jamais par un silence réseau sur un canal de contrôle.
- Le `release` vit **dans le tunnel WireGuard**, sur `POST
  /api/key-negotiation/release`, et nulle part ailleurs : le port QUIC public
  ne porte plus que challenge, requête, confirmation et commit, et le tag
  hérité `release` n’y décode plus. Négocier doit précéder WireGuard, se
  déconnecter le suit — rouvrir le port public pour annoncer un arrêt
  réauthentifiait par mTLS, challenge et ML-DSA une machine qui tenait déjà un
  canal chiffré et authentifié vers la gateway. `require_peer` résout la VIP
  source vers l’unique pair admis ; la clé du corps n’est que **comparée** à
  celle-là, jamais la clé de recherche. Pas de challenge, pas d’horodatage,
  pas de repli QUIC : l’identifiant de transaction suffit à rendre une
  commande ancienne inoffensive, et WireGuard refuse déjà les paquets rejoués.
  L’opération est best-effort, bornée à deux secondes côté Orion, et son échec
  ne retarde pas la déconnexion — la récupération à 300 s est le filet.
- Un `release` ne retire qu’un état `committed` dont il nomme exactement le
  propriétaire. Pendant `preparing` c’est un **no-op** : le candidat appartient
  à la connexion qui le prépare, et sa garde de rollback est la seule sortie,
  y compris quand la tâche est détruite. Lui laisser annuler un candidat
  donnait deux écrivains sans ordre à un même slot.
- Le commit signé est le **point de non-retour**. `take_for_rollback` ne
  cherche que dans les transactions `active` : après la signature il ne trouve
  rien, et c’est structurel. La v4 restaurait le slot quand le commit
  n’arrivait pas à destination, ce qui laissait un client détenir un commit
  valide et vérifiable face à une gateway ayant tout défait.
- Le commit exige une **preuve de handshake WireGuard** lue sur le plan de
  données : une observation strictement postérieure à celle mémorisée juste
  avant la pose du candidat. C’est la seule preuve de l’échange qui engage la
  clé privée **WireGuard** du pair — TLS et ML-DSA-87 en attestent deux autres.
  Sans elle, une identité de négociation volée fait committer la gateway sur un
  PSK arbitraire et coupe le vrai client. La lecture passe par
  `ObserveHandshakeRequest`, pas par l’instantané `peer_runtime` : celui-ci
  retarde de 10 s et refuserait des confirmations légitimes.
- Chaque slot porte une **génération par pair**, et tout acteur tardif doit
  présenter celle qu’il a observée — rollback, `release` retardé, récupération
  décidée sur un instantané. Une génération périmée est un no-op, jamais une
  écriture. Sans cela, chacun des trois efface le PSK d’une transaction plus
  récente et coupe un tunnel qui marchait.
- La génération se **réserve**, elle ne s’observe pas. `prepare` l’incrémente
  et pose l’état `preparing` sous le **même** verrou qui réserve le pair, avant
  de lire le plan de données et avant d’installer le candidat. La lire sans la
  prendre laissait le slot décrire le PSK *déplacé* pendant que le fil portait
  déjà le nouveau : un `release` visant l’ancienne transaction correspondait
  encore, et la récupération aussi. La confirmation revérifie l’appartenance du
  slot — même génération, `preparing` à son nom — **avant** de persister le
  plancher et de signer, sinon la gateway signe un commit pour un PSK qu’elle
  ne détient plus.
- La vérification de propriété, la pose backend du candidat et l’insertion de
  la transaction active forment une **seule section sérialisée**. De même, un
  `release` classe et applique son action sous ce sérialiseur : si le commit a
  gagné il retire le PSK committé ; s’il arrive avant, le slot n’est pas encore
  `committed` et rien n’est touché. Découpler l’observation de l’écriture
  permet à une préparation annulée de poser son candidat en retard, ou à un
  `release` d’accuser un retrait sans effet.
- Un rollback doit survivre à la **destruction de la tâche**. Détruire une
  future n’exécute aucun chemin de sortie : l’échéance absolue de 90 s le
  faisait, et laissait candidat posé, pair réservé et transaction active — un
  pair admis s’enfermait dehors avec une seule connexion inachevée. Chaque
  phase est bornée par ce qui reste de l’échéance, et une garde de destruction
  couvre le reste. Le défaire s’appuie sur l’identifiant que le slot porte
  lui-même, jamais sur l’enregistrement de transaction : un `prepare`
  interrompu peut ne pas encore en avoir écrit. La garde ne se désarme donc
  qu’après le **retour** du rollback : le désarmer avant l’`await` rouvre le
  trou qu’elle bouche, et
  tout ce qui se déduisait de la présence de l’enregistrement — le repos
  compris — doit se lire sur le slot.
- Un rollback survenu **après** la pose d’un candidat met le pair au repos dix
  secondes. Une identité de négociation volée sans la clé WireGuard du pair ne
  peut jamais committer — la preuve de handshake l’arrête — mais rien ne
  l’empêchait de faire osciller un slot qui marchait, aussi vite que le
  round-trip le permet.
- Ordre d’un retrait : **vider le plan de données d’abord**, n’oublier l’état
  qu’après succès, le verrou tenu à travers l’écriture. L’inverse laisse un PSK
  orphelin quand l’écriture échoue — plus rien ne le désigne, un `release`
  rejoué devient un no-op sans rien retirer, et la récupération ignore que le
  slot existe.
- Un PSK **statique** n’entre pas dans le cycle transactionnel. Il n’a pas de
  propriétaire, n’expire pas, n’est pas retiré par `release` ni par la
  récupération : c’est la configuration de l’opérateur, présente avant la
  transaction et après elle. Le commit le laisse en `configured_static`, et
  Orion n’enregistre pas de reçu pour lui. L’effacer serait détruire une valeur
  qu’aucune renégociation ne restaure.
- `classic` n’est **pas** un mode négociable v5 : refusé par `validate()`
  (`ClassicNotNegotiable`) et à la préparation. Le décodeur serde l’accepte
  encore, puisque la variante doit survivre pour relire un `network.toml` ;
  c’est la validation qui refuse, et il faut le dire ainsi. Un tunnel sans PSK est un profil
  WireGuard générique, pas un résultat de négociation — sinon le plancher du
  protocole se satisfait de l’absence de protection. La variante survit dans le
  type pour qu’un `network.toml` existant se relise encore ; voir la limite
  ci-dessus.
- Anti-rejeu : un `server_challenge` de 32 octets par connexion, à usage
  unique, et **une seule** demande de challenge par connexion. Il vit dans la
  pile de la tâche de connexion — `Option::take` **est** la consommation
  atomique — et n’est délibérément **pas signé** par la gateway : le signer
  offrirait une opération ML-DSA-87 gratuite à un client non authentifié. Le
  cache de 4096 identifiants subsiste en défense en profondeur ; ne plus le
  présenter comme la défense anti-rejeu.
- Bornes DoS du port public, toutes nécessaires ensemble : Retry avant tout
  état, budget par IPv4 ou par **préfixe IPv6 `/64`** (compter par adresse
  exacte rend la limite décorative sur IPv6), budget par identité admise une
  fois mTLS passé, durée de vie absolue de 90 s par connexion (l’idle timeout
  ne borne pas une connexion occupée, et le permis de concurrence ne revient
  jamais), reprise TLS et 0-RTT désactivés des deux côtés, zéro flux
  unidirectionnel et fenêtres de réception bornées. Les limites de flux et de
  fenêtre s’annoncent des **deux** côtés : une borne que seule la gateway
  déclare ne borne que la gateway. L’échéance absolue borne chaque phase, elle
  n’enveloppe pas la connexion : détruire la tâche à l’échéance n’exécute
  aucun rollback.
- Deux longueurs ML-DSA, deux modules : `aether::key_negotiation::ML_DSA_87_*`
  pour la PKI de négociation, `aether::sig::ML_DSA_65_*` pour les artefacts
  éditeur. Valider du matériel de négociation avec la constante de `sig`
  compile, se lit bien, et refuse toute vraie clé ML-DSA-87.
- Sur le port QUIC public, trois codes d’erreur seulement : `protocol`,
  `rejected`, `internal`.
  Tout refus avant installation du slot est `rejected`, quelle qu’en soit la
  cause. Les sept codes de la v4 laissaient énumérer les pairs admis et lire
  leur plancher depuis un port public. Le motif réel va au journal protégé.
- Deux jeux de paramètres ML-DSA coexistent et **ne se remplacent pas** :
  `ml-dsa-65` porte les signatures d’artefacts éditeur (ADR-002,
  `aether::sig`, `REQUIRED_ALGS`), `ml-dsa-87` porte la PKI de négociation
  (ADR-005 v5). Remplacer le premier par le second invaliderait la
  vérification de toutes les releases déjà signées.
- Négociation de clé : datagrammes QUIC **épinglés à 1200 octets**, découverte
  de MTU désactivée des deux côtés. Le matériel PQ pèse plusieurs kilooctets et
  quinn sonde jusqu’à 1452 par défaut — une taille qui passe en labo puis
  échoue chez le client dès que l’interface WireGuard capte la route avec un
  MTU plus petit (`WSAEMSGSIZE`). 1200 est le plancher que RFC 9000 §14 impose
  à tout chemin QUIC.
- Un PSK négocié n’est pas un PSK statique, bien qu’ils occupent le même slot.
  Le profil éphémère passé au backend porte `preshared_key_is_negotiated` ;
  sans lui, `validate()` refuse le tunnel que la négociation vient de préparer.
  Toute copie qui installe un PSK à l’exécution doit poser ce drapeau.
- La négociation de clé n’est **pas** une feature de compilation, ni côté
  Orion ni côté `heliosd` : tout binaire la porte. Un client d’apparence
  normale qui importe un profil épinglé puis échoue avant WireGuard est
  indiscernable, côté utilisateur, d’une gateway en panne ; et une gateway qui
  accepte `key_negotiation_port` sans le servir l’est tout autant. Seul
  `key_negotiation_port` décide de l’ouverture du service — absent, il reste
  fermé, sans erreur. Côté Orion, seul le stockage protégé d’identité reste
  conditionnel : il est propre à la machine, pas à la compilation.
- **Plage CGNAT partagée** : Helios n'est pas seul à tirer ses adresses de
  `100.64.0.0/10`. NordLynx, Tailscale et la plupart des clients VPN grand
  public y puisent aussi, et surtout ils posent des **règles de routage** qui
  consultent leur table avant la principale — NordVPN en 32765 vers une table
  contenant `100.64.0.0/10 dev nordlynx`. À partir de là, tout paquet que la
  gateway envoie à **ses propres** clients part dans l'autre tunnel : rien
  n'est jeté, rien n'est journalisé, `ip route get` répond simplement une
  autre interface. `heliosd::vip_routing` pose donc une table à lui, une
  **route `/32` par pair admis** et une seule règle en 32000. Jamais la plage
  entière : elle contient aussi les pairs de l'autre VPN, et la reprendre en
  bloc réparerait Helios en cassant son voisin. Une destination absente de la
  table retombe sur la règle suivante, exactement comme avant. La pose est
  **inconditionnelle** : l'autre VPN peut se connecter longtemps après
  `heliosd` et réinstalle ses règles à chaque fois, donc un test au démarrage
  passerait sur une machine qui casse dix minutes plus tard. Un échec de pose
  n'est pas fatal — sur une gateway qui a la plage pour elle seule, cela ne
  change rien — mais il est journalisé en nommant la conséquence.
- **Uplink multiple** : `wan_iface` est un **ensemble**, pas un choix — une
  chaîne ou une liste (`"auto"`, `"eth0"`, `["enp3s0", "wlo1"]`), la clé TOML
  restant `wan_iface`. Chaque règle qui nomme le WAN est émise **une fois par
  interface**, et le masquerade aussi : une gateway avec câble et radio survit
  au débranchement sans redémarrage ni rechargement, parce que les règles de
  l'autre lien sont déjà posées. Le pare-feu ne doit jamais être ce qui casse
  une bascule. La préférence, elle, n'est pas ici : c'est le routage qui décide
  par où un paquet sort, et elle s'exprime en **métrique de route**. `auto`
  énumère toute interface physique ayant une porteuse — mieux routée en tête,
  filaire départageant à égalité — et l'ordre ne sert qu'aux mesures qui
  regardent un seul lien (sonde MTU, télémétrie). Un lien sans route est
  **permis quand même** : le refuser ferait jeter l'échange DHCP qui lui
  donnerait justement sa route. Le type ARPHRD ne distingue pas le Wi-Fi (il
  vaut 1 comme Ethernet) : c'est `phy80211`, et `wireless/` pour les pilotes
  antérieurs ; l'absence de lien `device` écarte les interfaces virtuelles,
  sans quoi `docker0` serait candidat. L'ensemble est établi **une fois** — un
  nom d'interface ne change pas sous un plan de données en marche — et
  `adopt_runtime_secrets_from` reporte la liste résolue à chaque relecture :
  laisser passer le marqueur reconstruirait le ruleset autour d'une interface
  nommée `auto`. `heliosd show-uplink` montre les candidats, l'ordre et les
  désaccords.
- `network.toml` est relu à chaud : le démon le surveille et réapplique la
  table de pairs sans redémarrer (`orchestrator::spawn_network_config_watcher`).
  Toute relecture doit passer par `NetworkConfig::adopt_runtime_secrets_from` —
  le fichier ne contient ni la clé privée scellée ni les PSK négociés, et les
  appliquer tels quels retirerait son identité à la gateway et casserait tous
  les handshakes. **Limite connue** : ce qui ne peut pas changer sous le plan
  de données en marche — nom d’interface, port d’écoute, adresse d’API — exige
  toujours un redémarrage.
- L’identité de négociation, elle, n’est **pas** relue : elle est lue une fois
  au démarrage et servie jusqu’à l’arrêt. `init-key-negotiation --rotate` sous
  un démon en marche change donc les fichiers sans changer ce qui est présenté,
  et les profils émis après la rotation épinglent un certificat que la gateway
  ne sert pas encore : le client refuse le handshake QUIC sur `invalid peer
  certificate: BadSignature`, qui nomme une signature et pas l’écart derrière
  elle. Une rotation s’applique par `systemctl restart heliosd`. Le démarrage
  journalise l’empreinte servie et la date d’écriture du fichier : un
  certificat plus récent que le démon est le diagnostic complet.
- Dans le code actuel, la CA opérateur vit dans
  `~/.helios/certs/internal-ca`, et à **un seul** endroit : la gateway n'en
  épingle qu'une. Un script qui la cherche ailleurs ne la trouve pas, en
  fabrique une neuve, fait tourner l'identité de la gateway pour l'y installer
  — et coupe tous les clients déjà admis. La cible ADR-008 migre ce registre
  vers Astra : coffre maître chiffré co-implanté mais déverrouillé et signé
  côté opérateur par YubiKey, plus émetteur Astra délégué et borné sur la
  gateway. Tant que cette migration atomique n'est pas livrée, aucun chemin ne
  mélange les deux emplacements et aucune seconde CA n'est créée.
- L’API vit derrière `admin_iface` (`helios0`). Elle ne monte jamais le tunnel
  initial. Toutes les mutations exigent du JSON, aucun CORS permissif, et les
  lectures ne doivent jamais sérialiser clé privée ou PSK.
- PSK post-quantique : toujours posé sur le plan de données **avant** d’être
  annoncé au client, et jamais persisté sur disque. Un slot PSK renseigné d’un
  seul côté fait échouer tous les handshakes, sans canal de rattrapage.
- Billets TPM : Ed25519 **et** ML-DSA-65 obligatoires, `key_epoch` signé,
  trousseau compilé, v1 refusé. Compteur strictement croissant ; PCR facultatif.
- Fenêtre de mise à jour (ADR-007) : elle **transporte** un verdict d'intégrité
  à travers un redémarrage planifié, elle n'en fabrique pas. L'armement exige un
  descellement nominal du démarrage courant — jamais depuis `Bypassed`,
  `Resealed` ou `Provisioned`. Au démarrage, le descellement nominal PCR 0/4/7
  passe **toujours en premier**, et son succès révoque une fenêtre restée armée.
  Le marqueur non secret est synchronisé avant l'écriture NV ; une erreur
  d'armement déclenche un écrasement compensatoire et le marqueur reste présent
  tant que cet écrasement n'est pas confirmé.
  À la consommation, le payload NV n'est écrasé qu'**après** que le blob
  rescellé est sur disque et synchronisé : révoquer plus tôt laisserait un état
  sans issue. Une erreur après ce point ne retombe jamais sur le billet. Le
  scellement nominal, lui, n'est pas modifiable par ce chemin.
- Identité de la gateway : elle naît **sur** la gateway (`heliosd
  init-identity`), scellée au TPM. `wg_private_key` en clair dans
  `network.toml` est un repli hérité, pas un chemin d’installation.
- Admission : jamais de *read-modify-write* de `network.toml` depuis la vue
  expurgée de l’API — les PSK des autres pairs y seraient effacés. Passer par
  `helios_provisioning::admission`, et persister sans clé privée ni PSK.
- Clé privée de séquestre : sur le poste opérateur, jamais sur la gateway
  qu’elle secourt.
- Une release exige `HELIOS_PUBLISHER_KEYRING_PATH`. Les secrets éditeur ne
  doivent jamais entrer dans une gateway ni dans le dépôt.

## Interdiction des TODO

Aucun marqueur `TODO`, `FIXME`, `XXX`, `HACK`, `TBD`, `todo!()` ni
`unimplemented!()` ne doit être introduit dans ce dépôt. Un marqueur est une
dette invisible : il ne compile aucun test, ne bloque aucune release et sort du
champ de vision dès la revue suivante.

Face à une fonctionnalité incomplète, trois issues seulement :

1. **La développer** — c’est le défaut. Si la tâche est faisable, la faire
   plutôt que de la baliser.
2. **La refuser explicitement dans le type** — variante d’erreur nommée et
   documentée (modèle : `helio_tpm::TpmError::NotImplemented`), testée, qui
   échoue franchement à l’exécution. Jamais un chemin silencieux ou dégradé.
3. **La documenter comme limite connue** — section « Limite connue » dans le
   doc-comment du module, plus une ligne dans l’ADR concerné si elle engage
   l’architecture. Le texte doit dire *pourquoi* c’est hors périmètre et *ce
   qui débloquerait*, pas seulement que ça manque.

Un blocage qui attend un arbitrage humain (ADR-002 amendement 2) relève du
point 3, pas d’un `TODO`. Une limite matérielle non vérifiable en WSL2 relève
du point 3 et de [docs/testing/TESTING.md](docs/testing/TESTING.md).

Si une limite documentée est visible par l’utilisateur, l’IHM doit la dire —
c’est déjà la pratique dans `web/src/views/Firewall.tsx` et
`apps/orion/src/views/ProfilesView.tsx`.

## Workspace

- `aether` : états, config, politique, ML-KEM, protocole et signatures hybrides.
  `aether::certificates` y ajoute le cycle de vie des certificats : objets
  signés, encodage canonique, générations et états bornés à deux slots.
  `aether::ml_dsa` est le **seul** point d'entrée ML-DSA-87 de la négociation
  v5 et du cycle de vie — pur, `ctx` non vide par type, HashML-DSA refusé —,
  et `aether::random` la **seule** porte vers l'aléa : une interface vers
  `aws_lc_rs::rand::SystemRandom`, jamais un DRBG écrit ici. Aucun autre module
  du dépôt n'appelle `SystemRandom`, `aws_lc_rs::rand::fill` ni `getrandom`.
- `astra` : coordinateur d'autorité (ADR-008), binaire co-implanté dans un
  conteneur séparé. Registre du domaine, journal d'audit chaîné dont la tête
  distingue une restauration d'un fork, émetteur délégué borné et endpoint
  public. Il ne détient **jamais** `CA-PQ` en clair. `astra::vault` y ajoute le
  format du coffre d'autorité — key-slots FIDO2, corps scellé lié à la table de
  slots. Astra le transporte et le sauvegarde ; il ne l'ouvre pas, et rien dans
  le conteneur ne le peut.
- `astra-signer` : compagnon du **poste opérateur** (ADR-008 §4), le seul
  programme du dépôt qui détienne `CA-PQ` en clair, et seulement le temps d'une
  opération. Il parle à CTAP2 directement — jamais un navigateur, jamais Orion,
  jamais la console. Trois modules : `authenticator` (la seule frontière avec
  le matériel), `gestures` (les séquences, éprouvées hors terminal), `store`
  (le fichier).
- `helios-firewall` : ruleset structuré, dry-run, backend Netlink.
- `helios-wireguard` : interface gateway et table de pairs.
- `helios-provisioning` : IPAM CGNAT et rotation/protocole ML-KEM.
- `helios-api` : Axum REST/WS, provisioning et IHM embarquée.
- `web` : console d’administration de la gateway, embarquée dans `heliosd` par
  la feature `embed-ui`. React et **MUI seul** — pas de Tailwind, pas de moteur
  3D : ce bundle part dans le binaire, et les polices y sont **auto-hébergées**
  (`@fontsource-variable`, 62 Ko) parce qu’une gateway ne joint aucun CDN.
  Quatre destinations : Aperçu, Clients, Sécurité, Système
  (`web/src/navigation.ts`) — la console montre un **état et des actions**, les
  explications d’architecture restent en infobulle et dans les ADR.
  `web/src/theme.ts` tient les pigments et `web/src/state.ts` le **sens** des
  états du tunnel ; les deux ne se mélangent pas, et trois familles de couleur
  ne s’empruntent rien : action (indigo), post-quantique (violet), état.
  `web/src/theme.test.ts` vérifie qu’aucun token ne manque dans l’un des deux
  schémas — l’oubli est invisible autrement, il rend transparent.
  Attention aux unités `sx` : `borderRadius: 3` vaut 3 × 12 px et `width: 1`
  vaut **100 %**, pas 1 px.
- `helio-tpm` : scellement PCR, séquestre et billets de rescellement.
- `helios-update` : mises à jour applicatives signées (ADR-003).
- `heliosd` : orchestration gateway.
- `orion-core` / `apps/orion` : cœur client et shell Tauri React.
- `xtask` : fabrique de bundles d’installation (poste de build, jamais la
  gateway) — `cargo xtask bundle`, `cargo xtask pack`, et
  `cargo xtask orion-msi` pour l’installateur Windows (même commande que la CI
  de release : les features y sont tenues en un seul endroit).
- `helios-ctl` : outil du **poste opérateur** — diagnostic, campagnes de bout en
  bout (`campaign`, agit en vrai client via `orion-core`), admission (`peer`),
  profils clients (`profile`) et séquestre (`escrow`). Il est aussi livré **sur
  la gateway**, où `helios-ctl update` fait la mise à jour de l’OS en une
  commande : listes, classement des paquets par PCR touché, `apt upgrade`,
  armement de la fenêtre et redémarrage — qui la tue. Le résultat se lit au
  journal du démarrage suivant, pas en retour de commande ;
  `helios-publisher` : outil du **poste éditeur**, hors gateway.

## Développement et validation

```sh
bash scripts/regression.sh
bash scripts/campaign.sh          # campagnes PQ, mise à jour signée et bundle
bash scripts/lab.sh --keep        # banc complet : gateway + client admis + profil
./scripts/deploy.sh               # construit, signe, copie et installe sur la gateway
./scripts/provision-client.sh nom # CA, négociation, admission et profil client
cargo test --workspace --all-features
cargo run -p heliosd -- run --dev
npm run dev --prefix web
```

`scripts/regression.sh` est la référence : fmt, Clippy/tests toutes features,
audits Cargo/npm, Vitest et builds frontend.

**Langue.** Tout ce qui est du code est en **anglais** : noms de fonctions, de
types, de champs et de variables (`render`, `assign_vip`, `verify_manifest`),
mais aussi les commentaires, les doc-comments, les messages de journal et les
noms de tests. Seule la documentation sous `docs/` (ADR, guides, `TESTING.md`)
reste en **français**.

`scripts/provision-client.sh` enchaîne les sept gestes d'une admission — créer
la CA opérateur, en pousser la moitié publique, initialiser la négociation de
la gateway, admettre le pair, rapatrier ses deux certificats, enrôler hors API,
écrire le `.orion`. Quatre copies de fichiers dans les deux sens, dont
chacune est un endroit où coller la mauvaise valeur ; et la panne ne se voit
qu'à la fin, en négociation refusée sans motif. La CA n'est jamais remplacée
sans `--refaire-ca` : la gateway l'épingle, en changer coupe tous les clients
déjà admis.

`scripts/deploy.sh` porte aussi Astra, en étape 7. Le conteneur n'entre **pas**
dans le bundle signé de l'ADR-004 — il est séparé, sans capacité, rootfs en
lecture seule, UID propre, un seul volume — mais le déployer par un second
script obligeait à recopier six valeurs entre trois commandes, ce qui est
exactement là où un déploiement casse. L'étape ne se déclenche que si un relais
de domaine existe ; sinon elle est sautée en une ligne, et une gateway sans
autorité reste une gateway qui marche. `--sans-astra` la saute explicitement.

`scripts/deploy.sh` enchaîne ce que l'ADR-004 sépare en trois outils — construire,
signer hors ligne, archiver — puis copie et installe. La séparation garde son
sens pour une release publique ; pour un opérateur qui détient les trois rôles,
la retaper à chaque fois n'apporte rien. La séquence de release est un
horodatage : l'anti-rollback exige une valeur strictement croissante, et un
compteur local se désynchronise dès qu'on déploie depuis une autre machine.

`scripts/lab.sh` monte un banc jetable avec les **mêmes outils qu'en
production** — `helios-ctl peer add`, `helios-ctl profile emit` — et non un
chemin de test parallèle : il éprouve donc l'outillage d'exploitation en même
temps qu'il sert au développement. Il produit un profil directement importable
dans Orion. Il ne fait pas partie de la régression : celle-ci vérifie des
invariants, elle ne lance pas d'environnements.

WSL2 compile les features `netlink`, `wireguard` et `tpm` si leurs dépendances
sont installées, mais ne prouve pas leurs effets réels. Les essais noyau, TPM,
WireGuard-NT et l'installation d'une release sont target-only ; suivre
[docs/testing/TESTING.md](docs/testing/TESTING.md).

Features matérielles :

```sh
cargo build -p heliosd --features netlink,wireguard,tpm,embed-ui
cargo build -p orion --features wireguard
```

Une release gateway se construit seulement après le frontend et avec le
trousseau public éditeur :

```sh
npm run build --prefix web
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
```

Ne pas « compléter » le lot récupération de l’ADR-002 tant que l’amendement 2
n’a pas été arbitré. Ne jamais présenter une compilation WSL2 comme une
validation matérielle.
