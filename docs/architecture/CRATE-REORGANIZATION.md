# Audit et proposition de réorganisation des crates

> Document d’audit préalable. Cette livraison ne migre aucun code, ne modifie
> aucun manifest et ne change aucun contrat. Les décisions proposées doivent
> être relues et validées avant toute phase d’implémentation.

## Périmètre et méthode

L’audit a porté sur les 21 packages du workspace Cargo racine : 14 crates sous
`crates/`, 6 outils sous `tools/` et l’application Tauri
`apps/orion/src-tauri`. Le workspace de fuzzing `fuzz/` est imbriqué et reste
hors du workspace racine.

Sources examinées :

- `Cargo.toml` racine et tous les `Cargo.toml` des crates, outils et apps ;
- `cargo metadata --format-version 1`, avec distinction entre dépendances
  normales, `dev` et `build` ;
- tous les `src/lib.rs` et `src/main.rs`, les modules principaux, les traits,
  types publics et réexports ;
- les tests unitaires, d’intégration, frontend et fuzzing ;
- les ADR, spécifications et documents de test pertinents ;
- les workflows CI et les scripts de build/livraison.

Les fan-in/fan-out sont les degrés directs du graphe des dépendances internes
normales. Les arêtes de test et de build sont données séparément. Les lignes
de code indiquées sont des ordres de grandeur issus de `wc -l`, utiles pour
repérer les concentrations, pas une mesure de complexité.

## 1. Architecture actuelle

Le découpage fonctionnel est déjà visible, mais il n’est pas toujours reflété
par les frontières Cargo. La cible de nommage et d’ownership Helios–Orion doit
se lire ainsi :

```text
orion (Tauri) -> orion-core
orion-core -> aether
           -> aether-fido
           -> aether-key-negotiation
           -> aether-vault

heliosd -> aether
        -> aether-key-negotiation
        -> aether-vault
        -> helios-api
        -> helios-escrow
        -> helios-firewall
        -> helios-provisioning
        -> helios-tpm
        -> helios-update
        -> helios-wireguard
```

`heliosd` assemble effectivement les composants, mais ses propres modules
contiennent encore une grande partie du comportement gateway : orchestrateur,
négociation, certificats, rotation, PSK statiques, uplinks, routage VIP,
clé gateway et canal Astra. Le binaire est donc un composition root incomplet,
pas un simple câblage.

Le graphe Cargo exact observé est donné en section 2. Il montre encore les
anciens packages `helios-fido`, `helios-key-negotiation` et `helios-vault` dans
les dépendances d’Orion ; ces noms et cette ownership sont précisément à
corriger, pas à conserver dans la cible.

- le graphe de production ne contient pas `heliosd -> orion-core` ;
- le test d’interopérabilité de `heliosd` dépend toutefois de `orion-core` en
  `dev-dependencies`, ce qui rend la frontière conceptuellement ambiguë.

### Règle de nommage et d’ownership Helios–Orion

L’état actuel expose directement à `orion-core` trois packages nommés
`helios-*` : `helios-fido`, `helios-key-negotiation` et `helios-vault`. Même si
leurs API sont réutilisables, leur nom suggère une propriété gateway et rend la
frontière serveur/client difficile à comprendre.

La cible doit donc interdire à Orion toute dépendance directe vers un package
`helios-*`. Une capacité utilisée par Helios et Orion doit être soit :

- un contrat réellement partagé dans `aether` ;
- une crate partagée au nom neutre ou `aether-*`, dont l’ownership est explicite
  (`aether-key-negotiation`, `aether-vault`, et éventuellement `aether-fido`) ;
- une abstraction partagée, avec son backend Linux/Windows conservé dans la
  couche qui en a besoin.

Cette règle ne signifie pas que toute implémentation doit être fusionnée dans
`aether`. Elle évite au contraire d’agrandir encore le socle en *god crate* :
les contrats/protocoles communs peuvent être dans Aether ou dans des crates
`aether-*`, tandis que les adaptateurs plateforme restent hors du modèle
partagé.

### Aether

`aether` représente environ 30 410 lignes Rust, dont environ 20 991 dans
`src/certificates/`. Il contient :

- les modèles de configuration gateway, états de tunnel, événements, policy
  firewall, types WireGuard, MTU et speedtest ;
- les contrats d’enrôlement et de négociation v5, ML-KEM, X25519 et secrets ;
- le RNG applicatif, ML-DSA, signatures de release et signatures PKI ;
- l’ensemble des contrats de certificats : encoding, X.509, autorité, gateway,
  client, révocation, statuts, capacités, transport, WebAuthn et fenêtres ;
- quelques capacités d’exécution : fichiers privés, verrouillage mémoire,
  sérialisation TOML/JSON et fixtures X.509.

Il mélange donc bien modèles, protocole, machine à états, politique, crypto,
RNG, certificats et sérialisation. Il contient aussi des utilitaires système
ciblés (`libc`/`windows-sys`) malgré sa promesse d’être sans ressource système
à l’exécution.

Cela en fait un *god crate* potentiel par son fan-in de 17, mais pas une raison
suffisante pour le découper immédiatement. Les modules de certificats sont
fortement couplés entre eux et portent des invariants de sécurité communs ;
les domaines ML-DSA-65 et ML-DSA-87 doivent rester séparés même s’ils partagent
le même socle. La décision est de conserver Aether, de limiter les nouveaux
ajouts et de clarifier ses modules/public APIs avant toute extraction.

### Heliosd et Orion

`orion-core` est une crate cliente portable d’environ 25 708 lignes. Elle
regroupe profils/configuration, coffre local, identité, provisioning,
négociation cliente, backend VPN, télémétrie, speedtest et cycle de vie des
certificats. Cette largeur est cohérente avec son cycle de vie et ses deux
consommateurs normaux (`orion` et `helios-ctl`) ; elle ne justifie pas encore
une division en micro-crates.

`apps/orion/src-tauri` est le shell : IPC Tauri, fenêtre/tray, lancement du
compagnon Astra, intégrations Windows et build. Il ne doit pas devenir une
dépendance de serveur.

La dépendance `heliosd -> orion-core` est donc suspecte uniquement parce
qu’elle existe dans les tests. Elle sert à prouver l’interopérabilité avec le
vrai client, notamment la dérivation de PSK. Il faut conserver cette preuve,
mais la déplacer vers un harnais d’intégration indépendant lorsque la seam
sera stabilisée, plutôt que d’extraire du code client vers Helios.

### Astra

`astra` est un sous-système cohérent avec registre, audit chaîné, autorité,
issuer délégué, opérations, renouvellement, récupération, distribution,
réconciliation, service HTTP et binaire Astra. Sa bibliothèque et son binaire
partagent le même cycle de vie du sous-système.

`astra-operator` est une frontière de sécurité distincte : coffre d’autorité,
gestes FIDO2, approbations, campagnes, récupération, transport public et
transport in-tunnel. Il dépend encore directement de `astra` pour
`IssuerDelegationRequest` et pour des vues d’opération que `astra` réexporte
déjà depuis Aether. C’est une dépendance de contrat mal placée, pas une raison
de fusionner les deux crates.

`astra-signer` et `helios-astra-helper` sont des processus distincts avec des
privilèges et des chemins de vie différents. Ils doivent rester des outils.

### Firewall, WireGuard et sécurité

`helios-firewall` est une bonne frontière : policy -> IR/ruleset -> validation
et rendu -> backend dry-run ou Netlink. Les modules `ruleset`, `dryrun` et
`netlink` doivent rester internes à la crate tant qu’aucun cycle de vie ou
consommateur indépendant ne l’exige.

`helios-wireguard` est également une bonne frontière : trait backend, config
d’interface/pairs, observation des handshakes, dry-run et backend réel. Son
unique arête vers `helios-provisioning` vient du trait `PeerTable` utilisé pour
l’IPAM ; c’est une inversion de couche à surveiller, pas un cycle.

Les frontières `helios-vault`, `helios-fido`, `helio-tpm` et
`helios-key-negotiation` sont justifiées respectivement par un format secret,
un périphérique matériel, le matériel TPM et un protocole de transport.

## 2. Graphe réel des dépendances internes

### Dépendances normales

```text
astra
  -> aether
  -> helios-api

astra-operator
  -> aether
  -> astra
  -> helios-fido
  -> helios-vault

astra-signer
  -> aether
  -> astra-operator
  -> helios-fido

helio-tpm
  -> aether
  -> helios-vault

helios-api
  -> aether
  -> helios-firewall
  -> helios-provisioning
  -> helios-update
  -> helios-wireguard

helios-astra-helper
  -> aether
  -> astra-operator
  -> helios-fido

helios-ctl
  -> aether
  -> helio-tpm
  -> helios-key-negotiation
  -> helios-update
  -> orion-core

helios-fido
  -> aether

helios-firewall
  -> aether

helios-installer
  -> helios-update

helios-key-negotiation
  -> aether

helios-provisioning
  -> aether

helios-publisher
  -> aether
  -> helios-update

helios-update
  -> aether

helios-vault
  -> aether

helios-wireguard
  -> helios-provisioning

heliosd
  -> aether
  -> helio-tpm
  -> helios-api
  -> helios-firewall
  -> helios-key-negotiation
  -> helios-provisioning
  -> helios-update
  -> helios-vault
  -> helios-wireguard

orion
  -> aether
  -> orion-core

orion-core
  -> aether
  -> helios-fido
  -> helios-key-negotiation
  -> helios-vault

xtask
  -> helios-update
```

### Arêtes non-runtime

```text
heliosd  -[dev]->   orion-core
orion    -[build]-> xtask
```

Les dépendances `dev` de `aether`, `helios-update` et `helio-tpm` activent des
fixtures/signatures pour leurs propres tests. Elles ne forment pas des arêtes
de production.

### Fan-in, fan-out et cycles

| Package | Fan-in normal | Fan-out normal |
| --- | ---: | ---: |
| `aether` | 17 | 0 |
| `astra` | 1 | 2 |
| `astra-operator` | 2 | 4 |
| `astra-signer` | 0 | 3 |
| `helio-tpm` | 2 | 2 |
| `helios-api` | 2 | 5 |
| `helios-astra-helper` | 0 | 3 |
| `helios-ctl` | 0 | 5 |
| `helios-fido` | 4 | 1 |
| `helios-firewall` | 2 | 1 |
| `helios-installer` | 0 | 1 |
| `helios-key-negotiation` | 3 | 1 |
| `helios-provisioning` | 3 | 1 |
| `helios-publisher` | 0 | 2 |
| `helios-update` | 6 | 1 |
| `helios-vault` | 4 | 1 |
| `helios-wireguard` | 2 | 1 |
| `heliosd` | 0 | 9 |
| `orion` | 0 | 2 |
| `orion-core` | 2 | 4 |
| `xtask` | 0 | 1 |

Le plus grand fan-in est celui d’Aether. Le plus grand fan-out est celui de
`heliosd`, ce qui est attendu pour un composition root mais révèle aussi la
logique encore locale. Le graphe normal est acyclique. Les arêtes de test et
de build ne créent pas de cycle Cargo, mais `heliosd -> orion-core` brouille la
lecture produit Helios/client Orion.

Packages à zéro consommateur normal : les outils/apps feuilles
(`astra-signer`, `helios-astra-helper`, `helios-ctl`, `helios-installer`,
`helios-publisher`, `heliosd`, `orion`, `xtask`). Package de sous-système à un
consommateur : `astra` n’est utilisé normalement que par `astra-operator` ;
cela renforce le besoin de découpler ses contrats sans imposer une fusion.

## 3. Problèmes détectés

### Frontières et responsabilités

1. `helios-api` est à la fois la façade HTTP/WS/UI de la gateway et le
   propriétaire effectif du protocole privé Astra–Helios (`internal.rs`, TLS,
   routes, clients et DTO). Cela force `astra -> helios-api`, une direction
   inverse à la composition attendue.
2. `astra-operator` dépend de l’implémentation `astra` pour des contrats qui
   sont soit déjà dans Aether, soit transportables dans la frontière du canal.
3. `helios-provisioning` contient un registre durable de certificats de plus de
   4 300 lignes (`certificates.rs`) en plus de l’admission, l’IPAM, les
   sessions ML-KEM et la rotation de PSK. Son nom ne décrit pas tout son
   propriétaire.
4. `helio-tpm::escrow` implémente un format et un protocole X25519/AEAD
   opérateur qui ne parlent pas au TPM. Il est consommé par `heliosd` et
   `helios-ctl` et mérite une frontière de sécurité propre.
5. `heliosd` porte 16 153 lignes de code et n’est pas encore principalement du
   câblage. Une crate `helios-runtime` n’est cependant pas démontrée : il n’y
   a pas de second hôte runtime réutilisant actuellement ce lifecycle.
6. La frontière de nommage Helios–Orion est inversée pour FIDO, négociation et
   vault : `orion-core` dépend directement de `helios-*`. Ces capacités doivent
   être reclassées comme Aether/shared ou recevoir un nom neutre avant leur
   prochaine évolution.

### Aether et réexports

Les réexports rendent l’usage agréable mais masquent parfois le vrai
propriétaire :

- `aether/src/lib.rs` réexporte config, erreurs, événements, policy, PQ,
  secrets, speedtest et états ; les certificats restent surtout sous leurs
  modules, avec quelques réexports dans `certificates/mod.rs` ;
- `astra::signing` réexporte `SigningOperationState` et
  `SigningOperationView` depuis Aether ; `helios-api::internal` réexporte aussi
  plusieurs vues et états de transport Aether ;
- `astra-operator::authority` réexporte `astra::issuer::IssuerDelegationRequest`;
  ce contrat ne devrait pas obliger l’opérateur à connaître l’implémentation
  Astra ;
- `orion-core::certificate_inventory` expose `ValidityPhase` sous le nom
  `CertificatePhase`, projection utile mais à documenter comme façade ;
- les vues `NetworkConfigView`, `NetworkPeerView`, `PeerSummary`,
  `KeyNegotiationMaterial` et les types `Relayed*` sont des DTO locaux ou des
  projections. Ils ne sont pas tous des doublons : la redaction des secrets et
  la séparation d’un message signé d’une vue HTTP sont intentionnelles.

Le risque est de supprimer un réexport avant d’avoir classifié le type comme
contrat partagé, DTO local ou projection de sécurité. Cette classification doit
précéder tout déplacement.

### Features Cargo

| Package | Features | Couplage observé |
| --- | --- | --- |
| `aether` | `publisher-signing`, `key-negotiation-signing`, `fuzzing` | fait entrer les capacités de signature et fixtures dans le socle partagé |
| `helio-tpm` | `tpm` | active `tss-esapi` et le backend matériel |
| `helios-api` | `embed-ui` | couple la façade API à l’asset web de production |
| `helios-firewall` | `netlink` | active `rustables`/`ipnetwork` pour le backend réel |
| `helios-provisioning` | `certificate-signing` | ne sert essentiellement qu’aux tests de signature de certificats |
| `helios-update` | `publisher-signing` | forward vers Aether, sans usage runtime identifié dans cette crate |
| `helios-wireguard` | `wireguard` | active `defguard_wireguard_rs` |
| `orion-core` | `wireguard`, `certificate-signing` | backend réel client et fixtures de certificats |
| `heliosd` | `netlink`, `wireguard`, `embed-ui`, `tpm` | composition des choix gateway |
| `orion` | `wireguard` | forward vers `orion-core` |

Le domaine de signature release ML-DSA-65 et le domaine PKI/négociation
ML-DSA-87 sont correctement distincts dans le code, mais les features Aether
font remonter une capacité d’implémentation dans plusieurs consommateurs. La
feature `helios-update/publisher-signing` est candidate à suppression après
vérification des commandes et tests, car elle ressemble à un forwarding mort.
Les features backend sont au bon niveau conceptuel, mais `netlink` et TPM
devraient être validées par cible dans la CI ; `--all-features` ne constitue
pas une preuve matérielle.

### Dépendances plateforme

| Zone | Dépendances | Lecture architecturale |
| --- | --- | --- |
| `aether` | `libc` Linux, `windows-sys` Windows | verrouillage mémoire/fichiers ; utilitaire partagé, mais pas totalement neutre plateforme |
| `helios-firewall` | `rustables`, `ipnetwork` optionnels | backend Netlink/nftables, à garder hors contrats |
| `helios-wireguard` | `defguard_wireguard_rs` optionnel | backend WireGuard réel de la gateway |
| `helio-tpm` | `tss-esapi` optionnel | TPM réel, cible matérielle |
| `helios-fido` | `ctap-hid-fido2`, hidapi/libudev, `windows-sys` | frontière FIDO/WebAuthn matérielle |
| `orion-core` | `windows`, `windows-sys`, `defguard_wireguard_rs` | DPAPI/CNG, BitLocker/WMI, Wintun/route pinning client |
| `heliosd` | `libc` Unix | protection des core dumps du daemon |
| `orion` | Tauri, WebView/GTK ou WebView2 | shell graphique uniquement |
| `helios-astra-helper` | Win32/GDI | propriété de fenêtre et désélévation du compagnon |
| `xtask` | téléchargement WireGuardNT et packaging | build workstation, jamais runtime |

Les contrats partagés ne dépendent pas directement de Tauri, Netlink, TPM,
WireGuard réel ou Win32. La contamination actuelle est localisée dans les
modules d’implémentation ; elle ne doit pas remonter dans le modèle partagé.

### Tests et emplacement

- Les tests unitaires sont majoritairement colocés dans les modules `src/`.
  C’est le cas d’Aether, API, firewall, WireGuard, provisioning, négociation,
  vault, update, `heliosd`, `orion-core` et de l’application Tauri.
- Les tests d’intégration sont dans `crates/astra/tests/` (`cli.rs`,
  `private_channel.rs`), `crates/astra-operator/tests/`,
  `crates/helio-tpm/tests/materiel.rs` et
  `tools/helios-publisher/tests/cli_security.rs`.
- `heliosd` possède un test d’interopérabilité client via sa dépendance dev à
  `orion-core`, mais pas de harnais indépendant.
- Les tests frontend vivent dans `web/` et `apps/orion/`; les cibles libFuzzer
  vivent sous `fuzz/`, hors workspace racine.

Le principal déficit de placement est donc le test Helios/Orion, pas l’absence
de tests dans les sous-systèmes.

## 4. Responsabilité actuelle et décision

| Package / application | Responsabilité observée | Décision | Justification |
| --- | --- | --- | --- |
| `aether` | Contrats, états, protocole, crypto, certificats, quelques I/O/utilitaires | **KEEP** | fan-in élevé et invariants liés ; clarifier les modules avant extraction |
| `astra` | Autorité PKI, registre/opérations, service et binaire | **KEEP** | sous-système cohérent avec cycle de vie propre |
| `astra-operator` | Coffre opérateur, FIDO, gestes, campagnes et relais | **KEEP** | frontière de sécurité réelle ; supprimer sa dépendance de contrat vers `astra` |
| `helios-firewall` | Policy, IR/ruleset, validation, compilation et backends | **KEEP** | bonne frontière ; conserver les backends comme modules |
| `helios-update` | Bundle, vérification, staging, activation et rollback | **KEEP** | cycle de vie et privilège indépendants |
| `helios-api` | API Axum/WS/UI et canal privé Astra | **SPLIT** | extraire le canal privé, conserver la façade HTTP gateway |
| `helio-tpm` | TPM, boot, rescellement, fenêtre d’update et escrow | **SPLIT / RENAME** | extraire `escrow`, puis renommer le package matériel en `helios-tpm` |
| `helios-provisioning` | Admission, IPAM, session ML-KEM, rotation et registre certificats | **SPLIT différé** | extraire le registre vers un sous-système trust seulement après preuve de seam |
| `helios-wireguard` | Plan de données, pairs, observation et backends | **KEEP** | frontière de plan de données claire |
| `helios-key-negotiation` | QUIC/mTLS et protocole v5 avant WireGuard | **RENAME / MOVE** | capacité Helios/Orion ; candidate `aether-key-negotiation`, avec transport partagé et backends hors modèle |
| `helios-vault` | Format AEAD HVLT et seal/open | **RENAME / MOVE** | format de sécurité Helios/Orion ; candidate `aether-vault`, sans préfixe gateway |
| `helios-fido` | CTAP2 HID et WebAuthn Windows | **RENAME** | adaptateur utilisé par Orion et l’opérateur ; candidate `aether-fido`, à garder séparé d’Aether si la dépendance plateforme l’exige |
| `orion-core` | Logique client portable, coffre, provisioning, certificats et backend VPN | **KEEP** | cycle de vie client cohérent ; pas de troisième crate prouvée |
| `heliosd` | CLI gateway, lifecycle et composition des sous-systèmes | **KEEP** | composition root à amincir ; `helios-runtime` non démontré |
| `astra-signer` | CLI d’approbation/signature opérateur | **KEEP** | processus hors ligne et privilège distincts |
| `helios-astra-helper` | Compagnon interactif Windows | **KEEP** | processus et intégration Win32 propres |
| `helios-ctl` | CLI opérateur : admission, campagnes, escrow, update, profils | **KEEP** | composition root d’outil |
| `helios-installer` | Helper privilégié d’installation/rollback | **KEEP** | frontière de privilège distincte |
| `helios-publisher` | Clés et signatures de releases/bundles | **KEEP** | doit rester hors gateway et hors client |
| `xtask` | Build, téléchargement de dépendances et packaging | **KEEP** | outil de build, non runtime |
| `orion` | Shell Tauri/React et intégrations desktop | **KEEP** | application et composition UI |
| `fuzz` | Workspace libFuzzer hors workspace racine | **KEEP** | cycle de build nightly volontairement séparé |

Les décisions `SPLIT` sont des cibles séquencées, pas la création immédiate de
crates d’erreurs, DTO, utils, sérialisation ou backend.

## 5. Architecture cible proposée

La cible conserve la majorité des crates existantes et ajoute seulement des
frontières démontrées :

```text
crates/
  aether/                    contrats partagés et crypto commune
  aether-fido/               FIDO partagé ou abstraction FIDO [renommé]
  aether-key-negotiation/    protocole v5 Helios/Orion [renommé]
  aether-vault/              conteneur AEAD partagé [renommé]
  astra/                     sous-système autorité/certificats
  helios-astra-channel/      canal privé Astra <-> gateway [nouveau]
  helios-api/                API/WS/UI gateway
  helios-escrow/             format et opérations de séquestre [nouveau]
  helios-firewall/           policy -> IR -> compiler -> backend
  helios-provisioning/       admission, IPAM, session et rotation PSK
  helios-trust/              registre durable des certificats [conditionnel]
  helios-tpm/                TPM, boot et fenêtre d’update [renommé]
  helios-update/             releases et activation
  helios-wireguard/          plan de données WireGuard
  orion-core/                logique cliente portable

apps/
  heliosd/                   composition root gateway
  orion/                     composition root Tauri

tools/
  helios-ctl/
  helios-installer/
  helios-publisher/
  astra-signer/
  helios-astra-helper/
  xtask/
```

`helios-astra-channel` est justifiée par un protocole de processus à processus,
ses bornes TLS/ALPN, deux côtés indépendants et la suppression de
`astra -> helios-api`. `helios-escrow` est justifiée par une frontière de
secret opérateur et son absence de dépendance TPM réelle. `helios-trust` reste
conditionnelle : si l’extraction du registre produit un package utilisé par un
seul consommateur sans simplifier son ownership, le registre peut rester un
module du sous-système gateway.

`helios-runtime` n’est pas retenue maintenant. Elle ne deviendra justifiée que
si un second binaire, un autre hôte ou un test de lifecycle réutilisable doit
assembler le même runtime gateway.

Le graphe Orion cible ne doit donc contenir que `aether`, les crates
`aether-*`/neutres explicitement partagées et ses propres modules. Les
packages `helios-*` restent réservés aux sous-systèmes gateway ou aux outils
qui en sont les compositions roots.

Les modules firewall et WireGuard restent internes à leurs crates. La
réorganisation physique ne crée pas de hiérarchie artificielle
`domain/services/infrastructure/application`.

## 6. Graphe cible

```text
aether-fido -> aether
aether-key-negotiation -> aether
aether-vault -> aether
helios-escrow -> aether
helios-firewall -> aether
helios-provisioning -> aether
helios-tpm -> aether
helios-trust -> aether                  [si extraction confirmée]
helios-update -> aether

helios-wireguard -> helios-provisioning  [contrat PeerTable/IPAM à stabiliser]

helios-astra-channel -> aether

astra
  -> aether
  -> helios-astra-channel

astra-operator
  -> aether
  -> aether-fido
  -> aether-vault
  -> helios-astra-channel       [uniquement si ses contrats y résident]

helios-api
  -> aether
  -> helios-astra-channel
  -> helios-firewall
  -> helios-provisioning
  -> helios-trust                  [si extraction confirmée]
  -> helios-update
  -> helios-wireguard

heliosd
  -> aether
  -> aether-key-negotiation
  -> aether-vault
  -> helios-api, helios-escrow et helios-firewall
  -> helios-provisioning, helios-tpm, helios-update et helios-wireguard
  -/-> orion-core                [ni normal ni dev après migration]

orion-core
  -> aether
  -> aether-fido
  -> aether-key-negotiation
  -> aether-vault

orion
  -> orion-core
  -> xtask                       [build seulement]

helios-ctl
  -> aether
  -> helios-escrow / helios-tpm
  -> aether-key-negotiation
  -> helios-update
  -> orion-core
```

Les applications restent au-dessus des sous-systèmes. Aether ne connaît ni
Helios, ni Orion, ni Tauri. Astra ne connaît plus la façade API de la gateway.
Le code commun à Helios et Orion reste dans Aether ou dans une future frontière
explicitement partagée, jamais dans une application.

## 7. Dépendances interdites

- Aether ne dépend d’aucune crate, app ou outil Helios/Orion.
- Une crate de sous-système ne dépend ni de `heliosd`, ni de `orion`, ni de
  Tauri, ni du frontend `web`.
- `heliosd` ne dépend pas de `orion-core`, y compris pour ses tests de package ;
  l’interopérabilité utilise un harnais dédié.
- `astra` ne dépend pas de `helios-api` ; le canal privé possède son propre
  propriétaire.
- `astra-operator` ne dépend pas de l’implémentation `astra` pour des DTO ou
  des états déjà partagés.
- `orion-core` ne dépend d’aucun serveur ou shell Helios.
- `orion-core` ne dépend directement d’aucun package nommé `helios-*` ; une
  capacité commune est possédée par `aether`, `aether-*` ou une crate au nom
  neutre documentée comme partagée.
- Les contrats partagés ne dépendent pas de Win32, WebView2, GTK, Netlink,
  `tss-esapi` ou du backend WireGuard réel.
- Firewall et WireGuard communiquent par interfaces de sous-système, pas par
  accès aux implémentations internes.
- Les signatures ML-DSA-65 de release et ML-DSA-87 de négociation/PKI restent
  deux domaines séparés.
- Aucun DTO API redigé ne reconstruit ni ne persiste `network.toml`.
- Aucune nouvelle crate n’est introduite pour une erreur, un type, un utilitaire
  ou un backend sans frontière de sécurité, protocole, plateforme, cycle de
  vie ou réutilisation indépendante démontrée.

## 8. Plan de migration progressive

Chaque phase doit former un diff reviewable, compiler, passer ses tests et
laisser inchangés protocoles, formats, clés, certificats, CLI et comportement.

### Phase 0 — cartographie

Livrer ce document comme référence. Aucun déplacement de source ou manifest.
Ajouter éventuellement un contrôle read-only du graphe après validation des
règles interdites.

Fichiers : `docs/architecture/CRATE-REORGANIZATION.md`, puis éventuellement un
script de contrôle et son workflow.

Validation : `cargo fmt --all -- --check`, `cargo check --workspace`,
`cargo test --workspace`, contrôle que seules la documentation et les règles
acceptées ont changé.

### Phase 1 — corrections sans déplacement

Simplifier le manifest racine avec des patterns, vérifier le périmètre du build
par défaut et caractériser les features mortes. L’option la plus simple est :

```toml
members = ["crates/*", "tools/*", "apps/orion/src-tauri"]
default-members = ["crates/*", "tools/*", "apps/orion/src-tauri"]
```

Cela inclut aussi `helios-publisher` dans le build par défaut. Si ce coût n’est
pas accepté, garder un `default-members` explicite mais réduire uniquement la
liste `members`; dans les deux cas, vérifier que `orion` reste compilé/testé.

Fichiers : `Cargo.toml`, manifests avec forwarding de features, workflows et
documentation de build si leurs sélections de packages sont explicites.

Validation : métadonnées par défaut et workspace, `cargo check`, tests de
`helios-publisher`, `orion` et frontend.

### Phase 2 — frontières partagées et canal Astra

Reclasser les dépendances de `orion-core` vers `helios-fido`,
`helios-key-negotiation` et `helios-vault`. Déplacer les responsabilités
partagées dans `aether` lorsque le module est un contrat pur ; sinon renommer
les packages en `aether-*` ou en noms neutres, sans déplacer les backends
plateforme dans le socle. Puis extraire les contrats, TLS/ALPN et client/serveur
du canal privé vers `helios-astra-channel`. Faire consommer cette crate par
Astra, `heliosd` et la façade API qui en a besoin. Classifier puis déplacer
`IssuerDelegationRequest` et les vues d’opération vers leur propriétaire
canonique. Déplacer le test d’interopérabilité hors de la dépendance dev de
`heliosd`.

Fichiers : manifests de `orion-core`, `helios-fido`,
`helios-key-negotiation`, `helios-vault`, leurs `src/lib.rs`,
`helios-api/src/internal.rs`, `src/certificates.rs`, `src/lib.rs`,
`astra/src/{gateway.rs,distribution.rs,operations.rs,renewal.rs,service.rs}`,
`astra-operator/src/{authority.rs,origin.rs,tunnel.rs,campaign.rs}`,
`heliosd/src/astra_channel.rs`, les manifests et les tests de canal.

Validation : tests mTLS/TLS 1.3/ALPN, canal privé dans
`crates/astra/tests/private_channel.rs`, tests opérateur, interopérabilité v5
et workspace complet.

### Phase 3 — frontières de sécurité et trust

Extraire `helio-tpm::escrow` vers `helios-escrow`, renommer le package matériel
en `helios-tpm` et mettre à jour les imports sans changer HESC, HVLT, tickets ni
clés. Ensuite, après caractérisation des tests, extraire
`helios-provisioning::certificates` vers `helios-trust` uniquement si son
ownership durable est réellement plus lisible.

Fichiers : `crates/helio-tpm/**`, futur `crates/helios-tpm/**`,
`tools/helios-ctl/src/escrow.rs`, `heliosd/src/{gateway_key.rs,gateway_rotation.rs}`,
`helios-provisioning/src/{certificates.rs,lib.rs}`, manifests et tests.

Validation : tests HVLT/HESC, tests dry-run TPM, tests de registre/rotation et
tests matériels conditionnels sur les cibles décrites dans
`docs/testing/TESTING.md`.

### Phase 4 — composition de heliosd

Mesurer le call graph après les phases précédentes. Déplacer vers les
propriétaires les fonctions sans état process/lifecycle global ; ne créer
`helios-runtime` que si un second consommateur est démontré. Réduire `main.rs`
à la configuration, construction des backends, injection, démarrage, arrêt et
gestion du process. Garder les politiques gateway dans leurs sous-systèmes,
pas dans une crate générique d’application.

Fichiers : `heliosd/src/main.rs`, `orchestrator.rs`, `key_negotiation.rs`,
`certificates.rs`, `gateway_rotation.rs`, `astra_channel.rs`, `static_psk.rs`,
`gateway_key.rs`, `uplink.rs`, `vip_routing.rs`, tests lifecycle.

Validation : démarrage/arrêt fail-closed, kill-switch, hot reload, firewall,
WireGuard, provisioning, négociation v5, API et tests Orion.

### Phase 5 — organisation physique

Déplacer uniquement les répertoires dont le propriétaire est stabilisé. Les
chemins courts `crates/firewall` et `crates/tpm` sont acceptables si les noms
Cargo restent compatibles (`helios-firewall`, `helios-tpm`). Mettre à jour les
scripts, workflows, Tauri et packaging. Aucun format protocolaire ou persistant
ne change dans cette phase.

Fichiers : manifests racine/locaux, scripts, workflows, `tools/xtask`, chemins
Tauri et liens documentaires.

Validation : build par défaut incluant Orion, workspace, bundles gateway,
packaging Orion sur les cibles disponibles et recherche des anciens chemins.

### Phase 6 — nettoyage

Supprimer les compatibilités, réexports et features de transition seulement
après migration de tous les consommateurs. Mettre à jour `docs/ARCHITECTURE.md`,
`docs/architecture/overview.md`, l’index et les guides de test.

Fichiers : manifests, `src/lib.rs`, modules de compatibilité, CI et
documentation concernée.

## 9. Risques

| Risque | Contrôle |
| --- | --- |
| casser une sérialisation ou un message signé | golden files, vecteurs et tests avant/après |
| séparer un invariant de certificat de son état | propriétaire explicite, tests de transition/rollback |
| transformer une dépendance de test en runtime | audit `cargo metadata` et manifests par section |
| affaiblir le canal Astra | tests mTLS, ALPN, pinning et bornes de taille |
| exposer un secret via un contrat déplacé | revue des types publics, Debug, logs et API de lecture |
| activer un backend sur la mauvaise cible | matrice Linux/Windows et refus explicite |
| masquer une casse Orion | assertion CI sur le build/test par défaut de Tauri |
| créer `helios-runtime` sans besoin | exiger un second hôte ou consommateur réel |
| renommer `helio-tpm` avec un contrat externe inconnu | recherche de références et transition de package |
| perdre l’interopérabilité Helios/Orion | harnais indépendant contre les implémentations livrées |

Cette refonte ne modifie volontairement aucun protocole réseau, format
persisté/configuration, format crypto, clé, signature, certificat, commande CLI,
comportement firewall, WireGuard, Orion ou Helios. Tout écart observé pendant
une phase doit arrêter cette phase et faire l’objet d’une décision distincte.

## 10. Tests et validations nécessaires

Référence exécutée avant cette livraison documentaire :

```text
cargo fmt --all -- --check       réussi
cargo check --workspace          réussi
cargo test --workspace           réussi
```

La suite `cargo test --workspace` a notamment compilé le package Tauri Orion
et exécuté les tests unitaires Aether et `orion-core`. Les tests matériels TPM,
FIDO, Netlink, WireGuard noyau/WireGuardNT et packaging natif ne sont pas
prouvés par cet environnement.

Après chaque phase de code, exécuter au minimum :

```text
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
npm run test:unit --prefix web
npm run test:unit --prefix apps/orion
```

Pour une phase multi-crates, sécurité, protocole ou packaging, ajouter
`bash scripts/regression.sh`. Les validations matérielles suivent
`docs/testing/TESTING.md`; WSL2/dry-run ne prouvent pas les effets du kernel,
TPM, Netlink, WireGuardNT ou de l’installation.

## 11. Résultat attendu pour un nouvel ingénieur

Le repository doit permettre d’identifier rapidement :

- Aether comme socle de contrats et invariants réellement partagés ;
- chaque sous-système gateway et son backend interne ;
- les frontières de confiance TPM, FIDO, vault, escrow, Astra et négociation ;
- Orion comme client indépendant, avec ses plateformes dans `orion-core` et
  Tauri ;
- `heliosd`, `orion` et les outils comme compositions roots ;
- les dépendances autorisées, interdites et les points d’extension.

## 12. Fichiers impactés par phase

| Phase | Fichiers principaux |
| --- | --- |
| 0 | `docs/architecture/CRATE-REORGANIZATION.md`, éventuel contrôle read-only |
| 1 | `Cargo.toml`, manifests de features, workflows, docs de build |
| 2 | manifests et sources de `orion-core`, `helios-fido`, `helios-key-negotiation`, `helios-vault`, `helios-api/src/{internal.rs,certificates.rs,lib.rs}`, Astra, `astra-operator`, `heliosd/src/astra_channel.rs`, tests de canal et d’interopérabilité |
| 3 | `crates/helio-tpm/**`, futur `helios-tpm`, futur `helios-escrow`, `helios-provisioning/src/certificates.rs`, `heliosd`, `helios-ctl`, tests de sécurité |
| 4 | `heliosd/src/main.rs` et modules lifecycle, tests de démarrage/arrêt, éventuellement manifest `helios-runtime` |
| 5 | chemins `crates/`, `tools/`, `apps/`, manifests, scripts, workflows, Tauri, packaging |
| 6 | réexports, compatibilités, features, `docs/ARCHITECTURE.md`, `docs/architecture/overview.md`, guides de test et ADR touchés |

## Recommended first migration

La plus petite modification au meilleur rapport bénéfice/risque est une
correction du workspace Cargo, sans déplacement de code : remplacer les listes
explicites de `members` et `default-members` par des patterns équivalents et
conserver Orion/Tauri dans le build par défaut.

La version la plus simple inclut `helios-publisher` dans le build par défaut :

```toml
members = ["crates/*", "tools/*", "apps/orion/src-tauri"]
default-members = ["crates/*", "tools/*", "apps/orion/src-tauri"]
```

Si l’augmentation du périmètre liée à `helios-publisher` n’est pas souhaitée,
la première migration doit garder une liste `default-members` explicite et
ajouter un contrôle CI qui vérifie que `apps/orion/src-tauri` est bien présent.
Dans les deux cas, la propriété non négociable est la compilation et les tests
du client Orion dans le build par défaut.

Cette étape est limitée au manifest, ne touche aucun contrat externe et produit
un diff facilement réversible. Elle doit être livrée seule puis relue et
validée avant toute extraction du canal Astra, du trust registry, de l’escrow,
ou toute tentative de création de `helios-runtime`.
