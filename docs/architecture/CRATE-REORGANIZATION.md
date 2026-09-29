# Audit et proposition de réorganisation des crates

> Document d’audit préalable. Cette livraison ne migre aucun code, ne modifie
> aucun manifest et ne change aucun contrat. Les décisions proposées doivent
> être relues et validées avant toute phase d’implémentation.
>
> **L’implémentation a commencé depuis.** Les sections 1 à 12 restent le
> constat daté qui a motivé chaque décision ; l’état réel du dépôt est en
> [§13](#13-état-dimplémentation), relevé à `HEAD = b9380ca`. Lire §13 avant
> de se fier à une description d’arbre ou de graphe des sections précédentes.

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

## 1. Architecture actuelle et direction cible

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

Cela en fait un *god crate* potentiel par son fan-in de 18, mais pas une raison
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
d’interface/pairs, observation des handshakes, dry-run et backend réel. La vue
qui adapte un snapshot de pairs au trait IPAM vit désormais chez son unique
appelant, `helios-api::provision`. `helios-wireguard` ne dépend donc plus de
`helios-provisioning` et constitue une crate feuille du graphe interne.

Les frontières `helios-vault`, `helios-fido`, `helios-tpm` et
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

helios-tpm
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
  -> helios-escrow
  -> helios-key-negotiation
  -> helios-update
  -> orion-core

helios-escrow
  -> aether

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

heliosd
  -> aether
  -> helios-api
  -> helios-escrow
  -> helios-firewall
  -> helios-key-negotiation
  -> helios-provisioning
  -> helios-tpm
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

Les dépendances `dev` de `aether`, `helios-update` et `helios-tpm` activent des
fixtures/signatures pour leurs propres tests. Elles ne forment pas des arêtes
de production.

### Fan-in, fan-out et cycles

| Package | Fan-in normal | Fan-out normal |
| --- | ---: | ---: |
| `aether` | 18 | 0 |
| `astra` | 1 | 2 |
| `astra-operator` | 2 | 4 |
| `astra-signer` | 0 | 3 |
| `helios-tpm` | 1 | 2 |
| `helios-api` | 2 | 5 |
| `helios-astra-helper` | 0 | 3 |
| `helios-ctl` | 0 | 5 |
| `helios-escrow` | 2 | 1 |
| `helios-fido` | 4 | 1 |
| `helios-firewall` | 2 | 1 |
| `helios-installer` | 0 | 1 |
| `helios-key-negotiation` | 3 | 1 |
| `helios-provisioning` | 2 | 1 |
| `helios-publisher` | 0 | 2 |
| `helios-update` | 6 | 1 |
| `helios-vault` | 4 | 1 |
| `helios-wireguard` | 2 | 0 |
| `heliosd` | 0 | 10 |
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
| `helios-tpm` | `tpm` | active `tss-esapi` et le backend matériel |
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
| `helios-tpm` | `tss-esapi` optionnel | TPM réel, cible matérielle |
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
  `crates/helios-tpm/tests/materiel.rs` et
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

### Organisation interne par blocs fonctionnels

La frontière Cargo ne suffit pas : `heliosd`, Orion/Tauri, le transport de
négociation et certains contrats Aether réunissent plusieurs capacités dans
un même fichier. À l’inverse, les tailles brutes de
`helios-provisioning::certificates`, `astra::registry`, du firewall, du vault
et de l’update sont fortement augmentées par leurs tests inline ; leur code de
production est plus cohérent que le nombre total de lignes ne le laisse croire.

La section `Internal Module Organization` distingue donc systématiquement
taille totale, code avant le module de tests, responsabilité réelle et action.
Elle privilégie les splits par agrégat, commande ou transport concret et
refuse les arbres génériques `models/services/validators/utils`.

## 5. Architecture cible proposée

La cible conserve la majorité des crates existantes et ajoute seulement des
frontières démontrées :

```text
crates/
  aether/                    contrats partagés et crypto commune
  aether-fido/               FIDO partagé ou abstraction FIDO [renommé]
  aether-key-negotiation/    transport QUIC/TLS v5 partagé [renommé]
  aether-vault/              conteneur AEAD partagé [renommé]
  astra/                     sous-système autorité/certificats
  astra-channel/             canal privé Astra <-> gateway [nouveau]
  helios-api/                API/WS/UI gateway
  helios-escrow/             format et opérations de séquestre [nouveau]
  helios-firewall/           FirewallPolicy -> IR -> backend
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

Les crates `aether-*` sont des crates sœurs de `aether`, pas des modules
internes ni des dépendances de `aether`. En particulier,
`aether-key-negotiation -> aether` : le transport partagé consomme les contrats
canoniques, tandis qu'`aether` ne dépend jamais de QUIC/TLS.

`astra-channel` est justifiée par un protocole de processus à processus,
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

helios-wireguard                         [feuille : arête supprimée, c050537]

astra-channel -> aether

astra
  -> aether
  -> astra-channel

astra-operator
  -> aether
  -> aether-fido
  -> aether-vault
  -> astra-channel              [uniquement si ses contrats y résident]

helios-api
  -> aether
  -> astra-channel
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
  -> aether
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
- `heliosd` ne dépend pas de `orion-core` **en production**. La dépendance
  `dev` est conservée : voir l’arbitrage ci-dessous.
- `astra` ne dépend ni de `helios-api` ni d’une crate nommée `helios-*` ; le
  canal privé possède son propre propriétaire neutre.
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

### Arbitrage : `heliosd -[dev]-> orion-core`

La règle initiale (« y compris pour ses tests de package ») **contredisait
l’arbre cible de la Phase 4 de ce même document**, qui place
`crates/heliosd/src/key_negotiation/tests/interop.rs` — donc sous la dépendance
`dev`. La contradiction est tranchée ici en faveur de l’arbre : **REJECTED**,
l’arête `dev` est conservée et la règle ci-dessus est restreinte à la
production.

Ce que l’audit a mesuré :

- `crates/heliosd/Cargo.toml` ne déclare qu’un `[[bin]]`. Sortir le test exige
  donc d’abord d’ajouter une cible `lib` à un composition root.
- Le test construit `GatewayHandler` par littéral de structure
  (`crates/heliosd/src/key_negotiation.rs:3954`) : ses **12 champs sont privés**
  et `TransactionState` (`:218`) l’est aussi. L’extraction demande de publier
  les deux — c’est-à-dire d’exposer l’état interne du serveur de négociation
  pour servir un test.
- Le second test (`crates/heliosd/src/certificates.rs:2125`) appelle
  `enrolment_view`, `pub fn` dans un binaire, donc inatteignable de l’extérieur
  pour la même raison.
- La preuve elle-même se dégraderait : aujourd’hui elle est une **comparaison
  déterministe de PSK** en `dry_run` contre un plan de données factice. Un
  harnais externe ne pourrait plus atteindre le PSK installé et devrait se
  rabattre sur l’observation d’un handshake WireGuard, donc sur un noyau — ce
  que `docs/testing/TESTING.md` réserve à la cible.

Le coût architectural (cible `lib`, surface publique élargie) dépasse le
bénéfice (une arête `dev` qui ne figure pas dans le graphe de production et
qu’aucun binaire livré ne porte). La justification est inscrite dans
`crates/heliosd/Cargo.toml` (`b9380ca`), qui nomme les deux propriétés
couvertes.

## 8. Plan de migration progressive

Chaque phase doit former un diff reviewable, compiler, passer ses tests et
laisser inchangés protocoles, formats, clés, certificats, CLI et comportement.

> L’état d’avancement réel de chacune de ces phases est en
> [§13](#13-état-dimplémentation). Les descriptions de phase ci-dessous ne sont
> pas réécrites : elles restent la trace de l’intention datée.

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

Simplifier uniquement `members` avec des patterns, vérifier le périmètre du
build par défaut et caractériser les features mortes :

```toml
members = ["crates/*", "tools/*", "apps/orion/src-tauri"]
```

Conserver `default-members` explicite et inchangé afin qu’Orion reste
compilé/testé par défaut sans ajouter silencieusement `helios-publisher` à ce
périmètre.

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
du canal privé vers `astra-channel`. Faire consommer cette crate par
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

État d'implémentation : l'extraction de l'escrow (`helios-escrow`) et le
renommage `helio-tpm` -> `helios-tpm` sont faits. Les noms `helio-tpm` employés
ci-dessus décrivent l'état audité qui a motivé la phase, pas l'ownership
actuel. L'extraction de `helios-provisioning::certificates` reste ouverte.

Validation : tests HVLT/HESC, tests dry-run TPM, tests de registre/rotation et
tests matériels conditionnels sur les cibles décrites dans
`docs/testing/TESTING.md`.

### Phase 4 — découpage interne par blocs fonctionnels

Traiter une crate à la fois, en commençant par les fichiers où plusieurs
workflows indépendants partagent un même état ou une même façade. Commencer par
les déplacements de tests qui clarifient la mesure sans toucher aux invariants
(`helios-provisioning::certificates`, `astra::registry`, ruleset firewall), une
crate à la fois. Traiter ensuite les seams de production démontrés : transport
de négociation, identité/transactions de `heliosd`, moteurs speedtest et
formats d’import Orion. Les contrats Aether viennent après, avec des golden
files inchangés. Chaque déplacement doit conserver noms de types,
sérialisation et surface publique, sauf réduction de visibilité explicitement
vérifiée.

Les tests suivent le déplacement : tests de validation avec la validation,
tests de transitions avec la machine à états, tests de protocole dans les
fichiers d’intégration dédiés et tests backend dans les modules conditionnés
par la plateforme. Une phase de découpage interne ne doit pas modifier le
comportement ; elle sert à rendre le propriétaire du comportement explicite.

Fichiers : les arbres indiqués dans `Internal Module Organization`, une crate
à la fois ; aucun nouveau package requis.

Validation : formatage, compilation, tests de la crate concernée, tests
d’intégration associés, puis workspace complet et contrôle des symboles
publics.

### Phase 5 — composition de heliosd

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

### Phase 6 — organisation physique

Déplacer uniquement les répertoires dont le propriétaire est stabilisé. Les
chemins courts `crates/firewall` et `crates/tpm` sont acceptables si les noms
Cargo restent compatibles (`helios-firewall`, `helios-tpm`). Mettre à jour les
scripts, workflows, Tauri et packaging. Aucun format protocolaire ou persistant
ne change dans cette phase.

Fichiers : manifests racine/locaux, scripts, workflows, `tools/xtask`, chemins
Tauri et liens documentaires.

Validation : build par défaut incluant Orion, workspace, bundles gateway,
packaging Orion sur les cibles disponibles et recherche des anciens chemins.

### Phase 7 — nettoyage

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
| 4 | arbres internes indiqués dans `Internal Module Organization`, tests colocalisés et surfaces publiques des crates concernées |
| 5 | `heliosd/src/main.rs` et modules lifecycle, tests de démarrage/arrêt, éventuellement manifest `helios-runtime` |
| 6 | chemins `crates/`, `tools/`, `apps/`, manifests, scripts, workflows, Tauri, packaging |
| 7 | réexports, compatibilités, features, `docs/ARCHITECTURE.md`, `docs/architecture/overview.md`, guides de test et ADR touchés |

## 13. État d’implémentation

> Relevé au 2026-09-13, `HEAD = b9380ca`, branche `refactor-module-organization` ;
> lignes de §13.1, §13.3 et §13.5 mises à jour le 2026-09-29 sur `rework/crates`.
> Chaque état est tiré du code, pas d’une intention. Les sections 1 à 12 et
> `Internal Module Organization` ne sont pas réécrites : elles restent le
> constat daté qui explique *pourquoi* chaque décision a été prise — même
> traitement que celui donné à ADR-004 pour l’escrow et aux mentions
> `helio-tpm` par `9e4f425`.
>
> Vocabulaire : **DONE** livré et vérifié ; **PARTIAL** commencé, reste
> mesurable ; **DEFERRED** non commencé, toujours souhaitable ;
> **REJECTED** mesuré puis abandonné, avec la mesure.

### Vérifications exécutées pour ce relevé

```text
cargo metadata --format-version 1 --no-deps          graphe interne
cargo fmt --all --check                              réussi
cargo test --workspace                               1530 réussis, 0 échec
cargo test -p orion-core --features certificate-signing        317
cargo test -p helios-provisioning --features certificate-signing 95
cargo test -p helios-firewall --features netlink                54
cargo clippy --workspace --all-targets --all-features -- -D warnings   réussi
cargo doc --workspace --no-deps --all-features        liens intra-doc
```

WSL2 ne prouve ni le noyau `nf_tables`, ni WireGuard, ni le TPM, ni
WireGuardNT : `docs/testing/TESTING.md` reste la référence pour ces cibles.

### 13.1 Frontières Cargo

| Élément de plan | État | Justification tirée du code |
| --- | --- | --- |
| Phase 1 — `members` par patterns | **DONE** | `Cargo.toml` porte `members = ["crates/*", "tools/*", "apps/orion/src-tauri"]`, et `default-members` reste la liste explicite qui inclut Orion et exclut `helios-publisher`. |
| `helios-escrow` (extraction de l’escrow) | **DONE** | `crates/helios-escrow/` existe ; `helios-tpm` ne l’a plus qu’en `dev-dependency`, `helios-ctl` et `heliosd` en dépendance normale. |
| `helio-tpm` -> `helios-tpm` | **DONE** | `9e4f425` ; plus aucune occurrence de `helio_tpm`/`helio-tpm` hors des constats datés de ce document et d’ADR-004. |
| `helios-wireguard -> helios-provisioning` | **DONE** | Arête supprimée (`c050537`). `helios-wireguard` ne déclare plus aucune dépendance de workspace. |
| `helios_wireguard::PeerAddressTable` | **RUPTURE SOURCE INTERNE À CONFIRMER** | `c050537` supprime ce chemin Rust public en déplaçant l’adaptateur chez son seul consommateur observé dans le workspace. Aucun contrat réseau, persistant ou CLI ne change, mais un consommateur Rust externe éventuel ne compilerait plus. Le dépôt ne déclare pas ces packages comme publiés ; cette absence d’usage externe doit néanmoins être confirmée avant fusion. |
| `heliosd -[dev]-> orion-core` | **REJECTED** | Voir l’arbitrage en §7 : cible `lib` requise, 12 champs privés de `GatewayHandler` + `TransactionState` à publier, et la preuve passerait d’une comparaison déterministe de PSK à une observation de handshake exigeant un noyau. |
| `astra -> helios-api` | **DONE** | Arête supprimée : `crates/astra/Cargo.toml` ne déclare plus `helios-api`, ni en dépendance normale ni en dev, et `cargo metadata` donne `astra -> aether, astra-channel`. Les 10 sites de `050c03c` et `TrustUpdateRefusal` nomment `aether` ; les 20 lignes qui visaient `helios_api::internal` nomment `astra_channel`. |
| `astra-channel` (SPLIT de `helios-api`) | **DONE** | `crates/astra-channel/src/lib.rs` est l’ancien `helios-api/src/internal.rs` déplacé par `git mv` (2 255 lignes, 14 tests), plus le trait `AstraStageHandler`, contrat Astra→Helios sans route in-tunnel, venu de `helios-api/src/certificates.rs`. La crate ne dépend que d’`aether`. Consommateurs : `astra`, `helios-api` (relais opérateur in-tunnel, bornes de corps) et `heliosd`, qui héberge le serveur — l’arête `heliosd -> astra-channel`, absente du graphe cible du §6, est exigée par le code. `helios-api` perd `pub mod internal` et les dépendances de transport qui ne servaient qu’au canal (`rustls`, `tokio-rustls`, `hyper`, `hyper-util`, `http-body-util`, `bytes`). Aucune compatibilité conservée : les consommateurs sont tous dans le dépôt. `heliosd` nomme la crate `::astra_channel`, son propre module `astra_channel` (le listener) la masquant sinon. Fil inchangé : ALPN, préfixes et routes sont les mêmes constantes, déplacées. |
| `astra-operator -> astra` | **DONE** | Arête supprimée : `astra` ne figure plus dans `crates/astra-operator/Cargo.toml`, et `cargo metadata` donne `astra-operator -> aether, aether-fido, aether-vault`. Les 12 chemins `SigningOperationView`/`SigningOperationState` nomment `aether::certificates::transport`, que `crates/astra/src/signing.rs` se contentait de réexporter (technique de `050c03c`). Le dernier chemin, `IssuerDelegationRequest`, a été classé **contrat partagé** : document sans secret que `astra` écrit et que le compagnon relit sur une autre machine. Il est défini en `crates/aether/src/certificates/authority.rs`, à côté de l’`AstraIssuerAuthorization` qu’il demande ; `astra::issuer` et `astra_operator::authority` le réexportent, si bien qu’aucun consommateur (`astra-signer`, tests d’intégration) n’a changé de chemin. Format JSON inchangé : mêmes champs, même `deny_unknown_fields`. |
| `aether-fido`, `aether-key-negotiation`, `aether-vault` | **DONE** | Renommage seul, aucune ligne de logique touchée. Les répertoires sont `crates/aether-fido/`, `crates/aether-key-negotiation/`, `crates/aether-vault/` et leurs `[package] name` suivent ; `crates/orion-core/Cargo.toml` ne déclare plus que `aether-key-negotiation`, `aether-vault` et `aether-fido`, donc plus aucun package `helios-*`. La règle de nommage de §1 n'est plus violée. Les valeurs de format et de protocole gardent volontairement leur nom historique — `AAD_PREFIX = b"helios-vault/v1"` (`crates/aether-vault/src/lib.rs:76`), `KEY_NEGOTIATION_ALPN = b"helios-key-negotiation/5"` (`crates/aether-key-negotiation/src/lib.rs:30`), les domaines ML-DSA-87 de `crates/aether/src/key_negotiation.rs` et le discriminant de profil Orion `helios_key_negotiation` — les renommer casserait des coffres, des sessions et des profils existants. Avec `astra -> helios-api` et `astra-operator -> astra` levés (13.1), plus aucun des trois interdits de §7 relevés ici n’est enfreint en production. |
| `helios-trust` (extraction de `helios-provisioning::certificates`) | **DEFERRED** | La *seam* que la Phase 3 exigeait avant extraction est désormais prouvée au niveau module : `096c1e9` a découpé le registre en cinq sous-modules dont chacun a son fichier de tests jumeau. Mais la condition de crate n’est pas remplie : un seul consommateur, `heliosd` (22 lignes) ; `helios-api` ne consomme que la moitié admission de `helios-provisioning`. Le registre reste donc un module, comme §5 l’autorisait explicitement. |
| `helios-runtime` | **REJECTED** | `e8e771f` a extrait `run()` vers `crates/heliosd/src/daemon.rs`, déclaré `mod daemon;` (privé) dans `main.rs:6`. Aucun second hôte runtime : la condition que §5 posait n’est pas rencontrée. Même conclusion pour `crates/astra/src/daemon.rs`, `mod daemon;` privé dans `astra/src/main.rs:29`. |
| Phase 6 — organisation physique | **DEFERRED** | Aucun répertoire de crate déplacé. Les regroupements `backend/` prévus pour `helios-firewall` et `helios-wireguard` ne sont pas faits : `dryrun.rs`, `kernel.rs`, `netlink.rs` restent à la racine de leur `src/`. |
| Phase 7 — nettoyage | **DEFERRED** | Aucune compatibilité ni feature de transition à retirer tant que les Phases 2 et 6 ne sont pas terminées. |

### 13.2 Découpage interne — tests par capacité

| Élément de plan | État | Justification tirée du code |
| --- | --- | --- |
| `helios-firewall::ruleset` | **DONE** | `src/ruleset/tests/{access,egress,transport,uplinks,support}.rs`, plus `golden.rs` ajouté par `d95be0c`. |
| `helios-provisioning::certificates` | **DONE** | `src/certificates/tests/{fixtures,staging,distribution,transitions,trust,persistence}.rs` — un fichier par sous-module de production, correspondance exacte. |
| `astra::registry` | **DONE** | `src/registry/tests/{challenges,delegation,peer_lifecycle,persistence,transitions}.rs`. La revue finale a replacé `a_delegation_may_not_walk_its_epoch_backwards` avec la production `registry/delegation.rs`. |
| `orion-core::profile_import` | **DONE** | `src/profile_import/tests/` — neuf fichiers par capacité plus les fixtures, 50 noms de tests inchangés (`15bd6b3`). |
| `orion-core::certificate_renewal` | **DONE** | `src/certificate_renewal/tests/` — cinq fichiers par capacité plus les fixtures, 26 noms de tests inchangés (`b0bcb42`). La gate `#[cfg(all(test, feature = "certificate-signing"))]` est préservée. |
| `aether-key-negotiation` | **DONE** | `src/tests/{fixtures,limits,material,protocol,rollback,transport}.rs` (`da36e3b`) : l’arbre livré est exactement celui que §« Négociation » proposait. |

### 13.3 Découpage interne — production

| Élément de plan | État | Justification tirée du code |
| --- | --- | --- |
| `aether-key-negotiation/src/lib.rs` (`SPLIT`, haute) | **DONE** | `identity.rs`, `endpoint.rs`, `framing.rs`, `server.rs`, `client.rs`, `transaction.rs`, `rate_limit.rs`, `error.rs` — l’arbre cible au fichier près ; `lib.rs` ne garde que les `mod` privés, les réexports et les constantes bornées. |
| `helios-provisioning::certificates` (`SPLIT`, haute) | **DONE** | `certificates/{persistence,staging,distribution,transitions,trust}.rs` (`096c1e9`). Seule modification de visibilité : `persist` passe `pub(super)`, portée effective identique. |
| `helios-firewall::ruleset` | **DONE** (au-delà du plan, qui disait `KEEP`) | `ruleset/{nftables,administration,astra_channel,transport,gateway_wan,meshnet,tunnel_interface,kill_switch}.rs` (`f788e14`). Les six snapshots de `d95be0c`, écrits **avant** le découpage contre le `render` monolithique, passent sans retouche : l’ordre des règles — sémantique en nftables — est prouvé inchangé. |
| `helios-firewall::netlink` | **DONE** | `netlink/{expressions,transaction,maintenance}.rs` (`2d49c17`). Non exercé contre un noyau : WSL2 n’a pas `nf_tables`. Comparaison ligne à ligne avant/après : aucune ligne de logique ne diffère, seulement imports, `mod`, visibilité et documentation. |
| `heliosd/src/main.rs` (`SPLIT`, très haute) | **DONE** | `main.rs` est ramené à la surface clap, `main()` et son dispatch (813 lignes, dont ~195 de tests de la surface clap) ; `daemon.rs`, `process_guards.rs`, `commands/{tpm,trust,identity,peer,wan}.rs` (`e8e771f`). `run()` fait 366 lignes, octet pour octet identiques à l’original. Les 24 écrans d’aide sont inchangés. |
| `astra/src/main.rs` (`SPLIT`, haute) | **DONE** | `main.rs` ramené à 598 lignes ; `daemon.rs`, `private_channel.rs`, `campaign_deposit.rs`, `commands/{trust_domain,campaign,chain,gateway_identity,revocation,issuer}.rs` (`2eb9afe`). Écarts assumés par rapport à l’arbre cible : `bootstrap.rs` s’appelle `trust_domain.rs` (le fichier porte aussi `pin_ca_tls` et `status`), et aucun `cli.rs` n’a été créé — la surface clap reste dans `main.rs`. Les 21 écrans d’aide sont inchangés. |
| `astra/src/registry.rs` (`SPLIT`, moyenne) | **DONE** (au-delà du plan) | Le plan ne demandait que `challenge.rs` et les tests ; `8b4fe96` a livré en plus `persistence.rs`, `peer_lifecycle.rs`, `transitions.rs`, `delegation.rs`, chacun propriétaire exclusif de champs de `AstraState`. `accept_transitions` n’a pas été découpé, volontairement : sa preuve de capacité précède toute mutation et son écriture est atomique. |
| `orion-core/src/profile_import.rs` (`SPLIT`, moyenne) | **DONE** | `profile_import/{document,json,wg_quick,field_rules,validation}.rs` (`0908da2`). Deux écarts au plan, justifiés dans le commit : `field_rules` est séparé de `validation` (les validateurs de champ n’ont jamais vu un `ClientProfile`), et l’intake documentaire est réuni avec la complétion d’invitation. |
| `orion-core/src/certificate_renewal.rs` (`SPLIT`, haute) | **PARTIAL** | `certificate_renewal/{trust_store,promotion,exchange}.rs` (`17bf3d3`) livre la seam « trust store local vs session HTTP ». Reste `impl RenewalSession` : voir 13.4. |
| `aether/src/certificates/{state,status,client,approval}.rs`, `aether/src/key_negotiation.rs` | **PARTIAL** | `state.rs` est devenu `state/` : `mod.rs` (en-tête, `InstallOutcome` partagé, réexports), `gateway_identity.rs`, `client_identity.rs`, `astra.rs`, `revocation_schedule.rs`, `ledger.rs`. Les sous-modules évitent les noms `client`, `gateway` et `revocation`, déjà pris par des modules frères de `certificates`. Code déplacé identique token pour token ; deux méthodes passent `pub(super)` ; les 21 items publics gardent leur chemin `aether::certificates::state::…`. Un test golden posé avant le découpage (`775c210`) fige `base_state_fingerprint` sur un état construit d’octets constants, et passe à l’identique après. `client.rs` est devenu `client/` sur la même méthode, en suivant les objets que sa documentation énumère : `request.rs`, `stage.rs` (autorisation et reçu), `grant.rs`, `commit.rs`, `recovery.rs`, et `signing.rs` pour le côté signature derrière `key-negotiation-signing`, comme `authority::signing`. Seules les six méthodes `signing_bytes` passent `pub(super)`. Un golden posé avant (`8d7b91b`) fige les empreintes de la demande, du reçu, du commit et de la récupération ; l’autorisation et le grant, qui embarquent certificats et preuves signés, sont vérifiés token pour token. `approval.rs` est devenu `approval/` selon les blocs que sa documentation décrit : `policy.rs` (politique et épinglage), `credentials.rs` (bindings et registre), `renewal.rs` (approbation par requête), `campaign.rs`, `recovery.rs` et `signing.rs` ; `DelegatedApproval`, l’union des preuves, reste dans `mod.rs`. Cinq chemins `super::client::` / `super::status::` — dont un lien de documentation qui aurait cassé sans erreur de compilation — deviennent `crate::certificates::…` ; trois `signing_bytes` passent `pub(super)`. Un golden posé avant (`099f6a3`) fige l’empreinte de la politique standard, confirmée hors bande, celle d’un binding et le challenge WebAuthn d’une demande d’approbation. `status.rs` est devenu `status/` selon les blocs de sa documentation : `certificate_status.rs`, `campaign.rs`, `campaign_approval.rs`, `signer.rs` (requête et résultat du compagnon), `rollback.rs` et `signing.rs`. Seize chemins `super::<voisin>::` — dont un lien de documentation — deviennent `crate::certificates::…` ; six méthodes passent `pub(super)`. Un golden posé avant (`edcb80f`) fige l’empreinte d’une campagne, celle d’une autorisation de rollback et le transcript d’une requête de statut. Il ne reste de plat que `aether/src/key_negotiation.rs`, tests sortis (13.4). |
| `heliosd/src/key_negotiation.rs` (`SPLIT`, très haute) | **DONE** | Devenu `key_negotiation/` : `mod.rs` (en-tête, constantes de chemins et de bornes, quatre helpers partagés, réexports des chemins que le reste du démon nomme), `transaction.rs` (slots, générations, `GatewayHandler`), `protocol.rs` (`NegotiationHandler` et release in-tunnel), `server.rs` (`start`, reclaimer), `identity.rs` (identité servie) et `candidate.rs` (identité candidate de rotation) — aucun au-delà de 700 lignes. Écart assumé à l’arbre cible, qui prévoyait trois fichiers : `transaction.rs` y aurait fait ~1 400 lignes et `identity.rs` ~1 000. Les 23 tests sont dans `tests/{fixtures,identity,transaction,interop}.rs` ; `interop.rs` est le seul fichier qui nomme `orion-core`. Le code déplacé est identique token pour token, hors `pub(super)` et deux virgules finales ajoutées par rustfmt ; les 64 `pub(super)` ajoutés ont été dictés par le compilateur et gardent la portée effective d’avant, le sous-arbre `key_negotiation`. |
| `heliosd/src/orchestrator.rs` (`SPLIT`, très haute) | **DEFERRED** | 1 912 lignes, intact. |
| `heliosd/src/certificates.rs` (`SPLIT`, haute) | **DEFERRED** | 2 681 lignes, intact. |
| `helios-api/src/{internal,certificates,routes}.rs` | **PARTIAL** | `internal.rs` est sorti vers `astra-channel` (13.1). `certificates.rs` et `routes.rs` restent intacts hors requalification des chemins. |
| `orion-core/src/speedtest.rs`, `src/backend/mod.rs` | **PARTIAL** | `speedtest.rs` est devenu `speedtest/` : `mod.rs` (API publique, constantes, statistiques partagées par les deux moteurs), `raw.rs` (session brute, latence, TCP, progression), `udp.rs`, `failure.rs` (classification des erreurs de socket), `wire.rs` (cadrage TCP/UDP) et `http.rs` (moteur HTTP et ses six types privés). Code déplacé identique token pour token ; 46 `pub(super)` dictés par le compilateur ; les 13 items publics gardent leur chemin, `run_at` par réexport. Seuls 8 tests couvrent les 1 760 lignes de production. `backend/mod.rs` reste à faire, tests sortis (13.4). |
| `orion` Tauri `src/main.rs` (`SPLIT`, très haute) | **DEFERRED** | 3 725 lignes, intact. |
| `astra-signer/src/main.rs` (`SPLIT`, haute) | **DEFERRED** | 3 991 lignes, intact : c’est le plus gros binaire monolithique restant. |
| `astra-operator/src/authority.rs` -> `signing.rs` (`RENAME`) | **PARTIAL** | Découpé par **gestes**, décision prise contre le « à ne pas éclater » de l’annexe : chaque geste garde toute sa séquence dans sa fonction, ce qui n’est pas la coupure par couches techniques que l’annexe écarte. `authority/` : `mod.rs` (documentation, bornes, `DelegationBounds`, helpers communs), `ca_tls.rs`, `gateway.rs`, `revocation.rs`, `issuer.rs`, `bindings.rs`, `campaign.rs` (le seul geste qui n’ouvre pas le coffre), `anchor.rs`, `recovery.rs`. Code déplacé identique token pour token, un seul `pub(super)`, 27 items publics au même chemin. Le renommage en `signing` n’est pas fait : il toucherait 61 références dans `astra-signer` et les tests. La documentation du module fonde sa « règle unique » sur `approve_renewal`, qui n’existe plus — trois liens cassés préexistants, non corrigés ici. `operations/rotation.rs` n’est pas créé. |
| `helios-ctl` — extraction de `monitor.rs`, renommage `key_nego` | **DEFERRED** | `main.rs` (1 325 lignes) porte toujours le suivi WebSocket ; `campaign_key_nego.rs` et `key_nego.rs` gardent leur abréviation. |

### 13.4 Travaux nommés pendant l’implémentation

Ces points n’existaient pas dans l’audit initial : ils ont été mesurés en
cours de route et sont enregistrés ici plutôt que traités dans un déplacement.

| Point | État | Détail |
| --- | --- | --- |
| `impl RenewalSession` (orion-core) | **DEFERRED** | La plomberie HTTP est une vraie frontière — huit méthodes ne touchent que `self.http` — mais l’extraire n’est pas un déplacement : les méthodes restent des méthodes de `RenewalSession`, le champ `http` et cinq méthodes passeraient `pub(super)`, et la configuration de transport (`no_proxy`, `redirect::Policy::none`, `CALL_TIMEOUT`) est construite au milieu du protocole, dans `prepare`. L’extraction honnête introduit un type `RenewalTransport` propriétaire de son client : une réécriture de corps, pas un déplacement. |
| Imports des tests de `certificate_renewal` | **DONE** | La revue finale a remplacé les six globs par des imports explicites et supprimé du module de production le bloc `use` conditionnel qui ne servait qu’aux tests. |
| `PeerAddressTable::from_peers(&[])` | **À décider — hors réorganisation** | `crates/helios-api/src/provision.rs` construit la table avec une tranche vide inconditionnelle : la table de pairs vivante qu’ADR-001 §4 exige de consulter à l’enrôlement ne l’est jamais. C’est un écart de comportement **antérieur** au déplacement, laissé à une décision distincte car le corriger nécessite de propager un snapshot et de définir le comportement fail-closed si sa lecture échoue. La revue finale a seulement rendu l’adaptateur privé et corrigé le commentaire trompeur, sans modifier le comportement. |
| Tests du ruleset firewall vs modules de production | **PARTIAL** | `f788e14` a découpé la production par capacité (`administration`, `transport`, `kill_switch`…) mais n’a pas réaligné `ruleset/tests/`, organisé par comportement (`access`, `egress`, `transport`, `uplinks`) depuis `ff9f095`. Les deux axes coexistent ; `golden.rs` couvre l’ordre global. Réaligner n’est utile que si l’on accepte de renommer des tests, ce qu’aucun déplacement n’a fait jusqu’ici. |
| Liens intra-doc cassés préexistants | **À corriger — hors périmètre** | `cargo doc --workspace --no-deps --all-features` signale 34 liens non résolus ou pointant vers des items privés. Aucun n’a été introduit par la réorganisation : tous existent à l’identique avant `b837036`, et `096c1e9` en a au contraire réparé un (`RegistryState::client_leaf_issuers`, désormais `crates/helios-provisioning/src/certificates/trust.rs:47`). |
| Tests intégrés des fichiers de plus de 1 000 lignes | **DONE** | Les 36 blocs `#[cfg(test)] mod … { }` de premier niveau des 34 fichiers concernés sont sortis dans un fichier fils (`foo.rs` → `foo/tests.rs`, `lib.rs`/`main.rs`/`mod.rs` → fichier voisin), y compris ceux placés au milieu du fichier (`transport.rs`, `renewal.rs`, `issuer.rs`) et les trois de `astra-operator/src/vault.rs`. Les chemins de module des tests ne changent pas : `cargo test --workspace --all-features -- --list` donne les mêmes 1 702 noms avant et après. La production est identique octet pour octet hors du bloc remplacé par `mod …;` ; un seul `include_str!` relatif a dû prendre un `../` (`aether/src/config/tests.rs`). Il reste 20 fichiers de production au-delà de 1 000 lignes, et 5 fichiers de tests. |

### 13.5 Collision avec la spécification — tranchée

`docs/specification/ROTATION-CERTIFICATS.md` attribuait nommément à
`helios-api` « l’API privée appelée par Astra », c’est-à-dire la
responsabilité que §4 de ce document classe `SPLIT` et que §5 extrait vers
`astra-channel`. Les deux documents ne pouvaient pas être vrais en même temps.

La collision est tranchée en faveur de l’extraction. L’amendement du
29 septembre 2026 (§0.8 de la spécification) déplace cette ligne du §16 vers
`astra-channel` et précise que rien ne change sur le fil : veth, mTLS épinglé,
ALPN `helios-astra-lifecycle/1`, routes et autorisations ML-DSA-87. La
classification de `TrustUpdateRefusal` (13.1) avait déjà tranché la même
question au niveau du type, dans le même sens.

L’extraction est livrée (13.1), et le §0.8 de la spécification le dit.

## Internal Module Organization

Cette analyse porte sur la structure interne des packages, indépendamment des
extractions de crates. Le signal principal est la cohésion fonctionnelle : un
fichier est problématique lorsqu’il mélange plusieurs workflows, frontières
de confiance ou modes d’exécution, même s’il reste court. Inversement, une
machine à états longue mais cohérente peut rester dans un seul module.

La règle de navigation retenue est :

```text
crate       = frontière architecturale forte
module      = capacité ou bloc fonctionnel cohérent
fichier     = responsabilité suffisamment précise et compréhensible
```

Le découpage recommandé est intra-crate et suit le propriétaire du
comportement, pas une taxonomie générique `models/errors/utils`. Un module doit
conserver ses invariants et les transitions de son workflow. `lib.rs` ou
`mod.rs` doit principalement déclarer les grands blocs et exposer la surface
stable. Un fichier de 1 000 lignes n’est pas automatiquement mauvais ; des
workflows indépendants dans le même fichier sont en revanche un signal de
découpage. Aucun dossier ou fichier ne doit être créé sans responsabilité
identifiable.

Les tailles du tableau sont totales. Lorsqu’un fichier termine par un module
de tests inline, la colonne distingue approximativement les lignes avant ce
module et sa suite de tests. Cette mesure ne remplace pas une analyse de
cohésion, mais évite de prendre un corpus de régression volumineux pour une
implémentation monolithique.

### Inventaire actuel des arbres `src/`

Cet inventaire reprend les fichiers Rust réellement présents au moment de
l’audit. Les fichiers imbriqués sont indiqués avec leur chemin ; les noms
correspondent donc à l’organisation actuelle, pas à la cible proposée.

```text
crates/aether/src/
  lib.rs config.rs error.rs events.rs display_time.rs enroll.rs
  key_negotiation.rs locked.rs mtu.rs policy.rs pq.rs private_file.rs
  random.rs secret.rs sig.rs speedtest.rs state.rs wg.rs ml_dsa.rs fuzzing.rs
  certificates/{mod,approval,authority,capability,client,encoding,gateway,
                operator_ipc,operator_session,revocation,state,status,transport,
                webauthn,window,x509}.rs

crates/astra/src/
  lib.rs main.rs audit.rs chain.rs distribution.rs gateway.rs issuer.rs
  operations.rs operator.rs planner.rs reconciliation.rs recovery.rs
  registry.rs renewal.rs service.rs signing.rs

crates/astra-operator/src/
  lib.rs authority.rs campaign.rs credentials.rs documents.rs gestures.rs
  handoff.rs origin.rs orion.rs prepared.rs store.rs tunnel.rs vault.rs
  operations.rs operations/{campaign,recovery}.rs

crates/helios-tpm/src/
  lib.rs blob_store.rs boot_controller.rs escrow.rs keystore.rs provisioning.rs
  reseal_ticket.rs secret.rs settings.rs tpm_interface.rs tpm_real.rs
  update_window.rs

crates/helios-api/src/
  lib.rs auth.rs certificates.rs embed.rs health.rs internal.rs
  key_negotiation.rs provision.rs routes.rs speedtest.rs update.rs ws.rs

crates/helios-fido/src/
  lib.rs authenticator.rs authenticator/webauthn.rs

crates/helios-firewall/src/
  lib.rs ruleset.rs netlink.rs dryrun.rs

crates/helios-key-negotiation/src/  lib.rs
crates/helios-provisioning/src/     lib.rs admission.rs certificates.rs ipam.rs rotation.rs session.rs
crates/helios-update/src/           lib.rs bundle.rs
crates/helios-vault/src/            lib.rs
crates/helios-wireguard/src/        lib.rs kernel.rs dryrun.rs

crates/heliosd/src/
  main.rs astra_channel.rs certificates.rs gateway_key.rs gateway_rotation.rs
  key_negotiation.rs orchestrator.rs static_psk.rs uplink.rs vip_routing.rs

crates/orion-core/src/
  lib.rs backend/{mod,wireguard,dryrun}.rs
  vault/{mod,settings,passphrase,keys,registry,store,manifest,codec}.rs
  vault/windows/{mod,dpapi,dumps,tpm,bitlocker,prompt}.rs
  certificate_actions.rs certificate_approval.rs certificate_inventory.rs
  certificate_recovery.rs certificate_renewal.rs certificates.rs config.rs
  events.rs identity_store.rs key_negotiation.rs mtu.rs net_pin.rs
  operator_pending.rs profile_import.rs provisioning.rs speedtest.rs
  telemetry.rs test_domain.rs trust_update.rs

tools/astra-signer/src/             main.rs
tools/helios-astra-helper/src/      main.rs owner.rs session.rs
tools/helios-ctl/src/               main.rs api.rs app_update.rs campaign.rs
                                    campaign_key_nego.rs enroll.rs escrow.rs
                                    files.rs key_nego.rs peer.rs profile.rs update.rs
tools/helios-installer/src/         main.rs
tools/helios-publisher/src/         main.rs
tools/xtask/src/                    lib.rs main.rs orion_deps.rs orion_helper.rs

apps/orion/src-tauri/src/           main.rs astra.rs companion.rs deelevate.rs
                                    operator.rs tray.rs
```

`fuzz/` possède son propre workspace hors du workspace racine ; ses harnesses
restent rattachés aux capacités qu’ils testent dans `aether` et ne constituent
pas une crate runtime supplémentaire.

### Tableau de synthèse

| Crate | Fichier | Taille totale (avant tests + tests) | Responsabilités détectées | Problème | Action | Priorité |
| --- | --- | ---: | --- | --- | --- | --- |
| `aether` | `src/certificates/state.rs` | 3 353 (2 078 + 1 275) | agrégats gateway/client/Astra, transitions et ledger de confiance | plusieurs agrégats bornés partagent un fichier ; aucune I/O de persistance | `SPLIT` | moyenne |
| `aether` | `src/certificates/status.rs` | 3 021 (1 465 + 1 556) | statut certificat, campagnes, échanges signer et rollback | plusieurs familles de contrats wire distinctes | `SPLIT` | haute |
| `aether` | `src/certificates/client.rs` | 2 806 (1 870 + 936) | rotation, staging, commit et recovery client | plusieurs étapes du lifecycle client, fortement liées | `SPLIT` | moyenne |
| `aether` | `src/certificates/approval.rs` | 2 546 (1 540 + 1 006) | policy, credentials et preuves d’approbation | trois capacités de contrat identifiables | `SPLIT` | moyenne |
| `aether` | `src/key_negotiation.rs` | 2 617 (1 523 + 1 094) | messages v5, authentification, dérivation et validation | wire types et opérations crypto réunis | `SPLIT` | haute |
| `astra` | `src/registry.rs` | 3 363 (1 488 + 1 875) | registre autoritatif, audit, transitions et persistance | majorité de tests ; conserver les mutations atomiques ensemble | `SPLIT` | moyenne |
| `astra` | `src/main.rs` | 2 491 (sans module de tests inline) | CLI, bootstrap, canaux, commandes et lifecycle | composition root trop chargé | `SPLIT` | haute |
| `astra-operator` | `src/authority.rs` | 1 733 (sans module de tests inline) | gestes de signature de l’autorité | fichier long mais cohérent ; nom actuel peu précis | `RENAME` | basse |
| `astra-operator` | `src/vault.rs` | 1 622 (994 + 628) | slots, ouverture et opérations du coffre | capacité cohérente, corpus de tests important | `KEEP` | basse |
| `helios-tpm` | `src/boot_controller.rs` | 884 | décisions de boot et état de démarrage | machine de décision cohérente | `KEEP` | basse |
| `helios-tpm` | `src/tpm_real.rs` | 777 | adaptation `tss-esapi` | backend externe clairement identifiable | `MOVE` | moyenne |
| `helio-tpm` | `src/escrow.rs` | 344 | HESC, X25519/AEAD et séquestre opérateur | responsabilité sans dépendance TPM | `MOVE` | haute |
| `helios-api` | `src/internal.rs` | 2 255 (1 666 + 589) | canal Astra, TLS/ALPN, clients, serveur et contrats privés | reverse dependency et frontière protocolaire autonome | `MOVE` | très haute |
| `helios-api` | `src/certificates.rs` | 1 746 (1 221 + 525) | vues HTTP, traits handlers et routes certificat | plusieurs capacités API, pas logique de registre | `SPLIT` | haute |
| `helios-api` | `src/routes.rs` | 1 105 (847 + 258) | DTO et routes status/network/peer/firewall/trust | plusieurs ressources HTTP indépendantes | `SPLIT` | moyenne |
| `helios-fido` | `src/authenticator.rs` | 1 032 (925 + 107) | contrat Authenticator et backends CTAP/plateforme | frontière matériel cohérente, WebAuthn déjà séparé | `KEEP` | basse |
| `helios-firewall` | `src/ruleset.rs` | 1 865 (987 + 878) | IR structurée et compilation d’une policy en ruleset | production cohérente ; près de la moitié du fichier est du test | `KEEP` | basse |
| `helios-key-negotiation` | `src/lib.rs` | 2 705 (1 688 + 1 017) | QUIC/TLS, serveur/client, limites, transaction et rollback | transport et lifecycle ont des seams réels | `SPLIT` | haute |
| `helios-provisioning` | `src/certificates.rs` | 4 373 (1 688 + 2 685) | registre gateway atomique et tests de toutes ses transitions | tests majoritaires ; ne pas disperser le sérialiseur des mutations | `SPLIT` | haute |
| `helios-update` | `src/lib.rs` | 833 (657 + 176) | store, vérification, staging et activation atomique | capacité compacte et cohérente | `KEEP` | basse |
| `helios-vault` | `src/lib.rs` | 1 128 (578 + 550) | format HVLT, KDF, seal/open et lecture bornée | format et crypto étroitement liés ; moitié de tests | `KEEP` | basse |
| `helios-wireguard` | `src/lib.rs` | 261 | types interface/peer et trait backend | petite surface cohérente | `KEEP` | basse |
| `heliosd` | `src/main.rs` | 2 464 (2 129 + 335) | CLI, bootstrap, commandes et lifecycle process | composition root et implémentation mélangés | `SPLIT` | très haute |
| `heliosd` | `src/key_negotiation.rs` | 4 076 (2 614 + 1 462) | transactions PSK et identité de service négociation | deux capacités de sécurité distinctes dans un fichier | `SPLIT` | très haute |
| `heliosd` | `src/certificates.rs` | 2 681 (1 593 + 1 088) | service gateway, admission, canal Astra et projections API | plusieurs adaptateurs autour du registre | `SPLIT` | haute |
| `heliosd` | `src/orchestrator.rs` | 1 912 (1 415 + 497) | data plane, commandes, reload, télémétrie, probes et lifecycle | plusieurs boucles/runtime sans propriétaire local clair | `SPLIT` | très haute |
| `orion-core` | `src/certificate_renewal.rs` | 2 721 (1 672 + 1 049) | trust store local et session HTTP de renewal | persistance locale et protocole client séparables | `SPLIT` | haute |
| `orion-core` | `src/profile_import.rs` | 2 702 (1 283 + 1 419) | JSON Orion, wg-quick, validation et complétion | tests majoritaires ; seams naturels par format | `SPLIT` | moyenne |
| `orion-core` | `src/speedtest.rs` | 2 190 (1 727 + 463) | moteurs HTTP, TCP brut, UDP brut et métriques | transports indépendants réunis | `SPLIT` | haute |
| `orion-core` | `src/backend/mod.rs` | 1 620 (1 019 + 601) | contrat backend et contrôleur VPN | façade publique et orchestration client réunies | `SPLIT` | moyenne |
| `orion` Tauri | `src/main.rs` | 3 725 (3 088 + 637) | état UI, commandes, certificats, profils, logs et lifecycle | shell Tauri utilisé comme service applicatif | `SPLIT` | très haute |
| `astra-signer` | `src/main.rs` | 3 991 (3 931 + 60) | commandes, cérémonies, vault, signatures et transport | vrai monolithe de binaire | `SPLIT` | haute |
| `helios-ctl` | `src/main.rs` | 1 325 (1 131 + 194) | dispatch CLI, affichage et suivi WebSocket | commandes métier déjà en modules ; extraire seulement le monitoring | `SPLIT` | basse |
| `xtask` | `src/main.rs` | 946 (624 + 322) | dispatch build/package et tests | taille de production modérée, support déjà séparé | `KEEP` | basse |
| `helios-astra-helper` | `src/main.rs` | 627 | protocole interactif et composition helper | cohésion acceptable avec modules voisins | `KEEP` | basse |
| `helios-publisher` | `src/main.rs` | 570 | CLI release, validation et signature | outil cohérent | `KEEP` | basse |
| `helios-installer` | `src/main.rs` | 422 | installation, activation et rollback | workflow privilégié cohérent | `KEEP` | basse |

### Arbres cibles par crate

#### Aether

`aether` doit d’abord être réorganisée en modules. Son fan-in élevé et le
couplage des invariants de certificats ne justifient pas une multiplication de
crates. Les extractions concernent les gros fichiers du sous-dossier
certificats et le contrat de négociation, sans déplacer les types à travers
des crates tant que leur ownership n’est pas prouvé.

```text
crates/aether/src/
  lib.rs
  certificates/
    mod.rs
    encoding.rs              encodage, fingerprint et X.509
    x509.rs
    capability.rs
    window.rs
    authority.rs             autorité, émission et délégation
    client/
      mod.rs
      rotation.rs
      staging.rs
      recovery.rs
    approval/
      mod.rs
      policy.rs
      credentials.rs
      renewal.rs
      recovery.rs
    state/
      mod.rs
      gateway.rs
      client.rs
      astra.rs
      ledger.rs
    status/
      mod.rs
      certificate.rs
      campaign.rs
      signer_exchange.rs
      rollback.rs
    revocation.rs            révocation et états associés
    transport.rs             contrats de transport et vues signées
    gateway.rs
    operator_ipc.rs
    operator_session.rs
    webauthn.rs
  key_negotiation/
    mod.rs
    messages.rs              wire types v5
    authentication.rs        bytes canoniques et signatures
    derivation.rs            dérivation et commitments PSK
  config.rs
  enroll.rs
  events.rs
  policy.rs
  pq.rs
  random.rs
  secret.rs
  sig.rs
  state.rs
  wg.rs
```

Les dossiers proposés correspondent à des familles déjà visibles dans les
types, pas à des couches génériques. Le split de `state.rs` doit conserver les
opérations du `TrustLedger` et chaque agrégat borné dans un même fichier ; il
ne doit pas séparer données et transitions. `lib.rs` conserve les modules
publics et les réexports canoniques. Les helpers et fixtures restent privés ou
`pub(crate)`. Les tests peuvent suivre les sous-modules, tandis que les golden
files et vecteurs restent des tests d’intégration Aether.

#### Astra et opérateur

`registry.rs` est moins monolithique que sa taille brute ne le suggère :
1 875 de ses 3 363 lignes appartiennent à son corpus de tests. Les mutations,
l’audit et la persistance forment une transaction autoritative et doivent
rester ensemble dans un premier temps. La première séparation concerne les
tests par comportement et le `ChallengeStore`, puis seulement les commandes du
binaire Astra.

```text
crates/astra/src/
  lib.rs
  registry.rs                état, mutations atomiques, audit et persistance
  registry/
    challenge.rs
    tests/
      mod.rs
      peers.rs
      rotations.rs
      trust_updates.rs
      migration.rs
  issuer.rs
  distribution.rs
  operations.rs
  renewal.rs
  reconciliation.rs
  recovery.rs
  service.rs
  main.rs                    composition process
  cli.rs
  commands/
    mod.rs
    bootstrap.rs
    campaign.rs
    chain.rs
    gateway_identity.rs
    issuer.rs
    revocation.rs

crates/astra-operator/src/
  lib.rs
  signing.rs                 renommage de authority.rs : gestes CA-PQ/CA-TLS
  campaign.rs
  credentials.rs
  documents.rs
  gestures.rs
  handoff.rs
  operations/
    mod.rs
    recovery.rs
    rotation.rs
  origin.rs
  prepared.rs
  store.rs
  tunnel.rs
  vault.rs
```

`authority.rs` ne doit pas être éclaté par couches techniques : sa cohésion est
la séquence des gestes qui utilisent les ancres. Le nom `signing.rs` décrit
mieux cette responsabilité. Les tests de campagne, de coffre et de transport
restent avec leurs modules ; les tests de bout en bout de l’autorité restent
sous `crates/astra/tests/`.

#### Firewall et WireGuard

`helios-firewall` constitue déjà une bonne frontière Cargo. Créer une
hiérarchie `policy/model/validation/compiler` serait excessif : la policy
canonique appartient à Aether, et les 987 lignes de production de
`ruleset.rs` forment un compilateur cohérent vers une IR structurée. Le gain
immédiat est de sortir son important corpus de tests et de regrouper les
backends, sans casser l’atomicité du ruleset. Le trait `FirewallBackend` reste
la frontière d’exécution.

```text
crates/helios-firewall/src/
  lib.rs
  ruleset.rs                 IR et compilation depuis FirewallPolicy
  ruleset/
    tests.rs
  backend/
    mod.rs
    netlink.rs               adaptation rustables/libnftables
    dryrun.rs

crates/helios-wireguard/src/
  lib.rs
  backend/
    mod.rs
    kernel.rs
    dryrun.rs
```

Le fichier `helios-wireguard/src/lib.rs` reste `KEEP` : ses 261 lignes forment
une petite surface publique de types et trait backend. Seul le rangement
physique des backends est proposé. Les tests de ruleset restent indépendants
de Linux ; les tests Netlink, noyau et dry-run sont séparés et conditionnés.

#### TPM, escrow, FIDO, vault et update

Ces crates sont des frontières de sécurité. Le découpage préserve une surface
réduite et ne doit jamais faire circuler de clé privée ou de plaintext dans des
modules de lecture génériques.

```text
crates/helios-tpm/src/
  lib.rs
  boot_controller.rs
  tpm_interface.rs            contrats TPM
  backend/
    mod.rs
    real.rs                   adaptation tss-esapi
  keystore.rs
  update_window.rs
  provisioning.rs
  reseal_ticket.rs
  secret.rs
  settings.rs

crates/helios-escrow/src/
  lib.rs                     HESC, X25519/AEAD et enveloppe ; 344 lignes

crates/aether-fido/src/
  lib.rs
  authenticator.rs           contrat et backend CTAP HID
  authenticator/webauthn.rs  backend Windows WebAuthn

crates/aether-vault/src/
  lib.rs                     HVLT, KDF, seal/open et lecture bornée

crates/helios-update/src/
  lib.rs
  bundle.rs
```

Ne pas créer de splits `format.rs`/`crypto.rs`/`file.rs` pour escrow et vault :
ils produiraient de petits fichiers tout en séparant les invariants du format
de leur authentification. Même conclusion pour `helios-update`, dont les 657
lignes de production forment un workflow atomique cohérent. Le nom
`aether-fido` reste conditionnel : si CTAP HID est
seulement un backend de plateforme, il faut un nom neutre de capacité plutôt
que faire croire qu’Aether possède l’adaptateur. Dans tous les cas, Orion ne
dépend pas d’un package `helios-fido`.

#### API et provisioning

Après extraction du canal Astra, `helios-api` devient une façade de transport
et de projection. Les modèles persistants, contrats signés et DTO HTTP restent
distincts.

```text
crates/helios-api/src/
  lib.rs                      AppState et surface router
  auth.rs
  health.rs
  routes/
    mod.rs
    status.rs
    peers.rs
    network.rs
    firewall.rs
    commands.rs
  certificates/
    mod.rs
    views.rs
    gateway_identity.rs
    renewal.rs
    trust_update.rs
    operator_relay.rs
  provision.rs
  key_negotiation.rs
  speedtest.rs
  update.rs
  ws.rs

crates/helios-provisioning/src/
  lib.rs
  admission.rs
  ipam.rs
  session.rs
  rotation.rs
  certificates.rs             registre et sérialiseur des mutations
  certificates/tests/
    mod.rs
    fixtures.rs
    staging.rs
    distribution.rs
    trust_transitions.rs
    persistence.rs
```

Le registre de certificats reste une machine à états cohérente. Ses 1 688
lignes de production partagent volontairement un seul sérialiseur : staging,
commit, promotion et purge calculent un état candidat, le persistent, puis
l’adoptent. Les disperser par opération affaiblirait la lecture de cet
invariant. Le premier découpage porte donc sur les 2 685 lignes de tests,
classées par comportement. L’extraction vers `helios-trust` reste une décision
de crate séparée.

#### Négociation

La crate protocolaire conserve une seule frontière Cargo, mais son fichier
unique doit distinguer contrat, transport, session et lifecycle.

```text
crates/aether-key-negotiation/src/      après renommage éventuel
  lib.rs
  identity.rs                identité TLS et empreintes
  endpoint.rs                endpoints QUIC et paramètres transport
  framing.rs                 framing JSON privé, borné et inchangé
  server.rs                  transaction servie et préparation du matériau
  client.rs                  ClientSession et PendingChallenge
  transaction.rs             deadline, commit et rollback cancellation-safe
  rate_limit.rs
  error.rs                   contrat d'erreur transversal client/serveur
  tests/
    mod.rs
    fixtures.rs
    limits.rs
    material.rs
    protocol.rs
    rollback.rs
    transport.rs
```

Les messages v5, signatures et dérivations restent dans Aether : la crate
actuelle les importe déjà depuis `aether::key_negotiation`. Il ne faut donc pas
recréer ici des fichiers `types`, `validation` ou `crypto` qui dupliqueraient
cette ownership. `error.rs` est une exception locale justifiée : `PublicError`
et `TransportError` forment le contrat transversal déjà consommé par les chemins
client et serveur ; ce n'est ni une crate d'erreurs ni un nouveau format. La
crate de transport porte TLS/QUIC, client, serveur, limites réseau et rollback.
Les tests QUIC internes restent dans cette crate. Les tests d'interopérabilité
réelle Helios/Orion sont actuellement dans `heliosd/src/key_negotiation.rs` ;
leur extraction est une migration séparée nécessaire pour retirer la dépendance
dev `heliosd -> orion-core`.

#### `heliosd`

`heliosd` est le point principal de mélange entre application et sous-système.
La priorité est de rendre visibles les blocs qui appartiennent déjà aux
crates gateway, puis de laisser `main.rs` exprimer le workflow de démarrage et
d’arrêt.

```text
crates/heliosd/src/
  main.rs                     dispatch et lancement du process
  cli.rs                      types clap
  commands/
    mod.rs
    tpm.rs
    identity.rs
    trust.rs
    peer.rs
  bootstrap.rs               configuration, préflight et construction
  key_negotiation/
    mod.rs
    transaction.rs            ownership PSK, handshake, commit et rollback
    identity.rs               identité TLS/PQ servie et stockage scellé
    server.rs                 endpoint et reclaimer
    tests/
      mod.rs
      transaction.rs
      identity.rs
      interop.rs
  certificates/
    mod.rs
    service.rs                orchestration autour du registre
    admission.rs              inbox et première génération
    astra.rs                  adaptation du canal privé
    views.rs                  projections API sans secrets
  orchestrator/
    mod.rs
    data_plane.rs             WireGuard, firewall et kill-switch
    commands.rs               commandes de l’orchestrateur
    reload.rs                 hot reload de network.toml
    observation.rs            handshakes et transitions peers
    probes.rs                 captive portal et MTU
    telemetry.rs
  gateway_key.rs
  gateway_rotation.rs
  static_psk.rs
  uplink.rs
  vip_routing.rs
  astra_channel.rs
```

`main.rs` ne doit pas parser des certificats, ouvrir le vault, configurer
WireGuard ou compiler le firewall. Le split de `key_negotiation.rs` suit ses
deux responsabilités observées — transaction PSK et identité servie — plutôt
que des couches abstraites admission/installation/observation. Celui de
`orchestrator.rs` suit les boucles réellement présentes : data plane,
commandes, reload, observation, probes et télémétrie. Ces modules restent dans
`heliosd` tant qu’un propriétaire de sous-système ou un second runtime n’est
pas démontré.

#### `orion-core` et Tauri

`orion-core` contient plusieurs capacités client légitimes, mais les gros
workflows doivent être organisés en dossiers. Il ne doit dépendre ni du
serveur ni de Tauri.

```text
crates/orion-core/src/
  lib.rs
  backend/
    mod.rs                     VpnBackend et sélection du backend
    controller.rs              VpnController et lifecycle client
    wireguard.rs
    dryrun.rs
  certificates/
    mod.rs
    inventory.rs
    actions.rs
    renewal.rs                 protocole et session de renouvellement
    trust_store.rs             seed, promotion et rollback locaux
    recovery.rs
    approval.rs
  config.rs
  identity_store.rs
  provisioning.rs
  profile_import/
    mod.rs
    json.rs
    wg_quick.rs
    validation.rs
  vault/
    mod.rs
    codec.rs
    keys.rs
    manifest.rs
    passphrase.rs
    registry.rs
    settings.rs
    store.rs
    windows/
      mod.rs
      bitlocker.rs
      dpapi.rs
      dumps.rs
      prompt.rs
      tpm.rs
  speedtest/
    mod.rs
    http.rs
    raw_tcp.rs
    raw_udp.rs
    metrics.rs
  telemetry.rs
  events.rs

apps/orion/src-tauri/src/
  main.rs                     composition Tauri et lifecycle
  state.rs                    état applicatif et synchronisation
  commands/
    mod.rs
    certificates.rs
    profiles.rs
    provisioning.rs
    recovery.rs
  views.rs                    projections sûres pour le frontend
  events.rs                   émission vers React
  platform/
    mod.rs
    deelevate.rs
    companion.rs
  tray.rs
  logging.rs
  astra.rs
  operator.rs
```

Les splits suivent les seams observés : trust store versus session HTTP pour
le renouvellement, JSON versus `wg-quick` pour l’import, HTTP versus TCP/UDP
bruts pour le speedtest, et contrôleur versus backend WireGuard. La structure
`vault/` existante est conservée : elle est déjà organisée par capacité et par
plateforme. Les commandes Tauri valident l’entrée, appellent `orion-core` et
convertissent le résultat en projection UI. Les tests de workflow client
restent dans `orion-core` ; les tests Tauri couvrent l’adaptation de commande,
d’état et d’événement.

#### Outils et tests

Les petits packages `helios-installer`, `helios-publisher` et
`helios-astra-helper` restent en fichiers courts. Les outils plus grands
peuvent suivre cette organisation sans devenir de nouvelles crates :

```text
tools/astra-signer/src/
  main.rs
  commands/
    mod.rs
    vault.rs                  init, enrol, verify, list, remove
    issuer.rs                 émission CA-TLS et délégation
    campaign.rs               approbation et dépôt de résultats
    gateway_identity.rs       bootstrap, transition, abort et rollback
    recovery.rs
    ca_rotation.rs

tools/helios-ctl/src/
  main.rs                     CLI, dispatch et rendu court
  monitor.rs                  suivi WebSocket et rendu des événements
  api.rs
  app_update.rs
  campaign.rs
  campaign_key_negotiation.rs
  enroll.rs
  escrow.rs
  files.rs
  key_negotiation.rs
  peer.rs
  profile.rs
  update.rs

tools/xtask/src/
  main.rs
  orion_deps.rs
  orion_helper.rs
```

`astra-signer` est le seul de ces outils où le split de production est
prioritaire : 3 931 lignes couvrent plusieurs cérémonies distinctes. Le nom de
chaque fichier cible correspond à une commande ou une famille de décisions de
sécurité. `helios-ctl` conserve ses modules actuels et extrait seulement le
monitoring encore présent dans `main.rs`; les abréviations `key_nego` sont
renommées pour rendre la navigation explicite. `xtask` reste inchangé tant que
ses 624 lignes de production restent un dispatch cohérent.

Les tests inline restent adaptés aux invariants locaux. Les tests de protocole,
interopérabilité, persistance et backend peuvent être séparés en fichiers
d’intégration nommés par comportement, plutôt qu’en un unique `tests.rs`.
Les tests nécessitant root, Netlink, WireGuard, TPM ou une plateforme restent
explicitement conditionnés et documentés selon `docs/testing/TESTING.md`.

### Visibilité et API à contrôler

La visibilité n’est pas uniformément mauvaise. Les constats précis sont :

| Crate | Surface observée | Recommandation |
| --- | --- | --- |
| `aether` | nombreux modules publics et réexports racine de contrats | conserver les contrats canoniques ; rendre privés les helpers issus des splits sans ajouter de nouveaux réexports globaux |
| `astra` | modules métier publics utilisés par son binaire et l’opérateur | retirer d’abord la dépendance `astra-operator -> astra` pour les DTO, puis réduire seulement les modules sans consommateur |
| `astra-operator` | réexport de `helios_fido::authenticator` et de contrats Astra | faire dépendre les consommateurs du propriétaire réel ; ne pas utiliser la façade opérateur pour masquer deux autres crates |
| `helios-tpm` | backend et stockage principalement privés, API racine explicite | conserver ce modèle ; l’extraction d’escrow retire son seul module public hors TPM |
| `helios-api` | `pub mod internal` expose canal, TLS, clients et contrats à Astra | supprimer ce module public après extraction vers `astra-channel` |
| `helios-firewall` | backend privé, types utiles réexportés à la racine | surface correcte ; les futurs sous-modules de backend restent privés |
| `helios-key-negotiation` | API publique directement dans `lib.rs` | garder les futurs modules privés et réexporter uniquement endpoints, sessions et traits réellement consommés |
| `helios-provisioning` | modules domaine publics, réexports partiels à la racine | conserver `certificates` nommé tant que son registre est consommé comme sous-système ; éviter un deuxième chemin réexporté pour chaque type |
| `helios-vault` / `helios-update` / `helios-wireguard` | surfaces racine compactes | pas de réduction motivée par la taille |
| `orion-core` | nombreux `pub mod` et réexports racine utilisés par Tauri/outils | définir la façade client attendue, migrer les consommateurs, puis rendre privés les modules de workflow et backends concrets |
| binaires et outils | modules privés par défaut | conserver ; les splits de `main.rs` ne nécessitent aucun `pub` externe |

Chaque découpage retenu inclut ensuite une passe de visibilité :

- supprimer les `pub mod` utilisés uniquement par des consommateurs internes ;
- préférer `mod` ou `pub(crate)` lorsque le contrat ne sort pas de la crate ;
- réduire les réexports de `lib.rs` à une façade intentionnelle ;
- séparer projections API, vues UI, modèles persistants et contrats signés ;
- vérifier `Debug`, sérialisation, logs et méthodes de lecture pour éviter toute
  exposition de secret ;
- ajouter un test lorsque la réduction de visibilité est une garantie
  importante.

Le critère final est la localité du changement : modifier l’admission, le
firewall, la rotation de certificats ou le backend Windows doit conduire à un
dossier fonctionnel et à ses tests, sans traverser plusieurs répertoires
techniques génériques.

## Recommended first migration

La plus petite modification au meilleur rapport bénéfice/risque est une
clarification du workspace Cargo, sans déplacement de code : remplacer
uniquement `members` par les patterns couvrant les emplacements canoniques,
conserver la liste `default-members` actuelle et ajouter un contrôle qui exige
toujours Orion/Tauri dans le build par défaut.

```toml
members = ["crates/*", "tools/*", "apps/orion/src-tauri"]
```

La liste explicite `default-members` reste inchangée : elle inclut Orion et
exclut volontairement `helios-publisher` du build par défaut.

> **État : DONE.** `Cargo.toml` porte les patterns et la liste explicite
> `default-members`. La suite décrite ci-dessous — canal Astra, trust registry,
> escrow, `helios-runtime` — a depuis été traitée ou tranchée : voir §13.

Utiliser les mêmes wildcards dans `default-members` n’est pas équivalent : cela
ajouterait `helios-publisher` au build par défaut et modifierait le périmètre de
validation. Cette variation n’apporte pas de bénéfice architectural suffisant
pour être glissée dans un nettoyage de manifest.

Cette étape est limitée au manifest, ne touche aucun contrat externe et produit
un diff facilement réversible. Elle doit être livrée seule puis relue et
validée avant toute extraction du canal Astra, du trust registry, de l’escrow,
ou toute tentative de création de `helios-runtime`.
