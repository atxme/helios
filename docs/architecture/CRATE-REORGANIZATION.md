# Audit et proposition de réorganisation des crates

> Document d'audit préalable. Aucune migration de code n'a été effectuée pour
> produire ce document. Les propositions ci-dessous restent soumises à revue.

## Périmètre et méthode

L'audit porte sur le workspace Cargo racine, ses 21 packages, les sources
Rust, les features, les réexports, les tests et les dépendances spécifiques
aux plateformes. Le workspace `fuzz/` est un workspace imbriqué distinct et
reste hors du graphe Cargo racine.

Sources consultées :

- `Cargo.toml` racine et chaque `Cargo.toml` de `crates/`, `tools/` et
  `apps/orion/src-tauri` ;
- `cargo metadata --format-version 1` pour le graphe réellement résolu ;
- les `src/lib.rs`, `src/main.rs` et les principaux modules de chaque package ;
- les ADR 001 à 008, la spécification de négociation v5 et la spécification de
  rotation des certificats ;
- `docs/ARCHITECTURE.md`, `docs/architecture/overview.md` et
  `docs/testing/TESTING.md` ;
- les workflows `.github/workflows/regression.yml` et `release.yml`.

Les métriques de fan-in et fan-out ci-dessous sont des degrés directs entre
packages internes. Une arête `dev` ou `build` est indiquée explicitement quand
elle a une portée architecturale différente d'une dépendance normale.

## 1. Architecture actuelle

Le dépôt contient quatre catégories qui ne sont pas encore matérialisées par
des répertoires distincts :

1. le socle partagé `aether` ;
2. les sous-systèmes de la gateway (`astra`, API, firewall, WireGuard,
   provisioning, négociation, coffre, TPM, mises à jour) ;
3. la logique cliente portable `orion-core` et le shell Tauri ;
4. les programmes de composition, d'exploitation, de signature et de build.

L'organisation fonctionnelle est déjà reconnaissable, mais l'organisation
Cargo laisse trois frontières moins nettes :

- `helios-api` porte à la fois l'API gateway et un canal privé Astra–Helios ;
- `helios-provisioning` porte l'admission/IPAM et une importante partie du
  registre de certificats gateway ;
- `helio-tpm` mélange le support matériel TPM de la gateway et l'enveloppe de
  séquestre opérateur.

`heliosd` est un binaire de composition, mais ses modules contiennent encore
une partie importante du comportement applicatif : négociation, certificats,
rotation Astra, PSK statiques, uplinks et routage VIP. Son fan-out est donc
élevé, sans que cela constitue à lui seul une preuve qu'une nouvelle crate est
nécessaire.

Le chemin d'exécution principal est :

```text
Orion/Tauri -> orion-core -> négociation QUIC/mTLS -> heliosd
                                                   -> provisioning
                                                   -> WireGuard
                                                   -> firewall
                                                   -> API/WebSocket/UI
                                                   -> Astra / TPM / vault / update
```

Cette vue est fonctionnellement correcte, mais elle ne montre pas que `astra`
utilise aujourd'hui `helios-api` pour son canal privé, ni que
`helios-wireguard` utilise le trait d'IPAM défini par `helios-provisioning`.

### Aether

`aether` est devenu un socle très large : environ 30 500 lignes Rust, dont
environ 21 000 dans `certificates/`. Il contient notamment :

- configuration, état de tunnel, événements, politiques firewall et types
  WireGuard ;
- contrats de négociation de clé v5, PQ, X25519 et secret ;
- génération aléatoire centralisée, signatures éditeur et signatures de
  négociation ;
- contrats X.509, certificats client/gateway, autorité, révocation, statut,
  approbation, transport et fenêtre de mise à jour ;
- quelques utilitaires partagés comme fichiers privés, verrouillage, temps et
  speedtest.

Les réexports de `aether/src/lib.rs` rendent directement visibles la
configuration, les erreurs, les événements, les politiques, les types PQ, les
secrets, le speedtest et l'état de tunnel. Les certificats restent plutôt
accessibles par leurs sous-modules, ce qui limite partiellement la façade.

Le constat n'est pas « une crate par thème ». `certificates/` forme un
ensemble de contrats de confiance et de sécurité cohérent, partagé par Astra,
la gateway, Orion et les outils. Cependant `aether` est le principal candidat
à l'appellation de *god crate* potentiel : son fan-in est de 17 et il réunit
contrats, implémentations cryptographiques et quelques fonctions d'exécution.
Son découpage immédiat créerait plusieurs problèmes : dépendances croisées
entre certificats, négociation, RNG et signatures ; réexports cassés ; et
risque de séparer des invariants de sécurité. La bonne décision à court terme
est de le conserver, tout en réduisant les nouveaux ajouts et en isolant les
responsabilités par modules avant toute extraction.

Un écart documentaire est à noter : `docs/ARCHITECTURE.md` décrit encore le
cycle de vie des certificats comme non implémenté, alors que le code actuel
contient Astra, les registres, les rotations et leurs tests. Pour l'état
présent, le code, les tests et les ADR/spécifications acceptées sont plus
probants. La mise à jour de cette documentation générale devra être une étape
distincte.

### Helios et Orion

`orion-core` est une crate cliente portable de grande taille, environ 25 700
lignes. Elle regroupe configuration/profils, admission, négociation, backend
VPN, identité, coffre client, certificats, renouvellement, récupération,
télémétrie et speedtest. Cette largeur est cohérente avec le rôle de logique
cliente portable ; elle ne justifie pas encore des crates séparées, car la
crate a une frontière de cycle de vie et trois consommateurs distincts : le
shell Orion, `helios-ctl` et les tests d'interopérabilité de `heliosd`.

La dépendance suspecte `heliosd -> orion-core` n'est pas une dépendance de
production. Elle se trouve dans `[dev-dependencies]` et sert à faire dialoguer
le vrai client avec le vrai serveur pour vérifier la dérivation de PSK et le
handshake. L'intention de test est légitime et explicitement documentée dans
l'ADR de négociation, mais la présence du lien dans le package gateway rend la
frontière moins lisible. À terme, ce test doit vivre dans un harnais
d'interopérabilité indépendant ou dans un package d'intégration ; il ne faut
pas extraire du code client dans Helios pour supprimer artificiellement ce
lien.

### Astra

`astra` est un sous-système réel : registre, autorité, chaîne d'audit,
opérations, renouvellement, récupération, distribution, réconciliation et
service. Le package fournit à la fois une bibliothèque et le binaire Astra,
qui peut rester un composition root du sous-système.

`astra-operator` est également une frontière de sécurité réelle : coffre
opérateur, FIDO, gestes d'approbation, opérations hors ligne et origines
client/tunnel. Il dépend toutefois de `astra` uniquement pour des vues d'état
d'opération et une demande de délégation d'émetteur. Ce sont des contrats qui
ne devraient pas imposer la dépendance à l'implémentation du service Astra.

`astra-signer` et `helios-astra-helper` sont des programmes séparés, avec des
cycles de vie et des privilèges différents. Ils ne sont pas des couches
internes à transformer en crates de bibliothèque générales.

### Firewall, WireGuard et sécurité

`helios-firewall` possède une frontière claire. Sa policy, son IR, sa
validation, sa compilation, son backend dry-run et son backend Netlink restent
des modules d'une seule crate. La feature `netlink` active l'implémentation
Linux sans imposer plusieurs crates artificielles.

`helios-wireguard` possède de même une frontière de plan de données claire :
trait backend, état, pairs, interface, dry-run et backend réel. Son unique
dépendance interne normale est `helios-provisioning`, car la table d'adresses
des pairs implémente le trait `PeerTable` défini par l'IPAM. C'est une petite
arête de contrat à surveiller, pas un cycle ni une raison suffisante pour
scinder le firewall ou WireGuard.

Les crates `helios-vault`, `helios-fido`, `helio-tpm` et
`helios-key-negotiation` sont toutes des frontières de sécurité ou de
protocole plausibles. Elles n'ont pas le même rôle :

- `helios-vault` possède le format de conteneur AEAD et son cycle seal/open ;
- `helios-fido` possède l'interaction avec l'authentificateur matériel et les
  APIs WebAuthn ;
- `helio-tpm` possède le scellement, les fenêtres de mise à jour et les états
  TPM, mais aussi le séquestre opérateur ;
- `helios-key-negotiation` possède le protocole QUIC/mTLS v5 et ses contrats de
  transport.

Ces frontières doivent être conservées. Le seul mélange suffisamment net pour
justifier une évolution est la séparation TPM/séquestre.

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

`astra`, `astra-operator`, `astra-signer` et `helios-astra-helper` composent
le sous-système Astra et ses opérateurs ; les outils restent des feuilles du
graphe. `heliosd` possède le plus grand fan-out direct, avec 10 dépendances
internes. `aether` possède le plus grand fan-in, avec 17 consommateurs
directs.

### Dépendances dev et build

```text
heliosd [dev]
  -> orion-core

orion [build]
  -> xtask
```

Les arêtes `aether [dev]` de plusieurs crates ne changent pas le graphe
normal : elles complètent leurs fixtures. L'arête `heliosd [dev]` doit rester
visible dans les outils d'architecture même si elle ne fuit pas dans le
binaire gateway. L'arête `orion [build] -> xtask` sert à télécharger/stager
WireGuardNT et l'helper Windows ; elle ne concerne pas le runtime, mais elle
couple le build de l'application à un outil.

### Fan-in et fan-out

| Package | Fan-in direct | Fan-out direct | Observation |
| --- | ---: | ---: | --- |
| `aether` | 17 | 0 | Socle partagé et principal god crate potentiel |
| `heliosd` | 0 | 10 | Composition root, mais encore beaucoup de logique locale |
| `orion-core` | 3 | 4 | Frontière cliente portable |
| `helios-api` | 2 | 5 | Façade API et canal Astra mélangés |
| `helios-update` | 6 | 1 | Sous-système réutilisé par gateway et outils |
| `astra-operator` | 2 | 4 | Frontière opérateur, consommée par deux outils |
| `helios-provisioning` | 3 | 1 | Admission/IPAM + registre de certificats |
| `helios-fido` | 4 | 1 | Bon adaptateur matériel partagé |
| `helios-vault` | 4 | 1 | Bon conteneur de sécurité partagé |
| `helios-firewall` | 2 | 1 | Sous-système de plan de données |
| `helios-wireguard` | 2 | 1 | Sous-système de plan de données |
| Autres feuilles/outils | 0 à 2 | 0 à 3 | Rôles ciblés ou composition locale |

Il n'existe aucun cycle direct dans le graphe Cargo actuel. Les cycles
architecturaux à éviter sont plutôt des cycles de responsabilité : service
Astra qui dépend de la façade HTTP gateway, opérateur qui dépend de
l'implémentation Astra, ou logique partagée qui dépend d'un shell.

## 3. Features Cargo et plateformes

### Features observées

| Package | Features | Effet architectural |
| --- | --- | --- |
| `aether` | `fuzzing`, `key-negotiation-signing`, `publisher-signing` | Mélange de contrats communs et de capacités cryptographiques optionnelles |
| `helio-tpm` | `tpm` | Active `tss-esapi`, dépendance cible et matériel |
| `helios-api` | `embed-ui` | Fait entrer l'asset web dans la façade API |
| `helios-firewall` | `netlink` | Active le backend Linux réel |
| `helios-provisioning` | `certificate-signing` | Forward vers la signature de négociation, surtout fixtures/certificats |
| `helios-update` | `publisher-signing` | Forward vers Aether, sans usage de code correspondant dans la crate |
| `helios-wireguard` | `wireguard` | Active le backend WireGuard réel |
| `orion-core` | `certificate-signing`, `wireguard` | Signature de fixtures/certificats et backend client |
| `heliosd` | `embed-ui`, `netlink`, `tpm`, `wireguard` | Composition des choix de plateforme gateway |
| `orion` | `wireguard` | Forward vers `orion-core` |

Les features de backend sont globalement placées au bon niveau : les
applications choisissent les implémentations et les crates de sous-système les
exposent. Elles devraient toutefois être vérifiées par cible afin qu'une
feature activée sur une plateforme incompatible échoue explicitement.

Le point le plus couplant est la signature de négociation :
`key-negotiation-signing` active `fips204` et `rcgen` dans `aether`, puis est
demandée sans condition par plusieurs consommateurs runtime. C'est une
capacité distincte des signatures de release ML-DSA-65, mais son nom et son
forwarding font remonter une grande partie de la pile X.509 dans le graphe.
Une évolution ultérieure devrait distinguer plus clairement contrat de
vérification, émission de fixtures et émission runtime, sans mélanger les
domaines ML-DSA-65 et ML-DSA-87.

La feature `helios-update/publisher-signing` paraît être un forwarding
historique ou inutilisé. Elle mérite une suppression contrôlée après
confirmation des consommateurs ; elle ne doit pas être conservée comme
fausse frontière entre publisher et gateway.

### Dépendances spécifiques aux plateformes

| Zone | Dépendance | Constat |
| --- | --- | --- |
| `aether` | `libc` Linux, `windows-sys` Windows | Utilitaires de verrouillage mémoire ; la crate n'est pas sans dépendance plateforme au sens strict |
| `helios-firewall` | `rustables`, `ipnetwork` | Backend Netlink/nftables Linux dans une feature, manifest non target-gardé |
| `helios-wireguard` | `defguard_wireguard_rs` | Backend réel de plan de données, correctement optionnel mais cible à expliciter |
| `helio-tpm` | `tss-esapi` | Matériel TPM ; doit rester hors du socle partagé |
| `heliosd` | `libc` Unix | `prctl` de protection des dumps, propre à l'application gateway |
| `helios-fido` | `ctap-hid-fido2`, hidapi/libudev, WebAuthn Windows | Adaptateur matériel et OS, correctement isolé dans sa crate |
| `orion-core` | `windows`, `windows-sys` | DPAPI/CNG, WMI/COM, BitLocker, exclusion des dumps et routage client |
| `orion` | Tauri, GTK/WebKit Linux, WebView2/Win32 Windows | Shell graphique et intégrations de plateforme |
| `xtask` | WireGuardNT et APIs Windows | Support de build et packaging client, non runtime |
| `helios-astra-helper` | Win32/GDI/owner window | Processus compagnon opérateur |

La contamination la plus importante n'est pas une dépendance Windows/Linux
dans `aether`, qui reste limitée à des utilitaires ciblés ; c'est le risque de
faire remonter ces APIs dans les contrats ou les applications opposées. Les
implémentations restent aujourd'hui principalement dans des modules
conditionnels de `orion-core`, `helios-fido`, `helios-firewall`,
`helios-wireguard`, `helio-tpm` et `heliosd`.

## 4. Responsabilité actuelle et décision

| Package / application | Responsabilité observée | Décision | Justification |
| --- | --- | --- | --- |
| `aether` | Contrats partagés, états, protocole, crypto, certificats et quelques utilitaires | **KEEP** | Fan-in élevé et invariants liés ; resserrer les modules avant toute extraction |
| `astra` | Autorité/coordonateur de certificats, registre, opérations, service et binaire | **KEEP** | Sous-système cohérent avec son propre cycle de vie |
| `astra-operator` | Coffre opérateur, FIDO, gestes, approbation et opérations hors ligne | **KEEP** | Frontière de sécurité réelle ; retirer la dépendance d'implémentation à `astra` |
| `helios-firewall` | Policy, IR, validation, compilation et backends nftables/dry-run | **KEEP** | Bonne frontière ; garder les parties comme modules internes |
| `helios-update` | Bundle, vérification, staging, activation et rollback | **KEEP** | Cycle de vie et frontière de confiance indépendants |
| `helios-api` | API Axum/WebSocket/UI gateway et relais privé Astra | **SPLIT** | Séparer l'API publique du canal privé et de ses contrats TLS |
| `helio-tpm` | TPM, boot, rescellement, fenêtres d'update et séquestre | **SPLIT + RENAME** | Garder `helios-tpm` pour le matériel ; extraire `helios-escrow` |
| `helios-provisioning` | Admission, IPAM, session et registre/certificats gateway | **SPLIT** | Extraire plus tard le registre de confiance si la seam est confirmée |
| `helios-wireguard` | Interface, pairs, état et backends WireGuard | **KEEP** | Frontière de plan de données claire |
| `helios-key-negotiation` | Transport QUIC/mTLS et protocole v5 | **KEEP** | Frontière de protocole explicite et partagée |
| `helios-vault` | Conteneur AEAD HVLT et seal/open | **KEEP** | Format et sécurité indépendants |
| `helios-fido` | Authentificateurs FIDO/WebAuthn | **KEEP** | Adaptateur matériel/OS réutilisable |
| `orion-core` | Logique cliente portable et cycle de vie Orion | **KEEP** | Cohérent malgré sa taille ; aucun nouveau découpage prouvé |
| `heliosd` | Binaire gateway, lifecycle et composition des sous-systèmes | **KEEP** | Composition root actuel ; pas encore de preuve pour `helios-runtime` |
| `astra-signer` | Outil de signature et approbation opérateur | **KEEP** | Processus de confiance distinct, pas une bibliothèque de service |
| `helios-astra-helper` | Compagnon opérateur et intégration Win32 | **KEEP** | Processus et privilèges propres |
| `helios-ctl` | CLI opérateur : API, enrollment, campagnes, update, escrow | **KEEP** | Composition root d'outil ; extraire seulement du code réellement partagé |
| `helios-installer` | Helper privilégié d'installation d'update | **KEEP** | Frontière de privilège et cycle de vie indépendants |
| `helios-publisher` | Génération de clés et signature de releases/bundles | **KEEP** | Doit rester hors gateway et hors logique client |
| `xtask` | Build, téléchargement/staging WireGuardNT, packaging | **KEEP** | Outil de build ; extraire un support stable seulement si nécessaire |
| `orion` | Shell Tauri/React, IPC et intégrations desktop | **KEEP** | Application ; ses modules locaux ne justifient pas des crates |
| `fuzz` | Workspace de fuzzing libFuzzer/nightly | **KEEP** | Délibérément hors workspace racine |

Les décisions `SPLIT` sont des cibles séquencées, pas une autorisation de
créer immédiatement trois nouvelles crates. En particulier, ni les erreurs,
ni les types génériques, ni la sérialisation, ni chaque backend ne doivent
devenir des packages autonomes.

### Réexports et types à surveiller

Les réexports principaux de `aether` sont utiles pour les consommateurs, mais
ils cachent la différence entre types de domaine, contrats de transport et
types d'affichage. Les cas les plus significatifs sont :

- `helios-api::internal` réexporte des types de transport Aether et ajoute des
  vues gateway (`PeerCertificateStateView`, `GatewayIdentityView`) ;
- `helios-api::certificates` ajoute de nombreuses vues HTTP autour de contrats
  Aether ;
- `orion-core::certificate_inventory` réexporte `ValidityPhase` sous le nom
  `CertificatePhase` ;
- `astra-operator` consomme directement
  `astra::signing::{SigningOperationState, SigningOperationView}` ;
- `astra::issuer::IssuerDelegationRequest` est consommé hors de `astra`, alors
  qu'il représente un contrat de délégation ;
- plusieurs crates possèdent leurs propres `*Request`, `*Response`, `*View`.

Il ne s'agit pas d'une preuve que tous ces types sont des doublons : les DTO
HTTP et les contrats signés n'ont pas le même propriétaire. Le problème est
que les frontières ne disent pas toujours si un type est canonique, une vue
locale ou un message de transport. La migration doit commencer par une
classification et des tests de sérialisation, puis déplacer seulement les
types réellement partagés. Il faut éviter les réexports de compatibilité
permanents qui masquent une dépendance supprimée.

## 5. Architecture cible proposée

Cette cible conserve le nombre de crates proche de l'existant et n'introduit
que des frontières justifiées par un changement de propriétaire :

```text
crates/
  aether/                    contrats partagés et crypto commune
  astra/                     sous-système autorité/certificats
  helios-astra-channel/      protocole privé Astra <-> gateway
  helios-api/                API/WS/UI de la gateway
  helios-escrow/             enveloppes de séquestre opérateur
  helios-fido/               FIDO/WebAuthn matériel
  helios-firewall/           policy -> IR -> compiler -> backend
  helios-key-negotiation/    QUIC/mTLS et négociation v5
  helios-provisioning/       admission, IPAM et session
  helios-trust/              registre de certificats gateway, si seam confirmée
  helios-tpm/                TPM, boot et fenêtres d'update
  helios-update/             releases et activation
  helios-vault/              format de coffre AEAD
  helios-wireguard/          plan de données WireGuard
  orion-core/                logique cliente portable

apps/
  heliosd/                   composition root gateway
  orion/src-tauri/           composition root Tauri

tools/
  helios-ctl/
  helios-installer/
  helios-publisher/
  astra-signer/
  helios-astra-helper/
  xtask/
```

Les noms de package peuvent rester ceux d'aujourd'hui pendant la migration.
Le déplacement physique de `crates/helio-tpm` vers `crates/helios-tpm` est
souhaitable pour la cohérence, mais ne doit intervenir qu'après la séparation
des responsabilités et la vérification des références externes. Les modules
firewall (`policy`, IR, validation, compiler, backend) et les modules
WireGuard restent dans leurs crates respectives.

`helios-runtime` n'est pas retenu dans la cible immédiate. Il deviendra
justifié uniquement si une seconde application ou un second hôte doit
construire et exécuter le même lifecycle gateway. Tant que `heliosd` est le
seul consommateur normal, une telle crate déplacerait simplement sa complexité
sans créer de frontière réelle.

## 6. Graphe cible

Le graphe ci-dessous représente les frontières après les extractions proposées.
Les crates nouvelles sont annotées ; l'arête WireGuard–provisioning peut rester
temporairement le temps de stabiliser le trait d'IPAM.

```text
aether
  ^
  ├── helios-vault
  ├── helios-escrow                 [nouvelle frontière]
  ├── helios-tpm
  ├── helios-fido
  ├── helios-key-negotiation
  ├── helios-provisioning
  ├── helios-trust                  [extraction confirmée par seam]
  ├── helios-astra-channel          [contrats/canal privé]
  ├── helios-firewall
  ├── helios-update
  └── orion-core

helios-wireguard
  -> helios-provisioning             [contrat PeerTable, à réduire si utile]

astra
  -> aether
  -> helios-astra-channel

astra-operator
  -> aether
  -> helios-fido
  -> helios-vault

helios-api
  -> aether
  -> helios-astra-channel
  -> helios-firewall
  -> helios-provisioning
  -> helios-trust
  -> helios-update
  -> helios-wireguard

heliosd
  -> sous-systèmes Helios ci-dessus
  -> helios-api
  -> helios-astra-channel
  -> helios-escrow / helios-tpm
  -/-> orion-core                   [aucune dépendance de production ni dev]

orion-core
  -> aether
  -> helios-fido
  -> helios-key-negotiation
  -> helios-vault

orion
  -> aether
  -> orion-core
  -> support de build éventuel      [build seulement]

helios-ctl
  -> aether
  -> helios-escrow / helios-tpm
  -> helios-key-negotiation
  -> helios-update
  -> orion-core
```

Le graphe cible ne rend pas `astra` dépendante d'une façade HTTP gateway et ne
rend pas `astra-operator` dépendante de l'implémentation du service. Le code
partagé demeure sous les deux produits et aucune crate de sous-système ne
connaît le shell Tauri ou l'application `heliosd`.

## 7. Dépendances interdites

Les règles suivantes doivent devenir des invariants vérifiables par revue et,
si possible, par un contrôle de graphe CI :

- `aether` ne dépend d'aucune crate Helios, Orion, application ou outil ;
- une crate de sous-système ne dépend ni de `heliosd`, ni de `orion`, ni de
  Tauri, ni de `web` ;
- `heliosd` ne dépend pas d'`orion-core` dans ses dépendances normales ; son
  interopérabilité doit être testée par un harnais indépendant ;
- `astra` ne dépend pas de `helios-api` ; le canal privé possède son propre
  propriétaire ;
- `astra-operator` ne dépend pas de l'implémentation `astra` ; ses contrats
  sont partagés ou fournis par le canal ;
- `orion-core` ne dépend d'aucune implémentation serveur Helios ;
- les contrats Aether ne dépendent pas de Win32, WebView2, GTK, Netlink,
  `tss-esapi` ou WireGuard réel ;
- `helios-firewall` et `helios-wireguard` ne s'appellent pas directement pour
  contourner leurs interfaces de sous-système ;
- la clé et la capacité de signature de release restent dans
  `helios-publisher`, tandis que les signatures de négociation/PKI restent
  dans leur domaine ; ML-DSA-65 et ML-DSA-87 ne sont pas fusionnées ;
- aucun API DTO redigé ne sert à reconstruire et persister `network.toml` ;
- aucune nouvelle crate n'est créée pour une erreur, un type, un utilitaire ou
  un backend tant qu'une frontière de cycle de vie, sécurité, protocole,
  plateforme ou réutilisation indépendante n'est pas démontrée.

## 8. Plan de migration progressive

Chaque phase doit former un commit ou une petite série cohérente, conserver
les formats et comportements existants, puis passer les validations adaptées.

### Phase 0 — cartographie et garde-fous

Livrable : le présent document. Aucun source Rust, manifest ou test n'est
déplacé. Ajouter seulement, après validation, une règle de revue ou un contrôle
de graphe qui signale les dépendances interdites.

Fichiers concernés :

- `docs/architecture/CRATE-REORGANIZATION.md` ;
- éventuellement un script de contrôle d'architecture et le workflow de
  régression, seulement après accord sur les règles.

Validation : `cargo fmt --all -- --check`, `cargo check --workspace`,
`cargo test --workspace` et vérification que seuls les fichiers de
documentation/contrôle ont changé.

### Phase 1 — corrections sans déplacement

Simplifier le manifest racine avec `crates/*`, `tools/*` et
`apps/orion/src-tauri`. La suppression de `default-members` ferait entrer
`helios-publisher` dans le build par défaut ; cette conséquence doit être
acceptée explicitement. Si son exclusion est intentionnelle, conserver une
liste documentée plutôt que de prétendre supprimer toute duplication.

Vérifier et corriger les features mortes ou trop larges, notamment le
forwarding `helios-update/publisher-signing`, sans modifier les algorithmes ni
les formats.

Fichiers concernés :

- `Cargo.toml` ;
- `crates/aether/Cargo.toml`, `crates/helios-update/Cargo.toml`,
  `crates/helios-provisioning/Cargo.toml`, `crates/orion-core/Cargo.toml` et
  les manifests des applications qui forwardent les features ;
- `.github/workflows/regression.yml`, `.github/workflows/release.yml` si la
  sélection de packages ou le cache doit être explicitée ;
- documentation de build concernée, après vérification des commandes.

Validation : métadonnées Cargo par défaut et `--workspace`, build/test de
`helios-publisher`, compilation/test d'Orion et tests unitaires frontend.

### Phase 2 — correction des dépendances de service

Extraire les contrats du canal privé Astra–Helios de `helios-api` vers une
crate dédiée, ou vers le propriétaire partagé retenu après revue. Faire
consommer cette crate par `astra` et `heliosd`, et conserver `helios-api` comme
façade HTTP/WS/UI. Déplacer les vues et types d'opération nécessaires à
`astra-operator` vers leur propriétaire canonique, puis retirer sa dépendance
à `astra`.

Déplacer enfin le test d'interopérabilité `heliosd`/`orion-core` vers un
harnais indépendant si Cargo permet de conserver le même niveau de preuve.

Fichiers concernés :

- `crates/helios-api/src/internal.rs`, `src/certificates.rs`, `src/lib.rs` ;
- `crates/astra/src/{issuer.rs,signing.rs,gateway.rs,operations.rs}` et les
  modules de service qui utilisent le canal ;
- `crates/astra-operator/src/{origin.rs,authority.rs,tunnel.rs,campaign.rs}` ;
- `crates/heliosd/src/astra_channel.rs`, `src/main.rs` et ses tests ;
- les tests `crates/astra/tests/private_channel.rs` et les tests concernés de
  `astra-operator` ;
- `crates/heliosd/Cargo.toml` et les nouveaux manifest/source du canal ou du
  harnais.

Validation : tests de canal privé, TLS 1.3/ALPN, tests Astra opérateur,
interopérabilité de négociation v5 et tests workspace.

### Phase 3 — frontières de sécurité

Séparer le séquestre de `helio-tpm` en `helios-escrow`, renommer le package
matériel en `helios-tpm` et conserver des points de compatibilité transitoires
si des consommateurs internes en ont besoin. Le format HESC, les tickets,
les clés et les politiques de rescellement restent inchangés.

Après caractérisation par tests, extraire le registre de certificats gateway
de `helios-provisioning` vers `helios-trust`. Les contrats partagés restent
dans Aether ; l'extraction ne doit pas dupliquer le registre ni ses invariants.

Fichiers concernés :

- `crates/helio-tpm/**`, `crates/helio-tpm/Cargo.toml` et le futur
  `crates/helios-tpm/` ;
- `crates/heliosd/src/gateway_key.rs`, les modules TPM de `heliosd` et
  `tools/helios-ctl/src/escrow.rs` ;
- `crates/helios-provisioning/src/certificates.rs`, `src/lib.rs` et les
  nouveaux fichiers de `helios-trust` ;
- les manifests et tests de `helios-api`, `heliosd`, `helios-ctl` et
  `astra-operator` ;
- `docs/adr/ADR-002-SIGNATURES-PQ.md`, `docs/adr/ADR-006-SECRETS-AU-REPOS.md`
  et la documentation TPM, uniquement pour refléter les propriétaires après
  validation.

Validation : tests de format HVLT/HESC, tests TPM dry-run, tests matériels
conditionnels sur cible, tests de rotation et de registre, puis régression
complète.

### Phase 4 — composition de `heliosd`

Mesurer le call graph réel après les phases précédentes. Déplacer vers les
crates propriétaires les fonctions qui ne nécessitent ni process ni lifecycle
global. Ne créer `helios-runtime` que si un second hôte réutilisable est
identifié. Le `main` doit alors charger la configuration, construire les
backends, injecter les dépendances, démarrer et arrêter le lifecycle.

Fichiers concernés :

- `crates/heliosd/src/main.rs` ;
- `crates/heliosd/src/{orchestrator.rs,key_negotiation.rs,certificates.rs,
  gateway_rotation.rs,astra_channel.rs,static_psk.rs,gateway_key.rs,
  uplink.rs,vip_routing.rs}` ;
- `crates/heliosd/Cargo.toml` et un éventuel manifest `helios-runtime` ;
- tests unitaires correspondants et tests de démarrage/arrêt ;
- `apps/orion/src-tauri/src/main.rs` et ses modules uniquement pour rendre le
  shell Tauri plus lisible, sans déplacer la logique d'`orion-core`.

Validation : lifecycle fail-closed, kill-switch, démarrage/arrêt, WireGuard,
firewall atomique, configuration hot reload, tests v5, tests API et tests
frontend.

### Phase 5 — organisation physique

Déplacer les dossiers vers `crates/*`, `apps/*` et `tools/*` seulement lorsque
les propriétaires sont stabilisés. Utiliser des déplacements Git simples,
mettre à jour les chemins Cargo et les scripts, et préserver les noms de
packages pour éviter un changement de contrat inutile.

Fichiers concernés : manifests racine et locaux, `tools/xtask/**`, scripts de
build/package, workflows CI, liens `docs/`, fichiers Tauri et fichiers de
configuration qui référencent des chemins. Aucun fichier de protocole ou de
format persistant ne doit être modifié dans cette phase.

Validation : build par défaut incluant Orion, build workspace, packaging
gateway, packaging Orion Windows/Linux selon la cible, et recherche des
anciens chemins.

### Phase 6 — nettoyage contrôlé

Supprimer les compatibilités temporaires, réexports qui masquent encore une
dépendance, features inutilisées et commentaires de transition, uniquement
après migration de tous les consommateurs. Mettre à jour la documentation
d'architecture générale, l'index et les guides de test.

Fichiers concernés : manifests, `src/lib.rs`, modules de compatibilité, CI,
`docs/ARCHITECTURE.md`, `docs/architecture/overview.md`,
`docs/testing/TESTING.md` et les ADR touchés.

## 9. Risques et contrôles

| Risque | Contrôle requis |
| --- | --- |
| Casser un message signé ou une sérialisation | Tests de vecteurs, golden files et compatibilité avant/après |
| Séparer un invariant certificat de son état | Définir le propriétaire avant déplacement ; tests de transition/rollback |
| Transformer une dépendance de test en dépendance runtime | Inspection de `cargo metadata` et de chaque section manifest |
| Affaiblir la frontière de confiance Astra | Tests TLS/ALPN/mTLS et vérification du canal privé dédié |
| Réintroduire une clé ou un secret dans une couche partagée | Revue des types publics, logs, sérialisation et API de lecture |
| Rendre une feature disponible sur la mauvaise cible | Matrices CI Linux/Windows et erreurs explicites hors cible |
| Cacher une régression Orion en simplifiant le workspace | Assertion CI sur la présence d'Orion/Tauri dans le build par défaut |
| Créer `helios-runtime` sans consommateur réel | Exiger un second hôte ou une réutilisation démontrée |
| Renommer `helio-tpm` avec un consommateur externe inconnu | Recherche de références, compatibilité de package ou période de transition |
| Perdre la preuve d'interopérabilité | Conserver le test contre les implémentations réelles dans un harnais dédié |

Les protocoles réseau v5, formats persistés, formats cryptographiques, clés,
signatures, certificats, commandes CLI et comportement runtime sont hors
objectif de cette réorganisation. Tout écart observé pendant une phase devra
être arrêté et documenté séparément.

## 10. Tests et validations

État de référence exécuté avant toute modification :

- `cargo fmt --all -- --check` : réussi ;
- `cargo check --workspace` : réussi ;
- `cargo test --workspace` : réussi, y compris 404 tests Aether et 259 tests
  `orion-core` dans cette exécution.

Les vérifications non exécutées dans cet audit documentaire sont :

- `cargo clippy --workspace --all-targets --all-features -- -D warnings` ;
- `npm run test:unit --prefix web` ;
- `npm run test:unit --prefix apps/orion` ;
- les tests matériels TPM/FIDO, WireGuard noyau, Netlink et packaging natif.

Après chaque phase de code, exécuter au minimum :

```text
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
npm run test:unit --prefix web
npm run test:unit --prefix apps/orion
```

Pour les phases de sécurité, protocole, packaging ou multi-crates, ajouter
`bash scripts/regression.sh`. Les limites de cible restent celles de
`docs/testing/TESTING.md` : WSL2 et dry-run ne prouvent pas le fonctionnement
du kernel WireGuard, de Netlink, du TPM ou de l'installation native.

## 11. Résultat attendu pour un nouvel ingénieur

Après migration, le dépôt doit permettre de répondre sans parcourir les
applications :

- les contrats et invariants partagés sont dans `aether` ;
- chaque sous-système gateway possède son propriétaire et son backend interne ;
- Astra, TPM, FIDO, vault et séquestre sont des frontières de sécurité
  explicites ;
- Orion est une logique cliente indépendante, avec ses adaptations de
  plateforme dans `orion-core`/Tauri ;
- `heliosd`, `orion` et les outils assemblent les composants mais ne les
  possèdent pas ;
- le graphe interdit les dépendances application-vers-sous-système inverse,
  les dépendances Helios-vers-Orion de production et les remontées de
  plateformes dans les contrats.

## Recommended first migration

La plus petite modification au meilleur rapport bénéfice/risque est une
modification du manifest racine uniquement : remplacer les listes explicites
du workspace par les patterns `crates/*`, `tools/*` et
`apps/orion/src-tauri`, puis supprimer `default-members` afin que tous les
packages membres, Orion compris, soient inclus par défaut.

Cette étape ne déplace aucun code et ne change aucun protocole. Elle supprime
la divergence actuelle entre `members` et `default-members`, rend visible
`helios-publisher` dans le build par défaut et conserve la garantie importante
que Tauri/Orion est compilé et testé. Elle doit néanmoins être revue comme un
changement de périmètre de build : si l'exclusion actuelle de
`helios-publisher` est intentionnelle, garder une liste `default-members`
explicitement justifiée et limiter la première migration à l'ajout d'un
contrôle CI attestant qu'Orion est toujours présent.

Cette première étape doit être livrée seule, avec vérification de
`cargo metadata`, `cargo check --workspace`, `cargo test --workspace`, les
tests frontend et une revue du diff. Aucune phase suivante ne doit commencer
avant validation de ce rapport et de cette décision.
