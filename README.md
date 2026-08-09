# Helios

Helios est une passerelle VPN **WireGuard** pour appliance Linux, pilotée par un
daemon Rust. Orion est son client de bureau Tauri. Le projet sépare le plan de
contrôle (états, politiques, provisioning, mise à jour) du plan de données noyau
(WireGuard et nftables).

La rupture avec IKEv2 est achevée dans le code et documentée par
[ADR-001](docs/adr/ADR-001-WIREGUARD.md). La signature hybride des artefacts
éditeur est arrêtée par [ADR-002](docs/adr/ADR-002-SIGNATURES-PQ.md). Le tunnel
est aujourd'hui précédé d'une **négociation de clé post-quantique** en protocole
v5 ([ADR-005](docs/adr/ADR-005-NEGOCIATION-DE-CLE.md)), qui pose un PSK ML-KEM
sur le **premier** handshake WireGuard.

```text
                         plan de contrôle (Rust)
  Orion ── QUIC/mTLS ───► heliosd  (négociation de clé, port UDP dédié)
    │  (avant le tunnel)     │
    │                        ├── helios-key-negotiation ── transport QUIC authentifié
  Orion ── WireGuard ──────► ├── helios-api ── REST / WebSocket / IHM embarquée
    │  (après le tunnel)     ├── helios-provisioning ── IPAM + ML-KEM + admission
    │                        ├── helios-firewall ── politique fail-closed
    │                        ├── helios-wireguard ── interface + pairs
    │                        ├── helio-tpm ── intégrité du démarrage + fenêtre
    │                        ├── helios-vault ── secrets au repos (AES-256-GCM)
    │                        └── helios-update ── binaire signé + rollback
    │
    └── orion-core ── profil, adaptateur, négociation, handshake, télémétrie

                         plan de données (noyau)
                 WireGuard · nf_tables · interfaces réseau
```

## Modèle de fonctionnement

Helios joue le rôle de **serveur WireGuard** : il crée `helios0`, écoute par
défaut en UDP 51820 et attend les clients admis. WireGuard n'ayant pas de notion
de connexion persistante, l'état `Up` est inféré lorsqu'au moins un pair possède
un handshake vieux de moins de 150 secondes.

La machine à états est commune aux deux applications :

- `down` : interface arrêtée ;
- `connecting` : interface montée, aucun handshake de moins de 150 s ;
- `up` : un handshake a réussi il y a moins de 150 s ;
- `failed` : échec opérationnel ;
- `captive_portal` : ouverture temporaire limitée au portail captif.

Sur la gateway, le pare-feu est **fail-closed** : seul `up` autorise le trafic
LAN. Le kill-switch reste engagé au démarrage, pendant la connexion, après
l'expiration d'un handshake, en échec et à l'arrêt. Le backend Netlink applique
le ruleset nftables — filtrage **et** NAT — dans une transaction atomique unique.

Orion suit un modèle différent : il ne possède pas de pare-feu client. Son
adaptateur portant `AllowedIPs = 0.0.0.0/0` reste monté après un échec afin que
WireGuard continue de jeter les paquets ; seule une déconnexion explicite le
démonte.

## Négociation de clé post-quantique (v5)

Avant tout paquet WireGuard, Orion négocie avec la gateway sur un **port UDP
dédié** (QUIC + mTLS), et en ressort avec le PSK que le premier handshake
utilisera. La spécification complète est
[NEGOCIATION-DE-CLE-V5.md](docs/specification/NEGOCIATION-DE-CLE-V5.md).

- **Authentification** : mTLS pour le transport, puis une PKI applicative
  **ML-DSA-87** qui est la véritable frontière post-quantique. Ne pas confondre
  avec le ML-DSA-65 des artefacts éditeur (ADR-002) : deux jeux de paramètres,
  deux modules, ils ne se remplacent pas.
- **Anti-rejeu** : un `server_challenge` de 32 octets par connexion, à usage
  unique, délibérément non signé par la gateway.
- **Modes négociables** : `static_psk` et `ml_kem`. `classic` n'est **pas** un
  mode v5 — un tunnel sans PSK est un profil WireGuard générique, pas un
  résultat de négociation.
- **Plancher anti-downgrade** : par pair côté gateway, par profil côté Orion.
  Il monte seul et ne redescend jamais sous la valeur de chargement.
- **Ordre de pose** : le PSK est installé sur le plan de données **avant**
  d'être annoncé au client. La pose échoue, la demande est refusée.
- **Fin de la session QUIC** : elle est fermée après le commit signé. Elle porte
  une transaction, pas une preuve de vivacité — c'est l'inverse de la v4.
- **Vivacité** : lue sur le plan de données uniquement. 150 s décident de l'état
  du tunnel, 300 s décident que la gateway récupère le PSK d'un pair disparu,
  24 h bornent l'âge d'un PSK sur un tunnel sain. La gateway pose elle-même un
  keep-alive de 25 s plutôt que de faire confiance à celui du client.
- **Libération** : `POST /api/key-negotiation/release`, **dans** le tunnel, et
  nulle part ailleurs. Le port QUIC public ne porte que challenge, requête,
  confirmation et commit.
- **Bornes DoS du port public** : Retry avant tout état, budget par IPv4 ou par
  préfixe IPv6 `/64`, budget par identité admise, durée de vie absolue de 90 s
  par connexion, reprise TLS et 0-RTT désactivés, datagrammes épinglés à
  1200 octets et découverte de MTU désactivée des deux côtés.
- **Codes d'erreur publics** : `protocol`, `rejected`, `internal`. Rien de plus,
  pour ne pas laisser énumérer les pairs admis depuis un port public.

La négociation n'est **pas** une feature de compilation : tout binaire la porte,
et seul `key_negotiation_port` décide de son ouverture. Absent, le service reste
fermé sans erreur.

**État d'implémentation.** La v5 est **partiellement implémentée** et ne doit pas
être présentée comme terminée. L'état de tête de la spécification nomme les lots
ouverts : discriminant de type de profil Orion, état terminal `revoked`,
renouvellement de PSK en place, renégociation d'Orion sur vieillissement de
handshake, enrôlement sans clé privée avec signature opérateur, libération à la
désinstallation d'un profil, et tout le cycle de vie des certificats.

## Cycle de vie des certificats — Astra (non implémenté)

La leaf PQ de la gateway est encore **auto-signée** et épinglée telle quelle dans
chaque profil ; il n'existe ni slot actif/suivant, ni génération anti-rollback.
La cible est fixée par la
[spécification de rotation](docs/specification/ROTATION-CERTIFICATS.md) et par
[ADR-008](docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md), qui nomme **Astra**
le coordinateur PKI : conteneur dédié co-implanté avec `heliosd`, canal public
HTTPS distinct, canal privé veth vers la gateway, ancre maîtresse en coffre HVLT
et clé d'émission déléguée bornée, approbations YubiKey/WebAuthn.

L'ADR est explicite sur ce que la co-implantation n'achète pas : Docker isole
des processus, des fichiers, des capacités et des interfaces — ce n'est pas une
frontière contre `root`, et une compromission de l'hôte reste une compromission
possible de l'émetteur opérationnel.

Rien de ce lot n'est encore écrit : ni le service Astra, ni le planificateur à
80 % de validité, ni la récupération après expiration, ni les campagnes
protégées par YubiKey.

## Workspace

| Composant | Rôle |
|---|---|
| `aether` | Types communs, états, politique, ML-KEM, protocole de négociation et enveloppes signées hybrides |
| `helios-firewall` | Rendu nftables et backends `dry-run` / `netlink` |
| `helios-wireguard` | Plan de données gateway, backends mémoire / noyau et table de pairs |
| `helios-provisioning` | IPAM CGNAT déterministe, admission, session ML-KEM et rotation de PSK |
| `helios-key-negotiation` | Transport QUIC authentifié de la négociation ; ne possède ni CA ni backend WireGuard |
| `helios-api` | API Axum, WebSocket, provisioning et fichiers web embarqués |
| `helios-update` | Manifeste hybride, staging, anti-rollback et bascule atomique |
| `helio-tpm` | Scellement PCR, séquestre, billets de rescellement et fenêtre de mise à jour |
| `helios-vault` | Conteneur AEAD unique des secrets au repos (ADR-006), AES-256-GCM et séparation de domaine |
| `heliosd` | CLI et orchestration de la gateway |
| `orion-core` | Logique portable du client : profil, adaptateur, négociation, stockage protégé |
| `apps/orion` | Application de bureau Tauri avec IHM React embarquée et zone de notification Windows |
| `web` | IHM d'administration React de la gateway (MUI seul, polices auto-hébergées) |
| `helios-ctl` | Outil du poste opérateur — et de la gateway pour `update` |
| `helios-publisher` | Outil éditeur hors gateway : clés Ed25519/ML-DSA-65 et billets signés |
| `helios-installer` | Helper privilégié sans réseau : activation, health check et rollback |
| `xtask` | Fabrique de bundles d'installation et installateur Windows d'Orion |

## Configuration de la gateway

La configuration opérateur unique est `/var/lib/helios/network.toml`. Un modèle
commenté se trouve dans [config/network.toml](config/network.toml). Les champs
principaux sont :

- interfaces WAN/LAN et sources SSH autorisées ;
- nom, adresse CGNAT et port de l'interface WireGuard ;
- `key_negotiation_port` : ouvre le service de négociation (absent = fermé) ;
- interface d'administration et routes de split-tunneling ;
- `allow_client_internet` et `allow_gateway_egress` ;
- pairs admis : nom, clé publique, VIP, empreintes de certificats, plancher de
  négociation et éventuel PSK statique ;
- pairs statiques sortants pour les scénarios site-à-site.

L'identité WireGuard de la gateway **naît sur la gateway** (`heliosd
init-identity`), scellée au TPM. Une `wg_private_key` en clair dans
`network.toml` est un repli hérité, pas un chemin d'installation.

Le fichier est **relu à chaud** : le démon le surveille et réapplique la table
de pairs sans redémarrer. Ce qui ne peut pas changer sous un plan de données en
marche — nom d'interface, port d'écoute, adresse d'API — exige toujours un
redémarrage. L'identité de négociation, elle, est lue une fois au démarrage :
`init-key-negotiation --rotate` sur un démon en marche change les fichiers sans
changer ce qui est servi, et s'applique par `systemctl restart heliosd`.

La gateway écoute son API sur l'adresse de tunnel extraite de `wg_address`
(par exemple `100.64.0.1:8080`). Si WireGuard n'est pas configuré, elle se
replie sur `127.0.0.1:8080`. Le pare-feu limite l'accès distant à `admin_iface`.

## Outillage d'exploitation

Sur la gateway :

```sh
heliosd init-identity                 # identité WireGuard scellée, jamais en clair
heliosd init-key-negotiation          # identité de négociation TLS + ML-DSA-87
heliosd peer add|list|remove          # admission (même code que helios-ctl peer)
heliosd tpm prepare-update --reboot   # fenêtre de mise à jour ADR-007
helios-ctl update                     # mise à jour de l'OS en une commande
```

Sur le poste opérateur :

```sh
helios-ctl peer add|revoke|list       # admission
helios-ctl profile emit|check         # document `.orion` importable par Orion
helios-ctl enroll                     # enrôlement d'un trait : clés, certificats,
                                      # admission, profil et identité en un document
helios-ctl key-nego ...               # PKI hors ligne et diagnostics
helios-ctl escrow ...                 # séquestre — jamais sur la gateway secourue
helios-ctl campaign ...               # campagnes de bout en bout via orion-core
```

Scripts d'enchaînement :

```sh
./scripts/deploy.sh                   # construit, signe, copie et installe
./scripts/provision-client.sh nom     # CA, négociation, admission et profil client
./scripts/key-negotiation-setup.sh    # mise en place de la négociation de bout en bout
bash scripts/lab.sh --keep            # banc jetable : gateway + client admis + profil
```

`lab.sh` monte le banc avec les **mêmes outils qu'en production** — pas de
chemin de test parallèle — et produit un profil directement importable dans
Orion.

La CA opérateur vit dans `~/.helios/certs/internal-ca`, et à **un seul** endroit :
la gateway n'en épingle qu'une. Un script qui la cherche ailleurs en fabrique une
neuve et coupe tous les clients déjà admis.

## Profils Orion

Les profils portent l'extension **`.orion`** (`.orionprofile` jusqu'en août
2026 : encore lue à l'import, plus écrite ni enregistrée auprès de Windows), avec
une icône de document propre posée par un fragment WiX.

Une invitation (`enroll --public-key`) ne porte pas de clé privée : à l'import,
Orion reprend celle du profil local qui détient la **clé admise**, quel que soit
son nom — la correspondance se fait sur la clé, jamais sur le nom.

Sous Windows, la zone de notification est une surface à part entière : état du
tunnel, liste de profils que l'on coche pour connecter, import, journal et
« À propos ». Seul son câblage est propre à Windows ; le modèle et les libellés
se compilent et se testent partout.

## Secrets au repos

[ADR-006](docs/adr/ADR-006-SECRETS-AU-REPOS.md) fixe un conteneur **unique**,
`helios-vault` : AES-256-GCM, séparation de domaine et de contexte, parseur
borné. Le chiffrement de volume (BitLocker / dm-crypt) y est un **prérequis
d'installation**.

Côté gateway, les identités sont scellées au TPM. Côté Orion, l'identité cliente
est scellée par DPAPI au compte Windows. **Limite connue** : DPAPI ne se compile
ni ne s'exerce en WSL2 — hors Windows, le scellement échoue explicitement plutôt
que d'écrire ces clés en clair.

Un PSK négocié n'est **jamais** persisté sur disque.

## Fenêtre de mise à jour de l'OS

[ADR-007](docs/adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md) : `heliosd tpm
prepare-update --reboot` porte le **même** secret à travers un redémarrage
planifié, dans un slot NV lisible sous PCR 0/7, écrasé après rescellement
durable. Les coffres survivent, aucun client n'est ré-enrôlé.

Trois limites explicites : pendant qu'une fenêtre est ouverte, un attaquant
ayant l'accès physique qui démarre un autre OS signé descelle le secret
(`TPM2_PolicyCounterTimer` n'est pas exposé par `tss-esapi` 7.7) ; une mise à
jour de firmware ou de base Secure Boot déplace PCR 0/7 et sort du périmètre ;
l'identité de négociation reste **sans séquestre**, donc un changement de PCR
subi impose encore une rotation et le ré-enrôlement du parc.

## Développement

Prérequis : Rust 1.82 ou plus récent, Node.js 20.19+ ou 22.12+ et npm. Le shell
Tauri Linux nécessite aussi WebKitGTK 4.1 et GTK3 (`scripts/setup-dev.sh`).

```sh
# Toute la logique testable sans plan de données noyau
cargo test --workspace --all-features

# Gateway en simulation (requiert une network.toml avec une clé WG de test)
cargo run -p heliosd -- run --dev

# Diagnostic de la configuration résolue
cargo run -p heliosd -- status

# IHM gateway en développement
npm run dev --prefix web
```

Vite écoute sur `:5173` et proxie `/api` et `/ws` vers `localhost:8080`.

**Langue.** Tout ce qui est du code est en anglais — noms, commentaires,
doc-comments, messages de journal et noms de tests. Seule la documentation sous
`docs/` reste en français.

**Aucun marqueur `TODO`, `FIXME`, `todo!()` ni `unimplemented!()`** n'est admis
dans le dépôt. Face à une fonctionnalité incomplète : la développer, la refuser
explicitement dans le type, ou la documenter comme limite connue.

## API et événements

| Route | Fonction |
|---|---|
| `GET /api/health` | Sonde de vie |
| `GET /api/status` | État, interfaces, pairs admis et politique résolue |
| `GET /api/trust` | Algorithmes requis, époques et empreintes du trousseau éditeur compilé |
| `GET /api/network` | Vue réseau expurgée : présence des secrets, jamais leur valeur |
| `POST /api/network` | Persistance atomique et rechargement à chaud |
| `GET /api/key-negotiation` | Matériel public de négociation lu par `helios-ctl enroll` |
| `POST /api/key-negotiation/release` | Libération du PSK à la déconnexion — **dans le tunnel** |
| `POST /api/peers` | Admission d'un client |
| `POST /api/peers/revoke` | Révocation d'une admission |
| `POST /api/gateway/wireguard-key` | Installation de l'identité WireGuard de la gateway |
| `POST /api/provision` | Échange ML-KEM dans le tunnel pour un pair déjà admis |
| `GET /api/update` | Canal, target, séquence confirmée et releases stagées |
| `POST /api/update/*` | Staging, finalisation et activation réservés à un pair administrateur |
| `POST /api/tunnel/start` | Montage/reconfiguration de l'interface WireGuard |
| `POST /api/tunnel/stop` | Démontage explicite de l'interface |
| `GET /api/firewall/rules` | Rendu du ruleset courant |
| `POST /api/firewall/rules` | Transmission de règles personnalisées à l'orchestrateur |
| `POST /api/captive-portal/release` | Validation du portail et reconnexion |
| `POST /api/split-tunnel` | Mise à jour dynamique des CIDR de contournement |
| `WS /ws` | Événements temps réel |

Le WebSocket diffuse `state_changed`, `log`, `telemetry`,
`captive_portal_detected`, `mtu_discovered` et `split_tunnel_changed`.

Toutes les mutations HTTP exigent `Content-Type: application/json` ; le serveur
ne publie aucun CORS permissif, et les lectures ne sérialisent jamais une clé
privée ou un PSK. Cela complète — sans le remplacer — le filtrage de l'API
derrière `admin_iface`. L'API ne monte jamais le tunnel initial.

## Interfaces embarquées

Pour embarquer l'IHM d'administration dans `heliosd` :

```sh
npm run build --prefix web
cargo build -p heliosd --features embed-ui
```

Sans `embed-ui`, l'API et le WebSocket fonctionnent mais la route statique
renvoie `503`, ce qui permet d'utiliser Vite séparément.

La console gateway a quatre destinations — Aperçu, Clients, Sécurité, Système.
Elle est en **MUI seul**, sans Tailwind ni moteur 3D, et ses polices sont
auto-hébergées : ce bundle part dans le binaire, et une gateway ne joint aucun
CDN.

L'IHM Orion est intégrée automatiquement par Tauri :

```sh
cd apps/orion
npm ci
npm run tauri build
```

`beforeBuildCommand` construit React/Vite et `frontendDist` embarque `dist/`
dans le package natif. Voir [le README Orion](apps/orion/README.md).

## Features et cible matérielle

Les chemins sûrs par défaut utilisent les backends de simulation. Les features
matérielles sont :

- `heliosd/netlink` : application nftables via Netlink ;
- `heliosd/wireguard` : backend WireGuard noyau de la gateway ;
- `heliosd/tpm` : accès TPM via TSS2 ;
- `heliosd/embed-ui` : fichiers React embarqués ;
- `orion/wireguard` : backend WireGuard réel du client.

La négociation de clé n'en fait pas partie : tout binaire la porte.

```sh
cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
cd apps/orion && npm run tauri build -- --features wireguard
```

Hors `--dev`, un backend noyau absent est une **erreur de démarrage** ; il n'y a
aucun repli implicite vers un backend simulé. Réciproquement, un Orion pour
Windows bâti sans `wireguard` ne compile pas : le repli produirait un client qui
n'ouvre aucun tunnel tout en affichant un profil et un mode négocié.

Compiler une feature noyau sur WSL2 ne valide que le code. Les essais noyau,
TPM, WireGuard-NT et l'installation d'une release sont **target-only** ; suivre
[docs/testing/TESTING.md](docs/testing/TESTING.md).

## Livraison

La gateway se livre en binaires ([ADR-004](docs/adr/ADR-004-CHAINE-DE-LIVRAISON.md),
lot 2) :

```sh
cargo xtask bundle          # assemble
helios-publisher bundle     # signe hors ligne
cargo xtask pack            # archive
helios-installer bootstrap  # vérifie tout avant d'écrire
cargo xtask orion-msi       # installateur Windows d'Orion (Windows uniquement)
```

`setup-target.sh` ne compile plus rien. `deploy.sh` enchaîne les trois premiers
outils pour un opérateur qui détient les trois rôles ; la séparation garde son
sens pour une release publique.

Une release gateway se construit après le frontend et avec le trousseau public
éditeur :

```sh
npm run build --prefix web
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
```

Les secrets éditeur ne doivent jamais entrer dans une gateway ni dans le dépôt.

## Signature des artefacts éditeur

Les billets de rescellement TPM v2 exigent **Ed25519 ET ML-DSA-65** sur les
mêmes octets canoniques. `key_epoch` est signé et indexe un trousseau public
compilé ; une signature absente, dupliquée, invalide ou une époque inconnue est
un rejet. Les builds release refusent le trousseau de développement.

La signature s'effectue exclusivement avec `helios-publisher`, hors gateway.
Voir [le guide éditeur](docs/security/PUBLISHER-SIGNING.md).

## Limites connues

- La VIP dérivée par l'IPAM n'est pas réconciliée avec l'adresse déclarée en
  configuration : chaque bout garde la sienne, l'écart est journalisé.
- Le fichier de récupération WireGuard signé reste bloqué jusqu'au choix
  explicite du compteur anti-rejeu (fichier ou NV TPM) — ADR-002, amendement 2.
- Le **DNS d'un client n'est pas tunnelé**, même `allow_client_internet` actif :
  ses requêtes sortent hors du tunnel.
- Le câblage PSK est validé en **dry-run seulement**. Aucun essai noyau n'a
  encore eu lieu, et la fenêtre de mise à jour n'a jamais été exercée sur un TPM
  réel.
- Le cycle de vie des certificats n'est pas implémenté (voir plus haut).

Une compilation WSL2 n'est jamais une validation matérielle.

## Tests de non-régression

La commande de référence avant chaque version est :

```sh
bash scripts/regression.sh
```

Elle vérifie le formatage, Clippy et les tests Rust avec toutes les features,
les contrats de sécurité, les audits Cargo/npm, les tests Vitest et les builds
de production des deux interfaces. La même campagne tourne dans GitHub Actions.

```sh
bash scripts/campaign.sh   # campagnes PQ, mise à jour signée et bundle
```

Les contrôles spécifiques au matériel sont détaillés dans
[docs/testing/TESTING.md](docs/testing/TESTING.md).

## Documentation

Voir [l'index de la documentation](docs/README.md) pour le plan complet
(architecture, ADR, spécifications, sécurité et tests).
