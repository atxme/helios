# Helios

Helios est une passerelle VPN **WireGuard** pour appliance Linux, pilotée par un
daemon Rust. Orion est son client de bureau Tauri. Le projet sépare le plan de
contrôle (états, politiques, provisioning, OTA) du plan de données noyau
(WireGuard et nftables).

La migration depuis IKEv2 est actée par
[ADR-001](docs/ADR-001-WIREGUARD.md). Il ne reste plus de crate VICI ni de
backend IPsec dans le workspace ; les références IKEv2 encore présentes dans
certains documents historiques ne décrivent pas le code actuel.

```text
                         plan de contrôle (Rust)
  Orion ── WireGuard ──► heliosd
    │                       ├── helios-api ── REST / WebSocket / IHM embarquée
    │                       ├── helios-provisioning ── IPAM + ML-KEM
    │                       ├── helios-firewall ── politique fail-closed
    │                       ├── helios-wireguard ── interface + pairs
    │                       ├── helio-tpm ── intégrité du démarrage
    │                       └── helios-update ── RAUC A/B
    │
    └── orion-core ── profil, adaptateur, handshake, télémétrie

                         plan de données (noyau)
                 WireGuard · nf_tables · interfaces réseau
```

## Modèle de fonctionnement

Helios joue le rôle de **serveur WireGuard** : il crée `helios0`, écoute par
défaut en UDP 51820 et attend les clients admis. WireGuard n’ayant pas de notion
de connexion persistante, l’état `Up` est inféré lorsqu’au moins un pair possède
un handshake vieux de moins de 150 secondes.

La machine à états est commune aux deux applications :

- `down` : interface arrêtée ;
- `connecting` : interface montée, en attente d’un handshake frais ;
- `up` : handshake frais observé ;
- `failed` : échec opérationnel ;
- `captive_portal` : ouverture temporaire limitée au portail captif.

Sur la gateway, le pare-feu est **fail-closed** : seul `up` autorise le trafic
LAN. Le kill-switch reste engagé au démarrage, pendant la connexion, après
l’expiration d’un handshake, en échec et à l’arrêt. Le backend Netlink applique
le ruleset nftables dans une transaction atomique.

Orion suit un modèle différent : il ne possède pas de pare-feu client. Son
adaptateur portant `AllowedIPs = 0.0.0.0/0` reste monté après un échec afin que
WireGuard continue de jeter les paquets ; seul une déconnexion explicite le
démonte.

## Workspace

| Composant | Rôle |
|---|---|
| `aether` | Types communs, états, politique, configuration, ML-KEM et contrat de provisioning |
| `helios-firewall` | Rendu nftables et backends `dry-run` / `netlink` |
| `helios-wireguard` | Plan de données gateway, backends mémoire / noyau et table de pairs |
| `helios-provisioning` | IPAM CGNAT déterministe, session ML-KEM et rotation de PSK |
| `helios-api` | API Axum, WebSocket, provisioning et fichiers web embarqués |
| `helios-update` | Vérification et installation OTA RAUC A/B |
| `helio-tpm` | Scellement PCR, billets de rescellement et contrôle du boot |
| `heliosd` | CLI et orchestration de la gateway |
| `orion-core` | Logique portable du client WireGuard |
| `apps/orion` | Application de bureau Tauri avec IHM React embarquée |
| `helios-ctl` | CLI de diagnostic et scénarios contre l’API |
| `web` | IHM d’administration React de la gateway |

## Configuration de la gateway

La configuration opérateur unique est
`/var/lib/helios/network.toml`. Un modèle commenté se trouve dans
[config/network.toml](config/network.toml). Les champs principaux sont :

- interfaces WAN/LAN et sources SSH autorisées ;
- nom, clé privée, adresse CGNAT et port de l’interface WireGuard ;
- interface d’administration et routes de split-tunneling ;
- pairs admis : nom, clé publique, VIP et éventuel PSK post-quantique ;
- pairs statiques sortants pour les scénarios site-à-site.

La gateway écoute son API sur l’adresse de tunnel extraite de `wg_address`
(par exemple `100.64.0.1:8080`). Si WireGuard n’est pas configuré, elle se
replie sur `127.0.0.1:8080`. Le pare-feu limite l’accès distant à
`admin_iface`.

## Développement

Prérequis : Rust 1.82 ou plus récent, Node.js 18 ou plus récent et npm. Le shell
Tauri Linux nécessite aussi WebKitGTK 4.1 et GTK3.

```sh
# Toute la logique testable sans plan de données noyau
cargo test --workspace

# Gateway en simulation (requiert une network.toml avec une clé WG de test)
cargo run -p heliosd -- run --dev

# Diagnostic de la configuration résolue
cargo run -p heliosd -- status

# IHM gateway en développement
cd web
npm ci
npm run dev
```

Vite écoute sur `:5173` et proxie `/api` et `/ws` vers `localhost:8080`.

## API et événements

| Route | Fonction |
|---|---|
| `GET /api/status` | État, interfaces, pairs admis et politique résolue |
| `GET /api/network` | Configuration réseau complète |
| `POST /api/network` | Persistance atomique et rechargement à chaud |
| `POST /api/provision` | Échange ML-KEM dans le tunnel pour un pair déjà admis |
| `POST /api/tunnel/start` | Montage/reconfiguration de l’interface WireGuard |
| `POST /api/tunnel/stop` | Démontage explicite de l’interface |
| `GET /api/firewall/rules` | Rendu du ruleset courant |
| `POST /api/firewall/rules` | Transmission de règles personnalisées à l’orchestrateur |
| `POST /api/captive-portal/release` | Validation du portail et reconnexion |
| `POST /api/split-tunnel` | Mise à jour dynamique des CIDR de contournement |
| `WS /ws` | Événements temps réel |

Le WebSocket diffuse `state_changed`, `log`, `telemetry`,
`captive_portal_detected`, `mtu_discovered` et `split_tunnel_changed`.

Attention : `GET /api/network` contient actuellement les secrets de
configuration. Cette route doit rester protégée derrière l’interface
d’administration WireGuard.

## Interfaces embarquées

Pour embarquer l’IHM d’administration dans `heliosd` :

```sh
cd web
npm ci
npm run build
cd ..
cargo build -p heliosd --features embed-ui
```

Sans `embed-ui`, l’API et le WebSocket fonctionnent mais la route statique
renvoie `503`, ce qui permet d’utiliser Vite séparément.

L’IHM Orion est intégrée automatiquement par Tauri :

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

Exemple de compilation cible :

```sh
cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
cd apps/orion && npm run tauri build -- --features wireguard
```

Compiler une feature noyau sur WSL2 ne valide que le code. Les tests réels
nécessitent `nf_tables`, WireGuard, un TPM et les privilèges adaptés sur la
machine cible.

## Provisioning post-quantique

L’admission initiale est hors bande : l’opérateur déclare la clé publique
WireGuard d’Orion dans `network.toml`. Une fois le tunnel classique accessible,
Orion et Helios peuvent effectuer un échange ML-KEM-768 via
`POST /api/provision`, dériver le même PSK et confirmer la VIP CGNAT.

Le format du protocole, la crypto, l’IPAM et l’endpoint sont implémentés et
testés. Il reste toutefois à câbler l’installation atomique du nouveau PSK dans
le pair WireGuard côté gateway et son orchestration de rotation. Tant que ce
câblage manque, le provisioning automatique ne doit pas être présenté comme une
fonction de production.

## Tests de non-régression

La commande de référence avant chaque version est :

```sh
bash scripts/regression.sh
```

Elle vérifie le formatage, Clippy avec avertissements interdits, tous les tests
Rust, les audits npm (seuil `moderate`), les tests Vitest et les builds de
production des deux interfaces. La même campagne tourne dans GitHub Actions.
Les contrôles spécifiques au matériel sont détaillés dans
[docs/TESTING.md](docs/TESTING.md).

## Documentation

- [ADR WireGuard](docs/ADR-001-WIREGUARD.md)
- [Tests et validation cible](docs/TESTING.md)
- [Tests manuels des binaires et des IHM](docs/MANUAL-TESTING.md)
- [Développement WSL2](docs/WSL2-DEV.md)
- [OTA RAUC](docs/OTA-RAUC.md)
- [Architecture](docs/ARCHITECTURE.md) — document historique en cours de migration
- [Post-quantique](docs/POST-QUANTUM.md) — document historique en cours de migration
