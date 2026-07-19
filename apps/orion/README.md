# Orion VPN

Orion est le client de bureau WireGuard de la gateway Helios. L’application
combine une IHM React/TypeScript embarquée par Tauri et un cœur Rust portable
dans `crates/orion-core`.

Elle monte elle-même l’adaptateur WireGuard vers l’endpoint UDP du profil. Elle
ne dépend pas de l’API HTTP Helios pour établir le tunnel : l’API interne n’est
utilisée qu’après la connexion pour la télémétrie et le provisioning.

## Architecture

```text
IHM React
   │ invoke / events Tauri
   ▼
shell apps/orion/src-tauri
   │
   ▼
orion-core ── VpnController ── backend dry-run ou WireGuard réel
   │
   └── télémétrie / provisioning ── API Helios dans le tunnel
```

- `src/` contient l’IHM, les profils et le journal temps réel ;
- `src-tauri/` expose les commandes Tauri et embarque le frontend ;
- `orion-core` porte la configuration, le backend, l’inférence de handshake et
  le client de provisioning sans dépendance Tauri.

## Profil WireGuard

Un profil contient :

- un nom et l’endpoint `IP:port` ou `FQDN:port` de la gateway ;
- la clé privée Curve25519 du client et la clé publique de la gateway ;
- la VIP CGNAT attribuée au client ;
- `AllowedIPs` (`0.0.0.0/0` par défaut) ;
- un keepalive persistant de 25 secondes par défaut ;
- un éventuel PSK post-quantique et l’URL interne de l’API Helios.

Les clés privées et PSK sont masqués dans les représentations `Debug`, mais ils
sont actuellement persistés dans le fichier de profils local. La configuration
est stockée dans le répertoire applicatif de l’OS sous `net/helios/orion`. La
variable `ORION_CONFIG` permet de surcharger le chemin en test ou en
développement.

## Cycle de vie et protection anti-fuite

L’état `up` est inféré à partir d’un handshake de moins de 150 secondes.
WireGuard rekeyant silencieusement, il n’existe aucun état `rekeying` dans
l’application.

Orion n’installe pas de pare-feu local. Son invariant est le cycle de vie de
l’adaptateur : avec `AllowedIPs = 0.0.0.0/0`, l’adaptateur reste monté en
`connecting` et après un échec. WireGuard capture alors les routes et jette les
paquets si aucun handshake n’est possible. Seule l’action explicite
« Déconnecter » appelle `down()`.

L’IHM affiche séparément l’état logique du tunnel et l’état réel de
l’adaptateur, afin qu’un échec protégé ne soit pas confondu avec un adaptateur
démonté.

## IHM embarquée

L’intégration est configurée dans `src-tauri/tauri.conf.json` :

- `beforeDevCommand` lance Vite sur le port 1420 ;
- `beforeBuildCommand` exécute `npm run build` ;
- `frontendDist: ../dist` embarque le résultat dans l’application native.
- une CSP restrictive est injectée, sans `unsafe-eval`, et
  `freezePrototype` est activé ;
- la capability de la fenêtre principale reste limitée à `core:default`.

Le package final se construit donc avec :

```sh
npm ci
npm run tauri build
```

Un simple `npm run build` produit uniquement `dist/`. Un simple `cargo build`
compile le shell Rust mais ne remplace pas le workflow de packaging Tauri.

## Développement

```sh
# Cœur portable et tests de sécurité
cargo test -p orion-core

# Tests et build du frontend
npm ci --prefix apps/orion
npm run test:unit --prefix apps/orion
npm run build --prefix apps/orion

# Application complète en simulation
cargo run -p orion

# Variante pilotée par la CLI Tauri
npm run tauri dev --prefix apps/orion
```

En profil de développement, `cargo run -p orion` vérifie que Vite écoute sur
le port 1420 et le démarre automatiquement si nécessaire. Le processus Vite est
arrêté avec Orion. La CLI Tauri continue d'utiliser `beforeDevCommand` ; Orion
détecte alors le serveur déjà actif et ne le lance pas une seconde fois.

Sous WSL2, l'affichage natif exige WSLg. `xdpyinfo` doit pouvoir joindre
`DISPLAY` avant le lancement ; sans WSLg, le shell peut être compilé mais aucune
fenêtre Linux ne peut être affichée.

Sous Linux, Tauri requiert notamment `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`librsvg2-dev`, `patchelf` et `libayatana-appindicator3-dev`. Sous Windows,
l’application utilise WebView2.

## Backend réel

Sans feature, Orion utilise le backend `dry-run`, qui simule l’adaptateur et le
handshake tout en testant le même cycle de vie. Le backend réel est fourni par
`defguard_wireguard_rs` derrière la feature `wireguard` :

```sh
# Compilation Rust du shell avec le backend réel
cargo build -p orion --features wireguard

# Package Tauri avec ce backend
cd apps/orion
npm run tauri build -- --features wireguard
```

Le backend réel doit être exécuté avec le plan de données et les droits requis
sur la plateforme. S’il ne peut pas être initialisé, Orion refuse de démarrer :
un binaire réel ne retombe jamais implicitement sur la simulation. L’IHM affiche
toujours le type de backend actif.

## Provisioning post-quantique

Le client sait générer une paire ML-KEM-768 éphémère, appeler
`POST /api/provision`, vérifier l’identité WireGuard annoncée par la gateway et
dériver un PSK de 32 octets lié aux deux identités et aux deux nonces.

Cette étape suppose que la clé publique du client a déjà été admise hors bande
sur Helios et que le tunnel WireGuard classique est joignable. L’installation
automatique du PSK côté plan de données gateway n’est pas encore câblée ; l’IHM
n’expose donc pas de bouton de provisioning trompeur et signale cette limite à
côté du champ PSK manuel.

## Commandes Tauri exposées

Le frontend utilise les commandes suivantes :

- `get_state`, `backend_kind`, `adapter_is_up` ;
- `get_config`, `save_profile`, `delete_profile`, `select_profile` ;
- `connect`, `disconnect`.

Les événements `state_changed`, `log`, `telemetry` et `error` sont relayés sur
le canal `helios://event`.

## Régression

Depuis la racine du dépôt, `bash scripts/regression.sh` compile le shell Tauri,
teste `orion-core` avec toutes ses features, vérifie le pont IPC, la CSP et les
capabilities, exécute Vitest et construit le frontend. Les tests du backend
WireGuard réel restent à effectuer sur la plateforme cible.

La recette complète pour l'application Tauri, les profils jetables et le cycle
adaptateur/connexion/déconnexion se trouve dans
[`../../docs/testing/MANUAL-TESTING.md`](../../docs/testing/MANUAL-TESTING.md).
