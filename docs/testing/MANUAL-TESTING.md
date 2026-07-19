# Tests manuels des binaires et des interfaces

Ce guide complète la campagne automatisée de `scripts/regression.sh`. Les essais
du plan de données réel doivent se faire sur une machine Linux isolée avec un
accès console : le kill-switch modifie le routage et le pare-feu.

## Prérequis

- Rust stable et Cargo ;
- Node.js `^20.19.0` ou `>=22.12.0`, avec npm ;
- `wireguard-tools` pour générer des clés de test ;
- pour Orion sous Linux : WebKitGTK 4.1, GTK 3, librsvg, patchelf et
  Ayatana AppIndicator.

Sur Ubuntu/Debian :

```sh
sudo apt install wireguard-tools libwebkit2gtk-4.1-dev libgtk-3-dev \
  librsvg2-dev patchelf libayatana-appindicator3-dev
```

Commencer par vérifier l'ensemble du dépôt :

```sh
bash scripts/regression.sh
```

Cette commande inclut désormais `npm audit` et refuse toute vulnérabilité npm
de niveau modéré ou supérieur.

Installer aussi `cargo-audit` une fois (`cargo install cargo-audit --locked`) :
la campagne refuse les avis de sécurité Rust connus.

## Helios et son IHM en simulation

### 1. Préparer une configuration jetable

Ne pas réutiliser une identité de production. Depuis la racine du dépôt :

```sh
cp config/network.toml /tmp/helios-manual.toml
wg genkey
```

Copier la clé affichée dans `wg_private_key` du fichier temporaire. Les
interfaces indiquées peuvent rester fictives en `--dev`. La variable
`HELIOS_NETWORK_CONFIG` isole cette configuration de
`/var/lib/helios/network.toml`.

### 2. Tester les binaires sans interface web

Terminal 1 :

```sh
HELIOS_NETWORK_CONFIG=/tmp/helios-manual.toml \
  RUST_LOG=heliosd=debug cargo run -p heliosd -- run --dev
```

Terminal 2 :

```sh
cargo run -p helios-ctl -- status
cargo run -p helios-ctl -- network show
cargo run -p helios-ctl -- scenario nominal
cargo run -p helios-ctl -- scenario flap
cargo run -p helios-ctl -- watch
```

En simulation, une montée atteint `connecting`, pas `up` : aucun faux handshake
n'est inventé. Le retour à `down` doit réengager le kill-switch. `watch` doit
afficher les changements d'état et les journaux jusqu'à `Ctrl-C`.

Pour viser une autre instance :

```sh
HELIOS_URL=http://ADRESSE:8080 cargo run -p helios-ctl -- status
```

### 3. Tester l'IHM Helios avec rechargement à chaud

Conserver `heliosd` du terminal 1, puis lancer :

```sh
npm ci --prefix web
npm run dev --prefix web -- --host 127.0.0.1
```

Ouvrir `http://127.0.0.1:5173`. Vérifier :

1. l'état initial `down` et le kill-switch engagé ;
2. **Monter l'interface**, puis l'état `connecting` ;
3. l'arrivée des événements dans le terminal de l'IHM ;
4. l'enregistrement puis la suppression de CIDR de split-tunneling ;
5. **Arrêter l'interface**, puis le retour à `down`.

### 4. Tester l'IHM réellement embarquée dans `heliosd`

```sh
npm run build --prefix web
cargo build -p heliosd --features embed-ui
HELIOS_NETWORK_CONFIG=/tmp/helios-manual.toml \
  target/debug/heliosd run --dev
```

Ouvrir `http://127.0.0.1:8080`, sans lancer Vite. Si l'écran s'affiche et que
`/api/status` répond, les fichiers React sont bien présents dans le binaire.

Contrôle rapide :

```sh
curl --fail http://127.0.0.1:8080/api/status
curl --fail http://127.0.0.1:8080/
```

### 5. Contrôler le contrat de sécurité HTTP

```sh
curl --fail http://127.0.0.1:8080/api/network
curl --fail http://127.0.0.1:8080/api/trust

# Doit répondre 415 et ne déclencher aucune commande.
curl --include --request POST http://127.0.0.1:8080/api/tunnel/start

# Doit répondre 200.
curl --fail --request POST --header 'Content-Type: application/json' \
  --data '{}' http://127.0.0.1:8080/api/tunnel/start
```

Vérifier qu’aucune valeur de `wg_private_key` ou `preshared_key` n’apparaît dans
la première réponse et qu’aucun en-tête `Access-Control-Allow-Origin: *` n’est
présent.

## Billets éditeur hybrides

Exercer le cycle dans un répertoire jetable, jamais avec une clé de production :

```sh
tmp_keys=$(mktemp -d)
cargo run -p helios-publisher -- keygen --key-epoch 99 --output-dir "$tmp_keys/keys"
cargo run -p helios-publisher -- reseal-ticket \
  --key-epoch 99 --version 1 \
  --ed25519-private-key "$tmp_keys/keys/ed25519-private.pk8" \
  --ml-dsa-65-private-key "$tmp_keys/keys/ml-dsa-65-private.bin" \
  --keyring "$tmp_keys/keys/publisher-keyring.json" \
  --output "$tmp_keys/ticket.json"
```

Le billet doit contenir exactement une signature `ed25519` et une
`ml-dsa-65`. Une deuxième commande vers le même `--output` doit échouer. Le
guide de production est [PUBLISHER-SIGNING.md](../security/PUBLISHER-SIGNING.md).

## Orion et son IHM Tauri

Un navigateur lancé avec `npm run dev` ne suffit pas pour Orion : les actions
de connexion passent par les commandes IPC Tauri. Tester l'application complète :

```sh
npm ci --prefix apps/orion
cd apps/orion
ORION_CONFIG=/tmp/orion-manual/profiles.toml npm run tauri dev
```

`ORION_CONFIG` empêche le test de modifier les profils habituels. Dans un autre
terminal, générer deux identités de test :

```sh
client_private=$(wg genkey)
client_public=$(printf '%s\n' "$client_private" | wg pubkey)
gateway_private=$(wg genkey)
gateway_public=$(printf '%s\n' "$gateway_private" | wg pubkey)
printf 'client privé: %s\nclient public: %s\ngateway public: %s\n' \
  "$client_private" "$client_public" "$gateway_public"
```

Créer un profil dans l'IHM avec :

- endpoint : `127.0.0.1:51820` ;
- clé privée : `client_private` ;
- clé publique de gateway : `gateway_public` ;
- adresse : `100.64.1.2/32` ;
- AllowedIPs : `0.0.0.0/0` ;
- keepalive : `25`.

Le backend par défaut est simulé. Vérifier que le profil peut être enregistré
et sélectionné, que **Connecter** mène à `up`, que l'indicateur d'adaptateur est
monté, puis que **Déconnecter** revient à `down` et démonte l'adaptateur.

Inspecter aussi la configuration Tauri générée : la CSP doit être présente,
`freezePrototype` actif et la capability limitée à `core:default` pour la
fenêtre `main`.

Pour tester le paquet réellement distribué :

```sh
cd apps/orion
npm run tauri build
```

Le binaire est produit dans `target/release/orion` et les installateurs dans
`target/release/bundle/` à la racine du workspace.

## Test réel WireGuard sur Linux

Effectuer ce scénario uniquement sur une gateway de laboratoire :

```sh
npm run build --prefix web
cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
cd apps/orion
npm run tauri build -- --features wireguard
```

Configurer `/var/lib/helios/network.toml` avec de vraies interfaces, une
identité gateway, la clé publique d'un client de test et sa VIP. Démarrer
`heliosd` avec les droits réseau/TPM requis, puis Orion avec le backend réel.

Contrôler sur la gateway :

```sh
sudo wg show helios0
ip address show dev helios0
sudo nft list table inet helios
ss -lun | grep 51820
```

La recette de sécurité attendue est :

1. au démarrage, politiques nftables à `drop` et aucun transfert LAN ;
2. après la commande de montée mais avant handshake, état `connecting` et
   trafic toujours bloqué ;
3. après handshake Orion, état `up` et compteurs WireGuard croissants ;
4. après expiration du handshake ou coupure du pair, retour fail-closed ;
5. après déconnexion explicite, interface client démontée et routes capturées
   supprimées ;
6. API et IHM Helios injoignables depuis le WAN, mais joignables depuis le
   tunnel sur l'adresse `wg_address`.
7. un Orion compilé avec `wireguard` refuse de démarrer si le backend réel est
   absent ou non initialisable ; aucun repli dry-run n’est acceptable.

Le provisioning ML-KEM peut être testé au niveau protocole, mais son PSK ne doit
pas être considéré comme installé automatiquement tant que le câblage atomique
du plan de données gateway n'est pas terminé.
