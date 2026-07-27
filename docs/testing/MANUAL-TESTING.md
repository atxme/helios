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

`ORION_CONFIG` empêche le test de modifier les profils habituels.

### Accessibilité et interactions

Sur Windows et Linux cible, vérifier au clavier et avec le lecteur d’écran
disponible sur la plateforme :

1. parcourir Connexion, Profils et Journal sans souris ; chaque contrôle actif
   doit recevoir un focus nettement visible ;
2. changer d’onglet avec les flèches, puis confirmer que son panneau est
   annoncé avec le bon intitulé ;
3. provoquer une erreur de connexion et confirmer son annonce immédiate, puis
   fermer l’alerte avec son bouton nommé ;
4. afficher et masquer chaque secret ; le nom accessible doit décrire l’action
   à venir et aucun secret ne doit être annoncé tant qu’il reste masqué ;
5. ouvrir la suppression d’un profil, annuler une première fois, puis confirmer
   que la boîte de dialogue décrit l’effet et précise que le pair distant reste
   admis ;
6. activer la réduction des animations dans l’OS et vérifier que le halo et
   l’orbite ne produisent plus d’animation perceptible ;
7. agrandir le texte à 200 % et vérifier que chaque vue reste défilable sans
   masquer les actions Enregistrer, Connecter ou Déconnecter.

Les couleurs ne doivent jamais être le seul signal : la posture comporte un
libellé et une icône, le journal un liseré et un niveau, et les erreurs un rôle
d’alerte. Les contrôles matériels, WireGuard et packaging restent à exécuter
séparément selon la plateforme.

### Installateurs Orion

Sur le poste de build **Windows**, une seule commande :

```powershell
$env:HELIOS_PUBLISHER_KEYRING_PATH = "C:\chemin\publisher-keyring.json"
$env:ORION_SIGNING_CERT_SHA1 = "EMPREINTE_SHA1_SANS_ESPACES"
$env:ORION_TIMESTAMP_URL = "https://tsa.interne.example/rfc3161"
cargo xtask orion-msi
```

C'est la **même** commande que joue la CI de release : les features y sont
tenues en un seul endroit (`ORION_FEATURES`), donc un installateur bâti ici et
un installateur bâti par la CI portent les mêmes drapeaux. Il n'en reste
qu'une, `wireguard` (backend réel ; sans elle Orion refuse de démarrer plutôt
que de simuler). La négociation PQC, elle, n'est plus une option de
compilation : tout Orion la porte, parce qu'un binaire d'apparence normale qui
importe un profil épinglé puis échoue à se connecter est indiscernable, pour
l'utilisateur, d'une gateway en panne.

Tous les prérequis sont vérifiés **avant** la compilation : trousseau éditeur,
certificat de signature, horodateur. Un build qui tourne plusieurs minutes puis
s'arrête sur une variable manquante est exactement ce que cette commande évite.

Pour un installateur de test, sans certificat Authenticode :

```powershell
cargo xtask orion-msi --unsigned
```

Ce chemin est bruyant par construction : chaque artefact est annoncé comme non
signé. Il sert à éprouver l'installation et la négociation, jamais à
distribuer — Windows affichera un avertissement SmartScreen.

Options : `--with-nsis` pour produire aussi le NSIS, `--skip-npm-ci` quand
`node_modules` est déjà installé. La commande termine en affichant le chemin et
l'empreinte SHA-256 de chaque artefact — la valeur à comparer après transfert.

Sur une machine qui n'est pas Windows, la commande **refuse immédiatement** en
expliquant pourquoi : WiX et l'éditeur de liens MSVC n'ont pas d'équivalent
croisé. Ce qui reste vérifiable ailleurs, c'est la compilation :

```sh
HELIOS_PUBLISHER_KEYRING_PATH=... cargo build -p orion --features wireguard
```

Après installation sur une machine propre :

1. vérifier `signtool verify /pa /tw` sur l'exécutable et l'installateur ;
2. vérifier la demande UAC au lancement ;
3. importer un profil `.orionprofile` par double-clic quand Orion est arrêté ;
4. recommencer avec Orion ouvert et confirmer qu'une seule fenêtre subsiste ;
5. pour une invitation sans clé privée, confirmer la reprise de la clé du
   profil local qui détient la **clé admise** — quel que soit son nom — et,
   si aucun profil local ne la détient, l'affichage du brouillon accompagné
   du message nommant cette clé ;
6. connecter réellement le tunnel et contrôler handshake, routes et retrait
   uniquement après déconnexion explicite.

### Négociation de clé PQC, de bout en bout

Prérequis : la gateway tourne un `heliosd` bâti avec `key-negotiation` (c'est le
cas depuis que `cargo xtask bundle` l'inclut ; `./scripts/deploy.sh` la met à
jour), et les deux ports UDP sont redirigés par la box — 51820 pour WireGuard,
51821 pour la négociation.

Depuis le poste opérateur, une seule commande produit les deux fichiers de
configuration :

```sh
./scripts/key-negotiation-setup.sh christophe@192.168.1.44 --nom portable
```

Pour **ajouter la négociation à un profil Orion déjà en place**, repartir de sa
clé publique — celle qu'affiche l'écran *Profils* sous « Votre clé publique » :

```sh
./scripts/key-negotiation-setup.sh --nom Helios-gateway \
  --public-key zU0Edj1phreNdcsrFujZRi+U7wrV607a...
```

Le document produit ne porte alors aucune clé privée WireGuard : à l'import,
Orion reprend celle du profil local qui détient cette clé publique et ne fait
que lui ajouter le bloc de négociation. L'admission déjà en place sur la
gateway reste valable, puisque la clé ne change pas.

La correspondance se fait sur la **clé**, pas sur le nom : le poste nomme
rarement son profil comme l'opérateur nomme le pair, et exiger l'égalité des
deux refusait des documents pourtant valables. La clé admise est celle
qu'affiche `helios-ctl profile check <fichier>`.

Elle crée la CA opérateur si besoin, fait naître l'identité de négociation
**sur** la gateway (scellée au TPM), ouvre le port dans son `network.toml`, émet
les certificats du client, admet le pair par `heliosd peer add` et assemble le
profil. Le profil produit porte les clés privées du client : le transférer par
un canal maîtrisé et le détruire des deux côtés après import.

Tout passe par SSH, **jamais par l'API de contrôle** : celle-ci vit derrière le
tunnel, et l'exiger reviendrait à faire dépendre d'une première connexion la
négociation qui protège précisément la première connexion. C'est aussi pourquoi
l'admission emprunte la console (`heliosd peer add`) plutôt que `POST
/api/peers`, réservé à un pair admin déjà connecté.

Sur le poste Windows :

1. importer le `.orionprofile` ; l'écran *Profils* doit annoncer
   **identité protégée · scellée** ;
2. comparer l'empreinte PQ affichée avec celle qu'a imprimée
   `heliosd init-key-negotiation` — c'est ce qui rattache le profil à cette
   gateway et rien d'autre ;
3. supprimer le fichier d'enrôlement, puis connecter : la négociation doit
   aboutir sans lui, l'identité étant scellée au compte Windows ;
4. l'écran *Connexion* doit afficher `négociation ML-KEM-1024` puis, une fois le
   handshake obtenu, la puce `PSK PQC · ML-KEM-1024` ;
5. côté gateway, `helios-ctl peer list` doit montrer le plancher monté à
   `ml_kem` pour ce pair ;
6. rejouer une connexion après avoir forcé `--mode classic` dans l'écran
   *Profils* : le mode doit être **indisponible**, le plancher ayant monté ;
7. toujours dans *Profils*, éprouver l'édition du bloc : coller un certificat
   PQ tronqué doit afficher l'empreinte « illisible », signaler le bloc en
   erreur et désactiver *Enregistrer* ; le *Plancher* ne doit proposer que
   des valeurs supérieures ou égales à celle du profil chargé, et *Retirer*
   doit disparaître dès que ce plancher dépasse « Classique ».

Contrôles négatifs, qui valent plus que le chemin nominal :

- copier le dossier `identities` scellé vers un autre compte Windows : le
  descellement doit échouer et la connexion être refusée avant WireGuard ;
- couper la redirection UDP 51821 : la connexion doit échouer explicitement,
  sans repli silencieux vers un premier handshake nu ;
- sur la gateway, `sudo ss -lun | grep 51821` doit montrer le port ouvert
  seulement quand `key_negotiation_port` est déclaré.

Sur une cible Debian, installer le `.deb`, puis vérifier :

```sh
getcap /usr/bin/orion
/usr/bin/orion
```

La première commande doit annoncer `cap_net_admin=ep`. La seconde doit ouvrir
WebKitGTK sans dépendre de `LD_LIBRARY_PATH`; si une distribution supportée
échoue précisément après `setcap`, conserver les traces du chargeur et appliquer
la décision ADR-004 de basculer le privilège réseau vers polkit.

### Le chemin court : un profil venu d'une vraie gateway

`bash scripts/lab.sh --keep` monte une gateway de développement, admet un client
et émet deux profils. Importer `lab-poste.json` : il porte tout ce qu'il faut et
son pair est réellement admis, ce que des clés fabriquées à la main ne
garantissent pas.

Vérifier ensuite, dans l'onglet **Profils** :

- la **clé publique du client** s'affiche en lecture seule et correspond à celle
  que `helios-ctl peer list` montre côté gateway — c'est la valeur que
  l'utilisateur transmet à l'opérateur ;
- importer `lab.invitation.json` (sans clé privée) alors qu'un profil `lab`
  existe déjà localement : la clé privée locale doit être reprise
  silencieusement, sans que l'utilisateur ait à la ressaisir ;
- importer ce même fichier d'invitation en ayant renommé le profil local :
  la clé doit être reprise quand même, la correspondance se faisant sur la
  clé admise ;
- importer une invitation dont **aucun** profil local ne détient la clé : le
  brouillon doit s'afficher, le champ *Clé privée* rester vide et le message
  nommer la clé attendue, sans qu'aucun profil enregistré ne soit modifié.

### Le chemin manuel

Dans un autre terminal, générer deux identités de test :

```sh
client_private=$(wg genkey)
client_public=$(printf '%s\n' "$client_private" | wg pubkey)
gateway_private=$(wg genkey)
gateway_public=$(printf '%s\n' "$gateway_private" | wg pubkey)
printf 'client privé: %s\nclient public: %s\ngateway public: %s\n' \
  "$client_private" "$client_public" "$gateway_public"
```

Dans l’onglet **Profils**, utiliser **Importer** avec un fichier WireGuard
`site-labo.conf` contenant :

```ini
[Interface]
PrivateKey = <client_private>
Address = 100.64.1.2/32

[Peer]
PublicKey = <gateway_public>
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
```

Remplacer les valeurs entre chevrons par les clés générées. Vérifier que le
profil importé est présenté comme un brouillon, puis l’enregistrer. Réimporter
le même fichier doit avertir que l’enregistrement remplacera le profil
existant. Un fichier contenant un second `[Peer]` ou `DNS = 100.64.0.1` doit
être refusé explicitement et ne doit modifier aucun profil enregistré.

Le même profil peut toujours être créé à la main avec :

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
