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

#### IPv6 du tunnel

La console lit l'état IPv6 dans `GET /api/status` (`ipv6`) et la VIP IPv6 de
chaque client dans `peers[].address_v6` de la même réponse
([ADRESSAGE-IPV6.md](../specification/ADRESSAGE-IPV6.md) §5.1, §6.2). L'état
est celui du dernier montage de l'interface : remonter l'interface après chaque
changement ci-dessous.

1. **Sans `wg_address_v6`.** Page **Système**, carte « Configuration » : la
   ligne « IPv6 tunnel » vaut `non configurée`, sans aucun avertissement. Page
   **Clients** : chaque ligne ne montre que la VIP IPv4 et l'endpoint, comme
   avant.
2. **Installée.** Décommenter `wg_address_v6` dans le fichier temporaire avec
   un préfixe tiré au hasard, redémarrer `heliosd`, monter l'interface : la
   ligne vaut `installée`. Admettre un client depuis la console : sa ligne
   porte, sous la VIP IPv4, une VIP IPv6 `…/128` en police à chasse fixe ; au
   survol, « VIP IPv6 du client, dans ses AllowedIPs. ». Une VIP IPv6 ou un
   endpoint `[v6]:port` trop long pour la colonne passe à la ligne au lieu
   d'être tronqué par des points de suspension.
3. **Indisponible.** Sans toucher aux sysctl de la machine, faire lire à
   `heliosd` un faux répertoire de réglages noyau :

   ```sh
   mkdir -p /tmp/helios-ipv6/all /tmp/helios-ipv6/default
   echo 1 > /tmp/helios-ipv6/all/disable_ipv6
   echo 0 > /tmp/helios-ipv6/default/disable_ipv6
   HELIOS_IPV6_CONF_PATH=/tmp/helios-ipv6 \
   HELIOS_NETWORK_CONFIG=/tmp/helios-manual.toml target/debug/heliosd run --dev
   ```

   Après montage, la ligne vaut `indisponible`, et un encadré d'avertissement
   (registre `caution`, celui des autres postures réduites) s'affiche sous les
   lignes : « IPv6 indisponible — passerelle en IPv4 seule », puis « Le noyau a
   désactivé IPv6 (net.ipv6.conf.all.disable_ipv6 = 1). » et le rappel que
   WireGuard jette le trafic IPv6 des clients. Page **Clients**, la VIP IPv6
   passe en gris ; au survol, « IPv6 indisponible sur la passerelle : cette VIP
   n’est pas dans les AllowedIPs du client, son trafic IPv6 est jeté. ». Avec
   un répertoire vide (`HELIOS_IPV6_CONF_PATH=/tmp/helios-ipv6-vide`), la
   raison devient « Le noyau n’a pas de pile IPv6 (…/all/disable_ipv6 n’existe
   pas). ». Les raisons `tunnel_mtu_too_small` et `address_refused` ne se
   provoquent que sur une cible réelle (MTU d'uplink, refus du noyau) ; une
   raison inconnue de la console s'affiche « Raison non reconnue par cette
   interface ; le journal de heliosd la donne en clair. », toujours dans
   l'encadré d'avertissement.
4. **Split-tunneling.** Le champ propose `fd12:3456:789a::/48` en exemple à
   côté des CIDR IPv4. Il ne valide rien lui-même : un CIDR IPv6 est transmis
   tel quel, comme un IPv4, et un refus s'affiche de la même manière
   (« Échec de la mise à jour. »).

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
$env:ORION_SIGNING_CERT_SHA1 = "EMPREINTE_SHA1_SANS_SEPARATEURS"
$env:ORION_TIMESTAMP_URL = "http://timestamp.digicert.com"
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
3. importer un profil `.orion` par double-clic quand Orion est arrêté ;
4. recommencer avec Orion ouvert et confirmer qu'une seule fenêtre subsiste ;
5. pour une invitation sans clé privée, confirmer la reprise de la clé du
   profil local qui détient la **clé admise** — quel que soit son nom — et,
   si aucun profil local ne la détient, l'affichage du brouillon accompagné
   du message nommant cette clé ;
6. connecter réellement le tunnel et contrôler handshake, routes et retrait
   uniquement après déconnexion explicite ;
7. dans l'Explorateur, vérifier que les `.orion` portent l'icône de document —
   feuille à coin plié — et non celle de l'application, en thème clair comme en
   thème sombre, en affichage « Grandes icônes » comme en « Détails » ;
8. fermer la fenêtre, puis conduire le tunnel depuis la zone de notification :
   la pastille et la ligne d'état suivent l'état, cocher un profil connecte, le
   décocher déconnecte, « Importer un profil… » ouvre le sélecteur de fichier de
   l'écran *Profils*, et « À propos » annonce la version, le backend et le
   chemin du journal. Enregistrer, supprimer puis renommer un profil pendant que
   le menu existe : la liste doit suivre sans redémarrage.

### Négociation de clé PQC, de bout en bout

Prérequis : la gateway tourne un `heliosd` bâti avec `key-negotiation` (c'est le
cas depuis que `cargo xtask bundle` l'inclut ; `./scripts/deploy.sh` la met à
jour), et les deux ports UDP sont redirigés par la box — 51820 pour WireGuard,
51821 pour la négociation.

Depuis le poste opérateur, une seule commande produit les deux fichiers de
configuration :

```sh
./scripts/key-negotiation-setup.sh christophe@100.72.220.76 --nom portable
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

1. importer le `.orion` ; l'écran *Profils* doit annoncer
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

#### La campagne automatique

Ce qui précède se joue à la main une fois ; la campagne se rejoue à chaque
build. Depuis le poste Windows enrôlé, à la racine du dépôt :

```powershell
pwsh scripts/campaign-windows.ps1 -Profile poste-windows
pwsh scripts/campaign-windows.ps1 -Profile poste-windows -Soak   # + scénarios lents
```

Ou directement l'outil, si l'on ne veut qu'une famille :

```powershell
cargo run -p helios-ctl -- campaign --only negociation-de-cle
cargo run -p helios-ctl -- campaign --only negociation-de-cle --profile poste-windows --soak
```

Trois familles, par ce qu'elles exigent :

| famille | exige | ce qu'elle prend |
|---|---|---|
| crypto | rien | ML-KEM aller-retour, secret implicite d'une clé étrangère, PSK lié à la transcription, dérivation refusée hors ML-KEM, signature ML-DSA-65 altérée, certificat épinglé (clé, nom, rôle, date) |
| profil | le profil enrôlé + l'identité scellée | bloc valide face à sa gateway, identité scellée émise pour **cette** clé WireGuard, plancher tenu avant tout réseau |
| gateway | la gateway joignable | négociation nominale, PSK frais à chaque fois, abandon qui libère le pair, **lien de vivacité maintenu 40 s** (`--soak`) |

La famille crypto tourne aussi dans `cargo test` : une primitive cassée est
prise par la régression, sans attendre que quelqu'un lance la campagne. Les
deux autres ne peuvent pas l'être — DPAPI et la gateway n'existent pas sous
WSL2 — et c'est précisément le trou que cette campagne comble.

**La famille gateway négocie pour de vrai** : la gateway pose puis retire un
PSK sur le plan de données. Un Orion connecté avec le même profil perd son
tunnel. À jouer quand le poste ne sert pas.

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
et émet deux profils. Importer `lab-poste.orion` : il porte tout ce qu'il faut et
son pair est réellement admis, ce que des clés fabriquées à la main ne
garantissent pas.

Vérifier ensuite, dans l'onglet **Profils** :

- la **clé publique du client** s'affiche en lecture seule et correspond à celle
  que `helios-ctl peer list` montre côté gateway — c'est la valeur que
  l'utilisateur transmet à l'opérateur ;
- importer `lab.invitation.orion` (sans clé privée) alors qu'un profil `lab`
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
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
```

Remplacer les valeurs entre chevrons par les clés générées. Vérifier que le
profil importé est présenté comme un brouillon, puis l’enregistrer. Réimporter
le même fichier doit avertir que l’enregistrement remplacera le profil
existant. Un fichier contenant un second `[Peer]` ou `DNS = 100.64.0.1` doit
être refusé explicitement et ne doit modifier aucun profil enregistré.

Le même fichier avec `AllowedIPs = 0.0.0.0/0` seul (l’ancien tunnel complet)
doit s’importer tel quel : sous « Avancé », le choix « Personnalisé » est actif
et l’avertissement « Tunnel complet IPv4 seulement : le trafic IPv6 sort en
clair » est affiché. Une fois enregistré puis rouvert, le profil reste
`0.0.0.0/0`, l’écran indique « Profil à jour » malgré l’avertissement, et le
panneau de posture affiche la ligne « trafic via le tunnel » en ambre. Choisir
« Tout » puis enregistrer écrit `0.0.0.0/0, ::/0` et fait disparaître les deux
avertissements.

Le même profil peut toujours être créé à la main avec :

- endpoint : `127.0.0.1:51820` ;
- clé privée : `client_private` ;
- clé publique de gateway : `gateway_public` ;
- adresse : `100.64.1.2/32` ;
- AllowedIPs : `0.0.0.0/0, ::/0` ;
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

### Capture réellement appliquée (VM Windows)

Ce contrôle exige une VM Windows dual-stack et un Orion compilé avec
`--features wireguard` : ni WSL ni le backend simulé ne l'exercent. Il vérifie
que `::/0`, retiré silencieusement par `defguard_wireguard_rs` quand
l'adaptateur ne porte pas l'IPv6, est signalé au lieu d'être tu.

1. **Cas nominal.** Connecter un profil `0.0.0.0/0, ::/0`. Le journal doit
   afficher « AllowedIPs appliqués vérifiés sur l'adaptateur », aucune erreur
   ne doit apparaître et la ligne « trafic via le tunnel » du panneau de
   posture doit rester neutre. `Get-NetRoute -InterfaceAlias orion0` doit
   lister `0.0.0.0/0` et `::/0`. Une alerte ici serait un faux positif à
   corriger avant tout le reste.
2. **IPv6 indisponible sur l'adaptateur.** Déconnecter, poser
   `DisabledComponents = 0xFF` (DWORD) sous
   `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`, redémarrer,
   puis connecter le même profil. Attendu : le tunnel monte en IPv4, l'erreur
   « AllowedIPs non appliqués par le pilote : ::/0 — ce trafic n'est pas capté
   par le tunnel et peut sortir en clair par l'interface physique » s'affiche
   dans le bandeau et le journal, et la ligne « trafic via le tunnel » passe
   en ambre : « ::/0 non appliqué par le pilote — hors tunnel ».
   `Get-NetRoute -InterfaceAlias orion0 -AddressFamily IPv6` ne liste rien.
   Ce réglage retire l'IPv6 de toutes les interfaces : il éprouve la
   détection, pas la fuite. Remettre la valeur d'origine et redémarrer.
3. **La fuite elle-même** — IPv6 présent sur l'interface physique, absent de
   l'adaptateur. Il faut que l'adaptateur soit **reconfiguré** après
   `Disable-NetAdapterBinding -Name orion0 -ComponentID ms_tcpip6` : le
   backend relit à chaque configuration, mais ne recrée l'adaptateur qu'au
   premier montage. C'est le cas du remontage post-quantique d'un profil
   portant `heliosd_url` sans bloc de négociation : désactiver la liaison
   entre le montage et le premier handshake (UDP 51820 bloqué le temps de la
   commande), puis débloquer. Attendu : l'alerte de l'étape 2 après le
   remontage, et `curl.exe -6 https://ifconfig.co` qui répond depuis
   l'adresse IPv6 de l'interface physique — la fuite que l'alerte nomme.
4. **Persistance.** Faire tomber le tunnel en échec, adaptateur monté : la
   ligne ambre doit rester, les routes n'ayant pas changé. **Déconnecter**
   doit la faire disparaître.

Rien de ceci n'a encore été observé sur cible : ni l'effet de
`DisabledComponents` ou de `Disable-NetAdapterBinding` sur un adaptateur
WireGuard-NT, ni la présence des routes juste après la remise en service de
l'adaptateur (`defguard` le désactive puis le réactive pour appliquer la MTU).
L'étape 1 est celle qui écarte un faux positif, l'étape 2 celle qui prouve la
détection.

### Endpoint en FQDN double pile : repli IPv4 visible (VM Windows)

Ce contrôle exige une VM Windows disposant d'une route IPv6 par défaut et un
Orion compilé avec `--features wireguard`. Sous WSL, seuls l'ordre des
candidats et la course échelonnée sont exercés, avec des connecteurs simulés
(`scripts/wsl-cargo test -p orion-core endpoint_resolution`) : ni une vraie
résolution `A`/`AAAA`, ni un chemin IPv6 cassé, ni WireGuard-NT.

Ce qu'il vérifie : le nom de la gateway est résolu **une seule fois** par
tentative, les candidats sont essayés selon RFC 8305 (famille triée en tête par
le résolveur, puis l'autre 250 ms plus tard, ou aussitôt après un échec), et le
tunnel WireGuard est posé sur l'adresse **littérale** qui a négocié, jamais sur
une seconde résolution.

1. **Préparer le nom.** Profil Helios dont l'endpoint WireGuard et l'endpoint
   de négociation nomment le même FQDN (ports 51820 et 51821). Dans
   `C:\Windows\System32\drivers\etc\hosts`, faire porter à ce nom l'IPv4 réelle
   de la gateway **et** une IPv6 qui ne répond pas, par exemple
   `2001:db8::dead`. Vérifier avec `Resolve-DnsName <fqdn>` que les deux
   réponses reviennent, et avec
   `[System.Net.Dns]::GetHostAddresses('<fqdn>')` (ordre de `getaddrinfo`)
   que Windows trie bien l'IPv6 en tête. Sans route IPv6 par défaut, Windows trie
   l'IPv4 en tête (RFC 6724) : le journal affiche alors l'IPv4 retenue sans
   candidat écarté, ce qui est le comportement attendu mais pas le cas testé.
2. **Connecter.** Le tunnel doit monter en IPv4 avec ~250 ms de retard au
   plus, sans attendre les 10 s du délai de connexion QUIC. Le journal doit
   afficher, en avertissement :
   « négociation 1/3 : endpoint `<fqdn>:51821` : IPv4 `<ip>:51821` retenu après
   IPv6 [2001:db8::dead]:51821 sans réponse, tentative annulée » (ou « en
   échec (…) » si Windows refuse l'envoi d'emblée), puis « endpoint WireGuard
   `<fqdn>:51820` : IPv4 `<ip>:51820` (l'adresse qui a négocié) » et
   « pair configuré vers `<ip>:51820` ». `orion.log` montre les deux lignes
   « endpoint candidate: attempt started », la seconde 250 ms après la
   première.
3. **Profil intact.** L'endpoint affiché par le profil reste `<fqdn>:51820` :
   seule la copie remise au plan de données porte le littéral. Une
   reconnexion doit refaire la résolution (les lignes de l'étape 2
   réapparaissent).
4. **Aucune transaction orpheline.** Côté gateway,
   `journalctl -u heliosd --since -5min` ne doit montrer qu'une seule requête
   de négociation pour la tentative. Si la gateway écoute aussi en IPv6 et que
   les deux candidats l'atteignent, la connexion perdante apparaît au plus
   comme « quic: key-negotiation connection rejected » sans transaction
   préparée : elle est abandonnée avant la requête signée.
5. **Tous les candidats injoignables.** Remplacer l'IPv4 par une adresse
   muette (`192.0.2.1`). Attendu : « négociation 1/3 : échec — no address of
   `<fqdn>:51821` answered — [2001:db8::dead]:51821 (IPv6): … ;
   192.0.2.1:51821 (IPv4): … », les trois tentatives habituelles, puis l'échec
   final. L'adaptateur reste monté s'il l'était (ADR-001 §3 bis).
6. **Profil classique.** Sans bloc de négociation, l'endpoint WireGuard est le
   premier candidat de l'ordre RFC 8305 : il n'y a pas de course possible,
   WireGuard n'acceptant qu'un endpoint par pair. Le journal affiche
   « endpoint WireGuard `<fqdn>:51820` : IPv6 … (premier candidat de sa
   résolution) ». Avec l'IPv6 muette de l'étape 1, ce tunnel ne monte pas :
   c'est la limite connue du profil classique, nommée par le journal.

Restaurer le fichier `hosts` à la fin.

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

## Le speedtest ne répond pas

Orion affiche « aucune réponse de la gateway sur le port 55182 » : les paquets
partent dans le tunnel et rien ne revient. Deux causes, deux vérifications sur
la gateway.

```sh
# 1. heliosd écoute-t-il, et sur la bonne adresse ?
ss -lntup | grep 55182  # attendu : 100.64.0.1:55182, pas 127.0.0.1:55182
journalctl --namespace=helios -u heliosd | grep 'raw speedtest'

# 2. le pare-feu ouvre-t-il le port sur l'interface du tunnel ?
nft list chain inet helios input | grep 55182
# attendu : deux règles `iifname "helios0" ... dport 55182 accept`
```

Une écoute sur `127.0.0.1` signifie que la gateway a démarré sans identité
WireGuard : l'adresse du tunnel n'existait pas, et le service s'est replié sur
la boucle locale jusqu'au prochain démarrage.

À ne pas confondre avec un port **occupé** : là, Orion dit que la gateway ne
sert pas le speedtest (un refus, `os error 10054`), et
`ss -lntup | grep 55182` nomme le programme fautif. Le service Helios utilise
`55182`, dans la plage privée/dynamique, afin de rester distinct de WireGuard
(`51820`), de la négociation de clé (`51821`) et d'iperf3 (`5201`). Le silence
est un problème de joignabilité, le refus un problème d'occupation.

## Recouper le speedtest avec `iperf3`

Le speedtest intégré mesure le plan de données WireGuard avec ses propres
sockets. Pour savoir si ses chiffres sont justes, il faut une seconde mesure
qui ne partage aucun code avec lui — `iperf3` est la référence.

### Ouvrir le port

Rien n'est ouvert par défaut : un `iperf3` joignable en permanence est une
surface joignable en permanence. Dans `/var/lib/helios/network.toml` :

```toml
iperf_port = 5202
```

Le fichier est relu à chaud, donc le pare-feu se reconstruit sans redémarrer
`heliosd`. Le port s'ouvre **dans les deux sens** sur l'interface du tunnel, et
c'est la moitié `output` qui compte : la gateway en rôle client ouvre un flux
sortant *neuf* sur `helios0`, que la politique `drop` prend si la chaîne
`output` ne l'accepte pas. Le symptôme est un `iperf3 -c` figé sur
« Connecting to host », qui se lit comme un serveur en face qui n'écoute pas.

Le port est fermé tant que `wireguard_ready()` est faux : une règle portant sur
une interface qui ne peut pas exister ne vaut rien.

Vérifier après rechargement :

```sh
sudo nft list chain inet helios input  | grep 5202
sudo nft list chain inet helios output | grep 5202
```

Quatre lignes attendues — TCP et UDP, `iifname` et `oifname`.

### Serveur sur la gateway

```sh
sudo apt-get install -y iperf3      # exige allow_gateway_egress
iperf3 --server --port 5202 --bind 100.64.0.1
```

`--bind` sur la VIP est délibéré : sans lui `iperf3` écoute sur `0.0.0.0`,
donc aussi sur le WAN. Le pare-feu le refuserait de toute façon, mais un
service qui n'écoute pas là où il ne doit pas est une défense de moins à
solliciter.

Depuis le client, tunnel monté :

```sh
iperf3 -c 100.64.0.1 -p 5202          # descendant : -R
iperf3 -c 100.64.0.1 -p 5202 -u -b 0  # UDP
```

### Serveur sur le client

C'est le sens le plus courant — on est déjà assis devant cette machine. Sous
Windows, ouvrir aussi le pare-feu Windows sur 5202, que ce port soit atteint
par l'adaptateur WireGuard :

```powershell
New-NetFirewallRule -DisplayName "iperf3 Helios" -Direction Inbound `
  -Protocol TCP -LocalPort 5202 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "iperf3 Helios UDP" -Direction Inbound `
  -Protocol UDP -LocalPort 5202 -Action Allow -Profile Any
iperf3.exe --server --port 5202
```

Puis, depuis la gateway, vers la VIP du client :

```sh
iperf3 -c 100.64.1.2 -p 5202
```

### Lire le résultat

Comparer au speedtest d'Orion, qui mesure la même chose par un autre chemin :

* **débit TCP proche** des deux côtés — le speedtest est juste ;
* **perte UDP proche de zéro** sous `iperf3 -u -b <débit TCP>` — c'est la même
  question que pose la jambe de qualité, cadencée à 85 % du débit TCP ;
* un `iperf3 -u -b 0` renvoie une perte énorme, et c'est **normal** : sans
  `-b`, `iperf3` émet à fond, et la perte mesure alors l'écart entre son
  émetteur et le lien, pas le lien. C'est exactement le défaut que la cadence
  corrige côté Helios ; ne pas comparer ce chiffre-là à celui d'Orion.

### Refermer

Retirer `iperf_port` de `network.toml` une fois la mesure faite. Le pare-feu
se referme au rechargement, sans redémarrage.
