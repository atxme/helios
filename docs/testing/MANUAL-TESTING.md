# Tests manuels des binaires et des interfaces

Ce guide complète la campagne automatisée de `scripts/regression.sh`. Les essais
du plan de données réel doivent se faire sur une machine Linux isolée avec un
accès console : le kill-switch modifie le routage et le pare-feu.

## Prérequis

- Rust stable et Cargo ;
- Node.js `^22.22.2`, `^24.15.0` ou `>=26.0.0`, avec npm ;
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
cargo run -p helios -- status
cargo run -p helios -- network show
cargo run -p helios -- scenario nominal
cargo run -p helios -- scenario flap
cargo run -p helios -- watch
```

En simulation, une montée atteint `connecting`, pas `up` : aucun faux handshake
n'est inventé. Le retour à `down` doit réengager le kill-switch. `watch` doit
afficher les changements d'état et les journaux jusqu'à `Ctrl-C`.

Pour viser une autre instance :

```sh
HELIOS_URL=http://ADRESSE:8080 cargo run -p helios -- status
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

`ORION_CONFIG` empêche le test de modifier les profils habituels. Elle n'est
lue qu'en build de développement (`cfg(debug_assertions)`) : un binaire de
release l'ignore, et sous Windows le moteur élevé ne reçoit aucun chemin de
l'IHM (voir « Séparation des privilèges (F11) »).

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

### Séparation des privilèges (F11)

Recette de la séparation de `orion.exe` en une IHM non élevée et un moteur élevé
([spec](../superpowers/specs/2026-10-24-separation-privileges-windows-design.md)
§13, [ADR-004](../adr/ADR-004-CHAINE-DE-LIVRAISON.md) §9,
[ADR-006](../adr/ADR-006-SECRETS-AU-REPOS.md) §7). Elle se déroule sur un
Windows réel, avec le TPM et le paquet de **release** produit par
`cargo xtask orion-msi`, installé pour la machine (sous `Program Files`).

**Rien de ce qui suit n'a été observé sous Windows à ce jour.** Chaque
« attendu » décrit ce que le code de la branche produit ; il est **à valider en
recette**, jamais acquis. Les tests Windows de la branche
(`cargo test -p orion --features wireguard` et
`cargo test -p orion-core --features wireguard`, depuis un dépôt cloné sous
Windows) sont à lancer avant, et leur résultat est à noter ici.

Repères communs :

- le journal de l'IHM est `orion-ui.log`, dans
  `%APPDATA%\helios\orion\config` ; celui du moteur est `orion.log`, sous la
  racine protégée `%ProgramData%\helios\orion\<SID>\` (lisible depuis un
  terminal administrateur seulement) ;
- le moteur est le processus `orion.exe` dont la ligne de commande commence par
  `--engine` ; dans le Gestionnaire des tâches (onglet Détails, colonne
  « Élévation »), l'IHM doit être **non élevée** et le moteur **élevé** ;
- codes de sortie du moteur (`crates/orion-engine/src/lifecycle.rs`) : 0 pour un
  arrêt demandé, 1 pour toute autre fin de session ou échec de démarrage,
  2 pour des arguments illisibles, **3** pour une racine protégée refusée,
  **4** pour une installation modifiable ;
- aucun journal ne doit contenir de clé privée, de PSK, de PIN ni de jeton.

**1. Lancement.** Lancer Orion depuis l'icône, avec un compte standard.
Attendu : un seul UAC, puis la fenêtre ; deux processus `orion.exe` (IHM non
élevée, moteur élevé caché) ; au premier démarrage, `%ProgramData%\helios`,
`orion` et `<SID>` existent, `icacls` n'y liste que Administrateurs et SYSTEM
(héritage désactivé), `vault\` et `identities\` en héritent ; le début de
`orion.log` montre `randomness provider` ; le journal du moteur contient
`propriétés de la clé TPM` avec `portee = Machine` et `acces = AdminsOnly`, et
`bootstrap.toml` porte `key_slot = "Helios Orion device root v2 <SID>"`. Points
de vigilance : le retour de `GetProcessId` sur le processus d'un `runas` ; un
second lancement pendant l'UAC du premier (son rappel attend la fin de `setup` :
ses chemins de profil sont ignorés et journalisés, aucune fenêtre n'apparaît
avant la fin de l'UAC).

**2. Connexion, renouvellement, déconnexion.** Connecter un profil ML-KEM,
renouveler la clé, déconnecter. Attendu : mêmes états qu'avant F11 ; l'adaptateur
`orion0` apparaît à la connexion et disparaît à la déconnexion.

**3. Fermer la fenêtre, la rouvrir.** Fermer la fenêtre pendant une connexion,
puis rouvrir depuis l'icône de la zone de notification. Attendu : le tunnel n'a
pas bougé, aucun nouvel UAC.

**4. Quitter.** « Quitter » depuis l'icône. Attendu : plus aucun processus
`orion.exe`, plus d'adaptateur `orion0` ; l'attente du moteur est bornée à 10 s
(`SHUTDOWN_GRACE`), au-delà de quoi `orion-ui.log` contient « arrêt du moteur non
terminé après 10 s : Orion sort quand même ». Le journal du moteur se termine par
`moteur d'Orion arrêté` avec `event=ShutdownRequested` et `code=0`. Point de
vigilance : `ExitRequested` puis `Exit` ne doivent produire qu'un seul démontage
(une seule attente).

**5. Tuer l'IHM.** Terminer le processus de l'IHM (non élevé) depuis le
Gestionnaire des tâches. Attendu : le moteur démonte le tunnel puis s'arrête ;
plus d'adaptateur ; `orion.log` contient `moteur d'Orion arrêté` avec
`event=ParentExited` (ou `ClientLeft`) et `code=1`.

**6. Tuer le moteur.** Terminer le processus élevé. Attendu : l'IHM affiche
« Le moteur d'Orion s'est arrêté : Orion va se fermer. » puis se ferme ; le
lancement suivant supprime l'adaptateur orphelin (nettoyage à l'ouverture du
moteur). Panne volontaire d'une commande du moteur (panique) : la session et
l'IHM se terminent, jamais de moteur qui continue seul (*fail-closed*).

**7. Refuser l'UAC.** Attendu : message « Orion a besoin de l'autorisation
administrateur pour monter le tunnel. » (erreur Win32 1223), aucun processus
`orion.exe` restant.

**8. Moteur lancé à la main, sans IHM.** Depuis un terminal administrateur,
lancer `orion.exe --engine` sans IHM. Attendu : sans les quatre options
(`--pipe`, `--ui-pid`, `--ui-created`, `--token`), sortie immédiate avec le
code 2 ; avec des options bien formées mais sans IHM correspondante, le moteur
s'arrête seul (processus parent absent, ou aucun client dans les 10 s de
`CONNECT_TIMEOUT`) avec le code 1. Lancé sans élévation : « le moteur d'Orion
doit être élevé. » sur stderr, code 1, et `orion-ui.log` n'est pas tronqué.
Aucun adaptateur `orion0` ne doit rester.

**9. Tube ouvert par un tiers.** Depuis un programme lancé sous le même compte
(une autre image que `orion.exe`), ouvrir `\\.\pipe\orion-engine-<pid>-<nonce>`
pendant le démarrage du moteur, avant l'IHM. Attendu : le tiers est refusé
(PID, image ou heure de création du client différents, ou jeton de session
absent), et le moteur s'arrête (`ClientRefused` ou `HelloRefused`, code 1, visible
dans `orion.log`) ; l'IHM affiche alors le message d'arrêt du moteur. Le tube est
créé en instance unique et n'accepte aucun client distant.

**10. Cérémonie YubiKey depuis l'IHM.** Récupération ou campagne de certificats
depuis Orion, **sans** `helios-astra-helper` installé (il n'est plus livré).
Attendu : la boîte WebAuthn de Windows apparaît au premier plan, rattachée à la
fenêtre Orion, et la cérémonie aboutit. Point de vigilance : le dialogue est
ouvert depuis un fil qui n'est pas celui de l'IHM ; aucun transfert de premier
plan n'est fait.

**11. Terminal SSH.** L'action d'ouverture d'un terminal SSH d'Orion. Attendu : le
shell ouvert est **non élevé** (`whoami /groups` n'indique pas
« Mandatory Label\High Mandatory Level »). Si l'IHM était lancée élevée, le
lancement est refusé.

**12. Mise à jour d'une installation existante.** Installer la version
précédente, créer un profil et une identité, noter le SHA-256 de `registry.hvlt`
et de chaque `profiles\*.hvlt` de `%APPDATA%\helios\orion\config`, puis
installer cette version et lancer Orion.

- Attendu : le journal du moteur contient « coffre repris sous la racine
  protégée » (nombres de profils et d'identités) puis « ancien coffre nettoyé
  sous l'identité de l'utilisateur » ; sous `...\<SID>\vault\`, les SHA-256 sont
  identiques, `.relocated` existe, `bootstrap.toml` porte la clé
  `Helios Orion device root v2 <SID>` et le même `install_id` ; profils et
  identités sont intacts, sans réenrôlement ; l'ancien coffre a disparu
  (`device-root`, `registry.hvlt`, `profiles\`, `profiles.toml`, magasins) mais
  `orion.log` et `orion-ui.log` restent ; l'ancienne clé TPM `v1` n'existe plus.
  Un second démarrage ne migre rien.
- Échec simulé (dossier neuf non écrivable, identité copiée corrompue) :
  message « La migration du coffre a échoué : l'ancien coffre est conservé.
  Cause : … », ancien coffre intact (mêmes SHA-256), aucun `device-root` sous le
  nouveau `vault\`, aucun `.relocating` restant.
- Reprise après arrêt brutal : un `.relocating` factice laissé sous la racine est
  supprimé et la migration aboutit.
- Un lien (jonction) planté dans l'ancien dossier est ignoré avec un
  avertissement (« lien ignoré dans l'ancien coffre ») ; un lien sur une entrée
  du coffre lui-même fait échouer la migration.
- Élévation par les identifiants d'un **autre** administrateur : le journal
  contient « l'ancien coffre appartient au compte de l'IHM, inaccessible au
  moteur élevé sous un autre compte », rien n'est migré ni lu, et le coffre
  créé est lié à ce compte (un autre administrateur ne pourra pas l'ouvrir la
  fois suivante).
- À valider : que le moteur élevé puisse ouvrir le jeton de l'IHM (nettoyage
  sous ce jeton) ; sinon « ancien coffre conservé : suppression impossible sans
  les droits de l'utilisateur » et l'ancien coffre ainsi que la clé `v1` restent.
- **Installation modifiable.** Copier le dossier d'installation de la release
  (`orion.exe`, `wireguard.dll`, ressources) dans un dossier que l'utilisateur
  peut modifier, et lancer `orion.exe` de là. Attendu : la boîte d'erreur
  affiche « Orion est installé dans un dossier modifiable sans droits
  administrateur : démarrage refusé. » **avant toute invite UAC**. Depuis un
  terminal administrateur, `orion.exe --engine …` lancé de ce dossier sort avec
  le code **4** et écrit le même message sur stderr, sans créer de fichier sous
  la racine protégée. Une installation sous `Program Files` démarre sans ce
  message. Constater aussi que le MSI s'installe bien pour la machine (sous
  `Program Files`, `HKLM`) : seul le `installMode` du NSIS est vérifié dans le
  dépôt.
- **Installation atteinte par un lien.** Avec `mklink /J`, une jonction placée
  dans un dossier modifiable et pointant vers le dossier d'installation protégé,
  ou un lien symbolique vers `orion.exe` : le démarrage est refusé de la même
  façon (message, avant l'UAC, code 4 côté moteur). Limite connue, non
  contrôlée : une jonction placée sur un ancêtre au-delà du dossier parent n'est
  pas détectée (ADR-004, Limites connues).

**13. Depuis un programme non élevé du même compte.** Lister et lire
`%ProgramData%\helios\orion\<SID>\vault` ; tenter d'ouvrir la clé machine
`Helios Orion device root v2 <SID>` du *Microsoft Platform Crypto Provider*
(par `NCryptOpenKey` avec `NCRYPT_MACHINE_KEY_FLAG`, depuis un petit programme
de test). Attendu : accès refusé au dossier ; clé inutilisable ;
rien n'est écrit dans le dossier protégé. Aucun secret ni racine dans le
journal.

**14. Dossier de coffre élargi.** Avec un terminal administrateur, donner à
l'utilisateur un droit sur `%ProgramData%\helios\orion\<SID>` (ou pré-créer ce
dossier depuis un compte standard, ou le remplacer par une jonction), puis lancer
Orion. Attendu : l'IHM affiche « Le dossier protégé d'Orion est accessible à un
compte non administrateur : démarrage refusé. » ; le moteur sort avec le code
**3**, et `orion-ui.log` contient `code=Some(3)` ; rien n'est écrit sous la
racine refusée (ni coffre, ni journal). Un dossier `ProgramData\helios` créé par
un compte non administrateur est refusé de même (propriétaire).

Points de vigilance supplémentaires, à constater pendant la recette :

- **Clé TPM machine** : que le *Microsoft Platform Crypto Provider* accepte un
  descripteur posé sur une clé machine avant finalisation (« restricting the
  machine key failed » sinon, et Orion ne démarre plus sous Windows) ; qu'il ne
  normalise ni le propriétaire ni le drapeau protégé (sinon `acces = Wider` ou
  `Unreadable` et le démarrage est refusé, ce qui est correct mais bloquant sur
  ce matériel). Le journal du moteur indique ce qui est lu.
- **Échec du moteur avant son journal** : l'IHM ne reçoit alors que le code de
  sortie ; vérifier que « Le moteur d'Orion s'est arrêté avant de répondre (code
  N). » s'affiche avec le bon code.
- **COM** : `ShellExecuteExW` est appelé sur le fil de `setup`, qui suppose COM
  initialisé (WebView2 le fait) ; à confirmer.
- **Journal de l'IHM** : un second lancement tronque `orion-ui.log` de
  l'instance qui tourne (comportement hérité de `orion.log`).

### Négociation de clé PQC, de bout en bout

Prérequis : la gateway tourne un `heliosd` bâti avec `key-negotiation` (c'est le
cas depuis que `cargo xtask bundle` l'inclut ; `./scripts/deploy.sh` la met à
jour), et les deux ports UDP sont redirigés par la box — 51820 pour WireGuard,
51821 pour la négociation.

Depuis le poste opérateur, une seule commande prépare la gateway :

```sh
./scripts/key-negotiation-setup.sh christophe@100.72.220.76
```

Elle crée la CA opérateur si besoin, fait naître l'identité de négociation
**sur** la gateway (scellée au TPM) et ouvre le port dans son `network.toml`.
Elle n'enrôle plus de client : le poste s'enrôle en v5, sans qu'aucune clé
privée voyage ([parcours](#enrôlement-v5-de-bout-en-bout-vm-windows)). Les
anciennes options `--nom` et `--public-key` sont refusées en renvoyant vers
[OPERATOR-TOOLING §6](../security/OPERATOR-TOOLING.md#6-profil-client).

Tout passe par SSH, **jamais par l'API de contrôle** : celle-ci vit derrière le
tunnel, et l'exiger reviendrait à faire dépendre d'une première connexion la
négociation qui protège précisément la première connexion. C'est aussi pourquoi
l'admission emprunte la console (`heliosd peer add`) plutôt que `POST
/api/peers`, réservé à un pair admin déjà connecté.

Sur le poste Windows :

1. importer le `.orion` signé issu de l'enrôlement v5 ; l'écran *Profils* doit
   annoncer **identité protégée · scellée** ;
2. comparer l'empreinte PQ affichée avec celle qu'a imprimée
   `heliosd init-key-negotiation` — c'est ce qui rattache le profil à cette
   gateway et rien d'autre ;
3. connecter : la négociation doit aboutir sur la seule identité scellée au
   compte Windows, le document ne portant aucune clé privée ;
4. l'écran *Connexion* doit afficher `négociation ML-KEM-1024` puis, une fois le
   handshake obtenu, la puce `PSK PQC · ML-KEM-1024` ;
5. côté gateway, `helios peer list` doit montrer le plancher monté à
   `ml_kem` pour ce pair ;
6. rejouer une connexion après avoir forcé un mode sous le plancher (par
   exemple `static_psk`) dans l'écran *Profils* : le mode doit être
   **indisponible**, le plancher ayant monté ;
7. toujours dans *Profils*, éprouver l'édition du bloc : coller un certificat
   PQ tronqué doit afficher l'empreinte « illisible », signaler le bloc en
   erreur et désactiver *Enregistrer* ; le *Plancher* ne doit proposer que
   des valeurs supérieures ou égales à celle du profil chargé.

#### La campagne automatique

Ce qui précède se joue à la main une fois ; la campagne se rejoue à chaque
build. Depuis le poste Windows enrôlé, à la racine du dépôt :

```powershell
pwsh scripts/campaign-windows.ps1 -Profile poste-windows
pwsh scripts/campaign-windows.ps1 -Profile poste-windows -Soak   # + scénarios lents
```

Ou directement l'outil, si l'on ne veut qu'une famille :

```powershell
cargo run -p helios -- campaign --only negociation-de-cle
cargo run -p helios -- campaign --only negociation-de-cle --profile poste-windows --soak
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
et émet son profil d'invitation `lab.invitation.orion`. Le profil assisté
`lab-poste.orion`, qui portait tout ce qu'il fallait pour un Orion neuf, n'est
plus produit depuis le 18 octobre 2026 : son émission admet un nouveau pair
sans certificats de négociation, ce que le plancher `ml_kem` refuse
([TESTING](TESTING.md#banc-de-développement)) ; l'option a été retirée depuis
(ADR-004 §6, amendement du 18 octobre 2026). Un Orion neuf s'enrôle en v5 :
[parcours ci-dessous](#enrôlement-v5-de-bout-en-bout-vm-windows).

Vérifier ensuite, dans l'onglet **Profils** :

- la **clé publique du client** s'affiche en lecture seule et correspond à celle
  que `helios peer list` montre côté gateway — c'est la valeur que
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

### Enrôlement v5 de bout en bout (VM Windows)

Ce parcours est le seul qui exerce DPAPI réel, une YubiKey réelle et le
téléchargement dans WebView2 : aucun n'est joignable depuis WSL2 ni la CI.
Prérequis : une gateway dotée d'un domaine de confiance (`astra-signer init`,
`heliosd init-trust-domain`), un credential opérateur enregistré, Orion
installé sur une VM Windows 11. Les commandes sont celles
d'[OPERATOR-TOOLING §6](../security/OPERATOR-TOOLING.md#6-profil-client).

1. Poste opérateur : `astra-signer enroll invite --gateway-certificate … --out
   poste.helios-invite`. La YubiKey doit demander un toucher ; noter
   l'empreinte affichée.
2. Orion, *Profils* → « Importer une invitation ». Vérifier que la gateway et
   l'échéance sont celles attendues et que « Créer la demande » reste grisé
   tant que l'empreinte recopiée diffère — un seul caractère faux suffit.
   Espaces et casse ne comptent pas.
3. Saisir l'empreinte juste et un nom, « Créer la demande ». « Enregistrer la
   demande » doit proposer un fichier `.helios-request` ; s'il ne se passe rien
   dans WebView2, le bouton de copie reste le recours, à signaler. La demande
   apparaît sous « Demandes en attente » et survit à un redémarrage d'Orion.
4. Inspecter, depuis un terminal administrateur,
   `%ProgramData%\helios\orion\<SID>\identities` (sous Linux, le dossier de
   données par défaut ; `ORION_IDENTITY_DIR` n'est lue qu'en build de
   développement) : aucune clé privée en clair, les fichiers de la
   demande en attente sont des blobs DPAPI. Les rouvrir sous un
   autre compte Windows doit échouer.
5. Poste opérateur : `astra-signer enroll accept`, puis la ligne
   `heliosd peer add` imprimée, sur la gateway ; `helios enroll document`,
   puis `astra-signer enroll sign-document`.
6. Orion, « Importer » le `.orion` signé : le profil devient connectable. Fermer
   Orion **sans enregistrer**, le rouvrir et réimporter le même document : il
   doit se compléter de nouveau. « Enregistrer » ensuite : la demande disparaît
   de la liste, et la connexion ML-KEM aboutit.

À vérifier aussi, chacun refusé en clair et sans effet :

- réutiliser l'invitation consommée pour une seconde demande, côté `accept` ;
- importer le `.orion` d'un autre poste : brouillon non connectable ;
- importer un ancien document v1 Helios portant une clé privée : refus qui
  renvoie vers une invitation v5 ;
- « Abandonner » une demande, puis importer son document signé : brouillon non
  connectable, plus aucune clé de cette demande sur le disque.

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

### Profil dual-stack : deux adresses sur l'adaptateur (VM Windows)

Ce contrôle exige une gateway dotée d'un préfixe IPv6 de tunnel
(`wg_address_v6`, IPv6 installée : `helios status` affiche `installed`) et
`allow_tunnel_icmp = true`, un pair admis ou réadmis depuis (il porte
`address_v6` dans `network.toml`), une VM Windows dual-stack et un Orion
compilé avec `--features wireguard`. Sous WSL, seuls l'import, la validation,
le scellement, la liste d'adresses remise à `defguard`, la comparaison de
relecture et l'écran sont exercés (`scripts/wsl-cargo test -p orion-core`,
`--features wireguard backend::wireguard`, `npm run test:unit`).

1. **Émission.** `helios profile emit --name <pair> …` puis
   `helios profile check <fichier>` : la ligne « adresse IPv6 » donne le
   `/128` du pair. Pour un pair sans IPv6, le document ne contient **pas** la
   clé : `Select-String address_v6 <fichier>` ne trouve rien.
2. **Import.** L'écran Profils montre « Adresse virtuelle IPv6 » remplie à
   côté de l'adresse virtuelle ; la ligne « adresse » du panneau de posture
   affiche les deux, IPv4 d'abord.
3. **Connexion.** `Get-NetIPAddress -InterfaceAlias orion0` liste la VIP IPv4
   en `/32` et la VIP IPv6 en `/128`. Le journal affiche « AllowedIPs et
   adresses appliqués vérifiés sur l'adaptateur », sans avertissement.
4. **Joindre la gateway en IPv6.** `ping -6 <préfixe>::1` répond (ICMPv6 ouvert
   sur l'interface du tunnel par `allow_tunnel_icmp`), comme
   `ping 100.64.0.1`. `heliosd_url` reste l'URL IPv4 de la gateway.
5. **« Helios seul ».** Sous « Avancé », le choix écrit
   `<VIP gateway>/32, <préfixe>::1/128`. Après reconnexion, le `ping -6` de
   l'étape 4 répond toujours. Le même choix sur un profil sans IPv6 écrit la
   seule VIP IPv4, comme avant.
6. **Adaptateur sans IPv6.** Avec `DisabledComponents = 0xFF` comme dans
   « Capture réellement appliquée », connecter le profil dual-stack. Attendu,
   en plus de l'erreur `::/0` de ce contrôle : l'avertissement « adresse non
   posée par le pilote sur l'adaptateur : <VIP IPv6>/128 — le tunnel ne porte
   pas cette famille d'adresses », et la ligne « adresse » en ambre
   (« … — <VIP IPv6>/128 non posée par le pilote »). Le tunnel IPv4 fonctionne.
   Remettre la valeur d'origine et redémarrer.
7. **Profil périmé.** Sur un profil portant `heliosd_url` sans bloc de
   négociation (chemin de provisioning après montage), remplacer la VIP IPv6
   par une autre adresse du préfixe, puis connecter. Attendu, en
   avertissement : « Profil périmé : la gateway a enregistré … pour ce poste,
   le profil déclare … » ; le profil enregistré n'est pas modifié.
8. **Orion antérieur.** Importer le document de l'étape 1 dans un Orion
   antérieur à `address_v6` : l'import est **refusé**. Le message est celui
   de cette version, hors de notre contrôle — attendu de la forme « document
   JSON Orion invalide : unknown field `address_v6`, … ». Le document d'un
   pair sans IPv6 s'y importe et s'y connecte en IPv4. Un profil scellé avec
   une `address_v6` (version de manifeste 8) n'est pas lisible non plus par
   cet Orion ; sans elle, il reste scellé dans l'encodage précédent.

Rien de ceci n'a encore été observé sur cible, en particulier la relecture
des adresses unicast de WireGuard-NT (`GetUnicastIpAddressTable`) et l'état de
l'adresse IPv6 juste après la remise en service de l'adaptateur.

### Sortie Internet IPv6 refusée (gateway Linux et client dual-stack)

Critère 4 de [SORTIE-IPV6.md](../specification/SORTIE-IPV6.md) (V1, rejet
explicite). Ce contrôle exige la gateway du contrôle précédent (IPv6 de tunnel
`installed`, pair portant `address_v6`), `heliosd` compilé avec
`--features netlink`, et un client dual-stack connecté en tunnel complet
(`0.0.0.0/0, ::/0`) : la VM Windows ci-dessus, ou un poste Linux. Le WAN de la
gateway peut avoir ou non de l'IPv6 : le rejet ne dépend pas de lui. Sous WSL,
seuls le rendu, l'ordre et les octets Netlink sont exercés
(`scripts/wsl-cargo test -p helios-firewall --features netlink`) : ni le
noyau, ni l'ICMPv6 réellement émis, ni le comportement des applications.

1. **Règles, tunnel `Down`.** Avant de connecter le client :

   ```sh
   sudo nft list chain inet helios forward
   ```

   Les dernières règles de la chaîne, une par uplink, sont
   `meta nfproto ipv6 iifname "helios0" oifname "<wan>" reject with icmpx admin-prohibited`
   (selon la version de `nft`, `reject with icmpx type admin-prohibited`). Elles
   suivent `ct state invalid counter drop` et
   `ct state established,related accept`. Noter si `nft` affiche la garde
   `meta nfproto ipv6` avant ou après les interfaces : le batch la place en
   tête.
2. **Règles, tunnel `Up`.** Connecter le client et relire la chaîne : les
   mêmes règles sont toujours les dernières, après la règle IPv4
   `meta nfproto ipv4 iifname "helios0" oifname "<wan>" accept` si
   `allow_client_internet` est actif. Aucune règle `accept` ne porte
   `meta nfproto ipv6` ni `ip6`, hors contournement `split_tunnel_cidrs` IPv6
   explicitement configuré, qui porte alors `iifname "<lan>"` — une règle par
   interface LAN, aucune sans interface LAN, jamais `helios0` ni un WAN
   (FIREWALL-V2).
3. **Échec immédiat.** Sur la gateway, `sudo tcpdump -ni helios0 icmp6`. Depuis
   le client :

   ```sh
   curl -6 -sS -o /dev/null -m 10 -w '%{time_total}\n' https://ipv6.google.com/
   ```

   (Windows : `curl.exe -6 …`). Attendu : un échec en bien moins d'une seconde,
   pas au bout des 10 s de `-m 10` ; sous Linux, l'erreur attendue est
   `Permission denied` (EACCES, la traduction noyau d'« administratively
   prohibited »), à confirmer. `tcpdump` montre un
   `destination unreachable … unreachable prohibited` (ICMPv6 type 1 code 1)
   de la gateway vers la VIP IPv6 du client.
4. **Repli dual-stack sans délai.** Dans un navigateur du client, charger un
   site publié en A et AAAA (par exemple `https://www.wikipedia.org/`), cache
   vidé. Attendu : chargement sans délai visible ; les outils de
   développement montrent une connexion en IPv4.
5. **La gateway reste joignable en IPv6.** `ping -6 <préfixe>::1` répond
   toujours (règles `input`, `allow_tunnel_icmp`) : le rejet ne concerne que
   le trafic vers un WAN.
6. **Débit des réponses.** Relever `sysctl net.ipv6.icmp.ratelimit` (défaut
   attendu 1000 ms) ; une rafale (`for i in $(seq 50); do curl -6 -s -m 2 …;
   done`) doit rester bornée côté `tcpdump` par cette limite noyau, aucune
   limite n'existant dans le ruleset (SORTIE-IPV6 §4.2).

Rien de ceci n'a encore été observé sur cible.

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
