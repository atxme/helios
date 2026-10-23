# Premier déploiement sur machines réelles

Marche à suivre pour installer une gateway Helios accessible en SSH, puis y
connecter un client Orion Windows. À suivre dans l'ordre : chaque étape suppose
la précédente vérifiée.

Cette recette couvre ce que `scripts/regression.sh` et `scripts/campaign.sh` ne
peuvent pas prouver — scellement TPM réel, pare-feu réel, tunnel réel.

## Le seul vrai risque, et le filet

`heliosd` est *fail-closed* : il engage le kill-switch **avant** tout réseau.
Mal configuré, il coupe votre SSH. Et l'arrêter ne suffit pas : le daemon laisse
délibérément le kill-switch installé en sortant.

Deux protections, à mettre en place **avant** le premier démarrage :

1. Un chemin de retour dans `network.toml`. Sur une gateway distante — le cas
   normal — c'est `admin_ifaces = ["tailscale0", "nordlynx"]` : port 22 accepté
   sur ces interfaces dans tous les états du tunnel. `allow_ssh_from` ne joue ce
   rôle que si un poste opérateur est sur le LAN et va y rester ; il filtre sur
   l'adresse seule et Helios refuse une source interne au tunnel. Dans les deux
   cas `ct state established,related` est accepté sur les trois chaînes, donc
   les réponses sortent.
2. **Ne pas `systemctl enable`** tant que tout n'est pas validé. Les règles
   nftables ne sont pas persistées : si vous perdez l'accès, un redémarrage de
   la machine restaure tout, puisque le daemon ne se relancera pas.

3. **Le bail DHCP, si l'adresse du WAN en vient une.** Kill-switch engagé, le
   renouvellement est bloqué par défaut et la machine perd son adresse — donc
   son tunnel et son administration à la fois. `allow_ssh_from` ne sauve rien
   quand il n'y a plus d'adresse à joindre. Soit figer l'adresse, soit poser
   `allow_dhcp_on_wan = true`.

4. **Les deux voies de secours hors-bande : Tailscale et NordVPN Meshnet.**
   Elles sont indépendantes de l'adresse LAN/WAN *et* du tunnel Helios, donc
   elles survivent à un `heliosd` arrêté — c'est tout leur intérêt. Déclarer les
   deux dans `admin_ifaces`, jamais une seule : un unique chemin de secours est
   un point de défaillance unique là où il est le moins acceptable.

   `nordvpn_meshnet.peer_cidrs` reste ce qui borne les *pairs* Meshnet admis
   pour les autres services ; `admin_ifaces` ouvre le port 22 sur l'interface.
   Relever les adresses des overlays :

   ```sh
   ip -brief addr show tailscale0
   ip -brief addr show nordlynx
   ```

   En cas de perte de l'accès principal, joindre la gateway par l'un ou
   l'autre — et vérifier périodiquement que **les deux** répondent, sans quoi
   la redondance n'est que théorique :

   ```sh
   ssh <utilisateur>@<adresse-tailscale-de-la-gateway>
   ssh <utilisateur>@<adresse-nordlynx-de-la-gateway>
   ```

   Ce n'est pas `100.64.0.1`, qui est l'adresse du tunnel WireGuard Helios.

   **Piège, côté poste opérateur.** Tailscale et NordVPN tirent leurs adresses
   de `100.64.0.0/10`, comme Helios. Le profil Orion pousse
   `AllowedIPs = 100.64.0.0/10` : **tunnel Helios monté, le poste envoie donc
   dans le tunnel tout son trafic vers ces deux overlays**, y compris les
   sessions qu'on croit hors-bande. Tunnel arrêté, les routes Helios
   disparaissent et les overlays reprennent la main — c'est pourquoi ils
   restent un secours valable.

   Conséquence pratique : **ne jamais lancer un déploiement pendant que le
   tunnel est monté vers une adresse en `100.x`**. La session part dans Helios,
   et le redémarrage de `heliosd` la coupe. C'est ce qui a verrouillé la
   gateway le 1er septembre 2026. `target-bootstrap.sh` interroge désormais
   `ip route get` et refuse ce cas, mais la vérification manuelle reste utile :

   ```sh
   ssh <gateway> 'ip route get <adresse-que-vous-utilisez>'   # doit dire nordlynx/tailscale0, pas helios0
   ```

   Côté gateway il n'y a pas de conflit : `vip_routing` n'installe qu'un `/32`
   par pair admis, jamais la plage entière, précisément pour que les deux VPN
   coexistent.

   Vérifier également que l'adresse Meshnet du poste apparaît dans
   `wg show nordlynx` et dans `peer_cidrs` de la configuration active.

S'assurer d'avoir un moyen de redémarrer la machine — bouton, console, panneau
d'hébergeur — avant de commencer.

## Étape 0 — Reconnaissance de la gateway

En SSH, relever ce dont dépendent les étapes suivantes :

```sh
ldd --version | head -1           # version de glibc
ip -br addr                       # noms d'interfaces
ip route get 1.1.1.1              # interface qui porte le WAN
ls -l /dev/tpmrm0                 # TPM présent ?
lsmod | grep -E 'wireguard|nf_tables'
who am i                          # depuis quelle IP vous arrivez
```

Notez : le nom de l'interface WAN, l'IP publique ou joignable de la machine, le
sous-réseau depuis lequel vous vous connectez, et la présence ou non du TPM.

### Le piège glibc

Un binaire lié à une glibc plus récente que celle de la cible **ne démarre
pas**, avec un message de symbole manquant. Comparez la glibc de la gateway à
celle de la machine de build (`ldd --version`).

Si la gateway est plus ancienne, construire dans un conteneur de la même
distribution que la cible, plutôt que directement sur le poste de
développement. C'est une limite du bundle actuel : il n'est pas lié
statiquement, `aws-lc-rs` et `tss2` tirant du C.

## Étape 1 — Époque éditeur (une seule fois)

Les clés qui signeront toutes vos releases. À garder hors ligne, hors du dépôt.

```sh
cargo run -p helios-publisher -- keygen --key-epoch 1 \
  --output-dir /chemin/hors-ligne/helios-epoch-1
```

Trois fichiers : deux clés privées à protéger, et `publisher-keyring.json` — la
moitié publique, qui sera compilée dans le binaire. Perdre les privées interdit
toute mise à jour signée ultérieure ; les divulguer permet à un tiers d'en
fabriquer une.

## Le raccourci, une fois l'étape 1 faite

`scripts/deploy.sh` enchaîne les étapes 2 et 3 — construction, signature,
archivage, copie, vérification d'empreinte et installation privilégiée :

```sh
./scripts/deploy.sh                       # l'adresse est en dur, aucun argument
./scripts/deploy.sh root@autre-machine    # ponctuellement ailleurs
```

Pendant une campagne de maintenance distante où la conservation de l'accès
prime temporairement sur le kill-switch :

```sh
./scripts/deploy.sh christophe@100.102.179.177 --sans-firewall
```

Cette option saute Astra, pose un drop-in systemd persistant aux mises à jour,
et vérifie après redémarrage que `firewall_enforced=false` et que la table
`inet helios` est absente. Le retour au comportement nominal est explicite :

```sh
./scripts/deploy.sh christophe@100.102.179.177 --sans-astra --avec-firewall
```

L'adresse de la gateway vit dans `scripts/lib-remote.sh`, sur la ligne
`HELIOS_CIBLE` — son adresse **Tailscale**, pas une adresse LAN : l'opérateur
est distant, et un défaut pointant vers un réseau qu'il ne rejoindra plus
échoue par « No route to host », ce qui se lit comme une gateway en panne.
C'est le seul endroit à changer quand elle déménage, et
`key-negotiation-setup.sh` et `target-bootstrap.sh` la
lisent au même endroit. Un argument l'emporte pour l'appel en cours sans rien
enregistrer — les scripts ne mémorisent plus d'hôte sous `~/.helios`, où une
copie périmée finissait par gagner contre celle qu'on venait de changer.

Il demande le mot de passe `sudo` de la gateway au moment de l'installation, et
rien d'autre. La séquence de release est un horodatage Unix : l'anti-rollback
exige une valeur strictement croissante, et un compteur tenu à la main se
désynchronise dès qu'on déploie depuis une autre machine.

Les étapes détaillées ci-dessous restent la référence — pour comprendre ce que
le script fait, ou pour une release publique où la signature se joue sur un
poste séparé.

Une fois la gateway installée et un pair administrateur connecté par
`helios0`, les mises à jour ordinaires du seul daemon ne repassent pas par SSH
ni par le bundle complet :

```sh
./scripts/deploy-app.sh
```

Depuis le poste Orion Windows, un manifeste et un ELF déjà signés empruntent
le même flux avec PowerShell :

```powershell
.\scripts\deploy-app.ps1 `
  -Manifest .\heliosd.release.json `
  -Binary .\heliosd `
  -Yes
```

Le poste qui construit et signe dans WSL peut tout enchaîner depuis PowerShell
avec `-BuildInWsl -WslRepo /home/utilisateur/helios`.

La commande construit, signe, transfère par l'API, active et attend la
confirmation ou le rollback. `deploy.sh` reste le chemin du premier
déploiement et des releases qui modifient aussi l'installateur, les outils ou
les unités systemd.

## Étape 2 — Fabriquer le bundle

```sh
export HELIOS_PUBLISHER_KEYRING_PATH=/chemin/hors-ligne/helios-epoch-1/publisher-keyring.json
cargo xtask bundle

cargo run -p helios-publisher -- bundle \
  --dir target/bundle/helios-0.1.0-x86_64-unknown-linux-gnu \
  --key-epoch 1 --release-sequence 1 \
  --channel production --version 0.1.0 \
  --git-commit "$(git rev-parse --short=16 HEAD)" \
  --target x86_64-unknown-linux-gnu \
  --ed25519-private-key /chemin/hors-ligne/helios-epoch-1/ed25519-private.pk8 \
  --ml-dsa-65-private-key /chemin/hors-ligne/helios-epoch-1/ml-dsa-65-private.bin \
  --keyring "$HELIOS_PUBLISHER_KEYRING_PATH"

cargo xtask pack --dir target/bundle/helios-0.1.0-x86_64-unknown-linux-gnu
```

Le canal doit être `production` : c'est celui que l'unité systemd déclare, et
l'installateur refuse un bundle d'un autre canal. Notez l'empreinte SHA-256
affichée par `pack`.

## Étape 3 — Installer, sans rien démarrer

```sh
scp target/bundle/helios-0.1.0-*.tar.gz gateway:
ssh gateway
```

Sur la gateway :

```sh
sha256sum helios-0.1.0-*.tar.gz      # comparer à l'empreinte notée
sudo apt-get install -y nftables wireguard-tools tpm2-tools \
     libnftnl-dev libmnl-dev libtss2-dev
sudo modprobe wireguard nf_tables

tar xzf helios-0.1.0-*.tar.gz
sudo ./helios-0.1.0-*/helios-installer bootstrap --archive helios-0.1.0-*.tar.gz
```

L'installateur vérifie la signature hybride, l'empreinte de chaque fichier et
l'absence de fichier surnuméraire **avant** d'écrire. Il n'active aucun
service : à ce stade, rien ne tourne et le réseau n'a pas changé.

Vérifier ce qui a été posé :

```sh
ls -l /opt/helios/current/ /usr/libexec/helios-installer /etc/systemd/system/heliosd.service
/opt/helios/current/heliosd --version
```

Si `heliosd --version` échoue sur un symbole manquant, c'est le piège glibc de
l'étape 0.

## Étape 4 — Configurer, avant tout démarrage

```sh
sudo nano /var/lib/helios/network.toml
```

Renseigner au minimum :

```toml
wan_iface = "auto"
lan_ifaces = []
admin_ifaces = ["tailscale0", "nordlynx"]
wg_iface = "helios0"
wg_address = "100.64.0.1/10"
wg_listen_port = 51820
admin_iface = "helios0"
```

`wan_iface = "auto"` fait choisir l'interface de sortie au démarrage, en
préférant le lien filaire, puis suit le noyau : une interface qui gagne ou perd
sa porteuse, ou un adaptateur branché après coup, entre dans le ruleset ou en
sort sans redémarrage, par une reconstruction atomique du pare-feu.
`heliosd show-uplink` montre les candidats et la raison du choix ; nommer l'interface explicitement reste possible et reste ce
qu'il faut faire si la machine a plusieurs sorties dont une seule doit servir.

**Un chemin de retour n'est pas optionnel ici.** Sans lui, le premier démarrage
vous coupe l'accès, et sur une gateway distante cela veut dire un déplacement.

Sur une gateway administrée à distance — le cas normal — ce chemin est
`admin_ifaces` : les interfaces des overlays d'administration, ouvertes dans
tous les états du tunnel. Adapter les noms à ce que porte la machine
(`ip -brief link show`).

`allow_ssh_from` ne convient que si un poste opérateur est réellement sur le
LAN de la gateway et va y rester. Il filtre sur l'adresse source seule, donc il
ne vaut rien pour un overlay — dont l'adresse change et qui en porte plusieurs —
et Helios refuse désormais toute entrée située dans le réseau du tunnel : une
règle qui disparaît avec le tunnel n'est pas un accès de secours. Voir
[Par où la gateway s'administre](#par-où-la-gateway-sadministre).

### Si l'adresse du WAN vient d'un bail

```sh
ip -4 addr show <interface> | grep -q dynamic && echo "DHCP"
```

Le kill-switch n'ouvre pas DHCP par défaut : c'est cohérent pour une gateway,
qui a normalement une adresse fixe. Une machine en DHCP, elle, perd son adresse
au premier renouvellement — typiquement quelques heures après le démarrage, donc
bien après que le test a semblé réussir.

Deux réponses, au choix :

```toml
allow_dhcp_on_wan = true
```

L'ouverture est scopée : UDP 67 en sortie et 68 en entrée, sur la seule
interface WAN, jamais en traversée.

Ou figer l'adresse au niveau du système (`netplan`, `systemd-networkd` ou
NetworkManager selon la distribution). Une réservation sur le routeur ne suffit
pas : le client continuerait à demander un bail.

## Étape 5 — Identité scellée

Avec TPM :

```sh
sudo /opt/helios/current/heliosd provision-tpm
sudo /opt/helios/current/heliosd init-identity
```

`init-identity` affiche la **clé publique** de la gateway. La noter : c'est le
`peer_public_key` de tous les profils clients. La clé privée est scellée et
n'est jamais affichée.

Sans TPM, `provision-tpm` échoue. Repli hérité, dégradé mais fonctionnel :
générer une paire avec `cargo run -p helios -- campaign --generate-keys` sur
le poste de développement et poser la privée dans `wg_private_key` de
`network.toml`. Elle sera alors en clair sur le disque de la gateway.

## Étape 6 — Premier démarrage, surveillé

Ne pas utiliser `systemctl` pour ce premier essai : lancer en avant-plan pour
voir les journaux défiler.

```sh
sudo /opt/helios/current/heliosd run
```

Ce qui doit apparaître : le kill-switch engagé, l'interface `helios0` créée,
l'API en écoute. Si votre session SSH tient, le chemin de retour est correct.
Le vérifier depuis **chaque** overlay déclaré, pas seulement celui en cours
d'usage : une entrée `admin_ifaces` fautive ne se voit qu'à l'essai.

Depuis une **seconde** session SSH, contrôler l'état réel :

```sh
sudo nft list ruleset | head -40
ip -br addr show helios0
sudo wg show
```

Puis `Ctrl-C`. Rappel : le kill-switch reste installé après l'arrêt. Tant que le
service n'est pas activé, un redémarrage nettoie tout.

## Étape 7 — Admettre le client et émettre son profil

Le client doit d'abord exister : installer Orion (étape 8), créer un profil, et
relever sa **clé publique** dans l'onglet Profils.

Ensuite, sur la gateway :

```sh
sudo /opt/helios/current/heliosd peer add \
  --name poste-windows --public-key <clé publique d'Orion> --admin
```

Puis, sur le poste de développement, fabriquer le profil — l'API n'étant
joignable qu'à travers le tunnel, cette commande se joue une fois le tunnel
monté, ou bien on recopie à la main les valeurs affichées par `peer add` :

```sh
cargo run -p helios -- --url http://100.64.0.1:8080 profile emit \
  --name poste-windows --endpoint <ip-de-la-gateway>:51820 \
  --public-key <clé publique d'Orion> --output poste-windows.json
```

Relancer `heliosd` pour que l'admission locale prenne effet.

## Étape 8 — Orion sur Windows

Pour un premier essai fonctionnel, **ne pas signer et ne pas toucher aux
magasins de certificats** : Windows affichera un avertissement d'éditeur
inconnu, qu'on accepte. Cela laisse la machine intacte pour un test ultérieur de
la chaîne de confiance interne, qui ne se teste qu'une fois par machine vierge.

Aucun MSI n'existe avant qu'on le fabrique. Deux façons :

**Par la CI — rien à installer sur le PC.**

```sh
git push -u origin <branche>
git tag v0.1.0-rc1 && git push origin v0.1.0-rc1
```

Le déclencheur `workflow_dispatch` n'apparaît dans l'onglet Actions que si le
workflow existe sur la branche **par défaut** du dépôt ; le déclencheur par tag,
lui, fonctionne depuis n'importe quelle branche. D'où le tag pour un premier
essai, qui évite de fusionner du travail en cours. Le tag se supprime ensuite
(`git push origin :v0.1.0-rc1`).

Avant de pousser, définir la variable de dépôt `HELIOS_PUBLISHER_KEYRING`
(Settings → Secrets and variables → Actions → **Variables**) avec le contenu de
`publisher-keyring.json` produit à l'étape 1. C'est la moitié **publique** :
elle n'a rien à faire dans les *secrets*, et le job refuse de démarrer si le
contenu ressemble à une clé privée.

Récupérer ensuite l'artefact `installateurs-orion-windows-non-signes` dans le
résumé du workflow.

**En local** — exige Visual Studio Build Tools (charge « Développement Desktop
en C++ », environ 7 Gio) et Node.js :

```powershell
$env:ORION_UNSIGNED_FOR_OFFLINE_SIGNING = "1"
npm ci --prefix apps\orion
npm run tauri build --prefix apps\orion -- --features wireguard
```

Installer le MSI, lancer Orion — il demande l'élévation — puis importer
`poste-windows.json` et connecter. WireGuardNT installe son pilote à la première
création d'adaptateur ; c'est le même que celui du client WireGuard officiel.

Vérifier des deux côtés que le PSK post-quantique est posé :

```sh
sudo wg show          # sur la gateway : preshared key doit apparaître
```

### Désinstaller Orion

L'installateur se retire par **Paramètres → Applications**, ou en ligne de
commande :

```powershell
msiexec /x "chemin\vers\Orion_0.1.0_x64_en-US.msi"   # variante MSI
```

Trois résidus que la désinstallation ne retire pas :

* **Les profils**, qui contiennent des clés privées :
  `%APPDATA%\helios\orion\config\profiles.toml`. À supprimer explicitement si
  la machine ne doit pas les garder.
* **L'adaptateur WireGuard**, s'il reste après un arrêt brutal. Le retirer dans
  le Gestionnaire de périphériques, section *Cartes réseau*.
* **Le pilote WireGuardNT**, qui reste dans la banque de pilotes. Pour l'ôter
  complètement, en PowerShell administrateur :

  ```powershell
  pnputil /enum-drivers | Select-String -Context 3 wireguard
  pnputil /delete-driver oemXX.inf /uninstall
  ```

  C'est le pilote du client WireGuard officiel : le supprimer casserait une
  installation de WireGuard for Windows présente sur la même machine.

## Par où la gateway s'administre

**Cette gateway est distante, et le restera.** Il n'y a pas de poste opérateur
sur son LAN : le `192.168.1.0/24` des exemples n'était vrai que le jour de
l'installation, et personne n'y reviendra. Une procédure qui suppose un accès
LAN est une procédure qui ne s'exécutera jamais.

Trois chemins, et seulement trois :

| Chemin | Usage | Survit à un `heliosd` arrêté |
| --- | --- | --- |
| API Helios, dans le tunnel | **Nominal** — mises à jour, admission, configuration | non |
| Tailscale (`tailscale0`) | Debug, reprise en main | **oui** |
| NordVPN Meshnet (`nordlynx`) | Debug, reprise en main | **oui** |

Le chemin nominal est l'API, à travers le tunnel. Les deux overlays sont le
filet : ils sont là pour les moments où Helios est précisément ce qui ne marche
pas.

### Les deux overlays ne doivent jamais être fermés par le pare-feu

C'est un invariant, pas un réglage. Ils sont le seul accès qui subsiste quand
`heliosd` refuse de démarrer, et le kill-switch ne doit pas pouvoir emporter le
moyen de le réparer.

```toml
admin_ifaces = ["tailscale0", "nordlynx"]
```

SSH y reste ouvert dans **tous** les états du tunnel, `Down` et `Connecting`
compris. `target-bootstrap.sh` détecte les overlays présents et les retient
**tous** — pas seulement celui qui porte la session du jour : garder un seul
chemin de secours, c'est un point de défaillance unique sur le chemin de
secours. Il refuse par ailleurs un déploiement qui fermerait l'interface par
laquelle il passe.

`HELIOS_ADMIN_IFACES="tailscale0,nordlynx"` impose la liste. Un redéploiement
qui ne passe pas l'option **préserve** la valeur en place : l'accès de secours
ne s'efface pas par omission.

### Pourquoi des interfaces et non des adresses

`allow_ssh_from` filtre sur l'adresse source seule, sans contrainte
d'interface. Cela ne convient à aucun des deux overlays :

* Tailscale porte une v4 **et** une v6 (`100.72.220.76` et
  `fd7a:115c:a1e0::3934:dc4d`) — les énumérer, c'est en oublier une ;
* l'adresse NordVPN suit le serveur choisi et change sans préavis ;
* une entrée `allow_ssh_from` est satisfaisable par un paquet qui falsifie sa
  source depuis le WAN, alors qu'un `iifname` ne l'est pas : seul le démon de
  l'overlay pose des paquets sur son interface.

Une règle par interface couvre toutes les adresses qu'elle portera, aujourd'hui
et après la prochaine réattribution.

### Ne jamais déployer *à travers* le tunnel Helios

Le script le refuse désormais. C'est ainsi que la gateway s'est verrouillée le
1er septembre 2026 : le déploiement a lu sa propre adresse source — un VIP de
pair — et a épinglé SSH dessus ; le redémarrage de `heliosd` a coupé le tunnel
et la seule source autorisée avec lui.

Attention particulière aux adresses en `100.64.0.0/10` : **l'adresse NordVPN de
cette gateway (`100.102.179.177`) est dans cette plage**, que Helios route
aussi. Selon l'état du tunnel, la même adresse peut être portée par `nordlynx`
ou capturée par `helios0`. C'est pourquoi le script interroge le noyau
(`ip route get`) plutôt que de se fier à la forme de l'adresse.

## Si vous perdez l'accès

Sur une gateway distante, « redémarrer la machine » n'est pas une étape : il n'y
a personne devant. Tout dépend de ce qui reste debout.

**Un overlay répond encore** (`ssh christophe@100.72.220.76`, ou l'adresse
Meshnet) — c'est le cas nominal, et la raison d'être de `admin_ifaces` :

```sh
sudo systemctl stop heliosd            # le kill-switch tombe avec le démon
sudo nft list table inet helios        # doit répondre « No such file or directory »
sudo $EDITOR /var/lib/helios/network.toml   # corriger admin_ifaces / allow_ssh_from
```

Puis reprendre à l'étape 6. Tant que `heliosd` est arrêté, aucune règle Helios
ne subsiste : la table est construite en mémoire et posée à chaque transition,
jamais rechargée au démarrage par `nftables.service`.

**Plus aucun overlay ne répond** — il ne reste que l'accès physique, ou le
redémarrage à distance de l'hyperviseur/de la box. Le service n'étant pas activé
tant que le parcours n'est pas validé, `heliosd` ne repart pas tout seul et les
règles disparaissent au reboot. S'il avait été activé :
`sudo systemctl disable --now heliosd` puis `sudo nft flush ruleset`.

C'est cette situation que `admin_ifaces` existe pour rendre impossible. Deux
overlays déclarés, c'est deux pannes indépendantes nécessaires avant d'en
arriver là.

## Ce qui reste à valider ensuite

Une fois ce parcours passé, activer le service (`systemctl enable --now heliosd
helios-update.path`) puis reprendre la liste des essais matériels de
[TESTING.md](TESTING.md) : rollback de mise à jour, séquestre après changement
de PCR, refus d'un pair non administrateur.
