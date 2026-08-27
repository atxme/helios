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

1. `allow_ssh_from` dans `network.toml`. La règle est réelle : port 22 accepté
   en entrée depuis les sources déclarées, et `ct state established,related`
   accepté sur les trois chaînes, donc les réponses sortent.
2. **Ne pas `systemctl enable`** tant que tout n'est pas validé. Les règles
   nftables ne sont pas persistées : si vous perdez l'accès, un redémarrage de
   la machine restaure tout, puisque le daemon ne se relancera pas.

3. **Le bail DHCP, si l'adresse du WAN en vient une.** Kill-switch engagé, le
   renouvellement est bloqué par défaut et la machine perd son adresse — donc
   son tunnel et son administration à la fois. `allow_ssh_from` ne sauve rien
   quand il n'y a plus d'adresse à joindre. Soit figer l'adresse, soit poser
   `allow_dhcp_on_wan = true`.

4. **La voie de secours NordVPN Meshnet**, si la gateway en dispose. Helios
   peut conserver un accès SSH d'administration via l'interface `nordlynx`,
   indépendant de l'adresse LAN/WAN et du tunnel Helios. Cette voie n'est
   ouverte qu'aux pairs Meshnet déclarés dans `nordvpn_meshnet.peer_cidrs` et
   pour le port TCP 22. Relever l'adresse Meshnet de la gateway avec :

   ```sh
   ip -4 addr show nordlynx
   ```

   En cas de perte de l'accès principal, utiliser cette adresse pour joindre
   la gateway :

   ```sh
   ssh <utilisateur>@<adresse-nordlynx-de-la-gateway>
   ```

   Ce n'est pas `100.64.0.1`, qui est l'adresse du tunnel WireGuard Helios.
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

L'adresse de la gateway vit dans `scripts/lib-remote.sh`, sur la ligne
`HELIOS_CIBLE` : c'est le seul endroit à changer quand elle déménage, et
`provision-client.sh`, `key-negotiation-setup.sh` et `target-bootstrap.sh` la
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
allow_ssh_from = ["<votre sous-réseau, ex. 192.168.1.0/24>"]
wg_iface = "helios0"
wg_address = "100.64.0.1/10"
wg_listen_port = 51820
admin_iface = "helios0"
```

`wan_iface = "auto"` fait choisir l'interface de sortie au démarrage, en
préférant le lien filaire. `heliosd show-uplink` montre les candidats et la
raison du choix ; nommer l'interface explicitement reste possible et reste ce
qu'il faut faire si la machine a plusieurs sorties dont une seule doit servir.

**`allow_ssh_from` n'est pas optionnel ici.** Sans lui, le premier démarrage
vous coupe l'accès et il faudra redémarrer la machine.

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
générer une paire avec `cargo run -p helios-ctl -- campaign --generate-keys` sur
le poste de développement et poser la privée dans `wg_private_key` de
`network.toml`. Elle sera alors en clair sur le disque de la gateway.

## Étape 6 — Premier démarrage, surveillé

Ne pas utiliser `systemctl` pour ce premier essai : lancer en avant-plan pour
voir les journaux défiler.

```sh
sudo /opt/helios/current/heliosd run
```

Ce qui doit apparaître : le kill-switch engagé, l'interface `helios0` créée,
l'API en écoute. Si votre session SSH tient, `allow_ssh_from` est correct.

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
cargo run -p helios-ctl -- --url http://100.64.0.1:8080 profile emit \
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

## Si vous perdez l'accès

1. Redémarrer la machine. Le service n'étant pas activé, `heliosd` ne se relance
   pas et les règles nftables disparaissent.
2. Corriger `allow_ssh_from` dans `/var/lib/helios/network.toml`.
3. Recommencer à l'étape 6.

Si le service avait été activé, il faut une console physique et
`sudo systemctl disable --now heliosd` puis `sudo nft flush ruleset`.

## Ce qui reste à valider ensuite

Une fois ce parcours passé, activer le service (`systemctl enable --now heliosd
helios-update.path`) puis reprendre la liste des essais matériels de
[TESTING.md](TESTING.md) : rollback de mise à jour, séquestre après changement
de PCR, refus d'un pair non administrateur.
