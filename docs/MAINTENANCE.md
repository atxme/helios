# Terminal Helios et maintenance

## Administration interactive

L'exécutable opérateur s'appelle `helios`. Sans sous-commande, ou avec `shell`,
il ouvre un terminal avec un écran d'accueil Helios, une zone de saisie `❯`
encadrée de séparateurs et des raccourcis visibles. Taper `/` ouvre immédiatement
le menu des commandes et de leurs descriptions ; la liste se filtre pendant la
saisie. Les flèches ↑/↓ parcourent le menu, Tab ou Entrée insère la suggestion,
Échap ferme le menu. Une suggestion n'exécute aucune action : valider ensuite
la commande complète avec Entrée. Les sous-commandes (`/peer `, `/firmware `)
et les options (`/peer add --`) sont proposées au même endroit. Une commande
complète tapée directement s'exécute avec Entrée.

Hors du menu, Tab complète la saisie et ↑/↓ parcourt l'historique en mémoire
pour la session. Le menu défile pour garder la sélection visible et adapte sa
largeur au terminal. `NO_COLOR=1 helios` désactive les couleurs.

Sous la saisie, une ligne d'état rappelle l'API active, l'état du tunnel, la
version de `heliosd` et le mode dry-run. Elle est relue sur `/api/status` au
démarrage, après `/use` et après chaque commande, avec un délai de 2 s : une
API muette s'affiche `○ no API answer (tunnel only)`, une réponse illisible
`○ incompatible API response`, sans bloquer la saisie. Chaque commande
s'affiche dans un bloc ouvert par `⏺ <commande>` et fermé par `⎿ ✓ <durée>`, ou
par `⎿ ✗ <erreur>` en rouge, sans troncature. L'en-tête nomme la commande sans recopier les
valeurs des arguments, qui peuvent contenir des clés. Le cadre de saisie ne
s'accumule pas : une commande validée reste affichée `❯ <commande>`, une ligne
vide, Ctrl-C ou Ctrl-D ne laissent aucune trace. Un terminal
sans édition (`TERM=dumb`,
`cons25` ou `emacs`) est refusé ; les commandes scriptées restent disponibles.
Exemple :

```text
❯ /status
❯ /peer list
❯ /network show
❯ /profile check "profils/client.orion"
❯ /firmware list --ssh-target admin@gateway
❯ /help
❯ /quit
```

Toutes les commandes de l'interface scriptée sont accessibles, avec ou sans
`/` initial. `/help firmware` affiche une aide ciblée. `/use http://gateway:8080`
change l'API active ; `--url` peut la remplacer pour une commande. `/clear`
efface l'écran et réaffiche l'accueil avec l'API active. Les arguments
entre guillemets sont acceptés, sans expansion de variables ni exécution de
shell. Ctrl-C efface la saisie ; pendant une commande, il l'abandonne et rend
la main (une requête déjà partie peut aboutir sur la gateway). Ctrl-D ou `/quit`
ferme le terminal. Une erreur de commande rend la main. L'historique n'est
jamais écrit sur disque ; les commandes `campaign`, susceptibles de contenir
une clé privée, en sont exclues. Aucune IA n'est intégrée.

Le package Cargo et son répertoire restent `helios-ctl` :
`scripts/wsl-cargo run -p helios-ctl -- status` fonctionne toujours. Les nouveaux
bundles installent `/usr/local/bin/helios`. Les anciens bundles signés contenant
`helios-ctl` restent acceptés ; aucune migration de la CA opérateur ni des profils
n'est effectuée. Les scripts qui invoquent directement l'ancien exécutable
doivent utiliser `helios` après la nouvelle livraison.

## Cible de la maintenance

`--url` cible seulement l'API. Par défaut, `http://100.64.0.1:8080`
(`aether::DEFAULT_WG_API_URL`), l'adresse où heliosd sert l'API dans le
tunnel ; un daemon en simulation (`heliosd run --dev`) écoute sur
`http://127.0.0.1:8080`, à passer avec `--url` ou `HELIOS_URL`. Le pare-feu
n'accepte l'API que par l'interface du tunnel, boucle locale comprise : depuis
le shell de la gateway, seules les commandes locales (`update`, `firmware`,
`profile check`) répondent, et la ligne d'état affiche
`○ no API answer (tunnel only)`. `update` et `update --check` agissent sur la machine
qui exécute le terminal. `firmware list` est local par défaut ; `--ssh-target`
le dirige vers une gateway. L'inventaire utilise les métadonnées déjà présentes,
sans rafraîchissement ni installation. Un échec d'inventaire est une erreur,
jamais une liste vide ; le code 2 documenté de fwupd signifie aucune action.

```sh
# Sur la gateway : contrôles passifs
helios update --check
helios firmware list
```

Le contrôle passif lit `heliosd tpm sealing-status`, simule APT et lit fwupd.
Il ne descelle aucun secret, ne consomme aucun billet et n'arme aucune fenêtre.
Un binaire sans TPM qui trouve une identité scellée refuse de déclarer la
maintenance sûre. L'outil et le daemon doivent être livrés ensemble.

`helios update` conserve le parcours APT de l'[ADR-007](adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md).
Les paquets Secure Boot classés PCR 0/7 sont refusés si le TPM est actif : ils
ne sont pas couverts par la fenêtre OS. Mettre à jour le paquet `fwupd` ne
flashe pas les firmwares proposés par celui-ci.

## Firmware : préparation, installation et redémarrage

Le parcours s'exécute **depuis un poste opérateur Linux distinct**. Cela conserve
la clé de récupération et le journal quand la gateway redémarre ou devient
injoignable. La gateway doit disposer de fwupdmgr 2.0.20 ou supérieur, de systemd, du nouveau `heliosd`
installé dans `/opt/helios/current/heliosd` et d'un SSH joignable indépendamment
du tunnel qu'elle fournit. Configurer au préalable la clé SSH, `known_hosts`
et les autorisations `sudo -n` pour les commandes nécessaires. Helios conserve
la vérification stricte de la clé hôte. Prévoir un accès console et une fenêtre
d'interruption de service pour une gateway principale.
La version du client fwupd est contrôlée avant préparation et avant arrêt du
service : ce minimum correspond au contrat vérifié d'installation par
périphérique et version, pas à une installation de fichier firmware.

Sur une gateway avec TPM, utiliser la clé de séquestre de l'opérateur, conservée
hors gateway. Si elle n'existe pas, `helios escrow keygen --output-dir cles`
la crée sur le poste opérateur. La préparation dérive sa moitié publique,
exporte une copie **chiffrée du secret racine existant**, puis vérifie qu'elle
s'ouvre et correspond à l'engagement de la requête. Aucune copie du secret en
clair n'est écrite sur disque. Cette sauvegarde préserve les coffres WireGuard,
identité de négociation et PSK statiques, sans persister les PSK négociés.

```sh
helios firmware list --ssh-target admin@gateway
helios firmware prepare --ssh-target admin@gateway \
  --device 5bc922b7bd1adb5b6f99592611404036bd9f42d0 --target-version 2023 \
  --plan maintenance.json --private-key cles/escrow-private.key
```

La préparation écrit `maintenance.json` (sauvegarde chiffrée et progression)
et `maintenance.request.json` (requête publique). Elle n'installe rien et ne
redémarre pas. Elle exige un descellement nominal ; une fenêtre OS ou un billet
en attente est refusé. L'index NV résiduel est révoqué avant export.

Faire signer la requête par l'éditeur **hors gateway**, avec une époque du
trousseau public compilé dans les outils livrés :

```sh
helios-publisher firmware-recovery --request maintenance.request.json \
  --key-epoch 1 --ed25519-private-key ed25519-private.pk8 \
  --ml-dsa-65-private-key ml-dsa-65-private.bin --keyring publisher-keyring.json \
  --output maintenance.authorization.json

helios firmware update --plan maintenance.json \
  --authorization maintenance.authorization.json --private-key cles/escrow-private.key
```

Après confirmation, Helios vérifie à nouveau machine, démarrage, capacités TPM,
version proposée et autorisation, puis arrête le service. fwupd installe le
**périphérique et la version préparés**, avec ses contrôles de sécurité et sans
redémarrage automatique. Helios enregistre ensuite l'intention de redémarrer,
ordonne le redémarrage et attend un nouveau `boot_id` de la même machine.
Une coupure SSH seule ne prouve pas qu'elle a redémarré.

Après reconnexion et vérification de la version fwupd attendue sans erreur,
le secret est transmis uniquement par l'entrée standard du
canal SSH authentifié. `heliosd tpm restore-firmware` vérifie les deux signatures,
l'ancre de l'ancien blob, l'engagement du secret et le compteur ; il rescelle
**le même secret** sur PCR 0/4/7 courants. Le service est démarré après restauration.
La maintenance n'est terminée que si fwupd annonce la version attendue sans
`UpdateError` ni état en attente ou en échec, si le service est actif et si sa disponibilité réelle, avec
pare-feu appliqué, appartient au même PID et au même démarrage. Cela ne prouve
pas encore un handshake d'un client : vérifier également la connexion Orion
sur la cible avant de clôturer la fenêtre d'exploitation.

Une gateway sans TPM utilise le même journal et les mêmes contrôles de
redémarrage ; les options de clé et d'autorisation sont alors omises.
`--yes` supprime seulement la confirmation initiale. `--timeout` borne l'attente
de retour (300 secondes par défaut, 10 à 3600). Les commandes distantes de contrôle et récupération sont bornées à 30 secondes,
auxquelles s'ajoute la connexion SSH ; un délai dépassé ne réinstalle rien.
Le flash lui-même conserve les délais de fwupd : Helios ne tue pas une écriture
firmware sur un délai arbitraire.

## Reprise après interruption

```sh
helios firmware status --plan maintenance.json
helios firmware resume --plan maintenance.json \
  --authorization maintenance.authorization.json --private-key cles/escrow-private.key
```

Le plan est exclusif, enregistré atomiquement en 0600 et synchronisé sur disque.
Une reprise ne relance **jamais** l'installateur. Si l'interruption survient
pendant le flash, Helios refuse de deviner son résultat : inspecter l'état
fwupd et confirmer explicitement `resume --confirm-installed` une fois
l'installation du périphérique et de la version terminée. Une seconde
confirmation interactive est exigée. Ne pas utiliser cette option pour masquer
un flash en échec.

Après une demande de reboot dont la réponse a été perdue, la reprise attend un
nouveau démarrage sans ordonner des reboots successifs. Si la machine n'a pas
redémarré, l'opérateur le fait depuis SSH ou la console. Si le bootloader est
révoqué par dbx ou si le firmware empêche Linux de démarrer, SSH et Helios ne
peuvent pas réparer ce démarrage : utiliser la console et un média compatible.
Le plan, la sauvegarde et la clé opérateur restent nécessaires.

Le compteur est avancé **avant** le remplacement du blob. Une coupure entre ces
écritures consomme l'autorisation sans perdre la sauvegarde : l'éditeur doit
signer la même requête avec une `version` supérieure au compteur courant,
l'opérateur reprend avec cette nouvelle autorisation. Les autres champs doivent
rester identiques. Une réponse perdue après restauration est récupérable avec
l'autorisation initiale : le descellement nominal vérifie que le même secret
est déjà présent, sans rejouer le rescellement.

La confidentialité HESC v1 utilise X25519, HKDF-SHA256 et AES-256-GCM ; elle
n'est pas post-quantique. Les signatures de restauration sont hybrides.
Les buffers sensibles sont effacés, le processus de récupération refuse les
core dumps et le frame de transfert utilise `LockedSecret`. Si le système
refuse le verrouillage mémoire, le terminal le signale ; le chiffrement des
volumes/swap du poste opérateur reste nécessaire (ADR-006). Limiter la durée
de conservation de la sauvegarde : elle donne accès à tous les coffres de ce
secret lorsqu'elle est associée à la clé opérateur.

## Validation avant production

Les tests automatiques couvrent signatures, contexte, mauvais secret, compteur,
conservation des coffres, erreurs TPM, journal, erreurs de restauration,
changement de machine, version inattendue et perte de réponse au reboot.
Ils ne prouvent ni les PCR réels ni la compatibilité du bootloader avec dbx.
Sur une gateway de laboratoire avec console : jouer préparation, interruption
SSH à chaque étape, reboot, restauration, ouverture des coffres et connexion
Orion sans ré-enrôlement, puis vérifier l'absence d'une fenêtre NV résiduelle.
Voir [TESTING.md](testing/TESTING.md). Ne pas commencer cette recette sur la
gateway principale de production.
