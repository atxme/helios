# Outillage d'exploitation

Ce document est le mode d'emploi du **poste opérateur**. Il ne couvre ni les
clés de l'éditeur ([PUBLISHER-SIGNING](PUBLISHER-SIGNING.md)), ni la
construction d'une release. Le raisonnement derrière ces chemins est dans
[ADR-004](../adr/ADR-004-CHAINE-DE-LIVRAISON.md).

Règle unique à retenir : **chaque secret naît là où il doit vivre**. L'identité
de la gateway naît sur la gateway, la clé du client naît sur le poste client, la
clé de séquestre naît sur le poste opérateur et n'en sort pas.

## 0. Installer la gateway

La gateway ne reçoit **que des binaires**. Elle n'a ni compilateur, ni dépôt, ni
accès au code source.

```sh
sudo ./scripts/setup-target.sh              # dépendances système, une fois
sha256sum helios-<version>-<target>.tar.gz  # comparer à l'empreinte publiée
sudo ./helios-installer bootstrap --archive helios-<version>-<target>.tar.gz
```

L'installateur vérifie la signature hybride du manifeste, puis l'empreinte de
chaque fichier, puis l'absence de tout fichier non déclaré — **avant** d'écrire
quoi que ce soit. Une installation refusée ne laisse rien derrière elle.

La comparaison manuelle de l'empreinte n'est pas une formalité : au tout premier
déploiement, `helios-installer` vient lui-même de l'archive, et rien sur la
machine ne peut encore attester de son authenticité. C'est le seul moment où la
confiance repose sur le canal de transport ; les installations suivantes sont
vérifiées par un installateur déjà installé et vérifié.

L'installateur n'active aucun service : sur une gateway neuve, l'identité
WireGuard n'existe pas encore et le kill-switch couperait l'accès.

## 1. Premier déploiement d'une gateway

Avec accès console, sur la gateway :

```sh
sudo heliosd provision-tpm     # une seule fois — scelle un secret neuf
sudo heliosd init-identity     # affiche la clé PUBLIQUE de la gateway
```

`init-identity` génère la clé privée en mémoire et la scelle directement : elle
ne touche jamais le disque en clair. Elle refuse d'écraser une identité
existante — `--rotate` l'assume explicitement, en sachant que **tous** les
clients devront mettre à jour leur `peer_public_key`.

Ce chemin est nécessairement local. `POST /api/gateway/wireguard-key` vit
derrière `helios0`, donc derrière un tunnel qui suppose déjà une identité et un
pair administrateur : c'est un chemin de rotation, pas de bootstrap.

## 2. Séquestre — avant d'en avoir besoin

Sur le poste opérateur, **jamais sur la gateway** :

```sh
helios-ctl escrow keygen --output-dir ~/helios-escrow
```

Déclarer la clé publique affichée dans `escrow_public_key` de `network.toml`.
La gateway écrit dès lors, à chaque scellement, une copie de son identité
chiffrée vers cette clé. Sans séquestre, un changement de PCR — nouveau noyau,
bootloader ou firmware — perd l'identité **définitivement**.

Le jour où c'est arrivé : récupérer `/var/lib/helios/wg-key.escrow`, puis

```sh
helios-ctl escrow open --escrow wg-key.escrow \
  --private-key ~/helios-escrow/escrow-private.key \
  --output wg-key.recovery
```

La commande affiche la clé **publique** retrouvée, pas le secret : elle doit
être celle que les clients connaissent déjà. Si elle diffère, ce séquestre n'est
pas celui de cette gateway — ne pas le déposer. Sinon, poser le fichier dans
`/var/lib/helios/wg-key.recovery` et redémarrer : la gateway rescelle et efface.

## 2 bis. Mettre à jour l'OS de la gateway

`apt upgrade` ne casse rien tant que la machine tourne : les PCR ne sont
étendus qu'au démarrage. Le risque est au **redémarrage suivant**, et seulement
si la mise à jour a touché la chaîne de démarrage — noyau, `grub`, `shim`, une
base Secure Boot, un firmware. Sans précaution, PCR 4 bouge, le descellement
échoue et le démon ne démarre pas.

La fenêtre de mise à jour ([ADR-007](../adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md))
porte le secret courant à travers **un** redémarrage planifié. Le secret ne
change pas, donc l'identité WireGuard, l'identité de négociation et la table des
PSK statiques sont intactes de l'autre côté : aucun client à ré-enrôler.

### En une commande, sur la gateway

`helios-ctl` est livré dans le bundle, à côté de `heliosd`. Dans la session SSH
où l'on met à jour de toute façon :

```sh
helios-ctl update
```

Elle rafraîchit les listes, annonce **quels paquets en attente déplacent quel
PCR**, met à jour, arme la fenêtre et redémarre. Le redémarrage la tue : il n'y a
rien à attendre ni à rapporter ensuite. Ce qui s'est passé est au journal du
démarrage suivant :

```sh
journalctl -u heliosd -b | grep -i 'update window'
```

Le classement des paquets est ce que la commande apporte de plus qu'un
`apt upgrade` suivi d'un `prepare-update` : un `linux-image` ou un `grub-efi`
déplacent PCR 4 et sont couverts par la fenêtre ; un `fwupd` ou un
`secureboot-db` déplacent PCR 0/7, que la fenêtre lie elle-même — elle ne
s'ouvrira pas, et la gateway retombera sur billet et séquestre. Mieux vaut
l'apprendre à l'invite de confirmation que depuis une gateway qui ne redémarre
plus. Le microcode et `linux-firmware` ne sont volontairement pas signalés :
l'initrd est mesuré en PCR 8/9, que Helios ne scelle pas.

`--yes` saute la confirmation. Une fenêtre déjà armée fait refuser la commande :
c'est le signe qu'un redémarrage précédent n'a pas eu lieu.

**La capacité d'armer est vérifiée avant `apt`, jamais après.** `apt upgrade`
est le point de non-retour : le noyau remplacé, les PCR bougeront au
redémarrage suivant, fenêtre ou pas, et un redémarrage sans fenêtre perd les
coffres. La commande interroge donc `heliosd tpm update-readiness` d'abord — un
TPM injoignable ou un démarrage qui n'est pas un descellement nominal fait
**refuser la mise à jour**, avant que quoi que ce soit ne soit écrit. Si le
scellement est désactivé (`tpm.enabled = false`), il n'y a pas de secret à
perdre : la mise à jour se fait, sans fenêtre ni redémarrage imposé.

L'armement ne passe **pas** par l'API, et c'est délibéré (ADR-007) : l'API vit
derrière le tunnel que la fenêtre existe précisément pour préserver, et une
fenêtre déclenchable à distance est une exposition déclenchable à distance.
`helios-ctl` lance donc `heliosd tpm` en sous-processus sous `sudo`.

### À la main

```sh
sudo apt update && sudo apt upgrade      # ne redémarrez pas encore
sudo heliosd tpm prepare-update --reboot
```

`--reboot` enchaîne le redémarrage, ce qui réduit la fenêtre à quelques
secondes — c'est le seul mode admis en exploitation. Sans lui, la fenêtre reste
ouverte jusqu'à son échéance (trente minutes) et le redémarrage est à votre
main ; cette variante sert aux essais contrôlés.

Au retour, le journal doit contenir :

```
update window consumed: the PCRs moved (OS upgrade) and the same secret
was resealed on the new state — vaults intact
```

Si la mise à jour n'a finalement rien déplacé, le descellement est nominal et la
fenêtre est révoquée automatiquement — rien à faire.

Pour annuler avant le redémarrage : `sudo heliosd tpm cancel-update`. Pour
savoir où on en est : `sudo heliosd tpm update-status`.

Sur une gateway sans fenêtre armée, cette interrogation affiche des lignes
`WARNING:esys:` / `ERROR:esys:` autour de `NV_ReadPublic` (`0x18b`) : c'est la
bibliothèque TSS qui commente l'absence de l'index NV, c'est-à-dire l'état
ordinaire. Le verdict est la dernière ligne — `armed` ou `none`.

**Ce que la fenêtre ne couvre pas.** Une mise à jour de firmware ou de la base
Secure Boot déplace PCR 0 ou 7 : la fenêtre ne s'ouvre pas, et on retombe sur
billet de rescellement et séquestre (§2). Et pendant qu'une fenêtre est ouverte,
quelqu'un qui a l'accès physique à la machine et démarre un autre OS signé peut
lire le secret sans que cette lecture soit détectable — d'où `--reboot`, qui
réduit cette exposition au redémarrage lui-même.

## 3. Premier pair administrateur

Il faut un chemin local, sinon rien ne peut démarrer : aucune mutation distante
n'est autorisée tant qu'aucun administrateur n'est déclaré (ADR-003 §3).

```sh
sudo heliosd peer add --name poste-admin --public-key <clé publique> --admin
sudo systemctl restart heliosd     # la config locale est relue au démarrage
```

## 4. Admission courante, dans le tunnel

```sh
helios-ctl peer list
helios-ctl peer add --name portable --public-key <clé publique du client>
helios-ctl peer revoke --name portable
```

La VIP n'est pas un choix : elle est dérivée de la clé publique, donc identique
côté gateway et côté client. Ne pas éditer `peers` à la main dans
`network.toml`, et ne jamais construire un `POST /api/network` à partir de
`GET /api/network` : la vue de lecture est expurgée des PSK, et la reposter les
effacerait pour **tous** les pairs — chacun d'eux perdrait ses handshakes, sans
canal de rattrapage.

Retirer un pair n'est pas une révocation cryptographique : il tombe à son
prochain handshake, il n'existe pas de liste de révocation.

## 5. PKI et key-negotiation

Créer l’autorité cliente sur le poste opérateur, jamais sur la gateway :

```sh
helios-ctl key-nego init-client-ca \
  --name helios-orion-clients --output-dir ~/.helios/certs/internal-ca
```

**Un seul emplacement, une seule autorité.** `~/.helios/certs/internal-ca` est
celui qu’emploient `target-bootstrap.sh` et `key-negotiation-setup.sh` ; c’est
aussi celui qu’il faut sauvegarder. Une gateway ne fait confiance qu’à
l’autorité dont elle détient les parties publiques : en créer une seconde
ailleurs ne donne pas une PKI neuve, ça donne une PKI qui ne signe plus rien
d’acceptable pour cette gateway. Les scripts reprennent une autorité laissée
par un workflow antérieur (`./orion-client-ca`, `~/.helios/orion-client-ca`)
plutôt que d’en fabriquer une autre, et retirent celle qu’ils viennent de créer
si la gateway la refuse.

La commande crée simultanément l'autorité TLS et l'autorité ML-DSA-65. Copier
seulement leurs parties publiques `orion-client-ca.der` et
`orion-client-pq-ca-public.bin` sur la gateway, puis créer les identités serveur
localement. Les clés privées TLS et PQ naissent en mémoire et sont scellées au
TPM :

```sh
sudo heliosd init-key-negotiation \
  --server-name vpn.example.net \
  --client-ca ./orion-client-ca/orion-client-ca.der \
  --client-pq-ca ./orion-client-ca/orion-client-pq-ca-public.bin
```

Récupérer les deux certificats publics indiqués par la commande. Le certificat
PQ JSON est épinglé dans le profil Orion. Émettre ensuite les deux certificats
du client, liés à sa même clé publique WireGuard :

```sh
helios-ctl key-nego issue-client \
  --name portable \
  --wireguard-public-key <clé publique WireGuard> \
  --ca-certificate ./orion-client-ca/orion-client-ca.der \
  --ca-private-key ./orion-client-ca/orion-client-ca-key.der \
  --ca-pq-private-key ./orion-client-ca/orion-client-pq-ca-private.bin \
  --output-dir ./portable-key-nego

helios-ctl peer add --name portable \
  --public-key <clé publique WireGuard> \
  --key-negotiation-certificate-sha256 <empreinte TLS affichée> \
  --key-negotiation-pq-certificate-sha256 <empreinte PQ affichée> \
  --minimum-mode ml-kem
```

Sans `--minimum-mode`, la présence de l'empreinte PQ choisit déjà `ml-kem`.
L'option explicite rend la politique visible dans les scripts. Une
renégociation réseau vers `static_psk` ou `classic` sera ensuite refusée.

Ces quatre commandes restent utiles pour inspecter la PKI ou réémettre un
certificat seul ; pour admettre un client, `helios-ctl enroll` (section 6) les
enchaîne et évite de recopier deux empreintes à la main.

Les deux clés clientes produites en `0600` servent au transfert vers le stockage
protégé du poste Orion, puis doivent être effacées du poste opérateur. Orion les
scelle par DPAPI, liées au compte Windows de l'utilisateur ; sur toute autre
plateforme, il refuse franchement plutôt que de les écrire en clair. Pour
valider mTLS, ML-DSA et les messages sans modifier durablement un slot :

```sh
helios-ctl key-nego probe \
  --endpoint vpn.example.net:51821 \
  --server-name vpn.example.net \
  --gateway-certificate key-negotiation-cert.der \
  --gateway-pq-certificate key-negotiation-pq-cert.json \
  --client-certificate portable-key-nego/orion-client-cert.der \
  --client-private-key portable-key-nego/orion-client-key.der \
  --client-pq-certificate portable-key-nego/orion-client-pq-cert.json \
  --client-pq-private-key portable-key-nego/orion-client-pq-private.bin \
  --client-wg-private-key-file ./portable-wg-private-key \
  --gateway-wg-public-key <clé publique WireGuard Helios> \
  --mode ml-kem
```

Le probe ferme volontairement la transaction sans confirmation ; Helios
restaure donc le slot précédent.

## 6. Profil client

Mode recommandé — le client détient déjà sa clé et communique sa moitié
publique (visible dans Orion, écran *Profils*) :

```sh
helios-ctl profile emit --name portable \
  --endpoint vpn.example.net:51820 \
  --public-key <clé publique du client> \
  --output portable.json
```

Le fichier produit ne contient **aucun** secret : il porte l'endpoint, la clé
publique de la gateway, la VIP attribuée et l'URL interne de l'API. Orion
l'importe et complète avec la clé privée du profil local de même nom.

Mode assisté, quand l'utilisateur ne peut rien faire lui-même :

```sh
helios-ctl profile emit --name portable \
  --endpoint vpn.example.net:51820 \
  --with-private-key --output portable.json
```

Ce fichier **contient la clé privée du client** : il naît en `0600`, se remet
par un canal maîtrisé et s'efface du poste opérateur ensuite. C'est le seul
chemin où une clé privée client existe hors du poste client.

Les deux modes admettent le pair au passage. Réémettre un profil pour une clé
déjà admise réutilise son adresse ; changer de clé pour un nom existant exige
une révocation explicite.

### Enrôlement complet — une seule commande

`profile emit` ne met **pas** de bloc de négociation : c'est le chemin qui ne
produit aucun secret, et un profil qui réclamerait un certificat sans le livrer
ne se connecterait pas. Pour un client qui négocie avant WireGuard, une seule
commande fait tout :

```sh
helios-ctl enroll --name portable \
  --endpoint vpn.example.net:51820 \
  --client-ca-dir ./orion-client-ca \
  --output portable.orionprofile
```

Elle enchaîne ce que la section 5 sépare : elle lit sur la gateway sa clé
publique WireGuard, ses certificats de négociation et le port qu'ils écoutent
(`GET /api/key-negotiation`), génère la paire WireGuard du client, émet ses deux
certificats depuis la CA opérateur, admet le pair avec les deux empreintes et
le plancher, puis écrit **un** document qui porte le profil et l'identité.

Options utiles : `--public-key` si le client détient déjà sa clé WireGuard,
`--mode classic` pour un pair qui ne peut pas encore faire ML-KEM,
`--negotiation-endpoint` si le port de négociation est redirigé ailleurs que le
tunnel, `--identity` pour nommer l'entrée du stockage protégé (par défaut
`orion-<nom>`), et `--replace` pour ré-enrôler un pair existant — ce qui révoque
l'ancienne identité, donc coupe le poste qui la détenait.

Le fichier produit **contient les clés privées du client**. Il naît en `0600`,
se remet par un canal maîtrisé et s'efface des deux postes après import : Orion
scelle l'identité au compte Windows et n'a plus besoin du fichier. C'est le même
régime que `profile emit --with-private-key`.

La commande refuse d'avancer si la gateway ne sert aucun matériel de
négociation, et si son certificat est épinglé à une autre identité WireGuard que
celle qu'elle utilise — cas d'une identité pivotée sans réémission du
certificat, qui ferait échouer tous les clients bâtis ensuite.

Orion vérifie à l'import que le certificat PQ est bien épinglé à la clé
WireGuard de cette gateway, scelle l'identité et affiche son empreinte sur
l'écran *Profils* : c'est la valeur qu'a imprimée `heliosd
init-key-negotiation`. Les comparer de vive voix est ce qui rattache le profil à
la bonne gateway.

## Ce que cet outillage ne fait pas

* Il ne construit ni ne signe de release — c'est le poste éditeur.
* Il ne révoque rien cryptographiquement.
* Il ne remplace pas la recette matérielle : le scellement TPM réel et
  l'ouverture d'un séquestre produit par une vraie gateway ne sont pas
  observables en WSL2 ([TESTING](../testing/TESTING.md)).
