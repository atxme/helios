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
sudo heliosd init-ipv6-prefix  # optionnel — génère et persiste le préfixe ULA
```

`init-identity` génère la clé privée en mémoire et la scelle directement : elle
ne touche jamais le disque en clair. Elle refuse d'écraser une identité
existante — `--rotate` l'assume explicitement, en sachant que **tous** les
clients devront mettre à jour leur `peer_public_key`.

Ce chemin est nécessairement local. `POST /api/gateway/wireguard-key` vit
derrière `helios0`, donc derrière un tunnel qui suppose déjà une identité et un
pair administrateur : c'est un chemin de rotation, pas de bootstrap.

`init-ipv6-prefix` tire un Global ID ULA et l'écrit dans `wg_address_v6` de
`network.toml`. La commande ne change jamais un préfixe déjà présent. Le
préfixe est appliqué au démarrage : arrêter puis redémarrer `heliosd` après sa
création. Il peut aussi être déclaré manuellement dans `network.toml`.

## 2. Séquestre — avant d'en avoir besoin

Sur le poste opérateur, **jamais sur la gateway** :

```sh
helios escrow keygen --output-dir ~/helios-escrow
```

Déclarer la clé publique affichée dans `escrow_public_key` de `network.toml`.
La gateway écrit dès lors, à chaque scellement, une copie de son identité
chiffrée vers cette clé. Sans séquestre, un changement de PCR — nouveau noyau,
bootloader ou firmware — perd l'identité **définitivement**.

Le jour où c'est arrivé : récupérer `/var/lib/helios/wg-key.escrow`, puis

```sh
helios escrow open --escrow wg-key.escrow \
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

`helios` est livré dans le bundle, à côté de `heliosd`. Dans la session SSH
où l'on met à jour de toute façon :

```sh
helios update
```

Elle rafraîchit les listes, annonce **quels paquets en attente déplacent quel
PCR**, met à jour, arme la fenêtre et redémarre. Le redémarrage la tue : il n'y a
rien à attendre ni à rapporter ensuite. Ce qui s'est passé est au journal du
démarrage suivant :

```sh
journalctl --namespace=helios -u heliosd -b | grep -i 'update window'
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
`helios` lance donc `heliosd tpm` en sous-processus sous `sudo`.

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

L'absence d'index NV — l'état ordinaire d'une gateway sans fenêtre armée — est
demandée par `TPM2_GetCapability`, qui répond « aucun » sans échouer. Une
version antérieure la déduisait de l'échec d'un `TPM2_NV_ReadPublic`, ce qui
faisait afficher `WARNING:esys:` / `ERROR:esys:` (`0x18b`) à chaque
interrogation : des lignes lues comme un diagnostic de panne alors qu'elles
disaient que tout allait bien. Si vous en revoyez, elles portent sur autre
chose.

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
helios peer list
helios peer add --name portable --public-key <clé publique du client>
helios peer revoke --name portable
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

> **État actuel.** Les commandes de cette section décrivent le chemin encore
> servi. La cible acceptée par
> [ADR-008](../adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md) déplace le cycle de
> vie vers Astra, conserve les CA maîtresses chiffrées et les ouvre localement
> avec `astra-signer` et une YubiKey. Ce lot est livré
> ([DEPLOIEMENT-ASTRA](../DEPLOIEMENT-ASTRA.md)) ; les commandes ci-dessous
> restent celles des scripts d'installation et d'un domaine qui n'est pas passé
> sous Astra.

Créer l’autorité cliente sur le poste opérateur, jamais sur la gateway :

```sh
helios key-nego init-client-ca \
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
helios key-nego issue-client \
  --name portable \
  --wireguard-public-key <clé publique WireGuard> \
  --ca-certificate ./orion-client-ca/orion-client-ca.der \
  --ca-private-key ./orion-client-ca/orion-client-ca-key.der \
  --ca-pq-private-key ./orion-client-ca/orion-client-pq-ca-private.bin \
  --output-dir ./portable-key-nego

helios peer add --name portable \
  --public-key <clé publique WireGuard> \
  --key-negotiation-certificate-sha256 <empreinte TLS affichée> \
  --key-negotiation-pq-certificate-sha256 <empreinte PQ affichée> \
  --minimum-mode ml-kem
```

Les empreintes peuvent aussi venir des feuilles elles-mêmes :
`--certificate ./portable-key-nego/orion-client-cert.der` et
`--pq-certificate ./portable-key-nego/orion-client-pq-cert.json` suffisent,
`peer add` en calcule les empreintes canoniques. Données en plus, les deux
formes doivent concorder : une empreinte qui désigne une autre feuille est
refusée plutôt qu'enregistrée.

Sans `--minimum-mode`, la présence de l'empreinte PQ choisit déjà `ml-kem`.
L'option explicite rend la politique visible dans les scripts. Une
renégociation réseau vers `static_psk` sera ensuite refusée.

Ces commandes sont un outillage de **laboratoire**, lié à la CA sur fichier :
`issue-client` fabrique les clés privées du client sur le poste opérateur. Elles
restent utiles pour inspecter la PKI ou sonder une gateway ; un vrai client
s'enrôle par une invitation v5 (section 6), dont les clés ne quittent jamais le
poste.

Les deux clés clientes que `issue-client` produit en `0600` ne servent qu'aux
sondes ci-dessous, et s'effacent ensuite du poste opérateur. Pour
valider mTLS, ML-DSA et les messages sans modifier durablement un slot :

```sh
helios key-nego probe \
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

### Enrôlement v5 — aucune clé privée ne voyage

Un client Helios s'enrôle sans qu'aucune clé privée quitte son poste
([NEGOCIATION-DE-CLE-V5 §15](../specification/NEGOCIATION-DE-CLE-V5.md#15-enrôlement)).
Prérequis : un domaine de confiance (`astra-signer init`, puis
`heliosd init-trust-domain`), donc une leaf PQ gateway émise sous `CA-PQ`, et
un credential opérateur matériel enregistré dans le coffre.

1. **Invitation** — sur le poste opérateur :

   ```sh
   astra-signer enroll invite      --gateway-certificate key-negotiation-pq-cert.json      --valid-for-hours 24      --out poste.helios-invite
   ```

   La commande demande un credential autorisé (deux distincts avec
   `--allow-readmission`, pour réadmettre une clé retirée), écrit l'invitation
   et affiche l'empreinte `CA-PQ` en groupes de quatre. L'invitation est
   publique ; sa clé de preuve reste dans le registre
   `~/.helios/enrollment-invitations` (`HELIOS_ENROLLMENT_REGISTRY` le déplace).

2. **Demande** — sur le poste client, écran *Profils* → « Importer une
   invitation ». Orion affiche la gateway, l'échéance et l'empreinte ;
   l'utilisateur recopie celle que l'opérateur lui **lit par un autre canal**.
   Tant qu'elles diffèrent, rien n'est généré. Orion crée alors ses trois paires
   — WireGuard, TLS, ML-DSA-87 —, les scelle comme demande en attente et
   seulement ensuite offre le fichier `.helios-request`. Il ne contient aucun
   secret.

3. **Acceptation** — sur le poste opérateur :

   ```sh
   astra-signer enroll accept --request poste.helios-request --out-dir ./feuilles
   ```

   L'invitation est consommée **avant** toute émission : un échec ultérieur
   exige une nouvelle invitation. La commande écrit les feuilles TLS et PQ,
   nommées d'après l'identifiant de la demande, et imprime la ligne
   `heliosd peer add … --minimum-mode ml-kem` qui admet le pair ; la lancer en
   console sur la gateway (ajouter `--admin` pour le premier administrateur).

4. **Brouillon** — `helios enroll document` assemble le profil public autour
   des feuilles :

   ```sh
   helios enroll document --request poste.helios-request \
     --tls-certificate ./feuilles/<id>-client-cert.der \
     --pq-certificate ./feuilles/<id>-client-pq-cert.json \
     --endpoint vpn.example.net:51820 \
     --out poste.draft.json
   ```

   En ligne il lit la gateway par l'API ; hors ligne, `--gateway-certificate`,
   `--gateway-pq-certificate`, `--address` et `--trust-material` (la sortie de
   `heliosd show-trust-enrolment`) remplacent l'API. Il vérifie que les feuilles
   certifient les clés de la demande et refuse une gateway sans domaine.

5. **Signature** — `astra-signer enroll sign-document --draft poste.draft.json
   --out poste.orion` vérifie que le brouillon nomme les feuilles émises, la
   `CA-PQ` et la gateway de l'invitation, puis le signe sous `CA-PQ`.

6. **Import** — Orion vérifie la signature sous la `CA-PQ` épinglée à l'étape 2,
   la liaison à sa demande en attente, les feuilles contre ses clés locales et
   la gateway contre l'invitation ; il scelle alors l'identité et détruit la
   demande en attente. Un document qu'aucune demande de ce poste n'attend
   s'affiche en brouillon non connectable.

`astra-signer enroll list` montre l'état des invitations ; `enroll revoke <id>`
en annule une et détruit sa clé de preuve. Côté Orion, « Abandonner » détruit
une demande en attente et ses clés.

L'ancien `helios enroll`, qui émettait les clés du client sur le poste opérateur
et les livrait dans le profil, n'existe plus ; Orion refuse un document v1 Helios
en renvoyant ici. `scripts/provision-client.sh` refuse pour la même raison, et
`scripts/key-negotiation-setup.sh` ne prépare plus que la gateway.

### Profil WireGuard classique

`profile emit` **réémet** l'invitation d'un client WireGuard classique déjà
admis ; il n'admet personne et ne porte pas de bloc de négociation. Le client
détient sa clé et communique sa moitié publique (visible dans Orion, écran
*Profils*) :

```sh
helios profile emit --name portable \
  --endpoint vpn.example.net:51820 \
  --public-key <clé publique du client> \
  --output portable.json
```

Le fichier produit ne contient **aucun** secret : il porte l'endpoint, la clé
publique de la gateway, la VIP attribuée et l'URL interne de l'API. Orion
l'importe et complète avec la clé privée du profil local de même nom.

La commande réutilise l'adresse persistée du pair ; une clé inconnue est
refusée avec les commandes d'admission, et changer de clé pour un nom existant
exige une révocation explicite. Le mode assisté (`--with-private-key`) et
`--admin` ont été retirés le 18 octobre 2026 : le premier générait une paire que
la gateway n'avait jamais admise ; le second choisissait un rôle à une admission
qui n'a plus lieu.

## Ce que cet outillage ne fait pas

* Il ne construit ni ne signe de release — c'est le poste éditeur.
* Il ne révoque rien cryptographiquement.
* Il ne remplace pas la recette matérielle : le scellement TPM réel et
  l'ouverture d'un séquestre produit par une vraie gateway ne sont pas
  observables en WSL2 ([TESTING](../testing/TESTING.md)).
