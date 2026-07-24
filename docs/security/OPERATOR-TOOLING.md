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
  --name helios-orion-clients --output-dir ./orion-client-ca
```

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

Les deux clés clientes produites en `0600` servent au transfert initial vers le
stockage protégé du poste Orion, puis doivent être effacées du poste opérateur.
Le câblage de ce stockage dans le shell Windows reste à faire : Orion l’annonce
sur son écran *Profils* et refuse la connexion plutôt que de la tenter. Pour
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

### Bloc de négociation dans le profil

`profile emit` n'écrit pas encore ce bloc : il se colle dans le document émis,
sous `profile`, à côté des champs WireGuard. Il ne porte que du public — le
certificat client et sa clé privée vont dans le stockage protégé du poste, le
document n'en nomme que l'entrée :

```json
"key_negotiation": {
  "mode": "ml_kem",
  "minimum_mode": "ml_kem",
  "endpoint": "vpn.example.net:51821",
  "server_name": "vpn.example.net",
  "gateway_ca_der": "<base64 de key-negotiation-cert.der>",
  "gateway_pq_certificate": "<base64 de key-negotiation-pq-cert.json>",
  "identity": "orion-portable"
}
```

`minimum_mode` est facultatif : absent, il prend la valeur de `mode`, car un
profil qui demande ML-KEM aujourd'hui et accepterait le classique demain ne
protège rien. Un `mode` sous son propre plancher fait refuser l'import. Orion
vérifie à l'import que le certificat PQ est bien épinglé à la clé WireGuard de
cette gateway, et affiche son empreinte sur l'écran *Profils* : c'est la valeur
qu'a imprimée `heliosd init-key-negotiation`.

## Ce que cet outillage ne fait pas

* Il ne construit ni ne signe de release — c'est le poste éditeur.
* Il ne révoque rien cryptographiquement.
* Il ne remplace pas la recette matérielle : le scellement TPM réel et
  l'ouverture d'un séquestre produit par une vraie gateway ne sont pas
  observables en WSL2 ([TESTING](../testing/TESTING.md)).
