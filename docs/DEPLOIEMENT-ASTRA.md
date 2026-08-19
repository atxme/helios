# Déployer Astra et amorcer un domaine de confiance

Guide opératoire de l'[ADR-008](adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md). Il
décrit ce qui existe aujourd'hui et **nomme ce qui manque encore**, parce qu'un
guide qui laisse croire que la rotation fonctionne coûte une journée à celui
qui le suit.

## Deux commandes

```sh
astra-signer init --rp-id astra.helios.local --label "YubiKey du bureau"
./scripts/deploy.sh
```

C'est tout. La première exige une clé de sécurité branchée et ne peut pas être
automatisée — c'est le but d'une clé physique. La seconde fait le reste :
image, transfert, amorçage d'Astra, amorçage du registre gateway, redémarrage.

Aucune valeur n'est recopiée à la main. `init` écrit un **relais** public à côté
du coffre (`~/.helios/astra/astra-domain.json`, `%APPDATA%\astra\` sous Windows) :
domaine, RP ID, ancre `CA-PQ`.
`deploy.sh` le lit, demande à la gateway son identité servie
(`heliosd show-identity`), amorce Astra, **capture** dans sa sortie la clé de
service et la tête de chaîne d'audit, les reporte dans le `.env` distant et
enchaîne sur `heliosd init-trust-domain`.

Sans relais, `deploy.sh` saute cette partie en une ligne et déploie la gateway
comme avant : une gateway sans autorité reste une gateway qui marche.
`--sans-astra` la saute explicitement.

## Ce que ce lot livre, et ce qu'il ne livre pas

Après ce guide, vous avez : un domaine de confiance existant des deux côtés, un
coffre d'autorité ouvert par clé de sécurité, un Astra qui tourne et tient son
registre et sa chaîne d'audit, une gateway dont les routes de cycle de vie
in-tunnel sont ouvertes.

Vous n'avez **pas** encore de renouvellement de certificats fonctionnel. Il
manque :

- le **dépôt** des demandes et des résultats d'`astra-signer`. Les commandes
  existent — `issue-ca-tls`, `authorize-issuer`, `bindings`, `approve`,
  `approve-campaign`, `rotate-ca-pq` — mais elles lisent une demande sur disque
  et écrivent leur résultat à côté. Le backend privé sait vérifier un résultat
  relayé, mais le compagnon ne sait pas encore utiliser `heliosd_url` : les
  routes publiques du §8.2 répondent `501` et Orion ne lance pas encore le
  compagnon. La copie de fichiers reste donc un geste d'outillage, pas un
  renouvellement Orion fonctionnel ;
- la **distribution des objets de transition** : le relais typé
  WireGuard–veth du §2 est livré dans ses deux sens — Orion appelle Helios dans
  WireGuard, Helios relaie sur le veth privé mTLS, et l'autorisation de stage
  comme le reçu circulent uniquement entre Astra et Helios — mais la gateway ne
  détient encore aucun objet pré-signé à distribuer par `trust-update`.
  L'ancienne route `stage` Orion ne doit
  pas être ouverte et sera retirée lors de cet alignement ;
- le **pilote client** du §7 dans `orion-core` : création des clés candidates,
  ouverture et suivi de l'opération, lancement du compagnon, vérification et
  persistance du grant, puis `stage-commit` ;
- la **bascule de confiance** du §13 et les objets pré-signés de `trust-update`.
  L'alignement cryptographique du 16 août (ctx ML-DSA, HVLT, pin de politique,
  jetons de capacité et fournisseur d'aléa sans DRBG applicatif) est livré ; la
  validation CAVP/ACVP n'est pas exigée par cette version de la spécification.

Ce qui est donc réellement éprouvé ici : la construction de l'image, le
démarrage du conteneur, les volumes, la sauvegarde, le durcissement, la
cohérence des deux moitiés du domaine et le relais applicatif serveur sur une
paire TLS de test. Le veth noyau réel et le parcours Orion complet ne le sont
pas encore.

## Le choix qu'on ne refait pas

Le **RP ID WebAuthn**, avant tout le reste.

Un credential FIDO2 est créé *sous* un RP ID, et une assertion doit présenter
le même. Le coffre le mémorise à `astra-signer init` ; en changer rend tous les
key-slots inouvrables, définitivement, sans recours — la spécification refuse
explicitement toute phrase de passe de secours.

Choisissez un nom que vous garderez : `astra.helios.local` en interne, ou un nom
public si Astra sort. Il se propage ensuite tout seul aux trois endroits qui en
ont besoin.

Ce nom reste le RP ID et l'origine logique de l'assertion WebAuthn même quand
le renouvellement ordinaire voyage par l'adresse WireGuard de Helios. Il
n'oblige pas Orion à ouvrir une connexion HTTPS directe vers Astra.

## Prérequis

- La gateway tourne, et `heliosd init-key-negotiation` a déjà été passé. Le
  registre décrit les leaves effectivement servies ; sans elles il n'y a rien à
  décrire, et `deploy.sh` le dit.
- Un moteur de conteneur sur la gateway (`docker compose` ou `podman compose`).
  Absent, l'étape est sautée avec la commande d'installation en clair. `buildx`
  n'est **pas** exigé : compose ≥ 2.33 délègue par défaut la construction à
  `docker buildx bake`, que le paquet Ubuntu n'entraîne pas, et se contente
  alors d'un avertissement — l'image n'est pas construite, mais rien n'échoue.
  `deploy.sh` force donc `COMPOSE_BAKE=0`, vérifie que l'image existe après
  construction, et n'avale plus la sortie du constructeur.
- **Deux** clés de sécurité FIDO2 avec PIN. Une seule suffit pour commencer :
  l'autorité restera « non amorcée » et le dira à chaque commande, jusqu'à
  l'enrôlement de la seconde.
- Le compagnon bâti sur la machine où la clé se branche :
  `cargo build -p astra-signer`. En **debug** : le garde-fou ADR-002 refuse le
  trousseau éditeur de développement dans toute compilation `--release`, et
  rien ici n'y gagne — le déverrouillage d'un key-slot est un HKDF-SHA256.
  Pour un binaire release, fournir `HELIOS_PUBLISHER_KEYRING_PATH`.
- Sous Windows, **aucune élévation n'est nécessaire** : le compagnon passe par
  l'API WebAuthn du système (`--transport platform`, le défaut), qui demande
  elle-même le PIN et le contact — le PIN n'entre donc jamais dans ce
  processus. Elle exige `WEBAUTHN_API_VERSION_4` pour les sels `hmac-secret` ;
  sur un Windows antérieur, le compagnon le dit et renvoie vers
  `--transport hid`, qui parle CTAP2 directement mais **exige une console
  administrateur** — Windows y réserve l'ouverture d'un HID FIDO aux processus
  élevés depuis la 1903. `astra-signer devices` liste ce que la pile HID
  montre, et distingue « aucun HID » de « des HID, mais aucun FIDO ».
  Un credential est celui de la clé, pas celui de l'API : un coffre créé par un
  transport s'ouvre par l'autre, tant que le RP ID est le même — le chemin HID
  applique la même conversion PRF que la plateforme, faute de quoi le même sel
  dériverait deux secrets différents.

## Le détail, si quelque chose casse

### `astra-signer init`

Génère `CA-PQ` (ML-DSA-87) et `CA-TLS`, les scelle sous un key-slot ouvert par
la clé branchée, écrit le coffre et le relais.

Le coffre est à `~/.helios/astra/authority-vault.json`, et sous Windows à
`%APPDATA%\astra\authority-vault.json`. **Sauvegardez-le.** Le perdre entièrement, c'est perdre le domaine ;
il est déjà chiffré, donc une copie hors ligne ne coûte rien.

Le relais, à côté, ne contient que du public. `astra-signer domain` le réécrit
depuis le coffre, sans clé de sécurité.

Quand la seconde clé est en main :

```sh
astra-signer enrol --label "YubiKey de récupération"
astra-signer verify        # à faire avec chacune des deux, séparément
```

`enrol` demande d'abord la clé déjà enregistrée, puis la nouvelle : deux objets,
branchés un à la fois. Une troisième ou une quatrième plus tard, c'est la même
commande — rien ne distingue la seconde de la cinquième.

L'ADR ne tient le bootstrap pour fini qu'« après enregistrement **et essai** des
deux clés ». `verify` est cet essai : il ouvre les ancres, pas seulement le
slot.

### Ce que `deploy.sh` fait à l'étape 7

1. détecte `docker compose` ou `podman compose` sur la gateway ;
2. lit le relais — domaine, RP ID, ancre ;
3. `heliosd show-identity` : nom de serveur et clé WireGuard, lus dans la leaf
   PQ servie plutôt que retapés ;
4. envoie les sources par `git archive HEAD` et construit l'image **sur la
   gateway** — ce qui part est donc ce qui est commité, jamais l'arbre de
   travail. Y compris le trousseau éditeur *public*, sans lequel `aether/build.rs`
   refuse la compilation `--release` de l'image. La construction tourne dans
   une unité systemd transitoire : une coupure SSH n'annule pas BuildKit, et le
   script se reconnecte pour lire son résultat et son journal ;
5. si le domaine n'est pas amorcé : `astra bootstrap`, capture de la clé de
   service et de la tête d'audit, écriture du `.env` distant, puis
   `heliosd init-trust-domain` et `systemctl restart heliosd` ;
6. `compose up -d`.

Le contexte `~/astra-build` est jetable et remplacé à chaque déploiement. Le
témoin durable passé à `--expected-audit-head` vit donc hors de ce contexte,
dans `/var/lib/helios/astra-compose.env`. Sur une reprise, `deploy.sh` relit la
tête du volume, la compare au témoin opérateur `~/.helios/astra/audit-head`, et
refuse un écart au lieu d'adopter silencieusement une histoire restaurée.

Après une panne limitée à cette étape, la reprise ne relivre ni les binaires ni
la configuration de la gateway :

```bash
./scripts/deploy.sh --astra
```

L'URL d'autorité vaut `https://<rp_id>` par défaut ; `ASTRA_AUTHORITY_URL` la
remplace. Elle sert à la récupération et au statut authentifié quand WireGuard
ne peut plus être monté, ainsi qu'aux opérations opérateur hors tunnel, pas au
renouvellement ordinaire. Le veth utilise deux adresses IP statiques locales à
la gateway, absentes du DNS et des profils Orion. Sa moitié Astra → Helios est
livrée ; le client Helios vers l'API Astra opposée reste le lot suivant.

### Pourquoi la construction emprunte le réseau de l'hôte

Le pare-feu Helios tient une chaîne `forward` en `drop` par défaut, et n'y ouvre
que le LAN et le tunnel. Le pont Docker n'y figure pas — les paquets d'un
conteneur sont donc jetés. Comme le premier d'entre eux est une requête DNS, la
panne se lit `Temporary failure resolving 'deb.debian.org'`, qui accuse le
réseau du conteneur alors que c'est la politique de la gateway.

L'ouvrir serait le mauvais geste. Astra n'a besoin d'aucune sortie Internet en
fonctionnement : il écoute sur la boucle locale et parlera à `heliosd` par un
veth privé. Un pont qui traverse le `forward` laisserait en revanche un
conteneur sortir en clair pendant que le kill-switch est engagé.

Seule la **construction** a besoin d'apt et de crates.io, d'où `network: host`
sur le seul bloc `build`. Ce trafic est alors émis localement : il passe par
`output`, que `allow_gateway_egress` régit déjà, et ne touche jamais `forward`.
Le conteneur qui tourne garde son réseau isolé.

Le bridge privé porte le nom stable `astra0`. Le ruleset atomique Helios
n'ouvre que `10.88.7.2 → 10.88.7.1:8444` pour l'API Helios et réserve le sens
opposé `10.88.7.1 → 10.88.7.2:8445` pour l'API Astra. Interface, source,
destination et port sont tous comparés ; aucune règle `forward` n'est ajoutée.
Ces coordonnées ne sont donc pas des paramètres libres de déploiement.

Le `pull` de l'image de base, lui, n'a jamais été concerné : il est émis par le
démon Docker sur l'hôte.

### Pourquoi l'étape 7 ne lit jamais le volume par `compose run`

L'adresse du conteneur Astra sur le veth privé est **épinglée** :
`ipv4_address: 10.88.7.2`. C'est délibéré — `heliosd` écoute sur l'autre bout
et n'accepte qu'une identité épinglée, donc les deux extrémités sont nommées
une fois pour toutes plutôt que découvertes.

La conséquence n'est pas évidente : `docker compose run` crée un **second**
conteneur du service, attaché aux mêmes réseaux, qui redemande donc la même
adresse. Elle est déjà prise, et Docker répond :

```text
failed to set up container networking: Address already in use
```

Autrement dit `compose run` échoue précisément quand Astra est déployé et
fonctionne — le seul cas où son registre existe vraiment. Un conteneur
**arrêté** retient sa réservation de la même façon, jusqu'à sa suppression.

L'étape 7 choisit donc son accès selon l'état du service :

| État du conteneur | Comment le volume est lu |
| --- | --- |
| en marche | `compose exec -T`, qui n'alloue aucune adresse |
| présent, arrêté | un conteneur jetable `--network none` monté sur le volume |
| absent | `compose run --rm --no-deps`, sans concurrent possible |

Le troisième cas est le seul où `run` est sûr. Les trois écritures de l'étape —
sonde, `bootstrap`, `init-channel` — passent par le même accès.

Si la sonde ne répond malgré tout rien, l'étape **s'arrête**. Elle ne suppose
ni « registre illisible » — cela accuserait le registre d'une panne que
personne n'a observée — ni « volume vierge », qui enchaînerait sur un amorçage
par-dessus une autorité existante. C'est la seule erreur irrattrapable de cette
étape.

### À la main

Chaque commande imprime la suivante. `astra bootstrap` imprime la ligne
`heliosd init-trust-domain` complète, et `heliosd init-trust-domain` dit ce qui
manque encore.

## Sauvegardes

Trois objets, trois endroits, et aucun ne remplace un autre :

| Quoi | Où | Perdre le seul exemplaire |
|---|---|---|
| Coffre d'autorité | poste opérateur | le domaine est perdu |
| Volume `astra-state` | gateway | registre et chaîne d'audit perdus |
| Clés de sécurité | vos poches | il en reste une autre — c'est le but |

Le coffre est chiffré : une copie hors ligne ne l'expose pas. Le volume Astra
contient la clé de service privée : traitez-le comme un secret.

La **tête de chaîne d'audit** est ce qui distingue une restauration légitime
d'un fork, et `astra run --expected-audit-head` est ce qui refuse le second.
`deploy.sh` la conserve dans `~/.helios/astra/audit-head`.

## Limite connue : retirer une clé ne rattrape pas les sauvegardes

`astra-signer remove` rescelle le corps du coffre sous la table de slots qu'il
laisse : le slot retiré, recollé depuis une sauvegarde, n'ouvre plus le fichier
courant. Mais une sauvegarde **antérieure** au retrait reste ouvrable par la clé
retirée, définitivement — c'est la situation de LUKS avec une phrase supprimée
depuis.

La réponse à un credential réellement compromis n'est donc pas un retrait de
slot, c'est une rotation de `CA-PQ`.

## Essais sur cible

Voir [testing/TESTING.md](testing/TESTING.md), sections « coffre d'autorité
Astra » et « domaine de confiance ». Rien de ce qui touche la clé de sécurité ne
s'exerce en WSL2 : aucun passthrough USB.
