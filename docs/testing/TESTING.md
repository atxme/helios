# Stratégie de test et de sécurité

La commande de référence est :

```sh
bash scripts/regression.sh
```

Elle doit être verte avant fusion ou livraison. Elle utilise les lockfiles,
interdit les avertissements Clippy et couvre les features matérielles au niveau
compilation/tests sans exécuter d’effet réel.

## Matrice automatisée

| Couche | Contrôles |
|---|---|
| Rust | `fmt`, Clippy `--all-targets --all-features`, tests workspace `--all-features`, doc-tests |
| Dépendances Rust | `cargo audit` : vulnérabilités bloquantes, avis informatifs suivis |
| Helios/Orion web | `npm ci`, `npm audit --audit-level=moderate`, Vitest, TypeScript et build Vite |
| Signatures | hybride AND, anti-downgrade, époque signée, domaines, JSON strict, Ed25519 faible/non canonique |
| TPM | anti-rejeu, PCR facultatif, rejet v1, ordre authentification → compteur → PCR |
| API | routeur complet, absence de secrets, JSON obligatoire pour les mutations, absence de CORS permissif |
| Tauri | commandes IPC, CSP, prototypes figés et capability minimale |
| Éditeur | permissions 0700/0600, auto-vérification, clés cohérentes et refus d’écrasement |
| Réseau | états, expiration de handshake, règles fail-closed et transaction préparée avant application |
| Provisioning PQ | tour ML-KEM complet via l’endpoint, PSK posé avant d’être annoncé, refus fail-closed si la pose échoue, annulation en mémoire et restauration du PSK précédent, adaptateur client jamais démonté |
| Mise à jour applicative | manifeste `helios-binary-release-v1` : signature hybride, altération du binaire, anti-rollback de `release_sequence`, staging borné et restauration du lien `current` (ADR-003) |
| Autorisation | routes de mutation réservées aux pairs `admin`, résolution par VIP source en `/32`, refus d'un pair ordinaire, en-têtes de proxy ignorés (ADR-003) |
| Admission | VIP dérivée de la clé publique, adresse de la gateway réservée, doublons de nom et de clé refusés, PSK des autres pairs préservés, persistance sans clé privée ni PSK (ADR-004) |
| Bundle d'installation | manifeste `helios-bundle-v1` : signature hybride, fichier altéré, manquant **et surnuméraire**, chemin hors racine, lien symbolique, destination inconnue, canal, anti-rollback, configuration préservée (ADR-004) |

`cargo-audit` est un prérequis local :

```sh
cargo install cargo-audit --locked
```

La CI l’installe explicitement. Les vulnérabilités RustSec font échouer la
campagne. Les avis informatifs `unmaintained`/`unsound` transitifs sont affichés
et suivis dans [SECURITY.md](../security/SECURITY.md), car `--deny warnings` rendrait la CI
inexécutable tant que Tauri Linux dépend de GTK3. Les audits ne détectent pas une
erreur de conception ; les tests d’invariants restent obligatoires.

## Invariants de sécurité verrouillés

1. Seul `TunnelState::Up` autorise le trafic gateway.
2. Le kill-switch précède tout réseau et reste engagé à l’arrêt.
3. Un mode réel sans backend noyau opérationnel échoue au démarrage.
4. Le ruleset Netlink est atomique ; une traduction incomplète n’est pas envoyée.
5. Orion ne démonte son adaptateur qu’après déconnexion explicite.
6. Un backend Orion réel indisponible ne retombe pas sur le dry-run.
7. `GET /api/network` ne sérialise jamais clé privée ni PSK.
8. Une mutation HTTP sans JSON est refusée et aucun CORS wildcard n’est publié.
9. Ed25519 et ML-DSA-65 sont toutes deux obligatoires ; `key_epoch` est signé.
10. Une release ne compile pas avec le trousseau éditeur de développement, même
   si son chemin est fourni explicitement.
11. Le billet TPM v1 ne bénéficie d’aucune période de compatibilité.
12. Une route de mutation exige un pair `admin`, identifié par l’adresse source
   du socket ; aucun en-tête de proxy ne participe à la décision.
13. Une `release_sequence` inférieure ou égale à la dernière confirmée est
   refusée, y compris avec des signatures valides.
14. Un binaire installé qui n’atteint pas son point de disponibilité rend la
   main à la version précédente.

Lorsqu’un bug de sécurité est corrigé, ajouter d’abord un test qui échoue avec
l’ancien comportement et le garder comme test de non-régression.

## Tests matériels obligatoires

Les tests automatisés ne peuvent pas promettre la fiabilité du matériel absent.
La gateway de laboratoire ne se compile plus sur place : elle reçoit un bundle,
comme une gateway de production (ADR-004).

Sur le poste de build :

```sh
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo xtask bundle
cargo run -p helios-publisher -- bundle --dir target/bundle/<nom> --channel testing …
cargo xtask pack --dir target/bundle/<nom>
```

Sur la gateway de laboratoire :

```sh
sudo ./scripts/setup-target.sh
sha256sum helios-<version>-<target>.tar.gz    # comparer à l'empreinte publiée
sudo ./helios-installer bootstrap --archive helios-<version>-<target>.tar.gz
```

Valider avec accès console :

- démarrage fail-closed avant création de l’interface ;
- handshake réel, passage `connecting` → `up`, puis expiration ;
- absence de trafic LAN dans tous les états sauf `up` ;
- erreur Netlink laissant intacte la politique précédente ;
- API inaccessible depuis le WAN et accessible via `helios0` ;
- Orion : adaptateur/routes maintenus sur panne UDP, retrait sur déconnexion ;
- installateur Orion Windows : `wireguard.dll` présente et signée par son
  éditeur dans un bundle produit après `cargo xtask orion-deps`, manifeste
  `requireAdministrator`, et horodatage RFC 3161 valide sur l'exécutable comme
  sur l'installateur ;
- association Orion : double-clic sur `.orionprofile` au premier lancement puis
  avec l'application déjà ouverte, une seule instance et reprise de la clé
  privée locale de même nom ;
- paquet Orion Debian : `getcap /usr/bin/orion` annonce
  `cap_net_admin=ep`, puis WebKitGTK démarre sans dépendre de
  `LD_LIBRARY_PATH` ;
- billet de rescellement : signé valide, rejoué, altéré et PCR optionnel — le
  scellement lui-même est désormais couvert par la catégorie `tpm` de la
  campagne, qui l'exerce sur `/dev/tpmrm0` ;
- provisioning PQ : un client Orion réel obtient son PSK dans le tunnel, le
  handshake suivant (≤ 2 min) réussit avec `PresharedKey` posé des deux côtés,
  et `wg show` confirme le slot renseigné sur la gateway comme sur le client ;
- provisioning PQ, chemin dégradé : gateway dont `sync_peers` échoue — le client
  doit rester en tunnel classique opérationnel, sans PSK orphelin ;
- mise à jour applicative ([ADR-003](../adr/ADR-003-MISES-A-JOUR-APPLICATIVES.md)) :
  transfert du manifeste et du binaire par fragments JSON, refus d'une signature
  altérée, refus d'une `release_sequence` inférieure ou égale à la dernière
  confirmée, activation, redémarrage du daemon et reconnexion de l'API ;
- mise à jour applicative, rollback : un binaire qui n'atteint pas son point de
  disponibilité dans le délai imparti doit rendre la main à la version
  précédente, service redémarré et lien `current` restauré ;
- autorisation : un pair `admin = false` se voit refuser toute route de
  mutation, et l'adresse source du socket seule fait foi — jamais un en-tête de
  proxy ;
- identité de la gateway ([ADR-004](../adr/ADR-004-CHAINE-DE-LIVRAISON.md) §3) :
  `heliosd init-identity` scelle réellement dans le TPM, refuse d'écraser un
  coffre existant sans `--rotate`, n'écrit la clé privée nulle part en clair, et
  la gateway redémarrée retrouve la même identité — seul le scellement effectif
  distingue ce chemin d'un succès apparent, et il n'est pas observable en WSL2 ;
- séquestre, circuit complet : `helios-ctl escrow keygen` sur le poste
  opérateur, `escrow_public_key` déclarée, séquestre écrit par la gateway au
  scellement, `helios-ctl escrow open` hors ligne, dépôt du fichier de
  récupération, redémarrage — l'identité doit être restaurée, rescellée, et le
  fichier de récupération effacé ;
- admission : la VIP dérivée par `heliosd peer add` est bien celle que le client
  reçoit à l'enrôlement, et l'ajout d'un pair n'efface ni la clé scellée ni les
  PSK des pairs déjà connectés — vérifier par `wg show` que leurs slots restent
  renseignés après l'opération ;
- bundle d'installation ([ADR-004](../adr/ADR-004-CHAINE-DE-LIVRAISON.md) §7 bis)
  sur une machine réelle : `bootstrap` sur une gateway vierge, unités
  effectivement rechargées par systemd, service démarrable, puis `bootstrap`
  d'une séquence supérieure sur une gateway **déjà configurée** — la
  configuration, l'identité scellée et les pairs admis doivent survivre. La
  campagne automatisée couvre la vérification et les refus, pas l'interaction
  avec systemd ni la persistance à travers un redémarrage.

Ces essais modifient le pare-feu, les routes, le TPM et le binaire installé : ne
jamais les lancer contre une appliance de production.

L'ADR-003 retire RAUC du chemin de mise à jour Helios : la mise à jour ne
remplace ni rootfs, ni kernel, ni bootloader, ne redémarre pas la machine, et
laisse donc les PCR 0/4/7 inchangés — aucun billet de rescellement n'est requis.
Administrer l'OS resterait une fonctionnalité distincte, à valider séparément.

## Banc de développement

`scripts/lab.sh` monte un environnement complet — gateway `--dev` isolée, client
admis par l'API, profils émis, campagne jouée — puis le démonte. `--keep` laisse
le daemon vivant pour l'exploration manuelle.

Il emprunte les **mêmes outils qu'un opérateur** (`helios-ctl peer add`,
`helios-ctl profile emit`) plutôt qu'un chemin de test parallèle : une régression
de l'outillage d'exploitation y tombe immédiatement. Il contrôle aussi la forme
des deux profils émis — l'invitation ne doit porter aucun secret, le profil
assisté doit être importable tel quel.

Il ne fait **pas** partie de `regression.sh` : la régression vérifie des
invariants, elle ne lance pas d'environnements. Le banc est un outil de
développement et un point d'entrée pour la recette manuelle d'Orion — le profil
`lab-poste.json` s'importe directement dans le client
([MANUAL-TESTING.md](MANUAL-TESTING.md)).

Ce qu'il ne prouve pas : le plan de données. Le tunnel reste simulé, comme dans
toute exécution `--dev`.

## Campagne d'installation par bundle signé

`scripts/campaign.sh` joue `scripts/bundle_campaign.py` après le provisioning et
la mise à jour applicative. Elle assemble un bundle, le signe avec l'époque
éphémère de la campagne, puis l'installe dans un faux système jetable.

Ce qu'elle prouve et que les tests unitaires ne prouvent pas : le chemin passe
par le trousseau éditeur **réellement compilé** dans `helios-installer`, pas par
un trousseau injecté. Une régression du build — ancre absente, époque
incohérente, encodage canonique modifié — se voit là.

Neuf scénarios : signature valide, binaire substitué après signature, unité
systemd ajoutée après signature, époque éditeur inconnue, canal confronté à
celui de la gateway, installation complète avec bascule du lien `current`,
anti-rollback semé, rejeu de séquence refusé, configuration existante préservée.

Ce qu'elle ne couvre pas : l'interaction réelle avec systemd, la persistance à
travers un redémarrage, et le premier `bootstrap` sur une machine vierge. Ces
trois points appartiennent à la recette matérielle.

## Campagne de provisioning post-quantique

`helios-ctl campaign` joue les mêmes scénarios en dry-run et sur la cible. Il
agit en **vrai client** : il emprunte `orion_core::provision`, le code
qu'embarque Orion. Une campagne qui tombe accuse donc le daemon *ou* le client.

Trois catégories, selon ce qu'elles exigent de l'environnement :

| Catégorie | Exige | Ce qu'elle établit |
| --- | --- | --- |
| `client` | rien | validation côté client : gateway usurpée, ciphertext malformé, version inconnue |
| `protocole` | un daemon joignable | tour ML-KEM complet, PSK frais par session, VIP stable, refus d’un pair non admis, absence de secret dans l’API |
| `plan-de-donnees` | `wg` et un noyau réel | le PSK est **réellement** dans le slot WireGuard, et le handshake a survécu à sa pose |

### Dry-run

```sh
bash scripts/campaign.sh            # daemon isolé, campagne, démontage
bash scripts/campaign.sh --repeat 20  # endurance
```

Le script monte son propre `heliosd --dev` sur une configuration temporaire :
il ne touche jamais `/var/lib/helios`. Il est joué par `scripts/regression.sh`.

### Cible

Le dry-run ne prouve rien du plan de données : `DryRunBackend` accepte un PSK
sans qu'aucun paquet ne soit chiffré. Seule la catégorie `plan-de-donnees`
tranche, et elle exige la cible.

Déclarer d’abord le pair de campagne sur la gateway (l’admission reste hors
bande — la campagne ne s’auto-admet jamais) :

```sh
helios-ctl campaign --generate-keys     # imprime le bloc [[peers]] à coller
```

Puis, **depuis le client**, tunnel classique monté :

```sh
helios-ctl --url http://100.64.0.1:8080 campaign \
  --client-key <privée du client> --gateway-key <publique de la gateway>
```

Enfin, **depuis la gateway**, la catégorie que le dry-run ne peut pas jouer :

```sh
helios-ctl campaign --only plan-de-donnees --wg-iface helios0 \
  --client-key <privée du client> --gateway-key <publique de la gateway>
```

Attendre au moins un handshake (≤ 2 min) entre le provisioning et cette
dernière commande : c’est précisément l’intervalle où un PSK posé d’un seul
côté se manifesterait, et le scénario `handshake vivant avec PSK` est là pour
l’attraper.

## Campagne matérielle automatisée

`scripts/target_campaign.py` joue la recette matérielle ci-dessus depuis la
machine de dev, sur une cible Linux accessible par SSH. Il n'a aucune
dépendance hors bibliothèque standard Python.

Le partage des rôles est explicite : les **tests unitaires restent en Rust** —
le script se contente d'exécuter `cargo test --workspace --all-features` sur la
cible, ce que WSL2 ne sait pas faire pour les features noyau/TPM — tandis que
l'**enchaînement d'états** de la campagne (daemon monté, handshake attendu,
kill-switch engagé) est orchestré en Python.

Provisionnement ponctuel de la cible, en deux commandes :

```sh
ssh -t <cible> 'cd ~/helios && bash scripts/setup-dev.sh --target'
python3 scripts/target_campaign.py --bootstrap
```

`--bootstrap` résout l'utilisateur et le chemin absolu du dépôt sur la cible,
compose la règle sudoers, **la fait valider par `visudo` avant de l'installer**
— un fichier invalide déposé dans `/etc/sudoers.d` casserait sudo pour toute la
machine — puis l'installe et ajoute l'utilisateur au groupe `tss` (accès
`/dev/tpmrm0`). Un seul mot de passe est demandé, et la vérification finale se
fait sur une session neuve, seule façon de constater que la règle porte.

La règle est limitée à `modprobe wireguard`, `modprobe nf_tables`, `nft`, `ip`,
`wg` et `setcap` sur les seuls binaires d'essai (`heliosd` et `helios-ctl`,
qui lit le plan de données via `wg show`) : jamais un shell générique, ni
`apt-get`, ni root inconditionnel. `--aide-sudoers` l'imprime pour contrôle.

La catégorie `tunnel` fait de la machine de dev un **vrai client WireGuard**.
Elle exige donc une règle locale, à poser une fois depuis un terminal :

```sh
echo "$(id -un) ALL=(root) NOPASSWD: /usr/sbin/modprobe wireguard, $(command -v ip), $(command -v wg)" \
  | sudo tee /etc/sudoers.d/helios-client-tests && sudo chmod 0440 /etc/sudoers.d/helios-client-tests
```

Trois contraintes de forme, constatées sur Ubuntu 26.04 qui embarque **sudo-rs**
et non le sudo classique :

- aucun joker n'est accepté dans les arguments de commande — les invocations de
  `setcap` sont donc écrites littéralement, dans leurs deux variantes de
  syntaxe de capacités (`+eip` et `=ep`) ;
- la virgule qui sépare les capacités doit être échappée (`cap_net_admin\,`),
  sinon elle est lue comme le séparateur de la liste de commandes ;
- le chemin du binaire est absolu, et doit correspondre au mot près à celui que
  la campagne passe à `setcap` — d'où sa résolution par `pwd -P`.

Ces contraintes sont la raison d'être de `--bootstrap` : recopiée à la main, la
règle échoue silencieusement ou casse sudo.

Exécution :

```sh
python3 scripts/target_campaign.py --only preflight    # sans effet de bord
python3 scripts/target_campaign.py --only unite        # cargo fmt/clippy/test
python3 scripts/target_campaign.py                     # tout sauf le pare-feu réel
python3 scripts/target_campaign.py --pare-feu --json rapport.json
```

Les catégories sont `preflight`, `synchro`, `unite`, `build`, `campagne`,
`mise-a-jour`, `tpm`, `tunnel` et `pare-feu`. Pour rejouer la mise à jour depuis
la branche distante courante :

```sh
python3 scripts/target_campaign.py --only synchro --only mise-a-jour
```

### Ce que la cible a permis d'établir

Ces points ne sont pas démontrables en WSL2, et deux d'entre eux ont révélé des
défauts réels lors du premier passage :

- le ruleset Netlink est réellement posé, en `drop` sur les trois chaînes, et
  **survit à l'arrêt du daemon** ;
- le scellement TPM sur `/dev/tpmrm0` refuse un blob absent, altéré, ou dont la
  sélection PCR a été modifiée, et restitue le secret à l'identique ;
- un vrai tunnel WireGuard s'établit entre la machine de dev et la gateway, et
  le provisioning post-quantique s'y déroule de bout en bout ;
- la gateway pose le PSK sur son plan de données **avant** de l'annoncer.

Deux pièges de terrain méritent d'être connus, car leurs symptômes égarent :

- **MTU.** WireGuard prend 1420 par défaut, ce qui suppose un transport à 1500.
  L'`eth0` de WSL2 est à 1280 : le handshake et les petites requêtes passent,
  mais un ciphertext ML-KEM disparaît en silence. Depuis, les deux bouts
  dérivent leur MTU du lien qui les porte (`aether::mtu`) ; le scénario
  `daemon réel` vérifie que la gateway l'applique. Mesure de référence sur
  cible, transport à 1280 : **1220 passe, 1221 échoue**, soit 60 octets de
  surcoût en IPv4 — la valeur retenue (80) couvre aussi IPv6.
- **Témoin de disponibilité.** Hors dry-run, heliosd écrit dans `/run/helios`,
  répertoire fourni par systemd (`RuntimeDirectory=helios`). Lancé à la main
  avec les seules capacités réseau, il s'arrête sur `EPERM` *après* avoir monté
  l'interface. La campagne passe `HELIOS_READY_PATH`, prévu pour ce cas.

### Limite connue : le slot PSK côté client

La campagne vérifie le slot PSK de la gateway, pas celui du client. `helios-ctl`
emprunte le **protocole** d'Orion (`orion_core::provision`), pas son
**adaptateur** : seul ce dernier écrit le PSK dans l'interface cliente. Le
client monté par la campagne l'est par `wg set`, et rien ne l'y renseigne.

Ce qui débloquerait la vérification : un mode headless d'Orion, ou une
sous-commande `helios-ctl` qui applique le profil reçu au lieu de se limiter à
l'inspecter. En attendant, le scénario le déclare hors de portée plutôt que de
le compter comme réussi.

La feature doit donc avoir été commitée et poussée avant cette commande ; la
campagne refuse une révision cible dont `helios-publisher` ne connaît pas
`binary-release`. La catégorie exerce le refus d’un manifeste altéré, le
transfert JSON borné, le SHA-256 et l’autorisation d’activation sur un daemon
cible isolé. Un scénario que l'environnement ne permet pas de trancher est
rapporté « hors portée », jamais « réussi ».

### Survie de la session SSH

Le backend Netlink réel pose une table `inet helios` en politique `drop` sur la
chaîne `input`, et cette table **survit à l'arrêt du daemon** (invariant
fail-closed : `teardown()` ne supprime jamais la table). Sans précaution, la
campagne se coupe l'accès à sa propre cible. Deux protections cumulées :

1. toutes les commandes passent par une **connexion SSH multiplexée unique**,
   déjà `established` avant l'engagement du kill-switch, donc acceptée par la
   règle `ct state established,related` ;
2. la configuration générée renseigne `allow_ssh_from` avec le préfixe de
   gestion (`--prefixe-gestion`, défaut `192.168.1.0/24`), ce qui rouvre le
   port 22 même kill-switch engagé.

Le scénario `SSH de gestion préservé par allow_ssh_from` ouvre délibérément une
connexion **hors** multiplexage pour vérifier cette seconde protection plutôt
que de la supposer. Les scénarios qui touchent au pare-feu réel exigent malgré
tout `--pare-feu` explicite. En cas de perte d'accès, depuis la console :

```sh
sudo nft delete table inet helios
```

### Ce que cette campagne ne couvre pas

**La pose effective du PSK exige un second poste.** Le PSK n'entre dans le slot
WireGuard qu'au terme d'un provisioning mené *par un client, à travers le
tunnel*. Or le ruleset refuse le port d'administration depuis toute interface
autre que celle du tunnel, loopback compris — « en tête de chaîne, avant même
le loopback » (`ruleset.rs`). La gateway ne peut donc pas se provisionner
elle-même, et c'est l'invariant recherché, pas une gêne à contourner.

Le scénario est déclaré « hors portée » plutôt que mis en échec : un échec
laisserait croire à une régression du PSK alors que rien n'aurait été éprouvé.
Ce qui le débloquerait : un second hôte monté en client WireGuard, d'où jouer
la recette en deux machines décrite plus haut.

Ce que la campagne établit malgré tout sur le plan de données réel : interface
WireGuard adressée par le noyau, pair déclaré et visible dans `wg show`, table
nft posée en politique `drop`, et slot PSK vide avant provisioning — ce dernier
point évitant de confondre « aucun provisioning » et « PSK posé ».

Le **scellement** TPM est automatisé depuis la catégorie `tpm` : elle exerce
`/dev/tpmrm0` pour de bon (provisionnement, déscellement du même secret, refus
d'un blob absent, altéré, ou dont la sélection PCR a été réécrite).

Ces essais sont réversibles, contrairement à ce que ce document affirmait : le
backend réel n'utilise que `create_primary` transitoire, `create`, `load`,
`policy_pcr` et `unseal` — ni écriture NV, ni handle persistant, ni changement
de hiérarchie. Ils travaillent dans un répertoire temporaire, jamais
`/var/lib/helios`, et n'étendent aucun PCR : la liaison est éprouvée en
réécrivant la sélection inscrite dans le blob, ce à quoi le TPM répond
`TPM2_RC_POLICY_FAIL`.

Restent manuels : les **billets de rescellement** (rejeu, altération, PCR
optionnel), qui supposent un changement de PCR donc un redémarrage contrôlé.
Ils sont dans [MANUAL-TESTING.md](MANUAL-TESTING.md). Ce qui débloquerait leur
automatisation : une cible à console série pilotable. Le seul contrôle TPM automatisé est un *refus* — heliosd
compilé avec la feature s'arrête faute de blob scellé — précisément parce qu'un
refus n'écrit rien.

### Bugs trouvés par le premier passage sur cible

Trois défauts que le dry-run ne pouvait structurellement pas voir, tous
confirmés puis corrigés avec test de non-régression :

| Défaut | Effet |
| --- | --- |
| `Del` d'une table nft absente | `ENOENT`, transaction entière rejetée : aucun kill-switch au premier démarrage d'une machine |
| `iif "lo"` sur la chaîne `output` | ne matche jamais ; tout le trafic loopback sortant tombait sous `drop` |
| API liée avant la création de la VIP | `bind` en échec, erreur avalée : gateway opérationnelle mais définitivement sans API |

## Limites connues

- le backend réel dépend du noyau, des pilotes et des privilèges de chaque OS ;
- le flux PSK ML-KEM n’est pas encore installé atomiquement de bout en bout ;
- la récupération signée attend l’arbitrage du compteur monotone ;
- le chemin Tauri Linux ne valide pas Windows/WireGuard-NT ;
- une campagne verte réduit le risque de régression, elle ne constitue ni audit
  externe ni preuve formelle.

La recette interactive est dans [MANUAL-TESTING.md](MANUAL-TESTING.md).
