# F15 — Bundle gateway reproductible

Statut : **conception**, 22 novembre 2026. Décrit F15 de la
[feuille de route](../../ROADMAP.md) et lève la limite « Le bundle n'est pas
reproductible bit à bit » d'[ADR-004](../../adr/ADR-004-CHAINE-DE-LIVRAISON.md).

## 1. Intention

Le bundle gateway (`heliosd`, `helios-installer`, `helios`, l'IHM embarquée,
les unités systemd, l'exemple de `network.toml`) est construit par
`cargo xtask bundle` (`tools/xtask/src/main.rs`), sur le poste de l'opérateur
via `scripts/deploy.sh` ou dans le job `bundle` de `.github/workflows/release.yml`.
Il est ensuite signé hors ligne par `helios-publisher bundle`, dont le manifeste
(`aether::sig::BundlePayload`) liste chaque fichier avec son chemin, sa taille,
son mode et son SHA-256, et nomme le commit (`git_commit`).

Deux builds du même commit donnent aujourd'hui des binaires différents :
chemins absolus de la machine dans les messages de panique, toolchain différente
(1.95.0 dans la CI de release, 1.99 sur le poste), gcc et en-têtes de la machine
pour le C d'`aws-lc-sys` et les bindings système, dates de modification de
`web/dist` intégrées par `rust-embed`. La signature prouve donc qui a publié le
bundle, pas qu'il vient du code source : personne ne peut le reconstruire pour
le confronter.

F15 rend cette confrontation possible et routinière. Un tiers, ou l'opérateur
depuis une autre machine, reconstruit le commit nommé par un manifeste signé et
obtient les mêmes empreintes. Un poste de build compromis qui glisserait un
binaire modifié se verrait à la première vérification.

L'utilisateur veut une solution qui tienne dans le temps : « on va pas le
recoder dans 3 mois ».

## 2. Décisions de l'utilisateur

- **Le bundle gateway d'abord**, Orion ensuite, dans un lot séparé
  (22 novembre 2026).
- **Approche 1 retenue : conteneur de build figé dans le dépôt** (§4),
  22 novembre 2026.
- **Monter en même temps les versions de travail** (22 novembre 2026) : les
  toolchains et les outils de CI passent aux dernières versions stables (§5.11).
  Les dépendances Rust et npm n'en font pas partie.

## 3. Objectifs, non-objectifs, anti-objectifs

**Objectifs**

- Deux builds du même commit, sur deux machines Linux x86_64 qui ont Docker,
  produisent des fichiers de bundle identiques octet pour octet : mêmes
  chemins, tailles, modes et SHA-256 que ceux du manifeste signé.
- Un seul chemin de build pour la CI de release, `scripts/deploy.sh` et la
  mise à jour applicative (`cargo xtask app`) : le conteneur.
- Une commande qui vérifie un bundle signé : elle reconstruit le commit du
  manifeste et compare fichier par fichier.
- Une archive (`cargo xtask pack`) qui ne dépend que du répertoire signé : le
  même répertoire donne la même archive, sur n'importe quel poste.
- Une vérification automatique en CI : deux builds indépendants comparés, sur
  chaque tag et une fois par semaine.

**Non-objectifs**

- Orion (MSI/NSIS, MSVC, Authenticode) : lot suivant.
- L'image Astra (`deploy/astra/Dockerfile`), construite sur la gateway.
- Une image Docker elle-même identique octet pour octet : ce qui compte est
  que les outils qu'elle contient soient les mêmes versions, épinglées par
  empreinte (§5.2).
- D'autres architectures que `x86_64-unknown-linux-gnu`.
- L'archive signée identique d'une publication à l'autre : la séquence de
  release (`date +%s` dans `deploy.sh`) et les signatures changent à chaque
  publication. La promesse porte sur les fichiers que le manifeste liste.

**Anti-objectifs**

- Bloquer un déploiement parce que Docker manque : la gateway déployée doit
  rester livrable. Un build natif reste possible sur demande explicite (§5.5).
- Deux chemins de build qui divergent sans qu'on le voie : le build natif est
  le même code que celui que lance le conteneur, pas une copie.
- Une reproductibilité qui casse en silence : la vérification CI échoue
  bruyamment, avec la liste des fichiers qui diffèrent.
- Faire entrer la clé privée éditeur dans le conteneur ou la CI : la signature
  reste hors ligne (ADR-004 §7).

## 4. Approches considérées

1. **Conteneur de build figé dans le dépôt (retenue).** Debian épinglée par
   digest, paquets apt pris sur `snapshot.debian.org` à une date fixe, rustc et
   Node épinglés par empreinte ; chemins remappés, `SOURCE_DATE_EPOCH`. Même
   conteneur pour tous les builds de livraison. Coût : Docker requis pour
   livrer, une image à construire la première fois, un fichier à mettre à jour
   pour monter de toolchain.
2. **Sans conteneur, toolchain épinglée.** Moins cher, mais une mise à jour de
   l'image du runner ou du poste (gcc, en-têtes `libtss2`, `libnftnl`) change
   les binaires sans prévenir. C'est la reproductibilité qui casse dans trois
   mois. Écartée.
3. **Nix ou Guix.** La garantie la plus forte, mais une chaîne entière nouvelle
   à apprendre et à maintenir pour un seul artefact. Écartée.

## 5. Conception

### 5.1 Ce qui est promis

Pour un commit propre `C`, un trousseau public éditeur `K` et la cible
`x86_64-unknown-linux-gnu`, `cargo xtask bundle` produit un répertoire dont la
liste `helios_update::bundle::collect` (chemin, taille, mode, SHA-256) ne dépend
que de `(C, K)`. Elle ne dépend pas de la machine, de l'utilisateur, du chemin
du dépôt, de l'heure, du fuseau, de la locale, de l'umask ni des caches Cargo
ou npm.

Le trousseau est une entrée du build : `aether/build.rs` compile ses clés
publiques dans le binaire. Il n'est pas secret (ADR-004), et la vérification
le demande explicitement (§5.7).

Un arbre modifié (`git_commit` suffixé de `-dirty`) n'est pas reproductible
par construction : la vérification le refuse.

### 5.2 L'environnement de build

Un fichier `tools/build-env/Dockerfile` (emplacement : mon choix) décrit
l'image. Tout ce qu'elle tire est épinglé :

- **Base :** `debian:trixie-slim` par digest `@sha256:…`.
- **Paquets système :** sources apt pointées sur
  `snapshot.debian.org/archive/debian/<horodatage>` (avec
  `check-valid-until=no`), pour que `apt-get install` donne les mêmes versions
  dans un an. La liste couvre ce que le build demande aujourd'hui : gcc et
  `build-essential`, `pkg-config`, `libnftnl-dev`, `libmnl-dev`,
  `libtss2-dev`, `libudev-dev`, plus `git`, `ca-certificates`, `curl`, `xz-utils`
  (et ce que bindgen demande, s'il est encore utilisé, à vérifier).
- **Rust :** `rustup-init` téléchargé et vérifié par SHA-256, toolchain
  exacte installée en profil minimal. Version : **1.100.0** (stable du
  9 novembre 2026), la même que le MSRV et la CI (§5.11).
- **Node :** archive officielle `node-v26.13.1-linux-x64.tar.xz` (LTS
  « Lithium »), vérifiée par SHA-256. `npm` est celui qu'elle embarque.

Les versions et empreintes sont des `ARG` en tête du Dockerfile : monter de
toolchain, c'est changer ces lignes, rien d'autre.

L'image est étiquetée par l'empreinte de son Dockerfile
(`helios-build:<12 premiers hex du SHA-256>`). `cargo xtask` la construit
s'il ne la trouve pas, et la réutilise sinon. Changer le Dockerfile donne donc
une nouvelle étiquette, sans confusion possible avec l'ancienne image.

### 5.3 L'entrée du build : l'arbre du commit, pas le répertoire de travail

Le conteneur ne monte pas le répertoire de travail. `cargo xtask` exporte les
fichiers suivis par git dans un répertoire temporaire (pour un arbre propre,
l'équivalent de `git archive HEAD` ; pour un arbre modifié, les fichiers suivis
tels qu'ils sont sur le disque, et le marqueur `-dirty` reste). Ni
`node_modules`, ni `web/dist`, ni `target/`, ni un fichier non suivi n'entrent
dans le build.

Dans le conteneur, les chemins sont fixes :

| Rôle | Chemin |
| --- | --- |
| Sources | `/helios/src` |
| `CARGO_HOME` | `/helios/cargo` |
| Répertoire cible Cargo | `/helios/target` |
| Sortie du bundle | `/helios/out` |

`CARGO_HOME` et le répertoire cible sont des volumes Docker nommés, réutilisés
d'un build à l'autre pour ne pas tout recompiler. Le cache ne change pas le
résultat : un build à volumes neufs et un build à volumes réutilisés doivent
donner le même bundle, et la CI le vérifie (§5.8). Ces volumes n'entrent pas
dans le budget de 65 GiB de `scripts/cargo-budget.sh` (ils vivent dans
`/var/lib/docker`) : `scripts/clean-wsl-targets` les supprime aussi.

Le conteneur tourne sous l'UID et le GID de l'appelant, pour que la sortie
copiée dans `target/bundle/` lui appartienne.

### 5.4 Les normalisations

- **Chemins :** `RUSTFLAGS` porte `--remap-path-prefix=/helios/src=/helios`
  et `--remap-path-prefix=/helios/cargo=/cargo`. `trim-paths` n'est pas stable
  dans Cargo 1.99 ni 1.100 (vérifié le 22 novembre 2026 : « feature `trim-paths` is
  required ») ; à reconsidérer quand il le sera. Les chemins de la bibliothèque
  standard sont déjà `/rustc/<hash>`.
- **`SOURCE_DATE_EPOCH` :** la date du commit (`git log -1 --format=%ct`),
  exportée dans le conteneur pour tout outil qui la lit.
- **IHM embarquée :** la feature `deterministic-timestamps` de `rust-embed`
  (présente en 8.13.0) est activée dans `crates/helios-api` derrière
  `embed-ui`. `serve_embedded` ne lit aucune métadonnée de fichier : aucun
  changement de comportement côté gateway.
- **Environnement :** `TZ=UTC`, `LANG=C.UTF-8`, `umask 022` dans le conteneur.
- **Permissions :** déjà fixées par `copy_executable` et `copy_data` (0755,
  0644). Inchangé.
- **Build ID, ordre de liaison, unités de compilation :** déterministes avec
  rustc et ld à entrées égales. Si la comparaison révèle une autre source
  d'écart, elle se corrige dans le Dockerfile ou dans `RUSTFLAGS`, avec un
  test qui la fige.

### 5.5 Un seul chemin de build

`cargo xtask bundle` et `cargo xtask app` gardent leur interface. Par défaut,
ils lancent le build dans le conteneur :

1. vérifier le trousseau (`HELIOS_PUBLISHER_KEYRING_PATH`), comme aujourd'hui ;
2. construire ou retrouver l'image ;
3. exporter l'arbre (§5.3) ;
4. `docker run` avec le trousseau monté en lecture seule, qui exécute dans
   le conteneur `cargo xtask bundle --native …` (ou `app --native`) ;
5. copier la sortie dans `target/bundle/<nom>` (ou `target/<cible>/release/heliosd`
   pour `app`), à l'emplacement où `deploy.sh` et la CI l'attendent déjà.

`--native` est le build d'aujourd'hui, sur la machine hôte : c'est le même code,
appelé par le conteneur. Un opérateur sans Docker peut toujours livrer avec
`--native`, et le dit explicitement. `deploy.sh` accepte un drapeau
`--build-natif` qui le transmet. Sans Docker et sans ce drapeau, `xtask`
s'arrête avant de compiler, avec un message qui nomme les deux issues
(installer Docker, ou `--native`).

Le build natif n'a pas de garantie de reproductibilité. Le manifeste ne porte
pas cette distinction : seule la vérification (§5.7) dit si un bundle est
reproductible.

### 5.6 Une archive déterministe

`cargo xtask pack` passe à `tar` les options qui retirent tout ce qui dépend de
l'hôte : tri des noms, propriétaire et groupe numériques à 0, date des entrées
fixée, attributs `atime`/`ctime` retirés, format fixé. La compression se fait
sans nom ni horodatage dans l'en-tête gzip (`gzip -n`). La date des entrées est
`SOURCE_DATE_EPOCH` s'il est défini, 0 sinon ; elle n'a aucun rôle dans
l'installation.

Les fichiers extraits par `helios-installer` appartiennent alors à root (UID 0)
au lieu de l'UID de l'opérateur qui a lancé `pack`. À vérifier : l'installateur
ne dépend pas du propriétaire des fichiers extraits.

`tar` reste l'outil système (GNU tar sous Linux, seule plateforme de `pack`).

### 5.7 Vérifier un bundle

Nouvelle commande `cargo xtask verify` :

```text
cargo xtask verify --bundle <répertoire signé ou archive .tar.gz> --keyring <trousseau public>
```

1. Lire le manifeste et vérifier sa signature sous le trousseau donné
   (même vérification que `helios-installer`). Un manifeste non signé ou mal
   signé est refusé avant tout build.
2. Refuser un `git_commit` suffixé de `-dirty`, ou une cible autre que
   `x86_64-unknown-linux-gnu`.
3. Résoudre `git_commit` dans le dépôt local (le préfixe court de 16 hex) ;
   un commit absent est refusé, avec la commande `git fetch` à lancer.
4. Exporter l'arbre de ce commit et le construire dans le conteneur (§5.5),
   avec ce trousseau, dans un répertoire temporaire.
5. Comparer la liste reconstruite à `payload.files` : chemin, taille, mode,
   SHA-256. Afficher chaque différence (fichier manquant, en trop ou différent,
   avec les deux empreintes). Code de sortie 0 seulement si tout est identique.

`verify` ne touche ni à `target/bundle/` ni au répertoire de travail.

### 5.8 La CI

- **`release.yml`, job `bundle` :** il construit par `cargo xtask bundle`
  dans le conteneur au lieu de `dtolnay/rust-toolchain@1.95.0` et de l'apt du
  runner. `actions/setup-node` et l'installation des paquets système
  disparaissent du job.
- **Nouveau workflow `reproducible.yml`** : sur chaque tag `v*`,
  `workflow_dispatch` et une fois par semaine (`schedule`), deux builds
  indépendants du même commit avec le trousseau public de production, lu
  dans la variable de dépôt `HELIOS_PUBLISHER_KEYRING` comme dans
  `release.yml` (le trousseau de développement est refusé en release par
  `aether/build.rs`). Le second build part de volumes neufs, d'un chemin de
  checkout différent, d'un autre `TZ` et d'un autre umask côté hôte. Le job
  échoue si les deux listes `collect` diffèrent, et publie les deux listes en
  artefact.
- **`scripts/regression.sh` n'exécute pas** le double build : trop lourd pour
  WSL (mémoire « regression-wsl-ram »). Il garde les tests unitaires de
  `xtask` (§7).

### 5.9 Documentation

- ADR-004, « Limites connues » : la limite est levée pour le bundle gateway
  et reste pour Orion. Dire ce qui est promis (§5.1) et ce qui ne l'est pas
  (l'archive signée, le build `--native`).
- `docs/DEPLOIEMENT-ASTRA.md` ou `docs/MAINTENANCE.md` : section « Vérifier un
  bundle », avec la commande `verify`, et Docker comme prérequis de livraison.
- `docs/ROADMAP.md` : F15.
- Le Dockerfile documente comment monter de toolchain (changer les `ARG`).

### 5.10 Précisions

Ces points ont été tranchés à la relecture de la conception. Sauf mention
contraire, ce sont des choix de conception, pas des décisions de l'utilisateur.

- **Le marqueur `-dirty`.** Il est déjà posé par `scripts/deploy.sh` (qui
  passe `--git-commit "$COMMIT"` à `helios-publisher`) ; dans la CI de
  release, l'éditeur passe `--git-commit` à la main sur un arbre propre.
  Aucun binaire n'embarque le commit : seul le manifeste le porte. Un arbre
  modifié reste livrable par `deploy.sh`, avec l'avertissement actuel ; c'est
  `verify` qui le refuse. Pas de nouveau refus dans `helios-publisher`.
- **Le réseau pendant le build.** Le build en conteneur a accès au réseau.
  Cargo tourne en `--locked`, sur le `Cargo.lock` et ses sommes de contrôle ;
  `npm ci` s'appuie sur les empreintes d'intégrité de `package-lock.json`.
  Aucune dépendance Cargo ne vient d'un dépôt git (vérifié le 22 novembre 2026).
  Un crate retiré (*yanked*) reste téléchargeable tant que le verrou le nomme.
  Pas de *vendoring* : il doublerait la taille du dépôt pour un risque
  (crates.io qui supprime une version) que ce lot accepte.
- **Le xtask dans le conteneur.** Le xtask de l'hôte orchestre (image, export,
  `docker run`, copie de la sortie). Dans le conteneur, `cargo xtask bundle
  --native` recompile le crate xtask de l'arbre exporté, avec la toolchain
  épinglée. Les `RUSTFLAGS` de remappage s'appliquent aussi à cette compilation,
  sans effet sur le bundle.
- **Rust 1.100.0 pour les binaires livrés** comme pour le MSRV (§5.11). Il
  n'existe pas de `rust-toolchain.toml` à la racine : l'image est la seule
  autorité pour les builds de livraison, et la concordance des épingles est
  vérifiée (§5.11).
- **Moteur de conteneur.** Docker avec démon (*rootful*), utilisateur dans le
  groupe `docker` : c'est le cas du poste de l'opérateur (vérifié le
  22 novembre 2026) et du runner `ubuntu-24.04`. Docker sans démon root
  (*rootless*) et podman ne sont pas pris en charge dans ce lot. Le
  commentaire de `deploy.sh` qui dit l'utilisateur hors du groupe `docker` sur
  le poste est à corriger (il reste vrai pour la gateway).
- **Le propriétaire des fichiers extraits.** `helios-installer` extrait dans
  un répertoire temporaire puis installe sous root, sans dépendre du
  propriétaire des fichiers de l'archive. Le test qui le fige est obligatoire :
  `bootstrap` installe une archive produite par le nouveau `pack`. S'il
  échoue, la correction de l'installateur fait partie du lot.
- **Le trousseau.** `aether/build.rs` analyse le JSON et génère le code des
  clés : les espaces et fins de ligne du fichier n'influent pas sur le binaire.
  `verify` construit avec le trousseau donné et vérifie la signature du
  manifeste sous ce même trousseau ; un autre trousseau que celui de la
  publication donne des empreintes différentes, et `verify` le signale comme
  tel. La CI prend la valeur courante de la variable de dépôt.
- **La vérification hebdomadaire** compare deux builds de la branche par
  défaut entre eux : c'est une vérification de cohérence, pas une
  confrontation à un manifeste publié. Sur un tag, c'est le même contrôle sur
  le commit du tag.

### 5.11 Les versions de travail

Dernières versions stables au 22 novembre 2026, relevées par `rustup check` et
`nodejs.org/dist/index.json` :

| Outil | Avant | Après | Où |
| --- | --- | --- | --- |
| Rust (livraison) | 1.95.0 (release), 1.99 (poste) | **1.100.0** | `tools/build-env/Dockerfile` |
| MSRV | 1.95 | **1.100** | `Cargo.toml` (`rust-version`), `scripts/setup-dev.sh` (`RUST_MIN`) |
| Rust (CI) | `dtolnay/rust-toolchain@1.95.0` | **`@1.100.0`** | `regression.yml`, `release.yml` |
| Node | 24 | **26.13.1** (conteneur), **26** (CI) | Dockerfile, `actions/setup-node` |
| `engines` | `^22.22.2 \|\| ^24.15.0 \|\| >=26.0.0` | **`>=26.0.0`** | `web/package.json`, `apps/orion/package.json` |
| Image Astra | `rust:1.92-bookworm` | **`rust:1.100-trixie`** (ou la base de `tools/build-env`) | `deploy/astra/Dockerfile` |
| Actions GitHub | `checkout@v4`, `setup-node@v4`, `upload-artifact@v4` | dernière majeure de chacune | tous les workflows |

Restent hors de ce tableau : le nightly du fuzz (`dtolnay/rust-toolchain@nightly`),
qui suit déjà la dernière version ; la toolchain `+stable` préinstallée de la
station de signature Windows d'Orion (lot Orion) ; les dépendances Rust et npm
(mémoire « deps-held-back » : `rustables` 0.9 reste bloqué).

**Une seule vérité.** Un contrôle de `scripts/check.sh` échoue si la version
Rust du Dockerfile, le `rust-version` du workspace, `RUST_MIN` et les épingles
`dtolnay/rust-toolchain@<x.y.z>` des workflows ne concordent pas (au niveau
`x.y`), ou si la majeure Node de la CI diffère de celle du Dockerfile. Monter
de version devient : changer ces lignes, et le contrôle dit lesquelles on a
oubliées.

**Conséquences à absorber dans le lot :**

- Les nouveaux avertissements de `clippy -D warnings` sous 1.100 sont corrigés
  dans le code ; pas de `allow` global pour les faire taire.
- Le poste passe à 1.100 (`rustup update stable`) et à Node 26 (`nvm`) ;
  le cache Cargo sera reconstruit.
- La régression complète repasse verte sous 1.100.

## 6. Contraintes

- Rust : **1.100.0** partout (conteneur, `rust-version`, CI, `setup-dev.sh`).
- Node : **26.13.1** dans le conteneur, **26** dans la CI ; `engines` de
  `web/` et d'`apps/orion/` exige `>=26`.
- Trousseau : jamais de clé privée dans le conteneur ; le trousseau public est
  monté en lecture seule. Le refus du trousseau de développement en release
  (`aether/build.rs`) reste en vigueur.
- Aucune dépendance Rust nouvelle sans nécessité (le `tar` système suffit à
  `pack`).
- Compilation locale : `scripts/wsl-cargo` et `CARGO_BUILD_JOBS=2` hors
  conteneur ; dans le conteneur, `CARGO_BUILD_JOBS` est transmis depuis l'hôte.
- Les versions : fusion par `python3 scripts/version.py merge` (AGENTS.md).

## 7. Tests

- **`xtask`, unitaires :**
  - les arguments du build en conteneur portent les deux `--remap-path-prefix`,
    `SOURCE_DATE_EPOCH`, `TZ`, `LANG`, l'UID/GID, le trousseau en lecture seule ;
  - l'étiquette d'image change quand le Dockerfile change ;
  - l'export de l'arbre exclut un fichier non suivi, `node_modules` et
    `web/dist` ;
  - sans Docker et sans `--native`, l'erreur arrive avant toute compilation ;
  - `pack` : le même répertoire, empaqueté deux fois avec des dates de fichiers,
    un umask et un répertoire parent différents, donne la même empreinte ;
    les tests existants de `pack` restent verts ;
  - `verify` : refuse un manifeste non signé, un commit `-dirty`, un commit
    absent ; la comparaison signale un fichier manquant, en trop, de mode ou
    d'empreinte différents (la comparaison est une fonction pure testée sans
    Docker).
- **Bout en bout, local (WSL, Docker) :** deux `cargo xtask bundle` du même
  commit depuis deux chemins de checkout différents donnent la même liste
  `collect`. C'est la preuve d'acceptation du lot, consignée dans le rapport
  final.
- **CI :** `reproducible.yml` vert sur la branche avant la fusion
  (`workflow_dispatch`).
- **Installateur :** `helios-installer bootstrap` installe une archive produite
  par le nouveau `pack` (test existant d'extraction adapté si besoin).

## 8. Laissé au constructeur

- Le digest exact de `debian:trixie-slim`, l'horodatage du snapshot apt, la
  version exacte de Node 24 et les empreintes, relevés au moment du build.
- La liste exacte des paquets apt, établie par le premier build qui réussit.
- L'export de l'arbre (`git archive` ou `git ls-files` + copie), tant qu'il
  respecte §5.3.
- La forme des options GNU tar, tant qu'elles respectent §5.6.
- Le nom des volumes Docker et leur ajout à `scripts/clean-wsl-targets`.
- Si la première comparaison révèle une source d'écart non listée en §5.4 : la
  corriger au plus près de sa cause, et l'ajouter à cette liste.
