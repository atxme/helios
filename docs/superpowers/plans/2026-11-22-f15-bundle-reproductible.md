# F15 — Bundle gateway reproductible : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** deux builds du même commit produisent un bundle gateway identique octet pour octet, vérifiable par `cargo xtask verify`, avec des toolchains à jour (Rust 1.100, Node 26).

**Architecture:** un conteneur figé (`tools/build-env/Dockerfile`) devient le seul chemin de build de livraison ; le xtask de l'hôte exporte l'arbre suivi par git, lance `cargo xtask bundle --native` dans le conteneur aux chemins fixes, et récupère la sortie. `pack` devient déterministe, `verify` reconstruit le commit d'un manifeste signé et compare fichier par fichier, et deux workflows CI s'en servent.

**Tech Stack:** Rust 1.100 (xtask, helios-update, aether), Docker (rootful), GNU tar/gzip, Debian trixie + snapshot.debian.org, Node 26.13.1, GitHub Actions, Python 3 (`scripts/tests`).

**Spec:** `docs/superpowers/specs/2026-11-22-f15-bundle-reproductible-design.md`

## Global Constraints

- Rust **1.100.0** partout : Dockerfile, `rust-version = "1.100"` (`Cargo.toml`), `RUST_MIN="1.100"` (`scripts/setup-dev.sh`), `dtolnay/rust-toolchain@1.100.0` dans les workflows (le nightly du fuzz reste nightly).
- Node **26.13.1** dans le conteneur (`node-v26.13.1-linux-x64.tar.xz`, vérifié par SHA-256), **26** dans la CI ; `engines` de `web/package.json` et `apps/orion/package.json` : `">=26.0.0"`.
- Aucune mise à jour de dépendances Rust ou npm (`Cargo.lock`, `package-lock.json` : seules les modifications imposées par une feature activée).
- Chemins fixes dans le conteneur : sources `/helios/src`, `CARGO_HOME` `/helios/cargo`, cible `/helios/target`, sortie `/helios/out`, trousseau `/helios/keyring.json` (lecture seule).
- `RUSTFLAGS` du conteneur : `--remap-path-prefix=/helios/src=/helios --remap-path-prefix=/helios/cargo=/cargo`. `trim-paths` n'est pas stable (1.99 ni 1.100).
- Environnement du conteneur : `SOURCE_DATE_EPOCH` = `git log -1 --format=%ct`, `TZ=UTC`, `LANG=C.UTF-8`, umask 022, `CARGO_BUILD_JOBS` transmis depuis l'hôte, UID:GID de l'appelant.
- Étiquette d'image : `helios-build:<12 premiers hex du SHA-256 du Dockerfile>`.
- Volumes Docker nommés : `helios-build-cargo` (`/helios/cargo`), `helios-build-target` (`/helios/target`).
- Cargo en `--locked` pour tout build lancé par xtask.
- Cible unique `x86_64-unknown-linux-gnu`. Docker rootful seulement ; ni rootless ni podman.
- Jamais de clé privée dans le conteneur ni en CI ; le refus du trousseau de développement en release (`crates/aether/build.rs`) reste.
- Build local hors conteneur : `scripts/wsl-cargo`, `CARGO_BUILD_JOBS=2` (mémoires « worktree-target-dir-tmpfs », « regression-wsl-ram »). `scripts/regression.sh` n'exécute **pas** le double build.
- Messages d'erreur et sorties de xtask en anglais (convention actuelle de `tools/xtask`) ; documentation en français.

## Review Focus

1. **Volumes neufs et UID de l'appelant :** sur une machine qui n'a jamais construit, les volumes nommés sont créés vides ; un conteneur lancé sous l'UID 1000 doit pouvoir y écrire. Attendu : le premier build réussit. Test : Task 4, acceptation avec volumes supprimés au préalable.
2. **Sortie partielle d'un build interrompu :** un `target/bundle/<nom>` laissé par un build précédent ne doit jamais se mélanger à la nouvelle sortie. Test : Task 3, `copy_out_replaces_an_existing_destination`.
3. **Trousseau donné par un chemin relatif ou contenant des espaces :** `docker -v` exige un chemin absolu. Attendu : le chemin est rendu absolu, passé comme argument séparé. Test : Task 3, `run_args_mount_the_keyring_by_absolute_path`.
4. **`verify` reçoit une archive `.tar.gz` au lieu d'un répertoire :** attendu, extraction dans un répertoire temporaire puis même flux. Test : Task 5, `verify_accepts_an_archive_and_a_directory`.
5. **Docker installé mais démon arrêté ou utilisateur hors du groupe :** attendu, la même erreur que l'absence de Docker, avant toute compilation, qui nomme les deux issues. Test : Task 3, `docker_unavailable_is_reported_before_building`.

---

### Task 1: Versions de travail et contrôle de concordance

**Files:**
- Modify: `Cargo.toml` (`rust-version`), `scripts/setup-dev.sh` (`RUST_MIN`), `.github/workflows/regression.yml`, `.github/workflows/release.yml` (job `bundle` seulement : la station Windows garde `+stable`), `.github/workflows/fuzz.yml` (actions seulement), `web/package.json`, `apps/orion/package.json` (`engines`), `deploy/astra/Dockerfile` (`FROM rust:1.100-trixie`, et le `FROM` d'exécution aligné sur trixie s'il est bookworm)
- Create: `scripts/toolchain_pins.py`, `scripts/tests/test_toolchain_pins.py`
- Modify: `scripts/check.sh` (appel du contrôle, à côté de « Retired operator tools guard »)
- Modify: tout fichier Rust que `clippy -D warnings` sous 1.100 signale

**Interfaces:**
- Produces: `scripts/toolchain_pins.py` avec `def collect_pins(root: Path) -> dict[str, list[tuple[str, str]]]` (outil → liste de `(fichier, version)`) et `def mismatches(pins) -> list[str]` (messages lisibles, vide si tout concorde) ; exécutable (`python3 scripts/toolchain_pins.py` → code 1 et la liste si désaccord). Lit : l'`ARG RUST_VERSION` et l'`ARG NODE_VERSION` de `tools/build-env/Dockerfile` **s'il existe** (Task 3 le crée), `rust-version` de `Cargo.toml`, `RUST_MIN` de `scripts/setup-dev.sh`, chaque `dtolnay/rust-toolchain@<x.y.z>` des workflows (pas `@nightly`), chaque `node-version:` des workflows. Comparaison Rust au niveau `x.y`, Node au niveau majeur.

- [ ] **Step 1: Tests (rouges)** dans `scripts/tests/test_toolchain_pins.py`, sur des arbres temporaires :
  - `test_matching_pins_report_nothing` : Dockerfile `ARG RUST_VERSION=1.100.0` / `ARG NODE_VERSION=26.13.1`, `rust-version = "1.100"`, `RUST_MIN="1.100"`, workflow `@1.100.0` et `node-version: 26` → `mismatches(...) == []` ;
  - `test_a_stale_workflow_pin_is_named` : un workflow en `@1.95.0` → un message qui contient le nom du fichier et `1.95` ;
  - `test_nightly_is_ignored` : `@nightly` n'est pas une épingle ;
  - `test_node_major_mismatch_is_named` : `node-version: 24` face à `26.13.1` → message ;
  - `test_missing_dockerfile_is_not_an_error` : sans Dockerfile, les autres épingles sont comparées entre elles ;
  - `test_repository_pins_agree` : sur la racine réelle du dépôt → `[]` (vert après Step 3).
- [ ] **Step 2:** `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_toolchain_pins.py'` → FAIL.
- [ ] **Step 3:** Implémenter `scripts/toolchain_pins.py` ; monter les versions selon le tableau §5.11 de la spec. Actions GitHub : dernière majeure publiée de `actions/checkout`, `actions/setup-node`, `actions/upload-artifact` (relever la version sur la page de releases de chaque action ; si elle ne peut pas être vérifiée, garder `v4` et le noter dans le rapport). Ajouter l'appel dans `scripts/check.sh`, et au job « Format et tests des scripts » de `regression.yml` (déjà couvert par `unittest discover -s scripts/tests`).
- [ ] **Step 4:** Toolchain locale : `rustc -V` doit dire 1.100.0 (déjà fait sur le poste). Corriger les avertissements : `CARGO_BUILD_JOBS=2 scripts/wsl-cargo clippy --workspace --all-targets --all-features -- -D warnings` → vert, sans `allow` global ajouté. Puis `CARGO_BUILD_JOBS=2 scripts/wsl-cargo test --workspace --all-features` et `scripts/wsl-cargo test -p heliosd` → verts ; `npm ci && npm test && npm run build` dans `web/` et `apps/orion/` sous Node 26 → verts.
- [ ] **Step 5:** les tests Python → PASS.
- [ ] **Step 6: Commit** `build!: move the working toolchains to Rust 1.100 and Node 26` (le `!` : le MSRV monte).

### Task 2: Entrées déterministes — IHM embarquée, `--locked`, archive

**Files:**
- Modify: `crates/helios-api/Cargo.toml` (`embed-ui = ["dep:rust-embed", "rust-embed/deterministic-timestamps"]`)
- Modify: `tools/xtask/src/main.rs` (`gateway_build_args`, build de `helios-installer`/`helios`, `pack`)
- Create: `tools/xtask/src/archive.rs` ; Modify: `tools/xtask/src/lib.rs` (`pub mod archive;`)
- Test: `tools/xtask/src/archive.rs` (tests), `tools/helios-installer/src/main.rs` (test d'extraction)

**Interfaces:**
- Produces: `pub fn xtask::archive::tar_args(archive: &Path, name: &str, mtime: u64) -> Vec<OsString>` : les arguments GNU tar d'une archive déterministe (sans la compression) ; `pub fn xtask::archive::create(parent: &Path, name: &str, archive: &Path, mtime: u64) -> anyhow::Result<()>` : `tar … | gzip -n` vers `archive`. `pub fn xtask::archive::entry_mtime() -> u64` : `SOURCE_DATE_EPOCH` s'il est défini et numérique, 0 sinon. Les arguments de build Cargo de xtask portent `--locked`.

- [ ] **Step 1: Tests (rouges)** :
  - `archive::tests::tar_args_fix_order_owner_and_dates` : contient `--sort=name`, `--owner=0`, `--group=0`, `--numeric-owner`, `--mtime=@<mtime>`, `--format=gnu` (ou `posix` avec `--pax-option=delete=atime,delete=ctime`), et se termine par `--`, `name` ;
  - `archive::tests::same_directory_gives_the_same_archive` : un répertoire de bundle temporaire, empaqueté deux fois, avec entre les deux un `touch` d'une autre date sur chaque fichier et un répertoire parent copié ailleurs → mêmes SHA-256 d'archive ;
  - `archive::tests::entry_mtime_reads_source_date_epoch` : `"1700000000"` → 1700000000 ; absent ou non numérique → 0 (fonction pure `entry_mtime_from(Option<&str>) -> u64` testée, `entry_mtime` l'appelle) ;
  - `tests::gateway_build_args_are_locked` : `gateway_build_args(...)` contient `--locked` ;
  - les tests `pack_*` existants restent verts ;
  - `helios-installer` : `bootstrap_installs_an_archive_owned_by_root` (ou l'adaptation du test d'extraction existant, `tools/helios-installer/src/main.rs:~410`) : une archive créée par `xtask::archive::create` (ou par les mêmes options tar) est extraite par `extract` et son contenu lu — si l'installateur dépend du propriétaire, le corriger (spec §5.10).
- [ ] **Step 2:** `scripts/wsl-cargo test -p xtask` et `-p helios-installer` → FAIL.
- [ ] **Step 3:** Implémenter ; `pack` appelle `archive::create(&parent, &name, &archive, archive::entry_mtime())`. Vérifier que `cargo tree -p helios-api -e features --features embed-ui` montre `deterministic-timestamps`.
- [ ] **Step 4:** `scripts/wsl-cargo test -p xtask -p helios-installer -p helios-api --all-features` et clippy `-D warnings` → verts.
- [ ] **Step 5: Commit** `feat(xtask): deterministic bundle archive and locked, timestamp-free builds`

### Task 3: Le conteneur de build, seul chemin de livraison

**Files:**
- Create: `tools/build-env/Dockerfile`
- Create: `tools/xtask/src/container.rs` ; Modify: `tools/xtask/src/lib.rs` (`pub mod container;`)
- Modify: `tools/xtask/src/main.rs` (`Cmd::App`, `Cmd::Bundle` : drapeau `--native`; `bundle`, `app`)

**Interfaces:**
- Consumes: Task 1 (`ARG RUST_VERSION`, `ARG NODE_VERSION` lus par `toolchain_pins.py` : ces deux noms exactement).
- Produces (`xtask::container`) :
  - `pub const IMAGE_REPOSITORY: &str = "helios-build";`
  - `pub fn image_tag(dockerfile: &Path) -> anyhow::Result<String>` → `"helios-build:<12 hex>"`
  - `pub fn ensure_docker() -> anyhow::Result<()>` : `docker info` ; échec ou absence → erreur qui nomme « install Docker (rootful, user in the `docker` group) » et « or rebuild with `--native` » ;
  - `pub fn ensure_image(root: &Path) -> anyhow::Result<String>` : construit l'image si `docker image inspect <tag>` échoue, renvoie l'étiquette ;
  - `pub fn export_tree(root: &Path, dest: &Path) -> anyhow::Result<()>` : copie les fichiers de `git ls-files -z` (tels qu'ils sont sur le disque), en conservant le bit exécutable ; rien d'autre ;
  - `pub fn source_date_epoch(root: &Path) -> anyhow::Result<u64>` : `git log -1 --format=%ct` ;
  - `pub struct ContainerRun { pub image: String, pub source: PathBuf, pub keyring: PathBuf, pub out: PathBuf, pub uid: u32, pub gid: u32, pub source_date_epoch: u64, pub jobs: Option<String>, pub command: Vec<String> }`
  - `pub fn run_args(run: &ContainerRun) -> anyhow::Result<Vec<OsString>>` : `run --rm`, `--user uid:gid`, montages `source:/helios/src`, `keyring(absolu):/helios/keyring.json:ro`, `out:/helios/out`, volumes `helios-build-cargo:/helios/cargo`, `helios-build-target:/helios/target`, `-w /helios/src`, les `-e` de Global Constraints (`RUSTFLAGS`, `SOURCE_DATE_EPOCH`, `TZ`, `LANG`, `CARGO_HOME`, `CARGO_TARGET_DIR`, `HELIOS_PUBLISHER_KEYRING_PATH=/helios/keyring.json`, `CARGO_BUILD_JOBS` si défini), l'image, puis `command` ;
  - `pub fn copy_out(from: &Path, to: &Path) -> anyhow::Result<()>` : remplace `to` entièrement (supprime l'existant, puis copie), modes conservés ;
  - `pub fn build_in_container(root: &Path, command: Vec<String>) -> anyhow::Result<PathBuf>` : `ensure_docker`, `ensure_image`, trousseau, export dans un répertoire temporaire, `docker run`, renvoie le répertoire hôte monté sur `/helios/out`.
- Produces (`main.rs`) : `bundle(target, skip_frontend, output, native: bool)` et `app(target, skip_frontend, native: bool)`. Sans `--native` : refus d'une cible autre que `x86_64-unknown-linux-gnu`, puis `build_in_container` avec `["cargo", "xtask", "bundle", "--native", "--target", <cible>, "--output", "/helios/out/<nom>"]` (resp. `app --native` suivi de la copie de `/helios/target/<cible>/release/heliosd` vers `/helios/out/heliosd`, dans la même commande `sh -c`), puis `copy_out` vers `target/bundle/<nom>` (resp. `cargo_target_dir(root)/<cible>/release/heliosd`, chemin que lit `scripts/deploy-app.sh`). Le message final de `bundle` (commande `helios-publisher` à taper) est inchangé.

**Dockerfile** (`tools/build-env/Dockerfile`), en tête les `ARG` : `DEBIAN_DIGEST`, `SNAPSHOT` (horodatage `YYYYMMDDThhmmssZ`), `RUSTUP_INIT_SHA256`, `RUST_VERSION=1.100.0`, `NODE_VERSION=26.13.1`, `NODE_SHA256`. Base `debian:trixie-slim@sha256:${DEBIAN_DIGEST}` (un `ARG` avant `FROM`). Sources apt sur `snapshot.debian.org/archive/debian/${SNAPSHOT}` et `…/debian-security/${SNAPSHOT}`, `check-valid-until=no`. Paquets : ceux de la spec §5.2, établis par le premier build qui réussit. `RUSTUP_HOME=/usr/local/rustup`, binaires dans `/usr/local/cargo/bin` (sur le `PATH`), `CARGO_HOME=/helios/cargo` à l'exécution. Répertoires `/helios/cargo` et `/helios/target` créés en mode 1777 dans l'image (un volume nommé neuf hérite du contenu et des modes du point de montage de l'image : c'est ce qui rend Review Focus 1 vrai). `HOME=/tmp`. Commentaire en tête : comment monter de version (changer les `ARG`, `toolchain_pins.py` dit le reste).

- [ ] **Step 1: Tests (rouges)** dans `container.rs` :
  - `image_tag_changes_with_the_dockerfile` : deux contenus → deux étiquettes, préfixe `helios-build:`, 12 hex ;
  - `run_args_carry_the_fixed_environment` : contient les deux `--remap-path-prefix`, `SOURCE_DATE_EPOCH=<n>`, `TZ=UTC`, `LANG=C.UTF-8`, `--user 1000:1000`, `helios-build-cargo:/helios/cargo`, `helios-build-target:/helios/target`, et le montage du trousseau en `:ro` ;
  - `run_args_mount_the_keyring_by_absolute_path` : trousseau `rel dir/keyring.json` (relatif, avec espace) → le montage nomme un chemin absolu, dans un seul argument ;
  - `run_args_forward_cargo_build_jobs_only_when_set` ;
  - `export_tree_takes_only_tracked_files` : dépôt git temporaire avec un fichier suivi exécutable, un non suivi, `node_modules/x`, `web/dist/y` → seul le suivi est copié, bit exécutable conservé ; une modification non commitée d'un fichier suivi est copiée telle quelle ;
  - `copy_out_replaces_an_existing_destination` : destination avec un fichier `stale` → absent après copie ;
  - `docker_unavailable_is_reported_before_building` : `ensure_docker` testé par une fonction pure `docker_error(status: Option<ExitStatus>) -> anyhow::Error` (ou équivalent) dont le message contient `--native` et `docker` ;
  - `tests::bundle_cli_accepts_native` (parse clap, à côté des tests CLI existants) ; `tests::container_build_refuses_other_targets`.
- [ ] **Step 2:** `scripts/wsl-cargo test -p xtask` → FAIL.
- [ ] **Step 3:** Implémenter le module, le Dockerfile, le câblage `main.rs`.
- [ ] **Step 4:** `scripts/wsl-cargo test -p xtask`, clippy `-D warnings`, `python3 scripts/toolchain_pins.py` → verts. Construire l'image une fois : `docker build -f tools/build-env/Dockerfile tools/build-env` → succès (reporter l'étiquette et la durée dans le rapport).
- [ ] **Step 5: Commit** `feat(xtask)!: build release artefacts in a pinned container by default`

### Task 4: Acceptation — deux builds, mêmes octets

**Files:**
- Modify: au besoin `tools/build-env/Dockerfile`, `tools/xtask/src/container.rs`, et la spec §5.4 (source d'écart découverte)
- Create: `docs/testing/reproductibilite-f15.md` (le procès-verbal)

**Interfaces:**
- Consumes: Task 3 (`cargo xtask bundle`), Task 2 (`archive`).

Tâche de jugement : implémenteur de niveau standard.

- [ ] **Step 1:** Trousseau de test : un trousseau public **non** marqué `development` (générer une époque jetable avec `cargo run -p helios-publisher -- keygen --key-epoch 9 --output-dir <tmp>` ; ne garder que `publisher-keyring.json` pour le build ; ne jamais commiter les clés privées).
- [ ] **Step 2:** `docker volume rm helios-build-cargo helios-build-target` (s'ils existent), puis build A : `HELIOS_PUBLISHER_KEYRING_PATH=<tmp>/publisher-keyring.json cargo xtask bundle` depuis le worktree ; sauvegarder la liste `sha256sum` triée de `target/bundle/<nom>/`.
- [ ] **Step 3:** Build B depuis un **second clone** du même commit, dans un autre chemin (`git clone --no-local … /tmp/…/b && git checkout <commit>`), avec `TZ=Pacific/Auckland`, `umask 077` côté hôte, volumes réutilisés.
- [ ] **Step 4:** Comparer : listes identiques → noter. Sinon, localiser chaque écart (`diffoscope` dans un conteneur jetable si besoin), le corriger à sa cause (Dockerfile, `RUSTFLAGS`, environnement), ajouter un test qui le fige et une ligne dans la spec §5.4, puis reprendre Step 2. Plafond : trois sources d'écart corrigées ; au-delà, rapport `DONE_WITH_CONCERNS` avec la liste.
- [ ] **Step 5:** Build C : volumes supprimés à nouveau (Review Focus 1), même liste attendue.
- [ ] **Step 6:** Rédiger `docs/testing/reproductibilite-f15.md` : commit, étiquette d'image, les trois empreintes de `heliosd`, durée des builds, écarts corrigés.
- [ ] **Step 7: Commit** `test(f15): two independent container builds give identical bundles`

### Task 5: `cargo xtask verify`

**Files:**
- Modify: `crates/helios-update/src/bundle.rs` (rendre publique la vérification sous un trousseau donné ; ajouter l'analyse du trousseau)
- Modify: `tools/helios-publisher/src/main.rs` (`load_keyring` réutilise l'analyse partagée)
- Create: `tools/xtask/src/verify.rs` ; Modify: `tools/xtask/src/lib.rs`, `tools/xtask/src/main.rs` (`Cmd::Verify`)

**Interfaces:**
- Consumes: Task 3 (`container::build_in_container`, `export_tree`), Task 2 (extraction : `tar -xzf` suffit).
- Produces :
  - `pub fn helios_update::bundle::parse_publisher_keyring(bytes: &[u8]) -> Result<Vec<aether::sig::PublisherPublicKeys>>` : même règles que l'actuel `load_keyring` (JSON, base64, liste non vide, époques uniques) ;
  - `pub fn helios_update::bundle::verify_signature_with_keyring(manifest: &SignedBundle, keyring: &[PublisherPublicKeys]) -> Result<()>` : signature, produit, métadonnées et `validate()` — sans contrôle de canal ni de cible ;
  - `pub enum xtask::verify::Difference { Missing(String), Extra(String), Changed { path: String, expected: BundleEntry, actual: BundleEntry } }`
  - `pub fn xtask::verify::compare(expected: &[BundleEntry], actual: &[BundleEntry]) -> Vec<Difference>` (pure, triée par chemin) ;
  - `pub fn xtask::verify::resolve_commit(root: &Path, git_commit: &str) -> anyhow::Result<String>` : refuse `-dirty`, résout le préfixe par `git rev-parse --verify <préfixe>^{commit}`, erreur qui donne `git fetch` ;
  - CLI : `cargo xtask verify --bundle <dir|archive.tar.gz> --keyring <path>` ; code 0 seulement si `compare` est vide ; chaque différence imprimée avec les deux empreintes en hex.
- Le build de vérification : `git worktree add --detach <tmp> <commit>` (ou `git archive <commit>` extrait), export de cet arbre, `build_in_container`, sortie dans un répertoire temporaire ; `target/bundle/` et le répertoire de travail ne sont pas touchés.

- [ ] **Step 1: Tests (rouges)** :
  - `helios_update` : `parse_publisher_keyring_matches_the_publisher_rules` (vide, époque dupliquée, base64 invalide → erreurs ; trousseau de dev des tests → ok) ; `verify_signature_with_keyring_rejects_another_keyring` ;
  - `verify::tests::identical_lists_have_no_difference` ;
  - `verify::tests::differences_are_named` : un manquant, un en trop, un `sha256` changé, un `executable` changé → quatre `Difference`, dans l'ordre des chemins ;
  - `verify::tests::dirty_commit_is_refused` : `"0123456789abcdef-dirty"` → erreur contenant `dirty` ;
  - `verify::tests::unknown_commit_names_git_fetch` (dépôt git temporaire) ;
  - `verify::tests::foreign_target_is_refused` : `payload.target` autre que `x86_64-unknown-linux-gnu` → erreur avant tout build ;
  - `verify::tests::unsigned_bundle_is_refused_before_building` : répertoire sans `manifest.json` → erreur, aucun appel à Docker (la fonction d'orchestration prend le constructeur en paramètre, `FnOnce(&Path, &str) -> Result<Vec<BundleEntry>>`, pour être testée sans Docker) ;
  - `verify::tests::verify_accepts_an_archive_and_a_directory` (Review Focus 4) : le même bundle signé de test, en répertoire puis en `.tar.gz` → le constructeur factice reçoit le même commit, et le résultat est identique.
- [ ] **Step 2:** `scripts/wsl-cargo test -p xtask -p helios-update -p helios-publisher --all-features` → FAIL.
- [ ] **Step 3:** Implémenter.
- [ ] **Step 4:** Tests et clippy `-D warnings` → verts. Bout en bout : signer le bundle de Task 4 avec l'époque jetable (`helios-publisher bundle … --git-commit $(git rev-parse --short=16 HEAD)`), puis `cargo xtask verify --bundle <dir> --keyring <tmp>/publisher-keyring.json` → code 0 ; modifier un octet d'`network.toml.example` dans une copie → code non nul et la différence nommée. Reporter les sorties dans le rapport.
- [ ] **Step 5: Commit** `feat(xtask): verify a signed bundle by rebuilding its commit`

### Task 6: CI et scripts de livraison

**Files:**
- Modify: `.github/workflows/release.yml` (job `bundle`)
- Create: `.github/workflows/reproducible.yml`
- Modify: `scripts/deploy.sh` (drapeau `--build-natif`, commentaire des lignes ~392-396), `scripts/deploy-app.sh` (même drapeau, transmis à `cargo xtask app`), `scripts/clean-wsl-targets` (volumes Docker)

**Interfaces:**
- Consumes: Task 3 (`cargo xtask bundle`, `--native`).

- [ ] **Step 1:** `release.yml`, job `bundle` : retirer `dtolnay/rust-toolchain`, `actions/setup-node` et l'installation apt ; garder l'ancre de confiance ; installer seulement de quoi lancer xtask sur l'hôte (le Rust préinstallé du runner `ubuntu-24.04` suffit pour compiler xtask — sinon `dtolnay/rust-toolchain@1.100.0`, la version de Global Constraints) ; `cargo xtask bundle` (conteneur par défaut). Les empreintes et l'upload sont inchangés.
- [ ] **Step 2:** `reproducible.yml` : déclencheurs `push: tags: ["v*"]`, `workflow_dispatch`, `schedule` hebdomadaire (lundi 04:00 UTC) ; un job `ubuntu-24.04`, `timeout-minutes: 120`, `CARGO_BUILD_JOBS: 2` ; trousseau depuis `vars.HELIOS_PUBLISHER_KEYRING` (même contrôle « private » que `release.yml`) ; build A dans `$GITHUB_WORKSPACE` ; build B : second checkout du même `github.sha` dans `$RUNNER_TEMP/b`, `TZ=Pacific/Auckland`, `umask 077`, après `docker volume rm helios-build-cargo helios-build-target` ; les deux listes `sha256sum` triées en artefact ; `diff` → échec avec la différence affichée.
- [ ] **Step 3:** `deploy.sh` : `--build-natif` → passe `--native` à `cargo xtask bundle` ; usage mis à jour ; commentaire ~392 corrigé (« l'utilisateur est dans le groupe `docker` du poste, pas sur la gateway »). `deploy-app.sh` : même drapeau. `clean-wsl-targets` : `docker volume rm helios-build-cargo helios-build-target` si `docker` est disponible, sans échouer s'ils n'existent pas.
- [ ] **Step 4:** `bash -n` sur les trois scripts ; `actionlint` s'il est installé (sinon `python3 -c 'import yaml…'` pour la syntaxe) ; `python3 scripts/toolchain_pins.py` → vert. Lancer `reproducible.yml` sur la branche nécessite un push : **ne pas pousser** ; le noter comme vérification restante dans le rapport.
- [ ] **Step 5: Commit** `ci: build the gateway bundle in the pinned container and check reproducibility weekly`

### Task 7: Documentation

**Files:**
- Modify: `docs/adr/ADR-004-CHAINE-DE-LIVRAISON.md` (« Limites connues »), `docs/MAINTENANCE.md` (section « Vérifier un bundle » ; Docker prérequis de livraison ; `--build-natif`), `docs/ROADMAP.md` (F15 ; Horizon 5 « Chaîne de livraison » ; séquencement), `docs/testing/TESTING.md` (le workflow `reproducible.yml` et le procès-verbal de Task 4)

- [ ] **Step 1:** ADR-004 : la limite devient « levée pour le bundle gateway (F15), reste pour Orion » ; dire ce qui est promis (fichiers du manifeste, spec §5.1) et ce qui ne l'est pas (archive signée d'une publication à l'autre, build `--native`).
- [ ] **Step 2:** MAINTENANCE : « Vérifier un bundle » avec la commande exacte de Task 5, ce que signifie un code non nul, et `git fetch` si le commit manque ; prérequis Docker ; `--build-natif` et sa conséquence (pas de garantie de reproductibilité) ; monter de toolchain (changer les `ARG`, puis `python3 scripts/toolchain_pins.py`).
- [ ] **Step 3:** ROADMAP : F15 « implémenté sur `feat/f15-reproducible-bundle` (22 novembre 2026) » avec la recette restante (`reproducible.yml` à jouer après le premier push).
- [ ] **Step 4:** Relire chaque commande citée contre le code (noms de drapeaux, chemins).
- [ ] **Step 5: Commit** `docs(f15): reproducible gateway bundle and how to verify one`
