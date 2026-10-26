# Séparation des privilèges d'Orion sous Windows (F11) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** couper `orion.exe` en un moteur élevé sans fenêtre (tunnel, coffre, secrets) et une IHM non élevée (Tauri, WebView2, WebAuthn), liés à vie, avec un coffre et un exécutable que seul un processus élevé peut ouvrir ou modifier.

**Architecture :** une crate `orion-engine` sans Tauri porte le protocole, l'authentification de session, la liste fermée des commandes (qui *est* la politique d'autorisation) et le service qui détient l'état aujourd'hui rangé dans l'`AppState` Tauri. Sous Windows, l'IHM lance le moteur par `ShellExecuteEx runas` et lui parle par un tube nommé vérifié ; ailleurs, le même service tourne dans le processus de l'IHM sur un canal mémoire, ce qui garde un seul chemin de code et le rend testable sous Linux. Le coffre passe dans un dossier réservé aux administrateurs, sous une clé TPM machine, par une migration qui ne détruit l'ancien qu'après relecture du nouveau.

**Tech Stack :** Rust 2021 (MSRV 1.95), tokio, serde_json, `windows-sys` 0.61, Tauri 2, `tauri-plugin-single-instance` 2.5.2, React/Vitest côté IHM (inchangé).

**Spec :** `docs/superpowers/specs/2026-10-24-separation-privileges-windows-design.md`

## Global Constraints

- AGENTS.md : aucun secret journalisé, sérialisé ni exposé ; *fail-closed* ; pas d'`unwrap`/`expect` en production ; aucun TODO/FIXME ; identifiants, commentaires et noms de tests en anglais ; messages de l'IHM en français ; `docs/` en français.
- Aucune dépendance externe nouvelle : `windows-sys` (features à ajouter au besoin), tokio, serde, `aether::random::secret_bytes`, `tauri-plugin-single-instance` existent déjà.
- Un seul binaire : `orion.exe`. Aucun binaire livré à part, aucun `externalBin`.
- Aucun secret du moteur vers l'IHM (spec §8). Les secrets saisis vont de l'IHM au moteur une fois.
- Le moteur n'écrit **jamais** hors de sa racine protégée : tout fichier destiné à l'utilisateur (`.helios-request`, export de journal) est rendu à l'IHM, qui l'écrit.
- Linux et macOS : comportement inchangé ; le service tourne en processus unique.
- Compilation : `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo …`, jamais `CARGO_TARGET_DIR`. Régression : `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh`.
- **Code `cfg(windows)` : non compilable depuis WSL2** (pas de MSVC). Chaque tâche qui en écrit sépare la logique portable, testée sous Linux, de l'appel Win32, qui reste mince. Les étapes « Windows » se vérifient par l'utilisateur sous Windows : `cargo test -p orion --features wireguard` et `cargo test -p orion-core --features wireguard` dans `C:\Users\Christophe\StudioProjects\helios`. L'exécutant le note dans son rapport et ne prétend jamais les avoir vues passer.

## Review Focus

1. **Écriture élevée dans un chemin contrôlé par l'utilisateur** (jonction, lien symbolique) : aucune commande du moteur ne prend de chemin de sortie, et toute écriture du moteur passe sous la racine protégée. Testé en tâche 3 (`no_engine_command_names_an_output_path`) et en tâche 10 (`every_engine_path_is_under_the_protected_root`).
2. **L'IHM meurt pendant l'UAC** : le moteur qui démarre ensuite trouve un parent absent ou recréé et doit s'arrêter seul. Testé en tâche 9 (`a_parent_gone_before_the_engine_starts_stops_it`).
3. **IHM lente ou figée qui ne lit plus ses événements** : la télémétrie et le journal se jettent quand la file est pleine, jamais un changement d'état ; une file critique pleine vaut une IHM perdue. Testé en tâche 4 (`a_stalled_client_never_blocks_the_controller`, `critical_events_are_never_dropped`).
4. **Deux comptes Windows ouverts en même temps** : noms de tube, dossiers de coffre et clés TPM ne doivent pas se croiser. Testé en tâches 8, 10 et 11 (`pipe_names_never_repeat`, `the_protected_root_is_per_user_sid`, `machine_key_slots_are_per_user_sid`).
5. **Ancien `orion.exe` dans un dossier modifiable par l'utilisateur** (NSIS par utilisateur resté installé, copie) : son moteur refuse de s'élever. Testé en tâche 13 (`an_executable_directory_writable_by_a_user_is_refused`).

---

## Partition des commandes

Règle : tout ce qui touche au contrôleur, au coffre, au magasin d'identités, aux clés en attente ou à la négociation va au **moteur** ; tout ce qui touche à une fenêtre, à WebAuthn, au coffre maître opérateur, au lancement d'un processus ou à l'écriture d'un fichier choisi par l'utilisateur reste à l'**IHM**.

| Famille | Moteur | IHM |
| --- | --- | --- |
| `app.rs` | `get_state`, `backend_kind`, `adapter_is_up`, `about_orion`, `key_negotiation_support`, `run_speed_test` | `resize_for_view`, `export_logs` |
| `connection.rs` | `connect`, `disconnect`, `renew_psk`, sondage du handshake, télémétrie | — |
| `profiles.rs` | `get_config`, `import_profile` (reçoit le contenu), `vault_posture`, `allow_unencrypted_volume`, `generate_private_key`, `adopt_private_key`, `discard_staged_key`, `adopt_preshared_key`, `discard_staged_psk`, `ssh_command`, `save_profile`, `delete_profile`, `select_profile`, `validate_profile` | `import_profile_path` (l'IHM lit le fichier avec les droits de l'utilisateur, puis envoie `import_profile`), `open_ssh_terminal` (demande `ssh_command`, lance le terminal) |
| `enrollment.rs` | les cinq commandes ; `export_pending_request` rend le contenu, l'IHM l'écrit | — |
| `certificates.rs` | `certificate_inventory`, `certificate_overview`, `certificate_actions`, `run_certificate_action`, `resume_certificate_recovery`, `certificate_approval_manifest`, `approve_certificate_renewal`, `certificate_approval_needs_pin`, `last_certificate_error` | `launch_certificate_companion` (lance `astra-signer` avec l'invocation que rend le moteur) |
| `ceremonies.rs`, `astra.rs`, `operator.rs` | — | les neuf commandes de rotation CA TLS et de cérémonie opérateur |
| `tray.rs` | — | menu ; ses gestes « connecter » et « déconnecter » appellent le moteur |

Une commande ambiguë qui n'apparaît pas ici suit la règle, et l'exécutant consigne sa décision.

---

### Task 1 : crate `orion-engine` et protocole

**Files :**
- Create : `crates/orion-engine/Cargo.toml`, `crates/orion-engine/src/lib.rs`, `crates/orion-engine/src/wire.rs`, `crates/orion-engine/src/wire/tests.rs`
- Modify : `Cargo.toml` (membre du workspace)

**Interfaces :**
- Produces :
  - `pub const PROTOCOL_VERSION: u16 = 1;`
  - `pub mod limits { pub const HELLO_BYTES: usize = 1024; pub const REQUEST_BYTES: usize = 1024 * 1024; pub const REPLY_BYTES: usize = 1024 * 1024; pub const EVENT_BYTES: usize = 64 * 1024; }`
  - `#[derive(Serialize, Deserialize)] pub struct Hello { pub protocol_version: u16, pub token: String }`
  - `pub enum ClientFrame { Hello(Hello), Request { id: u64, command: EngineCommand } }` et `pub enum EngineFrame { Reply { id: u64, result: Result<EngineReply, String> }, Event(orion_core::ClientEvent) }`, sérialisés `#[serde(tag = "frame", rename_all = "snake_case")]` (`EngineCommand`/`EngineReply` : tâche 3 ; un placeholder vide d'une variante suffit ici)
  - `pub async fn read_frame<R: AsyncBufRead + Unpin, T: DeserializeOwned>(reader: &mut R, limit: usize) -> Result<Option<T>, WireError>` (`None` = fin de flux propre)
  - `pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, frame: &T, limit: usize) -> Result<(), WireError>`
  - `pub enum WireError { TooLarge { limit: usize }, Malformed, Io(std::io::ErrorKind) }`

Un objet JSON par ligne, comme `tools/helios-astra-helper/src/session.rs` (`read_frame`/`write_frame`) : reprendre sa lecture bornée qui cesse de lire au-delà de la limite au lieu d'allouer.

- [ ] **Step 1 : tests rouges** dans `wire/tests.rs` : `a_frame_round_trips`, `a_line_over_its_limit_is_refused_without_reading_it_all` (ligne de `limit + 1` octets → `TooLarge`, et le lecteur n'a pas consommé plus de `limit + 1` octets), `a_malformed_line_is_refused`, `end_of_stream_is_none`, `a_writer_refuses_a_frame_over_its_limit`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-engine` → échec de compilation (module absent).
- [ ] **Step 3 :** implémenter `wire.rs`.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-engine` → 5 passed.
- [ ] **Step 5 :** commit `feat(orion-engine): bounded JSON-line wire for the engine channel`.

### Task 2 : authentification de session

**Files :**
- Create : `crates/orion-engine/src/session.rs`, `crates/orion-engine/src/session/tests.rs`

**Interfaces :**
- Consumes : `read_frame`, `Hello`, `limits` (tâche 1)
- Produces :
  - `pub struct SessionToken(Zeroizing<String>)` ; `SessionToken::generate() -> Result<Self, String>` (32 octets d'`aether::random::secret_bytes`, en hexadécimal) ; `as_str(&self) -> &str` ; pas de `Debug` qui l'affiche, pas de `Serialize`
  - `pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);`
  - `pub async fn accept_hello<R: AsyncBufRead + Unpin>(reader: &mut R, expected: &SessionToken) -> Result<(), SessionRefusal>`
  - `pub enum SessionRefusal { Timeout, WrongVersion, WrongToken, NotAHello, Wire(WireError), Closed }`
  - `fn same_secret(candidate: &str, expected: &str) -> bool` : la comparaison à temps constant d'`apps/orion/src-tauri/src/operator.rs` (`same_secret`), déplacée ici et réutilisée par `operator.rs`.

Une seule tentative : le moteur ne boucle pas sur les connexions comme le fait `authenticated_helper` (le tube n'a qu'une instance, tâche 8). Toute `SessionRefusal` arrête le moteur.

- [ ] **Step 1 : tests rouges** sur `tokio::io::duplex` : `the_right_hello_opens_the_session`, `a_wrong_token_is_refused`, `a_token_of_another_length_is_refused`, `another_protocol_version_is_refused`, `a_request_before_the_hello_is_refused`, `silence_past_the_hello_timeout_is_refused` (avec `tokio::time::pause`), `the_token_never_appears_in_debug_output`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-engine session` → échec.
- [ ] **Step 3 :** implémenter ; remplacer `same_secret` d'`operator.rs` par l'import.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-engine` et `-p orion` → verts.
- [ ] **Step 5 :** commit `feat(orion-engine): authenticate the one client of an engine`.

### Task 3 : commandes fermées et politique

**Files :**
- Create : `crates/orion-engine/src/command.rs`, `crates/orion-engine/src/command/tests.rs`

**Interfaces :**
- Produces :
  - `#[serde(tag = "command", rename_all = "snake_case")] pub enum EngineCommand` : une variante par commande « Moteur » de la partition, arguments en champs nommés repris des signatures Tauri actuelles (ex. `Connect { name: Option<String> }`, `AdoptPresharedKey { value: SecretInput }`, `ImportProfile { contents, file_name }`), plus `Shutdown`.
  - `#[serde(tag = "reply", rename_all = "snake_case")] pub enum EngineReply` : une variante par type de retour actuel (`Unit`, `State(String)`, `Config(ConfigView)`, `RequestFile(String)`…). Les types de vue (`ConfigView`, `AboutView`, `PendingEnrollment`…) passent d'`apps/orion/src-tauri` à `orion-engine` sans changement de forme JSON : le frontend ne change pas.
  - `pub struct SecretInput(Zeroizing<String>)` : `Serialize` et `Deserialize` (l'IHM l'envoie, le moteur le reçoit), `Debug` masqué. C'est le seul type par lequel un secret entre dans le moteur, et aucune `EngineReply` ne le porte.

La politique d'autorisation est cette liste : aucune variante générique, aucune variante qui nomme un exécutable, un chemin de sortie ou rende un secret.

- [ ] **Step 1 : tests rouges** : `every_reply_serializes_without_secret_material` (construire chaque `EngineReply` à partir de fixtures portant la valeur `"SECRET-QUI-NE-DOIT-PAS-FUIR"` dans tout champ secret de la source — clé privée de profil, PSK statique, clé en attente — et vérifier qu'elle est absente du JSON), `secret_input_never_shows_in_debug` (le `Debug` d'un `EngineCommand::AdoptPresharedKey` ne contient pas la valeur), `no_engine_command_names_an_output_path` (désérialiser chaque variante depuis un JSON d'exemple et vérifier par une table écrite dans le test qu'aucune ne porte de champ `output`, `out`, `destination` ni `path`), `the_command_list_matches_the_partition` (la liste des noms `snake_case` est égale à la colonne « Moteur » de la partition, écrite en dur dans le test).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-engine command` → échec.
- [ ] **Step 3 :** implémenter les deux énumérations et déplacer les types de vue.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-engine` → vert ; `cd apps/orion && npx vitest run` → inchangé (166/166 ou plus).
- [ ] **Step 5 :** commit `feat(orion-engine): the closed list of engine commands`.

### Task 4 : service moteur, événements et transport mémoire

**Files :**
- Create : `crates/orion-engine/src/service.rs`, `crates/orion-engine/src/service/` (un fichier par famille : `connection.rs`, `profiles.rs`, `enrollment.rs`, `certificates.rs`, `app.rs`), `crates/orion-engine/src/events.rs`, `crates/orion-engine/src/serve.rs`, leurs `tests.rs`
- Modify : `apps/orion/src-tauri/src/main.rs` (l'`AppState` ne garde que l'IHM), `apps/orion/src-tauri/src/commands/*.rs` (corps déplacés)

**Interfaces :**
- Consumes : tâches 1 à 3
- Produces :
  - `pub struct EngineService` : contrôleur, `ProfileStore`, `ClientConfig`, `TelemetryManager`, verrou du test de débit, imports en attente, `StagedKey`, `StagedPsk`, magasin d'identités, sondage du handshake — tout ce que l'`AppState` actuel tient et que la partition range côté moteur.
  - `EngineService::open(paths: orion_core::protected_root::EnginePaths) -> Result<Arc<Self>, String>`
  - `crates/orion-core/src/protected_root.rs` : `pub struct EnginePaths { pub root: PathBuf, pub config: PathBuf, pub vault: PathBuf, pub identities: PathBuf, pub log: PathBuf }` et `EnginePaths::for_current_user() -> Result<Self, String>`, qui rend ici les chemins actuels (`ProjectDirs`) ; la tâche 10 change la résolution Windows
  - `pub async fn handle(&self, command: EngineCommand, events: &EventQueue) -> Result<EngineReply, String>`
  - `pub struct EventQueue` : `fn sink(&self) -> orion_core::backend::EventSink` ; capacité `EVENT_QUEUE: usize = 1024` ; `ClientEvent::Telemetry` et `ClientEvent::Log` se jettent quand la file est pleine ; tout autre événement qui ne trouve pas de place ferme la session (`EventQueue::overflowed() -> bool`).
  - `pub async fn serve<S: AsyncRead + AsyncWrite>(stream: S, token: &SessionToken, service: Arc<EngineService>) -> ServeOutcome` : `accept_hello`, puis requêtes et événements multiplexés ; `ServeOutcome::{ClientLeft, ShutdownRequested, Refused(SessionRefusal), EventsOverflowed}`.
  - `pub fn in_process(service: Arc<EngineService>) -> EngineClient` (canal `tokio::io::duplex`) ; `pub struct EngineClient` : `async fn call(&self, command: EngineCommand) -> Result<EngineReply, String>`, `fn events(&self) -> mpsc::Receiver<ClientEvent>`.

Chaque commande Tauri « Moteur » devient un mandataire d'une ligne vers `EngineClient::call`, avec la même signature côté frontend. Un pont dans `main.rs` relaie `EngineClient::events()` vers `emit("helios://event", …)`. Hors Windows, `main.rs` construit l'`EngineClient` par `in_process`.

À faire famille par famille, un commit chacune, dans l'ordre `app` + `connection`, `profiles`, `enrollment`, `certificates`. Les tests existants des corps déplacés partent avec eux.

- [ ] **Step 1 : tests rouges** dans `serve/tests.rs` : `a_request_gets_the_reply_of_its_id`, `events_reach_the_client_between_replies`, `shutdown_ends_the_session_with_shutdown_requested`, `a_client_that_leaves_ends_the_session`, `a_stalled_client_never_blocks_the_controller` (client qui ne lit jamais ; 10 000 `Telemetry` poussés ; `sink` revient toujours en moins de 10 ms), `critical_events_are_never_dropped` (file pleine de `Log`, un `StateChanged` → `overflowed()` vrai et `ServeOutcome::EventsOverflowed`, jamais un `StateChanged` perdu silencieusement).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-engine serve` → échec.
- [ ] **Step 3 :** implémenter `events.rs` et `serve.rs`, puis déplacer famille par famille.
- [ ] **Step 4 :** après chaque famille : `scripts/wsl-cargo test -p orion-engine`, `-p orion`, `-p orion-core`, `cd apps/orion && npx vitest run && npx tsc --noEmit -p .` → verts ; Orion sous Linux (`cargo run -p orion`) se connecte toujours en mode simulé.
- [ ] **Step 5 :** un commit par famille, `refactor(orion): move the <famille> commands into the engine service`.

### Task 5 : WebAuthn dans l'IHM, retrait de `helios-astra-helper`

**Files :**
- Create : `apps/orion/src-tauri/src/operator/ceremony.rs`, `apps/orion/src-tauri/src/operator/owner.rs` (depuis `tools/helios-astra-helper/src/main.rs` et `owner.rs`)
- Modify : `apps/orion/src-tauri/src/operator.rs` (devient `operator/mod.rs`), `apps/orion/src-tauri/src/astra.rs`, `apps/orion/src-tauri/src/deelevate.rs` (retrait de `spawn_astra_helper`), `apps/orion/src-tauri/tauri.windows.conf.json` (retrait d'`externalBin`), `Cargo.toml` (membre retiré), `apps/orion/src-tauri/Cargo.toml` (`aether-fido` direct si absent)
- Delete : `tools/helios-astra-helper/`

**Interfaces :**
- Produces : `operator::ceremony::run(locator: OperationLocator, status: impl Fn(OperatorStatus)) -> Result<(), String>` exécuté dans une tâche bloquante de l'IHM, à la place du processus et du canal TCP. Le fond (`aether_fido::authenticator::connect_owned`, fenêtre propriétaire, résolution de l'origine depuis le hand-off épinglé) est repris tel quel.

- [ ] **Step 1 : tests rouges** : déplacer les tests de `tools/helios-astra-helper` qui ne dépendent pas de Win32 vers `operator/ceremony/tests.rs` ; ils doivent échouer tant que `operator::ceremony` n'existe pas.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion operator` → échec.
- [ ] **Step 3 :** déplacer, câbler, supprimer le binaire.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion` vert ; `grep -rn "helios-astra-helper" --include=*.rs --include=*.toml --include=*.json .` ne renvoie plus que des mentions historiques dans `docs/superpowers/` ; **Windows** : une cérémonie YubiKey aboutit depuis l'IHM (recette §13 point 10).
- [ ] **Step 5 :** commit `feat(orion): run WebAuthn ceremonies in the de-elevated UI, drop the helper`.

### Task 6 : terminal SSH et `astra-signer` sans désélévation

**Files :**
- Modify : `apps/orion/src-tauri/src/deelevate.rs` → `apps/orion/src-tauri/src/launch.rs`, `apps/orion/src-tauri/src/companion.rs`, `apps/orion/src-tauri/src/commands/profiles.rs`, `apps/orion/src-tauri/src/security_tests.rs`

**Interfaces :**
- Produces : `launch::spawn_ssh_terminal(target: &str) -> Result<(), String>` et `launch::spawn_astra_signer(arguments: &[String]) -> Result<(), String>` par `std::process::Command` (Windows : `CREATE_NEW_CONSOLE`) ; `launch::refuse_if_elevated() -> Result<(), String>`, appelé avant tout lancement : si le jeton de l'IHM est élevé, rien ne part (« Orion s'exécute en administrateur : lancement refusé. »). C'est la post-condition de `deelevate.rs`, gardée ; le reste (jeton d'`explorer.exe`, `CreateProcessWithTokenW`) disparaît.

- [ ] **Step 1 : test rouge** dans `security_tests.rs` : `nothing_is_launched_from_an_elevated_ui` (le prédicat `should_launch(elevated: bool) -> bool` est faux pour `true`).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion security` → échec.
- [ ] **Step 3 :** implémenter, supprimer le code de désélévation.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion` vert ; **Windows** : le terminal ouvert n'est pas élevé (recette point 11).
- [ ] **Step 5 :** commit `refactor(orion): launch from a UI that is no longer elevated`.

### Task 7 : manifeste `asInvoker`

**Files :**
- Modify : `apps/orion/src-tauri/windows/orion-manifest.xml`, `apps/orion/src-tauri/src/security_tests.rs`

- [ ] **Step 1 : test rouge** : `the_manifest_asks_for_the_invoker_level` (lit `include_str!("../windows/orion-manifest.xml")`, exige `level="asInvoker"` et `uiAccess="false"`, refuse `requireAdministrator` et `highestAvailable`). Adapter tout test existant qui exigeait `requireAdministrator`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion manifest` → échec.
- [ ] **Step 3 :** changer le niveau.
- [ ] **Step 4 :** test vert.
- [ ] **Step 5 :** commit `feat(orion): the executable no longer asks for elevation by itself`. **Ne pas fusionner avant la tâche 9** : sans moteur élevé, WireGuard-NT ne se charge plus.

### Task 8 : tube nommé et vérification du client (Windows)

**Files :**
- Create : `crates/orion-engine/src/pipe.rs` (portable), `crates/orion-engine/src/pipe/windows.rs`, `crates/orion-engine/src/pipe/tests.rs`

**Interfaces :**
- Produces :
  - `pub fn pipe_name(ui_pid: u32, nonce: &[u8; 16]) -> String` → `\\.\pipe\orion-engine-<ui_pid>-<nonce hex>` ; le nonce vient d'`aether::random::secret_bytes`.
  - `pub struct ExpectedClient { pub pid: u32, pub image: PathBuf, pub created_at: u64 }` et `pub struct ObservedClient` (mêmes champs) ; `pub fn verify_client(expected: &ExpectedClient, observed: &ObservedClient) -> Result<(), ClientRefusal>` : PID égal, image égale après canonicalisation insensible à la casse, `created_at` égal.
  - Windows : `pub fn create_server(name: &str) -> Result<NamedPipeServer, String>` (tokio `ServerOptions` avec `first_pipe_instance(true)`, `max_instances(1)` et une DACL n'accordant `GENERIC_READ | GENERIC_WRITE` qu'au SID de l'utilisateur du jeton du moteur, `reject_remote_clients(true)`) ; `pub fn observe_client(server: &NamedPipeServer) -> Result<ObservedClient, String>` (`GetNamedPipeClientProcessId`, `QueryFullProcessImageNameW`, `GetProcessTimes`) ; `pub fn connect_client(name: &str) -> Result<NamedPipeClient, String>`.

- [ ] **Step 1 : tests rouges** (portables) : `the_launching_ui_is_accepted`, `another_pid_is_refused`, `another_image_is_refused`, `the_same_image_in_another_case_is_accepted`, `a_reused_pid_is_refused` (même PID, `created_at` différent), `pipe_names_never_repeat` (deux nonces → deux noms).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-engine pipe` → échec.
- [ ] **Step 3 :** implémenter la partie portable, puis `windows.rs`.
- [ ] **Step 4 :** tests portables verts ; **Windows** : `cargo test -p orion-engine` ; recette point 9 (un tiers qui ouvre le tube est refusé).
- [ ] **Step 5 :** commit `feat(orion-engine): a named pipe only the launching UI may open`.

### Task 9 : lancement élevé et cycle de vie lié

**Files :**
- Create : `crates/orion-engine/src/lifecycle.rs`, `crates/orion-engine/src/lifecycle/tests.rs`, `apps/orion/src-tauri/src/engine_host.rs` (mode moteur), `apps/orion/src-tauri/src/engine_launch.rs` (lancement depuis l'IHM, Windows)
- Modify : `apps/orion/src-tauri/src/main.rs`, `apps/orion/src-tauri/src/tray.rs`

**Interfaces :**
- Consumes : tâches 2, 4, 8
- Produces :
  - `pub struct EngineArgs { pub pipe: String, pub ui_pid: u32, pub ui_created_at: u64, pub token: SessionToken }` ; `EngineArgs::parse(args: &[String]) -> Result<Option<Self>, String>` sur `--engine --pipe <nom> --ui-pid <pid> --ui-created <horodatage> --token <hex>` : sans `--engine` → `Ok(None)` (mode IHM) ; `--engine` avec un argument inconnu ou une valeur manquante → `Err`, et `orion.exe` sort avec le code 2 sans rien démarrer.
  - `pub enum LifecycleEvent { ParentMissing, HelloRefused, ClientLeft, ShutdownRequested, EventsOverflowed, ConnectTimeout }` ; `pub fn on_event(event: LifecycleEvent) -> Action` où `Action` vaut toujours `TeardownAndExit` : aucune issue ne laisse le moteur servir après la perte de son IHM.
  - `pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);`
  - `engine_host::run(args: EngineArgs) -> i32` : restreint d'abord la recherche de DLL (`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`) ; vérifie qu'il est élevé ; ouvre le parent (`OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)`) et compare son heure de création à `ui_created_at` ; crée le tube ; attend la connexion au plus `CONNECT_TIMEOUT` ; vérifie le client (tâche 8) ; `serve` ; à toute issue, démonte (`VpnController::disconnect`, libération du PSK, suppression de l'adaptateur) et rend le code de sortie. Il ne crée aucune fenêtre et n'initialise pas Tauri.
  - `engine_launch::start() -> Result<EngineClient, String>` : tire le nonce et le jeton, `ShellExecuteExW` (verbe `runas`, `SEE_MASK_NOCLOSEPROCESS`, `SW_HIDE`), se connecte, envoie le `Hello`. `ERROR_CANCELLED` (1223) → « Orion a besoin de l'autorisation administrateur pour monter le tunnel. » ; puis surveille le processus moteur : sa fin → boîte de dialogue « Le moteur d'Orion s'est arrêté : Orion va se fermer. » et sortie.
  - `main.rs` : `EngineArgs::parse` avant toute initialisation Tauri ; sinon l'IHM démarre, enregistre `tauri-plugin-single-instance` **avant** `engine_launch::start()` (un second lancement ramène la fenêtre au premier plan et sort sans UAC), et ne montre sa fenêtre qu'après le `Hello` accepté. « Quitter » (menu de notification) envoie `EngineCommand::Shutdown`, attend la fin du moteur au plus 10 s, puis quitte. La fermeture de session suit le même chemin (`RunEvent::ExitRequested`) ; si l'IHM est tuée avant, la surveillance du parent par le moteur prend le relais.

- [ ] **Step 1 : tests rouges** : `every_lifecycle_event_tears_down_and_exits`, `engine_args_need_every_field` (un champ manquant → `Err`), `no_engine_flag_is_ui_mode`, `an_unknown_argument_in_engine_mode_is_refused`, `a_parent_gone_before_the_engine_starts_stops_it` (prédicat portable `parent_matches(expected_created_at, observed: Option<u64>) -> bool` : `None` ou heure différente → faux).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-engine lifecycle` → échec.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** tests portables verts ; Linux inchangé (`cargo run -p orion` sans moteur séparé) ; **Windows** : recette points 1 à 9.
- [ ] **Step 5 :** commit `feat(orion): an elevated engine bound to the UI that launched it`.

### Task 10 : racine protégée par utilisateur

**Files :**
- Create : `crates/orion-core/src/protected_root/windows.rs`, `crates/orion-core/src/protected_root/tests.rs`
- Modify : `crates/orion-core/src/protected_root.rs` (tâche 4)
- Modify : `crates/orion-core/src/config.rs:848` (`ClientConfig::path`), `crates/orion-core/src/vault/store.rs:171` (`default_dir`), `crates/orion-core/src/identity_store.rs:462` (`for_current_user`), `apps/orion/src-tauri/src/main.rs` (`init_logging`)

**Interfaces :**
- Produces :
  - `EnginePaths::for_current_user()` (tâche 4) : Windows → `%ProgramData%\helios\orion\<SID>\{config,vault,identities,orion.log}` ; ailleurs → les chemins `ProjectDirs` actuels, inchangés.
  - `pub struct Ace { pub sid: String, pub allow: bool, pub mask: u32, pub inherited: bool }` ; `pub fn admits_only_admins(aces: &[Ace], protected: bool) -> bool` : vrai si la DACL est protégée et que chaque ACE d'autorisation vise `S-1-5-32-544` (Administrateurs) ou `S-1-5-18` (SYSTEM).
  - Windows : `ensure_protected_dir(path) -> Result<(), String>` (crée avec une DACL protégée Administrateurs + SYSTEM, contrôle total, héritée aux enfants ; si le dossier existe, lit sa DACL et refuse si `admits_only_admins` est faux : « Le dossier protégé d'Orion est accessible à un compte non administrateur : démarrage refusé. »).
  - `ORION_CONFIG` et `ORION_IDENTITY_DIR` ne sont lus qu'en `cfg(debug_assertions)`.

- [ ] **Step 1 : tests rouges** : `an_admin_and_system_only_dacl_is_accepted`, `a_user_allow_ace_is_refused`, `an_unprotected_dacl_is_refused`, `deny_aces_do_not_widen_access` (une ACE de refus pour un utilisateur ne rend pas la DACL invalide), `the_protected_root_is_per_user_sid` (deux SID → deux racines), `every_engine_path_is_under_the_protected_root`, `release_builds_ignore_path_overrides` (le résolveur prend un drapeau `allow_overrides: bool` ; faux → la variable est ignorée).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core protected_root` → échec.
- [ ] **Step 3 :** implémenter ; brancher les quatre résolveurs et le journal sur `EnginePaths`.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-core` et `-p orion-engine` verts ; **Windows** : recette points 13 et 14.
- [ ] **Step 5 :** commit `feat(orion-core): a per-user root only elevated processes may open`.

### Task 11 : clé TPM machine

**Files :**
- Modify : `crates/orion-core/src/vault/windows/tpm.rs`, `crates/orion-core/src/vault/windows/mod.rs`, `crates/orion-core/src/vault/store.rs` (`Bootstrap.key_slot`)
- Create : `crates/orion-core/src/vault/windows/tpm/tests.rs` si absent

**Interfaces :**
- Produces :
  - `pub fn machine_key_slot(user_sid: &str) -> String` → `"Helios Orion device root v2 <SID>"` ; l'actuel `KEY_NAME` reste la tranche v1, lue seulement par la migration.
  - `pub enum KeyScope { User, Machine }` passé au fournisseur TPM : `Machine` ouvre et crée avec `NCRYPT_MACHINE_KEY_FLAG` et pose `NCRYPT_SECURITY_DESCR_PROPERTY` (DACL Administrateurs + SYSTEM) avant `NCryptFinalizeKey` ; la vérification existante (fournisseur, non-exportabilité, module) s'applique aux deux portées, et `Machine` relit en plus la DACL de la clé avec `admits_only_admins`.

- [ ] **Step 1 : tests rouges** (portables) : `machine_key_slots_are_per_user_sid`, `a_machine_slot_never_equals_the_user_slot`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core machine_key` → échec.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** tests portables verts ; **Windows** : `cargo test -p orion-core --features wireguard` ; recette point 13 (clé inutilisable depuis un processus non élevé).
- [ ] **Step 5 :** commit `feat(orion-core): the device root under an admin-only machine TPM key`.

### Task 12 : migration du coffre

**Files :**
- Create : `crates/orion-core/src/vault/relocation.rs`, `crates/orion-core/src/vault/relocation/tests.rs`
- Modify : `crates/orion-engine/src/service.rs` (`EngineService::open` migre avant d'ouvrir)

**Interfaces :**
- Consumes : `RootKeyProvider` (`vault/mod.rs:130`), `EnginePaths` (tâche 4, résolution de la tâche 10), `KeyScope` (tâche 11)
- Produces :
  - `pub struct LegacyLayout { pub config_dir: PathBuf, pub identities_dir: PathBuf }`
  - `pub fn relocate(legacy: &LegacyLayout, paths: &EnginePaths, unwrap_legacy: &dyn RootKeyProvider, wrap_new: &dyn RootWrapper) -> Result<Relocation, VaultError>` ; `pub enum Relocation { NothingToMove, Moved { profiles: usize, identities: usize }, AlreadyDone }` ; `pub trait RootWrapper { fn wrap(&self, root: &DeviceRootKey, into: &Path) -> Result<(), VaultError>; }`.

Algorithme, que la signature ne fixe pas :
1. si `paths.vault` existe et s'ouvre : `AlreadyDone`, et supprimer l'ancien s'il reste ;
2. supprimer un éventuel `<vault>.relocating` laissé par un arrêt brutal ;
3. déballer la racine avec `unwrap_legacy` (la racine ne change pas : profils et registre restent chiffrés sous elle, on les copie sans les rechiffrer) ;
4. copier l'arbre de configuration et les identités dans `<root>.relocating`, sauf `device-root`, puis `wrap_new.wrap` y écrit le nouveau `device-root` et `Bootstrap.key_slot` reçoit la tranche machine ;
5. `fsync`, ouvrir le `ProfileStore` de `<root>.relocating` avec le nouveau fournisseur et relire chaque profil du registre et chaque identité ; un échec supprime `<root>.relocating`, laisse l'ancien intact et rend l'erreur ;
6. renommer `<root>.relocating` en racine, puis supprimer l'ancien arbre et la clé TPM v1.

- [ ] **Step 1 : tests rouges** avec des fournisseurs factices : `a_legacy_vault_is_moved_and_reopens`, `a_failed_verification_leaves_the_legacy_vault_intact`, `a_leftover_relocation_from_a_crash_is_discarded`, `an_already_relocated_vault_is_left_alone`, `nothing_to_move_on_a_fresh_install`, `profiles_are_copied_not_reencrypted` (octets des fichiers de profil identiques avant et après).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core relocation` → échec.
- [ ] **Step 3 :** implémenter ; message de l'IHM sur échec : « La migration du coffre a échoué : l'ancien coffre est conservé. Cause : … ».
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-core` vert ; **Windows** : recette point 12.
- [ ] **Step 5 :** commit `feat(orion-core): move the vault under the protected root`.

### Task 13 : installation pour la machine et refus d'un exécutable modifiable

**Files :**
- Modify : `apps/orion/src-tauri/tauri.windows.conf.json` (`bundle.windows.nsis.installMode: "perMachine"`), `tools/xtask/src/main.rs` (test), `apps/orion/src-tauri/src/engine_host.rs`

**Interfaces :**
- Consumes : `Ace`, `admits_only_admins` (tâche 10)
- Produces : `engine_host::executable_dir_is_protected() -> Result<(), String>` appelé en release avant toute autre action du moteur : lit la DACL du dossier de `std::env::current_exe()` et refuse si un compte non administrateur peut y écrire (`FILE_WRITE_DATA`, `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `WRITE_DAC`, `WRITE_OWNER`, `DELETE`) : « Orion est installé dans un dossier modifiable sans droits administrateur : démarrage refusé. » La règle d'écriture est une fonction portable `grants_user_write(aces: &[Ace]) -> bool`.

- [ ] **Step 1 : tests rouges** : `an_executable_directory_writable_by_a_user_is_refused`, `a_program_files_like_dacl_is_accepted` (Administrateurs et SYSTEM en contrôle total, `S-1-5-32-545` Utilisateurs en lecture et exécution), et dans `xtask` `the_nsis_bundle_installs_per_machine`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-engine grants` et `-p xtask nsis` → échec.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** verts ; **Windows** : recette point 12, second alinéa.
- [ ] **Step 5 :** commit `feat(orion): install per machine and refuse to elevate from a writable directory`.

### Task 14 : documentation et recette

**Files :**
- Modify : `docs/adr/ADR-004-CHAINE-DE-LIVRAISON.md` (la limite « Orion s'exécute entièrement en administrateur » devient la description de la frontière moteur/IHM et de ses limites, dont le pilotage de l'IHM par un programme du même compte), `docs/adr/ADR-006-*.md` (coffre réservé à l'élévation, clé TPM machine, limite des autres administrateurs, migration), `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md` (le sidecar disparaît : les cérémonies vivent dans l'IHM non élevée), `docs/security/ORION-DISTRIBUTION.md`, `docs/testing/MANUAL-TESTING.md` (section « Séparation des privilèges (F11) » : les 14 points de la spec §13), `docs/testing/TESTING.md` (mention de `helios-astra-helper.exe` retirée), `docs/ROADMAP.md` (F11 : code livré, validation Windows à faire), `docs/architecture/CRATE-REORGANIZATION.md` (`orion-engine` ajouté, `helios-astra-helper` retiré)

- [ ] **Step 1 :** rédiger.
- [ ] **Step 2 :** `grep -rn "requireAdministrator\|helios-astra-helper" docs --include=*.md | grep -v superpowers` : seules restent des mentions au passé.
- [ ] **Step 3 :** régression complète en arrière-plan → exit 0, `cargo audit` 7 avertissements autorisés.
- [ ] **Step 4 :** commit `docs: describe the engine and UI split`.

---

L'ordre des tâches est le numéro, sauf la tâche 7 qui ne se fusionne qu'avec la 9 : sans moteur élevé, WireGuard-NT ne se charge plus.
