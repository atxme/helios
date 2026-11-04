# F14 lot 5a — La porte unique d'Astra — plan d'exécution

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Une seule fonction du service Astra ouvre toute campagne et porte toute écriture de son état ; la console devient cliente d'un socket Unix local, `heliosd` relaie depuis le tunnel trois ouvertures pour les pairs administrateurs, et un verrou du volume garantit un seul écrivain à la fois.

**Architecture:** Nouveau module de bibliothèque `astra::door` : types fermés (`DoorRequest`, `DoorOutcome`, `DoorRefusal`, `DoorConnector`), table de politique par connecteur, bornes et unicité, puis la résolution et la signature reprises des commandes du binaire (`commands/*.rs`, `campaign_deposit.rs`). Deux connecteurs l'appellent : `astra::door::local` (socket Unix servi par `astra run`) et la route privée `POST /internal/v1/operator/campaigns` (relayée par `heliosd`). Le binaire `astra` ne garde que l'analyse des arguments, l'affichage et le chemin local sous verrou quand le service est arrêté.

**Tech Stack:** Rust (aether, astra-channel, astra, helios-api, heliosd), axum 0.8, tokio, hyper 1 / hyper-util 0.1 (déjà dans le workspace).

**Spec:** `docs/superpowers/specs/2026-11-02-f14-lot5a-porte-unique-design.md` (§5 tranche les détails ; §5.9 a été corrigé après approbation : verrou du volume).

## Global Constraints

- Worktree `/home/christophe/helios-wt/f14-lot5a`, branche `feat/f14-lot5a-porte-unique`. Ne jamais travailler dans `~/helios`.
- Compiler et tester uniquement par `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo …` ; jamais `CARGO_TARGET_DIR`, jamais `cargo clean`, ne tuer aucun processus. Si un test pend, le signaler.
- Avant chaque commit : `scripts/wsl-cargo fmt` sur les crates touchés et `scripts/wsl-cargo clippy -p <crate> --all-targets --all-features -- -D warnings`.
- Aucune nouvelle dépendance externe. `hyper` et `hyper-util` s'ajoutent à `crates/astra/Cargo.toml` en `workspace = true` (déjà déclarés à la racine).
- `scripts/deploy.sh` n'est pas modifié, et doit continuer de fonctionner : `pin-ca-tls` service arrêté (conteneur jetable), `init-channel` et `status` par `exec` service en marche.
- Pas d'`unwrap`/`expect` hors tests ; aucun TODO/FIXME ; identifiants, commentaires et tests en anglais ; messages de la console et `docs/` en français.
- Aucun secret journalisé ni renvoyé : clé de service, clés de délégation privées, jetons de capacité. Les jetons restent émis par les routes existantes, jamais par la porte.
- L'origine publique ne gagne aucune route : `/v1/campaigns` reste `operator_credential_required`.
- Les refus publics du tunnel restent grossiers (§8.5.4) ; le détail va aux journaux. La console, locale, reçoit la phrase complète.
- Pas de changement de `SigningOperationView`, d'`OperatorPendingOperation` ni d'aucun type `deny_unknown_fields` existant : `astra-signer` et Orion déjà livrés doivent continuer de les lire.
- Commits terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- **Une réponse d'ouverture perdue dans le tunnel, puis un nouvel essai** : refusé `AlreadyOpen`, et `pending` montre toujours une seule opération, que l'opérateur peut approuver. Test : Task 2 `a_retried_open_is_refused_and_the_first_stays_pending`.
- **Un `requested_by` qui contient déjà un faux suffixe d'identité** (`"alice — pair wireguard:AAAA…"`) : le texte est gardé tel quel et le vrai suffixe ajouté après, si bien que la dernière identité affichée est toujours la vraie. Test : Task 2 `a_forged_identity_suffix_is_kept_and_the_real_one_appended`.
- **Un socket périmé après un arrêt brutal du service** : `astra run` le remplace s'il s'agit d'un socket (jamais un autre fichier), et une écriture de la console qui obtient le verrou le traite comme « service arrêté ». Tests : Task 6 `a_stale_socket_is_replaced_but_a_regular_file_is_not`, `a_write_with_a_stale_socket_and_a_free_lock_writes_locally`.
- **`pin-ca-tls` service en marche, puis une rotation sans redémarrage** : la campagne `trust_authorities` porte deux cibles (CA-PQ et CA-TLS). Test : Task 5 `a_pinned_ca_tls_is_a_target_without_restart`.
- **Un `astra run` lancé pendant qu'une console tient le volume** (amorçage de `deploy.sh` puis `up -d` trop tôt) : refus de démarrer par son nom, aucun fichier touché. Test : Task 5 `the_service_does_not_start_while_the_volume_is_held`.

---

### Task 1: Types de l'ouverture par le tunnel (aether, astra-channel)

**Files:**
- Modify: `crates/aether/src/certificates/transport.rs` (à côté d'`OperatorPendingOperation`)
- Modify: `crates/astra-channel/src/authority_routes.rs`, `crates/astra-channel/src/authority_client.rs`, `crates/astra-channel/src/lib.rs` (réexports), `crates/astra-channel/src/tests.rs`

**Interfaces:**
- Produces (aether, serde `snake_case`, `deny_unknown_fields`, nouveaux types seulement) :
  - `enum OperatorOpenAction { FleetLeafs, TrustAuthorities, ClientRevocation { peer: WireGuardKey } }` (`#[serde(tag = "action")]`).
  - `struct OperatorOpenRequest { action: OperatorOpenAction, reason: String, requested_by: String, window_secs: u64 }` (`window_secs` `#[serde(default = …)]` à 300).
  - `struct RevocationExpiries { tls_not_after: Option<u64>, pq_not_after: Option<u64> }`.
  - `struct OperatorOpened { operation_id: Id16, campaign_id: Id16, campaign_fingerprint: Fingerprint, scope: CampaignScope, target_count: usize, required_credentials: u8, expires_at: u64, revocation_expiries: Option<RevocationExpiries> }` (`skip_serializing_if = "Option::is_none"`).
- Produces (astra-channel) : `pub const OPERATOR_OPEN_ROUTE: &str = "/internal/v1/operator/campaigns"` ; `struct RelayedOperatorOpen { operator: OperatorIdentity, request: OperatorOpenRequest }` (`deny_unknown_fields`) ; `AuthorityClient::operator_open(&self, relayed: &RelayedOperatorOpen) -> Result<OperatorOpened, ChannelError>` par `post_bounded` (corps ≤ `MAX_OPERATOR_RELAY_BODY_BYTES`, réponse ≤ `MAX_OPERATOR_ANSWER_BYTES`).

- [ ] **Step 1: Write the failing tests** : dans le `mod tests` de `transport.rs`, `an_open_request_spells_its_action` (`{"action":"client_revocation","peer":…}`), `an_open_request_defaults_its_window_to_300`, `an_opened_answer_omits_absent_expiries`, `an_open_request_refuses_unknown_fields` ; dans `astra-channel/src/tests.rs`, `a_relayed_open_carries_the_operator_and_the_request`.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether transport` puis `-p astra-channel` → FAIL (types absents).
- [ ] **Step 3: Implement** les types et la méthode cliente.
- [ ] **Step 4: Run** les mêmes tests, clippy sur `aether` et `astra-channel` → PASS.
- [ ] **Step 5: Commit** — `feat(aether): describe an operator opening relayed from the tunnel`

### Task 2: Le cœur de la porte (astra::door) — politique, bornes, parc et autorités

**Files:**
- Create: `crates/astra/src/door/mod.rs` (types, `AstraService::door`, politique), `crates/astra/src/door/open.rs` (bornes, unicité, construction et signature de la campagne), `crates/astra/src/door/resolve.rs` (résolution des cibles), `crates/astra/src/door/tests.rs` (dont la fixture)
- Modify: `crates/astra/src/lib.rs` (`pub mod door;`), `crates/astra/src/signing.rs` (requête d'unicité sur le magasin)
- Source à reprendre (déplacée, pas recopiée ; l'appel du binaire est rebranché en Task 6) : `crates/astra/src/campaign_deposit.rs::open_campaign` et `::deposit_campaign` ; `crates/astra/src/commands/campaign.rs::{fleet_leaf_rows, client_tls_ca_row}`

**Interfaces:**
- Consumes : Task 1 (`OperatorOpenRequest`, `OperatorOpened`, `RevocationExpiries`).
- Produces :
  - `enum DoorConnector { Console { uid: u32 }, Tunnel { operator: astra_channel::OperatorIdentity } }`.
  - `enum DoorRequest` — ouvertures `{ FleetLeafs, TrustAuthorities, ClientRevocation { peer }, GatewayRevocation, GatewayIdentity, ChainOpen, ChainNext, ChainAbandon, IssuerDelegation }` portant chacune un `OpeningText { reason, requested_by, window_secs }` ; non-ouvertures `IssuerRequest`, `PinCaTls { fingerprint: Fingerprint }`, `IssuerInstall { authorization: Box<AstraIssuerAuthorization> }`, `GatewayIdentityPublish { epoch: u64 }`. Sérialisable (`Serialize`/`Deserialize`, `deny_unknown_fields`) : c'est le corps du socket local.
  - `impl From<OperatorOpenRequest> for DoorRequest`.
  - `enum DoorOutcome { Opened(OperatorOpened), ... }` — une variante par réponse de non-ouverture, ajoutée par la tâche qui la produit.
  - `enum DoorRefusal` (`thiserror`, phrase française complète) : `NotAllowedHere`, `TextMissing`, `WindowOutOfRange`, `AlreadyOpen { operation_id: Id16 }`, `NoTarget`, `TooManyTargets`, `NoVault`, `PeerUnknown`, `PeerRevoked`, `GatewayChannelUnavailable`, `Store(SigningError)`, `Registry(String)`, `Internal`. `fn class(&self) -> ServiceError` pour le tunnel.
  - `pub fn allowed(connector: &DoorConnector, request: &DoorRequest) -> bool` — exactement le tableau du §5.2.
  - `impl AstraService { pub async fn door(&self, connector: DoorConnector, request: DoorRequest, now_unix: u64) -> Result<DoorOutcome, DoorRefusal> }` — politique d'abord, puis l'action ; journalise chaque ouverture et chaque refus (connecteur, action, `operation_id`).
  - `SigningOperationStore::live_conflict(&self, scope: CampaignScope, targets: &[CampaignTarget], now_unix: u64) -> Option<Id16>` : une opération `AwaitingOperator` non expirée de la même `CampaignFamily` ; pour `Revocation`, seulement si elle vise la même `identity_key`.
  - `#[cfg(test)] pub(crate) fn fixture(dir: &Path) -> Arc<AstraService>` dans `door/tests.rs` : registre amorcé avec deux pairs admis, clé de service, coffre chiffré factice, sans canal gateway ; `fixture_with_ca_tls(dir)` avec une CA-TLS épinglée.

- [ ] **Step 1: Write the failing tests** (`door/tests.rs`) :
  - `the_policy_table_is_exactly_the_specification` : pour chaque `DoorRequest` et chaque connecteur, `allowed` rend la valeur du §5.2 (tunnel : seulement `FleetLeafs`, `TrustAuthorities`, `ClientRevocation`).
  - `a_tunnel_cannot_reach_a_console_action` : `ChainOpen` par `Tunnel` → `NotAllowedHere`, rien dans `signing`.
  - `fleet_leafs_targets_every_admitted_peer` (2 cibles), `trust_authorities_targets_ca_pq_alone_without_a_pinned_ca_tls` (1), `trust_authorities_targets_both_with_a_pinned_ca_tls` (2).
  - `an_opening_needs_its_text` (`reason` ou `requested_by` blanc → `TextMissing`), `the_window_is_one_to_three_hundred_seconds` (0 et 301 refusés, 300 accepté).
  - `a_retried_open_is_refused_and_the_first_stays_pending` : deuxième `FleetLeafs` → `AlreadyOpen { operation_id }` égal au premier ; `signing.pending(…)` en compte un.
  - `an_expired_opening_does_not_block_the_next` : `now_unix` au-delà de `expires_at` → nouvelle ouverture acceptée.
  - `an_anchor_opening_without_a_vault_is_refused` → `NoVault`.
  - `a_forged_identity_suffix_is_kept_and_the_real_one_appended` : par `Tunnel { WireGuard { k } }`, `requested_by = "alice — pair wireguard:AAAA"` → la campagne porte `"alice — pair wireguard:AAAA — pair wireguard:<k>"` ; par `Console`, le texte est inchangé.
  - `the_signer_request_verifies_under_the_service_key` : la demande de l'opération ouverte vérifie sous `service_public_key`.
- [ ] **Step 2: Run** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra door` → FAIL.
- [ ] **Step 3: Implement** : le module, la politique, `live_conflict`, puis `open.rs` (contenu d'`open_campaign` + `deposit_campaign` : bornes, coffre via `service.encrypted_vault`, pin de politique, `validate`, `AstraSignerRequest` signée par `service.service_private_key`, puis `SigningOperation::new` et `store.open` directement, sans fichier), et `resolve.rs` pour `FleetLeafs`/`TrustAuthorities` sur `service.registry`. Le suffixe tunnel est ` — pair wireguard:<clé>` (et ` — pair dev-loopback` pour `DevLoopback`). Les fonctions du binaire restent en place jusqu'à la Task 6 ; aucun doublon de logique : le binaire appellera la porte.
- [ ] **Step 4: Run** les tests, clippy `-p astra` → PASS.
- [ ] **Step 5: Commit** — `feat(astra): open campaigns through a single door in the service`

### Task 3: Révocations et identité gateway par la porte

**Files:**
- Modify: `crates/astra/src/door/resolve.rs`, `crates/astra/src/door/open.rs`, `crates/astra/src/door/tests.rs`
- Source à reprendre : `crates/astra/src/commands/revocation.rs` (client et gateway : résolution, échéances signées) et `crates/astra/src/commands/gateway_identity.rs::gateway_identity_open` (y compris l'export public `gateway-active-certificate.json` dans le volume)

**Interfaces:**
- Consumes : Task 2.
- Produces : `ClientRevocation`, `GatewayRevocation` et `GatewayIdentity` traités par `door` ; les deux révocations passent par les mêmes bornes que les autres ouvertures (fin des contrôles recopiés) ; `OperatorOpened::revocation_expiries` renseigné (client : les deux moitiés à la même échéance de génération ; gateway : `tls_not_after` et `pq_not_after` lus en direct). Les lectures gateway passent par `service.gateway` (`GatewayChannel::gateway_identity`) ; `None` → `GatewayChannelUnavailable`.

- [ ] **Step 1: Write the failing tests** : `a_client_revocation_carries_its_signed_expiry` (égale au `not_after` de la génération active du pair), `two_peers_can_be_revoked_at_once` (deux `ClientRevocation` de pairs distincts acceptées), `the_same_peer_cannot_be_revoked_twice_at_once` (`AlreadyOpen`), `an_unknown_peer_is_refused` (`PeerUnknown`), `a_revoked_peer_is_refused` (`PeerRevoked`), `gateway_openings_need_the_service_channel` (`GatewayRevocation` et `GatewayIdentity` sans canal → `GatewayChannelUnavailable`). Si le canal gateway peut être monté en test sur la boucle locale comme dans `crates/astra/tests/private_channel.rs`, ajouter `a_gateway_revocation_reads_both_expiries_live` ; sinon le dire dans le rapport.
- [ ] **Step 2: Run** `… test -p astra door` → FAIL.
- [ ] **Step 3: Implement** en déplaçant la résolution depuis les deux fichiers de commandes.
- [ ] **Step 4: Run** → PASS ; clippy.
- [ ] **Step 5: Commit** — `feat(astra): resolve revocations and the gateway identity at the door`

### Task 4: Chaîne et délégation d'émetteur par la porte

**Files:**
- Modify: `crates/astra/src/door/mod.rs`, `crates/astra/src/door/open.rs`, `crates/astra/src/door/tests.rs` ; Create: `crates/astra/src/door/chain.rs`, `crates/astra/src/door/issuer.rs`
- Source à reprendre : `crates/astra/src/commands/chain.rs` (`chain_open`, `chain_next`, `chain_abandon` ; plan `astra::chain::CHAIN_PLAN_FILE`) et `crates/astra/src/commands/issuer.rs::issuer_request` (matériel aux chemins `astra::issuer::{pq_key_path, tls_key_path}`)

**Interfaces:**
- Consumes : Tasks 2-3.
- Produces :
  - `DoorOutcome::ChainStep { opened: Option<OperatorOpened>, delegation_request: Option<String>, remaining: usize }` et `DoorOutcome::ChainAbandoned`.
  - `DoorOutcome::IssuerRequested { request: String, opened: Option<OperatorOpened> }` — `request` est la demande publique, exactement le JSON qu'imprime aujourd'hui `issuer request` ; `IssuerDelegation` l'ouvre en campagne, `IssuerRequest` non.
  - Le service écrit le plan et le matériel dans le volume, aux mêmes noms qu'aujourd'hui ; jamais à un chemin fourni par l'appelant.

- [ ] **Step 1: Write the failing tests** : `the_chain_opens_its_first_step_and_records_the_plan` (fichier de plan présent, `remaining` égal à celui de `chain open` aujourd'hui), `a_chain_step_and_a_fleet_campaign_block_each_other` (même famille → `AlreadyOpen`), `chain_next_refuses_a_step_that_has_not_landed` (refus actuel de `assert_current_landed` conservé), `an_issuer_request_writes_its_keys_and_returns_the_public_request` (les deux fichiers existent, la demande est du JSON valide), `an_issuer_request_without_text_opens_nothing` (`IssuerRequest` : `opened` est `None`, `signing` vide).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS ; clippy.
- [ ] **Step 5: Commit** — `feat(astra): drive the chain and the issuer request from the door`

### Task 5: Écritures par la porte et verrou du volume

**Files:**
- Create: `crates/astra/src/door/write.rs`, `crates/astra/src/door/lock.rs`
- Modify: `crates/astra/src/door/mod.rs`, `crates/astra/src/door/tests.rs`, `crates/astra/src/daemon.rs` (prise du verrou au début de `run`)
- Source à reprendre : `crates/astra/src/commands/trust_domain.rs::pin_ca_tls`, `crates/astra/src/commands/issuer.rs::issuer_install` (même `astra::issuer::adopt` que `service.rs:994`), `crates/astra/src/commands/gateway_identity.rs::gateway_identity_publish`

**Interfaces:**
- Consumes : Tasks 2-4.
- Produces :
  - `pub struct VolumeLock` (garde le `File` verrouillé ; relâché au `Drop`) ; `pub const VOLUME_LOCK_FILE: &str = "astra.lock"` ; `VolumeLock::try_acquire(state_dir: &Path) -> std::io::Result<Option<VolumeLock>>` (`None` = tenu ailleurs) par `std::fs::File::try_lock`.
  - Fonctions d'écriture partagées par les deux chemins, sur un `&mut AstraRegistry` : `write::pin_ca_tls(registry, fingerprint, now) -> Result<Fingerprint /*audit head*/, DoorRefusal>`, `write::issuer_install(registry, state_dir, authorization, now) -> Result<IssuerInstalled, DoorRefusal>`, et pour la publication une fonction async qui prend le registre et le `GatewayChannel`. La porte les appelle sous `service.registry` ; le binaire (Task 6) les appelle sur un registre chargé sous `VolumeLock`.
  - `DoorOutcome::Pinned { audit_head }`, `DoorOutcome::IssuerInstalled { issuer_epoch, not_after, audit_head }`, `DoorOutcome::Published { epoch, confirmed: bool }`. `issuer install` dit toujours « redémarrer Astra pour la charger » : le délégataire actif reste lu au démarrage.
  - `daemon::run` prend `VolumeLock` avant de charger le registre ; tenu ailleurs → erreur « un autre processus tient /var/lib/astra : rien n'a démarré ».

- [ ] **Step 1: Write the failing tests** : `a_pinned_ca_tls_is_a_target_without_restart` (porte : `PinCaTls` puis `TrustAuthorities` → 2 cibles, sans recharger), `a_pinned_anchor_is_never_replaced` (refus actuel conservé), `an_installed_delegation_is_recorded_in_memory_and_on_disk`, `a_publication_is_marked_before_the_relay` (marque persistée même si le relais échoue ; rejouable), `the_lock_is_exclusive` (deuxième `try_acquire` → `None`, libre après `drop`), `the_service_does_not_start_while_the_volume_is_held` (dans `crates/astra/tests/cli.rs` : verrou pris par le test, `astra run` sort en échec avec le message, registre inchangé).
- [ ] **Step 2: Run** `… test -p astra door` et `… test -p astra --test cli` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS ; clippy.
- [ ] **Step 5: Commit** — `feat(astra): make the service the only writer of its state while it runs`

### Task 6: Connecteur console — socket local, console cliente, retrait de l'inbox

**Files:**
- Create: `crates/astra/src/door/local.rs` (serveur du socket), `crates/astra/src/console.rs` (client du binaire)
- Modify: `crates/astra/Cargo.toml` (`hyper`, `hyper-util` en `workspace = true`), `crates/astra/src/daemon.rs` (sert le socket ; balayage `forget_expired_transitions` sur son propre intervalle de `INBOX_POLL_INTERVAL_SECS` renommé), `crates/astra/src/main.rs` (chaque sous-commande d'ouverture et d'écriture passe par `console` ; retrait de `--gateway-channel`/`--gateway-certificate` de `revocation open`, `gateway-identity open` et `gateway-identity publish`), `crates/astra/src/commands/*.rs` (ne gardent que l'affichage, sorties inchangées), `crates/astra/src/signing.rs` (retrait de `CAMPAIGN_INBOX_DIR`, `MAX_INBOX_ENTRY_BYTES`, `CampaignDeposit`, `adopt_deposit`)
- Delete: `crates/astra/src/campaign_deposit.rs` (`load_encrypted_vault` va dans `daemon.rs`, seul appelant restant)
- Test: `crates/astra/tests/cli.rs`

**Interfaces:**
- Consumes : Tasks 2-5.
- Produces :
  - `pub const DOOR_SOCKET_FILE: &str = "operator.sock"` ; `door::local::serve(path: &Path, service: Arc<AstraService>) -> anyhow::Result<()>` : remplace seulement un socket périmé (jamais un autre type de fichier, comme `helios-api/src/local.rs::bind`), mode `0600`, une seule route `POST /door` (corps `DoorRequest`, ≤ 64 Kio ; réponse `DoorOutcome` ou `{ "refusal": "<phrase>" }`), `DoorConnector::Console { uid }` lu par `UnixStream::peer_cred`. Socket retiré à l'arrêt propre.
  - `console::call(state_dir: &Path, request: &DoorRequest) -> anyhow::Result<DoorOutcome>` (HTTP/1 sur `tokio::net::UnixStream` par `hyper::client::conn::http1`).
  - Routage d'une écriture par la console : `VolumeLock::try_acquire` → obtenu : chemin local (fonctions `door::write::*` sur le registre du disque), verrou gardé jusqu'à la fin ; tenu : `console::call` ; tenu et socket muet : « un autre processus tient le volume ». Une ouverture : `console::call`, et socket absent ou muet → « le service Astra ne tourne pas : rien n'a été ouvert ». `bootstrap` exige le verrou.

- [ ] **Step 1: Write the failing tests** (`tests/cli.rs`, qui lance le vrai binaire) : `an_opening_without_the_service_is_refused_and_writes_nothing` (aucun fichier créé dans le volume), `pin_ca_tls_with_the_service_stopped_writes_locally` (le chemin de `deploy.sh`), `a_write_with_a_stale_socket_and_a_free_lock_writes_locally`, `bootstrap_refuses_while_the_volume_is_held` ; et si `astra run` peut être lancé en test sur un port libre (`--bind 127.0.0.1:0` ou port tiré) : `campaign_open_goes_through_the_running_service` (identifiant imprimé ; une seconde ouverture identique est refusée `AlreadyOpen`, preuve que la première est dans le magasin du service), `revocation_open_prints_the_full_revoke_line`. Dans `door/local.rs` : `a_stale_socket_is_replaced_but_a_regular_file_is_not`, `the_socket_is_owner_only`. Contrôle par recherche, en test : `no_console_command_reads_the_service_key_or_writes_the_registry` (les fichiers `commands/*.rs` et `console.rs` ne nomment ni `SERVICE_KEY_FILE` ni `AstraRegistry::load` hors `bootstrap`, `status` et le chemin local sous verrou de `door::write`).
- [ ] **Step 2: Run** `… test -p astra` → FAIL.
- [ ] **Step 3: Implement** ; migrer chaque sous-commande, puis seulement retirer l'inbox et `campaign_deposit.rs`. `status` reste une lecture du fichier (choix laissé par la spec §9 : le plus simple, et `deploy.sh` le lance service arrêté comme en marche).
- [ ] **Step 4: Run** `… test -p astra` → PASS ; clippy ; `scripts/wsl-cargo build -p astra`.
- [ ] **Step 5: Commit** — `feat(astra): turn the console into a connector of the door`

### Task 7: Connecteur tunnel — route privée d'Astra et relais heliosd

**Files:**
- Modify: `crates/astra/src/operator.rs` (route `OPERATOR_OPEN_ROUTE`, handler `open`), `crates/helios-api/src/certificates/operator_relay.rs` (méthode `open` du trait, handler `operator_open`), `crates/helios-api/src/lib.rs` (route `POST /api/certificates/operator/campaigns`), `crates/heliosd/src/astra_channel.rs` (impl par `AuthorityClient::operator_open`), `crates/helios-api/src/certificates/tests.rs` (`SpyCampaign`)
- Test: `crates/astra/src/door/tests.rs` ou `crates/astra/tests/private_channel.rs`, `crates/helios-api/src/certificates/tests.rs`

**Interfaces:**
- Consumes : Task 1 (`RelayedOperatorOpen`, `OperatorOpened`, `operator_open`), Task 2 (`AstraService::door`, `DoorRefusal::class`).
- Produces :
  - Astra : `open(State, Json<RelayedOperatorOpen>)` → `service.door(DoorConnector::Tunnel { operator }, request.into(), now)` ; `Opened` → `200` + `OperatorOpened` ; refus → `refuse(&operator, "open", refusal.class())`, phrase complète au journal.
  - helios-api : `async fn open(&self, operator: &OperatorIdentity, request: OperatorOpenRequest) -> Result<OperatorOpened, TrustUpdateRefusal>` ; handler derrière `operator_caller(&caller, "open")`, corps ≤ `MAX_OPERATOR_REQUEST_BYTES` (`413` au-delà), illisible → `400`, relais absent → `operator_unavailable` (`503`), monté au même endroit que `signer-results` pour hériter du contrôle d'origine des mutations.

- [ ] **Step 1: Write the failing tests** : helios-api `a_non_admin_cannot_open_and_nothing_is_relayed` (`403`, `SpyCampaign` n'a rien reçu), `an_open_is_relayed_with_the_resolved_admin`, `an_oversized_open_is_refused_before_the_relay` (`413`), `an_open_without_a_relay_is_503` ; Astra `a_tunnel_open_lands_in_pending` (par le router privé ou `door` avec `Tunnel` : l'opération est dans `pending`, `requested_by` porte le suffixe), `a_tunnel_open_of_a_console_action_is_refused_coarsely` (corps `{"action":"chain_open"}` refusé à la désérialisation, l'enum du tunnel n'ayant pas cette variante → `4xx` sans détail).
- [ ] **Step 2: Run** `… test -p helios-api certificates` et `… test -p astra` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS ; clippy sur `astra`, `helios-api`, `heliosd`.
- [ ] **Step 5: Commit** — `feat(heliosd): relay an operator opening from the tunnel to Astra's door`

### Task 8: Documentation et régression complète

**Files:**
- Modify: `docs/specification/ROTATION-CERTIFICATS.md` (§7.6 qui ouvre, §8.5.1 routes `pending` et ouverture, « aucune autre » réécrit, §8.5.6, §11.6, §12.3, amendement daté du 2 novembre 2026), `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md` (même amendement : Astra tient la porte, console connecteur, verrou du volume), `docs/RENOUVELLEMENT-CERTIFICATS.md` et `docs/DEPLOIEMENT-ASTRA.md` (service en marche requis pour ouvrir ; `ASTRA_GATEWAY_CHANNEL` du service pour les ouvertures gateway ; plus de `--gateway-channel` côté console ; échéance plus recopiée par le tunnel), `docs/ROADMAP.md` (F14 : lot 5a livré sur la branche, non fusionné), `docs/testing/MANUAL-TESTING.md` (« F. Lot 5a », étapes 1-6 de la spec §8), et les commentaires de code qui justifiaient l'inbox ou le refus d'ouvrir (`service.rs:340`, `CampaignCommand::Open`, `daemon.rs` en-tête).

- [ ] **Step 1: Rédiger** ; rechercher les restes : `grep -rn "campaign-inbox\|astra campaign open\|--gateway-channel\|quatre routes" docs crates` et justifier chaque occurrence restante.
- [ ] **Step 2: Régression** : `CARGO_BUILD_JOBS=2 scripts/regression.sh` (lancé par le contrôleur après la dernière tâche) → code 0, seuls les avertissements cargo-audit déjà admis.
- [ ] **Step 3: Commit** — `docs: Astra's single door (F14 lot 5a)`
