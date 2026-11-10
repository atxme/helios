# F14 lot 6b : l'identité de la gateway depuis Orion — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** renouveler, annuler, ramener temporairement et révoquer l'identité de la gateway depuis Orion, par le tunnel, sans fichier ni commande ; puis « Tout renouveler ».

**Architecture:**
- Fil du tunnel : l'ouverture d'opérateur (`OperatorOpenAction`) gagne `GatewayIdentity`, `GatewayRevocation` et `ChainOpen` ; trois opérations nouvelles traversent `astra-channel` → `heliosd` → `helios-api` : publier une transition gateway, avancer et abandonner le plan.
- Porte d'Astra : la table `allowed` ouvre ces actions au tunnel ; l'ouverture `GatewayIdentity` renvoie la feuille PQ en service.
- Gateway : la vue `GET /api/certificates` donne les échéances des deux feuilles gateway ; `GET /api/certificates/gateway-transition` sert la transition installée.
- `astra-operator` : deux opérations, `operations/gateway_identity.rs` (renouveler, annuler, revenir) et `operations/gateway_revocation.rs`, sur le modèle de `operations/revocation.rs` du 5c (trait distant, refus avant clé, enregistrement avant dépôt, reprise sans clé).
- Orion : un geste Tauri `GatewayGesture`, un bloc « Identité de la gateway » dans *Rotations*.
- « Tout renouveler » (Tasks 10-11) se livre en dernier et peut être détaché.

**Tech Stack:**
- Rust : `aether`, `astra`, `astra-channel`, `astra-operator`, `heliosd`, `helios-api`, `orion-core`.
- Orion : Tauri (`apps/orion/src-tauri`), React/TypeScript (`apps/orion/src`), Vitest.

**Spec:** `docs/superpowers/specs/2026-11-10-f14-lot6b-identite-gateway-design.md`.
Le spec fait autorité : en cas d'écart, le spec gagne.

## Global Constraints

- Ne jamais travailler sur `main` : worktree `/home/christophe/helios-wt/f14-lot6b`, branche `feat/f14-lot6b-identite-gateway`.
- Compiler et tester uniquement par `scripts/wsl-cargo`, avec `CARGO_BUILD_JOBS=2` et `RUST_TEST_THREADS=2`.
  - Jamais de `target/` dans le worktree, ni de `CARGO_TARGET_DIR`, ni de `HELIOS_WSL_BUILD_OVER_BUDGET`, ni de `scripts/clean-wsl-targets`.
  - Refus pour mémoire : attendre par une boucle `until` en arrière-plan sur `MemAvailable` (environ 10 min, 3 fois au plus). Ne jamais forcer ni tuer un processus.
- Langues : `docs/`, messages de console et libellés d'interface en français, courts et neutres, sans jamais tutoyer ; commentaires et identifiants en anglais.
- Aucun secret dans la WebView ni dans un journal : ni PIN, ni `Opened`, ni octets du coffre, ni clé privée. `Opened` reste sur le fil de cérémonie et s'efface à toute sortie.
- Aucune clé privée de la gateway ne quitte la gateway. Aucun objet signé, empreinte, époque ou identifiant n'est saisi par la personne : tout se lit à la source.
- Tunnel seul : l'origine publique d'Astra ne sert aucune de ces actions. `heliosd` par son API seulement, jamais par ses commandes hors ligne.
- Ne pas éditer de version à la main ; pas de tag `v*` ; `docs/audits` intouché. Ajouter un champ à une structure du coffre ou du fil : `clippy --workspace --all-features --all-targets` avant le commit (les fixtures d'autres crates l'initialisent).
- Commits : messages en anglais, préfixes `feat`/`fix`/`docs`/`test`/`refactor`, suffixe `(F14 lot 6b)`. Pied obligatoire : `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Libellés exacts du spec :
  - lignes et boutons : « Renouveler l'identité de la gateway », « Annuler », « Revenir à l'ancienne identité », « Révoquer la gateway », « Tout renouveler », « Abandonner le plan », bloc « Identité de la gateway » ;
  - options : « Remplacer aussi la feuille TLS », « La clé de la gateway est perdue » avec « Aucune preuve de continuité. Réservé à une clé disparue. » ;
  - états : « À faire », « Installée, publication à faire », « Bascule le {date} », « Recouvrement jusqu'au {date} », « Retour arrière jusqu'au {date} » ;
  - redémarrage : le motif `gateway_restart_due` puis « Redémarrer heliosd sur la gateway. » ;
  - annulation : « L'époque reste consommée. » ;
  - révocation sans remplaçant : « La gateway ne servira plus. Le domaine devra être reconstruit. » ;
  - fin du plan : « Parc autorisé ; chaque poste se renouvelle à sa prochaine connexion. »
- Termes par défaut du renouvellement : préparation 7 jours, recouvrement 7 jours, validité 365 jours (défauts de `SignGatewayTransition`, `tools/astra-signer/src/cli.rs`). Retour arrière : 24 h par défaut, borné par `not_after`.
- Motifs de révocation : ceux du 5c (`RevocationReasonChoice`, `crates/astra-operator/src/operations/revocation.rs`).

## Review Focus

1. **La gateway a changé entre l'ouverture et la signature** : la feuille PQ en service ou la demande préparée ne correspond plus aux empreintes figées par la campagne. Refus avant toute clé, rien de signé. Test : Task 4, `renewal_refuses_a_leaf_the_campaign_did_not_freeze`.
2. **Orion fermé entre l'installation et la publication** : la ligne dit « Installée, publication à faire » et « Reprendre » publie sans clé. Tests : Task 4, `resume_publishes_without_a_key` ; Task 9, `installed_unpublished_reads_publication_due`.
3. **Annuler à la seconde `activation_at`** : refusé avant la clé, et le bouton n'est plus proposé. Tests : Task 5, `abort_refused_at_activation` ; Task 9, `no_abort_button_once_published_or_activated`.
4. **Révocation gateway interrompue entre la révocation et la transition de remplacement** : une reprise applique ce qui manque, dans l'ordre, sans clé. Test : Task 6, `resume_applies_the_replacement_after_the_revocation`.
5. **Une opération `GatewayIdentity` déjà vivante** (renouvellement abandonné en route) : l'ouverture est refusée, Orion le dit et ne signe rien. Test : Task 5, `a_live_gateway_operation_blocks_the_abort_by_name`.

---

### Task 1: le tunnel ouvre les campagnes gateway

**Files:**
- Modify: `crates/aether/src/certificates/transport.rs` (`OperatorOpenAction`, `OperatorOpenActionTag`, `TryFrom<OperatorOpenRequestWire>`, `OperatorOpened`)
- Modify: `crates/astra/src/door/mod.rs` (`From<OperatorOpenRequest> for DoorRequest`, `allowed`, ouverture `GatewayIdentity`), `crates/astra/src/door/open.rs` si `Opening` → `OperatorOpened` y vit
- Modify: amendement daté du 10 novembre 2026 de la spec 5a §5.2 (`docs/superpowers/specs/2026-11-02-f14-lot5a-porte-unique-design.md`)
- Test : tests de `transport.rs`, `crates/astra/src/door/tests/`

**Interfaces:**
- Produces :

```rust
pub enum OperatorOpenAction {
    FleetLeafs, TrustAuthorities, ClientRevocation { peer: WireGuardKey }, IssuerDelegation,
    GatewayIdentity, GatewayRevocation, ChainOpen,
}
pub struct OperatorOpened { /* existing fields */
    /// The gateway PQ leaf in service, frozen with a `gateway_identity` campaign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_certificate: Option<PqCertificate>,
}
```

- Fil : `{"action":"gateway_identity"|"gateway_revocation"|"chain_open", …}`, sans `peer` (refusé s'il est présent).
- `allowed` : `GatewayIdentity`, `GatewayRevocation`, `ChainOpen`, `ChainNext`, `ChainAbandon`, `GatewayIdentityPublish` passent à `(true, true)`. `IssuerRequest`, `PinCaTls`, `IssuerInstall` inchangés.
- L'ouverture `GatewayIdentity` remplit `gateway_certificate` avec `GatewayIdentityView.pq_certificate`, déjà lu par `read_gateway_identity`. L'export dans le volume (`export_active_gateway_certificate`) reste pour la console.
- `ChainOpen` par le tunnel : l'issue `DoorOutcome::ChainStep` se rend au tunnel comme `OperatorOpened` de l'étape ouverte, `delegation_request` compris. Plan sans campagne ouverte : refus.

- [ ] **Step 1 : tests.**
  - `wire_opens_gateway_actions` : aller-retour JSON des trois actions ; `{"action":"gateway_identity","peer":…}` refusé.
  - `the_tunnel_may_open_gateway_actions` : la table, une assertion par ligne du tableau du spec §5.1, console et tunnel.
  - `a_tunnel_gateway_identity_opening_returns_the_leaf_in_service` : connecteur tunnel, gateway factice ; `gateway_certificate` est la feuille servie, son empreinte celle du sujet de la campagne.
  - `requested_by_names_the_resolved_peer_for_gateway_actions` : la règle 5a §5.3, sur `GatewayRevocation`.
  - Étendre le test d'équivalence des connecteurs existant aux trois actions.
- [ ] **Step 2 :** lancer `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p aether -p astra gateway_actions gateway_identity_opening requested_by`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter. Puis `scripts/wsl-cargo clippy --workspace --all-features --all-targets -- -D warnings`.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p aether -p astra`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra): the tunnel opens gateway identity, revocation and chain campaigns (F14 lot 6b)`.

### Task 2: publier une transition gateway par le tunnel

**Files:**
- Modify: `crates/astra-channel/src/authority_routes.rs` (route), `crates/astra-channel/src/authority_client.rs`, le routeur privé d'Astra (`crates/astra/src/operator.rs`, modèle `vault_copy`)
- Modify: `crates/helios-api/src/certificates/operator_relay.rs` (trait, handler), `crates/helios-api/src/lib.rs` (route), `crates/heliosd/src/astra_channel.rs` (implémentation du relais)
- Modify: `crates/astra-operator/src/tunnel.rs`
- Test : tests de ces modules

**Interfaces:**
- Consumes : `DoorRequest::GatewayIdentityPublish { epoch }` (déjà implémenté), `allowed` (Task 1).
- Produces :

```rust
// astra-channel
pub const OPERATOR_GATEWAY_PUBLISH_ROUTE: &str = "/internal/v1/operator/gateway-identity/publish";
pub struct OperatorGatewayPublish { pub epoch: u64 }            // deny_unknown_fields
pub struct OperatorGatewayPublished { pub epoch: u64, pub relayed: bool }
// helios-api, trait OperatorCampaignRelay
async fn publish_gateway_transition(&self, operator: &OperatorIdentity, request: OperatorGatewayPublish)
    -> Result<OperatorGatewayPublished, TrustUpdateRefusal>;
// route admin : POST /api/certificates/operator/gateway-identity/publish
// astra-operator
impl Tunnel { pub fn publish_gateway_transition(&self, epoch: u64) -> Result<OperatorGatewayPublished>; }
```

- Même contrôle d'appelant que les autres routes d'opérateur (`operator_caller`) : pair administrateur du tunnel, jamais le socket local.
- Rejouable : une seconde publication de la même époque répond sans erreur (`relayed` dit si le relais a eu lieu cette fois).

- [ ] **Step 1 :** tests `publish_route_relays_to_the_door` (astra-channel/astra, connecteur tunnel), `publish_is_refused_to_a_non_admin` (helios-api), `publish_twice_answers_twice` (astra).
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-channel -p astra -p helios-api -p heliosd publish`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter, sur le chemin exact de `vault_copy` (5b).
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-channel): publish a gateway transition through the tunnel (F14 lot 6b)`.

### Task 3: la gateway dit les échéances de ses feuilles et sert sa transition

**Files:**
- Modify: `crates/helios-api/src/certificates/views.rs` (`CertificateDomainView`), `crates/heliosd/src/certificates/views.rs` (construction)
- Modify: `crates/helios-api/src/certificates/gateway_identity.rs` (handler de lecture, méthode du trait `GatewayIdentityHandler`), `crates/helios-api/src/lib.rs` (route `GET`), `crates/heliosd/src/certificates/gateway_identity.rs` (lecture depuis `staged_transition_path()` de `crates/heliosd/src/gateway_rotation.rs`)
- Modify: `crates/orion-core/src/operator_rotations.rs` (`GatewayDomainRead`)
- Modify: `crates/astra-operator/src/tunnel.rs` (appels `/api` de la gateway)
- Test : tests de ces modules

**Interfaces:**
- Produces :

```rust
// CertificateDomainView, #[serde(default)]
pub gateway_tls_not_after: Option<u64>,   // DER parsed; None if unreadable
pub gateway_pq_not_after: Option<u64>,    // active_gateway_certificate.not_after_unix
// GET /api/certificates/gateway-transition -> 200 { "transition": GatewayIdentityTransition | null }
async fn staged_transition(&self) -> Result<Option<Box<GatewayIdentityTransition>>, GatewayActionRefusal>;
// orion-core GatewayDomainRead, all #[serde(default)]
pub gateway_identity_epoch: u64, pub gateway_tls_fingerprint: String, pub gateway_pq_fingerprint: String,
pub gateway_tls_not_after: Option<u64>, pub gateway_pq_not_after: Option<u64>,
pub gateway_transition_pending: bool, pub gateway_transition_published: bool,
pub gateway_activation_at: Option<u64>, pub gateway_retire_active_at: Option<u64>,
pub gateway_rollback_expires_at: Option<u64>, pub gateway_restart_due: Option<String>,
// astra-operator Tunnel. astra-operator depends on neither helios-api nor orion-core:
// it reads the gateway through its own tolerant types, like the existing `GatewayAnchors`
// (crates/astra-operator/src/tunnel.rs:590), which this task extends into `GatewayIdentityRead`
// with the gateway fields above (same names as `GatewayDomainRead`).
pub struct GatewayRenewalRead { pub gateway_identity_epoch: u64, pub request_fingerprint: String,
    pub expires_at: u64, pub candidate_tls_fingerprint: Option<String>, pub reused: bool, pub key_recovery: bool }
pub struct GatewayDecisionRead { pub gateway_identity_epoch: u64, pub fingerprint: String,
    pub already_present: bool, pub activation_at: Option<u64>, pub not_after: Option<u64> }
pub struct GatewayRollbackRead { pub expires_at: u64 }
pub struct RenewalAsk { pub rotate_tls: bool, pub new_key: bool, pub key_recovery: bool } // body of POST gateway-renewal
pub fn gateway_identity(&self) -> Result<GatewayIdentityRead>;
pub fn prepare_gateway_renewal(&self, ask: &RenewalAsk) -> Result<GatewayRenewalRead>;
pub fn gateway_renewal_request(&self) -> Result<GatewayCertificateRequest>;  // aether type, the full public request
pub fn gateway_candidate_tls(&self) -> Result<Option<DerCertificate>>;
pub fn install_gateway_transition(&self, t: &GatewayIdentityTransition) -> Result<GatewayDecisionRead>;
pub fn abort_gateway_transition(&self, a: &GatewayTransitionAbort) -> Result<GatewayDecisionRead>;
pub fn install_gateway_rollback(&self, r: &CertificateServiceRollbackAuthorization) -> Result<GatewayRollbackRead>;
pub fn staged_gateway_transition(&self) -> Result<Option<GatewayIdentityTransition>>;
```

- Les champs de `GatewayRollbackRead` suivent `GatewayRollbackView` (`crates/helios-api/src/certificates/gateway_identity.rs`) : le reprendre tel quel en sous-ensemble tolérant.

- La signature de la transition demande la demande publique complète et, si la TLS change, la feuille TLS candidate en DER : `GatewayRenewalView` n'en porte que les empreintes. Si aucune route ne les sert, en ajouter deux en lecture (`GET /api/certificates/gateway-renewal` pour la demande, `GET /api/certificates/gateway-renewal/tls` pour le DER), sur la surface admin. Tout est public : clé publique, preuves, feuille.
- La transition reste lisible pendant tout le recouvrement (elle sert au retour arrière) ; `null` hors transition.

- [ ] **Step 1 :** tests `domain_view_names_the_gateway_leaf_expiries`, `staged_transition_is_served_until_promotion`, `staged_transition_is_null_without_one`, `renewal_request_and_candidate_tls_are_readable_after_prepare` (heliosd/helios-api), `domain_read_tolerates_the_gateway_fields` (orion-core, JSON sans les champs → défauts).
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p helios-api -p heliosd -p orion-core gateway`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(heliosd): the gateway names its leaf expiries and serves its staged transition (F14 lot 6b)`.

### Task 4: renouveler l'identité de la gateway (astra-operator)

**Files:**
- Create: `crates/astra-operator/src/operations/gateway_identity.rs`, `crates/astra-operator/src/operations/gateway_identity/tests.rs`
- Modify: `crates/astra-operator/src/operations.rs` ou `mod.rs` (module)
- Test : `operations/gateway_identity/tests.rs`

**Interfaces:**
- Consumes : Tasks 1-3 ; `signing::sign_gateway_transition` (`crates/astra-operator/src/signing/gateway.rs:82`) ; `CampaignApprovalSession`, `ValidatedKeys` comme `operations/revocation.rs`.
- Produces :

```rust
pub trait GatewayIdentityRemote {
    fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened>;
    fn fetch_campaign(&self, operation_id: &Id16) -> Result<CampaignRequest>;
    fn submit_campaign(&self, operation_id: &Id16, result_token: &str, result: &AstraSignerResult)
        -> Result<SigningOperationState>;
    fn prepare_renewal(&self, ask: &RenewalAsk) -> Result<GatewayRenewalRead>;
    fn renewal_request(&self) -> Result<GatewayCertificateRequest>;
    fn candidate_tls(&self) -> Result<Option<DerCertificate>>;
    fn install(&self, transition: &GatewayIdentityTransition) -> Result<GatewayDecisionRead>;
    fn publish(&self, epoch: u64) -> Result<OperatorGatewayPublished>;
    fn abort(&self, abort: &GatewayTransitionAbort) -> Result<GatewayDecisionRead>;          // Task 5
    fn rollback(&self, r: &CertificateServiceRollbackAuthorization) -> Result<GatewayRollbackRead>; // Task 5
    fn staged_transition(&self) -> Result<Option<GatewayIdentityTransition>>;                 // Task 5
    fn gateway(&self) -> Result<GatewayIdentityRead>;
    fn authority_status(&self) -> Result<OperatorAuthorityStatus>;   // revoked gateway, CA-PQ overlap
    fn overlap_not_after(&self) -> Result<Option<u64>>;              // as RevocationRemote (5c)
}
impl GatewayIdentityRemote for Tunnel { /* delegates */ }

pub struct RenewalOptions { pub rotate_tls: bool, pub key_recovery: bool,
    pub prepare_days: u64, pub overlap_days: u64, pub validity_days: u64 }
pub enum GatewayRefusal {                       // thiserror, French messages ending « Rien n'a été signé. »
    TransitionInFlight, CaPqOverlap, AlreadyOpen, CampaignMismatch, LeafMismatch,
    RequestMismatch, Unreachable, GatewayRefused(String), Internal(String),
}
pub fn open_renewal(remote: &dyn GatewayIdentityRemote, vault_path: &Path, options: RenewalOptions, now: u64)
    -> Result<OpenedGatewayRenewal, GatewayRefusal>;
impl OpenedGatewayRenewal {
    pub fn keys(&self) -> &ValidatedKeys;
    pub fn approve(&mut self, /* same shape as OpenedRevocation::approve */) -> Result<…>;
    pub fn sign_and_record(self, vault_path: &Path, now: u64) -> Result<SignedGatewayDecision, GatewayRefusal>;
}
pub struct SignedGatewayDecision {               // public, serde, deny_unknown_fields
    pub operation_id: Id16, pub campaign_id: Id16, pub expires_at: u64,
    pub result: AstraSignerResult,              // one GatewayIdentityTransition
    pub installed: bool, pub published: bool,
}
pub fn carry(remote: &dyn GatewayIdentityRemote, vault_path: &Path, decision: SignedGatewayDecision, now: u64)
    -> Result<GatewayCarried, GatewayRefusal>;   // deposit → install → publish, recording each step
pub enum GatewayCarried { Published { activation_at: u64, not_after: u64 } }
pub fn pending(vault_path: &Path, now: u64) -> Result<Option<SignedGatewayDecision>>;
const PENDING_FILE: &str = "pending-gateway-decision.json";
```

- Ordre de `open_renewal`, rien de signé à aucune étape :
  1. lire la gateway (`gateway()`) : `gateway_transition_pending` → `TransitionInFlight` ; recouvrement `CA-PQ` (`overlap_not_after()` non nul, ou une `CA-PQ` sortante gardée dans le coffre) → `CaPqOverlap` ;
  2. `prepare_renewal` (`new_key` toujours `false`) ;
  3. `open_campaign(GatewayIdentity)` ; un refus `AlreadyOpen` de la porte (403 sur le fil) se lit dans `pending` comme au 5c (`refused_by_door`) → `AlreadyOpen` ;
  4. `fetch_campaign`, `renewal_request`, `candidate_tls` ; vérifier : empreinte de `gateway_certificate` = celle du sujet de la campagne (`LeafMismatch`) ; empreinte de la demande = `request_fingerprint` (`RequestMismatch`) ; empreinte du DER = `candidate_tls_fingerprint` (`RequestMismatch`) ; époque = celle de la campagne (`CampaignMismatch`) ;
  5. `key_recovery` : la demande ne porte pas de continuité et la transition le motif `key_recovery` ; sinon la continuité se vérifie sous `gateway_certificate`.
- `sign_and_record` écrit `PENDING_FILE` avant tout dépôt. `carry` met à jour `installed` puis `published` dans ce fichier, et le supprime une fois publié. Campagne expirée sans dépôt accepté : le fichier est jeté, la reprise recommence à `open_renewal` (la demande est reprise par la gateway, `reused`).
- Un refus définitif de la gateway à l'installation (`GatewayActionRefusal`) devient `GatewayRefused(raison)` et laisse le fichier, sans « réessayer ».

- [ ] **Step 1 : tests, remote factice et `FakeKey` de `tests/signing.rs`.**
  - `renewal_runs_to_published` : dépôt, installation, publication ; fichier supprimé ; `activation_at = now + 7 j`, `not_after = activation_at + 7 j`.
  - `renewal_refuses_a_leaf_the_campaign_did_not_freeze` : aucune clé demandée (`FakeKey::assertions() == 0`).
  - `renewal_refuses_during_a_ca_pq_overlap` et `renewal_refuses_while_a_transition_is_staged`.
  - `key_recovery_signs_without_continuity` : motif `key_recovery`, demande sans signature de continuité acceptée.
  - `rotate_tls_binds_the_candidate_der` : la transition porte le DER lu ; un DER d'empreinte différente → `RequestMismatch`.
  - `resume_publishes_without_a_key` : fichier avec `installed: true, published: false` ; `carry` publie, aucune assertion.
  - `a_lost_deposit_answer_replays_the_same_bytes`.
  - `a_definitive_install_refusal_is_not_retried`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator gateway_identity`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p astra-operator`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-operator): renew the gateway identity through the tunnel (F14 lot 6b)`.

### Task 5: annuler et revenir à l'ancienne identité (astra-operator)

**Files:**
- Modify: `crates/astra-operator/src/operations/gateway_identity.rs` (et tests)

**Interfaces:**
- Consumes : Task 4 ; `signing::sign_gateway_abort` (`signing/gateway.rs:171`), `signing::sign_service_rollback` (`signing/gateway.rs:236`).
- Produces :

```rust
pub fn open_abort(remote: &dyn GatewayIdentityRemote, vault_path: &Path, now: u64)
    -> Result<OpenedGatewayAbort, GatewayRefusal>;      // approve / sign_and_record / carry like Task 4
pub fn open_rollback(remote: &dyn GatewayIdentityRemote, vault_path: &Path, hours: u64, reason: &str,
    requested_by: &str, now: u64) -> Result<OpenedGatewayRollback, GatewayRefusal>;
// GatewayRefusal gains: NothingToAbort, AbortTooLate(u64 /*activation_at*/), NoOverlap, Revoked
```

- Annuler : transition installée (`staged_transition` non nul), non publiée, `now < activation_at` sur l'horloge de la gateway ; sinon `NothingToAbort` / `AbortTooLate`. Campagne `GatewayIdentity` ; époque de la transition = celle de la campagne. Motif signé `AbortReason::OperatorCancelled`. Pose par `abort`.
- Revenir : transition publiée, `activation_at <= now < not_after`, gateway non révoquée ; sinon `NoOverlap` / `Revoked`. Hors campagne Astra : campagne résolue localement depuis la transition (comme `tools/astra-signer/src/commands/gateway_identity.rs`, `sign-gateway-rollback`), une clé, `sign_service_rollback`. Durée bornée à `not_after - now`. `requested_by` : le nom du poste dans le profil du domaine, passé par l'appelant (Task 8).
- Ni l'un ni l'autre ne lit un fichier fourni par la personne : la transition vient de `staged_transition()`.

- [ ] **Step 1 :** tests `abort_runs_before_activation`, `abort_refused_at_activation` (à `activation_at` exactement, aucune clé demandée), `abort_refused_once_published`, `a_live_gateway_operation_blocks_the_abort_by_name` (`AlreadyOpen`, message nommé), `rollback_runs_inside_the_overlap`, `rollback_refused_before_activation_and_after_not_after`, `rollback_hours_are_capped_by_not_after`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator abort rollback`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-operator): cancel a gateway transition or roll its service back (F14 lot 6b)`.

### Task 6: révoquer la gateway (astra-operator)

**Files:**
- Create: `crates/astra-operator/src/operations/gateway_revocation.rs`, `crates/astra-operator/src/operations/gateway_revocation/tests.rs`

**Interfaces:**
- Consumes : Tasks 4-5 (`GatewayIdentityRemote`, `RenewalOptions`), `revocation_anchor` et `sign_revocation` (`signing/revocation.rs`, règle du 5c), `RevocationReasonChoice`.
- Produces :

```rust
pub fn open_gateway_revocation(remote: &dyn GatewayIdentityRemote, vault_path: &Path,
    reason: RevocationReasonChoice, with_replacement: bool, now: u64)
    -> Result<OpenedGatewayRevocation, GatewayRefusal>;
pub struct SignedGatewayRevocation {           // public, serde
    pub replacement: Option<SignedGatewayDecision>,
    pub revocation: SignedRevocation,           // operations::revocation (5c), reused as is
    pub revocation_applied: bool, pub replacement_installed: bool,
}
pub fn carry_revocation(remote: &dyn GatewayIdentityRemote, vault_path: &Path,
    signed: SignedGatewayRevocation, now: u64) -> Result<(), GatewayRefusal>;
pub fn pending_revocation(vault_path: &Path, now: u64) -> Result<Option<SignedGatewayRevocation>>;
const PENDING_FILE: &str = "pending-gateway-revocation.json";
// GatewayRefusal gains: ReplacementNotBefore(u64), AlreadyRevoked
```

- Avec remplaçant, dans cet ordre :
  1. `prepare_renewal { key_recovery: true }` ;
  2. campagne `GatewayIdentity`, transition motif `emergency_replacement` signée (`sign_gateway_transition` avec `emergency_replacement`), **déposée** : la campagne est consommée avant l'ouverture suivante ;
  3. campagne `GatewayRevocation` ; les deux moitiés révoquées, échéances prises dans `OperatorOpened.revocation_expiries` (refus `Internal` si l'une manque) ; `replacement_transition_fingerprint` calculé sur la transition signée ;
  4. dépôt de la révocation (Astra la relaie à la gateway, `crates/astra/src/service.rs`, et la gateway l'applique par `revoke_gateway_identity`) → `revocation_applied` ; puis `install` de la transition → `replacement_installed`.
- Sans remplaçant : étapes 3 et 4 seules, sans `replacement_transition_fingerprint`.
- Pendant un recouvrement `CA-PQ` : la révocation suit `revocation_anchor` comme au 5c. Pour la transition de remplacement, lire sous quelle ancre la gateway vérifie une transition pendant ce recouvrement (`crates/heliosd/src/key_negotiation/candidate.rs`, `crates/aether/src/certificates/state/gateway_identity.rs`). Si aucune ancre du coffre ne convient : `ReplacementNotBefore(fin du recouvrement)` avant toute clé, et « sans remplaçant » reste ouvert. Consigner le résultat de cette lecture dans le rapport.
- L'enregistrement est écrit avant le premier dépôt et suit les drapeaux ; la reprise reprend au premier drapeau faux, sans clé.

- [ ] **Step 1 :** tests `revocation_with_replacement_applies_revocation_then_transition` (ordre des appels du remote factice), `revocation_without_replacement_names_no_transition`, `resume_applies_the_replacement_after_the_revocation` (fichier avec `revocation_applied: true`), `both_halves_are_revoked_with_the_campaign_expiries`, `a_missing_expiry_refuses_before_a_key`, `during_a_ca_pq_overlap_the_revocation_follows_the_5c_anchor`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator gateway_revocation`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p astra-operator`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-operator): revoke the gateway, with or without its replacement (F14 lot 6b)`.

### Task 7: preuve de bout en bout par le connecteur tunnel

**Files:**
- Create: `crates/astra/src/door/tests/gateway_identity_tunnel.rs` (modèle : `crates/astra/src/door/tests/overlap_revocation.rs`)

**Interfaces:**
- Consumes : Tasks 1, 2, 4, 6. Pas de `heliosd` réel : état gateway `aether` comme le test du 5c, ce que le test dit en tête de fichier.

- [ ] **Step 1 :** tests.
  - `a_gateway_renewal_runs_through_the_tunnel` : ouverture tunnel, signature par `astra-operator`, dépôt accepté, installation sur l'état gateway, publication marquée par la porte.
  - `a_gateway_revocation_with_replacement_lands_in_order` : la gateway accepte la révocation puis la transition nommée ; la transition seule, avant la révocation, est refusée par l'état gateway.
  - `an_emergency_replacement_is_refused_by_a_healthy_gateway`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra gateway_identity_tunnel`. Attendu : FAIL, puis PASS après correction de ce que la preuve révèle (le rapport nomme chaque correction).
- [ ] **Step 3 :** commit `test(astra): gateway identity and revocation end to end through the tunnel (F14 lot 6b)`.

### Task 8: le geste Tauri `GatewayGesture`

**Files:**
- Create: `apps/orion/src-tauri/src/operator/ceremony/gateway.rs`, `apps/orion/src-tauri/src/operator/ceremony/gateway/tests.rs`
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (geste, `OperationKind`), `apps/orion/src-tauri/src/operator/ceremony.rs` (aiguillage), `apps/orion/src-tauri/src/commands/ceremonies.rs` et `main.rs` (commande), `apps/orion/src-tauri/src/operator/rotations.rs` (`RotationsOverview` relit le domaine avec les champs gateway de la Task 3 et `pending()`/`pending_revocation()`)

**Interfaces:**
- Consumes : Tasks 3-6 ; `Ceremony`/`publish`/`Press` du 5b ; la garde « gateway du domaine » du 5b.
- Produces :

```rust
#[derive(Deserialize)] #[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum GatewayGesture {
    Renew { rotate_tls: bool, key_recovery: bool },     // terms come with the approving press, as in 5b
    Abort,
    Rollback { hours: u64, reason: String },
    Revoke { reason: RevocationReasonChoice, with_replacement: bool },
    Resume,
}
#[tauri::command] async fn begin_gateway_ceremony(state, gesture: GatewayGesture) -> Result<(), String>;
// RotationsOverview gains:
pub gateway_pending: Option<GatewayPendingView>,  // { kind: "decision" | "revocation", installed, published, revocation_applied }
```

- `Rollback.reason` : non vide, 200 caractères au plus ; `hours` de 1 à 168. `requested_by` = nom du poste dans le profil du domaine.
- `Resume` reprend `pending_revocation` s'il existe, sinon `pending`, sans clé.
- Les étapes publiées à la WebView : Prérequis, Clés, Signature, Dépôt, Installation, Publication (ou Révocation appliquée, Remplaçant installé). Aucune donnée du coffre.

- [ ] **Step 1 :** tests, gateway et remote factices : `renew_runs_to_published`, `rollback_names_this_workstation_as_requester`, `revoke_with_replacement_publishes_two_key_rounds`, `resume_without_a_record_does_nothing`, `opened_is_erased_on_every_exit` (modèle 5b), `another_domains_gateway_is_never_touched`, `overview_reads_the_gateway_fields`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p orion gateway`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p orion`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(orion): the gateway identity ceremonies (F14 lot 6b)`.

### Task 9: le bloc « Identité de la gateway » (React)

**Files:**
- Create: `apps/orion/src/views/astra/gatewayRows.ts`, `gatewayRows.test.ts`, `GatewayIdentityBlock.tsx`, `GatewayIdentityBlock.test.tsx`
- Modify: `apps/orion/src/views/astra/RotationsPanel.tsx` (bloc en tête), `apps/orion/src/types.ts` (champs de la Task 3 et `GatewayPendingView`), `RotationSteps.tsx` (étapes réutilisées : Prérequis, Termes, Motif, Clés)

**Interfaces:**
- Consumes : `RotationsOverview` (Task 8), `begin_gateway_ceremony`, `formatDate`/`formatDateTime`/`effectiveNow`/`EXPIRING_SOON_SECS` de `rotationRows.ts`.
- Produces :

```ts
export type GatewayAction = 'renew' | 'abort' | 'rollback' | 'revoke' | 'resume'
export interface GatewayRow { state: string; due: boolean; actions: GatewayAction[];
  restart: string | null /* motif + « Redémarrer heliosd sur la gateway. » */; detail: string | null }
export function gatewayRow(o: RotationsOverview, local: number): GatewayRow
```

- États, sur l'horloge de la gateway (`effectiveNow`) :
  - rien en cours : « À faire » et `due` si `min(gateway_tls_not_after, gateway_pq_not_after) - now < EXPIRING_SOON_SECS`, sinon l'échéance ; actions `renew`, `revoke` ;
  - installée, non publiée : « Installée, publication à faire » ; actions `resume`, `abort` si `now < activation_at` ;
  - publiée, avant `activation_at` : « Bascule le {formatDate} » ; actions `revoke` ;
  - entre `activation_at` et `gateway_retire_active_at` : « Recouvrement jusqu'au {formatDate} » ; actions `rollback`, `revoke` ;
  - `gateway_rollback_expires_at` présent : `detail` « Retour arrière jusqu'au {formatDateTime} » ;
  - `gateway_pending` présent : action `resume` en tête.
  - `renew` désactivé pendant un recouvrement `CA-PQ` avec `OVERLAP_PQ`.
- Parcours :
  - Renouveler : Prérequis → options (« Remplacer aussi la feuille TLS », « La clé de la gateway est perdue » avec sa confirmation) → Termes (7/7/365) → Clés → Suivi.
  - Annuler : confirmation « L'époque reste consommée. » → Clé → Suivi.
  - Revenir : durée (24 h) et motif → Clé → Suivi, puis la phrase du redémarrage.
  - Révoquer : Motif → choix « avec remplaçant » (défaut) ou « sans remplaçant » avec seconde confirmation « La gateway ne servira plus. Le domaine devra être reconstruit. » → annonce du nombre de séries de touchers → Clés → Suivi.

- [ ] **Step 1 :** tests `gatewayRow` : un cas par état, `installed_unpublished_reads_publication_due`, `no_abort_button_once_published_or_activated`, `restart_due_shows_the_reason_and_the_sentence`, `renew_disabled_during_a_ca_pq_overlap`. `GatewayIdentityBlock` : chaque parcours avec ses libellés exacts ; la seconde confirmation « sans remplaçant ».
- [ ] **Step 2 :** lancer `npx vitest run src/views/astra` dans `apps/orion`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `npx vitest run` et `npx tsc --noEmit`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(orion): the gateway identity block (F14 lot 6b)`.

### Task 10: le plan « Tout renouveler » par le tunnel (détachable)

**Files:**
- Modify: `crates/astra-channel/src/authority_routes.rs` et `authority_client.rs`, `crates/astra/src/operator.rs` (routes), `crates/helios-api/src/certificates/operator_relay.rs` et `lib.rs`, `crates/heliosd/src/astra_channel.rs`, `crates/astra-operator/src/tunnel.rs`
- Modify: `crates/aether/src/certificates/transport.rs` (`OperatorAuthorityStatus`), `crates/astra/src/operator.rs` (`status`), `crates/orion-core/src/operator_rotations.rs` (`AuthorityStatusRead`)

**Interfaces:**
- Consumes : `DoorRequest::ChainNext {}`, `ChainAbandon {}`, `ChainPlan` (`crates/astra/src/chain.rs`), Task 1 (`ChainOpen` au tunnel).
- Produces :

```rust
pub const OPERATOR_CHAIN_NEXT_ROUTE: &str = "/internal/v1/operator/chain/next";
pub const OPERATOR_CHAIN_ABANDON_ROUTE: &str = "/internal/v1/operator/chain/abandon";
pub enum OperatorChainStep { Opened(Box<OperatorOpened>), Finished }   // serde tag "outcome"
// relay: chain_next(&self, operator) -> Result<OperatorChainStep, _>; chain_abandon(&self, operator) -> Result<(), _>
// routes admin : POST /api/certificates/operator/chain/next, /chain/abandon
// OperatorAuthorityStatus, #[serde(default)]:
pub chain: Option<OperatorChainView>,  // { steps: Vec<CampaignScope>, current: usize, operation_id: Option<Id16> }
// Tunnel: chain_next(), chain_abandon()
```

- Un refus « effet pas encore visible » de la porte (`plan_refusal`) arrive au tunnel avec sa raison lisible, pas en 403 nu : Orion l'affiche tel quel.

- [ ] **Step 1 :** tests `chain_runs_through_the_tunnel` (ouvrir, avancer jusqu'à `Finished`), `chain_next_refuses_until_the_effect_lands_with_a_reason`, `status_names_the_chain`, `abandon_drops_the_plan`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra -p astra-channel -p helios-api -p heliosd chain`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-channel): drive the renewal chain through the tunnel (F14 lot 6b)`.

### Task 11: « Tout renouveler » dans Orion (détachable)

**Files:**
- Modify: les opérations du 5b pour accepter une campagne déjà ouverte : `crates/astra-operator/src/operations/issuer.rs`, `operations/rotation.rs` (CA TLS), `operations/campaign.rs` (parc), Task 4 (gateway)
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`ChainGesture`), `operator/ceremony.rs`, `commands/ceremonies.rs`, `main.rs`
- Modify: `apps/orion/src/views/astra/rotationRows.ts` (action `renew_all`), `RotationsPanel.tsx`, tests

**Interfaces:**
- Consumes : Task 10.
- Produces :

```rust
// each 5b/6b opening gains a sibling that starts from a given campaign instead of opening one:
pub fn open_renewal_in(remote: &dyn GatewayIdentityRemote, vault_path: &Path, opened: OperatorOpened,
    options: RenewalOptions, now: u64) -> Result<OpenedGatewayRenewal, GatewayRefusal>;
// same pattern, same names suffixed `_in`, for the issuer delegation, the CA TLS rotation and the fleet approval
pub enum ChainGesture { Start { reason: String }, Step, Abandon }
```

- `Start` : `ChainOpen`, puis le geste de l'étape 1 sur l'opération rendue. `Step` : `chain_next`, puis le geste de l'étape rendue. Quatre touchers annoncés avant `Start`.
- La ligne « Tout renouveler » montre les quatre étapes (délégation de l'émetteur, CA TLS cliente, identité de la gateway, feuilles du parc) et l'étape en cours lue dans `status.chain` ; « Abandonner le plan » ; à `Finished` : « Parc autorisé ; chaque poste se renouvelle à sa prochaine connexion. »
- Si rendre un geste du 5b `_in` demande plus qu'un frère de son `open` (refonte de son déroulé), arrêter et rendre `NEEDS_CONTEXT` : le contrôleur décide de détacher.

- [ ] **Step 1 :** tests Rust `each_step_signs_under_the_plans_campaign`, `start_announces_four_touches` ; Vitest `renew_all_row_shows_the_current_step`, `abandon_keeps_what_was_approved`, `finished_reads_fleet_authorized`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator -p orion chain` et `npx vitest run src/views/astra`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis les suites complètes `-p astra-operator -p orion`, `npx vitest run`, `npx tsc --noEmit`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(orion): renew everything in one row (F14 lot 6b)`.

### Task 12: documentation et recette

**Files:**
- Modify:
  - `docs/RENOUVELLEMENT-CERTIFICATS.md` §7.1, §8, §8.1, §10 : Orion d'abord, les commandes en recours jusqu'au lot 7 ; §11 inchangé sur le redémarrage ;
  - `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md` : renvoi daté du 10 novembre 2026 (table de la porte, gestes gateway dans Orion) ;
  - `docs/testing/MANUAL-TESTING.md` : section « I. Lot 6b », étapes **[cible]** quand WSL ne peut pas les jouer (vraies clés, gateway cible, redémarrage de `heliosd`) ;
  - `docs/ROADMAP.md` : F14 lot 6b livré sur sa branche ; Tasks 10-11 livrées ou détachées, dit tel quel.
- Test : relecture ; chaque affirmation se vérifie dans le code, avec fichier:ligne dans le rapport.

- [ ] **Step 1 :** écrire.
- [ ] **Step 2 :** `grep -rn "gateway" docs/testing/MANUAL-TESTING.md` sur la section I, et contrôle des libellés contre `gatewayRows.ts` et `GatewayIdentityBlock.tsx`.
- [ ] **Step 3 :** commit `docs: the gateway identity from Orion (F14 lot 6b)`.

### Task 13: régression

- [ ] **Step 1 :** fusionner `main` dans la branche (Codex y pousse), résoudre, puis `scripts/wsl-cargo clippy --workspace --all-features --all-targets -- -D warnings`.
- [ ] **Step 2 :** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh`, en arrière-plan. Attendu : sortie 0, aucun test en échec ; l'audit des dépendances ne montre que les avertissements déjà tolérés sur `main`.
- [ ] **Step 3 :** `python3 scripts/version.py check --base main`. Attendu : changements sans version, normal avant `version.py merge`. Ne rien éditer à la main.
- [ ] **Step 4 :** lister les validations impossibles en WSL (vraies clés, gateway cible, redémarrage de `heliosd`, Windows) et les signaler à l'utilisateur.
