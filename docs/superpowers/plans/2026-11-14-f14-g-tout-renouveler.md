# F14-g — « Tout renouveler » dans Orion — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** conduire le plan « Tout renouveler » d'Astra depuis Orion (commencer, continuer, reprendre, rouvrir une étape expirée, abandonner), chaque étape jouant le geste Orion existant sous la campagne du plan.

**Architecture:** Astra gagne `ChainReopen` et une étape attendue sur `next`/`reopen`, relayés par `astra-channel` → `heliosd` → `helios-api`. `astra-operator` gagne `check_renewal`/`open_renewal_in` et les appels tunnel. Orion (Tauri) garde en mémoire l'`OperatorOpened` de l'étape et expose les commandes du plan ; l'écran ajoute une ligne « Tout renouveler » dont l'état est une fonction pure (`chainRow.ts`).

**Tech Stack:** Rust (axum, serde, tokio), Tauri 2, React + MUI, Vitest.

**Spec:** `docs/superpowers/specs/2026-11-14-f14-g-tout-renouveler-design.md` (lire §6 en entier avant toute tâche).

## Global Constraints

- Worktree `/home/christophe/helios-wt/f14-g`, branche `feat/f14-g-tout-renouveler` ; jamais `~/helios`.
- Construire uniquement par `scripts/wsl-cargo`, avec `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2` ; jamais `CARGO_TARGET_DIR`, `HELIOS_WSL_BUILD_OVER_BUDGET`, `clean-wsl-targets`. Erreur « champ inexistant » contredite par la source : `touch` les sources du crate (cache partagé).
- Vitest : `cd apps/orion && npx vitest run <fichier>` ; types : `npx tsc --noEmit`.
- Code, commentaires, journaux en anglais ; phrases de l'écran et `docs/` en français, courtes, qui nomment la cause.
- Aucun secret (PIN, `Opened`, octets du coffre, clé privée) dans la WebView ou un journal. La demande de délégation n'est jamais écrite sur disque ni journalisée.
- Aucun marqueur TODO ; aucune version modifiée à la main ; `docs/audits` intouché.
- Chaque commit se termine par `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`.
- Avant chaque commit Rust : `scripts/wsl-cargo fmt --all -- --check` et `clippy` du crate touché avec `--all-targets --all-features -- -D warnings`.

## Review Focus

1. Un plan avancé par la console entre la lecture d'Orion et le clic : `expected_step` refuse, rien n'est ouvert, la phrase s'affiche (Task 1, Task 6).
2. « Continuer » quand un contrôle de l'étape suivante échoue : aucun appel `chain/next` (Task 6).
3. Orion redémarré pendant l'étape délégation ou gateway : l'`OperatorOpened` est perdu, la ligne le dit et propose « Rouvrir l'étape » après l'échéance (Task 4, Task 5).
4. Étape du parc, campagne fermée sans cérémonie réussie dans la session : jamais un « Continuer » seul, mais « Rouvrir l'étape » et « Terminer le plan » avec l'avertissement (Task 5).
5. `reopen` alors qu'Astra tient encore l'opération vivante (écart d'horloge) : refus avec l'échéance, affiché tel quel (Task 1, Task 6).

---

### Task 1: Astra — rouvrir l'étape, étape attendue

**Files:**
- Modify: `crates/astra/src/chain.rs` (méthode de plan + tests du module)
- Modify: `crates/astra/src/door/chain.rs` (`chain_reopen`, `expected_step` sur `chain_next`)
- Modify: `crates/astra/src/door/mod.rs` (`DoorRequest`, `DoorRefusal`, `action()`, `allowed`, `perform`)
- Modify: `crates/astra/src/door/local.rs` et `crates/astra/src/commands/chain.rs` seulement si la console construit `ChainNext {}` (passer `expected_step: None`)
- Test: `crates/astra/src/door/tests.rs` (à côté des tests de chaîne existants, ~l.1480-1620)

**Interfaces:**
- Produces :

```rust
// door/mod.rs
ChainNext { #[serde(default)] expected_step: Option<usize> },
ChainReopen { #[serde(default)] expected_step: Option<usize> },   // action() = "chain_reopen", allowed = (true, true)
// DoorRefusal, nouvelles variantes (toutes « plan », comme ChainStepIncomplete) :
ChainStepNotDeposited,            // « l'étape n'a pas été ouverte : continuer le plan »
ChainStepLanded,                  // « l'étape a pris effet : continuer le plan »
ChainStepStillOpen { expires_at: u64 }, // « la campagne de l'étape est encore ouverte jusqu'à <date> : l'approuver »
ChainStepMoved { current: usize },      // « le plan n'est plus sur cette étape : relire le plan »
// chain.rs
impl ChainPlan {
    /// Refusals of a reopen that need only the plan and the registry.
    pub fn assert_reopenable(&self, state: &AstraState) -> Result<(), ChainError>;
    /// `Some(n)` that is not `self.current`: the plan moved.
    pub fn assert_expected(&self, expected: Option<usize>) -> Result<(), ChainError>;
}
// ChainError gagne : NotDeposited, Landed, Moved { current: usize } ; plan_refusal les traduit.
```

- Règles (spec §6.1) : ordre des refus de `reopen` = `NoChain`, `ChainFinished`, `ChainStepMoved`, `ChainStepNotDeposited`, `ChainStepLanded` (sauf étape `SpentByPeers`, jamais « landed » pour `reopen`), `ChainStepStillOpen` (opération de l'étape présente au magasin `service.operations` et non expirée à `now_unix`), puis `chain_deposit_current` sur la même étape. `chain_next` vérifie `assert_expected` avant `assert_current_landed`. Tout sous `volume_writes`.

- [ ] **Step 1 : tests qui échouent** dans `door/tests.rs`, sur le modèle des tests de chaîne voisins :
  - `reopen_without_a_plan_is_no_chain` → `Err(DoorRefusal::NoChain)`
  - `reopen_refuses_a_step_never_deposited` → plan écrit à la main avec `operation_id: None` sur l'étape courante → `ChainStepNotDeposited`
  - `reopen_refuses_a_step_that_landed` → effet de l'étape 1 visible (époque d'émetteur montée) → `ChainStepLanded`
  - `reopen_refuses_while_the_operation_lives` → juste après `ChainOpen` → `ChainStepStillOpen { expires_at }` avec l'`expires_at` de l'opération
  - `reopen_redeposits_an_expired_step_only` → `ChainOpen`, avancer l'horloge au-delà de la fenêtre, `ChainReopen` → `ChainStep { opened: Some(_) }`, `plan.current` inchangé, nouvel `operation_id` ≠ l'ancien, autres étapes intactes
  - `reopen_gateway_step_takes_the_new_campaign` → plan à l'étape 3 déposée puis expirée → après `reopen`, `GatewayDecisionStored.campaign_id` = celui de la nouvelle ouverture
  - `reopen_fleet_step_reopens_although_spent_by_peers` → étape 4 déposée, expirée → rouverte
  - `reopen_after_a_restart_counts_as_expired` → magasin d'opérations vidé (service neuf sur le même volume) → rouverte
  - `next_and_reopen_refuse_a_moved_plan` → `expected_step: Some(0)` quand `current == 1` → `ChainStepMoved { current: 1 }`
  - mise à jour du test de la table `allowed` et du test d'équivalence des connecteurs pour `chain_reopen`.
- [ ] **Step 2 :** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra chain` → FAIL (variantes absentes).
- [ ] **Step 3 :** implémenter selon les Interfaces.
- [ ] **Step 4 :** relancer → PASS ; puis `scripts/wsl-cargo test -p astra` → PASS.
- [ ] **Step 5 :** commit `feat(astra): reopen an expired chain step, and name the step a caller expects (F14-g)`.

### Task 2: le fil — `chain/reopen` et l'étape attendue, du tunnel à Astra

**Files:**
- Modify: `crates/astra-channel/src/authority_routes.rs` (route, corps relayé), `crates/astra-channel/src/authority_client.rs`
- Modify: `crates/astra/src/operator.rs` (route interne `reopen`, `expected_step` sur `next`, 409 des nouveaux refus)
- Modify: `crates/helios-api/src/certificates/operator_relay.rs`, `crates/helios-api/src/lib.rs` (route admin)
- Modify: `crates/heliosd/src/astra_channel.rs`
- Modify: `crates/astra-operator/src/tunnel.rs`
- Modify (docs) : `docs/adr/ADR-008*.md` et `docs/superpowers/specs/2026-11-02-f14-lot5a-porte-unique-design.md` §5.2 : amendement daté du 14 novembre 2026, ligne `chain_reopen` de la table de la porte
- Test: `crates/astra/src/door/tests/tunnel.rs`, `crates/helios-api/src/certificates/tests/operator_contract_tests.rs`, `crates/astra-operator/tests/tunnel.rs`

**Interfaces:**
- Consumes : Task 1 (`DoorRequest::ChainNext { expected_step }`, `ChainReopen { expected_step }`, refus « plan »).
- Produces :

```rust
// astra-channel
pub const OPERATOR_CHAIN_REOPEN_ROUTE: &str = "/internal/v1/operator/chain/reopen";
#[serde(deny_unknown_fields)]
pub struct RelayedChainStep { pub operator: OperatorIdentity, #[serde(default)] pub expected_step: Option<usize> }
// operator_chain_next(&self, relayed: &RelayedChainStep) (remplace RelayedOperatorCampaign pour next)
pub async fn operator_chain_reopen(&self, relayed: &RelayedChainStep) -> Result<OperatorChainStep, ChannelError>;
// helios-api : corps optionnel des routes admin next et reopen
#[serde(deny_unknown_fields)]
pub struct OperatorChainAsk { #[serde(default)] pub expected_step: Option<usize> }
// trait OperatorCampaignRelay
async fn chain_next(&self, operator: &OperatorIdentity, expected_step: Option<usize>) -> Result<OperatorChainStep, ChainRefusal>;
async fn chain_reopen(&self, operator: &OperatorIdentity, expected_step: Option<usize>) -> Result<OperatorChainStep, ChainRefusal>;
// route admin : POST /api/certificates/operator/chain/reopen (corps vide accepté = OperatorChainAsk::default())
// astra-operator::tunnel::Tunnel
pub fn chain_next(&self, expected_step: Option<usize>) -> Result<OperatorChainStep>;
pub fn chain_reopen(&self, expected_step: Option<usize>) -> Result<OperatorChainStep>;
```

- Les quatre nouveaux refus et `ChainStepIncomplete` traversent en 409 avec leur phrase (`OperatorChainRefusal` côté canal, `ChannelError::Plan`, `ChainRefusal::Reason`, `GatewayActionRefusal` côté admin), exactement comme `next` aujourd'hui. `reopen` partage la fonction de refus de `next` (`chain_next_refusal`, à renommer `chain_step_refusal`).

- [ ] **Step 1 : tests qui échouent** :
  - `door/tests/tunnel.rs` : `chain_reopen_runs_through_the_tunnel` (ouvrir, expirer, rouvrir → `Opened`), `chain_reopen_refusal_crosses_with_its_sentence` (409 + phrase de `ChainStepStillOpen`), `chain_next_with_a_moved_step_is_refused`.
  - `operator_contract_tests.rs` : `operator_chain_reopen_is_admin_only`, `operator_chain_reopen_relays_the_plan_sentence_as_409`, `operator_chain_next_accepts_an_empty_body_and_an_expected_step`.
  - `astra-operator/tests/tunnel.rs` : `chain_reopen_returns_the_opened_step`, `chain_reopen_refusal_is_astras_sentence`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p astra -p astra-channel -p helios-api -p heliosd -p astra-operator chain` → FAIL.
- [ ] **Step 3 :** implémenter ; amender ADR-008 et spec 5a §5.2.
- [ ] **Step 4 :** relancer → PASS ; puis les suites complètes des cinq crates → PASS.
- [ ] **Step 5 :** commit `feat(astra-channel): reopen a chain step through the tunnel, with the expected step (F14-g)`.

### Task 3: astra-operator — le renouvellement gateway sous la campagne du plan

**Files:**
- Modify: `crates/astra-operator/src/operations/gateway_identity.rs` (`open_renewal_as`, ~l.381-560)
- Test: `crates/astra-operator/src/operations/gateway_identity/tests.rs`

**Interfaces:**
- Produces :

```rust
/// Everything `open_renewal` refuses before it opens a campaign (terms, waiting decision,
/// waiting revocation, revoked, transition in flight, CA-PQ overlap, prepared request that
/// differs). Calls `prepare_renewal`, as `open_renewal` does before opening.
pub fn check_renewal(remote: &dyn GatewayIdentityRemote, vault_path: &Path,
    options: RenewalOptions, now: u64) -> Result<(), GatewayRefusal>;
/// `open_renewal`, under a campaign the chain opened: the same checks again, then the
/// given `opened` instead of an opening.
pub fn open_renewal_in(remote: &dyn GatewayIdentityRemote, vault_path: &Path,
    opened: OperatorOpened, options: RenewalOptions, now: u64)
    -> Result<OpenedGatewayRenewal, GatewayRefusal>;
```

- `open_renewal_as` se découpe en : contrôles (= `check_renewal`, rendant ce qu'il faut à la suite : `prepared`, `keys`, `relay`, `identity`, `anchor_key`), ouverture **ou** `opened` fourni, puis la suite inchangée. Une campagne fournie d'une autre famille que `GatewayIdentity` : `CampaignMismatch`, avant toute clé (la vérification de famille existante suffit si elle passe avant toute clé ; sinon l'avancer).

- [ ] **Step 1 : tests qui échouent** :
  - `check_renewal_refuses_what_open_renewal_refuses` : table de cas (termes hors bornes → `TermsOutOfRange` ; décision en attente → `AlreadyOpen` ; révocation en attente → `RevocationPending` ; gateway révoquée → `Revoked` ; transition en vol → `TransitionInFlight` ; recouvrement CA-PQ → `CaPqOverlap` ; demande reprise aux options différentes → `PreparedRequestDiffers`), et le faux distant n'a reçu **aucun** `open_campaign`.
  - `check_renewal_passes_and_opens_nothing` : cas nominal → `Ok(())`, zéro `open_campaign`.
  - `open_renewal_in_opens_no_campaign` : cas nominal avec un `OperatorOpened` fourni → `Ok(_)`, zéro `open_campaign`, l'opération de la suite est celle fournie.
  - `open_renewal_in_refuses_another_family` : `opened` d'une campagne `FleetLeafs` → `Err(CampaignMismatch)`, aucune clé demandée.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p astra-operator gateway_` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer → PASS ; `scripts/wsl-cargo test -p astra-operator` → PASS.
- [ ] **Step 5 :** commit `feat(astra-operator): renew the gateway under the chain's campaign, with its checks first (F14-g)`.

### Task 4: Orion (Rust) — le plan lu, les commandes du plan, le geste gateway dans le plan

**Files:**
- Modify: `crates/orion-core/src/operator_rotations.rs` (`AuthorityStatusRead.chain`)
- Modify: `apps/orion/src-tauri/src/commands/ceremonies.rs` (commandes), `apps/orion/src-tauri/src/main.rs` (enregistrement, `AppState`)
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`GatewayGesture::Renew.in_chain`)
- Modify: `apps/orion/src-tauri/src/operator/ceremony/gateway.rs` (renouvellement dans le plan)
- Modify: `apps/orion/src-tauri/src/operator/rotations.rs` (fonctions testables des commandes)
- Test: `apps/orion/src-tauri/src/operator/ceremony/gateway/tests.rs`, tests de `operator/rotations.rs`, tests d'`orion-core`

**Interfaces:**
- Consumes : Task 2 (`Tunnel::chain_next/chain_reopen(expected_step)`, `chain_abandon`, `open_campaign` avec `OperatorOpenAction::ChainOpen`), Task 3 (`check_renewal`, `open_renewal_in`).
- Produces :

```rust
// orion-core
pub struct ChainRead { pub steps: Vec<String> /* CampaignScope snake_case */, pub current: usize, #[serde(default)] pub operation_id: Option<String> }
// AuthorityStatusRead : #[serde(default)] pub chain: Option<ChainRead>
// AppState : pub chain_opened: std::sync::Mutex<Option<OperatorOpened>>  — mémoire seule
// commandes Tauri (toutes par le tunnel, pair vérifié comme operator_open_campaign, NO_TUNNEL sans cible,
// refusées si une cérémonie est ouverte, sauf abandon et held) :
operator_chain_start(reason: String, requested_by: String) -> Result<OperatorOpened, String>
operator_chain_next(expected_step: usize) -> Result<ChainStepOutcome, String>
operator_chain_reopen(expected_step: usize) -> Result<OperatorOpened, String>
operator_chain_abandon() -> Result<(), String>
operator_chain_held() -> Result<Option<OperatorOpened>, String>
operator_gateway_check_renewal(rotate_tls: bool, key_recovery: bool, prepare_days: u64, overlap_days: u64, validity_days: u64) -> Result<(), String>
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChainStepOutcome { Opened(Box<OperatorOpened>), Finished }
// GatewayGesture::Renew { …, #[serde(default)] in_chain: bool }
```

- `start`, `next` (`Opened`) et `reopen` remplacent `chain_opened` par l'`OperatorOpened` rendu ; `Finished` et `abandon` le vident. `held` le rend tel quel (public : identifiants, empreinte, demande PKCS#10, feuille en service).
- `Renew { in_chain: true }` : la cérémonie prend `chain_opened` ; absent, ou d'une autre portée que `GatewayIdentity` : refus « La campagne de l'étape n'est plus connue d'Orion : rouvrir l'étape après son échéance. » avant toute clé ; sinon `open_renewal_in`. `in_chain: false` : inchangé.
- Le refus d'un `next`/`reopen` est la phrase d'Astra telle quelle.
- `chain_opened` n'est jamais journalisé (`tracing`) ni écrit.

- [ ] **Step 1 : tests qui échouent** :
  - orion-core : `authority_status_reads_the_chain` (JSON avec `chain`) et `authority_status_without_chain_reads_none`.
  - rotations.rs (faux tunnel) : `chain_start_keeps_the_opened_step`, `chain_next_finished_clears_the_held_step`, `chain_reopen_replaces_the_held_step`, `chain_abandon_clears_the_held_step`, `chain_next_refusal_is_astras_sentence`.
  - gateway/tests.rs : `renew_in_chain_uses_the_held_campaign` (aucun `open_campaign` sur le faux distant), `renew_in_chain_without_a_held_step_is_refused_before_any_key`, `renew_in_chain_refuses_a_held_step_of_another_scope`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core -p orion chain` → FAIL.
- [ ] **Step 3 :** implémenter ; enregistrer les commandes dans `main.rs`.
- [ ] **Step 4 :** relancer → PASS ; `scripts/wsl-cargo test -p orion-core --all-features` et `-p orion` complets → PASS ; clippy workspace.
- [ ] **Step 5 :** commit `feat(orion): drive the renewal chain through the tunnel, and renew the gateway under it (F14-g)`.

### Task 5: Orion (TS) — types, API et état de la ligne

**Files:**
- Modify: `apps/orion/src/types.ts` (`OperatorAuthorityStatus.chain`, `ChainStepOutcome`, `GatewayGesture` Renew `in_chain`)
- Modify: `apps/orion/src/api.ts` (six fonctions)
- Create: `apps/orion/src/views/astra/chainRow.ts`
- Test: `apps/orion/src/views/astra/chainRow.test.ts`

**Interfaces:**
- Consumes : Task 4 (noms des commandes et formes JSON).
- Produces :

```ts
// types.ts
chain?: { steps: CampaignScope[]; current: number; operation_id: string | null } | null
export type ChainStepOutcome = ({ outcome: 'opened' } & OperatorOpened) | { outcome: 'finished' }
// api.ts
operatorChainStart(reason: string, requestedBy: string): Promise<OperatorOpened>
operatorChainNext(expectedStep: number): Promise<ChainStepOutcome>
operatorChainReopen(expectedStep: number): Promise<OperatorOpened>
operatorChainAbandon(): Promise<void>
operatorChainHeld(): Promise<OperatorOpened | null>
operatorGatewayCheckRenewal(terms: GatewayRenewTerms): Promise<void>
// GatewayRenewTerms (nouveau, exporté de types.ts) = les champs de `GatewayGesture` « renew » sans `gesture` ni `in_chain` :
//   { rotate_tls: boolean; key_recovery: boolean; prepare_days: number; overlap_days: number; validity_days: number }
// chainRow.ts
export type ChainAction = 'start' | 'resume_step' | 'continue' | 'reopen' | 'finish' | 'abandon'
export interface ChainRowInput {
  overview: RotationsOverview
  now: number
  held: OperatorOpened | null          // operatorChainHeld()
  fleetApprovedThisSession: string | null // operation_id dont la cérémonie parc a fini `done` ici
}
export interface ChainRow {
  title: 'Tout renouveler'
  state: string            // « Étape k sur 4 : <nom> · … » ou la phrase sans plan
  detail: string | null
  actions: ChainAction[]
  disabledReason: string | null   // pour 'start' seulement
}
export function chainRow(input: ChainRowInput): ChainRow
export const STEP_NAMES: Record<string, string> // issuer_delegation → « Délégation de l'émetteur », trust_authorities → « CA TLS cliente », gateway_identity → « Identité de la gateway », fleet_leafs → « Postes »
export function stepBlocker(o: RotationsOverview, scope: CampaignScope, now: number): string | null
```

- `stepBlocker` réutilise les raisons existantes : `rotationRows.ts` (`renew_delegation`, rotation CA TLS, `renew_fleet`) et `gatewayRows.ts` (renouvellement gateway), plus « Une opération <famille> est déjà ouverte » via `liveOperation`. Les exporter au besoin, sans changer leur sortie.
- Règles de `chainRow` (spec §6.2, §6.6) :
  - pas de `chain` : `actions: ['start']`, `state` = la phrase « Quatre étapes, une cérémonie chacune : délégation de l'émetteur, CA TLS cliente, identité de la gateway, postes. CA-PQ n'en fait pas partie. Chaque cérémonie demande ses clés. », `disabledReason` = premier `stepBlocker` non nul des quatre étapes ;
  - étape courante, opération vivante (dans `pending`, échéance non passée à l'horloge de la gateway) : `['resume_step', 'abandon']`, sauf délégation ou gateway sans `held` de même `operation_id` : `['abandon']` et `detail` « Campagne de l'étape perdue par Orion : rouvrir l'étape après <échéance>. » ;
  - opération fermée, étape ≠ parc : `['continue', 'reopen', 'abandon']` ;
  - opération fermée, étape parc : `fleetApprovedThisSession === operation_id` → `['continue', 'abandon']` ; sinon `['reopen', 'finish', 'abandon']` et `detail` « Orion ne peut pas savoir si les postes ont été autorisés : rouvrir l'étape si la cérémonie n'a pas abouti. » ;
  - `abandon` toujours accompagné, dans le composant, de « Ce qui est déjà approuvé garde son effet. »

- [ ] **Step 1 : tests qui échouent** (`chainRow.test.ts`, fixtures de `rotationFixtures.ts`) : `no_plan_offers_start`, `start_is_blocked_by_the_first_blocked_step`, `start_is_blocked_by_a_live_operation_of_a_chain_family`, `open_step_offers_resume`, `delegation_without_held_request_says_lost`, `gateway_without_held_step_says_lost`, `closed_step_offers_continue_and_reopen`, `closed_fleet_step_without_session_success_offers_reopen_and_finish`, `closed_fleet_step_after_session_success_offers_continue`, `expiry_reads_the_gateway_clock`.
- [ ] **Step 2 :** `cd apps/orion && npx vitest run src/views/astra/chainRow.test.ts` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer → PASS ; `npx vitest run src/views/astra` et `npx tsc --noEmit` → PASS.
- [ ] **Step 5 :** commit `feat(orion): the « Tout renouveler » row's state, from the plan Astra holds (F14-g)`.

### Task 6: Orion (TS) — la ligne « Tout renouveler » et ses gestes

**Files:**
- Create: `apps/orion/src/views/astra/RenewAllBlock.tsx`
- Modify: `apps/orion/src/views/astra/RotationsPanel.tsx` (la ligne au-dessus des lignes par action), `apps/orion/src/views/astra/RotationSteps.tsx` (prop `obtainOperation`)
- Modify: `apps/orion/src/views/astra/GatewayIdentityBlock.tsx` seulement pour exporter les champs de durées réutilisables (sans changer leur rendu)
- Test: `apps/orion/src/views/astra/RenewAllBlock.test.tsx`, `RotationSteps.test.tsx`

**Interfaces:**
- Consumes : Task 5 (`chainRow`, `stepBlocker`, `STEP_NAMES`, API), `onCeremony`, `beginIssuerCeremony`, `beginOperatorCeremony({kind:'approve_campaign', operation_id})`, `beginGatewayCeremony({gesture:'renew', …, in_chain: true})`.
- Produces :

```ts
// RotationSteps : prop optionnelle
obtainOperation?: () => Promise<string>  // appelée après les prérequis, avant approveRotationCeremony ; son résultat devient existing_operation
```

- Gestes (spec §6.3) ; chaque geste relit d'abord la vue (`refresh`), et passe `expected_step = chain.current` (`continue` : l'étape suivante est `current + 1` pour les contrôles, `expected_step` reste `current`) :
  - `start` : `stepBlocker(issuer_delegation)` nul et aucune cérémonie en cours (`operatorCeremonyStatus`), puis `operatorChainStart(motif, libellé)`, puis `beginIssuerCeremony({gesture:'authorize_issuer', operation_id, request: delegation_request})`.
  - `continue` / `reopen` vers une étape :
    - délégation : contrôles, puis `operatorChainNext`/`operatorChainReopen`, puis cérémonie émetteur ;
    - CA TLS : `RotationSteps` (action rotation CA TLS) avec `obtainOperation` = l'appel `next`/`reopen` rendant `operation_id` ; les prérequis passent avant ;
    - gateway : champs de durées et « Remplacer aussi la feuille TLS » dans la ligne ; `operatorGatewayCheckRenewal(terms)`, puis `next`/`reopen`, puis `beginGatewayCeremony({gesture:'renew', …terms, in_chain: true})` ;
    - parc : contrôles, puis `next`/`reopen`, puis `approve_campaign` ; le composant note l'`operation_id` et, quand `operatorCeremonyStatus()` lit `gesture === 'done'` pour cette opération, le passe en `fleetApprovedThisSession`.
    - `next` rendant `finished` : « Parc autorisé ; chaque poste se renouvelle à sa prochaine connexion. », plus le rappel « Terminer la rotation CA TLS » si une rotation CA TLS est en cours (`caTlsCloseAt` non nul).
  - `resume_step` : le geste de l'étape sur l'opération vivante, sans `next` (délégation : `held.delegation_request` ; gateway : `in_chain: true`).
  - `finish` : `operatorChainNext(current)` (rend `finished`).
  - `abandon` : confirmation avec « Ce qui est déjà approuvé garde son effet. », puis `operatorChainAbandon`.
  - Un refus d'Astra s'affiche tel quel, avec « Relire plus tard » (bouton qui relit la vue).
  - Tout bouton est désactivé pendant une cérémonie en cours.

- [ ] **Step 1 : tests qui échouent** (`RenewAllBlock.test.tsx`, API moquée comme `RotationsPanel.test.tsx`) :
  - `start_opens_the_chain_then_the_issuer_ceremony` (ordre des appels, `request` = `delegation_request`)
  - `continue_checks_before_asking_astra` : `stepBlocker` non nul pour l'étape suivante → `operatorChainNext` jamais appelé, raison affichée
  - `continue_to_gateway_checks_renewal_before_next` : `operatorGatewayCheckRenewal` rejette → `operatorChainNext` jamais appelé
  - `continue_to_gateway_renews_in_chain` : `beginGatewayCeremony` reçoit `in_chain: true`
  - `continue_passes_the_expected_step`
  - `a_moved_plan_sentence_is_shown_as_is`
  - `reopen_still_open_sentence_is_shown_as_is`
  - `finished_reads_fleet_authorized`
  - `abandon_says_what_was_approved_keeps_its_effect`
  - `fleet_done_this_session_offers_continue`
  - `RotationSteps.test.tsx` : `obtain_operation_runs_after_prerequisites_and_feeds_existing_operation`
- [ ] **Step 2 :** `cd apps/orion && npx vitest run src/views/astra/RenewAllBlock.test.tsx src/views/astra/RotationSteps.test.tsx` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer → PASS ; `npx vitest run` et `npx tsc --noEmit` → PASS.
- [ ] **Step 5 :** commit `feat(orion): « Tout renouveler » in the Rotations tab (F14-g)`.

### Task 7: documentation et recette

**Files:**
- Modify: `docs/RENOUVELLEMENT-CERTIFICATS.md` (l.40, §1/§7 mentions l.82-115, §10 l.1246-1291)
- Modify: `docs/testing/MANUAL-TESTING.md` (nouvelle section « K. F14-g », après « J. Lot 6c »)
- Modify: `docs/ROADMAP.md` (ligne F14-g : levé, au passé, livré sur la branche `feat/f14-g-tout-renouveler`, pas encore fusionné ; ligne F14 : la phrase du plan « Tout renouveler »)

- [ ] **Step 1 :** RENOUVELLEMENT §10 : « Dans Orion » d'abord (commencer, continuer, reprendre, rouvrir, abandonner, cas du parc, délégation ou gateway perdues après un redémarrage), la console en recours ; l.40 et §7 alignés.
- [ ] **Step 2 :** MANUAL-TESTING « K. F14-g » : étapes numérotées à la suite de la section J, **[cible]** quand WSL ne peut pas les jouer : plan complet ; « Continuer » bloqué par un contrôle ; étape expirée puis rouverte ; plan avancé par `astra chain next` à la console puis clic dans Orion (refus) ; Orion fermé pendant l'étape gateway ; étape du parc sans cérémonie réussie ; abandon.
- [ ] **Step 3 :** ROADMAP.
- [ ] **Step 4 :** relire les trois fichiers contre la spec §6 (noms des boutons et phrases identiques à l'écran).
- [ ] **Step 5 :** commit `docs: « Tout renouveler » in Orion, its recipe and the roadmap (F14-g)`.
