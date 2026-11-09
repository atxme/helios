# F14 lot 5c : révoquer un poste depuis Orion — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** révoquer un poste client depuis un onglet *Postes* d'Orion, couper d'abord à la gateway, signer ensuite, y compris pendant un recouvrement `CA-PQ`.

**Architecture:**
- Gateway : la gateway sert à Astra la liste de ses postes sur le canal privé.
- Astra :
  - elle les recopie (balayage et ouverture d'une révocation) ;
  - elle rejoue le relais d'une révocation non appliquée ;
  - elle publie dans `operator/status` les postes révoqués et le document de credentials qu'elle sert.
- Coffre : il garde la clé `CA-PQ` sortante de la signature d'une rotation jusqu'à « Terminer », pour la seule signature des révocations.
- Orion :
  - il coupe par l'API d'administration de la gateway, puis mène la campagne de révocation par la porte d'Astra (lot 5a) ;
  - il réutilise le fil de cérémonie et les étapes du 5b.

**Tech Stack:**
- Rust : `aether`, `astra`, `astra-channel`, `astra-operator`, `heliosd`, `helios-api`, `orion-core`.
- Orion : Tauri (`apps/orion/src-tauri`), React/TypeScript (`apps/orion/src`), Vitest.

**Spec:** `docs/superpowers/specs/2026-11-08-f14-lot5c-revocation-design.md`.
Le spec fait autorité : en cas d'écart, le spec gagne.

## Global Constraints

- Ne jamais travailler sur `main` : worktree `/home/christophe/helios-wt/f14-lot5c`, branche `feat/f14-lot5c-revocation`.
- Compiler et tester uniquement par `scripts/wsl-cargo`, avec `CARGO_BUILD_JOBS=2` et `RUST_TEST_THREADS=2`.
  - Jamais de `target/` dans le worktree, ni de `CARGO_TARGET_DIR`, ni de `HELIOS_WSL_BUILD_OVER_BUDGET`, ni de `scripts/clean-wsl-targets`.
  - Refus pour mémoire : attendre par une boucle `until` en arrière-plan sur `MemAvailable` (environ 10 min, 3 fois au plus). Ne jamais forcer ni tuer un processus.
- Langues :
  - `docs/`, messages de console et libellés d'interface en français, courts et neutres, sans jamais tutoyer ;
  - commentaires et identifiants en anglais.
- Aucun secret dans la WebView : ni PIN, ni `Opened`, ni octets du coffre, ni clé privée.
- `Opened` reste sur le fil de cérémonie et s'efface à toute sortie.
- Ne pas éditer de version à la main : `scripts/version.py merge` le fera à la fusion. Pas de tag `v*`. `docs/audits` intouché.
- Commits : messages en anglais, préfixes `feat`/`fix`/`docs`/`test`/`refactor`. Une rupture de format se marque `!` (Task 4).
  - Pied obligatoire : `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Libellés exacts du spec :
  - états : « Actif », « Renouvellement en cours », « Coupé, révocation à signer », « Révoqué », « Révoqué, gateway pas encore informée » ;
  - motifs : « Volé ou perdu », « Compromis », « Plus utilisé », « Remplacé » ;
  - confirmation : « Révoquer {nom} ? Le poste sera coupé tout de suite. C'est définitif. » ;
  - signature reportée : « Révocation possible après le {JJ/MM HH:MM} » ;
  - recouvrement en cours : « Terminer la rotation CA-PQ » ;
  - avertissement : « {nom} expire le {JJ/MM/AAAA}, pendant le changement. » ;
  - pour « Ce poste » : « Se coupe sur la gateway : helios peer revoke {nom}. »

## Review Focus

1. **Nom réattribué** : le nom tapé à la gateway désigne une autre clé que la ligne cliquée (poste réenrôlé sous le même nom). La coupure est refusée et rien n'est coupé. Test : Task 9, `cut_refuses_a_name_bound_to_another_key`.
2. **Bord de la marge** : signature demandée dans l'heure avant `not_after`, ou pile à `not_after`. Refus daté, coupure faite quand même. Test : Task 5, `outgoing_signature_refused_inside_the_margin`.
3. **Astra injoignable** au moment de couper. Le poste est coupé et la ligne dit « Coupé, révocation à signer ». Test : Task 9, `cut_happens_without_astra`.
4. **Coffre d'avant ce lot** en plein recouvrement (`Applied` sans clé sortante gardée). Le bouton est grisé avec la date, pas d'erreur obscure. Test : Task 5, `no_retained_key_means_after_not_after`.
5. **Ligne « Ce poste »** : aucun bouton « Révoquer », la phrase `helios peer revoke`. Test : Task 10, `own_workstation_has_no_revoke_button`.

---

### Task 1: la gateway liste ses postes sur le canal privé

**Files:**
- Modify: `crates/astra-channel/src/lib.rs` (constante de route), `crates/astra-channel/src/gateway_routes.rs` (trait et routeur), `crates/astra-channel/src/gateway_client.rs`
- Modify: `crates/heliosd/src/certificates/astra.rs` (implémentation du trait)
- Test: `crates/astra-channel/src/tests.rs`, tests de `heliosd/src/certificates/astra.rs`

**Interfaces:**
- Produces:
  - `pub const PEERS_PATH: &str = "/internal/v1/certificates/peers";`
  - `AstraChannelHandler::peer_keys(&self) -> Result<Vec<WireGuardKey>, TrustUpdateRefusal>` ;
  - `GatewayClient::peer_keys(&self) -> Result<Vec<WireGuardKey>, ChannelError>`, réponse JSON `{"peers":["<base64>",…]}` bornée comme `peer_state`.
- Contenu : chaque poste dont la gateway tient un état de certificat, admis **ou coupé**. Un poste coupé à l'admission reste listé.

- [ ] **Step 1 :** tests `peers_route_lists_every_certificate_record` (astra-channel, handler factice) et `a_cut_peer_is_still_listed` (heliosd : poste admis, retiré de l'admission, toujours dans `peer_keys`). Ajouter `PEERS_PATH` à la liste des routes réservées que `tests.rs` contrôle.
- [ ] **Step 2 :** lancer `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 scripts/wsl-cargo test -p astra-channel -p heliosd peers`. Attendu : FAIL (route absente).
- [ ] **Step 3 :** implémenter route `GET`, trait, client, implémentation heliosd depuis le registre de certificats (même source que `peer_state`).
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-channel): the gateway lists its peers to Astra (F14 lot 5c)`.

### Task 2: Astra recopie les postes admis et rejoue le relais des révocations

**Files:**
- Modify: `crates/astra/src/daemon.rs` (boucle), `crates/astra/src/renewal/request.rs` (`transcribe_peer`, rendu réutilisable si besoin), `crates/astra/src/door/mod.rs` (ouverture `ClientRevocation`)
- Test: tests de `daemon.rs`, `door/tests/`

**Interfaces:**
- Consumes : `GatewayClient::peer_keys` (Task 1), `transcribe_peer(service, key, now)` existant.
- Produces :
  - `const PEER_SWEEP_INTERVAL_SECS: u64 = 60;`
  - `fn spawn_peer_sweep(service: Arc<AstraService>)` ;
  - `pub(crate) async fn sweep_peers(service: &Arc<AstraService>, now_unix: u64) -> SweepReport`, avec `SweepReport { transcribed: usize, relayed: usize }`.

- [ ] **Step 1 : tests.**
  - `the_sweep_transcribes_a_peer_astra_never_saw` : gateway factice avec deux clés, une connue. Après `sweep_peers`, les deux sont dans `state.peers`, `transcribed == 1`.
  - `the_sweep_relays_a_recorded_revocation_the_gateway_lacks` : révocation cliente stockée dans `state.transitions`, `peer_state` répond `revoked: false`. Le balayage appelle `revoke` une fois, `relayed == 1`. Au tour suivant, avec `revoked: true`, plus d'appel.
  - `a_revocation_opens_for_a_peer_astra_never_saw` : `DoorRequest::ClientRevocation` sur une clé absente du registre mais connue de la gateway. La campagne s'ouvre ; le sujet porte le nom lu à la gateway.
  - `a_peer_unknown_to_both_is_refused_by_name` : `DoorRefusal::PeerUnknown`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra sweep revocation_opens peer_unknown`. Attendu : FAIL.
- [ ] **Step 3 : implémenter.**
  - `sweep_peers` lit `peer_keys`, appelle `transcribe_peer` pour chaque clé absente du registre, puis, pour chaque `CertificateRevocation` de portée client stockée, lit `peer_state` et relaie par `gateway.revoke` si la gateway ne la dit pas révoquée.
  - Une erreur de canal se journalise et laisse le tour suivant réessayer, sans paniquer.
  - La porte appelle `transcribe_peer` avant `resolve::client_revocation` quand la clé est inconnue, **hors** du verrou du registre (`transcribe_peer` attend le canal).
- [ ] **Step 4 :** relancer. Attendu : PASS. Puis `scripts/wsl-cargo test -p astra`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra): record every admitted peer and replay unapplied revocations (F14 lot 5c)`.

### Task 3: `operator/status` dit les postes révoqués et sert le document de credentials

**Files:**
- Modify: `crates/aether/src/certificates/transport.rs` (`OperatorAuthorityStatus`), `crates/astra/src/operator.rs` (`status`), `crates/orion-core/src/operator_rotations.rs` (`AuthorityStatusRead`)
- Vérifier : les bornes de réponse `MAX_OPERATOR_ANSWER_BYTES` (`astra-channel`) et `MAX_ANSWER_BYTES` (`orion-core`) avec un document de 8 liaisons. Relever la borne si elle ne suffit pas, et le dire dans le rapport.
- Test : `crates/astra/src/operator.rs` (tests), `crates/orion-core/src/operator_rotations.rs` (tests)

**Interfaces:**
- Produces, champs ajoutés à `OperatorAuthorityStatus`, tous deux `#[serde(default)]` :
  - `pub revoked_peers: Vec<WireGuardKey>` : les postes qu'Astra tient pour révoqués ;
  - `pub served_credentials: Option<Box<CredentialRegistry>>` : le document qu'Astra sert, entier ; `None` quand elle n'en sert pas.
- Le commentaire de type « no document » est corrigé : le document est public et signé.
- Côté Orion, `AuthorityStatusRead` gagne `revoked_peers: Vec<String>` et `served_credentials: Option<serde_json::Value>`. La valeur est gardée brute et vérifiée seulement par la Task 6, jamais crue telle quelle.

- [ ] **Step 1 :** tests `status_names_revoked_peers`, `status_serves_the_outgoing_document_during_an_overlap` (Astra, avec le cas `daemon.rs::the_overlap_keeps_serving_the_outgoing_document` comme modèle) et `status_read_tolerates_the_new_fields` (orion-core).
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra -p orion-core status`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter. heliosd relaie le type tel quel : vérifier qu'il compile, sans autre changement.
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra): status names revoked peers and serves the credential document (F14 lot 5c)`.

### Task 4: le coffre garde la clé `CA-PQ` sortante jusqu'à « Terminer »

**Files:**
- Modify: `crates/astra-operator/src/vault.rs` (`AuthoritySecrets`, `replace_anchors`, `stage_ca_tls_successor`), `crates/astra-operator/src/signing/anchor.rs` (`rotate_ca_pq`), `crates/astra-operator/src/signing/ca_tls.rs` (refus)
- Test : `crates/astra-operator/src/vault.rs` (tests), `crates/astra-operator/tests/signing.rs`

**Interfaces:**
- Produces :

```rust
/// The outgoing `CA-PQ`, kept from the signature of a rotation until « Terminer ».
pub struct RetainedOutgoingCaPq {
    pub private_key: String,      // ML-DSA-87 private key, base64
    #[zeroize(skip)] pub public_key: String,   // base64
    #[zeroize(skip)] pub ca_epoch: u64,
    #[zeroize(skip)] pub not_after: u64,       // the rotation window's not_after
}
// in AuthoritySecrets:
#[serde(default)]
pub retained_outgoing_ca_pq: Option<RetainedOutgoingCaPq>,
```

- `AuthorityVault::retire_outgoing_ca_pq(&mut self, opening: &Opened, now_unix: u64) -> Result<()>` : refuse avant `not_after` en nommant la seconde attendue ; détruit la clé en une écriture scellée.
- `AuthorityVault::retained_outgoing_ca_pq_public(&self) -> Option<(MlDsa87PublicKey, u64 /*ca_epoch*/, u64 /*not_after*/)>` : lisible sans ouvrir le coffre (champ clair à côté de `ca_pq_public_key`, scellé dans le corps et recopié en clair comme lui).
- `rotate_ca_pq` et `rotate_ca_tls` refusent tant que `retained_outgoing_ca_pq` est présent : « Terminer d'abord la rotation CA-PQ précédente. »

- [ ] **Step 1 : tests.**
  - `rotate_ca_pq_keeps_the_outgoing_key` : après rotation, le coffre ouvert porte l'ancienne clé privée dans `retained_outgoing_ca_pq`, avec `ca_epoch` sortant et `not_after` de la fenêtre.
  - `a_vault_written_before_this_lot_opens` : JSON sans le champ, ouverture et lecture sans erreur, champ `None`.
  - `retire_refuses_before_not_after` puis `retire_destroys_the_outgoing_key`.
  - `no_anchor_rotation_while_an_outgoing_key_is_kept` : `CA-PQ` et `CA-TLS`.
  - `ca_tls_staging_keeps_the_outgoing_ca_pq` : `stage_ca_tls_successor` et `replace_anchors` reportent le champ.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator outgoing retire rotation`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p astra-operator -p astra-signer`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-operator)!: keep the outgoing CA-PQ key until the rotation ends (F14 lot 5c)`, avec en pied `BREAKING CHANGE: a vault written by this version does not open with an older Orion or astra-signer.`

### Task 5: signer une révocation sous l'ancre qu'Astra vérifie

**Files:**
- Modify: `crates/astra-operator/src/signing/revocation.rs`, `tools/astra-signer/src/commands/revocation.rs`
- Test : `crates/astra-operator/tests/signing.rs`, tests de `signing/revocation.rs`

**Interfaces:**
- Consumes : Task 4.
- Produces :

```rust
pub const OUTGOING_REVOCATION_MARGIN_SECS: u64 = 3600;
pub enum RevocationAnchor { Current, Outgoing }
pub enum RevocationAnchorRefusal {
    /// Inside the margin, or Astra still on the outgoing anchor with no key kept.
    NotBefore(u64),
    /// Astra serves an anchor this vault holds no key for.
    UnknownAnchor,
}
pub fn revocation_anchor(
    vault: &AuthorityVault,
    astra_ca_fingerprint: &Fingerprint,
    astra_ca_epoch: u64,
    // The gateway's `ca_retire_active_at` (GatewayDomainRead), when an overlap runs.
    overlap_not_after: Option<u64>,
    now_unix: u64,
) -> Result<RevocationAnchor, RevocationAnchorRefusal>;
// sign_revocation gains `anchor: RevocationAnchor` and takes ca_epoch from it,
// never from `identity.ca_epoch` when the anchor is Outgoing.
```

- Règle :
  - l'ancre d'Astra est l'actuelle du coffre : `Current` ;
  - c'est la sortante gardée et `now < not_after - OUTGOING_REVOCATION_MARGIN_SECS` : `Outgoing` ;
  - la sortante gardée dans la marge : `NotBefore(not_after)` ;
  - la sortante sans clé gardée (coffre d'avant ce lot) : `NotBefore(overlap_not_after)` quand la gateway donne la fin du recouvrement, sinon `UnknownAnchor` ;
  - autre chose : `UnknownAnchor`.
- La clé sortante n'est lue que par `sign_revocation` : ses champs restent privés au module coffre, avec un accès `pub(crate)` dédié.

- [ ] **Step 1 : tests.**
  - `outgoing_signature_verifies_under_the_outgoing_anchor` : la révocation vérifie sous la clé publique sortante et l'époque sortante.
  - `outgoing_signature_refused_inside_the_margin` : à `not_after - 3600` et à `not_after`.
  - `current_anchor_outside_a_rotation`.
  - `no_retained_key_means_after_not_after`.
  - `unknown_anchor_is_refused`.
  - `no_other_signing_path_reads_the_outgoing_key` : un test qui signe une transition `CA-TLS`, une délégation et une liaison avec un coffre portant une clé sortante différente, et vérifie chaque signature sous l'actuelle.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator revocation`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter, puis adapter `astra-signer revoke`, qui lit l'ancre d'Astra dans la campagne vérifiée et appelle `revocation_anchor`.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p astra-operator -p astra-signer`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-operator): sign a revocation under the anchor Astra checks (F14 lot 5c)`.

### Task 6: l'opération de révocation (astra-operator)

**Files:**
- Create: `crates/astra-operator/src/operations/revocation.rs` (et `revocation/tests.rs`)
- Modify: `crates/astra-operator/src/operations.rs` (module), `crates/astra-operator/src/tunnel.rs` si un appel manque
- Test : `crates/astra-operator/src/operations/revocation/tests.rs`

**Interfaces:**
- Consumes :
  - `Tunnel::{open_campaign, fetch_campaign, submit_campaign, authority_status}` ;
  - `ValidatedKeys` du 5b (`operations/rotation.rs`), à réutiliser, pas à copier : le déplacer dans un module partagé si nécessaire ;
  - Task 3 (`served_credentials`) et Task 5.
- Produces :

```rust
pub enum RevocationReasonChoice { StolenOrLost, Compromised, NoLongerUsed, Replaced }
// → suspected_compromise, key_compromise, cessation, superseded
pub trait RevocationRemote { /* open_campaign, fetch_campaign, submit_campaign, authority_status */ }
pub struct OpenedRevocation { /* campaign verified, chosen credential document, anchor */ }
pub fn open(remote: &dyn RevocationRemote, vault_path: &Path, peer: &WireGuardKey,
            reason: RevocationReasonChoice, now: u64) -> Result<OpenedRevocation, RevocationRefusal>;
impl OpenedRevocation {
    pub fn subject_name(&self) -> &str;          // what the campaign names, shown to the operator
    pub fn required_credentials(&self) -> u8;
    pub fn offered(&self) -> Vec<Vec<u8>>;       // active ids of the chosen document only
    pub fn approve(&mut self, key: &dyn Authenticator, now: u64) -> Result<String, KeyStep>;
    pub fn sign_and_record(self, vault_path: &Path, now: u64) -> Result<SignedRevocation>;
}
pub fn deposit(remote: &dyn RevocationRemote, vault_path: &Path, signed: &SignedRevocation)
    -> Result<RevocationDeposit>;          // Accepted | AlreadyRevoked
pub fn pending(vault_path: &Path) -> Result<Option<SignedRevocation>>; // the local record, if any
pub enum RevocationRefusal { AlreadyRevoked, AlreadyPending, PeerUnknown, NotBefore(u64),
    UnknownAnchor, CredentialsUnverified, CampaignMismatch, Unreachable, Internal(String) }
```

- Règles du spec :
  - **choix du document** (§5.4) : avec l'ancre `Outgoing`, `served_credentials` vérifié sous la clé publique sortante et son `ca_epoch` ; avec `Current`, le document local, comme au 5b ; un document qui ne se vérifie pas donne `CredentialsUnverified`, avant tout toucher ;
  - **liaison** (§6) : le sujet affiché est celui de la campagne ; si sa clé diffère de `peer`, `CampaignMismatch` ;
  - **enregistrement local** (§5.7) : `pending-revocation.json` à côté du coffre, écrit avant le dépôt, effacé à l'acceptation ou à l'expiration de la campagne. Une décision signée ne resert que sous sa campagne.

- [ ] **Step 1 : tests, avec un `RevocationRemote` factice.**
  - `opens_and_offers_only_active_keys_of_the_chosen_document`.
  - `outgoing_anchor_uses_the_served_document`.
  - `unverifiable_served_document_is_refused_before_any_touch`.
  - `campaign_naming_another_key_is_refused`.
  - `signed_decision_is_recorded_before_deposit`.
  - `lost_answer_redeposits_the_same_bytes_without_a_key`.
  - `expired_campaign_discards_the_record`.
  - `already_revoked_is_named`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator operations::revocation`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p astra-operator`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(astra-operator): revoke a workstation through Astra's door (F14 lot 5c)`.

### Task 7: preuve de bout en bout pendant un recouvrement `CA-PQ`

**Files:**
- Create: `crates/astra/tests/revocation_during_overlap.rs` (ou le module de tests d'intégration existant d'Astra, au choix du constructeur)
- Test : vérification gateway via la fonction utilisée par `heliosd/src/certificates/astra.rs::revoke`

**Interfaces:**
- Consumes : Tasks 2-6.

- [ ] **Step 1 : test `a_revocation_during_a_ca_pq_overlap_is_accepted_by_astra_and_the_gateway`.**
  - Un domaine avec une rotation `CA-PQ` acceptée et non échue, un coffre portant la clé sortante.
  - Campagne de révocation ouverte par la porte et approuvée sous le document servi.
  - Signature par `revocation_anchor` puis `sign_revocation`.
  - Dépôt accepté par Astra ; le pair est `revoked`.
  - La même révocation vérifie sous l'ancre courante d'une gateway en recouvrement.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra revocation_during`.
  - Attendu : PASS avec le code des Tasks 2-6.
  - En cas d'échec, **s'arrêter et rendre `BLOCKED`** avec la cause : sans ce test, F14-b n'est pas levé (spec §5.4).
- [ ] **Step 3 :** commit `test(astra): a revocation passes during a CA-PQ overlap (F14 lot 5c)`.

### Task 8: lectures Orion pour l'onglet *Postes*

**Files:**
- Modify: `crates/orion-core/src/gateway_admin.rs` (lecture de l'admission, coupure par nom), `crates/orion-core/src/operator_rotations.rs` (lecture `/api/certificates` complète des postes)
- Modify: `apps/orion/src-tauri/src/commands/ceremonies.rs` (nouvelle commande), `apps/orion/src-tauri/src/main.rs` (enregistrement)
- Test : tests de ces modules

**Interfaces:**
- Produces :

```rust
// orion-core
pub async fn admitted_peers(client: &Client, base: &str) -> Result<Vec<AdmittedPeer>, GatewayAdminError>;
pub struct AdmittedPeer { pub name: String, pub wg_public_key: String }
pub async fn revoke_peer(client: &Client, base: &str, name: &str) -> Result<(), GatewayAdminError>;
pub struct PeerCertificateRead { pub name: String, pub wg_public_key: String,
    pub not_before: u64, pub not_after: u64, pub revoked: bool, pub renewing: bool }
// Tauri
#[tauri::command] async fn operator_peers_overview(state) -> Result<PeersOverview, String>;
pub struct PeersOverview {
    pub certificates: Reach<Vec<PeerCertificateRead>>,   // gateway /api/certificates
    pub admitted: Reach<Vec<AdmittedPeer>>,              // gateway /api/network
    pub astra_revoked: Reach<Vec<String>>,               // operator/status revoked_peers
    pub pending_revocations: Reach<Vec<String>>,         // keys with a pending client_revocation
    pub own_key: Option<String>,                         // this workstation's WG key in the domain profile
    pub now_unix: Option<u64>,                           // gateway clock
    pub local_pending: Option<String>,                   // key named by pending-revocation.json
}
```

- `renewing` vient de `pending` / `next_generation` de la vue gateway.
- Aucune clé privée, aucun document ne traverse : des noms, des clés publiques, des dates.

- [ ] **Step 1 :** tests `peers_overview_merges_the_three_reads`, `an_unreachable_astra_leaves_the_gateway_reads` et `own_key_comes_from_the_domain_profile`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p orion-core -p orion peers`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(orion): read the workstations of the domain (F14 lot 5c)`.

### Task 9: la cérémonie « Révoquer » et « Terminer la rotation CA-PQ » (Tauri)

**Files:**
- Create: `apps/orion/src-tauri/src/operator/ceremony/revocation.rs` (et tests)
- Modify:
  - `apps/orion/src-tauri/src/operator/mod.rs` : `RevocationGesture`, et `RotationGesture::FinishCaPq` ;
  - `apps/orion/src-tauri/src/operator/ceremony/rotation.rs` : « Terminer » CA-PQ ;
  - `apps/orion/src-tauri/src/operator/ceremony.rs` : aiguillage, refus.
- Test : `apps/orion/src-tauri/src/operator/ceremony/revocation.rs` (tests)

**Interfaces:**
- Consumes : Tasks 6 et 8, `Ceremony`/`publish`/`Press` du 5b, la garde « gateway du domaine » du 5b (comparaison de `gateway_wg_public_key`).
- Produces :

```rust
pub enum RevocationGesture {
    /// Cut, then open, approve, sign and deposit.
    Revoke { peer: String /*wg base64*/, name: String, reason: RevocationReasonChoice },
    /// Already cut: open, approve, sign and deposit, or redeposit the local record.
    Resume { peer: String },
}
pub fn run_revocation(session_id: Id16, gesture: RevocationGesture, gateway: Option<GatewayTarget>,
    presses: Receiver<Press>, publish: &mut dyn FnMut(OperatorStatus), vault_path: &Path)
    -> Result<(), String>;
```

- Ordre, `Revoke` :
  1. Garde « gateway du domaine ».
  2. Relire l'admission et vérifier que `name` porte `peer`, sinon refus sans couper.
  3. `revoke_peer`.
  4. Publier l'état « coupé ».
  5. Puis `revocation::open` et la suite.
- Toute erreur après l'étape 3 laisse le poste coupé et publie la raison. La coupure n'attend ni Astra, ni le coffre, ni la marge.
- `RotationGesture::FinishCaPq` : une clé, `retire_outgoing_ca_pq`, puis envoi de la copie du coffre comme après un geste de clé (5b).
- `OperationKind::RevokeCertificate` porte le geste dans le `OperationLocator`.

- [ ] **Step 1 : tests, avec gateway et remote factices.**
  - `cut_refuses_a_name_bound_to_another_key` : rien n'est coupé.
  - `cut_happens_without_astra` : coupé, état final « à signer », raison publiée.
  - `cut_happens_inside_the_margin` : coupé, `NotBefore` publié.
  - `revoke_runs_to_revoked`.
  - `resume_redeposits_without_a_key`.
  - `opened_is_erased_on_every_exit` : modèle des tests 5b.
  - `finish_ca_pq_retires_and_sends_the_copy`.
  - `another_domains_gateway_is_never_cut`.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p orion revocation finish_ca_pq`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `scripts/wsl-cargo test -p orion`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(orion): revoke a workstation and end a CA-PQ rotation (F14 lot 5c)`.

### Task 10: l'onglet *Postes* (React)

**Files:**
- Create: `apps/orion/src/views/astra/peerRows.ts`, `peerRows.test.ts`, `PeersPanel.tsx`, `PeersPanel.test.tsx`
- Modify: `apps/orion/src/views/AstraView.tsx` (onglet *Postes* à côté de *Rotations*), `RotationSteps.tsx` (étape Motif, réutilisée)

**Interfaces:**
- Consumes : `operator_peers_overview` (Task 8), `begin_operator_ceremony` avec `RevocationGesture` (Task 9).
- Produces : `export function peerRows(overview: PeersOverview): PeerRow[]`, avec `PeerRow { key, name, addedAt?, state, notAfter, own, action: 'revoke' | 'resume' | null, reason? }`.
- États, d'après le spec §5.1 : calculés, jamais stockés.
  - admis et non révoqué chez Astra : « Actif », ou « Renouvellement en cours » si `renewing` ;
  - non admis et non révoqué chez Astra : « Coupé, révocation à signer », action `resume` ;
  - révoqué chez Astra et non admis : « Révoqué », grisé ;
  - révoqué chez Astra et encore admis : « Révoqué, gateway pas encore informée ».
- `addedAt` (`not_before`) ne s'affiche que si deux lignes portent le même nom.
- La ligne `own` n'a aucune action et porte « Se coupe sur la gateway : helios peer revoke {nom}. »
- Rafraîchissement : à l'ouverture, au bouton ↻, après chaque geste.

- [ ] **Step 1 : tests.**
  - `peerRows` : un cas par état ; `duplicate_names_show_the_added_date` ; `own_workstation_has_no_revoke_button`.
  - `PeersPanel` : le parcours Prérequis → Motif → confirmation (libellé exact) → Clés → Suivi ; « Reprendre » sur une ligne coupée ; un refus `NotBefore` affiché « Révocation possible après le {JJ/MM HH:MM} ».
- [ ] **Step 2 :** lancer `npx vitest run src/views/astra` dans `apps/orion`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, puis `npx vitest run` et `npx tsc --noEmit`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(orion): the Postes tab (F14 lot 5c)`.

### Task 11: rotations — « Terminer la rotation CA-PQ » et avertissement d'échéance

**Files:**
- Modify: `apps/orion/src/views/astra/rotationRows.ts`, `rotationRows.test.ts`, `RotationsPanel.tsx`; `apps/orion/src-tauri/src/commands/ceremonies.rs` (`operator_rotations_overview` porte la fenêtre de la clé sortante gardée et la liste des échéances des postes)

**Interfaces:**
- Consumes : Task 4 (`retained_outgoing_ca_pq_public`), Task 8 (`PeerCertificateRead`), Task 9 (`FinishCaPq`).
- Produces : la ligne « Terminer la rotation CA-PQ », « À faire » dès `not_after`, sur le modèle de « Terminer » CA-TLS. Toute ligne « Remplacer » est désactivée tant qu'elle est à faire, avec la raison.
- Avertissement (§5.5) : dans les prérequis de « Remplacer la CA-PQ », une ligne par poste non révoqué dont `not_after` tombe avant la fin de la fenêtre prévue (`prepare_days + overlap_days` du 5b), au format exact du spec. C'est un avertissement, pas un blocage.

- [ ] **Step 1 :** tests `finish_ca_pq_row_appears_at_not_after`, `replace_rows_wait_for_finish_ca_pq` et `replace_ca_pq_warns_about_expiring_peers`.
- [ ] **Step 2 :** `npx vitest run src/views/astra/rotationRows`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer, plus `scripts/wsl-cargo test -p orion rotations_overview`. Attendu : PASS.
- [ ] **Step 5 :** commit `feat(orion): end a CA-PQ rotation and warn before one (F14 lot 5c)`.

### Task 12: suivis du 5b, ligne « Copie du coffre » (N1, N2)

**Files:**
- Modify: `apps/orion/src/views/astra/VaultCopy.tsx`, `VaultPanel.tsx`, leurs tests ; état partagé si nécessaire (`useOverview.ts`)

**Interfaces:**
- N1 :
  - la ligne se relit quand le tunnel monte (événement déjà émis au 5b pour la reprise) et après chaque geste ;
  - une ligne d'envoi retenu ou échoué, avec son bouton « Réessayer l'envoi », survit à un changement de vue, tenue hors du composant.
- N2 : pendant un recouvrement `CA-PQ` (`next_ca_fingerprint` présent), si le document local est plus récent que celui d'Astra, la ligne dit « Document en attente de la fin du recouvrement ».

- [ ] **Step 1 :** tests `copy_line_rereads_when_the_tunnel_comes_up`, `failed_send_survives_a_view_change` et `overlap_shows_the_document_waiting`.
- [ ] **Step 2 :** `npx vitest run src/views/astra`. Attendu : FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** relancer. Attendu : PASS.
- [ ] **Step 5 :** commit `fix(orion): keep the vault copy line current (F14 lot 5b follow-up)`.

### Task 13: documentation et recette

**Files:**
- Modify:
  - `docs/RENOUVELLEMENT-CERTIFICATS.md` §7 : le geste Orion d'abord, les commandes comme recours jusqu'au lot 7 ; §6 et les limites connues (F14-b levé) ;
  - `docs/specification/ROTATION-CERTIFICATS.md` : amendement daté du jour sur la clé `CA-PQ` sortante gardée (§9.2), la marge, les postes recopiés par Astra ;
  - `docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md` : renvoi daté (F14-b levé, Astra recopie les postes admis, la gateway reste l'autorité) ;
  - `docs/superpowers/specs/2026-11-04-f14-lot5b-rotations-design.md` §10.8 : renvoi daté ;
  - `docs/ROADMAP.md` : 5b fusionné le 8 novembre 2026 (Helios 3.0.0, Orion 3.0.0), 5c livré sur sa branche, F14-b levé, F14-c décision prise ;
  - `docs/testing/MANUAL-TESTING.md` : section « H. Lot 5c », étapes marquées « cible » quand WSL ne peut pas les jouer ;
  - `docs/DEPLOIEMENT-ASTRA.md` : notes de version, un coffre écrit par ce lot ne s'ouvre plus avec un Orion ou un `astra-signer` plus ancien.
- Test : relecture. Chaque affirmation se vérifie dans le code, avec fichier:ligne dans le rapport.

- [ ] **Step 1 :** écrire.
- [ ] **Step 2 :** `grep -rn "Révoquer\|révocation" docs/RENOUVELLEMENT-CERTIFICATS.md docs/testing/MANUAL-TESTING.md` et contrôle des libellés contre `peerRows.ts` et `PeersPanel.tsx`.
- [ ] **Step 3 :** commit `docs: revoking a workstation from Orion (F14 lot 5c)`.

### Task 14: régression

- [ ] **Step 1 :** `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10 bash scripts/regression.sh`, en arrière-plan.
  - Attendu : sortie 0, aucun test en échec.
  - L'audit des dépendances ne montre que les avertissements tolérés.
- [ ] **Step 2 :** `python3 scripts/version.py check --base main`. Attendu : changements sans version, normal avant `version.py merge`. Ne rien éditer à la main.
- [ ] **Step 3 :** lister les validations impossibles en WSL : vraies clés, Windows, cible, `helios peer revoke` par Tailscale. Les signaler à l'utilisateur.
