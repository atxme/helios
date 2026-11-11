# F14 lot 6c : les suivis de l'identité de la gateway — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** lever F14-h, F14-i et F14-j :
- la demande reprise est affichée et les termes sont réglables ;
- l'état « Révoquée » est lu à la gateway ;
- la sonde précède l'abandon d'une révocation ;
- les deux impasses ont un jet forcé.

**Architecture:**
- Gateway : `CertificateDomainView` gagne `gateway_revoked` et `gateway_awaited_replacement`. Les lectures côté poste les reprennent, dans `astra_operator::tunnel::GatewayIdentityRead` et `orion_core::operator_rotations::GatewayDomainRead`.
- `astra-operator` :
  - bornes des termes, `reused` porté par l'ouverture, refus sur gateway révoquée ;
  - sonde de la révocation par la vue ;
  - `publication_refused` dans le registre, et deux jets forcés qui relisent la vue.
- Orion (Tauri) : `OperatorStatus.request_reused`, geste `ForceDiscard` (par le tunnel), `GatewayPendingView` enrichi.
- Orion (React) : `gatewayRow` (états révoqués, impasse B, action `force_discard`), champs des termes, confirmation du jet forcé, phrase de la demande reprise.

**Tech Stack:**
- Rust : `aether`, `astra-operator`, `heliosd`, `helios-api`, `orion-core`, `apps/orion/src-tauri`.
- Interfaces : React/TypeScript (`apps/orion/src`, `web/src`) et Vitest.

**Spec:** `docs/superpowers/specs/2026-11-11-f14-lot6c-suivis-gateway-design.md`. Le spec fait autorité : en cas d'écart, il l'emporte.

## Global Constraints

- **Travail** : worktree `/home/christophe/helios-wt/f14-lot6c`, branche `feat/f14-lot6c-suivis-gateway`. Jamais sur `main`.
- **Compilation** : `scripts/wsl-cargo` uniquement, avec `CARGO_BUILD_JOBS=2` et `RUST_TEST_THREADS=2`.
  - Jamais de `target/` dans le worktree, ni de `CARGO_TARGET_DIR`, ni de `HELIOS_WSL_BUILD_OVER_BUDGET`, ni de `scripts/clean-wsl-targets`.
  - Refus pour mémoire : attendre par une boucle `until` sur `MemAvailable`, environ 10 min et 3 fois au plus. Ne jamais tuer de processus.
- **Langues** : `docs/`, messages et libellés en français, courts et neutres, sans tutoiement. Commentaires et identifiants en anglais.
- **Secrets** : aucun secret dans la WebView ni dans un journal. `GatewayRefusal::Internal` n'est jamais affiché tel quel (`page_sentence`).
- **Champs ajoutés** : `#[serde(default)]` partout, et `deny_unknown_fields` reste là où il est. Ajouter un champ à une structure du fil ou du registre impose `scripts/wsl-cargo clippy --workspace --all-features --all-targets -- -D warnings` avant le commit, car les fixtures d'autres crates l'initialisent.
- **Interdits** : pas de version éditée à la main, pas de tag, `docs/audits` intouché, pas de `TODO`.
- **Commits** : messages en anglais, préfixes `feat`/`fix`/`docs`/`test`/`refactor`, suffixe `(F14 lot 6c)`. Pied : `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Termes** : de 1 à 3650 jours chacun, et 7, 7 et 365 par défaut.
- **Libellés exacts du spec** :
  - demande reprise : « Demande déjà préparée par la gateway pour cette époque : elle est reprise, sans nouvelle clé. » ;
  - champs : « Préparation (jours) », « Recouvrement (jours) », « Validité (jours) » ;
  - états : « Révoquée, remplaçant à installer », « Révoquée, remplaçant attendu », « Révoquée » ;
  - détails :
    - « Le remplaçant nommé par la révocation n'est pas sur ce poste. »
    - « La gateway ne sert plus. Le domaine doit être reconstruit. »
  - impasse B avant activation : « La publication est refusée : annuler la transition avant le {date}. » ;
  - bouton : « Abandonner la décision » ;
  - confirmation, impasse A : « La révocation est appliquée ; le remplaçant ne sera jamais installé. La gateway ne servira plus et le domaine devra être reconstruit. » ;
  - confirmation, impasse B : « La transition reste installée sur la gateway, sans publication. heliosd ne redémarrera plus sur cette identité. Seule une révocation de la gateway sans remplaçant reste possible. » ;
  - case à cocher : « Je confirme l'abandon de la décision » ;
  - un refus de jet forcé finit par « Rien n'a été jeté. ».

## Review Focus

1. **Vue d'une gateway antérieure au lot** (champs absents) : `gateway_revoked` vaut `false` et le remplaçant attendu est absent. Rien ne passe en « Révoquée ». Test : Task 2, `an_older_gateway_reads_as_not_revoked`.
2. **Gateway révoquée qui attend précisément le remplaçant du registre** : « Reprendre » reste l'issue et le jet forcé est refusé. Tests :
   - Task 6, `force_discard_refuses_the_awaited_replacement` ;
   - Task 8, `revoked_awaiting_this_replacement_offers_resume_only`.
3. **Tunnel coupé pendant un jet forcé ou une sonde** : rien n'est jeté ni retiré, et l'erreur dit « injoignable ». Tests :
   - Task 5, `probe_unreachable_keeps_the_revocation` ;
   - Task 6, `force_discard_without_the_view_discards_nothing`.
4. **Impasse B pile à `activation_at`** sur l'horloge de la gateway : le jet forcé est permis à partir de cet instant, et « Annuler » ne l'est plus. Tests :
   - Task 6, `force_discard_publication_refused_at_activation` ;
   - Task 8, `publication_refused_switches_from_abort_to_force_at_activation`.
5. **Registre écrit au 6b** (sans `publication_refused`) : il se relit, se reprend et se jette comme avant. Test : Task 6, `a_6b_record_reads_back`.

---

### Task 1 : la gateway dit qu'elle est révoquée

**Files:**
- Modify: `crates/helios-api/src/certificates/views.rs` (`CertificateDomainView`)
- Modify: `crates/heliosd/src/certificates/views.rs` (construction de la vue, vers la ligne 150)
- Modify: `web/src/types.ts` (type du domaine), `web/src/components/CertificateDomainPanel.tsx` (une ligne)
- Test: les tests de vue existants de `heliosd`. Chercher `gateway_rollback_expires_at` dans `crates/heliosd/src/certificates/` pour trouver le module. Tests web à côté de `CertificateDomainPanel`.

**Interfaces:**
- Produces: `CertificateDomainView.gateway_revoked: bool` (`#[serde(default)]`) et `CertificateDomainView.gateway_awaited_replacement: Option<String>` (`#[serde(default)]`, empreinte en hex minuscule), lus dans `state.gateway.revoked` et `state.gateway.awaited_replacement`.

- [ ] **Step 1 : tests qui échouent (`heliosd`)**
  - `view_names_a_revoked_gateway_and_its_awaited_replacement` : état dont `gateway.revoked = true` et `awaited_replacement = Some(f)`. Attendu : `gateway_revoked == true` et `gateway_awaited_replacement == Some(f.to_hex())`.
  - `view_of_a_revoked_gateway_without_replacement` : attendu `true` et `None`.
  - `view_of_a_serving_gateway_is_not_revoked` : attendu `false` et `None`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p heliosd view_` doit échouer, faute des champs.
- [ ] **Step 3 :** ajouter les deux champs et les remplir.
- [ ] **Step 4 :** les tests passent. Lancer aussi `scripts/wsl-cargo test -p helios-api`.
- [ ] **Step 5 : console web.** Dans `CertificateDomainPanel`, une ligne « Révoquée » quand `gateway_revoked` est vrai, sur le modèle de la ligne du retour arrière (ligne 251) :
  - valeur `remplaçant attendu` si `gateway_awaited_replacement` est présent ;
  - sinon `domaine à reconstruire`.

  Test Vitest `shows_a_revoked_gateway`. Lancer `npm run test:unit --prefix web`.
- [ ] **Step 6 :** clippy sur le workspace, puis commit `feat(heliosd): the domain view says when the gateway is revoked (F14 lot 6c)`.

### Task 2 : les lectures côté poste reprennent les deux champs

**Files:**
- Modify: `crates/astra-operator/src/tunnel.rs` (`GatewayIdentityRead`, ligne 501)
- Modify: `crates/orion-core/src/operator_rotations.rs` (`GatewayDomainRead`, ligne 94)
- Modify: `apps/orion/src/types.ts` (`GatewayDomainRead`, ligne 1069)
- Test: tests de désérialisation existants de ces deux structures (chercher `GatewayIdentityRead` et `GatewayDomainRead` dans les `tests`).

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `GatewayIdentityRead.gateway_revoked: bool` et `GatewayIdentityRead.gateway_awaited_replacement: Option<Fingerprint>`, tous deux en `#[serde(default)]`. Le `Fingerprint` est désérialisé depuis l'hex, comme `ca_pq_fingerprint`.
  - `GatewayDomainRead.gateway_revoked: bool` et `GatewayDomainRead.gateway_awaited_replacement: Option<String>`.
  - En TS : `gateway_revoked: boolean`, `gateway_awaited_replacement: string | null`.

- [ ] **Step 1 :** tests qui échouent :
  - `an_older_gateway_reads_as_not_revoked` : JSON sans les champs, attendu `false` et `None`. Un test par structure.
  - `a_revoked_view_reads_its_awaited_replacement` : JSON avec `"gateway_revoked": true` et une empreinte hex. Attendu : `Some(Fingerprint)` égal à celle de l'entrée.
- [ ] **Step 2 :** exécuter `scripts/wsl-cargo test -p astra-operator tunnel` et `scripts/wsl-cargo test -p orion-core operator_rotations` : les tests doivent échouer.
- [ ] **Step 3 :** ajouter les champs, Rust et TS.
- [ ] **Step 4 :** les tests passent. Faire passer aussi `npm run test:unit --prefix apps/orion`, en complétant les fixtures TS qui construisent un `GatewayDomainRead`.
- [ ] **Step 5 :** clippy sur le workspace, puis commit `feat(astra-operator): read the gateway's revocation through the tunnel (F14 lot 6c)`.

### Task 3 : termes bornés, demande reprise portée, refus sur gateway révoquée

**Files:**
- Modify: `crates/astra-operator/src/operations/gateway_identity.rs` (`GatewayRefusal`, `RenewalOptions`, `OpenedGatewayRenewal`, `open_renewal_as`, `open_abort`, ouverture du retour arrière)
- Modify: `crates/astra-operator/src/operations/gateway_revocation.rs` (`open_replacement`, ouverture de la révocation, `OpenedGatewayRevocation`)
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` : `MAX_GATEWAY_TERM_DAYS` devient un `pub use` de la constante d'`astra-operator`.
- Test: `crates/astra-operator/src/operations/gateway_identity/tests.rs` et `gateway_revocation/tests.rs`, avec les fakes existants de `GatewayIdentityRemote`.

**Interfaces:**
- Consumes: `GatewayIdentityRead.gateway_revoked` (Task 2).
- Produces:
  - `pub const MAX_GATEWAY_TERM_DAYS: u64 = 3_650;` dans `gateway_identity.rs`.
  - `GatewayRefusal::TermsOutOfRange`, avec le message « les termes vont de 1 à 3650 jours. Rien n'a été signé. ». La plage est formatée depuis la constante.
  - `OpenedGatewayRenewal::request_reused(&self) -> bool` et `OpenedGatewayRevocation::request_reused(&self) -> bool`. Pour ce dernier, la valeur est `true` quand la demande du remplaçant a été reprise, `false` sans remplaçant.
  - `GatewayRefusal::AlreadyRevoked` est produit par l'ouverture d'une révocation quand `gateway().gateway_revoked` est vrai. Corriger son doc-comment, qui dit « never produced here ».
  - `GatewayRefusal::Revoked` est produit par `open_renewal`, `open_abort` et l'ouverture du retour arrière dans le même cas.

- [ ] **Step 1 :** tests qui échouent :
  - `renewal_refuses_terms_out_of_range` : `prepare_days` vaut 0, puis `validity_days` vaut 3651. Attendu `Err(TermsOutOfRange)`, et le fake n'a reçu aucun appel (ni `prepare_renewal` ni `open_campaign`).
  - `renewal_carries_a_reused_request` : `prepare_renewal` renvoie `reused: true` avec les mêmes options. Attendu `opened.request_reused() == true`, puis `false` pour `reused: false`.
  - `replacement_carries_a_reused_request` : même chose pour la révocation avec remplaçant.
  - `revocation_of_a_revoked_gateway_is_refused` : la vue donne `gateway_revoked: true`. Attendu `Err(AlreadyRevoked)`, sans campagne ouverte.
  - `renewal_abort_and_rollback_refuse_a_revoked_gateway` : attendu `Err(Revoked)` pour chacun, sans campagne ouverte.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p astra-operator gateway_` doit échouer.
- [ ] **Step 3 : implémenter.**
  - Bornes vérifiées en tête de `open_renewal_as`, avant tout appel distant.
  - `reused` gardé dans `OpenedGatewayRenewal`. Le remplaçant le reprend de l'ouverture qu'il emprunte.
  - Lecture de `gateway()` en tête des ouvertures concernées. Elle est déjà faite par certaines, et le résultat est réutilisé.
- [ ] **Step 4 : cohérence avec l'ancre.** Lire `GatewayIdentityTransition::verify` (`aether`) et l'installation par `heliosd`.
  - Si une règle borne la validité de la feuille par l'échéance de `CA-PQ`, ajouter le refus avant clé correspondant, avec la date, et son test.
  - Sinon, n'ajouter rien et le noter dans le message de commit.
- [ ] **Step 5 :** les tests passent. `scripts/wsl-cargo test -p orion` compile avec la constante réexportée. Utiliser le nom de paquet Tauri du `Cargo.toml` d'`apps/orion/src-tauri`.
- [ ] **Step 6 :** clippy sur le workspace, puis commit `feat(astra-operator): bound the gateway terms and carry the reused request (F14 lot 6c)`.

### Task 4 : la cérémonie dit que la demande est reprise

**Files:**
- Modify: `crates/aether/src/certificates/operator_session.rs` (`OperatorStatus`, ligne 785)
- Modify: `apps/orion/src-tauri/src/operator/ceremony/gateway.rs` (`Held`, `hold`)
- Modify: `apps/orion/src/types.ts` (`OperatorStatus`, à côté de `peer_cut`, ligne 946), `apps/orion/src/views/OperatorCeremony.tsx`
- Test: `apps/orion/src-tauri/src/operator/ceremony/gateway/tests.rs`, `apps/orion/src/views/OperatorCeremony*.test.tsx`

**Interfaces:**
- Consumes: `request_reused()` (Task 3).
- Produces: `OperatorStatus.request_reused: bool` (`#[serde(default)]`), en TS `request_reused?: boolean`, comme `peer_cut`.

- [ ] **Step 1 :** tests qui échouent :
  - Rust, `a_reused_request_is_said_before_the_keys` : le fake renvoie `reused: true`. Attendu : le premier statut qui attend une clé porte `request_reused == true`. Pour `reused: false`, il porte `false`.
  - Vitest, `says_the_reused_request` : un statut en attente de clé avec `request_reused: true` affiche la phrase exacte. Il ne l'affiche pas sans le champ.
- [ ] **Step 2 :** lancer les deux tests : ils doivent échouer.
- [ ] **Step 3 : implémenter.**
  - `Held::request_reused()` lit l'ouverture tenue, et `hold` recopie la valeur dans le statut.
  - L'écran affiche la phrase au-dessus des clés, en `Alert severity="info" variant="outlined"`, comme les autres notes de cérémonie.
- [ ] **Step 4 :** les tests passent. Lancer `scripts/wsl-cargo test -p aether operator_session`.
- [ ] **Step 5 :** clippy sur le workspace, puis commit `feat(orion): say when the gateway's request is reused (F14 lot 6c)`.

### Task 5 : la sonde avant d'abandonner une révocation

**Files:**
- Modify: `crates/astra-operator/src/operations/gateway_revocation.rs` (`carry_revocation`, vers la ligne 280 ; `probe_expired_revocation`)
- Test: `crates/astra-operator/src/operations/gateway_revocation/tests.rs`

**Interfaces:**
- Consumes: `GatewayIdentityRead.gateway_revoked` et `.gateway_awaited_replacement` (Task 2).
- Produces:
  - `enum RevocationProbe { AppliedWithThisReplacement, AppliedWithoutThisReplacement, AppliedNoReplacement, NotApplied }` (privé au module).
  - `fn probe_revocation(remote: &dyn GatewayIdentityRemote, signed: &SignedGatewayRevocation) -> Result<RevocationProbe, GatewayRefusal>`. Une vue illisible renvoie `Err(Unreachable)`.
  - `GatewayRefusal::ReplacementNotAwaited`, avec le message « la gateway est révoquée mais n'attend pas ce remplaçant : il ne s'installera pas. « Abandonner la décision » retire le registre ; le domaine devra être reconstruit. ».

- [ ] **Step 1 :** tests qui échouent. Dans chacun, le dépôt de la révocation renvoie un `TunnelRefusal` 409.
  - `late_refusal_on_an_applied_revocation_carries_on` : la vue donne `revoked` avec ce remplaçant. Attendu : `revocation_applied` passe à vrai dans le registre, l'installation du remplaçant est appelée, et le registre est effacé à la fin.
  - `late_refusal_with_another_awaited_replacement_stops_at_impasse_a` : la vue donne `revoked` avec une autre empreinte. Attendu `Err(ReplacementNotAwaited)`, le registre a `revocation_applied`, et aucune installation n'a été tentée.
  - `late_refusal_without_replacement_clears_the_record` : la vue donne `revoked` et le registre n'a pas de remplaçant. Attendu : `Ok(())` et le registre est effacé.
  - `late_refusal_on_a_serving_gateway_drops_the_revocation` : la vue donne `revoked` faux. Attendu : le comportement du 6b, inchangé (révocation retirée, `GatewayRefused`).
  - `probe_unreachable_keeps_the_revocation` : `gateway()` échoue faute de réseau. Attendu `Err(Unreachable)` et un registre identique, octet pour octet.
  - `carry_stops_at_impasse_a_before_installing` : registre avec `revocation_applied`, sans `replacement_installed`, et la vue donne une autre empreinte. Attendu `Err(ReplacementNotAwaited)`, sans aucun appel à `install`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p astra-operator gateway_revocation` doit échouer.
- [ ] **Step 3 : implémenter.**
  - `probe_revocation` compare `Fingerprint`s, via l'empreinte de `transition_of(replacement)`.
  - `carry_revocation` appelle la sonde sur `GatewayRefused` avant de retirer quoi que ce soit, puis avant d'installer un remplaçant quand `revocation_applied` est déjà vrai.
  - `probe_expired_revocation` garde sa sonde par installation, mais consulte `probe_revocation` d'abord quand la vue répond. Pas de duplication de la comparaison.
- [ ] **Step 4 :** les tests passent, y compris ceux du 6b dans ce module.
- [ ] **Step 5 :** commit `fix(astra-operator): read the gateway before dropping a late-refused revocation (F14 lot 6c)`.

### Task 6 : publication refusée et jets forcés

**Files:**
- Modify: `crates/astra-operator/src/operations/gateway_identity.rs` (`SignedGatewayDecision`, `carry`, nouvelle `force_discard_pending`)
- Modify: `crates/astra-operator/src/operations/gateway_revocation.rs` (nouvelle `force_discard_pending_revocation`)
- Test: les deux modules `tests.rs`

**Interfaces:**
- Consumes: Task 2, Task 5 (`probe_revocation`, `ReplacementNotAwaited`).
- Produces:
  - `SignedGatewayDecision.publication_refused: Option<String>` (`#[serde(default)]`). Il est rempli dans `carry` par tout `GatewayRefusal::GatewayRefused(reason)` venu de `remote.publish`, et le refus est renvoyé tel quel. Un succès ultérieur efface le registre comme aujourd'hui.
  - `pub fn force_discard_pending(remote: &dyn GatewayIdentityRemote, vault_path: &Path, now: u64) -> Result<(), GatewayRefusal>`.
  - `pub fn force_discard_pending_revocation(remote: &dyn GatewayIdentityRemote, vault_path: &Path) -> Result<(), GatewayRefusal>`.
  - `GatewayRefusal::NotForceDiscardable(String)` : une phrase qui dit ce qui reste possible et finit par « Rien n'a été jeté. ».
- **Règles** (lues dans la vue de la gateway, sur son horloge `now_unix`) :
  - `force_discard_pending` est permis si l'une des conditions suivantes tient. Sinon, il est refusé.
    - (a) Le registre est un `Renewal` installé, non publié, avec `publication_refused` présent, et la vue dit `now_unix >= gateway_activation_at`.
    - (b) La vue dit `gateway_revoked`.
  - `force_discard_pending_revocation` est permis si la vue dit `gateway_revoked` et que le remplaçant du registre n'est pas celui qu'elle attend : absent, différent, ou registre sans remplaçant. Sinon, il est refusé.
  - Les phrases de refus :
    - avant activation, impasse B : « la transition s'annule encore : choisir « Annuler ». Rien n'a été jeté. » ;
    - remplaçant attendu : « la gateway attend ce remplaçant : le reprendre pour l'installer. Rien n'a été jeté. » ;
    - autre cas : « cette décision peut encore aboutir : la reprendre. Rien n'a été jeté. ».
  - Une vue illisible donne `Err(Unreachable)`, et rien n'est jeté.

- [ ] **Step 1 :** tests qui échouent :
  - `a_definitive_publication_refusal_is_recorded` : `publish` renvoie un 409. Attendu : `publication_refused == Some(_)` dans le registre relu.
  - `a_transient_publication_refusal_is_not_recorded` : `publish` renvoie un 503. Attendu : `publication_refused == None`.
  - `force_discard_publication_refused_before_activation_is_refused` : attendu `Err(NotForceDiscardable)` avec la phrase « Annuler », et le registre reste.
  - `force_discard_publication_refused_at_activation` : `now_unix == gateway_activation_at`. Attendu : `Ok`, et le registre est effacé.
  - `force_discard_refuses_a_publishable_record` : sans `publication_refused`, après activation, attendu `Err(NotForceDiscardable)`.
  - `force_discard_on_a_revoked_gateway` : un registre `Renewal` quelconque et `gateway_revoked`. Attendu : `Ok`.
  - `force_discard_refuses_the_awaited_replacement` : registre de révocation dont le remplaçant est celui qu'attend la vue. Attendu `Err(NotForceDiscardable)` et le registre reste.
  - `force_discard_impasse_a` : le remplaçant diffère. Attendu : `Ok`, et le registre est effacé.
  - `force_discard_without_the_view_discards_nothing` : `gateway()` échoue faute de réseau, dans les deux fonctions. Attendu `Err(Unreachable)` et le registre reste.
  - `a_6b_record_reads_back` : le JSON d'un `SignedGatewayDecision` sans `publication_refused` se relit par `pending`, avec `publication_refused == None`.
  - Les jets ordinaires (`discard_pending`, `discard_pending_revocation`) gardent leurs refus du 6b : les tests existants restent verts sans modification.
- [ ] **Step 2 :** lancer `scripts/wsl-cargo test -p astra-operator gateway_` : les nouveaux tests échouent.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** les tests passent.
- [ ] **Step 5 :** clippy sur le workspace, puis commit `feat(astra-operator): force-discard the two gateway records with no way out (F14 lot 6c)`.

### Task 7 : Orion (Tauri) — le geste `ForceDiscard` et le registre exposé

**Files:**
- Modify: `apps/orion/src-tauri/src/operator/mod.rs` (`GatewayGesture`, `validate`, `operation`, nouvelle `force_discard_gateway_record`)
- Modify: `apps/orion/src-tauri/src/operator/ceremony/gateway.rs` (`run` refuse `ForceDiscard` comme `Discard` ; nouvelle `force_discard_waiting`)
- Modify: `apps/orion/src-tauri/src/commands/ceremonies.rs` (`begin_gateway_ceremony`, ligne 196)
- Modify: `apps/orion/src-tauri/src/operator/rotations.rs` (`GatewayPendingView`, `gateway_pending_of`)
- Modify: `apps/orion/src/types.ts` (`GatewayGesture`, `GatewayPendingView`)
- Test: `apps/orion/src-tauri/src/operator/ceremony/gateway/tests.rs`, et les tests de `rotations.rs`

**Interfaces:**
- Consumes: Task 6.
- Produces:
  - `GatewayGesture::ForceDiscard`, désérialisé depuis `{"gesture":"force_discard"}`.
  - `pub(crate) fn force_discard_waiting(remote: &dyn GatewayIdentityRemote, vault_path: &Path) -> Result<(), String>`. Elle appelle la fonction du registre qui attend, révocation d'abord, comme `discard_waiting`. Un `NotForceDiscardable(s)` arrive sur la page tel quel ; toute autre erreur passe par `page_sentence`.
  - `begin_gateway_ceremony` vérifie qu'aucune cérémonie n'est ouverte, construit le `Tunnel` depuis `connected_target`, puis appelle `force_discard_waiting` dans `spawn_blocking`. Sans profil connecté, il renvoie `NO_TUNNEL`.
  - `GatewayPendingView.publication_refused: Option<String>` (la raison n'est pas affichée à la page : seul son fait l'est). Le TS reçoit `publication_refused: boolean`, calculé côté Rust par `.is_some()`, pour ne pas faire traverser un texte de refus inutile.
  - `GatewayPendingView.replacement_fingerprint: Option<String>` (hex de la transition de remplacement enregistrée, `None` pour une décision). En TS : `replacement_fingerprint: string | null`.

- [ ] **Step 1 :** tests qui échouent :
  - `force_discard_goes_through_the_tunnel` : un fake dont la vue est révoquée et un registre `Renewal`. Attendu : `Ok`, et `pending` renvoie `None`.
  - `force_discard_refusal_reaches_the_page_as_is` : attendu, la phrase qui finit par « Rien n'a été jeté. ».
  - `pending_view_names_the_replacement_and_the_refused_publication` : les deux champs nouveaux sont remplis depuis le registre.
  - `force_discard_is_no_ceremony` : `run` avec `ForceDiscard` finit en refus interne, comme `Discard`.
- [ ] **Step 2 :** lancer ces tests : ils échouent.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** les tests passent.
- [ ] **Step 5 :** commit `feat(orion): force-discard a gateway record through the tunnel (F14 lot 6c)`.

### Task 8 : Orion (React) — états révoqués, impasse B, termes, jet forcé

**Files:**
- Modify: `apps/orion/src/views/astra/gatewayRows.ts` (`GatewayAction`, `GATEWAY_LABELS`, `gatewayRow`)
- Modify: `apps/orion/src/views/astra/GatewayIdentityBlock.tsx` (champs des termes, flux `force_discard`)
- Test: `apps/orion/src/views/astra/gatewayRows.test.ts`, `GatewayIdentityBlock.test.tsx`

**Interfaces:**
- Consumes: Task 2 (TS `GatewayDomainRead`), Task 7 (`GatewayPendingView`, geste `force_discard`).
- Produces:
  - `GatewayAction` gagne `'force_discard'`.
  - `GATEWAY_LABELS.force_discard = 'Abandonner la décision'`.
  - `GatewayRow.forceKind: 'replacement' | 'publication' | null`, qui choisit la confirmation.

**Règles de `gatewayRow`** (en tête, avant les états ordinaires) :
- Révocation en attente, non appliquée : l'état du 6b, inchangé.
- `domain.gateway_revoked`, avec un remplaçant attendu égal à `waiting.replacement_fingerprint` : « Révoquée, remplaçant à installer », actions `['resume']`.
- `domain.gateway_revoked`, avec un remplaçant attendu présent mais différent du registre, ou aucun registre : « Révoquée, remplaçant attendu », avec le détail du spec. Actions : `['force_discard']` si un registre attend, sinon `[]`. `forceKind: 'replacement'`.
- `domain.gateway_revoked` sans remplaçant attendu : « Révoquée », avec le détail du spec. Actions : `['force_discard']` si un registre attend, sinon `[]`. `forceKind: 'replacement'`.
- Registre `decision` `renewal`, installé, non publié, `publication_refused` :
  - avant `gateway_activation_at` : état « Installée, publication à faire » et détail « La publication est refusée : annuler la transition avant le {formatDateTime(activation)}. ». Actions `['abort', 'resume']`.
  - à partir de `gateway_activation_at` : même état, sans détail d'annulation. Actions `['force_discard', 'resume']`, `forceKind: 'publication'`.
- Sur une gateway révoquée, ni `renew`, ni `abort`, ni `rollback`, ni `revoke`, ni `discard`.

- [ ] **Step 1 :** tests qui échouent :
  - `gatewayRows.test.ts`, en table de cas :
    - `revoked_awaiting_this_replacement_offers_resume_only` ;
    - `revoked_awaiting_another_replacement_offers_force_discard` ;
    - `revoked_without_replacement_and_no_record_offers_nothing` ;
    - `revoked_without_replacement_with_a_record_offers_force_discard` ;
    - `publication_refused_switches_from_abort_to_force_at_activation` : un cas à `activation - 1`, un cas à `activation` ;
    - `a_revoked_gateway_never_offers_renew_rollback_or_revoke`.
  - `GatewayIdentityBlock.test.tsx` :
    - `renew_sends_the_terms_typed` : saisir 10, 14 et 400, puis cliquer sur « Continuer ». Attendu : `beginGatewayCeremony` reçoit `prepare_days: 10, overlap_days: 14, validity_days: 400`.
    - `renew_refuses_terms_out_of_range_before_any_call` : saisir 0, puis 3651. Attendu : l'alerte « Préparation : de 1 à 3650 jours » (même forme que `termsError` du 5b), et aucun appel.
    - `renew_defaults_are_7_7_365`.
    - `force_discard_requires_its_confirmation` : la confirmation de l'impasse A, puis celle de l'impasse B, selon `forceKind`. Le bouton est désactivé tant que la case n'est pas cochée. Attendu : `beginGatewayCeremony({gesture: 'force_discard'})`, puis `refresh`.
- [ ] **Step 2 :** `npm run test:unit --prefix apps/orion` doit échouer.
- [ ] **Step 3 : implémenter.**
  - Les champs des termes reprennent la forme de `RotationSteps.tsx` : `TextField` numérique et brouillon en chaînes, validés au clic. La phrase fixe des termes et `RENEW_TERMS` sont retirés.
  - `force_discard` suit le chemin de `discard` dans `launch` : pas de cérémonie, puis `refresh`.
- [ ] **Step 4 :** les tests passent. Lancer aussi `npm run lint --prefix apps/orion` si le script existe.
- [ ] **Step 5 :** commit `feat(orion): revoked states, adjustable terms and the forced discard in the gateway block (F14 lot 6c)`.

### Task 9 : documentation, recette, vérification complète

**Files:**
- Modify: `docs/RENOUVELLEMENT-CERTIFICATS.md` :
  - §7.1 : « Deux cas sans issue » devient le jet forcé, et la sonde est décrite dans « Reprise » ;
  - §8 : termes réglables et demande reprise ;
  - table des états de la ligne : les trois états révoqués et l'impasse B.
- Modify: `docs/specification/ROTATION-CERTIFICATS.md`, seulement s'il décrit les champs de `CertificateDomainView` (chercher `gateway_rollback_expires_at`).
- Modify: `docs/testing/MANUAL-TESTING.md` : section « J. Lot 6c », après « I. Lot 6b » (ligne 1268), avec des étapes **[cible]**. Elle couvre :
  - termes réglables ;
  - demande reprise ;
  - gateway révoquée, avec et sans remplaçant ;
  - jet forcé des deux impasses ;
  - sonde sur refus tardif.
- Modify: `docs/ROADMAP.md` :
  - F14-h, F14-i et F14-j marqués levés au lot 6c, livré sur la branche et pas encore fusionné ;
  - ligne F14 : ajout du lot 6c.

- [ ] **Step 1 :** écrire la documentation. Vérifier que chaque libellé cité est celui du code (`grep` des chaînes exactes).
- [ ] **Step 2 :** lancer `cargo fmt --check` et `bash scripts/regression.sh` avec `CARGO_BUILD_JOBS=2`. Tout doit passer. Lancer aussi `npm run test:unit --prefix web` et `npm run test:unit --prefix apps/orion`, qui doivent passer.
- [ ] **Step 3 :** commit `docs: gateway identity follow-ups of F14 lot 6c`.
