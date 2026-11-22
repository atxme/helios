# F7 — DNS des postes dans le tunnel : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** un profil Orion en tunnel complet résout par le tunnel, vers le
résolveur proposé par la passerelle (DNS4EU par défaut) ou celui de
l'utilisateur.

**Architecture :** `aether` porte le défaut, la validation et le type de la
proposition. `heliosd` lit `client_dns` dans `network.toml` et la sert sur
`GET /api/client/dns` (pairs seulement). Orion pose un DNS au montage par
`defguard` (règle NRPT `.` sous Windows), lit la proposition une fois `Up`,
et la réapplique ; une décision pure choisit les serveurs.

**Tech Stack :** Rust (axum, serde, reqwest, `defguard_wireguard_rs` 0.12),
React/MUI + Vitest pour Orion.

**Spec :** `docs/superpowers/specs/2026-11-21-f7-dns-tunnel-design.md`

## Global Constraints

- Défaut unique : `DEFAULT_CLIENT_DNS = [86.54.11.100, 86.54.11.200]`, défini
  une seule fois, dans `aether`.
- Résolveurs : IPv4 seulement, unicast public (ni `10/8`, `172.16/12`,
  `192.168/16`, `100.64/10`, `127/8`, `169.254/16`, `0/8`, `224/4`,
  `240/4`, `255.255.255.255`), sans doublon, au plus 3.
- `network.toml` : `client_dns` absent = défaut ; liste vide autorisée (rien
  proposé) ; liste invalide = chargement refusé, jamais corrigée.
- Côté Orion, un remplacement contient 1 à 3 adresses.
- DNS appliqué seulement si le profil capture tout l'IPv4
  (`TunnelCapture::Full` ou `Ipv4Only`).
- Aucune dépendance nouvelle, aucun changement du document `.orion` émis,
  aucune règle de pare-feu nouvelle.
- Le cycle de vie de l'adaptateur (ADR-001 §3 bis) ne change pas : un échec
  DNS ne démonte rien.
- Builds : `scripts/wsl-cargo` uniquement ; tests d'`orion-core` avec
  `--all-features` (sans `certificate-signing`, ils ne compilent pas, défaut
  antérieur).
- Libellés UI en français, composants existants réutilisés (AGENTS.md, UI).

## Review Focus

1. **Passerelle antérieure sans la route (404)** : Orion garde le DNS posé au
   montage, émet une seule fois « proposition non lue », ne boucle pas.
   Test : Task 6, `an_old_gateway_keeps_the_mount_dns`.
2. **Remplacement + passerelle qui répond `[]`** : DNS retiré, remplacement
   conservé dans le profil. Test : Task 5, `an_empty_proposal_clears_even_a_custom_choice`.
3. **Reconnexion** : la proposition retenue est oubliée au `down`, la
   connexion suivante repart du défaut. Test : Task 5,
   `down_forgets_the_gateway_proposal`.
4. **`network.toml` avec une IPv6 ou une adresse privée dans `client_dns`** :
   chargement refusé en nommant le champ. Test : Task 1,
   `client_dns_refuses_private_and_ipv6_entries`.
5. **Ligne wg-quick `DNS =` sans IPv4 utilisable** (IPv6 ou domaines seuls) :
   `dns = None` et avertissement. Test : Task 4,
   `a_dns_line_without_ipv4_stays_a_notice`.

---

### Task 1 : Contrat `aether::client_dns` et champ `network.toml`

**Files :**
- Create : `crates/aether/src/client_dns.rs` (+ `pub mod client_dns;` dans `crates/aether/src/lib.rs`)
- Modify : `crates/aether/src/config.rs` (`NetworkConfig`, `validate`)
- Test : `crates/aether/src/client_dns.rs` (`mod tests`), `crates/aether/src/config/tests.rs`

**Interfaces :**
- Produces :
  - `pub const DEFAULT_CLIENT_DNS: [Ipv4Addr; 2]`
  - `pub const CLIENT_DNS_MAX: usize = 3`
  - `pub const CLIENT_DNS_PATH: &str = "/api/client/dns"`
  - `pub fn validate_resolvers(servers: &[Ipv4Addr]) -> Result<(), ClientDnsError>` (vide accepté)
  - `pub enum ClientDnsError { NotPublic(Ipv4Addr), Duplicate(Ipv4Addr), TooMany(usize) }` (`thiserror`, message français nommant l'adresse)
  - `#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)] pub struct ClientDnsProposal { pub servers: Vec<Ipv4Addr> }`
  - `NetworkConfig.client_dns: Option<Vec<Ipv4Addr>>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`)
  - `NetworkConfig::client_dns_proposal(&self) -> ClientDnsProposal` : `[]` si `!allow_client_internet`, sinon la liste, sinon le défaut

- [ ] **Step 1 : tests en échec**
  - `default_is_dns4eu_unfiltered` : `DEFAULT_CLIENT_DNS == [86.54.11.100, 86.54.11.200]` et `validate_resolvers(&DEFAULT_CLIENT_DNS).is_ok()`.
  - `validate_refuses_non_public_ranges` : chaque adresse de la liste Global Constraints (`10.1.2.3`, `172.16.0.1`, `192.168.1.1`, `100.64.0.1`, `127.0.0.1`, `169.254.1.1`, `0.0.0.0`, `224.0.0.1`, `240.0.0.1`, `255.255.255.255`) → `NotPublic`.
  - `validate_refuses_duplicates_and_more_than_three` : `[1.1.1.1, 1.1.1.1]` → `Duplicate` ; quatre adresses publiques → `TooMany(4)` ; `[]` → `Ok`.
  - `client_dns_refuses_private_and_ipv6_entries` (config/tests.rs) : un `network.toml` avec `client_dns = ["192.168.1.1"]` échoue à `validate()` et le message contient `client_dns` ; `client_dns = ["2001:db8::1"]` échoue à la désérialisation.
  - `proposal_follows_config_and_internet_flag` : absent + internet → défaut ; `["1.1.1.1"]` → `[1.1.1.1]` ; `[]` → `[]` ; `allow_client_internet = false` avec une liste → `[]`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p aether --all-features client_dns` → FAIL (symboles absents).
- [ ] **Step 3 :** implémenter ; dans `NetworkConfig::validate`, appeler `validate_resolvers` si `Some`, erreur `HeliosError::Config("client_dns: …")`.
- [ ] **Step 4 :** même commande → PASS ; puis `scripts/wsl-cargo test -p aether --all-features` → PASS.
- [ ] **Step 5 :** commit `feat(aether): client DNS proposal contract and network.toml field`.

### Task 2 : Route `GET /api/client/dns`

**Files :**
- Create : `crates/helios-api/src/routes/client_dns.rs` (+ export dans `routes/mod.rs`)
- Modify : `crates/helios-api/src/lib.rs` (groupe `require_peer`, à côté de `/api/provision`), `crates/helios-api/src/routes/network.rs` (`NetworkConfigView.client_dns: Option<Vec<Ipv4Addr>>`)
- Test : `crates/helios-api/src/security_tests.rs`

**Interfaces :**
- Consumes : `CLIENT_DNS_PATH`, `ClientDnsProposal`, `NetworkConfig::client_dns_proposal` (Task 1)
- Produces : `pub async fn client_dns(State(s): State<AppState>) -> Json<ClientDnsProposal>` ; lit `s.network.read().await` à chaque appel.

- [ ] **Step 1 : tests en échec**, sur le modèle de `the_operator_status_is_an_admin_read` (`router(state).oneshot(...)` avec `ConnectInfo`) :
  - `client_dns_is_refused_to_an_unknown_source` → 401 ;
  - `client_dns_serves_the_default_to_a_peer` (config avec `allow_client_internet = true`, sans `client_dns`) → 200, corps `{"servers":["86.54.11.100","86.54.11.200"]}` ;
  - `client_dns_is_empty_without_client_internet` → `{"servers":[]}` ;
  - `network_view_shows_client_dns` : `GET /api/network` contient `client_dns` quand il est posé.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p helios-api client_dns` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p helios-api` → PASS ; `scripts/wsl-cargo clippy -p helios-api --all-targets -- -D warnings` → propre.
- [ ] **Step 5 :** commit `feat(helios-api): serve the client DNS proposal to peers`.

### Task 3 : Champ `dns` du profil Orion et manifeste v9

**Files :**
- Modify : `crates/orion-core/src/config.rs` (`ClientProfile`, `validate`), `crates/orion-core/src/vault/manifest.rs`
- Test : tests existants de `config.rs` et `vault/manifest.rs`

**Interfaces :**
- Consumes : `validate_resolvers`, `CLIENT_DNS_MAX` (Task 1)
- Produces : `ClientProfile.dns: Option<Vec<Ipv4Addr>>` (`#[serde(default, skip_serializing_if = "Option::is_none")]`) ; `ClientProfile::validate` refuse `Some(vec![])` et toute liste que `validate_resolvers` refuse.

Manifeste : `MANIFEST_VERSION = 9`, `MANIFEST_VERSION_WITHOUT_DNS = 8`. Un profil sans `dns` s'encode exactement comme aujourd'hui (7 ou 8). Avec `dns`, version 9 : après la place d'`address_v6`, un octet de présence d'`address_v6` puis son texte éventuel, puis la liste DNS (nombre d'entrées, 4 octets par adresse). Le décodeur refuse une liste vide en v9.

- [ ] **Step 1 : tests en échec**
  - `a_profile_without_dns_encodes_as_before` : octets identiques à l'encodage antérieur pour un profil avec et sans `address_v6`.
  - `dns_round_trips_with_and_without_address_v6` : les quatre combinaisons se relisent à l'identique.
  - `an_empty_dns_list_is_refused_in_v9` : manifeste v9 fabriqué avec 0 entrée → `ManifestEncoding`.
  - `profile_validate_refuses_an_empty_or_private_dns` : `Some(vec![])` et `Some(vec![10.0.0.1])` → erreur.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core --all-features manifest` → FAIL.
- [ ] **Step 3 :** implémenter ; compléter les initialisations de `ClientProfile` (`dns: None`) partout où le compilateur les signale.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-core --all-features` → PASS.
- [ ] **Step 5 :** commit `feat(orion-core): store a DNS choice in the profile (manifest v9)`.

### Task 4 : Ligne `DNS =` des imports wg-quick

**Files :**
- Modify : `crates/orion-core/src/profile_import/wg_quick.rs`
- Test : tests du module

**Interfaces :**
- Consumes : `ClientProfile.dns` (Task 3), `validate_resolvers` (Task 1)
- Produces : import d'un profil classique avec `dns: Some(ipv4 valides, au plus 3)`.

Les entrées IPv4 valides deviennent `dns`. Les entrées IPv6, les domaines de
recherche et les IPv4 refusées par `validate_resolvers` restent un avis, qui
nomme précisément ce qui n'est pas appliqué. Le texte actuel de
`wg_unapplied_notice("dns", …)` disparaît.

- [ ] **Step 1 : tests en échec**
  - `a_dns_line_becomes_the_profile_dns` : `DNS = 86.54.11.100, 1.1.1.1` → `dns == Some([86.54.11.100, 1.1.1.1])`, aucun avis DNS.
  - `a_dns_line_keeps_ipv4_and_names_the_rest` : `DNS = 1.1.1.1, 2606:4700::1111, corp.example` → `dns == Some([1.1.1.1])`, un avis qui contient `2606:4700::1111` et `corp.example`.
  - `a_dns_line_without_ipv4_stays_a_notice` : `DNS = 2606:4700::1111` → `dns == None`, un avis.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core --all-features wg_quick` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** même commande → PASS.
- [ ] **Step 5 :** commit `feat(orion-core): apply the DNS line of an imported wg-quick file`.

### Task 5 : Décision DNS et application par le backend

**Files :**
- Create : `crates/orion-core/src/dns.rs` (+ `pub mod dns;` dans `lib.rs`)
- Modify : `crates/orion-core/src/events.rs`, `crates/orion-core/src/backend/mod.rs` (trait), `crates/orion-core/src/backend/wireguard.rs`, `crates/orion-core/src/backend/dryrun.rs`
- Test : `dns.rs` (`mod tests`), tests de `dryrun.rs`

**Interfaces :**
- Consumes : Tasks 1 et 3 ; `profile_import::tunnel_capture`
- Produces :
  - `pub enum DnsOrigin { Gateway, Default, Custom, Profile }` (serde `snake_case`)
  - `pub enum DnsDecision { Apply { servers: Vec<Ipv4Addr>, origin: DnsOrigin }, Leave { reason: DnsLeaveReason } }`
  - `pub enum DnsLeaveReason { NotFullTunnel, GatewayDeclines, NoResolver }`
  - `pub fn decide(profile: &ClientProfile, proposal: Option<&ClientDnsProposal>) -> DnsDecision`
  - `ClientEvent::Dns { dns: DnsCheck }` avec `pub enum DnsCheck { Applied { servers: Vec<Ipv4Addr>, origin: DnsOrigin }, Left { reason: DnsLeaveReason }, Failed { reason: String }, ProposalUnread { reason: String } }` (serde `tag = "status"`, `snake_case`, comme `CaptureCheck`)
  - trait `VpnBackend` : `async fn apply_gateway_dns(&self, profile: &ClientProfile, proposal: ClientDnsProposal, sink: &EventSink) -> anyhow::Result<()>`

Règle de `decide`, dans l'ordre :
1. capture ni `Full` ni `Ipv4Only` → `Leave(NotFullTunnel)` ;
2. profil Helios et proposition `Some` à liste vide → `Leave(GatewayDeclines)` ;
3. `profile.dns` posé → `Apply(dns, Custom)`, ou `Profile` pour un profil classique ;
4. profil Helios et proposition non vide → `Apply(proposition, Gateway)` ;
5. profil Helios sans proposition → `Apply(DEFAULT_CLIENT_DNS, Default)` ;
6. profil classique sans `dns` → `Leave(NoResolver)`.

Backend : `up` applique `decide(profile, proposition retenue)` après la
configuration de l'adaptateur et émet `ClientEvent::Dns`. `Apply` →
`set_dns(&DnsConfig::full_tunnel(&servers))`. `Leave` →
`set_dns(&DnsConfig { servers: &[], search_domains: &[], routing_domains: &[], default_route: false })`.
Un échec émet `DnsCheck::Failed` et ne fait pas échouer `up`.
`apply_gateway_dns` retient la proposition dans un `Mutex<Option<ClientDnsProposal>>`
et réapplique ; `down` l'oublie. `DryRunBackend` enregistre la dernière
décision appliquée, exposée en `#[cfg(test)]`.

- [ ] **Step 1 : tests en échec**
  - `decide` : un test par règle 1 à 6, et `an_ipv4_only_capture_still_gets_dns`.
  - `an_empty_proposal_clears_even_a_custom_choice` : profil Helios avec `dns = Some([1.1.1.1])`, proposition `[]` → `Leave(GatewayDeclines)`.
  - dryrun : `up_applies_the_default_then_the_gateway_proposal` (`up` → `Default` ; `apply_gateway_dns([1.0.0.1])` → `Gateway`) ; `down_forgets_the_gateway_proposal` (après `down` puis `up` → `Default`) ; `a_dns_failure_does_not_fail_up` (backend simulé dont `set_dns` échoue → `up` `Ok`, événement `Failed`).
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core --all-features dns` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-core --all-features` et `scripts/wsl-cargo clippy -p orion-core --all-targets --all-features -- -D warnings` → PASS.
- [ ] **Step 5 :** commit `feat(orion-core): decide and apply the tunnel DNS`.

### Task 6 : Lecture de la proposition par le moteur

**Files :**
- Modify : `crates/orion-core/src/dns.rs` (lecture HTTP), `crates/orion-engine/src/service/connection.rs` (sur `TunnelState::Up`, à côté de `telemetry.start`), `crates/orion-engine/src/wire.rs` (`PROTOCOL_VERSION = 4` : le schéma des événements change)
- Test : `crates/orion-core/src/dns.rs`, `crates/orion-engine/src/service/` (tests existants de connexion)

**Interfaces :**
- Consumes : Task 5 (`apply_gateway_dns`, `DnsCheck::ProposalUnread`), `CLIENT_DNS_PATH`
- Produces : `pub async fn fetch_proposal(heliosd_url: &str) -> Result<ClientDnsProposal, ProposalError>`, avec `pub enum ProposalError { NotServed, Unreachable(String), Invalid(String) }` : 404 → `NotServed` ; une proposition dont `validate_resolvers` refuse le contenu → `Invalid`.

Dans le moteur, pour un profil qui a un `heliosd_url`, sur `Up` : tâche
annulée par `Down`/`Failed` comme la télémétrie. Jusqu'à 5 essais espacés de
3 s sur `Unreachable` ; `NotServed` ou `Invalid` arrêtent tout de suite. En
échec : un seul `DnsCheck::ProposalUnread`, le DNS du montage reste. En
succès : `apply_gateway_dns`.

- [ ] **Step 1 : tests en échec**
  - `fetch_reads_the_proposal` / `fetch_maps_404_to_not_served` / `fetch_refuses_a_private_resolver` (serveur HTTP local, motif `serve_one_request` de `speedtest/tests.rs`).
  - `an_old_gateway_keeps_the_mount_dns` (moteur avec backend simulé, passerelle qui répond 404) : un seul `ProposalUnread`, aucun second `set_dns`.
- [ ] **Step 2 :** `scripts/wsl-cargo test -p orion-core --all-features fetch_` puis `scripts/wsl-cargo test -p orion-engine` → FAIL.
- [ ] **Step 3 :** implémenter.
- [ ] **Step 4 :** `scripts/wsl-cargo test -p orion-engine` et `-p orion-core --all-features` → PASS.
- [ ] **Step 5 :** commit `feat(orion-engine): read the gateway DNS proposal once the tunnel is up`.

### Task 7 : Interface Orion

**Files :**
- Modify : `apps/orion/src/types.ts` (`ClientProfile.dns: string[] | null`, `DnsCheck`, événement `dns`), `apps/orion/src/hooks/useClient.ts` (état `dns`, sur le modèle de `capture`), `apps/orion/src/views/ProfilesView.tsx` (section « Avancé »), `apps/orion/src/components/PosturePanel.tsx` (ligne « DNS »)
- Test : `ProfilesView.test.tsx`, `PosturePanel.test.tsx` (ou le test le plus proche existant)

**Interfaces :**
- Consumes : forme JSON de `ClientEvent::Dns` et de `ClientProfile.dns` (Tasks 3 et 5).

Copie fixée :
- champ : « DNS » ; choix « Proposé par la passerelle » (profil Helios, `dns = null`) / « Personnalisé » (une à trois adresses IPv4, séparées par des virgules) ; erreur : « Adresse IPv4 publique attendue : <saisie> » ;
- posture, origines : `gateway` « passerelle », `default` « DNS4EU par défaut », `custom` « personnalisé », `profile` « profil » → « DNS : 86.54.11.100, 86.54.11.200 — passerelle » ;
- `left/not_full_tunnel` : « DNS local : le profil ne capture pas tout le trafic » ; `left/gateway_declines` : « DNS local : la passerelle ne propose pas de DNS par le tunnel » ; `left/no_resolver` : « DNS local : le profil n'en déclare pas » ; `failed` (ambre) : « DNS non appliqué : les requêtes sortent hors du tunnel — <reason> » ; `proposal_unread` : la ligne d'application garde sa valeur et ajoute « (proposition de la passerelle non lue) ».

- [ ] **Step 1 : tests en échec** : bascule « Personnalisé » écrit `dns`, retour à « Proposé par la passerelle » écrit `null`, saisie privée refusée avec le message ; la posture affiche chacun des cas ci-dessus, `failed` en ambre.
- [ ] **Step 2 :** `npm run test:unit --prefix apps/orion` → FAIL.
- [ ] **Step 3 :** implémenter avec les composants voisins (`ssh_target` pour le champ, `trafficFact` pour la ligne).
- [ ] **Step 4 :** `npm run test:unit --prefix apps/orion` → PASS.
- [ ] **Step 5 :** commit `feat(orion): choose and show the tunnel DNS`.

### Task 8 : Banc netns et documentation

**Files :**
- Modify : `scripts/netns-bench.sh`, `config/network.toml` (exemple commenté de `client_dns`), `crates/helios-firewall/src/ruleset.rs` et `crates/aether/src/policy.rs` (commentaires « Known limitation: DNS » réécrits), `docs/adr/ADR-001-WIREGUARD.md` (amendement « DNS des postes »), `docs/adr/ADR-006-SECRETS-AU-REPOS.md`, `docs/specification/SORTIE-IPV6.md`, `docs/ROADMAP.md` (D5 tranché le 21 novembre 2026, F7), `docs/testing/MANUAL-TESTING.md` (recette Windows), `docs/testing/TESTING.md` (scénario du banc)

- [ ] **Step 1 :** scénario de banc : depuis `cl`, `curl` sur `http://100.64.0.1:8080/api/client/dns` → `{"servers":["86.54.11.100","86.54.11.200"]}` ; scénario PASS/FAIL avec `check`.
- [ ] **Step 2 :** `bash scripts/netns-bench.sh` → tous les scénarios passent.
- [ ] **Step 3 :** recette MANUAL-TESTING (spec §7, cible Windows) : `Get-DnsClientNrptPolicy` montre `.` vers les serveurs annoncés ; `Resolve-DnsName example.com` répond ; capture sur la carte physique sans port 53 ; arrêt brutal d'Orion puis résolution toujours possible ; profil « Helios seul » sans règle ; passerelle avec `client_dns = []` → posture « DNS local ».
- [ ] **Step 4 :** documentation ; `bash scripts/regression.sh` (avec `CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 nice -n 10`) → succès.
- [ ] **Step 5 :** commit `docs(f7): tunnel DNS, D5 decided, bench and Windows recipe`.
