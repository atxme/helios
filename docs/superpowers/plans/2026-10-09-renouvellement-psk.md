# Renouvellement automatique du PSK ML-KEM — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Orion renouvelle seul son PSK `ml_kem` à 80 % de la durée de vie (19 h 12) ou de 100 Gio transférés, par la transaction v5 inchangée adressée à la gateway **dans le tunnel**, et la gateway retire le slot à 100 % de l'un ou l'autre.

**Architecture:** Côté gateway, le listener QUIC existant reçoit l'adresse source de chaque connexion ; une source qui est la VIP d'un pair admis classe la connexion « tunnel », qui n'est acceptée que pour renouveler un slot `ml_kem` déjà committé. Côté Orion, une horloge de renouvellement (temps + octets) déclenche une négociation sur une socket liée à la VIP, puis `rekey_peer` retire et réinscrit le pair pour forcer le handshake de preuve ; une garde remet l'ancien PSK en place sur toute sortie anticipée, annulation comprise.

**Tech Stack:** Rust 2021 (MSRV 1.95), tokio, quinn, `defguard_wireguard_rs 0.12`, `rustables` vendored, Tauri 2, React 19 + MUI, vitest.

**Spec:** [`docs/superpowers/specs/2026-10-09-renouvellement-psk-design.md`](../specs/2026-10-09-renouvellement-psk-design.md) — lire avant toute tâche. Contexte normatif : `docs/specification/NEGOCIATION-DE-CLE-V5.md` §7.5, §11, §12.3, §20 ; `AGENTS.md` (invariants « Key negotiation »).

## Global Constraints

- Démarrer **après la fusion de la migration `SecretString` d'`orion-core` (lot H4)**. Les extraits suivent `main` à `5d7f296` ; si H4 a rendu `ClientProfile` non `Clone` ou `preshared_key` de type `SecretString`, adapter les extraits (`duplicate()`, `expose()`) sans changer le comportement.
- Branche `feat/renouvellement-psk` depuis `main`. Toute compilation passe par `scripts/wsl-cargo` ; jamais de `CARGO_TARGET_DIR` ni de `target/` propre à un worktree.
- Seuils : `NEGOTIATED_PSK_LIFETIME_SECS = 86 400` (inchangé, signé) ; `NEGOTIATED_PSK_BYTE_LIMIT = 100 Gio = 107 374 182 400` (constante, **non signée**) ; renouvellement à **80 %** soit 69 120 s et 85 899 345 920 octets.
- Nouvelles tentatives Orion : 1, 2, 4, 8 puis 15 min maximum.
- Aucun message, transcription signée ni ALPN v5 ne change.
- Aucun repli vers le port QUIC public pendant un renouvellement.
- Aucune variable ni option ne raccourcit la durée de vie ou le plafond dans un binaire livré.
- Identifiants, commentaires, logs et noms de tests en anglais ; messages d'interface Orion en français ; docs `docs/` en français.
- Ni `TODO`, `FIXME`, `unwrap`/`expect` sur un chemin de production.
- Refus publics de la gateway : toujours `PublicError::Rejected`, la cause n'apparaît que dans le journal.
- Commits Conventional Commits, un par tâche, terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Compteurs client remis à zéro par `rekey_peer`** : après réinscription du pair, `rx/tx` repartent de 0 côté Orion ; l'horloge renouvelée doit prendre ce nouveau point de départ, sinon le volume ne se redéclenche jamais. Test en tâche 9 (`a_renewal_restarts_the_volume_count_from_the_re_registered_peer`).
2. **Renouvellement concurrent d'une déconnexion ou reconnexion** : un reçu remplacé pendant la négociation ne doit pas être écrasé par le résultat. Test en tâche 9 (`a_renewal_outcome_never_overwrites_a_newer_receipt`).
3. **Horloge murale qui recule ou avance (veille)** : l'échéance retient la plus proche des deux horloges. Tests en tâche 7.
4. **Source IPv4 mappée `::ffff:100.64.1.2`** sur la socket double pile : elle doit être classée « tunnel ». Test en tâche 4 (`classify_canonicalizes_a_mapped_source`).
5. **Compteur gateway qui redescend** (pair recréé par un rechargement à chaud) : point de départ réinitialisé, aucun retrait intempestif. Test en tâche 5 (`a_counter_that_went_backwards_rebases_instead_of_reclaiming`).

---

### Task 1: Constantes de renouvellement dans `aether`

**Files:**
- Modify: `crates/aether/src/key_negotiation/mod.rs` (après `NEGOTIATED_PSK_LIFETIME_SECS`, ligne ~102)
- Test: `crates/aether/src/key_negotiation/tests.rs`

**Interfaces:**
- Produces: `aether::key_negotiation::NEGOTIATED_PSK_BYTE_LIMIT: u64`, `PSK_RENEWAL_THRESHOLD_PERCENT: u64`, `const fn psk_renewal_after_secs() -> u64`, `const fn psk_renewal_after_bytes() -> u64`.

- [ ] **Step 1: Write the failing test** — à la fin de `tests.rs` :

```rust
#[test]
fn renewal_thresholds_sit_at_eighty_percent_of_each_bound() {
    assert_eq!(NEGOTIATED_PSK_BYTE_LIMIT, 100 * 1024 * 1024 * 1024);
    assert_eq!(psk_renewal_after_secs(), 69_120, "19 h 12 of a 24 h lifetime");
    assert_eq!(psk_renewal_after_bytes(), 85_899_345_920, "80 GiB of 100 GiB");
    assert!(psk_renewal_after_secs() < u64::from(NEGOTIATED_PSK_LIFETIME_SECS));
    assert!(psk_renewal_after_bytes() < NEGOTIATED_PSK_BYTE_LIMIT);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `scripts/wsl-cargo test -p aether renewal_thresholds_sit_at_eighty_percent`
Expected: FAIL — `cannot find value NEGOTIATED_PSK_BYTE_LIMIT`.

- [ ] **Step 3: Write minimal implementation** — sous `NEGOTIATED_PSK_LIFETIME_SECS` :

```rust
/// Transfer ceiling of a negotiated `ml_kem` PSK: 100 GiB, sent plus received.
///
/// The time bound alone lets a saturated tunnel push an unbounded volume
/// through one ML-KEM secret. This is the *lifebytes* of IPsec next to its
/// lifetime. Unlike the lifetime it is **not** signed in the response: both
/// ends compile the same constant, so no v5 transcript changes. Changing the
/// value one day means signing it, as the lifetime is.
pub const NEGOTIATED_PSK_BYTE_LIMIT: u64 = 100 * 1024 * 1024 * 1024;

/// Share of the lifetime, or of the byte ceiling, at which Orion renews.
///
/// The gateway enforces 100 %; the 20 % left is the window in which a failed
/// renewal is retried before the slot is reclaimed.
pub const PSK_RENEWAL_THRESHOLD_PERCENT: u64 = 80;

/// Seconds after commit at which Orion renews: 19 h 12.
pub const fn psk_renewal_after_secs() -> u64 {
    NEGOTIATED_PSK_LIFETIME_SECS as u64 * PSK_RENEWAL_THRESHOLD_PERCENT / 100
}

/// Bytes carried after commit at which Orion renews: 80 GiB.
pub const fn psk_renewal_after_bytes() -> u64 {
    NEGOTIATED_PSK_BYTE_LIMIT / 100 * PSK_RENEWAL_THRESHOLD_PERCENT
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `scripts/wsl-cargo test -p aether renewal_thresholds_sit_at_eighty_percent`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/aether/src/key_negotiation/mod.rs crates/aether/src/key_negotiation/tests.rs
git commit -m "feat(aether): name the PSK byte ceiling and the 80 % renewal threshold"
```

---

### Task 2: Ouvrir le port de négociation sur l'interface du tunnel

**Files:**
- Modify: `crates/helios-firewall/src/ruleset/transport.rs:59-100` (`key_negotiation_listener`)
- Test: `crates/helios-firewall/src/ruleset/tests/transport.rs`
- Modify (snapshots): `crates/helios-firewall/src/ruleset/tests/golden.rs`

**Interfaces:**
- Consumes: `FirewallPolicy::{key_negotiation_port, wg_iface}`.
- Produces: règles `iifname "<wg_iface>" udp dport <port> accept` (input) et `oifname "<wg_iface>" udp sport <port> accept` (output).

- [ ] **Step 1: Write the failing tests** — dans `tests/transport.rs`, ajouter `every_state` à l'import de `support`, puis :

```rust
/// The in-tunnel PSK renewal reaches the same listener through `wg_iface`.
#[test]
fn key_negotiation_port_is_open_on_the_tunnel_interface() {
    for state in every_state() {
        let rs = render(&policy(), state);
        assert!(
            text(&rs, ChainKind::Input)
                .iter()
                .any(|rule| rule == "iifname \"helios0\" udp dport 51821 accept"),
            "state {state:?}: the renewal must reach the listener through the tunnel"
        );
        assert!(
            text(&rs, ChainKind::Output)
                .iter()
                .any(|rule| rule == "oifname \"helios0\" udp sport 51821 accept"),
            "state {state:?}: the listener must answer through the tunnel"
        );
    }
}

/// Without a tunnel interface there is nothing to scope the opening to, and
/// an unscoped variant would be reachable from anywhere.
#[test]
fn the_tunnel_opening_needs_a_tunnel_interface() {
    let mut p = policy();
    p.wg_iface = String::new();
    let mut rules = Vec::new();
    super::super::transport::key_negotiation_listener(&mut rules, &p, &["eth0".to_string()]);
    assert!(
        rules
            .iter()
            .all(|rule| rule.to_string().contains("\"eth0\"")),
        "every key-negotiation rule must name an interface: {rules:?}"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `scripts/wsl-cargo test -p helios-firewall key_negotiation_port_is_open_on_the_tunnel_interface the_tunnel_opening_needs_a_tunnel_interface`
Expected: le premier FAIL (règle absente), le second PASS (aucune règle tunnel aujourd'hui).

- [ ] **Step 3: Write minimal implementation** — dans `key_negotiation_listener`, à l'intérieur de `if let Some(port) = policy.key_negotiation_port {`, après la boucle `for wan in wan_ifaces { … }` :

```rust
        // ── The same listener, reached through the tunnel ───────────────────
        // In-tunnel PSK renewal: Orion renegotiates through the tunnel it
        // already holds rather than reopening the public port. Scoped by
        // interface, never by source address: only WireGuard puts packets on
        // `wg_iface`, and only for a peer it has authenticated. The gateway
        // then checks that the source VIP is the peer mTLS named.
        if !policy.wg_iface.is_empty() {
            rules.push(
                Rule::new(
                    Input,
                    vec![
                        Match::InIface(policy.wg_iface.clone()),
                        Match::DestPort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("in-tunnel PSK renewal on the key-negotiation listener"),
            );
            rules.push(
                Rule::new(
                    Output,
                    vec![
                        Match::OutIface(policy.wg_iface.clone()),
                        Match::SourcePort {
                            port,
                            proto: L4::Udp,
                        },
                    ],
                    Verdict::Accept,
                )
                .with_note("in-tunnel renewal replies — the final frame can outlive conntrack"),
            );
        }
```

- [ ] **Step 4: Run tests, then update the golden snapshots**

Run: `scripts/wsl-cargo test -p helios-firewall`
Expected: les deux nouveaux tests PASS ; les tests `golden_*` dont la politique déclare `key_negotiation_port` et `wg_iface` FAIL avec un diff qui ne montre **que** les deux lignes ajoutées après les règles WAN du port 51821. Reporter ces deux lignes dans les `expected` de `golden.rs` concernés (le test `golden_meshnet_without_listeners` ne doit pas changer : il retire le port). Relancer : tout PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/helios-firewall/src/ruleset/transport.rs crates/helios-firewall/src/ruleset/tests/
git commit -m "feat(firewall): open the key-negotiation port on the tunnel interface for PSK renewal"
```

---

### Task 3: Transmettre l'adresse source au gestionnaire de négociation

**Files:**
- Modify: `crates/aether-key-negotiation/src/server.rs:148-185` (trait `NegotiationHandler`), `:324`, `:508` (appels)
- Modify: `crates/aether-key-negotiation/src/tests/fixtures.rs:248-…` (impl de test)
- Modify: `crates/heliosd/src/key_negotiation/protocol.rs:19-43` (signatures seulement)
- Modify: `crates/heliosd/src/key_negotiation/tests/fixtures.rs`, `tests/transaction.rs`, `tests/identity.rs`, `tests/interop.rs` (appels)

**Interfaces:**
- Produces:
  - `async fn resolve_admitted_peer(&self, certificate_sha256: &str, source: std::net::IpAddr) -> Option<String>`
  - `async fn prepare(&self, certificate_sha256: String, source: std::net::IpAddr, request: AuthenticatedKeyNegotiationRequest) -> Result<PreparedNegotiation, PublicError>`
  - `source` est **canonique** (`aether::net::canonical_source`, une IPv4 mappée redevient IPv4).
  - Fixture heliosd : `pub(super) const PUBLIC_SOURCE: IpAddr` (203.0.113.50) et `pub(super) const TUNNEL_SOURCE: IpAddr` (100.64.1.2, la VIP du pair de `network()`).

- [ ] **Step 1: Write the failing test** — dans `crates/aether-key-negotiation/src/tests/fixtures.rs`, ajouter au `Handler` de test un champ `pub(crate) sources: std::sync::Mutex<Vec<std::net::IpAddr>>` (initialisé `Default::default()` dans son constructeur). Puis repérer le test qui va jusqu'au commit (`grep -n "confirm" crates/aether-key-negotiation/src/tests/*.rs`) et y ajouter, après le commit réussi :

```rust
    let sources = handler.sources.lock().unwrap().clone();
    assert!(
        !sources.is_empty() && sources.iter().all(|source| source.is_loopback()),
        "the handler must receive the canonical source of the connection: {sources:?}"
    );
```

- [ ] **Step 2: Run test to verify it fails**

Run: `scripts/wsl-cargo test -p aether-key-negotiation`
Expected: FAIL — `sources` vide (rien ne l'alimente).

- [ ] **Step 3: Change the trait and its callers**

Dans `server.rs`, trait :

```rust
    /// The one admitted peer this TLS certificate belongs to, if any.
    ///
    /// `source` is the canonical address the connection comes from. A source
    /// that is a tunnel VIP lets the implementation require that the VIP and
    /// the certificate name the same peer (in-tunnel PSK renewal).
    async fn resolve_admitted_peer(&self, certificate_sha256: &str, source: IpAddr)
        -> Option<String>;

    async fn prepare(
        &self,
        certificate_sha256: String,
        source: IpAddr,
        request: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError>;
```

(`use std::net::IpAddr;` en tête si absent.) Dans `handle_connection` : `handler.resolve_admitted_peer(&fingerprint, remote.ip())` et `handler.prepare(fingerprint, remote.ip(), request)` — `remote` est déjà canonique.

Fixture `aether-key-negotiation` : ajouter le paramètre `source: IpAddr` aux deux méthodes et, en tête de chacune, `self.sources.lock().unwrap().push(source);`.

heliosd `protocol.rs` : ajouter `_source: std::net::IpAddr` aux deux signatures (utilisé en tâche 4).

heliosd `tests/fixtures.rs` :

```rust
/// A WAN address: the public port, as every test used before renewal existed.
pub(super) const PUBLIC_SOURCE: std::net::IpAddr =
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 50));
/// The VIP `network()` admits the test peer with: a connection through the tunnel.
pub(super) const TUNNEL_SOURCE: std::net::IpAddr =
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 1, 2));
```

Puis chaque appel `.prepare(CERTIFICATE_FINGERPRINT.into(), request…)` des tests heliosd devient `.prepare(CERTIFICATE_FINGERPRINT.into(), PUBLIC_SOURCE, request…)` et chaque `.resolve_admitted_peer(x)` devient `.resolve_admitted_peer(x, PUBLIC_SOURCE)` ; le compilateur liste les sites.

- [ ] **Step 4: Run tests to verify they pass**

Run: `scripts/wsl-cargo test -p aether-key-negotiation && scripts/wsl-cargo test -p heliosd key_negotiation`
Expected: PASS, aucun comportement modifié.

- [ ] **Step 5: Commit**

```bash
git add crates/aether-key-negotiation crates/heliosd/src/key_negotiation
git commit -m "refactor(key-negotiation): hand the canonical connection source to the handler"
```

---

### Task 4: Classer une connexion « tunnel » et la réserver au renouvellement

**Files:**
- Create: `crates/heliosd/src/key_negotiation/origin.rs`
- Modify: `crates/heliosd/src/key_negotiation/mod.rs` (`mod origin;`)
- Modify: `crates/heliosd/src/key_negotiation/protocol.rs` (`resolve_admitted_peer`, `prepare`)
- Create: `crates/heliosd/src/key_negotiation/tests/renewal.rs` ; Modify: `tests/mod.rs` (`mod renewal;`), `tests/fixtures.rs` (helper `commit`)

**Interfaces:**
- Consumes: `source: IpAddr` (tâche 3), `SlotState`, `ProtectionMode`.
- Produces:
  - `pub(super) enum Origin { Public, Tunnel { peer_public_key: String } }`
  - `pub(super) fn classify(network: &aether::NetworkConfig, source: IpAddr) -> Origin`
  - `pub(super) fn tunnel_renewal_allowed(mode: ProtectionMode, slot: &SlotState) -> bool`
  - fixture `pub(super) async fn commit(handler, plane, fixture, transaction_id, source)`

- [ ] **Step 1: Write the failing tests**

`origin.rs` (module complet avec ses tests unitaires ; implémentation à l'étape 3) — tests :

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    fn network() -> aether::NetworkConfig {
        let mut network = aether::NetworkConfig::default();
        network.peers.push(aether::WgPeer {
            name: "laptop".into(),
            public_key: "laptop-key".into(),
            address: "100.64.1.2/32".into(),
            address_v6: Some("fd00::2".parse().unwrap()),
            ..aether::WgPeer::default()
        });
        network
    }

    #[test]
    fn a_peer_vip_is_a_tunnel_source() {
        assert_eq!(
            classify(&network(), "100.64.1.2".parse().unwrap()),
            Origin::Tunnel { peer_public_key: "laptop-key".into() }
        );
        assert_eq!(
            classify(&network(), IpAddr::V6("fd00::2".parse::<Ipv6Addr>().unwrap())),
            Origin::Tunnel { peer_public_key: "laptop-key".into() }
        );
    }

    #[test]
    fn classify_canonicalizes_a_mapped_source() {
        assert_eq!(
            classify(&network(), "::ffff:100.64.1.2".parse().unwrap()),
            Origin::Tunnel { peer_public_key: "laptop-key".into() }
        );
    }

    #[test]
    fn any_other_address_is_public() {
        assert_eq!(classify(&network(), "203.0.113.50".parse().unwrap()), Origin::Public);
        assert_eq!(classify(&network(), "100.64.1.3".parse().unwrap()), Origin::Public);
    }

    #[test]
    fn only_a_committed_ml_kem_slot_may_be_renewed_in_the_tunnel() {
        let committed = SlotState::Committed(InstalledPsk {
            transaction_id: [1; 16],
            public_key: "laptop-key".into(),
            address: "100.64.1.2/32".into(),
            installed_at: std::time::Instant::now(),
            bytes_baseline: None,
        });
        assert!(tunnel_renewal_allowed(ProtectionMode::MlKem, &committed));
        assert!(!tunnel_renewal_allowed(ProtectionMode::StaticPsk, &committed));
        assert!(!tunnel_renewal_allowed(ProtectionMode::MlKem, &SlotState::Empty));
        assert!(!tunnel_renewal_allowed(ProtectionMode::MlKem, &SlotState::ConfiguredStatic));
    }
}
```

> Si `aether::WgPeer` n'implémente pas `Default`, construire le pair champ par champ comme `tests/fixtures.rs::network()`. Le champ `bytes_baseline` vient de la tâche 5 : si la tâche 4 passe avant, le retirer ici et l'ajouter en tâche 5.

`tests/fixtures.rs` :

```rust
/// Prepares, proves a handshake and confirms: one committed negotiation.
pub(super) async fn commit(
    handler: &GatewayHandler,
    plane: &TestDataPlane,
    fixture: &PqFixture,
    transaction_id: [u8; 16],
    source: std::net::IpAddr,
) {
    handler
        .prepare(CERTIFICATE_FINGERPRINT.into(), source, request(transaction_id, fixture))
        .await
        .expect("prepare");
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, transaction_id, &fixture.client_private_key)
                .expect("confirmation"),
        )
        .await
        .expect("commit");
}
```

`tests/renewal.rs` :

```rust
//! In-tunnel PSK renewal: the tunnel path only ever renews.

use super::super::*;
use super::fixtures::*;

fn psk() -> String {
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

#[tokio::test]
async fn an_in_tunnel_negotiation_renews_a_committed_slot() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [30; 16], PUBLIC_SOURCE).await;
    commit(&handler, &plane, &fixture, [31; 16], TUNNEL_SOURCE).await;

    assert_eq!(plane.writes().await.len(), 2, "one PSK per committed negotiation");
    let mut state = handler.transactions.lock().await;
    let SlotState::Committed(installed) = &state.slot(CLIENT_KEY).state else {
        panic!("the renewal must leave an owned slot");
    };
    assert_eq!(installed.transaction_id, [31; 16], "the renewal owns the slot now");
}

#[tokio::test]
async fn an_in_tunnel_negotiation_cannot_post_a_first_psk() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    let refused = handler
        .prepare(CERTIFICATE_FINGERPRINT.into(), TUNNEL_SOURCE, request([32; 16], &fixture))
        .await;
    assert!(matches!(refused, Err(PublicError::Rejected)));
    assert!(plane.writes().await.is_empty(), "nothing may reach the data plane");
    assert!(
        handler.transactions.lock().await.peers.is_empty(),
        "a refused renewal must not keep the peer reserved"
    );
}

#[tokio::test]
async fn a_vip_belonging_to_another_peer_is_not_admitted() {
    let fixture = pq_fixture();
    let (handler, _plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    let mut other = handler.network.read().await.peers[0].clone();
    other.name = "other".into();
    other.public_key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    other.address = "100.64.1.3/32".into();
    other.key_negotiation_certificate_sha256 = Some("ff".repeat(32));
    handler.network.write().await.peers.push(other);

    assert_eq!(
        handler.resolve_admitted_peer(CERTIFICATE_FINGERPRINT, TUNNEL_SOURCE).await.as_deref(),
        Some(CLIENT_KEY)
    );
    assert_eq!(
        handler.resolve_admitted_peer(CERTIFICATE_FINGERPRINT, PUBLIC_SOURCE).await.as_deref(),
        Some(CLIENT_KEY)
    );
    assert_eq!(
        handler
            .resolve_admitted_peer(CERTIFICATE_FINGERPRINT, "100.64.1.3".parse().unwrap())
            .await,
        None,
        "a certificate cannot negotiate from another peer's VIP"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `scripts/wsl-cargo test -p heliosd key_negotiation`
Expected: FAIL à la compilation (`origin` absent), puis, une fois le module vide créé, `an_in_tunnel_negotiation_cannot_post_a_first_psk` et `a_vip_belonging_to_another_peer_is_not_admitted` FAIL.

- [ ] **Step 3: Write the implementation**

`origin.rs` :

```rust
//! Where a negotiation comes from: the public port, or through the tunnel.
//!
//! A connection whose source is a peer's VIP arrived through WireGuard, which
//! only delivers it for a peer it has authenticated. Such a connection is an
//! in-tunnel PSK renewal and nothing else (design 2026-10-09 §4.3): it may not
//! post a first PSK, nor select another mode than `ml_kem`.

use std::net::IpAddr;

use aether::key_negotiation::ProtectionMode;

use super::{InstalledPsk, SlotState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Origin {
    Public,
    Tunnel { peer_public_key: String },
}

/// Classifies a source against the peers currently admitted.
///
/// Read from the live configuration at each call, so a hot reload that moves
/// a VIP is honoured at the next connection.
pub(super) fn classify(network: &aether::NetworkConfig, source: IpAddr) -> Origin {
    let source = aether::net::canonical_source(source);
    network
        .peers
        .iter()
        .find(|peer| holds(peer, source))
        .map_or(Origin::Public, |peer| Origin::Tunnel {
            peer_public_key: peer.public_key.clone(),
        })
}

fn holds(peer: &aether::WgPeer, source: IpAddr) -> bool {
    match source {
        IpAddr::V4(source) => peer
            .address
            .split('/')
            .next()
            .and_then(|host| host.trim().parse::<std::net::Ipv4Addr>().ok())
            == Some(source),
        IpAddr::V6(source) => peer.address_v6 == Some(source),
    }
}

/// May a connection through the tunnel prepare in this mode, over this slot?
pub(super) fn tunnel_renewal_allowed(mode: ProtectionMode, slot: &SlotState) -> bool {
    mode == ProtectionMode::MlKem && matches!(slot, SlotState::Committed(InstalledPsk { .. }))
}
```

`mod.rs` : `mod origin;` à côté des autres `mod`.

`protocol.rs`, `resolve_admitted_peer` : renommer le corps actuel en méthode privée `async fn certificate_peer(&self, certificate_sha256: &str) -> Option<String>` (même code), puis :

```rust
    async fn resolve_admitted_peer(&self, certificate_sha256: &str, source: IpAddr)
        -> Option<String> {
        let resolved = self.certificate_peer(certificate_sha256).await?;
        match origin::classify(&*self.network.read().await, source) {
            origin::Origin::Public => Some(resolved),
            origin::Origin::Tunnel { peer_public_key } if peer_public_key == resolved => {
                Some(resolved)
            }
            origin::Origin::Tunnel { peer_public_key } => {
                tracing::warn!(
                    %source,
                    vip_owner = %peer_public_key,
                    certificate_peer = %resolved,
                    "key negotiation refused: an in-tunnel source belongs to another peer than \
                     the presented certificate"
                );
                None
            }
        }
    }
```

`protocol.rs`, `prepare` : renommer `_source` en `source` ; juste après le contrôle du plancher (`if !request.mode.satisfies(minimum_mode) { … }`) :

```rust
        let in_tunnel = matches!(
            origin::classify(&*self.network.read().await, source),
            origin::Origin::Tunnel { .. }
        );
```

puis, dans le bloc `let generation = { let mut state = self.transactions.lock().await; … }`, juste après le contrôle `resting_until` et avant `state.replay_set.insert(…)` :

```rust
            if in_tunnel
                && !origin::tunnel_renewal_allowed(
                    request.mode,
                    &state.slot(&request.client_wg_public_key).state,
                )
            {
                state.peers.remove(&request.client_wg_public_key);
                tracing::warn!(
                    %transaction,
                    peer = %peer_key,
                    mode = ?request.mode,
                    "key negotiation refused: through the tunnel, only a committed ml_kem slot \
                     may be renewed"
                );
                return Err(PublicError::Rejected);
            }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `scripts/wsl-cargo test -p heliosd key_negotiation`
Expected: PASS, tests existants compris.

- [ ] **Step 5: Commit**

```bash
git add crates/heliosd/src/key_negotiation
git commit -m "feat(heliosd): accept in-tunnel negotiations only to renew a committed ml_kem slot"
```

---

### Task 5: Retrait du slot à 100 Gio côté gateway

**Files:**
- Modify: `crates/heliosd/src/key_negotiation/transaction.rs:119-124` (`InstalledPsk`), `:585-630` (`reclaimable`)
- Modify: `crates/heliosd/src/key_negotiation/protocol.rs:530-535` (construction au commit)
- Test: `crates/heliosd/src/key_negotiation/tests/renewal.rs`

**Interfaces:**
- Consumes: `aether::key_negotiation::NEGOTIATED_PSK_BYTE_LIMIT`, `helios_wireguard::PeerStatus::{rx_bytes, tx_bytes}`.
- Produces: `InstalledPsk.bytes_baseline: Option<u64>` ; `InstalledPsk::charge_transfer(&mut self, total: u64) -> Option<String>`.

- [ ] **Step 1: Write the failing tests** — dans `tests/renewal.rs` :

```rust
fn installed() -> InstalledPsk {
    InstalledPsk {
        transaction_id: [1; 16],
        public_key: CLIENT_KEY.into(),
        address: "100.64.1.2/32".into(),
        installed_at: std::time::Instant::now(),
        bytes_baseline: None,
    }
}

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn the_first_observation_only_sets_the_baseline() {
    let mut psk = installed();
    assert_eq!(psk.charge_transfer(500 * GIB), None);
    assert_eq!(psk.bytes_baseline, Some(500 * GIB));
    assert_eq!(psk.charge_transfer(599 * GIB), None, "99 GiB carried");
    assert!(psk.charge_transfer(600 * GIB).is_some(), "100 GiB carried");
}

#[test]
fn a_counter_that_went_backwards_rebases_instead_of_reclaiming() {
    let mut psk = installed();
    psk.charge_transfer(90 * GIB);
    assert_eq!(psk.charge_transfer(GIB), None, "peer re-created: counting restarts");
    assert_eq!(psk.bytes_baseline, Some(GIB));
}

fn status(total: u64) -> helios_wireguard::PeerStatus {
    helios_wireguard::PeerStatus {
        public_key: base64::engine::general_purpose::STANDARD.decode(CLIENT_KEY).unwrap(),
        allowed_ips: Vec::new(),
        last_handshake: Some(std::time::SystemTime::now()),
        endpoint: None,
        rx_bytes: total / 2,
        tx_bytes: total - total / 2,
    }
}

#[tokio::test]
async fn a_committed_psk_is_reclaimed_at_its_byte_ceiling() {
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &psk(), ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [40; 16], PUBLIC_SOURCE).await;

    assert!(handler.reclaimable(&[status(10 * GIB)]).await.is_empty(), "baseline");
    assert!(handler.reclaimable(&[status(109 * GIB)]).await.is_empty(), "99 GiB");
    let reclaimed = handler.reclaimable(&[status(110 * GIB)]).await;
    assert_eq!(reclaimed.len(), 1);
    assert!(reclaimed[0].2.contains("ceiling"), "the journal names the cause: {reclaimed:?}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `scripts/wsl-cargo test -p heliosd renewal`
Expected: FAIL à la compilation (`bytes_baseline`, `charge_transfer` absents).

- [ ] **Step 3: Write the implementation**

`transaction.rs` — champ et méthode :

```rust
pub struct InstalledPsk {
    pub transaction_id: [u8; 16],
    pub public_key: String,
    pub address: String,
    pub installed_at: std::time::Instant,
    /// `rx + tx` of the peer at the first snapshot after the commit.
    ///
    /// The gateway never re-registers a peer for a new PSK, so its counters
    /// run on across PSKs: what this one carried is the difference. Set by the
    /// reclaimer, whose snapshot is at most ten seconds old — negligible next
    /// to the ceiling.
    pub bytes_baseline: Option<u64>,
}

impl InstalledPsk {
    /// Counts what this PSK has carried and names the ceiling once reached.
    ///
    /// A counter below the baseline means the peer was re-created (hot
    /// reload): counting restarts from it rather than reading a wrap-around
    /// as a huge transfer. The lifetime still bounds the slot meanwhile.
    pub(super) fn charge_transfer(&mut self, total: u64) -> Option<String> {
        let baseline = match self.bytes_baseline {
            Some(baseline) if total >= baseline => baseline,
            _ => {
                self.bytes_baseline = Some(total);
                return None;
            }
        };
        let carried = total - baseline;
        (carried >= aether::key_negotiation::NEGOTIATED_PSK_BYTE_LIMIT).then(|| {
            format!(
                "PSK carried {} GiB, its {} GiB ceiling, without a renewal",
                carried >> 30,
                aether::key_negotiation::NEGOTIATED_PSK_BYTE_LIMIT >> 30
            )
        })
    }
}
```

`reclaimable` : `let mut state = …lock().await;`, `.slots.values_mut()`, `let SlotState::Committed(installed) = &mut slot.state else { return None; };`. Garder le contrôle `MAX_PSK_LIFETIME` en premier ; après `let peer = observed.iter().find(…)?;`, insérer :

```rust
                if let Some(reason) =
                    installed.charge_transfer(peer.rx_bytes.saturating_add(peer.tx_bytes))
                {
                    return Some((installed.public_key.clone(), generation, reason));
                }
```

puis le contrôle de vieillissement du handshake inchangé.

`protocol.rs:530` : ajouter `bytes_baseline: None,` à la construction de `InstalledPsk`. Mettre à jour la doc de `spawn_psk_reclaimer` (`server.rs`) : « Three questions » avec le volume.

- [ ] **Step 4: Run tests to verify they pass**

Run: `scripts/wsl-cargo test -p heliosd key_negotiation`
Expected: PASS, dont `a_candidate_being_prepared_is_not_reclaimable`.

- [ ] **Step 5: Commit**

```bash
git add crates/heliosd/src/key_negotiation
git commit -m "feat(heliosd): reclaim a negotiated PSK once it has carried 100 GiB"
```

---

### Task 6: `rekey_peer` et `transfer_bytes` dans les backends Orion

**Files:**
- Modify: `crates/orion-core/src/backend/mod.rs:85-118` (trait `VpnBackend`)
- Modify: `crates/orion-core/src/backend/dryrun.rs`
- Modify: `crates/orion-core/src/backend/wireguard.rs`
- Modify: `crates/orion-core/src/backend/tests.rs` (backends de test `RefusingDownBackend` ~l.130 et celui de ~l.684)

**Interfaces:**
- Produces:
  - `async fn rekey_peer(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()>`
  - `async fn transfer_bytes(&self) -> Option<u64>`
  - `DryRunBackend::{rekeyed_psks(&self) -> Vec<Option<String>>, fail_rekeys(&self, bool), set_transfer_bytes(&self, Option<u64>)}`

- [ ] **Step 1: Write the failing tests** — dans le module de tests de `dryrun.rs` :

```rust
#[tokio::test]
async fn rekeying_re_registers_the_peer_and_restarts_its_counters() {
    let backend = DryRunBackend { negotiate_delay: Duration::ZERO, ..DryRunBackend::default() };
    let sink: EventSink = std::sync::Arc::new(|_| {});
    let mut profile = test_profile();
    backend.up(&profile, &sink).await.unwrap();
    backend.set_transfer_bytes(Some(4096));
    backend.set_handshake_age(Some(Duration::from_secs(90)));

    profile.preshared_key = Some("cGVlcnBza3BlZXJwc2twZWVycHNrcGVlcnBzazEyMw==".into());
    backend.rekey_peer(&profile, &sink).await.unwrap();

    assert_eq!(backend.rekeyed_psks(), vec![profile.preshared_key.clone()]);
    assert_eq!(backend.transfer_bytes().await, Some(0), "a re-registered peer counts from zero");
    assert_eq!(backend.last_handshake_age().await, Some(Duration::ZERO));
}

#[tokio::test]
async fn rekeying_needs_a_mounted_adapter_and_can_be_made_to_fail() {
    let backend = DryRunBackend::default();
    let sink: EventSink = std::sync::Arc::new(|_| {});
    assert!(backend.rekey_peer(&test_profile(), &sink).await.is_err(), "no adapter");

    let backend = DryRunBackend { negotiate_delay: Duration::ZERO, ..DryRunBackend::default() };
    backend.up(&test_profile(), &sink).await.unwrap();
    backend.fail_rekeys(true);
    assert!(backend.rekey_peer(&test_profile(), &sink).await.is_err());
    assert!(backend.rekeyed_psks().is_empty());
}
```

> `test_profile()` : réutiliser le constructeur de profil déjà présent dans ce module de tests ; s'il n'y en a pas, copier `profile()` de `backend/tests.rs` (endpoint littéral `203.0.113.10:51820`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `scripts/wsl-cargo test -p orion-core dryrun`
Expected: FAIL à la compilation.

- [ ] **Step 3: Write the implementation**

Trait (`mod.rs`), après `down` :

```rust
    /// Re-registers the peer from `profile`, which resets its WireGuard session.
    ///
    /// The in-tunnel PSK renewal needs a handshake **after** the new PSK is in
    /// place, and changing a peer's configuration does not reset its session:
    /// WireGuard would only rekey after 120 s of use (spec §12.3). Removing
    /// then re-adding the peer does. Costs one handshake of interruption.
    ///
    /// **Contract**: never unmounts the adapter, whatever fails.
    async fn rekey_peer(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()>;

    /// Bytes sent plus received with the peer since it was last registered,
    /// or `None` when the data plane cannot say.
    async fn transfer_bytes(&self) -> Option<u64>;
```

`dryrun.rs` — champs `rekeyed: std::sync::Mutex<Vec<Option<String>>>`, `fail_rekey: AtomicBool`, `transfer: AtomicU64` (sentinelle `NO_COUNTER = u64::MAX`), initialisés dans `Default`. Méthodes :

```rust
    /// PSKs the peer was re-registered with, in order.
    pub fn rekeyed_psks(&self) -> Vec<Option<String>> {
        self.rekeyed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Makes every following `rekey_peer` fail (rollback tests).
    pub fn fail_rekeys(&self, fail: bool) {
        self.fail_rekey.store(fail, Ordering::SeqCst);
    }

    /// Forces the transfer counter (`None` = unreadable).
    pub fn set_transfer_bytes(&self, bytes: Option<u64>) {
        self.transfer.store(bytes.unwrap_or(NO_COUNTER), Ordering::SeqCst);
    }
```

et dans `impl VpnBackend` :

```rust
    async fn rekey_peer(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        profile.validate_for_data_plane()?;
        crate::endpoint_resolution::literal_endpoint(&profile.endpoint)
            .map_err(|e| anyhow::anyhow!("endpoint `{}` invalide : {e}", profile.endpoint))?;
        if !self.adapter_up.load(Ordering::SeqCst) {
            anyhow::bail!("[dry-run] aucun adaptateur monté : aucun pair à réinscrire");
        }
        if self.fail_rekey.load(Ordering::SeqCst) {
            anyhow::bail!("[dry-run] réinscription du pair refusée");
        }
        self.rekeyed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(profile.preshared_key.clone());
        self.transfer.store(0, Ordering::SeqCst);
        self.handshake_age_secs.store(0, Ordering::SeqCst);
        sink(ClientEvent::log(
            "info",
            "[dry-run] pair réinscrit — session WireGuard réinitialisée".to_string(),
        ));
        Ok(())
    }

    async fn transfer_bytes(&self) -> Option<u64> {
        match self.transfer.load(Ordering::SeqCst) {
            NO_COUNTER => None,
            bytes => Some(bytes),
        }
    }
```

`wireguard.rs` :

```rust
    async fn rekey_peer(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        profile.validate_for_data_plane()?;
        let addresses = adapter_addresses(profile)?;
        let peer = Self::build_peer(profile)?;
        if !self.adapter_up.load(Ordering::SeqCst) {
            anyhow::bail!("interface {} absente : aucun pair à réinscrire", self.ifname);
        }
        #[allow(unused_mut)]
        let mut api = self.api()?;
        // Updating the PSK in place would keep the current session, and no
        // handshake would come to prove the new PSK (spec §12.3). Removing
        // the peer drops its session keys; re-adding it makes the keep-alive
        // start a handshake at once. The adapter stays mounted throughout.
        api.remove_peer(&peer.public_key)
            .map_err(|e| anyhow::anyhow!("retrait du pair : {e}"))?;
        api.configure_peer(&peer)
            .map_err(|e| anyhow::anyhow!("réinscription du pair : {e}"))?;
        api.configure_peer_routing(&routing_peers(std::slice::from_ref(&peer)))
            .map_err(|e| anyhow::anyhow!("routage du pair : {e}"))?;
        let observed = self.observe_capture(&api, &peer.public_key);
        drop(api);
        *self.peer_key() = Some(peer.public_key.clone());
        let capture = assess_capture(
            &RequestedCapture {
                allowed_ips: &peer.allowed_ips,
                addresses: &addresses,
            },
            &observed,
        );
        for event in capture_events(&capture) {
            sink(event);
        }
        sink(ClientEvent::log(
            "info",
            "pair réinscrit — session WireGuard réinitialisée sur le nouveau PSK".to_string(),
        ));
        Ok(())
    }

    async fn transfer_bytes(&self) -> Option<u64> {
        let peer_key = self.peer_key().clone()?;
        let host = self.api().ok()?.read_interface_data().ok()?;
        let peer = host.peers.get(&peer_key)?;
        Some(peer.rx_bytes.saturating_add(peer.tx_bytes))
    }
```

Backends de test de `backend/tests.rs` : `rekey_peer` → `Ok(())`, `transfer_bytes` → `None`.

- [ ] **Step 4: Run tests and clippy**

Run: `scripts/wsl-cargo test -p orion-core backend && scripts/wsl-cargo clippy -p orion-core --all-targets --all-features -- -D warnings`
Expected: PASS, aucun avertissement. Le comportement réel de `remove_peer`/`configure_peer` sur le noyau et WireGuard-NT est **target-only** (V1).

- [ ] **Step 5: Commit**

```bash
git add crates/orion-core/src/backend
git commit -m "feat(orion-core): re-register the peer to reset its session and read its transfer counters"
```

---

### Task 7: Horloge de renouvellement (décision pure)

**Files:**
- Create: `crates/orion-core/src/backend/renewal.rs`
- Modify: `crates/orion-core/src/backend/mod.rs` (`pub mod renewal;`)

**Interfaces:**
- Consumes: `psk_renewal_after_secs()`, `psk_renewal_after_bytes()` (tâche 1).
- Produces:
  - `pub enum RenewalTrigger { Lifetime, Volume, Manual }` + `fn describe(self) -> &'static str`
  - `pub struct RenewalClock` ; `RenewalClock::start(now: Instant, wall: SystemTime, bytes: Option<u64>) -> Self` ; `RenewalClock::due(&mut self, now: Instant, wall: SystemTime, bytes: Option<u64>) -> Option<RenewalTrigger>`
  - `pub fn retry_delay(failures: u32) -> Duration`

- [ ] **Step 1: Write the failing tests** — module `tests` en bas de `renewal.rs` :

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn clock() -> (RenewalClock, Instant, SystemTime) {
        let now = Instant::now();
        let wall = SystemTime::now();
        (RenewalClock::start(now, wall, Some(0)), now, wall)
    }

    #[test]
    fn nothing_is_due_before_eighty_percent() {
        let (mut clock, now, wall) = clock();
        let later = Duration::from_secs(69_119);
        assert_eq!(clock.due(now + later, wall + later, Some(79 * GIB)), None);
    }

    #[test]
    fn the_lifetime_triggers_at_nineteen_hours_twelve() {
        let (mut clock, now, wall) = clock();
        let later = Duration::from_secs(69_120);
        assert_eq!(clock.due(now + later, wall + later, Some(0)), Some(RenewalTrigger::Lifetime));
    }

    #[test]
    fn a_suspend_seen_only_by_the_wall_clock_still_counts() {
        let (mut clock, now, wall) = clock();
        let asleep = Duration::from_secs(70_000);
        assert_eq!(
            clock.due(now + Duration::from_secs(10), wall + asleep, Some(0)),
            Some(RenewalTrigger::Lifetime)
        );
    }

    #[test]
    fn a_wall_clock_moved_back_never_delays_the_deadline() {
        let (mut clock, now, wall) = clock();
        let later = Duration::from_secs(69_120);
        assert_eq!(
            clock.due(now + later, wall - Duration::from_secs(3600), Some(0)),
            Some(RenewalTrigger::Lifetime)
        );
    }

    #[test]
    fn the_volume_triggers_at_eighty_gib() {
        let (mut clock, now, wall) = clock();
        assert_eq!(clock.due(now, wall, Some(80 * GIB)), Some(RenewalTrigger::Volume));
    }

    #[test]
    fn an_unreadable_counter_only_leaves_the_lifetime() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let mut clock = RenewalClock::start(now, wall, None);
        assert_eq!(clock.due(now, wall, None), None);
        assert_eq!(clock.due(now, wall, Some(500 * GIB)), None, "first reading is a baseline");
        assert_eq!(clock.due(now, wall, Some(580 * GIB)), Some(RenewalTrigger::Volume));
    }

    #[test]
    fn a_counter_that_went_backwards_rebases() {
        let (mut clock, now, wall) = clock();
        clock.due(now, wall, Some(70 * GIB));
        assert_eq!(clock.due(now, wall, Some(GIB)), None);
        assert_eq!(clock.due(now, wall, Some(80 * GIB)), None, "79 GiB since the rebase");
    }

    #[test]
    fn retries_back_off_up_to_fifteen_minutes() {
        let minutes: Vec<u64> = (1..=7).map(|n| retry_delay(n).as_secs() / 60).collect();
        assert_eq!(minutes, vec![1, 2, 4, 8, 15, 15, 15]);
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(15 * 60));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `scripts/wsl-cargo test -p orion-core renewal`
Expected: FAIL à la compilation.

- [ ] **Step 3: Write the implementation** — haut de `renewal.rs` :

```rust
//! When the negotiated PSK is renewed (design 2026-10-09 §2).
//!
//! At 80 % of its lifetime or of its byte ceiling, whichever comes first. The
//! gateway reclaims at 100 %; the remaining 20 % is the room failed renewals
//! are retried in.

use std::time::{Duration, Instant, SystemTime};

use aether::key_negotiation::{psk_renewal_after_bytes, psk_renewal_after_secs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalTrigger {
    Lifetime,
    Volume,
    Manual,
}

impl RenewalTrigger {
    /// The cause, as the event log names it.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Lifetime => "durée de vie à 80 %",
            Self::Volume => "volume à 80 %",
            Self::Manual => "demande manuelle",
        }
    }
}

/// Age and transfer of the PSK in place, measured from its commit.
#[derive(Debug, Clone)]
pub struct RenewalClock {
    committed_at: Instant,
    committed_wall: SystemTime,
    bytes_baseline: Option<u64>,
}

impl RenewalClock {
    pub fn start(now: Instant, wall: SystemTime, bytes: Option<u64>) -> Self {
        Self {
            committed_at: now,
            committed_wall: wall,
            bytes_baseline: bytes,
        }
    }

    /// Is a renewal due, and why?
    ///
    /// Two clocks, the earliest deadline wins (spec §12.3): the monotonic one
    /// may skip a suspend, the wall one may be moved back. A wall clock behind
    /// the commit reads as no time at all, never as a later deadline.
    pub fn due(
        &mut self,
        now: Instant,
        wall: SystemTime,
        bytes: Option<u64>,
    ) -> Option<RenewalTrigger> {
        let monotonic = now.saturating_duration_since(self.committed_at);
        let walled = wall
            .duration_since(self.committed_wall)
            .unwrap_or(Duration::ZERO);
        if monotonic.max(walled) >= Duration::from_secs(psk_renewal_after_secs()) {
            return Some(RenewalTrigger::Lifetime);
        }
        let total = bytes?;
        match self.bytes_baseline {
            Some(baseline) if total >= baseline => {
                (total - baseline >= psk_renewal_after_bytes()).then_some(RenewalTrigger::Volume)
            }
            // First reading, or a counter that went backwards: count from here.
            _ => {
                self.bytes_baseline = Some(total);
                None
            }
        }
    }
}

/// Upper bound between two renewal attempts.
pub const RETRY_CEILING: Duration = Duration::from_secs(15 * 60);

/// Pause before attempt `failures + 1`: 1, 2, 4, 8, then 15 minutes.
pub fn retry_delay(failures: u32) -> Duration {
    let minutes = 1u64
        .checked_shl(failures.saturating_sub(1))
        .unwrap_or(u64::MAX);
    Duration::from_secs(minutes.saturating_mul(60)).min(RETRY_CEILING)
}
```

`mod.rs` : `pub mod renewal;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `scripts/wsl-cargo test -p orion-core renewal`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/orion-core/src/backend/renewal.rs crates/orion-core/src/backend/mod.rs
git commit -m "feat(orion-core): decide PSK renewal on lifetime or volume at 80 %"
```

---

### Task 8: Négocier dans le tunnel depuis Orion

**Files:**
- Modify: `crates/orion-core/src/net_pin.rs` (nouvelle `tunnel_socket`)
- Modify: `crates/orion-core/src/key_negotiation.rs` (`KeyNegotiationClient`, `prepare`, `prepare_for_profile`, nouvelles fonctions)
- Modify: `tools/helios/src/key_nego.rs:276` (constructeur)
- Test: `crates/orion-core/src/key_negotiation/tests.rs`

**Interfaces:**
- Produces:
  - `pub enum NegotiationRoute { OffTunnel, InTunnel { local_vip: IpAddr } }` (Copy) ; champ `KeyNegotiationClient::route`
  - `pub fn net_pin::tunnel_socket(local_vip: IpAddr) -> anyhow::Result<UdpSocket>`
  - `pub(crate) struct RenewalRoute { pub remote: SocketAddr, pub local_vip: IpAddr }` ; `pub(crate) fn renewal_route(profile: &ClientProfile) -> anyhow::Result<RenewalRoute>`
  - `pub async fn prepare_renewal_for_profile(profile: &ClientProfile, identities: &dyn IdentityProvider) -> anyhow::Result<NegotiatedKey>`

- [ ] **Step 1: Write the failing tests** — dans `key_negotiation/tests.rs`, en partant du constructeur de profil négociant déjà présent dans ce fichier (`grep -n "key_negotiation: Some(" crates/orion-core/src/key_negotiation/tests.rs`) ; l'appeler ici `negotiating_profile()` :

```rust
fn renewal_profile() -> ClientProfile {
    let mut profile = negotiating_profile();
    profile.heliosd_url = Some("http://100.64.0.1:8080".into());
    profile.allowed_ips = "0.0.0.0/0, ::/0".into();
    profile.address = Some("100.64.1.2/32".into());
    profile.address_v6 = Some("fd00::2/128".into());
    if let Some(settings) = profile.key_negotiation.as_mut() {
        settings.endpoint = "gateway.example:51821".into();
    }
    profile
}

#[test]
fn a_renewal_dials_the_gateway_inside_the_tunnel_from_the_vip() {
    let route = renewal_route(&renewal_profile()).unwrap();
    assert_eq!(route.remote, "100.64.0.1:51821".parse().unwrap());
    assert_eq!(route.local_vip, "100.64.1.2".parse::<std::net::IpAddr>().unwrap());
}

#[test]
fn an_ipv6_gateway_address_takes_the_ipv6_vip() {
    let mut profile = renewal_profile();
    profile.heliosd_url = Some("http://[fd00::1]:8080".into());
    let route = renewal_route(&profile).unwrap();
    assert_eq!(route.remote, "[fd00::1]:51821".parse().unwrap());
    assert_eq!(route.local_vip, "fd00::2".parse::<std::net::IpAddr>().unwrap());
}

#[test]
fn a_renewal_route_is_refused_rather_than_guessed() {
    let mut missing = renewal_profile();
    missing.heliosd_url = None;
    assert!(renewal_route(&missing).is_err(), "no internal URL");

    let mut named = renewal_profile();
    named.heliosd_url = Some("http://helios.lan:8080".into());
    assert!(renewal_route(&named).is_err(), "a name would be resolved in clear");

    let mut outside = renewal_profile();
    outside.allowed_ips = "10.0.0.0/8".into();
    assert!(renewal_route(&outside).is_err(), "outside AllowedIPs leaves in clear");

    let mut no_vip = renewal_profile();
    no_vip.address = None;
    assert!(renewal_route(&no_vip).is_err(), "no VIP of the gateway's family");
}

#[test]
fn the_tunnel_socket_is_bound_to_the_given_source() {
    let socket = crate::net_pin::tunnel_socket("127.0.0.1".parse().unwrap()).unwrap();
    assert_eq!(socket.local_addr().unwrap().ip(), std::net::Ipv4Addr::LOCALHOST);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `scripts/wsl-cargo test -p orion-core key_negotiation`
Expected: FAIL à la compilation (`renewal_route`, `tunnel_socket` absents).

- [ ] **Step 3: Write the implementation**

`net_pin.rs` :

```rust
/// Opens the UDP socket of an in-tunnel PSK renewal, bound to the client VIP.
///
/// The opposite of [`negotiation_socket`]: a renewal must ride the tunnel it
/// renews. Binding the source to the VIP selects the tunnel interface on every
/// platform, and keeps that source across the peer re-registration of the
/// renewal — the adapter and its address stay in place, so the gateway sees
/// no QUIC migration.
pub fn tunnel_socket(local_vip: IpAddr) -> Result<UdpSocket> {
    let bind = SocketAddr::new(local_vip, 0);
    UdpSocket::bind(bind).with_context(|| format!("binding the renewal socket on {bind}"))
}
```

`key_negotiation.rs` :

```rust
/// Which way the negotiation socket goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationRoute {
    /// First negotiation: before the tunnel, pinned off it (`net_pin`).
    OffTunnel,
    /// Renewal: through the tunnel already up, from the client VIP.
    InTunnel { local_vip: IpAddr },
}
```

Ajouter `pub route: NegotiationRoute,` à `KeyNegotiationClient` (et au `Debug` manuel : `.field("route", &self.route)`). Dans `prepare`, avant `race` : `let route = client.route;` puis, dans la closure, remplacer l'ouverture de socket par :

```rust
            let socket = match route {
                NegotiationRoute::OffTunnel => {
                    crate::net_pin::negotiation_socket(remote, crate::net_pin::TUNNEL_IFNAME)
                }
                NegotiationRoute::InTunnel { local_vip } => crate::net_pin::tunnel_socket(local_vip),
            }
            .context("opening the key-negotiation socket")?;
```

Découper `prepare_for_profile` : son corps devient `async fn prepare_for_profile_via(profile, identities, remote: String, route: NegotiationRoute)` où `remote: settings.endpoint.clone()` est remplacé par `remote` et `route` est passé au `KeyNegotiationClient` ; puis :

```rust
pub async fn prepare_for_profile(
    profile: &ClientProfile,
    identities: &dyn IdentityProvider,
) -> Result<NegotiatedKey> {
    let settings = profile
        .key_negotiation
        .as_ref()
        .context("profile has no key-negotiation settings")?;
    prepare_for_profile_via(profile, identities, settings.endpoint.clone(), NegotiationRoute::OffTunnel)
        .await
}

/// Prepares an in-tunnel renewal of the PSK in place (design 2026-10-09).
///
/// Same transaction, same pins, same `server_name`; only the path changes.
/// Never falls back to the public endpoint.
pub async fn prepare_renewal_for_profile(
    profile: &ClientProfile,
    identities: &dyn IdentityProvider,
) -> Result<NegotiatedKey> {
    let route = renewal_route(profile)?;
    prepare_for_profile_via(
        profile,
        identities,
        route.remote.to_string(),
        NegotiationRoute::InTunnel {
            local_vip: route.local_vip,
        },
    )
    .await
}

pub(crate) struct RenewalRoute {
    pub remote: std::net::SocketAddr,
    pub local_vip: IpAddr,
}

/// The gateway address inside the tunnel, on the negotiation port, and the
/// VIP of the same family to send from.
pub(crate) fn renewal_route(profile: &ClientProfile) -> Result<RenewalRoute> {
    let url = profile.heliosd_url.as_deref().context(
        "no internal Helios URL in the profile: an in-tunnel renewal has no gateway address",
    )?;
    let gateway = tunnel_routed_address(url, &profile.allowed_ips)?;
    let address: IpAddr = match gateway.host() {
        Some(url::Host::Ipv4(address)) => address.into(),
        Some(url::Host::Ipv6(address)) => address.into(),
        _ => anyhow::bail!("the renewal is only sent to a literal gateway address"),
    };
    let settings = profile
        .key_negotiation
        .as_ref()
        .context("profile has no key-negotiation settings")?;
    let port = crate::endpoint_resolution::port_of(&settings.endpoint)
        .context("the key-negotiation endpoint names no port")?;
    let declared = match address {
        IpAddr::V4(_) => profile.address.as_deref(),
        IpAddr::V6(_) => profile.address_v6.as_deref(),
    };
    let local_vip = declared
        .and_then(|vip| vip.trim().split('/').next()?.parse::<IpAddr>().ok())
        .filter(|vip| vip.is_ipv4() == address.is_ipv4())
        .context("the profile declares no VIP of the gateway address family")?;
    Ok(RenewalRoute {
        remote: std::net::SocketAddr::new(address, port),
        local_vip,
    })
}
```

`tools/helios/src/key_nego.rs:276` : ajouter `route: orion_core::key_negotiation::NegotiationRoute::OffTunnel,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `scripts/wsl-cargo test -p orion-core key_negotiation && scripts/wsl-cargo test -p helios`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/orion-core/src/net_pin.rs crates/orion-core/src/key_negotiation.rs crates/orion-core/src/key_negotiation tools/helios/src/key_nego.rs
git commit -m "feat(orion-core): negotiate a PSK renewal inside the tunnel from the client VIP"
```

---

### Task 9: Renouvellement par le contrôleur Orion

**Files:**
- Modify: `crates/orion-core/src/backend/mod.rs` (`InstalledNegotiation`, `VpnController`, `connect_with_key_negotiation`, nouvelles fonctions)
- Test: `crates/orion-core/src/backend/tests.rs`

**Interfaces:**
- Consumes: `rekey_peer`, `transfer_bytes` (tâche 6), `RenewalClock`, `RenewalTrigger`, `retry_delay` (tâche 7), `prepare_renewal_for_profile` (tâche 8), `wait_for_new_handshake` (existant).
- Produces:
  - `InstalledNegotiation { transaction_id, profile, data_plane: ClientProfile, clock: RenewalClock, failures: u32, next_attempt: Option<std::time::Instant> }` + `InstalledNegotiation::new(transaction_id, profile, data_plane, bytes: Option<u64>) -> Self`
  - `pub(crate) trait PendingRenewal` (implémenté par `NegotiatedKey`)
  - `pub(crate) async fn renew_slot(backend: &Arc<dyn VpnBackend>, current: &InstalledNegotiation, pending: Box<dyn PendingRenewal>, sink: &EventSink) -> anyhow::Result<InstalledNegotiation>`
  - `fn settle_renewal(slot: &mut Option<InstalledNegotiation>, renewed_from: [u8; 16], outcome: anyhow::Result<InstalledNegotiation>, sink: &EventSink)`
  - `pub async fn VpnController::poll_renewal(&self, user_sink: EventSink)`
  - `pub async fn VpnController::renew_now(&self, user_sink: EventSink) -> anyhow::Result<()>`

- [ ] **Step 1: Write the failing tests** — dans `backend/tests.rs` :

```rust
const NEW_PSK: &str = "bmV3cHNrbmV3cHNrbmV3cHNrbmV3cHNrbmV3cHNrMTI=";
const OLD_PSK: &str = "b2xkcHNrb2xkcHNrb2xkcHNrb2xkcHNrb2xkcHNrMTI=";

struct FakePending {
    psk: aether::SecretString,
    confirm: Result<(), String>,
    hang: bool,
}

#[async_trait::async_trait]
impl PendingRenewal for FakePending {
    fn psk(&self) -> Option<&aether::SecretString> {
        Some(&self.psk)
    }
    fn transaction_id(&self) -> [u8; 16] {
        [9; 16]
    }
    fn confirmation_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
    async fn confirm(self: Box<Self>) -> anyhow::Result<()> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        self.confirm.map_err(|e| anyhow::anyhow!(e))
    }
}

fn pending(confirm: Result<(), String>) -> Box<dyn PendingRenewal> {
    Box::new(FakePending { psk: aether::SecretString::new(NEW_PSK), confirm, hang: false })
}

async fn mounted() -> (Arc<DryRunBackend>, Arc<dyn VpnBackend>, InstalledNegotiation) {
    let dry = Arc::new(DryRunBackend { negotiate_delay: Duration::ZERO, ..DryRunBackend::default() });
    let backend: Arc<dyn VpnBackend> = dry.clone();
    let data_plane = ClientProfile { preshared_key: Some(OLD_PSK.into()), ..profile() };
    backend.up(&data_plane, &sink()).await.unwrap();
    let receipt = InstalledNegotiation::new([7; 16], profile(), data_plane, Some(0));
    (dry, backend, receipt)
}

#[tokio::test]
async fn a_confirmed_renewal_installs_the_new_psk_and_a_new_receipt() {
    let (dry, backend, current) = mounted().await;
    let renewed = renew_slot(&backend, &current, pending(Ok(())), &sink()).await.unwrap();
    assert_eq!(renewed.transaction_id, [9; 16]);
    assert_eq!(dry.rekeyed_psks(), vec![Some(NEW_PSK.to_string())]);
    assert_eq!(renewed.data_plane.preshared_key.as_deref(), Some(NEW_PSK));
}

#[tokio::test]
async fn a_renewal_restarts_the_volume_count_from_the_re_registered_peer() {
    let (dry, backend, current) = mounted().await;
    dry.set_transfer_bytes(Some(70 * 1024 * 1024 * 1024));
    let mut renewed = renew_slot(&backend, &current, pending(Ok(())), &sink()).await.unwrap();
    // `rekey_peer` restarted the client counters at zero; 80 GiB from there.
    let now = std::time::Instant::now();
    let wall = std::time::SystemTime::now();
    assert_eq!(renewed.clock.due(now, wall, Some(79 * 1024 * 1024 * 1024)), None);
}

#[tokio::test]
async fn a_failed_confirmation_puts_the_previous_psk_back() {
    let (dry, backend, current) = mounted().await;
    assert!(renew_slot(&backend, &current, pending(Err("lost".into())), &sink()).await.is_err());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        dry.rekeyed_psks(),
        vec![Some(NEW_PSK.to_string()), Some(OLD_PSK.to_string())],
        "the rollback re-registers the peer with the PSK it had"
    );
}

#[tokio::test]
async fn a_cancelled_renewal_still_puts_the_previous_psk_back() {
    let (dry, backend, current) = mounted().await;
    let task = tokio::spawn(async move {
        let hanging = Box::new(FakePending {
            psk: aether::SecretString::new(NEW_PSK),
            confirm: Ok(()),
            hang: true,
        });
        renew_slot(&backend, &current, hanging, &sink()).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(dry.rekeyed_psks().last(), Some(&Some(OLD_PSK.to_string())));
}

#[tokio::test]
async fn a_renewal_outcome_never_overwrites_a_newer_receipt() {
    let (_dry, _backend, current) = mounted().await;
    let newer = InstalledNegotiation::new([8; 16], profile(), current.data_plane.clone(), None);
    let mut slot = Some(newer);
    let renewed = InstalledNegotiation::new([9; 16], profile(), current.data_plane.clone(), None);
    settle_renewal(&mut slot, [7; 16], Ok(renewed), &sink());
    assert_eq!(slot.unwrap().transaction_id, [8; 16], "a reconnection owns the slot now");
}

#[tokio::test]
async fn a_failed_renewal_schedules_the_next_attempt() {
    let (_dry, _backend, current) = mounted().await;
    let mut slot = Some(current);
    settle_renewal(&mut slot, [7; 16], Err(anyhow::anyhow!("refused")), &sink());
    let receipt = slot.unwrap();
    assert_eq!(receipt.failures, 1);
    assert!(receipt.next_attempt.is_some_and(|at| at > std::time::Instant::now()));
}

#[tokio::test]
async fn nothing_is_renewed_before_the_threshold_or_without_a_tunnel() {
    let (dry, _backend, receipt) = mounted().await;
    let ctrl = VpnController::new(dry.clone());
    *ctrl.installed.lock().await = Some(receipt);
    ctrl.poll_renewal(sink()).await; // state is Down
    *ctrl.state.write().unwrap() = TunnelState::Up;
    ctrl.poll_renewal(sink()).await; // fresh receipt
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(dry.rekeyed_psks().is_empty());
    assert!(!ctrl.renewing.load(Ordering::SeqCst));

    *ctrl.state.write().unwrap() = TunnelState::Down;
    assert!(ctrl.renew_now(sink()).await.is_err(), "no tunnel up: nothing to renew");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `scripts/wsl-cargo test -p orion-core backend`
Expected: FAIL à la compilation.

- [ ] **Step 3: Write the implementation** — dans `backend/mod.rs`.

Reçu :

```rust
#[derive(Clone)]
struct InstalledNegotiation {
    transaction_id: [u8; 16],
    profile: ClientProfile,
    /// The copy the data plane received — literal endpoint, PSK in place.
    ///
    /// A renewal re-registers the peer from it with the new PSK, and puts it
    /// back as it was if the renewal does not commit.
    data_plane: ClientProfile,
    clock: renewal::RenewalClock,
    /// Renewals failed since this PSK was committed.
    failures: u32,
    /// No automatic renewal before this instant (back-off).
    next_attempt: Option<std::time::Instant>,
}

impl InstalledNegotiation {
    fn new(
        transaction_id: [u8; 16],
        profile: ClientProfile,
        data_plane: ClientProfile,
        bytes: Option<u64>,
    ) -> Self {
        Self {
            transaction_id,
            profile,
            data_plane,
            clock: renewal::RenewalClock::start(
                std::time::Instant::now(),
                std::time::SystemTime::now(),
                bytes,
            ),
            failures: 0,
            next_attempt: None,
        }
    }
}
```

Dans `connect_with_key_negotiation`, la création du reçu devient :

```rust
                let bytes = backend.transfer_bytes().await;
                *installed.lock().await = (mode == aether::key_negotiation::ProtectionMode::MlKem)
                    .then(|| {
                        InstalledNegotiation::new(
                            transaction_id,
                            profile.clone(),
                            negotiated_profile.clone(),
                            bytes,
                        )
                    });
```

et `stalled_with_receipt` (tests) : `InstalledNegotiation::new([7; 16], profile(), profile(), None)`.

Négociation en attente et garde :

```rust
/// What a renewal needs from a prepared negotiation.
///
/// Implemented by [`crate::key_negotiation::NegotiatedKey`]; tests substitute
/// a fake to drive the failure and cancellation paths without a gateway.
#[async_trait]
pub(crate) trait PendingRenewal: Send {
    fn psk(&self) -> Option<&aether::SecretString>;
    fn transaction_id(&self) -> [u8; 16];
    fn confirmation_timeout(&self) -> Duration;
    async fn confirm(self: Box<Self>) -> anyhow::Result<()>;
}

#[async_trait]
impl PendingRenewal for crate::key_negotiation::NegotiatedKey {
    fn psk(&self) -> Option<&aether::SecretString> {
        self.psk.as_ref()
    }
    fn transaction_id(&self) -> [u8; 16] {
        crate::key_negotiation::NegotiatedKey::transaction_id(self)
    }
    fn confirmation_timeout(&self) -> Duration {
        self.confirmation_timeout
    }
    async fn confirm(self: Box<Self>) -> anyhow::Result<()> {
        crate::key_negotiation::NegotiatedKey::confirm(*self).await
    }
}

/// Re-registers the previous peer unless disarmed.
///
/// On an error return **and** when the renewal future is dropped mid-way: a
/// cancelled future runs no exit path of its own, so the restore is spawned
/// from `Drop`. Dropping the pending negotiation closes its QUIC session and
/// the gateway restores its own previous slot — both ends land on the old PSK.
struct RestorePrevious {
    backend: Arc<dyn VpnBackend>,
    previous: Option<ClientProfile>,
    sink: EventSink,
}

impl RestorePrevious {
    fn disarm(mut self) {
        self.previous = None;
    }
}

impl Drop for RestorePrevious {
    fn drop(&mut self) {
        let Some(previous) = self.previous.take() else {
            return;
        };
        let backend = Arc::clone(&self.backend);
        let sink = Arc::clone(&self.sink);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    match backend.rekey_peer(&previous, &sink).await {
                        Ok(()) => sink(ClientEvent::log(
                            "warn",
                            "renouvellement non abouti : l'ancien PSK est remis en place"
                                .to_string(),
                        )),
                        Err(error) => sink(ClientEvent::log(
                            "error",
                            format!(
                                "renouvellement non abouti et ancien PSK non remis en place \
                                 ({error:#}) : la reconnexion automatique prendra le relais"
                            ),
                        )),
                    }
                });
            }
            Err(_) => {
                tracing::error!("renewal rollback: no runtime left to restore the previous peer")
            }
        }
    }
}

/// Installs a renewed PSK by re-registering the peer, proves it with a fresh
/// handshake, then commits (design 2026-10-09 §3).
pub(crate) async fn renew_slot(
    backend: &Arc<dyn VpnBackend>,
    current: &InstalledNegotiation,
    pending: Box<dyn PendingRenewal>,
    sink: &EventSink,
) -> anyhow::Result<InstalledNegotiation> {
    let psk = pending
        .psk()
        .context("an in-tunnel renewal must derive an ml_kem PSK")?
        .expose()
        .to_string();
    let renewed = ClientProfile {
        preshared_key: Some(psk),
        preshared_key_is_negotiated: true,
        ..current.data_plane.clone()
    };
    let timeout = pending.confirmation_timeout();
    let transaction_id = pending.transaction_id();
    let prepared_at = tokio::time::Instant::now();
    let restore = RestorePrevious {
        backend: Arc::clone(backend),
        previous: Some(current.data_plane.clone()),
        sink: Arc::clone(sink),
    };
    backend
        .rekey_peer(&renewed, sink)
        .await
        .context("re-registering the peer with the renewed PSK")?;
    if !wait_for_new_handshake(backend, prepared_at, timeout).await {
        anyhow::bail!(
            "no WireGuard handshake with the renewed PSK within {} s",
            timeout.as_secs()
        );
    }
    pending.confirm().await.context("confirming the renewal")?;
    restore.disarm();
    Ok(InstalledNegotiation::new(
        transaction_id,
        current.profile.clone(),
        renewed,
        backend.transfer_bytes().await,
    ))
}

/// Applies a renewal outcome to the receipt it started from — and only to it.
fn settle_renewal(
    slot: &mut Option<InstalledNegotiation>,
    renewed_from: [u8; 16],
    outcome: anyhow::Result<InstalledNegotiation>,
    sink: &EventSink,
) {
    // A disconnection or a reconnection meanwhile owns the slot now.
    let Some(receipt) = slot
        .as_mut()
        .filter(|receipt| receipt.transaction_id == renewed_from)
    else {
        return;
    };
    match outcome {
        Ok(renewed) => {
            *receipt = renewed;
            sink(ClientEvent::protection(PskKind::MlKem));
            sink(ClientEvent::log(
                "info",
                "clé renouvelée — nouveau PSK ML-KEM en place, durée et volume remis à zéro"
                    .to_string(),
            ));
        }
        Err(error) => {
            receipt.failures = receipt.failures.saturating_add(1);
            let delay = renewal::retry_delay(receipt.failures);
            receipt.next_attempt = Some(std::time::Instant::now() + delay);
            sink(ClientEvent::log(
                "warn",
                format!(
                    "renouvellement du PSK : échec — {error:#}. Nouvel essai dans {} min ; \
                     l'ancien PSK reste en place jusqu'à son échéance.",
                    delay.as_secs() / 60
                ),
            ));
        }
    }
}

async fn run_renewal(
    backend: &Arc<dyn VpnBackend>,
    identities: &dyn crate::key_negotiation::IdentityProvider,
    installed: &Mutex<Option<InstalledNegotiation>>,
    trigger: renewal::RenewalTrigger,
    sink: &EventSink,
) {
    let Some(current) = installed.lock().await.clone() else {
        return;
    };
    sink(ClientEvent::log(
        "info",
        format!(
            "renouvellement du PSK ML-KEM déclenché ({}) — négociation dans le tunnel",
            trigger.describe()
        ),
    ));
    let outcome = async {
        let negotiated =
            crate::key_negotiation::prepare_renewal_for_profile(&current.profile, identities)
                .await?;
        renew_slot(backend, &current, Box::new(negotiated), sink).await
    }
    .await;
    settle_renewal(
        &mut *installed.lock().await,
        current.transaction_id,
        outcome,
        sink,
    );
}

/// Clears the in-flight flag however the renewal task ends.
struct ClearOnDrop(Arc<AtomicBool>);

impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
```

`VpnController` : champ `renewing: Arc<AtomicBool>` (initialisé `Arc::new(AtomicBool::new(false))` dans `new`), puis :

```rust
    /// Renews the negotiated PSK through the tunnel once it is due.
    ///
    /// Called by the shell's state loop beside [`Self::poll_handshake`].
    /// Never touches the adapter beyond re-registering the peer.
    pub async fn poll_renewal(&self, user_sink: EventSink) {
        if self.state() != TunnelState::Up {
            return;
        }
        let trigger = {
            let mut installed = self.installed.lock().await;
            let Some(receipt) = installed.as_mut() else {
                return;
            };
            if receipt
                .next_attempt
                .is_some_and(|at| std::time::Instant::now() < at)
            {
                return;
            }
            let bytes = self.backend.transfer_bytes().await;
            match receipt.clock.due(
                std::time::Instant::now(),
                std::time::SystemTime::now(),
                bytes,
            ) {
                Some(trigger) => trigger,
                None => return,
            }
        };
        self.start_renewal(trigger, user_sink).await;
    }

    /// Renews now, at the user's request (and for the V1 measurement).
    pub async fn renew_now(&self, user_sink: EventSink) -> anyhow::Result<()> {
        if self.state() != TunnelState::Up || self.installed.lock().await.is_none() {
            anyhow::bail!("aucun tunnel ML-KEM monté : rien à renouveler");
        }
        self.start_renewal(renewal::RenewalTrigger::Manual, user_sink)
            .await;
        Ok(())
    }

    async fn start_renewal(&self, trigger: renewal::RenewalTrigger, user_sink: EventSink) {
        if self.renewing.swap(true, Ordering::SeqCst) {
            return;
        }
        let flag = ClearOnDrop(Arc::clone(&self.renewing));
        let Some(identities) = self.key_negotiation_identities.clone() else {
            return;
        };
        let backend = Arc::clone(&self.backend);
        let installed = Arc::clone(&self.installed);
        let sink = self.wrap_sink(user_sink);
        tokio::spawn(async move {
            let _flag = flag;
            run_renewal(&backend, identities.as_ref(), &installed, trigger, &sink).await;
        });
    }
```

Dans `disconnect`, après `self.abort_task().await;` s'il existe, ou au début : rien à ajouter — un renouvellement en vol voit son reçu disparaître et `settle_renewal` l'ignore ; la garde remet l'ancien pair si la tâche est encore active, puis `down()` démonte l'adaptateur.

- [ ] **Step 4: Run tests to verify they pass**

Run: `scripts/wsl-cargo test -p orion-core backend && scripts/wsl-cargo clippy -p orion-core --all-targets --all-features -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/orion-core/src/backend
git commit -m "feat(orion-core): renew the negotiated PSK inside the tunnel with a rollback guard"
```

---

### Task 10: Commande Tauri, boucle d'état et action « Renouveler la clé maintenant »

**Files:**
- Modify: `apps/orion/src-tauri/src/main.rs` (commande `renew_psk`, enregistrement `generate_handler!`, boucle ~l.2299-2311)
- Modify: `apps/orion/src/api.ts`, `apps/orion/src/api.test.ts`
- Modify: `apps/orion/src/hooks/useClient.ts`
- Modify: `apps/orion/src/views/ConnectView.tsx`, `apps/orion/src/App.tsx:399-410`
- Test: `apps/orion/src/components/rendering.test.tsx`

**Interfaces:**
- Consumes: `VpnController::{poll_renewal, renew_now}` (tâche 9).
- Produces: commande `renew_psk` ; `api.renewPsk(): Promise<void>` ; `useClient().renewPsk` ; prop `onRenewKey: () => void` de `ConnectView`.

- [ ] **Step 1: Write the failing tests**

`rendering.test.tsx`, dans le helper `render` du test « renders connection decisions… » : ajouter `onRenewKey={callback}` ; puis à la fin du test :

```tsx
    expect(render('up', profile())).toContain('Renouveler la clé maintenant')
    expect(render('connecting', profile())).not.toContain('Renouveler la clé maintenant')
```

`api.test.ts`, à côté de `await disconnect()` : ajouter `renewPsk` à l'import et

```ts
    await renewPsk()
```

puis l'attente sur `invoke` qui suit le modèle du fichier pour `disconnect` (`expect(invoke).toHaveBeenCalledWith('renew_psk')`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm run test:unit --prefix apps/orion`
Expected: FAIL (`renewPsk` absent, bouton absent).

- [ ] **Step 3: Write the implementation**

`api.ts` (à côté de `disconnect`) :

```ts
/** Renews the ML-KEM PSK now, through the tunnel. */
export const renewPsk = () => invoke<void>('renew_psk')
```

`useClient.ts`, sur le modèle de `openSshTerminal` :

```ts
  const renewPsk = useCallback(async () => {
    setError(null)
    try {
      await api.renewPsk()
      pushLog('info', 'Renouvellement de la clé demandé.')
    } catch (cause) {
      pushLog('warn', `Renouvellement non lancé — ${String(cause)}`)
    }
  }, [pushLog])
```

et l'exposer dans l'objet retourné (`renewPsk,`). Adapter le tableau de dépendances à celui d'`openSshTerminal`.

`ConnectView.tsx` : prop `/** Renews the ML-KEM PSK through the tunnel. */ onRenewKey: () => void`, `KeyRound` ajouté à l'import d'icônes existant (même paquet que `Power`), et sous le bouton SSH :

```tsx
        {/* Shown only on a tunnel carrying traffic under an ML-KEM PSK: the
            renewal rides that tunnel, and Rust refuses it otherwise. */}
        {state === 'up' && psk === 'ml_kem' && (
          <Button
            fullWidth
            variant="text"
            color="inherit"
            startIcon={<KeyRound size={16} aria-hidden />}
            onClick={onRenewKey}
            sx={{ fontSize: 12, textTransform: 'none', color: 'text.secondary' }}
          >
            Renouveler la clé maintenant
          </Button>
        )}
```

`App.tsx` : `onRenewKey={c.renewPsk}` à côté de `onOpenSsh`.

`main.rs` :

```rust
/// Renews the ML-KEM PSK now, through the tunnel (design 2026-10-09).
#[tauri::command]
async fn renew_psk(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    state
        .controller
        .renew_now(emit_sink(app.clone()))
        .await
        .map_err(|error| error.to_string())
}
```

ajouter `renew_psk` à la liste `generate_handler!` principale (~l.2913), et dans la boucle d'inférence, juste après `controller.poll_handshake(sink.clone()).await;` :

```rust
            controller.poll_renewal(sink.clone()).await;
```

Si `apps/orion/src-tauri/src/security_tests.rs` ou un manifeste de capacités énumère les commandes (`grep -rn "open_ssh_terminal" apps/orion/src-tauri`), y ajouter `renew_psk` au même endroit.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm run test:unit --prefix apps/orion && scripts/wsl-cargo clippy -p orion --all-targets -- -D warnings`
Expected: PASS. (Nom de package Tauri : vérifier `apps/orion/src-tauri/Cargo.toml` `[package] name`.)

- [ ] **Step 5: Commit**

```bash
git add apps/orion
git commit -m "feat(orion): renew the ML-KEM key on schedule and on request"
```

---

### Task 11: Documentation normative et de suivi

**Files:**
- Modify: `docs/specification/NEGOCIATION-DE-CLE-V5.md` (en-tête « Ce qui n'est pas implémenté », §7.5 voisinage, §12.3, §20.0, §20.2, §21)
- Modify: `docs/adr/ADR-005-NEGOCIATION-DE-CLE.md`
- Modify: `README.md` (« État et limites »), `docs/ROADMAP.md` (F1, V1), `docs/testing/TESTING.md`

**Interfaces:** aucune (documentation, en français).

- [ ] **Step 1: Amender la spécification v5**
  - En-tête : retirer « le renouvellement de PSK en place » de la liste non implémentée ; ajouter une ligne datée 2026-10-09 qui renvoie au design.
  - Nouvelle section « 7.6 Renouvellement dans le tunnel » après §7.5 : même transaction, adressée à `<hôte de heliosd_url>:<port de négociation>` depuis une socket liée à la VIP ; classement par VIP source ; refus générique hors slot `ml_kem` committé ou hors mode `ml_kem` ; aucun repli vers le port public.
  - §12.3 : seuil 80 % (au lieu de 90 %) ; plafond 100 Gio non signé et limite ferme gateway ; nouvelles tentatives 1–15 min ; garde de rollback Orion.
  - §20.0 : « essai bloquant levé par décision du 2026-10-09 ; la mesure V1 se fait sur le code de production via l'action manuelle ; le repli §12.3 reste l'issue si V1 échoue ».
  - §21 : remplacer « Et cette interruption n'est pas encore mesurée » par l'état réel (mesure à mener sur cible).

- [ ] **Step 2: ADR-005, README, ROADMAP, TESTING**
  - ADR-005 : un paragraphe sous l'amendement du 24 juillet sur le canal de renouvellement dans le tunnel et son ouverture pare-feu limitée à `wg_iface`.
  - README « État et limites » : le renouvellement de PSK en place est livré, sa validation sur cible reste à mener.
  - ROADMAP : F1 « livré, V1 à mesurer » ; horizon 1, V1 décrit par la recette TESTING.
  - TESTING.md, nouvelle sous-section « Renouvellement du PSK à chaud (V1) » : 20 renouvellements via « Renouveler la clé maintenant », `ping -D -i 0.01 <VIP>` depuis la gateway, une connexion `iperf3 -t 1500 -J` unique, capture `tcpdump -ttt 'udp port <port> and (udp[8]=1 or udp[8]=2)'`, chemin sain puis `netem delay 150ms 30ms loss 5%`, sur noyau Linux et WireGuard-NT, critères du §12.3 et verdict PASS/FAIL par critère ; rien n'est coché depuis WSL2.

- [ ] **Step 3: Vérifier qu'aucun fichier source n'a changé dans ce commit**

Run: `git diff --name-only --cached`
Expected: uniquement des fichiers `.md`.

- [ ] **Step 4: Commit**

```bash
git add docs README.md
git commit -m "docs(key-negotiation): specify the in-tunnel PSK renewal and its V1 recipe"
```

---

### Task 12: Vérification complète

- [ ] **Step 1: Format et lint**

Run: `cargo fmt --check && scripts/wsl-cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: aucun écart, aucun avertissement.

- [ ] **Step 2: Régression canonique**

Run: `CARGO_BUILD_JOBS=2 bash scripts/regression.sh`
Expected: succès. (Plafond de jobs requis sous WSL, sinon la RAM sature.)

- [ ] **Step 3: Interfaces**

Run: `npm run test:unit --prefix apps/orion && npm run test:unit --prefix web`
Expected: PASS.

- [ ] **Step 4: Rapport**

Lister les commandes exécutées et leur résultat, et écrire explicitement ce qui reste **target-only** : comportement de `remove_peer`/`configure_peer` sur le noyau et WireGuard-NT, règle pare-feu réelle sur `helios0`, et la recette V1 complète. Aucun de ces points n'est validé par WSL2.
