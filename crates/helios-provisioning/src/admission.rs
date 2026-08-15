//! Admission of a peer: the out-of-band step that provisioning never performs.
//!
//! Declaring a public key in `peers` is what authorizes a client to bring up
//! the tunnel (see [`crate`]). This operation used to be done by hand in
//! `network.toml`; it lives here so the two paths of ADR-004 §4 — local on
//! the gateway, and remote via the API — share the **same** code.
//!
//! # Why this isn't a plain `push`
//!
//! Three rules must hold together, and none of them is obvious from the
//! caller's side:
//!
//! * the VIP comes from the IPAM, not from a human choice — in WireGuard,
//!   `AllowedIPs` **is** the cryptographic routing table, two peers cannot
//!   claim the same address;
//! * the gateway's address is reserved: assigning it would cut the control
//!   plane, i.e. the only channel that would allow fixing the mistake;
//! * a public key already admitted under another name is a duplicate, not a
//!   second peer: WireGuard indexes its peers by public key and the second
//!   one would silently overwrite the first.
//!
//! # What admission does not do
//!
//! It installs no PSK: that one is derived at enrollment ([`crate::session`])
//! and has no value beforehand. It does not revoke anything cryptographically
//! either — removing a peer makes it drop at its next handshake attempt,
//! with no revocation list (ADR-004).

use std::net::Ipv4Addr;

use aether::key_negotiation::ProtectionMode;
use aether::{wg, NetworkConfig, WgPeer};

use crate::ipam::{assign_vip, PeerTable, MAX_VIP_PROBES};

/// Admission refusal. Each variant corresponds to an explicit rule: an
/// admission must never fail "because it didn't work".
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("empty peer name")]
    EmptyName,
    #[error("invalid public key: {0}")]
    Key(#[from] wg::WgKeyError),
    #[error("a peer named « {0} » is already admitted")]
    NameTaken(String),
    #[error("this public key is already admitted under the name « {0} »")]
    KeyTaken(String),
    #[error("no peer named « {0} »")]
    Unknown(String),
    #[error("VIP assignment impossible: {0}")]
    Ipam(#[from] crate::ipam::IpamError),
    #[error("certificate fingerprint must be 64 lowercase SHA-256 hexadecimal characters")]
    CertificateFingerprint,
    #[error(
        "admission requires both the TLS and the PQ key-negotiation certificate; the \
         classic path leaves the first handshake unprotected and is retired on 2027-02-01"
    )]
    MissingNegotiationIdentity,
    #[error(
        "admission floor must be `ml_kem`, not `{0:?}`; a weaker floor is only reachable \
         by editing network.toml locally"
    )]
    FloorBelowMlKem(ProtectionMode),
}

/// Admits a peer with both transport and PQ identity bindings.
///
/// The configuration is only modified on success: a refusal leaves `config`
/// intact, which lets the caller persist it unconditionally after an `Ok`.
///
/// The v4 shims that admitted a peer without a certificate, or with only the
/// TLS one, are gone rather than deprecated. Under v5 rules they could only
/// ever return [`AdmissionError::MissingNegotiationIdentity`], and a function
/// whose every call fails is worse than no function.
pub fn admit_with_key_negotiation(
    config: &mut NetworkConfig,
    name: &str,
    public_key: &str,
    admin: bool,
    certificate_sha256: Option<&str>,
    pq_certificate_sha256: Option<&str>,
    minimum_mode: ProtectionMode,
) -> Result<WgPeer, AdmissionError> {
    let name = name.trim();
    let public_key = public_key.trim();
    let certificate_sha256 = certificate_sha256.map(str::trim);
    let pq_certificate_sha256 = pq_certificate_sha256.map(str::trim);

    if name.is_empty() {
        return Err(AdmissionError::EmptyName);
    }
    wg::validate_key(public_key)?;
    // v5 admits no peer without both identities, and every admission lands on
    // the `ml_kem` floor. The v4 default — no certificate, therefore
    // `classic` — is gone: it produced peers whose first handshake was
    // unprotected while nothing in any interface distinguished them from the
    // others. A weaker floor remains reachable, but only by editing
    // `network.toml` by hand, which is a deliberate act rather than a default.
    let (certificate_sha256, pq_certificate_sha256) = certificate_sha256
        .zip(pq_certificate_sha256)
        .ok_or(AdmissionError::MissingNegotiationIdentity)?;
    for fingerprint in [certificate_sha256, pq_certificate_sha256] {
        aether::key_negotiation::validate_certificate_fingerprint(fingerprint)
            .map_err(|_| AdmissionError::CertificateFingerprint)?;
    }
    if minimum_mode != ProtectionMode::MlKem {
        return Err(AdmissionError::FloorBelowMlKem(minimum_mode));
    }

    if let Some(existing) = config.peers.iter().find(|peer| peer.name.trim() == name) {
        return Err(AdmissionError::NameTaken(existing.name.clone()));
    }
    if let Some(existing) = config
        .peers
        .iter()
        .find(|peer| peer.public_key.trim() == public_key)
    {
        return Err(AdmissionError::KeyTaken(existing.name.clone()));
    }

    let raw = decode_key(public_key);
    let table = DeclaredPeers::new(config);
    let vip = assign_vip(&table, &raw, MAX_VIP_PROBES)?;

    let peer = WgPeer {
        name: name.to_string(),
        public_key: public_key.to_string(),
        address: format!("{vip}/32"),
        admin,
        // The PSK is born from the ML-KEM exchange, not from admission.
        // Setting it here would amount to inventing a secret no client
        // knows, and a PSK slot filled on only one side breaks every
        // handshake of the peer.
        preshared_key: None,
        key_negotiation_certificate_sha256: Some(certificate_sha256.to_string()),
        key_negotiation_pq_certificate_sha256: Some(pq_certificate_sha256.to_string()),
        minimum_key_negotiation_mode: minimum_mode,
        // Posed by the gateway, never inherited from the client: it is what
        // makes the handshake age a readable signal on an idle tunnel, and
        // the gateway cannot inspect a client's configuration to check it.
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    };
    config.peers.push(peer.clone());
    Ok(peer)
}

/// Removes a peer from admission and returns it.
pub fn revoke(config: &mut NetworkConfig, name: &str) -> Result<WgPeer, AdmissionError> {
    let name = name.trim();
    let index = config
        .peers
        .iter()
        .position(|peer| peer.name.trim() == name)
        .ok_or_else(|| AdmissionError::Unknown(name.to_string()))?;
    Ok(config.peers.remove(index))
}

/// VIP table backed by the **declared** configuration.
///
/// Provisioning, meanwhile, queries the kernel's **live** table: the two
/// views deliberately coexist. This one is used to choose an address at
/// admission time, when no tunnel exists yet.
struct DeclaredPeers {
    /// `(VIP, owner)`. `None` designates a reserved address that no peer can
    /// claim — the gateway's own address.
    entries: Vec<(Ipv4Addr, Option<Vec<u8>>)>,
}

impl DeclaredPeers {
    fn new(config: &NetworkConfig) -> Self {
        let mut entries = Vec::with_capacity(config.peers.len() + 1);
        if let Some(addr) = host_of(&config.wg_address) {
            entries.push((addr, None));
        }
        for peer in &config.peers {
            // An unreadable address cannot collide with a derived VIP: it is
            // ignored rather than blocking every admission over a malformed
            // legacy entry.
            if let Some(addr) = host_of(&peer.address) {
                entries.push((addr, Some(decode_key(peer.public_key.trim()))));
            }
        }
        Self { entries }
    }
}

impl PeerTable for DeclaredPeers {
    fn is_taken_by_other(&self, addr: Ipv4Addr, pubkey: &[u8]) -> bool {
        self.entries.iter().any(|(taken, owner)| {
            *taken == addr
                && match owner {
                    Some(owner) => owner != pubkey,
                    None => true,
                }
        })
    }
}

/// Host part of a CIDR address (`100.64.1.2/32` → `100.64.1.2`).
fn host_of(cidr: &str) -> Option<Ipv4Addr> {
    cidr.trim().split('/').next()?.parse().ok()
}

/// Raw bytes of a base64 public key, empty if it is unreadable.
///
/// The IPAM derives the VIP from the bytes, never from the encoding. An
/// unreadable key cannot reach here via [`admit`], which validates first;
/// the case only remains for entries inherited from a manual edit of
/// `network.toml`.
fn decode_key(public_key: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(public_key.trim())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::derive_cgnat_ip;

    fn key(seed: u8) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    fn config() -> NetworkConfig {
        NetworkConfig {
            wg_address: "100.64.0.1/10".into(),
            ..NetworkConfig::default()
        }
    }

    /// A v5-conforming admission, so the tests below stay about what they were
    /// written for — VIP assignment, duplicates, name and key validation —
    /// instead of restating the identity requirements at every call.
    fn admit(
        config: &mut NetworkConfig,
        name: &str,
        public_key: &str,
        admin: bool,
    ) -> Result<WgPeer, AdmissionError> {
        admit_with_key_negotiation(
            config,
            name,
            public_key,
            admin,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            ProtectionMode::MlKem,
        )
    }

    #[test]
    fn admission_assigns_a_32_vip_within_the_cgnat() {
        let mut config = config();
        let peer = admit(&mut config, "workstation", &key(1), false).expect("admission");

        assert!(peer.address.ends_with("/32"), "address: {}", peer.address);
        let addr = host_of(&peer.address).expect("readable address");
        assert_eq!(addr.octets()[0], 100);
        assert!((64..=127).contains(&addr.octets()[1]));
        assert_eq!(config.peers.len(), 1);
        assert!(!peer.admin);
        assert!(
            peer.preshared_key.is_none(),
            "admission does not install a PSK"
        );
    }

    #[test]
    fn admission_binds_both_canonical_certificate_fingerprints() {
        let mut config = config();
        let peer = admit(&mut config, "workstation", &key(1), false).expect("admission");

        assert_eq!(
            peer.key_negotiation_certificate_sha256.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(
            peer.key_negotiation_pq_certificate_sha256.as_deref(),
            Some("b".repeat(64).as_str())
        );
    }

    #[test]
    fn invalid_certificate_fingerprint_is_refused_before_any_write() {
        let mut config = config();
        assert!(matches!(
            admit_with_key_negotiation(
                &mut config,
                "workstation",
                &key(1),
                false,
                Some("AABB"),
                Some(&"b".repeat(64)),
                ProtectionMode::MlKem,
            ),
            Err(AdmissionError::CertificateFingerprint)
        ));
        assert!(config.peers.is_empty());
    }

    /// Le défaut v4 — pas de certificat, donc `classic` — produisait des pairs
    /// dont le premier handshake était nu sans que rien ne les distingue.
    #[test]
    fn an_admission_without_a_pq_identity_is_refused() {
        let mut config = config();
        for (tls, pq) in [
            (None, None),
            (Some("a".repeat(64)), None),
            (None, Some("b".repeat(64))),
        ] {
            assert!(matches!(
                admit_with_key_negotiation(
                    &mut config,
                    "workstation",
                    &key(1),
                    false,
                    tls.as_deref(),
                    pq.as_deref(),
                    ProtectionMode::MlKem,
                ),
                Err(AdmissionError::MissingNegotiationIdentity)
            ));
        }
        assert!(config.peers.is_empty());
    }

    /// Un plancher plus faible reste atteignable, mais seulement en éditant
    /// `network.toml` — jamais par un défaut d'admission.
    #[test]
    fn an_admission_below_the_ml_kem_floor_is_refused() {
        let mut config = config();
        for weaker in [ProtectionMode::Classic, ProtectionMode::StaticPsk] {
            assert!(matches!(
                admit_with_key_negotiation(
                    &mut config,
                    "workstation",
                    &key(1),
                    false,
                    Some(&"a".repeat(64)),
                    Some(&"b".repeat(64)),
                    weaker,
                ),
                Err(AdmissionError::FloorBelowMlKem(_))
            ));
        }
        assert!(config.peers.is_empty());
    }

    /// La gateway pose le keep-alive elle-même : sans lui, ni la récupération
    /// de slot ni la renégociation client ne se déclenchent jamais.
    #[test]
    fn admission_poses_the_gateway_keep_alive() {
        let mut config = config();
        let peer = admit(&mut config, "workstation", &key(1), false).expect("admission");
        assert_eq!(
            peer.persistent_keepalive_secs,
            aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS
        );
        assert_ne!(peer.persistent_keepalive_secs, 0);
        config.validate_peer_identities().expect("pair conforme");

        config.peers[0].persistent_keepalive_secs = 0;
        assert!(
            config.validate_peer_identities().is_err(),
            "un pair négocié sans keep-alive doit être refusé au chargement"
        );
    }

    /// The point of going through the IPAM: the gateway and the client
    /// derive the same address, so enrollment does not contradict admission.
    #[test]
    fn the_admitted_vip_is_the_one_provisioning_derives() {
        let mut config = config();
        let peer = admit(&mut config, "workstation", &key(7), false).expect("admission");
        assert_eq!(
            host_of(&peer.address).expect("readable address"),
            derive_cgnat_ip(&[7u8; 32], 0)
        );
    }

    #[test]
    fn two_peers_receive_two_vips() {
        let mut config = config();
        let a = admit(&mut config, "a", &key(1), false).expect("admission a");
        let b = admit(&mut config, "b", &key(2), false).expect("admission b");
        assert_ne!(a.address, b.address);
    }

    #[test]
    fn the_same_public_key_is_refused() {
        let mut config = config();
        admit(&mut config, "first", &key(3), false).expect("admission");
        let refusal = admit(&mut config, "second", &key(3), false);
        assert!(matches!(refusal, Err(AdmissionError::KeyTaken(name)) if name == "first"));
        assert_eq!(
            config.peers.len(),
            1,
            "a refusal does not modify the config"
        );
    }

    #[test]
    fn the_same_name_is_refused() {
        let mut config = config();
        admit(&mut config, "workstation", &key(4), false).expect("admission");
        assert!(matches!(
            admit(&mut config, " workstation ", &key(5), false),
            Err(AdmissionError::NameTaken(_))
        ));
    }

    #[test]
    fn an_invalid_key_is_refused_before_any_write() {
        let mut config = config();
        assert!(matches!(
            admit(&mut config, "workstation", "not-a-key", false),
            Err(AdmissionError::Key(_))
        ));
        assert!(matches!(
            admit(&mut config, "workstation", "", false),
            Err(AdmissionError::Key(_))
        ));
        assert!(config.peers.is_empty());
    }

    #[test]
    fn an_empty_name_is_refused() {
        let mut config = config();
        assert!(matches!(
            admit(&mut config, "   ", &key(1), false),
            Err(AdmissionError::EmptyName)
        ));
    }

    /// The gateway's address is reserved: taking it away would cut the
    /// control plane, i.e. the only channel that would allow repairing it.
    #[test]
    fn the_gateways_vip_is_never_assigned() {
        let target = derive_cgnat_ip(&[9u8; 32], 0);
        let mut config = NetworkConfig {
            wg_address: format!("{target}/10"),
            ..NetworkConfig::default()
        };
        let peer = admit(&mut config, "workstation", &key(9), false).expect("admission");
        assert_ne!(
            host_of(&peer.address).expect("readable address"),
            target,
            "the gateway's VIP was reassigned"
        );
    }

    /// The ADR-004 §4 trap: adding a peer must not touch other peers'
    /// secrets, or every one of their handshakes would break.
    #[test]
    fn admission_preserves_the_psk_of_other_peers() {
        let mut config = config();
        admit(&mut config, "old", &key(1), true).expect("admission");
        config.peers[0].preshared_key = Some("existing-psk".into());

        admit(&mut config, "new", &key(2), false).expect("admission");

        assert_eq!(
            config.peers[0].preshared_key.as_deref(),
            Some("existing-psk")
        );
        assert!(config.peers[0].admin, "the admin role is preserved");
    }

    #[test]
    fn revocation_removes_the_named_peer() {
        let mut config = config();
        admit(&mut config, "a", &key(1), false).expect("admission");
        admit(&mut config, "b", &key(2), false).expect("admission");

        let removed = revoke(&mut config, "a").expect("revocation");
        assert_eq!(removed.name, "a");
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].name, "b");
    }

    #[test]
    fn revoking_an_unknown_peer_fails_without_changing_anything() {
        let mut config = config();
        admit(&mut config, "a", &key(1), false).expect("admission");
        assert!(matches!(
            revoke(&mut config, "ghost"),
            Err(AdmissionError::Unknown(_))
        ));
        assert_eq!(config.peers.len(), 1);
    }

    /// A freed VIP must be reclaimable by the same peer: since derivation is
    /// deterministic, readmitting yields the same address.
    #[test]
    fn readmitting_after_revocation_yields_the_same_vip() {
        let mut config = config();
        let before = admit(&mut config, "a", &key(1), false).expect("admission");
        revoke(&mut config, "a").expect("revocation");
        let after = admit(&mut config, "a", &key(1), false).expect("re-admission");
        assert_eq!(before.address, after.address);
    }
}
