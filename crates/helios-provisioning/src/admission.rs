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
//! * the VIPs come from the IPAM, not from a human choice — in WireGuard,
//!   `AllowedIPs` **is** the cryptographic routing table, two peers cannot
//!   claim the same address. Admission is the IPAM's only caller, and what it
//!   writes to `network.toml` is the peer's address from then on
//!   (`ADRESSAGE-IPV6.md` §3 bis.2);
//! * the gateway's address is reserved: assigning it would cut the control
//!   plane, i.e. the only channel that would allow fixing the mistake;
//! * a public key already admitted under another name is a duplicate, not a
//!   second peer: WireGuard indexes its peers by public key and the second
//!   one would silently overwrite the first.
//!
//! # Readmission
//!
//! Admitting again the same name, key and identity is not a conflict: it
//! returns the addresses the peer already has. The one thing it may add is
//! the IPv6 VIP of a peer admitted before the gateway had a tunnel prefix —
//! the only way such a peer gets one besides an explicit declaration
//! (§5.3). Its IPv4 VIP is never touched.
//!
//! # What admission does not do
//!
//! It installs no PSK: that one is derived at enrollment ([`crate::session`])
//! and has no value beforehand. It does not revoke anything cryptographically
//! either — removing a peer makes it drop at its next handshake attempt,
//! with no revocation list (ADR-004).

use aether::key_negotiation::ProtectionMode;
use aether::net::AddressError;
use aether::{wg, NetworkConfig, WgPeer};

use crate::ipam::{decode_key, AddressView, LivePeer};

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
    #[error(
        "« {0} » is already admitted with this key, but with another role, certificate or \
         floor; revoke it first to change them"
    )]
    ReadmissionDiffers(String),
    #[error("« {name} » is admitted without a readable address: {source}")]
    UndeclaredAddress { name: String, source: AddressError },
    #[error("no peer named « {0} »")]
    Unknown(String),
    #[error("VIP assignment impossible: {0}")]
    Ipam(#[from] crate::ipam::IpamError),
    #[error("certificate fingerprint must be 64 lowercase SHA-256 hexadecimal characters")]
    CertificateFingerprint,
    #[error(
        "admission requires both the TLS and the PQ key-negotiation certificate; a peer \
         without them would negotiate nothing and is not admitted"
    )]
    MissingNegotiationIdentity,
    #[error(
        "admission floor must be `ml_kem`, not `{0:?}`; a weaker floor is only reachable \
         by editing network.toml locally"
    )]
    FloorBelowMlKem(ProtectionMode),
}

/// What an admission did to the peer table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// A new peer, declared with VIPs fresh from the IPAM.
    Admitted,
    /// The same identity was already admitted: nothing changed, and the
    /// peer keeps the addresses it was admitted with.
    Unchanged,
    /// The same identity was already admitted, before the gateway had an
    /// IPv6 tunnel prefix: its IPv6 VIP was allocated and declared, its IPv4
    /// VIP left as it was.
    Ipv6Added,
}

/// A successful admission.
#[derive(Debug)]
pub struct Admission {
    /// The peer as declared. Never carries a PSK: admission neither creates
    /// one nor hands out the one a readmitted peer may hold.
    pub peer: WgPeer,
    pub outcome: AdmissionOutcome,
}

impl Admission {
    /// Whether the configuration changed and must be persisted.
    pub fn changed_config(&self) -> bool {
        self.outcome != AdmissionOutcome::Unchanged
    }
}

/// Admits a peer with both transport and PQ identity bindings.
///
/// `live` is the WireGuard table as the data plane last reported it, the
/// one input of the collision view the file does not give (see
/// [`LivePeer`]). A caller with no data plane passes `&[]`: the declared
/// peers are always in the view.
///
/// The configuration is only modified on success: a refusal leaves `config`
/// intact, which lets the caller persist it unconditionally after an `Ok`
/// whose [`Admission::changed_config`] holds.
///
/// The v4 shims that admitted a peer without a certificate, or with only the
/// TLS one, are gone rather than deprecated. Under v5 rules they could only
/// ever return [`AdmissionError::MissingNegotiationIdentity`], and a function
/// whose every call fails is worse than no function.
#[allow(clippy::too_many_arguments)]
pub fn admit_with_key_negotiation(
    config: &mut NetworkConfig,
    live: &[LivePeer<'_>],
    name: &str,
    public_key: &str,
    admin: bool,
    certificate_sha256: Option<&str>,
    pq_certificate_sha256: Option<&str>,
    minimum_mode: ProtectionMode,
) -> Result<Admission, AdmissionError> {
    let name = name.trim();
    let public_key = public_key.trim();
    let certificate_sha256 = certificate_sha256.map(str::trim);
    let pq_certificate_sha256 = pq_certificate_sha256.map(str::trim);

    if name.is_empty() {
        return Err(AdmissionError::EmptyName);
    }
    wg::validate_key(public_key)?;
    // v5 admits no peer without both identities, and every admission lands on
    // the `ml_kem` floor. The v4 default — no certificate, therefore no
    // negotiation — is gone: it produced peers whose first handshake was
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

    let raw = decode_key(public_key);
    let view = AddressView::new(config, live);

    if let Some(index) = config
        .peers
        .iter()
        .position(|peer| peer.name.trim() == name)
    {
        let existing = &config.peers[index];
        if existing.public_key.trim() != public_key {
            return Err(AdmissionError::NameTaken(existing.name.clone()));
        }
        let same_identity = existing.admin == admin
            && existing
                .key_negotiation_certificate_sha256
                .as_deref()
                .map(str::trim)
                == Some(certificate_sha256)
            && existing
                .key_negotiation_pq_certificate_sha256
                .as_deref()
                .map(str::trim)
                == Some(pq_certificate_sha256)
            && existing.minimum_key_negotiation_mode == Some(minimum_mode);
        if !same_identity {
            return Err(AdmissionError::ReadmissionDiffers(existing.name.clone()));
        }
        // The declaration is the peer's address: read back, never derived
        // again (§3 bis.2, rule 3). Only a missing family is allocated.
        let declared = existing
            .vips()
            .map_err(|source| AdmissionError::UndeclaredAddress {
                name: existing.name.clone(),
                source,
            })?;
        let vips = view.assign(&raw, Some(declared))?;
        let outcome = if vips == declared {
            AdmissionOutcome::Unchanged
        } else {
            AdmissionOutcome::Ipv6Added
        };
        let peer = &mut config.peers[index];
        peer.address_v6 = vips.v6;
        return Ok(Admission {
            peer: declared_copy(peer),
            outcome,
        });
    }
    if let Some(existing) = config
        .peers
        .iter()
        .find(|peer| peer.public_key.trim() == public_key)
    {
        return Err(AdmissionError::KeyTaken(existing.name.clone()));
    }

    let vips = view.assign(&raw, None)?;

    let peer = WgPeer {
        name: name.to_string(),
        public_key: public_key.to_string(),
        address: vips.address(),
        // `None` on a gateway without `wg_address_v6`: the peer, and the file
        // written from it, are then exactly what they were before IPv6.
        address_v6: vips.v6,
        admin,
        // The PSK is born from the ML-KEM exchange, not from admission.
        // Setting it here would amount to inventing a secret no client
        // knows, and a PSK slot filled on only one side breaks every
        // handshake of the peer.
        preshared_key: None,
        key_negotiation_certificate_sha256: Some(certificate_sha256.to_string()),
        key_negotiation_pq_certificate_sha256: Some(pq_certificate_sha256.to_string()),
        minimum_key_negotiation_mode: Some(minimum_mode),
        // Posed by the gateway, never inherited from the client: it is what
        // makes the handshake age a readable signal on an idle tunnel, and
        // the gateway cannot inspect a client's configuration to check it.
        persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
    };
    let admitted = declared_copy(&peer);
    config.peers.push(peer);
    Ok(Admission {
        peer: admitted,
        outcome: AdmissionOutcome::Admitted,
    })
}

/// The peer as declared, minus its PSK.
///
/// Written out rather than [`WgPeer::duplicate`]: a readmitted peer may hold
/// a negotiated PSK, and the caller has no use for a copy of it.
fn declared_copy(peer: &WgPeer) -> WgPeer {
    WgPeer {
        name: peer.name.clone(),
        public_key: peer.public_key.clone(),
        address: peer.address.clone(),
        address_v6: peer.address_v6,
        admin: peer.admin,
        preshared_key: None,
        key_negotiation_certificate_sha256: peer.key_negotiation_certificate_sha256.clone(),
        key_negotiation_pq_certificate_sha256: peer.key_negotiation_pq_certificate_sha256.clone(),
        minimum_key_negotiation_mode: peer.minimum_key_negotiation_mode,
        persistent_keepalive_secs: peer.persistent_keepalive_secs,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::{derive_cgnat_ip, derive_ula_iid};
    use aether::net::{parse_vip_v4, PeerVips, TunnelPrefixV6};
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The prefix of the specification's own example (§5.1).
    const PREFIX: &str = "fd3c:91a2:7e04::1/64";

    fn prefix() -> TunnelPrefixV6 {
        PREFIX.parse().expect("the specification's example prefix")
    }

    fn vip6(iid: u64) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(prefix().network()) | u128::from(iid))
    }

    fn host_of(address: &str) -> Option<Ipv4Addr> {
        parse_vip_v4(address).ok()
    }

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
        admit_seeing(config, &[], name, public_key, admin).map(|admission| admission.peer)
    }

    /// The same admission, with a live WireGuard table and the whole outcome.
    fn admit_seeing(
        config: &mut NetworkConfig,
        live: &[LivePeer<'_>],
        name: &str,
        public_key: &str,
        admin: bool,
    ) -> Result<Admission, AdmissionError> {
        admit_with_key_negotiation(
            config,
            live,
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
                &[],
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

    /// Le défaut v4 — pas de certificat, donc aucune négociation — produisait des pairs
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
                    &[],
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
        assert!(matches!(
            admit_with_key_negotiation(
                &mut config,
                &[],
                "workstation",
                &key(1),
                false,
                Some(&"a".repeat(64)),
                Some(&"b".repeat(64)),
                ProtectionMode::StaticPsk,
            ),
            Err(AdmissionError::FloorBelowMlKem(_))
        ));
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

    /// With nothing in the way, the IPAM's choice is the key's natural VIP.
    #[test]
    fn the_admitted_vip_is_the_natural_one_when_nothing_collides() {
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
            config.peers[0]
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose),
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

    /// A gateway with a tunnel prefix gives a new peer both VIPs, from the
    /// one allocation point.
    #[test]
    fn admission_on_a_dual_stack_gateway_declares_both_vips() {
        let mut config = NetworkConfig {
            wg_address_v6: Some(prefix()),
            ..config()
        };
        let peer = admit(&mut config, "workstation", &key(7), false).expect("admission");

        assert_eq!(
            peer.vips().expect("declared VIPs"),
            PeerVips {
                v4: derive_cgnat_ip(&[7u8; 32], 0),
                v6: Some(vip6(derive_ula_iid(&[7u8; 32], 0))),
            }
        );
        assert_eq!(config.peers[0].address_v6, peer.address_v6);
        config
            .validate()
            .expect("what admission writes, the gateway loads");
    }

    /// The live table is part of the view: a peer the data plane still
    /// carries holds its address even when the file no longer declares it.
    #[test]
    fn admission_avoids_an_address_held_in_the_live_table() {
        let mut config = config();
        let allowed = vec![format!("{}/32", derive_cgnat_ip(&[7u8; 32], 0))];
        let live = [LivePeer {
            public_key: &[8u8; 32],
            allowed_ips: &allowed,
        }];
        let admission =
            admit_seeing(&mut config, &live, "workstation", &key(7), false).expect("admission");
        assert_eq!(
            host_of(&admission.peer.address),
            Some(derive_cgnat_ip(&[7u8; 32], 1))
        );
    }

    /// §9 criterion 11, the defect of §3 bis.1. A is declared but not
    /// connected, on B's natural VIP. B is admitted on a probed VIP — and its
    /// provisioning announces that very address, the one the gateway routes,
    /// where it used to re-derive against the live table and announce the
    /// natural one.
    #[test]
    fn provisioning_announces_the_vip_admission_chose_after_a_collision() {
        use aether::enroll::{ProvisionRequest, NONCE_LEN, PROTOCOL_VERSION};
        use aether::pq::{Kem, MlKem1024Kem};

        let natural_b = derive_cgnat_ip(&[2u8; 32], 0);
        let mut config = config();
        admit(&mut config, "a", &key(1), false).expect("admission of A");
        config.peers[0].address = format!("{natural_b}/32");
        config.validate().expect("A holds B's natural VIP");

        // No live table: A is offline, and B is not connected yet.
        let b = admit(&mut config, "b", &key(2), false).expect("admission of B");
        let probed_b = derive_cgnat_ip(&[2u8; 32], 1);
        assert_eq!(host_of(&b.address), Some(probed_b), "B avoids A, offline");

        let (_, kem_public_key) = MlKem1024Kem::generate().expect("ML-KEM pair");
        let request = ProvisionRequest {
            protocol_version: PROTOCOL_VERSION,
            client_wg_public_key: key(2),
            kem_public_key,
            client_nonce: [1; NONCE_LEN],
        };
        let identity = crate::session::GatewayIdentity {
            wg_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            psk_lifetime_secs: crate::session::DEFAULT_PSK_LIFETIME_SECS,
        };
        let provisioned =
            crate::session::handle_request(&request, &identity, &config, [2; NONCE_LEN])
                .expect("provisioning of B");

        assert_eq!(provisioned.response.assigned_address, b.address);
        assert_eq!(provisioned.vips.v4, probed_b);
        assert_eq!(
            provisioned.response.assigned_address, config.peers[1].address,
            "what the gateway installs — the declared address — is what it announces"
        );
    }

    /// §9 criterion 12: readmitting the same identity changes nothing and
    /// returns the same addresses.
    #[test]
    fn readmission_is_idempotent() {
        let mut config = config();
        let first =
            admit_seeing(&mut config, &[], "workstation", &key(1), true).expect("admission");
        assert_eq!(first.outcome, AdmissionOutcome::Admitted);
        assert!(first.changed_config());
        config.peers[0].preshared_key = Some("negotiated-psk".into());

        let again =
            admit_seeing(&mut config, &[], " workstation ", &key(1), true).expect("readmission");
        assert_eq!(again.outcome, AdmissionOutcome::Unchanged);
        assert!(!again.changed_config());
        assert_eq!(again.peer.address, first.peer.address);
        assert_eq!(again.peer.address_v6, None);
        assert!(
            again.peer.preshared_key.is_none(),
            "admission hands out no PSK, not even the one the peer holds"
        );
        assert_eq!(config.peers.len(), 1);
        assert_eq!(
            config.peers[0]
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose),
            Some("negotiated-psk"),
            "a readmission leaves the peer's PSK alone"
        );
    }

    /// §9 criterion 12, the family the gateway gained: the IPv6 VIP alone is
    /// allocated and declared, the IPv4 one stays as it was — even when it
    /// is not the natural one.
    #[test]
    fn readmission_after_the_gateway_gained_a_prefix_adds_only_the_ipv6_vip() {
        let mut config = config();
        admit(&mut config, "workstation", &key(1), false).expect("admission");
        let declared_v4 = "100.64.1.2/32";
        config.peers[0].address = declared_v4.into();

        config.wg_address_v6 = Some(prefix());
        let completed =
            admit_seeing(&mut config, &[], "workstation", &key(1), false).expect("readmission");
        assert_eq!(completed.outcome, AdmissionOutcome::Ipv6Added);
        assert!(completed.changed_config());
        assert_eq!(completed.peer.address, declared_v4, "IPv4 untouched");
        let v6 = Some(vip6(derive_ula_iid(&[1u8; 32], 0)));
        assert_eq!(completed.peer.address_v6, v6);
        assert_eq!(config.peers[0].address, declared_v4);
        assert_eq!(config.peers[0].address_v6, v6);
        config.validate().expect("the completed peer loads");

        let again = admit_seeing(&mut config, &[], "workstation", &key(1), false)
            .expect("second readmission");
        assert_eq!(again.outcome, AdmissionOutcome::Unchanged);
        assert_eq!(again.peer.address_v6, v6);
    }

    /// A readmission is the same identity, not an edit: another role, pin
    /// or floor under the same name and key is refused, and nothing moves.
    #[test]
    fn a_readmission_with_another_identity_is_refused() {
        let mut config = config();
        admit(&mut config, "workstation", &key(1), false).expect("admission");
        let before = config.peers[0].duplicate();

        assert!(matches!(
            admit(&mut config, "workstation", &key(1), true),
            Err(AdmissionError::ReadmissionDiffers(name)) if name == "workstation"
        ));
        assert!(matches!(
            admit_with_key_negotiation(
                &mut config,
                &[],
                "workstation",
                &key(1),
                false,
                Some(&"c".repeat(64)),
                Some(&"b".repeat(64)),
                ProtectionMode::MlKem,
            ),
            Err(AdmissionError::ReadmissionDiffers(_))
        ));
        assert_eq!(config.peers, vec![before]);
    }

    /// A peer whose declared address cannot be read is a named error: the
    /// IPAM is not asked to make one up.
    #[test]
    fn a_readmission_without_a_readable_address_is_refused() {
        let mut config = NetworkConfig {
            wg_address_v6: Some(prefix()),
            ..config()
        };
        admit(&mut config, "workstation", &key(1), false).expect("admission");
        config.peers[0].address = "100.64.1.2".into();

        assert!(matches!(
            admit(&mut config, "workstation", &key(1), false),
            Err(AdmissionError::UndeclaredAddress { name, .. }) if name == "workstation"
        ));
        assert_eq!(config.peers[0].address, "100.64.1.2");
    }

    /// A gateway without `wg_address_v6` writes, for an admitted peer,
    /// exactly what it wrote before IPv6: the production file of the
    /// configuration tests, plus one `[[peers]]` block of the old form.
    #[cfg(unix)]
    #[test]
    fn admission_without_ipv6_writes_the_same_file_as_before() {
        const FILE: &str =
            include_str!("../../aether/src/config/fixtures/network-production-without-ipv6.toml");
        static NETWORK_CONFIG_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = NETWORK_CONFIG_ENV
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "helios-provisioning-admission-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        let path = dir.join("network.toml");
        std::fs::write(&path, FILE).expect("seed network.toml");
        std::env::set_var("HELIOS_NETWORK_CONFIG", &path);

        let written = NetworkConfig::load().and_then(|mut config| {
            assert!(config.wg_address_v6.is_none());
            let admission =
                admit_seeing(&mut config, &[], "laptop", &key(7), false).expect("admission");
            assert_eq!(admission.peer.address_v6, None);
            config.save()
        });
        let rewritten = std::fs::read_to_string(&path);
        std::env::remove_var("HELIOS_NETWORK_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
        written.expect("load, admit, save");

        let expected = format!(
            "{FILE}\n[[peers]]\nname = \"laptop\"\npublic_key = \"{}\"\naddress = \"{}/32\"\n\
             admin = false\nkey_negotiation_certificate_sha256 = \"{}\"\n\
             key_negotiation_pq_certificate_sha256 = \"{}\"\n\
             minimum_key_negotiation_mode = \"ml_kem\"\npersistent_keepalive_secs = 25\n",
            key(7),
            derive_cgnat_ip(&[7u8; 32], 0),
            "a".repeat(64),
            "b".repeat(64),
        );
        assert_eq!(rewritten.expect("the written file"), expected);
    }
}
