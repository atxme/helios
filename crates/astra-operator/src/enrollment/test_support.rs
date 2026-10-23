//! Invitations and requests built from real keys, for the registry and the
//! signing gestures alike.

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey,
};
use aether::key_negotiation::{
    wireguard_proof, EnrollmentInvitation, EnrollmentRequest, ProtectionMode,
    ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION, MAX_INVITATION_LIFETIME_SECS,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::Zeroizing;

pub(crate) const NOW: u64 = 1_800_000_000;

pub(crate) struct Ca {
    pub(crate) private: Zeroizing<Vec<u8>>,
    pub(crate) public: MlDsa87PublicKey,
}

pub(crate) fn ca() -> Ca {
    let (private, public) = generate_ml_dsa_87_keypair().expect("ca keys");
    Ca { private, public }
}

pub(crate) struct WgKeys {
    pub(crate) private: Zeroizing<[u8; 32]>,
    pub(crate) public: WireGuardKey,
}

pub(crate) fn wg_keys() -> WgKeys {
    let keys = aether::wg::generate_keypair().expect("wg keys");
    let private: [u8; 32] = STANDARD
        .decode(keys.private_key.expose())
        .expect("base64")
        .try_into()
        .expect("32 bytes");
    WgKeys {
        private: Zeroizing::new(private),
        public: WireGuardKey::parse(&keys.public_key).expect("public"),
    }
}

/// A signed invitation and the private half of its proof key.
pub(crate) fn invitation(
    ca: &Ca,
    id: u8,
    allow_readmission: bool,
) -> (EnrollmentInvitation, Zeroizing<[u8; 32]>) {
    let proof = wg_keys();
    let invitation = EnrollmentInvitation {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: Id16::new([id; 16]).expect("id"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        gateway_certificate_fingerprint: Fingerprint::from_bytes([4; 32]),
        server_name: "vpn.example.net".into(),
        operator_ca_public_key: ca.public.clone(),
        wireguard_proof_public_key: proof.public,
        not_before_unix: NOW - 60,
        not_after_unix: NOW - 60 + MAX_INVITATION_LIFETIME_SECS,
        minimum_mode: ProtectionMode::MlKem,
        allow_readmission,
        operator_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca.private)
    .expect("signed invitation");
    (invitation, proof.private)
}

/// The client's side of an enrollment: its keys and the request they sign.
pub(crate) struct ClientSide {
    pub(crate) wg: WgKeys,
    pub(crate) request: EnrollmentRequest,
}

pub(crate) fn request(invitation: &EnrollmentInvitation, name: &str) -> ClientSide {
    request_with(invitation, name, wg_keys())
}

/// A request for an existing WireGuard key — the readmission case.
pub(crate) fn request_with(
    invitation: &EnrollmentInvitation,
    name: &str,
    wg: WgKeys,
) -> ClientSide {
    let (ml_dsa_private, ml_dsa_public) = generate_ml_dsa_87_keypair().expect("ml-dsa");
    let csr = aether::certificates::x509::client_rotation_csr(name).expect("csr");
    let mut request = EnrollmentRequest {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: invitation.invitation_id,
        invitation_fingerprint: invitation.fingerprint(),
        request_id: Id16::new(aether::random::public_bytes().expect("random")).expect("id"),
        timestamp_unix: NOW,
        requested_name: name.into(),
        client_wg_public_key: wg.public,
        tls_csr: csr.csr,
        client_ml_dsa_87_public_key: ml_dsa_public,
        wireguard_proof: [0; 32],
        client_signature: MlDsa87Signature::placeholder(),
    };
    request.wireguard_proof = wireguard_proof(&wg.private, invitation, &request).expect("proof");
    let request = request.sign(&ml_dsa_private).expect("signed request");
    ClientSide { wg, request }
}
