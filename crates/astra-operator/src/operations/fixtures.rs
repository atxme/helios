//! Fixtures shared by the ceremonies' tests: a finished domain with three simulated
//! keys, a pinned service key, and the campaign requests Astra would sign.
//!
//! Only the CTAP2 boundary is simulated, and the tunnel's answers are scripted by
//! each test's own remote. Every signature and the vault are the production code.

use std::cell::Cell;
#[cfg(test)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aether::certificates::approval::{AstraIssuancePolicy, CredentialRegistry};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
    MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::status::{
    AstraRotationCampaign, AstraSignerRequest, CampaignScope, CampaignTarget, CertificateKind,
};
use aether::certificates::transport::OperatorAuthorityStatus;
use aether::certificates::webauthn::WebAuthnAssertion;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use zeroize::Zeroizing;

use crate::authenticator::{
    Approval, ApprovedOpening, Authenticator, AuthenticatorError, CredentialSubject, Opened,
    Registration,
};
use crate::gestures::{NewAuthority, NewKey};
use crate::origin::CampaignRequest;
#[cfg(test)]
use crate::rotation_journal::{self, RotationJournal};
use crate::vault::{SlotRole, SlotSecret};
use crate::vault_gestures::{add_key_with, create_first_key, finalize_with};
use crate::{credentials, handoff};

pub const NOW: u64 = 1_800_000_000;
pub const EXPIRES: u64 = NOW + 300;
pub(crate) const RP_ID: &str = "astra.helios.test";
pub(crate) const ORIGIN: &str = "https://astra.helios.test";
pub(crate) const AUTHORITY_URL: &str = "https://astra.helios.test/";
pub(crate) const SERVER_NAME: &str = "gateway.helios.test";
pub const OPERATION: [u8; 16] = [0x0B; 16];

pub fn operation() -> Id16 {
    Id16::new(OPERATION).expect("operation")
}

/// One simulated security key, holding one credential.
///
/// `derive` answers `hmac-secret` in shape and `approve` signs a real assertion.
/// A key that ignores the allow-list stands for what Windows WebAuthn does: the
/// key present answers, whichever was asked for.
pub struct TestKey {
    pub serial: u8,
    pub registered: Cell<bool>,
    pub touches: Cell<u32>,
    pub(crate) ignores_allow_list: Cell<bool>,
    pub declines: Cell<bool>,
}

impl TestKey {
    pub fn new(serial: u8) -> Self {
        Self {
            serial,
            registered: Cell::new(false),
            touches: Cell::new(0),
            ignores_allow_list: Cell::new(false),
            declines: Cell::new(false),
        }
    }

    pub fn credential_id(&self) -> Vec<u8> {
        vec![self.serial; 64]
    }

    pub(crate) fn signing_key(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[self.serial ^ 0x5A; 32]).expect("seed")
    }

    /// What a token does with an allow-list, and the one thing `declines` stops.
    pub(crate) fn answer(&self, credentials: &[Vec<u8>]) -> Result<Vec<u8>, AuthenticatorError> {
        if self.declines.get() {
            return Err(AuthenticatorError::Device("geste annulé".into()));
        }
        let own = self.credential_id();
        if !self.registered.get() || !(self.ignores_allow_list.get() || credentials.contains(&own))
        {
            return Err(AuthenticatorError::UnknownCredential);
        }
        self.touches.set(self.touches.get() + 1);
        Ok(own)
    }
}

impl Authenticator for TestKey {
    fn register(
        &self,
        _rp_id: &str,
        _subject: &CredentialSubject,
        _exclude: &[Vec<u8>],
        _pin: &str,
    ) -> Result<Registration, AuthenticatorError> {
        self.registered.set(true);
        let mut cose = vec![0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        cose.extend_from_slice(self.signing_key().public_key().as_ref());
        Ok(Registration {
            credential_id: self.credential_id(),
            credential_public_key: cose,
            aaguid: [0; 16],
        })
    }

    fn derive(
        &self,
        _rp_id: &str,
        credentials: &[Vec<u8>],
        salt: &[u8; 32],
        _pin: &str,
    ) -> Result<Opened, AuthenticatorError> {
        let credential_id = self.answer(credentials)?;
        let mut output = *salt;
        output.iter_mut().for_each(|byte| *byte ^= self.serial);
        Ok(Opened {
            credential_id,
            secret: SlotSecret::new(output.to_vec()),
        })
    }

    fn approve(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        _pin: &str,
    ) -> Result<Approval, AuthenticatorError> {
        let credential_id = self.answer(credentials)?;
        let digest = |bytes: &[u8]| {
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
                .as_ref()
                .to_vec()
        };
        let mut authenticator_data = digest(rp_id.as_bytes());
        // User presence and user verification, then a sign count.
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&digest(client_data_json));
        Ok(Approval {
            credential_id,
            assertion: WebAuthnAssertion {
                authenticator_data,
                client_data_json: client_data_json.to_vec(),
                signature: self.signing_key().sign(&message).as_ref().to_vec(),
            },
        })
    }

    fn approve_and_derive(
        &self,
        _rp_id: &str,
        _credentials: &[Vec<u8>],
        _client_data_json: &[u8],
        _salt: &[u8; 32],
        _pin: &str,
    ) -> Result<ApprovedOpening, AuthenticatorError> {
        unreachable!("a rotation takes its two gestures apart")
    }
}

/// A finished domain with three enrolled keys and a pinned service key.
pub struct Domain {
    pub(crate) _directory: tempfile::TempDir,
    pub path: PathBuf,
    pub keys: [TestKey; 3],
    pub(crate) service_key: Zeroizing<Vec<u8>>,
}

pub fn trust_domain() -> TrustDomainId {
    TrustDomainId::new([0x2A; 16]).expect("domain")
}

pub fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x11; 32])
}

pub fn domain() -> Domain {
    let directory = tempfile::tempdir().expect("dir");
    let path = directory.path().join("authority-vault.json");
    let keys = [TestKey::new(1), TestKey::new(2), TestKey::new(3)];
    let first = create_first_key(
        &path,
        &NewAuthority {
            rp_id: RP_ID.into(),
            trust_domain_id: trust_domain(),
            label: "Clé 1".into(),
            role: SlotRole::Primary,
        },
        AUTHORITY_URL,
        &keys[0],
        "",
        NOW,
    )
    .expect("the domain is created");
    for (key, label) in [(&keys[1], "Clé 2"), (&keys[2], "Clé 3")] {
        let request = NewKey {
            label: label.into(),
            role: SlotRole::Recovery,
        };
        add_key_with(&path, &first, key, &request, "", NOW).expect("key added");
    }
    let (service_key, service_public) = generate_ml_dsa_87_keypair().expect("service key");
    let relay_path = handoff::path_beside(&path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key = Some(gateway_key().to_base64());
    relay.server_name = Some(SERVER_NAME.into());
    relay.astra_service_public_key = Some(service_public.to_base64());
    relay.astra_service_key_epoch = Some(1);
    handoff::save(&relay_path, &relay).expect("relay saved");
    finalize_with(&path, &first, NOW).expect("the domain is finished");
    keys.iter().for_each(|key| key.touches.set(0));
    Domain {
        _directory: directory,
        path,
        keys,
        service_key,
    }
}

impl Domain {
    pub fn relay(&self) -> handoff::DomainHandoff {
        handoff::load(&handoff::path_beside(&self.path)).expect("relay")
    }

    pub fn registry(&self) -> CredentialRegistry {
        credentials::load(&credentials::path_beside(&self.path))
            .expect("document")
            .expect("present")
    }

    pub fn touches(&self) -> u32 {
        self.keys.iter().map(|key| key.touches.get()).sum()
    }

    /// Every file of the directory, to tell that nothing was written.
    #[cfg(test)]
    pub(crate) fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        std::fs::read_dir(self.path.parent().expect("parent"))
            .expect("listing")
            .map(|entry| {
                let path = entry.expect("entry").path();
                let bytes = std::fs::read(&path).expect("file");
                (path, bytes)
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn journal_on_disk(&self) -> Option<RotationJournal> {
        rotation_journal::load(&rotation_journal::path_beside(&self.path)).expect("journal")
    }

    /// The campaign the door resolves for `trust_authorities`: one row per
    /// anchor, each naming what the domain holds now.
    pub fn authority_campaign(&self, expires_at: u64) -> AstraRotationCampaign {
        let relay = self.relay();
        let identity = handoff::identity_of(&relay).expect("identity");
        let anchor = MlDsa87PublicKey::parse(relay.ca_pq_public_key.trim())
            .expect("anchor")
            .authority_fingerprint();
        let client_tls = DerCertificate::parse(relay.ca_tls_certificate.as_ref().expect("CA-TLS"))
            .expect("certificate")
            .fingerprint();
        let row = |certificate_kind, epoch, fingerprint| CampaignTarget {
            certificate_kind,
            identity_key: gateway_key(),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: fingerprint,
            active_pq_certificate_fingerprint: fingerprint,
        };
        self.campaign(
            CampaignScope::TrustAuthorities,
            vec![
                row(CertificateKind::CaPq, identity.ca_epoch, anchor),
                row(CertificateKind::CaTls, identity.ca_tls_epoch, client_tls),
            ],
            expires_at,
        )
    }

    pub fn campaign(
        &self,
        scope: CampaignScope,
        targets: Vec<CampaignTarget>,
        expires_at: u64,
    ) -> AstraRotationCampaign {
        AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([9; 16]).expect("id"),
            trust_domain_id: trust_domain(),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            created_at: NOW,
            expires_at,
            scope,
            targets,
            reason: "remplacement".into(),
            requested_by: "opératrice".into(),
            policy_fingerprint: AstraIssuancePolicy::standard(
                trust_domain(),
                gateway_key(),
                SERVER_NAME.into(),
            )
            .fingerprint()
            .expect("policy"),
            required_credentials: scope.required_credentials(),
        }
    }

    pub fn request(&self, campaign: AstraRotationCampaign) -> CampaignRequest {
        let signer_request = AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: operation(),
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: self.relay().astra_authority_url.expect("origin"),
            encrypted_vault_fingerprint: Fingerprint::of(b"vault"),
            required_credentials: campaign.required_credentials,
            created_at: NOW,
            expires_at: campaign.expires_at,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&self.service_key)
        .expect("signed request");
        CampaignRequest {
            operation_id: operation(),
            signer_request: Box::new(signer_request),
            campaign: Box::new(campaign),
            webauthn_rp_id: RP_ID.into(),
            webauthn_origin: ORIGIN.into(),
            result_token: "jeton-de-depot".into(),
            vault_token: None,
        }
    }
}

/// What Astra says of a domain in step with the vault at `vault_path`.
pub fn nothing_in_flight(vault_path: &Path) -> OperatorAuthorityStatus {
    let relay = handoff::load(&handoff::path_beside(vault_path)).expect("relay");
    let identity = handoff::identity_of(&relay).expect("identity");
    let anchor = MlDsa87PublicKey::parse(relay.ca_pq_public_key.trim()).expect("anchor");
    let client_tls = DerCertificate::parse(relay.ca_tls_certificate.as_ref().expect("CA-TLS"))
        .expect("certificate");
    OperatorAuthorityStatus {
        ca_epoch: identity.ca_epoch,
        ca_fingerprint: anchor.authority_fingerprint(),
        next_ca_fingerprint: None,
        ca_tls_epoch: identity.ca_tls_epoch,
        ca_tls_fingerprint: Some(client_tls.fingerprint()),
        next_ca_tls_fingerprint: None,
        issuer: None,
        vault_copy_fingerprint: None,
        credential_registry_epoch: None,
        revoked_peers: Vec::new(),
        served_credentials: None,
    }
}
