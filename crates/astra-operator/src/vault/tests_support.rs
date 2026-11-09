use super::*;

pub const RP_ID: &str = "astra.example";

pub fn secrets() -> AuthoritySecrets {
    AuthoritySecrets {
        ca_pq_private_key: "Y2EtcHEtcHJpdmF0ZQ==".into(),
        ca_pq_public_key: "Y2EtcHEtcHVibGlj".into(),
        ca_tls_private_key: "Y2EtdGxzLXByaXZhdGU=".into(),
        retained_ca_tls: None,
        retained_outgoing_ca_pq: None,
    }
}

pub fn domain() -> TrustDomainId {
    TrustDomainId::new([3; 16]).expect("domain")
}

pub fn credential(seed: u8) -> Vec<u8> {
    vec![seed; 64]
}

pub fn enrolment(role: SlotRole, seed: u8) -> SlotEnrolment {
    SlotEnrolment {
        role,
        label: format!("clé {seed}"),
        credential_id: credential(seed),
        credential_public_key: vec![0xa5, seed],
        aaguid: [seed; 16],
        enrolled_at: 2_000,
    }
}

pub fn material(seed: u8) -> SlotSecret {
    SlotSecret::new(vec![seed; 32])
}

pub fn vault() -> AuthorityVault {
    AuthorityVault::create(
        domain(),
        RP_ID,
        draw_salt().expect("salt"),
        &secrets(),
        enrolment(SlotRole::Primary, 1),
        &material(1),
        1_000,
    )
    .expect("create")
}
