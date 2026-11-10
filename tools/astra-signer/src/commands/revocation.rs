//! Signing an emergency revocation.

use super::*;

/// What the operator decides about a revocation, and the authority does not.
pub(crate) struct RevocationInputs {
    pub(crate) scope: aether::certificates::revocation::RevocationScope,
    pub(crate) halves: RevokedHalvesArg,
    /// Signed expiry of each half. Absent means that half is not named.
    pub(crate) tls_not_after: Option<u64>,
    pub(crate) pq_not_after: Option<u64>,
    pub(crate) reason: aether::certificates::revocation::RevocationReason,
    /// The signed replacement transition this revocation names, if any.
    pub(crate) replacement: Option<std::path::PathBuf>,
}

/// Signs and deposits the revocation frozen into an Astra campaign (§10).
pub(crate) fn revoke(
    path: &Path,
    authority_url: &str,
    operation_id: &str,
    origin: Option<&str>,
    inputs: RevocationInputs,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::revocation::RevocationScope;

    let RevocationInputs {
        scope,
        halves,
        tls_not_after,
        pq_not_after,
        reason,
        replacement,
    } = inputs;
    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let client = astra_operator::origin::Origin::new(authority_url)?;
    let request = origin_client_fetch(&client, &operation)?;
    handoff::verify_campaign_request(&handoff, &vault, &request, authority_url, now_unix())?;
    let campaign = request.campaign.as_ref().clone();
    if !campaign.scope.revokes() {
        bail!("cette opération n'est pas une révocation. Rien n'a été signé.");
    }
    if campaign.targets.len() != 1 {
        bail!(
            "une révocation doit nommer exactement une identité, {} présentes. Rien n'a été signé.",
            campaign.targets.len()
        );
    }
    let target = campaign
        .targets
        .first()
        .context("la campagne ne nomme aucune identité")?;
    let revocation_epoch = target
        .epoch
        .checked_add(1)
        .context("revocation counter overflow")?;
    let (revoke_tls, revoke_pq) = match halves {
        RevokedHalvesArg::Both => (true, true),
        RevokedHalvesArg::Tls => (true, false),
        RevokedHalvesArg::Pq => (false, true),
    };
    // Each named half carries its own signed expiry (§10.1). A missing one is
    // refused rather than defaulted: an expiry chosen here would be an expiry
    // no leaf actually carries, and every recipient would refuse the object.
    if revoke_tls && tls_not_after.is_none() {
        bail!("--tls-not-after (or --not-after) is required to withdraw the TLS leaf");
    }
    if revoke_pq && pq_not_after.is_none() {
        bail!("--pq-not-after (or --not-after) is required to withdraw the PQ leaf");
    }
    let now = now_unix();

    // Read from the signed document rather than typed on a command line: a
    // fingerprint an operator retypes is a fingerprint that can be retyped
    // wrong, and the failure would be a revoked gateway waiting forever for a
    // transition nobody can produce.
    let replacement_transition_fingerprint = match &replacement {
        None => None,
        Some(source) => {
            if scope != RevocationScope::Gateway {
                bail!(
                    "--replacement-transition ne vaut que pour --scope gateway : une identité \
                     cliente révoquée est réadmise, elle n'est pas remplacée par une transition."
                );
            }
            let transition: aether::certificates::gateway::GatewayIdentityTransition =
                read_json(source, "la transition de remplacement")?;
            if transition.reason
                != aether::certificates::authority::RotationReason::EmergencyReplacement
            {
                bail!(
                    "cette transition ne porte pas le motif emergency_replacement : une gateway \
                     révoquée n'accepte que celui-là (§6.1). Rien n'a été signé."
                );
            }
            if transition.gateway_wg_public_key != target.identity_key
                || transition.server_name != campaign.server_name
            {
                bail!(
                    "la transition de remplacement vise une autre gateway que celle que cette \
                     révocation retire. Rien n'a été signé."
                );
            }
            Some(transition.fingerprint()?)
        }
    };

    println!("révocation       : {}", operation.to_hex());
    println!("portée           : {scope:?}");
    println!("identité         : {}", target.identity_key.to_base64());
    println!("gateway          : {}", campaign.server_name);
    println!("génération       : {}", target.generation);
    println!("compteur         : {} → {revocation_epoch}", target.epoch);
    println!(
        "feuilles         : {}",
        match (revoke_tls, revoke_pq) {
            (true, true) => "TLS et PQ",
            (true, false) => "TLS",
            (false, true) => "PQ",
            (false, false) => unreachable!("the command always selects a half"),
        }
    );
    println!(
        "échéances signées: TLS {} · PQ {}",
        tls_not_after.map_or("—".to_string(), horodatage),
        pq_not_after.map_or("—".to_string(), horodatage)
    );
    println!("effet            : immédiat ({})", horodatage(now));
    println!("catégorie        : {reason:?}");
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "terminal         : {}",
        match (scope, replacement_transition_fingerprint) {
            (RevocationScope::Client, _) => "cette identité devra être réadmise".to_string(),
            (RevocationScope::Gateway, None) => "la gateway ne négociera plus ; aucune transition \
                                                 ne sera acceptée ensuite"
                .to_string(),
            (RevocationScope::Gateway, Some(fingerprint)) => format!(
                "la gateway ne négociera plus, sauf par la transition {fingerprint} — le seul \
                 document qu'elle acceptera ensuite"
            ),
        }
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let approval = signing::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let decision = signing::RevocationDecision {
        scope,
        identity_key: target.identity_key,
        // §10.1 names the service only for a gateway: a client leaf is
        // identified by its WireGuard key, and a name there would be a second
        // identifier nobody verifies.
        server_name: match scope {
            RevocationScope::Client => None,
            RevocationScope::Gateway => Some(campaign.server_name.clone()),
        },
        revocation_epoch,
        revoked_tls: revoke_tls
            .then(|| tls_not_after.map(|at| (target.active_tls_certificate_fingerprint, at)))
            .flatten(),
        revoked_pq: revoke_pq
            .then(|| pq_not_after.map(|at| (target.active_pq_certificate_fingerprint, at)))
            .flatten(),
        effective_at: now,
        reason,
        replacement_transition_fingerprint,
    };
    let revocation = signing::sign_revocation(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &decision,
        target.epoch,
    )?;
    campaign
        .covers_revocation(&revocation)
        .context("la décision signée ne correspond pas à la campagne approuvée")?;

    let result = campaign_result(
        &approval,
        vec![
            aether::certificates::transport::TrustUpdateObject::CertificateRevocation(Box::new(
                revocation,
            )),
        ],
        None,
    );
    let state = client.submit(&request.operation_id, &request.result_token, &result)?;
    println!("état             : {state:?}");
    println!("décision déposée : Astra la relaie à la gateway et la distribue aux clients");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::revocation::{RevocationReason, RevocationScope};

    #[test]
    fn invalid_operation_ids_are_refused_before_loading_the_vault() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing_vault = directory.path().join("missing-vault");
        for operation_id in [
            "",
            "00",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "0101010101010101010101010101010101",
        ] {
            let error = revoke(
                &missing_vault,
                "https://example.invalid",
                operation_id,
                None,
                RevocationInputs {
                    scope: RevocationScope::Client,
                    halves: RevokedHalvesArg::Both,
                    tls_not_after: None,
                    pq_not_after: None,
                    reason: RevocationReason::KeyCompromise,
                    replacement: None,
                },
                Transport::Hid,
            )
            .expect_err("malformed operation must be refused");
            assert!(error.to_string().contains("--operation-id"), "{error:#}");
            assert!(!missing_vault.exists());
        }
    }

    use base64::Engine as _;

    struct Fixture {
        _directory: tempfile::TempDir,
        vault_path: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary directory");
            let vault_path = directory.path().join("authority-vault.json");
            let (pq_private, pq_public) =
                aether::certificates::encoding::generate_ml_dsa_87_keypair()
                    .expect("CA-PQ keypair");
            let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
            let trust_domain_id = aether::certificates::encoding::TrustDomainId::new([0x31; 16])
                .expect("trust domain");
            let gateway_key = aether::certificates::encoding::WireGuardKey::from_bytes([0x42; 32]);
            let vault = astra_operator::vault::AuthorityVault::create(
                trust_domain_id,
                "astra.example",
                astra_operator::vault::draw_salt().expect("vault salt"),
                &astra_operator::vault::AuthoritySecrets {
                    ca_pq_private_key: encode(&pq_private),
                    ca_pq_public_key: pq_public.to_base64(),
                    ca_tls_private_key: encode(b"test-only CA-TLS private key"),
                    retained_ca_tls: None,
                },
                astra_operator::vault::SlotEnrolment {
                    role: astra_operator::vault::SlotRole::Primary,
                    label: "test slot".into(),
                    credential_id: vec![0x51; 32],
                    credential_public_key: vec![0xa5, 0x01],
                    aaguid: [0; 16],
                    enrolled_at: 1,
                },
                &astra_operator::vault::SlotSecret::new(vec![0x61; 32]),
                1,
            )
            .expect("test vault");
            astra_operator::store::save(&vault_path, &vault).expect("save vault");

            let mut handoff =
                astra_operator::handoff::DomainHandoff::of(&vault).expect("domain handoff");
            handoff.gateway_wg_public_key = Some(gateway_key.to_base64());
            handoff.server_name = Some("gateway.example".into());
            astra_operator::handoff::save(
                &astra_operator::handoff::path_beside(&vault_path),
                &handoff,
            )
            .expect("save handoff");
            credentials::save(
                &credentials::path_beside(&vault_path),
                &aether::certificates::approval::CredentialRegistry {
                    trust_domain_id,
                    gateway_wg_public_key: gateway_key,
                    ca_epoch: 1,
                    credential_registry_epoch: 1,
                    bindings: Vec::new(),
                },
            )
            .expect("save credential registry");

            Self {
                _directory: directory,
                vault_path,
            }
        }

        fn load_handoff(&self) -> astra_operator::handoff::DomainHandoff {
            astra_operator::handoff::load(&astra_operator::handoff::path_beside(&self.vault_path))
                .expect("load handoff")
        }

        fn save_handoff(&self, handoff: &astra_operator::handoff::DomainHandoff) {
            astra_operator::handoff::save(
                &astra_operator::handoff::path_beside(&self.vault_path),
                handoff,
            )
            .expect("save handoff");
        }

        fn revoke(&self, authority_url: &str) -> anyhow::Result<()> {
            super::revoke(
                &self.vault_path,
                authority_url,
                "01010101010101010101010101010101",
                None,
                RevocationInputs {
                    scope: RevocationScope::Client,
                    halves: RevokedHalvesArg::Both,
                    tls_not_after: Some(10_000),
                    pq_not_after: Some(10_000),
                    reason: RevocationReason::KeyCompromise,
                    replacement: None,
                },
                Transport::Hid,
            )
        }
    }

    #[test]
    fn non_https_authority_origins_are_refused_before_a_request_or_key_touch() {
        let fixture = Fixture::new();

        let error = fixture
            .revoke("http://astra.example")
            .expect_err("the authority must authenticate this public channel with TLS");

        assert!(
            error.to_string().contains("doit être en https://"),
            "{error:#}"
        );
    }

    #[test]
    fn revocation_refuses_a_handoff_without_the_gateway_server_name() {
        let fixture = Fixture::new();
        let mut handoff = fixture.load_handoff();
        handoff.server_name = None;
        fixture.save_handoff(&handoff);

        let error = fixture
            .revoke("http://astra.example")
            .expect_err("the signed decision must be bound to its gateway identity");

        assert!(
            error.to_string().contains("nom de service de la gateway"),
            "{error:#}"
        );
    }

    #[test]
    fn revocation_refuses_an_unreadable_ca_pq_anchor_before_networking() {
        let fixture = Fixture::new();
        let mut vault = store::load(&fixture.vault_path).expect("load vault");
        vault.ca_pq_public_key = "A".into();
        store::save(&fixture.vault_path, &vault).expect("persist malformed test anchor");

        let error = fixture
            .revoke("http://astra.example")
            .expect_err("a revocation cannot be signed under an unreadable trust anchor");

        assert!(
            error.to_string().contains("public key is malformed"),
            "{error:#}"
        );
    }

    #[test]
    fn revocation_refuses_to_contact_astra_without_credential_bindings() {
        let fixture = Fixture::new();
        std::fs::remove_file(credentials::path_beside(&fixture.vault_path))
            .expect("remove credential bindings");

        let error = fixture
            .revoke("http://astra.example")
            .expect_err("the signed credential registry is required before a campaign");

        assert!(
            error.to_string().contains("document de credentials"),
            "{error:#}"
        );
    }
}
