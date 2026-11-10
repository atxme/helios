//! Issuing `CA-TLS` and delegating Astra's issuer.

use super::*;

pub(crate) fn issue_ca_tls(
    path: &Path,
    days: u64,
    out: Option<&Path>,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
    if handoff.ca_tls_certificate.is_some() {
        bail!(
            "ce domaine porte déjà une CA-TLS à l'époque {} : `issue-ca-tls` initialise l'ancre, \
             il ne la remplace pas ; employer la transition CA-TLS du §9.4",
            handoff.ca_tls_epoch.unwrap_or(1)
        );
    }
    let identity = handoff::identity_of(&handoff)?;
    let not_before = now_unix();
    let not_after = not_before
        .checked_add(days.checked_mul(DAY_SECS).context("durée hors bornes")?)
        .context("durée hors bornes")?;

    let opening = open_vault(
        &vault,
        transport,
        "Auto-signature de CA-TLS. Brancher une clé autorisée, puis appuyer sur Entrée.",
    )?;
    let certificate = signing::issue_ca_tls(&vault, &opening, &identity, not_before, not_after)?;

    // The epoch moves with the certificate, in the same write: a hand-off
    // naming one epoch and carrying another would have every later delegation
    // refused at the gateway, under a signature that is perfectly valid.
    handoff.ca_tls_epoch = Some(identity.ca_tls_epoch);
    handoff.ca_tls_certificate = Some(certificate.to_base64());
    handoff::save(&handoff::path_beside(path), &handoff)?;
    if let Some(out) = out {
        std::fs::write(out, pem_of(&certificate))
            .with_context(|| format!("écriture de {}", out.display()))?;
        println!("certificat PEM   : {}", out.display());
    }

    println!(
        "relais           : {}",
        handoff::path_beside(path).display()
    );
    println!("époque CA-TLS    : {}", identity.ca_tls_epoch);
    println!("valide de        : {}", horodatage(not_before));
    println!("valide jusqu'à   : {}", horodatage(not_after));
    println!(
        "cette CA est épinglée par la gateway : la remplacer coupe tous les clients déjà \
         admis, et c'est la rotation du §9.4 qui la remplace"
    );
    Ok(())
}

/// Signs one bounded delegation to Astra's online issuer (spec §9.5).
///
/// # Why the campaign is the ordinary path
///
/// An [`IssuerDelegationRequest`] carries no signature. Read from a file, it
/// authorizes whoever handed the operator that file: substitute the ML-DSA-87
/// key, and the delegation certifies a key its holder chose. The campaign is
/// what closes that — it is signed by the authority's service key, it pins the
/// epoch and both public halves, and the operator reads them before the touch.
/// The offline form survives for a domain with no reachable origin, and says
/// so rather than pretending the two are equivalent.
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_issuer(
    path: &Path,
    request_path: &Path,
    out: Option<&Path>,
    online: Option<(&str, &str)>,
    days: u64,
    leaf_days: u64,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::status::CampaignFamily;

    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_tls = DerCertificate::parse(handoff.require(
        handoff.ca_tls_certificate.as_ref(),
        "le certificat CA-TLS",
        "issue-ca-tls",
    )?)?;
    let campaign_context = match online {
        Some((authority_url, operation_id)) => {
            let operation = Id16::parse_hex(operation_id)
                .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
            let client = astra_operator::origin::Origin::new(authority_url)?;
            let request_document = origin_client_fetch(&client, &operation)?;
            handoff::verify_campaign_request(
                &handoff,
                &vault,
                &request_document,
                authority_url,
                now_unix(),
            )?;
            let campaign = request_document.campaign.as_ref().clone();
            if !matches!(campaign.scope.family(), CampaignFamily::IssuerDelegation) {
                bail!(
                    "cette opération n'autorise pas de délégation d'émetteur. Rien n'a été signé."
                );
            }
            Some((client, request_document, campaign))
        }
        None => None,
    };

    let request: IssuerDelegationRequest = documents::read(request_path)?;

    // The campaign pins the exact material, so a substituted request is
    // refused here — before the vault opens, and before the operator is asked
    // for anything.
    if let Some((_, _, campaign)) = &campaign_context {
        let csr = DerCertificate::new(
            <base64::engine::general_purpose::GeneralPurpose as base64::Engine>::decode(
                &base64::engine::general_purpose::STANDARD,
                request.tls_intermediate_csr.trim(),
            )
            .context("décodage de la demande d'intermédiaire")?,
        )?;
        let public_key_info =
            aether::certificates::x509::certification_request_public_key_info(&csr)?;
        let pq = MlDsa87PublicKey::parse(request.pq_issuer_public_key.trim())?;
        campaign
            .covers_issuer_delegation(
                identity.trust_domain_id,
                request.issuer_epoch,
                &aether::certificates::encoding::Fingerprint::of(pq.as_bytes()),
                &aether::certificates::encoding::Fingerprint::of(&public_key_info),
            )
            .context(
                "la demande de délégation n'est pas celle que la campagne nomme : époque ou clé \
                 substituée. Rien n'a été signé.",
            )?;
    }

    let not_before = now_unix();
    let bounds = DelegationBounds {
        maximum_leaf_lifetime_secs: leaf_days
            .checked_mul(DAY_SECS)
            .context("durée hors bornes")?,
        not_before,
        not_after: not_before
            .checked_add(days.checked_mul(DAY_SECS).context("durée hors bornes")?)
            .context("durée hors bornes")?,
    };

    println!("émetteur délégué : époque {}", request.issuer_epoch);
    println!("domaine          : {}", request.trust_domain_id);
    println!("gateway          : {}", identity.gateway_wg_public_key);
    println!("leaf au plus     : {leaf_days} jours");
    println!("délégation       : {days} jours");
    match &campaign_context {
        Some((_, _, campaign)) => {
            println!("campagne         : {}", campaign.campaign_id.to_hex());
            println!("empreinte        : {}", campaign.fingerprint());
            println!("motif            : {}", campaign.reason);
            println!("demandée par     : {}", campaign.requested_by);
        }
        None => println!(
            "hors campagne    : rien ne rattache cette demande à une autorité ; elle vaut ce que \
             vaut le fichier"
        ),
    }

    let authorization = match &campaign_context {
        Some((_, _, campaign)) => {
            let origin = origin
                .map(str::to_string)
                .unwrap_or_else(|| format!("https://{}", vault.rp_id));
            let registry =
                credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "aucun document de credentials : l'émettre par `astra-signer bindings`"
                    )
                })?;
            let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
            eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
            wait_for_operator()?;
            let key = authenticator::connect(transport)?;
            let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
            let approval = signing::approve_campaign(
                &[key.as_ref()],
                campaign,
                &registry,
                &identity,
                &ca_pq_public_key,
                &vault.rp_id,
                &origin,
                &[pin.as_str()],
                now_unix(),
            )?;
            let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
            let authorization = signing::authorize_issuer(
                &vault,
                &opening,
                &identity,
                &ca_tls,
                &request,
                &bounds,
                now_unix(),
            )?;
            (Some(approval), authorization)
        }
        None => {
            let opening = open_vault(
                &vault,
                transport,
                "Signature de la délégation. Brancher une clé autorisée, puis appuyer sur Entrée.",
            )?;
            let authorization = signing::authorize_issuer(
                &vault,
                &opening,
                &identity,
                &ca_tls,
                &request,
                &bounds,
                now_unix(),
            )?;
            (None, authorization)
        }
    };
    let (approval, authorization) = authorization;

    if let Some(out) = out {
        documents::write(out, &authorization)?;
        println!("autorisation     : {}", out.display());
    }
    match (&campaign_context, approval) {
        (Some((client, request_document, _)), Some(approval)) => {
            let mut result = campaign_result(&approval, Vec::new(), None);
            result.issuer_authorization = Some(Box::new(authorization));
            let state = client.submit(
                &request_document.operation_id,
                &request_document.result_token,
                &result,
            )?;
            println!("état             : {state:?}");
            println!(
                "la délégation est enregistrée par l'autorité, qui l'adopte sans redémarrage ; \
                 l'échec d'adoption se lit au journal d'Astra"
            );
        }
        _ => println!("à reporter sur l'autorité : astra issuer install --authorization <fichier>"),
    }
    println!(
        "cette délégation n'autorise qu'un renouvellement de leaf cliente admise, et rien \
         d'autre : ni gateway, ni CA, ni pair inconnu"
    );
    Ok(())
}

/// The PEM form of a certificate, for the tools that read one.
fn pem_of(certificate: &DerCertificate) -> String {
    let body = certificate.to_base64();
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_operator::vault::{
        AuthoritySecrets, AuthorityVault, SlotEnrolment, SlotRole, SlotSecret,
    };
    use base64::Engine as _;

    struct Fixture {
        _directory: tempfile::TempDir,
        vault_path: PathBuf,
        handoff_path: PathBuf,
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
            let vault = AuthorityVault::create(
                trust_domain_id,
                "astra.example",
                astra_operator::vault::draw_salt().expect("vault salt"),
                &AuthoritySecrets {
                    ca_pq_private_key: encode(&pq_private),
                    ca_pq_public_key: pq_public.to_base64(),
                    ca_tls_private_key: encode(b"test-only CA-TLS private key"),
                    retained_ca_tls: None,
                    retained_outgoing_ca_pq: None,
                },
                SlotEnrolment {
                    role: SlotRole::Primary,
                    label: "test slot".into(),
                    credential_id: vec![0x51; 32],
                    credential_public_key: vec![0xa5, 0x01],
                    aaguid: [0; 16],
                    enrolled_at: 1,
                },
                &SlotSecret::new(vec![0x61; 32]),
                1,
            )
            .expect("test vault");
            astra_operator::store::save(&vault_path, &vault).expect("save vault");

            let mut handoff =
                astra_operator::handoff::DomainHandoff::of(&vault).expect("domain handoff");
            handoff.gateway_wg_public_key = Some(
                aether::certificates::encoding::WireGuardKey::from_bytes([0x42; 32]).to_base64(),
            );
            handoff.server_name = Some("gateway.example".into());
            let certificate =
                aether::certificates::test_x509::client_material("gateway.example").authority;
            handoff.ca_tls_epoch = Some(1);
            handoff.ca_tls_certificate = Some(certificate.to_base64());
            let handoff_path = astra_operator::handoff::path_beside(&vault_path);
            astra_operator::handoff::save(&handoff_path, &handoff).expect("save handoff");

            Self {
                _directory: directory,
                vault_path,
                handoff_path,
            }
        }
    }

    fn request() -> aether::certificates::authority::IssuerDelegationRequest {
        aether::certificates::authority::IssuerDelegationRequest {
            trust_domain_id: "31".repeat(16),
            issuer_epoch: 1,
            pq_issuer_public_key: String::new(),
            tls_intermediate_csr: String::new(),
        }
    }

    #[test]
    fn issue_ca_tls_refuses_to_replace_an_existing_anchor_before_any_gesture() {
        let fixture = Fixture::new();
        let before = std::fs::read(&fixture.handoff_path).expect("handoff before");
        let output = fixture._directory.path().join("ca-tls.pem");

        let error = issue_ca_tls(&fixture.vault_path, 30, Some(&output), Transport::Hid)
            .expect_err("initialization must not replace a CA-TLS anchor");

        assert!(error.to_string().contains("déjà une CA-TLS"));
        assert_eq!(
            std::fs::read(&fixture.handoff_path).expect("handoff after"),
            before
        );
        assert!(!output.exists(), "a refused rotation writes no PEM");
    }

    #[test]
    fn issuer_authorization_rejects_an_invalid_operation_id_before_network_or_key_access() {
        let fixture = Fixture::new();
        let absent_request = fixture._directory.path().join("request.json");

        let error = authorize_issuer(
            &fixture.vault_path,
            &absent_request,
            None,
            Some(("https://astra.example", "not-an-operation-id")),
            30,
            90,
            None,
            Transport::Hid,
        )
        .expect_err("invalid operation id must stop before fetch or FIDO");

        assert!(error.to_string().contains("--operation-id"));
        assert!(!absent_request.exists());
    }

    #[test]
    fn issuer_authorization_reports_duration_overflow_before_opening_the_vault() {
        let fixture = Fixture::new();
        let request_path = fixture._directory.path().join("request.json");
        std::fs::write(
            &request_path,
            serde_json::to_vec(&request()).expect("request JSON"),
        )
        .expect("write request");

        let error = authorize_issuer(
            &fixture.vault_path,
            &request_path,
            None,
            None,
            u64::MAX,
            1,
            None,
            Transport::Hid,
        )
        .expect_err("overflow must stop before a hardware-key gesture");

        assert!(error.to_string().contains("durée hors bornes"));
    }

    #[test]
    fn issuer_authorization_does_not_treat_a_malformed_request_as_absent() {
        let fixture = Fixture::new();
        let request_path = fixture._directory.path().join("request.json");
        std::fs::write(&request_path, b"{not-json").expect("write malformed request");

        let error = authorize_issuer(
            &fixture.vault_path,
            &request_path,
            None,
            None,
            30,
            90,
            None,
            Transport::Hid,
        )
        .expect_err("malformed request must stop before a hardware-key gesture");

        assert!(format!("{error:#}").contains("request.json"));
    }

    #[test]
    fn pem_output_wraps_base64_at_sixty_four_columns() {
        let certificate = DerCertificate::new(vec![0x55; 96]).expect("DER bytes");

        let pem = pem_of(&certificate);
        let lines: Vec<_> = pem.lines().collect();

        assert_eq!(lines.first(), Some(&"-----BEGIN CERTIFICATE-----"));
        assert_eq!(lines.last(), Some(&"-----END CERTIFICATE-----"));
        assert!(lines[1..lines.len() - 1]
            .iter()
            .all(|line| line.len() <= 64));
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2].len(), 64);
    }
}
