//! Approving a client renewal or a campaign with security keys.

use super::*;

/// Where the request comes from, and where the assertion goes back to.
///
/// Two shapes, one gesture. What differs is only the transport, and the
/// verification is deliberately identical: the objects carry the signatures,
/// so a request fetched through a tunnel is trusted exactly as much — and
/// exactly as little — as one read from a path an operator typed.
enum ApprovalChannel {
    /// Files an operator names, for a machine outside the tunnel.
    Files { request: PathBuf, out: PathBuf },
    /// The client's own gateway, over the typed in-tunnel routes (§8.1.2).
    Tunnel {
        tunnel: tunnel::Tunnel,
        operation_id: Id16,
    },
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn approve(
    path: &Path,
    request_path: Option<&Path>,
    out: Option<&Path>,
    heliosd_url: Option<&str>,
    operation_id: Option<&str>,
    active_generation: Option<u64>,
    transport: Transport,
) -> Result<()> {
    let channel = match (request_path, out, heliosd_url, operation_id) {
        (Some(request), Some(out), None, None) => ApprovalChannel::Files {
            request: request.to_path_buf(),
            out: out.to_path_buf(),
        },
        (None, None, Some(url), Some(operation)) => ApprovalChannel::Tunnel {
            tunnel: tunnel::Tunnel::new(url)?,
            operation_id: Id16::parse_hex(operation.trim())
                .context("identifiant d'opération invalide")?,
        },
        // Named rather than left to clap: `--request` without `--out` and
        // `--out` without `--request` are both legal for clap — neither
        // conflicts with anything — and the failure would otherwise be an
        // approval written nowhere, after the key was touched.
        _ => bail!(
            "choisir un chemin : soit --request et --out ensemble, soit --heliosd-url et \
             --operation-id ensemble"
        ),
    };

    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let service_key = MlDsa87PublicKey::parse(handoff.require(
        handoff.astra_service_public_key.as_ref(),
        "la clé de service d'Astra",
        "--astra-service-public-key",
    )?)?;
    let service_key_epoch = *handoff.require(
        handoff.astra_service_key_epoch.as_ref(),
        "l'époque de la clé de service d'Astra",
        "--astra-service-key-epoch",
    )?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!(
            "aucun document de credentials : l'émettre par `astra-signer bindings` avant \
             d'approuver quoi que ce soit"
        )
    })?;

    let (request, fetched) = match &channel {
        ApprovalChannel::Files { request, .. } => (
            Box::new(documents::read::<
                aether::certificates::approval::AstraCredentialApprovalRequest,
            >(request)?),
            None,
        ),
        ApprovalChannel::Tunnel {
            tunnel,
            operation_id,
        } => {
            println!("gateway          : demande récupérée dans le tunnel");
            let fetched = tunnel.fetch(operation_id)?;
            // Reported, never adopted. The RP ID the ceremony actually runs
            // under is the vault's, and a gateway that named another one would
            // otherwise have this key answer a challenge for another domain.
            if fetched.webauthn_rp_id != vault.rp_id {
                bail!(
                    "la gateway annonce le RP ID « {} » alors que ce coffre est celui de « {} ». \
                     Rien n'est signé : une assertion produite sous un autre RP ID vaudrait pour \
                     un autre domaine.",
                    fetched.webauthn_rp_id,
                    vault.rp_id
                );
            }
            println!("autorité annoncée: {}", fetched.authority_url);
            (fetched.approval_request, Some(fetched.result_token))
        }
    };

    // Shown before the key is touched, and shown from the request that Astra
    // signed rather than from anything this program chose.
    println!("opération        : {}", request.operation_id.to_hex());
    println!("client           : {}", request.client_wg_public_key);
    println!(
        "génération       : {} → {}",
        request.active_generation, request.requested_generation
    );
    println!(
        "demande          : {}",
        request.request_fingerprint.to_hex()
    );
    println!("expire à         : {}", horodatage(request.expires_at));

    // No vault, and no salt: §14.1 in the shape of a call. This is the whole
    // reason the vault is loaded above only for the hand-off and the registry.
    eprintln!("Brancher la clé d'approbation, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let approval = aether_fido::approve_renewal(
        key.as_ref(),
        &request,
        &service_key,
        service_key_epoch,
        &identity,
        &ca_pq_public_key,
        &registry,
        &vault.rp_id,
        active_generation,
        &pin,
        now_unix(),
    )?;

    match (&channel, fetched) {
        (ApprovalChannel::Files { out, .. }, _) => {
            documents::write(out, &approval)?;
            println!("approbation      : {}", out.display());
        }
        (
            ApprovalChannel::Tunnel {
                tunnel,
                operation_id,
            },
            Some(result_token),
        ) => {
            let state = tunnel.submit(operation_id, &result_token, &approval)?;
            println!("approbation      : déposée dans le tunnel");
            match state {
                ClientRenewalOperationState::PendingCommit => println!(
                    "état             : pending_commit — l'autorité a émis, la gateway a persisté \
                     et signé son reçu. Le client committe."
                ),
                ClientRenewalOperationState::PendingGrant => println!(
                    "état             : pending_grant — l'approbation est prise, l'émission est \
                     en cours."
                ),
                ClientRenewalOperationState::AwaitingOperator => bail!(
                    "l'autorité attend toujours un opérateur après avoir reçu cette assertion : \
                     elle ne l'a pas consommée. Ne pas réessayer sans savoir pourquoi."
                ),
                ClientRenewalOperationState::Failed => bail!(
                    "l'autorité a refusé après avoir reçu l'assertion. L'opération est terminée : \
                     le client doit en ouvrir une nouvelle."
                ),
            }
        }
        // Unreachable by construction: the tunnel arm always produces a token,
        // and the files arm never consults one. Named rather than unwrapped so
        // that a future third channel cannot silently drop the submission.
        (ApprovalChannel::Tunnel { .. }, None) => bail!(
            "aucun jeton de dépôt pour cette opération : l'assertion n'a été envoyée nulle part"
        ),
    }

    println!("empreinte        : {}", approval.fingerprint().to_hex());
    println!("valable jusqu'à  : {}", horodatage(approval.expires_at));
    println!(
        "le coffre n'a pas été ouvert : une approbation ordinaire n'obtient aucune sortie PRF \
         et Astra y ajoute sa propre signature"
    );
    Ok(())
}

/// Approves a manual campaign, offline or through Astra's public origin.
///
/// # Two transports, one ceremony
///
/// The gesture below is the same either way, and that is the point: what the
/// operator's key answers is the campaign fingerprint, recomputed from the
/// campaign itself. A campaign read from a file and one fetched from the
/// origin are the same object with the same signature over it — the wire
/// carries no authority.
///
/// The origin is the case the in-tunnel relay cannot cover (§8.2): an operator
/// on their own workstation has no VIP the gateway would resolve. What comes
/// back is compared against the vault's own relying party rather than adopted:
/// an assertion produced under another RP ID would be valid for another
/// domain.
#[allow(clippy::too_many_arguments)]
pub(crate) fn approve_campaign(
    path: &Path,
    campaign_path: Option<&Path>,
    out: Option<&Path>,
    authority_url: Option<&str>,
    operation_id: Option<&str>,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let online = match (authority_url, operation_id) {
        (Some(url), Some(id)) => {
            let operation =
                Id16::parse_hex(id).map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
            let origin_client = astra_operator::origin::Origin::new(url)?;
            let request = origin_client_fetch(&origin_client, &operation)?;
            Some((origin_client, request))
        }
        _ => None,
    };

    let campaign = match &online {
        Some((_, request)) => {
            handoff::verify_campaign_request(
                &handoff,
                &vault,
                request,
                authority_url.unwrap_or_default(),
                now_unix(),
            )?;
            request.campaign.as_ref().clone()
        }
        None => {
            let Some(campaign_path) = campaign_path else {
                bail!(
                    "donner soit --campaign et --out, soit --authority-url et --operation-id : \
                     un fichier hors ligne, ou l'origine publique du §8.2"
                );
            };
            if out.is_none() {
                bail!("--out est requis avec --campaign : sans lui l'approbation est perdue");
            }
            documents::read(campaign_path)?
        }
    };

    let origin = match origin {
        Some(origin) => origin.to_string(),
        None => format!("https://{}", vault.rp_id),
    };

    if campaign.scope.revokes() {
        bail!(
            "cette campagne retire une identité : l'exécuter par `astra-signer revoke \
             --authority-url … --operation-id …`, qui ouvre le coffre et dépose la décision \
             signée dans le même geste. Rien n'a été signé."
        );
    }
    if campaign.scope.rotates_authority() {
        // An anchor campaign is not approved and then applied: the approval
        // and the objects `CA-PQ` signs travel in one deposit (§0.6). Taking
        // the touch here would spend the operator's window on a result that
        // carries nothing.
        bail!(
            "cette campagne fait tourner une ancre : elle s'exécute par `astra-signer rotate-ca-pq \
             --authority-url … --operation-id …`, qui ouvre le coffre et rend les objets signés \
             dans le même dépôt. Rien n'a été signé."
        );
    }

    // Validate the manifest, bindings, domain pin and active credential count
    // before asking the operator to connect a key. Keep the session across the
    // ceremony so each physical key answers while it is still plugged in.
    let session = signing::CampaignApprovalSession::new(
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        now_unix(),
    )?;
    let required = session.required();
    println!("campagne         : {}", campaign.campaign_id.to_hex());
    println!("portée           : {:?}", campaign.scope);
    println!("cibles           : {}", campaign.targets.len());
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!("confirmations    : {required} clé(s) distincte(s)");

    let approval = approve_campaign_sequentially(session, |index| {
        eprintln!("Brancher la clé {index}/{required}, puis appuyer sur Entrée.");
        wait_for_operator()?;
        let key = authenticator::connect(transport)?;
        let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
        Ok((key, pin))
    })?;

    match (&online, out) {
        (Some((client, request)), _) => {
            let result = campaign_result(&approval, Vec::new(), None);
            let state = client.submit(&request.operation_id, &request.result_token, &result)?;
            println!("opération        : {}", request.operation_id.to_hex());
            println!("état             : {state:?}");
            println!(
                "cette approbation est dépensée par la demande de chaque pair couvert, dans la \
                 fenêtre de la campagne. Un pair hors ligne pendant celle-ci n'est pas renouvelé."
            );
        }
        (None, Some(out)) => {
            documents::write(out, &approval)?;
            println!("approbation      : {}", out.display());
        }
        (None, None) => unreachable!("--out is required above when there is no origin"),
    }
    println!(
        "empreinte        : {}",
        approval.campaign_fingerprint.to_hex()
    );
    println!(
        "cette empreinte couvre les cibles et leur ordre : une cible ajoutée ensuite est \
         refusée, pas réapprouvée"
    );
    Ok(())
}

/// Collects each campaign assertion before asking for the next physical key.
///
/// The factory is injected so tests can use simulated authenticators without a
/// terminal or HID device; production supplies one after every prompt. The
/// shrinking allow-list belongs to the session and is read only after the next
/// authenticator has been connected.
fn approve_campaign_sequentially<'key>(
    mut session: signing::CampaignApprovalSession,
    mut connect_key: impl FnMut(
        usize,
    ) -> Result<(
        Box<dyn astra_operator::authenticator::Authenticator + 'key>,
        Zeroizing<String>,
    )>,
) -> Result<aether::certificates::status::CampaignApproval> {
    for index in 1..=session.required() {
        let (key, pin) = connect_key(index)?;
        let offered = session.offered_credentials();
        let assertion = key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            &pin,
        )?;
        session.accept(assertion, now_unix())?;
    }
    Ok(session.finish(now_unix())?)
}

#[cfg(test)]
mod precondition_tests {
    use super::*;

    fn invalid_channel(
        request: Option<&Path>,
        out: Option<&Path>,
        heliosd_url: Option<&str>,
        operation_id: Option<&str>,
    ) -> anyhow::Error {
        let directory = tempfile::tempdir().expect("temporary directory");
        let unavailable_vault = directory.path().join("missing-vault");
        approve(
            &unavailable_vault,
            request,
            out,
            heliosd_url,
            operation_id,
            None,
            Transport::Hid,
        )
        .expect_err("invalid channel shape must fail")
    }

    #[test]
    fn approval_rejects_incomplete_and_mixed_channels_before_opening_vault() {
        let request = Path::new("request.json");
        let out = Path::new("approval.json");
        for error in [
            invalid_channel(None, None, None, None),
            invalid_channel(Some(request), None, None, None),
            invalid_channel(None, Some(out), None, None),
            invalid_channel(None, None, Some("http://127.0.0.1:1"), None),
            invalid_channel(None, None, None, Some("01010101010101010101010101010101")),
            invalid_channel(Some(request), Some(out), Some("http://127.0.0.1:1"), None),
            invalid_channel(
                Some(request),
                Some(out),
                None,
                Some("01010101010101010101010101010101"),
            ),
            invalid_channel(
                Some(request),
                Some(out),
                Some("http://127.0.0.1:1"),
                Some("01010101010101010101010101010101"),
            ),
        ] {
            assert!(
                error.to_string().contains("choisir un chemin"),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn valid_file_pair_is_selected_before_vault_load_without_touching_authenticator() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let vault = directory.path().join("missing-vault");
        let error = approve(
            &vault,
            Some(Path::new("request.json")),
            Some(Path::new("approval.json")),
            None,
            None,
            None,
            Transport::Hid,
        )
        .expect_err("missing vault follows valid file-channel selection");

        assert!(!error.to_string().contains("choisir un chemin"));
        assert!(format!("{error:#}").contains(&vault.display().to_string()));
    }

    #[test]
    fn tunnel_channel_rejects_malformed_operation_id_before_vault_load() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let vault = directory.path().join("missing-vault");
        let error = approve(
            &vault,
            None,
            None,
            Some("http://127.0.0.1:1"),
            Some("not-an-operation-id"),
            None,
            Transport::Hid,
        )
        .expect_err("malformed operation id must fail before vault access");

        assert!(error
            .to_string()
            .contains("identifiant d'opération invalide"));
    }
}
#[cfg(test)]
mod campaign_approval_precondition_tests {
    use super::*;
    use aether::certificates::{
        approval::CredentialRegistry,
        encoding::{Fingerprint, TrustDomainId, WireGuardKey},
        status::{AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind},
    };
    use astra_operator::vault::{
        AuthoritySecrets, AuthorityVault, SlotEnrolment, SlotRole, SlotSecret,
    };
    use base64::Engine as _;

    struct Fixture {
        _directory: tempfile::TempDir,
        vault_path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary directory");
            let vault_path = directory.path().join("authority-vault.json");
            let (pq_private, pq_public) =
                aether::certificates::encoding::generate_ml_dsa_87_keypair()
                    .expect("ML-DSA keypair");
            let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
            let trust_domain_id = TrustDomainId::new([0x31; 16]).expect("domain id");
            let gateway_key = WireGuardKey::from_bytes([0x42; 32]);
            let vault = AuthorityVault::create(
                trust_domain_id,
                "astra.example",
                astra_operator::vault::draw_salt().expect("vault salt"),
                &AuthoritySecrets {
                    ca_pq_private_key: encode(&pq_private),
                    ca_pq_public_key: pq_public.to_base64(),
                    ca_tls_private_key: encode(b"test-only TLS private key"),
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
            astra_operator::store::save(&vault_path, &vault).expect("save test vault");

            let mut handoff =
                astra_operator::handoff::DomainHandoff::of(&vault).expect("test handoff");
            handoff.gateway_wg_public_key = Some(gateway_key.to_base64());
            handoff.server_name = Some("gateway.example".into());
            astra_operator::handoff::save(
                &astra_operator::handoff::path_beside(&vault_path),
                &handoff,
            )
            .expect("save test handoff");

            credentials::save(
                &credentials::path_beside(&vault_path),
                &CredentialRegistry {
                    trust_domain_id,
                    gateway_wg_public_key: gateway_key,
                    ca_epoch: 1,
                    credential_registry_epoch: 1,
                    bindings: Vec::new(),
                },
            )
            .expect("save empty test registry");

            Self {
                _directory: directory,
                vault_path,
            }
        }

        fn campaign(&self, scope: CampaignScope) -> AstraRotationCampaign {
            let now = now_unix();
            let trust_domain_id = TrustDomainId::new([0x31; 16]).expect("domain id");
            AstraRotationCampaign {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                campaign_id: Id16::new([0x71; 16]).expect("campaign id"),
                trust_domain_id,
                gateway_wg_public_key: WireGuardKey::from_bytes([0x42; 32]),
                server_name: "gateway.example".into(),
                created_at: now.saturating_sub(1),
                expires_at: now.saturating_add(300),
                scope,
                targets: vec![CampaignTarget {
                    certificate_kind: CertificateKind::GatewayTls,
                    identity_key: WireGuardKey::from_bytes([0x42; 32]),
                    epoch: 1,
                    generation: 1,
                    active_tls_certificate_fingerprint: Fingerprint::of(b"active TLS"),
                    active_pq_certificate_fingerprint: Fingerprint::of(b"active PQ"),
                }],
                reason: "test fixture".into(),
                requested_by: "test operator".into(),
                policy_fingerprint: Fingerprint::of(b"test policy"),
                required_credentials: scope.required_credentials(),
            }
        }

        fn write_campaign(&self, campaign: &AstraRotationCampaign) -> PathBuf {
            let path = self._directory.path().join("campaign.json");
            documents::write(&path, &campaign).expect("write campaign fixture");
            path
        }

        fn campaign_file(&self, scope: CampaignScope) -> PathBuf {
            let campaign = self.campaign(scope);
            self.write_campaign(&campaign)
        }

        fn approve_file(&self, campaign_path: &Path, out: &Path) -> anyhow::Error {
            approve_campaign(
                &self.vault_path,
                Some(campaign_path),
                Some(out),
                None,
                None,
                None,
                Transport::Hid,
            )
            .expect_err("fixture campaign must stop at a precondition")
        }
    }

    #[test]
    fn revocation_campaign_is_refused_before_any_key_prompt_or_output() {
        let fixture = Fixture::new();
        let campaign = fixture.campaign_file(CampaignScope::EmergencyRevocation);
        let out = fixture._directory.path().join("approval.json");

        let error = fixture.approve_file(&campaign, &out);

        assert!(
            format!("{error:#}").contains("retire une identité"),
            "{error:#}"
        );
        assert!(
            !out.exists(),
            "a refused campaign must not produce an approval"
        );
    }

    #[test]
    fn authority_rotation_campaign_is_refused_before_any_key_prompt_or_output() {
        let fixture = Fixture::new();
        let campaign = fixture.campaign_file(CampaignScope::TrustAuthorities);
        let out = fixture._directory.path().join("approval.json");

        let error = fixture.approve_file(&campaign, &out);

        assert!(
            format!("{error:#}").contains("fait tourner une ancre"),
            "{error:#}"
        );
        assert!(
            !out.exists(),
            "a refused campaign must not produce an approval"
        );
    }

    #[test]
    fn offline_approval_requires_campaign_and_output_before_touching_a_key() {
        let fixture = Fixture::new();
        let missing_campaign = fixture._directory.path().join("missing-campaign.json");

        let missing_campaign_error = approve_campaign(
            &fixture.vault_path,
            None,
            None,
            None,
            None,
            None,
            Transport::Hid,
        )
        .expect_err("offline approval without a campaign must fail");
        assert!(
            format!("{missing_campaign_error:#}").contains("donner soit --campaign et --out"),
            "{missing_campaign_error:#}"
        );

        let no_output_error = approve_campaign(
            &fixture.vault_path,
            Some(&missing_campaign),
            None,
            None,
            None,
            None,
            Transport::Hid,
        )
        .expect_err("offline approval without an output path must fail");
        assert!(
            no_output_error
                .to_string()
                .contains("--out est requis avec --campaign"),
            "{no_output_error:#}"
        );
        assert!(
            !format!("{no_output_error:#}").contains("missing-campaign.json"),
            "the missing output is rejected before reading the campaign: {no_output_error:#}"
        );
    }

    #[test]
    fn offline_campaign_lease_is_checked_before_requesting_a_key() {
        let fixture = Fixture::new();
        let mut campaign = fixture.campaign(CampaignScope::GatewayIdentity);
        campaign.expires_at = now_unix();
        let campaign_path = fixture.write_campaign(&campaign);
        let out = fixture._directory.path().join("approval.json");

        let error = fixture.approve_file(&campaign_path, &out);

        assert!(format!("{error:#}").contains("lease"), "{error:#}");
        assert!(!format!("{error:#}").contains("terminal"));
        assert!(!out.exists());
    }

    #[test]
    fn unsupported_campaign_format_is_rejected_before_requesting_a_key() {
        let fixture = Fixture::new();
        let mut campaign = fixture.campaign(CampaignScope::GatewayIdentity);
        campaign.format_version = u16::MAX;
        let campaign_path = fixture.write_campaign(&campaign);
        let out = fixture._directory.path().join("approval.json");

        let error = fixture.approve_file(&campaign_path, &out);

        assert!(format!("{error:#}").contains("version"), "{error:#}");
        assert!(!format!("{error:#}").contains("terminal"));
        assert!(!out.exists());
    }

    #[test]
    fn offline_campaign_requires_a_usable_credential_registry_before_requesting_a_key() {
        let fixture = Fixture::new();
        let campaign = fixture.campaign(CampaignScope::GatewayIdentity);
        let campaign_path = fixture.write_campaign(&campaign);
        let out = fixture._directory.path().join("approval.json");

        let error = fixture.approve_file(&campaign_path, &out);

        assert!(format!("{error:#}").contains("empty document"), "{error:#}");
        assert!(!format!("{error:#}").contains("terminal"));
        assert!(!out.exists());
    }

    #[test]
    fn credential_registry_for_another_gateway_is_rejected_before_requesting_a_key() {
        let fixture = Fixture::new();
        let path = credentials::path_beside(&fixture.vault_path);
        let mut registry = credentials::load(&path)
            .expect("registry can be read")
            .expect("fixture registry exists");
        registry.gateway_wg_public_key = WireGuardKey::from_bytes([0x77; 32]);
        credentials::save(&path, &registry).expect("save mismatched registry");

        let campaign = fixture.campaign_file(CampaignScope::GatewayIdentity);
        let out = fixture._directory.path().join("approval.json");
        let error = fixture.approve_file(&campaign, &out);

        assert!(format!("{error:#}").contains("gateway"), "{error:#}");
        assert!(!format!("{error:#}").contains("terminal"));
        assert!(!out.exists());
    }
}

#[cfg(test)]
mod sequential_approval_tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    use astra_operator::{
        authenticator::{
            Approval, ApprovedOpening, Authenticator, AuthenticatorError, CredentialSubject,
            Opened, Registration,
        },
        operations::fixtures::{self, Domain, TestKey},
    };

    type OfferedHistory = Rc<RefCell<Vec<Vec<Vec<u8>>>>>;

    struct RecordingAuthenticator<'a> {
        inner: &'a TestKey,
        offered: OfferedHistory,
        fail_approval: bool,
    }

    impl Authenticator for RecordingAuthenticator<'_> {
        fn register(
            &self,
            _rp_id: &str,
            _subject: &CredentialSubject,
            _exclude: &[Vec<u8>],
            _pin: &str,
        ) -> std::result::Result<Registration, AuthenticatorError> {
            Err(AuthenticatorError::Device("unused in campaign test".into()))
        }

        fn derive(
            &self,
            _rp_id: &str,
            _credentials: &[Vec<u8>],
            _salt: &[u8; 32],
            _pin: &str,
        ) -> std::result::Result<Opened, AuthenticatorError> {
            Err(AuthenticatorError::Device("unused in campaign test".into()))
        }

        fn approve(
            &self,
            rp_id: &str,
            credentials: &[Vec<u8>],
            client_data_json: &[u8],
            pin: &str,
        ) -> std::result::Result<Approval, AuthenticatorError> {
            self.offered.borrow_mut().push(credentials.to_vec());
            if self.fail_approval {
                return Err(AuthenticatorError::Device(
                    "simulated assertion failure".into(),
                ));
            }
            self.inner
                .approve(rp_id, credentials, client_data_json, pin)
        }

        fn approve_and_derive(
            &self,
            _rp_id: &str,
            _credentials: &[Vec<u8>],
            _client_data_json: &[u8],
            _salt: &[u8; 32],
            _pin: &str,
        ) -> std::result::Result<ApprovedOpening, AuthenticatorError> {
            Err(AuthenticatorError::Device("unused in campaign test".into()))
        }
    }

    struct CampaignFixture {
        session: signing::CampaignApprovalSession,
        domain: Domain,
    }

    impl CampaignFixture {
        fn new() -> Self {
            let now = now_unix();
            let domain = fixtures::domain();
            let relay = domain.relay();
            let identity = handoff::identity_of(&relay).expect("domain identity");
            let vault = store::load(&domain.path).expect("operator vault");
            let registry = domain.registry();
            let ca_pq =
                aether::certificates::encoding::MlDsa87PublicKey::parse(&relay.ca_pq_public_key)
                    .expect("read test CA-PQ public key");
            let mut campaign = domain.authority_campaign(fixtures::NOW + 300);
            campaign.created_at = now;
            campaign.expires_at = now.saturating_add(300);
            let session = signing::CampaignApprovalSession::new(
                &campaign,
                &registry,
                &identity,
                &ca_pq,
                &vault.rp_id,
                &format!("https://{}", vault.rp_id),
                now,
            )
            .expect("valid campaign session");

            Self { session, domain }
        }

        fn credential_ids(&self) -> [Vec<u8>; 2] {
            let vault = store::load(&self.domain.path).expect("operator vault");
            [
                vault.slots[0].credential_id().expect("first credential id"),
                vault.slots[1]
                    .credential_id()
                    .expect("second credential id"),
            ]
        }
    }

    fn recording_key<'a>(
        inner: &'a TestKey,
        history: &OfferedHistory,
    ) -> Box<dyn Authenticator + 'a> {
        recording_key_with_failure(inner, history, false)
    }

    fn recording_key_with_failure<'a>(
        inner: &'a TestKey,
        history: &OfferedHistory,
        fail_approval: bool,
    ) -> Box<dyn Authenticator + 'a> {
        Box::new(RecordingAuthenticator {
            inner,
            offered: Rc::clone(history),
            fail_approval,
        })
    }

    #[test]
    fn helper_collects_two_real_assertions_with_a_shrinking_allow_list() {
        let fixture = CampaignFixture::new();
        let [first_id, second_id] = fixture.credential_ids();
        let initial_offered = fixture.session.offered_credentials();
        assert_eq!(initial_offered.len(), 3);
        let history = Rc::new(RefCell::new(Vec::new()));
        let first_key = &fixture.domain.keys[0];
        let second_key = &fixture.domain.keys[1];
        let mut keys = VecDeque::from([
            recording_key(first_key, &history),
            recording_key(second_key, &history),
        ]);

        let approval = approve_campaign_sequentially(fixture.session, |_| {
            let key = keys
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("no simulated key remains"))?;
            Ok((key, Zeroizing::new(String::new())))
        })
        .expect("both physical keys approve sequentially");

        let offered = history.borrow();
        assert_eq!(offered.len(), 2);
        assert_eq!(offered[0], initial_offered);
        assert_eq!(offered[1].len(), 2);
        assert!(!offered[1].contains(&first_id));
        assert!(offered[1].contains(&second_id));
        assert!(offered[0].contains(&first_id));
        assert_eq!(approval.approvals.len(), 2);
        assert_eq!(approval.approvals[0].credential_id, first_id);
        assert_eq!(approval.approvals[1].credential_id, second_id);
    }

    #[test]
    fn a_repeated_simulated_key_is_refused_after_first_assertion() {
        let fixture = CampaignFixture::new();
        let [first_id, second_id] = fixture.credential_ids();
        let history = Rc::new(RefCell::new(Vec::new()));
        let first_key = &fixture.domain.keys[0];
        let mut keys = VecDeque::from([
            recording_key(first_key, &history),
            recording_key(first_key, &history),
        ]);
        let mut supplied = 0;

        let error = approve_campaign_sequentially(fixture.session, |_| {
            supplied += 1;
            let key = keys
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("no simulated key remains"))?;
            Ok((key, Zeroizing::new(String::new())))
        })
        .expect_err("a repeated key cannot answer the narrowed allow-list");

        let offered = history.borrow();
        assert_eq!(supplied, 2);
        assert_eq!(offered.len(), 2);
        assert_eq!(offered[1].len(), 2);
        assert!(!offered[1].contains(&first_id));
        assert!(offered[1].contains(&second_id));
        assert!(format!("{error:#}").contains("credential"));
    }

    #[test]
    fn assertion_failure_stops_before_connecting_the_next_key() {
        let fixture = CampaignFixture::new();
        let history = Rc::new(RefCell::new(Vec::new()));
        let first_key = &fixture.domain.keys[0];
        let mut supplied = 0;

        let error = approve_campaign_sequentially(fixture.session, |_| {
            supplied += 1;
            Ok((
                recording_key_with_failure(first_key, &history, true),
                Zeroizing::new(String::new()),
            ))
        })
        .expect_err("an authenticator assertion error must abort the ceremony");

        assert_eq!(supplied, 1, "no second device should be requested");
        assert_eq!(history.borrow().len(), 1);
        assert!(format!("{error:#}").contains("simulated assertion failure"));
    }

    #[test]
    fn connection_failure_stops_before_attempting_an_assertion() {
        let fixture = CampaignFixture::new();
        let mut supplied = 0;

        let error = approve_campaign_sequentially(fixture.session, |_| {
            supplied += 1;
            Err(anyhow::anyhow!("simulated device connection failure"))
        })
        .expect_err("a device connection error must abort the ceremony");

        assert_eq!(supplied, 1);
        assert!(format!("{error:#}").contains("simulated device connection failure"));
    }
}
