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

    let required = usize::from(campaign.required_credentials);
    println!("campagne         : {}", campaign.campaign_id.to_hex());
    println!("portée           : {:?}", campaign.scope);
    println!("cibles           : {}", campaign.targets.len());
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!("confirmations    : {required} clé(s) distincte(s)");

    // Plugged one at a time, and each connection is its own: two touches of
    // one token is what `approve_campaign` refuses, and asking for the keys
    // one after another is how an operator finds that out at the second.
    let mut keys = Vec::new();
    let mut pins = Vec::new();
    for index in 1..=required {
        eprintln!("Brancher la clé {index}/{required}, puis appuyer sur Entrée.");
        wait_for_operator()?;
        let key = authenticator::connect(transport)?;
        pins.push(pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?);
        keys.push(key);
    }
    let key_refs: Vec<&dyn astra_operator::authenticator::Authenticator> =
        keys.iter().map(|key| key.as_ref()).collect();
    let pin_refs: Vec<&str> = pins.iter().map(|pin| pin.as_str()).collect();

    let approval = signing::approve_campaign(
        &key_refs,
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &pin_refs,
        now_unix(),
    )?;

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
