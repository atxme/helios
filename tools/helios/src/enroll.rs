//! `enroll document`: the public half of an enrollment v5 document.
//!
//! Enrollment no longer moves a private key (NEGOCIATION-DE-CLE-V5 §15). The
//! client generated its three key pairs and sent a signed request;
//! `astra-signer enroll accept` issued its two leaves under the operator's
//! authorities and printed the `heliosd peer add` that admits it. What is left
//! is the profile: the gateway's public material, the client's leaves, and the
//! binding to the request — a document `astra-signer enroll sign-document`
//! then signs under `CA-PQ`.
//!
//! This command assembles that draft. It reads the gateway (through the API,
//! or from files fetched over SSH), checks that the leaves certify the very
//! keys the request names, and writes an unsigned `EnrollmentDocument`. The
//! draft carries no secret; it is still never written over an existing file.

use std::path::{Path, PathBuf};

use aether::certificates::encoding::{DerCertificate, MlDsa87PublicKey};
use aether::key_negotiation::{
    decode_request_file, EnrollmentDocument, EnrollmentRequest, PqCertificate, PqCertificateRole,
    ProtectionMode, ENROLLMENT_DOCUMENT_FORMAT, ENROLLMENT_DOCUMENT_VERSION,
};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use reqwest::Client;

use crate::{api, profile};

pub struct DocumentOptions {
    /// The client's `.helios-request`.
    pub request: PathBuf,
    /// TLS leaf `astra-signer enroll accept` wrote, DER.
    pub tls_certificate: PathBuf,
    /// PQ leaf `astra-signer enroll accept` wrote, JSON.
    pub pq_certificate: PathBuf,
    /// Gateway's public WireGuard endpoint (`IP:port` or `FQDN:port`).
    pub endpoint: String,
    /// Negotiation endpoint. Defaults to the tunnel host with the port the
    /// gateway publishes.
    pub negotiation_endpoint: Option<String>,
    /// Split tunnel to ship with the profile. Absent = full tunnel.
    ///
    /// Stated once by the operator and carried by the document, rather than
    /// retyped into each machine's Advanced panel — which is how a fleet ends
    /// up with as many routing tables as it has users.
    pub allowed_ips: Option<String>,
    /// SSH destination to ship with the profile. Absent = no terminal button.
    pub ssh_target: Option<String>,
    pub output: PathBuf,
    /// Enrollment without the control-plane API. See [`OfflineInputs`].
    pub offline: Option<OfflineInputs>,
}

/// Everything the API would have supplied, taken from the gateway by hand.
///
/// # Why this path exists
///
/// The API lives **behind the tunnel** (`admin_iface`), so reaching it means
/// already being connected. That is harmless for day-to-day operations and
/// absurd for the very first enrollment: it would make the negotiation that
/// protects the first handshake depend on a first handshake.
///
/// The protocol has no such dependency — Orion dials the public negotiation
/// port before mounting anything. Only the tooling did, and this is where it
/// stops: the operator already has an SSH session to the gateway, which is
/// enough to read two public certificates and the trust block, and to admit
/// the peer with `heliosd peer add`.
pub struct OfflineInputs {
    /// `/var/lib/helios/key-negotiation-cert.der`, fetched over SSH.
    pub gateway_certificate: PathBuf,
    /// `/var/lib/helios/key-negotiation-pq-cert.json`, fetched over SSH.
    pub gateway_pq_certificate: PathBuf,
    /// VIP printed by `heliosd peer add`, which performed the admission.
    pub address: String,
    /// IPv6 VIP of the same peer, `…/128`, as `network.toml` records it
    /// (`address_v6`). Absent for a peer without one — the document then
    /// omits the key, and every Orion reads it.
    pub address_v6: Option<String>,
    /// Internal API URL, for telemetry only. Absent is fine.
    pub heliosd_url: Option<String>,
    /// The §19 trust block, as `heliosd show-trust-enrolment` printed it.
    ///
    /// Required: the document is signed under the `CA-PQ` this block names,
    /// and a v5 profile without it has no anchor to renew under.
    pub trust_material: Option<PathBuf>,
}

/// Reads a trust block printed by `heliosd show-trust-enrolment`.
///
/// Validated here rather than at import: an operator running this command has
/// the gateway in front of them, and a block that is wrong is one SSH call
/// away from being reprinted. The same block discovered as invalid on a user's
/// machine is a redeployment.
fn read_trust_material(path: &Path) -> Result<orion_core::TrustMaterial> {
    let raw = std::fs::read(path)
        .with_context(|| format!("reading the trust block from {}", path.display()))?;
    let material: orion_core::TrustMaterial = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "{} is not a trust block — it is what `heliosd show-trust-enrolment --public-key \
             <clé>` prints",
            path.display()
        )
    })?;
    material
        .validate()
        .with_context(|| format!("the trust block in {} is unusable", path.display()))?;
    Ok(material)
}

/// Gateway-side material a profile pins, however it was obtained.
struct GatewayMaterial {
    server_name: String,
    gateway_ca_der: String,
    gateway_pq_certificate: String,
    wireguard_public_key: String,
    pq_certificate_sha256: String,
    negotiation_port: Option<u16>,
}

/// Reads the material from the two public certificates on disk.
///
/// The PQ certificate carries the subject **and** the WireGuard key it is
/// pinned to, so the operator has nothing to retype: everything the profile
/// needs is inside the file, and verifying it here means a mistyped copy is
/// caught now rather than as a refused negotiation later.
fn offline_material(inputs: &OfflineInputs) -> Result<GatewayMaterial> {
    use aether::key_negotiation::PqCertificate;

    let certificate_der = std::fs::read(&inputs.gateway_certificate).with_context(|| {
        format!(
            "reading the gateway certificate {}",
            inputs.gateway_certificate.display()
        )
    })?;
    let pq_certificate_json = std::fs::read(&inputs.gateway_pq_certificate).with_context(|| {
        format!(
            "reading the gateway PQ certificate {}",
            inputs.gateway_pq_certificate.display()
        )
    })?;
    let certificate: PqCertificate = serde_json::from_slice(&pq_certificate_json)
        .context("the gateway PQ certificate is not a readable JSON document")?;

    // The signature is **not** checked here. Which authority signs this leaf
    // depends on whether the gateway has a trust domain — self-signed without
    // one, `CA-PQ` with one (ADR-008 §13.1) — and the anchor for the second
    // case lives in the trust block, which is only known once the peer is
    // admitted. Verifying here would therefore accept exactly one of the two
    // shapes. `build_draft` checks the leaf once, for both paths, against the anchor
    // the profile is about to pin.
    let encoder = base64::engine::general_purpose::STANDARD;
    Ok(GatewayMaterial {
        server_name: certificate.subject.clone(),
        gateway_ca_der: encoder.encode(&certificate_der),
        gateway_pq_certificate: encoder.encode(&pq_certificate_json),
        wireguard_public_key: certificate.wireguard_public_key.clone(),
        pq_certificate_sha256: certificate.fingerprint()?,
        // Unknown offline: the port lives in the gateway's network.toml, not
        // in any certificate. `--negotiation-endpoint` states it.
        negotiation_port: None,
    })
}

/// What the gateway says about the admitted peer, however it was read.
struct Admission {
    address: String,
    address_v6: Option<String>,
    heliosd_url: Option<String>,
    trust: Option<orion_core::TrustMaterial>,
}

pub async fn document(client: &Client, base: &str, options: DocumentOptions) -> Result<()> {
    let request = read_request(&options.request)?;
    let tls_certificate =
        DerCertificate::new(read_file(&options.tls_certificate)?).with_context(|| {
            format!(
                "{} is not a DER certificate",
                options.tls_certificate.display()
            )
        })?;
    let pq_certificate: PqCertificate =
        serde_json::from_slice(&read_file(&options.pq_certificate)?).with_context(|| {
            format!(
                "{} is not a PQ certificate",
                options.pq_certificate.display()
            )
        })?;
    // Checked before the gateway is contacted: leaves for another request are
    // a mix-up of files, and nothing the gateway says can repair it.
    check_leaves(&request, &tls_certificate, &pq_certificate)?;

    let client_key = request.client_wg_public_key.to_base64();
    let (material, admission) = match &options.offline {
        Some(inputs) => (
            offline_material(inputs)?,
            Admission {
                address: inputs.address.clone(),
                address_v6: inputs.address_v6.clone(),
                heliosd_url: inputs.heliosd_url.clone(),
                trust: inputs
                    .trust_material
                    .as_deref()
                    .map(read_trust_material)
                    .transpose()?,
            },
        ),
        None => online_material(client, base, &client_key).await?,
    };
    let negotiation_endpoint = resolve_negotiation_endpoint(
        &options.endpoint,
        options.negotiation_endpoint.as_deref(),
        material.negotiation_port,
    )?;
    let draft = build_draft(Draft {
        request: &request,
        tls_certificate,
        pq_certificate: &pq_certificate,
        material: &material,
        admission,
        endpoint: &options.endpoint,
        negotiation_endpoint,
        allowed_ips: options.allowed_ips.as_deref(),
        ssh_target: options.ssh_target.as_deref(),
        now_unix: now_unix()?,
    })?;
    let json = draft.to_json().context("encoding the draft")?;
    // The consumer reads the draft before anyone signs it: a document Orion
    // would refuse must not cost a ceremony.
    orion_core::parse_profile_import(&json, "draft.orion")
        .context("the draft is not readable by Orion — this is a tooling bug")?;
    crate::files::write_new(&options.output, json.as_bytes(), false)?;
    report(&options, &request, &material);
    Ok(())
}

async fn online_material(
    client: &Client,
    base: &str,
    client_key: &str,
) -> Result<(GatewayMaterial, Admission)> {
    let network = api::network(client, base).await?;
    let gateway_public_key = network
        .wg_public_key
        .clone()
        .filter(|key| !key.is_empty())
        .context(
            "the gateway has no WireGuard identity yet — run `heliosd init-identity` on the \
             gateway, with console access",
        )?;
    let negotiation = api::key_negotiation(client, base).await?.context(
        "this gateway serves no key-negotiation material — build heliosd with the \
         `key-negotiation` feature and run `heliosd init-key-negotiation`",
    )?;
    // The gateway certificate is pinned to a WireGuard key. If that is not
    // the identity the gateway actually runs on, every client built here
    // would fail its pinning check — and the message would blame the client.
    if negotiation.wireguard_public_key != gateway_public_key {
        bail!(
            "the gateway negotiation certificate is bound to another WireGuard identity: it pins \
             {}, while the gateway runs {}. Its identity was rotated without reissuing the \
             certificate — re-run `heliosd init-key-negotiation --rotate`.",
            negotiation.wireguard_public_key,
            gateway_public_key
        );
    }
    let peer = network
        .peers
        .iter()
        .find(|peer| peer.public_key.trim() == client_key)
        .with_context(|| {
            format!(
                "no peer holds the key {client_key} on this gateway: admit it first with the \
                 `heliosd peer add` line `astra-signer enroll accept` printed"
            )
        })?;
    let admission = Admission {
        address: peer.address.clone(),
        address_v6: peer
            .address_v6
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        heliosd_url: profile::heliosd_url(&network.wg_address),
        trust: api::trust_enrolment(client, base, client_key).await?,
    };
    Ok((
        GatewayMaterial {
            server_name: negotiation.server_name,
            gateway_ca_der: negotiation.gateway_ca_der,
            gateway_pq_certificate: negotiation.gateway_pq_certificate,
            wireguard_public_key: negotiation.wireguard_public_key,
            pq_certificate_sha256: negotiation.pq_certificate_sha256,
            negotiation_port: negotiation.port,
        },
        admission,
    ))
}

/// The inputs of a draft, once every file and the gateway have been read.
struct Draft<'a> {
    request: &'a EnrollmentRequest,
    tls_certificate: DerCertificate,
    pq_certificate: &'a PqCertificate,
    material: &'a GatewayMaterial,
    admission: Admission,
    endpoint: &'a str,
    negotiation_endpoint: String,
    allowed_ips: Option<&'a str>,
    ssh_target: Option<&'a str>,
    now_unix: u64,
}

/// The leaves must certify the keys the request names, and nothing else.
fn check_leaves(
    request: &EnrollmentRequest,
    tls_certificate: &DerCertificate,
    pq_certificate: &PqCertificate,
) -> Result<()> {
    aether::certificates::x509::assert_csr_matches(&request.tls_csr, tls_certificate)
        .map_err(|error| anyhow::anyhow!("the TLS leaf does not certify the request: {error}"))?;
    if pq_certificate.role != PqCertificateRole::Client {
        bail!("the PQ leaf is not a client leaf");
    }
    let wireguard = request.client_wg_public_key.to_base64();
    if pq_certificate.wireguard_public_key != wireguard {
        bail!(
            "the PQ leaf certifies the WireGuard key {}, while the request names {wireguard}",
            pq_certificate.wireguard_public_key
        );
    }
    let ml_dsa = request.client_ml_dsa_87_public_key.to_base64();
    if pq_certificate.ml_dsa_87_public_key != ml_dsa {
        bail!("the PQ leaf certifies another ML-DSA-87 key than the request's");
    }
    Ok(())
}

fn build_draft(draft: Draft<'_>) -> Result<EnrollmentDocument> {
    let Some(trust) = draft.admission.trust else {
        bail!(
            "cette gateway n'a pas de domaine de confiance : `astra-signer init` puis \
             `heliosd init-trust-domain`. Un document v5 est signé sous la CA-PQ que ce domaine \
             épingle."
        );
    };
    let ca_pq_public_key = MlDsa87PublicKey::parse(&trust.ca_pq_public_key)
        .context("the trust block names an unreadable CA-PQ key")?;
    draft
        .pq_certificate
        .verify(
            ca_pq_public_key.as_bytes(),
            PqCertificateRole::Client,
            Some(&draft.request.requested_name),
            &draft.request.client_wg_public_key.to_base64(),
            draft.now_unix,
        )
        .map_err(|error| {
            anyhow::anyhow!("the PQ leaf does not verify under this domain's CA-PQ: {error}")
        })?;

    // The one place the pinned gateway leaf is verified, under the authority
    // that issued it — the trust block's `CA-PQ`.
    let gateway_certificate: PqCertificate = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(&draft.material.gateway_pq_certificate)
            .context("the gateway PQ certificate is not valid base64")?,
    )
    .context("the gateway PQ certificate is not a readable JSON document")?;
    orion_core::verify_pinned_gateway_certificate(
        &gateway_certificate,
        &draft.material.server_name,
        &draft.material.wireguard_public_key,
        Some(&trust),
        draft.now_unix,
    )
    .context("the gateway PQ certificate does not verify — copied incompletely, or expired")?;

    let public = profile::public_profile(&profile::Profile {
        name: &draft.request.requested_name,
        endpoint: draft.endpoint,
        private_key: None,
        peer_public_key: &draft.material.wireguard_public_key,
        address: &draft.admission.address,
        address_v6: draft.admission.address_v6.as_deref(),
        allowed_ips: draft.allowed_ips,
        ssh_target: draft.ssh_target,
        heliosd_url: draft.admission.heliosd_url,
        key_negotiation: Some(profile::KeyNegotiation {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::MlKem,
            endpoint: draft.negotiation_endpoint,
            server_name: draft.material.server_name.clone(),
            gateway_ca_der: draft.material.gateway_ca_der.clone(),
            gateway_pq_certificate: draft.material.gateway_pq_certificate.clone(),
            trust: Some(trust),
        }),
    })?;
    Ok(EnrollmentDocument {
        format: ENROLLMENT_DOCUMENT_FORMAT.into(),
        format_version: ENROLLMENT_DOCUMENT_VERSION,
        invitation_id: draft.request.invitation_id,
        request_id: draft.request.request_id,
        request_fingerprint: draft.request.fingerprint(),
        operator_ca_fingerprint: ca_pq_public_key.authority_fingerprint(),
        issued_at_unix: draft.now_unix,
        profile: public,
        client_tls_certificate: draft.tls_certificate,
        client_pq_certificate: base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(draft.pq_certificate).context("encoding the client PQ leaf")?,
        ),
        operator_signature: None,
    })
}

fn read_request(path: &Path) -> Result<EnrollmentRequest> {
    // Decoded as Orion decodes it: the client's machine may have re-saved it
    // in UTF-16.
    let text = aether::transit_text::decode_transit_text(&read_file(path)?)
        .with_context(|| format!("{} is not readable text", path.display()))?;
    let request = decode_request_file(&text)
        .with_context(|| format!("{} is not an enrollment request", path.display()))?;
    Ok(request)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

/// Endpoint of the negotiation service, as the client will dial it.
///
/// Derived from the tunnel endpoint by default: the two services live on the
/// same host, and asking the operator to retype the address is one more place
/// to get it wrong. The port comes from the gateway, never from a guess — a
/// hardcoded 51821 would silently be wrong on a gateway that moved it.
fn resolve_negotiation_endpoint(
    endpoint: &str,
    explicit: Option<&str>,
    port: Option<u16>,
) -> Result<String> {
    if let Some(explicit) = explicit {
        return Ok(explicit.trim().to_string());
    }
    let port = port.context(
        "the gateway publishes no key-negotiation port — set `key_negotiation_port` in \
         network.toml, or pass --negotiation-endpoint",
    )?;
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(endpoint);
    Ok(format!("{host}:{port}"))
}

/// The command the operator is told to paste next.
///
/// The requested name is the client's choice and never reaches it: pasted on
/// the machine holding the hardware credential, `$(…)` in a name would run
/// there. The output is named after the request id, as `accept` names the
/// leaves, and the draft path is quoted.
fn sign_command(draft: &Path, request: &EnrollmentRequest) -> String {
    format!(
        "astra-signer enroll sign-document --draft {} --out {}.orion",
        shell_word(&draft.display().to_string()),
        request.request_id.to_hex()
    )
}

/// One shell word, quoted only when it needs to be.
fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:+,@".contains(c));
    if plain {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn report(options: &DocumentOptions, request: &EnrollmentRequest, material: &GatewayMaterial) {
    println!(
        "{} draft for \"{}\" → {}",
        crate::ok(),
        request.requested_name,
        options.output.display()
    );
    println!();
    println!("  \x1b[2mNo private key in this file, and no signature yet. Sign it with:\x1b[0m");
    println!("  {}", sign_command(&options.output, request));
    println!();
    println!(
        "  \x1b[2mgateway PQ certificate: {}\x1b[0m",
        material.pq_certificate_sha256
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{Fingerprint, Id16, MlDsa87Signature, WireGuardKey};
    use aether::key_negotiation::{
        generate_ml_dsa_87_keypair, issue_pq_certificate, ENROLLMENT_FORMAT_VERSION,
        ENROLLMENT_PROTOCOL_VERSION, PQ_CERTIFICATE_VERSION,
    };
    use base64::engine::general_purpose::STANDARD;

    const SERVER_NAME: &str = "vpn.example.net";

    struct Fixture {
        request: EnrollmentRequest,
        tls_certificate: DerCertificate,
        pq_certificate: PqCertificate,
        material: GatewayMaterial,
        trust: orion_core::TrustMaterial,
    }

    fn now() -> u64 {
        now_unix().unwrap()
    }

    fn pq_leaf(
        ca: &[u8],
        role: PqCertificateRole,
        subject: &str,
        wireguard: &str,
        ml_dsa: &str,
    ) -> PqCertificate {
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [5; 16],
                subject: subject.into(),
                issuer: "CA-PQ".into(),
                role,
                wireguard_public_key: wireguard.into(),
                ml_dsa_87_public_key: ml_dsa.into(),
                not_before_unix: now() - 60,
                not_after_unix: now() + 86_400,
                ml_dsa_87_signature: String::new(),
            },
            ca,
        )
        .unwrap()
    }

    fn tls_leaf(csr: &DerCertificate) -> (DerCertificate, DerCertificate) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let request =
            rcgen::CertificateSigningRequestParams::from_der(&csr.as_bytes().into()).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_der(ca.der(), &ca_key).unwrap();
        (
            DerCertificate::new(request.signed_by(&issuer).unwrap().der().to_vec()).unwrap(),
            DerCertificate::new(ca.der().to_vec()).unwrap(),
        )
    }

    fn fixture() -> Fixture {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
        let ca_public = MlDsa87PublicKey::new(ca_public).unwrap();
        let (_, client_ml_dsa) = generate_ml_dsa_87_keypair().unwrap();
        let client_ml_dsa = MlDsa87PublicKey::new(client_ml_dsa).unwrap();
        let client_wg = aether::wg::generate_keypair().unwrap();
        let gateway_wg = aether::wg::generate_keypair().unwrap();
        let csr = aether::certificates::x509::client_rotation_csr("poste-windows").unwrap();
        let request = EnrollmentRequest {
            format_version: ENROLLMENT_FORMAT_VERSION,
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: Id16::new([1; 16]).unwrap(),
            invitation_fingerprint: Fingerprint::from_bytes([2; 32]),
            request_id: Id16::new([3; 16]).unwrap(),
            timestamp_unix: now(),
            requested_name: "poste-windows".into(),
            client_wg_public_key: WireGuardKey::parse(&client_wg.public_key).unwrap(),
            tls_csr: csr.csr,
            client_ml_dsa_87_public_key: client_ml_dsa.clone(),
            wireguard_proof: [0; 32],
            client_signature: MlDsa87Signature::placeholder(),
        };
        let (tls_certificate, tls_ca) = tls_leaf(&request.tls_csr);
        let pq_certificate = pq_leaf(
            &ca_private,
            PqCertificateRole::Client,
            "poste-windows",
            &client_wg.public_key,
            &client_ml_dsa.to_base64(),
        );
        let (_, gateway_ml_dsa) = generate_ml_dsa_87_keypair().unwrap();
        let gateway = pq_leaf(
            &ca_private,
            PqCertificateRole::Gateway,
            SERVER_NAME,
            &gateway_wg.public_key,
            &STANDARD.encode(&gateway_ml_dsa),
        );
        Fixture {
            material: GatewayMaterial {
                server_name: SERVER_NAME.into(),
                gateway_ca_der: STANDARD.encode([0x30, 0x82, 0x01, 0x00]),
                gateway_pq_certificate: STANDARD.encode(serde_json::to_vec(&gateway).unwrap()),
                wireguard_public_key: gateway_wg.public_key,
                pq_certificate_sha256: gateway.fingerprint().unwrap(),
                negotiation_port: Some(51821),
            },
            trust: orion_core::TrustMaterial {
                trust_domain_id: "11".repeat(16),
                ca_epoch: 1,
                ca_pq_public_key: ca_public.to_base64(),
                ca_tls_epoch: 1,
                client_tls_ca_der: STANDARD.encode(tls_ca.as_bytes()),
                client_generation: 1,
                astra_authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint: Fingerprint::of(b"policy").to_hex(),
                credential_registry_epoch: 1,
                astra_credential_bindings: Vec::new(),
                astra_service_key_epoch: 1,
                astra_service_public_key: ca_public.to_base64(),
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
            },
            request,
            tls_certificate,
            pq_certificate,
        }
    }

    fn draft(
        fixture: &Fixture,
        trust: Option<orion_core::TrustMaterial>,
    ) -> Result<EnrollmentDocument> {
        build_draft(Draft {
            request: &fixture.request,
            tls_certificate: fixture.tls_certificate.clone(),
            pq_certificate: &fixture.pq_certificate,
            material: &fixture.material,
            admission: Admission {
                address: "100.64.1.2/32".into(),
                address_v6: None,
                heliosd_url: None,
                trust,
            },
            endpoint: "vpn.example.net:51820",
            negotiation_endpoint: "vpn.example.net:51821".into(),
            allowed_ips: None,
            ssh_target: None,
            now_unix: now(),
        })
    }

    #[test]
    fn a_draft_without_a_trust_domain_is_refused() {
        let fixture = fixture();
        let error = format!("{:#}", draft(&fixture, None).expect_err("refused"));
        assert!(error.contains("domaine de confiance"), "{error}");
        assert!(error.contains("heliosd init-trust-domain"), "{error}");
    }

    #[test]
    fn a_draft_for_leaves_that_do_not_certify_the_request_is_refused() {
        let mine = fixture();
        let other = fixture();
        assert!(check_leaves(&mine.request, &other.tls_certificate, &mine.pq_certificate).is_err());
        assert!(check_leaves(&mine.request, &mine.tls_certificate, &other.pq_certificate).is_err());
        check_leaves(&mine.request, &mine.tls_certificate, &mine.pq_certificate)
            .expect("the leaves of this request");
        // Leaves of this request, under another domain's CA-PQ.
        let mut foreign = other.trust.clone();
        foreign.client_tls_ca_der = mine.trust.client_tls_ca_der.clone();
        assert!(draft(&mine, Some(foreign)).is_err());
    }

    #[test]
    fn a_draft_carries_no_identity_and_no_signature() {
        let fixture = fixture();
        let document = draft(&fixture, Some(fixture.trust.clone())).expect("draft");
        assert!(document.operator_signature.is_none());
        assert_eq!(document.request_fingerprint, fixture.request.fingerprint());
        assert_eq!(
            document.operator_ca_fingerprint,
            MlDsa87PublicKey::parse(&fixture.trust.ca_pq_public_key)
                .unwrap()
                .authority_fingerprint()
        );
        let json = document.to_json().unwrap();
        for absent in [
            "key_negotiation_identity",
            "private_key",
            "operator_signature",
            "\"identity\"",
            "preshared_key",
        ] {
            assert!(!json.contains(absent), "{absent} in {json}");
        }
        let imported =
            orion_core::parse_profile_import(&json, "draft.orion").expect("Orion reads it");
        assert!(imported.enrollment.is_some());
        assert_eq!(imported.profile.name, "poste-windows");
    }

    #[test]
    fn the_suggested_sign_command_never_carries_the_client_chosen_name() {
        let mut request = fixture().request;
        request.requested_name = "x$(touch pwned); ../../etc/y".into();
        let command = sign_command(Path::new("brouillon de poste.json"), &request);
        assert!(!command.contains("pwned"), "{command}");
        assert!(!command.contains(".."), "{command}");
        assert_eq!(
            command,
            format!(
                "astra-signer enroll sign-document --draft 'brouillon de poste.json' --out {}.orion",
                request.request_id.to_hex()
            )
        );
    }

    #[test]
    fn the_old_one_shot_options_are_gone() {
        use clap::Parser as _;
        let base = [
            "helios",
            "enroll",
            "document",
            "--request",
            "r",
            "--tls-certificate",
            "t",
            "--pq-certificate",
            "p",
            "--endpoint",
            "vpn.example.net:51820",
            "--out",
            "d.json",
        ];
        crate::Cli::try_parse_from(base).expect("the v5 form parses");
        for old in [
            ["--private-key-file", "k"],
            ["--public-key", "k"],
            ["--client-pki-dir", "d"],
            ["--client-ca-dir", "d"],
            ["--identity", "i"],
            ["--mode", "ml-kem"],
        ] {
            let mut argv = base.to_vec();
            argv.extend(old);
            assert!(
                crate::Cli::try_parse_from(argv).is_err(),
                "{old:?} still parses"
            );
        }
    }

    /// The negotiation port is the gateway's to state: hardcoding 51821 would
    /// silently produce unreachable profiles on a gateway that moved it.
    #[test]
    fn the_negotiation_endpoint_keeps_the_host_and_takes_the_published_port() {
        assert_eq!(
            resolve_negotiation_endpoint("vpn.example.net:51820", None, Some(51821)).unwrap(),
            "vpn.example.net:51821"
        );
        assert_eq!(
            resolve_negotiation_endpoint("[2001:db8::1]:51820", None, Some(7777)).unwrap(),
            "[2001:db8::1]:7777"
        );
        assert_eq!(
            resolve_negotiation_endpoint(
                "vpn.example.net:51820",
                Some("autre.example.net:51821"),
                None
            )
            .unwrap(),
            "autre.example.net:51821"
        );
        assert!(resolve_negotiation_endpoint("vpn.example.net:51820", None, None).is_err());
    }

    /// Offline, everything the profile pins comes out of the two public
    /// certificates — nothing is retyped, so nothing can be mistyped.
    #[test]
    fn the_offline_material_is_read_entirely_from_the_gateway_certificates() {
        use aether::key_negotiation::{
            generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
            PQ_CERTIFICATE_VERSION,
        };
        use base64::engine::general_purpose::STANDARD;

        let gateway_key = aether::wg::generate_keypair().unwrap();
        let (private_key, public_key) = generate_ml_dsa_87_keypair().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [5u8; 16],
                subject: "vpn.example.net".into(),
                issuer: "vpn.example.net".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: gateway_key.public_key.clone(),
                ml_dsa_87_public_key: STANDARD.encode(&public_key),
                not_before_unix: now - 60,
                not_after_unix: now + 3600,
                ml_dsa_87_signature: String::new(),
            },
            &private_key,
        )
        .unwrap();

        let directory = std::env::temp_dir().join(format!("orion-offline-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let der = directory.join("cert.der");
        let json = directory.join("pq.json");
        std::fs::write(&der, [0x30, 0x82, 0x01, 0x00]).unwrap();
        std::fs::write(&json, serde_json::to_vec(&certificate).unwrap()).unwrap();

        let inputs = OfflineInputs {
            gateway_certificate: der.clone(),
            gateway_pq_certificate: json.clone(),
            address: "100.64.1.2/32".into(),
            address_v6: None,
            heliosd_url: None,
            trust_material: None,
        };
        let material = offline_material(&inputs).expect("material read from the certificates");
        assert_eq!(material.server_name, "vpn.example.net");
        assert_eq!(material.wireguard_public_key, gateway_key.public_key);
        assert_eq!(
            material.pq_certificate_sha256,
            certificate.fingerprint().unwrap()
        );
        // No port in any certificate: it lives in the gateway's network.toml.
        assert_eq!(material.negotiation_port, None);

        // A truncated copy must be caught here, not as a refused negotiation
        // days later on the user's machine.
        std::fs::write(&json, b"{\"version\":1}").unwrap();
        assert!(offline_material(&inputs).is_err());

        let _ = std::fs::remove_dir_all(&directory);
    }
}
